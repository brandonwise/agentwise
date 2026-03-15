mod config;
mod cvedb;
mod depsdev;
mod epss;
mod osv;
mod report;
mod rules;
mod scanner;
mod score;
mod supply_chain;

use clap::{Parser, Subcommand};
use report::OutputFormat;
use rules::Severity;
use std::collections::HashSet;

#[derive(Parser)]
#[command(
    name = "agentwise",
    version,
    about = "A fast, offline security scanner for MCP server configurations",
    long_about = "agentwise scans MCP (Model Context Protocol) server configurations for security vulnerabilities, misconfigurations, and known CVEs. Single binary. Zero dependencies. Millisecond scans."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan MCP server configurations for security issues
    Scan {
        /// Path to scan (file or directory)
        #[arg(default_value = ".")]
        path: String,

        /// Output format
        #[arg(long, default_value = "terminal", value_parser = ["terminal", "json", "sarif"])]
        format: String,

        /// Exit with code 1 if findings at this severity or above are found
        #[arg(long, value_parser = ["critical", "high", "medium", "low"])]
        fail_on: Option<String>,

        /// Query OSV live for package CVEs found during this scan
        #[arg(long)]
        live: bool,

        /// Force offline mode (embedded + local cache only)
        #[arg(long)]
        offline: bool,

        /// Run supply chain and dependency analysis (requires network)
        #[arg(long)]
        supply_chain: bool,
    },

    /// Update local CVE cache from OSV
    Update,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            path,
            format,
            fail_on,
            live,
            offline,
            supply_chain,
        } => {
            let output_format = OutputFormat::from_str(&format).unwrap_or(OutputFormat::Terminal);

            let result = if supply_chain && !offline {
                scanner::scan_with_supply_chain(&path, live).await
            } else if live && !offline {
                scanner::scan_with_live(&path).await
            } else {
                scanner::scan(&path)
            };

            let output = report::render(&result, output_format);
            print!("{}", output);

            // Check fail-on threshold
            if let Some(fail_on) = fail_on {
                if let Some(threshold) = Severity::from_str(&fail_on) {
                    let has_violation = result.findings.iter().any(|f| f.severity >= threshold);
                    if has_violation {
                        std::process::exit(1);
                    }
                }
            }
        }
        Commands::Update => {
            match update_cache_from_osv().await {
                Ok((count, packages)) => {
                    println!(
                        "Updated: {} vulnerabilities for {} packages (cached at {})",
                        count,
                        packages,
                        cvedb::cache_path().display()
                    );
                }
                Err(e) => {
                    eprintln!("Update failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }
}

async fn update_cache_from_osv() -> Result<(usize, usize), String> {
    let batch = osv::query_packages_batch(osv::KNOWN_MCP_PACKAGES, "npm").await?;

    let mut entries = Vec::new();
    for (package, vulns) in &batch {
        let mut converted = osv::vulns_to_cve_entries(package, vulns);
        entries.append(&mut converted);
    }

    // Deduplicate by (id, package)
    let mut seen = HashSet::new();
    entries.retain(|e| seen.insert((e.id.clone(), e.package.clone())));

    cvedb::save_cache(&entries)?;

    let packages_with_results = batch.iter().filter(|(_, v)| !v.is_empty()).count();
    Ok((entries.len(), packages_with_results))
}
