mod badge;
mod baseline;
mod config;
mod cvedb;
mod depsdev;
mod diff;
mod discover;
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
        #[arg(long, default_value = "terminal", value_parser = ["terminal", "json", "sarif", "markdown", "html"])]
        format: String,

        /// Optional output file path (used for HTML reports)
        #[arg(long)]
        output: Option<String>,

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

        /// Auto-discover all system MCP configs and scan them
        #[arg(long)]
        auto: bool,

        /// Path to a baseline ignore file (.agentwise-ignore.json)
        #[arg(long)]
        baseline: Option<String>,
    },

    /// Discover MCP configuration files across the system
    Discover {
        /// Output as JSON
        #[arg(long)]
        json: bool,

        /// Discover and scan all found configs
        #[arg(long)]
        scan: bool,

        /// Output format for --scan mode
        #[arg(long, default_value = "terminal", value_parser = ["terminal", "json", "sarif", "markdown", "html"])]
        format: String,
    },

    /// Compare two JSON scan reports
    Diff {
        /// Path to the "before" JSON report
        before: String,

        /// Path to the "after" JSON report
        after: String,

        /// Output format
        #[arg(long, default_value = "terminal")]
        format: String,
    },

    /// Manage baseline ignore files
    Baseline {
        #[command(subcommand)]
        action: BaselineAction,
    },

    /// Generate a score badge URL or SVG
    Badge {
        /// Badge output format (url or svg)
        #[arg(long, default_value = "url", value_parser = ["url", "svg"])]
        format: String,

        /// Optional output file path
        #[arg(long)]
        output: Option<String>,

        /// Path to scan before generating the badge
        #[arg(default_value = ".")]
        path: String,
    },

    /// Update local CVE cache from OSV
    Update,
}

#[derive(Subcommand)]
enum BaselineAction {
    /// Create a starter .agentwise-ignore.json in the current directory
    Init,

    /// Print the baseline file from the current directory
    Show,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            path,
            format,
            output,
            fail_on,
            live,
            offline,
            supply_chain,
            auto,
            baseline,
        } => {
            let output_format = OutputFormat::from_str(&format).unwrap_or(OutputFormat::Terminal);

            let mut result = if auto {
                let paths = discover::discover_existing_paths();
                if paths.is_empty() {
                    eprintln!("No MCP configurations found on this system.");
                    return;
                }
                if supply_chain && !offline {
                    scanner::scan_paths_with_supply_chain(&paths, live).await
                } else if live && !offline {
                    scanner::scan_paths_with_live(&paths).await
                } else {
                    scanner::scan_paths(&paths)
                }
            } else if supply_chain && !offline {
                scanner::scan_with_supply_chain(&path, live).await
            } else if live && !offline {
                scanner::scan_with_live(&path).await
            } else {
                scanner::scan(&path)
            };

            match baseline::load_for_scan(&path, baseline.as_deref()) {
                Ok(Some((baseline_config, _baseline_path))) => {
                    match baseline::filter_findings(
                        std::mem::take(&mut result.findings),
                        &baseline_config,
                    ) {
                        Ok((filtered, suppressed)) => {
                            result.findings = filtered;
                            result.suppressed_count = suppressed.len();
                            let severities: Vec<Severity> =
                                result.findings.iter().map(|f| f.severity).collect();
                            let (score, grade) = score::compute_score(&severities);
                            result.score = score;
                            result.grade = grade;
                        }
                        Err(e) => {
                            eprintln!("{}", e);
                            std::process::exit(1);
                        }
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    eprintln!("{}", e);
                    std::process::exit(1);
                }
            }

            let rendered_output = report::render(&result, output_format);

            if output_format == OutputFormat::Html {
                if let Some(output_path) = output {
                    if let Err(e) = std::fs::write(&output_path, &rendered_output) {
                        eprintln!("Failed to write HTML report to {}: {}", output_path, e);
                        std::process::exit(1);
                    }
                } else {
                    print!("{}", rendered_output);
                }
            } else {
                print!("{}", rendered_output);
            }

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
        Commands::Discover { json, scan, format } => {
            if scan {
                // Discover + scan mode
                let paths = discover::discover_existing_paths();
                if paths.is_empty() {
                    eprintln!("No MCP configurations found on this system.");
                    return;
                }
                let result = scanner::scan_paths(&paths);
                let output_format = if json {
                    OutputFormat::Json
                } else {
                    OutputFormat::from_str(&format).unwrap_or(OutputFormat::Terminal)
                };
                let output = report::render(&result, output_format);
                print!("{}", output);
            } else if json {
                // JSON discovery report
                let configs = discover::discover_configs();
                let output = serde_json::to_string_pretty(&configs).unwrap();
                println!("{}", output);
            } else {
                // Pretty terminal discovery report
                let configs = discover::discover_configs();
                print!("{}", report::terminal::render_discover(&configs));
            }
        }
        Commands::Diff {
            before,
            after,
            format,
        } => {
            let diff_result = match diff::compare_reports(&before, &after) {
                Ok(result) => result,
                Err(e) => {
                    eprintln!("{}", e);
                    std::process::exit(1);
                }
            };

            match format.to_lowercase().as_str() {
                "terminal" | "text" => print!("{}", diff::render_terminal(&diff_result)),
                "json" => match diff::render_json(&diff_result) {
                    Ok(output) => println!("{}", output),
                    Err(e) => {
                        eprintln!("{}", e);
                        std::process::exit(1);
                    }
                },
                _ => {
                    eprintln!(
                        "Unsupported diff format '{}'. Use 'terminal' or 'json'.",
                        format
                    );
                    std::process::exit(1);
                }
            }
        }
        Commands::Baseline { action } => match action {
            BaselineAction::Init => match baseline::init_in_dir(std::path::Path::new(".")) {
                Ok(path) => println!("Created baseline file: {}", path.display()),
                Err(e) => {
                    eprintln!("{}", e);
                    std::process::exit(1);
                }
            },
            BaselineAction::Show => match baseline::show_in_dir(std::path::Path::new(".")) {
                Ok(content) => println!("{}", content),
                Err(e) => {
                    eprintln!("{}", e);
                    std::process::exit(1);
                }
            },
        },
        Commands::Badge {
            format,
            output,
            path,
        } => {
            let result = scanner::scan(&path);
            let badge = match format.as_str() {
                "svg" => badge::generate_badge_svg(result.score, &result.grade),
                _ => badge::generate_badge_url(result.score, &result.grade),
            };

            if let Some(output_path) = output {
                if let Err(e) = std::fs::write(&output_path, &badge) {
                    eprintln!("Failed to write badge to {}: {}", output_path, e);
                    std::process::exit(1);
                }
            } else {
                println!("{}", badge);
            }
        }
        Commands::Update => match update_cache_from_osv().await {
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
        },
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
