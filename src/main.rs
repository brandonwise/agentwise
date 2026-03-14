mod config;
mod cvedb;
mod report;
mod rules;
mod scanner;
mod score;

use clap::{Parser, Subcommand};
use report::OutputFormat;
use rules::Severity;

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
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            path,
            format,
            fail_on,
        } => {
            let output_format = OutputFormat::from_str(&format).unwrap_or(OutputFormat::Terminal);
            let result = scanner::scan(&path);
            let output = report::render(&result, output_format);
            print!("{}", output);

            // Check fail-on threshold
            if let Some(fail_on) = fail_on {
                if let Some(threshold) = Severity::from_str(&fail_on) {
                    let has_violation = result
                        .findings
                        .iter()
                        .any(|f| f.severity >= threshold);
                    if has_violation {
                        std::process::exit(1);
                    }
                }
            }
        }
    }
}
