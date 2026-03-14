pub mod json;
pub mod sarif;
pub mod terminal;

use crate::scanner::ScanResult;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Terminal,
    Json,
    Sarif,
}

impl OutputFormat {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "terminal" | "text" => Some(OutputFormat::Terminal),
            "json" => Some(OutputFormat::Json),
            "sarif" => Some(OutputFormat::Sarif),
            _ => None,
        }
    }
}

/// Render the scan result in the requested format, returning the output string.
pub fn render(result: &ScanResult, format: OutputFormat) -> String {
    match format {
        OutputFormat::Terminal => terminal::render(result),
        OutputFormat::Json => json::render(result),
        OutputFormat::Sarif => sarif::render(result),
    }
}
