pub mod allowlist;
pub mod auth;
pub mod cve;
pub mod filesystem;
pub mod injection;
pub mod network;
pub mod secrets;
pub mod shell;
pub mod transport;
pub mod write_tools;

pub mod deps;
pub mod supply_chain;

use crate::config::McpServer;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Severity {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

#[derive(Debug, Clone, Serialize)]
pub struct EpssData {
    pub probability: f64,
    pub percentile: f64,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
        }
    }

    pub fn from_str(s: &str) -> Option<Severity> {
        match s.to_lowercase().as_str() {
            "critical" => Some(Severity::Critical),
            "high" => Some(Severity::High),
            "medium" => Some(Severity::Medium),
            "low" => Some(Severity::Low),
            _ => None,
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub rule_id: String,
    pub severity: Severity,
    pub title: String,
    pub message: String,
    pub fix: String,
    pub config_file: String,
    pub server_name: String,
    /// Source of the finding: None for rule checks, Some("osv") for live OSV lookups.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// EPSS exploitation probability data for CVE findings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epss: Option<EpssData>,
    /// Sub-items for supply chain risk signals, rendered as a tree in terminal output.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_items: Option<Vec<String>>,
}

/// Trait that all detection rules must implement.
pub trait Rule: Send + Sync {
    fn id(&self) -> &'static str;
    fn check(&self, server_name: &str, server: &McpServer, config_file: &str) -> Vec<Finding>;
}

/// Create an instance of every detection rule.
pub fn all_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(auth::AuthRule),
        Box::new(filesystem::FilesystemRule),
        Box::new(shell::ShellRule),
        Box::new(secrets::SecretsRule::new()),
        Box::new(transport::TransportRule),
        Box::new(cve::CveRule::new()),
        Box::new(allowlist::AllowlistRule),
        Box::new(write_tools::WriteToolsRule),
        Box::new(network::NetworkRule),
        Box::new(injection::InjectionRule::new()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
    }

    #[test]
    fn test_severity_from_str() {
        assert_eq!(Severity::from_str("critical"), Some(Severity::Critical));
        assert_eq!(Severity::from_str("HIGH"), Some(Severity::High));
        assert_eq!(Severity::from_str("Medium"), Some(Severity::Medium));
        assert_eq!(Severity::from_str("low"), Some(Severity::Low));
        assert_eq!(Severity::from_str("unknown"), None);
    }

    #[test]
    fn test_all_rules_count() {
        let rules = all_rules();
        assert_eq!(rules.len(), 10);
    }

    #[test]
    fn test_all_rules_unique_ids() {
        let rules = all_rules();
        let ids: Vec<&str> = rules.iter().map(|r| r.id()).collect();
        let mut unique = ids.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(ids.len(), unique.len(), "Rule IDs must be unique");
    }
}
