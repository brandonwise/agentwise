use crate::config::{extract_package_info, McpServer};
use crate::cvedb;
use crate::rules::{Finding, Rule, Severity};

/// AW-006: Match package names + versions against embedded CVE database.
pub struct CveRule {
    db: Vec<cvedb::CveEntry>,
}

impl CveRule {
    pub fn new() -> Self {
        Self {
            db: cvedb::load_cve_db(),
        }
    }
}

impl Rule for CveRule {
    fn id(&self) -> &'static str {
        "AW-006"
    }

    fn check(&self, server_name: &str, server: &McpServer, config_file: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let packages = extract_package_info(server);

        for (package, version) in &packages {
            let cves = cvedb::check_package(package, version, &self.db);
            for cve in cves {
                let severity = match cve.severity.as_str() {
                    "critical" => Severity::Critical,
                    "high" => Severity::High,
                    "medium" => Severity::Medium,
                    _ => Severity::Low,
                };

                findings.push(Finding {
                    rule_id: self.id().to_string(),
                    severity,
                    title: format!("{}: {}", cve.id, cve.description),
                    message: format!(
                        "Server '{}' uses {}@{} which is affected by {} (CVSS {:.1})",
                        server_name, package, version, cve.id, cve.cvss
                    ),
                    fix: cve.fix.clone(),
                    config_file: config_file.to_string(),
                    server_name: server_name.to_string(),
                });
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vulnerable_filesystem_server() {
        let rule = CveRule::new();
        let server = McpServer {
            command: Some("npx".to_string()),
            args: Some(vec![
                "-y".to_string(),
                "@modelcontextprotocol/server-filesystem@0.5.0".to_string(),
            ]),
            ..Default::default()
        };
        let findings = rule.check("filesystem", &server, "test.json");
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.title.contains("CVE-2025-53110")));
    }

    #[test]
    fn test_patched_filesystem_server() {
        let rule = CveRule::new();
        let server = McpServer {
            command: Some("npx".to_string()),
            args: Some(vec![
                "-y".to_string(),
                "@modelcontextprotocol/server-filesystem@0.6.3".to_string(),
            ]),
            ..Default::default()
        };
        let findings = rule.check("filesystem", &server, "test.json");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_vulnerable_git_server() {
        let rule = CveRule::new();
        let server = McpServer {
            command: Some("npx".to_string()),
            args: Some(vec![
                "-y".to_string(),
                "@modelcontextprotocol/server-git@0.6.2".to_string(),
            ]),
            ..Default::default()
        };
        let findings = rule.check("git", &server, "test.json");
        assert_eq!(findings.len(), 2); // Two CVEs for git server
    }

    #[test]
    fn test_no_version_no_match() {
        let rule = CveRule::new();
        let server = McpServer {
            command: Some("npx".to_string()),
            args: Some(vec![
                "-y".to_string(),
                "@modelcontextprotocol/server-filesystem".to_string(),
            ]),
            ..Default::default()
        };
        let findings = rule.check("filesystem", &server, "test.json");
        assert!(findings.is_empty());
    }
}
