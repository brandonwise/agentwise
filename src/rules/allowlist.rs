use crate::config::McpServer;
use crate::rules::{Finding, Rule, Severity};

/// AW-007: Flag configs with no tool filtering (allowedTools).
pub struct AllowlistRule;

impl Rule for AllowlistRule {
    fn id(&self) -> &'static str {
        "AW-007"
    }

    fn check(&self, server_name: &str, server: &McpServer, config_file: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        let has_allowlist = server
            .allowed_tools
            .as_ref()
            .is_some_and(|t| !t.is_empty());

        if !has_allowlist {
            findings.push(Finding {
                rule_id: self.id().to_string(),
                severity: Severity::Medium,
                title: "No tool allowlist configured".to_string(),
                message: format!(
                    "Server '{}' exposes all available tools with no filtering",
                    server_name
                ),
                fix: "Add \"allowedTools\" to restrict which tools are available".to_string(),
                config_file: config_file.to_string(),
                server_name: server_name.to_string(),
                source: None,
                    epss: None,
                    sub_items: None,
            });
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_allowlist_flagged() {
        let rule = AllowlistRule;
        let server = McpServer {
            command: Some("npx".to_string()),
            ..Default::default()
        };
        let findings = rule.check("test", &server, "test.json");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn test_with_allowlist_ok() {
        let rule = AllowlistRule;
        let server = McpServer {
            command: Some("npx".to_string()),
            allowed_tools: Some(vec!["read_file".to_string(), "list_files".to_string()]),
            ..Default::default()
        };
        let findings = rule.check("test", &server, "test.json");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_empty_allowlist_flagged() {
        let rule = AllowlistRule;
        let server = McpServer {
            command: Some("npx".to_string()),
            allowed_tools: Some(vec![]),
            ..Default::default()
        };
        let findings = rule.check("test", &server, "test.json");
        assert_eq!(findings.len(), 1);
    }
}
