use crate::config::McpServer;
use crate::rules::{Finding, Rule, Severity};

const WRITE_TOOL_PATTERNS: &[&str] = &[
    "server-postgres",
    "server-mysql",
    "server-sqlite",
    "server-redis",
    "server-mongo",
    "database",
    "db-server",
    "server-github",
    "server-gitlab",
    "server-slack",
    "server-email",
    "server-s3",
    "server-gcs",
    "server-azure-storage",
];

const WRITE_SERVER_NAMES: &[&str] = &[
    "postgres",
    "mysql",
    "sqlite",
    "redis",
    "mongo",
    "database",
    "github",
    "gitlab",
    "slack",
    "email",
    "s3",
];

/// AW-008: Flag tools known to have write capabilities.
pub struct WriteToolsRule;

impl WriteToolsRule {
    fn is_write_capable(server_name: &str, server: &McpServer) -> bool {
        let name_lower = server_name.to_lowercase();
        if WRITE_SERVER_NAMES.iter().any(|p| name_lower.contains(p)) {
            return true;
        }
        if let Some(args) = &server.args {
            let joined = args.join(" ").to_lowercase();
            if WRITE_TOOL_PATTERNS.iter().any(|p| joined.contains(p)) {
                return true;
            }
        }
        false
    }
}

impl Rule for WriteToolsRule {
    fn id(&self) -> &'static str {
        "AW-008"
    }

    fn check(&self, server_name: &str, server: &McpServer, config_file: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        if !Self::is_write_capable(server_name, server) {
            return findings;
        }

        // Only flag if there's no tool restriction
        let has_allowlist = server
            .allowed_tools
            .as_ref()
            .is_some_and(|t| !t.is_empty());

        if !has_allowlist {
            findings.push(Finding {
                rule_id: self.id().to_string(),
                severity: Severity::Medium,
                title: "Write-capable tools without restriction".to_string(),
                message: format!(
                    "Server '{}' has write capabilities (create/update/delete) with no tool filtering",
                    server_name
                ),
                fix: "Add \"allowedTools\" to limit to read-only operations, or explicitly opt into write access".to_string(),
                config_file: config_file.to_string(),
                server_name: server_name.to_string(),
            });
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_database_server_flagged() {
        let rule = WriteToolsRule;
        let server = McpServer {
            command: Some("npx".to_string()),
            args: Some(vec![
                "-y".to_string(),
                "@modelcontextprotocol/server-postgres".to_string(),
            ]),
            ..Default::default()
        };
        let findings = rule.check("database", &server, "test.json");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn test_database_with_allowlist_ok() {
        let rule = WriteToolsRule;
        let server = McpServer {
            command: Some("npx".to_string()),
            args: Some(vec![
                "-y".to_string(),
                "@modelcontextprotocol/server-postgres".to_string(),
            ]),
            allowed_tools: Some(vec!["query".to_string()]),
            ..Default::default()
        };
        let findings = rule.check("database", &server, "test.json");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_non_write_server_ok() {
        let rule = WriteToolsRule;
        let server = McpServer {
            command: Some("npx".to_string()),
            args: Some(vec!["-y".to_string(), "mcp-memory-server".to_string()]),
            ..Default::default()
        };
        let findings = rule.check("memory", &server, "test.json");
        assert!(findings.is_empty());
    }
}
