use crate::config::McpServer;
use crate::rules::{Finding, Rule, Severity};

const SHELL_PATTERNS: &[&str] = &[
    "shell",
    "exec",
    "terminal",
    "bash",
    "cmd",
    "powershell",
    "command-exec",
    "run-command",
    "subprocess",
];

/// AW-003: Flag shell/exec MCP tools with unrestricted command access.
pub struct ShellRule;

impl ShellRule {
    fn is_shell_server(server_name: &str, server: &McpServer) -> bool {
        let name_lower = server_name.to_lowercase();
        if SHELL_PATTERNS.iter().any(|p| name_lower.contains(p)) {
            return true;
        }
        if let Some(args) = &server.args {
            let joined = args.join(" ").to_lowercase();
            if SHELL_PATTERNS.iter().any(|p| joined.contains(p)) {
                return true;
            }
        }
        if let Some(cmd) = &server.command {
            let cmd_lower = cmd.to_lowercase();
            if cmd_lower == "bash" || cmd_lower == "sh" || cmd_lower == "cmd" {
                return true;
            }
        }
        false
    }
}

impl Rule for ShellRule {
    fn id(&self) -> &'static str {
        "AW-003"
    }

    fn check(&self, server_name: &str, server: &McpServer, config_file: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        if !Self::is_shell_server(server_name, server) {
            return findings;
        }

        // Check if there are any restrictions (allowedTools, allowedCommands in env)
        let has_restrictions = server.allowed_tools.as_ref().is_some_and(|t| !t.is_empty())
            || server.env.as_ref().is_some_and(|env| {
                env.keys().any(|k| {
                    let k = k.to_lowercase();
                    k.contains("allowed") || k.contains("whitelist") || k.contains("restrict")
                })
            });

        if !has_restrictions {
            findings.push(Finding {
                rule_id: self.id().to_string(),
                severity: Severity::Critical,
                title: "Unrestricted shell/exec access".to_string(),
                message: format!(
                    "Server '{}' provides shell/exec capabilities with no command restrictions",
                    server_name
                ),
                fix: "Add allowedTools or remove shell access entirely".to_string(),
                config_file: config_file.to_string(),
                server_name: server_name.to_string(),
                source: None,
            });
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shell_server_flagged() {
        let rule = ShellRule;
        let server = McpServer {
            command: Some("npx".to_string()),
            args: Some(vec!["-y".to_string(), "mcp-shell-server".to_string()]),
            ..Default::default()
        };
        let findings = rule.check("shell", &server, "test.json");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_non_shell_server_ok() {
        let rule = ShellRule;
        let server = McpServer {
            command: Some("npx".to_string()),
            args: Some(vec!["-y".to_string(), "mcp-memory-server".to_string()]),
            ..Default::default()
        };
        let findings = rule.check("memory", &server, "test.json");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_shell_with_restrictions() {
        let rule = ShellRule;
        let server = McpServer {
            command: Some("npx".to_string()),
            args: Some(vec!["-y".to_string(), "mcp-shell-server".to_string()]),
            allowed_tools: Some(vec!["ls".to_string(), "cat".to_string()]),
            ..Default::default()
        };
        let findings = rule.check("shell", &server, "test.json");
        assert!(findings.is_empty());
    }
}
