use crate::config::{
    has_effective_allowed_tools, has_global_wildcard_allowed_tools,
    has_pattern_wildcard_allowed_tools, McpServer,
};
use crate::rules::{Finding, Rule, Severity};

/// AW-007: Flag configs with no tool filtering (allowedTools).
pub struct AllowlistRule;

impl AllowlistRule {
    fn is_high_risk(server_name: &str, server: &McpServer) -> bool {
        if server.url.is_some() {
            return true;
        }

        let mut text = server_name.to_lowercase();
        if let Some(command) = &server.command {
            text.push(' ');
            text.push_str(&command.to_lowercase());
        }
        if let Some(args) = &server.args {
            text.push(' ');
            text.push_str(&args.join(" ").to_lowercase());
        }

        let high_risk_keywords = [
            "shell",
            "exec",
            "bash",
            "powershell",
            "cmd",
            "terminal",
            "filesystem",
            "file",
            "write",
            "delete",
            "modify",
            "fetch",
            "http",
            "browser",
            "playwright",
            "docker",
            "sql",
            "postgres",
            "mysql",
        ];

        high_risk_keywords.iter().any(|k| text.contains(k))
    }
}

impl Rule for AllowlistRule {
    fn id(&self) -> &'static str {
        "AW-007"
    }

    fn check(&self, server_name: &str, server: &McpServer, config_file: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        let has_allowlist = has_effective_allowed_tools(server);
        let has_global_wildcard_allowlist = has_global_wildcard_allowed_tools(server);
        let has_pattern_wildcard_allowlist = has_pattern_wildcard_allowed_tools(server);

        if !has_allowlist {
            let high_risk = Self::is_high_risk(server_name, server);
            let severity = if high_risk {
                Severity::High
            } else {
                Severity::Medium
            };

            let title = if has_global_wildcard_allowlist {
                if high_risk {
                    "Wildcard tool allowlist on high-risk server"
                } else {
                    "Wildcard tool allowlist is effectively unrestricted"
                }
            } else if has_pattern_wildcard_allowlist {
                if high_risk {
                    "Wildcard-pattern tool allowlist on high-risk server"
                } else {
                    "Wildcard-pattern tool allowlist is too broad"
                }
            } else if high_risk {
                "No tool allowlist on high-risk server"
            } else {
                "No tool allowlist configured"
            };

            let message = if has_global_wildcard_allowlist {
                format!(
                    "Server '{}' uses a global wildcard in allowedTools, which effectively exposes all tools",
                    server_name
                )
            } else if has_pattern_wildcard_allowlist {
                format!(
                    "Server '{}' uses wildcard patterns in allowedTools, which can expose more tools than intended",
                    server_name
                )
            } else {
                format!(
                    "Server '{}' exposes all available tools with no filtering",
                    server_name
                )
            };

            let fix = if has_global_wildcard_allowlist {
                "Replace wildcard entries in \"allowedTools\" with explicit least-privilege tool names"
                    .to_string()
            } else if has_pattern_wildcard_allowlist {
                "Replace wildcard patterns in \"allowedTools\" with explicit least-privilege tool names"
                    .to_string()
            } else {
                "Add \"allowedTools\" to restrict exposed tools to least privilege".to_string()
            };

            findings.push(Finding {
                rule_id: self.id().to_string(),
                severity,
                title: title.to_string(),
                message,
                fix,
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
    fn test_no_allowlist_on_high_risk_server_is_high() {
        let rule = AllowlistRule;
        let server = McpServer {
            command: Some("npx".to_string()),
            args: Some(vec![
                "-y".to_string(),
                "@modelcontextprotocol/server-fetch".to_string(),
            ]),
            ..Default::default()
        };
        let findings = rule.check("fetch", &server, "test.json");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
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

    #[test]
    fn test_wildcard_allowlist_flagged() {
        let rule = AllowlistRule;
        let server = McpServer {
            command: Some("npx".to_string()),
            allowed_tools: Some(vec!["*".to_string()]),
            ..Default::default()
        };

        let findings = rule.check("test", &server, "test.json");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("Wildcard"));
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn test_wildcard_allowlist_on_high_risk_server_is_high() {
        let rule = AllowlistRule;
        let server = McpServer {
            command: Some("npx".to_string()),
            args: Some(vec![
                "-y".to_string(),
                "@modelcontextprotocol/server-fetch".to_string(),
            ]),
            allowed_tools: Some(vec!["all".to_string()]),
            ..Default::default()
        };

        let findings = rule.check("fetch", &server, "test.json");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn test_pattern_wildcard_allowlist_flagged() {
        let rule = AllowlistRule;
        let server = McpServer {
            command: Some("npx".to_string()),
            allowed_tools: Some(vec!["github:*".to_string()]),
            ..Default::default()
        };

        let findings = rule.check("github", &server, "test.json");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("Wildcard-pattern"));
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn test_pattern_wildcard_allowlist_on_high_risk_server_is_high() {
        let rule = AllowlistRule;
        let server = McpServer {
            command: Some("npx".to_string()),
            args: Some(vec![
                "-y".to_string(),
                "@modelcontextprotocol/server-fetch".to_string(),
            ]),
            allowed_tools: Some(vec!["mcp__fetch__*".to_string()]),
            ..Default::default()
        };

        let findings = rule.check("fetch", &server, "test.json");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }
}
