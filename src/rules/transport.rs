use crate::config::McpServer;
use crate::rules::{Finding, Rule, Severity};

/// AW-005: Flag http:// URLs (insecure transport) for remote MCP servers.
pub struct TransportRule;

impl Rule for TransportRule {
    fn id(&self) -> &'static str {
        "AW-005"
    }

    fn check(&self, server_name: &str, server: &McpServer, config_file: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(url) = &server.url {
            if url.starts_with("http://") && !is_localhost(url) {
                findings.push(Finding {
                    rule_id: self.id().to_string(),
                    severity: Severity::High,
                    title: "Insecure HTTP transport".to_string(),
                    message: format!(
                        "Server '{}' uses unencrypted HTTP: {}",
                        server_name, url
                    ),
                    fix: "Change URL to use https://".to_string(),
                    config_file: config_file.to_string(),
                    server_name: server_name.to_string(),
                });
            }
        }

        // Also check args for HTTP URLs
        if let Some(args) = &server.args {
            for arg in args {
                if arg.starts_with("http://") && !is_localhost(arg) {
                    findings.push(Finding {
                        rule_id: self.id().to_string(),
                        severity: Severity::High,
                        title: "Insecure HTTP URL in args".to_string(),
                        message: format!(
                            "Server '{}' has insecure HTTP URL in args: {}",
                            server_name, arg
                        ),
                        fix: "Change URL to use https://".to_string(),
                        config_file: config_file.to_string(),
                        server_name: server_name.to_string(),
                    });
                }
            }
        }

        findings
    }
}

fn is_localhost(url: &str) -> bool {
    let url_lower = url.to_lowercase();
    url_lower.contains("://localhost") || url_lower.contains("://127.0.0.1")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_url_flagged() {
        let rule = TransportRule;
        let server = McpServer {
            url: Some("http://api.example.com:8080/mcp".to_string()),
            ..Default::default()
        };
        let findings = rule.check("remote", &server, "test.json");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn test_https_url_ok() {
        let rule = TransportRule;
        let server = McpServer {
            url: Some("https://api.example.com/mcp".to_string()),
            ..Default::default()
        };
        let findings = rule.check("remote", &server, "test.json");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_localhost_http_ok() {
        let rule = TransportRule;
        let server = McpServer {
            url: Some("http://localhost:3000/mcp".to_string()),
            ..Default::default()
        };
        let findings = rule.check("local", &server, "test.json");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_url_ok() {
        let rule = TransportRule;
        let server = McpServer {
            command: Some("npx".to_string()),
            ..Default::default()
        };
        let findings = rule.check("local", &server, "test.json");
        assert!(findings.is_empty());
    }
}
