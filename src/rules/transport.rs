use crate::config::McpServer;
use crate::rules::{Finding, Rule, Severity};

/// AW-005: Flag cleartext remote transport endpoints (`http://`, `ws://`).
pub struct TransportRule;

impl TransportRule {
    fn insecure_scheme(value: &str) -> Option<&'static str> {
        let trimmed = value.trim();
        if trimmed.starts_with("http://") {
            Some("http")
        } else if trimmed.starts_with("ws://") {
            Some("ws")
        } else {
            None
        }
    }

    fn make_finding(
        &self,
        server_name: &str,
        config_file: &str,
        value: &str,
        from_args: bool,
    ) -> Option<Finding> {
        let scheme = Self::insecure_scheme(value)?;
        if is_localhost(value) {
            return None;
        }

        let (title, message) = if from_args {
            (
                "Insecure cleartext URL in args".to_string(),
                format!(
                    "Server '{}' has insecure {} endpoint in args: {}",
                    server_name,
                    scheme.to_uppercase(),
                    value
                ),
            )
        } else {
            (
                "Insecure cleartext transport".to_string(),
                format!(
                    "Server '{}' uses unencrypted {} transport: {}",
                    server_name,
                    scheme.to_uppercase(),
                    value
                ),
            )
        };

        Some(Finding {
            rule_id: self.id().to_string(),
            severity: Severity::High,
            title,
            message,
            fix: "Change endpoint to TLS transport (https:// or wss://)".to_string(),
            config_file: config_file.to_string(),
            server_name: server_name.to_string(),
            source: None,
            epss: None,
            sub_items: None,
        })
    }
}

impl Rule for TransportRule {
    fn id(&self) -> &'static str {
        "AW-005"
    }

    fn check(&self, server_name: &str, server: &McpServer, config_file: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(url) = &server.url {
            if let Some(finding) = self.make_finding(server_name, config_file, url, false) {
                findings.push(finding);
            }
        }

        if let Some(args) = &server.args {
            for arg in args {
                if let Some(finding) = self.make_finding(server_name, config_file, arg, true) {
                    findings.push(finding);
                }
            }
        }

        findings
    }
}

fn is_localhost(url: &str) -> bool {
    let url_lower = url.to_lowercase();
    url_lower.contains("://localhost")
        || url_lower.contains("://127.0.0.1")
        || url_lower.contains("://[::1]")
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
    fn test_ws_url_flagged() {
        let rule = TransportRule;
        let server = McpServer {
            url: Some("ws://api.example.com:8080/mcp".to_string()),
            ..Default::default()
        };
        let findings = rule.check("remote", &server, "test.json");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("WS"));
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
    fn test_wss_url_ok() {
        let rule = TransportRule;
        let server = McpServer {
            url: Some("wss://api.example.com/mcp".to_string()),
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
    fn test_localhost_ws_ok() {
        let rule = TransportRule;
        let server = McpServer {
            url: Some("ws://127.0.0.1:3000/mcp".to_string()),
            ..Default::default()
        };
        let findings = rule.check("local", &server, "test.json");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_ws_arg_flagged() {
        let rule = TransportRule;
        let server = McpServer {
            args: Some(vec![
                "--endpoint".to_string(),
                "ws://api.example.com:8080/mcp".to_string(),
            ]),
            ..Default::default()
        };
        let findings = rule.check("remote", &server, "test.json");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "Insecure cleartext URL in args");
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
