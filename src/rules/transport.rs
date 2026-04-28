use crate::config::McpServer;
use crate::rules::{Finding, Rule, Severity};
use std::collections::HashMap;

const BIND_FLAGS: &[&str] = &[
    "--host",
    "--bind",
    "--listen",
    "--address",
    "--addr",
    "--hostname",
];

const BIND_ENV_KEYS: &[&str] = &[
    "host",
    "bind",
    "bind_host",
    "bind_address",
    "listen_host",
    "listen_addr",
    "listen_address",
    "mcp_host",
    "server_host",
];

/// AW-005: Flag cleartext remote transport endpoints (`http://`, `ws://`) and
/// wildcard bind addresses that expose local MCP services beyond loopback.
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

pub(crate) fn has_wildcard_bind_exposure(server: &McpServer) -> Option<String> {
    server
        .args
        .as_ref()
        .and_then(|args| wildcard_bind_from_args(args))
        .or_else(|| server.env.as_ref().and_then(wildcard_bind_from_env))
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

        if let Some(bind_hint) = has_wildcard_bind_exposure(server) {
            findings.push(Finding {
                rule_id: self.id().to_string(),
                severity: Severity::High,
                title: "Wildcard bind address".to_string(),
                message: format!(
                    "Server '{}' binds a local MCP service to all interfaces via {}, which can expose it beyond loopback",
                    server_name, bind_hint
                ),
                fix: "Bind the server to 127.0.0.1 or ::1 unless remote exposure is intentional and protected by auth + TLS".to_string(),
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

fn wildcard_bind_from_args(args: &[String]) -> Option<String> {
    for (idx, arg) in args.iter().enumerate() {
        let lowered = arg.to_lowercase();

        for flag in BIND_FLAGS {
            if lowered == *flag {
                if let Some(next) = args.get(idx + 1) {
                    if is_wildcard_bind_value(next) {
                        return Some(format!("{} {}", arg, next));
                    }
                }
            }

            let inline_prefix = format!("{}=", flag);
            if lowered.starts_with(&inline_prefix) {
                let value = &arg[inline_prefix.len()..];
                if is_wildcard_bind_value(value) {
                    return Some(arg.clone());
                }
            }
        }
    }

    None
}

fn wildcard_bind_from_env(env: &HashMap<String, String>) -> Option<String> {
    for (key, value) in env {
        let lowered = key.to_lowercase();
        if BIND_ENV_KEYS.contains(&lowered.as_str()) && is_wildcard_bind_value(value) {
            return Some(format!("{}={}", key, value));
        }
    }

    None
}

fn is_wildcard_bind_value(value: &str) -> bool {
    let trimmed = value
        .trim()
        .trim_matches(|c| c == '"' || c == '\'')
        .to_lowercase();

    if trimmed == "*" {
        return true;
    }

    let host = trimmed
        .split("://")
        .nth(1)
        .unwrap_or(trimmed.as_str())
        .trim();

    host == "0.0.0.0"
        || host.starts_with("0.0.0.0:")
        || host == "::"
        || host == "[::]"
        || host.starts_with("[::]:")
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
    use std::collections::HashMap;

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
    fn test_wildcard_bind_arg_flagged() {
        let rule = TransportRule;
        let server = McpServer {
            args: Some(vec![
                "server.py".to_string(),
                "--host".to_string(),
                "0.0.0.0".to_string(),
            ]),
            ..Default::default()
        };
        let findings = rule.check("remote", &server, "test.json");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "Wildcard bind address");
        assert!(findings[0].message.contains("0.0.0.0"));
    }

    #[test]
    fn test_wildcard_bind_inline_arg_flagged() {
        let rule = TransportRule;
        let server = McpServer {
            args: Some(vec!["--bind=0.0.0.0:3000".to_string()]),
            ..Default::default()
        };
        let findings = rule.check("remote", &server, "test.json");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn test_wildcard_bind_env_flagged() {
        let rule = TransportRule;
        let mut env = HashMap::new();
        env.insert("HOST".to_string(), "0.0.0.0".to_string());
        let server = McpServer {
            env: Some(env),
            ..Default::default()
        };
        let findings = rule.check("remote", &server, "test.json");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("HOST=0.0.0.0"));
    }

    #[test]
    fn test_loopback_bind_ok() {
        let rule = TransportRule;
        let server = McpServer {
            args: Some(vec!["--host".to_string(), "127.0.0.1:3000".to_string()]),
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
