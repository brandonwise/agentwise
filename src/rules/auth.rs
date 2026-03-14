use crate::config::McpServer;
use crate::rules::{Finding, Rule, Severity};

/// AW-001: Flag MCP servers using remote transport (SSE/HTTP) without authentication.
pub struct AuthRule;

impl Rule for AuthRule {
    fn id(&self) -> &'static str {
        "AW-001"
    }

    fn check(&self, server_name: &str, server: &McpServer, config_file: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        let is_remote = server.url.is_some()
            || matches!(
                server.transport.as_deref(),
                Some("sse") | Some("streamable-http") | Some("http")
            );

        if !is_remote {
            return findings;
        }

        // Check if any auth-related env vars are set
        let has_auth = if let Some(env) = &server.env {
            env.keys().any(|k| {
                let k = k.to_lowercase();
                k.contains("auth")
                    || k.contains("token")
                    || k.contains("api_key")
                    || k.contains("apikey")
                    || k.contains("secret")
                    || k.contains("password")
                    || k.contains("bearer")
            })
        } else {
            false
        };

        if !has_auth {
            findings.push(Finding {
                rule_id: self.id().to_string(),
                severity: Severity::Critical,
                title: "No authentication on remote MCP server".to_string(),
                message: format!(
                    "Server '{}' uses remote transport but has no authentication configured",
                    server_name
                ),
                fix: "Add authentication via env vars (AUTH_TOKEN, API_KEY, etc.)".to_string(),
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
    use std::collections::HashMap;

    #[test]
    fn test_sse_no_auth() {
        let rule = AuthRule;
        let server = McpServer {
            url: Some("http://localhost:3000/mcp".to_string()),
            transport: Some("sse".to_string()),
            ..Default::default()
        };
        let findings = rule.check("test", &server, "test.json");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_sse_with_auth() {
        let rule = AuthRule;
        let mut env = HashMap::new();
        env.insert("AUTH_TOKEN".to_string(), "Bearer secret".to_string());
        let server = McpServer {
            url: Some("https://example.com/mcp".to_string()),
            transport: Some("sse".to_string()),
            env: Some(env),
            ..Default::default()
        };
        let findings = rule.check("test", &server, "test.json");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_stdio_no_auth_ok() {
        let rule = AuthRule;
        let server = McpServer {
            command: Some("npx".to_string()),
            args: Some(vec!["-y".to_string(), "some-server".to_string()]),
            ..Default::default()
        };
        let findings = rule.check("test", &server, "test.json");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_url_without_transport_is_remote() {
        let rule = AuthRule;
        let server = McpServer {
            url: Some("https://example.com/mcp".to_string()),
            ..Default::default()
        };
        let findings = rule.check("test", &server, "test.json");
        assert_eq!(findings.len(), 1);
    }
}
