use crate::config::McpServer;
use crate::rules::{Finding, Rule, Severity};

/// AW-001: Flag MCP servers using remote transport (SSE/HTTP) without authentication.
pub struct AuthRule;

impl AuthRule {
    fn is_remote(server: &McpServer) -> bool {
        server.url.is_some()
            || matches!(
                server.transport.as_deref(),
                Some("sse") | Some("streamable-http") | Some("http")
            )
    }

    fn has_auth_env(server: &McpServer) -> bool {
        server.env.as_ref().is_some_and(|env| {
            env.iter().any(|(k, v)| {
                let key = k.to_lowercase();
                let value = v.trim();
                value.len() > 2
                    && (key.contains("authorization")
                        || key.contains("auth")
                        || key.contains("token")
                        || key.contains("api_key")
                        || key.contains("apikey")
                        || key.contains("secret")
                        || key.contains("bearer")
                        || key.contains("password"))
            })
        })
    }

    fn has_auth_headers(server: &McpServer) -> bool {
        server.headers.as_ref().is_some_and(|headers| {
            headers.keys().any(|k| {
                let key = k.to_lowercase();
                key.contains("authorization")
                    || key == "x-api-key"
                    || key == "api-key"
                    || key.contains("bearer")
                    || key.contains("cookie")
            })
        }) || server.env_http_headers.as_ref().is_some_and(|headers| {
            headers.keys().any(|k| {
                let key = k.to_lowercase();
                key.contains("authorization")
                    || key == "x-api-key"
                    || key == "api-key"
                    || key.contains("bearer")
                    || key.contains("cookie")
            })
        })
    }

    fn has_auth_args(server: &McpServer) -> bool {
        server.args.as_ref().is_some_and(|args| {
            let joined = args.join(" ").to_lowercase();
            joined.contains("--bearer")
                || joined.contains("--token")
                || joined.contains("--api-key")
                || joined.contains("authorization:")
                || joined.contains("x-api-key:")
        })
    }

    fn has_auth_references(server: &McpServer) -> bool {
        server
            .bearer_token_env_var
            .as_ref()
            .is_some_and(|value| !value.trim().is_empty())
            || server.env_vars.as_ref().is_some_and(|vars| {
                vars.iter().any(|value| {
                    let lowered = value.to_lowercase();
                    lowered.contains("authorization")
                        || lowered.contains("auth")
                        || lowered.contains("token")
                        || lowered.contains("api_key")
                        || lowered.contains("apikey")
                        || lowered.contains("secret")
                        || lowered.contains("bearer")
                        || lowered.contains("password")
                })
            })
    }
}

impl Rule for AuthRule {
    fn id(&self) -> &'static str {
        "AW-001"
    }

    fn check(&self, server_name: &str, server: &McpServer, config_file: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        if !Self::is_remote(server) {
            return findings;
        }

        let has_auth = Self::has_auth_env(server)
            || Self::has_auth_headers(server)
            || Self::has_auth_args(server)
            || Self::has_auth_references(server);

        if !has_auth {
            findings.push(Finding {
                rule_id: self.id().to_string(),
                severity: Severity::Critical,
                title: "No authentication on remote MCP server".to_string(),
                message: format!(
                    "Server '{}' uses remote transport but no auth token/header was detected",
                    server_name
                ),
                fix: "Configure authentication (Authorization header, bearer token, or API key env var)"
                    .to_string(),
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
    fn test_sse_with_auth_env() {
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
    fn test_sse_with_auth_header() {
        let rule = AuthRule;
        let mut headers = HashMap::new();
        headers.insert("Authorization".to_string(), "Bearer abc".to_string());
        let server = McpServer {
            url: Some("https://example.com/mcp".to_string()),
            transport: Some("sse".to_string()),
            headers: Some(headers),
            ..Default::default()
        };
        let findings = rule.check("test", &server, "test.json");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_sse_with_auth_args() {
        let rule = AuthRule;
        let server = McpServer {
            url: Some("https://example.com/mcp".to_string()),
            transport: Some("streamable-http".to_string()),
            args: Some(vec![
                "--header".to_string(),
                "Authorization: Bearer test".to_string(),
            ]),
            ..Default::default()
        };
        let findings = rule.check("test", &server, "test.json");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_empty_auth_value_does_not_count() {
        let rule = AuthRule;
        let mut env = HashMap::new();
        env.insert("AUTH_TOKEN".to_string(), "".to_string());
        let server = McpServer {
            url: Some("https://example.com/mcp".to_string()),
            transport: Some("sse".to_string()),
            env: Some(env),
            ..Default::default()
        };
        let findings = rule.check("test", &server, "test.json");
        assert_eq!(findings.len(), 1);
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

    #[test]
    fn test_remote_server_with_bearer_token_env_var_is_ok() {
        let rule = AuthRule;
        let server = McpServer {
            url: Some("https://example.com/mcp".to_string()),
            bearer_token_env_var: Some("FIGMA_OAUTH_TOKEN".to_string()),
            ..Default::default()
        };
        let findings = rule.check("figma", &server, "config.toml");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_remote_server_with_env_http_headers_is_ok() {
        let rule = AuthRule;
        let server = McpServer {
            url: Some("https://example.com/mcp".to_string()),
            env_http_headers: Some(HashMap::from([(
                "Authorization".to_string(),
                "FIGMA_OAUTH_TOKEN".to_string(),
            )])),
            ..Default::default()
        };
        let findings = rule.check("figma", &server, "config.toml");
        assert!(findings.is_empty());
    }
}
