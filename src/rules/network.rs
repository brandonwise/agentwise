use crate::config::McpServer;
use crate::rules::{Finding, Rule, Severity};

const NETWORK_PATTERNS: &[&str] = &[
    "fetch",
    "server-fetch",
    "http-client",
    "web-request",
    "curl",
    "puppeteer",
    "browser",
    "playwright",
    "scraper",
    "crawl",
];

const DOMAIN_RESTRICTION_HINTS: &[&str] = &[
    "allowed_domains",
    "domain_whitelist",
    "allowed_urls",
    "allowed_hosts",
    "allowlist",
    "restrict",
    "origins",
    "localhost_only",
];

/// AW-009: Flag fetch/HTTP tools with unrestricted network access.
pub struct NetworkRule;

impl NetworkRule {
    fn is_network_tool(server_name: &str, server: &McpServer) -> bool {
        let name_lower = server_name.to_lowercase();
        if NETWORK_PATTERNS.iter().any(|p| name_lower.contains(p)) {
            return true;
        }

        if let Some(command) = &server.command {
            let lower = command.to_lowercase();
            if NETWORK_PATTERNS.iter().any(|p| lower.contains(p)) {
                return true;
            }
        }

        if let Some(args) = &server.args {
            let joined = args.join(" ").to_lowercase();
            if NETWORK_PATTERNS.iter().any(|p| joined.contains(p)) {
                return true;
            }
        }

        false
    }

    fn has_domain_restrictions(server: &McpServer) -> bool {
        let env_restricted = server.env.as_ref().is_some_and(|env| {
            env.iter().any(|(k, v)| {
                let key = k.to_lowercase();
                DOMAIN_RESTRICTION_HINTS.iter().any(|h| key.contains(h))
                    && Self::has_specific_targets(v)
            })
        });

        let args_restricted = server.args.as_ref().is_some_and(|args| {
            for (idx, arg) in args.iter().enumerate() {
                let lowered = arg.to_lowercase();
                let hint_match = DOMAIN_RESTRICTION_HINTS.iter().any(|h| lowered.contains(h))
                    || lowered.contains("--allow-domain")
                    || lowered.contains("--allowed-domain")
                    || lowered.contains("--allowed-host")
                    || lowered.contains("--allowed-origin")
                    || lowered.contains("--deny-domain");

                if !hint_match {
                    continue;
                }

                if let Some((_, rhs)) = arg.split_once('=') {
                    if Self::has_specific_targets(rhs) {
                        return true;
                    }
                    continue;
                }

                if let Some(next) = args.get(idx + 1) {
                    if !next.starts_with('-') && Self::has_specific_targets(next) {
                        return true;
                    }
                }

                if !arg.starts_with('-') && Self::has_specific_targets(arg) {
                    return true;
                }
            }
            false
        });

        env_restricted || args_restricted
    }

    fn has_specific_targets(value: &str) -> bool {
        value
            .split([',', ';'])
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .any(|target| !Self::is_wildcard_target(target))
    }

    fn is_wildcard_target(value: &str) -> bool {
        let lower = value.trim().to_lowercase();
        lower == "*"
            || lower == "all"
            || lower == "any"
            || lower == "0.0.0.0/0"
            || lower == "::/0"
            || lower == "0.0.0.0"
            || lower.contains('*')
    }
}

impl Rule for NetworkRule {
    fn id(&self) -> &'static str {
        "AW-009"
    }

    fn check(&self, server_name: &str, server: &McpServer, config_file: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        if !Self::is_network_tool(server_name, server) {
            return findings;
        }

        if !Self::has_domain_restrictions(server) {
            findings.push(Finding {
                rule_id: self.id().to_string(),
                severity: Severity::Medium,
                title: "Unrestricted network access".to_string(),
                message: format!(
                    "Server '{}' appears to make outbound HTTP requests with no domain restrictions",
                    server_name
                ),
                fix: "Add explicit allowlist/denylist for domains or hosts in server config"
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
    fn test_fetch_server_flagged() {
        let rule = NetworkRule;
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
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn test_non_network_server_ok() {
        let rule = NetworkRule;
        let server = McpServer {
            command: Some("npx".to_string()),
            args: Some(vec!["-y".to_string(), "mcp-memory-server".to_string()]),
            ..Default::default()
        };
        let findings = rule.check("memory", &server, "test.json");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_fetch_with_allowed_tools_still_flagged() {
        let rule = NetworkRule;
        let server = McpServer {
            command: Some("npx".to_string()),
            args: Some(vec![
                "-y".to_string(),
                "@modelcontextprotocol/server-fetch".to_string(),
            ]),
            allowed_tools: Some(vec!["fetch_html".to_string()]),
            ..Default::default()
        };
        let findings = rule.check("fetch", &server, "test.json");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_fetch_with_env_domain_restrictions_ok() {
        let rule = NetworkRule;
        let mut env = HashMap::new();
        env.insert("ALLOWED_DOMAINS".to_string(), "example.com".to_string());
        let server = McpServer {
            command: Some("npx".to_string()),
            args: Some(vec![
                "-y".to_string(),
                "@modelcontextprotocol/server-fetch".to_string(),
            ]),
            env: Some(env),
            ..Default::default()
        };
        let findings = rule.check("fetch", &server, "test.json");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_fetch_with_arg_domain_restrictions_ok() {
        let rule = NetworkRule;
        let server = McpServer {
            command: Some("npx".to_string()),
            args: Some(vec![
                "-y".to_string(),
                "@modelcontextprotocol/server-fetch".to_string(),
                "--allowed-domain".to_string(),
                "example.com".to_string(),
            ]),
            ..Default::default()
        };
        let findings = rule.check("fetch", &server, "test.json");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_fetch_with_arg_inline_domain_restrictions_ok() {
        let rule = NetworkRule;
        let server = McpServer {
            command: Some("npx".to_string()),
            args: Some(vec![
                "-y".to_string(),
                "@modelcontextprotocol/server-fetch".to_string(),
                "--allowed-domain=example.com".to_string(),
            ]),
            ..Default::default()
        };
        let findings = rule.check("fetch", &server, "test.json");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_fetch_with_env_wildcard_still_flagged() {
        let rule = NetworkRule;
        let mut env = HashMap::new();
        env.insert("ALLOWED_DOMAINS".to_string(), "*".to_string());
        let server = McpServer {
            command: Some("npx".to_string()),
            args: Some(vec![
                "-y".to_string(),
                "@modelcontextprotocol/server-fetch".to_string(),
            ]),
            env: Some(env),
            ..Default::default()
        };
        let findings = rule.check("fetch", &server, "test.json");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_fetch_with_arg_wildcard_still_flagged() {
        let rule = NetworkRule;
        let server = McpServer {
            command: Some("npx".to_string()),
            args: Some(vec![
                "-y".to_string(),
                "@modelcontextprotocol/server-fetch".to_string(),
                "--allowed-domain".to_string(),
                "*".to_string(),
            ]),
            ..Default::default()
        };
        let findings = rule.check("fetch", &server, "test.json");
        assert_eq!(findings.len(), 1);
    }
}
