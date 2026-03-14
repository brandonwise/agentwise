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

/// AW-009: Flag fetch/HTTP tools with unrestricted network access.
pub struct NetworkRule;

impl NetworkRule {
    fn is_network_tool(server_name: &str, server: &McpServer) -> bool {
        let name_lower = server_name.to_lowercase();
        if NETWORK_PATTERNS.iter().any(|p| name_lower.contains(p)) {
            return true;
        }
        if let Some(args) = &server.args {
            let joined = args.join(" ").to_lowercase();
            if NETWORK_PATTERNS.iter().any(|p| joined.contains(p)) {
                return true;
            }
        }
        false
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

        // Check if there are domain restrictions in env or args
        let has_restrictions = server.env.as_ref().is_some_and(|env| {
            env.keys().any(|k| {
                let k = k.to_lowercase();
                k.contains("allowed_domains")
                    || k.contains("domain_whitelist")
                    || k.contains("allowed_urls")
                    || k.contains("restrict")
            })
        }) || server.allowed_tools.as_ref().is_some_and(|t| !t.is_empty());

        if !has_restrictions {
            findings.push(Finding {
                rule_id: self.id().to_string(),
                severity: Severity::Medium,
                title: "Unrestricted network access".to_string(),
                message: format!(
                    "Server '{}' can make HTTP requests to any domain with no restrictions",
                    server_name
                ),
                fix: "Add domain restrictions or use allowedTools to limit network operations"
                    .to_string(),
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
    fn test_fetch_with_tool_restrictions_ok() {
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
        assert!(findings.is_empty());
    }
}
