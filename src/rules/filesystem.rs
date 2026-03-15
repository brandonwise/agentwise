use crate::config::McpServer;
use crate::rules::{Finding, Rule, Severity};

const FS_PATTERNS: &[&str] = &[
    "filesystem",
    "server-filesystem",
    "fs-server",
    "file-server",
];

const DANGEROUS_PATHS: &[&str] = &[
    "/",
    "C:\\",
    "C:/",
    "/home",
    "/Users",
    "/etc",
    "/var",
    "/root",
];

/// AW-002: Flag filesystem MCP servers with no allowedDirectories or serving overly broad paths.
pub struct FilesystemRule;

impl FilesystemRule {
    fn is_filesystem_server(server_name: &str, server: &McpServer) -> bool {
        let name_lower = server_name.to_lowercase();
        if FS_PATTERNS.iter().any(|p| name_lower.contains(p)) {
            return true;
        }
        if let Some(args) = &server.args {
            let joined = args.join(" ").to_lowercase();
            if FS_PATTERNS.iter().any(|p| joined.contains(p)) {
                return true;
            }
        }
        false
    }
}

impl Rule for FilesystemRule {
    fn id(&self) -> &'static str {
        "AW-002"
    }

    fn check(&self, server_name: &str, server: &McpServer, config_file: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        if !Self::is_filesystem_server(server_name, server) {
            return findings;
        }

        // Check for allowedDirectories
        let has_allowed_dirs = server
            .allowed_directories
            .as_ref()
            .is_some_and(|dirs| !dirs.is_empty());

        if !has_allowed_dirs {
            // Check if args include broad paths
            let serves_root = server.args.as_ref().is_some_and(|args| {
                args.iter().any(|a| {
                    let trimmed = a.trim_end_matches('/');
                    DANGEROUS_PATHS.iter().any(|p| {
                        a == *p || trimmed == p.trim_end_matches('/')
                    })
                })
            });

            if serves_root {
                findings.push(Finding {
                    rule_id: self.id().to_string(),
                    severity: Severity::Critical,
                    title: "Filesystem server with dangerous root access".to_string(),
                    message: format!(
                        "Server '{}' exposes a broad filesystem path with no allowedDirectories restriction",
                        server_name
                    ),
                    fix: "Add \"allowedDirectories\" to restrict access to specific project directories".to_string(),
                    config_file: config_file.to_string(),
                    server_name: server_name.to_string(),
                    source: None,
                });
            } else {
                findings.push(Finding {
                    rule_id: self.id().to_string(),
                    severity: Severity::High,
                    title: "Filesystem server without allowedDirectories".to_string(),
                    message: format!(
                        "Server '{}' has no allowedDirectories restriction configured",
                        server_name
                    ),
                    fix: "Add \"allowedDirectories\" to restrict filesystem access scope".to_string(),
                    config_file: config_file.to_string(),
                    server_name: server_name.to_string(),
                    source: None,
                });
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filesystem_serving_root() {
        let rule = FilesystemRule;
        let server = McpServer {
            command: Some("npx".to_string()),
            args: Some(vec![
                "-y".to_string(),
                "@modelcontextprotocol/server-filesystem@0.5.0".to_string(),
                "/".to_string(),
            ]),
            ..Default::default()
        };
        let findings = rule.check("filesystem", &server, "test.json");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_filesystem_with_allowed_dirs() {
        let rule = FilesystemRule;
        let server = McpServer {
            command: Some("npx".to_string()),
            args: Some(vec![
                "-y".to_string(),
                "@modelcontextprotocol/server-filesystem@0.6.3".to_string(),
                "/Users/me/project".to_string(),
            ]),
            allowed_directories: Some(vec!["/Users/me/project".to_string()]),
            ..Default::default()
        };
        let findings = rule.check("filesystem", &server, "test.json");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_non_filesystem_server_ignored() {
        let rule = FilesystemRule;
        let server = McpServer {
            command: Some("npx".to_string()),
            args: Some(vec!["-y".to_string(), "some-other-server".to_string()]),
            ..Default::default()
        };
        let findings = rule.check("database", &server, "test.json");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_filesystem_no_dirs_no_root() {
        let rule = FilesystemRule;
        let server = McpServer {
            command: Some("npx".to_string()),
            args: Some(vec![
                "-y".to_string(),
                "@modelcontextprotocol/server-filesystem@0.5.0".to_string(),
                "/Users/me/docs".to_string(),
            ]),
            ..Default::default()
        };
        let findings = rule.check("filesystem", &server, "test.json");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }
}
