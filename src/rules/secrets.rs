use crate::config::McpServer;
use crate::rules::{Finding, Rule, Severity};
use regex::Regex;

/// Secret patterns to detect.
struct SecretPattern {
    name: &'static str,
    regex: Regex,
}

/// AW-004: Detect API keys, tokens, and passwords in env vars and args.
pub struct SecretsRule {
    patterns: Vec<SecretPattern>,
}

impl SecretsRule {
    pub fn new() -> Self {
        let patterns = vec![
            SecretPattern {
                name: "OpenAI API key",
                regex: Regex::new(r"sk-[a-zA-Z0-9_-]{20,}").unwrap(),
            },
            SecretPattern {
                name: "GitHub personal access token",
                regex: Regex::new(r"ghp_[a-zA-Z0-9]{36,}").unwrap(),
            },
            SecretPattern {
                name: "GitHub OAuth token",
                regex: Regex::new(r"gho_[a-zA-Z0-9]{36,}").unwrap(),
            },
            SecretPattern {
                name: "AWS access key",
                regex: Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
            },
            SecretPattern {
                name: "Slack token",
                regex: Regex::new(r"xox[bpors]-[a-zA-Z0-9-]{10,}").unwrap(),
            },
            SecretPattern {
                name: "Anthropic API key",
                regex: Regex::new(r"sk-ant-[a-zA-Z0-9_-]{20,}").unwrap(),
            },
            SecretPattern {
                name: "Generic password in connection string",
                regex: Regex::new(r"://[^:]+:([^@\s]{8,})@").unwrap(),
            },
            SecretPattern {
                name: "Stripe API key",
                regex: Regex::new(r"sk_live_[a-zA-Z0-9]{20,}").unwrap(),
            },
            SecretPattern {
                name: "Stripe test key",
                regex: Regex::new(r"sk_test_[a-zA-Z0-9]{20,}").unwrap(),
            },
            SecretPattern {
                name: "Google API key",
                regex: Regex::new(r"AIza[0-9A-Za-z_-]{35}").unwrap(),
            },
        ];
        Self { patterns }
    }

    fn check_value(&self, value: &str) -> Option<&str> {
        for pattern in &self.patterns {
            if pattern.regex.is_match(value) {
                return Some(pattern.name);
            }
        }
        None
    }

    fn mask_secret(value: &str) -> String {
        if value.len() <= 8 {
            "*".repeat(value.len())
        } else {
            format!("{}...{}", &value[..4], &value[value.len() - 4..])
        }
    }
}

impl Rule for SecretsRule {
    fn id(&self) -> &'static str {
        "AW-004"
    }

    fn check(&self, server_name: &str, server: &McpServer, config_file: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check env vars
        if let Some(env) = &server.env {
            for (key, value) in env {
                if let Some(secret_type) = self.check_value(value) {
                    findings.push(Finding {
                        rule_id: self.id().to_string(),
                        severity: Severity::High,
                        title: format!("{} in env var", secret_type),
                        message: format!(
                            "Server '{}' has {} exposed in env var '{}' = {}",
                            server_name,
                            secret_type,
                            key,
                            Self::mask_secret(value)
                        ),
                        fix: "Use environment variable references instead of hardcoded secrets"
                            .to_string(),
                        config_file: config_file.to_string(),
                        server_name: server_name.to_string(),
                        source: None,
                        epss: None,
                        sub_items: None,
                    });
                }
            }
        }

        // Check args
        if let Some(args) = &server.args {
            for arg in args {
                if let Some(secret_type) = self.check_value(arg) {
                    findings.push(Finding {
                        rule_id: self.id().to_string(),
                        severity: Severity::High,
                        title: format!("{} in args", secret_type),
                        message: format!(
                            "Server '{}' has {} exposed in command args: {}",
                            server_name,
                            secret_type,
                            Self::mask_secret(arg)
                        ),
                        fix: "Use environment variable references instead of hardcoded secrets"
                            .to_string(),
                        config_file: config_file.to_string(),
                        server_name: server_name.to_string(),
                        source: None,
                        epss: None,
                        sub_items: None,
                    });
                }
            }
        }

        // Check URL for embedded credentials
        if let Some(url) = &server.url {
            if let Some(secret_type) = self.check_value(url) {
                findings.push(Finding {
                    rule_id: self.id().to_string(),
                    severity: Severity::High,
                    title: format!("{} in URL", secret_type),
                    message: format!(
                        "Server '{}' has {} exposed in URL: {}",
                        server_name,
                        secret_type,
                        Self::mask_secret(url)
                    ),
                    fix: "Use environment variable references for credentials in URLs".to_string(),
                    config_file: config_file.to_string(),
                    server_name: server_name.to_string(),
                    source: None,
                    epss: None,
                    sub_items: None,
                });
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_openai_key_in_env() {
        let rule = SecretsRule::new();
        let mut env = HashMap::new();
        env.insert(
            "OPENAI_API_KEY".to_string(),
            "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234".to_string(),
        );
        let server = McpServer {
            command: Some("npx".to_string()),
            env: Some(env),
            ..Default::default()
        };
        let findings = rule.check("test", &server, "test.json");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("OpenAI"));
    }

    #[test]
    fn test_password_in_connection_string() {
        let rule = SecretsRule::new();
        let server = McpServer {
            args: Some(vec![
                "-y".to_string(),
                "server-postgres".to_string(),
                "postgresql://admin:password123@prod-db.company.com:5432/main".to_string(),
            ]),
            ..Default::default()
        };
        let findings = rule.check("database", &server, "test.json");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("password"));
    }

    #[test]
    fn test_no_secrets() {
        let rule = SecretsRule::new();
        let server = McpServer {
            command: Some("npx".to_string()),
            args: Some(vec!["-y".to_string(), "some-server".to_string()]),
            ..Default::default()
        };
        let findings = rule.check("test", &server, "test.json");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_mask_secret() {
        assert_eq!(SecretsRule::mask_secret("sk-proj-abc123def456"), "sk-p...f456");
        assert_eq!(SecretsRule::mask_secret("short"), "*****");
    }

    #[test]
    fn test_aws_key_detected() {
        let rule = SecretsRule::new();
        let mut env = HashMap::new();
        env.insert(
            "AWS_ACCESS_KEY_ID".to_string(),
            "AKIAIOSFODNN7EXAMPLE".to_string(),
        );
        let server = McpServer {
            env: Some(env),
            ..Default::default()
        };
        let findings = rule.check("aws", &server, "test.json");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("AWS"));
    }
}
