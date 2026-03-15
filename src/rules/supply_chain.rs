use crate::rules::{Finding, Severity};
use crate::supply_chain;

/// Run supply chain risk analysis for discovered packages (AW-011).
pub async fn check_supply_chain(
    packages: &[(String, String, String)], // (package, server_name, config_file)
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (package, server_name, config_file) in packages {
        match supply_chain::analyze_package(package).await {
            Ok(risk) => {
                if risk.signals.is_empty() {
                    continue;
                }

                let severity = match risk.overall_risk {
                    supply_chain::RiskLevel::High => Severity::High,
                    supply_chain::RiskLevel::Medium => Severity::Medium,
                    supply_chain::RiskLevel::Low | supply_chain::RiskLevel::Info => Severity::Low,
                };

                let sub_items: Vec<String> =
                    risk.signals.iter().map(|s| s.description.clone()).collect();

                findings.push(Finding {
                    rule_id: "AW-011".to_string(),
                    severity,
                    title: format!(
                        "Supply chain risk: {} for {}",
                        risk.overall_risk, package
                    ),
                    message: format!(
                        "Supply chain analysis for '{}' in server '{}'",
                        package, server_name
                    ),
                    fix: "Review package provenance and consider using official @modelcontextprotocol packages".to_string(),
                    config_file: config_file.clone(),
                    server_name: server_name.clone(),
                    source: Some("supply-chain".to_string()),
                    epss: None,
                    sub_items: Some(sub_items),
                });
            }
            Err(e) => {
                eprintln!("Warning: supply chain check failed for {}: {}", package, e);
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use crate::supply_chain::{levenshtein, RiskLevel, RiskSignal, SupplyChainRisk};

    #[test]
    fn test_risk_level_mapping_high() {
        let risk = SupplyChainRisk {
            package: "test".to_string(),
            overall_risk: RiskLevel::High,
            signals: vec![RiskSignal {
                level: RiskLevel::High,
                description: "Single maintainer".to_string(),
            }],
        };
        assert_eq!(risk.overall_risk, RiskLevel::High);
    }

    #[test]
    fn test_risk_level_mapping_medium() {
        let risk = SupplyChainRisk {
            package: "test".to_string(),
            overall_risk: RiskLevel::Medium,
            signals: vec![RiskSignal {
                level: RiskLevel::Medium,
                description: "Low downloads".to_string(),
            }],
        };
        assert_eq!(risk.overall_risk, RiskLevel::Medium);
    }

    #[test]
    fn test_typosquat_detection_threshold() {
        // Should detect: distance <= 2
        assert!(levenshtein("server-filesystm", "server-filesystem") <= 2);
        assert!(levenshtein("mcp-remte", "mcp-remote") <= 2);

        // Should not detect: distance > 2
        assert!(levenshtein("my-cool-package", "mcp-remote") > 2);
    }

    #[test]
    fn test_empty_signals() {
        let risk = SupplyChainRisk {
            package: "safe-package".to_string(),
            overall_risk: RiskLevel::Low,
            signals: vec![],
        };
        assert!(risk.signals.is_empty());
    }
}
