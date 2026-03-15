use crate::rules::{Finding, Severity};
use crate::scanner::ScanResult;
use serde::Serialize;

#[derive(Serialize)]
struct SarifReport {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: Vec<SarifRun>,
}

#[derive(Serialize)]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
}

#[derive(Serialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Serialize)]
struct SarifDriver {
    name: &'static str,
    version: String,
    #[serde(rename = "informationUri")]
    information_uri: &'static str,
    rules: Vec<SarifRule>,
}

#[derive(Serialize)]
struct SarifRule {
    id: String,
    name: String,
    #[serde(rename = "shortDescription")]
    short_description: SarifMessage,
    #[serde(rename = "defaultConfiguration")]
    default_configuration: SarifConfiguration,
    #[serde(rename = "helpUri")]
    help_uri: String,
}

#[derive(Serialize)]
struct SarifConfiguration {
    level: String,
}

#[derive(Serialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    level: String,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
    fixes: Vec<SarifFix>,
}

#[derive(Serialize)]
struct SarifMessage {
    text: String,
}

#[derive(Serialize)]
struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    physical_location: SarifPhysicalLocation,
}

#[derive(Serialize)]
struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: SarifArtifactLocation,
}

#[derive(Serialize)]
struct SarifArtifactLocation {
    uri: String,
}

#[derive(Serialize)]
struct SarifFix {
    description: SarifMessage,
}

fn severity_to_sarif_level(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

fn build_rules(findings: &[Finding]) -> Vec<SarifRule> {
    let mut seen = std::collections::HashSet::new();
    let mut rules = Vec::new();

    for finding in findings {
        if seen.insert(finding.rule_id.clone()) {
            rules.push(SarifRule {
                id: finding.rule_id.clone(),
                name: finding.rule_id.clone(),
                short_description: SarifMessage {
                    text: finding.title.clone(),
                },
                default_configuration: SarifConfiguration {
                    level: severity_to_sarif_level(&finding.severity).to_string(),
                },
                help_uri: format!(
                    "https://github.com/brandonwise/agentwise#{}",
                    finding.rule_id.to_lowercase()
                ),
            });
        }
    }

    rules
}

pub fn render(result: &ScanResult) -> String {
    let rules = build_rules(&result.findings);

    let results: Vec<SarifResult> = result
        .findings
        .iter()
        .map(|f| SarifResult {
            rule_id: f.rule_id.clone(),
            level: severity_to_sarif_level(&f.severity).to_string(),
            message: SarifMessage {
                text: format!("{}: {}", f.title, f.message),
            },
            locations: vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: f.config_file.clone(),
                    },
                },
            }],
            fixes: vec![SarifFix {
                description: SarifMessage {
                    text: f.fix.clone(),
                },
            }],
        })
        .collect();

    let report = SarifReport {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        version: "2.1.0",
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "agentwise",
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    information_uri: "https://github.com/brandonwise/agentwise",
                    rules,
                },
            },
            results,
        }],
    };

    serde_json::to_string_pretty(&report).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sarif_output_valid() {
        let result = ScanResult {
            findings: vec![Finding {
                rule_id: "AW-001".to_string(),
                severity: Severity::Critical,
                title: "No auth".to_string(),
                message: "Server has no auth".to_string(),
                fix: "Add auth".to_string(),
                config_file: "test.json".to_string(),
                server_name: "test".to_string(),
                source: None,
                epss: None,
                sub_items: None,
            }],
            configs_scanned: 1,
            servers_scanned: 1,
            score: 80,
            grade: "B".to_string(),
            duration_ms: 1,
            osv_stats: None,
            suppressed_count: 0,
        };
        let output = render(&result);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["version"], "2.1.0");
        assert_eq!(parsed["runs"][0]["tool"]["driver"]["name"], "agentwise");
        assert_eq!(parsed["runs"][0]["results"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_sarif_severity_mapping() {
        assert_eq!(severity_to_sarif_level(&Severity::Critical), "error");
        assert_eq!(severity_to_sarif_level(&Severity::High), "error");
        assert_eq!(severity_to_sarif_level(&Severity::Medium), "warning");
        assert_eq!(severity_to_sarif_level(&Severity::Low), "note");
    }

    #[test]
    fn test_sarif_empty_results() {
        let result = ScanResult {
            findings: vec![],
            configs_scanned: 0,
            servers_scanned: 0,
            score: 100,
            grade: "A".to_string(),
            duration_ms: 0,
            osv_stats: None,
            suppressed_count: 0,
        };
        let output = render(&result);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert!(parsed["runs"][0]["results"].as_array().unwrap().is_empty());
    }
}
