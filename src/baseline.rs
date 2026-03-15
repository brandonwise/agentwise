use crate::rules::Finding;
use chrono::{Local, NaiveDate};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

pub const BASELINE_FILE_NAME: &str = ".agentwise-ignore.json";

#[derive(Debug, Deserialize, Serialize)]
pub struct BaselineConfig {
    pub version: u32,
    pub ignore: Vec<IgnoreRule>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct IgnoreRule {
    pub rule: String,
    pub server: Option<String>,
    pub reason: String,
    pub expires: Option<String>, // ISO date
}

pub fn load_for_scan(
    scan_path: &str,
    baseline_path: Option<&str>,
) -> Result<Option<(BaselineConfig, PathBuf)>, String> {
    if let Some(path) = baseline_path {
        let baseline_path = PathBuf::from(path);
        let config = load_from_file(&baseline_path)?;
        return Ok(Some((config, baseline_path)));
    }

    if let Some(path) = auto_detect_path(scan_path) {
        let config = load_from_file(&path)?;
        return Ok(Some((config, path)));
    }

    Ok(None)
}

pub fn load_from_file(path: &Path) -> Result<BaselineConfig, String> {
    let raw = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read baseline file '{}': {}", path.display(), e))?;

    serde_json::from_str(&raw)
        .map_err(|e| format!("Failed to parse baseline file '{}': {}", path.display(), e))
}

pub fn auto_detect_path(scan_path: &str) -> Option<PathBuf> {
    let path = Path::new(scan_path);

    let base_dir = if path.is_file() {
        path.parent().unwrap_or_else(|| Path::new("."))
    } else if path.is_dir() {
        path
    } else {
        path.parent().unwrap_or_else(|| Path::new("."))
    };

    let candidate = base_dir.join(BASELINE_FILE_NAME);
    if candidate.exists() {
        Some(candidate)
    } else {
        None
    }
}

pub fn filter_findings(
    findings: Vec<Finding>,
    baseline: &BaselineConfig,
) -> Result<(Vec<Finding>, Vec<Finding>), String> {
    let today = Local::now().date_naive();
    filter_findings_with_date(findings, baseline, today)
}

fn filter_findings_with_date(
    findings: Vec<Finding>,
    baseline: &BaselineConfig,
    today: NaiveDate,
) -> Result<(Vec<Finding>, Vec<Finding>), String> {
    let mut active_rules = Vec::new();
    for rule in &baseline.ignore {
        if is_rule_active(rule, today)? {
            active_rules.push(rule);
        }
    }

    let mut filtered = Vec::new();
    let mut suppressed = Vec::new();

    for finding in findings {
        let matched = active_rules.iter().any(|rule| matches_rule(&finding, rule));
        if matched {
            suppressed.push(finding);
        } else {
            filtered.push(finding);
        }
    }

    Ok((filtered, suppressed))
}

pub fn init_in_dir(dir: &Path) -> Result<PathBuf, String> {
    let path = dir.join(BASELINE_FILE_NAME);
    if path.exists() {
        return Err(format!("Baseline file already exists: {}", path.display()));
    }

    let template = BaselineConfig {
        version: 1,
        ignore: vec![],
    };

    let content = serde_json::to_string_pretty(&template)
        .map_err(|e| format!("Failed to serialize baseline template: {}", e))?;

    fs::write(&path, format!("{}\n", content))
        .map_err(|e| format!("Failed to write baseline file '{}': {}", path.display(), e))?;

    Ok(path)
}

pub fn show_in_dir(dir: &Path) -> Result<String, String> {
    let path = dir.join(BASELINE_FILE_NAME);
    let config = load_from_file(&path)?;
    serde_json::to_string_pretty(&config).map_err(|e| {
        format!(
            "Failed to serialize baseline file '{}': {}",
            path.display(),
            e
        )
    })
}

fn matches_rule(finding: &Finding, rule: &IgnoreRule) -> bool {
    finding.rule_id == rule.rule
        && match rule.server.as_deref() {
            Some(server) => server == finding.server_name,
            None => true,
        }
}

fn is_rule_active(rule: &IgnoreRule, today: NaiveDate) -> Result<bool, String> {
    match rule.expires.as_deref() {
        Some(date_str) => {
            let expires = NaiveDate::parse_from_str(date_str, "%Y-%m-%d")
                .map_err(|e| format!("Invalid baseline expires date '{}': {}", date_str, e))?;
            Ok(expires >= today)
        }
        None => Ok(true),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::Severity;
    use chrono::Duration;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn finding(rule_id: &str, server_name: &str) -> Finding {
        Finding {
            rule_id: rule_id.to_string(),
            severity: Severity::High,
            title: "Test".to_string(),
            message: "Test".to_string(),
            fix: "Fix".to_string(),
            config_file: "test.json".to_string(),
            server_name: server_name.to_string(),
            source: None,
            epss: None,
            sub_items: None,
        }
    }

    fn temp_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("agentwise-baseline-test-{}", nanos));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_filter_findings_suppresses_matching_rules() {
        let baseline = BaselineConfig {
            version: 1,
            ignore: vec![IgnoreRule {
                rule: "AW-007".to_string(),
                server: None,
                reason: "Accepted risk".to_string(),
                expires: None,
            }],
        };

        let findings = vec![finding("AW-007", "fetch"), finding("AW-009", "fetch")];
        let (filtered, suppressed) = filter_findings(findings, &baseline).unwrap();

        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].rule_id, "AW-009");
        assert_eq!(suppressed.len(), 1);
        assert_eq!(suppressed[0].rule_id, "AW-007");
    }

    #[test]
    fn test_expired_rules_are_inactive() {
        let yesterday = (Local::now() - Duration::days(1)).date_naive();

        let baseline = BaselineConfig {
            version: 1,
            ignore: vec![IgnoreRule {
                rule: "AW-007".to_string(),
                server: None,
                reason: "Temporary suppress".to_string(),
                expires: Some(yesterday.format("%Y-%m-%d").to_string()),
            }],
        };

        let findings = vec![finding("AW-007", "fetch")];
        let (filtered, suppressed) = filter_findings(findings, &baseline).unwrap();

        assert_eq!(filtered.len(), 1);
        assert!(suppressed.is_empty());
    }

    #[test]
    fn test_auto_detect_baseline_path_for_file_scan() {
        let dir = temp_dir();
        let target_file = dir.join("vulnerable-mcp.json");
        std::fs::write(&target_file, "{}\n").unwrap();

        let baseline_file = dir.join(BASELINE_FILE_NAME);
        std::fs::write(&baseline_file, r#"{"version":1,"ignore":[]}"#).unwrap();

        let found = auto_detect_path(target_file.to_str().unwrap());
        assert_eq!(found.unwrap(), baseline_file);
    }

    #[test]
    fn test_init_and_show_baseline() {
        let dir = temp_dir();
        let path = init_in_dir(&dir).unwrap();
        assert!(path.exists());

        let shown = show_in_dir(&dir).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&shown).unwrap();
        assert_eq!(parsed["version"], 1);
        assert!(parsed["ignore"].is_array());
    }
}
