use crate::scanner::ScanResult;
use serde::Serialize;

#[derive(Serialize)]
struct JsonReport<'a> {
    version: &'static str,
    configs_scanned: usize,
    servers_scanned: usize,
    score: i32,
    grade: &'a str,
    duration_ms: u64,
    findings: &'a [crate::rules::Finding],
    summary: Summary,
}

#[derive(Serialize)]
struct Summary {
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    total: usize,
}

pub fn render(result: &ScanResult) -> String {
    use crate::rules::Severity;

    let summary = Summary {
        critical: result
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .count(),
        high: result
            .findings
            .iter()
            .filter(|f| f.severity == Severity::High)
            .count(),
        medium: result
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Medium)
            .count(),
        low: result
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Low)
            .count(),
        total: result.findings.len(),
    };

    let report = JsonReport {
        version: env!("CARGO_PKG_VERSION"),
        configs_scanned: result.configs_scanned,
        servers_scanned: result.servers_scanned,
        score: result.score,
        grade: &result.grade,
        duration_ms: result.duration_ms,
        findings: &result.findings,
        summary,
    };

    serde_json::to_string_pretty(&report).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{Finding, Severity};

    #[test]
    fn test_json_output_valid() {
        let result = ScanResult {
            findings: vec![Finding {
                rule_id: "AW-001".to_string(),
                severity: Severity::Critical,
                title: "Test".to_string(),
                message: "Test message".to_string(),
                fix: "Fix it".to_string(),
                config_file: "test.json".to_string(),
                server_name: "test".to_string(),
            }],
            configs_scanned: 1,
            servers_scanned: 1,
            score: 80,
            grade: "B".to_string(),
            duration_ms: 1,
        };
        let output = render(&result);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["score"], 80);
        assert_eq!(parsed["summary"]["critical"], 1);
        assert_eq!(parsed["findings"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_json_empty_findings() {
        let result = ScanResult {
            findings: vec![],
            configs_scanned: 0,
            servers_scanned: 0,
            score: 100,
            grade: "A".to_string(),
            duration_ms: 0,
        };
        let output = render(&result);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["summary"]["total"], 0);
    }
}
