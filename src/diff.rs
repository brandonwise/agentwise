use crate::rules::Finding;
use owo_colors::OwoColorize;
use serde::{Deserialize, Serialize};
use std::cmp::min;
use std::collections::{BTreeSet, HashMap};
use std::fs;

#[derive(Debug, Serialize)]
pub struct DiffResult {
    pub before_score: i32,
    pub after_score: i32,
    pub score_delta: i32,
    pub before_grade: String,
    pub after_grade: String,
    pub fixed: Vec<Finding>,
    pub new: Vec<Finding>,
    pub unchanged: Vec<Finding>,
}

#[derive(Debug, Deserialize)]
struct JsonScanReport {
    score: i32,
    grade: String,
    findings: Vec<Finding>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct FindingKey {
    rule_id: String,
    server_name: String,
    config_file: String,
}

pub fn compare_reports(before_path: &str, after_path: &str) -> Result<DiffResult, String> {
    let before = load_report(before_path)?;
    let after = load_report(after_path)?;

    Ok(diff_reports(before, after))
}

pub fn render_terminal(diff: &DiffResult) -> String {
    let mut out = String::new();

    out.push('\n');
    out.push_str(&format!(
        "  {}\n",
        "╔══════════════════════════════════════════════════════════════╗".dimmed()
    ));
    out.push_str(&format!(
        "  {}  {}{}{}\n",
        "║".dimmed(),
        "agentwise diff".bold().cyan(),
        " ".repeat(62usize.saturating_sub(4 + "agentwise diff".len())),
        "║".dimmed(),
    ));
    out.push_str(&format!(
        "  {}\n\n",
        "╚══════════════════════════════════════════════════════════════╝".dimmed()
    ));

    let trend = if diff.score_delta > 0 {
        "▲".green().bold().to_string()
    } else if diff.score_delta < 0 {
        "▼".red().bold().to_string()
    } else {
        "■".dimmed().to_string()
    };

    let delta = if diff.score_delta > 0 {
        format!("+{}", diff.score_delta).green().bold().to_string()
    } else if diff.score_delta < 0 {
        diff.score_delta.to_string().red().bold().to_string()
    } else {
        diff.score_delta.to_string().dimmed().to_string()
    };

    let grade_before = color_grade(&diff.before_grade);
    let grade_after = color_grade(&diff.after_grade);

    out.push_str(&format!(
        "  Score: {} → {}  ({})  Grade: {} → {}  {}\n\n",
        diff.before_score, diff.after_score, delta, grade_before, grade_after, trend
    ));

    for finding in &diff.fixed {
        out.push_str(&format!(
            "  {} {} {:<7} {}\n",
            "✓".green().bold(),
            "FIXED".green().bold(),
            finding.rule_id.green().bold(),
            finding.title
        ));
    }

    if !diff.fixed.is_empty() && (!diff.new.is_empty() || !diff.unchanged.is_empty()) {
        out.push('\n');
    }

    for finding in &diff.new {
        out.push_str(&format!(
            "  {} {} {:<7} {}\n",
            "✖".red().bold(),
            "NEW  ".red().bold(),
            finding.rule_id.red().bold(),
            finding.title
        ));
    }

    if !diff.new.is_empty() && !diff.unchanged.is_empty() {
        out.push('\n');
    }

    for finding in &diff.unchanged {
        out.push_str(&format!(
            "  {} {} {:<7} {}\n",
            "─".dimmed(),
            "SAME ".dimmed(),
            finding.rule_id.dimmed(),
            finding.title.dimmed()
        ));
    }

    out.push_str(&format!(
        "\n  {} fixed · {} new · {} unchanged\n",
        diff.fixed.len(),
        diff.new.len(),
        diff.unchanged.len()
    ));

    out
}

pub fn render_json(diff: &DiffResult) -> Result<String, String> {
    serde_json::to_string_pretty(diff)
        .map_err(|e| format!("Failed to serialize diff report: {}", e))
}

fn load_report(path: &str) -> Result<JsonScanReport, String> {
    let raw =
        fs::read_to_string(path).map_err(|e| format!("Failed to read report '{}': {}", path, e))?;

    serde_json::from_str(&raw).map_err(|e| format!("Failed to parse JSON report '{}': {}", path, e))
}

fn diff_reports(before: JsonScanReport, after: JsonScanReport) -> DiffResult {
    let before_score = before.score;
    let after_score = after.score;

    let mut before_map = bucket_findings(before.findings);
    let mut after_map = bucket_findings(after.findings);

    let keys: BTreeSet<FindingKey> = before_map
        .keys()
        .cloned()
        .chain(after_map.keys().cloned())
        .collect();

    let mut fixed = Vec::new();
    let mut new = Vec::new();
    let mut unchanged = Vec::new();

    for key in keys {
        let mut before_bucket = before_map.remove(&key).unwrap_or_default();
        let mut after_bucket = after_map.remove(&key).unwrap_or_default();

        let overlap = min(before_bucket.len(), after_bucket.len());

        unchanged.extend(after_bucket.drain(..overlap));
        before_bucket.drain(..overlap);
        fixed.append(&mut before_bucket);
        new.append(&mut after_bucket);
    }

    sort_findings(&mut fixed);
    sort_findings(&mut new);
    sort_findings(&mut unchanged);

    DiffResult {
        before_score,
        after_score,
        score_delta: after_score - before_score,
        before_grade: before.grade,
        after_grade: after.grade,
        fixed,
        new,
        unchanged,
    }
}

fn bucket_findings(findings: Vec<Finding>) -> HashMap<FindingKey, Vec<Finding>> {
    let mut buckets: HashMap<FindingKey, Vec<Finding>> = HashMap::new();

    for finding in findings {
        let key = FindingKey {
            rule_id: finding.rule_id.clone(),
            server_name: finding.server_name.clone(),
            config_file: finding.config_file.clone(),
        };
        buckets.entry(key).or_default().push(finding);
    }

    buckets
}

fn sort_findings(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.rule_id.cmp(&b.rule_id))
            .then_with(|| a.server_name.cmp(&b.server_name))
            .then_with(|| a.config_file.cmp(&b.config_file))
            .then_with(|| a.title.cmp(&b.title))
    });
}

fn color_grade(grade: &str) -> String {
    match grade {
        "A" => grade.green().bold().to_string(),
        "B" => grade.green().to_string(),
        "C" => grade.yellow().to_string(),
        "D" => grade.yellow().bold().to_string(),
        _ => grade.red().bold().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::Severity;

    fn finding(rule_id: &str, server_name: &str, config_file: &str, title: &str) -> Finding {
        Finding {
            rule_id: rule_id.to_string(),
            severity: Severity::High,
            title: title.to_string(),
            message: title.to_string(),
            fix: "Fix".to_string(),
            config_file: config_file.to_string(),
            server_name: server_name.to_string(),
            source: None,
            epss: None,
            sub_items: None,
        }
    }

    #[test]
    fn test_diff_categorizes_fixed_new_and_unchanged() {
        let before = JsonScanReport {
            score: 30,
            grade: "F".to_string(),
            findings: vec![
                finding("AW-001", "server-a", "one.json", "Auth missing"),
                finding("AW-004", "server-a", "one.json", "Secret found"),
            ],
        };

        let after = JsonScanReport {
            score: 70,
            grade: "C".to_string(),
            findings: vec![
                finding("AW-004", "server-a", "one.json", "Secret found"),
                finding("AW-009", "server-b", "two.json", "Network access"),
            ],
        };

        let diff = diff_reports(before, after);

        assert_eq!(diff.score_delta, 40);
        assert_eq!(diff.fixed.len(), 1);
        assert_eq!(diff.fixed[0].rule_id, "AW-001");
        assert_eq!(diff.new.len(), 1);
        assert_eq!(diff.new[0].rule_id, "AW-009");
        assert_eq!(diff.unchanged.len(), 1);
        assert_eq!(diff.unchanged[0].rule_id, "AW-004");
    }

    #[test]
    fn test_diff_json_serialization() {
        let diff = DiffResult {
            before_score: 20,
            after_score: 80,
            score_delta: 60,
            before_grade: "F".to_string(),
            after_grade: "B".to_string(),
            fixed: vec![finding("AW-001", "server-a", "one.json", "Auth missing")],
            new: vec![],
            unchanged: vec![],
        };

        let output = render_json(&diff).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["score_delta"], 60);
        assert_eq!(parsed["fixed"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_terminal_render_has_sections() {
        let diff = DiffResult {
            before_score: 20,
            after_score: 80,
            score_delta: 60,
            before_grade: "F".to_string(),
            after_grade: "B".to_string(),
            fixed: vec![finding("AW-001", "server-a", "one.json", "Auth missing")],
            new: vec![finding(
                "AW-007",
                "server-b",
                "two.json",
                "Missing allowlist",
            )],
            unchanged: vec![finding(
                "AW-009",
                "server-c",
                "three.json",
                "Network access",
            )],
        };

        let output = render_terminal(&diff);
        assert!(output.contains("agentwise diff"));
        assert!(output.contains("FIXED"));
        assert!(output.contains("NEW"));
        assert!(output.contains("SAME"));
        assert!(output.contains("1 fixed · 1 new · 1 unchanged"));
    }
}
