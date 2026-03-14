use crate::rules::{Finding, Severity};
use crate::scanner::ScanResult;
use owo_colors::OwoColorize;

pub fn render(result: &ScanResult) -> String {
    let mut out = String::new();

    // Header
    out.push('\n');
    out.push_str(&render_header());
    out.push('\n');

    // Scan summary
    out.push_str(&render_scan_summary(result));
    out.push('\n');

    if result.findings.is_empty() {
        out.push_str(&render_clean());
        out.push('\n');
    } else {
        // Findings summary bar
        out.push_str(&render_severity_summary(result));
        out.push('\n');

        // Individual findings
        let mut sorted = result.findings.clone();
        sorted.sort_by(|a, b| b.severity.cmp(&a.severity));

        for finding in &sorted {
            out.push_str(&render_finding(finding));
        }
    }

    // Score
    out.push_str(&render_score(result));
    out.push('\n');

    out
}

fn render_header() -> String {
    let top = format!("  {}",
        "╔══════════════════════════════════════════════════════════════╗"
            .dimmed());
    let mid = format!("  {}  {} {}  {}",
        "║".dimmed(),
        "agentwise".bold().cyan(),
        format!("v{}", env!("CARGO_PKG_VERSION")).dimmed(),
        "║".dimmed());
    let label = "MCP Security Scanner";
    let mid2 = format!("  {}  {}{}{}",
        "║".dimmed(),
        label.white(),
        " ".repeat(62 - 4 - label.len()),
        "║".dimmed());
    let bot = format!("  {}",
        "╚══════════════════════════════════════════════════════════════╝"
            .dimmed());
    format!("{}\n{}\n{}\n{}\n", top, mid, mid2, bot)
}

fn render_scan_summary(result: &ScanResult) -> String {
    let duration_str = if result.duration_ms < 1 {
        "<1ms".to_string()
    } else {
        format!("{}ms", result.duration_ms)
    };

    format!(
        "  {} Scanned {} {} ({} {}) in {}\n",
        "●".green(),
        result.configs_scanned,
        if result.configs_scanned == 1 { "config" } else { "configs" },
        result.servers_scanned,
        if result.servers_scanned == 1 { "server" } else { "servers" },
        duration_str.dimmed(),
    )
}

fn render_clean() -> String {
    let top = format!("  {}", "┌──────────────────────────────────────────────────────────────┐".green());
    let mid = format!("  {}  {}  {}", "│".green(), "No security issues found!".green().bold(), "│".green());
    let bot = format!("  {}", "└──────────────────────────────────────────────────────────────┘".green());
    format!("{}\n{}\n{}\n", top, mid, bot)
}

fn render_severity_summary(result: &ScanResult) -> String {
    let critical = result
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    let high = result
        .findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count();
    let medium = result
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Medium)
        .count();
    let low = result
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Low)
        .count();

    let summary = format!(
        "{} critical  {} high  {} medium  {} low",
        critical, high, medium, low
    );

    let top = format!("  {}", "┌──────────────────────────────────────────────────────────────┐".dimmed());
    let mid = format!(
        "  {}  {} {}  {} {}  {} {}  {} {}{}{}",
        "│".dimmed(),
        "■".red().bold(),
        format!("{} critical", critical).red().bold(),
        "■".yellow().bold(),
        format!("{} high", high).yellow().bold(),
        "■".blue(),
        format!("{} medium", medium).blue(),
        "■".dimmed(),
        format!("{} low", low).dimmed(),
        " ".repeat(62usize.saturating_sub(summary.len() + 8)),
        "│".dimmed(),
    );
    let bot = format!("  {}", "└──────────────────────────────────────────────────────────────┘".dimmed());
    format!("{}\n{}\n{}\n", top, mid, bot)
}

fn render_finding(finding: &Finding) -> String {
    let severity_label = match finding.severity {
        Severity::Critical => "CRITICAL".red().bold().to_string(),
        Severity::High => "HIGH    ".yellow().bold().to_string(),
        Severity::Medium => "MEDIUM  ".blue().to_string(),
        Severity::Low => "LOW     ".dimmed().to_string(),
    };

    let icon = match finding.severity {
        Severity::Critical => "✖".red().bold().to_string(),
        Severity::High => "▲".yellow().bold().to_string(),
        Severity::Medium => "●".blue().to_string(),
        Severity::Low => "○".dimmed().to_string(),
    };

    let location = format!("{} → {}", finding.config_file, finding.server_name).dimmed().to_string();
    let rule_id = finding.rule_id.dimmed().to_string();

    let mut out = String::new();
    out.push_str(&format!(
        "  {} {} {} {}\n",
        icon, severity_label, location, rule_id
    ));
    out.push_str(&format!("    {}\n", finding.title));
    out.push_str(&format!(
        "    {} {}\n\n",
        "Fix:".green().bold(),
        finding.fix
    ));

    out
}

fn render_score(result: &ScanResult) -> String {
    let (score, grade) = (result.score, &result.grade);

    let bar_width = 30;
    let filled = (score as usize * bar_width) / 100;
    let empty = bar_width - filled;

    let bar_char = "█";
    let empty_char = "░";

    let bar = format!(
        "{}{}",
        bar_char.repeat(filled),
        empty_char.repeat(empty)
    );

    let colored_bar = match score {
        80..=100 => bar.green().to_string(),
        60..=79 => bar.yellow().to_string(),
        40..=59 => bar.red().to_string(),
        _ => bar.red().bold().to_string(),
    };

    let colored_grade = match grade.as_str() {
        "A" => grade.green().bold().to_string(),
        "B" => grade.green().to_string(),
        "C" => grade.yellow().to_string(),
        "D" => grade.yellow().bold().to_string(),
        _ => grade.red().bold().to_string(),
    };

    let top = format!("  {}", "╔══════════════════════════════════════════════════════════════╗".dimmed());
    let mid = format!(
        "  {}  Score: {}/100  {}  Grade: {}{}{}",
        "║".dimmed(),
        score,
        colored_bar,
        colored_grade,
        " ".repeat(62usize.saturating_sub(41 + grade.len())),
        "║".dimmed(),
    );
    let bot = format!("  {}", "╚══════════════════════════════════════════════════════════════╝".dimmed());
    format!("{}\n{}\n{}\n", top, mid, bot)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::ScanResult;

    #[test]
    fn test_render_no_findings() {
        let result = ScanResult {
            findings: vec![],
            configs_scanned: 1,
            servers_scanned: 2,
            score: 100,
            grade: "A".to_string(),
            duration_ms: 0,
        };
        let output = render(&result);
        assert!(output.contains("agentwise"));
        assert!(output.contains("No security issues found"));
        assert!(output.contains("100"));
    }

    #[test]
    fn test_render_with_findings() {
        let result = ScanResult {
            findings: vec![Finding {
                rule_id: "AW-001".to_string(),
                severity: Severity::Critical,
                title: "Test finding".to_string(),
                message: "Test message".to_string(),
                fix: "Test fix".to_string(),
                config_file: "test.json".to_string(),
                server_name: "test-server".to_string(),
            }],
            configs_scanned: 1,
            servers_scanned: 1,
            score: 80,
            grade: "B".to_string(),
            duration_ms: 1,
        };
        let output = render(&result);
        assert!(output.contains("CRITICAL"));
        assert!(output.contains("Test finding"));
        assert!(output.contains("Test fix"));
    }
}
