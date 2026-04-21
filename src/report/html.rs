use crate::rules::{Finding, Severity};
use crate::scanner::ScanResult;
use std::f64::consts::PI;
use std::fmt::Write;
use std::time::{SystemTime, UNIX_EPOCH};

const CSS: &str = r#"
:root {
  color-scheme: dark;
  --bg: #0d1117;
  --card: #161b22;
  --border: #30363d;
  --text: #c9d1d9;
  --muted: #8b949e;
  --accent: #58a6ff;
  --critical: #ff4757;
  --high: #ff6348;
  --medium: #ffa502;
  --low: #747d8c;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
  line-height: 1.5;
}
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
main.report {
  max-width: 1180px;
  margin: 0 auto;
  padding: 24px;
  display: grid;
  gap: 16px;
}
.card {
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 16px;
}
.header {
  display: flex;
  justify-content: space-between;
  gap: 16px;
  align-items: flex-start;
  flex-wrap: wrap;
}
.header h1 {
  margin: 0;
  font-size: 1.8rem;
}
.subtitle {
  margin-top: 6px;
  color: var(--muted);
}
.meta {
  color: var(--muted);
  text-align: right;
  font-size: 0.95rem;
}
.meta strong {
  display: block;
  color: var(--text);
  margin-bottom: 2px;
}
.overview {
  display: grid;
  grid-template-columns: minmax(220px, 280px) 1fr;
  gap: 16px;
}
.gauge-wrap {
  display: grid;
  place-items: center;
}
.score-gauge {
  width: 190px;
  height: 190px;
}
.gauge-track {
  fill: none;
  stroke: #2f353d;
  stroke-width: 14;
}
.gauge-progress {
  fill: none;
  stroke-width: 14;
  stroke-linecap: round;
}
.gauge-score {
  text-anchor: middle;
  font-size: 2rem;
  font-weight: 800;
  fill: var(--text);
}
.gauge-grade {
  text-anchor: middle;
  font-size: 1rem;
  font-weight: 700;
}
.gauge-label {
  margin-top: 8px;
  color: var(--muted);
  font-size: 0.9rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
}
.stats-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(120px, 1fr));
  gap: 12px;
}
.stat {
  border: 1px solid var(--border);
  border-radius: 10px;
  background: #10161d;
  padding: 12px;
}
.stat-label {
  color: var(--muted);
  font-size: 0.75rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
}
.stat-value {
  margin-top: 4px;
  font-size: 1.35rem;
  font-weight: 700;
}
.section-title {
  margin: 0 0 12px;
  font-size: 1.1rem;
}
.severity-bar {
  height: 22px;
  display: flex;
  border-radius: 999px;
  overflow: hidden;
  border: 1px solid var(--border);
  background: #21262d;
}
.segment { height: 100%; }
.segment.critical { background: var(--critical); }
.segment.high { background: var(--high); }
.segment.medium { background: var(--medium); }
.segment.low { background: var(--low); }
.legend {
  display: grid;
  grid-template-columns: repeat(4, minmax(100px, 1fr));
  gap: 10px;
  margin-top: 10px;
}
.legend-item {
  display: flex;
  align-items: center;
  gap: 8px;
  color: var(--muted);
  font-size: 0.9rem;
}
.swatch {
  width: 10px;
  height: 10px;
  border-radius: 999px;
}
.swatch.critical { background: var(--critical); }
.swatch.high { background: var(--high); }
.swatch.medium { background: var(--medium); }
.swatch.low { background: var(--low); }
.findings-grid {
  display: grid;
  gap: 12px;
}
.finding-card {
  display: grid;
  gap: 10px;
}
.finding-head {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
}
.left-head {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}
.pill {
  display: inline-flex;
  align-items: center;
  border-radius: 999px;
  border: 1px solid transparent;
  padding: 2px 10px;
  font-size: 0.74rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.06em;
}
.pill.critical { color: var(--critical); border-color: rgba(255, 71, 87, 0.45); background: rgba(255, 71, 87, 0.18); }
.pill.high { color: var(--high); border-color: rgba(255, 99, 72, 0.45); background: rgba(255, 99, 72, 0.16); }
.pill.medium { color: var(--medium); border-color: rgba(255, 165, 2, 0.45); background: rgba(255, 165, 2, 0.14); }
.pill.low { color: var(--low); border-color: rgba(116, 125, 140, 0.5); background: rgba(116, 125, 140, 0.18); }
.rule-id {
  color: var(--muted);
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 0.8rem;
}
.source-tag {
  color: var(--accent);
  font-size: 0.78rem;
  border: 1px solid rgba(88, 166, 255, 0.4);
  border-radius: 999px;
  padding: 1px 8px;
  text-transform: uppercase;
  letter-spacing: 0.04em;
}
.location {
  margin: 0;
  color: var(--muted);
  font-size: 0.9rem;
}
.finding-card h3 {
  margin: 0;
  font-size: 1.08rem;
}
.message {
  margin: 0;
}
.fix-box {
  border: 1px solid #3a3f4b;
  background: #111822;
  border-radius: 10px;
  padding: 10px;
}
.fix-box strong {
  color: var(--accent);
}
.epss {
  border: 1px solid var(--border);
  background: #10161d;
  border-radius: 10px;
  padding: 10px;
}
.epss-meta {
  display: flex;
  justify-content: space-between;
  color: var(--muted);
  font-size: 0.85rem;
  gap: 8px;
  flex-wrap: wrap;
}
.epss-bar {
  margin-top: 8px;
  height: 8px;
  border-radius: 999px;
  overflow: hidden;
  background: #222a33;
}
.epss-fill {
  height: 100%;
  display: block;
  background: linear-gradient(90deg, #1e90ff, #2ed573);
}
.sub-tree {
  margin: 4px 0 0;
  padding-left: 18px;
}
.sub-tree li {
  list-style: none;
  position: relative;
  padding-left: 14px;
  color: var(--muted);
  margin: 4px 0;
}
.sub-tree li::before {
  content: "";
  position: absolute;
  left: 0;
  top: 0.78em;
  width: 8px;
  height: 1px;
  background: #6e7681;
}
.empty-state {
  text-align: center;
  color: var(--muted);
  padding: 26px;
}
.footer {
  text-align: center;
  color: var(--muted);
  font-size: 0.9rem;
}
@media (max-width: 900px) {
  .overview {
    grid-template-columns: 1fr;
  }
  .stats-grid {
    grid-template-columns: repeat(2, minmax(120px, 1fr));
  }
  .legend {
    grid-template-columns: repeat(2, minmax(100px, 1fr));
  }
}
@media print {
  :root { color-scheme: light; }
  body {
    background: #fff;
    color: #000;
  }
  .card {
    border-color: #c9d1d9;
    background: #fff;
    break-inside: avoid;
  }
  a { color: #0969da; }
}
"#;

pub fn render(result: &ScanResult) -> String {
    let (critical, high, medium, low) = severity_counts(&result.findings);
    let total_findings = result.findings.len();

    let mut sorted = result.findings.clone();
    sorted.sort_by_key(|finding| std::cmp::Reverse(finding.severity));

    let findings_html = if sorted.is_empty() {
        String::from(
            "<article class=\"card empty-state\"><h3>No findings detected</h3><p>This scan completed cleanly.</p></article>",
        )
    } else {
        sorted
            .iter()
            .map(render_finding_card)
            .collect::<Vec<_>>()
            .join("\n")
    };

    let score_gauge = render_score_gauge(result.score, &result.grade);
    let severity_chart = render_severity_chart(critical, high, medium, low);
    let timestamp = current_timestamp();

    let mut out = String::new();

    out.push_str("<!DOCTYPE html>\n");
    out.push_str("<html lang=\"en\">\n<head>\n");
    out.push_str("  <meta charset=\"utf-8\" />\n");
    out.push_str("  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />\n");
    out.push_str("  <title>agentwise Security Report</title>\n");
    out.push_str("  <style>\n");
    out.push_str(CSS);
    out.push_str("  </style>\n");
    out.push_str("</head>\n<body>\n");
    out.push_str("  <main class=\"report\">\n");
    out.push_str("    <header class=\"card header\">\n");
    out.push_str("      <div>\n");
    out.push_str("        <h1>agentwise Security Report</h1>\n");
    let _ = writeln!(
        out,
        "        <div class=\"subtitle\">version v{} • scan timestamp {}</div>",
        env!("CARGO_PKG_VERSION"),
        escape_html(&timestamp)
    );
    out.push_str("      </div>\n");
    out.push_str("      <div class=\"meta\">\n");
    out.push_str("        <strong>Scan Summary</strong>\n");
    let _ = writeln!(
        out,
        "        <div>{} configs • {} servers</div>",
        result.configs_scanned, result.servers_scanned
    );
    let _ = writeln!(
        out,
        "        <div>duration {}</div>",
        format_duration(result.duration_ms)
    );
    out.push_str("      </div>\n");
    out.push_str("    </header>\n");

    out.push_str("    <section class=\"overview\">\n");
    out.push_str("      <article class=\"card\">\n");
    out.push_str(&score_gauge);
    out.push_str("      </article>\n");
    out.push_str("      <article class=\"card\">\n");
    out.push_str("        <h2 class=\"section-title\">Stats</h2>\n");
    out.push_str("        <div class=\"stats-grid\">\n");
    append_stat(&mut out, "Configs scanned", result.configs_scanned);
    append_stat(&mut out, "Servers scanned", result.servers_scanned);
    append_stat(&mut out, "Duration", format_duration(result.duration_ms));
    append_stat(&mut out, "Total findings", total_findings);
    out.push_str("        </div>\n");
    out.push_str("      </article>\n");
    out.push_str("    </section>\n");

    out.push_str("    <section class=\"card\">\n");
    out.push_str("      <h2 class=\"section-title\">Severity breakdown</h2>\n");
    out.push_str(&severity_chart);
    out.push_str("    </section>\n");

    out.push_str("    <section>\n");
    out.push_str("      <h2 class=\"section-title\">Findings</h2>\n");
    out.push_str("      <div class=\"findings-grid\">\n");
    out.push_str(&findings_html);
    out.push_str("\n      </div>\n");
    out.push_str("    </section>\n");

    out.push_str("    <footer class=\"card footer\">\n");
    out.push_str(&format!("      Generated by agentwise v{} • <a href=\"https://github.com/brandonwise/agentwise\">GitHub</a>\n", env!("CARGO_PKG_VERSION")));

    out.push_str("    </footer>\n");
    out.push_str("  </main>\n");
    out.push_str("</body>\n</html>\n");

    out
}

fn append_stat<T: std::fmt::Display>(out: &mut String, label: &str, value: T) {
    let _ = writeln!(
        out,
        "<div class=\"stat\"><div class=\"stat-label\">{}</div><div class=\"stat-value\">{}</div></div>",
        escape_html(label),
        escape_html(&value.to_string())
    );
}

fn render_score_gauge(score: i32, grade: &str) -> String {
    let clamped_score = score.clamp(0, 100);
    let grade_letter = normalized_grade(grade, clamped_score);
    let grade_color = grade_color(grade_letter);

    let radius = 64.0;
    let circumference = 2.0 * PI * radius;
    let progress = circumference * (f64::from(clamped_score) / 100.0);

    format!(
        "<div class=\"gauge-wrap\">\n  <svg class=\"score-gauge\" viewBox=\"0 0 200 200\" role=\"img\" aria-label=\"Security score {}/100, grade {}\">\n    <circle class=\"gauge-track\" cx=\"100\" cy=\"100\" r=\"{}\"></circle>\n    <circle class=\"gauge-progress\" cx=\"100\" cy=\"100\" r=\"{}\" stroke=\"{}\" stroke-dasharray=\"0 {:.2}\" transform=\"rotate(-90 100 100)\">\n      <animate attributeName=\"stroke-dasharray\" from=\"0 {:.2}\" to=\"{:.2} {:.2}\" dur=\"1.2s\" fill=\"freeze\" />\n    </circle>\n    <text class=\"gauge-score\" x=\"100\" y=\"106\">{}</text>\n    <text class=\"gauge-grade\" x=\"100\" y=\"128\" fill=\"{}\">{}</text>\n  </svg>\n  <div class=\"gauge-label\">Security score</div>\n</div>\n",
        clamped_score,
        grade_letter,
        radius,
        radius,
        grade_color,
        circumference,
        circumference,
        progress,
        circumference,
        clamped_score,
        grade_color,
        grade_letter
    )
}

fn render_severity_chart(critical: usize, high: usize, medium: usize, low: usize) -> String {
    let total = critical + high + medium + low;

    let critical_pct = percentage(critical, total);
    let high_pct = percentage(high, total);
    let medium_pct = percentage(medium, total);
    let low_pct = percentage(low, total);

    format!(
        "<div class=\"severity-bar\" role=\"img\" aria-label=\"{} critical, {} high, {} medium, {} low findings\">\n  <span class=\"segment critical\" style=\"width: {:.2}%\"></span>\n  <span class=\"segment high\" style=\"width: {:.2}%\"></span>\n  <span class=\"segment medium\" style=\"width: {:.2}%\"></span>\n  <span class=\"segment low\" style=\"width: {:.2}%\"></span>\n</div>\n<div class=\"legend\">\n  <div class=\"legend-item\"><span class=\"swatch critical\"></span>Critical: {}</div>\n  <div class=\"legend-item\"><span class=\"swatch high\"></span>High: {}</div>\n  <div class=\"legend-item\"><span class=\"swatch medium\"></span>Medium: {}</div>\n  <div class=\"legend-item\"><span class=\"swatch low\"></span>Low: {}</div>\n</div>\n",
        critical,
        high,
        medium,
        low,
        critical_pct,
        high_pct,
        medium_pct,
        low_pct,
        critical,
        high,
        medium,
        low
    )
}

fn render_finding_card(finding: &Finding) -> String {
    let severity_class = severity_class(finding.severity);
    let severity_label = severity_label(finding.severity);
    let source_tag = finding
        .source
        .as_ref()
        .map(|s| {
            format!(
                "<span class=\"source-tag\">{}</span>",
                escape_html(&s.replace('-', " "))
            )
        })
        .unwrap_or_default();

    let epss_html = finding
        .epss
        .as_ref()
        .map(|epss| {
            let probability = (epss.probability * 100.0).clamp(0.0, 100.0);
            let percentile = (epss.percentile * 100.0).clamp(0.0, 100.0);
            format!(
                "<div class=\"epss\">\n  <div class=\"epss-meta\"><span>EPSS {:.1}% exploitation probability</span><span>{:.0}th percentile</span></div>\n  <div class=\"epss-bar\"><span class=\"epss-fill\" style=\"width: {:.2}%\"></span></div>\n</div>",
                probability,
                percentile,
                probability
            )
        })
        .unwrap_or_default();

    let sub_items_html = finding
        .sub_items
        .as_ref()
        .filter(|items| !items.is_empty())
        .map(|items| {
            let list_items = items
                .iter()
                .map(|item| format!("<li>{}</li>", escape_html(item)))
                .collect::<Vec<_>>()
                .join("");
            format!("<ul class=\"sub-tree\">{}</ul>", list_items)
        })
        .unwrap_or_default();

    format!(
        "<article class=\"card finding-card\">\n  <div class=\"finding-head\">\n    <div class=\"left-head\">\n      <span class=\"pill {}\">{}</span>\n      <span class=\"rule-id\">{}</span>\n    </div>\n    {}\n  </div>\n  <p class=\"location\">{} &rarr; {}</p>\n  <h3>{}</h3>\n  <p class=\"message\">{}</p>\n  {}\n  {}\n  <div class=\"fix-box\"><strong>Fix:</strong> {}</div>\n</article>",
        severity_class,
        severity_label,
        escape_html(&finding.rule_id),
        source_tag,
        escape_html(&finding.config_file),
        escape_html(&finding.server_name),
        escape_html(&finding.title),
        escape_html(&finding.message),
        epss_html,
        sub_items_html,
        escape_html(&finding.fix)
    )
}

fn severity_counts(findings: &[Finding]) -> (usize, usize, usize, usize) {
    let critical = findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    let high = findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count();
    let medium = findings
        .iter()
        .filter(|f| f.severity == Severity::Medium)
        .count();
    let low = findings
        .iter()
        .filter(|f| f.severity == Severity::Low)
        .count();

    (critical, high, medium, low)
}

fn severity_class(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
    }
}

fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "Critical",
        Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Low => "Low",
    }
}

fn normalized_grade(grade: &str, score: i32) -> char {
    grade
        .chars()
        .next()
        .map(|c| c.to_ascii_uppercase())
        .filter(|c| matches!(c, 'A' | 'B' | 'C' | 'D' | 'F'))
        .unwrap_or_else(|| score_to_grade(score))
}

fn score_to_grade(score: i32) -> char {
    match score {
        90..=100 => 'A',
        80..=89 => 'B',
        70..=79 => 'C',
        60..=69 => 'D',
        _ => 'F',
    }
}

fn grade_color(grade: char) -> &'static str {
    match grade {
        'A' => "#2ed573",
        'B' => "#1e90ff",
        'C' => "#ffa502",
        'D' => "#ff6348",
        _ => "#ff4757",
    }
}

fn percentage(count: usize, total: usize) -> f64 {
    if total == 0 {
        0.0
    } else {
        (count as f64 / total as f64) * 100.0
    }
}

fn format_duration(duration_ms: u64) -> String {
    if duration_ms == 0 {
        "<1ms".to_string()
    } else {
        format!("{}ms", duration_ms)
    }
}

fn current_timestamp() -> String {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => format!("{}s since Unix epoch", duration.as_secs()),
        Err(_) => "unknown".to_string(),
    }
}

pub(crate) fn escape_html(input: &str) -> String {
    let mut escaped = String::with_capacity(input.len());

    for c in input.chars() {
        match c {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(c),
        }
    }

    escaped
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::ScanResult;

    #[test]
    fn test_escape_html_special_characters() {
        let input = "<script>alert(\"x\" & 'y')</script>";
        let escaped = escape_html(input);
        assert_eq!(
            escaped,
            "&lt;script&gt;alert(&quot;x&quot; &amp; &#39;y&#39;)&lt;/script&gt;"
        );
    }

    #[test]
    fn test_score_gauge_svg_generation() {
        let gauge = render_score_gauge(85, "B");
        assert!(gauge.contains("<svg"));
        assert!(gauge.contains("stroke-dasharray"));
        assert!(gauge.contains("#1e90ff"));
        assert!(gauge.contains(">85<"));
        assert!(gauge.contains(">B<"));
    }

    #[test]
    fn test_render_empty_findings_case() {
        let result = ScanResult {
            findings: vec![],
            configs_scanned: 1,
            servers_scanned: 1,
            score: 100,
            grade: "A".to_string(),
            duration_ms: 1,
            osv_stats: None,
            suppressed_count: 0,
        };

        let html = render(&result);
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("No findings detected"));
        assert!(html.contains("agentwise Security Report"));
        assert!(html.contains(&format!(
            "Generated by agentwise v{}",
            env!("CARGO_PKG_VERSION")
        )));
    }
}
