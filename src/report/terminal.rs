use crate::discover::DiscoveredConfig;
use crate::rules::{Finding, Severity};
use crate::scanner::{OsvStats, ScanResult};
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

    // OSV live query stats
    if let Some(ref stats) = result.osv_stats {
        out.push_str(&render_osv_stats(stats));
        out.push('\n');
    }

    // Score
    out.push_str(&render_score(result));
    out.push('\n');

    out
}

fn render_header() -> String {
    let top = format!(
        "  {}",
        "╔══════════════════════════════════════════════════════════════╗".dimmed()
    );
    let mid = format!(
        "  {}  {} {}  {}",
        "║".dimmed(),
        "agentwise".bold().cyan(),
        format!("v{}", env!("CARGO_PKG_VERSION")).dimmed(),
        "║".dimmed()
    );
    let label = "MCP Security Scanner";
    let mid2 = format!(
        "  {}  {}{}{}",
        "║".dimmed(),
        label.white(),
        " ".repeat(62 - 4 - label.len()),
        "║".dimmed()
    );
    let bot = format!(
        "  {}",
        "╚══════════════════════════════════════════════════════════════╝".dimmed()
    );
    format!("{}\n{}\n{}\n{}\n", top, mid, mid2, bot)
}

fn render_scan_summary(result: &ScanResult) -> String {
    let duration_str = if result.duration_ms < 1 {
        "<1ms".to_string()
    } else {
        format!("{}ms", result.duration_ms)
    };

    let mut out = format!(
        "  {} Scanned {} {} ({} {}) in {}\n",
        "●".green(),
        result.configs_scanned,
        if result.configs_scanned == 1 {
            "config"
        } else {
            "configs"
        },
        result.servers_scanned,
        if result.servers_scanned == 1 {
            "server"
        } else {
            "servers"
        },
        duration_str.dimmed(),
    );

    if result.suppressed_count > 0 {
        out.push_str(&format!(
            "  {} Suppressed {} {} via baseline\n",
            "○".dimmed(),
            result.suppressed_count,
            if result.suppressed_count == 1 {
                "finding"
            } else {
                "findings"
            }
        ));
    }

    out
}

fn render_clean() -> String {
    let top = format!(
        "  {}",
        "┌──────────────────────────────────────────────────────────────┐".green()
    );
    let mid = format!(
        "  {}  {}  {}",
        "│".green(),
        "No security issues found!".green().bold(),
        "│".green()
    );
    let bot = format!(
        "  {}",
        "└──────────────────────────────────────────────────────────────┘".green()
    );
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

    let top = format!(
        "  {}",
        "┌──────────────────────────────────────────────────────────────┐".dimmed()
    );
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
    let bot = format!(
        "  {}",
        "└──────────────────────────────────────────────────────────────┘".dimmed()
    );
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

    let source_tag = match finding.source.as_deref() {
        Some("osv") => format!(" {}", "[LIVE]".cyan().bold()),
        Some("supply-chain") => format!(" {}", "[SUPPLY-CHAIN]".magenta().bold()),
        Some("deps.dev") => format!(" {}", "[DEPS.DEV]".magenta().bold()),
        _ => String::new(),
    };

    let location = format!("{} → {}", finding.config_file, finding.server_name)
        .dimmed()
        .to_string();
    let rule_id = finding.rule_id.dimmed().to_string();

    let mut out = String::new();
    out.push_str(&format!(
        "  {} {} {} {}{}\n",
        icon, severity_label, location, rule_id, source_tag
    ));
    out.push_str(&format!("    {}\n", finding.title));

    // EPSS data for CVE findings
    if let Some(ref epss) = finding.epss {
        let pct = (epss.probability * 100.0) as u32;
        let ptile = (epss.percentile * 100.0) as u32;
        let emoji = if pct > 50 {
            " \u{1F525}" // 🔥
        } else if pct > 20 {
            " \u{26A0}\u{FE0F}" // ⚠️
        } else {
            ""
        };
        out.push_str(&format!(
            "    EPSS: {}% exploitation probability ({}th percentile){}\n",
            pct, ptile, emoji
        ));
    }

    // Sub-items for supply chain findings (tree format)
    if let Some(ref items) = finding.sub_items {
        for (i, item) in items.iter().enumerate() {
            let prefix = if i == items.len() - 1 {
                "\u{2514}" // └
            } else {
                "\u{251C}" // ├
            };
            out.push_str(&format!("    {} {}\n", prefix, item));
        }
    }

    out.push_str(&format!(
        "    {} {}\n\n",
        "Fix:".green().bold(),
        finding.fix
    ));

    out
}

fn render_osv_stats(stats: &OsvStats) -> String {
    format!(
        "  {} Live CVE check: queried OSV for {} {} ({} new {} found)\n",
        "●".cyan(),
        stats.packages_queried,
        if stats.packages_queried == 1 {
            "package"
        } else {
            "packages"
        },
        stats.new_vulnerabilities,
        if stats.new_vulnerabilities == 1 {
            "vulnerability"
        } else {
            "vulnerabilities"
        },
    )
}

fn render_score(result: &ScanResult) -> String {
    let (score, grade) = (result.score, &result.grade);

    let bar_width = 30;
    let filled = (score as usize * bar_width) / 100;
    let empty = bar_width - filled;

    let bar_char = "█";
    let empty_char = "░";

    let bar = format!("{}{}", bar_char.repeat(filled), empty_char.repeat(empty));

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

    let top = format!(
        "  {}",
        "╔══════════════════════════════════════════════════════════════╗".dimmed()
    );
    let mid = format!(
        "  {}  Score: {}/100  {}  Grade: {}{}{}",
        "║".dimmed(),
        score,
        colored_bar,
        colored_grade,
        " ".repeat(62usize.saturating_sub(41 + grade.len())),
        "║".dimmed(),
    );
    let bot = format!(
        "  {}",
        "╚══════════════════════════════════════════════════════════════╝".dimmed()
    );
    format!("{}\n{}\n{}\n", top, mid, bot)
}

/// Render a discovery report in terminal format.
pub fn render_discover(configs: &[DiscoveredConfig]) -> String {
    let mut out = String::new();

    out.push('\n');
    out.push_str(&render_header());
    out.push('\n');

    let existing: Vec<&DiscoveredConfig> = configs.iter().filter(|c| c.exists).collect();
    let missing: Vec<&DiscoveredConfig> = configs.iter().filter(|c| !c.exists).collect();

    let total_servers: usize = existing.iter().map(|c| c.server_count).sum();

    out.push_str(&format!(
        "  {} Discovered {} {} ({} with MCP configs, {} {})\n\n",
        "●".green(),
        configs.len(),
        if configs.len() == 1 {
            "location"
        } else {
            "locations"
        },
        existing.len(),
        total_servers,
        if total_servers == 1 {
            "server"
        } else {
            "servers"
        },
    ));

    if !existing.is_empty() {
        let top = format!(
            "  {}",
            "┌──────────────────────────────────────────────────────────────┐".green()
        );
        let mid = format!(
            "  {}  {}{}{}",
            "│".green(),
            "Found Configurations".green().bold(),
            " ".repeat(62 - 4 - 20),
            "│".green()
        );
        let bot = format!(
            "  {}",
            "└──────────────────────────────────────────────────────────────┘".green()
        );
        out.push_str(&format!("{}\n{}\n{}\n\n", top, mid, bot));

        for config in &existing {
            out.push_str(&format!(
                "  {} {}\n",
                "✔".green().bold(),
                config.path.bold()
            ));
            out.push_str(&format!(
                "    Source: {}  Servers: {}\n",
                config.source.cyan(),
                config.server_count
            ));
            if !config.servers.is_empty() {
                for (i, name) in config.servers.iter().enumerate() {
                    let prefix = if i == config.servers.len() - 1 {
                        "└"
                    } else {
                        "├"
                    };
                    out.push_str(&format!("    {} {}\n", prefix, name.dimmed()));
                }
            }
            out.push('\n');
        }
    }

    if !missing.is_empty() {
        out.push_str(&format!(
            "  {} {}\n\n",
            "Checked but not found:".dimmed(),
            format!("({} locations)", missing.len()).dimmed()
        ));
        for config in &missing {
            out.push_str(&format!(
                "    {} {} {}\n",
                "○".dimmed(),
                config.path.dimmed(),
                format!("({})", config.source).dimmed()
            ));
        }
        out.push('\n');
    }

    // Summary line with checked/found/server totals
    out.push_str(&format!(
        "  Summary: checked {} {}, found {} {}, {} {} total\n\n",
        configs.len(),
        if configs.len() == 1 {
            "location"
        } else {
            "locations"
        },
        existing.len(),
        if existing.len() == 1 {
            "config"
        } else {
            "configs"
        },
        total_servers,
        if total_servers == 1 {
            "server"
        } else {
            "servers"
        },
    ));

    out
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
            osv_stats: None,
            suppressed_count: 0,
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
        assert!(output.contains("CRITICAL"));
        assert!(output.contains("Test finding"));
        assert!(output.contains("Test fix"));
    }

    #[test]
    fn test_render_with_epss() {
        use crate::rules::EpssData;
        let result = ScanResult {
            findings: vec![Finding {
                rule_id: "AW-006".to_string(),
                severity: Severity::High,
                title: "CVE-2025-53110: Path traversal".to_string(),
                message: "Test".to_string(),
                fix: "Upgrade".to_string(),
                config_file: "test.json".to_string(),
                server_name: "test".to_string(),
                source: Some("osv".to_string()),
                epss: Some(EpssData {
                    probability: 0.72,
                    percentile: 0.95,
                }),
                sub_items: None,
            }],
            configs_scanned: 1,
            servers_scanned: 1,
            score: 90,
            grade: "A".to_string(),
            duration_ms: 1,
            osv_stats: None,
            suppressed_count: 0,
        };
        let output = render(&result);
        assert!(output.contains("EPSS: 72% exploitation probability"));
        assert!(output.contains("95th percentile"));
    }

    #[test]
    fn test_render_with_sub_items() {
        let result = ScanResult {
            findings: vec![Finding {
                rule_id: "AW-011".to_string(),
                severity: Severity::High,
                title: "Supply chain risk: HIGH for test-pkg".to_string(),
                message: "Test".to_string(),
                fix: "Review".to_string(),
                config_file: "test.json".to_string(),
                server_name: "test".to_string(),
                source: Some("supply-chain".to_string()),
                epss: None,
                sub_items: Some(vec![
                    "Single maintainer (account takeover risk)".to_string(),
                    "Has postinstall script".to_string(),
                    "43 weekly downloads".to_string(),
                ]),
            }],
            configs_scanned: 1,
            servers_scanned: 1,
            score: 90,
            grade: "A".to_string(),
            duration_ms: 1,
            osv_stats: None,
            suppressed_count: 0,
        };
        let output = render(&result);
        assert!(output.contains("Supply chain risk"));
        assert!(output.contains("Single maintainer"));
        assert!(output.contains("postinstall"));
    }

    #[test]
    fn test_render_discover_with_configs() {
        let configs = vec![
            DiscoveredConfig {
                path: "/home/user/.mcp.json".to_string(),
                source: "Generic (~/.mcp.json)".to_string(),
                exists: true,
                server_count: 2,
                servers: vec!["server-a".to_string(), "server-b".to_string()],
            },
            DiscoveredConfig {
                path: "/home/user/.config/Claude/claude_desktop_config.json".to_string(),
                source: "Claude Desktop".to_string(),
                exists: false,
                server_count: 0,
                servers: vec![],
            },
        ];
        let output = render_discover(&configs);
        assert!(output.contains("agentwise"));
        assert!(output.contains("2 locations"));
        assert!(output.contains("server-a"));
        assert!(output.contains("server-b"));
        assert!(output.contains("Claude Desktop"));
        assert!(output.contains("not found"));
        // Summary line
        assert!(output.contains("Summary:"));
        assert!(output.contains("checked 2 locations"));
        assert!(output.contains("found 1 config"));
        assert!(output.contains("2 servers total"));
    }

    #[test]
    fn test_render_discover_empty() {
        let configs: Vec<DiscoveredConfig> = vec![];
        let output = render_discover(&configs);
        assert!(output.contains("0 locations"));
        assert!(output.contains("Summary:"));
        assert!(output.contains("checked 0 locations"));
    }
}
