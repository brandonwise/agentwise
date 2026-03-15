use std::process::Command;

fn agentwise() -> Command {
    Command::new(env!("CARGO_BIN_EXE_agentwise"))
}

// ── CLI basics ──────────────────────────────────────────────

#[test]
fn test_cli_version() {
    let output = agentwise().arg("--version").output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("agentwise"));
}

#[test]
fn test_cli_help() {
    let output = agentwise().arg("--help").output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("scan"));
}

#[test]
fn test_scan_help() {
    let output = agentwise()
        .args(["scan", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--format"));
    assert!(stdout.contains("--fail-on"));
}

// ── Scanning files ──────────────────────────────────────────

#[test]
fn test_scan_vulnerable_file() {
    let output = agentwise()
        .args(["scan", "testdata/vulnerable-mcp.json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("CRITICAL"));
}

#[test]
fn test_scan_clean_file() {
    let output = agentwise()
        .args(["scan", "testdata/clean-mcp.json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Score:"));
}

#[test]
fn test_scan_directory() {
    let output = agentwise()
        .args(["scan", "testdata/"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("agentwise"));
}

#[test]
fn test_scan_empty_config() {
    let output = agentwise()
        .args(["scan", "testdata/empty-config.json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("100"));
}

// ── Output formats ──────────────────────────────────────────

#[test]
fn test_json_output() {
    let output = agentwise()
        .args(["scan", "testdata/vulnerable-mcp.json", "--format", "json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(parsed["findings"].is_array());
    assert!(parsed["score"].is_number());
}

#[test]
fn test_sarif_output() {
    let output = agentwise()
        .args(["scan", "testdata/vulnerable-mcp.json", "--format", "sarif"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(parsed["version"], "2.1.0");
    assert!(parsed["runs"].is_array());
}

#[test]
fn test_json_clean_config() {
    let output = agentwise()
        .args(["scan", "testdata/clean-mcp.json", "--format", "json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(parsed["score"].as_i64().unwrap() > 50);
}

// ── --fail-on flag ──────────────────────────────────────────

#[test]
fn test_fail_on_critical_with_criticals() {
    let output = agentwise()
        .args([
            "scan",
            "testdata/vulnerable-mcp.json",
            "--fail-on",
            "critical",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
}

#[test]
fn test_fail_on_critical_clean_config() {
    let output = agentwise()
        .args([
            "scan",
            "testdata/clean-mcp.json",
            "--fail-on",
            "critical",
        ])
        .output()
        .unwrap();
    // Clean config shouldn't have critical findings
    assert!(output.status.success());
}

#[test]
fn test_fail_on_low_catches_everything() {
    let output = agentwise()
        .args([
            "scan",
            "testdata/vulnerable-mcp.json",
            "--fail-on",
            "low",
        ])
        .output()
        .unwrap();
    // Should fail because there are findings at or above low
    assert!(!output.status.success());
}

// ── Specific rule detections ────────────────────────────────

#[test]
fn test_detects_sse_no_auth() {
    let output = agentwise()
        .args(["scan", "testdata/sse-no-auth.json", "--format", "json"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let findings = parsed["findings"].as_array().unwrap();
    assert!(findings.iter().any(|f| f["rule_id"] == "AW-001"));
}

#[test]
fn test_detects_insecure_transport() {
    let output = agentwise()
        .args(["scan", "testdata/sse-no-auth.json", "--format", "json"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let findings = parsed["findings"].as_array().unwrap();
    assert!(findings.iter().any(|f| f["rule_id"] == "AW-005"));
}

#[test]
fn test_detects_secrets() {
    let output = agentwise()
        .args([
            "scan",
            "testdata/vulnerable-mcp.json",
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let findings = parsed["findings"].as_array().unwrap();
    assert!(findings.iter().any(|f| f["rule_id"] == "AW-004"));
}

#[test]
fn test_detects_shell_access() {
    let output = agentwise()
        .args([
            "scan",
            "testdata/vulnerable-mcp.json",
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let findings = parsed["findings"].as_array().unwrap();
    assert!(findings.iter().any(|f| f["rule_id"] == "AW-003"));
}

#[test]
fn test_detects_filesystem_issues() {
    let output = agentwise()
        .args([
            "scan",
            "testdata/vulnerable-mcp.json",
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let findings = parsed["findings"].as_array().unwrap();
    assert!(findings.iter().any(|f| f["rule_id"] == "AW-002"));
}

#[test]
fn test_detects_known_cves() {
    let output = agentwise()
        .args([
            "scan",
            "testdata/vulnerable-mcp.json",
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let findings = parsed["findings"].as_array().unwrap();
    assert!(findings.iter().any(|f| f["rule_id"] == "AW-006"));
}

#[test]
fn test_detects_injection_risk() {
    let output = agentwise()
        .args([
            "scan",
            "testdata/injection-risk.json",
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let findings = parsed["findings"].as_array().unwrap();
    assert!(findings.iter().any(|f| f["rule_id"] == "AW-010"));
}

#[test]
fn test_detects_missing_allowlist() {
    let output = agentwise()
        .args([
            "scan",
            "testdata/vulnerable-mcp.json",
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let findings = parsed["findings"].as_array().unwrap();
    assert!(findings.iter().any(|f| f["rule_id"] == "AW-007"));
}

#[test]
fn test_detects_network_access() {
    let output = agentwise()
        .args([
            "scan",
            "testdata/vulnerable-mcp.json",
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let findings = parsed["findings"].as_array().unwrap();
    // fetch server in vulnerable config should trigger AW-009
    assert!(findings.iter().any(|f| f["rule_id"] == "AW-009"));
}

#[test]
fn test_detects_cve_in_claude_desktop() {
    let output = agentwise()
        .args([
            "scan",
            "testdata/claude-desktop.json",
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let findings = parsed["findings"].as_array().unwrap();
    // Should detect CVE for filesystem@0.5.0 and git@0.6.2
    let cve_findings: Vec<_> = findings
        .iter()
        .filter(|f| f["rule_id"] == "AW-006")
        .collect();
    assert!(
        cve_findings.len() >= 2,
        "Expected at least 2 CVE findings, got {}",
        cve_findings.len()
    );
}

// ── scan --auto ─────────────────────────────────────────────

#[test]
fn test_scan_auto_runs_discovery() {
    let output = agentwise()
        .args(["scan", "--auto", "--format", "json"])
        .output()
        .unwrap();
    // --auto should succeed (exit 0) whether or not configs exist on this machine
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stdout.is_empty() {
        // No configs found — stderr should say so
        assert!(
            stderr.contains("No MCP configurations found"),
            "Expected 'No MCP configurations found' in stderr, got: {}",
            stderr
        );
    } else {
        // Configs found — output should be valid JSON with findings array
        let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        assert!(parsed["findings"].is_array());
        assert!(parsed["score"].is_number());
    }
}

// ── Nonexistent paths ───────────────────────────────────────

#[test]
fn test_scan_nonexistent_path() {
    let output = agentwise()
        .args(["scan", "nonexistent/path/file.json"])
        .output()
        .unwrap();
    // Should still succeed (just no findings)
    assert!(output.status.success());
}
