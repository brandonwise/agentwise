use crate::config::{load_config, ParsedConfig};
use crate::rules::{all_rules, Finding, Severity};
use crate::score::compute_score;
use std::path::Path;
use std::time::Instant;
use walkdir::WalkDir;

/// Known MCP config file names to search for.
const CONFIG_FILE_NAMES: &[&str] = &[
    ".mcp.json",
    "mcp.json",
    "claude_desktop_config.json",
];

/// Result of a complete scan.
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub findings: Vec<Finding>,
    pub configs_scanned: usize,
    pub servers_scanned: usize,
    pub score: i32,
    pub grade: String,
    pub duration_ms: u64,
}

/// Run a full scan on the given path.
/// If path is a file, scan just that file.
/// If path is a directory, discover and scan all MCP configs.
pub fn scan(path: &str) -> ScanResult {
    let start = Instant::now();
    let p = Path::new(path);

    let configs = if p.is_file() {
        match load_config(p) {
            Ok(config) => vec![config],
            Err(e) => {
                eprintln!("Warning: {}", e);
                vec![]
            }
        }
    } else if p.is_dir() {
        discover_configs(p)
    } else {
        eprintln!("Warning: Path does not exist: {}", path);
        vec![]
    };

    let rules = all_rules();
    let mut findings = Vec::new();
    let mut servers_scanned = 0;

    for parsed_config in &configs {
        for (server_name, server) in &parsed_config.config.mcp_servers {
            // Skip disabled servers
            if server.disabled == Some(true) {
                continue;
            }
            servers_scanned += 1;

            for rule in &rules {
                let mut rule_findings =
                    rule.check(server_name, server, &parsed_config.file_path);
                findings.append(&mut rule_findings);
            }
        }
    }

    let severities: Vec<Severity> = findings.iter().map(|f| f.severity).collect();
    let (score, grade) = compute_score(&severities);

    let duration = start.elapsed();
    let duration_ms = duration.as_millis() as u64;

    ScanResult {
        findings,
        configs_scanned: configs.len(),
        servers_scanned,
        score,
        grade,
        duration_ms,
    }
}

/// Discover MCP config files in a directory.
fn discover_configs(dir: &Path) -> Vec<ParsedConfig> {
    let mut configs = Vec::new();

    for entry in WalkDir::new(dir)
        .max_depth(5)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }

        let file_name = entry.file_name().to_string_lossy();

        // Skip hidden dirs (except .mcp.json and .cursor)
        let path = entry.path();
        let path_str = path.to_string_lossy();
        if path_str.contains("node_modules")
            || path_str.contains(".git/")
            || path_str.contains("target/")
        {
            continue;
        }

        let is_config = CONFIG_FILE_NAMES.iter().any(|name| file_name == *name)
            || file_name.ends_with(".mcp.json");

        if is_config {
            match load_config(path) {
                Ok(config) => {
                    if !config.config.mcp_servers.is_empty() {
                        configs.push(config);
                    }
                }
                Err(e) => {
                    eprintln!("Warning: {}", e);
                }
            }
        }
    }

    configs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_vulnerable_config() {
        let result = scan("testdata/vulnerable-mcp.json");
        assert!(result.configs_scanned == 1);
        assert!(result.servers_scanned > 0);
        assert!(!result.findings.is_empty());
        assert!(result.score < 100);
    }

    #[test]
    fn test_scan_clean_config() {
        let result = scan("testdata/clean-mcp.json");
        assert!(result.configs_scanned == 1);
        // Clean config still gets AW-007 (no allowlist) since most servers don't set it
        assert!(result.score > 50);
    }

    #[test]
    fn test_scan_empty_config() {
        let result = scan("testdata/empty-config.json");
        // Single file scan always loads the file, but it has 0 servers
        assert_eq!(result.configs_scanned, 1);
        assert_eq!(result.servers_scanned, 0);
        assert_eq!(result.findings.len(), 0);
        assert_eq!(result.score, 100);
    }

    #[test]
    fn test_scan_directory() {
        // testdata/project/ contains a .mcp.json file
        let result = scan("testdata/project/");
        assert_eq!(result.configs_scanned, 1);
        assert!(result.servers_scanned > 0);
    }

    #[test]
    fn test_scan_nonexistent() {
        let result = scan("nonexistent/path");
        assert_eq!(result.configs_scanned, 0);
        assert_eq!(result.score, 100);
    }
}
