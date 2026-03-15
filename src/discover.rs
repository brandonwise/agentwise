use crate::config::{self, McpConfig};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::env;
use std::path::{Path, PathBuf};

/// A discovered MCP configuration file location.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredConfig {
    pub path: String,
    pub source: String,
    pub exists: bool,
    pub server_count: usize,
    pub servers: Vec<String>,
}

/// Discover all known MCP configuration file locations across the system.
/// Returns a deduplicated list of candidate config paths with metadata.
pub fn discover_configs() -> Vec<DiscoveredConfig> {
    let mut seen = HashSet::new();
    let mut results = Vec::new();

    let home = home_dir();
    let cwd = env::current_dir().ok();

    // Claude Desktop
    for path in claude_desktop_paths(&home) {
        add_candidate(&mut results, &mut seen, path, "Claude Desktop");
    }

    // Claude Code project-level: walk up from cwd
    if let Some(ref cwd) = cwd {
        for dir in walk_up(cwd) {
            add_candidate(
                &mut results,
                &mut seen,
                dir.join(".mcp.json"),
                "Claude Code (project)",
            );
            add_candidate(
                &mut results,
                &mut seen,
                dir.join(".claude").join("mcp.json"),
                "Claude Code (project)",
            );
        }
    }

    // Cursor global
    for path in cursor_global_paths(&home) {
        add_candidate(&mut results, &mut seen, path, "Cursor (global)");
    }

    // Cursor project-level: walk up from cwd
    if let Some(ref cwd) = cwd {
        for dir in walk_up(cwd) {
            add_candidate(
                &mut results,
                &mut seen,
                dir.join(".cursor").join("mcp.json"),
                "Cursor (project)",
            );
        }
    }

    // VS Code Continue global
    for path in vscode_continue_paths(&home) {
        add_candidate(&mut results, &mut seen, path, "VS Code Continue (global)");
    }

    // Windsurf global
    for path in windsurf_paths(&home) {
        add_candidate(&mut results, &mut seen, path, "Windsurf (global)");
    }

    // Zed settings.json
    for path in zed_paths(&home) {
        add_candidate(&mut results, &mut seen, path, "Zed");
    }

    // Generic ~/.mcp.json
    if let Some(ref home) = home {
        add_candidate(
            &mut results,
            &mut seen,
            home.join(".mcp.json"),
            "Generic (~/.mcp.json)",
        );
    }

    // Generic project-level .mcp.json and mcp.json walk up from cwd
    if let Some(ref cwd) = cwd {
        for dir in walk_up(cwd) {
            add_candidate(
                &mut results,
                &mut seen,
                dir.join(".mcp.json"),
                "Generic (project)",
            );
            add_candidate(
                &mut results,
                &mut seen,
                dir.join("mcp.json"),
                "Generic (project)",
            );
        }
    }

    results
}

/// Return only the configs that exist on disk.
pub fn discover_existing() -> Vec<DiscoveredConfig> {
    discover_configs()
        .into_iter()
        .filter(|c| c.exists)
        .collect()
}

/// Return paths of all existing discovered configs.
pub fn discover_existing_paths() -> Vec<String> {
    discover_existing().iter().map(|c| c.path.clone()).collect()
}

fn add_candidate(
    results: &mut Vec<DiscoveredConfig>,
    seen: &mut HashSet<String>,
    path: PathBuf,
    source: &str,
) {
    let canonical = match path.canonicalize() {
        Ok(c) => c.display().to_string(),
        Err(_) => path.display().to_string(),
    };

    if !seen.insert(canonical.clone()) {
        return;
    }

    let (exists, server_count, servers) = if path.is_file() {
        probe_config(&path, source)
    } else {
        (false, 0, vec![])
    };

    results.push(DiscoveredConfig {
        path: canonical,
        source: source.to_string(),
        exists,
        server_count,
        servers,
    });
}

fn probe_config(path: &Path, source: &str) -> (bool, usize, Vec<String>) {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return (true, 0, vec![]),
    };

    // Zed uses a different structure: settings.json with "lsp" -> "mcpServers" or top-level mcpServers
    if source == "Zed" {
        return probe_zed_config(&content);
    }

    match config::parse_config(&content) {
        Ok(cfg) => {
            let names: Vec<String> = server_names_sorted(&cfg);
            (true, names.len(), names)
        }
        Err(_) => (true, 0, vec![]),
    }
}

fn probe_zed_config(content: &str) -> (bool, usize, Vec<String>) {
    // Zed settings.json may have mcpServers at top level or nested
    let val: serde_json::Value = match serde_json::from_str(content) {
        Ok(v) => v,
        Err(_) => return (true, 0, vec![]),
    };

    // Try top-level mcpServers
    if let Some(servers) = val.get("mcpServers").and_then(|v| v.as_object()) {
        let names: Vec<String> = servers.keys().cloned().collect();
        let count = names.len();
        return (true, count, sorted(names));
    }

    // Try context_servers key (Zed's native format)
    if let Some(servers) = val.get("context_servers").and_then(|v| v.as_object()) {
        let names: Vec<String> = servers.keys().cloned().collect();
        let count = names.len();
        return (true, count, sorted(names));
    }

    (true, 0, vec![])
}

fn server_names_sorted(cfg: &McpConfig) -> Vec<String> {
    sorted(cfg.mcp_servers.keys().cloned().collect())
}

fn sorted(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v
}

fn home_dir() -> Option<PathBuf> {
    // Use HOME on Unix, USERPROFILE on Windows
    env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

/// Expand a leading `~/` in a path string to the user's home directory.
#[cfg(test)]
fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = home_dir() {
            return home.join(rest);
        }
    }
    PathBuf::from(path)
}

/// Walk up from a directory to the filesystem root.
fn walk_up(start: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    let mut current = start.to_path_buf();
    loop {
        dirs.push(current.clone());
        match current.parent() {
            Some(parent) if parent != current => current = parent.to_path_buf(),
            _ => break,
        }
    }
    dirs
}

// --- Platform-specific path generators ---

fn claude_desktop_paths(home: &Option<PathBuf>) -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if cfg!(target_os = "macos") {
        if let Some(ref h) = home {
            paths.push(
                h.join("Library")
                    .join("Application Support")
                    .join("Claude")
                    .join("claude_desktop_config.json"),
            );
        }
    }

    if cfg!(target_os = "linux") {
        if let Some(ref h) = home {
            paths.push(
                h.join(".config")
                    .join("Claude")
                    .join("claude_desktop_config.json"),
            );
        }
    }

    if cfg!(target_os = "windows") {
        if let Some(appdata) = env::var_os("APPDATA") {
            paths.push(
                PathBuf::from(appdata)
                    .join("Claude")
                    .join("claude_desktop_config.json"),
            );
        }
    }

    paths
}

fn cursor_global_paths(home: &Option<PathBuf>) -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if cfg!(target_os = "macos") {
        if let Some(ref h) = home {
            paths.push(
                h.join("Library")
                    .join("Application Support")
                    .join("Cursor")
                    .join("User")
                    .join("globalStorage")
                    .join("cursor.mcp")
                    .join("mcp.json"),
            );
        }
    }

    if cfg!(target_os = "linux") {
        if let Some(ref h) = home {
            paths.push(
                h.join(".config")
                    .join("Cursor")
                    .join("User")
                    .join("globalStorage")
                    .join("cursor.mcp")
                    .join("mcp.json"),
            );
        }
    }

    if cfg!(target_os = "windows") {
        if let Some(appdata) = env::var_os("APPDATA") {
            paths.push(
                PathBuf::from(appdata)
                    .join("Cursor")
                    .join("User")
                    .join("globalStorage")
                    .join("cursor.mcp")
                    .join("mcp.json"),
            );
        }
    }

    paths
}

fn vscode_continue_paths(home: &Option<PathBuf>) -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if cfg!(target_os = "macos") {
        if let Some(ref h) = home {
            paths.push(
                h.join("Library")
                    .join("Application Support")
                    .join("Code")
                    .join("User")
                    .join("globalStorage")
                    .join("continue.continue")
                    .join("config.json"),
            );
        }
    }

    if cfg!(target_os = "linux") {
        if let Some(ref h) = home {
            paths.push(
                h.join(".config")
                    .join("Code")
                    .join("User")
                    .join("globalStorage")
                    .join("continue.continue")
                    .join("config.json"),
            );
        }
    }

    if cfg!(target_os = "windows") {
        if let Some(appdata) = env::var_os("APPDATA") {
            paths.push(
                PathBuf::from(appdata)
                    .join("Code")
                    .join("User")
                    .join("globalStorage")
                    .join("continue.continue")
                    .join("config.json"),
            );
        }
    }

    paths
}

fn windsurf_paths(home: &Option<PathBuf>) -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if cfg!(target_os = "macos") {
        if let Some(ref h) = home {
            paths.push(
                h.join("Library")
                    .join("Application Support")
                    .join("Windsurf")
                    .join("User")
                    .join("globalStorage")
                    .join("codeium.windsurf")
                    .join("mcp.json"),
            );
        }
    }

    if cfg!(target_os = "linux") {
        if let Some(ref h) = home {
            paths.push(
                h.join(".config")
                    .join("Windsurf")
                    .join("User")
                    .join("globalStorage")
                    .join("codeium.windsurf")
                    .join("mcp.json"),
            );
        }
    }

    if cfg!(target_os = "windows") {
        if let Some(appdata) = env::var_os("APPDATA") {
            paths.push(
                PathBuf::from(appdata)
                    .join("Windsurf")
                    .join("User")
                    .join("globalStorage")
                    .join("codeium.windsurf")
                    .join("mcp.json"),
            );
        }
    }

    paths
}

fn zed_paths(home: &Option<PathBuf>) -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if cfg!(target_os = "macos") {
        if let Some(ref h) = home {
            paths.push(
                h.join("Library")
                    .join("Application Support")
                    .join("Zed")
                    .join("settings.json"),
            );
        }
    }

    if cfg!(target_os = "linux") {
        if let Some(ref h) = home {
            paths.push(h.join(".config").join("zed").join("settings.json"));
        }
    }

    paths
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_home_dir_returns_some() {
        // HOME should be set in test env
        let home = home_dir();
        assert!(home.is_some());
    }

    #[test]
    fn test_walk_up_from_nested_dir() {
        let path = PathBuf::from("/a/b/c/d");
        let dirs = walk_up(&path);
        assert_eq!(dirs[0], PathBuf::from("/a/b/c/d"));
        assert_eq!(dirs[1], PathBuf::from("/a/b/c"));
        assert_eq!(dirs[2], PathBuf::from("/a/b"));
        assert_eq!(dirs[3], PathBuf::from("/a"));
        assert_eq!(dirs[4], PathBuf::from("/"));
        assert_eq!(dirs.len(), 5);
    }

    #[test]
    fn test_walk_up_root() {
        let dirs = walk_up(Path::new("/"));
        assert_eq!(dirs.len(), 1);
        assert_eq!(dirs[0], PathBuf::from("/"));
    }

    #[test]
    fn test_discovered_config_serialization() {
        let dc = DiscoveredConfig {
            path: "/tmp/test.json".to_string(),
            source: "Test".to_string(),
            exists: true,
            server_count: 2,
            servers: vec!["server-a".to_string(), "server-b".to_string()],
        };
        let json = serde_json::to_string(&dc).unwrap();
        let parsed: DiscoveredConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.path, "/tmp/test.json");
        assert_eq!(parsed.source, "Test");
        assert!(parsed.exists);
        assert_eq!(parsed.server_count, 2);
        assert_eq!(parsed.servers.len(), 2);
    }

    #[test]
    fn test_discovered_config_json_fields() {
        let dc = DiscoveredConfig {
            path: "/test".to_string(),
            source: "Claude Desktop".to_string(),
            exists: false,
            server_count: 0,
            servers: vec![],
        };
        let val: serde_json::Value = serde_json::to_value(&dc).unwrap();
        assert!(val.get("path").is_some());
        assert!(val.get("source").is_some());
        assert!(val.get("exists").is_some());
        assert!(val.get("server_count").is_some());
        assert!(val.get("servers").is_some());
    }

    #[test]
    fn test_claude_desktop_paths_nonempty() {
        let home = Some(PathBuf::from("/home/testuser"));
        let paths = claude_desktop_paths(&home);
        // On macOS or Linux at least one path
        assert!(!paths.is_empty() || cfg!(target_os = "windows"));
    }

    #[test]
    fn test_deduplication() {
        let mut seen = HashSet::new();
        let mut results = Vec::new();
        let tmp = std::env::temp_dir().join("agentwise_test_dedup.json");
        // Add same path twice
        add_candidate(&mut results, &mut seen, tmp.clone(), "Source A");
        add_candidate(&mut results, &mut seen, tmp, "Source B");
        // Should only have one entry
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_probe_config_with_real_file() {
        let tmp = std::env::temp_dir().join("agentwise_probe_test.json");
        fs::write(
            &tmp,
            r#"{"mcpServers": {"alpha": {"command": "test"}, "beta": {"command": "test2"}}}"#,
        )
        .unwrap();
        let (exists, count, servers) = probe_config(&tmp, "Test");
        assert!(exists);
        assert_eq!(count, 2);
        assert!(servers.contains(&"alpha".to_string()));
        assert!(servers.contains(&"beta".to_string()));
        fs::remove_file(&tmp).ok();
    }

    #[test]
    fn test_probe_config_invalid_json() {
        let tmp = std::env::temp_dir().join("agentwise_probe_bad.json");
        fs::write(&tmp, "not json at all").unwrap();
        let (exists, count, servers) = probe_config(&tmp, "Test");
        assert!(exists);
        assert_eq!(count, 0);
        assert!(servers.is_empty());
        fs::remove_file(&tmp).ok();
    }

    #[test]
    fn test_probe_zed_config_with_mcp_servers() {
        let content = r#"{"mcpServers": {"zed-server": {"command": "test"}}}"#;
        let (exists, count, servers) = probe_zed_config(content);
        assert!(exists);
        assert_eq!(count, 1);
        assert_eq!(servers[0], "zed-server");
    }

    #[test]
    fn test_probe_zed_config_with_context_servers() {
        let content = r#"{"context_servers": {"my-ctx": {}}}"#;
        let (exists, count, servers) = probe_zed_config(content);
        assert!(exists);
        assert_eq!(count, 1);
        assert_eq!(servers[0], "my-ctx");
    }

    #[test]
    fn test_discover_configs_returns_vec() {
        // Smoke test: should not panic and return a vec
        let configs = discover_configs();
        assert!(!configs.is_empty() || configs.is_empty()); // just no panic
    }

    #[test]
    fn test_discover_existing_paths_subset() {
        let all = discover_configs();
        let existing = discover_existing();
        // All existing should be a subset of all
        assert!(existing.len() <= all.len());
        for e in &existing {
            assert!(e.exists);
        }
    }

    #[test]
    fn test_sorted_helper() {
        let v = vec!["c".to_string(), "a".to_string(), "b".to_string()];
        let s = sorted(v);
        assert_eq!(s, vec!["a", "b", "c"]);
    }

    #[test]
    fn test_discover_json_output_validity() {
        let configs = discover_configs();
        let json = serde_json::to_string_pretty(&configs).unwrap();
        let parsed: Vec<DiscoveredConfig> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), configs.len());
    }

    #[test]
    fn test_expand_tilde_expands_home() {
        let expanded = expand_tilde("~/some/path");
        let home = home_dir().unwrap();
        assert_eq!(expanded, home.join("some/path"));
    }

    #[test]
    fn test_expand_tilde_no_tilde() {
        let expanded = expand_tilde("/absolute/path");
        assert_eq!(expanded, PathBuf::from("/absolute/path"));
    }

    #[test]
    fn test_expand_tilde_bare_tilde() {
        // "~" without slash should not expand
        let expanded = expand_tilde("~");
        assert_eq!(expanded, PathBuf::from("~"));
    }

    #[test]
    fn test_claude_desktop_paths_contain_expected_segments() {
        let home = Some(PathBuf::from("/home/testuser"));
        let paths = claude_desktop_paths(&home);
        for p in &paths {
            let s = p.display().to_string();
            assert!(s.contains("Claude"), "path should contain 'Claude': {}", s);
            assert!(
                s.contains("claude_desktop_config.json"),
                "path should end with claude_desktop_config.json: {}",
                s
            );
        }
    }

    #[test]
    fn test_cursor_global_paths_contain_expected_segments() {
        let home = Some(PathBuf::from("/home/testuser"));
        let paths = cursor_global_paths(&home);
        for p in &paths {
            let s = p.display().to_string();
            assert!(s.contains("Cursor"), "path should contain 'Cursor': {}", s);
            assert!(
                s.contains("cursor.mcp"),
                "path should contain 'cursor.mcp': {}",
                s
            );
            assert!(
                s.ends_with("mcp.json"),
                "path should end with mcp.json: {}",
                s
            );
        }
    }

    #[test]
    fn test_vscode_continue_paths_contain_expected_segments() {
        let home = Some(PathBuf::from("/home/testuser"));
        let paths = vscode_continue_paths(&home);
        for p in &paths {
            let s = p.display().to_string();
            assert!(s.contains("Code"), "path should contain 'Code': {}", s);
            assert!(
                s.contains("continue.continue"),
                "path should contain 'continue.continue': {}",
                s
            );
            assert!(
                s.ends_with("config.json"),
                "path should end with config.json: {}",
                s
            );
        }
    }

    #[test]
    fn test_windsurf_paths_contain_expected_segments() {
        let home = Some(PathBuf::from("/home/testuser"));
        let paths = windsurf_paths(&home);
        for p in &paths {
            let s = p.display().to_string();
            assert!(
                s.contains("Windsurf") || s.contains("windsurf"),
                "path should contain 'Windsurf': {}",
                s
            );
            assert!(
                s.contains("codeium.windsurf"),
                "path should contain 'codeium.windsurf': {}",
                s
            );
            assert!(
                s.ends_with("mcp.json"),
                "path should end with mcp.json: {}",
                s
            );
        }
    }

    #[test]
    fn test_zed_paths_contain_expected_segments() {
        let home = Some(PathBuf::from("/home/testuser"));
        let paths = zed_paths(&home);
        for p in &paths {
            let s = p.display().to_string();
            assert!(
                s.contains("Zed") || s.contains("zed"),
                "path should contain 'Zed' or 'zed': {}",
                s
            );
            assert!(
                s.ends_with("settings.json"),
                "path should end with settings.json: {}",
                s
            );
        }
    }

    #[test]
    fn test_discover_with_mock_filesystem() {
        let tmp = std::env::temp_dir().join("agentwise_discover_mock");
        let _ = fs::remove_dir_all(&tmp);
        let cursor_dir = tmp.join(".cursor").join("mcp.json");
        // Create parent dirs
        fs::create_dir_all(cursor_dir.parent().unwrap()).unwrap();
        fs::write(
            &cursor_dir,
            r#"{"mcpServers": {"mock-server": {"command": "echo"}}}"#,
        )
        .unwrap();

        // Probe directly to verify discovery logic on the temp file
        let (exists, count, servers) = probe_config(&cursor_dir, "Cursor (project)");
        assert!(exists);
        assert_eq!(count, 1);
        assert_eq!(servers, vec!["mock-server"]);

        fs::remove_dir_all(&tmp).ok();
    }
}
