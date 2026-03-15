use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// Represents a parsed MCP configuration file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpConfig {
    #[serde(rename = "mcpServers", default)]
    pub mcp_servers: HashMap<String, McpServer>,
}

/// Represents a single MCP server entry.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct McpServer {
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub args: Option<Vec<String>>,
    #[serde(default)]
    pub env: Option<HashMap<String, String>>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub transport: Option<String>,
    #[serde(rename = "allowedDirectories", default)]
    pub allowed_directories: Option<Vec<String>>,
    #[serde(rename = "allowedTools", default)]
    pub allowed_tools: Option<Vec<String>>,
    #[serde(default)]
    pub disabled: Option<bool>,
}

/// A config file that has been loaded and parsed.
#[derive(Debug, Clone)]
pub struct ParsedConfig {
    pub file_path: String,
    pub config: McpConfig,
}

/// Parse an MCP config from a JSON string.
pub fn parse_config(json: &str) -> Result<McpConfig, serde_json::Error> {
    serde_json::from_str(json)
}

/// Load and parse an MCP config from a file path.
pub fn load_config(path: &Path) -> Result<ParsedConfig, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;
    let config = parse_config(&content)
        .map_err(|e| format!("Failed to parse {}: {}", path.display(), e))?;
    Ok(ParsedConfig {
        file_path: path.display().to_string(),
        config,
    })
}

/// Extract package name and version from MCP server args.
/// Handles patterns like "@modelcontextprotocol/server-filesystem@0.5.0"
pub fn extract_package_info(server: &McpServer) -> Vec<(String, String)> {
    let mut packages = Vec::new();
    if let Some(args) = &server.args {
        for arg in args {
            // Match @scope/package@version or package@version
            if let Some((name, version)) = parse_package_version(arg) {
                packages.push((name, version));
            }
        }
    }
    // Also check command itself
    if let Some(cmd) = &server.command {
        if let Some((name, version)) = parse_package_version(cmd) {
            packages.push((name, version));
        }
    }
    packages
}

/// Extract all npm package names from MCP server config, with or without versions.
pub fn extract_all_package_names(server: &McpServer) -> Vec<String> {
    let mut names = Vec::new();

    // Get versioned packages first
    let versioned = extract_package_info(server);
    for (name, _) in &versioned {
        names.push(name.clone());
    }

    // Also look for unversioned package references in args
    if let Some(args) = &server.args {
        for arg in args {
            if let Some(name) = parse_package_name(arg) {
                if !names.contains(&name) {
                    names.push(name);
                }
            }
        }
    }

    names
}

/// Parse a potential npm package name from a string (ignoring version).
fn parse_package_name(s: &str) -> Option<String> {
    // Skip flags, paths, URLs
    if s.starts_with('-') || s.starts_with('/') || s.starts_with('.') || s.contains("://") {
        return None;
    }

    // Already handles versioned packages
    if let Some((name, _)) = parse_package_version(s) {
        return Some(name);
    }

    // Scoped unversioned: @scope/name
    if s.starts_with('@') && s[1..].contains('/') && !s[1..].contains('@') {
        return Some(s.to_string());
    }

    // Unscoped unversioned: name with hyphens (like "mcp-shell-server")
    if !s.is_empty()
        && !s.contains('/')
        && !s.contains('@')
        && s.chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return Some(s.to_string());
    }

    None
}

/// Parse a package@version string into (package_name, version).
fn parse_package_version(s: &str) -> Option<(String, String)> {
    // Handle scoped packages: @scope/name@version
    if let Some(rest) = s.strip_prefix('@') {
        // Find the second '@' which separates package from version
        if let Some(at_pos) = rest.find('@') {
            let name = &s[..at_pos + 1]; // include the leading @
            let version = &rest[at_pos + 1..];
            if !version.is_empty() && version.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                return Some((name.to_string(), version.to_string()));
            }
        }
    } else {
        // Unscoped package: name@version
        if let Some(at_pos) = s.find('@') {
            let name = &s[..at_pos];
            let version = &s[at_pos + 1..];
            if !name.is_empty()
                && !version.is_empty()
                && version.chars().next().is_some_and(|c| c.is_ascii_digit())
            {
                return Some((name.to_string(), version.to_string()));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_basic_config() {
        let json = r#"{
            "mcpServers": {
                "test": {
                    "command": "npx",
                    "args": ["-y", "some-package"]
                }
            }
        }"#;
        let config = parse_config(json).unwrap();
        assert_eq!(config.mcp_servers.len(), 1);
        assert!(config.mcp_servers.contains_key("test"));
    }

    #[test]
    fn test_parse_empty_config() {
        let json = r#"{"mcpServers": {}}"#;
        let config = parse_config(json).unwrap();
        assert!(config.mcp_servers.is_empty());
    }

    #[test]
    fn test_parse_config_with_all_fields() {
        let json = r#"{
            "mcpServers": {
                "remote": {
                    "url": "https://example.com/mcp",
                    "transport": "sse",
                    "env": {"TOKEN": "abc"},
                    "allowedTools": ["read"],
                    "allowedDirectories": ["/home"]
                }
            }
        }"#;
        let config = parse_config(json).unwrap();
        let server = &config.mcp_servers["remote"];
        assert_eq!(server.url.as_deref(), Some("https://example.com/mcp"));
        assert_eq!(server.transport.as_deref(), Some("sse"));
        assert!(server.allowed_tools.is_some());
        assert!(server.allowed_directories.is_some());
    }

    #[test]
    fn test_extract_scoped_package() {
        let server = McpServer {
            args: Some(vec![
                "-y".to_string(),
                "@modelcontextprotocol/server-filesystem@0.5.0".to_string(),
            ]),
            ..Default::default()
        };
        let packages = extract_package_info(&server);
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].0, "@modelcontextprotocol/server-filesystem");
        assert_eq!(packages[0].1, "0.5.0");
    }

    #[test]
    fn test_extract_unscoped_package() {
        let server = McpServer {
            args: Some(vec!["-y".to_string(), "mcp-package-docs@1.0.0".to_string()]),
            ..Default::default()
        };
        let packages = extract_package_info(&server);
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].0, "mcp-package-docs");
        assert_eq!(packages[0].1, "1.0.0");
    }

    #[test]
    fn test_extract_no_version() {
        let server = McpServer {
            args: Some(vec![
                "-y".to_string(),
                "@modelcontextprotocol/server-fetch".to_string(),
            ]),
            ..Default::default()
        };
        let packages = extract_package_info(&server);
        assert!(packages.is_empty());
    }

    #[test]
    fn test_extract_all_package_names_with_version() {
        let server = McpServer {
            args: Some(vec![
                "-y".to_string(),
                "@modelcontextprotocol/server-filesystem@0.5.0".to_string(),
            ]),
            ..Default::default()
        };
        let names = extract_all_package_names(&server);
        assert_eq!(names.len(), 1);
        assert_eq!(names[0], "@modelcontextprotocol/server-filesystem");
    }

    #[test]
    fn test_extract_all_package_names_without_version() {
        let server = McpServer {
            args: Some(vec![
                "-y".to_string(),
                "@modelcontextprotocol/server-fetch".to_string(),
            ]),
            ..Default::default()
        };
        let names = extract_all_package_names(&server);
        assert_eq!(names.len(), 1);
        assert_eq!(names[0], "@modelcontextprotocol/server-fetch");
    }

    #[test]
    fn test_extract_all_package_names_unscoped() {
        let server = McpServer {
            args: Some(vec!["-y".to_string(), "mcp-shell-server".to_string()]),
            ..Default::default()
        };
        let names = extract_all_package_names(&server);
        assert_eq!(names.len(), 1);
        assert_eq!(names[0], "mcp-shell-server");
    }

    #[test]
    fn test_extract_all_skips_flags_and_paths() {
        let server = McpServer {
            args: Some(vec![
                "-y".to_string(),
                "/home/user/data".to_string(),
                "mcp-remote".to_string(),
            ]),
            ..Default::default()
        };
        let names = extract_all_package_names(&server);
        assert_eq!(names.len(), 1);
        assert_eq!(names[0], "mcp-remote");
    }

    #[test]
    fn test_extract_all_no_duplicates() {
        let server = McpServer {
            args: Some(vec![
                "-y".to_string(),
                "@modelcontextprotocol/server-filesystem@0.5.0".to_string(),
            ]),
            ..Default::default()
        };
        let names = extract_all_package_names(&server);
        // Should not have duplicates even though both extract_package_info and parse_package_name find it
        assert_eq!(names.len(), 1);
    }
}
