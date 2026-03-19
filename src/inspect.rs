use crate::config::{extract_all_package_names, extract_package_info, McpServer};
use crate::scanner;
use serde::Serialize;
use std::fmt::Write;

const NETWORK_PATTERNS: &[&str] = &[
    "fetch",
    "server-fetch",
    "http-client",
    "web-request",
    "curl",
    "puppeteer",
    "browser",
    "playwright",
    "scraper",
    "crawl",
];

const DOMAIN_RESTRICTION_HINTS: &[&str] = &[
    "allowed_domains",
    "domain_whitelist",
    "allowed_urls",
    "allowed_hosts",
    "allowlist",
    "restrict",
    "origins",
    "localhost_only",
];

const FILESYSTEM_PATTERNS: &[&str] = &[
    "filesystem",
    "server-filesystem",
    "fs-server",
    "file-server",
];

const DANGEROUS_PATHS: &[&str] = &[
    "/", "C:\\", "C:/", "/home", "/Users", "/etc", "/var", "/root",
];

#[derive(Debug, Clone, Serialize)]
pub struct InspectResult {
    pub version: String,
    pub inspected_path: String,
    pub configs_scanned: usize,
    pub servers_scanned: usize,
    pub high_risk_servers: usize,
    pub servers: Vec<InspectServer>,
}

#[derive(Debug, Clone, Serialize)]
pub struct InspectServer {
    pub server_name: String,
    pub config_file: String,
    pub transport: String,
    pub command: Option<String>,
    pub packages: Vec<String>,
    pub versioned_packages: Vec<String>,
    pub auth_present: bool,
    pub allowlist_present: bool,
    pub network_restricted: bool,
    pub filesystem_restricted: bool,
    pub risk_tags: Vec<String>,
}

pub fn inspect(path: &str) -> InspectResult {
    let configs = scanner::discover_and_parse(path);

    let mut servers = Vec::new();

    for parsed in &configs {
        for (server_name, server) in &parsed.config.mcp_servers {
            if server.disabled == Some(true) {
                continue;
            }
            servers.push(inspect_server(server_name, &parsed.file_path, server));
        }
    }

    let high_risk_servers = servers
        .iter()
        .filter(|s| {
            s.risk_tags.iter().any(|t| t == "remote_no_auth")
                || s.risk_tags.iter().any(|t| t == "broad_filesystem")
                || s.risk_tags.len() >= 2
        })
        .count();

    InspectResult {
        version: env!("CARGO_PKG_VERSION").to_string(),
        inspected_path: path.to_string(),
        configs_scanned: configs.len(),
        servers_scanned: servers.len(),
        high_risk_servers,
        servers,
    }
}

fn inspect_server(server_name: &str, config_file: &str, server: &McpServer) -> InspectServer {
    let remote = is_remote(server);
    let transport = if remote { "remote" } else { "stdio" }.to_string();
    let auth_present = has_auth(server);
    let allowlist_present = server.allowed_tools.as_ref().is_some_and(|t| !t.is_empty());

    let network_tool = is_network_tool(server_name, server);
    let network_restricted = if network_tool {
        has_domain_restrictions(server)
    } else {
        true
    };

    let filesystem_tool = is_filesystem_tool(server_name, server);
    let filesystem_restricted = if filesystem_tool {
        has_safe_allowed_directories(server)
    } else {
        true
    };

    let mut packages = extract_all_package_names(server);
    packages.sort();
    packages.dedup();

    let mut versioned_packages: Vec<String> = extract_package_info(server)
        .into_iter()
        .map(|(name, version)| format!("{}@{}", name, version))
        .collect();
    versioned_packages.sort();
    versioned_packages.dedup();

    let mut risk_tags = Vec::new();
    if remote && !auth_present {
        risk_tags.push("remote_no_auth".to_string());
    }
    if !allowlist_present {
        risk_tags.push("no_allowlist".to_string());
    }
    if !network_restricted {
        risk_tags.push("unrestricted_network".to_string());
    }
    if !filesystem_restricted {
        risk_tags.push("broad_filesystem".to_string());
    }
    if !packages.is_empty() && versioned_packages.is_empty() {
        risk_tags.push("package_unpinned".to_string());
    }

    InspectServer {
        server_name: server_name.to_string(),
        config_file: config_file.to_string(),
        transport,
        command: server.command.clone(),
        packages,
        versioned_packages,
        auth_present,
        allowlist_present,
        network_restricted,
        filesystem_restricted,
        risk_tags,
    }
}

pub fn render_json(result: &InspectResult) -> Result<String, String> {
    serde_json::to_string_pretty(result)
        .map_err(|e| format!("Failed to serialize inspect JSON: {}", e))
}

pub fn render_terminal(result: &InspectResult) -> String {
    let mut out = String::new();

    let _ = writeln!(out, "\nagentwise inspect v{}", result.version);
    let _ = writeln!(out, "Path: {}", result.inspected_path);
    let _ = writeln!(
        out,
        "Scanned: {} config(s), {} server(s)\n",
        result.configs_scanned, result.servers_scanned
    );

    if result.servers.is_empty() {
        let _ = writeln!(out, "No MCP servers found.");
        return out;
    }

    let _ = writeln!(out, "High-risk servers: {}\n", result.high_risk_servers);

    for server in &result.servers {
        let _ = writeln!(out, "- {} ({})", server.server_name, server.config_file);
        let _ = writeln!(
            out,
            "  transport={} auth={} allowlist={} network_restricted={} filesystem_restricted={}",
            server.transport,
            yes_no(server.auth_present),
            yes_no(server.allowlist_present),
            yes_no(server.network_restricted),
            yes_no(server.filesystem_restricted)
        );

        if let Some(cmd) = &server.command {
            let _ = writeln!(out, "  command={}", cmd);
        }

        if !server.packages.is_empty() {
            let _ = writeln!(out, "  packages={}", server.packages.join(", "));
        }

        if !server.versioned_packages.is_empty() {
            let _ = writeln!(
                out,
                "  versioned_packages={}",
                server.versioned_packages.join(", ")
            );
        }

        if server.risk_tags.is_empty() {
            let _ = writeln!(out, "  risk_tags=none\n");
        } else {
            let _ = writeln!(out, "  risk_tags={}\n", server.risk_tags.join(", "));
        }
    }

    out
}

fn yes_no(v: bool) -> &'static str {
    if v {
        "yes"
    } else {
        "no"
    }
}

fn is_remote(server: &McpServer) -> bool {
    server.url.is_some()
        || matches!(
            server.transport.as_deref(),
            Some("sse") | Some("streamable-http") | Some("http")
        )
}

fn has_auth(server: &McpServer) -> bool {
    has_auth_env(server) || has_auth_headers(server) || has_auth_args(server)
}

fn has_auth_env(server: &McpServer) -> bool {
    server.env.as_ref().is_some_and(|env| {
        env.iter().any(|(k, v)| {
            let key = k.to_lowercase();
            let value = v.trim();
            value.len() > 2
                && (key.contains("authorization")
                    || key.contains("auth")
                    || key.contains("token")
                    || key.contains("api_key")
                    || key.contains("apikey")
                    || key.contains("secret")
                    || key.contains("bearer")
                    || key.contains("password"))
        })
    })
}

fn has_auth_headers(server: &McpServer) -> bool {
    server.headers.as_ref().is_some_and(|headers| {
        headers.keys().any(|k| {
            let key = k.to_lowercase();
            key.contains("authorization")
                || key == "x-api-key"
                || key == "api-key"
                || key.contains("bearer")
                || key.contains("cookie")
        })
    })
}

fn has_auth_args(server: &McpServer) -> bool {
    server.args.as_ref().is_some_and(|args| {
        let joined = args.join(" ").to_lowercase();
        joined.contains("--bearer")
            || joined.contains("--token")
            || joined.contains("--api-key")
            || joined.contains("authorization:")
            || joined.contains("x-api-key:")
    })
}

fn is_network_tool(server_name: &str, server: &McpServer) -> bool {
    let name_lower = server_name.to_lowercase();
    if NETWORK_PATTERNS.iter().any(|p| name_lower.contains(p)) {
        return true;
    }

    if let Some(command) = &server.command {
        let lower = command.to_lowercase();
        if NETWORK_PATTERNS.iter().any(|p| lower.contains(p)) {
            return true;
        }
    }

    if let Some(args) = &server.args {
        let joined = args.join(" ").to_lowercase();
        if NETWORK_PATTERNS.iter().any(|p| joined.contains(p)) {
            return true;
        }
    }

    false
}

fn has_domain_restrictions(server: &McpServer) -> bool {
    let env_restricted = server.env.as_ref().is_some_and(|env| {
        env.iter().any(|(k, v)| {
            let key = k.to_lowercase();
            DOMAIN_RESTRICTION_HINTS.iter().any(|h| key.contains(h)) && has_specific_targets(v)
        })
    });

    let args_restricted = server.args.as_ref().is_some_and(|args| {
        for (idx, arg) in args.iter().enumerate() {
            let lowered = arg.to_lowercase();
            let hint_match = DOMAIN_RESTRICTION_HINTS.iter().any(|h| lowered.contains(h))
                || lowered.contains("--allow-domain")
                || lowered.contains("--allowed-domain")
                || lowered.contains("--allowed-host")
                || lowered.contains("--allowed-origin")
                || lowered.contains("--deny-domain");

            if !hint_match {
                continue;
            }

            if let Some((_, rhs)) = arg.split_once('=') {
                if has_specific_targets(rhs) {
                    return true;
                }
                continue;
            }

            if let Some(next) = args.get(idx + 1) {
                if !next.starts_with('-') && has_specific_targets(next) {
                    return true;
                }
            }

            if !arg.starts_with('-') && has_specific_targets(arg) {
                return true;
            }
        }
        false
    });

    env_restricted || args_restricted
}

fn has_specific_targets(value: &str) -> bool {
    value
        .split([',', ';'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .any(|target| !is_wildcard_target(target))
}

fn is_wildcard_target(value: &str) -> bool {
    let lower = value.trim().to_lowercase();
    lower == "*"
        || lower == "all"
        || lower == "any"
        || lower == "0.0.0.0/0"
        || lower == "::/0"
        || lower == "0.0.0.0"
        || lower.contains('*')
}

fn is_filesystem_tool(server_name: &str, server: &McpServer) -> bool {
    let name_lower = server_name.to_lowercase();
    if FILESYSTEM_PATTERNS.iter().any(|p| name_lower.contains(p)) {
        return true;
    }

    if let Some(command) = &server.command {
        let lower = command.to_lowercase();
        if FILESYSTEM_PATTERNS.iter().any(|p| lower.contains(p)) {
            return true;
        }
    }

    if let Some(args) = &server.args {
        let joined = args.join(" ").to_lowercase();
        if FILESYSTEM_PATTERNS.iter().any(|p| joined.contains(p)) {
            return true;
        }
    }

    false
}

fn has_safe_allowed_directories(server: &McpServer) -> bool {
    let dirs = match &server.allowed_directories {
        Some(d) if !d.is_empty() => d,
        _ => return false,
    };

    !dirs.iter().any(|dir| {
        let d = dir.trim();
        DANGEROUS_PATHS
            .iter()
            .any(|dangerous| d.eq_ignore_ascii_case(dangerous))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inspect_vulnerable_file_has_servers() {
        let result = inspect("testdata/vulnerable-mcp.json");
        assert_eq!(result.configs_scanned, 1);
        assert!(result.servers_scanned > 0);
        assert!(!result.servers.is_empty());
    }

    #[test]
    fn test_inspect_json_render() {
        let result = inspect("testdata/clean-mcp.json");
        let json = render_json(&result).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed["servers"].is_array());
        assert!(parsed["servers_scanned"].is_number());
    }

    #[test]
    fn test_terminal_render_contains_header() {
        let result = inspect("testdata/clean-mcp.json");
        let out = render_terminal(&result);
        assert!(out.contains("agentwise inspect"));
        assert!(out.contains("Scanned:"));
    }
}
