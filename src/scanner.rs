use crate::config::{extract_all_package_names, extract_package_info, load_config, ParsedConfig};
use crate::cvedb;
use crate::osv;
use crate::rules::{all_rules, EpssData, Finding, Severity};
use crate::score::compute_score;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::Instant;
use walkdir::WalkDir;

/// Known MCP config file names to search for.
const CONFIG_FILE_NAMES: &[&str] = &[".mcp.json", "mcp.json", "claude_desktop_config.json"];

/// Statistics from a live OSV query.
#[derive(Debug, Clone)]
pub struct OsvStats {
    pub packages_queried: usize,
    pub new_vulnerabilities: usize,
}

/// Result of a complete scan.
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub findings: Vec<Finding>,
    pub configs_scanned: usize,
    pub servers_scanned: usize,
    pub score: i32,
    pub grade: String,
    pub duration_ms: u64,
    pub osv_stats: Option<OsvStats>,
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
                let mut rule_findings = rule.check(server_name, server, &parsed_config.file_path);
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
        osv_stats: None,
    }
}

/// Run scan and augment with live OSV lookups + EPSS enrichment.
pub async fn scan_with_live(path: &str) -> ScanResult {
    let mut result = scan(path);

    let configs = discover_and_parse(path);
    let mut package_usages = Vec::new();
    let mut unique_packages: HashSet<String> = HashSet::new();

    for parsed_config in &configs {
        for (server_name, server) in &parsed_config.config.mcp_servers {
            if server.disabled == Some(true) {
                continue;
            }
            for (package, version) in extract_package_info(server) {
                unique_packages.insert(package.clone());
                package_usages.push((
                    package,
                    version,
                    server_name.to_string(),
                    parsed_config.file_path.clone(),
                ));
            }
        }
    }

    if unique_packages.is_empty() {
        result.osv_stats = Some(OsvStats {
            packages_queried: 0,
            new_vulnerabilities: 0,
        });
        // Still run EPSS on any existing CVE findings from embedded DB
        enrich_with_epss(&mut result.findings).await;
        return result;
    }

    let package_vec: Vec<String> = unique_packages.into_iter().collect();
    let package_refs: Vec<&str> = package_vec.iter().map(String::as_str).collect();

    let batch: Vec<(String, Vec<osv::OsvVulnerability>)> = if package_refs.len() == 1 {
        let pkg = package_refs[0];
        match osv::query_package(pkg, "npm").await {
            Ok(vulns) => vec![(pkg.to_string(), vulns)],
            Err(e) => {
                eprintln!("Warning: live OSV lookup failed: {}", e);
                result.osv_stats = Some(OsvStats {
                    packages_queried: package_refs.len(),
                    new_vulnerabilities: 0,
                });
                enrich_with_epss(&mut result.findings).await;
                return result;
            }
        }
    } else {
        match osv::query_packages_batch(&package_refs, "npm").await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Warning: live OSV lookup failed: {}", e);
                result.osv_stats = Some(OsvStats {
                    packages_queried: package_refs.len(),
                    new_vulnerabilities: 0,
                });
                enrich_with_epss(&mut result.findings).await;
                return result;
            }
        }
    };

    let mut live_cves_by_package: HashMap<String, Vec<cvedb::CveEntry>> = HashMap::new();
    for (package, vulns) in &batch {
        let entries = osv::vulns_to_cve_entries(package, vulns);
        live_cves_by_package.insert(package.clone(), entries);
    }

    // Existing CVE findings key: (cve_id, config_file, server_name)
    let mut existing_cve_keys: HashSet<(String, String, String)> = HashSet::new();
    for finding in &result.findings {
        if finding.rule_id == "AW-006" {
            let cve_id = finding
                .title
                .split(':')
                .next()
                .unwrap_or("")
                .trim()
                .to_string();
            if !cve_id.is_empty() {
                existing_cve_keys.insert((
                    cve_id,
                    finding.config_file.clone(),
                    finding.server_name.clone(),
                ));
            }
        }
    }

    let mut new_findings = Vec::new();

    for (package, version, server_name, config_file) in package_usages {
        if let Some(cves) = live_cves_by_package.get(&package) {
            let matching = cvedb::check_package(&package, &version, cves);
            for cve in matching {
                let key = (cve.id.clone(), config_file.clone(), server_name.clone());
                if existing_cve_keys.contains(&key) {
                    continue;
                }

                let severity = match cve.severity.as_str() {
                    "critical" => Severity::Critical,
                    "high" => Severity::High,
                    "medium" => Severity::Medium,
                    _ => Severity::Low,
                };

                new_findings.push(Finding {
                    rule_id: "AW-006".to_string(),
                    severity,
                    title: format!("{}: {}", cve.id, cve.description),
                    message: format!(
                        "Server '{}' uses {}@{} which is affected by {} (CVSS {:.1})",
                        server_name, package, version, cve.id, cve.cvss
                    ),
                    fix: cve.fix,
                    config_file: config_file.clone(),
                    server_name: server_name.clone(),
                    source: Some("osv".to_string()),
                    epss: None,
                    sub_items: None,
                });

                existing_cve_keys.insert(key);
            }
        }
    }

    let new_count = new_findings.len();
    result.findings.extend(new_findings);

    // EPSS enrichment for all CVE findings
    enrich_with_epss(&mut result.findings).await;

    let severities: Vec<Severity> = result.findings.iter().map(|f| f.severity).collect();
    let (score, grade) = compute_score(&severities);
    result.score = score;
    result.grade = grade;
    result.osv_stats = Some(OsvStats {
        packages_queried: package_refs.len(),
        new_vulnerabilities: new_count,
    });

    result
}

/// Run scan with supply chain and deps.dev analysis.
/// If `live` is true, also runs OSV lookups + EPSS enrichment.
pub async fn scan_with_supply_chain(path: &str, live: bool) -> ScanResult {
    let mut result = if live {
        scan_with_live(path).await
    } else {
        scan(path)
    };

    let configs = discover_and_parse(path);
    let mut packages_for_supply_chain: Vec<(String, String, String)> = Vec::new();
    let mut packages_for_deps: Vec<(String, String, String, String)> = Vec::new();
    let mut seen_supply_chain: HashSet<String> = HashSet::new();
    let mut seen_deps: HashSet<(String, String)> = HashSet::new();

    for parsed_config in &configs {
        for (server_name, server) in &parsed_config.config.mcp_servers {
            if server.disabled == Some(true) {
                continue;
            }

            // All package names (with or without versions) for supply chain
            for name in extract_all_package_names(server) {
                if seen_supply_chain.insert(name.clone()) {
                    packages_for_supply_chain.push((
                        name,
                        server_name.to_string(),
                        parsed_config.file_path.clone(),
                    ));
                }
            }

            // Versioned packages for deps.dev
            for (package, version) in extract_package_info(server) {
                if seen_deps.insert((package.clone(), version.clone())) {
                    packages_for_deps.push((
                        package,
                        version,
                        server_name.to_string(),
                        parsed_config.file_path.clone(),
                    ));
                }
            }
        }
    }

    // Run supply chain checks
    if !packages_for_supply_chain.is_empty() {
        let supply_chain_findings =
            crate::rules::supply_chain::check_supply_chain(&packages_for_supply_chain).await;
        result.findings.extend(supply_chain_findings);
    }

    // Run deps.dev checks
    if !packages_for_deps.is_empty() {
        let deps_findings = crate::rules::deps::check_deps(&packages_for_deps).await;
        result.findings.extend(deps_findings);
    }

    // Recompute score
    let severities: Vec<Severity> = result.findings.iter().map(|f| f.severity).collect();
    let (score, grade) = compute_score(&severities);
    result.score = score;
    result.grade = grade;

    result
}

/// Enrich CVE findings (AW-006) with EPSS exploitation probability data.
async fn enrich_with_epss(findings: &mut [Finding]) {
    let cve_ids: Vec<String> = findings
        .iter()
        .filter(|f| f.rule_id == "AW-006")
        .filter_map(|f| {
            let id = f.title.split(':').next().map(|s| s.trim().to_string())?;
            if id.starts_with("CVE-") {
                Some(id)
            } else {
                None
            }
        })
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();

    if cve_ids.is_empty() {
        return;
    }

    let cve_refs: Vec<&str> = cve_ids.iter().map(String::as_str).collect();
    match crate::epss::query_epss(&cve_refs).await {
        Ok(epss_scores) => {
            for finding in findings.iter_mut() {
                if finding.rule_id == "AW-006" {
                    if let Some(cve_id) = finding.title.split(':').next().map(|s| s.trim()) {
                        if let Some(score) = epss_scores.get(cve_id) {
                            finding.epss = Some(EpssData {
                                probability: score.probability,
                                percentile: score.percentile,
                            });
                        }
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("Warning: EPSS lookup failed: {}", e);
        }
    }
}

/// Discover and parse MCP config files at the given path.
pub fn discover_and_parse(path: &str) -> Vec<ParsedConfig> {
    let p = Path::new(path);
    if p.is_file() {
        match load_config(p) {
            Ok(config) => vec![config],
            Err(_) => vec![],
        }
    } else if p.is_dir() {
        discover_configs(p)
    } else {
        vec![]
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

        // Skip noisy dirs
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
        assert!(result.score > 50);
    }

    #[test]
    fn test_scan_empty_config() {
        let result = scan("testdata/empty-config.json");
        assert_eq!(result.configs_scanned, 1);
        assert_eq!(result.servers_scanned, 0);
        assert_eq!(result.findings.len(), 0);
        assert_eq!(result.score, 100);
    }

    #[test]
    fn test_scan_directory() {
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

    #[test]
    fn test_osv_stats_default_none() {
        let result = scan("testdata/clean-mcp.json");
        assert!(result.osv_stats.is_none());
    }

    #[test]
    fn test_discover_and_parse_file() {
        let parsed = discover_and_parse("testdata/vulnerable-mcp.json");
        assert_eq!(parsed.len(), 1);
        assert!(!parsed[0].config.mcp_servers.is_empty());
    }
}
