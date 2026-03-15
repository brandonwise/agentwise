use crate::cvedb::CveEntry;
use serde::{Deserialize, Serialize};
use std::time::Duration;

const OSV_API_URL: &str = "https://api.osv.dev/v1/query";
const OSV_BATCH_URL: &str = "https://api.osv.dev/v1/querybatch";
const TIMEOUT: Duration = Duration::from_secs(3);

/// Known MCP package names for the update command.
pub const KNOWN_MCP_PACKAGES: &[&str] = &[
    "@modelcontextprotocol/server-filesystem",
    "@modelcontextprotocol/server-git",
    "@modelcontextprotocol/server-fetch",
    "@modelcontextprotocol/server-postgres",
    "@modelcontextprotocol/server-sqlite",
    "@modelcontextprotocol/server-puppeteer",
    "@modelcontextprotocol/server-brave-search",
    "@modelcontextprotocol/server-slack",
    "@modelcontextprotocol/server-github",
    "@modelcontextprotocol/server-memory",
    "@modelcontextprotocol/sdk",
    "mcp-remote",
    "claude-code",
    "mcp-shell-server",
    "mcp-server-kubernetes",
    "mcp-server-docker",
    "@anthropic-ai/claude-code",
    "@modelcontextprotocol/server-everything",
    "@modelcontextprotocol/server-sequential-thinking",
    "@modelcontextprotocol/server-gdrive",
    "@modelcontextprotocol/server-redis",
    "@modelcontextprotocol/server-sentry",
    "@modelcontextprotocol/server-raygun",
    "mcp-server-playwright",
    "mcp-obsidian",
    "mcp-server-linear",
    "mcp-server-notion",
    "mcp-server-stripe",
    "mcp-server-supabase",
    "mcp-server-vercel",
];

// ── OSV API request/response types ──────────────────────────

#[derive(Serialize)]
struct OsvQuery {
    package: OsvPackage,
}

#[derive(Serialize)]
struct OsvPackage {
    name: String,
    ecosystem: String,
}

#[derive(Serialize)]
struct OsvBatchRequest {
    queries: Vec<OsvQuery>,
}

#[derive(Debug, Deserialize)]
struct OsvResponse {
    #[serde(default)]
    vulns: Vec<OsvVulnerability>,
}

#[derive(Debug, Deserialize)]
struct OsvBatchResponse {
    #[serde(default)]
    results: Vec<OsvBatchResult>,
}

#[derive(Debug, Deserialize)]
struct OsvBatchResult {
    #[serde(default)]
    vulns: Vec<OsvVulnerability>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OsvVulnerability {
    pub id: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub details: String,
    #[serde(default)]
    pub severity: Vec<OsvSeverity>,
    #[serde(default)]
    pub affected: Vec<OsvAffected>,
    #[serde(default)]
    pub aliases: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OsvSeverity {
    #[serde(rename = "type", default)]
    pub severity_type: String,
    #[serde(default)]
    pub score: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OsvAffected {
    #[serde(default)]
    pub package: Option<OsvAffectedPackage>,
    #[serde(default)]
    pub ranges: Vec<OsvRange>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OsvAffectedPackage {
    #[serde(default)]
    pub name: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OsvRange {
    #[serde(default)]
    pub events: Vec<OsvEvent>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OsvEvent {
    #[serde(default)]
    pub fixed: Option<String>,
}

// ── API client functions ────────────────────────────────────

/// Query OSV for vulnerabilities affecting a single package.
pub async fn query_package(name: &str, ecosystem: &str) -> Result<Vec<OsvVulnerability>, String> {
    let client = reqwest::Client::builder()
        .timeout(TIMEOUT)
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

    let query = OsvQuery {
        package: OsvPackage {
            name: name.to_string(),
            ecosystem: ecosystem.to_string(),
        },
    };

    let response = client
        .post(OSV_API_URL)
        .json(&query)
        .send()
        .await
        .map_err(|e| format!("OSV API request failed for {}: {}", name, e))?;

    if !response.status().is_success() {
        return Err(format!(
            "OSV API returned status {} for {}",
            response.status(),
            name
        ));
    }

    let osv_response: OsvResponse = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse OSV response for {}: {}", name, e))?;

    Ok(osv_response.vulns)
}

/// Query OSV for vulnerabilities affecting multiple packages in a single batch request.
pub async fn query_packages_batch(
    packages: &[&str],
    ecosystem: &str,
) -> Result<Vec<(String, Vec<OsvVulnerability>)>, String> {
    if packages.is_empty() {
        return Ok(Vec::new());
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10)) // longer timeout for batch
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

    let batch_request = OsvBatchRequest {
        queries: packages
            .iter()
            .map(|name| OsvQuery {
                package: OsvPackage {
                    name: name.to_string(),
                    ecosystem: ecosystem.to_string(),
                },
            })
            .collect(),
    };

    let response = client
        .post(OSV_BATCH_URL)
        .json(&batch_request)
        .send()
        .await
        .map_err(|e| format!("OSV batch API request failed: {}", e))?;

    if !response.status().is_success() {
        return Err(format!(
            "OSV batch API returned status {}",
            response.status()
        ));
    }

    let batch_response: OsvBatchResponse = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse OSV batch response: {}", e))?;

    let results: Vec<(String, Vec<OsvVulnerability>)> = packages
        .iter()
        .zip(batch_response.results)
        .map(|(name, result)| (name.to_string(), result.vulns))
        .collect();

    Ok(results)
}

// ── Conversion to CveEntry ──────────────────────────────────

/// Convert OSV vulnerabilities to our CveEntry format.
pub fn vulns_to_cve_entries(package_name: &str, vulns: &[OsvVulnerability]) -> Vec<CveEntry> {
    let mut entries = Vec::new();

    for vuln in vulns {
        // Prefer CVE alias if available, otherwise use OSV ID
        let cve_id = vuln
            .aliases
            .iter()
            .find(|a| a.starts_with("CVE-"))
            .cloned()
            .unwrap_or_else(|| vuln.id.clone());

        // Extract CVSS score
        let cvss = extract_cvss(&vuln.severity);

        // Determine severity from CVSS
        let severity = cvss_to_severity(cvss);

        // Find the fixed version from affected ranges
        let fixed_version = extract_fixed_version(vuln, package_name);

        let description = if vuln.summary.is_empty() {
            vuln.details.lines().next().unwrap_or("").to_string()
        } else {
            vuln.summary.clone()
        };

        let fix = if let Some(ref ver) = fixed_version {
            format!("Upgrade {} to >={}", package_name, ver)
        } else {
            format!("Check {} for updates", package_name)
        };

        entries.push(CveEntry {
            id: cve_id,
            package: package_name.to_string(),
            affected_below: fixed_version.unwrap_or_else(|| "999.0.0".to_string()),
            severity: severity.to_string(),
            cvss,
            description,
            fix,
        });
    }

    entries
}

/// Extract the CVSS score from OSV severity data.
fn extract_cvss(severities: &[OsvSeverity]) -> f64 {
    for sev in severities {
        if sev.severity_type == "CVSS_V3" || sev.severity_type == "CVSS_V2" {
            // CVSS vector string format: "CVSS:3.1/AV:N/..." - parse score from end
            // Or it might just be a numeric score
            if let Ok(score) = sev.score.parse::<f64>() {
                return score;
            }
            // Try to extract score from CVSS vector (it's at the end after last /)
            // OSV typically provides the score directly, but handle vector format too
        }
    }
    // Default to medium severity if no CVSS data
    5.0
}

/// Map CVSS score to severity string.
fn cvss_to_severity(cvss: f64) -> &'static str {
    match cvss {
        s if s >= 9.0 => "critical",
        s if s >= 7.0 => "high",
        s if s >= 4.0 => "medium",
        _ => "low",
    }
}

/// Extract the fixed version from OSV affected ranges.
fn extract_fixed_version(vuln: &OsvVulnerability, package_name: &str) -> Option<String> {
    for affected in &vuln.affected {
        // Match by package name if available
        if let Some(ref pkg) = affected.package {
            if pkg.name != package_name {
                continue;
            }
        }

        for range in &affected.ranges {
            for event in &range.events {
                if let Some(ref fixed) = event.fixed {
                    return Some(fixed.clone());
                }
            }
        }
    }
    None
}

// ── Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_osv_response_json() -> &'static str {
        r#"{
            "vulns": [
                {
                    "id": "GHSA-xxxx-yyyy-zzzz",
                    "summary": "Path traversal vulnerability in filesystem server",
                    "details": "A path traversal vulnerability allows reading files outside allowed directories.",
                    "severity": [
                        {
                            "type": "CVSS_V3",
                            "score": "7.5"
                        }
                    ],
                    "affected": [
                        {
                            "package": {
                                "name": "@modelcontextprotocol/server-filesystem",
                                "ecosystem": "npm"
                            },
                            "ranges": [
                                {
                                    "type": "SEMVER",
                                    "events": [
                                        {"introduced": "0"},
                                        {"fixed": "0.6.3"}
                                    ]
                                }
                            ]
                        }
                    ],
                    "aliases": ["CVE-2025-53110"]
                },
                {
                    "id": "GHSA-aaaa-bbbb-cccc",
                    "summary": "Symlink escape in filesystem server",
                    "details": "Symlink following allows escaping allowed directories.",
                    "severity": [],
                    "affected": [
                        {
                            "package": {
                                "name": "@modelcontextprotocol/server-filesystem",
                                "ecosystem": "npm"
                            },
                            "ranges": [
                                {
                                    "type": "SEMVER",
                                    "events": [
                                        {"introduced": "0"},
                                        {"fixed": "0.6.3"}
                                    ]
                                }
                            ]
                        }
                    ],
                    "aliases": []
                }
            ]
        }"#
    }

    fn sample_batch_response_json() -> &'static str {
        r#"{
            "results": [
                {
                    "vulns": [
                        {
                            "id": "GHSA-xxxx-yyyy-zzzz",
                            "summary": "Path traversal in filesystem server",
                            "details": "",
                            "severity": [{"type": "CVSS_V3", "score": "7.5"}],
                            "affected": [
                                {
                                    "package": {
                                        "name": "@modelcontextprotocol/server-filesystem",
                                        "ecosystem": "npm"
                                    },
                                    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "0.6.3"}]}]
                                }
                            ],
                            "aliases": ["CVE-2025-53110"]
                        }
                    ]
                },
                {
                    "vulns": []
                }
            ]
        }"#
    }

    fn sample_no_cvss_vuln_json() -> &'static str {
        r#"{
            "vulns": [
                {
                    "id": "GHSA-no-cvss",
                    "summary": "Some vulnerability without CVSS",
                    "details": "",
                    "severity": [],
                    "affected": [
                        {
                            "package": {
                                "name": "test-package",
                                "ecosystem": "npm"
                            },
                            "ranges": [
                                {
                                    "type": "SEMVER",
                                    "events": [
                                        {"introduced": "0"}
                                    ]
                                }
                            ]
                        }
                    ],
                    "aliases": []
                }
            ]
        }"#
    }

    #[test]
    fn test_parse_osv_response() {
        let response: OsvResponse =
            serde_json::from_str(sample_osv_response_json()).expect("should parse OSV response");
        assert_eq!(response.vulns.len(), 2);
        assert_eq!(response.vulns[0].id, "GHSA-xxxx-yyyy-zzzz");
        assert_eq!(response.vulns[0].aliases, vec!["CVE-2025-53110"]);
        assert_eq!(response.vulns[1].id, "GHSA-aaaa-bbbb-cccc");
    }

    #[test]
    fn test_parse_batch_response() {
        let response: OsvBatchResponse = serde_json::from_str(sample_batch_response_json())
            .expect("should parse batch response");
        assert_eq!(response.results.len(), 2);
        assert_eq!(response.results[0].vulns.len(), 1);
        assert!(response.results[1].vulns.is_empty());
    }

    #[test]
    fn test_vulns_to_cve_entries() {
        let response: OsvResponse =
            serde_json::from_str(sample_osv_response_json()).expect("should parse");
        let entries =
            vulns_to_cve_entries("@modelcontextprotocol/server-filesystem", &response.vulns);
        assert_eq!(entries.len(), 2);

        // First entry should use CVE alias
        assert_eq!(entries[0].id, "CVE-2025-53110");
        assert_eq!(
            entries[0].package,
            "@modelcontextprotocol/server-filesystem"
        );
        assert_eq!(entries[0].affected_below, "0.6.3");
        assert_eq!(entries[0].severity, "high");
        assert_eq!(entries[0].cvss, 7.5);

        // Second entry has no CVE alias, should use GHSA ID
        assert_eq!(entries[1].id, "GHSA-aaaa-bbbb-cccc");
        assert_eq!(entries[1].affected_below, "0.6.3");
    }

    #[test]
    fn test_vulns_to_cve_entries_no_cvss() {
        let response: OsvResponse =
            serde_json::from_str(sample_no_cvss_vuln_json()).expect("should parse");
        let entries = vulns_to_cve_entries("test-package", &response.vulns);
        assert_eq!(entries.len(), 1);
        // No CVSS should default to 5.0 / medium
        assert_eq!(entries[0].cvss, 5.0);
        assert_eq!(entries[0].severity, "medium");
        // No fixed version should default to 999.0.0
        assert_eq!(entries[0].affected_below, "999.0.0");
    }

    #[test]
    fn test_extract_cvss_from_score() {
        let severities = vec![OsvSeverity {
            severity_type: "CVSS_V3".to_string(),
            score: "9.8".to_string(),
        }];
        assert_eq!(extract_cvss(&severities), 9.8);
    }

    #[test]
    fn test_extract_cvss_empty() {
        assert_eq!(extract_cvss(&[]), 5.0);
    }

    #[test]
    fn test_cvss_to_severity_mapping() {
        assert_eq!(cvss_to_severity(9.8), "critical");
        assert_eq!(cvss_to_severity(9.0), "critical");
        assert_eq!(cvss_to_severity(7.5), "high");
        assert_eq!(cvss_to_severity(7.0), "high");
        assert_eq!(cvss_to_severity(5.0), "medium");
        assert_eq!(cvss_to_severity(4.0), "medium");
        assert_eq!(cvss_to_severity(3.9), "low");
        assert_eq!(cvss_to_severity(0.0), "low");
    }

    #[test]
    fn test_known_mcp_packages_count() {
        assert!(
            KNOWN_MCP_PACKAGES.len() >= 16,
            "Should have at least 16 known MCP packages"
        );
    }

    #[test]
    fn test_known_mcp_packages_contains_required() {
        let required = [
            "@modelcontextprotocol/server-filesystem",
            "@modelcontextprotocol/server-git",
            "@modelcontextprotocol/server-fetch",
            "mcp-remote",
            "claude-code",
            "mcp-shell-server",
        ];
        for pkg in required {
            assert!(
                KNOWN_MCP_PACKAGES.contains(&pkg),
                "Missing required package: {}",
                pkg
            );
        }
    }
}
