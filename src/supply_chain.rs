use serde::Deserialize;
use std::collections::HashMap;
use std::time::Duration;

const NPM_REGISTRY_URL: &str = "https://registry.npmjs.org";
const NPM_DOWNLOADS_URL: &str = "https://api.npmjs.org/downloads/point/last-week";
const TIMEOUT: Duration = Duration::from_secs(5);

/// Known MCP package bare names for typosquatting detection.
const KNOWN_MCP_NAMES: &[&str] = &[
    "server-filesystem",
    "server-git",
    "server-fetch",
    "server-postgres",
    "server-sqlite",
    "server-puppeteer",
    "server-brave-search",
    "server-slack",
    "server-github",
    "server-memory",
    "mcp-remote",
    "mcp-shell-server",
    "mcp-server-kubernetes",
    "mcp-server-docker",
    "mcp-server-playwright",
    "mcp-server-linear",
    "mcp-server-notion",
    "mcp-server-stripe",
    "mcp-server-supabase",
    "mcp-server-vercel",
];

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct SupplyChainRisk {
    pub package: String,
    pub overall_risk: RiskLevel,
    pub signals: Vec<RiskSignal>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RiskLevel {
    High,
    Medium,
    Low,
    Info,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskLevel::High => write!(f, "HIGH"),
            RiskLevel::Medium => write!(f, "MEDIUM"),
            RiskLevel::Low => write!(f, "LOW"),
            RiskLevel::Info => write!(f, "INFO"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RiskSignal {
    pub level: RiskLevel,
    pub description: String,
}

// ── npm registry response types ────────────────────────────

#[derive(Debug, Deserialize)]
struct NpmPackageMetadata {
    #[serde(default)]
    maintainers: Vec<NpmMaintainer>,
    #[serde(default)]
    time: HashMap<String, String>,
    #[serde(rename = "dist-tags", default)]
    dist_tags: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct NpmMaintainer {
    #[serde(default)]
    name: String,
}

#[derive(Debug, Deserialize)]
struct NpmVersionMetadata {
    #[serde(default)]
    scripts: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct NpmDownloads {
    #[serde(default)]
    downloads: u64,
}

// ── Analysis function ──────────────────────────────────────

/// Analyze a single npm package for supply chain risk signals.
pub async fn analyze_package(package: &str) -> Result<SupplyChainRisk, String> {
    let client = reqwest::Client::builder()
        .timeout(TIMEOUT)
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

    let mut signals = Vec::new();

    // Check if from official scope
    if !package.starts_with("@modelcontextprotocol/") {
        signals.push(RiskSignal {
            level: RiskLevel::Info,
            description: "Not from official @modelcontextprotocol scope".to_string(),
        });
    }

    // Check for typosquatting
    let bare_name = package
        .strip_prefix("@modelcontextprotocol/")
        .or_else(|| {
            if package.starts_with('@') {
                package.split('/').next_back()
            } else {
                Some(package)
            }
        })
        .unwrap_or(package);

    for known in KNOWN_MCP_NAMES {
        let dist = levenshtein(bare_name, known);
        if dist > 0 && dist <= 2 {
            signals.push(RiskSignal {
                level: RiskLevel::High,
                description: format!(
                    "Possible typosquat of '{}' (edit distance: {})",
                    known, dist
                ),
            });
            break;
        }
    }

    // Query npm registry for package metadata
    let encoded = package.replace('/', "%2F");
    let metadata_url = format!("{}/{}", NPM_REGISTRY_URL, encoded);

    if let Ok(response) = client.get(&metadata_url).send().await {
        if response.status().is_success() {
            if let Ok(metadata) = response.json::<NpmPackageMetadata>().await {
                // Single maintainer check
                if metadata.maintainers.len() == 1 {
                    signals.push(RiskSignal {
                        level: RiskLevel::High,
                        description: format!(
                            "Single maintainer '{}' (account takeover risk)",
                            metadata.maintainers[0].name
                        ),
                    });
                }

                // New package check (< 90 days)
                if let Some(created) = metadata.time.get("created") {
                    if is_recently_created(created, 90) {
                        signals.push(RiskSignal {
                            level: RiskLevel::Medium,
                            description: format!("New package (created {})", created),
                        });
                    }
                }

                // Check install scripts on latest version
                if let Some(latest) = metadata.dist_tags.get("latest") {
                    let version_url = format!("{}/{}/{}", NPM_REGISTRY_URL, encoded, latest);
                    if let Ok(ver_response) = client.get(&version_url).send().await {
                        if ver_response.status().is_success() {
                            if let Ok(ver_meta) = ver_response.json::<NpmVersionMetadata>().await {
                                if let Some(scripts) = &ver_meta.scripts {
                                    let dangerous = ["preinstall", "install", "postinstall"];
                                    for script_name in dangerous {
                                        if scripts.contains_key(script_name) {
                                            signals.push(RiskSignal {
                                                level: RiskLevel::High,
                                                description: format!("Has {} script", script_name),
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Check weekly downloads
    let downloads_url = format!("{}/{}", NPM_DOWNLOADS_URL, encoded);
    if let Ok(response) = client.get(&downloads_url).send().await {
        if response.status().is_success() {
            if let Ok(downloads) = response.json::<NpmDownloads>().await {
                if downloads.downloads < 1000 {
                    signals.push(RiskSignal {
                        level: RiskLevel::Medium,
                        description: format!("{} weekly downloads", downloads.downloads),
                    });
                }
            }
        }
    }

    // Determine overall risk level
    let overall_risk = if signals.iter().any(|s| s.level == RiskLevel::High) {
        RiskLevel::High
    } else if signals.iter().any(|s| s.level == RiskLevel::Medium) {
        RiskLevel::Medium
    } else if signals.iter().any(|s| s.level == RiskLevel::Info) {
        RiskLevel::Info
    } else {
        RiskLevel::Low
    };

    Ok(SupplyChainRisk {
        package: package.to_string(),
        overall_risk,
        signals,
    })
}

// ── Levenshtein distance ───────────────────────────────────

/// Compute Levenshtein edit distance between two strings.
pub fn levenshtein(a: &str, b: &str) -> usize {
    let a_len = a.len();
    let b_len = b.len();

    if a_len == 0 {
        return b_len;
    }
    if b_len == 0 {
        return a_len;
    }

    let mut prev_row: Vec<usize> = (0..=b_len).collect();
    let mut curr_row = vec![0; b_len + 1];

    for (i, a_char) in a.chars().enumerate() {
        curr_row[0] = i + 1;
        for (j, b_char) in b.chars().enumerate() {
            let cost = if a_char == b_char { 0 } else { 1 };
            curr_row[j + 1] = (prev_row[j + 1] + 1)
                .min(curr_row[j] + 1)
                .min(prev_row[j] + cost);
        }
        std::mem::swap(&mut prev_row, &mut curr_row);
    }

    prev_row[b_len]
}

// ── Date utilities ─────────────────────────────────────────

/// Check if an ISO 8601 date string is within the last N days.
fn is_recently_created(date_str: &str, days: u64) -> bool {
    let date_part = date_str.split('T').next().unwrap_or(date_str);
    let parts: Vec<i64> = date_part
        .split('-')
        .filter_map(|p| p.parse().ok())
        .collect();
    if parts.len() != 3 {
        return false;
    }
    let (y, m, d) = (parts[0], parts[1], parts[2]);

    let created = civil_to_days(y, m, d);
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let today = now_secs / 86400;

    (today - created) < days as i64
}

/// Convert civil date to days since Unix epoch (1970-01-01).
/// Algorithm from Howard Hinnant's date library.
fn civil_to_days(y: i64, m: i64, d: i64) -> i64 {
    let (y, m) = if m <= 2 { (y - 1, m + 9) } else { (y, m - 3) };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let doy = (153 * m + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

// ── Tests ──────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_levenshtein_identical() {
        assert_eq!(levenshtein("hello", "hello"), 0);
    }

    #[test]
    fn test_levenshtein_one_edit() {
        assert_eq!(levenshtein("mcp-remote", "mcp-remte"), 1); // deletion
        assert_eq!(levenshtein("kitten", "sitten"), 1); // substitution
    }

    #[test]
    fn test_levenshtein_two_edits() {
        assert_eq!(levenshtein("server-git", "server-gti"), 2); // transposition
        assert_eq!(levenshtein("kitten", "sitting"), 3);
    }

    #[test]
    fn test_levenshtein_empty() {
        assert_eq!(levenshtein("", "abc"), 3);
        assert_eq!(levenshtein("abc", ""), 3);
        assert_eq!(levenshtein("", ""), 0);
    }

    #[test]
    fn test_levenshtein_typosquat_detection() {
        // These should be caught (distance <= 2)
        assert!(levenshtein("server-filesystm", "server-filesystem") <= 2);
        assert!(levenshtein("mcp-remte", "mcp-remote") <= 2);
        assert!(levenshtein("mcp-remot", "mcp-remote") <= 2);
    }

    #[test]
    fn test_levenshtein_not_typosquat() {
        // These should NOT be caught (distance > 2)
        assert!(levenshtein("totally-different", "server-filesystem") > 2);
        assert!(levenshtein("my-package", "mcp-remote") > 2);
    }

    #[test]
    fn test_parse_npm_metadata() {
        let json = r#"{
            "maintainers": [{"name": "alice"}],
            "time": {"created": "2026-01-01T00:00:00.000Z"},
            "dist-tags": {"latest": "1.0.0"}
        }"#;
        let metadata: NpmPackageMetadata = serde_json::from_str(json).expect("should parse");
        assert_eq!(metadata.maintainers.len(), 1);
        assert_eq!(metadata.maintainers[0].name, "alice");
        assert_eq!(metadata.dist_tags.get("latest").unwrap(), "1.0.0");
    }

    #[test]
    fn test_parse_npm_metadata_multiple_maintainers() {
        let json = r#"{
            "maintainers": [{"name": "alice"}, {"name": "bob"}, {"name": "charlie"}],
            "time": {},
            "dist-tags": {}
        }"#;
        let metadata: NpmPackageMetadata = serde_json::from_str(json).expect("should parse");
        assert_eq!(metadata.maintainers.len(), 3);
    }

    #[test]
    fn test_parse_npm_version_metadata_with_scripts() {
        let json = r#"{
            "scripts": {
                "preinstall": "node setup.js",
                "postinstall": "node build.js",
                "test": "jest"
            }
        }"#;
        let metadata: NpmVersionMetadata = serde_json::from_str(json).expect("should parse");
        let scripts = metadata.scripts.unwrap();
        assert!(scripts.contains_key("preinstall"));
        assert!(scripts.contains_key("postinstall"));
        assert!(!scripts.contains_key("install"));
    }

    #[test]
    fn test_parse_npm_version_metadata_no_scripts() {
        let json = r#"{}"#;
        let metadata: NpmVersionMetadata = serde_json::from_str(json).expect("should parse");
        assert!(metadata.scripts.is_none());
    }

    #[test]
    fn test_parse_npm_downloads() {
        let json =
            r#"{"downloads": 43, "start": "2026-03-07", "end": "2026-03-13", "package": "test"}"#;
        let downloads: NpmDownloads = serde_json::from_str(json).expect("should parse");
        assert_eq!(downloads.downloads, 43);
    }

    #[test]
    fn test_parse_npm_downloads_high() {
        let json = r#"{"downloads": 500000}"#;
        let downloads: NpmDownloads = serde_json::from_str(json).expect("should parse");
        assert!(downloads.downloads >= 1000);
    }

    #[test]
    fn test_risk_level_display() {
        assert_eq!(format!("{}", RiskLevel::High), "HIGH");
        assert_eq!(format!("{}", RiskLevel::Medium), "MEDIUM");
        assert_eq!(format!("{}", RiskLevel::Low), "LOW");
        assert_eq!(format!("{}", RiskLevel::Info), "INFO");
    }

    #[test]
    fn test_civil_to_days_epoch() {
        assert_eq!(civil_to_days(1970, 1, 1), 0);
    }

    #[test]
    fn test_civil_to_days_known_date() {
        // 2000-01-01 is day 10957
        assert_eq!(civil_to_days(2000, 1, 1), 10957);
    }

    #[test]
    fn test_is_recently_created_old_date() {
        // A date from 2020 should not be recent
        assert!(!is_recently_created("2020-01-01T00:00:00.000Z", 90));
    }

    #[test]
    fn test_is_recently_created_invalid() {
        assert!(!is_recently_created("not-a-date", 90));
        assert!(!is_recently_created("", 90));
    }
}
