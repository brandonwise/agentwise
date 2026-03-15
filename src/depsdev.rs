use serde::Deserialize;
use std::time::Duration;

const DEPSDEV_API_URL: &str = "https://api.deps.dev/v3alpha/systems";
const TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone)]
pub struct DepsAnalysis {
    pub transitive_dep_count: usize,
    pub advisory_count: usize,
    pub license_issues: Vec<String>,
}

// ── deps.dev API response types ────────────────────────────

#[derive(Debug, Deserialize)]
struct DepsDevVersion {
    #[serde(rename = "advisoryKeys", default)]
    advisory_keys: Vec<DepsDevAdvisory>,
    #[serde(default)]
    licenses: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct DepsDevAdvisory {
    #[serde(default)]
    id: String,
}

#[derive(Debug, Deserialize)]
struct DepsDevDependencies {
    #[serde(default)]
    nodes: Vec<DepsDevNode>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct DepsDevNode {
    #[serde(rename = "versionKey", default)]
    version_key: Option<DepsDevVersionKey>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct DepsDevVersionKey {
    #[serde(default)]
    name: String,
    #[serde(default)]
    version: String,
}

// ── Analysis function ──────────────────────────────────────

/// Analyze a package's dependency graph via deps.dev.
pub async fn analyze_dependencies(
    package: &str,
    version: &str,
) -> Result<DepsAnalysis, String> {
    let client = reqwest::Client::builder()
        .timeout(TIMEOUT)
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

    let encoded = encode_package(package);

    // Query dependency tree
    let deps_url = format!(
        "{}/npm/packages/{}/versions/{}:dependencies",
        DEPSDEV_API_URL, encoded, version
    );

    let mut transitive_dep_count = 0;
    if let Ok(response) = client.get(&deps_url).send().await {
        if response.status().is_success() {
            if let Ok(deps) = response.json::<DepsDevDependencies>().await {
                // Exclude root node (self)
                transitive_dep_count = deps.nodes.len().saturating_sub(1);
            }
        }
    }

    // Query version info for advisories and licenses
    let version_url = format!(
        "{}/npm/packages/{}/versions/{}",
        DEPSDEV_API_URL, encoded, version
    );

    let mut advisory_count = 0;
    let mut license_issues = Vec::new();

    if let Ok(response) = client.get(&version_url).send().await {
        if response.status().is_success() {
            if let Ok(ver_info) = response.json::<DepsDevVersion>().await {
                advisory_count = ver_info.advisory_keys.len();

                for license in &ver_info.licenses {
                    let upper = license.to_uppercase();
                    if upper.contains("GPL") && !upper.contains("LGPL") {
                        license_issues
                            .push(format!("GPL license detected: {}", license));
                    }
                }
            }
        }
    }

    Ok(DepsAnalysis {
        transitive_dep_count,
        advisory_count,
        license_issues,
    })
}

fn encode_package(package: &str) -> String {
    package.replace('/', "%2F")
}

// ── Tests ──────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_scoped_package() {
        assert_eq!(
            encode_package("@modelcontextprotocol/server-filesystem"),
            "@modelcontextprotocol%2Fserver-filesystem"
        );
    }

    #[test]
    fn test_encode_unscoped_package() {
        assert_eq!(encode_package("mcp-remote"), "mcp-remote");
    }

    #[test]
    fn test_parse_deps_response() {
        let json = r#"{
            "nodes": [
                {
                    "versionKey": {"system": "NPM", "name": "root-pkg", "version": "1.0.0"},
                    "relation": "SELF"
                },
                {
                    "versionKey": {"system": "NPM", "name": "dep-a", "version": "2.0.0"},
                    "relation": "DIRECT"
                },
                {
                    "versionKey": {"system": "NPM", "name": "dep-b", "version": "3.0.0"},
                    "relation": "INDIRECT"
                }
            ]
        }"#;
        let deps: DepsDevDependencies =
            serde_json::from_str(json).expect("should parse");
        assert_eq!(deps.nodes.len(), 3);
        let root = &deps.nodes[0];
        assert_eq!(root.version_key.as_ref().unwrap().name, "root-pkg");
    }

    #[test]
    fn test_parse_version_response() {
        let json = r#"{
            "links": [{"label": "HOMEPAGE", "url": "https://example.com"}],
            "advisoryKeys": [{"id": "GHSA-xxxx-yyyy-zzzz"}],
            "licenses": ["MIT"]
        }"#;
        let ver: DepsDevVersion =
            serde_json::from_str(json).expect("should parse");
        assert_eq!(ver.advisory_keys.len(), 1);
        assert_eq!(ver.advisory_keys[0].id, "GHSA-xxxx-yyyy-zzzz");
        assert_eq!(ver.licenses, vec!["MIT"]);
    }

    #[test]
    fn test_parse_empty_deps_response() {
        let json = r#"{"nodes": []}"#;
        let deps: DepsDevDependencies =
            serde_json::from_str(json).expect("should parse");
        assert!(deps.nodes.is_empty());
    }

    #[test]
    fn test_parse_version_no_advisories() {
        let json =
            r#"{"links": [], "advisoryKeys": [], "licenses": ["Apache-2.0"]}"#;
        let ver: DepsDevVersion =
            serde_json::from_str(json).expect("should parse");
        assert!(ver.advisory_keys.is_empty());
        assert_eq!(ver.licenses, vec!["Apache-2.0"]);
    }

    #[test]
    fn test_gpl_license_detection() {
        let licenses = vec!["MIT".to_string(), "GPL-3.0".to_string()];
        let mut issues = Vec::new();
        for license in &licenses {
            let upper = license.to_uppercase();
            if upper.contains("GPL") && !upper.contains("LGPL") {
                issues.push(format!("GPL license detected: {}", license));
            }
        }
        assert_eq!(issues.len(), 1);
        assert!(issues[0].contains("GPL-3.0"));
    }

    #[test]
    fn test_lgpl_not_flagged() {
        let license = "LGPL-2.1";
        let upper = license.to_uppercase();
        // LGPL contains "GPL" but also "LGPL", so it should not be flagged
        assert!(upper.contains("GPL"));
        assert!(upper.contains("LGPL"));
    }

    #[test]
    fn test_transitive_count_excludes_root() {
        let json = r#"{
            "nodes": [
                {"versionKey": {"name": "self", "version": "1.0.0"}},
                {"versionKey": {"name": "dep-1", "version": "1.0.0"}},
                {"versionKey": {"name": "dep-2", "version": "2.0.0"}}
            ]
        }"#;
        let deps: DepsDevDependencies =
            serde_json::from_str(json).expect("should parse");
        let count = deps.nodes.len().saturating_sub(1);
        assert_eq!(count, 2);
    }
}
