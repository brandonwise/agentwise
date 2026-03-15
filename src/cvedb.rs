use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;

const CVE_DB_JSON: &str = include_str!("../cvedb/mcp-cves.json");

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CveEntry {
    pub id: String,
    pub package: String,
    pub affected_below: String,
    pub severity: String,
    pub cvss: f64,
    pub description: String,
    pub fix: String,
}

/// Load the embedded CVE database.
pub fn load_cve_db() -> Vec<CveEntry> {
    serde_json::from_str(CVE_DB_JSON).expect("embedded CVE database should be valid JSON")
}

/// Return the path to the local CVE cache file.
pub fn cache_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home)
        .join(".agentwise")
        .join("cve-cache.json")
}

/// Load CVEs from the local cache (~/.agentwise/cve-cache.json), if it exists.
pub fn load_cached_db() -> Vec<CveEntry> {
    let path = cache_path();
    if !path.exists() {
        return Vec::new();
    }
    match std::fs::read_to_string(&path) {
        Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

/// Save CVE entries to the local cache.
pub fn save_cache(entries: &[CveEntry]) -> Result<(), String> {
    let path = cache_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create cache directory: {}", e))?;
    }
    let json = serde_json::to_string_pretty(entries)
        .map_err(|e| format!("Failed to serialize CVE cache: {}", e))?;
    std::fs::write(&path, json).map_err(|e| format!("Failed to write CVE cache: {}", e))?;
    Ok(())
}

/// Load CVEs from embedded DB + local cache, deduplicated by CVE ID.
pub fn load_merged_db() -> Vec<CveEntry> {
    let mut entries = load_cve_db();
    let cached = load_cached_db();

    let existing_ids: HashSet<String> = entries.iter().map(|e| e.id.clone()).collect();

    for entry in cached {
        if !existing_ids.contains(&entry.id) {
            entries.push(entry);
        }
    }

    entries
}

/// Check if a package + version is affected by any known CVE.
pub fn check_package(package: &str, version: &str, db: &[CveEntry]) -> Vec<CveEntry> {
    db.iter()
        .filter(|cve| {
            cve.package == package && version_less_than(version, &cve.affected_below)
        })
        .cloned()
        .collect()
}

/// Simple semver less-than comparison.
/// Returns true if `version` < `threshold`.
/// Handles x.y.z format. Falls back to string comparison for non-standard versions.
fn version_less_than(version: &str, threshold: &str) -> bool {
    let v = parse_version(version);
    let t = parse_version(threshold);
    v < t
}

/// Parse a version string into a comparable tuple of (major, minor, patch).
fn parse_version(s: &str) -> (u64, u64, u64) {
    let parts: Vec<&str> = s.split('.').collect();
    let major = parts.first().and_then(|p| p.parse().ok()).unwrap_or(0);
    let minor = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(0);
    let patch = parts.get(2).and_then(|p| p.parse().ok()).unwrap_or(0);
    (major, minor, patch)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_cve_db() {
        let db = load_cve_db();
        assert!(!db.is_empty());
        assert!(db.iter().any(|c| c.id == "CVE-2025-53110"));
    }

    #[test]
    fn test_version_less_than() {
        assert!(version_less_than("0.5.0", "0.6.3"));
        assert!(version_less_than("0.6.2", "0.6.3"));
        assert!(!version_less_than("0.6.3", "0.6.3"));
        assert!(!version_less_than("0.7.0", "0.6.3"));
        assert!(!version_less_than("1.0.0", "0.6.3"));
    }

    #[test]
    fn test_version_comparison_major() {
        assert!(version_less_than("0.9.9", "1.0.0"));
        assert!(!version_less_than("1.0.0", "1.0.0"));
        assert!(!version_less_than("2.0.0", "1.0.0"));
    }

    #[test]
    fn test_check_package_match() {
        let db = load_cve_db();
        let results = check_package("@modelcontextprotocol/server-filesystem", "0.5.0", &db);
        assert_eq!(results.len(), 2);
        let ids: Vec<&str> = results.iter().map(|c| c.id.as_str()).collect();
        assert!(ids.contains(&"CVE-2025-53110"));
        assert!(ids.contains(&"CVE-2025-53109"));
    }

    #[test]
    fn test_check_package_no_match() {
        let db = load_cve_db();
        let results = check_package("@modelcontextprotocol/server-filesystem", "0.6.3", &db);
        assert!(results.is_empty());
    }

    #[test]
    fn test_check_package_unknown() {
        let db = load_cve_db();
        let results = check_package("unknown-package", "1.0.0", &db);
        assert!(results.is_empty());
    }

    #[test]
    fn test_load_merged_db_includes_embedded() {
        let merged = load_merged_db();
        // Should at least have all embedded entries
        let embedded = load_cve_db();
        assert!(merged.len() >= embedded.len());
    }

    #[test]
    fn test_cache_path() {
        let path = cache_path();
        assert!(path.to_string_lossy().contains("cve-cache.json"));
    }

    #[test]
    fn test_cve_entry_serialization() {
        let entry = CveEntry {
            id: "CVE-2025-00001".to_string(),
            package: "test-package".to_string(),
            affected_below: "1.0.0".to_string(),
            severity: "high".to_string(),
            cvss: 7.5,
            description: "Test vulnerability".to_string(),
            fix: "Upgrade to >=1.0.0".to_string(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: CveEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, "CVE-2025-00001");
        assert_eq!(deserialized.cvss, 7.5);
    }
}
