use serde::Deserialize;

const CVE_DB_JSON: &str = include_str!("../cvedb/mcp-cves.json");

#[derive(Debug, Clone, Deserialize)]
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
}
