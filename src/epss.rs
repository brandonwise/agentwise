use serde::Deserialize;
use std::collections::HashMap;
use std::time::Duration;

const EPSS_API_URL: &str = "https://api.first.org/data/v1/epss";
const TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone)]
pub struct EpssScore {
    pub probability: f64,
    pub percentile: f64,
}

#[derive(Debug, Deserialize)]
struct EpssResponse {
    #[serde(default)]
    data: Vec<EpssEntry>,
}

#[derive(Debug, Deserialize)]
struct EpssEntry {
    cve: String,
    epss: String,
    percentile: String,
}

/// Query the EPSS API for exploitation probability scores for one or more CVE IDs.
/// Multiple CVEs are batched in a single comma-separated request.
pub async fn query_epss(cve_ids: &[&str]) -> Result<HashMap<String, EpssScore>, String> {
    if cve_ids.is_empty() {
        return Ok(HashMap::new());
    }

    let client = reqwest::Client::builder()
        .timeout(TIMEOUT)
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

    let cve_param = cve_ids.join(",");
    let url = format!("{}?cve={}", EPSS_API_URL, cve_param);

    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("EPSS API request failed: {}", e))?;

    if !response.status().is_success() {
        return Err(format!("EPSS API returned status {}", response.status()));
    }

    let epss_response: EpssResponse = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse EPSS response: {}", e))?;

    let mut results = HashMap::new();
    for entry in epss_response.data {
        let probability = entry.epss.parse::<f64>().unwrap_or(0.0);
        let percentile = entry.percentile.parse::<f64>().unwrap_or(0.0);
        results.insert(
            entry.cve,
            EpssScore {
                probability,
                percentile,
            },
        );
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_epss_response_json() -> &'static str {
        r#"{
            "status": "OK",
            "status-code": 200,
            "version": "1.0",
            "total": 2,
            "offset": 0,
            "limit": 100,
            "data": [
                {
                    "cve": "CVE-2025-53110",
                    "epss": "0.72",
                    "percentile": "0.95"
                },
                {
                    "cve": "CVE-2025-53109",
                    "epss": "0.15",
                    "percentile": "0.42"
                }
            ]
        }"#
    }

    #[test]
    fn test_parse_epss_response() {
        let response: EpssResponse =
            serde_json::from_str(sample_epss_response_json()).expect("should parse EPSS response");
        assert_eq!(response.data.len(), 2);
        assert_eq!(response.data[0].cve, "CVE-2025-53110");
        assert_eq!(response.data[0].epss, "0.72");
        assert_eq!(response.data[0].percentile, "0.95");
    }

    #[test]
    fn test_parse_epss_scores() {
        let response: EpssResponse =
            serde_json::from_str(sample_epss_response_json()).expect("should parse");
        let mut results = HashMap::new();
        for entry in response.data {
            let probability = entry.epss.parse::<f64>().unwrap_or(0.0);
            let percentile = entry.percentile.parse::<f64>().unwrap_or(0.0);
            results.insert(
                entry.cve,
                EpssScore {
                    probability,
                    percentile,
                },
            );
        }

        assert_eq!(results.len(), 2);
        let score = results.get("CVE-2025-53110").unwrap();
        assert!((score.probability - 0.72).abs() < 0.001);
        assert!((score.percentile - 0.95).abs() < 0.001);

        let score2 = results.get("CVE-2025-53109").unwrap();
        assert!((score2.probability - 0.15).abs() < 0.001);
        assert!((score2.percentile - 0.42).abs() < 0.001);
    }

    #[test]
    fn test_parse_empty_epss_response() {
        let json = r#"{"status":"OK","data":[]}"#;
        let response: EpssResponse = serde_json::from_str(json).expect("should parse");
        assert!(response.data.is_empty());
    }

    #[test]
    fn test_parse_epss_malformed_scores() {
        let json =
            r#"{"data":[{"cve":"CVE-2025-00001","epss":"not-a-number","percentile":"also-not"}]}"#;
        let response: EpssResponse = serde_json::from_str(json).expect("should parse");
        let entry = &response.data[0];
        let probability = entry.epss.parse::<f64>().unwrap_or(0.0);
        assert_eq!(probability, 0.0);
    }

    #[test]
    fn test_parse_single_cve_response() {
        let json = r#"{
            "status": "OK",
            "data": [
                {
                    "cve": "CVE-2025-53110",
                    "epss": "0.00043",
                    "percentile": "0.12"
                }
            ]
        }"#;
        let response: EpssResponse = serde_json::from_str(json).expect("should parse");
        assert_eq!(response.data.len(), 1);
        let prob = response.data[0].epss.parse::<f64>().unwrap_or(0.0);
        assert!((prob - 0.00043).abs() < 0.00001);
    }
}
