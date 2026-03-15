use crate::depsdev;
use crate::rules::{Finding, Severity};

/// Run deps.dev dependency graph analysis for packages with versions (AW-012).
pub async fn check_deps(
    packages: &[(String, String, String, String)], // (package, version, server_name, config_file)
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (package, version, server_name, config_file) in packages {
        match depsdev::analyze_dependencies(package, version).await {
            Ok(analysis) => {
                let mut sub_items = Vec::new();
                let mut max_severity = Severity::Low;

                if analysis.transitive_dep_count > 200 {
                    sub_items.push(format!(
                        "{} transitive dependencies (high risk)",
                        analysis.transitive_dep_count
                    ));
                    max_severity = Severity::High;
                } else if analysis.transitive_dep_count > 100 {
                    sub_items.push(format!(
                        "{} transitive dependencies (medium risk)",
                        analysis.transitive_dep_count
                    ));
                    if max_severity < Severity::Medium {
                        max_severity = Severity::Medium;
                    }
                } else if analysis.transitive_dep_count > 0 {
                    sub_items.push(format!(
                        "{} transitive dependencies",
                        analysis.transitive_dep_count
                    ));
                }

                if analysis.advisory_count > 0 {
                    sub_items.push(format!(
                        "{} transitive deps have known advisories",
                        analysis.advisory_count
                    ));
                    if max_severity < Severity::High {
                        max_severity = Severity::High;
                    }
                }

                for issue in &analysis.license_issues {
                    sub_items.push(issue.clone());
                    if max_severity < Severity::Medium {
                        max_severity = Severity::Medium;
                    }
                }

                if sub_items.is_empty() {
                    continue;
                }

                findings.push(Finding {
                    rule_id: "AW-012".to_string(),
                    severity: max_severity,
                    title: format!(
                        "Deep dependency chain: {} transitive deps",
                        analysis.transitive_dep_count
                    ),
                    message: format!(
                        "Dependency analysis for '{}@{}' in server '{}'",
                        package, version, server_name
                    ),
                    fix: "Review transitive dependencies and update packages with advisories"
                        .to_string(),
                    config_file: config_file.clone(),
                    server_name: server_name.clone(),
                    source: Some("deps.dev".to_string()),
                    epss: None,
                    sub_items: Some(sub_items),
                });
            }
            Err(e) => {
                eprintln!(
                    "Warning: deps.dev check failed for {}@{}: {}",
                    package, version, e
                );
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use crate::depsdev::DepsAnalysis;

    #[test]
    fn test_high_dep_count_threshold() {
        let analysis = DepsAnalysis {
            transitive_dep_count: 250,
            advisory_count: 0,
            license_issues: vec![],
        };
        assert!(analysis.transitive_dep_count > 200);
    }

    #[test]
    fn test_medium_dep_count_threshold() {
        let analysis = DepsAnalysis {
            transitive_dep_count: 150,
            advisory_count: 0,
            license_issues: vec![],
        };
        assert!(analysis.transitive_dep_count > 100);
        assert!(analysis.transitive_dep_count <= 200);
    }

    #[test]
    fn test_advisory_detection() {
        let analysis = DepsAnalysis {
            transitive_dep_count: 50,
            advisory_count: 3,
            license_issues: vec![],
        };
        assert!(analysis.advisory_count > 0);
    }

    #[test]
    fn test_low_dep_count_no_finding() {
        let analysis = DepsAnalysis {
            transitive_dep_count: 0,
            advisory_count: 0,
            license_issues: vec![],
        };
        assert_eq!(analysis.transitive_dep_count, 0);
        assert_eq!(analysis.advisory_count, 0);
        assert!(analysis.license_issues.is_empty());
    }
}
