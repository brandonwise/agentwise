use crate::rules::Severity;

/// Compute a security score (0-100) and letter grade from findings.
pub fn compute_score(severities: &[Severity]) -> (i32, String) {
    let mut score: i32 = 100;
    for sev in severities {
        score -= match sev {
            Severity::Critical => 20,
            Severity::High => 10,
            Severity::Medium => 5,
            Severity::Low => 2,
        };
    }
    let score = score.max(0);
    let grade = match score {
        90..=100 => "A",
        80..=89 => "B",
        70..=79 => "C",
        60..=69 => "D",
        _ => "F",
    };
    (score, grade.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_perfect_score() {
        let (score, grade) = compute_score(&[]);
        assert_eq!(score, 100);
        assert_eq!(grade, "A");
    }

    #[test]
    fn test_single_critical() {
        let (score, grade) = compute_score(&[Severity::Critical]);
        assert_eq!(score, 80);
        assert_eq!(grade, "B");
    }

    #[test]
    fn test_mixed_findings() {
        let severities = vec![
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
        ];
        let (score, grade) = compute_score(&severities);
        // 100 - 20 - 10 - 5 - 2 = 63
        assert_eq!(score, 63);
        assert_eq!(grade, "D");
    }

    #[test]
    fn test_floor_at_zero() {
        let severities = vec![Severity::Critical; 10];
        let (score, grade) = compute_score(&severities);
        assert_eq!(score, 0);
        assert_eq!(grade, "F");
    }

    #[test]
    fn test_grade_boundaries() {
        assert_eq!(compute_score(&[]).1, "A");
        assert_eq!(compute_score(&[Severity::Low]).1, "A"); // 98
        assert_eq!(compute_score(&[Severity::High]).1, "A"); // 90
        assert_eq!(compute_score(&[Severity::High, Severity::Low]).1, "B"); // 88
        assert_eq!(compute_score(&[Severity::Critical]).1, "B"); // 80
        assert_eq!(
            compute_score(&[Severity::Critical, Severity::High]).1,
            "C"
        ); // 70
        assert_eq!(
            compute_score(&[Severity::Critical, Severity::High, Severity::Medium]).1,
            "D"
        ); // 65
        assert_eq!(
            compute_score(&[Severity::Critical, Severity::Critical]).1,
            "D"
        ); // 60
        assert_eq!(
            compute_score(&[Severity::Critical; 3]).1,
            "F"
        ); // 40
    }
}
