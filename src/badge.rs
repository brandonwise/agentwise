const LABEL: &str = "MCP Security";

pub fn generate_badge_svg(score: i32, grade: &str) -> String {
    let score = score.clamp(0, 100);
    let grade = normalize_grade(grade);
    let (badge_color, _) = grade_color(&grade);
    let message = format!("{} ({}/100)", grade, score);

    let label_width = text_width(LABEL) + 10;
    let message_width = text_width(&message) + 10;
    let total_width = label_width + message_width;

    let label_x = (label_width * 10) / 2;
    let message_x = (label_width + message_width / 2) * 10;

    let label_text_length = text_width(LABEL) * 10;
    let message_text_length = text_width(&message) * 10;

    let label_escaped = escape_xml(LABEL);
    let message_escaped = escape_xml(&message);
    let aria_label = escape_xml(&format!("{}: {}", LABEL, message));

    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="{total_width}" height="20" role="img" aria-label="{aria_label}">
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="{total_width}" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="{label_width}" height="20" fill="#555"/>
    <rect x="{label_width}" width="{message_width}" height="20" fill="{badge_color}"/>
    <rect width="{total_width}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">
    <text aria-hidden="true" x="{label_x}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="{label_text_length}">{label_escaped}</text>
    <text x="{label_x}" y="140" transform="scale(.1)" fill="#fff" textLength="{label_text_length}">{label_escaped}</text>
    <text aria-hidden="true" x="{message_x}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="{message_text_length}">{message_escaped}</text>
    <text x="{message_x}" y="140" transform="scale(.1)" fill="#fff" textLength="{message_text_length}">{message_escaped}</text>
  </g>
</svg>"##
    )
}

pub fn generate_badge_url(score: i32, grade: &str) -> String {
    let score = score.clamp(0, 100);
    let grade = normalize_grade(grade);
    let (_, color_no_hash) = grade_color(&grade);

    format!(
        "https://img.shields.io/badge/MCP_Security-{}_({}%2F100)-{}",
        grade, score, color_no_hash
    )
}

fn normalize_grade(grade: &str) -> String {
    let upper = grade.trim().to_uppercase();
    match upper.as_str() {
        "A" | "B" | "C" | "D" | "F" => upper,
        _ => "F".to_string(),
    }
}

fn grade_color(grade: &str) -> (&'static str, &'static str) {
    match grade {
        "A" => ("#2ed573", "2ed573"),
        "B" => ("#1e90ff", "1e90ff"),
        "C" => ("#ffa502", "ffa502"),
        "D" => ("#ff6348", "ff6348"),
        _ => ("#ff4757", "ff4757"),
    }
}

fn text_width(text: &str) -> usize {
    text.chars()
        .map(|ch| match ch {
            'i' | 'l' | 'I' | '|' | '\'' | '.' | ',' | ':' | ';' => 2,
            ' ' => 3,
            't' | 'f' | 'r' | 'j' => 4,
            'm' | 'w' | 'M' | 'W' => 7,
            _ => 6,
        })
        .sum()
}

fn escape_xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_badge_svg_is_valid() {
        let svg = generate_badge_svg(95, "A");
        assert!(svg.contains("<svg"));
        assert!(svg.contains("</svg>"));
    }

    #[test]
    fn test_badge_url_encoding() {
        let url = generate_badge_url(95, "A");
        assert_eq!(
            url,
            "https://img.shields.io/badge/MCP_Security-A_(95%2F100)-2ed573"
        );
    }

    #[test]
    fn test_all_grade_colors() {
        let cases = [
            ("A", "#2ed573", "2ed573"),
            ("B", "#1e90ff", "1e90ff"),
            ("C", "#ffa502", "ffa502"),
            ("D", "#ff6348", "ff6348"),
            ("F", "#ff4757", "ff4757"),
        ];

        for (grade, svg_color, url_color) in cases {
            let svg = generate_badge_svg(88, grade);
            let url = generate_badge_url(88, grade);
            assert!(svg.contains(svg_color));
            assert!(url.ends_with(url_color));
        }
    }
}
