//! Arrow formatting for call flow ladder diagrams.
//!
//! Provides the unified `format_arrow` function that draws arrows between
//! arbitrary column positions, as well as the legacy `format_arrow_right`
//! and `format_arrow_left` wrappers for the Paragraph-based rendering path.

/// Format an arrow between two column positions.
///
/// Returns the arrow string and the x-position to start drawing.
pub fn format_arrow(label: &str, src_x: u16, dst_x: u16, is_response: bool) -> (String, u16) {
    let goes_right = dst_x > src_x;
    let start = src_x.min(dst_x) + 1; // after the source pipe
    let end = src_x.max(dst_x); // at the dest pipe (arrow head lands here)
    let width = (end - start) as usize;

    let line_char = if is_response { '\u{254C}' } else { '\u{2500}' };

    if width < 4 {
        // Too narrow, minimal arrow
        let arrow = if goes_right {
            format!("{line_char}\u{25B6}")
        } else {
            format!("\u{25C0}{line_char}")
        };
        return (arrow, start);
    }

    let label_with_pad = label.len() + 2;
    let arrow = if label_with_pad + 2 > width {
        // Label doesn't fit, just draw the line
        let line: String = std::iter::repeat_n(line_char, width.saturating_sub(1)).collect();
        if goes_right {
            format!("{line}\u{25B6}")
        } else {
            format!("\u{25C0}{line}")
        }
    } else {
        let total_lines = width.saturating_sub(label_with_pad + 1);
        let left = total_lines / 2;
        let right = total_lines - left;
        let left_str: String = std::iter::repeat_n(line_char, left).collect();
        let right_str: String = std::iter::repeat_n(line_char, right).collect();
        if goes_right {
            format!("{left_str} {label} {right_str}\u{25B6}")
        } else {
            format!("\u{25C0}{left_str} {label} {right_str}")
        }
    };

    (arrow, start)
}

/// Format a right-pointing arrow with the label centered: `─────── LABEL ────────▶`
///
/// Uses dashed lines (`╌`) for responses, solid lines (`─`) for requests.
/// Used by the Paragraph-based rendering path.
pub fn format_arrow_right(label: &str, width: usize, is_response: bool) -> String {
    let line_char = if is_response { '\u{254C}' } else { '\u{2500}' }; // ╌ or ─
    let arrow_head = '\u{25B6}'; // ▶
    let label_with_pad = label.len() + 2;
    if width <= label_with_pad + 3 {
        let line = if is_response {
            "\u{254C}\u{254C}"
        } else {
            "\u{2500}\u{2500}"
        };
        return format!("{line} {label} {line_char}{arrow_head}");
    }
    let total_lines = width.saturating_sub(label_with_pad + 1);
    let left = total_lines / 2;
    let right = total_lines - left;
    let left_str: String = std::iter::repeat_n(line_char, left).collect();
    let right_str: String = std::iter::repeat_n(line_char, right).collect();
    format!("{left_str} {label} {right_str}{arrow_head}")
}

/// Format a left-pointing arrow with the label centered: `◀────── LABEL ─────────`
///
/// Uses dashed lines (`╌`) for responses, solid lines (`─`) for requests.
/// Used by the Paragraph-based rendering path.
pub fn format_arrow_left(label: &str, width: usize, is_response: bool) -> String {
    let line_char = if is_response { '\u{254C}' } else { '\u{2500}' }; // ╌ or ─
    let arrow_head = '\u{25C0}'; // ◀
    let label_with_pad = label.len() + 2;
    if width <= label_with_pad + 3 {
        let line = if is_response {
            "\u{254C}\u{254C}"
        } else {
            "\u{2500}\u{2500}"
        };
        return format!("{arrow_head}{line_char} {label} {line}");
    }
    let total_lines = width.saturating_sub(label_with_pad + 1);
    let left = total_lines / 2;
    let right = total_lines - left;
    let left_str: String = std::iter::repeat_n(line_char, left).collect();
    let right_str: String = std::iter::repeat_n(line_char, right).collect();
    format!("{arrow_head}{left_str} {label} {right_str}")
}

/// Truncate a string to a maximum display length, appending "..." if truncated.
/// Uses char boundaries to avoid panics on multi-byte UTF-8 input.
pub fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        return s.to_string();
    }
    if max_len <= 3 {
        return s.chars().take(max_len).collect();
    }
    let mut end = max_len - 3;
    // Walk back to a char boundary
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &s[..end])
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_arrow_right_contains_label() {
        let arrow = format_arrow_right("INVITE", 24, false);
        assert!(arrow.contains("INVITE"));
        assert!(arrow.ends_with('\u{25B6}')); // ▶
    }

    #[test]
    fn format_arrow_left_contains_label() {
        let arrow = format_arrow_left("200 OK", 24, true);
        assert!(arrow.contains("200 OK"));
        assert!(arrow.starts_with('\u{25C0}')); // ◀
    }

    #[test]
    fn truncate_long_string() {
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("hello world foo", 10), "hello w...");
    }

    #[test]
    fn truncate_short_max() {
        assert_eq!(truncate("hello", 3), "hel");
    }

    #[test]
    fn format_arrow_right_goes_right() {
        // src_x=10, dst_x=50 => goes right
        let (arrow, start) = format_arrow("INVITE", 10, 50, false);
        assert!(arrow.contains("INVITE"));
        assert!(arrow.ends_with('\u{25B6}')); // ▶
        assert_eq!(start, 11); // src_x + 1
    }

    #[test]
    fn format_arrow_left_goes_left() {
        // src_x=50, dst_x=10 => goes left
        let (arrow, start) = format_arrow("200 OK", 50, 10, true);
        assert!(arrow.contains("200 OK"));
        assert!(arrow.starts_with('\u{25C0}')); // ◀
        assert_eq!(start, 11); // min(50,10) + 1
    }

    #[test]
    fn format_arrow_narrow() {
        // Very narrow: width = 3
        let (arrow, _) = format_arrow("X", 10, 13, false);
        assert!(arrow.contains('\u{25B6}') || arrow.contains('\u{25C0}'));
    }

    // ── UTF-8 safe truncation ──────────────────────────────────────────

    #[test]
    fn truncate_short_string_unchanged() {
        assert_eq!(truncate("hello", 10), "hello");
    }

    #[test]
    fn truncate_exact_fit() {
        assert_eq!(truncate("hello world", 8), "hello...");
    }

    #[test]
    fn truncate_multibyte_latin_no_panic() {
        // "héllo wörld" contains 2-byte UTF-8 chars (é = 0xC3 0xA9, ö = 0xC3 0xB6)
        let result = truncate("héllo wörld", 8);
        assert!(result.len() <= 11); // Output bytes may vary due to multibyte
        assert!(result.ends_with("..."));
    }

    #[test]
    fn truncate_cjk_no_panic() {
        // "日本語テスト" — each char is 3 bytes in UTF-8
        let result = truncate("日本語テスト", 6);
        // Should not panic. The result length in bytes may be <= 6 or just the
        // chars that fit plus "...", depending on boundary walking.
        assert!(!result.is_empty());
    }
}
