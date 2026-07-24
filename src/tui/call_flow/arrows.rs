// SPDX-License-Identifier: MIT OR Apache-2.0

//! Arrow formatting for call flow ladder diagrams.
//!
//! Provides the unified `format_arrow` function that draws arrows between
//! arbitrary column positions, as well as the legacy `format_arrow_right`
//! and `format_arrow_left` wrappers for the Paragraph-based rendering path.
//! Also home of the UTF-8-safe `truncate` helper used for labels throughout
//! the call-flow view.

/// Format an arrow between two column positions.
///
/// The arrow occupies the columns strictly between the two pipes: it starts
/// one column after the leftmost pipe and its head lands on the column of
/// the rightmost pipe. Requests use a solid shaft (`─`), responses a dashed
/// one (`╌`). The label is centered on the shaft when it fits; a label wider
/// than the gap is truncated (with ellipsis) rather than dropped, and only a
/// gap too narrow for any meaningful text (< 8 usable columns) falls back to
/// a bare line. A gap under 4 columns yields a minimal 2-character arrow.
///
/// # Arguments
/// * `label` — method/status text to center on the shaft.
/// * `src_x` — buffer column of the source participant's pipe.
/// * `dst_x` — buffer column of the destination participant's pipe;
///   `dst_x > src_x` points the arrowhead right, otherwise left.
/// * `is_response` — dashed shaft when true, solid when false.
///
/// # Returns
/// `(arrow, start_x)`: the rendered arrow string and the buffer column to
/// start drawing it at (`min(src_x, dst_x) + 1`).
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

    // A label wider than the gap is truncated to fit — dropping the text
    // entirely leaves a blank arrow that reads as an empty row (seen with
    // OpenSIPS' 42-char "100 trying -- your call is important to us").
    // Only a gap too narrow for any meaningful text falls back to a bare
    // line. `width - 4` = pads + line char + arrow head.
    let fit_label = if label.len() + 4 > width {
        let avail = width.saturating_sub(4);
        (avail >= 8).then(|| truncate(label, avail))
    } else {
        Some(label.to_string())
    };
    let arrow = match fit_label {
        None => {
            // No room for text, just draw the line
            let line: String = std::iter::repeat_n(line_char, width.saturating_sub(1)).collect();
            if goes_right {
                format!("{line}\u{25B6}")
            } else {
                format!("\u{25C0}{line}")
            }
        }
        Some(label) => {
            let label_with_pad = label.len() + 2;
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
        }
    };

    (arrow, start)
}

/// Format a right-pointing arrow with the label centered: `─────── LABEL ────────▶`
///
/// Uses dashed lines (`╌`) for responses, solid lines (`─`) for requests.
/// Used by the Paragraph-based rendering path. `width` is the target column
/// span of the arrow; a label too wide for it degrades to a fixed short
/// two-dash form rather than truncating. Returns the arrow string ending in
/// the `▶` head.
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
/// Used by the Paragraph-based rendering path. `width` is the target column
/// span of the arrow; a label too wide for it degrades to a fixed short
/// two-dash form rather than truncating. Returns the arrow string starting
/// with the `◀` head.
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

/// Truncate a string to at most `max_len` bytes, appending "..." if truncated
/// (for ASCII input this equals a character count). A `max_len` of 3 or less
/// keeps the first `max_len` chars with no ellipsis. Walks back to a char
/// boundary so multi-byte UTF-8 input never panics; the result may therefore
/// come in under the limit. Returns the (possibly shortened) owned string.
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

/// Tests for arrow formatting and UTF-8-safe label truncation.
#[cfg(test)]
mod tests {
    use super::*;

    /// Field report: OpenSIPS' long default reason phrase
    /// ("100 trying -- your call is important to us", 42 chars) rendered
    /// as a bare dashed arrow with no text because the label was dropped
    /// whenever it was wider than the pipe gap. It must be truncated
    /// onto the arrow instead — a labelless arrow reads as an empty row.
    #[test]
    fn format_arrow_truncates_oversized_label() {
        let label = "100 trying -- your call is important to us";
        // Pipes at columns 10 and 40 → a 29-column gap, far narrower
        // than the 42-char label.
        let (arrow, _) = format_arrow(label, 10, 40, true);
        assert!(
            arrow.contains("100 trying"),
            "label must survive (truncated), got: {arrow}"
        );
        assert!(arrow.contains("..."), "truncation must be visible: {arrow}");
        assert!(arrow.chars().count() <= 29, "must fit the gap: {arrow}");
        assert!(arrow.ends_with('\u{25B6}'), "arrow head kept: {arrow}");

        // Same, pointing left.
        let (arrow, _) = format_arrow(label, 40, 10, true);
        assert!(arrow.contains("100 trying"), "got: {arrow}");
        assert!(arrow.starts_with('\u{25C0}'), "got: {arrow}");
        assert!(arrow.chars().count() <= 29, "got: {arrow}");
    }

    /// A gap too narrow for any meaningful text keeps the bare line
    /// (no panic, no negative widths).
    #[test]
    fn format_arrow_tiny_gap_keeps_bare_line() {
        let label = "100 trying -- your call is important to us";
        for dst in 11..22 {
            let (arrow, _) = format_arrow(label, 10, dst, true);
            assert!(!arrow.is_empty());
            // Never wider than the gap plus the minimal 2-char arrow.
            let gap = (dst - 11) as usize;
            assert!(arrow.chars().count() <= gap.max(2));
        }
    }

    /// A right arrow keeps its label and ends in the `▶` head.
    #[test]
    fn format_arrow_right_contains_label() {
        let arrow = format_arrow_right("INVITE", 24, false);
        assert!(arrow.contains("INVITE"));
        assert!(arrow.ends_with('\u{25B6}')); // ▶
    }

    /// A left arrow keeps its label and starts with the `◀` head.
    #[test]
    fn format_arrow_left_contains_label() {
        let arrow = format_arrow_left("200 OK", 24, true);
        assert!(arrow.contains("200 OK"));
        assert!(arrow.starts_with('\u{25C0}')); // ◀
    }

    /// Short input passes through; long input truncates to `max_len` with "...".
    #[test]
    fn truncate_long_string() {
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("hello world foo", 10), "hello w...");
    }

    /// `max_len <= 3` keeps the first chars without an ellipsis.
    #[test]
    fn truncate_short_max() {
        assert_eq!(truncate("hello", 3), "hel");
    }

    /// `dst_x > src_x` renders a rightward arrow starting at `src_x + 1`.
    #[test]
    fn format_arrow_right_goes_right() {
        // src_x=10, dst_x=50 => goes right
        let (arrow, start) = format_arrow("INVITE", 10, 50, false);
        assert!(arrow.contains("INVITE"));
        assert!(arrow.ends_with('\u{25B6}')); // ▶
        assert_eq!(start, 11); // src_x + 1
    }

    /// `dst_x < src_x` renders a leftward arrow starting after the lower pipe.
    #[test]
    fn format_arrow_left_goes_left() {
        // src_x=50, dst_x=10 => goes left
        let (arrow, start) = format_arrow("200 OK", 50, 10, true);
        assert!(arrow.contains("200 OK"));
        assert!(arrow.starts_with('\u{25C0}')); // ◀
        assert_eq!(start, 11); // min(50,10) + 1
    }

    /// A sub-4-column gap still yields a minimal arrow with a head.
    #[test]
    fn format_arrow_narrow() {
        // Very narrow: width = 3
        let (arrow, _) = format_arrow("X", 10, 13, false);
        assert!(arrow.contains('\u{25B6}') || arrow.contains('\u{25C0}'));
    }

    // ── UTF-8 safe truncation ──────────────────────────────────────────

    /// Input shorter than the limit is returned unchanged.
    #[test]
    fn truncate_short_string_unchanged() {
        assert_eq!(truncate("hello", 10), "hello");
    }

    /// The ellipsis is counted inside the limit: 11 chars into 8 keeps 5 + "...".
    #[test]
    fn truncate_exact_fit() {
        assert_eq!(truncate("hello world", 8), "hello...");
    }

    /// 2-byte Latin chars near the cut point truncate without panicking.
    #[test]
    fn truncate_multibyte_latin_no_panic() {
        // "héllo wörld" contains 2-byte UTF-8 chars (é = 0xC3 0xA9, ö = 0xC3 0xB6)
        let result = truncate("héllo wörld", 8);
        assert!(result.len() <= 11); // Output bytes may vary due to multibyte
        assert!(result.ends_with("..."));
    }

    /// 3-byte CJK chars truncate on a char boundary without panicking.
    #[test]
    fn truncate_cjk_no_panic() {
        // "日本語テスト" — each char is 3 bytes in UTF-8
        let result = truncate("日本語テスト", 6);
        // Should not panic. The result length in bytes may be <= 6 or just the
        // chars that fit plus "...", depending on boundary walking.
        assert!(!result.is_empty());
    }
}
