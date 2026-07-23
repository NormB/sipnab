//! Result-shaping helpers for MCP tool responses.
//!
//! Every tool response is bounded by default to keep agent tool-call costs
//! predictable. Hard caps come from the constants here; per-call `limit`
//! parameters narrow further but never exceed the hard cap.

/// Default `limit` parameter for list-style tools.
pub const DEFAULT_LIMIT: usize = 50;

/// Maximum `limit` value a tool will accept; requests above this are clamped.
pub const HARD_LIMIT: usize = 1000;

/// Maximum SIP body / snippet bytes returned in a single response.
pub const MAX_BODY_BYTES: usize = 4096;

/// Truncate a string to `max_chars` bytes (UTF-8 boundary aware), appending
/// a marker on truncation. Used for SIP body and snippet returns.
///
/// # Arguments
///
/// * `s` — the string to bound.
/// * `max_chars` — maximum length in **bytes** (despite the name); the cut
///   point walks back to the nearest UTF-8 character boundary.
///
/// # Returns
///
/// The input unchanged when it fits, otherwise the bounded prefix with an
/// `…[truncated]` marker appended.
pub fn truncate_string(s: &str, max_chars: usize) -> String {
    if s.len() <= max_chars {
        return s.to_string();
    }
    let mut end = max_chars;
    // Walk back to a UTF-8 char boundary.
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…[truncated]", &s[..end])
}

/// Clamp a caller-supplied `limit` to `[1, HARD_LIMIT]`. A `None` or zero
/// resolves to `DEFAULT_LIMIT`.
pub fn resolve_limit(requested: Option<u32>) -> usize {
    match requested {
        None | Some(0) => DEFAULT_LIMIT,
        Some(n) => (n as usize).min(HARD_LIMIT),
    }
}

/// Unit tests for the response-bounding helpers.
#[cfg(test)]
mod tests {
    use super::*;

    /// A string shorter than the cap is returned unchanged, no marker.
    #[test]
    fn truncate_short_string_unchanged() {
        assert_eq!(truncate_string("hello", 100), "hello");
    }

    /// A string over the cap is cut at the cap and gains the truncation marker.
    #[test]
    fn truncate_long_string_marks_truncation() {
        let long = "a".repeat(50);
        let truncated = truncate_string(&long, 10);
        assert!(truncated.starts_with("aaaaaaaaaa"));
        assert!(truncated.contains("truncated"));
    }

    /// Truncating in the middle of a multi-byte codepoint must not panic.
    #[test]
    fn truncate_respects_utf8_boundaries() {
        // The é is two bytes; truncating mid-codepoint must not panic.
        let s = "abcdéfgh";
        let _ = truncate_string(s, 5);
    }

    /// `None` and `Some(0)` both resolve to the default limit.
    #[test]
    fn resolve_limit_defaults_when_unset() {
        assert_eq!(resolve_limit(None), DEFAULT_LIMIT);
        assert_eq!(resolve_limit(Some(0)), DEFAULT_LIMIT);
    }

    /// Requests above `HARD_LIMIT` are clamped down to it.
    #[test]
    fn resolve_limit_clamps_to_hard_cap() {
        assert_eq!(resolve_limit(Some(99_999)), HARD_LIMIT);
    }

    /// An in-range request passes through unmodified.
    #[test]
    fn resolve_limit_passes_through_in_range() {
        assert_eq!(resolve_limit(Some(7)), 7);
    }
}
