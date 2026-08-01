// SPDX-License-Identifier: MIT OR Apache-2.0

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

/// Truncate a string to `max_bytes` bytes (UTF-8 boundary aware), appending
/// a marker on truncation. Used for SIP body and snippet returns.
///
/// # Arguments
///
/// * `s` — the string to bound.
/// * `max_bytes` — maximum length in bytes; the cut point walks back to the
///   nearest UTF-8 character boundary.
///
/// # Returns
///
/// The input unchanged when it fits, otherwise the bounded prefix with an
/// `…[truncated]` marker appended.
pub fn truncate_string(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut end = max_bytes;
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

// ── compound pagination cursors ──────────────────────────────────────

/// Separator between the timestamp and identity halves of a compound cursor.
///
/// `|` appears in neither an RFC 3339 timestamp, a valid Call-ID (RFC 3261
/// `word`), nor the `0xSSRC@src>dst` identity the stream tools build, so
/// splitting on the first one is unambiguous.
pub const CURSOR_SEP: char = '|';

/// A parsed pagination cursor: a position in time plus the identity that
/// breaks ties at that instant.
///
/// The identity half is what makes the cursor correct rather than merely
/// present. Records sharing a timestamp are ordinary — a burst of registrations
/// lands on the same millisecond — and a bare-timestamp cursor has to choose
/// between `>` (drops the rest of the tie group) and `>=` (returns the whole
/// group again). Neither is right and both are silent. Resuming after the
/// `(timestamp, identity)` PAIR splits the group exactly where the page ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cursor {
    /// Position in time. Records at or before this are behind the cursor,
    /// subject to the identity tie-break.
    pub at: chrono::DateTime<chrono::Utc>,
    /// Identity of the last record on the previous page. `None` for a bare
    /// timestamp, which keeps the pre-compound strictly-after behaviour for
    /// clients that still send one.
    pub id: Option<String>,
}

impl Cursor {
    /// Whether a record at `(at, id)` sits strictly after this cursor.
    #[must_use]
    pub fn precedes(&self, at: chrono::DateTime<chrono::Utc>, id: &str) -> bool {
        match &self.id {
            None => at > self.at,
            Some(prev) => at > self.at || (at == self.at && id > prev.as_str()),
        }
    }
}

/// Parse `<RFC 3339>` or `<RFC 3339>|<identity>` into a [`Cursor`].
///
/// # Errors
///
/// The timestamp half when it is not RFC 3339, as a message naming the format.
/// Restarting from the beginning on a malformed cursor would loop a polling
/// agent forever without ever reporting a problem.
pub fn parse_cursor(raw: &str) -> Result<Cursor, String> {
    let (ts, id) = match raw.split_once(CURSOR_SEP) {
        Some((ts, id)) => (ts, Some(id.to_string())),
        None => (raw, None),
    };
    match chrono::DateTime::parse_from_rfc3339(ts) {
        Ok(dt) => Ok(Cursor {
            at: dt.with_timezone(&chrono::Utc),
            id,
        }),
        Err(e) => Err(format!("cursor must be RFC 3339: {e}")),
    }
}

/// Build the cursor a client passes back to resume after `(at, id)`.
#[must_use]
pub fn format_cursor(at: chrono::DateTime<chrono::Utc>, id: &str) -> String {
    format!("{}{CURSOR_SEP}{id}", at.to_rfc3339())
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

    /// A timestamp in UTC, for the cursor tests.
    fn at(s: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(s)
            .expect("test timestamp")
            .with_timezone(&chrono::Utc)
    }

    /// A compound cursor round-trips through format and parse.
    #[test]
    fn cursor_round_trips() {
        let raw = format_cursor(at("2026-07-31T10:00:00Z"), "abc@host");
        let parsed = parse_cursor(&raw).expect("parses");
        assert_eq!(parsed.at, at("2026-07-31T10:00:00Z"));
        assert_eq!(parsed.id.as_deref(), Some("abc@host"));
    }

    /// A bare timestamp parses, keeping the pre-compound client working.
    #[test]
    fn cursor_accepts_a_bare_timestamp() {
        let parsed = parse_cursor("2026-07-31T10:00:00Z").expect("parses");
        assert_eq!(parsed.id, None);
        // Strictly after, with no tie-break available.
        assert!(!parsed.precedes(at("2026-07-31T10:00:00Z"), "anything"));
        assert!(parsed.precedes(at("2026-07-31T10:00:01Z"), "anything"));
    }

    /// A tie group split across a page boundary is neither dropped nor repeated.
    ///
    /// The reason the cursor carries an identity at all. With three records on
    /// the same instant and a page ending at the middle one, the next page must
    /// contain exactly the third.
    #[test]
    fn cursor_splits_a_tie_group_at_the_page_boundary() {
        let t = at("2026-07-31T10:00:00Z");
        let c = parse_cursor(&format_cursor(t, "b")).expect("parses");
        assert!(!c.precedes(t, "a"), "already returned");
        assert!(!c.precedes(t, "b"), "the boundary itself was returned");
        assert!(c.precedes(t, "c"), "the rest of the tie group must follow");
    }

    /// An identity containing the separator still splits at the FIRST one.
    #[test]
    fn cursor_splits_on_the_first_separator_only() {
        let parsed = parse_cursor("2026-07-31T10:00:00Z|a|b").expect("parses");
        assert_eq!(parsed.id.as_deref(), Some("a|b"));
    }

    /// A cursor whose timestamp half is not RFC 3339 is an error, not a reset.
    #[test]
    fn cursor_rejects_a_non_timestamp() {
        let err = parse_cursor("yesterday|abc").expect_err("must reject");
        assert!(err.contains("RFC 3339"), "got {err:?}");
    }
}
