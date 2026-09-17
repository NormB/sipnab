// SPDX-License-Identifier: MIT OR Apache-2.0

//! Compound pagination cursors: a position in time plus the identity that
//! breaks ties at that instant.
//!
//! Change-tracking pollers resume from a cursor rather than re-reading from the
//! start. The rule is delicate in exactly one place — a tie group of records
//! sharing a timestamp, split across a page boundary — and getting it wrong is
//! silent: a `>` filter drops the rest of the group, a `>=` filter returns the
//! whole group again. Resuming after the `(timestamp, identity)` PAIR splits
//! the group exactly where the page ended.
//!
//! This lives outside the `mcp` feature so every surface that paginates by
//! change — the MCP `tail_dialogs`/`tail_streams`/`list_*` tools and the REST
//! `/v1/dialogs/tail` route — resumes from one implementation of the tie-break.

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
    /// timestamp, which keeps the pre-compound strictly-after behavior for
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

/// Whether an instant falls inside a half-open `[after, before)` window.
///
/// The lower bound is inclusive and the upper bound EXCLUSIVE — the rule the MCP
/// `search_by_time` tool has always applied, and, because this is the one shared
/// implementation, the rule the REST `/v1/dialogs` `after`/`before` filter and
/// the TUI's time-range filter apply too. Half-open is what lets adjacent
/// windows tile without overlap: a dialog at exactly `before` belongs to the
/// next window, so `[09:00, 10:00)` and `[10:00, 11:00)` each claim the 10:00
/// instant exactly once. A `None` bound is unbounded on that side.
#[must_use]
pub fn in_time_window(
    t: chrono::DateTime<chrono::Utc>,
    after: Option<chrono::DateTime<chrono::Utc>>,
    before: Option<chrono::DateTime<chrono::Utc>>,
) -> bool {
    after.is_none_or(|a| t >= a) && before.is_none_or(|b| t < b)
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
///
/// The timestamp renders as Zulu (`Z`), not `+00:00`. The cursor travels back
/// in a URL query (REST `?since=`), where `+` decodes to a space and would
/// corrupt the timestamp into a 400. `Z` is the same instant, valid RFC 3339,
/// URL-safe, and the form the `after`/`before` query params already use.
/// [`parse_cursor`] accepts both, so a cursor minted before this still resumes.
#[must_use]
pub fn format_cursor(at: chrono::DateTime<chrono::Utc>, id: &str) -> String {
    format!(
        "{}{CURSOR_SEP}{id}",
        at.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true)
    )
}

/// Unit tests for the compound cursor: round-trip, the tie-break that is the
/// reason it carries an identity, and the two ways it can be malformed.
#[cfg(test)]
mod tests {
    use super::*;

    /// A timestamp in UTC, for the cursor tests.
    fn at(s: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(s)
            .expect("test timestamp")
            .with_timezone(&chrono::Utc)
    }

    /// The cursor travels back in a URL query, so it must carry no `+`: there
    /// `+` decodes to a space and corrupts the timestamp. UTC renders as `Z`.
    #[test]
    fn format_cursor_is_url_safe_zulu() {
        let c = format_cursor(at("2026-07-31T10:00:00Z"), "abc@host");
        assert!(!c.contains('+'), "a `+` in a query decodes to a space: {c}");
        assert!(c.contains('Z'), "UTC renders as Zulu, not +00:00: {c}");
    }

    /// The window is half-open: the lower bound is inclusive, the upper
    /// EXCLUSIVE, so adjacent windows tile without double-counting the shared
    /// instant. This is the one rule REST `/v1/dialogs` and MCP `search_by_time`
    /// share, and the boundary case is the whole reason to share it.
    #[test]
    fn time_window_is_half_open() {
        let lo = at("2026-07-31T10:00:00Z");
        let hi = at("2026-07-31T11:00:00Z");
        // Inclusive lower bound.
        assert!(
            in_time_window(lo, Some(lo), Some(hi)),
            "t == after is inside"
        );
        // EXCLUSIVE upper bound — the crux of the unification.
        assert!(
            !in_time_window(hi, Some(lo), Some(hi)),
            "t == before is OUTSIDE the window"
        );
        // Interior stays in; either side stays out.
        assert!(in_time_window(
            at("2026-07-31T10:30:00Z"),
            Some(lo),
            Some(hi)
        ));
        assert!(!in_time_window(
            at("2026-07-31T09:59:59Z"),
            Some(lo),
            Some(hi)
        ));
        assert!(!in_time_window(
            at("2026-07-31T11:00:01Z"),
            Some(lo),
            Some(hi)
        ));
        // A `None` bound is unbounded on that side.
        assert!(in_time_window(at("2000-01-01T00:00:00Z"), None, Some(hi)));
        assert!(in_time_window(at("2099-01-01T00:00:00Z"), Some(lo), None));
        assert!(in_time_window(lo, None, None));
        // Adjacent windows tile: the boundary instant belongs to the LATER one.
        let later = at("2026-07-31T12:00:00Z");
        assert!(
            !in_time_window(hi, Some(lo), Some(hi)) && in_time_window(hi, Some(hi), Some(later)),
            "the shared boundary instant is claimed by exactly one window"
        );
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
