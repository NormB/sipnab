// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

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

/// Parse one RFC 3339 instant, as every surface takes a time bound.
///
/// The one parser behind the CLI's `--since`/`--until`, the REST
/// `/v1/dialogs` `after`/`before` query parameters, the MCP `search_by_time`
/// `start`/`end` arguments, the timestamp half of a [`Cursor`], and the filter
/// DSL's `time` literals. An offset other than `Z` is accepted and converted:
/// `2026-10-09T12:00:00+02:00` is `2026-10-09T10:00:00Z`.
///
/// # Errors
///
/// A message quoting the value and naming the format, without the name of the
/// flag or parameter: each caller prefixes its own.
pub fn parse_instant(raw: &str) -> Result<chrono::DateTime<chrono::Utc>, String> {
    chrono::DateTime::parse_from_rfc3339(raw)
        .map(|t| t.with_timezone(&chrono::Utc))
        .map_err(|e| format!("'{raw}' is not RFC 3339: {e}"))
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
    match parse_instant(ts) {
        Ok(at) => Ok(Cursor { at, id }),
        Err(e) => Err(format!("cursor timestamp {e}")),
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

/// The prefix of a change-sequence tail cursor: version 2 of the
/// `tail_dialogs` / `GET /v1/dialogs/tail` cursor.
///
/// Version 1 was `<RFC 3339>|<Call-ID>`, a position on `updated_at`, which
/// moves back when sipnab reads a message stamped older than one it already
/// read; a dialog could then fall behind a cursor already handed out and
/// never be returned again. Version 2 names a position in the store's own
/// change sequence, which only rises.
pub const TAIL_CURSOR_V2: &str = "v2:";

/// A parsed `tail_dialogs` / `GET /v1/dialogs/tail` cursor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TailCursor {
    /// `v2:<N>`: every dialog whose last change is after change `N`.
    Change(u64),
    /// A version-1 cursor, `<RFC 3339>` or `<RFC 3339>|<Call-ID>`, from a
    /// client that stored one: dialogs whose `updated_at` is after it, as
    /// before. The page it returns hands back a version-2 cursor.
    Legacy(Cursor),
}

/// Parse a tail cursor: `v2:<N>`, or a version-1 cursor.
///
/// # Errors
///
/// A message naming the problem: a `v2:` cursor whose number is not a whole
/// number from 0 up, a version this sipnab does not read (`v3:...`), or a
/// version-1 cursor whose timestamp is not RFC 3339.
pub fn parse_tail_cursor(raw: &str) -> Result<TailCursor, String> {
    if let Some(number) = raw.strip_prefix(TAIL_CURSOR_V2) {
        // Digits only: `u64::from_str` would also take a leading `+`.
        return if !number.is_empty() && number.bytes().all(|b| b.is_ascii_digit()) {
            number.parse().map(TailCursor::Change).map_err(|_| {
                format!(
                    "cursor '{raw}': the v2 change number is not a whole number up to {}",
                    u64::MAX
                )
            })
        } else {
            Err(format!(
                "cursor '{raw}': a v2 cursor is `v2:` and a whole number from 0 up"
            ))
        };
    }
    // `v<digits>:` is a versioned cursor, never an RFC 3339 instant, which
    // starts with a year.
    if let Some((version, _)) = raw.split_once(':')
        && version.len() > 1
        && version.starts_with('v')
        && version[1..].bytes().all(|b| b.is_ascii_digit())
    {
        return Err(format!(
            "cursor '{raw}': cursor version {version} is not one this sipnab reads; \
             pass back a next_cursor it returned, or start without a cursor"
        ));
    }
    parse_cursor(raw).map(TailCursor::Legacy)
}

/// The cursor a client passes back to resume after change `seq`.
#[must_use]
pub fn format_tail_cursor(seq: u64) -> String {
    format!("{TAIL_CURSOR_V2}{seq}")
}

/// Unit tests for the compound cursor: round-trip, the tie-break that is the
/// reason it carries an identity, and the two ways it can be malformed.
#[cfg(test)]
mod tests {
    use super::*;
    type TestError = Box<dyn std::error::Error>;

    /// A timestamp in UTC, for the cursor tests.
    fn at(s: &str) -> Result<chrono::DateTime<chrono::Utc>, TestError> {
        Ok(chrono::DateTime::parse_from_rfc3339(s)
            .map_err(|e| format!("test timestamp: {e:?}"))?
            .with_timezone(&chrono::Utc))
    }

    /// The cursor travels back in a URL query, so it must carry no `+`: there
    /// `+` decodes to a space and corrupts the timestamp. UTC renders as `Z`.
    #[test]
    fn format_cursor_is_url_safe_zulu() -> Result<(), TestError> {
        let c = format_cursor(at("2026-07-31T10:00:00Z")?, "abc@host");
        assert!(!c.contains('+'), "a `+` in a query decodes to a space: {c}");
        assert!(c.contains('Z'), "UTC renders as Zulu, not +00:00: {c}");
        Ok(())
    }

    /// The window is half-open: the lower bound is inclusive, the upper
    /// EXCLUSIVE, so adjacent windows tile without double-counting the shared
    /// instant. This is the one rule REST `/v1/dialogs` and MCP `search_by_time`
    /// share, and the boundary case is the whole reason to share it.
    #[test]
    fn time_window_is_half_open() -> Result<(), TestError> {
        let lo = at("2026-07-31T10:00:00Z")?;
        let hi = at("2026-07-31T11:00:00Z")?;
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
            at("2026-07-31T10:30:00Z")?,
            Some(lo),
            Some(hi)
        ));
        assert!(!in_time_window(
            at("2026-07-31T09:59:59Z")?,
            Some(lo),
            Some(hi)
        ));
        assert!(!in_time_window(
            at("2026-07-31T11:00:01Z")?,
            Some(lo),
            Some(hi)
        ));
        // A `None` bound is unbounded on that side.
        assert!(in_time_window(at("2000-01-01T00:00:00Z")?, None, Some(hi)));
        assert!(in_time_window(at("2099-01-01T00:00:00Z")?, Some(lo), None));
        assert!(in_time_window(lo, None, None));
        // Adjacent windows tile: the boundary instant belongs to the LATER one.
        let later = at("2026-07-31T12:00:00Z")?;
        assert!(
            !in_time_window(hi, Some(lo), Some(hi)) && in_time_window(hi, Some(hi), Some(later)),
            "the shared boundary instant is claimed by exactly one window"
        );
        Ok(())
    }

    /// A compound cursor round-trips through format and parse.
    #[test]
    fn cursor_round_trips() -> Result<(), TestError> {
        let raw = format_cursor(at("2026-07-31T10:00:00Z")?, "abc@host");
        let parsed = parse_cursor(&raw).map_err(|e| format!("parses: {e:?}"))?;
        assert_eq!(parsed.at, at("2026-07-31T10:00:00Z")?);
        assert_eq!(parsed.id.as_deref(), Some("abc@host"));
        Ok(())
    }

    /// A bare timestamp parses, keeping the pre-compound client working.
    #[test]
    fn cursor_accepts_a_bare_timestamp() -> Result<(), TestError> {
        let parsed = parse_cursor("2026-07-31T10:00:00Z").map_err(|e| format!("parses: {e:?}"))?;
        assert_eq!(parsed.id, None);
        // Strictly after, with no tie-break available.
        assert!(!parsed.precedes(at("2026-07-31T10:00:00Z")?, "anything"));
        assert!(parsed.precedes(at("2026-07-31T10:00:01Z")?, "anything"));
        Ok(())
    }

    /// A tie group split across a page boundary is neither dropped nor repeated.
    ///
    /// The reason the cursor carries an identity at all. With three records on
    /// the same instant and a page ending at the middle one, the next page must
    /// contain exactly the third.
    #[test]
    fn cursor_splits_a_tie_group_at_the_page_boundary() -> Result<(), TestError> {
        let t = at("2026-07-31T10:00:00Z")?;
        let c = parse_cursor(&format_cursor(t, "b")).map_err(|e| format!("parses: {e:?}"))?;
        assert!(!c.precedes(t, "a"), "already returned");
        assert!(!c.precedes(t, "b"), "the boundary itself was returned");
        assert!(c.precedes(t, "c"), "the rest of the tie group must follow");
        Ok(())
    }

    /// An identity containing the separator still splits at the FIRST one.
    #[test]
    fn cursor_splits_on_the_first_separator_only() -> Result<(), TestError> {
        let parsed =
            parse_cursor("2026-07-31T10:00:00Z|a|b").map_err(|e| format!("parses: {e:?}"))?;
        assert_eq!(parsed.id.as_deref(), Some("a|b"));
        Ok(())
    }

    /// An RFC 3339 instant parses, in any offset, to the same UTC instant.
    #[test]
    fn parse_instant_reads_rfc3339_in_any_offset() -> Result<(), TestError> {
        assert_eq!(
            parse_instant("2026-10-09T10:00:00Z")?,
            at("2026-10-09T10:00:00Z")?
        );
        assert_eq!(
            parse_instant("2026-10-09T12:00:00+02:00")?,
            at("2026-10-09T10:00:00Z")?
        );
        assert_eq!(
            parse_instant("2026-10-09T10:00:00.250Z")?,
            at("2026-10-09T10:00:00.250Z")?
        );
        Ok(())
    }

    /// Anything else is refused with the value quoted and the format named,
    /// so a caller's prefix is all the message needs.
    #[test]
    fn parse_instant_refuses_what_is_not_rfc3339() -> Result<(), TestError> {
        for bad in [
            "yesterday",
            "2026-10-09",
            "2026-10-09 10:00:00",
            "2026-10-09T10:00:00",
            "",
        ] {
            let err = parse_instant(bad)
                .err()
                .ok_or(format!("{bad:?} must fail"))?;
            assert!(err.contains("RFC 3339"), "{bad:?}: {err}");
            assert!(err.contains(&format!("'{bad}'")), "{bad:?}: {err}");
        }
        Ok(())
    }

    /// A cursor whose timestamp half is not RFC 3339 is an error, not a reset.
    #[test]
    fn cursor_rejects_a_non_timestamp() -> Result<(), TestError> {
        let err = parse_cursor("yesterday|abc").err().ok_or("must reject")?;
        assert!(err.contains("RFC 3339"), "got {err:?}");
        Ok(())
    }

    // ── the version-2 tail cursor ──────────────────────────────────────

    /// `v2:<N>` parses to change `N`.
    #[test]
    fn a_version_2_cursor_parses_to_its_change() -> Result<(), TestError> {
        assert_eq!(
            parse_tail_cursor("v2:42")?,
            TailCursor::Change(42),
            "v2:42 is change 42"
        );
        assert_eq!(
            parse_tail_cursor("v2:0")?,
            TailCursor::Change(0),
            "v2:0 is before every change"
        );
        Ok(())
    }

    /// The largest change number round-trips.
    #[test]
    fn the_largest_change_round_trips() -> Result<(), TestError> {
        assert_eq!(
            parse_tail_cursor(&format_tail_cursor(u64::MAX))?,
            TailCursor::Change(u64::MAX),
            "u64::MAX formats and parses back"
        );
        Ok(())
    }

    /// A version-1 cursor, compound or bare, still parses.
    #[test]
    fn a_version_1_cursor_still_parses() -> Result<(), TestError> {
        let t = at("2026-10-09T12:00:00Z")?;
        assert_eq!(
            parse_tail_cursor("2026-10-09T12:00:00Z|c@h")?,
            TailCursor::Legacy(Cursor {
                at: t,
                id: Some("c@h".to_string())
            }),
            "a compound version-1 cursor"
        );
        assert_eq!(
            parse_tail_cursor("2026-10-09T12:00:00Z")?,
            TailCursor::Legacy(Cursor { at: t, id: None }),
            "a bare version-1 cursor"
        );
        Ok(())
    }

    /// A `v2:` cursor whose number is not a whole number is refused, naming
    /// the version.
    #[test]
    fn a_version_2_cursor_without_a_number_is_refused() {
        for bad in [
            "v2:",
            "v2:abc",
            "v2:-1",
            "v2:+5",
            "v2:1.5",
            "v2: 7",
            "v2:18446744073709551616",
        ] {
            let e = parse_tail_cursor(bad).err().unwrap_or_default();
            assert!(
                e.contains("v2") && e.contains("whole number"),
                "{bad:?} is refused as a v2 cursor without a whole number: {e:?}"
            );
        }
    }

    /// A version this sipnab does not read is refused as such, not as a bad
    /// timestamp.
    #[test]
    fn an_unknown_cursor_version_is_refused_as_one() {
        for bad in ["v3:5", "v10:1"] {
            let e = parse_tail_cursor(bad).err().unwrap_or_default();
            assert!(
                e.contains("version") && !e.contains("RFC 3339"),
                "{bad:?} is refused as an unknown version: {e:?}"
            );
        }
    }

    /// A version-2 cursor is safe in a URL query: no `+`, no space, no `|`.
    #[test]
    fn a_version_2_cursor_is_url_safe() {
        let c = format_tail_cursor(1_234_567);
        assert_eq!(c, "v2:1234567", "the prefix and the number");
        assert!(
            !c.contains(['+', ' ', '|', '&', '#']),
            "{c} carries nothing a query string changes"
        );
    }
}
