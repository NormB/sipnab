// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The F7 dialog's Expression history: the expressions applied in this
//! session, newest first, which Up and Down recall into the field.
//!
//! Only an expression the dialog applied enters it, so every entry is one
//! the parser accepted. An entry applied again moves to the front instead of
//! being stored twice, and the oldest entry leaves once
//! [`EXPRESSION_HISTORY_MAX`] are held. The history lives for the session and
//! is never written to disk.

use std::collections::VecDeque;

/// How many expressions the history keeps: the newest 50.
///
/// Enough to walk back through one investigation; a bound so a long session
/// that applies expressions from a script or a pasted list cannot grow it
/// without end.
pub(in crate::tui) const EXPRESSION_HISTORY_MAX: usize = 50;

/// Where a recall walk stands: which entry the field shows, and the text the
/// field held before the walk began, which walking past the newest entry
/// puts back.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Walk {
    /// Index into the entries, 0 being the newest.
    index: usize,
    /// The field's text when the first Up was pressed.
    draft: String,
}

/// The applied expressions of a session, newest first, and the state of a
/// recall walk through them.
#[derive(Debug, Clone, Default)]
pub(in crate::tui) struct ExpressionHistory {
    /// Newest first, each trimmed, no two equal, at most
    /// [`EXPRESSION_HISTORY_MAX`].
    entries: VecDeque<String>,
    /// The recall walk in progress, if any.
    walk: Option<Walk>,
}

impl ExpressionHistory {
    /// Record `text`, an expression the dialog just applied.
    ///
    /// The text is trimmed; a blank one is not recorded. A text already held
    /// moves to the front. Past [`EXPRESSION_HISTORY_MAX`] the oldest entry is
    /// dropped. Ends any recall walk.
    pub(in crate::tui) fn record(&mut self, text: &str) {
        self.walk = None;
        let text = text.trim();
        if text.is_empty() {
            return;
        }
        self.entries.retain(|held| held != text);
        self.entries.push_front(text.to_owned());
        self.entries.truncate(EXPRESSION_HISTORY_MAX);
    }

    /// The entries, newest first. Read by the tests; the dialog walks them
    /// with [`Self::older`] and [`Self::newer`].
    #[cfg(test)]
    pub(in crate::tui) fn entries(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(String::as_str)
    }

    /// The next older entry for the field, starting a walk at the newest one.
    ///
    /// # Arguments
    /// * `current` - the field's text now; kept as the draft when this starts
    ///   a walk, so walking back past the newest entry restores it.
    ///
    /// # Returns
    /// The entry to show, or `None` when there is no older one (an empty
    /// history, or the walk is at the oldest entry); the walk is then
    /// unchanged.
    pub(in crate::tui) fn older(&mut self, current: &str) -> Option<&str> {
        let next = self.walk.as_ref().map_or(0, |w| w.index + 1);
        if next >= self.entries.len() {
            return None;
        }
        match &mut self.walk {
            Some(walk) => walk.index = next,
            None => {
                self.walk = Some(Walk {
                    index: next,
                    draft: current.to_owned(),
                });
            }
        }
        self.entries.get(next).map(String::as_str)
    }

    /// The next newer entry for the field, or the draft after the newest.
    ///
    /// # Returns
    /// `None` when no walk is in progress. Otherwise the newer entry, or, from
    /// the newest entry, the draft the walk began with, which ends the walk.
    pub(in crate::tui) fn newer(&mut self) -> Option<String> {
        let walk = self.walk.as_mut()?;
        if walk.index == 0 {
            return self.walk.take().map(|w| w.draft);
        }
        walk.index -= 1;
        self.entries.get(walk.index).cloned()
    }

    /// End the recall walk, if one is in progress. The field keeps its text:
    /// it is a copy, and editing it never changes an entry.
    pub(in crate::tui) fn end_walk(&mut self) {
        self.walk = None;
    }

    /// Whether a recall walk is in progress. Read by the tests.
    #[cfg(test)]
    pub(in crate::tui) fn is_walking(&self) -> bool {
        self.walk.is_some()
    }
}

/// Unit tests for the history's order, bound, de-duplication and walk.
#[cfg(test)]
mod tests {
    use super::*;

    type TestError = Box<dyn std::error::Error>;

    /// A history holding `texts`, recorded in order (the last is newest).
    fn history(texts: &[&str]) -> ExpressionHistory {
        let mut h = ExpressionHistory::default();
        for t in texts {
            h.record(t);
        }
        h
    }

    /// The entries of `h`, newest first, as owned strings.
    fn listed(h: &ExpressionHistory) -> Vec<String> {
        h.entries().map(str::to_owned).collect()
    }

    /// Recorded expressions come back newest first.
    #[test]
    fn entries_are_newest_first() {
        let h = history(&["msg_count > 5", "method == 'BYE'"]);
        assert_eq!(
            listed(&h),
            ["method == 'BYE'", "msg_count > 5"],
            "the last one applied is first"
        );
    }

    /// Applying an expression again moves it to the front; it is held once.
    #[test]
    fn a_repeat_moves_to_the_front_and_is_held_once() {
        let h = history(&["a == 'x'", "b == 'y'", "a == 'x'"]);
        assert_eq!(
            listed(&h),
            ["a == 'x'", "b == 'y'"],
            "the repeat collapses into the front entry"
        );
    }

    /// Texts that differ only by surrounding whitespace are one entry.
    #[test]
    fn surrounding_whitespace_does_not_make_a_new_entry() {
        let h = history(&["msg_count > 5", "  msg_count > 5\t"]);
        assert_eq!(listed(&h), ["msg_count > 5"], "trimmed before comparing");
    }

    /// Texts that differ inside are different entries, case included.
    #[test]
    fn a_different_text_is_a_different_entry() {
        let h = history(&["ua =~ 'x'", "ua =~ 'X'"]);
        assert_eq!(
            listed(&h).len(),
            2,
            "case is part of the text: {:?}",
            listed(&h)
        );
    }

    /// A blank text is not recorded.
    #[test]
    fn a_blank_text_is_not_recorded() {
        let h = history(&["", "   ", "\t"]);
        assert_eq!(listed(&h), Vec::<String>::new(), "nothing to recall");
    }

    /// The history keeps the newest [`EXPRESSION_HISTORY_MAX`] and drops the
    /// oldest past it.
    #[test]
    fn the_oldest_entry_leaves_past_the_bound() {
        let mut h = ExpressionHistory::default();
        for n in 0..=EXPRESSION_HISTORY_MAX {
            h.record(&format!("msg_count > {n}"));
        }
        let all = listed(&h);
        assert_eq!(all.len(), EXPRESSION_HISTORY_MAX, "held at the bound");
        assert_eq!(
            all.first().map(String::as_str),
            Some(format!("msg_count > {EXPRESSION_HISTORY_MAX}").as_str()),
            "the newest is kept"
        );
        assert!(
            !all.contains(&"msg_count > 0".to_owned()),
            "the oldest left: {all:?}"
        );
    }

    /// A repeat at the bound does not drop an entry: it only moves.
    #[test]
    fn a_repeat_at_the_bound_drops_nothing() {
        let mut h = ExpressionHistory::default();
        for n in 0..EXPRESSION_HISTORY_MAX {
            h.record(&format!("msg_count > {n}"));
        }
        h.record("msg_count > 0");
        let all = listed(&h);
        assert_eq!(all.len(), EXPRESSION_HISTORY_MAX, "still full");
        assert_eq!(all[0], "msg_count > 0", "the repeat is at the front");
        assert!(
            all.contains(&"msg_count > 1".to_owned()),
            "the second oldest stays: {all:?}"
        );
    }

    /// Up walks from the newest entry to the oldest, then stops.
    #[test]
    fn older_walks_back_and_stops_at_the_oldest() -> Result<(), TestError> {
        let mut h = history(&["one == 'a'", "two == 'b'", "three == 'c'"]);
        assert_eq!(h.older("draft"), Some("three == 'c'"), "the newest first");
        assert_eq!(h.older("ignored"), Some("two == 'b'"), "then older");
        assert_eq!(h.older("ignored"), Some("one == 'a'"), "then the oldest");
        assert_eq!(h.older("ignored"), None, "nothing older");
        assert!(h.is_walking(), "the walk stays at the oldest");
        assert_eq!(
            h.newer().as_deref(),
            Some("two == 'b'"),
            "and steps back from there"
        );
        Ok(())
    }

    /// Down walks forward again and, past the newest, restores the draft.
    #[test]
    fn newer_walks_forward_and_restores_the_draft() {
        let mut h = history(&["one == 'a'", "two == 'b'"]);
        assert_eq!(h.older("half typed"), Some("two == 'b'"), "the newest");
        assert_eq!(h.older(""), Some("one == 'a'"), "the oldest");
        assert_eq!(h.newer().as_deref(), Some("two == 'b'"), "forward");
        assert_eq!(h.newer().as_deref(), Some("half typed"), "the draft");
        assert!(!h.is_walking(), "restoring the draft ends the walk");
        assert_eq!(h.newer(), None, "nothing newer than the draft");
    }

    /// With nothing recorded, Up has nothing to show and starts no walk.
    #[test]
    fn an_empty_history_recalls_nothing() {
        let mut h = ExpressionHistory::default();
        assert_eq!(h.older("x"), None, "no entry");
        assert!(!h.is_walking(), "no walk starts");
        assert_eq!(h.newer(), None, "no draft to restore");
    }

    /// Down without a walk shows nothing.
    #[test]
    fn newer_without_a_walk_is_none() {
        let mut h = history(&["a == 'x'"]);
        assert_eq!(h.newer(), None, "no walk in progress");
    }

    /// Ending a walk forgets the draft: the next Up starts at the newest
    /// entry and keeps the new field text as its draft.
    #[test]
    fn ending_a_walk_starts_the_next_one_afresh() {
        let mut h = history(&["one == 'a'", "two == 'b'"]);
        assert_eq!(h.older("first draft"), Some("two == 'b'"), "walk one");
        assert_eq!(h.older(""), Some("one == 'a'"), "walk one, older");
        h.end_walk();
        assert!(!h.is_walking(), "ended");
        assert_eq!(
            h.older("edited copy"),
            Some("two == 'b'"),
            "from the newest again"
        );
        assert_eq!(h.newer().as_deref(), Some("edited copy"), "the new draft");
    }

    /// Recording ends a walk in progress.
    #[test]
    fn recording_ends_a_walk() {
        let mut h = history(&["a == 'x'"]);
        assert_eq!(h.older(""), Some("a == 'x'"), "walking");
        h.record("b == 'y'");
        assert!(!h.is_walking(), "a new entry ends the walk");
        assert_eq!(listed(&h), ["b == 'y'", "a == 'x'"], "and is first");
    }

    /// A recalled entry handed out is a copy: changing the field's text never
    /// changes what the history holds.
    #[test]
    fn a_recalled_entry_is_a_copy() {
        let mut h = history(&["msg_count > 5"]);
        let mut field = h.older("").map(str::to_owned).unwrap_or_default();
        field.push_str(" AND ua =~ 'x'");
        h.end_walk();
        assert_eq!(listed(&h), ["msg_count > 5"], "the entry is untouched");
        assert_eq!(field, "msg_count > 5 AND ua =~ 'x'", "the copy was edited");
    }
}
