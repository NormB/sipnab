// SPDX-License-Identifier: MIT OR Apache-2.0

//! The TUI capture-filter editor's state (append-only, v1).
//!
//! An input buffer for the expression the operator types, and an AND/OR mode.
//! [`BpfEditor::compose`] combines the typed expression with the CURRENT
//! effective filter through [`crate::capture::bpf_filter::compose_selection`].
//! v1 is append-only, so the whole current filter -- tunnel scaffolding included
//! -- is preserved (it sits inside `current`); the spec's finding explains why
//! Replace is deferred. Pure: no terminal, no capture, no libpcap.
//!
//! Spec: `docs/design/tui-bpf-filter-editing.md`.

use crate::capture::bpf_filter::{ComposeMode, compose_selection};

/// Whether the typed expression narrows (AND) or widens (OR) the current filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AppendMode {
    /// Capture only packets matching BOTH the current filter and the typed one.
    #[default]
    And,
    /// Capture packets matching EITHER.
    Or,
}

/// The append editor's state: what the operator is typing, and the mode.
#[derive(Debug, Clone, Default)]
pub struct BpfEditor {
    input: String,
    mode: AppendMode,
}

impl BpfEditor {
    /// A fresh editor: empty input, narrowing (AND) by default.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a typed character to the input.
    pub fn insert(&mut self, c: char) {
        self.input.push(c);
    }

    /// Delete the last typed character (no-op on an empty input).
    pub fn backspace(&mut self) {
        self.input.pop();
    }

    /// Flip between AND (narrow) and OR (widen).
    pub fn toggle_mode(&mut self) {
        self.mode = match self.mode {
            AppendMode::And => AppendMode::Or,
            AppendMode::Or => AppendMode::And,
        };
    }

    /// The expression typed so far.
    #[must_use]
    pub fn input(&self) -> &str {
        &self.input
    }

    /// The current AND/OR mode.
    #[must_use]
    pub fn mode(&self) -> AppendMode {
        self.mode
    }

    /// The effective filter that applying now would produce: the typed
    /// expression appended to `current` under the mode. An empty input leaves
    /// `current` unchanged (compose_selection's no-op).
    #[must_use]
    pub fn compose(&self, current: &str) -> String {
        let mode = match self.mode {
            AppendMode::And => ComposeMode::AppendAnd,
            AppendMode::Or => ComposeMode::AppendOr,
        };
        compose_selection(current, &self.input, mode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_starts_empty_and_narrowing() {
        let e = BpfEditor::new();
        assert_eq!(e.input(), "");
        assert_eq!(e.mode(), AppendMode::And);
    }

    #[test]
    fn insert_and_backspace_edit_the_input() {
        let mut e = BpfEditor::new();
        for c in "host".chars() {
            e.insert(c);
        }
        assert_eq!(e.input(), "host");
        e.backspace();
        assert_eq!(e.input(), "hos");
    }

    #[test]
    fn backspace_on_empty_is_a_noop() {
        let mut e = BpfEditor::new();
        e.backspace();
        assert_eq!(e.input(), "");
    }

    #[test]
    fn toggle_flips_between_and_and_or() {
        let mut e = BpfEditor::new();
        e.toggle_mode();
        assert_eq!(e.mode(), AppendMode::Or);
        e.toggle_mode();
        assert_eq!(e.mode(), AppendMode::And);
    }

    #[test]
    fn compose_and_narrows_the_current_filter() {
        let mut e = BpfEditor::new();
        for c in "host 192.0.2.5".chars() {
            e.insert(c);
        }
        assert_eq!(e.compose("port 5060"), "(port 5060) and (host 192.0.2.5)");
    }

    #[test]
    fn compose_or_widens_the_current_filter() {
        let mut e = BpfEditor::new();
        for c in "host 192.0.2.5".chars() {
            e.insert(c);
        }
        e.toggle_mode();
        assert_eq!(e.compose("port 5060"), "(port 5060) or (host 192.0.2.5)");
    }

    #[test]
    fn compose_with_empty_input_leaves_the_filter_unchanged() {
        let e = BpfEditor::new();
        assert_eq!(e.compose("port 5060"), "port 5060");
    }
}
