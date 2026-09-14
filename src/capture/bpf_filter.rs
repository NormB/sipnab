// SPDX-License-Identifier: MIT OR Apache-2.0

//! Composing a BPF capture-filter SELECTION from an operator's edit (the TUI
//! BPF-filter editing feature).
//!
//! Pure string composition, no libpcap. The operator edits the *selection* --
//! what to match -- and this combines a new expression with the current one
//! under replace or append (AND/OR) semantics. The tunnel/encapsulation
//! scaffolding is wrapped around the result elsewhere, so nothing here touches
//! it and an operator cannot delete it by accident.
//!
//! Spec: `docs/design/tui-bpf-filter-editing.md`.

/// How an operator's typed expression combines with the current selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComposeMode {
    /// The typed expression becomes the whole selection.
    Replace,
    /// Capture only what matches BOTH the current selection and the new one.
    AppendAnd,
    /// Capture what matches EITHER the current selection or the new one.
    AppendOr,
}

/// Combine `new` with `current` under `mode`, returning the new selection.
///
/// Replace returns `new` (an empty `new` clears the selection). Append wraps
/// each side in parentheses -- `(current) and (new)` or `(current) or (new)` --
/// so an `or` inside either side cannot escape its group and change what the
/// combined filter matches, since BPF binds `and` tighter than `or`. Appending
/// to an empty current is just `new`, and appending an empty `new` is a no-op.
#[must_use]
pub fn compose_selection(current: &str, new: &str, mode: ComposeMode) -> String {
    let new = new.trim();
    match mode {
        ComposeMode::Replace => new.to_string(),
        ComposeMode::AppendAnd | ComposeMode::AppendOr => {
            let current = current.trim();
            if current.is_empty() {
                return new.to_string();
            }
            if new.is_empty() {
                return current.to_string();
            }
            let op = if matches!(mode, ComposeMode::AppendAnd) {
                "and"
            } else {
                "or"
            };
            format!("({current}) {op} ({new})")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Replace makes the typed expression the whole selection.
    #[test]
    fn replace_returns_the_new_expression() {
        assert_eq!(
            compose_selection("port 5060", "host 192.0.2.5", ComposeMode::Replace),
            "host 192.0.2.5"
        );
    }

    /// Replace with an empty expression clears the selection.
    #[test]
    fn replace_with_empty_clears() {
        assert_eq!(compose_selection("port 5060", "", ComposeMode::Replace), "");
    }

    /// Append-AND wraps both sides and joins with `and`.
    #[test]
    fn append_and_parenthesizes_both_sides() {
        assert_eq!(
            compose_selection("port 5060", "host 192.0.2.5", ComposeMode::AppendAnd),
            "(port 5060) and (host 192.0.2.5)"
        );
    }

    /// Append-OR wraps both sides and joins with `or`.
    #[test]
    fn append_or_parenthesizes_both_sides() {
        assert_eq!(
            compose_selection("port 5060", "host 192.0.2.5", ComposeMode::AppendOr),
            "(port 5060) or (host 192.0.2.5)"
        );
    }

    /// An `or` inside a side stays grouped, so an append-AND cannot silently
    /// widen to `a or (b and c)`. This is the whole reason the parentheses are
    /// not optional.
    #[test]
    fn an_or_inside_a_side_stays_grouped() {
        let combined = compose_selection("udp or tcp", "port 5060", ComposeMode::AppendAnd);
        assert_eq!(combined, "(udp or tcp) and (port 5060)");
    }

    /// Appending to an empty current is just the new expression -- there is
    /// nothing to combine it with, and `() and (x)` would not compile.
    #[test]
    fn append_to_empty_current_is_just_new() {
        assert_eq!(
            compose_selection("", "host 192.0.2.5", ComposeMode::AppendAnd),
            "host 192.0.2.5"
        );
        assert_eq!(
            compose_selection("", "host 192.0.2.5", ComposeMode::AppendOr),
            "host 192.0.2.5"
        );
    }

    /// Appending an empty expression is a no-op: the current selection stands.
    #[test]
    fn append_empty_new_is_a_noop() {
        assert_eq!(
            compose_selection("port 5060", "", ComposeMode::AppendAnd),
            "port 5060"
        );
    }
}
