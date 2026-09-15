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

/// Check that `bpf` compiles as a capture filter, returning libpcap's own error
/// message when it does not.
///
/// This is the validate-before-apply guard: the TUI editor runs it on the
/// composed expression before an apply, so a typo is caught and reported
/// without touching the running capture. It compiles against a *dead* handle
/// ([`pcap::Capture::dead`]) with the DLT the live loop uses, which is exactly
/// what a dead handle is for -- `pcap_compile` is fully supported there, needs
/// no device or privileges, and does not call `pcap_setfilter` (which a dead
/// handle can reject on some libpcap builds). The runtime apply still calls
/// `cap.filter()` on the live handle, so this never substitutes for the
/// authoritative apply-time check -- it is the fast, safe pre-flight.
pub fn validate_filter(bpf: &str) -> Result<(), String> {
    // Ethernet: the loop compiles against whatever DLT the device reports, but
    // a filter's syntactic validity does not depend on the link type for the
    // expressions an operator types here, and a dead handle needs a concrete
    // one. `compile`, not `filter`: compile is the reliable dead-handle step.
    let cap = pcap::Capture::dead(pcap::Linktype::ETHERNET)
        .map_err(|e| format!("could not open a validation handle: {e}"))?;
    cap.compile(bpf, true)
        .map(|_| ())
        .map_err(|e| e.to_string())
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

    /// A well-formed filter compiles; an empty one is valid (matches all).
    #[test]
    fn validate_accepts_a_well_formed_filter() {
        validate_filter("udp port 5060").expect("a real BPF expression compiles");
        validate_filter("").expect("an empty filter is valid (matches everything)");
    }

    /// A composed append validates as one expression (the parentheses hold).
    #[test]
    fn validate_accepts_a_composed_append() {
        let composed = compose_selection("udp port 5060", "host 192.0.2.5", ComposeMode::AppendAnd);
        validate_filter(&composed).expect("the composed append compiles");
    }

    /// A malformed filter fails with libpcap's message, not a panic.
    #[test]
    fn validate_rejects_a_malformed_filter() {
        let err = validate_filter("port and and 5060").expect_err("garbage must not compile");
        assert!(!err.is_empty(), "the compiler error is reported: {err}");
    }
}
