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

/// What a capture filter that would not compile owes an operator who typed it
/// after the options, or `None` for one from `--bpf-file` or the config.
///
/// sngrep and sipgrep both take `[match expression] [bpf filter]` there;
/// sipnab takes only the filter, so `sipnab -I call.pcap INVITE` hands libpcap
/// `INVITE` and fails. The sentence says where the match expression goes.
#[must_use]
pub fn positional_filter_hint(positional: bool) -> Option<&'static str> {
    positional.then_some(
        "sipnab reads only a capture (BPF) filter after its options. To match SIP \
         text, use -e '<pattern>': sngrep and sipgrep take a match expression there \
         first, and sipnab does not.",
    )
}

/// The refusal for a lone positional argument that names an existing file,
/// which sngrep users type as `sngrep call.pcap`. sipnab would read it as a
/// capture filter; `None` for anything else.
pub fn forgot_input_flag(
    positional: &[String],
    exists: impl Fn(&std::path::Path) -> bool,
) -> Option<String> {
    match positional {
        [only] if exists(std::path::Path::new(only)) => Some(format!(
            "'{only}' is a file, and sipnab reads the words after its options as a \
             capture filter. Read the file with: sipnab -I {only}"
        )),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Any error a test can return; `?` converts into it.
    type TestError = Box<dyn std::error::Error>;

    #[test]
    fn a_positional_filter_that_fails_gets_the_match_expression_hint() -> Result<(), TestError> {
        let hint = positional_filter_hint(true).ok_or("positional")?;
        assert!(hint.contains("-e '<pattern>'"), "{hint}");
        assert!(
            hint.contains("sngrep") && hint.contains("sipgrep"),
            "{hint}"
        );
        Ok(())
    }

    #[test]
    fn a_filter_from_a_file_or_the_config_gets_no_such_hint() -> Result<(), TestError> {
        assert_eq!(positional_filter_hint(false), None);
        Ok(())
    }

    #[test]
    fn a_lone_positional_naming_a_file_is_refused_with_the_input_flag() -> Result<(), TestError> {
        let exists = |p: &std::path::Path| p == std::path::Path::new("call.pcap");
        let msg = forgot_input_flag(&["call.pcap".to_string()], exists).ok_or("a file")?;
        assert!(msg.contains("-I call.pcap"), "{msg}");
        Ok(())
    }

    #[test]
    fn a_real_filter_or_several_words_are_not_mistaken_for_a_file() -> Result<(), TestError> {
        let exists = |p: &std::path::Path| p == std::path::Path::new("call.pcap");
        assert_eq!(
            forgot_input_flag(
                &["udp".to_string(), "port".to_string(), "5060".to_string()],
                exists
            ),
            None
        );
        assert_eq!(forgot_input_flag(&["port".to_string()], exists), None);
        assert_eq!(forgot_input_flag(&[], exists), None);
        Ok(())
    }

    /// Replace makes the typed expression the whole selection.
    #[test]
    fn replace_returns_the_new_expression() -> Result<(), TestError> {
        assert_eq!(
            compose_selection("port 5060", "host 192.0.2.5", ComposeMode::Replace),
            "host 192.0.2.5"
        );
        Ok(())
    }

    /// Replace with an empty expression clears the selection.
    #[test]
    fn replace_with_empty_clears() -> Result<(), TestError> {
        assert_eq!(compose_selection("port 5060", "", ComposeMode::Replace), "");
        Ok(())
    }

    /// Append-AND wraps both sides and joins with `and`.
    #[test]
    fn append_and_parenthesizes_both_sides() -> Result<(), TestError> {
        assert_eq!(
            compose_selection("port 5060", "host 192.0.2.5", ComposeMode::AppendAnd),
            "(port 5060) and (host 192.0.2.5)"
        );
        Ok(())
    }

    /// Append-OR wraps both sides and joins with `or`.
    #[test]
    fn append_or_parenthesizes_both_sides() -> Result<(), TestError> {
        assert_eq!(
            compose_selection("port 5060", "host 192.0.2.5", ComposeMode::AppendOr),
            "(port 5060) or (host 192.0.2.5)"
        );
        Ok(())
    }

    /// An `or` inside a side stays grouped, so an append-AND cannot silently
    /// widen to `a or (b and c)`. This is the whole reason the parentheses are
    /// not optional.
    #[test]
    fn an_or_inside_a_side_stays_grouped() -> Result<(), TestError> {
        let combined = compose_selection("udp or tcp", "port 5060", ComposeMode::AppendAnd);
        assert_eq!(combined, "(udp or tcp) and (port 5060)");
        Ok(())
    }

    /// Appending to an empty current is just the new expression -- there is
    /// nothing to combine it with, and `() and (x)` would not compile.
    #[test]
    fn append_to_empty_current_is_just_new() -> Result<(), TestError> {
        assert_eq!(
            compose_selection("", "host 192.0.2.5", ComposeMode::AppendAnd),
            "host 192.0.2.5"
        );
        assert_eq!(
            compose_selection("", "host 192.0.2.5", ComposeMode::AppendOr),
            "host 192.0.2.5"
        );
        Ok(())
    }

    /// Appending an empty expression is a no-op: the current selection stands.
    #[test]
    fn append_empty_new_is_a_noop() -> Result<(), TestError> {
        assert_eq!(
            compose_selection("port 5060", "", ComposeMode::AppendAnd),
            "port 5060"
        );
        Ok(())
    }

    /// A well-formed filter compiles; an empty one is valid (matches all).
    #[test]
    fn validate_accepts_a_well_formed_filter() -> Result<(), TestError> {
        validate_filter("udp port 5060")
            .map_err(|e| format!("a real BPF expression compiles: {e:?}"))?;
        validate_filter("")
            .map_err(|e| format!("an empty filter is valid (matches everything): {e:?}"))?;
        Ok(())
    }

    /// A composed append validates as one expression (the parentheses hold).
    #[test]
    fn validate_accepts_a_composed_append() -> Result<(), TestError> {
        let composed = compose_selection("udp port 5060", "host 192.0.2.5", ComposeMode::AppendAnd);
        validate_filter(&composed).map_err(|e| format!("the composed append compiles: {e:?}"))?;
        Ok(())
    }

    /// A malformed filter fails with libpcap's message, not a panic.
    #[test]
    fn validate_rejects_a_malformed_filter() -> Result<(), TestError> {
        let err = validate_filter("port and and 5060")
            .err()
            .ok_or("garbage must not compile")?;
        assert!(!err.is_empty(), "the compiler error is reported: {err}");
        Ok(())
    }
}
