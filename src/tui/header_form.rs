//! Display-time SIP header-name reformatting: show header names in their
//! compact (`f:`) or expanded (`From:`) form regardless of how they appear
//! on the wire. Purely visual — the stored message bytes are never touched.

use std::borrow::Cow;

/// How SIP header names are displayed in the message-text views.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HeaderFormMode {
    /// Exactly as captured (default).
    #[default]
    AsCaptured,
    /// Compact names rewritten to their full form (`f:` → `From:`).
    Expanded,
    /// Full names rewritten to their compact form (`From:` → `f:`).
    Compact,
}

impl HeaderFormMode {
    pub(in crate::tui) fn next(self) -> Self {
        match self {
            Self::AsCaptured => Self::Expanded,
            Self::Expanded => Self::Compact,
            Self::Compact => Self::AsCaptured,
        }
    }

    pub(in crate::tui) fn label(self) -> &'static str {
        match self {
            Self::AsCaptured => "Headers: as captured",
            Self::Expanded => "Headers: expanded",
            Self::Compact => "Headers: compact",
        }
    }
}

/// The IANA-registered SIP compact header forms (RFC 3261 §20 plus the
/// registered extensions), as (compact, full) pairs.
const COMPACT_FORMS: &[(char, &str)] = &[
    ('a', "Accept-Contact"),
    ('b', "Referred-By"),
    ('c', "Content-Type"),
    ('d', "Request-Disposition"),
    ('e', "Content-Encoding"),
    ('f', "From"),
    ('i', "Call-ID"),
    ('j', "Reject-Contact"),
    ('k', "Supported"),
    ('l', "Content-Length"),
    ('m', "Contact"),
    ('n', "Identity-Info"),
    ('o', "Event"),
    ('r', "Refer-To"),
    ('s', "Subject"),
    ('t', "To"),
    ('u', "Allow-Events"),
    ('v', "Via"),
    ('x', "Session-Expires"),
    ('y', "Identity"),
];

/// Rewrite the header NAMES of a raw SIP message for display.
///
/// Only lines in the header section are considered (after the start-line,
/// before the first blank line); the start-line, folded continuation lines
/// (leading whitespace) and the body are passed through untouched. Header
/// names match ASCII-case-insensitively; everything after the colon is
/// preserved byte-for-byte, as are the line endings.
pub fn reformat_headers(raw: &str, mode: HeaderFormMode) -> Cow<'_, str> {
    if mode == HeaderFormMode::AsCaptured || raw.is_empty() {
        return Cow::Borrowed(raw);
    }

    let mut out = String::with_capacity(raw.len() + 64);
    let mut changed = false;
    let mut in_headers = false; // becomes true after the start-line
    let mut first = true;

    for line in raw.split_inclusive('\n') {
        if first {
            // Start-line (request- or status-line): never rewritten.
            first = false;
            in_headers = true;
            out.push_str(line);
            continue;
        }
        if !in_headers {
            out.push_str(line);
            continue;
        }
        let content = line.trim_end_matches(['\r', '\n']);
        if content.is_empty() {
            // Blank separator: everything after is body.
            in_headers = false;
            out.push_str(line);
            continue;
        }
        if content.starts_with([' ', '\t']) {
            // Folded continuation of the previous header.
            out.push_str(line);
            continue;
        }
        let Some(colon) = content.find(':') else {
            out.push_str(line);
            continue;
        };
        let name = &content[..colon];
        let replacement = match mode {
            HeaderFormMode::Expanded => COMPACT_FORMS
                .iter()
                .find(|(short, _)| {
                    name.len() == 1
                        && name
                            .bytes()
                            .next()
                            .is_some_and(|b| b.eq_ignore_ascii_case(&(*short as u8)))
                })
                .map(|(_, full)| (*full).to_string()),
            HeaderFormMode::Compact => COMPACT_FORMS
                .iter()
                .find(|(_, full)| name.eq_ignore_ascii_case(full))
                .map(|(short, _)| short.to_string()),
            HeaderFormMode::AsCaptured => unreachable!(),
        };
        match replacement {
            Some(new_name) if new_name != name => {
                changed = true;
                out.push_str(&new_name);
                out.push_str(&line[colon..]);
            }
            _ => out.push_str(line),
        }
    }

    if changed {
        Cow::Owned(out)
    } else {
        Cow::Borrowed(raw)
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const WIRE_COMPACT: &str = "INVITE sip:bob@example.com SIP/2.0\r\n\
        v: SIP/2.0/UDP 10.0.0.1;branch=z9hG4bK1\r\n\
        f: \"Alice\" <sip:alice@example.com>;tag=t1\r\n\
        t: <sip:bob@example.com>\r\n\
        i: cid-1@host\r\n\
        CSeq: 1 INVITE\r\n\
        m: <sip:alice@10.0.0.1>\r\n\
        c: application/sdp\r\n\
        l: 5\r\n\
        \r\n\
        v=0\r\n";

    const WIRE_FULL: &str = "INVITE sip:bob@example.com SIP/2.0\r\n\
        Via: SIP/2.0/UDP 10.0.0.1;branch=z9hG4bK1\r\n\
        From: \"Alice\" <sip:alice@example.com>;tag=t1\r\n\
        To: <sip:bob@example.com>\r\n\
        Call-ID: cid-1@host\r\n\
        CSeq: 1 INVITE\r\n\
        Contact: <sip:alice@10.0.0.1>\r\n\
        Content-Type: application/sdp\r\n\
        Content-Length: 5\r\n\
        \r\n\
        v=0\r\n";

    #[test]
    fn as_captured_is_identity() {
        assert_eq!(
            reformat_headers(WIRE_COMPACT, HeaderFormMode::AsCaptured),
            WIRE_COMPACT
        );
        assert_eq!(
            reformat_headers(WIRE_FULL, HeaderFormMode::AsCaptured),
            WIRE_FULL
        );
    }

    #[test]
    fn expand_rewrites_compact_names_only() {
        let out = reformat_headers(WIRE_COMPACT, HeaderFormMode::Expanded);
        assert_eq!(out, WIRE_FULL, "compact wire form expands to full form");
    }

    #[test]
    fn compress_rewrites_full_names_only() {
        let out = reformat_headers(WIRE_FULL, HeaderFormMode::Compact);
        assert_eq!(out, WIRE_COMPACT, "full wire form compresses to compact");
    }

    #[test]
    fn round_trip_and_idempotence() {
        let expanded = reformat_headers(WIRE_COMPACT, HeaderFormMode::Expanded).into_owned();
        let back = reformat_headers(&expanded, HeaderFormMode::Compact).into_owned();
        assert_eq!(back, WIRE_COMPACT);
        // Applying a mode to already-converted text changes nothing.
        assert_eq!(
            reformat_headers(&expanded, HeaderFormMode::Expanded),
            expanded
        );
        let compacted = reformat_headers(WIRE_FULL, HeaderFormMode::Compact).into_owned();
        assert_eq!(
            reformat_headers(&compacted, HeaderFormMode::Compact),
            compacted
        );
    }

    #[test]
    fn matching_is_case_insensitive_and_canonicalizes() {
        let raw = "OPTIONS sip:a@b SIP/2.0\r\nFROM: <sip:x@y>\r\ncall-id: z\r\n\r\n";
        let out = reformat_headers(raw, HeaderFormMode::Compact);
        assert!(out.contains("\r\nf: <sip:x@y>\r\n"), "got: {out}");
        assert!(out.contains("\r\ni: z\r\n"), "got: {out}");
        // And expanding compact forms canonicalizes case too.
        let raw2 = "OPTIONS sip:a@b SIP/2.0\r\nF: <sip:x@y>\r\nI: z\r\n\r\n";
        let out2 = reformat_headers(raw2, HeaderFormMode::Expanded);
        assert!(out2.contains("\r\nFrom: <sip:x@y>\r\n"), "got: {out2}");
        assert!(out2.contains("\r\nCall-ID: z\r\n"), "got: {out2}");
    }

    #[test]
    fn start_line_and_body_are_never_touched() {
        // The request-line contains "sip:" (a colon) and the body contains
        // lines that LOOK like compressible headers — none may change.
        let raw = "MESSAGE sip:to@example.com SIP/2.0\r\n\
            From: <sip:a@b>\r\n\
            Content-Type: text/plain\r\n\
            \r\n\
            From: not a header\r\n\
            f: also not a header\r\n";
        let out = reformat_headers(raw, HeaderFormMode::Compact);
        assert!(out.starts_with("MESSAGE sip:to@example.com SIP/2.0\r\n"));
        assert!(out.contains("\r\nf: <sip:a@b>\r\n"));
        assert!(
            out.ends_with("\r\n\r\nFrom: not a header\r\nf: also not a header\r\n"),
            "body must be untouched, got: {out}"
        );
        // Status-line start (no colon) also untouched.
        let resp = "SIP/2.0 100 trying -- your call is important to us\r\nTo: <sip:x@y>\r\n\r\n";
        let out = reformat_headers(resp, HeaderFormMode::Compact);
        assert!(out.starts_with("SIP/2.0 100 trying"));
        assert!(out.contains("\r\nt: <sip:x@y>\r\n"));
    }

    #[test]
    fn folded_continuations_and_unknown_headers_pass_through() {
        let raw = "INVITE sip:a@b SIP/2.0\r\n\
            Subject: first line\r\n\
            \tfolded: continuation\r\n\
            X-Custom-Header: kept\r\n\
            P-Asserted-Identity: <sip:p@q>\r\n\
            \r\n";
        let out = reformat_headers(raw, HeaderFormMode::Compact);
        assert!(out.contains("\r\ns: first line\r\n"), "got: {out}");
        assert!(
            out.contains("\r\n\tfolded: continuation\r\n"),
            "folded line untouched: {out}"
        );
        assert!(out.contains("\r\nX-Custom-Header: kept\r\n"));
        assert!(out.contains("\r\nP-Asserted-Identity: <sip:p@q>\r\n"));
    }

    #[test]
    fn adversarial_inputs_do_not_panic_or_mangle() {
        // Empty, no blank line, LF-only endings, colon-free header line,
        // replacement chars from lossy UTF-8, backslashes and quotes.
        assert_eq!(reformat_headers("", HeaderFormMode::Compact), "");
        let headers_only = "OPTIONS sip:a@b SIP/2.0\nFrom: <sip:x@y>\nTo: <sip:z@w>";
        let out = reformat_headers(headers_only, HeaderFormMode::Compact);
        assert!(out.contains("\nf: <sip:x@y>\n"), "LF endings work: {out}");
        assert!(out.ends_with("t: <sip:z@w>"), "got: {out}");
        let weird = "INVITE sip:a@b SIP/2.0\r\nnocolonline\r\nFrom\u{FFFD}: x\r\nFrom: \"a\\\"b\" <sip:q@w>\r\n\r\n";
        let out = reformat_headers(weird, HeaderFormMode::Compact);
        assert!(out.contains("\r\nnocolonline\r\n"), "got: {out}");
        assert!(out.contains("From\u{FFFD}: x"), "unknown name kept: {out}");
        assert!(out.contains("f: \"a\\\"b\" <sip:q@w>"), "got: {out}");
        // Single-line message (no headers at all).
        assert_eq!(
            reformat_headers("ACK sip:a@b SIP/2.0", HeaderFormMode::Expanded),
            "ACK sip:a@b SIP/2.0"
        );
    }

    #[test]
    fn every_registered_compact_form_round_trips() {
        for (short, full) in COMPACT_FORMS {
            let raw = format!("OPTIONS sip:a@b SIP/2.0\r\n{short}: value\r\n\r\n");
            let expanded = reformat_headers(&raw, HeaderFormMode::Expanded).into_owned();
            assert!(
                expanded.contains(&format!("\r\n{full}: value\r\n")),
                "{short} must expand to {full}, got: {expanded}"
            );
            let back = reformat_headers(&expanded, HeaderFormMode::Compact);
            assert_eq!(back, raw, "{full} must compress back to {short}");
        }
    }

    #[test]
    fn mode_cycle_and_labels() {
        let m = HeaderFormMode::AsCaptured;
        assert_eq!(m.next(), HeaderFormMode::Expanded);
        assert_eq!(m.next().next(), HeaderFormMode::Compact);
        assert_eq!(m.next().next().next(), HeaderFormMode::AsCaptured);
        for m in [
            HeaderFormMode::AsCaptured,
            HeaderFormMode::Expanded,
            HeaderFormMode::Compact,
        ] {
            assert!(m.label().starts_with("Headers: "));
        }
    }
}
