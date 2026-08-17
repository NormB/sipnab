// SPDX-License-Identifier: MIT OR Apache-2.0

//! RFC 7315 `P-Charging-Vector` — reading `icid-value` and `related-icid`.
//!
//! # Which RFC, and which one is current
//!
//! **RFC 7315** (Informational, July 2014), which **obsoletes RFC 3455**. Cite
//! 7315: `related-icid` and `transit-ioi` do not appear in RFC 3455 at all, so
//! a reading of the obsolete document misses the only parameter that addresses
//! a B2BUA. RFC 7315 is updated by RFC 7913 (P-Access-Network-Info only), by
//! RFC 9878, and by RFC 7976 — which **RFC 9878 obsoletes**, so 7976 is not
//! cited here. RFC 9878's change to this header is placement only (which
//! methods and responses may carry it); it alters nothing about what
//! `icid-value` means.
//!
//! Four errata are reported against RFC 7315 and none is verified, so none is
//! applied here.
//!
//! # What the two parameters are, and what a match actually proves
//!
//! §5.6 makes `icid-value` mandatory in the header and says *"The first proxy
//! that receives the request generates this value"*. §4.6 requires it to be
//! globally unique — a real normative MUST, and the reason comparing two of
//! them is an identifier comparison rather than a guess.
//!
//! But §4.6's first sentence also says ICID *"identifies a dialog or a
//! transaction outside a dialog"*, and a B2BUA is by definition two dialogs.
//! **A conformant B2BUA therefore emits a DIFFERENT `icid-value` on each side.**
//! Plain `icid-value` equality across two differing Call-IDs is evidence that
//! some intermediary copied a per-dialog identifier onto a second dialog. It
//! happens, and it is useful when it does, but no RFC grants it.
//!
//! The parameter the RFC provides for that hop is `related-icid`, §4.6.4.1:
//!
//! > The UAS acting as a B2BUA MAY add the related-icid into the
//! > P-Charging-Vector header field into SIP request or SIP responses. […] The
//! > value of the related-icid is the icid value of the original dialog towards
//! > the remote end.
//!
//! It is optional (`MAY`) and it is a **one-way pointer** from the new leg to
//! the old one — structurally like `X-Call-ID`, not like `Session-ID`'s
//! symmetric pair. That is why this module exposes two lookups and the store
//! scores them differently.
//!
//! # What this module does NOT claim
//!
//! * **Not end to end.** §4.6.2.2 says a proxy *SHOULD* include the header
//!   towards a trusted next hop and *MAY modify the contents*, and §6.6 calls
//!   modification *"normal behavior"*. There is no constancy requirement of any
//!   kind. This is the opposite of RFC 7989's guarantee and the docs must never
//!   let the two read alike.
//! * **Useless at the access edge.** If the SBC is the first proxy it generates
//!   the icid, so the leg arriving from the endpoint carries none.
//! * **Nothing about 3GPP TS 24.229**, about any vendor's behavior, or about
//!   how common the header is in real traffic. None of that was checked, so
//!   none of it is asserted.
//!
//! # Why `xcid_headers` could not have done this
//!
//! `[sip] xcid_headers` accepts any header name, so
//! `xcid_headers = ["P-Charging-Vector"]` looks like a zero-code answer. It is
//! not. That strategy compares the header's VALUE against the candidate's
//! **Call-ID**, and a `P-Charging-Vector` value is
//! `icid-value=…;icid-generated-at=…`, which is never equal to a Call-ID. The
//! configuration would be accepted, would never match, and would read as "we
//! tried icid correlation and it found nothing" — the quiet negative that is
//! worse than no feature.
//!
//! # Why this is a real parser and not a substring scan
//!
//! Every parameter of this header carries operator-supplied text, so a scan for
//! the substring `icid-value` finds it wherever it appears, including inside
//! ANOTHER parameter's value:
//!
//! ```text
//!   P-Charging-Vector: orig-ioi="x;icid-value=not-the-icid;y";icid-value=the-icid
//! ```
//!
//! That is not hypothetical for this tree: the same shape — `find("sip:")`
//! reaching into a quoted display name — produced a real bug in
//! `src/sip/message.rs`, fixed the day this module was written. Here the
//! consequence is worse than a wrong display name: two unrelated calls
//! correlated on text the far end chose, reported with `identifier_match: true`.
//!
//! So the header is split into parameters with a quote-aware scanner, the
//! parameter NAME is compared for equality rather than containment, and a
//! quoted value is unquoted with RFC 3261 `quoted-pair` escapes honored.
//!
//! # What never matches
//!
//! * An absent header, an empty value (`icid-value=`, `icid-value=""`), and a
//!   parameter with no `=`. Two legs that both lack the header would otherwise
//!   share the empty string and correlate with everything.
//! * A malformed quoted-string — unterminated, or with text after the closing
//!   quote. What a middlebox made of it is unknowable, so nothing is claimed.
//! * Two DIFFERENT values for one parameter in one header. The ABNF admits one;
//!   a second is a rewrite that went wrong or an injection, and picking either
//!   is a guess. Identical duplicates are fine — there is nothing to choose.
//!
//! # Privacy: what is read and what is never surfaced
//!
//! `icid-generated-at` and `related-icid-generated-at` are, per §5.6, the
//! hostname or IP of the generating proxy; `orig-ioi`, `term-ioi` and
//! `transit-ioi` name the operators on each side of an interconnect. **This
//! module never reads any of them and nothing may match on them** — an
//! implementation that fell back to the generating address would correlate
//! every call one proxy touched.
//!
//! `icid-value` itself is treated as sensitive rather than as opaque, because
//! §4.6's own suggested construction concatenates a local value with *"the
//! hostname or IP address of the SIP proxy that generated"* it. Nothing here
//! returns a value into a report, a log line or a rendered ladder: the store
//! compares values and reports only the NAME of the strategy that matched.

use std::borrow::Cow;

/// The header this module reads. RFC 7315 defines no compact form.
pub const P_CHARGING_VECTOR: &str = "P-Charging-Vector";

/// The `icid-value` of ONE `P-Charging-Vector` header value.
///
/// `value` is everything after the colon — what [`SipMessage::header`] returns.
///
/// [`SipMessage::header`]: crate::sip::SipMessage::header
#[must_use]
pub fn icid_value(value: &str) -> Option<Cow<'_, str>> {
    gen_value_param(value, "icid-value")
}

/// The `related-icid` of ONE `P-Charging-Vector` header value.
///
/// Optional per §4.6.4.1, and a pointer at the icid of the *other* dialog —
/// never at this one's.
#[must_use]
pub fn related_icid(value: &str) -> Option<Cow<'_, str>> {
    gen_value_param(value, "related-icid")
}

/// Every `icid-value` a message carries, across repeated headers.
///
/// The header has no comma-separated list form, so a second node that inserts
/// its own inserts a whole header line. Each is read on its own terms: one
/// malformed header does not silence a well-formed one beside it.
#[must_use]
pub fn message_icids(msg: &crate::sip::SipMessage) -> Vec<Cow<'_, str>> {
    msg.headers_by_name(P_CHARGING_VECTOR)
        .into_iter()
        .filter_map(icid_value)
        .collect()
}

/// Every `related-icid` a message carries, across repeated headers.
#[must_use]
pub fn message_related_icids(msg: &crate::sip::SipMessage) -> Vec<Cow<'_, str>> {
    msg.headers_by_name(P_CHARGING_VECTOR)
        .into_iter()
        .filter_map(related_icid)
        .collect()
}

/// Read one named `gen-value` parameter out of a header value.
///
/// Returns `None` when the parameter is absent, empty, malformed, or present
/// twice with disagreeing values. See the module docs for why each of those is
/// silence rather than a best guess.
fn gen_value_param<'a>(value: &'a str, want: &str) -> Option<Cow<'a, str>> {
    let mut found: Option<Cow<'a, str>> = None;
    for param in params(value) {
        // No `=` is not a `gen-value` parameter at all. `split_once` rather
        // than a search for the last `=`: `gen-value` is a token, a host or a
        // quoted-string, and none of the three contains a bare `=`.
        let Some((name, raw)) = param.split_once('=') else {
            continue;
        };
        // EQUALITY, not containment. `related-icid` is not `icid-value`,
        // `related-icid-generated-at` is not `related-icid`, and a
        // generic-param someone named `x-icid-value` is neither.
        if !name.trim().eq_ignore_ascii_case(want) {
            continue;
        }
        // A malformed value aborts the whole header rather than skipping to
        // the next parameter: this parameter WAS the one asked for, and
        // reading past it would answer with something the sender never sent
        // under that name.
        let parsed = unquote(raw.trim())?;
        if parsed.is_empty() {
            return None;
        }
        match &found {
            // A second that agrees is redundant, not ambiguous; a second that
            // disagrees means nothing can be claimed.
            Some(first) if *first != parsed => return None,
            Some(_) => {}
            None => found = Some(parsed),
        }
    }
    found
}

/// Split a header value on `;`, ignoring separators inside a quoted-string.
///
/// The quote tracking is the whole point: without it,
/// `orig-ioi="a;icid-value=x;b"` splits into three parameters and the middle
/// one looks exactly like a real `icid-value`.
fn params(value: &str) -> Params<'_> {
    Params { rest: Some(value) }
}

/// Iterator behind [`params`].
struct Params<'a> {
    /// What is left to scan, or `None` once the last parameter was yielded.
    rest: Option<&'a str>,
}

impl<'a> Iterator for Params<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<&'a str> {
        let rest = self.rest?;
        let mut in_quotes = false;
        let mut escaped = false;
        for (i, b) in rest.bytes().enumerate() {
            // A quoted-pair escapes the NEXT octet, including a closing quote.
            if escaped {
                escaped = false;
                continue;
            }
            match b {
                b'\\' if in_quotes => escaped = true,
                b'"' => in_quotes = !in_quotes,
                b';' if !in_quotes => {
                    // `;`, `"` and `\` are ASCII, so every index this yields is
                    // a UTF-8 character boundary and the slicing cannot panic.
                    let (head, tail) = rest.split_at(i);
                    self.rest = Some(&tail[1..]);
                    return Some(head);
                }
                _ => {}
            }
        }
        self.rest = None;
        Some(rest)
    }
}

/// Read a `gen-value`: a bare token, or a quoted-string with its escapes
/// resolved.
///
/// Returns `None` for a quoted-string that is unterminated or followed by text,
/// and for a bare value with a stray quote. Those are values two
/// implementations would read differently, which is the case where correlating
/// is worse than not.
fn unquote(raw: &str) -> Option<Cow<'_, str>> {
    let Some(body) = raw.strip_prefix('"') else {
        // A token cannot contain DQUOTE (RFC 3261 §25.1), so one here means the
        // value is neither a token nor a quoted-string.
        return (!raw.contains('"')).then_some(Cow::Borrowed(raw));
    };
    let mut out = String::with_capacity(body.len());
    let mut chars = body.chars();
    let mut closed = false;
    while let Some(c) = chars.next() {
        match c {
            '\\' => out.push(chars.next()?),
            '"' => {
                closed = true;
                break;
            }
            _ => out.push(c),
        }
    }
    if !closed || !chars.as_str().trim().is_empty() {
        return None;
    }
    Some(Cow::Owned(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The plain form: one parameter, nothing else.
    #[test]
    fn a_bare_icid_value_is_read() {
        assert_eq!(icid_value("icid-value=abc123").as_deref(), Some("abc123"));
    }

    /// The ABNF puts `icid-value` first, and real kit does not always.
    #[test]
    fn other_parameters_may_precede_it() {
        assert_eq!(
            icid_value("orig-ioi=home1.example.net;icid-value=abc123;term-ioi=home2.example.net")
                .as_deref(),
            Some("abc123")
        );
    }

    /// `related-icid` is read by its own accessor and never by `icid_value`.
    #[test]
    fn related_icid_is_a_separate_parameter() {
        let header = "icid-value=new-leg;related-icid=old-leg;related-icid-generated-at=192.0.2.1";
        assert_eq!(icid_value(header).as_deref(), Some("new-leg"));
        assert_eq!(related_icid(header).as_deref(), Some("old-leg"));
    }

    /// A header carrying only `related-icid` yields no `icid-value`, and the
    /// reverse. Neither stands in for the other.
    #[test]
    fn neither_parameter_substitutes_for_the_other() {
        assert_eq!(icid_value("related-icid=old-leg").as_deref(), None);
        assert_eq!(related_icid("icid-value=new-leg").as_deref(), None);
    }

    /// `related-icid-generated-at` starts with the name of another parameter
    /// and is not it. Reading it would correlate every call one proxy touched.
    #[test]
    fn the_generating_address_is_not_the_related_icid() {
        assert_eq!(
            related_icid("related-icid-generated-at=192.0.2.1").as_deref(),
            None
        );
    }

    /// `gen-value` admits a quoted-string, and the quotes are not part of it.
    #[test]
    fn a_quoted_value_is_unquoted() {
        assert_eq!(
            icid_value("icid-value=\"abc123\"").as_deref(),
            Some("abc123")
        );
    }

    /// A quoted-string may carry the separator, and it is not a separator there.
    #[test]
    fn a_quoted_value_may_contain_a_semicolon() {
        assert_eq!(
            icid_value("icid-value=\"a;b\";orig-ioi=home1.example.net").as_deref(),
            Some("a;b")
        );
    }

    /// RFC 3261 `quoted-pair`: the backslash escapes the next octet, so an
    /// escaped DQUOTE does not end the string.
    #[test]
    fn quoted_pair_escapes_survive() {
        assert_eq!(
            icid_value("icid-value=\"a\\\"b\\\\c\"").as_deref(),
            Some("a\"b\\c")
        );
    }

    /// Parameter names are case-insensitive tokens.
    #[test]
    fn the_parameter_name_is_case_insensitive() {
        assert_eq!(icid_value("ICID-Value=abc123").as_deref(), Some("abc123"));
        assert_eq!(
            related_icid("Related-ICID=old-leg").as_deref(),
            Some("old-leg")
        );
    }

    /// Whitespace around the `=` is LWS, not part of the name or the value.
    #[test]
    fn surrounding_whitespace_is_not_part_of_the_value() {
        assert_eq!(
            icid_value(" icid-value = abc123 ; orig-ioi=home1.example.net").as_deref(),
            Some("abc123")
        );
    }

    /// THE attack this module exists to refuse: the text `icid-value=` between
    /// two `;` INSIDE somebody else's quoted parameter. A `find("icid-value")`
    /// scan returns the attacker's string here, and so does any splitter that
    /// does not track quotes.
    #[test]
    fn an_icid_value_inside_another_parameters_quoted_text_is_not_the_icid() {
        let header = "orig-ioi=\"x;icid-value=attacker-chose-this;y\";icid-value=the-real-one";
        assert!(
            header.contains("icid-value=attacker-chose-this"),
            "the fixture must actually contain the decoy, or this proves nothing"
        );
        assert_eq!(icid_value(header).as_deref(), Some("the-real-one"));
    }

    /// The same decoy without quotes: a preceding parameter whose VALUE is the
    /// literal text `icid-value=…`. Nothing is quoted, so a scanner that only
    /// learned about quotes still falls for it.
    #[test]
    fn an_icid_value_inside_an_unquoted_parameter_value_is_not_the_icid() {
        assert_eq!(icid_value("orig-ioi=icid-value=decoy").as_deref(), None);
    }

    /// A parameter whose name merely ENDS with the one we want.
    #[test]
    fn a_parameter_whose_name_only_ends_in_icid_value_is_not_it() {
        assert_eq!(icid_value("x-icid-value=decoy").as_deref(), None);
        assert_eq!(icid_value("related-icid-value=decoy").as_deref(), None);
    }

    /// An empty identifier must never be a match, or every leg missing the
    /// header correlates with every other one.
    #[test]
    fn an_empty_value_is_absence() {
        assert_eq!(icid_value("icid-value=").as_deref(), None);
        assert_eq!(icid_value("icid-value=\"\"").as_deref(), None);
        assert_eq!(
            icid_value("icid-value= ;orig-ioi=home1.example.net").as_deref(),
            None
        );
        assert_eq!(related_icid("related-icid=").as_deref(), None);
    }

    /// A parameter with no `=` is not a value.
    #[test]
    fn a_parameter_with_no_equals_yields_nothing() {
        assert_eq!(icid_value("icid-value").as_deref(), None);
        assert_eq!(icid_value("").as_deref(), None);
        assert_eq!(icid_value(";;;").as_deref(), None);
    }

    /// An unterminated quoted-string is unreadable, and what follows it is
    /// swallowed rather than re-scanned for a second `icid-value`.
    #[test]
    fn an_unterminated_quoted_string_yields_nothing() {
        assert_eq!(icid_value("icid-value=\"abc").as_deref(), None);
        assert_eq!(
            icid_value("icid-value=\"abc;icid-value=decoy").as_deref(),
            None
        );
    }

    /// Text after the closing quote: two parsers would disagree about where
    /// the value ends, so this one refuses.
    #[test]
    fn trailing_text_after_a_closing_quote_yields_nothing() {
        assert_eq!(icid_value("icid-value=\"abc\"junk").as_deref(), None);
    }

    /// A bare value with a stray quote is neither a token nor a quoted-string.
    #[test]
    fn a_stray_quote_in_a_bare_value_yields_nothing() {
        assert_eq!(icid_value("icid-value=ab\"c").as_deref(), None);
    }

    /// Two `icid-value` parameters that disagree: picking one is a guess.
    #[test]
    fn two_disagreeing_icid_values_in_one_header_yield_nothing() {
        assert_eq!(
            icid_value("icid-value=first;icid-value=second").as_deref(),
            None
        );
    }

    /// Two that agree leave nothing to choose between.
    #[test]
    fn two_identical_icid_values_in_one_header_are_not_ambiguous() {
        assert_eq!(
            icid_value("icid-value=same;icid-value=same").as_deref(),
            Some("same")
        );
    }

    /// The value is compared byte for byte, so its case is preserved. RFC 7315
    /// gives `icid-value` no alphabet and no comparison rule beyond RFC 3261's
    /// `gen-value`; case-folding it would merge two identifiers a conformant
    /// generator is entitled to treat as distinct.
    #[test]
    fn the_value_keeps_its_case() {
        assert_eq!(icid_value("icid-value=AbC").as_deref(), Some("AbC"));
        assert_ne!(
            icid_value("icid-value=AbC").as_deref(),
            icid_value("icid-value=abc").as_deref()
        );
    }

    /// Values differing by ONE character are different identifiers. Trivial
    /// here by construction, and stated anyway because the store-level version
    /// of this test is the one that catches matching on header PRESENCE.
    #[test]
    fn one_character_makes_a_different_identifier() {
        assert_ne!(
            icid_value("icid-value=P-CSCF1.example.net-1718452800-0001").as_deref(),
            icid_value("icid-value=P-CSCF1.example.net-1718452800-0002").as_deref()
        );
    }
}
