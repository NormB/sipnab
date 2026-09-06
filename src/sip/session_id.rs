// SPDX-License-Identifier: MIT OR Apache-2.0

//! RFC 7989 `Session-ID` — the one identifier that survives a B2BUA.
//!
//! # Why this header and not another
//!
//! Correlating a call across an SBC is the hard case, because a B2BUA rewrites
//! both the Call-ID and the Via branch. Of the identifiers already in a SIP
//! message, none crosses that boundary by design:
//!
//! * `Call-ID` — rewritten, by definition of a back-to-back user agent.
//! * Via `branch` — a new transaction on the far side, so a new branch.
//! * `X-Call-ID` — works, and is a vendor convention rather than a standard.
//!
//! RFC 7989 exists precisely to fix that. Its abstract is explicit that the
//! identifier is meant to remain constant end to end across intermediaries that
//! otherwise rewrite everything else about the dialog. Proposed Standard,
//! obsoletes RFC 7329, and nothing obsoletes it.
//!
//! # THE HALVES SWAP, and everything here follows from that
//!
//! A `Session-ID` is not one identifier. It is a PAIR of UUIDs, one contributed
//! by each endpoint, and each side reports the pair from its own point of view:
//!
//! ```text
//!   A -> SBC     Session-ID: aaaa…;remote=bbbb…
//!   SBC -> B     Session-ID: bbbb…;remote=aaaa…
//! ```
//!
//! Both describe the same session. A naive string comparison of the header
//! values finds nothing, which would look exactly like "these are unrelated
//! calls" — the confidently-wrong answer this project exists to eliminate. So
//! correlation here is set intersection over the non-nil halves, never string
//! equality.
//!
//! # `nil` is absence, and must never match
//!
//! The ABNF admits `nil` — 32 ASCII zeros — for a half that is not yet known,
//! which is normal on the first INVITE before the far end has contributed its
//! UUID. Treating `nil` as a value would correlate every call that has not
//! finished establishing with every other one, because they all say the same
//! thing. `nil` is parsed, recorded, and then excluded from matching.
//!
//! # Conformance is recorded, not corrected
//!
//! The ABNF is `32(DIGIT / %x61-66)` — 32 LOWERCASE hex digits. Kit that emits
//! uppercase is non-conforming, and this module preserves what arrived and
//! flags the deviation rather than silently normalizing it. Whether a vendor
//! conforms is itself a finding an operator may need; a parser that quietly
//! repairs the wire destroys the evidence for it.
//!
//! # Where the deviations come out
//!
//! [`SessionId::deviations`] is not a diagnostic left for someone to read in a
//! debugger. It is the classifier behind two conformance rules —
//! [`SIP-7989-5-SESSION-ID-MALFORMED`] and [`SIP-7989-5-SESSION-ID-UPPERCASE`]
//! in [`crate::sip::lint::message`] — which fire on what it reports and on
//! nothing else, and which reach an operator through the linter's findings.
//!
//! That wiring is the whole value of the detector. Correlation across an SBC
//! succeeds only when both ends implement RFC 7989 correctly, so when two legs
//! that plainly belong together do not match, the first question is whether the
//! identifier they were matched on was well formed. Without the rules, the
//! answer sat in this module where nothing could ask for it.
//!
//! [`SIP-7989-5-SESSION-ID-MALFORMED`]: crate::sip::lint::finding::SESSION_ID_MALFORMED
//! [`SIP-7989-5-SESSION-ID-UPPERCASE`]: crate::sip::lint::finding::SESSION_ID_UPPERCASE

/// Length of a `sess-uuid` in characters, per the RFC 7989 ABNF.
const UUID_LEN: usize = 32;

/// How a `Session-ID` half departed from the ABNF, when it did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SessionIdDeviation {
    /// Hex digits arrived uppercase. The ABNF permits `%x61-66` only.
    ///
    /// Recorded rather than repaired: this is a conformance fact about the
    /// sender, and it is still usable for correlation once compared
    /// case-insensitively.
    UppercaseHex,
    /// Not 32 characters.
    WrongLength,
    /// A character outside `[0-9a-fA-F]`.
    NonHex,
}

/// One half of a `Session-ID`: a UUID, `nil`, or something that did not parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionIdHalf {
    /// A usable 32-character hex UUID, stored lowercase for comparison.
    ///
    /// `deviation` is `Some` when the wire form was not exactly what the ABNF
    /// asks for but was still unambiguous — uppercase hex being the only such
    /// case today.
    Uuid {
        /// Lowercased, for comparison.
        value: String,
        /// How the wire form departed from the ABNF, if it did.
        deviation: Option<SessionIdDeviation>,
    },
    /// The RFC's `nil`: 32 zeros, meaning "not known yet". Never matches.
    Nil,
    /// Present but unparseable. Kept so a lint can report it.
    Malformed {
        /// What arrived, so a report can quote it.
        raw: String,
        /// Why it was rejected.
        deviation: SessionIdDeviation,
    },
}

impl SessionIdHalf {
    /// The comparable UUID, if this half is one. `nil` and malformed yield
    /// `None`, which is what keeps them out of correlation.
    #[must_use]
    pub fn uuid(&self) -> Option<&str> {
        match self {
            Self::Uuid { value, .. } => Some(value.as_str()),
            _ => None,
        }
    }
}

/// A parsed `Session-ID` header value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionId {
    /// The `local-uuid`, which is local from the SENDER's point of view.
    pub local: SessionIdHalf,
    /// The `remote` parameter. Absent entirely in the RFC 7329 form.
    pub remote: Option<SessionIdHalf>,
    /// True when no `remote` parameter was present at all.
    ///
    /// RFC 7989 obsoletes RFC 7329, whose form was a single UUID, and says the
    /// `remote` parameter must generally be present except when interoperating
    /// with that older form. So this is a compatibility observation about the
    /// peer, not an error.
    pub legacy_rfc7329_form: bool,
}

/// Classify one half against the ABNF.
fn parse_half(raw: &str) -> SessionIdHalf {
    if raw.len() != UUID_LEN {
        return SessionIdHalf::Malformed {
            raw: raw.to_string(),
            deviation: SessionIdDeviation::WrongLength,
        };
    }
    if !raw.chars().all(|c| c.is_ascii_hexdigit()) {
        return SessionIdHalf::Malformed {
            raw: raw.to_string(),
            deviation: SessionIdDeviation::NonHex,
        };
    }
    // `nil` is 32 zeros. Checked before the uppercase test because zeros have
    // no case, and reporting a deviation on them would be noise.
    if raw.bytes().all(|b| b == b'0') {
        return SessionIdHalf::Nil;
    }
    let deviation = raw
        .chars()
        .any(|c| c.is_ascii_uppercase())
        .then_some(SessionIdDeviation::UppercaseHex);
    SessionIdHalf::Uuid {
        value: raw.to_ascii_lowercase(),
        deviation,
    }
}

impl SessionId {
    /// Parse a `Session-ID` header VALUE (everything after the colon).
    ///
    /// Returns `None` only when the value is empty; anything else parses into
    /// halves that may individually be `Malformed`, because a header that
    /// arrived deserves to be reported rather than dropped.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        let value = value.trim();
        if value.is_empty() {
            return None;
        }
        // The quote-aware walker from `charging_vector`, not `split(';')`.
        // RFC 7989 §5 admits `generic-param` beside `remote`, and RFC 3261
        // §25.1 puts `;` (%x3B) inside `qdtext` — so a quoted value may carry
        // one. Splitting naively let anyone on the signaling path append
        // `foo="x;remote=<32 hex>"` and overwrite the genuine remote half,
        // killing B2BUA correlation silently. One rule, one walker.
        let mut parts = super::charging_vector::params(value);
        let local = parse_half(parts.next().unwrap_or_default().trim());

        let mut remote = None;
        for param in parts {
            let param = param.trim();
            // `generic-param` is permitted alongside `remote`, so anything that
            // is not `remote=` is skipped rather than treated as an error.
            let Some((name, v)) = param.split_once('=') else {
                continue;
            };
            // RFC 3261 §7.3.1 makes the parameter NAME case-insensitive, and
            // RFC 7989 states no exception — `Remote=` is the same parameter.
            if !name.trim().eq_ignore_ascii_case("remote") {
                continue;
            }
            // FIRST wins. RFC 7989 §5: "The Session-ID header field MUST NOT
            // have more than one 'remote' parameter." Taking the last let a
            // later parameter override an earlier one, which is the half an
            // attacker can append to.
            if remote.is_none() {
                remote = Some(parse_half(v.trim()));
            }
        }
        let legacy_rfc7329_form = remote.is_none();
        Some(Self {
            local,
            remote,
            legacy_rfc7329_form,
        })
    }

    /// The UUIDs usable for correlation: non-nil, well-formed halves only.
    ///
    /// This is the set that matching compares. It is deliberately small and
    /// deliberately excludes `nil`, because a `nil` that matched would tie
    /// together every session still being established.
    #[must_use]
    pub fn correlatable(&self) -> Vec<&str> {
        let mut out = Vec::new();
        if let Some(u) = self.local.uuid() {
            out.push(u);
        }
        if let Some(u) = self.remote.as_ref().and_then(SessionIdHalf::uuid) {
            out.push(u);
        }
        out
    }

    /// Whether these two headers describe the same session.
    ///
    /// Set intersection over [`Self::correlatable`], NOT string equality. The
    /// halves swap perspective across a B2BUA — the SBC sends
    /// `local=B;remote=A` where it received `local=A;remote=B` — so the two
    /// values are different strings describing one call. Comparing the strings
    /// would report "unrelated", which is the failure this whole module exists
    /// to prevent.
    ///
    /// It intersects rather than requiring equality of the pair because a
    /// session is often observed mid-establishment, when one side still says
    /// `nil` and the pair has not converged.
    #[must_use]
    pub fn same_session_as(&self, other: &Self) -> bool {
        let mine = self.correlatable();
        !mine.is_empty() && other.correlatable().iter().any(|u| mine.contains(u))
    }

    /// Every deviation observed, for a linter or a conformance report.
    #[must_use]
    pub fn deviations(&self) -> Vec<SessionIdDeviation> {
        let mut out = Vec::new();
        for half in [Some(&self.local), self.remote.as_ref()]
            .into_iter()
            .flatten()
        {
            match half {
                SessionIdHalf::Uuid {
                    deviation: Some(d), ..
                }
                | SessionIdHalf::Malformed { deviation: d, .. } => out.push(*d),
                _ => {}
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    /// The `remote` parameter name is case-insensitive.
    ///
    /// RFC 3261 §7.3.1: "field values, parameter names, and parameter values
    /// are case-insensitive", and RFC 7989 §5 states no exception. ABNF string
    /// literals are case-insensitive by RFC 5234 §2.3, so `remote-param =
    /// "remote" EQUAL remote-uuid` matches `Remote=` too.
    ///
    /// The defect: `strip_prefix("remote")` matched one spelling. A conformant
    /// peer writing `Remote=` was reported as an obsolete RFC 7329 stack AND
    /// lost its remote half from correlation — the identifier that exists
    /// precisely to survive a B2BUA.
    #[test]
    fn the_remote_parameter_name_is_case_insensitive() {
        for spelling in ["remote", "Remote", "REMOTE", "ReMoTe"] {
            let v = format!(
                "ab30317f1a784dc48ff824d0d3715d86;{spelling}=47755a9de7794ba387653f2099600ef2"
            );
            let sid = SessionId::parse(&v).expect("parses");
            assert!(
                !sid.legacy_rfc7329_form,
                "{spelling}= is a remote parameter, so this is not the legacy form"
            );
            assert_eq!(
                sid.correlatable().len(),
                2,
                "both halves correlate: {spelling}"
            );
        }
    }

    /// A `;` inside a quoted generic-param does not split the parameter list.
    ///
    /// RFC 7989 §5: `sess-id-param = remote-param / generic-param`, and
    /// RFC 3261 §25.1 puts `;` (%x3B) inside `qdtext`. So a quoted value may
    /// contain one and it must not be read as a separator.
    ///
    /// The defect was remotely triggerable: anyone on the signaling path could
    /// append one conformant generic-param and overwrite the genuine remote
    /// half with a fabricated one, killing B2BUA correlation silently.
    #[test]
    fn a_semicolon_inside_a_quoted_parameter_does_not_split_the_list() {
        // The decoy comes FIRST, deliberately. With it second, the
        // first-wins rule alone would defeat it and this test would pass
        // against a naive `split(';')` — a mutation proved exactly that. Only
        // quote-awareness saves the genuine half when the decoy precedes it.
        let sid = SessionId::parse(
            "ab30317f1a784dc48ff824d0d3715d86;\
             foo=\"x;remote=deadbeefdeadbeefdeadbeefdeadbeef\";\
             remote=47755a9de7794ba387653f2099600ef2",
        )
        .expect("parses");
        let correlatable = sid.correlatable();
        assert_eq!(
            correlatable.len(),
            2,
            "both real halves survive: {correlatable:?}"
        );
        assert!(
            correlatable.contains(&"47755a9de7794ba387653f2099600ef2"),
            "the genuine remote half must not be overwritten: {correlatable:?}"
        );
        assert!(
            !correlatable.iter().any(|h| h.contains("deadbeef")),
            "the decoy must not become the remote half: {correlatable:?}"
        );
    }

    /// A duplicate `remote` takes the FIRST, and the RFC forbids the second.
    ///
    /// RFC 7989 §5: "The Session-ID header field MUST NOT have more than one
    /// 'remote' parameter." RFC 3261 §7.3.1 says the same generally. Taking
    /// the last let a later parameter override an earlier one; taking the
    /// first at least matches RFC 8489's rule for the analogous case and is
    /// the half an attacker cannot append to.
    #[test]
    fn a_duplicate_remote_parameter_takes_the_first() {
        let sid = SessionId::parse(
            "ab30317f1a784dc48ff824d0d3715d86;remote=47755a9de7794ba387653f2099600ef2;\
             remote=11111111111111111111111111111111",
        )
        .expect("parses");
        assert!(
            sid.correlatable()
                .contains(&"47755a9de7794ba387653f2099600ef2"),
            "the first remote wins: {:?}",
            sid.correlatable()
        );
        assert!(
            !sid.correlatable().iter().any(|h| h.starts_with("1111")),
            "the second must not override it"
        );
    }

    /// Whitespace around the separators is legal and must not lose the half.
    ///
    /// `SEMI = SWS ";" SWS` and `EQUAL = SWS "=" SWS`.
    #[test]
    fn conformant_whitespace_still_yields_both_halves() {
        for v in [
            "ab30317f1a784dc48ff824d0d3715d86 ; remote = 47755a9de7794ba387653f2099600ef2",
            "ab30317f1a784dc48ff824d0d3715d86;\tremote\t=\t47755a9de7794ba387653f2099600ef2",
        ] {
            let sid = SessionId::parse(v).expect("parses");
            assert_eq!(sid.correlatable().len(), 2, "{v:?}");
        }
    }

    use super::*;

    const A: &str = "ab30317f1a784dc48ff824d0d3715d86";
    const B: &str = "47755a9de7794ba387653f2099600ef2";
    const NIL: &str = "00000000000000000000000000000000";

    #[test]
    fn a_full_header_parses_both_halves() {
        let s = SessionId::parse(&format!("{A};remote={B}")).expect("parses");
        assert_eq!(s.local.uuid(), Some(A));
        assert_eq!(s.remote.as_ref().and_then(SessionIdHalf::uuid), Some(B));
        assert!(!s.legacy_rfc7329_form);
    }

    /// The whole point of the module: the SBC swaps the halves, and the two
    /// values must still be recognized as one session.
    #[test]
    fn the_halves_swap_across_a_b2bua_and_still_correlate() {
        let a_side = SessionId::parse(&format!("{A};remote={B}")).expect("parses");
        let b_side = SessionId::parse(&format!("{B};remote={A}")).expect("parses");
        assert_ne!(
            format!("{A};remote={B}"),
            format!("{B};remote={A}"),
            "the two header VALUES differ — string equality would find nothing"
        );
        assert!(
            a_side.same_session_as(&b_side),
            "swapped halves describe one session"
        );
        assert!(
            b_side.same_session_as(&a_side),
            "and the relation is symmetric"
        );
    }

    #[test]
    fn two_unrelated_sessions_do_not_correlate() {
        // The mutation guard for the test above: if `same_session_as` returned
        // true unconditionally, that test would pass and this one would fail.
        let one = SessionId::parse(&format!("{A};remote={B}")).expect("parses");
        let other = SessionId::parse(
            "11111111111111111111111111111111;remote=22222222222222222222222222222222",
        )
        .expect("parses");
        assert!(!one.same_session_as(&other));
    }

    #[test]
    fn nil_is_absence_and_never_correlates() {
        // Two different calls, each still establishing, both saying "remote
        // unknown". Correlating them would tie together every session in
        // setup at once.
        let first = SessionId::parse(&format!("{A};remote={NIL}")).expect("parses");
        let second = SessionId::parse(&format!("{B};remote={NIL}")).expect("parses");
        assert_eq!(first.remote, Some(SessionIdHalf::Nil));
        assert!(
            !first.same_session_as(&second),
            "a shared nil must not correlate two unrelated sessions"
        );
        // But the known half still works.
        let same = SessionId::parse(&format!("{NIL};remote={A}")).expect("parses");
        assert!(
            first.same_session_as(&same),
            "the non-nil half still matches"
        );
    }

    #[test]
    fn a_wholly_nil_header_correlates_with_nothing_including_itself() {
        let s = SessionId::parse(&format!("{NIL};remote={NIL}")).expect("parses");
        assert!(s.correlatable().is_empty());
        assert!(!s.same_session_as(&s), "nil is absence, not identity");
    }

    #[test]
    fn the_rfc7329_single_uuid_form_is_accepted_and_flagged() {
        // RFC 7989 obsoletes 7329 and explicitly anticipates meeting it.
        let s = SessionId::parse(A).expect("parses");
        assert_eq!(s.local.uuid(), Some(A));
        assert!(s.remote.is_none());
        assert!(
            s.legacy_rfc7329_form,
            "the older form is a fact about the peer"
        );
        assert_eq!(s.correlatable(), vec![A], "and it still correlates");
    }

    #[test]
    fn uppercase_hex_is_recorded_as_a_deviation_and_still_matches() {
        // The ABNF says %x61-66. Non-conforming kit is common, and whether a
        // vendor conforms is itself a finding — so record it rather than
        // silently repairing the wire.
        let upper = A.to_ascii_uppercase();
        let s = SessionId::parse(&upper).expect("parses");
        assert_eq!(s.deviations(), vec![SessionIdDeviation::UppercaseHex]);
        assert_eq!(s.local.uuid(), Some(A), "compared lowercase");
        let lower = SessionId::parse(A).expect("parses");
        assert!(s.same_session_as(&lower), "case must not split a session");
    }

    #[test]
    fn a_conforming_header_reports_no_deviations() {
        // Mutation guard: a `deviations()` that always returned UppercaseHex
        // would pass the test above and fail this one.
        let s = SessionId::parse(&format!("{A};remote={B}")).expect("parses");
        assert!(s.deviations().is_empty());
    }

    #[test]
    fn malformed_halves_are_kept_for_reporting_and_excluded_from_matching() {
        for (raw, want) in [
            ("tooshort", SessionIdDeviation::WrongLength),
            (
                "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
                SessionIdDeviation::NonHex,
            ),
        ] {
            let s = SessionId::parse(raw).expect("parses");
            assert_eq!(s.deviations(), vec![want], "raw was {raw}");
            assert!(
                s.correlatable().is_empty(),
                "an unparseable half must not correlate"
            );
        }
    }

    #[test]
    fn generic_params_are_ignored_rather_than_breaking_the_parse() {
        // `sess-id-param = remote-param / generic-param`, so unknown params
        // are legal and must not cost us the remote half.
        let s = SessionId::parse(&format!("{A};foo=bar;remote={B};baz")).expect("parses");
        assert_eq!(s.remote.as_ref().and_then(SessionIdHalf::uuid), Some(B));
    }

    #[test]
    fn whitespace_around_the_value_and_params_is_tolerated() {
        let s = SessionId::parse(&format!("  {A} ; remote = {B}  ")).expect("parses");
        assert_eq!(s.local.uuid(), Some(A));
        assert_eq!(s.remote.as_ref().and_then(SessionIdHalf::uuid), Some(B));
    }

    #[test]
    fn an_empty_value_is_not_a_session_id() {
        assert!(SessionId::parse("").is_none());
        assert!(SessionId::parse("   ").is_none());
    }
}
