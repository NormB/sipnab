// SPDX-License-Identifier: MIT OR Apache-2.0

//! Which signaling stack a request was built by, read off its own syntax.
//!
//! A `User-Agent` banner names a PRODUCT, and one product ships more than one
//! stack. Measured against the private corpus on 2026-09-08, `top_talkers
//! by=ua` reports a single row — `Asterisk PBX 20.15.2` at `share_pct: 100.0`
//! across 507 dialogs — while the requests carrying that identical banner
//! split cleanly into two populations by construction, and the split
//! reproduces per source IP and across three separate capture sets.
//!
//! Whether an endpoint is `chan_sip` or `res_pjsip` changes the entire
//! debugging path: different configuration, different NAT handling, different
//! re-INVITE behavior. The banner cannot answer it and the syntax can.
//!
//! # This reports the observation, not the vendor
//!
//! The `z9hG4bKPj` branch cookie is pjproject's, and pjproject is embedded in
//! Grandstream UCM and FreePBX as well as in Asterisk's `res_pjsip` — so the
//! shape identifies a STACK, and naming a product from it would be a guess
//! wearing the shape of a measurement. Every field below is what was on the
//! wire; `inference` is the one derived value and it names the library.
//!
//! The same discipline `find_correlated` applies with `identifier_match`.

use serde::Serialize;

/// The magic cookie [RFC 3261 §8.1.1.7](https://www.rfc-editor.org/rfc/rfc3261#section-8.1.1.7) requires every compliant branch to
/// begin with.
///
/// Not a fingerprint on its own — it is mandatory, so its presence says only
/// that the sender is RFC 3261 compliant. What follows it is the signal.
pub const BRANCH_MAGIC_COOKIE: &str = "z9hG4bK";

/// Longest fingerprint string reported, in characters.
///
/// `branch_cookie` is echoed from the wire rather than classified, so it is
/// the sender's own bytes. 32 characters is far past every cookie a stack
/// writes — the longest in the private corpus is `z9hG4bKPj`, at 9 — and
/// short enough that a crafted branch cannot spend a reader's screen.
pub const MAX_FINGERPRINT_CHARS: usize = 32;

/// The shape of one syntactic token, as sipnab classified it.
///
/// A closed vocabulary of sipnab's own words, so the value is never the
/// sender's text: a shape label cannot carry an injection the way an echoed
/// token could.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
#[serde(rename_all = "kebab-case")]
pub enum TokenShape {
    /// `8-4-4-4-12` hex — what pjproject writes for a `From` tag.
    Uuid,
    /// `as` followed by hex digits — what `chan_sip` writes.
    AsHex,
    /// Hex digits and nothing else, of any length. The corpus carries 8, 9 and
    /// 10; pinning one length would have missed most of them.
    Hex,
    /// Something else. Reported rather than dropped: an unrecognized shape is
    /// a real observation about an endpoint, and the alternative is a field
    /// that silently means "not measured".
    Other,
}

impl TokenShape {
    /// Classify one token.
    #[must_use]
    pub fn of(token: &str) -> Self {
        let is_hex = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit());
        let groups: Vec<&str> = token.split('-').collect();
        if groups.len() == 5
            && groups.iter().map(|g| g.len()).collect::<Vec<_>>() == [8, 4, 4, 4, 12]
            && groups.iter().all(|g| is_hex(g))
        {
            return Self::Uuid;
        }
        if let Some(rest) = token.strip_prefix("as")
            && is_hex(rest)
        {
            return Self::AsHex;
        }
        if is_hex(token) {
            return Self::Hex;
        }
        Self::Other
    }
}

/// What one endpoint's requests say about the stack that built them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub struct StackFingerprint {
    /// The `Via` branch's cookie: the mandatory `z9hG4bK` plus whatever the
    /// stack appends before its per-transaction part. Echoed from the wire and
    /// bounded to [`MAX_FINGERPRINT_CHARS`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch_cookie: Option<String>,
    /// The shape of what follows the branch cookie.
    ///
    /// Reported beside the cookie because the two together are the branch
    /// signal: `chan_sip` has no vendor extension, so the only thing
    /// distinguishing it from any other compliant sender is that its
    /// per-transaction part is hexadecimal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch_shape: Option<TokenShape>,
    /// The shape of the `From` tag.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag_shape: Option<TokenShape>,
    /// Whether the `Call-ID` carries an `@host` part.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callid_has_host: Option<bool>,
    /// The stack the three observations point at, when they point anywhere.
    ///
    /// A LIBRARY, never a product: `z9hG4bKPj` is pjproject's, and pjproject
    /// ships inside Asterisk's `res_pjsip`, Grandstream UCM and FreePBX alike.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inference: Option<&'static str>,
    /// How many of the three observations agree with `inference`, out of
    /// three. Zero when nothing was inferred.
    pub confidence: u8,
    /// How many requests the fingerprint was taken from.
    ///
    /// The denominator. A fingerprint from one request and one from four
    /// hundred are different claims, and a reader cannot tell them apart from
    /// the shapes alone.
    pub requests_read: usize,
    /// True when this endpoint's own requests disagreed about a shape.
    ///
    /// The reason this is worth a field: one banner covering several machines
    /// is what motivated the whole fingerprint, and an endpoint whose own
    /// traffic carries two stacks is either a proxy relaying for others or an
    /// address several hosts share.
    pub mixed: bool,
}

/// Collects the three observations across an endpoint's requests.
#[derive(Debug, Default)]
pub struct FingerprintAccumulator {
    /// Branch cookies seen, and how often. A count rather than a single value
    /// so a disagreement is visible rather than overwritten.
    cookies: std::collections::BTreeMap<String, usize>,
    /// Shapes of what followed each cookie.
    branch_shapes: std::collections::BTreeMap<TokenShape, usize>,
    /// Shapes of the `From` tags.
    tags: std::collections::BTreeMap<TokenShape, usize>,
    /// Whether each `Call-ID` carried an `@host` part.
    hosts: std::collections::BTreeMap<bool, usize>,
    /// Requests read, including any that carried none of the three tokens.
    requests: usize,
}

impl FingerprintAccumulator {
    /// Read one request's three tokens.
    ///
    /// Takes the tokens rather than a `SipMessage`, so both halves of every
    /// rule can be driven without building a dialog — and so the classifier
    /// stays testable against the shapes measured in the corpus rather than
    /// against whichever fixture a test author could assemble.
    pub fn observe(&mut self, branch: &str, from_tag: &str, call_id: &str) {
        self.requests += 1;
        if let Some((cookie, shape)) = branch_parts(branch) {
            *self.cookies.entry(cookie).or_insert(0) += 1;
            *self.branch_shapes.entry(shape).or_insert(0) += 1;
        }
        if !from_tag.is_empty() {
            *self.tags.entry(TokenShape::of(from_tag)).or_insert(0) += 1;
        }
        if !call_id.is_empty() {
            *self.hosts.entry(call_id.contains('@')).or_insert(0) += 1;
        }
    }

    /// The fingerprint these observations add up to.
    #[must_use]
    pub fn finish(self) -> StackFingerprint {
        let cookie = dominant(&self.cookies);
        let branch_shape = dominant(&self.branch_shapes);
        let tag = dominant(&self.tags);
        let host = dominant(&self.hosts);
        let mixed = self.cookies.len() > 1
            || self.branch_shapes.len() > 1
            || self.tags.len() > 1
            || self.hosts.len() > 1;

        // Score each candidate against the three observations, and take the
        // one that scores highest. A tie infers nothing: two stacks that fit
        // equally well is not a measurement of either.
        let mut best: Option<(&'static str, u8)> = None;
        let mut tied = false;
        for (name, want_cookie, want_branch, want_tag, want_host) in [
            (
                "pjproject",
                "z9hG4bKPj",
                TokenShape::Uuid,
                TokenShape::Uuid,
                false,
            ),
            (
                "chan_sip",
                BRANCH_MAGIC_COOKIE,
                TokenShape::Hex,
                TokenShape::AsHex,
                true,
            ),
        ] {
            let mut score = 0u8;
            // The BRANCH signal is the vendor extension, or -- where there is
            // none -- the remainder's shape. The magic cookie on its own is
            // mandatory for every compliant sender ([RFC 3261 §8.1.1.7](https://www.rfc-editor.org/rfc/rfc3261#section-8.1.1.7)), so
            // counting it would hand a free point to whichever candidate
            // happens to want no extension, and `z9hG4bK-not-hex-at-all` --
            // an unrecognized stack -- read as `chan_sip` because of it.
            let branch_agrees = if want_cookie == BRANCH_MAGIC_COOKIE {
                cookie.as_deref() == Some(want_cookie) && branch_shape == Some(want_branch)
            } else {
                cookie.as_deref() == Some(want_cookie)
            };
            if branch_agrees {
                score += 1;
            }
            if tag == Some(want_tag) {
                score += 1;
            }
            if host == Some(want_host) {
                score += 1;
            }
            match best {
                Some((_, s)) if score == s => tied = true,
                Some((_, s)) if score < s => {}
                _ => {
                    best = Some((name, score));
                    tied = false;
                }
            }
        }
        // A single agreeing observation is not evidence: `z9hG4bK` alone is
        // mandatory for every compliant sender, and `callid_has_host` alone
        // splits the world roughly in half.
        let (inference, confidence) = match best {
            Some((name, score)) if score >= 2 && !tied => (Some(name), score),
            _ => (None, 0),
        };

        StackFingerprint {
            branch_cookie: cookie,
            branch_shape,
            tag_shape: tag,
            callid_has_host: host,
            inference,
            confidence,
            requests_read: self.requests,
            mixed,
        }
    }
}

/// The most-seen key, or `None` when nothing was seen.
///
/// A tie breaks on the key rather than on iteration order, so one capture read
/// twice cannot report two different dominant shapes.
fn dominant<K: Clone + Ord>(counts: &std::collections::BTreeMap<K, usize>) -> Option<K> {
    counts
        .iter()
        .max_by(|a, b| a.1.cmp(b.1).then_with(|| b.0.cmp(a.0)))
        .map(|(k, _)| k.clone())
}

/// Vendor extensions that follow the magic cookie, longest first.
///
/// A CLOSED list, and it has to be. The extension cannot be recovered by
/// character class: pjproject writes `z9hG4bKPj` followed by a UUID, and in
/// `z9hG4bKPjabc` the `abc` is as alphabetic as the `Pj` and as hexadecimal as
/// the transaction part it belongs to. Taking the leading alphabetic run
/// yielded `z9hG4bKPjabc` as the "cookie" — a per-transaction value in a field
/// meant to identify a stack, and a different cookie for every request.
///
/// Longest first so a future `Pjx` cannot be shadowed by `Pj`.
const VENDOR_EXTENSIONS: &[&str] = &["Pj"];

/// The cookie part of a `Via` branch, and the shape of what follows it.
///
/// The remainder is per-transaction and identifies nothing about the stack, so
/// only its SHAPE is kept — which is also what keeps a transaction identifier
/// out of a field an agent reads.
fn branch_parts(branch: &str) -> Option<(String, TokenShape)> {
    let rest = branch.strip_prefix(BRANCH_MAGIC_COOKIE)?;
    let extension = VENDOR_EXTENSIONS
        .iter()
        .find(|e| rest.starts_with(**e))
        .copied()
        .unwrap_or("");
    let remainder = &rest[extension.len()..];
    let cookie: String = format!("{BRANCH_MAGIC_COOKIE}{extension}")
        .chars()
        .take(MAX_FINGERPRINT_CHARS)
        .collect();
    Some((cookie, TokenShape::of(remainder)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a fingerprint from `(branch, from_tag, call_id)` triples.
    fn fingerprint(rows: &[(&str, &str, &str)]) -> StackFingerprint {
        let mut acc = FingerprintAccumulator::default();
        for (branch, tag, call_id) in rows {
            acc.observe(branch, tag, call_id);
        }
        acc.finish()
    }

    /// The two populations one banner was hiding.
    #[test]
    fn the_two_populations_are_told_apart_by_construction() {
        // Population A, measured in the private corpus on 2026-09-08: 42,475
        // branches carrying pjproject's cookie.
        let a = fingerprint(&[(
            "z9hG4bKPj8a1b2c3d",
            "5f2c9e1a-3b4d-4e5f-8a9b-0c1d2e3f4a5b",
            "5f2c9e1a3b4d4e5f8a9b0c1d2e3f4a5b",
        )]);
        assert_eq!(a.branch_cookie.as_deref(), Some("z9hG4bKPj"));
        assert_eq!(a.tag_shape, Some(TokenShape::Uuid));
        assert_eq!(a.callid_has_host, Some(false));
        assert_eq!(a.inference, Some("pjproject"));
        assert_eq!(a.confidence, 3);

        // Population B: `chan_sip`, 12,589 `as`-prefixed tags in the same
        // capture set.
        let b = fingerprint(&[(
            "z9hG4bK1a2b3c4d",
            "as1a2b3c4d",
            "0123456789abcdef0123456789abcdef@pbx.example:5060",
        )]);
        assert_eq!(b.branch_cookie.as_deref(), Some("z9hG4bK"));
        assert_eq!(b.tag_shape, Some(TokenShape::AsHex));
        assert_eq!(b.callid_has_host, Some(true));
        assert_eq!(b.inference, Some("chan_sip"));
        assert_eq!(b.confidence, 3);
    }

    /// A branch suffix of any length is still a hex suffix.
    #[test]
    fn a_branch_suffix_of_any_length_is_hex() {
        // 8, 9 and 10 hex digits all appear in the corpus. The backlog entry
        // that prompted this said "8 hex", and pinning that would have missed
        // the 12,550 branches carrying the other two lengths.
        for suffix in ["1a2b3c4d", "1a2b3c4d5", "1a2b3c4d5e"] {
            let f = fingerprint(&[(&format!("z9hG4bK{suffix}"), "as1a2b3c4d", "abc@pbx.example")]);
            assert_eq!(
                f.inference,
                Some("chan_sip"),
                "a {}-digit branch suffix must still read as chan_sip",
                suffix.len()
            );
            assert_eq!(f.branch_cookie.as_deref(), Some("z9hG4bK"));
        }
    }

    /// Partial agreement lowers the confidence, not the answer.
    #[test]
    fn partial_agreement_lowers_the_confidence_rather_than_the_answer() {
        let f = fingerprint(&[(
            "z9hG4bKPjabc",
            "5f2c9e1a-3b4d-4e5f-8a9b-0c1d2e3f4a5b",
            "abc@pbx.example",
        )]);
        assert_eq!(f.inference, Some("pjproject"));
        assert_eq!(
            f.confidence, 2,
            "two of three observations agree, and the field says so rather \
             than the answer being withheld or asserted whole"
        );
    }

    /// One agreeing observation is not evidence.
    #[test]
    fn a_single_agreeing_observation_infers_nothing() {
        // `z9hG4bK` alone is mandatory for every compliant sender, so it
        // cannot distinguish anything; the tag and the Call-ID here match
        // neither population.
        let f = fingerprint(&[("z9hG4bK-opaque", "opaque.tag", "abc")]);
        assert_eq!(f.inference, None);
        assert_eq!(f.confidence, 0);
    }

    /// An unrecognized stack infers nothing, and still reports what was seen.
    #[test]
    fn an_unrecognized_stack_infers_nothing() {
        let f = fingerprint(&[("z9hG4bK-not-hex-at-all", "opaque.tag", "abc@x")]);
        assert_eq!(
            f.inference, None,
            "no rule matches, so nothing is inferred -- an unrecognized stack \
             is a real observation and inventing a label for it would be worse \
             than reporting none"
        );
        // The observations are still reported. That is the whole point of
        // reporting the observation rather than the conclusion.
        assert_eq!(f.branch_cookie.as_deref(), Some("z9hG4bK"));
        assert_eq!(f.tag_shape, Some(TokenShape::Other));
        assert_eq!(f.callid_has_host, Some(true));
    }

    /// One address carrying two stacks says so.
    #[test]
    fn one_address_carrying_two_stacks_is_reported_as_mixed() {
        // The case the whole fingerprint exists for: `tshark` found 18 source
        // IPs behind one banner, and an address several hosts share -- or a
        // proxy relaying for them -- carries both populations at once.
        let f = fingerprint(&[
            (
                "z9hG4bKPjabc",
                "5f2c9e1a-3b4d-4e5f-8a9b-0c1d2e3f4a5b",
                "abc",
            ),
            ("z9hG4bK1a2b3c4d", "as1a2b3c4d", "def@pbx.example"),
        ]);
        assert!(
            f.mixed,
            "an endpoint whose own requests disagree must say so; a majority \
             vote that hid the disagreement would report one stack for a \
             machine running two"
        );
        assert_eq!(f.requests_read, 2, "the denominator is reported");
    }

    /// Nothing to read reports absence rather than a guess.
    #[test]
    fn nothing_to_read_reports_absence_rather_than_a_guess() {
        let f = fingerprint(&[]);
        assert_eq!(f.branch_cookie, None);
        assert_eq!(f.tag_shape, None);
        assert_eq!(f.callid_has_host, None);
        assert_eq!(f.inference, None);
        assert_eq!(f.confidence, 0);
        assert_eq!(f.requests_read, 0);
        assert!(!f.mixed);
    }

    /// A crafted branch cookie cannot spend the screen.
    #[test]
    fn a_crafted_branch_cookie_cannot_spend_the_screen() {
        let long = format!("z9hG4bK{}", "A".repeat(4096));
        let f = fingerprint(&[(&long, "as1a2b", "abc@x")]);
        let cookie = f.branch_cookie.expect("a cookie is reported");
        assert!(
            cookie.chars().count() <= MAX_FINGERPRINT_CHARS,
            "the echoed cookie is {} chars, over the {MAX_FINGERPRINT_CHARS} bound",
            cookie.chars().count()
        );
    }

    /// A branch with no magic cookie is not a branch this reads.
    #[test]
    fn a_branch_without_the_magic_cookie_contributes_nothing() {
        let f = fingerprint(&[("someOtherBranch", "as1a2b3c", "abc@x")]);
        assert_eq!(
            f.branch_cookie, None,
            "RFC 3261 requires the cookie; a branch without one is not \
             compliant and reading a vendor extension out of it would be \
             inventing structure that is not there"
        );
        assert_eq!(f.requests_read, 1, "the request was still read");
    }
}
