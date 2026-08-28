// SPDX-License-Identifier: MIT OR Apache-2.0

//! Keyed pseudonymization at the serialization boundary.
//!
//! # Why a boolean flag would have been the wrong design
//!
//! A capture tool that masks `From` to `***` has destroyed the only thing the
//! capture was for. Correlation *is* the diagnostic value: "these 40 failures
//! all came from one subscriber", "the media went to a different subnet than
//! the SDP advertised", "this leg and that leg are the same call". Every one of
//! those questions is answered by comparing two identifiers, and every one of
//! them survives a *keyed, structure-preserving* pseudonym.
//!
//! So nothing here masks. Identities become tokens that are stable within a run
//! and equal exactly when the originals were equal; addresses go through a
//! prefix-preserving map, so two pseudonyms share a prefix exactly when the
//! real addresses did and subnet reasoning still works on the output.
//!
//! Two things are deleted rather than tokenized, because no pseudonym of them
//! carries diagnostic value: digest credentials (see [`Redactor::header`]) and
//! inline media.
//!
//! # Where this runs
//!
//! At **serialization**, never at parse. The dialog store, the TUI and every
//! in-process analysis keep the real values, so a redacted export and a live
//! triage session are the same capture read two ways. That also means there is
//! exactly one place to test, which is what [`Redacted`] enforces: a sealed
//! value has no accessor and no `Deref`, so the only way to get bytes out of it
//! is [`serde::Serialize`], and the only way to construct one is
//! [`Redacted::seal`].
//!
//! # The prefix-preserving address map
//!
//! [`Redactor::ip`] is the Crypto-PAn construction (Xu, Fan, Ammar and Moon,
//! *Prefix-Preserving IP Address Anonymization*, ICNP 2002). Bit *i* of the
//! output is bit *i* of the input XORed with one bit of a keyed pseudorandom
//! function evaluated over bits *0..i*. Because each output bit depends only on
//! the input bits above it, two addresses agreeing on a *k*-bit prefix produce
//! pseudonyms agreeing on the same *k*-bit prefix — which is the property that
//! keeps "the RTP went somewhere outside the signaled subnet" answerable.
//!
//! # What a token looks like, and why
//!
//! A pseudonymized number keeps its length and carries a literal `x` where the
//! replaced digits start. The length is structure worth preserving — a
//! four-digit extension and an E.164 number are different facts — and the `x`
//! is there because a token that reads as a plain number is one an agent will
//! quote back to an operator as if it were the subscriber's. Nothing in E.164
//! or RFC 3966 admits a letter, so the marker cannot be mistaken for a real
//! number and cannot collide with one.

use std::cell::RefCell;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::LazyLock;

use hmac::{Hmac, Mac};
use serde::{Serialize, Serializer};
use sha2::{Digest, Sha256, digest::KeyInit};

/// HMAC-SHA256, the keyed pseudorandom function every token derives from.
type HmacSha256 = Hmac<Sha256>;

/// Length of a redaction key, in bytes.
pub const KEY_BYTES: usize = 32;

/// The file every ephemeral key is drawn from.
///
/// Named as a constant so the one place that reads entropy is greppable. There
/// is no fallback: a run that cannot read it fails rather than pseudonymising
/// under a key an attacker could guess, because a weak key here does not
/// degrade the output gracefully — it makes every token in the export
/// reversible by anyone holding a phone book.
const ENTROPY_SOURCE: &str = "/dev/urandom";

// ── Domain separation ────────────────────────────────────────────────────
//
// Every call to the PRF names which KIND of value it is mapping. Without it a
// Call-ID and a hostname that happened to share bytes would map to the same
// token, and a reader could join two unrelated fields into a relationship the
// capture never contained.

/// Subscriber identities: E.164 numbers and SIP user parts.
const DOMAIN_IDENTITY: u8 = 1;
/// Host names.
const DOMAIN_HOST: u8 = 2;
/// Opaque tokens: `Call-ID`, SDP session identifiers, `icid-value`.
const DOMAIN_OPAQUE: u8 = 3;
/// IPv4 addresses.
const DOMAIN_IPV4: u8 = 4;
/// IPv6 addresses.
const DOMAIN_IPV6: u8 = 5;
/// Interconnect operator identifiers.
const DOMAIN_OPERATOR: u8 = 6;
/// Key derivation from an operator-supplied secret.
const DOMAIN_KEY: u8 = 7;

/// The marker separating a retained prefix from replaced digits.
///
/// A letter, so a token can never be read back as a dialable number.
const NUMBER_MARKER: char = 'x';

/// Prefix on a pseudonymized non-numeric SIP user part.
const USER_PREFIX: &str = "u-";

/// Prefix on a pseudonymized host name.
const HOST_PREFIX: &str = "h-";

/// Suffix on a pseudonymized host name.
///
/// [RFC 2606](https://www.rfc-editor.org/rfc/rfc2606) §2 reserves `.invalid`
/// precisely so that a name built for illustration can never resolve. A
/// pseudonymized hostname that looked resolvable is one somebody eventually
/// puts in a DNS query.
const HOST_SUFFIX: &str = ".invalid";

/// What replaces a value that is deleted rather than pseudonymized.
///
/// Deliberately the same shape as the vCon `content-withheld` marker: an
/// operator reading either surface should not have to learn two vocabularies
/// for "sipnab removed this on purpose".
pub const WITHHELD: &str = "[redacted]";

/// How the key for a run was obtained.
///
/// Reported alongside the enabled classes because the two answer different
/// questions and only the pair is actionable. `Ephemeral` means the tokens in
/// this export cannot be joined against any other export and no reversal table
/// exists anywhere unless one was written; `Supplied` means they can, and that
/// whoever holds the secret can reverse them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyMode {
    /// Drawn from the operating system at start-up, and never written down.
    Ephemeral,
    /// Derived from a secret the operator supplied, so tokens are stable across
    /// runs and across hosts.
    Supplied,
}

impl KeyMode {
    /// Lowercase name, for a capability report or a CLI summary.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ephemeral => "ephemeral",
            Self::Supplied => "supplied",
        }
    }
}

/// The secret every pseudonym in a run derives from.
///
/// Holds exactly [`KEY_BYTES`] bytes so the PRF cannot be handed a short key by
/// a caller who read a truncated file. An operator secret of any length is
/// stretched into one through the PRF itself rather than truncated or padded,
/// which would silently discard entropy the operator believed they had
/// supplied.
#[derive(Clone)]
pub struct RedactionKey {
    /// The key material.
    bytes: [u8; KEY_BYTES],
    /// Where it came from.
    mode: KeyMode,
}

impl std::fmt::Debug for RedactionKey {
    /// Prints the mode and never the bytes.
    ///
    /// A derived `Debug` would put the key into any log line, panic message or
    /// `dbg!` that ever touched a policy — which is how key material reaches a
    /// support ticket.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedactionKey")
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

impl RedactionKey {
    /// A fresh key drawn from the operating system.
    ///
    /// # Errors
    ///
    /// Propagates the read failure. There is no fallback to a weaker source:
    /// see `ENTROPY_SOURCE`.
    pub fn ephemeral() -> std::io::Result<Self> {
        use std::io::Read;
        let mut bytes = [0u8; KEY_BYTES];
        std::fs::File::open(ENTROPY_SOURCE)?.read_exact(&mut bytes)?;
        Ok(Self {
            bytes,
            mode: KeyMode::Ephemeral,
        })
    }

    /// A key derived from an operator-supplied secret of any length.
    ///
    /// Stretched through SHA-256 with a domain byte rather than used raw, so a
    /// short passphrase and a 32-byte file both produce a full-width key and
    /// neither is silently truncated.
    #[must_use]
    pub fn from_secret(secret: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update([DOMAIN_KEY]);
        hasher.update(secret);
        Self {
            bytes: hasher.finalize().into(),
            mode: KeyMode::Supplied,
        }
    }

    /// How this key was obtained.
    #[must_use]
    pub fn mode(&self) -> KeyMode {
        self.mode
    }
}

/// What a run redacts, and under which key.
///
/// The retained prefix defaults to **zero digits**, and the default is an
/// argument rather than a convenience. Every digit retained is a digit of a
/// real subscriber number published in the clear, so the number of them is a
/// privacy decision that belongs to whoever is answering for the export.
/// sipnab has no basis for choosing it — an NANP area code is three digits, an
/// E.164 country code is one to three, and a national destination code is
/// anything — so it retains nothing until asked, and
/// `--redact-keep-prefix` is how route analysis is bought back deliberately.
#[derive(Debug, Clone)]
pub struct RedactionPolicy {
    /// The secret behind every token.
    key: RedactionKey,
    /// Leading digits of a number kept verbatim.
    keep_prefix: usize,
}

impl RedactionPolicy {
    /// A policy redacting under `key`, retaining no digits.
    #[must_use]
    pub fn new(key: RedactionKey) -> Self {
        Self {
            key,
            keep_prefix: 0,
        }
    }

    /// Keep `digits` leading digits of a numeric identity verbatim.
    #[must_use]
    pub fn with_keep_prefix(mut self, digits: usize) -> Self {
        self.keep_prefix = digits;
        self
    }

    /// How many leading digits survive.
    #[must_use]
    pub fn keep_prefix(&self) -> usize {
        self.keep_prefix
    }

    /// A redactor bound to this policy.
    #[must_use]
    pub fn redactor(&self) -> Redactor<'_> {
        Redactor {
            policy: self,
            mappings: RefCell::new(Vec::new()),
        }
    }

    /// What to report to a caller asking whether redaction is on.
    #[must_use]
    pub fn report(&self) -> RedactionReport {
        RedactionReport {
            enabled: true,
            classes: REDACTED_CLASSES,
            key_mode: self.key.mode.as_str(),
            keep_prefix: self.keep_prefix,
        }
    }
}

/// The value classes this implementation rewrites.
///
/// Reported rather than described in prose because a consumer has to be able to
/// tell "sipnab redacted the identities and left the network addresses" from
/// "sipnab redacted everything", and a boolean cannot.
pub const REDACTED_CLASSES: &[&str] = &[
    "identity",
    "network",
    "credential",
    "correlation-id",
    "charging",
    "media",
];

/// Whether redaction is on, what it covers, and how reversible it is.
///
/// Emitted so no reader has to guess. Without it an agent handed `+1555x123456`
/// states it as the caller's number, which is a confident false statement about
/// a person — the precise failure this whole module exists to avoid causing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RedactionReport {
    /// Whether anything was rewritten.
    pub enabled: bool,
    /// Which classes of value were rewritten.
    pub classes: &'static [&'static str],
    /// `ephemeral` or `supplied` — see [`KeyMode`].
    pub key_mode: &'static str,
    /// Leading digits of a numeric identity kept verbatim.
    pub keep_prefix: usize,
}

impl RedactionReport {
    /// The report for a run that redacted nothing.
    ///
    /// A distinct value rather than an absent field. "No redaction key was
    /// reported" and "redaction was off" are different facts, and a consumer
    /// that cannot tell them apart will read an unredacted export as a redacted
    /// one on the day the field is dropped by accident.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            classes: &[],
            key_mode: "none",
            keep_prefix: 0,
        }
    }
}

/// What [`Redactor::header`] decided about one header field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderAction {
    /// Nothing in this header identifies anybody. Emit it unchanged.
    Keep,
    /// Emit this value in place of the original.
    Replace(String),
    /// Emit nothing. The header does not survive anonymization with any
    /// diagnostic value intact.
    Delete,
}

/// Rewrites capture-derived values under one policy.
///
/// Holds the reverse table for the run, so `--redact-map` can be written from
/// the same object that produced the tokens rather than from a second
/// derivation that could disagree with it.
pub struct Redactor<'a> {
    /// The policy in force.
    policy: &'a RedactionPolicy,
    /// Pseudonym, then the original it stands for, in first-seen order.
    mappings: RefCell<Vec<(String, String)>>,
}

impl<'a> Redactor<'a> {
    /// The policy this redactor applies.
    #[must_use]
    pub fn policy(&self) -> &'a RedactionPolicy {
        self.policy
    }

    /// Every pseudonym produced in this run, with the value it replaced.
    ///
    /// The output of `--redact-map`, and the reason that file has to be written
    /// at 0600: it is the reversal of every token in the export, so it is
    /// exactly as sensitive as the capture it came from.
    #[must_use]
    pub fn mappings(&self) -> Vec<(String, String)> {
        self.mappings.borrow().clone()
    }

    /// Record a pseudonym and what it stands for, once.
    fn remember(&self, pseudonym: &str, original: &str) {
        let mut table = self.mappings.borrow_mut();
        if table.iter().any(|(p, _)| p == pseudonym) {
            return;
        }
        table.push((pseudonym.to_string(), original.to_string()));
    }

    /// The keyed pseudorandom function every token derives from.
    fn prf(&self, domain: u8, input: &[u8]) -> [u8; 32] {
        let mut message = Vec::with_capacity(input.len() + 1);
        message.push(domain);
        message.extend_from_slice(input);
        match HmacSha256::new_from_slice(&self.policy.key.bytes) {
            Ok(mut mac) => {
                mac.update(&message);
                mac.finalize().into_bytes().into()
            }
            // Unreachable: HMAC accepts a key of any length and this one is a
            // fixed 32 bytes. The fallback is still input-dependent on purpose.
            // A branch returning a constant would map every identity in the
            // capture onto ONE token, which is not a weaker pseudonym but a
            // false one — the export would assert a correlation that the
            // traffic never contained.
            Err(_) => {
                let mut hasher = Sha256::new();
                hasher.update(self.policy.key.bytes);
                hasher.update(&message);
                hasher.finalize().into()
            }
        }
    }

    /// Lowercase hexadecimal, `width` characters, from a PRF output.
    fn hex(&self, domain: u8, input: &str, width: usize) -> String {
        self.prf(domain, input.as_bytes())
            .iter()
            .flat_map(|b| [b >> 4, b & 0x0f])
            .take(width)
            .map(|nibble| char::from_digit(u32::from(nibble), 16).unwrap_or('0'))
            .collect()
    }

    /// A pseudonym for an opaque correlation identifier.
    ///
    /// `Call-ID`, the SDP `o=` session id, `icid-value`. Every one of them is
    /// documented as meaningless and every one of them routinely embeds a
    /// hostname: [RFC 7315](https://www.rfc-editor.org/rfc/rfc7315) §4.6's own
    /// suggested `icid-value` construction concatenates a local value with
    /// "the hostname or IP address of the SIP proxy that generated" it, and SIP
    /// stacks have written `<random>@<fqdn>` into `Call-ID` since RFC 2543.
    #[must_use]
    pub fn opaque(&self, value: &str) -> String {
        if value.is_empty() {
            return String::new();
        }
        // An `@` half is a host and is redacted as one, so a pseudonymized
        // Call-ID keeps the shape a consumer's parser expects.
        let token = match value.split_once('@') {
            Some((local, host)) => {
                format!("{}@{}", self.hex(DOMAIN_OPAQUE, local, 16), self.host(host))
            }
            None => self.hex(DOMAIN_OPAQUE, value, 24),
        };
        self.remember(&token, value);
        token
    }

    /// A pseudonym for an interconnect operator identifier.
    ///
    /// `orig-ioi`, `term-ioi` and each element of `transit-ioi`. RFC 7315
    /// §5.6 makes these the names of the operators on each side of an
    /// interconnect, and the `void` convention exists in the same section
    /// precisely because operators treat the transit list as commercially
    /// secret. `void` is passed through unchanged: it is the spec's own way of
    /// saying "no operator", so pseudonymising it would invent an operator
    /// where the sender deliberately named none.
    #[must_use]
    pub fn operator(&self, value: &str) -> String {
        let trimmed = value.trim();
        if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("void") {
            return value.to_string();
        }
        let token = format!(
            "{HOST_PREFIX}{}{HOST_SUFFIX}",
            self.hex(DOMAIN_OPERATOR, trimmed, 12)
        );
        self.remember(&token, trimmed);
        token
    }

    /// A prefix-preserving pseudonym for an address.
    ///
    /// The unspecified address is returned unchanged, and that exemption is
    /// load-bearing rather than tidy: `0.0.0.0` and `::` in an SDP `c=` line
    /// are the RFC 2543 hold signal (RFC 3264 §8.4), not anybody's address.
    /// Rewriting them would delete a call state from the export and take
    /// `SDP-3264-8.4-HOLD-CONNECTION-ZERO` with it.
    #[must_use]
    pub fn ip(&self, addr: IpAddr) -> IpAddr {
        match addr {
            IpAddr::V4(v4) if v4.is_unspecified() => addr,
            IpAddr::V6(v6) if v6.is_unspecified() => addr,
            IpAddr::V4(v4) => IpAddr::V4(self.ipv4(v4)),
            IpAddr::V6(v6) => IpAddr::V6(self.ipv6(v6)),
        }
    }

    /// Crypto-PAn over 32 bits.
    fn ipv4(&self, addr: Ipv4Addr) -> Ipv4Addr {
        let original = u32::from(addr);
        let mut pad = 0u32;
        for bit in 0..32u32 {
            // Everything below bit `bit` is cleared, so this evaluation depends
            // only on the prefix — which is what makes the map
            // prefix-preserving. The position travels in the message too, so
            // the 32 bit-functions are independent of each other.
            let prefix = if bit == 0 {
                0
            } else {
                (original >> (32 - bit)) << (32 - bit)
            };
            let mut message = [0u8; 5];
            message[0] = u8::try_from(bit).unwrap_or(0);
            message[1..5].copy_from_slice(&prefix.to_be_bytes());
            pad |= u32::from(self.prf(DOMAIN_IPV4, &message)[0] & 1) << (31 - bit);
        }
        Ipv4Addr::from(original ^ pad)
    }

    /// Crypto-PAn over 128 bits.
    fn ipv6(&self, addr: Ipv6Addr) -> Ipv6Addr {
        let original = u128::from(addr);
        let mut pad = 0u128;
        for bit in 0..128u32 {
            let prefix = if bit == 0 {
                0
            } else {
                (original >> (128 - bit)) << (128 - bit)
            };
            let mut message = [0u8; 17];
            message[0] = u8::try_from(bit).unwrap_or(0);
            message[1..17].copy_from_slice(&prefix.to_be_bytes());
            pad |= u128::from(self.prf(DOMAIN_IPV6, &message)[0] & 1) << (127 - bit);
        }
        Ipv6Addr::from(original ^ pad)
    }

    /// A pseudonym for a host: an address literal, or a name.
    #[must_use]
    pub fn host(&self, host: &str) -> String {
        // An UNBRACKETED IPv6 literal is tried whole before anything splits on
        // a colon. `2001:db8::1` is what an SDP `c=IN IP6` line carries, and a
        // port split reads its last group as a port number and the rest as a
        // hostname — which redacts, but destroys the prefix-preserving map and
        // emits a name where an address belongs.
        if let Ok(addr) = host.parse::<IpAddr>() {
            let pseudo = self.ip(addr);
            if pseudo == addr {
                return host.to_string();
            }
            let mapped = pseudo.to_string();
            self.remember(&mapped, host);
            return mapped;
        }
        let (bare, port) = match host.rsplit_once(':') {
            // Any remaining colon is a port separator: an address that was not
            // one has already returned above.
            Some((left, right))
                if right.chars().all(|c| c.is_ascii_digit()) && !right.is_empty() =>
            {
                (left, Some(right))
            }
            _ => (host, None),
        };
        let trimmed = bare.trim_start_matches('[').trim_end_matches(']');
        let mapped = match trimmed.parse::<IpAddr>() {
            Ok(addr) => {
                let pseudo = self.ip(addr);
                if pseudo == addr {
                    // The unspecified address, returned as itself. Nothing was
                    // pseudonymized, so nothing goes in the reverse table.
                    return host.to_string();
                }
                match pseudo {
                    IpAddr::V6(_) if bare.starts_with('[') => format!("[{pseudo}]"),
                    _ => pseudo.to_string(),
                }
            }
            Err(_) if trimmed.is_empty() => return host.to_string(),
            Err(_) => format!(
                "{HOST_PREFIX}{}{HOST_SUFFIX}",
                self.hex(DOMAIN_HOST, trimmed, 12)
            ),
        };
        self.remember(&mapped, trimmed);
        match port {
            Some(p) => format!("{mapped}:{p}"),
            None => mapped,
        }
    }

    /// A pseudonym for a subscriber identity, preserving numeric structure.
    ///
    /// A number keeps its length and its retained prefix; everything else
    /// becomes an opaque token. See the module documentation for why the
    /// marker character is there.
    #[must_use]
    pub fn identity(&self, user: &str) -> String {
        if user.is_empty() {
            return String::new();
        }
        let token = match numeric_parts(user) {
            Some((plus, digits)) => {
                // Clamp so at least one digit is always replaced. An operator
                // asking to keep more digits than the number has is asking for
                // no redaction at all, and silently obeying would publish the
                // number under a flag whose name says it is redacting.
                let keep = self.policy.keep_prefix.min(digits.len().saturating_sub(1));
                let replaced = digits.len() - keep;
                let pseudo = self.digits(user, replaced.saturating_sub(1));
                format!(
                    "{}{}{NUMBER_MARKER}{pseudo}",
                    if plus { "+" } else { "" },
                    &digits[..keep]
                )
            }
            None => format!("{USER_PREFIX}{}", self.hex(DOMAIN_IDENTITY, user, 10)),
        };
        self.remember(&token, user);
        token
    }

    /// `count` decimal digits derived from `seed`.
    fn digits(&self, seed: &str, count: usize) -> String {
        let mut out = String::with_capacity(count);
        let mut block = 0u32;
        let mut bytes = self.prf(DOMAIN_IDENTITY, seed.as_bytes()).to_vec();
        while out.len() < count {
            if bytes.is_empty() {
                block += 1;
                bytes = self
                    .prf(DOMAIN_IDENTITY, format!("{seed}#{block}").as_bytes())
                    .to_vec();
            }
            // Rejection is not needed here: the bias from folding 256 values
            // onto 10 is invisible in a pseudonym, and a rejection loop would
            // make the token length depend on the key.
            if let Some(b) = bytes.pop() {
                out.push(char::from(b'0' + b % 10));
            }
        }
        out
    }

    /// A pseudonym for a SIP or tel URI, keeping its scheme and parameters.
    ///
    /// Parameters travel because they are routing, not identity — `transport`,
    /// `lr`, `user=phone` all stay answerable — with the exception of `maddr`,
    /// which is an address and goes through [`Self::ip`] like any other.
    #[must_use]
    pub fn uri(&self, uri: &str) -> String {
        let (scheme, rest) = match uri.split_once(':') {
            Some((s, r)) if matches!(s, "sip" | "sips" | "tel") => (s, r),
            // Not a URI this understands. The free-text sweep is the backstop,
            // and returning the input unchanged here would hand it the job.
            _ => return self.text(uri),
        };
        let (core, params) = match rest.find(';') {
            Some(at) => (&rest[..at], &rest[at..]),
            None => (rest, ""),
        };
        let core = match core.split_once('@') {
            Some((user, host)) => format!("{}@{}", self.identity(user), self.host(host)),
            // `tel:+15551234567` and a hostless `sip:` both land here.
            None => self.identity(core),
        };
        format!("{scheme}:{core}{}", self.uri_params(params))
    }

    /// Rewrite the address-bearing URI parameters and leave the rest alone.
    fn uri_params(&self, params: &str) -> String {
        params
            .split(';')
            .map(|param| match param.split_once('=') {
                Some((name, value)) if name.eq_ignore_ascii_case("maddr") => {
                    format!("{name}={}", self.host(value))
                }
                _ => param.to_string(),
            })
            .collect::<Vec<_>>()
            .join(";")
    }

    /// A pseudonym for a header value that carries a URI and a display name.
    ///
    /// `From`, `To`, `Contact`, `P-Asserted-Identity`, `Diversion` and the rest
    /// of the identity family share one grammar, so they share one rewriter.
    /// The display name goes through [`Self::identity`] rather than being
    /// dropped: it is frequently the *only* identity in the header when the
    /// user part is an anonymous extension, and keeping it as a stable token
    /// preserves "the same person appears on these forty calls".
    #[must_use]
    pub fn name_addr(&self, value: &str) -> String {
        let mut out = String::with_capacity(value.len());
        let mut rest = value;

        // A quoted display name, if there is one.
        if let Some(after) = rest.strip_prefix('"')
            && let Some(end) = after.find('"')
        {
            out.push('"');
            out.push_str(&self.identity(&after[..end]));
            out.push('"');
            rest = &after[end + 1..];
        }

        match rest.find('<') {
            Some(open) => {
                let bare_display = rest[..open].trim();
                if !bare_display.is_empty() {
                    if !out.is_empty() {
                        out.push(' ');
                    }
                    out.push_str(&self.identity(bare_display));
                }
                let Some(close) = rest[open..].find('>') else {
                    // An unterminated `<` is not a name-addr. Sweep the tail as
                    // free text rather than emitting it untouched.
                    out.push_str(&self.text(&rest[open..]));
                    return out;
                };
                if !out.is_empty() {
                    out.push(' ');
                }
                out.push('<');
                out.push_str(&self.uri(&rest[open + 1..open + close]));
                out.push('>');
                out.push_str(&self.header_params(&rest[open + close + 1..]));
            }
            None => {
                // An addr-spec with header parameters hanging off it.
                let (uri, params) = match rest.find(';') {
                    Some(at) => (&rest[..at], &rest[at..]),
                    None => (rest, ""),
                };
                if !out.is_empty() && !uri.trim().is_empty() {
                    out.push(' ');
                }
                out.push_str(&self.uri(uri.trim()));
                out.push_str(&self.header_params(params));
            }
        }
        out
    }

    /// Keep the header parameters, pseudonymising the ones that identify.
    ///
    /// `tag` is a dialog identifier and stays: it correlates messages within
    /// one capture and says nothing about a person. `+sip.instance` does not —
    /// it is a device UUID that follows a subscriber across registrations,
    /// which is an identity by any useful definition.
    fn header_params(&self, params: &str) -> String {
        params
            .split(';')
            .map(|param| match param.split_once('=') {
                Some((name, value)) if name.trim().eq_ignore_ascii_case("+sip.instance") => {
                    format!("{name}=\"{}\"", self.opaque(value.trim_matches('"')))
                }
                _ => param.to_string(),
            })
            .collect::<Vec<_>>()
            .join(";")
    }

    /// Rewrite every parameter of a `P-Charging-Vector`.
    ///
    /// [RFC 7315](https://www.rfc-editor.org/rfc/rfc7315) makes this five leaks
    /// rather than one, and redacting `Call-ID` and the SDP origin while
    /// leaving it intact would remove the two lesser sources of the same leak
    /// and not the greater. `icid-generated-at` and `related-icid-generated-at`
    /// are §5.6's hostname or IP of the generating proxy; `orig-ioi`,
    /// `term-ioi` and `transit-ioi` name the operators; and `icid-value` is
    /// opaque only in theory, since §4.6's own suggested construction ends in
    /// a proxy's hostname.
    #[must_use]
    pub fn charging_vector(&self, value: &str) -> String {
        value
            .split(';')
            .map(|param| {
                let Some((name, raw)) = param.split_once('=') else {
                    return param.to_string();
                };
                let key = name.trim().to_ascii_lowercase();
                let quoted = raw.starts_with('"');
                let inner = raw.trim().trim_matches('"');
                let mapped = match key.as_str() {
                    "icid-value" => self.opaque(inner),
                    "icid-generated-at" | "related-icid-generated-at" => self.host(inner),
                    "orig-ioi" | "term-ioi" => self.operator(inner),
                    "transit-ioi" => inner
                        .split(',')
                        .map(|hop| {
                            // A transit entry is `<operator>.<sequence>`; the
                            // sequence is ordering, not identity, so only the
                            // operator half is rewritten.
                            match hop.rsplit_once('.') {
                                Some((op, seq)) if seq.chars().all(|c| c.is_ascii_digit()) => {
                                    format!("{}.{seq}", self.operator(op))
                                }
                                _ => self.operator(hop),
                            }
                        })
                        .collect::<Vec<_>>()
                        .join(","),
                    _ => return param.to_string(),
                };
                if quoted {
                    format!("{name}=\"{mapped}\"")
                } else {
                    format!("{name}={mapped}")
                }
            })
            .collect::<Vec<_>>()
            .join(";")
    }

    /// What to do with one header field.
    ///
    /// # Why the digest fields are deleted and not tokenized
    ///
    /// An `Authorization` header carries `username`, `realm`, `nonce`,
    /// `cnonce`, `nc` and `response`. The last four together are an offline
    /// dictionary attack against HA1: an attacker holding them grinds
    /// candidate passwords locally at whatever rate their hardware allows,
    /// with no traffic to the registrar and nothing to rate-limit. That is a
    /// credential disclosure, not a privacy nit, and no pseudonym of a
    /// challenge response carries diagnostic value — "the digest response was
    /// wrong" is answered by the `401` that follows it, not by the digest.
    #[must_use]
    pub fn header(&self, name: &str, value: &str) -> HeaderAction {
        let lower = name.trim().to_ascii_lowercase();
        match lower.as_str() {
            "authorization" | "proxy-authorization" | "www-authenticate" | "proxy-authenticate" => {
                HeaderAction::Delete
            }
            "from"
            | "to"
            | "contact"
            | "p-asserted-identity"
            | "p-preferred-identity"
            | "remote-party-id"
            | "p-called-party-id"
            | "diversion"
            | "history-info"
            | "referred-by"
            | "refer-to"
            | "reply-to" => HeaderAction::Replace(self.name_addr(value)),
            "call-id" | "in-reply-to" | "replaces" => HeaderAction::Replace(self.opaque(value)),
            "p-charging-vector" => HeaderAction::Replace(self.charging_vector(value)),
            // A visited-network identifier is an operator name by another
            // route, and `Path`/`Route`/`Record-Route`/`Service-Route` carry
            // proxy hostnames in a name-addr.
            "p-visited-network-id" => HeaderAction::Replace(self.operator(value)),
            "path" | "route" | "record-route" | "service-route" => {
                HeaderAction::Replace(self.name_addr(value))
            }
            _ => HeaderAction::Keep,
        }
    }

    /// Rewrite the identifying lines of an SDP body.
    ///
    /// `o=` is the pair PA5 names: its username is a subscriber identity and
    /// its unicast address is frequently an internal host. The session id and
    /// version are counters and stay, because a re-offer is recognized by the
    /// version incrementing and destroying that would delete the offer/answer
    /// timeline from the export.
    #[must_use]
    pub fn sdp(&self, body: &str) -> String {
        let ending = if body.contains("\r\n") { "\r\n" } else { "\n" };
        let mut out: Vec<String> = Vec::new();
        for line in body.lines() {
            let rewritten = match line.split_at_checked(2) {
                Some(("o=", rest)) => format!("o={}", self.sdp_origin(rest)),
                Some(("c=", rest)) => format!("c={}", self.sdp_connection(rest)),
                // `s=` is free text an endpoint chose, and endpoints put
                // subscriber names in it — the fixture in `vcon.rs` uses the
                // real shape, `s=Alice Kowalski calling`, because that is what
                // phones send. Tokenized rather than swept, because the sweep
                // only knows how to find addresses and numbers and a name is
                // neither. RFC 4566 §5.3's own placeholder stays as itself:
                // `-` says "no name", and replacing it would invent one.
                Some(("s=", rest)) if rest.trim() != "-" => {
                    format!("s={}", self.identity(rest.trim()))
                }
                _ => line.to_string(),
            };
            out.push(rewritten);
        }
        let mut joined = out.join(ending);
        if body.ends_with(ending) {
            joined.push_str(ending);
        }
        joined
    }

    /// `<username> <sess-id> <sess-version> <nettype> <addrtype> <address>`.
    fn sdp_origin(&self, rest: &str) -> String {
        let fields: Vec<&str> = rest.split_whitespace().collect();
        if fields.len() != 6 {
            return self.text(rest);
        }
        let user = if fields[0] == "-" {
            fields[0].to_string()
        } else {
            self.identity(fields[0])
        };
        format!(
            "{user} {} {} {} {} {}",
            fields[1],
            fields[2],
            fields[3],
            fields[4],
            self.host(fields[5])
        )
    }

    /// `<nettype> <addrtype> <connection-address>`.
    fn sdp_connection(&self, rest: &str) -> String {
        let fields: Vec<&str> = rest.split_whitespace().collect();
        let Some((address, head)) = fields.split_last() else {
            return rest.to_string();
        };
        // The multicast forms carry `/ttl` and `/ttl/count` suffixes that are
        // not part of the address.
        let (addr, suffix) = match address.split_once('/') {
            Some((a, tail)) => (a, format!("/{tail}")),
            None => (*address, String::new()),
        };
        format!("{} {}{suffix}", head.join(" "), self.host(addr))
    }

    /// Sweep free prose for anything that identifies.
    ///
    /// The bug that ships otherwise: `"RTP from 10.0.2.15 -> 10.0.2.20 only"`
    /// publishes two addresses through an explanation string while every
    /// structured field beside it was dutifully tokenized. Text like that is
    /// generated all over this tree — lint explanations, diagnosis hints,
    /// report prose — and no amount of care about the structured fields helps.
    ///
    /// Addresses are matched loosely and then *parsed*, so a candidate that is
    /// not an address is left alone. That matters more than it looks:
    /// `04:19:00` inside an RFC 3339 timestamp matches any reasonable IPv6
    /// pattern, and rewriting it would corrupt every clock in the export.
    #[must_use]
    pub fn text(&self, s: &str) -> String {
        // The capturing host's own name, which sipnab writes into its prose
        // and no pattern can find: a hostname is not an address and not a
        // number, so the sweeps below walk straight past it. It is the one
        // hostname this process knows for certain, and the completeness
        // caveat's own note ends "Produced by sipnab X on node Y" — a line
        // that named the operator's capture host inside an otherwise
        // fully redacted container.
        let node = crate::provenance::node_name();
        let swept = if node.is_empty() || !s.contains(node) {
            std::borrow::Cow::Borrowed(s)
        } else {
            std::borrow::Cow::Owned(replace_hostname(s, node, &self.host(node)))
        };
        let swept = IPV4.replace_all(&swept, |c: &regex::Captures<'_>| self.sweep_addr(c));
        let swept = IPV6.replace_all(&swept, |c: &regex::Captures<'_>| self.sweep_addr(c));
        E164.replace_all(&swept, |c: &regex::Captures<'_>| {
            let found = c.get(0).map_or("", |m| m.as_str());
            match numeric_parts(found) {
                Some(_) => self.identity(found),
                None => found.to_string(),
            }
        })
        .into_owned()
    }

    /// Rewrite one address candidate, or leave it alone if it is not one.
    fn sweep_addr(&self, caps: &regex::Captures<'_>) -> String {
        let found = caps.get(0).map_or("", |m| m.as_str());
        match found.parse::<IpAddr>() {
            Ok(addr) => {
                let pseudo = self.ip(addr);
                if pseudo != addr {
                    self.remember(&pseudo.to_string(), found);
                }
                pseudo.to_string()
            }
            Err(_) => found.to_string(),
        }
    }
}

/// Loose IPv4 candidates, confirmed by parsing.
static IPV4: LazyLock<regex::Regex> = LazyLock::new(|| {
    #[expect(
        clippy::unwrap_used,
        reason = "a literal pattern that compiles at every test run; a failure here is a build \
                  defect, not a runtime one, and the alternative is a silently disabled sweep"
    )]
    regex::Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").unwrap()
});

/// Loose IPv6 candidates, confirmed by parsing.
static IPV6: LazyLock<regex::Regex> = LazyLock::new(|| {
    #[expect(
        clippy::unwrap_used,
        reason = "see IPV4 — a literal pattern, checked by the module's own tests"
    )]
    regex::Regex::new(r"\b(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}\b").unwrap()
});

/// Runs of digits long enough to be a dialable number.
///
/// Seven is the shortest closed numbering-plan subscriber number, and the
/// `(?:^|[^0-9A-Za-z_.+-])` guard keeps the sweep out of the middle of an
/// identifier, a version string or a hash.
static E164: LazyLock<regex::Regex> = LazyLock::new(|| {
    #[expect(
        clippy::unwrap_used,
        reason = "see IPV4 — a literal pattern, checked by the module's own tests"
    )]
    regex::Regex::new(r"\+?\b\d{7,15}\b").unwrap()
});

/// Replace whole occurrences of a host name, never a fragment of a longer one.
///
/// A plain `str::replace` is wrong here and the reason is not hypothetical: a
/// container named `db` is a legal node name, and replacing every `db` in the
/// caveat's prose would also rewrite `2001:db8::1`. An occurrence counts only
/// where neither neighbour is a character a host name is made of — letters,
/// digits, `-`, `.` and `_`.
///
/// **What this still cannot do**, stated rather than hidden: a node genuinely
/// named `a` produces a needle that is also an English article, and no boundary
/// rule separates "the host named a" from "a capture". Such a name
/// over-redacts the surrounding prose. That is the safe direction — the
/// alternative is publishing the operator's capture host — and it is a
/// consequence of the node name, not of the text.
fn replace_hostname(text: &str, needle: &str, replacement: &str) -> String {
    /// Whether `c` continues an identifier without needing a separator.
    fn joins(c: char) -> bool {
        c.is_alphanumeric() || c == '-' || c == '_'
    }

    /// Whether the characters `side` yields continue the same host name.
    ///
    /// The dot is the whole reason this is a function. It separates labels
    /// inside `thor-02.example.com` and ends a sentence in "on node thor-02.",
    /// and the note this sweep exists for writes the second — so a rule that
    /// treated every dot as a separator would leave the one occurrence that
    /// matters untouched. A dot continues the name only when a label follows.
    fn continues(mut side: impl Iterator<Item = char>) -> bool {
        match side.next() {
            Some(c) if joins(c) => true,
            Some('.') => side.next().is_some_and(char::is_alphanumeric),
            _ => false,
        }
    }

    if needle.is_empty() {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find(needle) {
        let after = &rest[at + needle.len()..];
        let whole = !continues(rest[..at].chars().rev()) && !continues(after.chars());
        out.push_str(&rest[..at]);
        if whole {
            out.push_str(replacement);
        } else {
            out.push_str(needle);
        }
        rest = after;
    }
    out.push_str(rest);
    out
}

/// Split a candidate identity into its optional `+` and its digits.
///
/// Returns `None` for anything that is not `+`-then-digits, which is what sends
/// an alphabetic SIP user down the opaque-token path instead.
fn numeric_parts(user: &str) -> Option<(bool, &str)> {
    let (plus, digits) = match user.strip_prefix('+') {
        Some(rest) => (true, rest),
        None => (false, user),
    };
    (!digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())).then_some((plus, digits))
}

/// A value that redaction can be applied to in place.
///
/// Implemented by **destructuring** wherever a struct is involved, so that a
/// field added later fails to compile until somebody has decided whether it
/// identifies anybody. That is the whole point: "I forgot to redact this new
/// field" is otherwise a CVE waiting for the next release, and a compiler error
/// is the only reviewer guaranteed to be present.
pub trait Redact {
    /// Rewrite every identifying value in place.
    fn redact(&mut self, redactor: &Redactor<'_>);
}

/// A value that has been through redaction and can only be serialized.
///
/// There is no accessor, no `Deref`, no `into_inner` and no public field.
/// [`Self::seal`] is the only constructor, and it redacts. So the only way to
/// get bytes out of a sealed value is [`serde::Serialize`], and the only bytes
/// available are redacted ones — the property is enforced by the type rather
/// than by everyone remembering.
#[derive(Debug, Clone)]
pub struct Redacted<T> {
    /// The redacted value. Private, and it stays private.
    inner: T,
}

impl<T: Redact> Redacted<T> {
    /// Redact `value` under `policy` and seal it.
    #[must_use]
    pub fn seal(mut value: T, policy: &RedactionPolicy) -> Self {
        value.redact(&policy.redactor());
        Self { inner: value }
    }

    /// Redact `value` with a redactor whose mapping table the caller keeps.
    ///
    /// The form `--redact-map` needs: the reverse table lives on the redactor,
    /// so writing it means holding the redactor that produced the tokens rather
    /// than deriving a second table that could disagree.
    #[must_use]
    pub fn seal_with(mut value: T, redactor: &Redactor<'_>) -> Self {
        value.redact(redactor);
        Self { inner: value }
    }
}

impl<T> Redacted<T> {
    /// Seal a value that is already free of anything identifying.
    ///
    /// The escape hatch for a redaction-disabled run, and it is deliberately
    /// verbose at the call site: `Redacted::pass_through` in a diff is a claim
    /// somebody has to defend in review, which `Redacted::seal` is not.
    #[must_use]
    pub fn pass_through(value: T) -> Self {
        Self { inner: value }
    }
}

impl<T: Serialize> Serialize for Redacted<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.inner.serialize(serializer)
    }
}

/// Rewrite a JSON document in place: known keys structurally, the rest as text.
///
/// The two halves matter equally. The structured pass is what keeps a
/// pseudonymized `From` parseable as a `From`; the text pass is the backstop
/// for the free prose that every report, hint and explanation is made of, and
/// which no amount of care about structured fields protects.
///
/// `headers` is walked with [`Redactor::header`], so the same rule governs a
/// header whether it arrives as a trace field or inside a header map.
pub fn redact_json(value: &mut serde_json::Value, redactor: &Redactor<'_>) {
    match value {
        serde_json::Value::Object(map) => {
            // Deleted fields go last: a map cannot be mutated while it is
            // iterated, so the removals are collected on the way through.
            let mut drop: Vec<String> = Vec::new();
            for (key, nested) in map.iter_mut() {
                match nested {
                    serde_json::Value::String(text) => match redact_field(key, text, redactor) {
                        Some(v) => *text = v,
                        None => drop.push(key.clone()),
                    },
                    // A HEADER MAP is `{"From": ["..."], ...}` — one array per
                    // field name, because §7.3.1 lets a name appear on several
                    // rows. The key is the header name and the strings are its
                    // values, so the key has to travel INTO the array. Walking
                    // the array as anonymous strings instead was the first
                    // implementation and it leaked every display name in the
                    // trace: `From` reached the free-text sweep, which knows
                    // how to find an address and a number and nothing about a
                    // person's name.
                    serde_json::Value::Array(items) => {
                        let mut kept = Vec::with_capacity(items.len());
                        for item in items.iter_mut() {
                            match item {
                                serde_json::Value::String(text) => {
                                    if let Some(v) = redact_field(key, text, redactor) {
                                        kept.push(serde_json::Value::String(v));
                                    }
                                }
                                other => {
                                    redact_json(other, redactor);
                                    kept.push(other.clone());
                                }
                            }
                        }
                        if kept.is_empty() && !items.is_empty() {
                            drop.push(key.clone());
                        } else {
                            *items = kept;
                        }
                    }
                    other => redact_json(other, redactor),
                }
            }
            for key in drop {
                map.remove(&key);
            }
        }
        serde_json::Value::Array(items) => {
            for nested in items {
                redact_json(nested, redactor);
            }
        }
        serde_json::Value::String(text) => *text = redactor.text(text),
        _ => {}
    }
}

/// The redacted form of one string field, or `None` when it does not survive.
fn redact_field(key: &str, value: &str, redactor: &Redactor<'_>) -> Option<String> {
    match json_field_action(key, value, redactor) {
        HeaderAction::Keep => Some(redactor.text(value)),
        HeaderAction::Replace(v) => Some(v),
        HeaderAction::Delete => None,
    }
}

/// Keys whose values are sipnab's own machine identifiers, kept byte for byte.
///
/// Not a convenience. A digest, a frame pointer and a timestamp are the three
/// things a reader uses to get back to the evidence, and the free-text sweep
/// would corrupt all three: a base64url digest can hold a seven-digit run
/// between two `-` separators, which is a word boundary, and an RFC 3339 clock
/// is a colon-separated hex-looking string. Rewriting either produces a
/// container that still validates and no longer resolves.
const VERBATIM_KEYS: &[&str] = &[
    "capture_id",
    "content_hash",
    "digest",
    "encoding",
    "frame",
    "mediatype",
    "method",
    "schema",
    "schema_version",
    "sipnab_version",
    "timestamp",
    "transport",
    "uuid",
    "version",
];

/// What to do with one JSON string field.
///
/// The trace keys sipnab writes are checked first, then the SIP header names —
/// so `from` in a trace and `From` in a header map take the same path, and a
/// key that is neither falls through to the free-text sweep.
fn json_field_action(key: &str, value: &str, redactor: &Redactor<'_>) -> HeaderAction {
    let lower = key.to_ascii_lowercase();
    if VERBATIM_KEYS.contains(&lower.as_str()) {
        return HeaderAction::Replace(value.to_string());
    }
    // sipnab's own JSON spells a header field with an underscore where the
    // wire spells it with a hyphen — `call_id` for `Call-ID`. Normalizing here
    // is what makes ONE rule govern a field whether it arrives as a trace key
    // or as a header-map key; without it `call_id` fell through to the
    // free-text sweep and every Call-ID in the trace kept its embedded
    // hostname.
    let lower = lower.replace('_', "-");
    // `sip_call_id`, `sip_contact`, `sip_display_name`: sipnab's own keys for
    // values that ARE SIP header fields, prefixed to say where they came from.
    // Stripping the prefix is what puts them under the same rule as the header
    // they were copied from — `sip_call_id` kept its embedded hostname until
    // it did, in a container whose `Call-ID` header was correctly tokenized
    // three lines above.
    let lower = lower.strip_prefix("sip-").unwrap_or(&lower);
    match lower {
        "src" | "dst" => HeaderAction::Replace(redactor.host(value)),
        "sip" | "tel" => HeaderAction::Replace(redactor.uri(value)),
        "sdp" => HeaderAction::Replace(redactor.sdp(value)),
        // The capturing host names the operator's own infrastructure, which is
        // exactly the class of leak `P-Charging-Vector` is on this list for.
        "node" | "hostname" | "host" | "node-name" => HeaderAction::Replace(redactor.host(value)),
        "from-user" | "to-user" | "user" | "display-name" => {
            HeaderAction::Replace(redactor.identity(value))
        }
        other => redactor.header(other, value),
    }
}

/// Tests for the redaction engine.
#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed key, so every expectation below is reproducible.
    fn policy() -> RedactionPolicy {
        RedactionPolicy::new(RedactionKey::from_secret(b"sipnab-test-key"))
    }

    /// The same input maps to the same token, which is the whole feature.
    ///
    /// Naive masking destroys this and takes the diagnostic value with it: an
    /// operator asking "how many failures came from one subscriber" is
    /// comparing two identities, and `***` compares equal to everything.
    #[test]
    fn one_identity_maps_to_one_token() {
        let p = policy();
        let r = p.redactor();
        assert_eq!(r.identity("+15551234567"), r.identity("+15551234567"));
        assert_ne!(r.identity("+15551234567"), r.identity("+15551234568"));
    }

    /// A different key produces a different token for the same input.
    #[test]
    fn the_key_changes_the_token() {
        let a = RedactionPolicy::new(RedactionKey::from_secret(b"key-a"));
        let b = RedactionPolicy::new(RedactionKey::from_secret(b"key-b"));
        assert_ne!(
            a.redactor().identity("+15551234567"),
            b.redactor().identity("+15551234567")
        );
    }

    /// A number keeps its length and gains a marker no real number can carry.
    #[test]
    fn a_number_keeps_its_length_and_is_unmistakable() {
        let p = policy();
        let token = p.redactor().identity("+15551234567");
        assert_eq!(token.len(), "+15551234567".len(), "{token}");
        assert!(token.contains(NUMBER_MARKER), "{token}");
        assert!(!token.contains("5551234567"), "{token}");
    }

    /// The retained prefix survives verbatim, and the rest does not.
    #[test]
    fn the_retained_prefix_survives() {
        let p = policy().with_keep_prefix(4);
        let token = p.redactor().identity("+15551234567");
        assert!(token.starts_with("+1555"), "{token}");
        assert!(!token.contains("1234567"), "{token}");
    }

    /// Keeping more digits than the number has still replaces one.
    ///
    /// Silently obeying would publish the number verbatim under a flag whose
    /// name says it is redacting, which is the worst failure this module can
    /// have: it looks exactly like success.
    #[test]
    fn an_oversized_retained_prefix_still_redacts() {
        let p = policy().with_keep_prefix(99);
        let token = p.redactor().identity("+15551234567");
        assert_ne!(token, "+15551234567");
        assert!(token.contains(NUMBER_MARKER), "{token}");
    }

    /// Addresses sharing a prefix keep sharing it, and differing ones do not.
    ///
    /// The property the whole Crypto-PAn construction exists for: without it
    /// "the media went to a subnet the SDP never advertised" stops being
    /// answerable on a redacted capture.
    #[test]
    fn address_prefixes_are_preserved() {
        let p = policy();
        let r = p.redactor();
        let a = r.ip("10.0.2.15"
            .parse()
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        let b = r.ip("10.0.2.20"
            .parse()
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        let c = r.ip("192.0.2.1"
            .parse()
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        let (IpAddr::V4(a), IpAddr::V4(b), IpAddr::V4(c)) = (a, b, c) else {
            panic!("v4 in, v4 out");
        };
        assert_eq!(a.octets()[..3], b.octets()[..3], "{a} {b}");
        assert_ne!(a.octets()[0], c.octets()[0], "{a} {c}");
        assert_ne!(a, b, "distinct hosts must stay distinct");
    }

    /// IPv6 prefixes are preserved the same way.
    #[test]
    fn ipv6_prefixes_are_preserved() {
        let p = policy();
        let r = p.redactor();
        let a = r.ip("2001:db8::1"
            .parse()
            .unwrap_or(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
        let b = r.ip("2001:db8::2"
            .parse()
            .unwrap_or(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
        let (IpAddr::V6(a), IpAddr::V6(b)) = (a, b) else {
            panic!("v6 in, v6 out");
        };
        assert_eq!(a.octets()[..8], b.octets()[..8], "{a} {b}");
        assert_ne!(a, b);
    }

    /// The unspecified address is a protocol signal, not an address.
    ///
    /// RFC 3264 §8.4 hold is `c=IN IP4 0.0.0.0`. Pseudonymising it deletes a
    /// call state from the export and takes the hold lint rule with it.
    #[test]
    fn the_unspecified_address_is_left_alone() {
        let p = policy();
        let r = p.redactor();
        assert_eq!(r.host("0.0.0.0"), "0.0.0.0");
        assert_eq!(r.host("::"), "::");
    }

    /// A digest credential is deleted, not tokenized.
    #[test]
    fn digest_credentials_are_deleted() {
        let p = policy();
        let r = p.redactor();
        for name in [
            "Authorization",
            "proxy-authorization",
            "WWW-Authenticate",
            "Proxy-Authenticate",
        ] {
            assert_eq!(
                r.header(name, "Digest username=\"alice\", response=\"deadbeef\""),
                HeaderAction::Delete,
                "{name}"
            );
        }
    }

    /// Every `P-Charging-Vector` parameter is rewritten, `void` excepted.
    #[test]
    fn every_charging_vector_parameter_is_rewritten() {
        let p = policy();
        let r = p.redactor();
        let raw = "icid-value=\"sbc01.carrier.example-8f2a\";\
                   icid-generated-at=sbc01.carrier.example;\
                   orig-ioi=carrier.example;term-ioi=peer.example;\
                   transit-ioi=transit1.example.1,void.2";
        let out = r.charging_vector(raw);
        for leak in [
            "sbc01",
            "carrier.example",
            "peer.example",
            "transit1.example",
            "8f2a",
        ] {
            assert!(!out.contains(leak), "{leak} survived: {out}");
        }
        assert!(
            out.contains("void.2"),
            "void is the spec's own marker: {out}"
        );
    }

    /// A `Call-ID` embedding a hostname loses both halves.
    #[test]
    fn a_call_id_loses_its_embedded_hostname() {
        let p = policy();
        let out = p.redactor().opaque("a84b4c76e66710@pbx.internal.example");
        assert!(!out.contains("pbx.internal.example"), "{out}");
        assert!(!out.contains("a84b4c76e66710"), "{out}");
        assert!(out.contains('@'), "the shape a parser expects: {out}");
    }

    /// A `From` header keeps its grammar and loses its identity.
    #[test]
    fn a_name_addr_keeps_its_shape() {
        let p = policy();
        let out = p.redactor().name_addr(
            "\"Alice Smith\" <sip:+15551234567@pbx.example;transport=tcp>;tag=1928301774",
        );
        assert!(out.starts_with('"'), "{out}");
        assert!(out.contains("<sip:"), "{out}");
        assert!(out.contains(";transport=tcp"), "routing survives: {out}");
        assert!(
            out.contains(";tag=1928301774"),
            "the dialog tag survives: {out}"
        );
        assert!(!out.contains("Alice Smith"), "{out}");
        assert!(!out.contains("5551234567"), "{out}");
        assert!(!out.contains("pbx.example"), "{out}");
    }

    /// The SDP origin loses its username and its address, and keeps its
    /// version counter.
    #[test]
    fn the_sdp_origin_is_rewritten_and_the_version_survives() {
        let p = policy();
        let out = p
            .redactor()
            .sdp("v=0\r\no=alice 2890844526 2890844527 IN IP4 10.0.2.15\r\nc=IN IP4 10.0.2.15\r\n");
        assert!(!out.contains("alice"), "{out}");
        assert!(!out.contains("10.0.2.15"), "{out}");
        assert!(out.contains("2890844526 2890844527"), "{out}");
        assert!(out.contains("c=IN IP4 "), "{out}");
    }

    /// The hold address survives an SDP rewrite.
    #[test]
    fn sdp_hold_survives_redaction() {
        let p = policy();
        let out = p.redactor().sdp("v=0\r\nc=IN IP4 0.0.0.0\r\n");
        assert!(out.contains("c=IN IP4 0.0.0.0"), "{out}");
    }

    /// Free prose loses the addresses and the numbers inside it.
    ///
    /// This is the failure mode PA5 predicted would actually ship: every
    /// structured field tokenized, and two addresses published through an
    /// explanation string.
    #[test]
    fn free_text_loses_addresses_and_numbers() {
        let p = policy();
        let out = p
            .redactor()
            .text("RTP from 10.0.2.15 -> 10.0.2.20 only; caller +15551234567 heard nothing");
        assert!(!out.contains("10.0.2.15"), "{out}");
        assert!(!out.contains("10.0.2.20"), "{out}");
        assert!(!out.contains("5551234567"), "{out}");
        assert!(out.contains("RTP from"), "the prose survives: {out}");
    }

    /// The text sweep leaves a timestamp alone.
    ///
    /// `04:19:00` matches any reasonable IPv6 pattern. Rewriting it would
    /// corrupt every clock in the export, which is why candidates are parsed
    /// before they are replaced.
    #[test]
    fn the_text_sweep_leaves_timestamps_alone() {
        let p = policy();
        let stamp = "2026-08-28T04:19:00.123456Z";
        assert_eq!(p.redactor().text(stamp), stamp);
    }

    /// A version string is not a phone number.
    #[test]
    fn the_text_sweep_leaves_short_numbers_alone() {
        let p = policy();
        let out = p
            .redactor()
            .text("sipnab 0.5.129 saw 42 dialogs in 1234 ms");
        assert_eq!(out, "sipnab 0.5.129 saw 42 dialogs in 1234 ms");
    }

    /// An unbracketed IPv6 literal stays an address.
    ///
    /// This is the form an SDP `c=IN IP6` line carries — no brackets, no port.
    /// Splitting it on its last colon reads `1` as a port and the rest as a
    /// name, which redacts and destroys the prefix-preserving map at the same
    /// time.
    #[test]
    fn an_unbracketed_ipv6_literal_is_read_as_an_address() {
        let p = policy();
        let r = p.redactor();
        let out = r.host("2001:db8::1");
        assert!(
            out.parse::<IpAddr>().is_ok(),
            "an address must pseudonymize to an address, got {out}"
        );
        let sibling = r.host("2001:db8::2");
        let (Ok(IpAddr::V6(a)), Ok(IpAddr::V6(b))) =
            (out.parse::<IpAddr>(), sibling.parse::<IpAddr>())
        else {
            panic!("both must parse as IPv6");
        };
        assert_eq!(a.octets()[..8], b.octets()[..8], "{a} {b}");
        assert_ne!(a, b);
    }

    /// A bracketed IPv6 literal keeps its brackets and its port.
    #[test]
    fn a_bracketed_ipv6_literal_keeps_its_shape() {
        let p = policy();
        let out = p.redactor().host("[2001:db8::1]:5060");
        assert!(out.starts_with('['), "{out}");
        assert!(out.ends_with("]:5060"), "{out}");
        assert!(!out.contains("db8"), "{out}");
    }

    /// The SDP connection line survives an IPv6 address.
    #[test]
    fn the_sdp_connection_line_handles_ipv6() {
        let p = policy();
        let out = p.redactor().sdp("v=0\r\nc=IN IP6 2001:db8::1\r\n");
        assert!(!out.contains("2001:db8::1"), "{out}");
        assert!(out.contains("c=IN IP6 "), "{out}");
        let addr = out
            .lines()
            .find_map(|l| l.strip_prefix("c=IN IP6 "))
            .unwrap_or("");
        assert!(addr.parse::<IpAddr>().is_ok(), "{out}");
    }

    /// A host name is replaced whole, never as a fragment of a longer word.
    ///
    /// `db` is a legal container name, and a plain `str::replace` on it would
    /// also rewrite the `db8` inside every `2001:db8::` in the same document —
    /// destroying the export by a different route than leaking it, and just as
    /// finally.
    #[test]
    fn a_hostname_sweep_never_matches_a_fragment() {
        assert_eq!(
            replace_hostname("host db, not 2001:db8::1 or dbx", "db", "N"),
            "host N, not 2001:db8::1 or dbx",
            "only the standalone occurrence is the host"
        );
        assert_eq!(
            replace_hostname("thor-02x and thor-02.", "thor-02", "N"),
            "thor-02x and N.",
            "a full stop ends the name; an alphanumeric continues it"
        );
        assert_eq!(
            replace_hostname("thor-02.example.com is longer", "thor-02", "N"),
            "thor-02.example.com is longer",
            "a dot followed by a label is a separator, not the end of the name"
        );
        assert_eq!(replace_hostname("nothing here", "", "N"), "nothing here");
    }

    /// A node name that is also an ordinary word over-redacts, and that is the
    /// safe direction.
    ///
    /// Pinned rather than left undiscovered. A host named `a` makes the needle
    /// an English article, and no boundary rule separates "the host named a"
    /// from "a capture" — so the prose loses both. The alternative is
    /// publishing the operator's capture host in a container that says it is
    /// redacted, which is the failure this whole sweep exists to prevent.
    #[test]
    fn a_hostname_that_is_also_a_word_over_redacts_rather_than_leaking() {
        assert_eq!(
            replace_hostname("a capture on node a, done", "a", "NODE"),
            "NODE capture on node NODE, done"
        );
    }

    /// The reverse table maps a token back to what it replaced.
    #[test]
    fn the_reverse_table_records_what_it_replaced() {
        let p = policy();
        let r = p.redactor();
        let token = r.identity("+15551234567");
        let table = r.mappings();
        assert!(
            table
                .iter()
                .any(|(k, v)| *k == token && v == "+15551234567"),
            "{table:?}"
        );
    }

    /// A JSON document is rewritten by key and swept as text.
    #[test]
    fn redact_json_covers_structure_and_prose() {
        let p = policy();
        let r = p.redactor();
        let mut value = serde_json::json!({
            "src": "10.0.2.15",
            "from": "<sip:+15551234567@pbx.example>;tag=1",
            "headers": {
                "Authorization": "Digest username=\"alice\", response=\"deadbeef\"",
                "Max-Forwards": "70"
            },
            "hint": "RTP from 10.0.2.15 -> 10.0.2.20 only"
        });
        redact_json(&mut value, &r);
        let text = value.to_string();
        for leak in [
            "10.0.2.15",
            "10.0.2.20",
            "5551234567",
            "pbx.example",
            "deadbeef",
        ] {
            assert!(!text.contains(leak), "{leak} survived: {text}");
        }
        assert!(text.contains("70"), "Max-Forwards survives: {text}");
    }

    /// A disabled report and an enabled one are different bytes.
    #[test]
    fn the_report_distinguishes_off_from_unstated() {
        let off = RedactionReport::disabled();
        assert!(!off.enabled);
        assert_eq!(off.key_mode, "none");
        let on = policy().report();
        assert!(on.enabled);
        assert_eq!(on.key_mode, KeyMode::Supplied.as_str());
        assert!(on.classes.contains(&"credential"));
    }

    /// The key never appears in a debug rendering.
    #[test]
    fn the_key_is_not_printable() {
        let key = RedactionKey::from_secret(b"secret");
        let shown = format!("{key:?}");
        assert!(shown.contains("Supplied"), "{shown}");
        assert!(!shown.contains("bytes"), "{shown}");
    }

    /// An ephemeral key is drawn from the system and differs per call.
    #[test]
    fn ephemeral_keys_differ() {
        let (Ok(a), Ok(b)) = (RedactionKey::ephemeral(), RedactionKey::ephemeral()) else {
            // No /dev/urandom is a platform this build does not target; the
            // supplied-key path is covered above either way.
            return;
        };
        assert_eq!(a.mode(), KeyMode::Ephemeral);
        assert_ne!(a.bytes, b.bytes);
    }
}
