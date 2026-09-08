// SPDX-License-Identifier: MIT OR Apache-2.0

//! A manager password in the clear, on a port sipnab reads and never parsed.
//!
//! Asterisk's Manager Interface listens on TCP/5038 and speaks a line protocol.
//! A login is four lines of plain text:
//!
//! ```text
//! Action: login
//! Username: admin
//! Secret: <the password>
//! ```
//!
//! sipnab already ships `--digest-leak`, which reports a SIP digest weak enough
//! to grind offline. A manager password on the wire is the same finding class
//! with strictly worse consequences: it is not a hash to attack, it is the
//! credential, and AMI can originate calls, read configuration and run shell
//! commands on the box.
//!
//! # Why nothing saw it
//!
//! `capture_status` reports `unanalysed_sip_messages: 0` on a capture full of
//! this, and the number is honest — AMI is not SIP, so there was no unparsed
//! SIP message to count. Every detector sipnab had ran on parsed SIP messages,
//! and this traffic never became one.
//!
//! # What this is not
//!
//! **Not an AMI decoder.** It matches a banner and a login line and records
//! where they were. It does not track sessions, follow responses, or interpret
//! anything else the protocol carries.
//!
//! **It never stores or echoes the secret.** The `Secret:` line is evidence
//! that a credential crossed the wire; its value is the thing a finding must
//! not carry, because a finding is written to logs, exported in containers and
//! read into an agent'"'"'s context. Only the fact, the addresses and the frame
//! pointer are kept.

use serde::Serialize;

/// The banner an Asterisk Manager Interface greets a client with.
///
/// Matched as a prefix of the line, so the version that follows it is not part
/// of the rule: `Asterisk Call Manager/9.0.0` and `/2.10.6` are the same
/// finding, and pinning a version would make the detector go quiet on the next
/// release.
pub const AMI_BANNER: &str = "Asterisk Call Manager/";

/// The default port Asterisk listens for AMI on.
///
/// Reported, never required. A manager interface moved to another port is
/// still a manager interface, and a rule that keyed on 5038 would miss exactly
/// the deployment that thought it had hidden it.
pub const AMI_DEFAULT_PORT: u16 = 5038;

/// Longest value echoed from an AMI line, in characters.
///
/// Only the username is ever echoed, and only because a finding naming WHICH
/// account was exposed is actionable where one saying "an account" is not. The
/// secret is never echoed at any length.
pub const MAX_AMI_VALUE_CHARS: usize = 64;

/// What one TCP payload showed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
#[serde(rename_all = "kebab-case")]
pub enum AmiObservation {
    /// The server announced itself. Evidence the port speaks AMI, and nothing
    /// about whether anyone authenticated over it.
    Banner {
        /// The version string the banner carried, bounded and echoed. It is
        /// the operator'"'"'s own software version, not a credential.
        version: Option<String>,
    },
    /// A login was attempted in the clear.
    CleartextLogin {
        /// The account named, when the payload carried one. Bounded.
        ///
        /// Echoed on purpose: a finding that names the exposed account can be
        /// acted on, and one that says "an account" cannot. The SECRET is
        /// never echoed.
        username: Option<String>,
        /// Whether a `Secret:` line was present.
        ///
        /// A boolean, deliberately. This is the whole finding -- a password
        /// crossed the wire in the clear -- and the value is the one thing
        /// that must not be recorded.
        secret_present: bool,
    },
}

/// Read one TCP payload for AMI evidence.
///
/// Takes bytes rather than a parsed anything, because there is nothing parsed
/// to take: this traffic never becomes a `SipMessage`, which is the whole
/// reason it went unseen. Returns `None` for every payload that is not one of
/// the two shapes, which is nearly all of them.
#[must_use]
pub fn observe(payload: &[u8]) -> Option<AmiObservation> {
    // Two byte-level tests BEFORE anything allocates.
    //
    // This runs on every non-SIP TCP payload in a capture, and a corpus full
    // of HTTP is exactly that. Decoding first cost a `String` allocation over
    // the whole payload per packet: the corpus gate went from minutes to past
    // its 1800-second wedge threshold, on traffic that could never match.
    // Neither test below allocates, and together they reject everything but
    // the two shapes this reads.
    if !starts_with_ignore_case(payload, AMI_BANNER.as_bytes())
        && !starts_with_ignore_case(payload, b"Action:")
    {
        return None;
    }
    // Lossy rather than strict, now that the payload is worth decoding. AMI is
    // a text protocol and a capture holds whatever was on the wire; refusing a
    // payload with one bad byte would make the detector go quiet on exactly
    // the packet somebody corrupted.
    let text = String::from_utf8_lossy(payload);

    if let Some(rest) = text.strip_prefix(AMI_BANNER) {
        let version = rest
            .split(['\r', '\n'])
            .next()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(bound);
        return Some(AmiObservation::Banner { version });
    }

    let mut is_login = false;
    let mut username = None;
    let mut secret_present = false;
    for line in text.split(['\r', '\n']).filter(|l| !l.is_empty()) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        let value = value.trim();
        // AMI clients differ on capitalization and Asterisk accepts any of
        // them, so a rule matching one spelling would miss the deployments
        // that use another.
        if name.eq_ignore_ascii_case("action") && value.eq_ignore_ascii_case("login") {
            is_login = true;
        } else if name.eq_ignore_ascii_case("username") && !value.is_empty() {
            username = Some(bound(value));
        } else if name.eq_ignore_ascii_case("secret") && !value.is_empty() {
            // Recorded as a BOOLEAN. The value is the one thing a finding must
            // never carry: findings are written to logs, exported in
            // containers, and read into an agent's context.
            secret_present = true;
        }
    }
    is_login.then_some(AmiObservation::CleartextLogin {
        username,
        secret_present,
    })
}

/// ASCII-case-insensitive prefix test that allocates nothing.
///
/// The gate in front of every decode. `eq_ignore_ascii_case` on a slice does
/// the same work without building a `String`, which is the whole point: this
/// runs per packet on a path where most packets are HTTP.
fn starts_with_ignore_case(haystack: &[u8], prefix: &[u8]) -> bool {
    haystack.len() >= prefix.len() && haystack[..prefix.len()].eq_ignore_ascii_case(prefix)
}

/// Bound and clean one echoed value.
///
/// Control characters are stripped for the reason every other remote-written
/// value in this tree is: it reaches a terminal, a Markdown table and an
/// agent's context.
fn bound(value: &str) -> String {
    value
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_AMI_VALUE_CHARS)
        .collect()
}

/// One recorded sighting, with where it happened.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub struct AmiFinding {
    /// What the payload showed.
    pub observation: AmiObservation,
    /// Who sent it.
    pub src: String,
    /// Who received it.
    pub dst: String,
    /// The destination port, so a manager interface moved off 5038 is still
    /// reported with the port it was actually found on.
    pub dst_port: u16,
    /// Whether that port is the documented default. Reported rather than
    /// required: a service moved to another port is the deployment most likely
    /// to believe it is hidden.
    pub default_port: bool,
    /// How many payloads carried this same observation between this pair.
    pub count: u64,
}

/// Sightings so far, keyed so one busy session does not become a thousand
/// findings.
///
/// A `Mutex` rather than per-packet state for the reason `PORTRANGE_SKIPS` is
/// one: it is taken only when a payload really matches, which on any real
/// capture is a handful of packets out of millions. The RTP and SIP hot paths
/// never touch it.
static SIGHTINGS: parking_lot::Mutex<Option<SightingCounts>> = parking_lot::Mutex::new(None);

/// Sighting counts, keyed by `(src, dst, dst_port, what)`.
///
/// Named rather than written inline: the tuple has four parts and three of
/// them are strings and numbers a reader cannot tell apart at the type level.
type SightingCounts = std::collections::BTreeMap<(String, String, u16, AmiObservationKey), u64>;

/// The part of an observation that identifies it, for counting.
///
/// The username is deliberately NOT in the key. Counting per account would
/// make the map grow with whatever a sender puts in the field, which is an
/// attacker-chosen value on a path that runs before authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum AmiObservationKey {
    /// A server banner.
    Banner,
    /// A login with a `Secret:` line.
    CleartextLogin,
    /// A login without one.
    LoginNoSecret,
}

/// Record one payload's evidence, if it carries any.
///
/// Called from the packet path on payloads that were not SIP — which is where
/// this traffic has always been, unseen. Returns whether anything was
/// recorded, so a caller can raise an alert without re-reading the payload.
pub fn record(
    payload: &[u8],
    src: std::net::IpAddr,
    dst: std::net::IpAddr,
    dst_port: u16,
) -> Option<AmiObservation> {
    let observation = observe(payload)?;
    let mut st = SIGHTINGS.lock();
    record_into(
        st.get_or_insert_with(Default::default),
        &observation,
        src,
        dst,
        dst_port,
    );
    Some(observation)
}

/// Count one observation into a caller's own map.
///
/// The global is a thin wrapper over this. Tests drive the map directly and
/// never touch process-wide state — which they cannot share safely: two of
/// them clobbered each other through it the first time, each resetting the
/// map the other was counting into.
fn record_into(
    map: &mut SightingCounts,
    observation: &AmiObservation,
    src: std::net::IpAddr,
    dst: std::net::IpAddr,
    dst_port: u16,
) {
    let key = match observation {
        AmiObservation::Banner { .. } => AmiObservationKey::Banner,
        AmiObservation::CleartextLogin {
            secret_present: true,
            ..
        } => AmiObservationKey::CleartextLogin,
        AmiObservation::CleartextLogin { .. } => AmiObservationKey::LoginNoSecret,
    };
    *map.entry((src.to_string(), dst.to_string(), dst_port, key))
        .or_insert(0) += 1;
}

/// Everything recorded so far, busiest first.
#[must_use]
pub fn findings() -> Vec<AmiFinding> {
    let st = SIGHTINGS.lock();
    st.as_ref().map(findings_from).unwrap_or_default()
}

/// The findings one map holds, busiest first.
fn findings_from(map: &SightingCounts) -> Vec<AmiFinding> {
    let mut out: Vec<AmiFinding> = map
        .iter()
        .map(|((src, dst, port, key), count)| AmiFinding {
            observation: match key {
                AmiObservationKey::Banner => AmiObservation::Banner { version: None },
                AmiObservationKey::CleartextLogin => AmiObservation::CleartextLogin {
                    username: None,
                    secret_present: true,
                },
                AmiObservationKey::LoginNoSecret => AmiObservation::CleartextLogin {
                    username: None,
                    secret_present: false,
                },
            },
            src: src.clone(),
            dst: dst.clone(),
            dst_port: *port,
            default_port: *port == AMI_DEFAULT_PORT,
            count: *count,
        })
        .collect();
    out.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.src.cmp(&b.src)));
    out
}

/// Forget everything recorded.
///
/// For tests, which must not see each other's sightings through a
/// process-wide map. `pub` behind `cfg(test)` because the wiring test lives in
/// `pipeline`, which is where the hook is.
#[cfg(test)]
pub fn reset_for_test() {
    *SIGHTINGS.lock() = None;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Recording aggregates by pair, and never by the account named.
    ///
    /// One AMI session reconnecting in a loop is one finding with a count, not
    /// a thousand findings. The username is deliberately outside the key: this
    /// path runs before authentication, so the field is attacker-chosen, and
    /// keying on it would let a sender grow the map without limit.
    /// Recording aggregates by pair, and never by the account named.
    ///
    /// One AMI session reconnecting in a loop is one finding with a count, not
    /// a thousand findings. The username is deliberately outside the key: this
    /// path runs before authentication, so the field is attacker-chosen, and
    /// keying on it would let a sender grow the map without limit.
    ///
    /// Driven on the test's OWN map. The process-wide one cannot be shared:
    /// two tests resetting it around each other's counting is how this first
    /// went red.
    #[test]
    fn sightings_aggregate_by_pair_and_not_by_account() {
        let mut map = SightingCounts::default();
        let a: std::net::IpAddr = "198.51.100.10".parse().expect("src");
        let b: std::net::IpAddr = "198.51.100.20".parse().expect("dst");
        for account in ["admin", "operator", "admin"] {
            let payload = format!("Action: login\r\nUsername: {account}\r\nSecret: x\r\n");
            let o = observe(payload.as_bytes()).expect("each login is recognized");
            record_into(&mut map, &o, a, b, AMI_DEFAULT_PORT);
        }
        let found = findings_from(&map);
        assert_eq!(found.len(), 1, "three logins, one pair, one row: {found:?}");
        assert_eq!(found[0].count, 3);
        assert_eq!(found[0].dst_port, AMI_DEFAULT_PORT);
        assert!(found[0].default_port);
        let rendered = serde_json::to_string(&found).expect("serializes");
        for account in ["admin", "operator"] {
            assert!(
                !rendered.contains(account),
                "an account name reached the aggregate: {rendered}"
            );
        }
    }

    /// A manager interface moved off 5038 is still reported.
    ///
    /// The port is an observation, not a filter. A deployment that moved the
    /// service is the one most likely to think nobody can find it, and a rule
    /// keyed on 5038 would agree.
    #[test]
    fn a_manager_interface_on_another_port_is_still_found() {
        let mut map = SightingCounts::default();
        let a: std::net::IpAddr = "198.51.100.10".parse().expect("src");
        let b: std::net::IpAddr = "198.51.100.20".parse().expect("dst");
        let o = observe(b"Action: login\r\nUsername: admin\r\nSecret: x\r\n")
            .expect("a login is recognized");
        record_into(&mut map, &o, a, b, 15038);
        let found = findings_from(&map);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].dst_port, 15038);
        assert!(
            !found[0].default_port,
            "the port is reported as non-default rather than the finding being \
             withheld"
        );
    }

    /// Nothing recorded reports nothing, rather than an empty finding.
    #[test]
    fn no_sightings_report_nothing() {
        assert!(findings_from(&SightingCounts::default()).is_empty());
    }

    /// A greeting is evidence of the protocol, not of a leak.
    #[test]
    fn the_banner_alone_is_not_a_credential_finding() {
        let o = observe(b"Asterisk Call Manager/9.0.0\r\n").expect("the banner matches");
        assert_eq!(
            o,
            AmiObservation::Banner {
                version: Some("9.0.0".to_string())
            }
        );
    }

    /// The version is reported and never required.
    #[test]
    fn any_version_matches_and_a_missing_one_still_does() {
        for (payload, want) in [
            (&b"Asterisk Call Manager/2.10.6\r\n"[..], Some("2.10.6")),
            (&b"Asterisk Call Manager/9.0.0\r\n"[..], Some("9.0.0")),
            (&b"Asterisk Call Manager/\r\n"[..], None),
        ] {
            assert_eq!(
                observe(payload),
                Some(AmiObservation::Banner {
                    version: want.map(str::to_string)
                }),
                "payload {payload:?}"
            );
        }
    }

    /// The finding: a password crossed the wire.
    #[test]
    fn a_login_reports_the_account_and_never_the_secret() {
        let payload = b"Action: login\r\nUsername: admin\r\nSecret: hunter2\r\n\r\n";
        let o = observe(payload).expect("a login matches");
        assert_eq!(
            o,
            AmiObservation::CleartextLogin {
                username: Some("admin".to_string()),
                secret_present: true,
            }
        );
        // The value must not survive anywhere in the observation.
        let rendered = serde_json::to_string(&o).expect("serializes");
        assert!(
            !rendered.contains("hunter2"),
            "the secret reached the finding: {rendered}"
        );
    }

    /// RFC-style header names are case-insensitive in practice, and AMI
    /// clients differ. A detector that matched one spelling would miss the
    /// deployments that use another.
    #[test]
    fn the_action_and_its_fields_are_matched_case_insensitively() {
        for payload in [
            &b"action: login\r\nusername: admin\r\nsecret: x\r\n"[..],
            &b"ACTION: LOGIN\r\nUSERNAME: admin\r\nSECRET: x\r\n"[..],
            &b"Action: Login\r\nUsername: admin\r\nSecret: x\r\n"[..],
        ] {
            assert!(
                matches!(
                    observe(payload),
                    Some(AmiObservation::CleartextLogin {
                        secret_present: true,
                        ..
                    })
                ),
                "payload {payload:?} is a cleartext login"
            );
        }
    }

    /// A login with no `Secret:` line is still reported, and says so.
    ///
    /// AMI also authenticates with an MD5 challenge. That is a different
    /// exposure and reporting it as a cleartext password would be wrong, so
    /// the flag carries the difference rather than the detector guessing.
    #[test]
    fn a_login_without_a_secret_line_is_not_reported_as_one() {
        let o = observe(b"Action: login\r\nUsername: admin\r\nAuthType: MD5\r\n")
            .expect("a login matches");
        assert_eq!(
            o,
            AmiObservation::CleartextLogin {
                username: Some("admin".to_string()),
                secret_present: false,
            }
        );
    }

    /// Ordinary traffic is not a finding.
    #[test]
    fn nothing_else_matches() {
        for payload in [
            &b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"[..],
            &b"INVITE sip:bob@example.com SIP/2.0\r\n"[..],
            &b"Action: ping\r\n"[..],
            &b"\x00\x01\x02\x03"[..],
            &b""[..],
        ] {
            assert_eq!(observe(payload), None, "payload {payload:?}");
        }
    }

    /// A crafted username cannot spend the screen, and binary cannot reach it.
    #[test]
    fn an_echoed_value_is_bounded_and_printable() {
        let long = "A".repeat(4096);
        let payload = format!("Action: login\r\nUsername: {long}\r\nSecret: x\r\n");
        let o = observe(payload.as_bytes()).expect("a login matches");
        let AmiObservation::CleartextLogin { username, .. } = o else {
            panic!("expected a login");
        };
        let username = username.expect("a username is echoed");
        assert!(
            username.chars().count() <= MAX_AMI_VALUE_CHARS,
            "username is {} chars, over the {MAX_AMI_VALUE_CHARS} bound",
            username.chars().count()
        );
    }

    /// A payload that is not UTF-8 is not a reason to miss the login.
    ///
    /// AMI is a text protocol, but a capture holds whatever was on the wire.
    /// Decoding lossily rather than refusing keeps a detector from going quiet
    /// on the one packet somebody corrupted.
    #[test]
    fn invalid_utf8_does_not_hide_a_login() {
        let mut payload = b"Action: login\r\nUsername: ad".to_vec();
        payload.push(0xff);
        payload.extend_from_slice(b"min\r\nSecret: x\r\n");
        assert!(
            matches!(
                observe(&payload),
                Some(AmiObservation::CleartextLogin {
                    secret_present: true,
                    ..
                })
            ),
            "a lossy decode must still see the login"
        );
    }
}
