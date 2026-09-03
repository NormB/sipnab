// SPDX-License-Identifier: MIT OR Apache-2.0

//! Digest authentication vulnerability detection.
//!
//! Analyzes SIP 401/407 challenges and Authorization/Proxy-Authorization
//! responses to identify weaknesses in digest authentication configuration:
//! - **Weak algorithm** — MD5 instead of SHA-256 or stronger
//! - **Nonce reuse** — same nonce issued on more than one transaction
//!   (replay risk)
//! - **Missing qop** — challenge without `qop=auth` (downgrade risk)
//! - **Missing cnonce** — response without `cnonce` when `qop` is present

use std::collections::HashMap;

use crate::sip::SipMessage;

/// Cap on remembered nonces, to bound memory on a long capture.
const MAX_NONCE_ENTRIES: usize = 10_000;

/// The transaction a challenge was issued in: its Call-ID, CSeq number and
/// top `Via` branch.
///
/// RFC 3261 section 17.2.2 requires a non-INVITE server transaction to answer
/// a retransmitted request with the same final response it already sent. A
/// 401 lost on UDP therefore arrives a second time carrying the same nonce,
/// and the only thing that tells that copy from a second challenge is the
/// transaction it belongs to. All three fields are compared: a
/// retransmission repeats every one of them, and a new request differs in at
/// least one. A field the message lacks compares as empty, so two malformed
/// copies still match each other and nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ChallengeTransaction {
    /// The `Call-ID` header, or empty when absent.
    call_id: String,
    /// The `CSeq` sequence number, or `None` when absent or malformed.
    cseq: Option<u32>,
    /// The top `Via` branch, or empty when absent.
    branch: String,
}

impl ChallengeTransaction {
    /// The transaction `msg` was sent in.
    fn of(msg: &SipMessage) -> Self {
        Self {
            call_id: msg.call_id().unwrap_or("").to_owned(),
            cseq: msg.cseq().map(|(number, _)| number),
            branch: msg.top_via_branch().unwrap_or("").to_owned(),
        }
    }
}

/// What one more sighting of a nonce means, given the transaction it was
/// last seen in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NonceSighting {
    /// Never seen before.
    First,
    /// Seen before on this same transaction: the registrar retransmitted its
    /// final response, as RFC 3261 section 17.2.2 requires.
    Retransmission,
    /// Seen before on another transaction: the registrar issued it twice.
    Reuse,
}

/// Classify a sighting of a nonce on `current`, given the transaction
/// `previous` it was last seen in.
///
/// The whole of the reuse decision, kept as a function of its two inputs so
/// the set of remembered nonces cannot re-enter it.
fn classify_nonce_sighting(
    previous: Option<&ChallengeTransaction>,
    current: &ChallengeTransaction,
) -> NonceSighting {
    match previous {
        None => NonceSighting::First,
        Some(seen) if seen == current => NonceSighting::Retransmission,
        Some(_) => NonceSighting::Reuse,
    }
}

/// Classification of digest authentication vulnerabilities.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DigestVulnerability {
    /// Server uses MD5 algorithm (should use SHA-256 or stronger).
    WeakAlgorithm,
    /// Same nonce value issued in 401/407 challenges on more than one
    /// transaction. A retransmitted challenge is the same transaction again.
    NonceReuse,
    /// Challenge lacks `qop` parameter (weaker authentication).
    MissingQop,
    /// Authorization response missing `cnonce` when `qop` is present.
    MissingCnonce,
}

/// Alert produced when a digest authentication weakness is found.
#[derive(Debug, Clone)]
pub struct DigestAlert {
    /// The specific vulnerability detected.
    pub vulnerability: DigestVulnerability,
    /// Human-readable description of the issue.
    pub detail: String,
}

/// Detects digest authentication vulnerabilities in SIP messages.
///
/// Statefully tracks nonces across 401/407 challenges to detect reuse.
pub struct DigestLeakDetector {
    /// Every nonce seen in a challenge, with the transaction it was last
    /// issued on.
    seen_nonces: HashMap<String, ChallengeTransaction>,
}

impl DigestLeakDetector {
    /// Create a new digest leak detector.
    pub fn new() -> Self {
        Self {
            seen_nonces: HashMap::new(),
        }
    }

    /// Check a SIP message for digest authentication vulnerabilities.
    ///
    /// Returns a list of all detected vulnerabilities. Multiple issues
    /// can be present in a single message (e.g., weak algorithm AND
    /// missing qop in the same 401 challenge).
    #[must_use]
    pub fn check(&mut self, msg: &SipMessage) -> Vec<DigestAlert> {
        let mut alerts = Vec::new();

        // Check 401/407 challenges (WWW-Authenticate / Proxy-Authenticate)
        if !msg.is_request
            && let Some(code) = msg.status_code
            && (code == 401 || code == 407)
        {
            self.check_challenge(msg, &mut alerts);
        }

        // Check Authorization / Proxy-Authorization responses
        if msg.is_request {
            self.check_authorization(msg, &mut alerts);
        }

        alerts
    }

    /// Analyze a 401/407 challenge for weaknesses.
    fn check_challenge(&mut self, msg: &SipMessage, alerts: &mut Vec<DigestAlert>) {
        let auth_headers: Vec<&str> = msg
            .headers_by_name("WWW-Authenticate")
            .into_iter()
            .chain(msg.headers_by_name("Proxy-Authenticate"))
            .collect();

        for header_value in auth_headers {
            // Skip non-Digest schemes
            let trimmed = header_value.trim();
            if !trimmed.starts_with("Digest") && !trimmed.starts_with("digest") {
                continue;
            }

            // Check for weak algorithm (MD5)
            if let Some(algo) = extract_param(header_value, "algorithm") {
                if algo.eq_ignore_ascii_case("MD5") {
                    alerts.push(DigestAlert {
                        vulnerability: DigestVulnerability::WeakAlgorithm,
                        detail: format!("challenge uses algorithm={algo} (should be SHA-256+)"),
                    });
                }
            } else {
                // RFC 2617: absent algorithm defaults to MD5
                alerts.push(DigestAlert {
                    vulnerability: DigestVulnerability::WeakAlgorithm,
                    detail: "challenge has no algorithm parameter (defaults to MD5)".to_string(),
                });
            }

            // Check for missing qop
            if extract_param(header_value, "qop").is_none() {
                alerts.push(DigestAlert {
                    vulnerability: DigestVulnerability::MissingQop,
                    detail: "challenge missing qop parameter (weaker authentication)".to_string(),
                });
            }

            // Nonce reuse: the same nonce issued on two transactions. On the
            // SAME transaction it is the registrar retransmitting the final
            // response it already sent -- one lost 401 on UDP and the copy
            // arrives -- which is not a second challenge and, before this
            // was keyed, reported a healthy registrar for replay risk.
            if let Some(nonce) = extract_param(header_value, "nonce") {
                let transaction = ChallengeTransaction::of(msg);
                match classify_nonce_sighting(self.seen_nonces.get(nonce), &transaction) {
                    NonceSighting::Retransmission => {}
                    NonceSighting::Reuse => {
                        alerts.push(DigestAlert {
                            vulnerability: DigestVulnerability::NonceReuse,
                            detail: format!(
                                "nonce '{nonce}' reused across challenges (replay risk)"
                            ),
                        });
                        // Reported once: the reused challenge's own
                        // retransmission is this transaction again.
                        self.seen_nonces.insert(nonce.to_string(), transaction);
                    }
                    NonceSighting::First => {
                        if self.seen_nonces.len() >= MAX_NONCE_ENTRIES {
                            // Drop an arbitrary entry to stay bounded.
                            let first = self.seen_nonces.keys().next().cloned();
                            if let Some(key) = first {
                                self.seen_nonces.remove(&key);
                            }
                        }
                        self.seen_nonces.insert(nonce.to_string(), transaction);
                    }
                }
            }
        }
    }

    /// Analyze an Authorization/Proxy-Authorization response for weaknesses.
    fn check_authorization(&self, msg: &SipMessage, alerts: &mut Vec<DigestAlert>) {
        let auth_headers: Vec<&str> = msg
            .headers_by_name("Authorization")
            .into_iter()
            .chain(msg.headers_by_name("Proxy-Authorization"))
            .collect();

        for header_value in auth_headers {
            let trimmed = header_value.trim();
            if !trimmed.starts_with("Digest") && !trimmed.starts_with("digest") {
                continue;
            }

            // Check for missing cnonce when qop is present
            let has_qop = extract_param(header_value, "qop").is_some();
            let has_cnonce = extract_param(header_value, "cnonce").is_some();

            if has_qop && !has_cnonce {
                alerts.push(DigestAlert {
                    vulnerability: DigestVulnerability::MissingCnonce,
                    detail: "authorization has qop but missing cnonce parameter".to_string(),
                });
            }
        }
    }
}

impl Default for DigestLeakDetector {
    /// Equivalent to `DigestLeakDetector::new` — an empty detector.
    fn default() -> Self {
        Self::new()
    }
}

/// Extract a parameter value from a Digest authentication header.
///
/// Handles both quoted (`param="value"`) and unquoted (`param=value`) forms.
/// Parameter matching is case-insensitive.
fn extract_param<'a>(header: &'a str, param_name: &str) -> Option<&'a str> {
    let lower_header = header.to_ascii_lowercase();
    let search = format!("{}=", param_name.to_ascii_lowercase());

    let idx = lower_header.find(&search)?;
    let value_start = idx + search.len();
    let remainder = &header[value_start..];

    if let Some(after_quote) = remainder.strip_prefix('"') {
        // Quoted value
        let end_quote = after_quote.find('"')?;
        Some(&after_quote[..end_quote])
    } else {
        // Unquoted value — ends at comma, space, or end-of-string
        let end = remainder.find([',', ' ', '\t']).unwrap_or(remainder.len());
        let value = remainder[..end].trim();
        if value.is_empty() { None } else { Some(value) }
    }
}

// ── Tests ────────────────────────────────────────────────────────────

/// Unit tests for digest authentication vulnerability detection.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::TransportProto;
    use crate::sip::parser::parse_sip;
    use chrono::{DateTime, Utc};
    use std::net::{IpAddr, Ipv4Addr};

    /// The loopback address used as source/destination in the test messages.
    fn localhost() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    /// A fixed capture timestamp for the parsed SIP messages.
    fn ts() -> DateTime<Utc> {
        chrono::TimeZone::with_ymd_and_hms(&Utc, 2024, 6, 15, 12, 0, 0).unwrap()
    }

    use crate::test_utils::build_sip_message as build_sip;

    /// Build a 401 challenge whose digest declares the weak MD5 algorithm.
    fn make_401_md5() -> SipMessage {
        let raw = build_sip(
            "SIP/2.0 401 Unauthorized",
            &[
                "From: <sip:alice@example.com>;tag=t1",
                "To: <sip:alice@example.com>;tag=t2",
                "Call-ID: digest-test@example.com",
                "CSeq: 1 REGISTER",
                r#"WWW-Authenticate: Digest realm="example.com", nonce="abc123", algorithm=MD5"#,
                "Content-Length: 0",
            ],
            b"",
        );
        parse_sip(
            &raw,
            ts(),
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("parse 401")
    }

    /// Build a 401 challenge using SHA-256 but omitting the `qop` parameter.
    fn make_401_no_qop() -> SipMessage {
        let raw = build_sip(
            "SIP/2.0 401 Unauthorized",
            &[
                "From: <sip:alice@example.com>;tag=t1",
                "To: <sip:alice@example.com>;tag=t2",
                "Call-ID: digest-noqop@example.com",
                "CSeq: 1 REGISTER",
                r#"WWW-Authenticate: Digest realm="example.com", nonce="def456", algorithm=SHA-256"#,
                "Content-Length: 0",
            ],
            b"",
        );
        parse_sip(
            &raw,
            ts(),
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("parse 401")
    }

    /// Build a strong 401 challenge (SHA-256, unique nonce, `qop=auth`).
    fn make_401_good() -> SipMessage {
        let raw = build_sip(
            "SIP/2.0 401 Unauthorized",
            &[
                "From: <sip:alice@example.com>;tag=t1",
                "To: <sip:alice@example.com>;tag=t2",
                "Call-ID: digest-good@example.com",
                "CSeq: 1 REGISTER",
                r#"WWW-Authenticate: Digest realm="example.com", nonce="unique999", algorithm=SHA-256, qop="auth""#,
                "Content-Length: 0",
            ],
            b"",
        );
        parse_sip(
            &raw,
            ts(),
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("parse 401")
    }

    /// An MD5 challenge is flagged as a weak algorithm.
    #[test]
    fn detect_weak_algorithm() {
        let mut detector = DigestLeakDetector::new();
        let msg = make_401_md5();

        let alerts = detector.check(&msg);
        assert!(
            alerts
                .iter()
                .any(|a| a.vulnerability == DigestVulnerability::WeakAlgorithm),
            "should detect weak MD5 algorithm"
        );
    }

    /// A challenge without `qop` is flagged as missing qop.
    #[test]
    fn detect_missing_qop() {
        let mut detector = DigestLeakDetector::new();
        let msg = make_401_no_qop();

        let alerts = detector.check(&msg);
        assert!(
            alerts
                .iter()
                .any(|a| a.vulnerability == DigestVulnerability::MissingQop),
            "should detect missing qop"
        );
    }

    /// A strong 401 (SHA-256 + qop) produces no alerts.
    #[test]
    fn good_401_no_alerts() {
        let mut detector = DigestLeakDetector::new();
        let msg = make_401_good();

        let alerts = detector.check(&msg);
        assert!(
            alerts.is_empty(),
            "good 401 with SHA-256 + qop should produce no alerts, got: {alerts:?}"
        );
    }

    /// A 401 issued on the transaction (`call_id`, `cseq`, top-`Via`
    /// `branch`), challenging with `nonce`. Strong in every other respect, so
    /// the only alert it can draw is `NonceReuse`.
    fn challenge(call_id: &str, cseq: u32, branch: &str, nonce: &str) -> SipMessage {
        let via = format!("Via: SIP/2.0/UDP 10.0.0.7:5060;branch={branch}");
        let call_id = format!("Call-ID: {call_id}");
        let cseq = format!("CSeq: {cseq} REGISTER");
        let www = format!(
            r#"WWW-Authenticate: Digest realm="example.com", nonce="{nonce}", algorithm=SHA-256, qop="auth""#
        );
        let raw = build_sip(
            "SIP/2.0 401 Unauthorized",
            &[
                via.as_str(),
                "From: <sip:alice@example.com>;tag=t1",
                "To: <sip:alice@example.com>;tag=t2",
                call_id.as_str(),
                cseq.as_str(),
                www.as_str(),
                "Content-Length: 0",
            ],
            b"",
        );
        parse_sip(
            &raw,
            ts(),
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("parse 401")
    }

    /// How many of `alerts` are `NonceReuse`.
    fn nonce_reuse_alerts(alerts: &[DigestAlert]) -> usize {
        alerts
            .iter()
            .filter(|a| a.vulnerability == DigestVulnerability::NonceReuse)
            .count()
    }

    /// The same nonce handed to two different transactions -- here two
    /// Call-IDs, two phones challenged with one nonce -- is reuse.
    ///
    /// The control for the retransmission test below: the detector must keep
    /// firing on real reuse once it has learned to ignore a retransmission.
    #[test]
    fn detect_nonce_reuse() {
        let mut detector = DigestLeakDetector::new();
        let _ = detector.check(&challenge("phone-a@10.0.0.7", 1, "z9hG4bK-a1", "n-shared"));
        let alerts = detector.check(&challenge("phone-b@10.0.0.8", 1, "z9hG4bK-b1", "n-shared"));
        assert_eq!(
            nonce_reuse_alerts(&alerts),
            1,
            "one nonce challenging two Call-IDs is reuse, and must be reported: {alerts:?}"
        );
    }

    /// The failure this shipped with. A REGISTER over lossy UDP: the 401 is
    /// lost, the client retransmits, and RFC 3261 section 17.2.2 REQUIRES the
    /// registrar to answer the retransmission with the same final response --
    /// the same 401, carrying the same nonce. One set of nonces with no
    /// notion of a transaction read that second copy as a second challenge
    /// and reported a healthy registrar for nonce reuse; with `--alert-exec`
    /// a command spawned for it.
    #[test]
    fn a_retransmitted_401_is_not_nonce_reuse() {
        let mut detector = DigestLeakDetector::new();
        let first = challenge("reg-1@phone", 1, "z9hG4bK-reg-1", "n-1");
        assert_eq!(
            nonce_reuse_alerts(&detector.check(&first)),
            0,
            "control: the first sighting of a nonce is not reuse"
        );

        let retransmitted = challenge("reg-1@phone", 1, "z9hG4bK-reg-1", "n-1");
        let alerts = detector.check(&retransmitted);
        assert_eq!(
            nonce_reuse_alerts(&alerts),
            0,
            "a retransmission of the same 401 -- same Call-ID, CSeq and Via branch, \
             which RFC 3261 section 17.2.2 requires the registrar to send -- was \
             reported as nonce reuse against a healthy registrar: {alerts:?}"
        );
    }

    /// One dialog, next CSeq, same nonce: the registrar re-challenged a
    /// credentialed retry with the nonce it had already issued. That is a new
    /// transaction and real reuse, and the transaction key must not be so
    /// loose that a shared Call-ID hides it.
    #[test]
    fn the_same_nonce_on_the_next_cseq_of_one_dialog_is_reuse() {
        let mut detector = DigestLeakDetector::new();
        let _ = detector.check(&challenge("reg-2@phone", 1, "z9hG4bK-reg-2a", "n-2"));
        let alerts = detector.check(&challenge("reg-2@phone", 2, "z9hG4bK-reg-2b", "n-2"));
        assert_eq!(
            nonce_reuse_alerts(&alerts),
            1,
            "the same nonce on the next CSeq of one dialog is a second challenge \
             with a used nonce, and must be reported: {alerts:?}"
        );
    }

    /// A reused challenge is reported once. Its own retransmission -- the
    /// second phone's 401 lost and re-sent -- is the same message again, and
    /// must not count as a third challenge.
    #[test]
    fn a_retransmission_of_a_reused_challenge_is_not_reported_again() {
        let mut detector = DigestLeakDetector::new();
        let _ = detector.check(&challenge("phone-a@10.0.0.7", 1, "z9hG4bK-a1", "n-shared"));
        let reused = challenge("phone-b@10.0.0.8", 1, "z9hG4bK-b1", "n-shared");
        assert_eq!(
            nonce_reuse_alerts(&detector.check(&reused)),
            1,
            "control: the second transaction with this nonce is reuse"
        );

        let retransmitted = challenge("phone-b@10.0.0.8", 1, "z9hG4bK-b1", "n-shared");
        let alerts = detector.check(&retransmitted);
        assert_eq!(
            nonce_reuse_alerts(&alerts),
            0,
            "the retransmission of an already-reported reused challenge was \
             reported again: {alerts:?}"
        );
    }

    /// An Authorization with `qop` but no `cnonce` is flagged.
    #[test]
    fn detect_missing_cnonce() {
        let mut detector = DigestLeakDetector::new();

        let raw = build_sip(
            "REGISTER sip:registrar@example.com SIP/2.0",
            &[
                "From: <sip:alice@example.com>;tag=t1",
                "To: <sip:alice@example.com>",
                "Call-ID: cnonce-test@example.com",
                "CSeq: 2 REGISTER",
                r#"Authorization: Digest username="alice", realm="example.com", nonce="xyz", qop=auth, response="aabbcc""#,
                "Content-Length: 0",
            ],
            b"",
        );
        let msg = parse_sip(
            &raw,
            ts(),
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("parse");

        let alerts = detector.check(&msg);
        assert!(
            alerts
                .iter()
                .any(|a| a.vulnerability == DigestVulnerability::MissingCnonce),
            "should detect missing cnonce when qop is present"
        );
    }

    /// Quoted parameter values are extracted without their surrounding quotes.
    #[test]
    fn extract_param_quoted() {
        let header = r#"Digest realm="example.com", nonce="abc123", algorithm=MD5"#;
        assert_eq!(extract_param(header, "realm"), Some("example.com"));
        assert_eq!(extract_param(header, "nonce"), Some("abc123"));
        assert_eq!(extract_param(header, "algorithm"), Some("MD5"));
    }

    /// Parameter name matching is case-insensitive.
    #[test]
    fn extract_param_case_insensitive() {
        let header = r#"Digest Realm="test.com", Algorithm=SHA-256"#;
        assert_eq!(extract_param(header, "realm"), Some("test.com"));
        assert_eq!(extract_param(header, "algorithm"), Some("SHA-256"));
    }

    /// A parameter absent from the header extracts as `None`.
    #[test]
    fn extract_param_missing() {
        let header = r#"Digest realm="example.com""#;
        assert_eq!(extract_param(header, "qop"), None);
    }

    /// The reuse decision as a function of its two inputs: no previous
    /// transaction is a first sighting, the same transaction again is a
    /// retransmission, and any other transaction is reuse -- whichever of
    /// the three fields differs.
    #[test]
    fn classify_nonce_sighting_covers_first_retransmission_and_reuse() {
        let seen = ChallengeTransaction {
            call_id: "a@host".to_owned(),
            cseq: Some(1),
            branch: "z9hG4bK-a".to_owned(),
        };
        assert_eq!(classify_nonce_sighting(None, &seen), NonceSighting::First);
        assert_eq!(
            classify_nonce_sighting(Some(&seen), &seen.clone()),
            NonceSighting::Retransmission
        );
        let other_call = ChallengeTransaction {
            call_id: "b@host".to_owned(),
            ..seen.clone()
        };
        let other_cseq = ChallengeTransaction {
            cseq: Some(2),
            ..seen.clone()
        };
        let other_branch = ChallengeTransaction {
            branch: "z9hG4bK-b".to_owned(),
            ..seen.clone()
        };
        for (name, current) in [
            ("Call-ID", &other_call),
            ("CSeq", &other_cseq),
            ("Via branch", &other_branch),
        ] {
            assert_eq!(
                classify_nonce_sighting(Some(&seen), current),
                NonceSighting::Reuse,
                "a transaction differing only in its {name} is a new transaction"
            );
        }
    }
}
