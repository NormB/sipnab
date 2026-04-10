//! Digest authentication vulnerability detection.
//!
//! Analyzes SIP 401/407 challenges and Authorization/Proxy-Authorization
//! responses to identify weaknesses in digest authentication configuration:
//! - **Weak algorithm** — MD5 instead of SHA-256 or stronger
//! - **Nonce reuse** — same nonce in multiple challenges (replay risk)
//! - **Missing qop** — challenge without `qop=auth` (downgrade risk)
//! - **Missing cnonce** — response without `cnonce` when `qop` is present

use std::collections::HashSet;

use crate::sip::SipMessage;

/// Classification of digest authentication vulnerabilities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DigestVulnerability {
    /// Server uses MD5 algorithm (should use SHA-256 or stronger).
    WeakAlgorithm,
    /// Same nonce value seen in multiple 401/407 challenges.
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
    /// Set of previously observed nonce values.
    seen_nonces: HashSet<String>,
}

impl DigestLeakDetector {
    /// Create a new digest leak detector.
    pub fn new() -> Self {
        Self {
            seen_nonces: HashSet::new(),
        }
    }

    /// Check a SIP message for digest authentication vulnerabilities.
    ///
    /// Returns a list of all detected vulnerabilities. Multiple issues
    /// can be present in a single message (e.g., weak algorithm AND
    /// missing qop in the same 401 challenge).
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

            // Check for nonce reuse (cap at 10,000 entries to bound memory)
            if let Some(nonce) = extract_param(header_value, "nonce") {
                if !self.seen_nonces.insert(nonce.to_string()) {
                    alerts.push(DigestAlert {
                        vulnerability: DigestVulnerability::NonceReuse,
                        detail: format!("nonce '{nonce}' reused across challenges (replay risk)"),
                    });
                } else if self.seen_nonces.len() > 10_000 {
                    // Drop an arbitrary entry to stay bounded
                    let first = self.seen_nonces.iter().next().cloned();
                    if let Some(key) = first {
                        self.seen_nonces.remove(&key);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sip::parser::parse_sip;
    use chrono::{DateTime, Utc};
    use std::net::{IpAddr, Ipv4Addr};

    fn localhost() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    fn ts() -> DateTime<Utc> {
        chrono::TimeZone::with_ymd_and_hms(&Utc, 2024, 6, 15, 12, 0, 0).unwrap()
    }

    fn build_sip(first_line: &str, headers: &[&str], body: &[u8]) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(first_line.as_bytes());
        msg.extend_from_slice(b"\r\n");
        for h in headers {
            msg.extend_from_slice(h.as_bytes());
            msg.extend_from_slice(b"\r\n");
        }
        msg.extend_from_slice(b"\r\n");
        msg.extend_from_slice(body);
        msg
    }

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
        parse_sip(&raw, ts(), localhost(), localhost(), 5060, 5060, "UDP").expect("parse 401")
    }

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
        parse_sip(&raw, ts(), localhost(), localhost(), 5060, 5060, "UDP").expect("parse 401")
    }

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
        parse_sip(&raw, ts(), localhost(), localhost(), 5060, 5060, "UDP").expect("parse 401")
    }

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

    #[test]
    fn detect_nonce_reuse() {
        let mut detector = DigestLeakDetector::new();

        // First 401 with nonce "abc123"
        let msg1 = make_401_md5();
        let _ = detector.check(&msg1);

        // Second 401 with same nonce
        let msg2 = make_401_md5();
        let alerts = detector.check(&msg2);

        assert!(
            alerts
                .iter()
                .any(|a| a.vulnerability == DigestVulnerability::NonceReuse),
            "should detect nonce reuse"
        );
    }

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
        let msg =
            parse_sip(&raw, ts(), localhost(), localhost(), 5060, 5060, "UDP").expect("parse");

        let alerts = detector.check(&msg);
        assert!(
            alerts
                .iter()
                .any(|a| a.vulnerability == DigestVulnerability::MissingCnonce),
            "should detect missing cnonce when qop is present"
        );
    }

    #[test]
    fn extract_param_quoted() {
        let header = r#"Digest realm="example.com", nonce="abc123", algorithm=MD5"#;
        assert_eq!(extract_param(header, "realm"), Some("example.com"));
        assert_eq!(extract_param(header, "nonce"), Some("abc123"));
        assert_eq!(extract_param(header, "algorithm"), Some("MD5"));
    }

    #[test]
    fn extract_param_case_insensitive() {
        let header = r#"Digest Realm="test.com", Algorithm=SHA-256"#;
        assert_eq!(extract_param(header, "realm"), Some("test.com"));
        assert_eq!(extract_param(header, "algorithm"), Some("SHA-256"));
    }

    #[test]
    fn extract_param_missing() {
        let header = r#"Digest realm="example.com""#;
        assert_eq!(extract_param(header, "qop"), None);
    }
}
