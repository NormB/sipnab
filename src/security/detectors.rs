// SPDX-License-Identifier: MIT OR Apache-2.0

//! One SIP message through every armed detector, decided rather than done.
//!
//! [`run_detectors`] runs the scanner, `--kill-target`, fraud, digest-leak and
//! registration-flood checks over one parsed message and returns the
//! [`Effect`]s that should follow: a finding to file, a jail line to write, a
//! kill response to hand to the isolated worker. It performs none of them. The
//! batch loop applies the list once it has it.
//!
//! Why a list and not a set of calls: the batch loop runs this under both
//! store write locks, inside a function that had grown past five hundred
//! lines, and the wiring of each detector -- which check runs, what it files,
//! which lines pass the origin gate -- was visible only to a test that drove
//! the whole loop. A function that takes its inputs as arguments and returns
//! what should happen is one whose every wire is a unit test.
//!
//! What stays out on purpose: the alert engine's lock, the output sink, the
//! kill worker's channel and the clock. Those are the side effects the
//! deferred-effects design keeps off the locked path, and this module keeps
//! them off it by never touching them.

use std::net::IpAddr;

use crate::capture::parse::InputOrigin;
use crate::output::render_absent;
use crate::sip::SipMessage;
use crate::sip::dialog::SipDialog;

use super::scanner_kill::{self, KillTarget};
use super::{DigestLeakDetector, FraudDetector, RegFloodDetector, ScannerDetector};

/// The armed detectors, borrowed for one message.
///
/// `None` is "not armed", and an unarmed detector runs no check at all: the
/// batch loop builds each one from its flag and leaves the rest absent.
pub struct Detectors<'a> {
    /// UA/behavioral scanner detector (`--kill-scanner`, `--kill-ua`).
    pub scanner: Option<&'a mut ScannerDetector>,
    /// Toll-fraud pattern detector (`--fraud-detect`).
    pub fraud: Option<&'a mut FraudDetector>,
    /// Digest-authentication weakness detector (`--digest-leak`).
    pub digest: Option<&'a mut DigestLeakDetector>,
    /// Registration-flood detector (`--reg-flood`).
    pub reg_flood: Option<&'a mut RegFloodDetector>,
    /// `-K`/`--kill-target` directives; empty when none were given.
    pub kill_targets: &'a [KillTarget],
}

/// What the run is allowed to do with a detection.
///
/// Every gate a site consults, gathered from the CLI and the packet so the
/// decision is a function of these five values and nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    /// `--fail2ban`: a jail line is wanted for each detection that has one.
    pub fail2ban: bool,
    /// `--hep-allow-kill`: sender-asserted addressing may be acted on.
    pub hep_allow_kill: bool,
    /// Where the packet's addressing came from.
    pub origin: InputOrigin,
    /// A kill worker is running, so a kill response has somewhere to go.
    pub kill_armed: bool,
    /// Status code a kill response carries (`--kill-response`).
    pub kill_response_code: u16,
}

/// Which detector a finding came from.
///
/// The batch loop files each under the rule name the alert engine, `--alert`
/// rules and the MCP `security_findings` tool know it by. That name is
/// assigned where the finding is filed, not here, so the vocabulary stays in
/// one place. A `--kill-target` match is a [`Self::Scanner`] finding: it is
/// the targeted form of the same defense.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectorKind {
    /// Scanner detection, by signature, behavior or `--kill-target`.
    Scanner,
    /// Toll-fraud pattern.
    Fraud,
    /// Digest-authentication weakness.
    Digest,
    /// Registration flood.
    RegFlood,
}

/// What a jail line names. The fail2ban formatter renders it; carrying the
/// values rather than the text keeps the clock out of this module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JailLine {
    /// A `scanner_detected` line: a scanner detection or a `--kill-target`
    /// match.
    Scanner {
        /// The address the jail will ban.
        src_ip: IpAddr,
        /// `User-Agent` of the triggering request, when it carried one.
        ua: Option<String>,
        /// Method of the triggering request, when the request line carried
        /// one.
        method: Option<String>,
    },
    /// A `reg_flood` line.
    RegFlood {
        /// The address the jail will ban.
        src_ip: IpAddr,
        /// The challenged failures that crossed the threshold.
        count: u32,
    },
}

/// One thing a detection asks the run to do.
///
/// Returned in the order the sites ran, so a caller that applies them in
/// sequence reproduces the order the batch loop performed them in when they
/// were inline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// File a finding with the alert engine.
    Alert {
        /// Which detector raised it.
        detector: DetectorKind,
        /// Source address the finding is about.
        src_ip: IpAddr,
        /// Human-readable detail, already formatted.
        detail: String,
    },
    /// Write a line to the `--fail2ban` jail log.
    JailLine(JailLine),
    /// Hand a SIP response to the isolated kill worker, aimed at the request's
    /// source and stamped with the address the request targeted.
    Kill {
        /// Where the response goes: the scanner.
        dst_addr: IpAddr,
        /// The scanner's source port.
        dst_port: u16,
        /// The address the scanner targeted, used as the forged source when
        /// raw-socket spoofing is active.
        src_addr: IpAddr,
        /// The port the scanner targeted.
        src_port: u16,
        /// The response, already built.
        response_bytes: Vec<u8>,
    },
}

/// Run every armed detector over `msg` and return what should follow.
///
/// The sites run in a fixed order -- scanner, `--kill-target`, fraud, digest
/// leak, registration flood -- and none of them short-circuits another: a
/// message can be a scanner's and a flood's at once, and both are reported.
///
/// The jail line and the kill response pass
/// [`scanner_kill::kill_response_eligible`] at every site that writes one, in
/// the position the inline code kept it: after the finding is filed, because
/// the finding reaches a human and is not origin-gated, and before anything
/// that names an address a firewall or a socket will act on.
///
/// # Arguments
///
/// * `detectors` — the armed detectors; each check mutates its detector's
///   state, which is why they are borrowed mutably.
/// * `msg` — the parsed SIP message.
/// * `dialog` — the dialog `msg` belongs to, when the caller tracks dialogs
///   and the fraud detector is armed to read it. The fraud detector runs
///   only when this is `Some`.
/// * `policy` — the gates: `--fail2ban`, `--hep-allow-kill`, the packet's
///   origin, whether a kill worker is running and the response code it sends.
///
/// # Returns
///
/// The effects, in the order the sites decided them; empty when nothing
/// fired.
pub fn run_detectors(
    detectors: &mut Detectors<'_>,
    msg: &SipMessage,
    dialog: Option<&SipDialog>,
    policy: Policy,
) -> Vec<Effect> {
    let mut effects = Vec::new();

    // Security detection: scanner
    if let Some(det) = detectors.scanner.as_deref_mut()
        && let Some(alert) = det.check(msg)
    {
        effects.push(Effect::Alert {
            detector: DetectorKind::Scanner,
            src_ip: alert.src_ip,
            detail: format!(
                "method={} ua={} detection={}",
                render_absent(alert.method.as_deref()),
                render_absent(alert.ua.as_deref()),
                alert.detection_method
            ),
        });
        // The jail line names the packet's source address, and under HEP that
        // address is the sender's claim. Same gate as the kill response below,
        // and for the same reason -- with the difference that a ban outlives
        // this process, so the bar is not lower.
        if policy.fail2ban
            && scanner_kill::kill_response_eligible(policy.origin, policy.hep_allow_kill)
        {
            effects.push(Effect::JailLine(JailLine::Scanner {
                src_ip: alert.src_ip,
                ua: alert.ua,
                method: alert.method,
            }));
        }

        // D16: the response goes to the isolated worker thread.
        // SN-01: HEP-origin packets are ineligible unless the operator opted
        // in (--hep-allow-kill), since their src/dst are sender-asserted and
        // unauthenticated absent --hep-auth.
        if policy.kill_armed
            && scanner_kill::kill_response_eligible(policy.origin, policy.hep_allow_kill)
            && let Some(response_bytes) =
                scanner_kill::build_scanner_response(msg, policy.kill_response_code)
        {
            effects.push(kill_order(msg, response_bytes));
        }
    }

    // Targeted scanner kill: kill any request whose source matches a
    // --kill-target, independent of UA/behavioral detection.
    if !detectors.kill_targets.is_empty()
        && msg.is_request
        && detectors
            .kill_targets
            .iter()
            .any(|t| t.matches(msg.src_addr, msg.src_port))
    {
        let method = msg.method.as_ref().map(|m| m.as_str());
        let ua = msg.user_agent();
        effects.push(Effect::Alert {
            detector: DetectorKind::Scanner,
            src_ip: msg.src_addr,
            detail: format!(
                "method={} ua={} detection=kill-target",
                render_absent(method),
                render_absent(ua)
            ),
        });
        // Same origin gate as the scanner detection above.
        if policy.fail2ban
            && scanner_kill::kill_response_eligible(policy.origin, policy.hep_allow_kill)
        {
            effects.push(Effect::JailLine(JailLine::Scanner {
                src_ip: msg.src_addr,
                ua: ua.map(str::to_string),
                method: method.map(str::to_string),
            }));
        }
        // SN-01: same HEP-origin ineligibility as behavioral kill above.
        if policy.kill_armed
            && scanner_kill::kill_response_eligible(policy.origin, policy.hep_allow_kill)
            && let Some(response_bytes) =
                scanner_kill::build_scanner_response(msg, policy.kill_response_code)
        {
            effects.push(kill_order(msg, response_bytes));
        }
    }

    // Security detection: fraud
    if let Some(det) = detectors.fraud.as_deref_mut()
        && let Some(dialog) = dialog
        && let Some(alert) = det.check(msg, dialog)
    {
        effects.push(Effect::Alert {
            detector: DetectorKind::Fraud,
            src_ip: alert.src_ip,
            detail: format!("{:?}: {}", alert.alert_type, alert.detail),
        });
    }

    // Security detection: digest leak
    if let Some(det) = detectors.digest.as_deref_mut() {
        let leaks = det.check(msg);
        for alert in &leaks {
            effects.push(Effect::Alert {
                detector: DetectorKind::Digest,
                src_ip: msg.src_addr,
                detail: format!("{:?}: {}", alert.vulnerability, alert.detail),
            });
        }
    }

    // Security detection: registration flood
    if let Some(det) = detectors.reg_flood.as_deref_mut()
        && let Some(alert) = det.check(msg)
    {
        effects.push(Effect::Alert {
            detector: DetectorKind::RegFlood,
            src_ip: alert.src_ip,
            // The failures are what crossed the threshold; the REGISTER count
            // is the shape of the traffic around them.
            detail: format!(
                "auth_failures={} registers={} threshold={}",
                alert.auth_fail_count, alert.register_count, alert.threshold
            ),
        });
        // Same origin gate as the scanner detection above.
        if policy.fail2ban
            && scanner_kill::kill_response_eligible(policy.origin, policy.hep_allow_kill)
        {
            effects.push(Effect::JailLine(JailLine::RegFlood {
                src_ip: alert.src_ip,
                count: alert.auth_fail_count,
            }));
        }
    }

    effects
}

/// The kill response for `msg`: aimed back at its source, stamped with the
/// address and port it targeted.
fn kill_order(msg: &SipMessage, response_bytes: Vec<u8>) -> Effect {
    Effect::Kill {
        dst_addr: msg.src_addr,
        dst_port: msg.src_port,
        src_addr: msg.dst_addr,
        src_port: msg.dst_port,
        response_bytes,
    }
}

// ── Tests ────────────────────────────────────────────────────────────

/// Each detector's wiring as a unit test: the effect it produces when it
/// fires, nothing when it does not, and the origin gate on the two effects a
/// firewall or a socket acts on.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::TransportProto;
    use crate::sip::dialog_store::DialogStore;
    use crate::sip::parser::parse_sip;
    use crate::test_utils::build_sip_message as build_sip;
    use chrono::{DateTime, TimeDelta, Utc};
    use std::net::Ipv4Addr;

    /// The registrar / callee side of every exchange.
    fn localhost() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    /// The source every detection is about.
    fn attacker() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 50))
    }

    /// A fixed capture time inside default business hours, so the fraud
    /// detector's off-hours rule cannot fire on its own.
    fn ts() -> DateTime<Utc> {
        chrono::TimeZone::with_ymd_and_hms(&Utc, 2024, 6, 15, 14, 0, 0).unwrap()
    }

    /// Parse `raw` as a UDP message from `src`:`src_port` to `dst`:5060 at
    /// capture time `at`.
    fn parse_at(
        raw: &[u8],
        src: IpAddr,
        src_port: u16,
        dst: IpAddr,
        at: DateTime<Utc>,
    ) -> SipMessage {
        parse_sip(raw, at, src, dst, src_port, 5060, TransportProto::Udp).expect("parse")
    }

    /// An OPTIONS from the attacker announcing a scanner's `User-Agent`,
    /// which the signature rule matches on sight.
    fn scanner_options() -> SipMessage {
        let raw = build_sip(
            "OPTIONS sip:target@example.com SIP/2.0",
            &[
                "Via: SIP/2.0/UDP 10.0.0.50:5060;branch=z9hG4bK-scan",
                "From: <sip:scanner@example.com>;tag=s1",
                "To: <sip:target@example.com>",
                "Call-ID: scan@10.0.0.50",
                "CSeq: 1 OPTIONS",
                "User-Agent: friendly-scanner",
                "Content-Length: 0",
            ],
            b"",
        );
        parse_at(&raw, attacker(), 5060, localhost(), ts())
    }

    /// An ordinary INVITE from `src`:`src_port` with a PBX's `User-Agent`.
    fn plain_invite(src: IpAddr, src_port: u16, call_id: &str) -> SipMessage {
        let raw = build_sip(
            "INVITE sip:bob@example.com SIP/2.0",
            &[
                "Via: SIP/2.0/UDP 10.0.0.7:5060;branch=z9hG4bK-plain",
                "From: <sip:alice@example.com>;tag=a1",
                "To: <sip:bob@example.com>",
                &format!("Call-ID: {call_id}"),
                "CSeq: 1 INVITE",
                "User-Agent: Asterisk PBX",
                "Content-Length: 0",
            ],
            b"",
        );
        parse_at(&raw, src, src_port, localhost(), ts())
    }

    /// A `200 OK` from the attacker's address: a response, not a request.
    fn response_from_attacker() -> SipMessage {
        let raw = build_sip(
            "SIP/2.0 200 OK",
            &[
                "Via: SIP/2.0/UDP 10.0.0.7:5060;branch=z9hG4bK-resp",
                "From: <sip:alice@example.com>;tag=a1",
                "To: <sip:bob@example.com>;tag=b1",
                "Call-ID: resp@10.0.0.50",
                "CSeq: 1 INVITE",
                "Content-Length: 0",
            ],
            b"",
        );
        parse_at(&raw, attacker(), 5075, localhost(), ts())
    }

    /// A 401 whose challenge names MD5, the weak algorithm the digest
    /// detector reports.
    fn md5_challenge() -> SipMessage {
        let raw = build_sip(
            "SIP/2.0 401 Unauthorized",
            &[
                "Via: SIP/2.0/UDP 10.0.0.50:5060;branch=z9hG4bK-md5",
                "From: <sip:alice@example.com>;tag=t1",
                "To: <sip:alice@example.com>;tag=t2",
                "Call-ID: digest@10.0.0.50",
                "CSeq: 1 REGISTER",
                r#"WWW-Authenticate: Digest realm="example.com", nonce="abc123", algorithm=MD5"#,
                "Content-Length: 0",
            ],
            b"",
        );
        parse_at(&raw, localhost(), 5060, attacker(), ts())
    }

    /// A credentialed REGISTER from the attacker on transaction `branch`.
    fn register(branch: &str, at: DateTime<Utc>) -> SipMessage {
        let raw = build_sip(
            "REGISTER sip:registrar@example.com SIP/2.0",
            &[
                &format!("Via: SIP/2.0/UDP 10.0.0.50:5060;branch={branch}"),
                "From: <sip:user@example.com>;tag=r1",
                "To: <sip:user@example.com>",
                &format!("Call-ID: {branch}@10.0.0.50"),
                "CSeq: 1 REGISTER",
                "Authorization: Digest username=\"user\", realm=\"example.com\", \
                 nonce=\"abc\", uri=\"sip:example.com\", response=\"0000\"",
                "Content-Length: 0",
            ],
            b"",
        );
        parse_at(&raw, attacker(), 5060, localhost(), at)
    }

    /// The registrar's 401 refusing the REGISTER on `branch`.
    fn challenge(branch: &str, at: DateTime<Utc>) -> SipMessage {
        let raw = build_sip(
            "SIP/2.0 401 Unauthorized",
            &[
                &format!("Via: SIP/2.0/UDP 10.0.0.50:5060;branch={branch}"),
                "From: <sip:user@example.com>;tag=r1",
                "To: <sip:user@example.com>;tag=r2",
                &format!("Call-ID: {branch}@10.0.0.50"),
                "CSeq: 1 REGISTER",
                "Content-Length: 0",
            ],
            b"",
        );
        parse_at(&raw, localhost(), 5060, attacker(), at)
    }

    /// Three credentialed REGISTERs, each refused: one more challenged
    /// failure than a threshold of 2 allows.
    fn refused_registrations() -> Vec<SipMessage> {
        (0..3)
            .flat_map(|i| {
                let branch = format!("z9hG4bK-flood-{i}");
                let at = ts() + TimeDelta::milliseconds(i * 100);
                [register(&branch, at), challenge(&branch, at)]
            })
            .collect()
    }

    /// An INVITE from the attacker to `did`, opening `call_id`.
    fn invite_to(did: &str, call_id: &str, at: DateTime<Utc>) -> SipMessage {
        let raw = build_sip(
            &format!("INVITE sip:{did}@example.com SIP/2.0"),
            &[
                "Via: SIP/2.0/UDP 10.0.0.50:5060;branch=z9hG4bK-fraud",
                "From: <sip:caller@example.com>;tag=f1",
                &format!("To: <sip:{did}@example.com>"),
                &format!("Call-ID: {call_id}"),
                "CSeq: 1 INVITE",
                "Content-Length: 0",
            ],
            b"",
        );
        parse_at(&raw, attacker(), 5060, localhost(), at)
    }

    /// The callee's `404` refusing `call_id`.
    fn refused(did: &str, call_id: &str, at: DateTime<Utc>) -> SipMessage {
        let raw = build_sip(
            "SIP/2.0 404 Not Found",
            &[
                "Via: SIP/2.0/UDP 10.0.0.50:5060;branch=z9hG4bK-fraud",
                "From: <sip:caller@example.com>;tag=f1",
                &format!("To: <sip:{did}@example.com>;tag=t1"),
                &format!("Call-ID: {call_id}"),
                "CSeq: 1 INVITE",
                "Content-Length: 0",
            ],
            b"",
        );
        parse_at(&raw, localhost(), 5060, attacker(), at)
    }

    /// The policy of a wire-origin `--fail2ban` run with a kill worker.
    fn wire_policy() -> Policy {
        Policy {
            fail2ban: true,
            hep_allow_kill: false,
            origin: InputOrigin::Wire,
            kill_armed: true,
            kill_response_code: 200,
        }
    }

    /// Nothing armed; each test arms what it needs.
    fn unarmed() -> Detectors<'static> {
        Detectors {
            scanner: None,
            fraud: None,
            digest: None,
            reg_flood: None,
            kill_targets: &[],
        }
    }

    /// One tag per effect, in order, so a test can assert the whole list at
    /// once without spelling out every field.
    fn tags(effects: &[Effect]) -> Vec<String> {
        effects
            .iter()
            .map(|e| match e {
                Effect::Alert { detector, .. } => format!("alert:{detector:?}"),
                Effect::JailLine(JailLine::Scanner { .. }) => "jail:scanner".to_string(),
                Effect::JailLine(JailLine::RegFlood { .. }) => "jail:reg_flood".to_string(),
                Effect::Kill { .. } => "kill".to_string(),
            })
            .collect()
    }

    /// The detail of the first finding in `effects`.
    fn first_detail(effects: &[Effect]) -> &str {
        effects
            .iter()
            .find_map(|e| match e {
                Effect::Alert { detail, .. } => Some(detail.as_str()),
                _ => None,
            })
            .expect("a finding")
    }

    /// The effects of the scanner OPTIONS under `policy`, with the scanner
    /// detector armed.
    fn scanner_effects(policy: Policy) -> Vec<Effect> {
        let mut scanner = ScannerDetector::new(&[]);
        let mut detectors = Detectors {
            scanner: Some(&mut scanner),
            ..unarmed()
        };
        run_detectors(&mut detectors, &scanner_options(), None, policy)
    }

    /// The effects of an INVITE from the attacker's port 5075 under
    /// `policy`, with a `--kill-target` covering that port.
    fn kill_target_effects(policy: Policy) -> Vec<Effect> {
        let targets = [KillTarget::parse("10.0.0.50:5060-5090").expect("target")];
        let mut detectors = Detectors {
            kill_targets: &targets,
            ..unarmed()
        };
        run_detectors(
            &mut detectors,
            &plain_invite(attacker(), 5075, "kt@10.0.0.50"),
            None,
            policy,
        )
    }

    /// The effects of the last refusal of a registration flood under
    /// `policy`, with the flood detector armed at a threshold of 2.
    fn reg_flood_effects(policy: Policy) -> Vec<Effect> {
        let mut flood = RegFloodDetector::new(2);
        let mut detectors = Detectors {
            reg_flood: Some(&mut flood),
            ..unarmed()
        };
        let mut last = Vec::new();
        for msg in refused_registrations() {
            last = run_detectors(&mut detectors, &msg, None, policy);
        }
        last
    }

    /// A scanner detection files a finding, writes the jail line and asks
    /// for a kill, in that order, each naming the scanner.
    #[test]
    fn a_scanner_detection_files_a_finding_writes_the_jail_line_and_kills() {
        let effects = scanner_effects(wire_policy());
        assert_eq!(
            tags(&effects),
            ["alert:Scanner", "jail:scanner", "kill"],
            "{effects:?}"
        );
        let detail = first_detail(&effects);
        assert!(
            detail.contains("ua=\"friendly-scanner\"") && detail.contains("detection=ua_pattern"),
            "the finding must say what matched and how: {detail}"
        );
        assert_eq!(
            effects[1],
            Effect::JailLine(JailLine::Scanner {
                src_ip: attacker(),
                ua: Some("friendly-scanner".to_string()),
                method: Some("OPTIONS".to_string()),
            })
        );
        match &effects[2] {
            Effect::Kill {
                dst_addr,
                dst_port,
                src_addr,
                src_port,
                response_bytes,
            } => {
                assert_eq!(
                    (*dst_addr, *dst_port),
                    (attacker(), 5060),
                    "aimed at the scanner"
                );
                assert_eq!(
                    (*src_addr, *src_port),
                    (localhost(), 5060),
                    "from the target"
                );
                assert!(
                    response_bytes.starts_with(b"SIP/2.0 200 OK"),
                    "carries --kill-response: {:?}",
                    String::from_utf8_lossy(response_bytes)
                );
            }
            other => panic!("expected a kill, got {other:?}"),
        }
    }

    /// A `--kill-target` match is the targeted form of the same defense: the
    /// same three effects, filed as a scanner finding, with no scanner
    /// detector present.
    #[test]
    fn a_kill_target_match_files_a_finding_writes_the_jail_line_and_kills() {
        let effects = kill_target_effects(wire_policy());
        assert_eq!(
            tags(&effects),
            ["alert:Scanner", "jail:scanner", "kill"],
            "{effects:?}"
        );
        assert!(
            first_detail(&effects).contains("detection=kill-target"),
            "{effects:?}"
        );
        assert!(
            matches!(&effects[2], Effect::Kill { dst_port: 5075, .. }),
            "the kill goes back to the port that matched: {effects:?}"
        );
    }

    /// A source port outside the target's range is not a match.
    #[test]
    fn a_kill_target_ignores_a_port_outside_its_range() {
        let targets = [KillTarget::parse("10.0.0.50:5060-5090").expect("target")];
        let mut detectors = Detectors {
            kill_targets: &targets,
            ..unarmed()
        };
        let effects = run_detectors(
            &mut detectors,
            &plain_invite(attacker(), 6000, "kt-miss@10.0.0.50"),
            None,
            wire_policy(),
        );
        assert!(effects.is_empty(), "{effects:?}");
    }

    /// A response from a targeted address is never killed: the kill answers
    /// a request, and a response has nothing to answer.
    #[test]
    fn a_response_never_matches_a_kill_target() {
        let targets = [KillTarget::parse("10.0.0.50").expect("target")];
        let mut detectors = Detectors {
            kill_targets: &targets,
            ..unarmed()
        };
        let effects = run_detectors(
            &mut detectors,
            &response_from_attacker(),
            None,
            wire_policy(),
        );
        assert!(effects.is_empty(), "{effects:?}");
    }

    /// A fraud pattern files a finding and nothing else: fraud has no jail
    /// line and no kill.
    ///
    /// Driven through a dialog store the way the batch loop drives it,
    /// because the detector reads the dialog the caller hands it.
    #[test]
    fn a_fraud_pattern_files_a_finding_and_nothing_else() {
        let mut fraud = FraudDetector::new(None);
        let mut store = DialogStore::new(100, false);
        let mut detectors = Detectors {
            fraud: Some(&mut fraud),
            ..unarmed()
        };
        let mut all = Vec::new();
        for (i, did) in [
            "+15551000",
            "+15551001",
            "+15551002",
            "+15551003",
            "+15551004",
        ]
        .iter()
        .enumerate()
        {
            let call_id = format!("refused-{i}@10.0.0.50");
            let start = ts() + TimeDelta::seconds(i as i64 * 2);
            for msg in [
                invite_to(did, &call_id, start),
                refused(did, &call_id, start + TimeDelta::milliseconds(80)),
            ] {
                store.process_message(msg.clone());
                let dialog = store.get(&call_id);
                all.extend(run_detectors(&mut detectors, &msg, dialog, wire_policy()));
            }
        }
        assert!(
            all.iter().any(|e| matches!(
                e,
                Effect::Alert { detector: DetectorKind::Fraud, detail, .. }
                    if detail.contains("sequential dialing")
            )),
            "five refused calls to consecutive numbers are a scan: {all:?}"
        );
        assert!(
            all.iter().all(|e| matches!(e, Effect::Alert { .. })),
            "fraud never writes a jail line or kills: {all:?}"
        );
    }

    /// A digest weakness files one finding per vulnerability the detector
    /// reports, under the packet's source, and nothing else.
    #[test]
    fn a_digest_weakness_files_one_finding_per_vulnerability() {
        let mut digest = DigestLeakDetector::new();
        let expected = DigestLeakDetector::new().check(&md5_challenge()).len();
        assert!(expected >= 1, "the fixture must trip the detector");
        let mut detectors = Detectors {
            digest: Some(&mut digest),
            ..unarmed()
        };
        let effects = run_detectors(&mut detectors, &md5_challenge(), None, wire_policy());
        assert_eq!(effects.len(), expected, "{effects:?}");
        assert!(
            effects.iter().all(|e| matches!(
                e,
                Effect::Alert { detector: DetectorKind::Digest, src_ip, .. } if *src_ip == localhost()
            )),
            "{effects:?}"
        );
        assert!(
            first_detail(&effects).contains("WeakAlgorithm"),
            "{effects:?}"
        );
    }

    /// A registration flood files a finding and writes the jail line with
    /// the failure count that crossed the threshold; it never kills.
    #[test]
    fn a_registration_flood_files_a_finding_and_writes_the_jail_line() {
        let effects = reg_flood_effects(wire_policy());
        assert_eq!(
            tags(&effects),
            ["alert:RegFlood", "jail:reg_flood"],
            "{effects:?}"
        );
        assert_eq!(
            first_detail(&effects),
            "auth_failures=3 registers=3 threshold=2"
        );
        assert_eq!(
            effects[1],
            Effect::JailLine(JailLine::RegFlood {
                src_ip: attacker(),
                count: 3,
            })
        );
    }

    /// An ordinary message through every armed detector produces nothing.
    #[test]
    fn an_ordinary_message_through_every_armed_detector_produces_nothing() {
        let mut scanner = ScannerDetector::new(&[]);
        let mut fraud = FraudDetector::new(None);
        let mut digest = DigestLeakDetector::new();
        let mut flood = RegFloodDetector::new(2);
        let targets = [KillTarget::parse("10.0.0.50").expect("target")];
        let mut detectors = Detectors {
            scanner: Some(&mut scanner),
            fraud: Some(&mut fraud),
            digest: Some(&mut digest),
            reg_flood: Some(&mut flood),
            kill_targets: &targets,
        };
        let pbx = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7));
        let msg = plain_invite(pbx, 5060, "plain@10.0.0.7");
        let dialog = SipDialog::new(&msg).expect("dialog");
        let effects = run_detectors(&mut detectors, &msg, Some(&dialog), wire_policy());
        assert!(effects.is_empty(), "{effects:?}");
    }

    /// With nothing armed, a scanner's request is not a detection: no
    /// detector, no finding, whatever the policy allows.
    #[test]
    fn nothing_armed_produces_nothing() {
        let effects = run_detectors(&mut unarmed(), &scanner_options(), None, wire_policy());
        assert!(effects.is_empty(), "{effects:?}");
    }

    /// HEP-carried addressing is the sender's claim. Without the opt-in the
    /// finding is still filed -- a human is told -- but nothing that names
    /// the address to a firewall or a socket is produced, at all three
    /// sites that write one. With `--hep-allow-kill` they are.
    #[test]
    fn hep_origin_without_the_opt_in_keeps_the_finding_and_drops_the_jail_line_and_the_kill() {
        let hep = Policy {
            origin: InputOrigin::Hep,
            ..wire_policy()
        };
        assert_eq!(tags(&scanner_effects(hep)), ["alert:Scanner"]);
        assert_eq!(tags(&kill_target_effects(hep)), ["alert:Scanner"]);
        assert_eq!(tags(&reg_flood_effects(hep)), ["alert:RegFlood"]);

        let admitted = Policy {
            hep_allow_kill: true,
            ..hep
        };
        assert_eq!(
            tags(&scanner_effects(admitted)),
            ["alert:Scanner", "jail:scanner", "kill"],
            "control: the opt-in admits the HEP-carried detection"
        );
        assert_eq!(
            tags(&kill_target_effects(admitted)),
            ["alert:Scanner", "jail:scanner", "kill"]
        );
        assert_eq!(
            tags(&reg_flood_effects(admitted)),
            ["alert:RegFlood", "jail:reg_flood"]
        );
    }

    /// Bytes lifted out of a process carry no socket, so a uprobe read is
    /// never written to the jail log or answered, opt-in or not.
    #[test]
    fn a_uprobe_origin_never_writes_or_kills_even_with_the_opt_in() {
        let uprobe = Policy {
            origin: InputOrigin::Uprobe,
            hep_allow_kill: true,
            ..wire_policy()
        };
        assert_eq!(tags(&scanner_effects(uprobe)), ["alert:Scanner"]);
        assert_eq!(tags(&kill_target_effects(uprobe)), ["alert:Scanner"]);
        assert_eq!(tags(&reg_flood_effects(uprobe)), ["alert:RegFlood"]);
    }

    /// Without `--fail2ban` no jail line is produced; the finding and the
    /// kill are unaffected.
    #[test]
    fn without_fail2ban_no_jail_line_is_written() {
        let quiet = Policy {
            fail2ban: false,
            ..wire_policy()
        };
        assert_eq!(tags(&scanner_effects(quiet)), ["alert:Scanner", "kill"]);
        assert_eq!(tags(&kill_target_effects(quiet)), ["alert:Scanner", "kill"]);
        assert_eq!(tags(&reg_flood_effects(quiet)), ["alert:RegFlood"]);
    }

    /// Without a kill worker no kill is asked for: an offline run detects
    /// and reports and never builds a response with nowhere to go.
    #[test]
    fn without_a_kill_worker_no_kill_is_asked_for() {
        let offline = Policy {
            kill_armed: false,
            ..wire_policy()
        };
        assert_eq!(
            tags(&scanner_effects(offline)),
            ["alert:Scanner", "jail:scanner"]
        );
        assert_eq!(
            tags(&kill_target_effects(offline)),
            ["alert:Scanner", "jail:scanner"]
        );
    }
}
