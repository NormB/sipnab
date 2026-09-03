// SPDX-License-Identifier: MIT OR Apache-2.0

//! Registration flood detection.
//!
//! Counts, per source, the REGISTERs that carried credentials and were
//! refused by the registrar, and alerts when those FAILURES cross the
//! configured threshold inside a one-second window.
//!
//! The evidence is an outcome, never a volume. This detector shipped for a
//! long time firing on the REGISTER count alone, and the peer that produces
//! the most REGISTERs on any network is the operator's own SBC re-registering
//! every phone it fronts after a registrar restart -- every one of them
//! answered `200 OK`, every one of them counted, and `--fail2ban` handed the
//! trunk to the firewall. A count of requests says nothing about whether the
//! registrar accepted them, so it decides nothing here; only a challenge
//! answering a REGISTER that already carried credentials is a failure, and any
//! successful registration clears the count. `docs/design/threat-mitigation-hooks.md`
//! §5 is the rule this follows.

use std::net::IpAddr;

use chrono::{DateTime, TimeDelta, Utc};

use crate::lru::LruMap;
use crate::sip::{SipMessage, SipMethod};

/// Default challenged-failures-per-second threshold.
const DEFAULT_THRESHOLD: u32 = 50;

/// Cap on credentialed REGISTER transactions awaiting an answer, per source.
///
/// A source that sends credentials and is never answered accumulates open
/// transactions and no evidence; past this many, the oldest is forgotten. The
/// same figure as the scanner detector's transaction cap, and for the same
/// reason: reaching it degrades toward reporting nothing, which is the right
/// direction for a detector that feeds a firewall.
const MAX_PENDING_PER_SOURCE: usize = 1024;

/// Per-source registration flood tracking state.
struct RegFloodState {
    /// Number of REGISTER requests in the current window.
    ///
    /// Carried into the alert so the operator can see the shape of the
    /// traffic. It never decides anything: see the module doc.
    register_count: u32,
    /// Challenged failures in the current window -- a REGISTER that carried
    /// `Authorization` or `Proxy-Authorization` and was answered 401 or 407 on
    /// the same transaction. This is the count the threshold applies to.
    auth_fail_count: u32,
    /// Start of the current one-second measurement window, in capture time.
    window_start: DateTime<Utc>,
    /// Capture time of the newest message from or to this source, which is
    /// what [`RegFloodDetector::sweep`] ages against.
    last_seen: DateTime<Utc>,
    /// Credentialed REGISTER transactions this source has open, by top `Via`
    /// branch, oldest first. A challenge is a failure only when it names one
    /// of these. Bounded by [`MAX_PENDING_PER_SOURCE`]; past it the oldest is
    /// forgotten, in constant time.
    pending: LruMap<String, ()>,
}

impl RegFloodState {
    /// A source first seen at `now`, with nothing counted yet.
    fn new(now: DateTime<Utc>) -> Self {
        Self {
            register_count: 0,
            auth_fail_count: 0,
            window_start: now,
            last_seen: now,
            pending: LruMap::new(MAX_PENDING_PER_SOURCE),
        }
    }

    /// Start a fresh one-second window at `now` if the current one has
    /// elapsed. Both counts restart; the open transactions do not, because a
    /// REGISTER sent late in one window is answered in the next.
    fn roll_window(&mut self, now: DateTime<Utc>) {
        if window_elapsed(self.window_start, now) {
            self.register_count = 0;
            self.auth_fail_count = 0;
            self.window_start = now;
        }
    }
}

/// Alert produced when a registration flood is detected.
#[derive(Debug, Clone)]
pub struct RegFloodAlert {
    /// Source IP address of the flood.
    pub src_ip: IpAddr,
    /// Number of REGISTER requests in the current window. Context for the
    /// operator; the decision was made on `auth_fail_count`.
    pub register_count: u32,
    /// Challenged failures in the current window: the figure that crossed
    /// `threshold`.
    pub auth_fail_count: u32,
    /// Configured threshold that was exceeded.
    pub threshold: u32,
}

/// Maximum entries in the sources map. Past it, admitting a new source
/// evicts the least recently touched one, in constant time: see [`LruMap`].
const MAX_SOURCE_ENTRIES: usize = 10_000;

/// Whether the one-second window that opened at `window_start` has elapsed
/// at `now`, both in capture time.
///
/// Capture time, not the wall clock. A file is read as fast as the disk
/// delivers it, so a window paced by `Instant::now()` never expires offline:
/// a phone re-registering once a minute for an hour became sixty REGISTERs in
/// one wall-clock second, and `--fail2ban` banned it from a replay of
/// yesterday's traffic. The scanner detector moved for the same reason.
fn window_elapsed(window_start: DateTime<Utc>, now: DateTime<Utc>) -> bool {
    now.signed_duration_since(window_start) >= TimeDelta::seconds(1)
}

/// Whether a REGISTER carried the credentials a challenge asks for.
///
/// A REGISTER without them is the first half of every registration on the
/// network, and the 401 it draws is the registrar asking, not refusing.
fn carries_credentials(msg: &SipMessage) -> bool {
    msg.header("Authorization").is_some() || msg.header("Proxy-Authorization").is_some()
}

/// Whether a final response is a credential challenge.
fn is_challenge(status: u16) -> bool {
    matches!(status, 401 | 407)
}

/// Whether a response completes a registration: a 2xx whose `CSeq` names
/// REGISTER. Read the `CSeq` rather than trust the code alone, because a 2xx
/// to an OPTIONS says nothing about whether the sender may register.
fn completes_registration(msg: &SipMessage) -> bool {
    msg.status_code.is_some_and(|c| (200..300).contains(&c))
        && msg
            .cseq()
            .is_some_and(|(_, method)| method.eq_ignore_ascii_case("REGISTER"))
}

/// The decision, and the only input it takes: challenged failures against the
/// threshold. The REGISTER count is deliberately not a parameter, so it cannot
/// re-enter the verdict without changing this signature.
fn is_flood(auth_fail_count: u32, threshold: u32) -> bool {
    auth_fail_count > threshold
}

/// Detects registration floods by counting, per source, the credentialed
/// REGISTERs the registrar refused.
pub struct RegFloodDetector {
    /// Per-source tracking state, least recently touched first.
    sources: LruMap<IpAddr, RegFloodState>,
    /// Challenged-failures-per-second alert threshold.
    threshold: u32,
    /// Capture time of the newest message seen, which is the clock `sweep`
    /// reads. `None` before the first message.
    latest_packet: Option<DateTime<Utc>>,
}

impl RegFloodDetector {
    /// Create a new registration flood detector with the given threshold.
    ///
    /// # Arguments
    ///
    /// * `threshold` — Challenged failures per second from one source before
    ///   alerting. Use `0` for the default threshold of 50/sec.
    pub fn new(threshold: u32) -> Self {
        Self {
            sources: LruMap::new(MAX_SOURCE_ENTRIES),
            threshold: if threshold == 0 {
                DEFAULT_THRESHOLD
            } else {
                threshold
            },
            latest_packet: None,
        }
    }

    /// Check a SIP message for registration flood conditions.
    ///
    /// A REGISTER is recorded against its sender and never itself returns an
    /// alert. A 401 or 407 answering a credentialed REGISTER from a source,
    /// on the same transaction, is one failure for that source, and the
    /// failure that crosses the threshold returns the alert. A 2xx to a
    /// REGISTER clears the source's failures.
    #[must_use]
    pub fn check(&mut self, msg: &SipMessage) -> Option<RegFloodAlert> {
        // Capture time. Advance the clock before any early return, so `sweep`
        // still ages state out over a stretch of capture that held only
        // messages this detector ignores.
        let now = msg.timestamp;
        if self.latest_packet.is_none_or(|latest| now > latest) {
            self.latest_packet = Some(now);
        }

        if msg.is_request {
            if msg.method.as_ref() == Some(&SipMethod::Register) {
                self.observe_register(msg, now);
            }
            return None;
        }
        self.observe_response(msg, now)
    }

    /// Record a REGISTER against its sender.
    fn observe_register(&mut self, msg: &SipMessage, now: DateTime<Utc>) {
        // The map is capped (H4). Admitting a new source past
        // MAX_SOURCE_ENTRIES evicts the least recently touched one, in
        // constant time, so a spoofed-source flood that fills the map does
        // not make every packet after it pay for a scan of the whole map on
        // the capture thread.
        let state = self
            .sources
            .get_or_insert_with(msg.src_addr, || RegFloodState::new(now));
        state.last_seen = now;
        state.roll_window(now);
        state.register_count += 1;

        if carries_credentials(msg)
            && let Some(branch) = msg.top_via_branch()
        {
            // Past MAX_PENDING_PER_SOURCE the oldest open transaction is
            // forgotten, in constant time as well.
            state.pending.insert(branch.to_owned(), ());
        }
    }

    /// Settle a response against the source it answers.
    ///
    /// The peer is the response's DESTINATION: a response travels back the
    /// way the request came, so `dst_addr` is the source whose REGISTER this
    /// settles.
    ///
    /// Only an existing entry is updated -- a response never creates one. A
    /// response whose REGISTER was never seen anchors nothing, and the cap
    /// on tracked sources is applied where entries are created, so a flood
    /// of 401s toward a /16 of destinations must not be a second way in.
    fn observe_response(&mut self, msg: &SipMessage, now: DateTime<Utc>) -> Option<RegFloodAlert> {
        let status = msg.status_code?;
        let state = self.sources.get_mut(&msg.dst_addr)?;
        state.last_seen = now;

        if completes_registration(msg) {
            state.auth_fail_count = 0;
            if let Some(branch) = msg.top_via_branch() {
                state.pending.remove(branch);
            }
            return None;
        }
        if !is_challenge(status) {
            return None;
        }
        // A challenge is evidence only against the credentialed REGISTER it
        // answers. One that names no open transaction from this source is
        // the ordinary first half of a registration, or a retransmission,
        // or an answer to somebody else's request behind the same address.
        let branch = msg.top_via_branch()?;
        state.pending.remove(branch)?;

        state.roll_window(now);
        state.auth_fail_count += 1;
        is_flood(state.auth_fail_count, self.threshold).then_some(RegFloodAlert {
            src_ip: msg.dst_addr,
            register_count: state.register_count,
            auth_fail_count: state.auth_fail_count,
            threshold: self.threshold,
        })
    }

    /// Remove tracking entries whose last activity is older than `max_age`
    /// **in capture time**, measured from the newest message seen.
    ///
    /// A no-op before the first message: with no capture time there is
    /// nothing to measure against, and nothing tracked to remove.
    pub fn sweep(&mut self, max_age: std::time::Duration) {
        let Some(now) = self.latest_packet else {
            return;
        };
        let Ok(max_age) = TimeDelta::from_std(max_age) else {
            return;
        };
        self.sources
            .retain(|_, state| now.signed_duration_since(state.last_seen) < max_age);
    }
}

// ── Tests ────────────────────────────────────────────────────────────

/// Unit tests for per-source registration flood detection.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::TransportProto;
    use crate::sip::parser::parse_sip;
    use chrono::{DateTime, Utc};
    use std::net::{IpAddr, Ipv4Addr};

    /// A fixed capture timestamp for the parsed messages.
    fn ts() -> DateTime<Utc> {
        chrono::TimeZone::with_ymd_and_hms(&Utc, 2024, 6, 15, 12, 0, 0).unwrap()
    }

    /// The loopback address used as registrar/destination.
    fn localhost() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    /// The source IP used to simulate a flooding attacker.
    fn attacker_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99))
    }

    /// A second, independent source IP.
    fn other_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 100))
    }

    use crate::test_utils::build_sip_message as build_sip;

    /// A registrar that is down answers nothing, and nothing is not evidence:
    /// sixty credentialed REGISTERs with no response at all raise no alert.
    #[test]
    fn unanswered_registers_are_not_failures() {
        let mut detector = RegFloodDetector::new(50);
        for i in 0..60 {
            let msg = register_at(attacker_ip(), &format!("z9hG4bK-silent-{i}"), true, ts());
            assert!(
                detector.check(&msg).is_none(),
                "REGISTER {} fired with no answer from the registrar",
                i + 1
            );
        }
    }

    /// Staying under the threshold raises no alert.
    #[test]
    fn below_threshold_no_alert() {
        let mut detector = RegFloodDetector::new(50);
        for i in 0..40 {
            let branch = format!("z9hG4bK-ok-{i}");
            let _ = detector.check(&register_at(attacker_ip(), &branch, true, ts()));
            assert!(
                detector
                    .check(&response_at(401, attacker_ip(), &branch, ts()))
                    .is_none(),
                "should not alert at {} failures (threshold 50)",
                i + 1
            );
        }
    }

    /// Two sources each below the threshold are tracked independently: thirty
    /// failures apiece do not add up to sixty.
    #[test]
    fn different_sources_independent() {
        let mut detector = RegFloodDetector::new(50);
        for i in 0..30 {
            for src in [attacker_ip(), other_ip()] {
                let branch = format!("z9hG4bK-{src}-{i}");
                let _ = detector.check(&register_at(src, &branch, true, ts()));
                assert!(
                    detector
                        .check(&response_at(401, src, &branch, ts()))
                        .is_none(),
                    "failure {} from {src} fired: the two sources are being summed",
                    i + 1
                );
            }
        }
    }

    /// A 401 answering a credentialed REGISTER is one failure for its
    /// sender; the same 401 answering a bare REGISTER is none.
    #[test]
    fn auth_failure_tracking() {
        let mut detector = RegFloodDetector::new(50);

        let _ = detector.check(&register_at(attacker_ip(), "z9hG4bK-cred", true, ts()));
        let _ = detector.check(&response_at(401, attacker_ip(), "z9hG4bK-cred", ts()));
        let state = detector.sources.peek(&attacker_ip()).expect("state exists");
        assert_eq!(
            state.auth_fail_count, 1,
            "should track the challenged failure"
        );

        let _ = detector.check(&register_at(other_ip(), "z9hG4bK-bare", false, ts()));
        let _ = detector.check(&response_at(401, other_ip(), "z9hG4bK-bare", ts()));
        let state = detector.sources.peek(&other_ip()).expect("state exists");
        assert_eq!(
            state.auth_fail_count, 0,
            "a challenge to a REGISTER that carried no credentials is not a failure"
        );
    }

    /// A threshold of 0 selects the built-in default (50/sec).
    #[test]
    fn default_threshold() {
        let detector = RegFloodDetector::new(0);
        assert_eq!(
            detector.threshold, DEFAULT_THRESHOLD,
            "threshold=0 should use default"
        );
    }

    /// The customer's SBC, seen from the registrar it re-registers against.
    fn sbc_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7))
    }

    /// A REGISTER from `src` on transaction `branch`, stamped `at`, carrying
    /// an `Authorization` header when `with_credentials` is set.
    ///
    /// The branch is what ties the registrar's answer back to this request:
    /// a REGISTER and the response that settles it share the top `Via`.
    fn register_at(
        src: IpAddr,
        branch: &str,
        with_credentials: bool,
        at: DateTime<Utc>,
    ) -> SipMessage {
        let via = format!("Via: SIP/2.0/UDP 10.0.0.7:5060;branch={branch}");
        let call_id = format!("Call-ID: {branch}@test");
        let mut headers = vec![
            via.as_str(),
            "From: <sip:user@example.com>;tag=r1",
            "To: <sip:user@example.com>",
            call_id.as_str(),
            "CSeq: 1 REGISTER",
        ];
        if with_credentials {
            headers.push(
                "Authorization: Digest username=\"user\", realm=\"example.com\", \
                 nonce=\"abc\", uri=\"sip:example.com\", response=\"0000\"",
            );
        }
        headers.push("Content-Length: 0");
        let raw = build_sip("REGISTER sip:registrar@example.com SIP/2.0", &headers, b"");
        parse_sip(&raw, at, src, localhost(), 5060, 5060, TransportProto::Udp).expect("parse")
    }

    /// The registrar's answer to a REGISTER on transaction `branch`, sent
    /// back to `dst`, stamped `at`.
    fn response_at(code: u16, dst: IpAddr, branch: &str, at: DateTime<Utc>) -> SipMessage {
        let reason = match code {
            200 => "OK",
            401 => "Unauthorized",
            407 => "Proxy Authentication Required",
            _ => "Other",
        };
        let via = format!("Via: SIP/2.0/UDP 10.0.0.7:5060;branch={branch}");
        let call_id = format!("Call-ID: {branch}@test");
        let raw = build_sip(
            &format!("SIP/2.0 {code} {reason}"),
            &[
                via.as_str(),
                "From: <sip:user@example.com>;tag=r1",
                "To: <sip:user@example.com>;tag=r2",
                call_id.as_str(),
                "CSeq: 1 REGISTER",
                "Content-Length: 0",
            ],
            b"",
        );
        parse_sip(&raw, at, localhost(), dst, 5060, 5060, TransportProto::Udp).expect("parse")
    }

    /// The failure this detector shipped with. A registrar restarts, the
    /// customer's SBC re-registers two hundred phones inside one second, and
    /// the registrar accepts every one of them. A count of REGISTERs is a
    /// volume, the peer that produces the most of it is the operator's own
    /// SBC, and `--fail2ban` bans whatever this returns.
    #[test]
    fn a_re_register_storm_answered_200_is_not_a_flood() {
        let mut det = RegFloodDetector::new(50);
        let mut fired = 0usize;
        for i in 0..200 {
            let branch = format!("z9hG4bK-storm-{i}");
            if det
                .check(&register_at(sbc_ip(), &branch, true, ts()))
                .is_some()
            {
                fired += 1;
            }
            if det
                .check(&response_at(200, sbc_ip(), &branch, ts()))
                .is_some()
            {
                fired += 1;
            }
        }
        assert_eq!(
            fired, 0,
            "{fired} alert(s) for 200 registrations the registrar ACCEPTED: the detector \
             is counting REGISTERs rather than failures, and this source is the customer's SBC"
        );
    }

    /// The ordinary shape of every registration: a bare REGISTER, a 401
    /// challenge, the same REGISTER again with credentials, a 200. The
    /// challenge is the first half of a registration that WORKED, and the
    /// storm is a hundred phones doing it at once.
    #[test]
    fn an_ordinary_challenged_registration_is_not_a_failure() {
        let mut det = RegFloodDetector::new(50);
        let mut fired = 0usize;
        for i in 0..100 {
            let first = format!("z9hG4bK-first-{i}");
            let second = format!("z9hG4bK-second-{i}");
            for msg in [
                register_at(sbc_ip(), &first, false, ts()),
                response_at(401, sbc_ip(), &first, ts()),
                register_at(sbc_ip(), &second, true, ts()),
                response_at(200, sbc_ip(), &second, ts()),
            ] {
                if det.check(&msg).is_some() {
                    fired += 1;
                }
            }
        }
        assert_eq!(
            fired, 0,
            "{fired} alert(s) across 100 registrations that each completed: a challenge \
             answered with working credentials is not a failure"
        );
    }

    /// The negative control: a credential-stuffing run is fifty-one
    /// REGISTERs that each carried credentials and were each refused, inside
    /// one second. The threshold is crossed by the 51st FAILURE, never by a
    /// REGISTER on its own.
    #[test]
    fn a_credential_stuffing_run_answered_401_still_fires() {
        let mut det = RegFloodDetector::new(50);
        let mut fired_on_failure = None;
        for i in 0..60 {
            let branch = format!("z9hG4bK-stuff-{i}");
            assert!(
                det.check(&register_at(attacker_ip(), &branch, true, ts()))
                    .is_none(),
                "REGISTER {} raised the alert on its own: a request is a volume, and only \
                 the registrar's answer to it is an outcome",
                i + 1
            );
            let alert = det.check(&response_at(401, attacker_ip(), &branch, ts()));
            if let Some(alert) = alert
                && fired_on_failure.is_none()
            {
                assert_eq!(alert.src_ip, attacker_ip());
                assert_eq!(alert.threshold, 50);
                assert_eq!(alert.auth_fail_count, i + 1);
                fired_on_failure = Some(i + 1);
            }
        }
        assert_eq!(
            fired_on_failure,
            Some(51),
            "51 challenged failures inside one second must fire at threshold 50"
        );
    }

    /// A 407 is the proxy's form of the same refusal.
    #[test]
    fn a_407_to_a_credentialed_register_is_a_failure_too() {
        let mut det = RegFloodDetector::new(2);
        let mut fired = 0usize;
        for i in 0..3 {
            let branch = format!("z9hG4bK-proxy-{i}");
            let _ = det.check(&register_at(attacker_ip(), &branch, true, ts()));
            if det
                .check(&response_at(407, attacker_ip(), &branch, ts()))
                .is_some()
            {
                fired += 1;
            }
        }
        assert_eq!(
            fired, 1,
            "the third 407 to a credentialed REGISTER crosses threshold 2"
        );
    }

    /// Sixty challenges to REGISTERs that carried no credentials count for
    /// nothing: every phone in the building is challenged before it
    /// registers, and this is what that looks like from the wire.
    #[test]
    fn a_challenge_to_a_register_without_credentials_is_not_a_failure() {
        let mut det = RegFloodDetector::new(5);
        for i in 0..60 {
            let branch = format!("z9hG4bK-bare-{i}");
            assert!(
                det.check(&register_at(sbc_ip(), &branch, false, ts()))
                    .is_none(),
                "REGISTER {} fired on its own",
                i + 1
            );
            assert!(
                det.check(&response_at(401, sbc_ip(), &branch, ts()))
                    .is_none(),
                "challenge {} to an uncredentialed REGISTER was counted as a failure",
                i + 1
            );
        }
    }

    /// A challenge is a failure only for the transaction it answers. A 401
    /// whose top `Via` names no credentialed REGISTER from this source settles
    /// somebody else's request, or a retransmission, and counts for nothing.
    #[test]
    fn a_challenge_on_another_branch_is_not_this_registers_failure() {
        let mut det = RegFloodDetector::new(1);
        for (reg, resp) in [("a", "x"), ("b", "y"), ("c", "z")] {
            let _ = det.check(&register_at(
                attacker_ip(),
                &format!("z9hG4bK-{reg}"),
                true,
                ts(),
            ));
            assert!(
                det.check(&response_at(
                    401,
                    attacker_ip(),
                    &format!("z9hG4bK-{resp}"),
                    ts()
                ))
                .is_none(),
                "a 401 on branch {resp} was charged to the REGISTER on branch {reg}"
            );
        }
        // Control: the same three, answered on their own branches, fire from
        // the second -- else the assertion above is satisfied by a detector
        // that never counts anything.
        let mut control = RegFloodDetector::new(1);
        let mut fired = 0usize;
        for b in ["p", "q", "r"] {
            let branch = format!("z9hG4bK-{b}");
            let _ = control.check(&register_at(attacker_ip(), &branch, true, ts()));
            if control
                .check(&response_at(401, attacker_ip(), &branch, ts()))
                .is_some()
            {
                fired += 1;
            }
        }
        assert_eq!(
            fired, 2,
            "control: matched branches must fire from the 2nd failure"
        );
    }

    /// A 2xx to a REGISTER is the registrar saying this source belongs here.
    /// It clears the failure count: a phone that mistyped its password twice
    /// and then got in is not halfway to a ban.
    #[test]
    fn a_2xx_to_a_register_clears_the_failure_count() {
        let mut det = RegFloodDetector::new(5);
        let fail = |det: &mut RegFloodDetector, branch: &str| -> bool {
            let _ = det.check(&register_at(attacker_ip(), branch, true, ts()));
            det.check(&response_at(401, attacker_ip(), branch, ts()))
                .is_some()
        };
        // Five failures: at the threshold, not over it.
        for i in 0..5 {
            assert!(!fail(&mut det, &format!("z9hG4bK-before-{i}")));
        }
        // Then the registrar accepts one.
        let _ = det.check(&register_at(attacker_ip(), "z9hG4bK-ok", true, ts()));
        assert!(
            det.check(&response_at(200, attacker_ip(), "z9hG4bK-ok", ts()))
                .is_none()
        );
        // Five more inside the same second must not cross the threshold,
        // because the count restarted at the 200.
        for i in 0..5 {
            assert!(
                !fail(&mut det, &format!("z9hG4bK-after-{i}")),
                "failure {} after a successful registration fired: the 200 did not clear \
                 the count",
                i + 1
            );
        }
        // Control: the count is live again -- one more crosses it.
        assert!(
            fail(&mut det, "z9hG4bK-after-5"),
            "control: a sixth failure after the clear must fire, else the clear is \
             indistinguishable from never counting"
        );
    }

    /// Capture time `secs` seconds after the fixed base timestamp.
    fn at(secs: i64) -> DateTime<Utc> {
        ts() + chrono::TimeDelta::seconds(secs)
    }

    /// The window counts what the CAPTURE says, not how long sipnab took to
    /// read it.
    ///
    /// `sipnab -I yesterday.pcap --reg-flood --fail2ban -N` reads a file as
    /// fast as the disk delivers it. A phone with a stale password that
    /// re-registers every sixty seconds and is refused every time is sixty
    /// challenged failures across an hour of capture -- and sixty inside one
    /// wall-clock second, which is a ban, when the window is paced by
    /// `Instant::now()`.
    #[test]
    fn window_is_measured_in_packet_time() {
        let mut det = RegFloodDetector::new(50);
        let mut fired = 0usize;
        for i in 0..60 {
            let branch = format!("z9hG4bK-stale-{i}");
            let when = at(i * 60);
            let _ = det.check(&register_at(attacker_ip(), &branch, true, when));
            if det
                .check(&response_at(401, attacker_ip(), &branch, when))
                .is_some()
            {
                fired += 1;
            }
        }
        assert_eq!(
            fired, 0,
            "one refused registration a minute is one failure per window, far under \
             50 -- {fired} alert(s) means the window is paced by how fast the file was \
             read, not by the capture"
        );
    }

    /// A genuine burst inside one packet-time second still fires: the
    /// packet-time window must not become a way to never detect anything.
    #[test]
    fn a_real_burst_inside_one_packet_time_window_still_fires() {
        let mut det = RegFloodDetector::new(50);
        let mut fired_on = None;
        for i in 0..60 {
            let branch = format!("z9hG4bK-burst-{i}");
            // Ten milliseconds apart: sixty land inside 600 ms of capture.
            let when = ts() + chrono::TimeDelta::milliseconds(i * 10);
            let _ = det.check(&register_at(attacker_ip(), &branch, true, when));
            if det
                .check(&response_at(401, attacker_ip(), &branch, when))
                .is_some()
                && fired_on.is_none()
            {
                fired_on = Some(i + 1);
            }
        }
        assert_eq!(
            fired_on,
            Some(51),
            "51 challenged failures inside one packet-time second must fire at 50"
        );
    }

    /// A source that stops sending is aged out on capture time. Two sources:
    /// one last seen at the base timestamp, one five minutes later. A sweep
    /// of two minutes measured from the newest packet keeps only the second.
    #[test]
    fn sweep_ages_entries_out_on_packet_time() {
        let mut det = RegFloodDetector::new(50);
        let _ = det.check(&register_at(attacker_ip(), "z9hG4bK-old", true, at(0)));
        let _ = det.check(&register_at(other_ip(), "z9hG4bK-new", true, at(300)));
        assert_eq!(det.sources.len(), 2);
        det.sweep(std::time::Duration::from_secs(120));
        assert!(
            !det.sources.contains_key(&attacker_ip()),
            "a source last seen 300 s of capture before the newest packet survived a \
             120 s sweep: the sweep is measuring wall time"
        );
        assert!(
            det.sources.contains_key(&other_ip()),
            "the source seen at the newest packet must survive the sweep"
        );
    }

    /// A response never creates a source entry; it only settles an existing
    /// one.
    ///
    /// The cap on tracked sources was applied on the REGISTER branch alone,
    /// so a 401 flood aimed at a /16 of destinations -- fifty thousand a
    /// second, none of them answering a REGISTER this detector ever saw --
    /// created an entry per destination, millions before the first sweep,
    /// and none of them evidence of anything.
    #[test]
    fn a_response_never_creates_a_source_entry() {
        let mut det = RegFloodDetector::new(50);
        let n = MAX_SOURCE_ENTRIES + 1;
        for i in 0..n {
            let dst = IpAddr::V4(Ipv4Addr::from(0x0a10_0000 + i as u32));
            let branch = format!("z9hG4bK-unseen-{i}");
            for code in [401, 200] {
                assert!(det.check(&response_at(code, dst, &branch, ts())).is_none());
            }
        }
        assert_eq!(
            det.sources.len(),
            0,
            "{} source entries created by responses alone: a response to a REGISTER \
             this detector never saw anchors nothing, and the map grew past its cap of \
             {MAX_SOURCE_ENTRIES} without a REGISTER in sight",
            det.sources.len()
        );
    }

    /// A source address in the 12.0.0.0/8 test range, distinct per `i`.
    fn probe_ip(i: usize) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(0x0c00_0000 + i as u32))
    }

    /// A detector holding exactly `MAX_SOURCE_ENTRIES` sources, none of them
    /// in the probe range.
    fn full_detector() -> RegFloodDetector {
        let mut det = RegFloodDetector::new(50);
        for i in 0..MAX_SOURCE_ENTRIES {
            let src = IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + i as u32));
            let _ = det.check(&register_at(src, "z9hG4bK-fill", false, ts()));
        }
        assert_eq!(
            det.sources.len(),
            MAX_SOURCE_ENTRIES,
            "fixture: the map is full"
        );
        det
    }

    /// The failure this shipped with. A spoofed-source flood fills the map,
    /// and from then on every REGISTER from a new address pays for a scan of
    /// all ten thousand entries to choose a victim -- on the capture thread,
    /// inside `process_parsed_packet`, under both store write locks, while
    /// every MCP and API reader waits and the kernel's drop counter climbs.
    ///
    /// Measured as a ratio rather than a bound: the same thousand messages,
    /// parsed up front so only `check` is timed, into a fresh detector and
    /// into a full one, the minimum of three rounds each so a descheduled
    /// thread cannot inflate either side. Constant-time eviction makes the
    /// two costs alike (measured at 1.3x); the shipped scan made the full one
    /// 371x dearer.
    #[test]
    fn admitting_a_source_at_cap_costs_no_more_than_admitting_one_to_an_empty_map() {
        use std::time::{Duration, Instant};
        let probe: Vec<SipMessage> = (0..1_000)
            .map(|i| register_at(probe_ip(i), &format!("z9hG4bK-probe-{i}"), false, ts()))
            .collect();
        let time_probe = |det: &mut RegFloodDetector| {
            let started = Instant::now();
            for msg in &probe {
                let _ = det.check(msg);
            }
            started.elapsed()
        };

        let mut empty_cost = Duration::MAX;
        let mut full_cost = Duration::MAX;
        for _ in 0..3 {
            let mut fresh = RegFloodDetector::new(50);
            empty_cost = empty_cost.min(time_probe(&mut fresh));
            let mut full = full_detector();
            full_cost = full_cost.min(time_probe(&mut full));
            assert_eq!(
                full.sources.len(),
                MAX_SOURCE_ENTRIES,
                "control: the cap must still hold after a thousand new sources"
            );
        }
        let ratio = full_cost.as_nanos() as f64 / empty_cost.as_nanos().max(1) as f64;
        assert!(
            ratio < 5.0,
            "admitting a source to a full map cost {ratio:.1}x what admitting one to \
             an empty map cost ({full_cost:?} against {empty_cost:?} for 1,000 \
             REGISTERs): eviction is scanning the map"
        );
    }

    /// At the cap the source evicted is the one touched least recently, not
    /// the one inserted first: a REGISTER or a response to a source refreshes
    /// it. The oldest-inserted source is touched again before the map fills,
    /// and it is the second-inserted, untouched since, that goes.
    #[test]
    fn at_cap_the_least_recently_touched_source_is_evicted() {
        let mut det = RegFloodDetector::new(50);
        let first = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1));
        let second = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 2));
        let _ = det.check(&register_at(first, "z9hG4bK-first", true, ts()));
        let _ = det.check(&register_at(second, "z9hG4bK-second", true, ts()));
        for i in 2..MAX_SOURCE_ENTRIES {
            let src = IpAddr::V4(Ipv4Addr::from(0x0a02_0000 + i as u32));
            let _ = det.check(&register_at(src, "z9hG4bK-fill", false, ts()));
        }
        assert_eq!(det.sources.len(), MAX_SOURCE_ENTRIES, "fixture: at the cap");
        // Touch `first` with a response, which is the other path that
        // refreshes a source.
        let _ = det.check(&response_at(401, first, "z9hG4bK-first", ts()));

        let _ = det.check(&register_at(probe_ip(0), "z9hG4bK-new", false, ts()));

        assert_eq!(det.sources.len(), MAX_SOURCE_ENTRIES, "the cap holds");
        assert!(
            !det.sources.contains_key(&second),
            "the least recently touched source must be the one evicted"
        );
        assert!(
            det.sources.contains_key(&first),
            "a source touched after the map filled survived the flood: it was \
             evicted as the oldest INSERTED rather than the least recently USED"
        );
        assert!(
            det.sources.contains_key(&probe_ip(0)),
            "the new source is admitted"
        );
    }

    /// The emitted alert carries the failure count that crossed the
    /// threshold, the REGISTER count for context, the threshold, and the
    /// source.
    #[test]
    fn alert_includes_counts() {
        let mut detector = RegFloodDetector::new(5);

        let mut alert = None;
        for i in 0..6 {
            let branch = format!("z9hG4bK-count-{i}");
            let _ = detector.check(&register_at(attacker_ip(), &branch, true, ts()));
            if let Some(a) = detector.check(&response_at(401, attacker_ip(), &branch, ts())) {
                alert = Some(a);
            }
        }

        let alert = alert.expect("should have triggered");
        assert_eq!(alert.auth_fail_count, 6);
        assert_eq!(alert.register_count, 6);
        assert_eq!(alert.threshold, 5);
        assert_eq!(alert.src_ip, attacker_ip());
    }
}
