// SPDX-License-Identifier: MIT OR Apache-2.0

//! SIP scanner and reconnaissance tool detection.
//!
//! Detects SIP scanning activity through two methods:
//! - **User-Agent pattern matching** against known scanner signatures
//!   (friendly-scanner, sipvicious, etc.) and user-defined patterns.
//! - **Behavioral analysis** detecting high-rate REGISTER/OPTIONS/INVITE probing
//!   from a single source, and **extension enumeration** — many *distinct*
//!   target users from one source — which catches a UA-randomized, INVITE-based,
//!   or low-and-slow sweep that signature/rate detection alone would miss.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use chrono::{DateTime, TimeDelta, Utc};
use regex::{Regex, RegexBuilder};

use crate::sip::SipMessage;

/// Known SIP scanner User-Agent patterns (case-insensitive).
const KNOWN_SCANNER_PATTERNS: &[&str] = &[
    "friendly-scanner",
    "sipvicious",
    "sipcli",
    "sipsak",
    "sundayddr",
    "VaxSIPUserAgent",
    "sip-scan",
];

/// Number of requests from the same source within the behavioral window
/// that triggers a behavioral detection alert.
const BEHAVIORAL_THRESHOLD: u32 = 10;

/// Number of DISTINCT target extensions probed by one source within the window
/// that triggers an enumeration alert. Lower than the rate threshold because
/// hitting many *different* users is a far more specific recon signal than
/// volume alone (svwar's signature) — and it catches a UA-randomized, INVITE-
/// based, or low-and-slow sweep that the rate counter misses.
const ENUMERATION_THRESHOLD: usize = 5;

/// Cap on tracked distinct targets per source (bounds memory under a flood that
/// also randomizes the target user-part).
const MAX_TARGETS_PER_SOURCE: usize = 1024;

/// Behavioral detection window in seconds.
const BEHAVIORAL_WINDOW_SECS: u64 = 5;

/// Tracks per-source behavioral state for probe detection.
///
/// Both timestamps are CAPTURE time — the timestamp the packet carries — not
/// wall time. See [`ScannerDetector::latest_packet`] for why.
struct BehavioralState {
    /// REGISTER requests seen from this source in the current window.
    register_count: u32,
    /// OPTIONS requests seen from this source in the current window.
    options_count: u32,
    /// INVITE requests seen from this source in the current window.
    invite_count: u32,
    /// Distinct target extensions (To/R-URI user-part) seen this window.
    targets: HashSet<String>,
    /// Start of the current behavioral window, in capture time.
    first_seen: DateTime<Utc>,
    /// Most recent activity from this source, in capture time (used for
    /// sweeping).
    last_seen: DateTime<Utc>,
    /// Monotonic counter of when this source was last touched, used to pick
    /// the eviction victim.
    ///
    /// Not a timestamp, because capture timestamps TIE: two packets can share
    /// a microsecond, and a replay of one crafted message repeated is entirely
    /// legitimate input. Under a tie `min_by_key` returns whichever entry the
    /// hash order happened to visit first, so which source the memory cap
    /// evicted became unpredictable — and the source being evicted is the one
    /// whose detection state is discarded.
    last_used: u64,
}

/// Alert produced when scanner activity is detected.
#[derive(Debug, Clone)]
pub struct ScannerAlert {
    /// Source IP address of the scanner.
    pub src_ip: IpAddr,
    /// `User-Agent` from the triggering message, or `None` when it carried
    /// none.
    ///
    /// `Option`, not an empty string: a request with no `User-Agent` is itself
    /// a scanner signal, and collapsing it into `""` made it indistinguishable
    /// from a header present but empty — which an attacker can send.
    pub ua: Option<String>,
    /// SIP method of the triggering message, or `None` when the request line
    /// carried none.
    ///
    /// `Option` for the same reason as [`ua`](Self::ua): the placeholder it
    /// replaced, `"UNKNOWN"`, is a value `SipMethod::Custom` can legitimately
    /// hold, so absence and a peculiar method read identically.
    pub method: Option<String>,
    /// How the scanner was detected: `"ua_pattern"`, `"behavioral"` (rate), or
    /// `"enumeration"` (many distinct targets from one source).
    pub detection_method: String,
}

/// Maximum compiled regex size in bytes to prevent ReDoS.
const REGEX_SIZE_LIMIT: usize = 1_000_000;

/// Maximum entries in the behavioral tracking map.
const MAX_BEHAVIORAL_ENTRIES: usize = 10_000;

/// Detects SIP scanners via UA signature matching and behavioral heuristics.
pub struct ScannerDetector {
    /// Compiled regex patterns for known scanner User-Agents.
    known_patterns: Vec<Regex>,
    /// Per-source behavioral tracking state.
    behavioral: HashMap<IpAddr, BehavioralState>,
    /// Capture time of the most recent message checked — the detector's
    /// "now". `None` before the first message.
    ///
    /// The rate and enumeration windows used to be paced by
    /// `std::time::Instant`, which is the clock of the machine doing the
    /// reading rather than of the traffic being read. Live those agree, since
    /// a packet is timestamped as it arrives. Offline they do not: a file is
    /// replayed as fast as the disk allows, so several minutes of a busy trunk
    /// land inside one wall-clock second, the
    /// [`BEHAVIORAL_WINDOW_SECS`]-second window never expires, and the
    /// per-source counters accumulate over the WHOLE capture. Every peer that
    /// sent more than [`BEHAVIORAL_THRESHOLD`] requests or reached more than
    /// [`ENUMERATION_THRESHOLD`] extensions — an ordinary carrier SBC does
    /// both in a minute — was then reported as a scanner, and with
    /// `--kill-scanner` that decides whether sipnab answers it. It also made
    /// the verdict a function of machine speed: the same bytes on a slower box
    /// gave a different answer.
    ///
    /// This is the same defect [`crate::app::batch::SweepClock`] fixed for the
    /// dialog and stream sweeps, applied where the clock is already to hand:
    /// every message carries its own capture timestamp, so the detector reads
    /// its "now" off the traffic and needs nothing threaded in from the caller.
    ///
    /// Never moves backwards. Captures do contain out-of-order timestamps, and
    /// one reordered packet must not rewind the sweep horizon.
    latest_packet: Option<DateTime<Utc>>,
    /// Ticks once per tracked source touched; the value stamped into
    /// [`BehavioralState::last_used`] to order eviction.
    use_counter: u64,
}

impl ScannerDetector {
    /// Create a new scanner detector.
    ///
    /// # Arguments
    ///
    /// * `custom_patterns` — Additional User-Agent regex patterns to match
    ///   (e.g., from `--kill-ua`). Invalid or oversized patterns are silently skipped.
    pub fn new(custom_patterns: &[String]) -> Self {
        let mut patterns = Vec::with_capacity(KNOWN_SCANNER_PATTERNS.len() + custom_patterns.len());

        // Compile built-in patterns (case-insensitive, size-limited)
        for pat in KNOWN_SCANNER_PATTERNS {
            if let Ok(re) = RegexBuilder::new(&format!("(?i){pat}"))
                .size_limit(REGEX_SIZE_LIMIT)
                .build()
            {
                patterns.push(re);
            }
        }

        // Compile user-supplied patterns (size-limited to prevent ReDoS)
        for pat in custom_patterns {
            match RegexBuilder::new(&format!("(?i){pat}"))
                .size_limit(REGEX_SIZE_LIMIT)
                .build()
            {
                Ok(re) => patterns.push(re),
                Err(e) => {
                    tracing::warn!("Skipping invalid or oversized --kill-ua pattern '{pat}': {e}");
                }
            }
        }

        Self {
            known_patterns: patterns,
            behavioral: HashMap::new(),
            latest_packet: None,
            use_counter: 0,
        }
    }

    /// Check a SIP message for scanner activity.
    ///
    /// Returns a `ScannerAlert` if the message matches a known scanner
    /// pattern or if the source IP's behavioral profile exceeds the
    /// probing threshold.
    #[must_use]
    pub fn check(&mut self, msg: &SipMessage) -> Option<ScannerAlert> {
        // Advance the capture clock before any early return, so `sweep` still
        // ages state out over a stretch of capture that held only responses.
        if self
            .latest_packet
            .is_none_or(|latest| msg.timestamp > latest)
        {
            self.latest_packet = Some(msg.timestamp);
        }

        // `None` when the request line carried no recognisable method. It used
        // to substitute the literal "UNKNOWN", which is a value a `Custom`
        // method can also hold — the same collision the `ua` field had.
        let method = if msg.is_request {
            msg.method.as_ref().map(|m| m.as_str())
        } else {
            return None; // Only check requests
        };

        let ua = msg.user_agent().map(str::to_string);

        // Check UA pattern match. An absent header matches nothing — the
        // patterns describe what a scanner *says*, and a request that says
        // nothing is caught by the behavioural analysis below instead.
        if let Some(ref ua) = ua
            && !ua.is_empty()
        {
            for pattern in &self.known_patterns {
                if pattern.is_match(ua) {
                    return Some(ScannerAlert {
                        src_ip: msg.src_addr,
                        ua: Some(ua.clone()),
                        method: method.map(str::to_string),
                        detection_method: "ua_pattern".to_string(),
                    });
                }
            }
        }

        // Behavioral analysis: track REGISTER/OPTIONS/INVITE rates
        if matches!(method, Some("REGISTER" | "OPTIONS" | "INVITE")) {
            let now = msg.timestamp;

            // Cap the behavioral map to prevent memory exhaustion (H4)
            if self.behavioral.len() >= MAX_BEHAVIORAL_ENTRIES
                && !self.behavioral.contains_key(&msg.src_addr)
            {
                // Evict the least recently used entry.
                if let Some(oldest_ip) = self
                    .behavioral
                    .iter()
                    .min_by_key(|(_, s)| s.last_used)
                    .map(|(&ip, _)| ip)
                {
                    self.behavioral.remove(&oldest_ip);
                }
            }

            self.use_counter += 1;
            let use_counter = self.use_counter;
            let state = self
                .behavioral
                .entry(msg.src_addr)
                .or_insert(BehavioralState {
                    register_count: 0,
                    options_count: 0,
                    invite_count: 0,
                    targets: HashSet::new(),
                    first_seen: now,
                    last_seen: now,
                    last_used: use_counter,
                });
            state.last_used = use_counter;

            // Reset window if expired. `signed_duration_since` rather than a
            // subtraction that could go negative: an out-of-order packet
            // yields a negative delta, which must not be read as an expired
            // window (nor panic on an `unsigned_abs` that would read a packet
            // from the past as one far in the future).
            if now.signed_duration_since(state.first_seen)
                > TimeDelta::seconds(BEHAVIORAL_WINDOW_SECS as i64)
            {
                state.register_count = 0;
                state.options_count = 0;
                state.invite_count = 0;
                state.targets.clear();
                state.first_seen = now;
            }

            match method {
                Some("REGISTER") => state.register_count += 1,
                Some("OPTIONS") => state.options_count += 1,
                Some("INVITE") => state.invite_count += 1,
                _ => {}
            }
            // Track distinct probed extensions (To user, falling back to R-URI).
            if let Some(target) = msg.to_user().or_else(|| {
                msg.request_uri
                    .as_deref()
                    .and_then(crate::sip::message::extract_uri_user)
            }) && state.targets.len() < MAX_TARGETS_PER_SOURCE
            {
                state.targets.insert(target);
            }
            state.last_seen = now;

            // Enumeration: many DISTINCT targets from one source — catches a
            // UA-randomized, INVITE-based, or low-and-slow sweep the rate path
            // misses. Checked first as the more specific (lower-FP) signal.
            if state.targets.len() > ENUMERATION_THRESHOLD {
                return Some(ScannerAlert {
                    src_ip: msg.src_addr,
                    ua,
                    method: method.map(str::to_string),
                    detection_method: "enumeration".to_string(),
                });
            }

            // Rate: high volume of REGISTER/OPTIONS probes (now incl. INVITE) in
            // the window — a same-target flood the enumeration signal won't see.
            let probe_count = state.register_count + state.options_count + state.invite_count;
            if probe_count > BEHAVIORAL_THRESHOLD {
                return Some(ScannerAlert {
                    src_ip: msg.src_addr,
                    ua,
                    method: method.map(str::to_string),
                    detection_method: "behavioral".to_string(),
                });
            }
        }

        None
    }

    /// Remove behavioral tracking entries whose last activity is older than
    /// `max_age` **in capture time**.
    ///
    /// Ages against the most recent packet checked, not `Instant::now()`: the
    /// caller sweeps on a schedule, and offline the wall clock barely moves
    /// between the first packet of a capture and the last, so a wall-clock
    /// sweep held every source it ever saw for the whole run.
    ///
    /// A no-op before the first message: with no capture time there is nothing
    /// to measure against, and nothing tracked to remove.
    pub fn sweep(&mut self, max_age: std::time::Duration) {
        let Some(now) = self.latest_packet else {
            return;
        };
        let Ok(max_age) = TimeDelta::from_std(max_age) else {
            return;
        };
        self.behavioral
            .retain(|_, state| now.signed_duration_since(state.last_seen) < max_age);
    }
}

// ── Tests ────────────────────────────────────────────────────────────

/// Unit tests for scanner UA-signature and behavioral/enumeration detection.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::TransportProto;
    use crate::sip::parser::parse_sip;
    use chrono::{DateTime, Utc};
    use std::net::{IpAddr, Ipv4Addr};

    /// The loopback address used as a benign source/destination.
    fn localhost() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    /// The source IP used to simulate a scanner.
    fn scanner_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99))
    }

    /// A fixed capture timestamp for the parsed messages.
    fn ts() -> DateTime<Utc> {
        chrono::TimeZone::with_ymd_and_hms(&Utc, 2024, 6, 15, 12, 0, 0).unwrap()
    }

    use crate::test_utils::build_sip_message as build_sip;

    /// Build a request of `method` carrying the given User-Agent from `src`.
    fn make_request_with_ua(method: &str, ua: &str, src: IpAddr) -> SipMessage {
        let raw = build_sip(
            &format!("{method} sip:target@example.com SIP/2.0"),
            &[
                "From: <sip:scanner@example.com>;tag=s1",
                "To: <sip:target@example.com>",
                "Call-ID: scan-test@example.com",
                &format!("CSeq: 1 {method}"),
                &format!("User-Agent: {ua}"),
                "Content-Length: 0",
            ],
            b"",
        );
        parse_sip(
            &raw,
            ts(),
            src,
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse")
    }

    /// Build a request of `method` with no User-Agent header from `src`.
    fn make_request_no_ua(method: &str, src: IpAddr, call_id: &str) -> SipMessage {
        let raw = build_sip(
            &format!("{method} sip:target@example.com SIP/2.0"),
            &[
                "From: <sip:scanner@example.com>;tag=s1",
                "To: <sip:target@example.com>",
                &format!("Call-ID: {call_id}"),
                &format!("CSeq: 1 {method}"),
                "Content-Length: 0",
            ],
            b"",
        );
        parse_sip(
            &raw,
            ts(),
            src,
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse")
    }

    /// A friendly-scanner User-Agent is detected via signature match.
    #[test]
    fn detect_friendly_scanner_ua() {
        let mut detector = ScannerDetector::new(&[]);
        let msg = make_request_with_ua("OPTIONS", "friendly-scanner", scanner_ip());

        let alert = detector.check(&msg);
        assert!(alert.is_some(), "should detect friendly-scanner");
        let alert = alert.unwrap();
        assert_eq!(alert.detection_method, "ua_pattern");
        assert_eq!(alert.ua.as_deref(), Some("friendly-scanner"));
    }

    /// A sipvicious User-Agent is detected via signature match.
    #[test]
    fn detect_sipvicious_ua() {
        let mut detector = ScannerDetector::new(&[]);
        let msg = make_request_with_ua("REGISTER", "sipvicious/0.3.4", scanner_ip());

        let alert = detector.check(&msg);
        assert!(alert.is_some(), "should detect sipvicious");
        let alert = alert.unwrap();
        assert_eq!(alert.detection_method, "ua_pattern");
    }

    /// A benign User-Agent does not trigger a signature alert.
    #[test]
    fn normal_ua_not_detected() {
        let mut detector = ScannerDetector::new(&[]);
        let msg = make_request_with_ua("INVITE", "Oasis/4.0", localhost());

        let alert = detector.check(&msg);
        assert!(alert.is_none(), "normal UA should not trigger alert");
    }

    /// A high REGISTER rate from one source triggers a behavioral alert.
    #[test]
    fn behavioral_detection_high_rate() {
        let mut detector = ScannerDetector::new(&[]);
        let src = scanner_ip();

        // Send 15 REGISTERs from same IP — should trigger after >10
        for i in 0..15 {
            let msg = make_request_no_ua("REGISTER", src, &format!("reg-{i}@test"));
            let alert = detector.check(&msg);
            if i > BEHAVIORAL_THRESHOLD as usize {
                assert!(
                    alert.is_some(),
                    "should detect behavioral scanning at message {i}"
                );
                if let Some(a) = alert {
                    assert_eq!(a.detection_method, "behavioral");
                }
            }
        }
    }

    /// Build a request that enumerates a specific target extension, with an
    /// arbitrary (attacker-chosen, here randomized-looking) User-Agent — the
    /// evasion: no known scanner UA, so ua_pattern can never fire.
    /// Build a request probing extension `target` with an arbitrary UA (the
    /// evasion: no known scanner signature) from `src`.
    fn enum_request(method: &str, target: &str, ua: &str, src: IpAddr, n: usize) -> SipMessage {
        let raw = build_sip(
            &format!("{method} sip:{target}@example.com SIP/2.0"),
            &[
                &format!("From: <sip:probe@example.com>;tag=t{n}"),
                &format!("To: <sip:{target}@example.com>"),
                &format!("Call-ID: enum-{n}@example.com"),
                &format!("CSeq: 1 {method}"),
                &format!("User-Agent: {ua}"),
                "Content-Length: 0",
            ],
            b"",
        );
        parse_sip(
            &raw,
            ts(),
            src,
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse")
    }

    /// INVITE-based extension enumeration with a randomized UA is caught by the
    /// distinct-target signal.
    #[test]
    fn detect_invite_extension_enumeration_with_randomized_ua() {
        // EVASION: attacker enumerates extensions over INVITE with a different,
        // innocuous UA each probe. ua_pattern never fires; the old behavioral
        // path only summed REGISTER+OPTIONS, so INVITE enumeration slipped
        // through entirely. The distinct-target signal must catch it.
        let mut det = ScannerDetector::new(&[]);
        let src = scanner_ip();
        let uas = [
            "PolyUA/1",
            "Acme/2",
            "Zoip/3",
            "Xlite/4",
            "Bria/5",
            "Linphone/6",
            "Baresip/7",
            "Csip/8",
        ];
        let mut fired = None;
        for (i, ua) in uas.iter().enumerate() {
            let msg = enum_request("INVITE", &format!("ext{i:04}"), ua, src, i);
            if let Some(a) = det.check(&msg) {
                fired = Some(a);
            }
        }
        let a = fired.expect("extension enumeration over INVITE must be detected");
        assert_eq!(a.detection_method, "enumeration");
    }

    /// Six distinct targets under the rate threshold still trigger enumeration.
    #[test]
    fn detect_low_and_slow_enumeration_under_rate_threshold() {
        // EVASION: stay UNDER the rate threshold (only 6 probes), but hit 6
        // DISTINCT extensions — a rate-only detector misses it; distinct-target
        // enumeration does not.
        let mut det = ScannerDetector::new(&[]);
        let src = scanner_ip();
        let mut fired = None;
        for i in 0..6 {
            let msg = enum_request("OPTIONS", &format!("user{i:04}"), "Normalish/9.0", src, i);
            if let Some(a) = det.check(&msg) {
                fired = Some(a);
            }
        }
        assert!(
            fired.is_some(),
            "6 distinct extensions from one source is enumeration"
        );
        assert_eq!(fired.unwrap().detection_method, "enumeration");
    }

    /// Repeated requests to only one or two targets are not flagged as
    /// enumeration.
    #[test]
    fn normal_call_to_few_targets_not_flagged_as_enumeration() {
        // FALSE-POSITIVE guard: a normal client placing several requests to the
        // SAME one or two targets (retransmits / re-INVITE / a couple of calls)
        // must NOT be flagged as enumeration.
        let mut det = ScannerDetector::new(&[]);
        let src = localhost();
        for i in 0..12 {
            let target = if i % 2 == 0 { "alice" } else { "bob" };
            let msg = enum_request("INVITE", target, "Linphone/5.1", src, i);
            if let Some(a) = det.check(&msg) {
                assert_ne!(
                    a.detection_method, "enumeration",
                    "two distinct targets must not be enumeration (msg {i})"
                );
            }
        }
    }

    /// A user-supplied `--kill-ua` pattern is matched like a built-in signature.
    #[test]
    fn custom_kill_ua_detected() {
        let custom = vec!["my-scanner".to_string()];
        let mut detector = ScannerDetector::new(&custom);
        let msg = make_request_with_ua("OPTIONS", "my-scanner/1.0", scanner_ip());

        let alert = detector.check(&msg);
        assert!(alert.is_some(), "should detect custom --kill-ua pattern");
        let alert = alert.unwrap();
        assert_eq!(alert.detection_method, "ua_pattern");
    }

    // ── Packet time vs wall clock ────────────────────────────────────

    /// Build a request of `method` probing `target` from `src`, stamped with
    /// the capture time `at` — the knob these tests turn.
    fn request_at(
        method: &str,
        target: &str,
        src: IpAddr,
        n: usize,
        at: DateTime<Utc>,
    ) -> SipMessage {
        let raw = build_sip(
            &format!("{method} sip:{target}@example.com SIP/2.0"),
            &[
                &format!("From: <sip:probe@example.com>;tag=t{n}"),
                &format!("To: <sip:{target}@example.com>"),
                &format!("Call-ID: clock-{n}@example.com"),
                &format!("CSeq: 1 {method}"),
                "Content-Length: 0",
            ],
            b"",
        );
        parse_sip(&raw, at, src, localhost(), 5060, 5060, TransportProto::Udp)
            .expect("should parse")
    }

    /// Capture time `secs` seconds after the fixed base timestamp.
    fn at(secs: i64) -> DateTime<Utc> {
        ts() + chrono::TimeDelta::seconds(secs)
    }

    /// The behavioural window counts what the CAPTURE says, not how long
    /// sipnab took to read it.
    ///
    /// A file replayed from disk delivers every packet within milliseconds of
    /// wall time, so a window paced by `Instant::now()` never expires offline
    /// and the per-source counters accumulate over the whole capture. A busy
    /// trunk then trips `BEHAVIORAL_THRESHOLD` on volume it never had: here,
    /// one REGISTER every two seconds — three per five-second window against a
    /// threshold of ten — replayed in a tight loop.
    #[test]
    fn behavioural_window_is_measured_in_packet_time() {
        let mut det = ScannerDetector::new(&[]);
        let src = scanner_ip();
        let mut fired = 0usize;
        for i in 0..60 {
            let msg = request_at("REGISTER", "sameuser", src, i, at(i as i64 * 2));
            if det.check(&msg).is_some() {
                fired += 1;
            }
        }
        assert_eq!(
            fired, 0,
            "one REGISTER every 2s is 3 per {BEHAVIORAL_WINDOW_SECS}s window, well under \
             the threshold of {BEHAVIORAL_THRESHOLD} — {fired} alerts means the window is \
             being paced by how fast the file was read, not by the capture"
        );
    }

    /// The enumeration window is packet time too.
    ///
    /// Ten seconds between probes is two full windows apart, so no window ever
    /// holds more than one distinct target. Paced by wall time, all sixty land
    /// in one window and the sixth trips `ENUMERATION_THRESHOLD`.
    #[test]
    fn enumeration_window_is_measured_in_packet_time() {
        let mut det = ScannerDetector::new(&[]);
        let src = scanner_ip();
        let mut fired = 0usize;
        for i in 0..60 {
            let msg = request_at("OPTIONS", &format!("ext{i:04}"), src, i, at(i as i64 * 10));
            if det.check(&msg).is_some() {
                fired += 1;
            }
        }
        assert_eq!(
            fired, 0,
            "probes {BEHAVIORAL_WINDOW_SECS}s apart put one target in each window, under the \
             enumeration threshold of {ENUMERATION_THRESHOLD} — {fired} alerts means distinct \
             targets are accumulating across the whole capture"
        );
    }

    /// A genuine burst inside one window still fires — the packet-time window
    /// must not become a way to never detect anything.
    #[test]
    fn a_real_burst_inside_one_packet_time_window_still_fires() {
        let mut det = ScannerDetector::new(&[]);
        let src = scanner_ip();
        let mut fired = None;
        for i in 0..15 {
            // 100ms apart: all fifteen inside one BEHAVIORAL_WINDOW_SECS window.
            let msg = request_at(
                "REGISTER",
                "sameuser",
                src,
                i,
                ts() + chrono::TimeDelta::milliseconds(i as i64 * 100),
            );
            if let Some(a) = det.check(&msg) {
                fired = Some(a);
            }
        }
        let a = fired.expect("15 REGISTERs in 1.5s of capture time is a flood and must fire");
        assert_eq!(a.detection_method, "behavioral");
    }

    /// A genuine sweep inside one window still fires as enumeration.
    #[test]
    fn a_real_sweep_inside_one_packet_time_window_still_fires() {
        let mut det = ScannerDetector::new(&[]);
        let src = scanner_ip();
        let mut fired = None;
        for i in 0..8 {
            let msg = request_at(
                "OPTIONS",
                &format!("ext{i:04}"),
                src,
                i,
                ts() + chrono::TimeDelta::milliseconds(i as i64 * 100),
            );
            if let Some(a) = det.check(&msg) {
                fired = Some(a);
            }
        }
        let a = fired.expect("8 distinct targets in 0.8s of capture time is enumeration");
        assert_eq!(a.detection_method, "enumeration");
    }

    /// `sweep` ages entries out on capture time as well — in both directions.
    ///
    /// The two assertions pin the two ways a wrong clock goes wrong, and
    /// neither alone is enough. An `Instant`-paced sweep retains everything:
    /// offline the wall clock barely advances between the first packet and the
    /// last, so nothing is ever old enough to drop, however long ago the
    /// capture says the source went quiet. A `Utc::now()`-paced sweep does the
    /// opposite on any capture that is not from today — every source is years
    /// idle the moment it is read, so the sweep empties the map and the
    /// detector forgets a scanner mid-scan.
    #[test]
    fn sweep_ages_entries_out_on_packet_time() {
        let mut det = ScannerDetector::new(&[]);
        let (quiet, active) = (scanner_ip(), localhost());
        let _ = det.check(&request_at("REGISTER", "u", quiet, 0, at(0)));
        assert_eq!(det.behavioral.len(), 1, "the source must be tracked");

        // A packet 10 minutes later in capture time, then a 2-minute sweep.
        let _ = det.check(&request_at("REGISTER", "u", active, 1, at(600)));
        det.sweep(std::time::Duration::from_secs(120));
        assert!(
            !det.behavioral.contains_key(&quiet),
            "a source last seen 600s ago in capture time must not survive a 120s sweep"
        );
        assert!(
            det.behavioral.contains_key(&active),
            "the source that sent the most recent packet is 0s idle in capture time and \
             must survive — a sweep aged against `Utc::now()` drops it, because a capture \
             recorded before today is already older than any max_age"
        );
    }

    /// SIP responses are ignored (only requests are checked).
    #[test]
    fn response_messages_ignored() {
        let mut detector = ScannerDetector::new(&[]);
        let raw = build_sip(
            "SIP/2.0 200 OK",
            &[
                "From: <sip:alice@example.com>;tag=t1",
                "To: <sip:bob@example.com>;tag=t2",
                "Call-ID: resp-test@example.com",
                "CSeq: 1 OPTIONS",
                "User-Agent: friendly-scanner",
                "Content-Length: 0",
            ],
            b"",
        );
        let msg = parse_sip(
            &raw,
            ts(),
            scanner_ip(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("parse");
        assert!(
            detector.check(&msg).is_none(),
            "responses should not trigger scanner alerts"
        );
    }
}
