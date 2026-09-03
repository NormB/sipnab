// SPDX-License-Identifier: MIT OR Apache-2.0

//! Detection and diagnosis thresholds reach the run that enforces them.
//!
//! Every threshold here used to be a parameter with a doc comment describing
//! when to change it and no production caller that ever supplied one:
//! `RegFloodDetector::new(0)`, `FraudDetector::new(None)`,
//! `AsymmetryThresholds::default()`, `LintConfig::new()`. Each would pass a
//! unit test of its resolver and change nothing an operator sees.
//!
//! So every test in this file drives the REAL BINARY over a capture built to
//! sit between the shipped value and the declared one, and observes what
//! sipnab REPORTS. A run that ignored the key would print the same thing
//! twice, which is what these assertions are looking for.
//!
//! Precedence is asserted alongside: the flag must beat the config key, the
//! same rule `--limit` and `[limits] dialog_limit` follow.
#![cfg(feature = "native")]

use std::io::Write;
use std::path::{Path, PathBuf};

#[path = "support/pcap_build.rs"]
mod pcap_build;
#[path = "support/run.rs"]
mod run_support;

use pcap_build::{invite_without_max_forwards, udp_frame, write_pcap_at};

/// Caller side of every synthetic capture here.
const A: [u8; 4] = [10, 1, 0, 1];
/// Callee side of every synthetic capture here.
const B: [u8; 4] = [10, 2, 0, 1];
/// A third peer, used where a scanner capture needs one WORKING source
/// alongside the one under examination.
///
/// The unanswered half of the scanner's probing test stands down until the
/// detector has seen a response exist at all — in a capture of requests alone
/// every probe ever sent looks unanswered. So a capture whose subject is never
/// answered still needs somebody else's answered exchange in it.
const C: [u8; 4] = [10, 3, 0, 1];

/// Run sipnab with `SIPNAB_LOG=warn`, returning `(stdout, stderr)`.
///
/// Alerts are emitted through `tracing` at WARN, so stderr is where a
/// detection shows up; diagnoses come back on stdout as NDJSON.
///
/// # Side effects
/// Spawns the compiled `sipnab` binary as a subprocess.
fn run(args: &[&str]) -> (String, String) {
    let (stdout, stderr, code) = run_support::run(args, Some("warn"));
    assert_eq!(code, Some(0), "sipnab must exit cleanly; stderr:\n{stderr}");
    (stdout, stderr)
}

/// Write `content` as `sipnab.toml` inside `dir` and return its path.
///
/// # Side effects
/// Creates a file under the caller's tempdir.
fn write_config(dir: &tempfile::TempDir, content: &str) -> PathBuf {
    let path = dir.path().join("sipnab.toml");
    let mut f = std::fs::File::create(&path).expect("create config");
    write!(f, "{content}").expect("write config");
    path
}

/// Write `frames` (payload, microseconds from capture start) as a pcap.
///
/// # Side effects
/// Creates `<name>.pcap` under the caller's tempdir.
fn write_capture(dir: &tempfile::TempDir, name: &str, frames: &[(Vec<u8>, u64)]) -> PathBuf {
    let path = dir.path().join(format!("{name}.pcap"));
    write_pcap_at(&path, frames, 1);
    path
}

/// The path as the CLI takes it.
fn arg(path: &Path) -> String {
    path.to_str().expect("utf-8 path").to_string()
}

// ── SIP message builders ────────────────────────────────────────────────

/// A credentialed `REGISTER` from the caller, numbered so each has its own
/// Call-ID and transaction branch. The `Authorization` header is what makes
/// the registrar's 401 a refusal rather than the challenge every registration
/// opens with.
fn register(i: usize) -> Vec<u8> {
    let msg = format!(
        "REGISTER sip:10.2.0.1 SIP/2.0\r\n\
         Via: SIP/2.0/UDP 10.1.0.1:5060;branch=z9hG4bKreg{i}\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:alice@10.1.0.1>;tag=treg{i}\r\n\
         To: <sip:alice@10.2.0.1>\r\n\
         Call-ID: reg-{i}@10.1.0.1\r\n\
         CSeq: 1 REGISTER\r\n\
         Contact: <sip:alice@10.1.0.1:5060>\r\n\
         Authorization: Digest username=\"alice\", realm=\"10.2.0.1\", nonce=\"abc\", \
         uri=\"sip:10.2.0.1\", response=\"0000\"\r\n\
         Content-Length: 0\r\n\r\n"
    );
    udp_frame(A, B, 5060, 5060, msg.as_bytes())
}

/// The registrar refusing `register(i)`: a 401 on the same transaction.
fn refused_register(i: usize) -> Vec<u8> {
    response(
        401,
        "Unauthorized",
        &format!("reg-{i}@10.1.0.1"),
        &format!("reg{i}"),
        "alice",
        "1 REGISTER",
        None,
        true,
    )
}

/// An `INVITE` to `to_user`, optionally carrying an SDP offer.
fn invite(call_id: &str, branch: &str, to_user: &str, sdp: Option<&str>) -> Vec<u8> {
    let body = sdp.unwrap_or("");
    let ctype = if body.is_empty() {
        String::new()
    } else {
        "Content-Type: application/sdp\r\n".to_string()
    };
    let msg = format!(
        "INVITE sip:{to_user}@10.2.0.1 SIP/2.0\r\n\
         Via: SIP/2.0/UDP 10.1.0.1:5060;branch=z9hG4bK{branch}\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:alice@10.1.0.1>;tag=t{branch}\r\n\
         To: <sip:{to_user}@10.2.0.1>\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: 1 INVITE\r\n\
         Contact: <sip:alice@10.1.0.1:5060>\r\n\
         {ctype}Content-Length: {}\r\n\r\n{body}",
        body.len()
    );
    udp_frame(A, B, 5060, 5060, msg.as_bytes())
}

/// A response from the callee. `to_tag` off is how a `100 Trying` arrives.
///
/// Eight parameters because a SIP response has eight independent parts a test
/// needs to choose, and bundling them behind a struct would put the fixture
/// one indirection away from the wire text it produces — which is the thing
/// being read when one of these tests fails.
#[expect(clippy::too_many_arguments)]
fn response(
    code: u16,
    reason: &str,
    call_id: &str,
    branch: &str,
    to_user: &str,
    cseq: &str,
    sdp: Option<&str>,
    to_tag: bool,
) -> Vec<u8> {
    let body = sdp.unwrap_or("");
    let ctype = if body.is_empty() {
        String::new()
    } else {
        "Content-Type: application/sdp\r\n".to_string()
    };
    let tag = if to_tag {
        format!(";tag=tt{branch}")
    } else {
        String::new()
    };
    let msg = format!(
        "SIP/2.0 {code} {reason}\r\n\
         Via: SIP/2.0/UDP 10.1.0.1:5060;branch=z9hG4bK{branch}\r\n\
         From: <sip:alice@10.1.0.1>;tag=t{branch}\r\n\
         To: <sip:{to_user}@10.2.0.1>{tag}\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: {cseq}\r\n\
         Contact: <sip:{to_user}@10.2.0.1:5060>\r\n\
         {ctype}Content-Length: {}\r\n\r\n{body}",
        body.len()
    );
    udp_frame(B, A, 5060, 5060, msg.as_bytes())
}

/// An in-dialog request from the caller (`ACK`, `BYE`).
fn in_dialog(method: &str, call_id: &str, branch: &str, to_user: &str, cseq: &str) -> Vec<u8> {
    let msg = format!(
        "{method} sip:{to_user}@10.2.0.1 SIP/2.0\r\n\
         Via: SIP/2.0/UDP 10.1.0.1:5060;branch=z9hG4bK{branch}\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:alice@10.1.0.1>;tag=t{branch}\r\n\
         To: <sip:{to_user}@10.2.0.1>;tag=tt{branch}\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: {cseq}\r\n\
         Content-Length: 0\r\n\r\n"
    );
    udp_frame(A, B, 5060, 5060, msg.as_bytes())
}

/// One answered call: `INVITE`, `200`, `ACK`, `BYE`, `200`.
///
/// `hangup_us` is when the `BYE` goes out, so the caller chooses the call's
/// measured duration — which is the whole input to the short-call threshold.
fn answered_call(
    call_id: &str,
    branch: &str,
    to_user: &str,
    start_us: u64,
    hangup_us: u64,
) -> Vec<(Vec<u8>, u64)> {
    vec![
        (invite(call_id, branch, to_user, None), start_us),
        (
            response(200, "OK", call_id, branch, to_user, "1 INVITE", None, true),
            start_us + 50_000,
        ),
        (
            in_dialog("ACK", call_id, branch, to_user, "1 ACK"),
            start_us + 100_000,
        ),
        (
            in_dialog("BYE", call_id, branch, to_user, "2 BYE"),
            start_us + hangup_us,
        ),
        (
            response(200, "OK", call_id, branch, to_user, "2 BYE", None, true),
            start_us + hangup_us + 50_000,
        ),
    ]
}

/// One call the network refused: `INVITE`, `404`, `ACK`.
fn refused_call(call_id: &str, branch: &str, to_user: &str, start_us: u64) -> Vec<(Vec<u8>, u64)> {
    vec![
        (invite(call_id, branch, to_user, None), start_us),
        (
            response(
                404,
                "Not Found",
                call_id,
                branch,
                to_user,
                "1 INVITE",
                None,
                true,
            ),
            start_us + 50_000,
        ),
        (
            in_dialog("ACK", call_id, branch, to_user, "1 ACK"),
            start_us + 100_000,
        ),
    ]
}

/// Whether stderr carries a fired alert of `kind`.
fn alerted(stderr: &str, kind: &str) -> bool {
    stderr
        .lines()
        .any(|l| l.contains("[ALERT]") && l.contains(kind))
}

// ── SIP probe builders for the scanner detector ─────────────────────────

/// A probe of `method` at `to_user` from `src`, carrying the top `Via` branch
/// a response echoes back.
///
/// The branch is what ties a response to the request it answers, and every
/// scanner signal now rests on that tie: a probe with no settled outcome counts
/// toward the rate and toward nothing else.
fn probe(src: [u8; 4], method: &str, to_user: &str, branch: &str) -> Vec<u8> {
    let msg = format!(
        "{method} sip:{to_user}@10.2.0.1 SIP/2.0\r\n\
         Via: SIP/2.0/UDP 10.9.0.1:5060;branch=z9hG4bK{branch}\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:probe@10.9.0.1>;tag=f{branch}\r\n\
         To: <sip:{to_user}@10.2.0.1>\r\n\
         Call-ID: {branch}@10.9.0.1\r\n\
         CSeq: 1 {method}\r\n\
         Content-Length: 0\r\n\r\n"
    );
    udp_frame(src, B, 5060, 5060, msg.as_bytes())
}

/// The answer `code` sent back to `dst` on transaction `branch`.
///
/// Addressed deliberately: a response travels back the way the request came, so
/// its DESTINATION is the source whose probe it settles.
fn answer(dst: [u8; 4], code: u16, method: &str, to_user: &str, branch: &str) -> Vec<u8> {
    let msg = format!(
        "SIP/2.0 {code} Whatever\r\n\
         Via: SIP/2.0/UDP 10.9.0.1:5060;branch=z9hG4bK{branch}\r\n\
         From: <sip:probe@10.9.0.1>;tag=f{branch}\r\n\
         To: <sip:{to_user}@10.2.0.1>;tag=t{branch}\r\n\
         Call-ID: {branch}@10.9.0.1\r\n\
         CSeq: 1 {method}\r\n\
         Content-Length: 0\r\n\r\n"
    );
    udp_frame(B, dst, 5060, 5060, msg.as_bytes())
}

/// One working peer's answered keepalive, at the very start of the capture.
///
/// Arms the unanswered test without putting a single packet on the account of
/// the source the test is about — see [`C`].
fn working_peer_keepalive() -> Vec<(Vec<u8>, u64)> {
    vec![
        (probe(C, "OPTIONS", "trunk", "-arm"), 0),
        (answer(C, 200, "OPTIONS", "trunk", "-arm"), 10_000),
    ]
}

/// Run the scanner detector over `pcap` with `extra` arguments, returning
/// stderr.
///
/// `--kill-scanner` is what builds the detector; offline it only reports, and
/// never transmits.
fn scan(pcap: &str, extra: &[&str]) -> String {
    let mut args = vec!["-N", "-I", pcap, "--kill-scanner"];
    args.extend_from_slice(extra);
    run(&args).1
}

// ── [security] reg_flood_threshold ──────────────────────────────────────

/// The declared failure rate is what decides whether a burst is a flood.
///
/// Five credentialed REGISTERs, each refused, land inside one window. The
/// shipped 50/s cannot see them — which is the complaint: 50/s is a
/// carrier-registrar figure and a small PBX is brute-forced at ten. A
/// declared 2/s does see them.
#[test]
fn reg_flood_threshold_decides_when_a_burst_is_a_flood() {
    let dir = tempfile::tempdir().expect("tempdir");
    let frames: Vec<(Vec<u8>, u64)> = (0..5)
        .flat_map(|i| {
            let at = i as u64 * 10_000;
            [(register(i), at), (refused_register(i), at + 1_000)]
        })
        .collect();
    let pcap = arg(&write_capture(&dir, "regflood", &frames));
    let cfg = arg(&write_config(&dir, "[security]\nreg_flood_threshold = 2\n"));

    let (_, shipped) = run(&["-N", "-I", &pcap, "--reg-flood", "--no-config"]);
    assert!(
        !alerted(&shipped, "reg_flood"),
        "five REGISTERs are below the shipped 50/s, so nothing should fire:\n{shipped}"
    );

    let (_, declared) = run(&["-N", "-I", &pcap, "--reg-flood", "--config", &cfg]);
    assert!(
        alerted(&declared, "reg_flood"),
        "[security] reg_flood_threshold = 2 must reach the detector:\n{declared}"
    );

    let (_, overridden) = run(&[
        "-N",
        "-I",
        &pcap,
        "--reg-flood",
        "--reg-flood-threshold",
        "200",
        "--config",
        &cfg,
    ]);
    assert!(
        !alerted(&overridden, "reg_flood"),
        "--reg-flood-threshold must beat the config key:\n{overridden}"
    );
}

// ── [security] fraud_* ──────────────────────────────────────────────────

/// The declared short-call duration decides which calls count as lures.
///
/// Three two-second calls to one prefix. Under the shipped three seconds they
/// are short, and three short calls to a prefix is wangiri. Declaring one
/// second — the case that matters, a carrier whose ring-no-answer clears
/// faster than the shipped default assumes — makes them ordinary calls.
#[test]
fn fraud_short_call_secs_decides_which_calls_are_short() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut frames = Vec::new();
    for i in 0..3u64 {
        frames.extend(answered_call(
            &format!("wangiri-{i}"),
            &format!("w{i}"),
            &format!("1555100{i}"),
            i * 10_000_000,
            2_000_000,
        ));
    }
    let pcap = arg(&write_capture(&dir, "wangiri3", &frames));
    let cfg = arg(&write_config(
        &dir,
        "[security]\nfraud_short_call_secs = 1\n",
    ));

    let (_, shipped) = run(&["-N", "-I", &pcap, "--fraud-detect", "--no-config"]);
    assert!(
        alerted(&shipped, "Wangiri"),
        "two-second calls are short under the shipped three, so three of them \
         to one prefix must raise wangiri:\n{shipped}"
    );

    let (_, declared) = run(&["-N", "-I", &pcap, "--fraud-detect", "--config", &cfg]);
    assert!(
        !alerted(&declared, "Wangiri"),
        "[security] fraud_short_call_secs = 1 must make a two-second call \
         ordinary:\n{declared}"
    );

    let (_, overridden) = run(&[
        "-N",
        "-I",
        &pcap,
        "--fraud-detect",
        "--fraud-short-call",
        "5",
        "--config",
        &cfg,
    ]);
    assert!(
        alerted(&overridden, "Wangiri"),
        "--fraud-short-call must beat the config key:\n{overridden}"
    );
}

/// The declared count decides how many short calls make a lure.
#[test]
fn fraud_wangiri_calls_decides_how_many_short_calls_are_a_lure() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut frames = Vec::new();
    for i in 0..2u64 {
        frames.extend(answered_call(
            &format!("wangiri-{i}"),
            &format!("w{i}"),
            &format!("1555100{i}"),
            i * 10_000_000,
            1_000_000,
        ));
    }
    let pcap = arg(&write_capture(&dir, "wangiri2", &frames));
    let cfg = arg(&write_config(&dir, "[security]\nfraud_wangiri_calls = 2\n"));

    let (_, shipped) = run(&["-N", "-I", &pcap, "--fraud-detect", "--no-config"]);
    assert!(
        !alerted(&shipped, "Wangiri"),
        "two short calls are below the shipped three:\n{shipped}"
    );

    let (_, declared) = run(&["-N", "-I", &pcap, "--fraud-detect", "--config", &cfg]);
    assert!(
        alerted(&declared, "Wangiri"),
        "[security] fraud_wangiri_calls = 2 must reach the detector:\n{declared}"
    );

    let (_, overridden) = run(&[
        "-N",
        "-I",
        &pcap,
        "--fraud-detect",
        "--fraud-wangiri-calls",
        "9",
        "--config",
        &cfg,
    ]);
    assert!(
        !alerted(&overridden, "Wangiri"),
        "--fraud-wangiri-calls must beat the config key:\n{overridden}"
    );
}

/// The declared run length decides how long a dial-plan walk must be.
#[test]
fn fraud_sequential_calls_decides_how_long_a_scan_must_be() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut frames = Vec::new();
    for i in 0..2u64 {
        frames.extend(refused_call(
            &format!("seq-{i}"),
            &format!("s{i}"),
            &format!("1555100{}", i + 1),
            i * 5_000_000,
        ));
    }
    let pcap = arg(&write_capture(&dir, "sequential", &frames));
    let cfg = arg(&write_config(
        &dir,
        "[security]\nfraud_sequential_calls = 2\n",
    ));

    let (_, shipped) = run(&["-N", "-I", &pcap, "--fraud-detect", "--no-config"]);
    assert!(
        !alerted(&shipped, "SequentialScanning"),
        "two consecutive refusals are below the shipped three:\n{shipped}"
    );

    let (_, declared) = run(&["-N", "-I", &pcap, "--fraud-detect", "--config", &cfg]);
    assert!(
        alerted(&declared, "SequentialScanning"),
        "[security] fraud_sequential_calls = 2 must reach the detector:\n{declared}"
    );

    let (_, overridden) = run(&[
        "-N",
        "-I",
        &pcap,
        "--fraud-detect",
        "--fraud-sequential-calls",
        "9",
        "--config",
        &cfg,
    ]);
    assert!(
        !alerted(&overridden, "SequentialScanning"),
        "--fraud-sequential-calls must beat the config key:\n{overridden}"
    );
}

/// Narrowing the VOLUME window must not narrow sequential scanning with it.
///
/// The refused calls a dial-plan walk is read from were pruned by the volume
/// window, which was invisible while both were compiled-in 60-second figures
/// and shared one helper. Making the volume window settable would have made
/// that sharing a live coupling: an operator narrowing the window to catch a
/// burst shorter than a minute would, without being told, have shortened the
/// run a dial-plan walk has to make. The two questions are unrelated — a walk
/// is defined by the numbers being consecutive, not by any rate — so they now
/// have separate windows and this pins them apart.
#[test]
fn a_narrow_volume_window_leaves_sequential_scanning_alone() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut frames = Vec::new();
    for i in 0..3u64 {
        frames.extend(refused_call(
            &format!("wide-seq-{i}"),
            &format!("w{i}"),
            &format!("1555300{}", i + 1),
            i * 15_000_000,
        ));
    }
    let pcap = arg(&write_capture(&dir, "widescan", &frames));

    let (_, shipped) = run(&["-N", "-I", &pcap, "--fraud-detect", "--no-config"]);
    assert!(
        alerted(&shipped, "SequentialScanning"),
        "three consecutive dead numbers over 30s is the shipped detection, or \
         this test proves nothing:\n{shipped}"
    );

    let (_, narrowed) = run(&[
        "-N",
        "-I",
        &pcap,
        "--fraud-detect",
        "--fraud-volume-window",
        "5",
        "--no-config",
    ]);
    assert!(
        alerted(&narrowed, "SequentialScanning"),
        "--fraud-volume-window 5 asks a question about bursts and must not \
         shorten the run a dial-plan walk has to make:\n{narrowed}"
    );
}

/// A capture that establishes a baseline of two calls a minute and then places
/// fifteen in the next one.
///
/// The source has to complete a window before it has a baseline to depart
/// from, so the first two calls are what makes the burst measurable at all.
/// Bare `INVITE`s: nothing terminates, so neither the wangiri nor the
/// sequential detector can claim the alert instead.
fn volume_spike_capture(dir: &tempfile::TempDir) -> String {
    let mut frames = Vec::new();
    let mut n = 0usize;
    for secs in [0u64, 5] {
        frames.push((
            invite(&format!("vol-{n}"), &format!("v{n}"), "2000", None),
            secs * 1_000_000,
        ));
        n += 1;
    }
    for secs in 61u64..76 {
        frames.push((
            invite(&format!("vol-{n}"), &format!("v{n}"), "2000", None),
            secs * 1_000_000,
        ));
        n += 1;
    }
    arg(&write_capture(dir, "volume", &frames))
}

/// The declared multiple decides how far above its own baseline a source has
/// to go.
#[test]
fn fraud_volume_multiplier_decides_how_big_a_spike_must_be() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pcap = volume_spike_capture(&dir);
    let cfg = arg(&write_config(
        &dir,
        "[security]\nfraud_volume_multiplier = 10\n",
    ));

    let (_, shipped) = run(&["-N", "-I", &pcap, "--fraud-detect", "--no-config"]);
    assert!(
        alerted(&shipped, "VolumeSpike"),
        "fifteen calls against a baseline of two clears the shipped 5x:\n{shipped}"
    );

    let (_, declared) = run(&["-N", "-I", &pcap, "--fraud-detect", "--config", &cfg]);
    assert!(
        !alerted(&declared, "VolumeSpike"),
        "[security] fraud_volume_multiplier = 10 needs 20 calls, and there are \
         fifteen:\n{declared}"
    );

    let (_, overridden) = run(&[
        "-N",
        "-I",
        &pcap,
        "--fraud-detect",
        "--fraud-volume-multiplier",
        "2",
        "--config",
        &cfg,
    ]);
    assert!(
        alerted(&overridden, "VolumeSpike"),
        "--fraud-volume-multiplier must beat the config key:\n{overridden}"
    );
}

/// The declared floor decides how few calls are too few to call a spike.
#[test]
fn fraud_volume_min_calls_decides_the_floor_under_a_spike() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pcap = volume_spike_capture(&dir);
    let cfg = arg(&write_config(
        &dir,
        "[security]\nfraud_volume_min_calls = 40\n",
    ));

    let (_, shipped) = run(&["-N", "-I", &pcap, "--fraud-detect", "--no-config"]);
    assert!(
        alerted(&shipped, "VolumeSpike"),
        "fifteen calls is over the shipped floor of six:\n{shipped}"
    );

    let (_, declared) = run(&["-N", "-I", &pcap, "--fraud-detect", "--config", &cfg]);
    assert!(
        !alerted(&declared, "VolumeSpike"),
        "[security] fraud_volume_min_calls = 40 must silence a fifteen-call \
         window:\n{declared}"
    );

    let (_, overridden) = run(&[
        "-N",
        "-I",
        &pcap,
        "--fraud-detect",
        "--fraud-volume-min-calls",
        "6",
        "--config",
        &cfg,
    ]);
    assert!(
        alerted(&overridden, "VolumeSpike"),
        "--fraud-volume-min-calls must beat the config key:\n{overridden}"
    );
}

/// The declared wangiri window decides whether a PACED lure is visible at all.
///
/// Three short calls to one prefix, five minutes apart. That spacing is the
/// pattern's real shape on a trunk — a lure firing three times a minute is one
/// somebody has already blocked — and the shipped sixty-second window holds
/// exactly one of the three at a time. The count cannot rescue it: the only
/// setting that reports anything here is one short call, which reports every
/// ordinary short call anywhere in the capture as a lure too.
///
/// This test also pins the sweep age, which is the coupling that makes the
/// window settable rather than merely declared. Detector state is swept on a
/// fixed schedule, and a sweep that ages short calls out at 120 seconds
/// truncates a 900-second window to 120 whatever the operator declared — so a
/// run whose sweep age is a constant reports nothing here even with the window
/// wired. The sweep age is derived from the widest configured window instead.
#[test]
fn fraud_wangiri_window_secs_decides_whether_a_paced_lure_is_visible() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut frames = Vec::new();
    for i in 0..3u64 {
        frames.extend(answered_call(
            &format!("paced-{i}"),
            &format!("p{i}"),
            &format!("1555200{i}"),
            i * 300_000_000,
            1_000_000,
        ));
    }
    let pcap = arg(&write_capture(&dir, "pacedlure", &frames));
    let cfg = arg(&write_config(
        &dir,
        "[security]\nfraud_wangiri_window_secs = 900\n",
    ));

    let (_, shipped) = run(&["-N", "-I", &pcap, "--fraud-detect", "--no-config"]);
    assert!(
        !alerted(&shipped, "Wangiri"),
        "five minutes apart, the shipped sixty-second window never holds two \
         of these at once:\n{shipped}"
    );

    let (_, declared) = run(&["-N", "-I", &pcap, "--fraud-detect", "--config", &cfg]);
    assert!(
        alerted(&declared, "Wangiri"),
        "[security] fraud_wangiri_window_secs = 900 must both reach the \
         detector and outlast the state sweep:\n{declared}"
    );

    let (_, overridden) = run(&[
        "-N",
        "-I",
        &pcap,
        "--fraud-detect",
        "--fraud-wangiri-window",
        "60",
        "--config",
        &cfg,
    ]);
    assert!(
        !alerted(&overridden, "Wangiri"),
        "--fraud-wangiri-window must beat the config key:\n{overridden}"
    );
}

/// The declared volume window decides how concentrated a burst has to be.
///
/// A spike is a count measured against a baseline sampled over the same
/// window, so widening or narrowing the window moves both together and a
/// steady source reads the same at any width. What the width alone decides is
/// how short a burst can be and still stand out: forty calls in one second sit
/// inside a minute of ordinary one-a-second traffic and average away to
/// nothing, and only a window shorter than the burst separates them.
#[test]
fn fraud_volume_window_secs_decides_how_concentrated_a_burst_must_be() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut frames = Vec::new();
    let mut n = 0usize;
    // Seventy seconds of ordinary traffic at one call a second, which is what
    // the source's baseline is built from.
    for secs in 0u64..70 {
        frames.push((
            invite(&format!("steady-{n}"), &format!("s{n}"), "2000", None),
            secs * 1_000_000,
        ));
        n += 1;
    }
    // Forty calls inside one second, five seconds later.
    for i in 0u64..40 {
        frames.push((
            invite(&format!("burst-{n}"), &format!("b{n}"), "2000", None),
            75_000_000 + i * 20_000,
        ));
        n += 1;
    }
    let pcap = arg(&write_capture(&dir, "microburst", &frames));
    let cfg = arg(&write_config(
        &dir,
        "[security]\nfraud_volume_window_secs = 5\n",
    ));

    let (_, shipped) = run(&["-N", "-I", &pcap, "--fraud-detect", "--no-config"]);
    assert!(
        !alerted(&shipped, "VolumeSpike"),
        "the shipped sixty-second window already holds sixty ordinary calls, \
         so forty more inside one second is not five times anything:\n{shipped}"
    );

    let (_, declared) = run(&["-N", "-I", &pcap, "--fraud-detect", "--config", &cfg]);
    assert!(
        alerted(&declared, "VolumeSpike"),
        "[security] fraud_volume_window_secs = 5 measures the burst against \
         five seconds of ordinary traffic, not sixty:\n{declared}"
    );

    let (_, overridden) = run(&[
        "-N",
        "-I",
        &pcap,
        "--fraud-detect",
        "--fraud-volume-window",
        "60",
        "--config",
        &cfg,
    ]);
    assert!(
        !alerted(&overridden, "VolumeSpike"),
        "--fraud-volume-window must beat the config key:\n{overridden}"
    );
}

/// Declaring business hours is what makes the off-hours detection reachable.
///
/// Nothing else turns it on: with no window there is no "outside", so the
/// detector shipped with a documented detection that no run could produce.
/// The capture's fixed base timestamp falls at 22:13 UTC.
#[test]
fn business_hours_make_the_off_hours_detection_reachable() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pcap = arg(&write_capture(
        &dir,
        "offhours",
        &[(invite("oh-1", "o1", "3000", None), 0)],
    ));
    let cfg = arg(&write_config(
        &dir,
        "[security]\nbusiness_hours = \"8-18\"\n",
    ));

    let (_, shipped) = run(&["-N", "-I", &pcap, "--fraud-detect", "--no-config"]);
    assert!(
        !alerted(&shipped, "OffHours"),
        "with no window declared there is no outside:\n{shipped}"
    );

    let (_, declared) = run(&["-N", "-I", &pcap, "--fraud-detect", "--config", &cfg]);
    assert!(
        alerted(&declared, "OffHours"),
        "[security] business_hours must reach the detector; the capture is \
         stamped at 22:13 UTC:\n{declared}"
    );

    let (_, overridden) = run(&[
        "-N",
        "-I",
        &pcap,
        "--fraud-detect",
        "--business-hours",
        "20-23",
        "--config",
        &cfg,
    ]);
    assert!(
        !alerted(&overridden, "OffHours"),
        "--business-hours must beat the config key, and 22:13 is inside \
         20:00-23:00:\n{overridden}"
    );
}

/// A business-hours spec that is not two whole hours is refused by name.
#[test]
fn a_malformed_business_hours_spec_is_refused_by_name() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pcap = arg(&write_capture(
        &dir,
        "offhours",
        &[(invite("oh-1", "o1", "3000", None), 0)],
    ));
    for bad in ["8:30-18", "8", "8-99", "eight-six"] {
        let cfg = arg(&write_config(
            &dir,
            &format!("[security]\nbusiness_hours = \"{bad}\"\n"),
        ));
        let (_, stderr, code) =
            run_support::run(&["-N", "-I", &pcap, "--config", &cfg], Some("error"));
        assert_ne!(code, Some(0), "{bad:?} must fail the run");
        assert!(
            stderr.contains("business_hours"),
            "the error must name the key; got {stderr}"
        );
    }
}

// ── [security] scanner_* ────────────────────────────────────────────────

/// The declared window is what decides whether a PACED sweep is visible at all.
///
/// This is the case no count can reach. Every scanner count is "per window", so
/// a source probing once every ten seconds has its window reset before the
/// second probe lands: its rate is one, its spread is one, and its refusal
/// count is one, whatever the counts are set to. The middle run pins that —
/// every count driven to its floor of 1, the window left alone, still reports
/// nothing.
#[test]
fn scanner_window_secs_decides_whether_a_paced_sweep_is_visible() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut frames = Vec::new();
    for i in 0..8u64 {
        let branch = format!("-slow-{i}");
        let target = format!("ext{i:04}");
        frames.push((probe(A, "OPTIONS", &target, &branch), i * 10_000_000));
        frames.push((
            answer(A, 404, "OPTIONS", &target, &branch),
            i * 10_000_000 + 50_000,
        ));
    }
    let pcap = arg(&write_capture(&dir, "slowsweep", &frames));
    let cfg = arg(&write_config(
        &dir,
        "[security]\nscanner_window_secs = 60\n",
    ));

    let shipped = scan(&pcap, &["--no-config"]);
    assert!(
        !alerted(&shipped, "detection="),
        "a probe every 10s never puts two in one 5s window, so the shipped \
         detector cannot see this sweep:\n{shipped}"
    );

    let floored = scan(
        &pcap,
        &[
            "--no-config",
            "--scanner-behavioral-probes",
            "1",
            "--scanner-enumeration-targets",
            "1",
            "--scanner-rejected-probes",
            "1",
            "--scanner-unanswered-probes",
            "1",
        ],
    );
    assert!(
        !alerted(&floored, "detection="),
        "with the window unchanged the counts cannot reach this sweep at ANY \
         setting — each probe opens a fresh window holding one probe, one target \
         and no settled outcome:\n{floored}"
    );

    let declared = scan(&pcap, &["--config", &cfg]);
    assert!(
        alerted(&declared, "detection=enumeration"),
        "[security] scanner_window_secs = 60 holds all eight probes at once, so \
         six distinct extensions and five refusals are in the window \
         together:\n{declared}"
    );

    let overridden = scan(&pcap, &["--scanner-window", "5", "--config", &cfg]);
    assert!(
        !alerted(&overridden, "detection="),
        "--scanner-window must beat the config key:\n{overridden}"
    );
}

/// The declared probe count decides when an aggregated rate is a scanner.
///
/// Behind an SBC every source collapses to one address, so ordinary aggregated
/// traffic clears the shipped ten probes in five seconds and the whole site is
/// reported as one scanner.
#[test]
fn scanner_behavioral_probes_decides_when_an_aggregated_rate_is_a_scanner() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut frames = Vec::new();
    for i in 0..15u64 {
        let branch = format!("-agg-{i}");
        frames.push((probe(A, "REGISTER", "1001", &branch), i * 100_000));
        frames.push((
            answer(A, 403, "REGISTER", "1001", &branch),
            i * 100_000 + 10_000,
        ));
    }
    let pcap = arg(&write_capture(&dir, "aggregated", &frames));
    let cfg = arg(&write_config(
        &dir,
        "[security]\nscanner_behavioral_probes = 100\n",
    ));

    let shipped = scan(&pcap, &["--no-config"]);
    assert!(
        alerted(&shipped, "detection=behavioral"),
        "fifteen refused REGISTERs in 1.5s clears the shipped ten:\n{shipped}"
    );

    let declared = scan(&pcap, &["--config", &cfg]);
    assert!(
        !alerted(&declared, "detection="),
        "[security] scanner_behavioral_probes = 100 must reach the \
         detector:\n{declared}"
    );

    let overridden = scan(
        &pcap,
        &["--scanner-behavioral-probes", "10", "--config", &cfg],
    );
    assert!(
        alerted(&overridden, "detection=behavioral"),
        "--scanner-behavioral-probes must beat the config key:\n{overridden}"
    );
}

/// The declared target count decides how wide a sweep has to be.
#[test]
fn scanner_enumeration_targets_decides_how_wide_a_sweep_must_be() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut frames = Vec::new();
    for i in 0..8u64 {
        let branch = format!("-wide-{i}");
        let target = format!("ext{i:04}");
        frames.push((probe(A, "INVITE", &target, &branch), i * 100_000));
        frames.push((
            answer(A, 404, "INVITE", &target, &branch),
            i * 100_000 + 10_000,
        ));
    }
    let pcap = arg(&write_capture(&dir, "widesweep", &frames));
    let cfg = arg(&write_config(
        &dir,
        "[security]\nscanner_enumeration_targets = 50\n",
    ));

    let shipped = scan(&pcap, &["--no-config"]);
    assert!(
        alerted(&shipped, "detection=enumeration"),
        "eight extensions, none of them found, clears the shipped five:\n{shipped}"
    );

    let declared = scan(&pcap, &["--config", &cfg]);
    assert!(
        !alerted(&declared, "detection="),
        "an SBC fronting a large hunt group reaches dozens of extensions a \
         second, so fifty must reach the detector:\n{declared}"
    );

    let overridden = scan(
        &pcap,
        &["--scanner-enumeration-targets", "5", "--config", &cfg],
    );
    assert!(
        alerted(&overridden, "detection=enumeration"),
        "--scanner-enumeration-targets must beat the config key:\n{overridden}"
    );
}

/// The declared refusal count decides how much saying no is evidence.
#[test]
fn scanner_rejected_probes_decides_how_much_refusal_is_evidence() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut frames = Vec::new();
    for i in 0..12u64 {
        let branch = format!("-crack-{i}");
        frames.push((probe(A, "REGISTER", "1001", &branch), i * 100_000));
        frames.push((
            answer(A, 403, "REGISTER", "1001", &branch),
            i * 100_000 + 10_000,
        ));
    }
    let pcap = arg(&write_capture(&dir, "refused", &frames));
    let cfg = arg(&write_config(
        &dir,
        "[security]\nscanner_rejected_probes = 20\n",
    ));

    let shipped = scan(&pcap, &["--no-config"]);
    assert!(
        alerted(&shipped, "detection=behavioral"),
        "twelve refusals clears the shipped five, which is what makes the rate \
         reportable:\n{shipped}"
    );

    let declared = scan(&pcap, &["--config", &cfg]);
    assert!(
        !alerted(&declared, "detection="),
        "a registrar that refuses every unauthenticated first attempt earns \
         refusals all day, so twenty must reach the detector:\n{declared}"
    );

    let overridden = scan(&pcap, &["--scanner-rejected-probes", "5", "--config", &cfg]);
    assert!(
        alerted(&overridden, "detection=behavioral"),
        "--scanner-rejected-probes must beat the config key:\n{overridden}"
    );
}

/// The declared unanswered count decides how much silence is evidence.
#[test]
fn scanner_unanswered_probes_decides_how_much_silence_is_evidence() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut frames = working_peer_keepalive();
    for i in 0..15u64 {
        frames.push((
            probe(A, "REGISTER", "victim", &format!("-hole-{i}")),
            100_000 + i * 100_000,
        ));
    }
    let pcap = arg(&write_capture(&dir, "hole", &frames));
    let cfg = arg(&write_config(
        &dir,
        "[security]\nscanner_unanswered_probes = 40\n",
    ));

    let shipped = scan(&pcap, &["--no-config"]);
    assert!(
        alerted(&shipped, "detection=behavioral"),
        "fifteen probes nothing answered clears the shipped five:\n{shipped}"
    );

    let declared = scan(&pcap, &["--config", &cfg]);
    assert!(
        !alerted(&declared, "detection="),
        "[security] scanner_unanswered_probes = 40 must reach the \
         detector:\n{declared}"
    );

    let overridden = scan(
        &pcap,
        &["--scanner-unanswered-probes", "5", "--config", &cfg],
    );
    assert!(
        alerted(&overridden, "detection=behavioral"),
        "--scanner-unanswered-probes must beat the config key:\n{overridden}"
    );
}

/// The declared factor decides what completing a registration buys a peer.
#[test]
fn scanner_established_factor_decides_what_a_registration_buys() {
    let dir = tempfile::tempdir().expect("tempdir");
    // The registration that makes A a peer we serve: a REGISTER, its challenge,
    // the authenticated retry, and the 200 OK.
    let mut frames = vec![
        (probe(A, "REGISTER", "alice", "-reg-a"), 0),
        (answer(A, 401, "REGISTER", "alice", "-reg-a"), 20_000),
        (probe(A, "REGISTER", "alice", "-reg-b"), 40_000),
        (answer(A, 200, "REGISTER", "alice", "-reg-b"), 60_000),
    ];
    for i in 0..10u64 {
        let branch = format!("-comp-{i}");
        let target = format!("ext{i:04}");
        frames.push((probe(A, "INVITE", &target, &branch), 100_000 + i * 100_000));
        frames.push((
            answer(A, 404, "INVITE", &target, &branch),
            110_000 + i * 100_000,
        ));
    }
    let pcap = arg(&write_capture(&dir, "compromised", &frames));
    let cfg = arg(&write_config(
        &dir,
        "[security]\nscanner_established_factor = 1\n",
    ));

    let shipped = scan(&pcap, &["--no-config"]);
    assert!(
        !alerted(&shipped, "detection="),
        "a registered peer needs four times the evidence, and ten refusals is \
         twice:\n{shipped}"
    );

    let declared = scan(&pcap, &["--config", &cfg]);
    assert!(
        alerted(&declared, "detection=enumeration"),
        "[security] scanner_established_factor = 1 grants a registration no \
         extra credit, and ten dead extensions is a dialplan walk:\n{declared}"
    );

    let overridden = scan(
        &pcap,
        &["--scanner-established-factor", "4", "--config", &cfg],
    );
    assert!(
        !alerted(&overridden, "detection="),
        "--scanner-established-factor must beat the config key:\n{overridden}"
    );
}

/// The declared answer grace decides how slow a link may be.
///
/// The shipped 500 ms is RFC 3261's Timer T1. A link whose round trip is longer
/// than that has every probe outstanding when the next goes out, so an ordinary
/// working peer reads as a sweep into a hole.
#[test]
fn scanner_answer_grace_ms_decides_how_slow_a_link_may_be() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut frames = working_peer_keepalive();
    for i in 0..15u64 {
        let branch = format!("-slowlink-{i}");
        frames.push((probe(A, "REGISTER", "1001", &branch), 100_000 + i * 100_000));
        frames.push((
            answer(A, 200, "REGISTER", "1001", &branch),
            2_100_000 + i * 100_000,
        ));
    }
    frames.sort_by_key(|(_, t)| *t);
    let pcap = arg(&write_capture(&dir, "slowlink", &frames));
    let cfg = arg(&write_config(
        &dir,
        "[security]\nscanner_answer_grace_ms = 3000\n",
    ));

    let shipped = scan(&pcap, &["--no-config"]);
    assert!(
        alerted(&shipped, "detection=behavioral"),
        "under a 500 ms grace every probe on a 2s link is 'unanswered', so a \
         working peer is reported:\n{shipped}"
    );

    let declared = scan(&pcap, &["--config", &cfg]);
    assert!(
        !alerted(&declared, "detection="),
        "[security] scanner_answer_grace_ms = 3000 covers this link's round \
         trip, so nothing here was ever unanswered:\n{declared}"
    );

    let overridden = scan(&pcap, &["--scanner-answer-grace", "500", "--config", &cfg]);
    assert!(
        alerted(&overridden, "detection=behavioral"),
        "--scanner-answer-grace must beat the config key:\n{overridden}"
    );
}

/// A zero scanner threshold is refused by name rather than read as "off".
#[test]
fn a_zero_scanner_threshold_is_refused_by_name() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pcap = arg(&write_capture(
        &dir,
        "zero",
        &[(probe(A, "OPTIONS", "trunk", "-z"), 0)],
    ));
    for key in [
        "scanner_behavioral_probes",
        "scanner_enumeration_targets",
        "scanner_rejected_probes",
        "scanner_unanswered_probes",
        "scanner_window_secs",
        "scanner_established_factor",
        "scanner_answer_grace_ms",
    ] {
        let cfg = arg(&write_config(&dir, &format!("[security]\n{key} = 0\n")));
        let (_, stderr, code) = run_support::run(
            &["-N", "-I", &pcap, "--kill-scanner", "--config", &cfg],
            Some("error"),
        );
        assert_ne!(code, Some(0), "{key} = 0 must fail the run");
        assert!(
            stderr.contains(key),
            "the error must name the key; got {stderr}"
        );
    }
}

// ── [diagnosis] signaling thresholds ───────────────────────────────────

/// The declared post-dial delay budget is what decides a slow ring-back.
///
/// Five seconds to the `180`: inside E.721's international 95th-percentile
/// figure of eleven, outside a network that knows its calls are local.
#[test]
fn diagnosis_post_dial_delay_threshold_decides_a_slow_ringback() {
    let dir = tempfile::tempdir().expect("tempdir");
    let frames = vec![
        (invite("pdd-1", "p1", "bob", None), 0),
        (
            response(180, "Ringing", "pdd-1", "p1", "bob", "1 INVITE", None, true),
            5_000_000,
        ),
        (
            response(200, "OK", "pdd-1", "p1", "bob", "1 INVITE", None, true),
            5_500_000,
        ),
        (in_dialog("ACK", "pdd-1", "p1", "bob", "1 ACK"), 5_600_000),
        (in_dialog("BYE", "pdd-1", "p1", "bob", "2 BYE"), 8_000_000),
        (
            response(200, "OK", "pdd-1", "p1", "bob", "2 BYE", None, true),
            8_100_000,
        ),
    ];
    let pcap = arg(&write_capture(&dir, "pdd", &frames));
    let cfg = arg(&write_config(
        &dir,
        "[diagnosis]\npost_dial_delay_secs = 2.0\n",
    ));

    let (shipped, _) = run(&["-N", "-I", &pcap, "--json-dialogs", "--no-config"]);
    assert!(
        !shipped.contains("post_dial_delay"),
        "five seconds is inside the shipped 11 s:\n{shipped}"
    );

    let (declared, _) = run(&["-N", "-I", &pcap, "--json-dialogs", "--config", &cfg]);
    assert!(
        declared.contains("post_dial_delay"),
        "[diagnosis] post_dial_delay_secs = 2.0 must reach the diagnosis:\n{declared}"
    );

    let (overridden, _) = run(&[
        "-N",
        "-I",
        &pcap,
        "--json-dialogs",
        "--pdd-threshold",
        "30",
        "--config",
        &cfg,
    ]);
    assert!(
        !overridden.contains("post_dial_delay"),
        "--pdd-threshold must beat the config key:\n{overridden}"
    );
}

/// The declared `ACK` timeout is what turns an unacknowledged `200` into a
/// fault rather than a capture that stopped early.
///
/// The answer is retransmitted ten seconds on, which is the UAS's own evidence
/// that it never saw an `ACK` — and the last message of the dialog, so ten
/// seconds is what the detection measures.
#[test]
fn diagnosis_ack_timeout_decides_when_a_missing_ack_is_a_fault() {
    let dir = tempfile::tempdir().expect("tempdir");
    let frames = vec![
        (invite("ack-1", "a1", "bob", None), 0),
        (
            response(200, "OK", "ack-1", "a1", "bob", "1 INVITE", None, true),
            100_000,
        ),
        (
            response(200, "OK", "ack-1", "a1", "bob", "1 INVITE", None, true),
            10_100_000,
        ),
    ];
    let pcap = arg(&write_capture(&dir, "ack", &frames));
    let cfg = arg(&write_config(&dir, "[diagnosis]\nack_timeout_secs = 5.0\n"));

    let (shipped, _) = run(&["-N", "-I", &pcap, "--json-dialogs", "--no-config"]);
    assert!(
        !shipped.contains("ack_missing"),
        "ten seconds is inside Timer H's 32 s:\n{shipped}"
    );

    let (declared, _) = run(&["-N", "-I", &pcap, "--json-dialogs", "--config", &cfg]);
    assert!(
        declared.contains("ack_missing"),
        "[diagnosis] ack_timeout_secs = 5.0 must reach the diagnosis:\n{declared}"
    );

    let (overridden, _) = run(&[
        "-N",
        "-I",
        &pcap,
        "--json-dialogs",
        "--ack-timeout",
        "60",
        "--config",
        &cfg,
    ]);
    assert!(
        !overridden.contains("ack_missing"),
        "--ack-timeout must beat the config key:\n{overridden}"
    );
}

/// The declared Timer C budget is what decides when silence is worth
/// reporting.
#[test]
fn diagnosis_no_final_response_timeout_decides_when_silence_is_reported() {
    let dir = tempfile::tempdir().expect("tempdir");
    let frames = vec![
        (invite("nf-1", "n1", "bob", None), 0),
        (
            response(100, "Trying", "nf-1", "n1", "bob", "1 INVITE", None, false),
            100_000,
        ),
        (
            response(180, "Ringing", "nf-1", "n1", "bob", "1 INVITE", None, true),
            10_000_000,
        ),
    ];
    let pcap = arg(&write_capture(&dir, "nofinal", &frames));
    let cfg = arg(&write_config(
        &dir,
        "[diagnosis]\nno_final_response_secs = 5.0\n",
    ));

    let (shipped, _) = run(&["-N", "-I", &pcap, "--json-dialogs", "--no-config"]);
    assert!(
        !shipped.contains("\"abandoned\":{"),
        "ten seconds of ringing is inside Timer C's 180 s:\n{shipped}"
    );

    let (declared, _) = run(&["-N", "-I", &pcap, "--json-dialogs", "--config", &cfg]);
    assert!(
        declared.contains("\"abandoned\":{"),
        "[diagnosis] no_final_response_secs = 5.0 must reach the diagnosis:\n{declared}"
    );

    let (overridden, _) = run(&[
        "-N",
        "-I",
        &pcap,
        "--json-dialogs",
        "--no-final-response-timeout",
        "600",
        "--config",
        &cfg,
    ]);
    assert!(
        !overridden.contains("\"abandoned\":{"),
        "--no-final-response-timeout must beat the config key:\n{overridden}"
    );
}

// ── [diagnosis] media asymmetry thresholds ──────────────────────────────

/// A 12-byte RTP header plus a G.711 frame.
fn rtp_packet(seq: u16, timestamp: u32, ssrc: u32) -> Vec<u8> {
    let mut p = Vec::with_capacity(12 + 160);
    p.push(0x80);
    p.push(0x00); // PT 0 = PCMU
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&timestamp.to_be_bytes());
    p.extend_from_slice(&ssrc.to_be_bytes());
    p.extend(std::iter::repeat_n(0xffu8, 160));
    p
}

/// An SDP body offering PCMU at `port` on `ip`.
fn sdp(ip: &str, port: u16) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n"
    )
}

/// One answered call with media in both directions: the A leg runs five
/// seconds, the B leg two, and both start 200 ms after the `200 OK`.
///
/// That puts the capture between the shipped thresholds and the declared ones
/// in both directions at once: a 3 s / 60% duration delta is over the shipped
/// 2 s / 5%, and 200 ms of late media is under the shipped 500 ms.
fn asymmetric_media_capture(dir: &tempfile::TempDir) -> String {
    let offer = sdp("10.1.0.1", 40_000);
    let answer = sdp("10.2.0.1", 40_002);
    let mut frames = vec![
        (invite("media-1", "m1", "bob", Some(&offer)), 0),
        (
            response(
                200,
                "OK",
                "media-1",
                "m1",
                "bob",
                "1 INVITE",
                Some(&answer),
                true,
            ),
            100_000,
        ),
        (in_dialog("ACK", "media-1", "m1", "bob", "1 ACK"), 200_000),
    ];
    for i in 0..50u32 {
        frames.push((
            udp_frame(
                A,
                B,
                40_000,
                40_002,
                &rtp_packet(1000 + i as u16, i * 800, 0x1111),
            ),
            300_000 + u64::from(i) * 100_000,
        ));
    }
    for i in 0..20u32 {
        frames.push((
            udp_frame(
                B,
                A,
                40_002,
                40_000,
                &rtp_packet(2000 + i as u16, i * 800, 0x2222),
            ),
            300_000 + u64::from(i) * 100_000,
        ));
    }
    frames.push((in_dialog("BYE", "media-1", "m1", "bob", "2 BYE"), 6_000_000));
    frames.push((
        response(200, "OK", "media-1", "m1", "bob", "2 BYE", None, true),
        6_100_000,
    ));
    frames.sort_by_key(|(_, t)| *t);
    arg(&write_capture(dir, "media", &frames))
}

/// The declared duration delta decides when two legs are asymmetric.
#[test]
fn diagnosis_duration_asymmetry_threshold_decides_when_legs_disagree() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pcap = asymmetric_media_capture(&dir);
    let cfg = arg(&write_config(
        &dir,
        "[diagnosis]\nduration_asymmetry_secs = 4.0\n",
    ));

    let (shipped, _) = run(&["-N", "-I", &pcap, "--json-dialogs", "--no-config"]);
    assert!(
        shipped.contains("Duration asymmetry"),
        "a 3 s delta is over the shipped 2 s:\n{shipped}"
    );

    let (declared, _) = run(&["-N", "-I", &pcap, "--json-dialogs", "--config", &cfg]);
    assert!(
        !declared.contains("Duration asymmetry"),
        "[diagnosis] duration_asymmetry_secs = 4.0 must reach the diagnosis:\n{declared}"
    );

    let (overridden, _) = run(&[
        "-N",
        "-I",
        &pcap,
        "--json-dialogs",
        "--duration-asymmetry-secs",
        "0.5",
        "--config",
        &cfg,
    ]);
    assert!(
        overridden.contains("Duration asymmetry"),
        "--duration-asymmetry-secs must beat the config key:\n{overridden}"
    );
}

/// The declared percentage is the other half of the duration test, and either
/// one alone quiets it.
#[test]
fn diagnosis_duration_asymmetry_percentage_reaches_the_diagnosis() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pcap = asymmetric_media_capture(&dir);
    let cfg = arg(&write_config(
        &dir,
        "[diagnosis]\nduration_asymmetry_pct = 80.0\n",
    ));

    let (declared, _) = run(&["-N", "-I", &pcap, "--json-dialogs", "--config", &cfg]);
    assert!(
        !declared.contains("Duration asymmetry"),
        "a 60% delta is under a declared 80%:\n{declared}"
    );

    let (overridden, _) = run(&[
        "-N",
        "-I",
        &pcap,
        "--json-dialogs",
        "--duration-asymmetry-pct",
        "10",
        "--config",
        &cfg,
    ]);
    assert!(
        overridden.contains("Duration asymmetry"),
        "--duration-asymmetry-pct must beat the config key:\n{overridden}"
    );
}

/// The declared late-media budget decides when media that started 200 ms after
/// the `200 OK` is worth reporting.
#[test]
fn diagnosis_late_media_threshold_decides_when_media_is_late() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pcap = asymmetric_media_capture(&dir);
    let cfg = arg(&write_config(&dir, "[diagnosis]\nlate_media_ms = 100\n"));

    let (shipped, _) = run(&["-N", "-I", &pcap, "--json-dialogs", "--no-config"]);
    assert!(
        !shipped.contains("Late media"),
        "200 ms is inside the shipped 500 ms:\n{shipped}"
    );

    let (declared, _) = run(&["-N", "-I", &pcap, "--json-dialogs", "--config", &cfg]);
    assert!(
        declared.contains("Late media"),
        "[diagnosis] late_media_ms = 100 must reach the diagnosis:\n{declared}"
    );

    let (overridden, _) = run(&[
        "-N",
        "-I",
        &pcap,
        "--json-dialogs",
        "--late-media-ms",
        "1000",
        "--config",
        &cfg,
    ]);
    assert!(
        !overridden.contains("Late media"),
        "--late-media-ms must beat the config key:\n{overridden}"
    );
}

/// A 12-byte RTP header at payload type `pt`, plus a frame.
fn rtp_packet_pt(seq: u16, timestamp: u32, ssrc: u32, pt: u8) -> Vec<u8> {
    let mut p = rtp_packet(seq, timestamp, ssrc);
    p[1] = pt;
    p
}

/// One answered call with media in ONE direction, 40 % of whose packets are
/// comfort noise.
///
/// That sits between the shipped 0.3 and a declared 0.5, which is the whole
/// point: at the shipped ratio comfort noise "explains" the asymmetry and
/// one-way audio is never reported, and 40 % CN is what a VoLTE or mobile
/// trunk running aggressive voice-activity detection actually produces.
fn one_way_call_with_comfort_noise(dir: &tempfile::TempDir) -> String {
    let offer = sdp("10.1.0.1", 40_000);
    let answer = sdp("10.2.0.1", 40_002);
    let mut frames = vec![
        (invite("cn-1", "c1", "bob", Some(&offer)), 0),
        (
            response(
                200,
                "OK",
                "cn-1",
                "c1",
                "bob",
                "1 INVITE",
                Some(&answer),
                true,
            ),
            100_000,
        ),
        (in_dialog("ACK", "cn-1", "c1", "bob", "1 ACK"), 200_000),
    ];
    // 100 packets from A to B and nothing back: 60 speech (PT 0) and 40
    // comfort noise (PT 13), one SSRC, so the ratio the diagnosis computes is
    // 0.4 of a single stream.
    for i in 0..100u32 {
        let pt = if i % 5 < 2 { 13 } else { 0 };
        frames.push((
            udp_frame(
                A,
                B,
                40_000,
                40_002,
                &rtp_packet_pt(3000 + i as u16, i * 160, 0x3333, pt),
            ),
            300_000 + u64::from(i) * 20_000,
        ));
    }
    frames.push((in_dialog("BYE", "cn-1", "c1", "bob", "2 BYE"), 3_000_000));
    frames.push((
        response(200, "OK", "cn-1", "c1", "bob", "2 BYE", None, true),
        3_100_000,
    ));
    frames.sort_by_key(|(_, t)| *t);
    arg(&write_capture(dir, "comfort-noise", &frames))
}

/// The declared comfort-noise ratio decides whether one-way audio is reported
/// at all on a trunk with aggressive voice-activity detection.
///
/// This threshold fails in the QUIET direction — it withholds a finding rather
/// than raising one — so the shipped run below is asserting the defect: 40 %
/// comfort noise on a strictly one-directional flow is accepted as the
/// explanation, and the single most-reported VoIP fault goes unreported with
/// nothing in the output to say why.
#[test]
fn diagnosis_cn_suppression_ratio_decides_whether_one_way_audio_is_reported() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pcap = one_way_call_with_comfort_noise(&dir);
    let cfg = arg(&write_config(
        &dir,
        "[diagnosis]\ncn_suppression_ratio = 0.5\n",
    ));

    let (shipped, _) = run(&["-N", "-I", &pcap, "--json-dialogs", "--no-config"]);
    assert!(
        shipped.contains("\"one_way_audio\":false"),
        "40 % comfort noise is over the shipped 0.3, so the finding is \
         suppressed — this is the state the key exists to change:\n{shipped}"
    );

    let (declared, _) = run(&["-N", "-I", &pcap, "--json-dialogs", "--config", &cfg]);
    assert!(
        declared.contains("\"one_way_audio\":true"),
        "[diagnosis] cn_suppression_ratio = 0.5 must reach the diagnosis, so \
         40 % CN no longer explains a one-directional flow:\n{declared}"
    );

    let (overridden, _) = run(&[
        "-N",
        "-I",
        &pcap,
        "--json-dialogs",
        "--cn-suppression-ratio",
        "0.2",
        "--config",
        &cfg,
    ]);
    assert!(
        overridden.contains("\"one_way_audio\":false"),
        "--cn-suppression-ratio must beat the config key:\n{overridden}"
    );
}

// ── [limits] lint_max_per_rule ──────────────────────────────────────────

/// The declared per-rule cap decides how many repeats of one finding print.
///
/// Forty `INVITE`s in one dialog, none carrying `Max-Forwards`, so exactly one
/// rule fires forty times and the count on the summary line is the cap.
#[test]
fn lint_max_per_rule_bounds_the_findings_one_rule_prints() {
    /// The number sipnab reports on its own summary line.
    fn findings(stderr: &str) -> usize {
        stderr
            .lines()
            .find_map(|l| l.strip_prefix("Lint: "))
            .and_then(|rest| rest.split(' ').next())
            .and_then(|n| n.parse().ok())
            .unwrap_or_else(|| panic!("no lint summary line in:\n{stderr}"))
    }

    let dir = tempfile::tempdir().expect("tempdir");
    let frames: Vec<(Vec<u8>, u64)> = (0..40u32)
        .map(|i| {
            (
                invite_without_max_forwards("lint-1", &format!("l{i}"), i + 1),
                u64::from(i) * 200_000,
            )
        })
        .collect();
    let pcap = arg(&write_capture(&dir, "lint", &frames));
    let cfg = arg(&write_config(&dir, "[limits]\nlint_max_per_rule = 5\n"));

    let (_, shipped) = run(&["-N", "-I", &pcap, "--lint", "--no-config"]);
    assert_eq!(
        findings(&shipped),
        25,
        "the shipped cap is 25, so 40 repeats must print 25"
    );

    let (_, declared) = run(&["-N", "-I", &pcap, "--lint", "--config", &cfg]);
    assert_eq!(
        findings(&declared),
        5,
        "[limits] lint_max_per_rule = 5 must reach the linter"
    );

    let (_, overridden) = run(&[
        "-N",
        "-I",
        &pcap,
        "--lint",
        "--lint-max-per-rule",
        "40",
        "--config",
        &cfg,
    ]);
    assert_eq!(
        findings(&overridden),
        40,
        "--lint-max-per-rule must beat the config key, and must be able to \
         RAISE the cap as well as lower it"
    );
}

/// `lint_max_per_rule = 0` is refused by name rather than read as "uncapped".
#[test]
fn a_zero_lint_cap_is_refused_by_name() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pcap = arg(&write_capture(
        &dir,
        "lint",
        &[(invite_without_max_forwards("lint-1", "l1", 1), 0)],
    ));
    let cfg = arg(&write_config(&dir, "[limits]\nlint_max_per_rule = 0\n"));
    let (_, stderr, code) = run_support::run(
        &["-N", "-I", &pcap, "--lint", "--config", &cfg],
        Some("error"),
    );
    assert_ne!(code, Some(0), "a zero cap must fail the run");
    assert!(
        stderr.contains("lint_max_per_rule"),
        "the error must name the key; got {stderr}"
    );
}
