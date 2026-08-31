// SPDX-License-Identifier: MIT OR Apache-2.0

//! Every result envelope says how much of the capture is behind it (VAL3,
//! VAL4, and VAL2's MCP half), proved by driving the real server.
//!
//! The defect these cover is not a missing warning — the hazard is documented
//! and `capture_status.source_exhausted` has always been correct. It is that a
//! result-set tool answered from a store that was still filling and said
//! `truncated: false`, which is an affirmative claim that nothing was withheld.
//! Measured on 0.5.130: `list_dialogs` reported 6 of 18,241 dialogs with
//! `truncated: false`, and `get_capture_report` reported `complete: true` over
//! 0.09% of a file and `complete: false` once the file had been read.
//!
//! # Why these tests build their own captures
//!
//! Every checked-in fixture loads faster than the first tool call arrives, so a
//! fixture cannot show the window at all: a test written against one would pass
//! while asserting nothing. `write_big_capture` writes thousands of distinct calls
//! so that a call issued the instant `open_capture` returns lands mid-load, and
//! `partial_capture_lifecycle` asserts the early call really saw a SMALLER
//! population rather than merely carrying a field. Without that assertion the
//! test stops testing anything the moment it runs on a faster machine, and
//! nothing says so.
//!
//! the private capture corpus is deliberately not used and no capture is committed:
//! the corpus is real customer traffic.

// Gated on `full`: this file drives the whole tool surface, and the surface
// is FEATURE-DEPENDENT. Under `native,hep,api,mcp,mcp-http` the probe of
// `export_vcon` is answered with "this sipnab was built without the 'vcon'
// Cargo feature" -- a correct refusal, not a missing envelope, but the probe
// reads it as a tool that failed to carry its completeness fields. The
// documentation and the tool inventory both describe the full binary, so
// that is the only build this comparison means anything against.
#![cfg(feature = "full")]
#![cfg(all(unix, feature = "mcp"))]

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};

use serde_json::{Value, json};

#[path = "support/pcap_build.rs"]
mod pcap_build;
#[path = "support/source_scan.rs"]
mod source_scan;

/// A small, complete capture with one call and RTP.
const INTACT: &str = "tests/pcap-samples/sip-rtp-g711.pcap";

/// The key that says the source has been read to its end.
const EXHAUSTED: &str = "source_exhausted";

/// The key that says a source's read ended before the source did.
const STOPPED_EARLY: &str = "source_stopped_early";

/// Calls in the generated capture, sized so a load cannot finish instantly.
///
/// Six frames each. On this repository's debug build that is several seconds of
/// reading, which is the window every VAL3 measurement was taken inside.
const BIG_CALLS: usize = 6000;

/// Longest a reply may take before a test gives up, in read attempts.
const MAX_LINES: usize = 20_000;

// ── the wire ────────────────────────────────────────────────────────────

/// A `sipnab --mcp` process driven over stdio.
///
/// Stdin is held open for the life of the struct: closing it shuts the server
/// down, which masks exactly the mid-load results these tests are about.
struct Wire {
    child: Child,
    reader: BufReader<ChildStdout>,
    next_id: i64,
}

impl Wire {
    /// Spawn a server on `input` with `extra` arguments and handshake.
    ///
    /// Does NOT wait for the source to drain — [`Self::drain`] does that, and
    /// the tests that measure the window must run before it.
    fn start(input: &Path, extra: &[&str]) -> Self {
        let mut args: Vec<String> = vec![
            "--mcp".into(),
            "-N".into(),
            "-I".into(),
            input.to_string_lossy().into_owned(),
            "--quiet".into(),
        ];
        args.extend(extra.iter().map(|a| (*a).to_string()));

        let mut child = Command::new(env!("CARGO_BIN_EXE_sipnab"))
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sipnab --mcp");

        {
            let stdin = child.stdin.as_mut().expect("stdin");
            writeln!(
                stdin,
                "{}",
                json!({
                    "jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {},
                        "clientInfo": {"name": "completeness-test", "version": "1"}
                    }
                })
            )
            .expect("write initialize");
            writeln!(
                stdin,
                "{}",
                json!({"jsonrpc": "2.0", "method": "notifications/initialized"})
            )
            .expect("write initialized");
            stdin.flush().expect("flush");
        }

        let stdout = child.stdout.take().expect("stdout");
        let mut wire = Self {
            child,
            reader: BufReader::new(stdout),
            next_id: 2,
        };
        wire.await_id(1);
        wire
    }

    /// Read until the reply with `id` arrives, discarding notifications.
    fn await_id(&mut self, id: i64) -> Value {
        let mut line = String::new();
        for _ in 0..MAX_LINES {
            line.clear();
            match self.reader.read_line(&mut line) {
                Ok(0) => panic!("the server closed stdout before replying to {id}"),
                Ok(_) => {}
                Err(e) => panic!("reading the wire failed: {e}"),
            }
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let value: Value = serde_json::from_str(trimmed)
                .unwrap_or_else(|e| panic!("stdout line is not JSON-RPC: {e}\n{trimmed}"));
            if value.get("id").and_then(Value::as_i64) == Some(id) {
                return value;
            }
        }
        panic!("no reply to id {id} within {MAX_LINES} lines");
    }

    /// Call `tool` with `args` and return the whole JSON-RPC reply.
    fn call(&mut self, tool: &str, args: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        let request = json!({
            "jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": {"name": tool, "arguments": args}
        });
        {
            let stdin = self.child.stdin.as_mut().expect("stdin");
            writeln!(stdin, "{request}").expect("write request");
            stdin.flush().expect("flush");
        }
        self.await_id(id)
    }

    /// Every tool the server registers, from `tools/list`.
    fn tool_names(&mut self) -> Vec<String> {
        let id = self.next_id;
        self.next_id += 1;
        {
            let stdin = self.child.stdin.as_mut().expect("stdin");
            writeln!(
                stdin,
                "{}",
                json!({"jsonrpc": "2.0", "id": id, "method": "tools/list"})
            )
            .expect("write tools/list");
            stdin.flush().expect("flush");
        }
        let reply = self.await_id(id);
        reply["result"]["tools"]
            .as_array()
            .expect("tools array")
            .iter()
            .filter_map(|t| t["name"].as_str().map(str::to_string))
            .collect()
    }

    /// Poll `capture_status` until the source drains.
    fn drain(&mut self) {
        for _ in 0..1200 {
            let reply = self.call("capture_status", json!({}));
            if payload(&reply)[EXHAUSTED] == json!(true) {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        panic!("the capture never finished loading");
    }

    /// A Call-ID from the loaded store, for the per-dialog probes.
    fn a_call_id(&mut self) -> String {
        let reply = self.call("list_dialogs", json!({"limit": 1}));
        payload(&reply)["dialogs"][0]["call_id"]
            .as_str()
            .expect("the fixture holds at least one dialog")
            .to_string()
    }
}

impl Drop for Wire {
    fn drop(&mut self) {
        // Close stdin first: the server exits on EOF, so the child is reaped
        // rather than left holding a pipe for the rest of the run.
        drop(self.child.stdin.take());
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The first content block of a reply, parsed.
fn payload(reply: &Value) -> Value {
    let text = reply["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("no text content block in {reply}"));
    serde_json::from_str(text).unwrap_or_else(|e| panic!("payload is not JSON: {e}\n{text}"))
}

// ── generated captures ──────────────────────────────────────────────────

/// Write a capture of `calls` distinct SIP calls to `path`.
fn write_big_capture(path: &Path, calls: usize) {
    let mut frames: Vec<Vec<u8>> = Vec::with_capacity(calls * 6);
    for n in 0..calls {
        frames.extend(pcap_build::sip_call_frames(
            &format!("load-{n}@192.0.2.10"),
            &format!("z9hG4bK-{n}"),
            &format!("caller{n}"),
            &format!("callee{n}"),
        ));
    }
    pcap_build::write_pcap(path, &frames);
}

/// Copy `INTACT` into `dir` with its last packet record cut in half.
///
/// libpcap answers `truncated dump file; tried to read N captured bytes, only
/// got M` on the trailing partial record — the same condition a ring buffer's
/// newest member is in while it is still being written.
fn write_truncated_capture(dir: &Path, name: &str) -> PathBuf {
    let whole = std::fs::read(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(INTACT))
        .expect("read the intact fixture");
    assert!(
        whole.len() > 200,
        "the fixture must be long enough to cut meaningfully"
    );
    // Two thirds keeps a real prefix of packets and lands inside a record.
    let cut = whole.len() * 2 / 3;
    let path = dir.join(name);
    std::fs::write(&path, &whole[..cut]).expect("write the truncated capture");
    path
}

/// Absolute path to a checked-in sample.
fn sample(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
}

// ── VAL3: the window ────────────────────────────────────────────────────

/// A page answered mid-load says so, and a page answered after draining says
/// the opposite — with a bigger population behind it.
///
/// One test rather than two, because the two halves are one observation: a
/// separate "after" test could pass against a capture the "before" test never
/// caught loading, and neither would notice.
#[test]
fn partial_capture_lifecycle() {
    let dir = tempfile::tempdir().expect("temp dir");
    let big = dir.path().join("big.pcap");
    write_big_capture(&big, BIG_CALLS);

    let root = dir.path().to_string_lossy().into_owned();
    let mut wire = Wire::start(
        &sample(INTACT),
        &["--mcp-file-root", &root, "--mcp-allow-open-capture"],
    );
    wire.drain();

    // `open_capture` clears both stores and returns while the worker reads, so
    // the very next call is inside the window every VAL3 measurement was taken
    // in. The startup path has the same window; this one is reachable without
    // racing the handshake.
    let opened = wire.call("open_capture", json!({"filename": "big.pcap"}));
    assert_ne!(
        opened["result"]["isError"],
        json!(true),
        "open_capture must be permitted here: {opened}"
    );

    let early_dialogs = payload(&wire.call("list_dialogs", json!({"limit": 5})));
    let early_problems = payload(&wire.call("find_problems", json!({"limit": 5})));
    let early_report = payload(&wire.call("get_capture_report", json!({})));

    assert_eq!(
        early_dialogs[EXHAUSTED],
        json!(false),
        "a page computed while the file is still being read must say so: \
         {early_dialogs}"
    );
    // Absent OR `true` -- never `false`. The rule is that an UNEARNED
    // completeness claim must not be made; a row cap that really bit is a
    // fact and ships whatever the load state. Asserting absence instead was a
    // timing bug: with `limit: 5`, whether `truncated` appears at all depends
    // on how many dialogs happen to have loaded when the call lands. It held
    // on a loaded developer machine, where fewer than five were in by then,
    // and failed on a CI runner that got there first.
    assert_ne!(
        early_dialogs.get("truncated"),
        Some(&json!(false)),
        "`truncated: false` claims nothing was withheld, and mid-load that \
         claim is unearned: {early_dialogs}"
    );
    assert_eq!(early_problems[EXHAUSTED], json!(false), "{early_problems}");
    assert_ne!(
        early_report["complete"],
        json!(true),
        "`complete` says sipnab read all of its input; it cannot be true over a \
         partial read (VAL4): {early_report}"
    );

    let early_total = early_dialogs["total_matched"]
        .as_u64()
        .unwrap_or_else(|| panic!("total_matched missing: {early_dialogs}"));

    wire.drain();

    let late = payload(&wire.call("list_dialogs", json!({"limit": 5})));
    let late_total = late["total_matched"]
        .as_u64()
        .unwrap_or_else(|| panic!("total_matched missing: {late}"));

    assert_eq!(late[EXHAUSTED], json!(true), "{late}");
    assert_eq!(
        late["truncated"],
        json!(true),
        "5 of {late_total} rows: the cap really did withhold matches, and now \
         that the population is settled the flag may say so: {late}"
    );
    assert_eq!(
        late_total, BIG_CALLS as u64,
        "the drained store holds every generated call"
    );
    assert!(
        early_total < late_total,
        "the early call must actually have seen a PARTIAL population, or this \
         test stops testing anything on a faster machine: it saw {early_total} \
         of the eventual {late_total}. Raise BIG_CALLS."
    );
}

/// The report's own `complete` flag, before and after, on one session.
///
/// VAL4 measured this reading backwards: `true` at `frames_read: 312`, `false`
/// at `frames_read: 365747`.
#[test]
fn capture_report_complete_never_reads_backwards() {
    let dir = tempfile::tempdir().expect("temp dir");
    let big = dir.path().join("big.pcap");
    write_big_capture(&big, BIG_CALLS);

    let root = dir.path().to_string_lossy().into_owned();
    let mut wire = Wire::start(
        &sample(INTACT),
        &["--mcp-file-root", &root, "--mcp-allow-open-capture"],
    );
    wire.drain();
    wire.call("open_capture", json!({"filename": "big.pcap"}));

    let early = payload(&wire.call("get_capture_report", json!({})));
    let early_dialogs = early["dialogs_examined"].as_u64().unwrap_or_default();
    assert_eq!(
        early[EXHAUSTED],
        json!(false),
        "the mid-load probe must really be mid-load: {early}"
    );

    wire.drain();
    let late = payload(&wire.call("get_capture_report", json!({})));
    let late_dialogs = late["dialogs_examined"].as_u64().unwrap_or_default();

    // `dialogs_examined` rather than `frames_read`: the latter is read from the
    // process-wide captured-packet counter, which a background `open_capture`
    // load does not advance, so it would compare a number to itself and pass
    // whatever the report said.
    assert!(
        early_dialogs < late_dialogs,
        "the early report must describe fewer dialogs ({early_dialogs}) than \
         the drained one ({late_dialogs}), or the window was missed"
    );
    assert_ne!(early["complete"], json!(true), "{early}");
    assert_eq!(
        late["complete"],
        json!(true),
        "a whole read of an intact capture is complete: {late}"
    );
}

// ── VAL2: a capture that stopped early ──────────────────────────────────

/// `capture_health` is the tool an agent calls to ask whether a capture is
/// sound. On a truncated file it said nothing at all.
#[test]
fn capture_health_discloses_a_capture_that_stopped_early() {
    let dir = tempfile::tempdir().expect("temp dir");
    write_truncated_capture(dir.path(), "cut.pcap");

    let root = dir.path().to_string_lossy().into_owned();
    let mut wire = Wire::start(
        &sample(INTACT),
        &["--mcp-file-root", &root, "--mcp-allow-open-capture"],
    );
    wire.drain();
    wire.call("open_capture", json!({"filename": "cut.pcap"}));
    wire.drain();

    let health = payload(&wire.call("capture_health", json!({"sample_seconds": 1})));
    assert_eq!(
        health[STOPPED_EARLY],
        json!(true),
        "the read ended before the file did, and the tool that answers \
         'is this capture sound' has to say so: {health}"
    );
    assert_eq!(
        health[EXHAUSTED],
        json!(true),
        "the reader did reach the end of what there was to read: {health}"
    );
}

/// The startup `-I` path, which is the one VAL2 measured.
///
/// This half of the fact is the capture layer's: it tallies the file set it
/// read and publishes it as `output::run_integrity`, the same record the exit
/// status is decided from. The MCP surface reads that tally rather than keeping
/// a second copy, so an agent and `$?` cannot be told different things about
/// one run.
#[test]
fn capture_health_discloses_a_truncated_startup_capture() {
    let dir = tempfile::tempdir().expect("temp dir");
    let cut = write_truncated_capture(dir.path(), "cut.pcap");

    let mut wire = Wire::start(&cut, &[]);
    wire.drain();

    let health = payload(&wire.call("capture_health", json!({"sample_seconds": 1})));
    assert_eq!(
        health[STOPPED_EARLY],
        json!(true),
        "`0 of 1 file(s) read in full, 1 stopped early` reached stderr and \
         reached no MCP response at all: {health}"
    );

    let page = payload(&wire.call("list_dialogs", json!({"limit": 1000})));
    assert_eq!(page[STOPPED_EARLY], json!(true), "{page}");
    assert!(
        page.get("truncated").is_none(),
        "an answer resting on part of a capture must not say nothing was \
         withheld: {page}"
    );
}

/// A fix that always warns is useless. An intact capture must not be accused.
#[test]
fn capture_health_does_not_accuse_an_intact_capture() {
    let mut wire = Wire::start(&sample(INTACT), &[]);
    wire.drain();

    let health = payload(&wire.call("capture_health", json!({"sample_seconds": 1})));
    assert_eq!(
        health[STOPPED_EARLY],
        json!(false),
        "this capture was read in full: {health}"
    );
    assert_eq!(health[EXHAUSTED], json!(true), "{health}");
}

/// `capture_status` carries the same disclosure, so a poller learns it too.
#[test]
fn capture_status_discloses_a_capture_that_stopped_early() {
    let dir = tempfile::tempdir().expect("temp dir");
    write_truncated_capture(dir.path(), "cut.pcap");

    let root = dir.path().to_string_lossy().into_owned();
    let mut wire = Wire::start(
        &sample(INTACT),
        &["--mcp-file-root", &root, "--mcp-allow-open-capture"],
    );
    wire.drain();

    let before = payload(&wire.call("capture_status", json!({})));
    assert_eq!(
        before[STOPPED_EARLY],
        json!(false),
        "the intact startup capture is not accused: {before}"
    );

    wire.call("open_capture", json!({"filename": "cut.pcap"}));
    wire.drain();

    let after = payload(&wire.call("capture_status", json!({})));
    assert_eq!(after[STOPPED_EARLY], json!(true), "{after}");
}

/// A page over a capture that stopped early makes no completeness claim.
#[test]
fn a_page_over_a_partial_capture_does_not_claim_it_is_whole() {
    let dir = tempfile::tempdir().expect("temp dir");
    write_truncated_capture(dir.path(), "cut.pcap");

    let root = dir.path().to_string_lossy().into_owned();
    let mut wire = Wire::start(
        &sample(INTACT),
        &["--mcp-file-root", &root, "--mcp-allow-open-capture"],
    );
    wire.drain();
    wire.call("open_capture", json!({"filename": "cut.pcap"}));
    wire.drain();

    let page = payload(&wire.call("list_dialogs", json!({"limit": 1000})));
    assert_eq!(page[STOPPED_EARLY], json!(true), "{page}");
    assert!(
        page.get("truncated").is_none(),
        "the cap did not bite, but the FILE did: `truncated: false` would say \
         nothing was withheld from an answer resting on part of a capture: \
         {page}"
    );

    let report = payload(&wire.call("get_capture_report", json!({})));
    assert_ne!(
        report["complete"],
        json!(true),
        "a capture read in part is not a capture read in full: {report}"
    );
}

/// The record belongs to the capture, not to the process.
///
/// Without this, one truncated file would leave every later answer in the run
/// accused — a sticky false positive is the same defect as a missing one,
/// pointed the other way.
#[test]
fn opening_an_intact_capture_clears_the_partial_read_record() {
    let dir = tempfile::tempdir().expect("temp dir");
    write_truncated_capture(dir.path(), "cut.pcap");
    let whole = dir.path().join("whole.pcap");
    std::fs::copy(sample(INTACT), &whole).expect("copy the intact fixture");

    let root = dir.path().to_string_lossy().into_owned();
    let mut wire = Wire::start(
        &sample(INTACT),
        &["--mcp-file-root", &root, "--mcp-allow-open-capture"],
    );
    wire.drain();

    wire.call("open_capture", json!({"filename": "cut.pcap"}));
    wire.drain();
    let accused = payload(&wire.call("capture_status", json!({})));
    assert_eq!(accused[STOPPED_EARLY], json!(true), "{accused}");

    wire.call("open_capture", json!({"filename": "whole.pcap"}));
    wire.drain();
    let cleared = payload(&wire.call("capture_status", json!({})));
    assert_eq!(
        cleared[STOPPED_EARLY],
        json!(false),
        "the previous file's partial read is not this file's: {cleared}"
    );
}

// ── no regression on an intact, drained capture ─────────────────────────

/// Everything a drained intact capture used to answer, it still answers.
#[test]
fn a_drained_intact_capture_is_unchanged() {
    let mut wire = Wire::start(&sample(INTACT), &[]);
    wire.drain();

    let page = payload(&wire.call("list_dialogs", json!({"limit": 1000})));
    assert_eq!(page[EXHAUSTED], json!(true), "{page}");
    assert_eq!(page[STOPPED_EARLY], json!(false), "{page}");
    assert_eq!(
        page["truncated"],
        json!(false),
        "a whole answer still says plainly that nothing was withheld: {page}"
    );
    assert_eq!(page["schema_version"], json!(1), "{page}");
    assert!(
        page["total_matched"].as_u64().unwrap_or_default() >= 1,
        "the fixture holds a call: {page}"
    );
    assert!(page["dialogs"].is_array(), "{page}");
    assert!(
        page["capture_identity"].is_object(),
        "provenance survives: {page}"
    );

    // The structured view and the text view remain ONE document, which is the
    // guarantee `mcp::structured` exists to hold and which a rewrite of the
    // text block could quietly break.
    let reply = wire.call("list_dialogs", json!({"limit": 1000}));
    assert_eq!(
        reply["result"]["structuredContent"],
        payload(&reply),
        "structuredContent is parsed FROM the text block: {reply}"
    );
}

/// A tool whose answer cannot move with the load is not annotated.
#[test]
fn source_independent_tools_are_not_stamped() {
    let mut wire = Wire::start(&sample(INTACT), &[]);
    wire.drain();

    for (tool, args) in [
        ("explain_response_code", json!({"code": 488})),
        ("server_capabilities", json!({})),
    ] {
        let body = payload(&wire.call(tool, args));
        assert!(
            body.get(EXHAUSTED).is_none() && body.get(STOPPED_EARLY).is_none(),
            "{tool} answers the same whatever the load state, so annotating it \
             would invent a dependency it does not have: {body}"
        );
    }
}

/// `timeline` answers with a top-level array, which has no key to carry a
/// field. The envelope arrives as a further content block instead.
#[test]
fn an_array_answering_tool_carries_the_envelope_in_a_second_block() {
    let mut wire = Wire::start(&sample(INTACT), &[]);
    wire.drain();

    let reply = wire.call("timeline", json!({}));
    assert!(
        payload(&reply).is_array(),
        "timeline's published shape is unchanged: {reply}"
    );
    let blocks = reply["result"]["content"]
        .as_array()
        .expect("content array");
    let envelope: Value = serde_json::from_str(
        blocks
            .last()
            .and_then(|b| b["text"].as_str())
            .unwrap_or_else(|| panic!("no trailing block: {reply}")),
    )
    .unwrap_or_else(|e| panic!("the envelope block is not JSON: {e}\n{reply}"));
    assert_eq!(envelope[EXHAUSTED], json!(true), "{envelope}");
    assert_eq!(envelope[STOPPED_EARLY], json!(false), "{envelope}");
}

// ── the enumeration, derived from the source ────────────────────────────

/// Tools driven over the wire and required to carry both keys.
///
/// The arguments are the smallest legal call for each. `{CALL}` is replaced
/// with a Call-ID from the loaded fixture.
const PROBES: &[(&str, &str)] = &[
    ("list_dialogs", r#"{"limit":5}"#),
    ("find_problems", r#"{"limit":5}"#),
    ("search_messages", r#"{"query":"INVITE","limit":5}"#),
    (
        "search_by_time",
        r#"{"start":"1970-01-01T00:00:00Z","limit":5}"#,
    ),
    ("rtp_stats", r#"{"limit":5}"#),
    ("aggregate_dialogs", r#"{"group_by":"state"}"#),
    ("group_dialogs", r#"{"by":"ua"}"#),
    ("top_talkers", r#"{"by":"ip"}"#),
    ("get_capture_report", r#"{}"#),
    ("capture_status", r#"{}"#),
    ("capture_health", r#"{"sample_seconds":1}"#),
    ("tail_dialogs", r#"{}"#),
    ("security_findings", r#"{}"#),
    ("get_dialog", r#"{"call_id":"{CALL}"}"#),
    ("get_dialog_report", r#"{"call_id":"{CALL}"}"#),
    ("get_message", r#"{"call_id":"{CALL}","index":0}"#),
    ("get_call_tree", r#"{"call_id":"{CALL}"}"#),
    ("get_sdp_timeline", r#"{"call_id":"{CALL}"}"#),
    ("triage_call", r#"{"call_id":"{CALL}"}"#),
    ("lint_dialog", r#"{"call_id":"{CALL}"}"#),
    ("validate_message", r#"{"call_id":"{CALL}","index":0}"#),
    ("find_correlated", r#"{"call_id":"{CALL}"}"#),
    ("check_codec_negotiation", r#"{"call_id":"{CALL}"}"#),
    ("diagnose_registration", r#"{"call_id":"{CALL}"}"#),
    ("media_diagnostics", r#"{"call_id":"{CALL}"}"#),
    (
        "compare_dialogs",
        r#"{"call_id_a":"{CALL}","call_id_b":"{CALL}"}"#,
    ),
    ("validate_filter", r#"{"expr":"state == InCall"}"#),
    ("export_vcon", r#"{"call_id":"{CALL}"}"#),
    ("generate_wireshark_filter", r#"{"call_id":"{CALL}"}"#),
    ("explain_attribution", r#"{"call_id":"{CALL}"}"#),
    ("reconcile_orphans", r#"{"limit":5}"#),
    (
        "evaluate_expectations",
        r#"{"rules":[{"metric":"count","op":">=","value":0}]}"#,
    ),
];

/// Capture-derived tools NOT driven here, each with the reason.
///
/// A list like this is where coverage goes to die, so every entry names a
/// property of the tool rather than a convenience, and the gate below fails if
/// it grows past the probes.
const NOT_PROBED: &[(&str, &str)] = &[
    (
        "render_ladder",
        "answers with a drawn document, not an envelope",
    ),
    (
        "timeline",
        "answers with an array; covered by its own test above",
    ),
    (
        "describe_endpoint",
        "needs an address the fixture happens to carry",
    ),
    (
        "open_capture",
        "replaces the capture; covered by the VAL2 tests",
    ),
    ("shutdown_server", "ends the process"),
    ("export_capture", "writes a file into --mcp-file-root"),
    ("export_audio", "writes a file and needs --retain-audio"),
    (
        "build_evidence_package",
        "writes a directory into --mcp-file-root",
    ),
    (
        "save_findings",
        "a write, gated behind --mcp-allow-save-findings",
    ),
    ("generate_repro", "writes a SIPp scenario"),
    (
        "generate_fail2ban_rule",
        "needs a recorded finding id the fixture never produces",
    ),
    (
        "start_tls_capture",
        "installs kernel uprobes and needs --mcp-allow-tls-capture",
    ),
    ("stop_tls_capture", "the other half of the uprobe pair"),
];

/// Tools whose answer is derived from the capture, read out of the source.
///
/// The set is DERIVED rather than typed, so a tool added tomorrow is measured
/// against this gate without anyone remembering to add it. The markers are the
/// ways a handler reaches the capture: the two stores directly, or one of the
/// helpers that reads them for it.
fn capture_derived_tools() -> Vec<String> {
    const MARKERS: &[&str] = &[
        "self.dialog_store",
        "self.stream_store",
        "self.capture.read",
        "self.dialog_page",
        "self.timeline_buckets",
        "self.alert_engine",
        "self.build_vcon",
    ];

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/mcp");
    let mut files: Vec<PathBuf> = Vec::new();
    for dir in [root.clone(), root.join("tools")] {
        for entry in std::fs::read_dir(&dir).expect("read src/mcp").flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "rs") {
                files.push(path);
            }
        }
    }
    assert!(
        files.len() >= 10,
        "only {} source files found under src/mcp; the scan is looking in the \
         wrong place",
        files.len()
    );

    let mut found = Vec::new();
    for path in files {
        let text = std::fs::read_to_string(&path).expect("read a source file");
        let src = source_scan::production_source(&text);
        // Each handler runs from its `#[tool(` attribute to the next one (or to
        // the end of the production text), which is a superset of its body and
        // therefore cannot MISS a store read.
        let starts: Vec<usize> = src.match_indices("#[tool(").map(|(i, _)| i).collect();
        for (n, start) in starts.iter().enumerate() {
            let end = starts.get(n + 1).copied().unwrap_or(src.len());
            let block = &src[*start..end];
            let Some(name) = block
                .split_once("name = \"")
                .and_then(|(_, rest)| rest.split_once('"'))
                .map(|(name, _)| name)
            else {
                continue;
            };
            if MARKERS.iter().any(|m| block.contains(m)) {
                found.push(name.to_string());
            }
        }
    }
    found.sort();
    found.dedup();
    found
}

/// The derivation finds a real population, and nothing it finds has opted out.
#[test]
fn no_capture_derived_tool_is_marked_source_independent() {
    let derived = capture_derived_tools();
    assert!(
        derived.len() >= 30,
        "only {} capture-derived tools were derived from src/mcp. A scanner \
         that matches almost nothing agrees with any implementation, which is \
         how its predecessor died: {derived:?}",
        derived.len()
    );

    let opted_out: Vec<&String> = derived
        .iter()
        .filter(|name| sipnab::mcp::completeness::SOURCE_INDEPENDENT_TOOLS.contains(&name.as_str()))
        .collect();
    assert!(
        opted_out.is_empty(),
        "these read a capture store and are still marked source-independent, so \
         their answers move with the load and say nothing about it: {opted_out:?}"
    );
}

/// Every capture-derived tool is either probed on the wire or excused by name.
#[test]
fn every_capture_derived_tool_is_probed_or_excused() {
    let derived = capture_derived_tools();
    let missing: Vec<&String> = derived
        .iter()
        .filter(|name| {
            !PROBES.iter().any(|(t, _)| t == name) && !NOT_PROBED.iter().any(|(t, _)| t == name)
        })
        .collect();
    assert!(
        missing.is_empty(),
        "these read a capture store and nothing here checks that they say how \
         much of it they read. Add a probe, or an entry to NOT_PROBED naming \
         the property that prevents one: {missing:?}"
    );
    assert!(
        PROBES.len() > NOT_PROBED.len(),
        "{} probed against {} excused — the excuse list has become the \
         coverage",
        PROBES.len(),
        NOT_PROBED.len()
    );
}

/// Every probed tool really carries both facts, read off the wire.
#[test]
fn every_probed_tool_carries_both_facts() {
    let mut wire = Wire::start(&sample(INTACT), &[]);
    wire.drain();
    let call_id = wire.a_call_id();
    let registered = wire.tool_names();

    assert!(
        PROBES.len() >= 25,
        "only {} probes; this gate is checking almost nothing",
        PROBES.len()
    );

    for (tool, template) in PROBES {
        assert!(
            registered.iter().any(|r| r == tool),
            "{tool} is probed here and the server does not register it"
        );
        let args: Value = serde_json::from_str(&template.replace("{CALL}", &call_id))
            .unwrap_or_else(|e| panic!("{tool}: probe arguments are not JSON: {e}"));
        let reply = wire.call(tool, args);
        assert_ne!(
            reply["result"]["isError"],
            json!(true),
            "{tool} refused its probe: {reply}"
        );
        let body = payload(&reply);
        assert_eq!(
            body[EXHAUSTED],
            json!(true),
            "{tool} does not say how much of the capture is behind its answer: \
             {body}"
        );
        assert_eq!(
            body[STOPPED_EARLY],
            json!(false),
            "{tool} does not say whether the capture was read in full: {body}"
        );
    }
}

/// Every excuse names a tool the server actually registers.
#[test]
fn every_excused_tool_is_registered_and_reasoned() {
    let mut wire = Wire::start(&sample(INTACT), &[]);
    let registered = wire.tool_names();
    assert!(
        registered.len() >= 40,
        "only {} tools registered; tools/list stopped answering",
        registered.len()
    );

    for (tool, reason) in NOT_PROBED {
        assert!(
            registered.iter().any(|r| r == tool),
            "{tool} is excused from the probe list and is not a registered tool"
        );
        assert!(
            reason.len() > 15,
            "{tool}'s excuse says nothing: {reason:?}"
        );
    }
    for tool in sipnab::mcp::completeness::SOURCE_INDEPENDENT_TOOLS {
        assert!(
            registered.iter().any(|r| r == tool),
            "{tool} is marked source-independent and is not a registered tool"
        );
    }
}
