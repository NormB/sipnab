// SPDX-License-Identifier: MIT OR Apache-2.0

//! `resources/subscribe` and `notifications/resources/updated`, proved on the
//! wire (PB4).
//!
//! The unit tests in `src/mcp/subscribe.rs` prove the state machine: the
//! debounce collapses a burst, an unchanged store is never rendered, an
//! unsubscribed URI is dead. None of them proves a notification ever leaves
//! the process, and the ways for that to be false are all silent — the
//! capability unadvertised, the watcher never spawned, the peer handle wrong.
//! So this file drives a real `sipnab --mcp` over stdio and counts the
//! notifications that actually arrive.
//!
//! # Making the capture change on purpose
//!
//! A subscription is only interesting when the data moves, and a pcap replayed
//! at full speed has usually finished before a test can subscribe. `open_capture`
//! is the deterministic lever: it replaces the loaded capture, which is the
//! largest change a dialog list can undergo, and it is gated on
//! `--mcp-allow-open-capture` so it exists only where a test asks for it.

#![cfg(feature = "mcp")]

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

/// The capture the server starts on.
const PCAP: &str = "tests/pcap-samples/sip-register.pcap";

/// Captures `open_capture` swaps between, so every swap really changes the list.
const SWAPS: [&str; 3] = [
    "sip-rtp-g711.pcap",
    "sip-problem-call.pcap",
    "sip-proxy.pcap",
];

/// Where `--mcp-file-root` points.
const FILE_ROOT: &str = "tests/pcap-samples";

/// The debounce interval the server enforces, mirrored so the waits here are
/// expressed in it rather than in a number nobody can trace to a rule.
const DEBOUNCE: Duration = Duration::from_secs(1);

/// Longest a single reply may take before the test gives up.
const MAX_LINES: usize = 4000;

/// A `sipnab --mcp` process driven over stdio, KEEPING the notifications.
///
/// Local rather than taken from `tests/support/mcp.rs`, which matches replies
/// by id and discards everything else — exactly what a notification test
/// cannot do.
struct Wire {
    /// Kept so stdin stays open and `Drop` can stop the server.
    child: Child,
    /// Line reader over the server's stdout, which is the JSON-RPC wire.
    reader: BufReader<ChildStdout>,
    /// Next JSON-RPC request id, so replies are matched rather than assumed.
    next_id: i64,
    /// Every notification seen so far, in arrival order.
    notifications: Vec<Value>,
}

impl Wire {
    /// Spawn the server on [`PCAP`], handshake, and wait for the replay to drain.
    fn start() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_sipnab"))
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .args([
                "--mcp",
                "-N",
                "-I",
                PCAP,
                "--quiet",
                "--mcp-file-root",
                FILE_ROOT,
                "--mcp-allow-open-capture",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sipnab --mcp");

        {
            let stdin = child.stdin.as_mut().expect("stdin");
            for message in [
                json!({
                    "jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {},
                        "clientInfo": {"name": "subscription-test", "version": "1"}
                    }
                }),
                json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            ] {
                writeln!(stdin, "{message}").expect("write handshake");
            }
            stdin.flush().expect("flush");
        }

        let stdout = child.stdout.take().expect("stdout");
        let mut wire = Self {
            child,
            reader: BufReader::new(stdout),
            next_id: 2,
            notifications: Vec::new(),
        };
        wire.await_reply(1);
        wire.await_load();
        wire
    }

    /// Poll `capture_status` until the source is drained.
    ///
    /// Bounded, so a genuine hang fails rather than running forever. Without
    /// it these tests race the pcap reader and a notification caused by the
    /// INITIAL load would be counted as one caused by the change under test.
    fn await_load(&mut self) {
        const MAX_POLLS: usize = 400;
        for _ in 0..MAX_POLLS {
            let reply = self.request(
                "tools/call",
                json!({"name": "capture_status", "arguments": {}}),
            );
            if text_payload(&reply)["source_exhausted"] == json!(true) {
                return;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        panic!("the capture never finished loading");
    }

    /// Issue one request and return the raw JSON-RPC reply.
    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        {
            let stdin = self.child.stdin.as_mut().expect("stdin");
            writeln!(
                stdin,
                "{}",
                json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
            )
            .expect("write request");
            stdin.flush().expect("flush");
        }
        self.await_reply(id)
    }

    /// Read until the reply carrying `id` arrives, KEEPING notifications.
    fn await_reply(&mut self, id: i64) -> Value {
        let mut line = String::new();
        for _ in 0..MAX_LINES {
            line.clear();
            if self.reader.read_line(&mut line).unwrap_or(0) == 0 {
                panic!("sipnab closed stdout while waiting for id {id}");
            }
            let Ok(msg) = serde_json::from_str::<Value>(line.trim()) else {
                continue;
            };
            if msg["id"] == json!(id) {
                return msg;
            }
            if msg["method"].is_string() && msg["id"].is_null() {
                self.notifications.push(msg);
            }
        }
        panic!("no reply to id {id} within {MAX_LINES} lines");
    }

    /// Read the wire for `window`, collecting whatever notifications arrive.
    ///
    /// A blocking `read_line` cannot be given a deadline, so the wait is spent
    /// issuing cheap `capture_status` calls: each one forces a round trip that
    /// drains anything the server has queued, and the reply loop files the
    /// notifications. That is also closer to what a real client does than a
    /// silent sleep would be.
    fn drain_for(&mut self, window: Duration) {
        let until = Instant::now() + window;
        while Instant::now() < until {
            self.request(
                "tools/call",
                json!({"name": "capture_status", "arguments": {}}),
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Every `notifications/resources/updated` seen so far, by URI.
    fn updates(&self) -> Vec<String> {
        self.notifications
            .iter()
            .filter(|n| n["method"] == json!("notifications/resources/updated"))
            .filter_map(|n| n["params"]["uri"].as_str().map(str::to_string))
            .collect()
    }

    /// Forget every notification seen so far, so a test reads only what its
    /// own step produced.
    fn forget_notifications(&mut self) {
        self.notifications.clear();
    }

    /// Swap the loaded capture, and wait for the new one to drain.
    fn swap_to(&mut self, filename: &str) {
        let reply = self.request(
            "tools/call",
            json!({"name": "open_capture", "arguments": {"filename": filename}}),
        );
        assert!(
            reply["error"].is_null() && reply["result"]["isError"] != json!(true),
            "open_capture({filename}) failed: {reply}"
        );
        self.await_load();
    }
}

impl Drop for Wire {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The payload block of a successful tool result, parsed.
fn text_payload(reply: &Value) -> Value {
    let text = reply["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("expected a text payload, got {reply}"));
    serde_json::from_str(text).unwrap_or_else(|_| panic!("payload is not JSON: {text}"))
}

/// The live dialog list is listed as a resource, so a client can find it.
///
/// A subscribable resource nothing enumerates is one only a client that read
/// the source could ever ask for.
#[test]
fn the_live_dialog_list_is_listed_as_a_resource() {
    let mut wire = Wire::start();
    let listed = wire.request("resources/list", json!({}));
    let uris: Vec<String> = listed["result"]["resources"]
        .as_array()
        .unwrap_or_else(|| panic!("no resources array in {listed}"))
        .iter()
        .filter_map(|r| r["uri"].as_str().map(str::to_string))
        .collect();
    assert!(
        uris.contains(&"sipnab://live/dialogs".to_string()),
        "the subscribable resource is not in resources/list: {uris:?}"
    );
}

/// The resource door and the tool door render the same dialogs.
///
/// Two renderers would eventually disagree, and an operator holding two
/// versions of one capture has no way to decide which to believe.
#[test]
fn the_live_resource_reads_back_what_list_dialogs_returns() {
    let mut wire = Wire::start();
    let from_tool = text_payload(&wire.request(
        "tools/call",
        json!({"name": "list_dialogs", "arguments": {"limit": 1000}}),
    ));
    let read = wire.request("resources/read", json!({"uri": "sipnab://live/dialogs"}));
    let text = read["result"]["contents"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("no text in {read}"));
    let from_resource: Value = serde_json::from_str(text).expect("the resource is JSON");
    assert_eq!(
        from_resource["dialogs"], from_tool["dialogs"],
        "the resource door and the tool door describe different dialogs"
    );
    assert_eq!(
        from_resource["total_matched"], from_tool["total_matched"],
        "the two doors disagree about how many dialogs the capture holds"
    );
}

/// A URI built from the per-Call-ID template reads exactly that dialog.
#[test]
fn a_per_call_live_resource_reads_the_dialog_it_names() {
    let mut wire = Wire::start();
    let listed = text_payload(&wire.request(
        "tools/call",
        json!({"name": "list_dialogs", "arguments": {"limit": 1}}),
    ));
    let call_id = listed["dialogs"][0]["call_id"]
        .as_str()
        .unwrap_or_else(|| panic!("{PCAP} holds no dialogs: {listed}"))
        .to_string();

    let read = wire.request(
        "resources/read",
        json!({"uri": format!("sipnab://live/dialogs/{call_id}")}),
    );
    let text = read["result"]["contents"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("no text in {read}"));
    let page: Value = serde_json::from_str(text).expect("the resource is JSON");
    assert_eq!(page["returned"], json!(1), "expected one dialog: {page}");
    assert_eq!(page["dialogs"][0]["call_id"], json!(call_id));
}

/// Subscribe, change the capture, get exactly ONE notification.
#[test]
fn subscribe_then_change_yields_exactly_one_notification() {
    let mut wire = Wire::start();
    let ok = wire.request(
        "resources/subscribe",
        json!({"uri": "sipnab://live/dialogs"}),
    );
    assert!(ok["error"].is_null(), "subscribe failed: {ok}");

    wire.forget_notifications();
    wire.swap_to(SWAPS[0]);
    // Two debounce windows: one for the change to be announced, one to catch a
    // second announcement if the server were sending per mutation.
    wire.drain_for(DEBOUNCE * 3);

    assert_eq!(
        wire.updates(),
        vec!["sipnab://live/dialogs".to_string()],
        "one change must produce exactly one notification, naming the URI \
         that changed"
    );
}

/// Unsubscribe, change the capture, get NOTHING.
///
/// The other half, and the one a broken cancellation passes silently: a
/// watcher that keeps running is invisible until someone counts.
#[test]
fn unsubscribe_then_change_yields_no_notification() {
    let mut wire = Wire::start();
    wire.request(
        "resources/subscribe",
        json!({"uri": "sipnab://live/dialogs"}),
    );
    // Prove the subscription was live before it is canceled, so a test that
    // passes because nothing ever worked fails here instead.
    wire.forget_notifications();
    wire.swap_to(SWAPS[0]);
    wire.drain_for(DEBOUNCE * 3);
    assert_eq!(
        wire.updates().len(),
        1,
        "the subscription was never delivering, so canceling it proves nothing"
    );

    let stop = wire.request(
        "resources/unsubscribe",
        json!({"uri": "sipnab://live/dialogs"}),
    );
    assert!(stop["error"].is_null(), "unsubscribe failed: {stop}");

    wire.forget_notifications();
    wire.swap_to(SWAPS[1]);
    wire.drain_for(DEBOUNCE * 3);
    assert_eq!(
        wire.updates(),
        Vec::<String>::new(),
        "a canceled subscription is still delivering"
    );
}

/// A burst of changes collapses into far fewer notifications than changes.
///
/// The burst is SPREAD ACROSS the debounce window on purpose, and that is the
/// whole design of this test. An earlier version fired six `open_capture`
/// calls back to back; they finished in 140 ms, the watcher never looked
/// during them, and deleting the debounce rule left the test green. A burst
/// has to outlast the window before collapsing it means anything.
///
/// The ceiling is derived from the observed elapsed time rather than written
/// down, because what the debounce promises is a RATE — at most one
/// notification per window, plus one for the tail — and a fixed number would
/// be a different promise that happened to hold on this machine.
/// The most notifications a correctly debouncing server may send for a burst
/// of changes lasting `burst`.
///
/// One per debounce window, plus one for the change still pending when the
/// burst ended -- that last one is delivered after the burst, which is why the
/// drain that collects it must NOT be added to `burst` here. Doing so was a
/// real defect: the drain inflated the ceiling while the change count stopped
/// growing, so on a runner where each capture swap is slow the two met (6
/// changes, ceiling 6) and the fixture guard fired. It held on a fast machine
/// and failed on CI.
///
/// Extracted from the test body so the arithmetic can be checked directly.
/// Inline, the only way to learn it was wrong was to run the whole fixture on
/// a machine slow enough to expose it.
fn debounce_ceiling(burst: Duration) -> usize {
    (burst.as_secs_f64() / DEBOUNCE.as_secs_f64()).ceil() as usize + 1
}

/// The ceiling counts the burst, never the drain that follows it.
///
/// Pins the defect directly: a two-second burst drained for two more seconds
/// must still be judged against the burst.
#[test]
fn the_debounce_ceiling_excludes_the_drain_that_follows_the_burst() {
    let burst = DEBOUNCE * 2;
    let with_drain = burst + DEBOUNCE * 2;
    assert_eq!(
        debounce_ceiling(burst),
        3,
        "two windows of changes plus the one still pending is three"
    );
    assert!(
        debounce_ceiling(with_drain) > debounce_ceiling(burst),
        "this test is anchored on the drain inflating the ceiling; if that is \
         no longer true the defect it guards cannot recur and the anchor needs \
         rewriting rather than deleting"
    );
    assert_eq!(
        debounce_ceiling(burst),
        3,
        "the ceiling must not depend on how long the caller drains afterwards"
    );
}

/// The ceiling must leave a fixture room to fail.
///
/// A ceiling at or above the number of changes makes the test vacuous -- a
/// server notifying on every single change would pass it -- which is what the
/// fixture guard in the burst test refuses. This checks the arithmetic admits
/// a failing server across the range of burst lengths a slow or fast runner
/// actually produces, so the guard fires on a real defect rather than on the
/// machine it happened to run on.
#[test]
fn the_ceiling_leaves_room_for_a_fixture_that_can_fail() {
    // A change every 100ms is the burst test's spacing; even at a tenth of
    // that rate the fixture must still be able to fail.
    for secs in [2u64, 3, 5, 10, 20] {
        let burst = Duration::from_secs(secs);
        let ceiling = debounce_ceiling(burst);
        let slow_changes = secs as usize * 2; // one change every 500ms
        assert!(
            slow_changes > ceiling,
            "over {secs}s a server changing twice a second makes \
             {slow_changes} change(s) against a ceiling of {ceiling}; the \
             fixture could not fail and the test would prove nothing"
        );
    }
    assert_eq!(
        debounce_ceiling(Duration::from_millis(1)),
        2,
        "a burst shorter than one window still allows the pending flush"
    );
}

#[test]
fn a_burst_of_changes_collapses_into_fewer_notifications() {
    /// Gap between changes, comfortably longer than the watcher's look
    /// interval so that an undebounced server would get a look in between.
    const SPACING: Duration = Duration::from_millis(100);

    let mut wire = Wire::start();
    wire.request(
        "resources/subscribe",
        json!({"uri": "sipnab://live/dialogs"}),
    );
    wire.forget_notifications();

    let started = Instant::now();
    let mut changes = 0;
    while started.elapsed() < DEBOUNCE * 2 {
        wire.swap_to(SWAPS[changes % SWAPS.len()]);
        changes += 1;
        std::thread::sleep(SPACING);
    }
    // Measured BEFORE the drain. The ceiling must cover the window in which
    // changes were made, and the `+ 1` below already covers the one still
    // pending when that window closed -- which is what the drain collects.
    // Including the drain in this figure inflated the ceiling while `changes`
    // stopped growing, so on a runner where each swap is slow the two met and
    // the fixture guard fired: 6 changes against a ceiling of 6. It held on a
    // fast machine and failed on CI, which is the shape of every timing bug
    // in this file.
    let burst = started.elapsed();
    wire.drain_for(DEBOUNCE * 2);
    let observed = started.elapsed();
    let updates = wire.updates().len();

    let ceiling = debounce_ceiling(burst);
    assert!(
        changes > ceiling,
        "the fixture cannot fail: {changes} change(s) against a ceiling of \
         {ceiling}, so a server notifying on every single change would pass"
    );
    assert!(
        updates >= 1,
        "{changes} changes over {observed:?} produced no notification at all"
    );
    assert!(
        updates <= ceiling,
        "{changes} changes over {observed:?} produced {updates} notifications, \
         past the {ceiling} a one-per-{DEBOUNCE:?} floor allows; a busy capture \
         would be a notification storm"
    );
}

/// A quiet capture produces nothing, however long a client waits.
///
/// The "not on a timer" half. A watcher that announced on a schedule would
/// wake the client here, where the store has not moved since it subscribed.
#[test]
fn a_quiet_capture_produces_no_notifications() {
    let mut wire = Wire::start();
    wire.request(
        "resources/subscribe",
        json!({"uri": "sipnab://live/dialogs"}),
    );
    wire.forget_notifications();
    wire.drain_for(DEBOUNCE * 4);
    assert_eq!(
        wire.updates(),
        Vec::<String>::new(),
        "the capture is drained and nothing changed; a notification here means \
         the watcher is announcing on a clock rather than on a change"
    );
}

/// Subscribing twice is idempotent from the client's side: one change, one
/// notification.
///
/// What this does NOT prove is that the repeat was deduplicated internally --
/// every watcher for one URI shares one registry entry, so the count comes out
/// right either way. Mutation testing established that: deleting the guard in
/// `Subscriptions::add` leaves this test green and only the unit test
/// `a_repeated_subscribe_does_not_start_a_second_watcher` red. Kept anyway,
/// because "a client that re-subscribes is not punished for it" is a promise
/// worth pinning on the wire, and it is the assertion that would catch a
/// second watcher racing the first into a double delivery.
#[test]
fn subscribing_twice_does_not_double_the_notifications() {
    let mut wire = Wire::start();
    for _ in 0..3 {
        let ok = wire.request(
            "resources/subscribe",
            json!({"uri": "sipnab://live/dialogs"}),
        );
        assert!(
            ok["error"].is_null(),
            "a repeated subscribe was refused: {ok}"
        );
    }
    wire.forget_notifications();
    wire.swap_to(SWAPS[0]);
    wire.drain_for(DEBOUNCE * 3);
    assert_eq!(
        wire.updates().len(),
        1,
        "three subscribes to one URI must still yield one notification per change"
    );
}

/// A resource that cannot change is refused, and the refusal names what can.
///
/// Accepting it would be a promise the server cannot keep: a reference page is
/// compiled into the binary, so a client waiting on it waits forever and has
/// no way to tell that from a quiet network.
#[test]
fn subscribing_to_a_resource_that_cannot_change_is_refused_by_name() {
    let mut wire = Wire::start();
    for uri in [
        "sipnab://reference/filter-dsl",
        "sipnab:///sip-proxy.pcap",
        "sipnab://live/streams",
        "file:///etc/passwd",
    ] {
        let reply = wire.request("resources/subscribe", json!({"uri": uri}));
        let message = reply["error"]["message"]
            .as_str()
            .unwrap_or_else(|| panic!("subscribing to '{uri}' was accepted: {reply}"));
        assert!(
            message.contains("sipnab://live/dialogs"),
            "the refusal for '{uri}' does not name what IS subscribable: {message}"
        );
    }
}

/// Unsubscribing from something never subscribed says so.
///
/// A silent success would leave a client that unsubscribed from the wrong URI
/// believing it had stopped, while the right one keeps delivering.
#[test]
fn unsubscribing_from_an_unwatched_uri_is_refused() {
    let mut wire = Wire::start();
    let reply = wire.request(
        "resources/unsubscribe",
        json!({"uri": "sipnab://live/dialogs"}),
    );
    assert!(
        reply["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("not subscribed")),
        "unsubscribing from an unwatched URI reported success: {reply}"
    );
}

/// Each subscribed URI is notified under its OWN name, and tracked separately.
///
/// The addressing half of PB4. A server that kept one flag for "something
/// changed" would pass every count-based test above and still tell a client
/// watching one call that the LIST had changed — which sends it to read the
/// wrong resource.
#[test]
fn each_subscribed_uri_is_notified_under_its_own_name() {
    let mut wire = Wire::start();
    let listed = text_payload(&wire.request(
        "tools/call",
        json!({"name": "list_dialogs", "arguments": {"limit": 1}}),
    ));
    let call_id = listed["dialogs"][0]["call_id"]
        .as_str()
        .unwrap_or_else(|| panic!("{PCAP} holds no dialogs"))
        .to_string();
    let per_call = format!("sipnab://live/dialogs/{call_id}");

    for uri in [&per_call, &"sipnab://live/dialogs".to_string()] {
        let ok = wire.request("resources/subscribe", json!({"uri": uri}));
        assert!(ok["error"].is_null(), "subscribe to {uri} failed: {ok}");
    }

    wire.forget_notifications();
    wire.swap_to(SWAPS[0]);
    wire.drain_for(DEBOUNCE * 3);
    let mut both = wire.updates();
    both.sort();
    let mut want = vec![per_call.clone(), "sipnab://live/dialogs".to_string()];
    want.sort();
    assert_eq!(
        both, want,
        "each subscribed URI must be named in its own notification"
    );

    // Drop one. The other must keep delivering, under its own name only.
    let stop = wire.request(
        "resources/unsubscribe",
        json!({"uri": "sipnab://live/dialogs"}),
    );
    assert!(stop["error"].is_null(), "unsubscribe failed: {stop}");

    wire.forget_notifications();
    wire.swap_to(SWAPS[1]);
    wire.drain_for(DEBOUNCE * 3);
    assert_eq!(
        wire.updates(),
        vec![per_call],
        "unsubscribing one URI must not disturb the other, and must not leave \
         the canceled one delivering"
    );
}

/// A per-call subscription is told when its dialog leaves.
///
/// The capture swap is folded into the fingerprint on purpose: a Call-ID from
/// the discarded capture names nothing, so a client watching it is holding a
/// pointer that has stopped meaning anything and must be told, even though the
/// rendered rows are empty on both sides.
#[test]
fn a_per_call_subscription_is_told_when_its_capture_is_replaced() {
    let mut wire = Wire::start();
    let listed = text_payload(&wire.request(
        "tools/call",
        json!({"name": "list_dialogs", "arguments": {"limit": 1}}),
    ));
    let call_id = listed["dialogs"][0]["call_id"]
        .as_str()
        .unwrap_or_else(|| panic!("{PCAP} holds no dialogs"))
        .to_string();
    let uri = format!("sipnab://live/dialogs/{call_id}");

    let ok = wire.request("resources/subscribe", json!({"uri": uri}));
    assert!(ok["error"].is_null(), "subscribe failed: {ok}");

    wire.forget_notifications();
    wire.swap_to(SWAPS[0]);
    wire.drain_for(DEBOUNCE * 3);
    assert_eq!(
        wire.updates(),
        vec![uri.clone()],
        "the watched dialog left with its capture and the client was not told"
    );

    // And the read that follows agrees: the dialog is gone.
    let read = wire.request("resources/read", json!({"uri": uri}));
    let text = read["result"]["contents"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("no text in {read}"));
    let page: Value = serde_json::from_str(text).expect("the resource is JSON");
    assert_eq!(
        page["returned"],
        json!(0),
        "the notification said to re-read, and the re-read must show the change"
    );
}
