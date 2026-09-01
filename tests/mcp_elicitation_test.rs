// SPDX-License-Identifier: MIT OR Apache-2.0

//! `elicitation/create`, proved as a real round trip on the wire (PB6).
//!
//! The unit tests in `src/mcp/elicit.rs` prove the capability predicate and the
//! shape of the request. They cannot prove the thing PB6 is actually for: that
//! a destructive tool STOPS, puts a question to whoever is driving the client,
//! and lets that answer decide. A handler that built a perfect
//! `ElicitRequestParams` and never sent it would pass every one of them.
//!
//! So every assertion here is made against a real `sipnab --mcp` process over
//! stdio, and the load-bearing ones are about the ROUND TRIP:
//!
//! - the `elicitation/create` request appears on the wire, as a JSON-RPC
//!   request with an id, BEFORE the tool result;
//! - answering `decline` leaves the process running and the capture loaded;
//! - answering `accept` with `confirm: true` is what makes the act happen;
//! - a client that declared no elicitation capability is never sent one, and
//!   the `dry_run` convention still works exactly as it did.
//!
//! That last one is not a formality. Elicitation is a client capability, so if
//! "nobody to ask" were read as "they said no", `shutdown_server` would become
//! impossible on every stock client — and the tests above would all still pass.

#![cfg(feature = "mcp")]

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdout, Command, Stdio};

/// A capture with one dialog and RTP.
const PCAP: &str = "tests/pcap-samples/sip-rtp-g711.pcap";

/// A different capture, for proving `open_capture` did or did not swap.
const OTHER_PCAP: &str = "sip-problem-call.pcap";

/// Where `--mcp-file-root` points.
const FILE_ROOT: &str = "tests/pcap-samples";

/// Longest a single reply may take before the test gives up.
const MAX_LINES: usize = 4000;

/// What the fake client answers an `elicitation/create` with.
#[derive(Clone, Copy)]
enum Answer {
    /// `accept` carrying `confirm: true` — the only thing that is a yes.
    Yes,
    /// `accept` carrying `confirm: false`. A client can do this, and reading
    /// the action alone would take it for a yes.
    AcceptedButUnticked,
    /// `accept` with no `content` at all.
    ///
    /// The spec makes `content` optional, so this is a well-formed answer, and
    /// it is the one that decides what the MISSING field defaults to. Nothing
    /// was ticked, so nothing was confirmed.
    AcceptedWithNothing,
    /// `decline`.
    No,
}

impl Answer {
    /// The `result` object this answer sends back.
    fn result(self) -> Value {
        match self {
            Self::Yes => json!({"action": "accept", "content": {"confirm": true}}),
            Self::AcceptedButUnticked => {
                json!({"action": "accept", "content": {"confirm": false}})
            }
            Self::AcceptedWithNothing => json!({"action": "accept"}),
            Self::No => json!({"action": "decline"}),
        }
    }
}

/// A `sipnab --mcp` process driven over stdio by a client that answers
/// elicitations.
struct Wire {
    /// Kept so stdin stays open and `Drop` can stop the server.
    child: Child,
    /// Line reader over the server's stdout, which is the JSON-RPC wire.
    reader: BufReader<ChildStdout>,
    /// Next JSON-RPC request id, so replies are matched rather than assumed.
    next_id: i64,
}

impl Wire {
    /// Spawn the server, handshake advertising `capabilities`, and wait for
    /// the replay to drain.
    ///
    /// `capabilities` is the CLIENT's half of `initialize`, which is the whole
    /// experiment: the same server binary must behave differently depending on
    /// what the client said it can do.
    fn start(capabilities: Value) -> Self {
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
                "--mcp-allow-shutdown",
            ])
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
                        "capabilities": capabilities,
                        "clientInfo": {"name": "elicitation-test", "version": "1"}
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
        let handshake = wire.await_reply(1, None).0;
        assert!(
            handshake["result"]["capabilities"].is_object(),
            "handshake failed: {handshake}"
        );

        // Bounded, so a genuine hang fails rather than running forever.
        const MAX_POLLS: usize = 400;
        let mut loaded = false;
        for _ in 0..MAX_POLLS {
            let reply = wire.request("tools/call", json!({"name": "capture_status"}));
            if text_payload(&reply)["source_exhausted"] == json!(true) {
                loaded = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        assert!(loaded, "capture never finished loading for {PCAP}");
        wire
    }

    /// Issue one request and return the reply, expecting no elicitation.
    fn request(&mut self, method: &str, params: Value) -> Value {
        let (reply, asked) = self.ask_and_answer(method, params, None);
        assert!(
            asked.is_empty(),
            "{method} raised an elicitation nobody expected: {asked:?}"
        );
        reply
    }

    /// Issue one request, answering any `elicitation/create` with `answer`.
    ///
    /// Returns the reply and every elicitation request seen while waiting, so
    /// a test can assert on the QUESTION as well as on the outcome.
    fn ask_and_answer(
        &mut self,
        method: &str,
        params: Value,
        answer: Option<Answer>,
    ) -> (Value, Vec<Value>) {
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
        self.await_reply(id, answer)
    }

    /// Read until the reply carrying `id` arrives.
    ///
    /// Any inbound REQUEST — a message carrying both `method` and `id` — is a
    /// server-to-client call. Elicitations are collected and answered with
    /// `answer`; anything else fails the test rather than being ignored,
    /// because a server calling a method this harness does not implement would
    /// otherwise look like a hang.
    fn await_reply(&mut self, id: i64, answer: Option<Answer>) -> (Value, Vec<Value>) {
        let mut asked = Vec::new();
        let mut line = String::new();
        for _ in 0..MAX_LINES {
            line.clear();
            if self.reader.read_line(&mut line).unwrap_or(0) == 0 {
                panic!("sipnab closed stdout while waiting for id {id}; saw {asked:?}");
            }
            let Ok(msg) = serde_json::from_str::<Value>(line.trim()) else {
                continue;
            };
            if msg["id"] == json!(id) && msg["method"].is_null() {
                return (msg, asked);
            }
            if msg["method"].is_string() && !msg["id"].is_null() {
                assert_eq!(
                    msg["method"], "elicitation/create",
                    "the server called a method this client does not implement: {msg}"
                );
                let answer = answer.expect(
                    "the server asked for a confirmation in a case where none was expected",
                );
                let reply = json!({
                    "jsonrpc": "2.0",
                    "id": msg["id"].clone(),
                    "result": answer.result(),
                });
                asked.push(msg);
                let stdin = self.child.stdin.as_mut().expect("stdin");
                writeln!(stdin, "{reply}").expect("write elicitation answer");
                stdin.flush().expect("flush");
            }
        }
        panic!("no reply to id {id} within {MAX_LINES} lines; saw {asked:?}");
    }

    /// Every Call-ID the loaded capture currently holds.
    fn call_ids(&mut self) -> Vec<String> {
        let reply = self.request(
            "tools/call",
            json!({"name": "list_dialogs", "arguments": {"limit": 100}}),
        );
        text_payload(&reply)["dialogs"]
            .as_array()
            .expect("a dialogs array")
            .iter()
            .filter_map(|d| d["call_id"].as_str().map(str::to_string))
            .collect()
    }
}

impl Drop for Wire {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A client that declares it can answer a form elicitation.
fn a_client_that_can_be_asked() -> Value {
    json!({"elicitation": {"form": {}}})
}

/// The payload block of a successful tool result, parsed.
fn text_payload(reply: &Value) -> Value {
    let text = reply["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("expected a text payload, got {reply}"));
    serde_json::from_str(text).unwrap_or_else(|_| panic!("payload is not JSON: {text}"))
}

/// The confirmation is a REQUEST, and it carries a form sipnab can read back.
///
/// The one assertion the feature cannot be said to exist without: a
/// notification, or a message with no `id`, is something a client may ignore
/// and sipnab could never wait on. What must be on the wire is a request.
#[test]
fn stopping_asks_the_operator_with_a_real_request() {
    let mut wire = Wire::start(a_client_that_can_be_asked());
    let (reply, asked) = wire.ask_and_answer(
        "tools/call",
        json!({"name": "shutdown_server", "arguments": {"dry_run": false}}),
        Some(Answer::No),
    );

    assert_eq!(
        asked.len(),
        1,
        "a real stop must ask exactly once: {asked:?} / {reply}"
    );
    let ask = &asked[0];
    assert!(
        ask["id"].is_number() || ask["id"].is_string(),
        "the confirmation must be a request with an id, not a notification: {ask}"
    );
    assert!(
        ask["params"]["message"]
            .as_str()
            .expect("a message")
            .contains("STOP"),
        "the person is not told what they are approving: {ask}"
    );
    let schema = &ask["params"]["requestedSchema"];
    assert_eq!(schema["type"], "object", "not an object schema: {ask}");
    assert_eq!(
        schema["properties"]["confirm"]["type"], "boolean",
        "the form does not ask the field sipnab reads back: {ask}"
    );
}

/// Declining stops nothing, and the process is still answering afterwards.
#[test]
fn a_declined_confirmation_leaves_the_server_running() {
    let mut wire = Wire::start(a_client_that_can_be_asked());
    let (reply, asked) = wire.ask_and_answer(
        "tools/call",
        json!({"name": "shutdown_server", "arguments": {"dry_run": false}}),
        Some(Answer::No),
    );
    assert_eq!(asked.len(), 1, "no confirmation was asked for: {reply}");

    let payload = text_payload(&reply);
    assert_eq!(
        payload["would_stop"],
        json!(false),
        "a declined confirmation reported a stop: {payload}"
    );
    assert_eq!(payload["confirmed_by_operator"], json!(false));
    assert_eq!(payload["dry_run"], json!(false), "this was not a dry run");

    // The proof that outlives the payload: the process is still there.
    let status = wire.request("tools/call", json!({"name": "capture_status"}));
    assert!(
        status["error"].is_null(),
        "the server stopped despite the decline: {status}"
    );
}

/// An accepted form carrying `confirm: false` is a refusal, not a yes.
///
/// A client may render the checkbox and let the person submit it unticked.
/// Reading `action` alone would stop the server on a form deliberately left
/// empty, and every other test here would still pass.
#[test]
fn an_accepted_form_that_says_no_stops_nothing() {
    let mut wire = Wire::start(a_client_that_can_be_asked());
    let (reply, asked) = wire.ask_and_answer(
        "tools/call",
        json!({"name": "shutdown_server", "arguments": {"dry_run": false}}),
        Some(Answer::AcceptedButUnticked),
    );
    assert_eq!(asked.len(), 1);
    let payload = text_payload(&reply);
    assert_eq!(
        payload["would_stop"],
        json!(false),
        "action=accept was taken for a yes although confirm was false: {payload}"
    );
    assert!(
        payload["note"]
            .as_str()
            .expect("a note")
            .contains("confirm"),
        "the caller is not told which half refused: {payload}"
    );
    assert!(
        wire.request("tools/call", json!({"name": "capture_status"}))["error"].is_null(),
        "the server stopped on an unticked confirmation"
    );
}

/// An accepted form with NO content is a refusal, not a yes.
///
/// `content` is optional in the spec, so a client may answer `accept` and send
/// nothing. That makes the DEFAULT for the missing field a decision, and the
/// only safe one for an irreversible act is "not confirmed". Mutation testing
/// found this: flipping that default from `false` to `true` passed every other
/// test in this file, because they all send the field.
#[test]
fn an_accepted_form_carrying_nothing_stops_nothing() {
    let mut wire = Wire::start(a_client_that_can_be_asked());
    let (reply, asked) = wire.ask_and_answer(
        "tools/call",
        json!({"name": "shutdown_server", "arguments": {"dry_run": false}}),
        Some(Answer::AcceptedWithNothing),
    );
    assert_eq!(asked.len(), 1);
    let payload = text_payload(&reply);
    assert_eq!(
        payload["would_stop"],
        json!(false),
        "an answer that confirmed nothing was taken for a confirmation: {payload}"
    );
    assert_eq!(payload["confirmed_by_operator"], json!(false));
    assert!(
        wire.request("tools/call", json!({"name": "capture_status"}))["error"].is_null(),
        "the server stopped on a form that carried no confirmation"
    );
}

/// Confirming a stop stops the process.
///
/// The other half of the pair, and the one a handler that always refused would
/// fail while passing every decline test above. The exit is asserted rather
/// than the payload alone: `would_stop: true` from a process that is still
/// running is exactly the report `dry_run` used to make impossible.
#[test]
fn a_confirmed_stop_actually_stops() {
    let mut wire = Wire::start(a_client_that_can_be_asked());
    let (reply, asked) = wire.ask_and_answer(
        "tools/call",
        json!({"name": "shutdown_server", "arguments": {"dry_run": false}}),
        Some(Answer::Yes),
    );
    assert_eq!(asked.len(), 1, "the stop did not ask: {reply}");
    let payload = text_payload(&reply);
    assert_eq!(payload["would_stop"], json!(true), "{payload}");
    assert_eq!(payload["confirmed_by_operator"], json!(true), "{payload}");

    // Bounded: a shutdown that never happens must fail rather than hang.
    const MAX_POLLS: usize = 400;
    let mut exited = false;
    for _ in 0..MAX_POLLS {
        if wire.child.try_wait().ok().flatten().is_some() {
            exited = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    assert!(
        exited,
        "the confirmation was accepted, the reply said would_stop, and the \
         process is still running"
    );
}

/// A dry run asks nobody.
///
/// Nothing happens on a dry run, so there is nothing to approve — and a
/// confirmation dialog with no consequence behind it teaches whoever reads it
/// to click through the next one.
#[test]
fn a_dry_run_asks_nobody() {
    let mut wire = Wire::start(a_client_that_can_be_asked());
    let (reply, asked) = wire.ask_and_answer(
        "tools/call",
        json!({"name": "shutdown_server", "arguments": {}}),
        None,
    );
    assert!(
        asked.is_empty(),
        "a dry run raised a confirmation: {asked:?}"
    );
    let payload = text_payload(&reply);
    assert_eq!(payload["dry_run"], json!(true));
    assert_eq!(payload["would_stop"], json!(false));
    assert_eq!(
        payload["confirmed_by_operator"],
        Value::Null,
        "nobody was asked, so the answer is null rather than a verdict: {payload}"
    );
}

/// A client that cannot be asked still gets the `dry_run` convention.
///
/// The regression this whole design turns on. Elicitation is a client
/// capability; if "nobody to ask" were read as "they said no",
/// `shutdown_server` would stop working on every stock client, and the tests
/// above would all still pass.
#[test]
fn a_client_without_the_capability_is_never_asked_and_still_works() {
    let mut wire = Wire::start(json!({}));
    let (reply, asked) = wire.ask_and_answer(
        "tools/call",
        json!({"name": "shutdown_server", "arguments": {"dry_run": false}}),
        None,
    );
    assert!(
        asked.is_empty(),
        "a client that declared no elicitation capability was sent one: {asked:?}"
    );
    let payload = text_payload(&reply);
    assert_eq!(
        payload["would_stop"],
        json!(true),
        "the convention stopped working for a client that cannot be asked: {payload}"
    );
    assert_eq!(
        payload["confirmed_by_operator"],
        Value::Null,
        "nobody was asked, so the answer must be null rather than false: {payload}"
    );
}

/// Declining a capture swap keeps the capture, and says which one it kept.
#[test]
fn a_declined_swap_keeps_every_dialog() {
    let mut wire = Wire::start(a_client_that_can_be_asked());
    let before = wire.call_ids();
    assert!(
        !before.is_empty(),
        "{PCAP} holds no dialogs; the fixture cannot prove anything"
    );

    let (reply, asked) = wire.ask_and_answer(
        "tools/call",
        json!({"name": "open_capture", "arguments": {"filename": OTHER_PCAP}}),
        Some(Answer::No),
    );
    assert_eq!(asked.len(), 1, "the swap did not ask: {reply}");
    assert!(
        asked[0]["params"]["message"]
            .as_str()
            .expect("a message")
            .contains(OTHER_PCAP),
        "the person is not told which capture would replace theirs: {}",
        asked[0]
    );
    assert!(
        !reply["error"].is_null(),
        "a declined swap reported success: {reply}"
    );

    let after = wire.call_ids();
    assert_eq!(
        after, before,
        "the capture was replaced despite the decline"
    );
}

/// Confirming a capture swap performs it.
///
/// The other half of the pair. Without it, a handler that always refused
/// would pass every decline test in this file.
#[test]
fn a_confirmed_swap_replaces_the_capture() {
    let mut wire = Wire::start(a_client_that_can_be_asked());
    let before = wire.call_ids();
    assert!(!before.is_empty(), "{PCAP} holds no dialogs");

    let (reply, asked) = wire.ask_and_answer(
        "tools/call",
        json!({"name": "open_capture", "arguments": {"filename": OTHER_PCAP}}),
        Some(Answer::Yes),
    );
    assert_eq!(asked.len(), 1, "the swap did not ask: {reply}");
    assert!(
        reply["error"].is_null(),
        "the confirmed swap failed: {reply}"
    );
    assert_eq!(text_payload(&reply)["status"], "loading");

    // The load runs on a background thread; poll until it finishes, then the
    // vocabulary must be the other capture's.
    const MAX_POLLS: usize = 400;
    for _ in 0..MAX_POLLS {
        let status = wire.request("tools/call", json!({"name": "capture_status"}));
        if text_payload(&status)["load"]["done"] == json!(true) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    let after = wire.call_ids();
    assert_ne!(
        after, before,
        "the confirmation was accepted and nothing was replaced"
    );
}
