// SPDX-License-Identifier: MIT OR Apache-2.0

//! The 2025-06-18 protocol features sipnab uses, proved on the wire (PB1, PB5).
//!
//! Both are properties of the SERVER rather than of any one tool, and both live
//! in `SipnabMcp::call_tool` — the single hand-written point every tool call
//! passes through. A unit test over the helper functions proves the rules; only
//! a real client proves they are wired to anything, which is what this file is.
//!
//! - **PB1** — `structuredContent` beside the text block, and per-tool
//!   `outputSchema` for the tools that declare one. The schema is a promise to
//!   the client, so every declared one is compiled and the payload it describes
//!   is validated against it here. A tool that grows a schema without a case in
//!   [`schema_probes`] fails this suite rather than shipping an unchecked
//!   promise.
//! - **PB5** — `notifications/progress` from `capture_health`, which is the one
//!   tool that makes the caller wait. Both directions are asserted: reports
//!   arrive when a `progressToken` was sent, and NOTHING arrives when it was
//!   not, because the spec forbids the second.
//!
//! The wire plumbing is local rather than taken from `support/mcp.rs`. That
//! harness matches replies by id and discards everything else, which is exactly
//! what a progress test cannot do.

#![cfg(feature = "mcp")]

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdout, Command, Stdio};

/// A capture with real dialogs and RTP, so payloads are not all empty.
const PCAP: &str = "tests/pcap-samples/sip-rtp-g711.pcap";

/// Longest a single reply may take before the test gives up.
const MAX_LINES: usize = 4000;

/// A `sipnab --mcp` process driven over stdio, keeping the notifications.
struct Wire {
    /// Kept so stdin stays open and `Drop` can stop the server.
    child: Child,
    /// Line reader over the server's stdout, which is the JSON-RPC wire.
    reader: BufReader<ChildStdout>,
    /// Next JSON-RPC request id, so replies are matched rather than assumed.
    next_id: i64,
    /// Every notification seen while waiting for the most recent reply.
    notifications: Vec<Value>,
}

impl Wire {
    /// Spawn the server on [`PCAP`], handshake, and wait for the replay to drain.
    ///
    /// `--mcp-allow-save-findings` because `save_findings` declares an
    /// `outputSchema` and a server that refuses it cannot prove the payload
    /// conforms.
    fn start() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_sipnab"))
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .args([
                "--mcp",
                "-N",
                "-I",
                PCAP,
                "--quiet",
                "--mcp-allow-save-findings",
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
                        // The revision that defines `structuredContent`.
                        "protocolVersion": "2025-06-18",
                        "capabilities": {},
                        "clientInfo": {"name": "protocol-features-test", "version": "1"}
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
            notifications: Vec::new(),
        };

        // Bounded, so a genuine hang fails rather than running forever. Polling
        // `capture_status` until the file source drains is what that tool is
        // for, and without it these tests race the pcap reader.
        const MAX_POLLS: usize = 400;
        let mut loaded = false;
        for _ in 0..MAX_POLLS {
            let reply = wire.call("capture_status", json!({}), None);
            // Read from the TEXT block, never from `structuredContent`. The
            // harness must not depend on the feature these tests exist to
            // check: with the dependency in, removing structuredContent fails
            // every test here with "capture never finished loading", which
            // names the wrong cause.
            if text_payload(&reply)["source_exhausted"] == json!(true) {
                loaded = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        assert!(loaded, "capture never finished loading for {PCAP}");
        wire
    }

    /// Issue one `tools/call` and return the raw JSON-RPC reply.
    ///
    /// `progress_token`, when given, is sent as the request's
    /// `_meta.progressToken` — the only thing that entitles the server to send
    /// progress notifications back. Notifications seen while waiting land in
    /// [`Wire::notifications`], which is cleared per call so a test reads only
    /// what its own call produced.
    fn call(&mut self, tool: &str, args: Value, progress_token: Option<&str>) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.notifications.clear();

        let mut params = json!({"name": tool, "arguments": args});
        if let Some(token) = progress_token {
            params["_meta"] = json!({"progressToken": token});
        }
        {
            let stdin = self.child.stdin.as_mut().expect("stdin");
            writeln!(
                stdin,
                "{}",
                json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": params})
            )
            .expect("write tool call");
            stdin.flush().expect("flush");
        }

        let mut line = String::new();
        for _ in 0..MAX_LINES {
            line.clear();
            if self.reader.read_line(&mut line).unwrap_or(0) == 0 {
                panic!("sipnab closed stdout while waiting for {tool}");
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
        panic!("no reply to {tool} within {MAX_LINES} lines");
    }

    /// Every tool the server advertises, with its full metadata.
    fn tools(&mut self) -> Vec<Value> {
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
        let mut line = String::new();
        for _ in 0..MAX_LINES {
            line.clear();
            if self.reader.read_line(&mut line).unwrap_or(0) == 0 {
                panic!("sipnab closed stdout while waiting for tools/list");
            }
            let Ok(msg) = serde_json::from_str::<Value>(line.trim()) else {
                continue;
            };
            if msg["id"] == json!(id) {
                return msg["result"]["tools"]
                    .as_array()
                    .expect("tools/list returns an array")
                    .clone();
            }
        }
        panic!("no reply to tools/list within {MAX_LINES} lines");
    }

    /// The `notifications/progress` params carried by the last call.
    fn progress_reports(&self) -> Vec<&Value> {
        self.notifications
            .iter()
            .filter(|n| n["method"] == json!("notifications/progress"))
            .map(|n| &n["params"])
            .collect()
    }

    /// The first Call-ID this capture holds, so no test hardcodes one.
    fn a_call_id(&mut self) -> String {
        let reply = self.call("list_dialogs", json!({"limit": 1}), None);
        let payload = text_payload(&reply);
        payload["dialogs"][0]["call_id"]
            .as_str()
            .unwrap_or_else(|| panic!("no dialogs in {PCAP}: {reply}"))
            .to_string()
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

/// Arguments that make each schema-declaring tool answer.
///
/// Keyed by tool name and resolved against the live `tools/list`, so a tool
/// that starts declaring an `outputSchema` without an entry here is named by
/// the failure rather than skipped.
/// Schema-declaring tools that cannot be driven to a payload here, each with
/// the reason.
///
/// A list like this is where coverage goes to die, so every entry names a
/// PROPERTY of the tool rather than a convenience, and the gates below fail if
/// an entry stops being registered, loses its reason, or becomes drivable.
const SCHEMA_NOT_DRIVEN: &[(&str, &str)] = &[(
    "query_relay",
    "transmits to a relay that must be reachable, and needs a live capture \
     source for a transmit permit to exist at all. A stock test server has \
     neither, so every call here refuses before a payload is built. Driving it \
     would mean standing up a relay and a live interface inside a unit test, \
     and a fake reachable at a real address is a transmitting test.",
)];

fn schema_probes(call_id: &str) -> Vec<(&'static str, Value)> {
    vec![
        ("aggregate_dialogs", json!({"group_by": "state"})),
        ("capture_status", json!({})),
        ("server_capabilities", json!({})),
        ("list_tls_libraries", json!({})),
        // One second: the smallest window the tool accepts, because this is
        // about the response shape and not about the sampling.
        ("capture_health", json!({"sample_seconds": 1})),
        ("find_correlated", json!({"call_id": call_id})),
        (
            "save_findings",
            json!({"summary": "outputSchema conformance probe"}),
        ),
        ("explain_attribution", json!({"call_id": call_id})),
        // No `limit`, so the response is the untruncated shape: `truncated`
        // false and `relay_was_consulted` computed over every orphan rather
        // than over a page.
        ("reconcile_orphans", json!({})),
        // A well-formed pointer at a file that is not there. The answer is the
        // `unresolvable` shape, which is the half of `NgDecode` most likely to
        // drift out of its schema: it is the branch that fills almost nothing,
        // so a required field wrongly added to the type would show up HERE
        // first and nowhere else.
        (
            "decode_ng",
            json!({"frame_ref": "absent.pcap#1@0000000000000000"}),
        ),
    ]
}

/// PB1's whole point: the payload arrives parsed, not as a string to re-parse.
///
/// Asserted against the text block rather than against a literal, because the
/// guarantee is that the two are ONE document. A test comparing
/// `structuredContent` to a hand-written expectation would still pass if the
/// text block drifted away from it.
#[test]
fn a_json_payload_arrives_as_structured_content_matching_its_text_block() {
    let mut wire = Wire::start();
    let call_id = wire.a_call_id();

    for (tool, args) in [
        ("capture_status", json!({})),
        ("aggregate_dialogs", json!({"group_by": "state"})),
        ("get_dialog", json!({"call_id": call_id.clone()})),
        ("rtp_stats", json!({"call_id": call_id})),
    ] {
        let reply = wire.call(tool, args, None);
        let structured = &reply["result"]["structuredContent"];
        assert!(
            structured.is_object(),
            "{tool} returned no structuredContent: {reply}"
        );
        assert_eq!(
            *structured,
            text_payload(&reply),
            "{tool}'s structuredContent and its text block must be one document"
        );
    }
}

/// A drawn ladder is a document, not an object. Wrapping it in a synthetic key
/// would put a shape in `structuredContent` that the text block does not have.
#[test]
fn a_rendered_document_carries_no_structured_content() {
    let mut wire = Wire::start();
    let call_id = wire.a_call_id();
    let reply = wire.call("render_ladder", json!({"call_id": call_id}), None);

    assert!(
        reply["result"]["content"][0]["text"].is_string(),
        "render_ladder still returns its ladder as text: {reply}"
    );
    assert!(
        reply["result"]["structuredContent"].is_null(),
        "a rendered ladder has no object to publish: {reply}"
    );
}

/// `timeline` returns a top-level array, which the MCP schema types
/// `structuredContent` cannot carry.
#[test]
fn a_top_level_array_payload_carries_no_structured_content() {
    let mut wire = Wire::start();
    let reply = wire.call("timeline", json!({}), None);

    assert!(
        text_payload(&reply).is_array(),
        "the fixture is only meaningful while timeline returns an array: {reply}"
    );
    assert!(
        reply["result"]["structuredContent"].is_null(),
        "structuredContent is typed as an object; an array has none to give: {reply}"
    );
}

/// Every declared `outputSchema` must describe the payload the tool actually
/// returns, and every one must have a case above.
///
/// This is the check that makes a schema a promise instead of decoration: a
/// client is entitled to validate against it, so the server has to.
#[test]
fn every_declared_output_schema_matches_the_payload_it_describes() {
    let mut wire = Wire::start();
    let call_id = wire.a_call_id();
    let probes = schema_probes(&call_id);

    let declared: Vec<(String, Value)> = wire
        .tools()
        .into_iter()
        .filter(|t| t["outputSchema"].is_object())
        .map(|t| {
            (
                t["name"].as_str().unwrap_or_default().to_string(),
                t["outputSchema"].clone(),
            )
        })
        .collect();
    assert!(
        !declared.is_empty(),
        "no tool declares an outputSchema, so this gate proves nothing"
    );

    for (name, schema) in &declared {
        assert_eq!(
            schema["type"],
            json!("object"),
            "{name}'s outputSchema must have root type object; structuredContent \
             cannot carry anything else"
        );
        if SCHEMA_NOT_DRIVEN.iter().any(|(t, _)| t == name) {
            continue;
        }
        let Some((_, args)) = probes.iter().find(|(t, _)| t == name) else {
            panic!(
                "{name} declares an outputSchema but has no case in schema_probes, \
                 so nothing checks that its payload conforms"
            );
        };

        let validator = jsonschema::validator_for(schema)
            .unwrap_or_else(|e| panic!("{name}'s outputSchema does not compile: {e}"));
        let reply = wire.call(name, args.clone(), None);
        let structured = &reply["result"]["structuredContent"];
        assert!(
            structured.is_object(),
            "{name} declares an outputSchema but returned no structuredContent: {reply}"
        );
        if let Err(e) = validator.validate(structured) {
            panic!("{name}'s payload does not match its own outputSchema: {e}\n{structured:#}");
        }
    }
}

/// PB5: a caller that sent a `progressToken` is told how far through the wait
/// it is, rather than watching a request that could equally be a hung server.
#[test]
fn capture_health_reports_progress_when_the_caller_asks() {
    let mut wire = Wire::start();
    // Three seconds so more than one tick fits inside the window; a
    // one-second window could legitimately report once.
    let reply = wire.call(
        "capture_health",
        json!({"sample_seconds": 3}),
        Some("probe-token"),
    );
    // Asserted on `isError` rather than on `structuredContent`: this test is
    // about PB5, and borrowing PB1's field would make it fail for PB1's reasons.
    assert_eq!(
        reply["result"]["isError"],
        json!(false),
        "the tool must still answer: {reply}"
    );

    let reports = wire.progress_reports();
    assert!(
        reports.len() >= 2,
        "a three-second window must report more than once; got {}: {:?}",
        reports.len(),
        reports
    );
    for report in &reports {
        assert_eq!(
            report["progressToken"],
            json!("probe-token"),
            "every report is keyed to the caller's own token: {report}"
        );
        assert_eq!(
            report["total"],
            json!(3.0),
            "the window is the total a report is measured against: {report}"
        );
    }
    let values: Vec<f64> = reports
        .iter()
        .map(|r| r["progress"].as_f64().unwrap_or(f64::NAN))
        .collect();
    assert!(
        values.windows(2).all(|w| w[1] >= w[0]),
        "MCP requires progress to rise across a request's reports; got {values:?}"
    );
    assert!(
        values.iter().all(|v| *v <= 3.0),
        "no report may claim more elapsed than the window holds; got {values:?}"
    );
}

/// The other direction, which is the one the spec states as a MUST NOT: a
/// request with no `progressToken` earns no notifications.
#[test]
fn capture_health_sends_no_progress_when_the_caller_did_not_ask() {
    let mut wire = Wire::start();
    let reply = wire.call("capture_health", json!({"sample_seconds": 3}), None);
    // Asserted on `isError` rather than on `structuredContent`: this test is
    // about PB5, and borrowing PB1's field would make it fail for PB1's reasons.
    assert_eq!(
        reply["result"]["isError"],
        json!(false),
        "the tool must still answer: {reply}"
    );

    assert!(
        wire.progress_reports().is_empty(),
        "a request that carried no progressToken must earn no progress \
         notifications; got {:?}",
        wire.progress_reports()
    );
}

/// Every excuse names a registered tool and gives a reason.
///
/// Without this an entry could outlive the tool it excuses, and a list naming
/// something deleted asserts nothing while looking like it asserts something.
#[test]
fn every_schema_excuse_is_registered_and_reasoned() {
    let mut wire = Wire::start();
    let registered: Vec<String> = wire
        .tools()
        .into_iter()
        .filter_map(|t| t["name"].as_str().map(str::to_owned))
        .collect();
    assert!(
        !SCHEMA_NOT_DRIVEN.is_empty(),
        "the excuse list is empty, so the gate below proves nothing"
    );
    for (tool, reason) in SCHEMA_NOT_DRIVEN {
        assert!(
            registered.iter().any(|r| r == tool),
            "{tool} is excused from schema probing and is not a registered tool"
        );
        assert!(
            reason.len() > 60,
            "{tool}'s excuse must say WHY, not merely that it is excused"
        );
    }
}

/// The excused tool really is undrivable here, and refuses for the stated
/// reason rather than answering.
///
/// This is the half that keeps the excuse honest. If `query_relay` ever starts
/// answering on a stock server, that is a hole in the opt-in -- a tool that
/// transmits would be reachable without `--mcp-allow-relay-query`, without a
/// configured relay, and on a run reading a FILE. The excuse and the security
/// property rest on the same fact, so one test covers both.
#[test]
fn the_excused_tool_refuses_on_a_stock_server() {
    let mut wire = Wire::start();
    let reply = wire.call("query_relay", json!({}), None);

    assert!(
        reply["result"].is_null(),
        "query_relay answered on a server with no relay configured, no opt-in, \
         and a file source. A tool that transmits must not be reachable there: \
         {reply}"
    );
    let message = reply["error"]["message"].as_str().unwrap_or_default();
    for required in [
        "--mcp-allow-relay-query",
        "--rtpengine-control",
        "live",
        "transmit permit",
    ] {
        assert!(
            message.contains(required),
            "the refusal must name {required} so an operator knows which of the \
             three requirements is missing: {message}"
        );
    }
}
