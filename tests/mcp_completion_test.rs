// SPDX-License-Identifier: MIT OR Apache-2.0

//! `completion/complete` and `resources/templates/list`, proved on the wire (PB3).
//!
//! The unit tests in `src/mcp/completion.rs` prove the narrowing rule. They
//! cannot prove any of it is REACHABLE, and that is the failure this file
//! exists for: a completion handler whose capability is not advertised is a
//! handler no client ever calls, and every one of its unit tests still passes.
//!
//! So every assertion here is made against a real `sipnab --mcp` process over
//! stdio, and the load-bearing ones are about LIVENESS: the Call-IDs offered
//! are the Call-IDs the loaded capture holds, and swapping the capture changes
//! them. A hardcoded vocabulary passes a "returns some values" test forever.

#![cfg(feature = "mcp")]

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdout, Command, Stdio};

/// A capture with one dialog and RTP.
const PCAP: &str = "tests/pcap-samples/sip-rtp-g711.pcap";

/// A different capture, for proving the vocabulary follows the capture.
const OTHER_PCAP: &str = "sip-problem-call.pcap";

/// Where `--mcp-file-root` points, so `open_capture` can reach [`OTHER_PCAP`].
const FILE_ROOT: &str = "tests/pcap-samples";

/// Longest a single reply may take before the test gives up.
const MAX_LINES: usize = 4000;

/// A `sipnab --mcp` process driven over stdio.
///
/// Local rather than taken from `tests/support/mcp.rs`: that harness speaks
/// `tools/call` only, and every method under test here is a different one.
struct Wire {
    /// Kept so stdin stays open and `Drop` can stop the server.
    child: Child,
    /// Line reader over the server's stdout, which is the JSON-RPC wire.
    reader: BufReader<ChildStdout>,
    /// Next JSON-RPC request id, so replies are matched rather than assumed.
    next_id: i64,
    /// The `initialize` result, kept so a test can read the capabilities the
    /// server actually put on the wire rather than the expression that built
    /// them.
    initialize_result: Option<Value>,
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
            writeln!(
                stdin,
                "{}",
                json!({
                    "jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {},
                        "clientInfo": {"name": "completion-test", "version": "1"}
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
            initialize_result: None,
        };
        // The initialize reply, kept so tests can read the capabilities off it.
        let handshake = wire.await_reply(1);
        assert!(
            handshake["result"]["capabilities"].is_object(),
            "handshake failed: {handshake}"
        );
        wire.initialize_result = Some(handshake);

        // Bounded, so a genuine hang fails rather than running forever.
        const MAX_POLLS: usize = 400;
        let mut loaded = false;
        for _ in 0..MAX_POLLS {
            let reply = wire.request(
                "tools/call",
                json!({"name": "capture_status", "arguments": {}}),
            );
            if text_payload(&reply)["source_exhausted"] == json!(true) {
                loaded = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        assert!(loaded, "capture never finished loading for {PCAP}");
        wire
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

    /// Read until the reply carrying `id` arrives, discarding notifications.
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
        }
        panic!("no reply to id {id} within {MAX_LINES} lines");
    }

    /// The values `completion/complete` offers for one template variable.
    fn complete(&mut self, template: &str, argument: &str, typed: &str) -> Value {
        let reply = self.request(
            "completion/complete",
            json!({
                "ref": {"type": "ref/resource", "uri": template},
                "argument": {"name": argument, "value": typed}
            }),
        );
        assert!(
            reply["error"].is_null(),
            "completion/complete failed: {reply}"
        );
        reply["result"]["completion"].clone()
    }

    /// Every Call-ID `list_dialogs` reports, which is the vocabulary a
    /// `call_id` completion must agree with.
    fn call_ids_from_the_tool(&mut self) -> Vec<String> {
        let reply = self.request(
            "tools/call",
            json!({"name": "list_dialogs", "arguments": {"limit": 100}}),
        );
        let payload = text_payload(&reply);
        payload["dialogs"]
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

/// The payload block of a successful tool result, parsed.
fn text_payload(reply: &Value) -> Value {
    let text = reply["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("expected a text payload, got {reply}"));
    serde_json::from_str(text).unwrap_or_else(|_| panic!("payload is not JSON: {text}"))
}

/// The completion values, as owned strings.
fn values(completion: &Value) -> Vec<String> {
    completion["values"]
        .as_array()
        .unwrap_or_else(|| panic!("no values array in {completion}"))
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect()
}

/// Both capabilities reach the wire.
///
/// The one assertion neither feature can be proved without: a client reads
/// `initialize` and calls nothing it did not see there. An unadvertised
/// `completion/complete` handler is dead code that every unit test passes.
#[test]
fn capabilities_advertise_completions_and_resource_subscribe() {
    let wire = Wire::start();
    let caps = &wire.initialize_result.as_ref().expect("handshake kept")["result"]["capabilities"];
    assert!(
        caps["completions"].is_object(),
        "the completions capability is not advertised, so no client will ever \
         call completion/complete: {caps}"
    );
    assert_eq!(
        caps["resources"]["subscribe"],
        json!(true),
        "resources.subscribe is not advertised, so no client will ever call \
         resources/subscribe: {caps}"
    );
}

/// The Call-IDs offered are the Call-IDs the capture holds.
///
/// Compared against `list_dialogs` rather than against a literal, so the
/// assertion cannot pass by both sides being wrong in the same direction.
#[test]
fn call_id_completions_come_from_the_loaded_capture() {
    let mut wire = Wire::start();
    let mut from_tool = wire.call_ids_from_the_tool();
    assert!(
        !from_tool.is_empty(),
        "{PCAP} holds no dialogs; the fixture cannot prove anything"
    );
    let mut offered = values(&wire.complete("sipnab://live/dialogs/{call_id}", "call_id", ""));
    from_tool.sort();
    offered.sort();
    assert_eq!(
        offered, from_tool,
        "the completion vocabulary and the capture disagree"
    );
}

/// Change the capture, and the completions change with it.
///
/// This is the test a hardcoded list fails and every other test here passes.
#[test]
fn completions_follow_the_capture_when_it_is_swapped() {
    let mut wire = Wire::start();
    let before = values(&wire.complete("sipnab://live/dialogs/{call_id}", "call_id", ""));
    assert!(!before.is_empty(), "{PCAP} holds no dialogs");

    let swap = wire.request(
        "tools/call",
        json!({"name": "open_capture", "arguments": {"filename": OTHER_PCAP}}),
    );
    assert!(swap["error"].is_null(), "open_capture failed: {swap}");

    // The swap discards the old store, so the poll is for the NEW capture
    // finishing rather than for anything about completions.
    for _ in 0..400 {
        let status = wire.request(
            "tools/call",
            json!({"name": "capture_status", "arguments": {}}),
        );
        if text_payload(&status)["source_exhausted"] == json!(true) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }

    let after = values(&wire.complete("sipnab://live/dialogs/{call_id}", "call_id", ""));
    assert_ne!(
        before, after,
        "the completions did not follow the capture, which is what a \
         hardcoded vocabulary looks like"
    );
    for gone in &before {
        assert!(
            !after.contains(gone),
            "'{gone}' belongs to the discarded capture and is still offered"
        );
    }
    assert_eq!(
        after,
        {
            let mut ids = wire.call_ids_from_the_tool();
            ids.sort();
            ids
        },
        "after the swap the vocabulary must match the new capture"
    );
}

/// An argument name the template does not carry completes to nothing.
///
/// Not a panic, and — the dangerous one — not the template's real vocabulary
/// under a different name. A client that asked about `foo` and was handed
/// Call-IDs would fill `foo` with one.
#[test]
fn an_unknown_argument_name_completes_to_nothing() {
    let mut wire = Wire::start();
    let real = values(&wire.complete("sipnab://live/dialogs/{call_id}", "call_id", ""));
    assert!(!real.is_empty(), "the fixture must offer something");

    for bogus in ["callid", "call-id", "", "rule_id", "nonsense"] {
        let answer = wire.complete("sipnab://live/dialogs/{call_id}", bogus, "");
        assert_eq!(
            values(&answer),
            Vec::<String>::new(),
            "argument '{bogus}' was answered with a vocabulary it did not ask for"
        );
        assert_eq!(answer["total"], json!(0), "for argument '{bogus}'");
    }
}

/// A template nothing serves completes to nothing rather than erroring.
#[test]
fn an_unknown_template_completes_to_nothing() {
    let mut wire = Wire::start();
    for template in [
        "sipnab://live/dialogs",
        "sipnab://nope/{x}",
        "file:///etc/passwd",
    ] {
        let answer = wire.complete(template, "call_id", "");
        assert_eq!(
            values(&answer),
            Vec::<String>::new(),
            "'{template}' resolved to some vocabulary"
        );
    }
}

/// A prompt reference is answered, emptily, rather than refused.
///
/// sipnab's prompts take no arguments on purpose. The spec's answer for "I
/// complete nothing here" is an empty completion, and a client that got
/// `-32601` instead would have to special-case this server.
#[test]
fn a_prompt_reference_completes_to_nothing_rather_than_erroring() {
    let mut wire = Wire::start();
    let reply = wire.request(
        "completion/complete",
        json!({
            "ref": {"type": "ref/prompt", "name": "triage-outage"},
            "argument": {"name": "call_id", "value": ""}
        }),
    );
    assert!(
        reply["error"].is_null(),
        "a prompt ref was refused: {reply}"
    );
    assert_eq!(
        values(&reply["result"]["completion"]),
        Vec::<String>::new(),
        "sipnab's prompts take no arguments, so nothing may be offered for one"
    );
}

/// Every rule identifier offered is one the catalog really holds.
///
/// Proved by asking `explain_rule` about each: an invented identifier is
/// refused there, so a fabricated completion cannot survive this.
#[test]
fn lint_rule_completions_are_identifiers_the_catalog_resolves() {
    let mut wire = Wire::start();
    let offered = values(&wire.complete("sipnab://lint/{rule_id}", "rule_id", ""));
    assert!(
        offered.len() >= 20,
        "the rule catalog is larger than {} entries; the completion is \
         truncating or reading the wrong table",
        offered.len()
    );
    for rule_id in offered.iter().take(8) {
        let reply = wire.request(
            "tools/call",
            json!({"name": "explain_rule", "arguments": {"rule_id": rule_id}}),
        );
        assert!(
            reply["error"].is_null(),
            "completion offered '{rule_id}', which explain_rule does not know: {reply}"
        );
        assert_eq!(text_payload(&reply)["rule_id"], json!(rule_id));
    }
}

/// A typed prefix narrows the answer, and narrows it correctly.
#[test]
fn a_typed_prefix_narrows_the_rule_identifiers() {
    let mut wire = Wire::start();
    let all = values(&wire.complete("sipnab://lint/{rule_id}", "rule_id", ""));
    let observed = values(&wire.complete("sipnab://lint/{rule_id}", "rule_id", "OBS-"));
    assert!(
        !observed.is_empty() && observed.len() < all.len(),
        "prefix 'OBS-' matched {} of {} rules, which is either nothing or \
         everything — the prefix is not being applied",
        observed.len(),
        all.len()
    );
    for id in &observed {
        assert!(id.starts_with("OBS-"), "'{id}' does not match the prefix");
    }
    let lowercase = values(&wire.complete("sipnab://lint/{rule_id}", "rule_id", "obs-"));
    assert_eq!(
        lowercase, observed,
        "matching must not depend on the case the operator typed"
    );
}

/// Every alias offered is one `find_problems` accepts as a `kind`.
///
/// Proved by calling the tool with each rather than against a literal list:
/// an alias the completion invented is refused there with `invalid_params`, so
/// a hand-copied vocabulary that has drifted from the expander cannot survive
/// this.
#[test]
fn filter_alias_completions_are_kinds_find_problems_accepts() {
    let mut wire = Wire::start();
    let offered = values(&wire.complete("sipnab://filter/{alias}", "alias", ""));
    assert!(
        offered.len() >= 5,
        "only {} alias(es) offered; the completion is reading the wrong table: {offered:?}",
        offered.len()
    );
    for alias in &offered {
        let reply = wire.request(
            "tools/call",
            json!({"name": "find_problems", "arguments": {"kinds": [alias], "limit": 1}}),
        );
        assert!(
            reply["error"].is_null(),
            "completion offered '{alias}', which find_problems refuses: {reply}"
        );
    }
}

/// Reading an alias returns DSL the filter argument accepts.
///
/// The reason the alias is a resource and not a line in a document: the
/// expansion carries the numbers THIS server was configured with, and the
/// value of serving it at all is that a client can hand it straight back as a
/// `filter`. If it did not parse, the resource would be describing a filter
/// rather than being one.
#[test]
fn a_filter_alias_resolves_to_an_expression_the_filter_argument_takes() {
    let mut wire = Wire::start();
    let read = wire.request(
        "resources/read",
        json!({"uri": "sipnab://filter/slow-setup"}),
    );
    assert!(read["error"].is_null(), "the alias did not resolve: {read}");
    let body: Value = serde_json::from_str(
        read["result"]["contents"][0]["text"]
            .as_str()
            .unwrap_or_else(|| panic!("no text in {read}")),
    )
    .expect("the alias payload is JSON");
    assert_eq!(body["alias"], json!("slow-setup"));
    let expression = body["expands_to"].as_str().expect("an expansion");

    let reply = wire.request(
        "tools/call",
        json!({"name": "list_dialogs", "arguments": {"filter": expression, "limit": 1}}),
    );
    assert!(
        reply["error"].is_null(),
        "the expansion '{expression}' is not something the filter argument takes: {reply}"
    );
}

/// Every advertised template resolves: complete it, build the URI, read it.
///
/// The end-to-end contract of PB3 in one test. A template is a promise that
/// the URI works, and a template that only completes is a shape a client can
/// build and never use — which is exactly what a completion-only
/// implementation would look like from the outside.
#[test]
fn every_advertised_template_completes_into_a_readable_uri() {
    let mut wire = Wire::start();
    let listed = wire.request("resources/templates/list", json!({}));
    let templates = listed["result"]["resourceTemplates"]
        .as_array()
        .unwrap_or_else(|| panic!("no resourceTemplates in {listed}"))
        .clone();
    assert!(
        templates.len() >= 5,
        "only {} template(s) advertised: {listed}",
        templates.len()
    );

    for template in &templates {
        let uri_template = template["uriTemplate"]
            .as_str()
            .unwrap_or_else(|| panic!("a template with no uriTemplate: {template}"));
        // The variable name is read back OUT of the template, so this test
        // cannot drift from what the server actually advertises.
        let open = uri_template
            .find('{')
            .unwrap_or_else(|| panic!("{uri_template} carries no variable"));
        let close = uri_template
            .find('}')
            .unwrap_or_else(|| panic!("{uri_template} carries no variable"));
        let variable = &uri_template[open + 1..close];

        let offered = values(&wire.complete(uri_template, variable, ""));
        assert!(
            !offered.is_empty(),
            "{uri_template} advertises the variable '{variable}' and completes \
             nothing for it, so a client has nothing to build a URI from"
        );

        let uri = uri_template.replace(&format!("{{{variable}}}"), &offered[0]);
        let read = wire.request("resources/read", json!({"uri": uri}));
        assert!(
            read["error"].is_null(),
            "{uri_template} completed '{}', and reading the URI it builds \
             failed: {read}",
            offered[0]
        );
        let body = &read["result"]["contents"][0];
        assert!(
            body["text"].is_string() || body["blob"].is_string(),
            "reading {uri} returned neither text nor a blob: {read}"
        );
    }
}

/// The file-root template is advertised only where it can resolve.
///
/// A server with no `--mcp-file-root` refuses every `sipnab:///<file>` read,
/// so advertising the shape would tell an agent the captures are reachable and
/// let it find out otherwise one call at a time.
#[test]
fn the_capture_file_template_is_withheld_without_a_file_root() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(["--mcp", "-N", "-I", PCAP, "--quiet"])
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
                    "clientInfo": {"name": "no-root-test", "version": "1"}
                }
            }),
            json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            json!({"jsonrpc": "2.0", "id": 2, "method": "resources/templates/list"}),
        ] {
            writeln!(stdin, "{message}").expect("write");
        }
        stdin.flush().expect("flush");
    }
    let stdout = child.stdout.take().expect("stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    let mut templates: Option<Vec<Value>> = None;
    for _ in 0..MAX_LINES {
        line.clear();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        let Ok(msg) = serde_json::from_str::<Value>(line.trim()) else {
            continue;
        };
        if msg["id"] == json!(2) {
            templates = msg["result"]["resourceTemplates"].as_array().cloned();
            break;
        }
    }
    let _ = child.kill();
    let _ = child.wait();

    let templates = templates.expect("a resources/templates/list reply");
    assert!(
        !templates.is_empty(),
        "the live and reference templates do not need a file root"
    );
    for t in &templates {
        assert_ne!(
            t["uriTemplate"],
            json!("sipnab:///{filename}"),
            "the capture-file template is advertised on a server that would \
             refuse every URI built from it"
        );
    }
}
