// SPDX-License-Identifier: MIT OR Apache-2.0

//! Whether an answer is the WHOLE answer, on every tool result at once.
//!
//! # The defect this exists for
//!
//! A file source is read on a background thread while tool calls are already
//! being answered. An agent issues its first call milliseconds after
//! `notifications/initialized`, inside a window a human client never sees, and
//! is handed a page computed over whatever had arrived by then. Measured on the
//! released 0.5.130 binary: `list_dialogs` answered `total_matched: 6` on a
//! capture holding 18,241 dialogs, and said `truncated: false` while doing it.
//! `find_problems` answered `total_matched: 0, truncated: false` on a capture
//! holding 240 problem dialogs.
//!
//! Neither number was wrong about the store. Both responses were wrong about
//! themselves: `truncated: false` is an affirmative claim that nothing was
//! withheld, and it was emitted when the set was a thousandth of the answer.
//!
//! The mechanism to say so already existed and was correct —
//! `capture_status.source_exhausted` flips `false` to `true` exactly when it
//! should, `tail_dialogs` carries it in its own envelope, and the tool docs
//! name the remedy. What was missing is that every OTHER result-set tool made
//! the caller take that fact from a second call to a different tool. One
//! response was self-describing and forty-odd were not.
//!
//! # Why this is applied centrally
//!
//! [`stamp`] runs once, in `SipnabMcp::call_tool`, on the way out — the same
//! place, and for the same reason, as [`crate::mcp::structured::attach`].
//! Fifty-one tools build their results in fifty-one places and eight response
//! types are pages; a per-tool field is a rule fifty-one authors have to
//! remember, and the next tool registered would be the first one without it
//! with nothing to say so. Applying it at the ONE point every call already
//! passes through makes coverage a property of the dispatch instead of a habit.
//!
//! It runs BEFORE `structured::attach`, so the text block and
//! `structuredContent` carry the same document — the guarantee that module
//! exists to hold.
//!
//! # The two facts, and the one question they answer
//!
//! - [`SOURCE_EXHAUSTED_KEY`] — the source has been read to its end. False
//!   while a file is still loading.
//! - [`SOURCE_STOPPED_EARLY_KEY`] — the read of a source ENDED BEFORE the
//!   source did: a truncated dump file, or a read error part-way through.
//!   `sipnab -N -I truncated.pcap` already prints
//!   `0 of 1 file(s) read in full, 1 stopped early` on stderr and no MCP
//!   response said anything at all (VAL2). `capture_health` is precisely the
//!   tool an agent calls to ask whether a capture is sound.
//!
//! A caller reading ONE response answers "is this the whole answer?" with
//! [`answer_is_whole`]: both fields, no second call, no second tool.
//!
//! Both are booleans and never strings. `capture_health` samples a live
//! production capture carrying other people's calls and its response type is
//! structurally string-free so that it cannot leak packet content; a stamp that
//! injected prose would dissolve that guarantee from the outside.
//!
//! # `truncated: false` is not emitted unless it is true
//!
//! `truncated` keeps its meaning — the row cap withheld matching rows — and
//! `true` is emitted whenever it holds, because a cap that bit is a fact
//! regardless of how much has loaded. What is suppressed is the FALSE reading:
//! while the answer is not whole, `truncated: false` is removed rather than
//! sent, so a caller that reads only that field is handed no claim instead of a
//! wrong one. This is the shape `evaluate_expectations` already uses when a
//! rule's population is empty — *"unevaluable: no seizure was in scope... a
//! gate does not pass on data it never judged"* — a refusal to answer, rather
//! than an answer that happens to look reassuring.
//!
//! JSON absence and `false` are different values in every client that parses
//! it, which is what makes the removal readable rather than merely quieter.

use std::sync::atomic::{AtomicBool, Ordering};

use rmcp::model::{CallToolResult, ContentBlock};
use serde_json::{Map, Value};

/// Envelope key: the source has been read to its end.
pub const SOURCE_EXHAUSTED_KEY: &str = "source_exhausted";

/// Envelope key: a source's read ended before the source did.
pub const SOURCE_STOPPED_EARLY_KEY: &str = "source_stopped_early";

/// The row-cap flag this module suppresses when it would read as an assurance.
const TRUNCATED_KEY: &str = "truncated";

/// The `get_capture_report` field VAL4 measured reading backwards.
const COMPLETE_KEY: &str = "complete";

/// Tools whose answer cannot change as more of the capture is read.
///
/// Everything else is stamped, which is the direction that fails safe: a tool
/// added tomorrow carries the fields without anyone remembering to ask for
/// them, and only a deliberate entry here opts out.
///
/// Each entry earns its place by reading NO capture store:
///
/// - `compare_captures` reads two files from `--mcp-file-root` and says so in
///   its own description — *"Neither file becomes the loaded capture and no
///   answer about the loaded capture changes."*
/// - `decode_evidence`, `explain_response_code`, `explain_rule`,
///   `show_evidence` and `list_tls_libraries` answer from a frame the caller
///   handed over, from the IANA registry, from the rule catalog, or from the
///   host's linker.
/// - `list_captures` lists files on disk.
/// - `server_capabilities` describes the binary.
///
/// `mcp_completeness_test.rs` derives the set of store-reading tools from the
/// source and fails if any of them appears here.
pub const SOURCE_INDEPENDENT_TOOLS: &[&str] = &[
    "compare_captures",
    "decode_evidence",
    // Answers about ONE frame on disk, reached by pointer. Its answer does not
    // move with how much of the capture has been read, so a completeness stamp
    // about the capture would describe something the caller did not ask about.
    "decode_ng",
    "explain_response_code",
    "explain_rule",
    "list_captures",
    // Answers from the RELAY, not from the capture store. Stamping it with how
    // much of the capture has been read would attach a fact about sipnab's
    // reading to a statement made by another process.
    "query_relay",
    "list_tls_libraries",
    "server_capabilities",
    "show_evidence",
];

/// Tools whose `truncated` names something other than a withheld population.
///
/// `save_findings` reports whether the SUMMARY THE CALLER SUBMITTED was clipped
/// to fit. That has no relationship to how much of the capture has been read,
/// and suppressing it would both drop a fact the caller needs and break the
/// tool's declared `outputSchema`, which requires the field.
///
/// Every other `truncated` in this module tree — `DialogPage`, `MessagePage`,
/// `StreamPage`, `FindingsPage`, `CallTreeResponse`, `EndpointDetail`,
/// `TopTalkersResponse` — means "the cap kept matching rows out", which is
/// exactly the claim that must not be made while the population is still
/// arriving.
pub const TRUNCATED_IS_NOT_ABOUT_THE_POPULATION: &[&str] = &["save_findings"];

/// Set when a source THIS SERVER read stopped before its end.
///
/// The `-I` set the run started with is not recorded here: the capture layer
/// already tallies it, and [`source_stopped_early`] reads that tally rather
/// than keeping a second copy that could disagree with the exit code. What this
/// covers is the load `open_capture` starts, which the capture layer's file-set
/// reader never sees.
///
/// A process-global for the same reason `crate::capture::captured_packets` and
/// `crate::pipeline::portrange_skip_report` are: the fact belongs to the RUN
/// rather than to any one server object, and `capture_status` already reports
/// two of its neighbours.
///
/// Written by [`note_source_stopped_early`] and cleared by
/// [`clear_source_stopped_early`] when a new capture starts.
static SOURCE_STOPPED_EARLY: AtomicBool = AtomicBool::new(false);

/// Record that a source's read ended before the source did.
///
/// Truncated dump file, a read error part-way through, a decompression that
/// failed mid-stream: anything that leaves the analysis resting on part of a
/// file. Idempotent — a second stopped-early source cannot un-say the first.
pub fn note_source_stopped_early() {
    // Release, paired with the Acquire in `source_stopped_early`: whatever the
    // reader wrote into the stores before it gave up is visible to any reader
    // that sees this flag.
    SOURCE_STOPPED_EARLY.store(true, Ordering::Release);
}

/// Set once a capture has replaced the `-I` set the run started with.
///
/// The run-level tally still describes the run, and after `open_capture` it no
/// longer describes the loaded capture: those dialogs were cleared, and the new
/// file is not made unsound by a file that is no longer in the stores. A
/// false accusation and a missing one are the same defect pointed opposite
/// ways, and this is the one that would arrive by inheritance.
static RUN_TALLY_SUPERSEDED: AtomicBool = AtomicBool::new(false);

/// Clear the stopped-early record, for a capture that is being replaced.
///
/// `open_capture` rotates the capture identity and clears both stores; carrying
/// the previous file's partial-read fact into the new one would report a sound
/// capture as unsound for the life of the process. That applies to the `-I`
/// set's own tally too, which is why this supersedes it rather than only
/// clearing this module's flag.
pub fn clear_source_stopped_early() {
    SOURCE_STOPPED_EARLY.store(false, Ordering::Release);
    RUN_TALLY_SUPERSEDED.store(true, Ordering::Release);
}

/// Whether any source's read ended before the source did.
///
/// Two records, one answer. The capture layer tallies the `-I` set it read and
/// publishes it as [`crate::output::run_integrity`] — the same record that
/// decides the process exit status, so an MCP client and `$?` cannot be told
/// different things about one run. This module adds only what that tally cannot
/// see: a capture `open_capture` loaded afterwards, on a thread the file-set
/// reader knows nothing about.
///
/// `input_lost` rather than `files_stopped_early` alone, because a file that
/// would not open at all is the most partial read there is and the analysis
/// resting on it is no sounder for the file having produced zero packets
/// instead of some.
#[must_use]
pub fn source_stopped_early() -> bool {
    if SOURCE_STOPPED_EARLY.load(Ordering::Acquire) {
        return true;
    }
    !RUN_TALLY_SUPERSEDED.load(Ordering::Acquire)
        && crate::output::run_integrity::snapshot().input_lost
}

/// Whether an answer computed now covers the whole source.
///
/// Both halves are needed and neither implies the other. A file still loading
/// is not exhausted; a truncated file IS exhausted, because the reader reached
/// the end of what there was to read, and the analysis still rests on part of a
/// capture.
#[must_use]
pub fn answer_is_whole(source_exhausted: bool, stopped_early: bool) -> bool {
    source_exhausted && !stopped_early
}

/// Stamp one tool result with how much of the source is behind it.
///
/// A no-op for an error result, for a tool in [`SOURCE_INDEPENDENT_TOOLS`], and
/// for a payload that is neither a JSON object nor a JSON array — a rendered
/// ladder or a Markdown report has no envelope to carry a field.
///
/// # Arguments
///
/// * `tool` — the registered tool name, as `call_tool` received it.
/// * `source_exhausted` — the shared flag `capture_status` reports.
/// * `stopped_early` — [`source_stopped_early`], read by the caller.
/// * `result` — the successful result, rewritten in place.
///
/// Both facts are PARAMETERS rather than reads of the process globals. A test
/// that had to set a global to describe a capture would be setting it for every
/// other test in the binary at the same time, and `cargo test` runs them
/// concurrently: the shape rules below would then pass or fail on which test
/// won a race.
///
/// # What it does to an object payload
///
/// Inserts both keys, never overwriting one the tool set itself:
/// `capture_status` and `tail_dialogs` read their own flag under `Acquire`
/// beside a `done` they must not disagree with, and this must not race them
/// into a different answer.
///
/// Removes `truncated` when it is `false` and the answer is not whole, unless
/// the tool is in [`TRUNCATED_IS_NOT_ABOUT_THE_POPULATION`].
///
/// Forces `complete` to `false` when the answer is not whole. `complete` says
/// *"whether sipnab read all of its input"*
/// ([`crate::analysis::CaptureAnalysis::complete`]), and while a file is still
/// being read that is false by construction. Measured before this gate: the
/// same tool on the same session answered `complete: true` at
/// `frames_read: 312` and `complete: false` at `frames_read: 365747` — `true`
/// over 0.09% of the file and `false` once the file had been read (VAL4).
///
/// # What it does to an array payload
///
/// `timeline` answers with a top-level array, which has no key to carry a
/// field. The envelope is APPENDED as a further content block rather than
/// wrapped around the array, because wrapping would change the payload's
/// published shape; appending leaves the first block exactly as it was.
pub fn stamp(tool: &str, source_exhausted: bool, stopped_early: bool, result: &mut CallToolResult) {
    if result.is_error == Some(true) || SOURCE_INDEPENDENT_TOOLS.contains(&tool) {
        return;
    }
    let Some(ContentBlock::Text(block)) = result.content.first() else {
        return;
    };
    // The leading-character check is not an optimization for its own sake: it
    // keeps `render_ladder`-shaped results — kilobytes of drawn diagram — from
    // being handed to a JSON parser once per call to learn what their first
    // character already said.
    let text = block.text.trim_start();
    let object = text.starts_with('{');
    if !object && !text.starts_with('[') {
        return;
    }
    let Ok(value) = serde_json::from_str::<Value>(&block.text) else {
        return;
    };

    match value {
        Value::Object(mut map) => {
            apply(&mut map, tool, source_exhausted, stopped_early);
            let Ok(text) = serde_json::to_string(&Value::Object(map)) else {
                return;
            };
            result.content[0] = ContentBlock::text(text);
        }
        Value::Array(_) => {
            let mut envelope = Map::new();
            insert_facts(&mut envelope, source_exhausted, stopped_early);
            let Ok(text) = serde_json::to_string(&Value::Object(envelope)) else {
                return;
            };
            result.content.push(ContentBlock::text(text));
        }
        _ => {}
    }
}

/// Both facts, without disturbing a value the tool already published.
fn insert_facts(map: &mut Map<String, Value>, source_exhausted: bool, stopped_early: bool) {
    map.entry(SOURCE_EXHAUSTED_KEY)
        .or_insert_with(|| Value::Bool(source_exhausted));
    map.entry(SOURCE_STOPPED_EARLY_KEY)
        .or_insert_with(|| Value::Bool(stopped_early));
}

/// The whole rewrite of one object payload. See [`stamp`].
fn apply(map: &mut Map<String, Value>, tool: &str, source_exhausted: bool, stopped_early: bool) {
    insert_facts(map, source_exhausted, stopped_early);
    if answer_is_whole(source_exhausted, stopped_early) {
        return;
    }
    if !TRUNCATED_IS_NOT_ABOUT_THE_POPULATION.contains(&tool)
        && map.get(TRUNCATED_KEY) == Some(&Value::Bool(false))
    {
        map.remove(TRUNCATED_KEY);
    }
    if map.get(COMPLETE_KEY) == Some(&Value::Bool(true)) {
        map.insert(COMPLETE_KEY.to_string(), Value::Bool(false));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One text block holding `json`, the shape every tool returns.
    fn json_result(json: &str) -> CallToolResult {
        CallToolResult::success(vec![ContentBlock::text(json)])
    }

    /// The payload of a stamped result, parsed back.
    fn payload(result: &CallToolResult) -> Value {
        let ContentBlock::Text(block) = &result.content[0] else {
            panic!("the fixture's first block is text");
        };
        serde_json::from_str(&block.text).expect("payload parses")
    }

    /// A page answered mid-load says so in its own envelope.
    #[test]
    fn an_undrained_page_carries_source_exhausted_false() {
        let mut result = json_result(r#"{"total_matched":6,"truncated":false}"#);
        stamp("list_dialogs", false, false, &mut result);

        assert_eq!(payload(&result)["source_exhausted"], Value::Bool(false));
    }

    /// The affirmative claim VAL3 measured is not made while it is unearned.
    #[test]
    fn truncated_false_is_removed_while_the_source_is_undrained() {
        let mut result = json_result(r#"{"total_matched":6,"truncated":false}"#);
        stamp("list_dialogs", false, false, &mut result);

        let page = payload(&result);
        assert!(
            page.get("truncated").is_none(),
            "`truncated: false` claims nothing was withheld; mid-load it is \
             unearned and must be absent rather than false: {page}"
        );
    }

    /// A cap that bit is a fact whatever the load state, so it is still said.
    #[test]
    fn truncated_true_survives_an_undrained_source() {
        let mut result = json_result(r#"{"total_matched":6000,"truncated":true}"#);
        stamp("list_dialogs", false, false, &mut result);

        assert_eq!(payload(&result)["truncated"], Value::Bool(true));
    }

    /// A drained, intact source answers exactly as it did before this module.
    #[test]
    fn a_whole_answer_keeps_truncated_false() {
        let mut result = json_result(r#"{"total_matched":6,"truncated":false}"#);
        stamp("list_dialogs", true, false, &mut result);

        let page = payload(&result);
        assert_eq!(page["truncated"], Value::Bool(false));
        assert_eq!(page["source_exhausted"], Value::Bool(true));
        assert_eq!(page["source_stopped_early"], Value::Bool(false));
    }

    /// `save_findings.truncated` is about the caller's own submitted text.
    #[test]
    fn save_findings_keeps_its_own_truncated_flag() {
        let mut result = json_result(r#"{"seq":1,"truncated":false}"#);
        stamp("save_findings", false, false, &mut result);

        assert_eq!(
            payload(&result)["truncated"],
            Value::Bool(false),
            "this flag reports whether the SUMMARY was clipped, and its \
             outputSchema requires it"
        );
    }

    /// VAL4: `complete` cannot read `true` over a partial read.
    #[test]
    fn complete_is_false_while_the_source_is_undrained() {
        let mut result = json_result(r#"{"frames_read":312,"complete":true}"#);
        stamp("get_capture_report", false, false, &mut result);

        assert_eq!(
            payload(&result)["complete"],
            Value::Bool(false),
            "`complete` says sipnab read all of its input"
        );
    }

    /// And is left alone once the file really has been read.
    #[test]
    fn complete_is_untouched_on_a_drained_source() {
        let mut result = json_result(r#"{"frames_read":365747,"complete":true}"#);
        stamp("get_capture_report", true, false, &mut result);

        assert_eq!(payload(&result)["complete"], Value::Bool(true));
    }

    /// A truncated file is exhausted AND partial; both facts are reported.
    #[test]
    fn a_stopped_early_source_is_disclosed_even_though_it_drained() {
        let mut result = json_result(r#"{"packets_seen":10,"complete":true}"#);
        stamp("capture_health", true, true, &mut result);

        let health = payload(&result);
        assert_eq!(health["source_exhausted"], Value::Bool(true));
        assert_eq!(health["source_stopped_early"], Value::Bool(true));
        assert_eq!(
            health["complete"],
            Value::Bool(false),
            "a capture read in part is not a capture read in full"
        );
    }

    /// The stamp carries no string, so `capture_health` stays string-free.
    #[test]
    fn nothing_this_module_inserts_is_a_string() {
        let mut result = json_result("{}");
        stamp("capture_health", false, true, &mut result);

        let health = payload(&result);
        let object = health.as_object().expect("object payload");
        assert_eq!(object.len(), 2, "exactly the two facts: {health}");
        for (key, value) in object {
            assert!(
                value.is_boolean(),
                "{key} is not a boolean; capture_health's response type is \
                 structurally string-free so it cannot leak packet content"
            );
        }
    }

    /// `timeline` answers with an array; the envelope is appended, not wrapped.
    #[test]
    fn an_array_payload_gets_the_envelope_as_a_further_block() {
        let mut result = json_result(r#"[{"start":"2026-01-01T00:00:00Z","dialogs":2}]"#);
        stamp("timeline", false, false, &mut result);

        assert!(
            payload(&result).is_array(),
            "the first block keeps the published shape"
        );
        assert_eq!(result.content.len(), 2, "the envelope is a second block");
        let ContentBlock::Text(block) = &result.content[1] else {
            panic!("the envelope block is text");
        };
        let envelope: Value = serde_json::from_str(&block.text).expect("envelope parses");
        assert_eq!(envelope["source_exhausted"], Value::Bool(false));
        assert_eq!(envelope["source_stopped_early"], Value::Bool(false));
    }

    /// A tool that already reports the flag keeps its own, better-ordered read.
    #[test]
    fn a_flag_the_tool_set_itself_is_not_overwritten() {
        let mut result = json_result(r#"{"source_exhausted":true}"#);
        stamp("capture_status", false, false, &mut result);

        assert_eq!(
            payload(&result)["source_exhausted"],
            Value::Bool(true),
            "capture_status reads the flag under Acquire beside `done`; this \
             must not race it into a different answer"
        );
    }

    /// A rendered document has no envelope, and is not handed to a parser.
    #[test]
    fn a_rendered_document_is_left_alone() {
        let mut result = json_result("alice -> bob  INVITE\nbob -> alice  200 OK\n");
        stamp("render_ladder", false, false, &mut result);

        assert_eq!(result.content.len(), 1);
        let ContentBlock::Text(block) = &result.content[0] else {
            panic!("text block");
        };
        assert!(block.text.starts_with("alice -> bob"));
    }

    /// An error result's content is a message, not a payload.
    #[test]
    fn an_error_result_is_left_alone() {
        let mut result = CallToolResult::error(vec![ContentBlock::text(r#"{"error":"nope"}"#)]);
        stamp("list_dialogs", false, false, &mut result);

        assert_eq!(payload(&result), serde_json::json!({"error": "nope"}));
    }

    /// A tool whose answer cannot move with the load is not annotated.
    #[test]
    fn a_source_independent_tool_is_not_stamped() {
        let mut result = json_result(r#"{"code":488}"#);
        stamp("explain_response_code", false, false, &mut result);

        assert_eq!(payload(&result), serde_json::json!({"code": 488}));
    }

    /// Half-written JSON must not become a half-parsed structure, or panic.
    #[test]
    fn truncated_json_is_left_alone() {
        let mut result = json_result(r#"{"schema_version":1,"dialogs":"#);
        stamp("list_dialogs", false, false, &mut result);

        let ContentBlock::Text(block) = &result.content[0] else {
            panic!("text block");
        };
        assert_eq!(block.text, r#"{"schema_version":1,"dialogs":"#);
    }

    /// A result with no content must not index past the end.
    #[test]
    fn an_empty_result_is_left_alone() {
        let mut result = CallToolResult::success(vec![]);
        stamp("list_dialogs", false, false, &mut result);

        assert!(result.content.is_empty());
    }

    /// The two halves of "is this whole" are independent.
    #[test]
    fn an_answer_is_whole_only_when_drained_and_intact() {
        assert!(answer_is_whole(true, false));
        assert!(!answer_is_whole(false, false), "still loading");
        assert!(
            !answer_is_whole(true, true),
            "read what there was, of a part"
        );
        assert!(!answer_is_whole(false, true));
    }

    /// The run-wide record round-trips.
    ///
    /// The ONLY test in this module that touches the process globals. Every
    /// shape rule above takes both facts as parameters precisely so that this
    /// one cannot decide their outcome by winning or losing a race with them.
    ///
    /// It opens by superseding the run tally rather than asserting that tally
    /// is clear: `src/capture/file.rs`'s own unit tests publish read outcomes
    /// into it, and `cargo test` runs this binary's tests concurrently, so
    /// "nothing has been lost yet" is a claim about another test's progress.
    #[test]
    fn the_stopped_early_record_round_trips() {
        clear_source_stopped_early();
        assert!(
            !source_stopped_early(),
            "a capture that replaced the run's own input starts unaccused"
        );
        note_source_stopped_early();
        assert!(source_stopped_early());
        note_source_stopped_early();
        assert!(
            source_stopped_early(),
            "a second partial source cannot un-say the first"
        );
        clear_source_stopped_early();
        assert!(
            !source_stopped_early(),
            "open_capture replaces the capture, and with it the record"
        );
    }

    /// The opt-out list names tools, not typos.
    #[test]
    fn every_opt_out_is_spelled_as_a_tool_name() {
        for name in SOURCE_INDEPENDENT_TOOLS
            .iter()
            .chain(TRUNCATED_IS_NOT_ABOUT_THE_POPULATION)
        {
            assert!(
                !name.is_empty() && name.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "{name} is not shaped like a registered tool name"
            );
        }
    }
}
