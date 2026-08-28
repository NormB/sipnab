// SPDX-License-Identifier: MIT OR Apache-2.0

//! Golden-answer eval: does an agent asking a question of a capture get the
//! RIGHT ANSWER?
//!
//! Every other MCP suite in this tree proves the code is correct — the tool
//! runs, the schema holds, the refusal fires. None of them proves the thing an
//! operator actually depends on, which is that the number the agent reads out
//! of the reply is the number in the capture. Those are different properties,
//! and the gap between them has a documented shape here: `search_messages`
//! answered `{"query":"REGISTER"}` with 50 rows and said nothing about the
//! thousands it withheld, so an agent asked "how many REGISTERs are there"
//! counted its rows and answered 50. Every unit test passed. The answer was
//! wrong by three orders of magnitude.
//!
//! So this file runs a corpus of (capture, question, expected answer) over the
//! real MCP surface and asserts the answer, not the plumbing.
//!
//! ## What makes a golden answer a golden answer
//!
//! A value copied from what the tool returned the day the test was written is
//! a change-detector wearing a correctness test's clothes: it will happily
//! keep asserting a wrong number forever, because the wrong number is what it
//! was taught. So every `expected` in
//! [`tests/golden-answers/mcp-eval.json`](../golden-answers/mcp-eval.json) was
//! derived FROM THE CAPTURE by a route that does not pass through sipnab, and
//! each case carries the command that produces it in its `derivation` field —
//! a data file cannot hold a Rust comment, so the derivation is a field, and
//! the rule is the same one: the next person re-derives rather than trusts.
//!
//! Two derivation routes are used, and they agree on every count in the
//! corpus:
//!
//! 1. **tshark**, named per case. Not run here — CI is not guaranteed to have
//!    it, and a check that silently skips is worse than no check.
//! 2. **A raw byte scan of the capture file**, which needs nothing but
//!    `std::fs::read`. SIP over UDP is stored verbatim in a pcap, so counting
//!    the literal `REGISTER sip:` counts request lines and counting
//!    `SIP/2.0 403 ` counts status lines with no packet parsing whatever. That
//!    is [`Oracle`], and it runs on every pass.
//!
//! ## Changed, or wrong?
//!
//! A failing eval must say which of two things it found, because they call for
//! opposite responses: a regression is fixed in the code, an improvement is
//! absorbed into the corpus. [`classify`] decides from the oracle:
//!
//! * the tool disagrees with the golden and the byte scan STILL re-derives the
//!   golden → the tool is **wrong**;
//! * the tool disagrees and there is no in-process oracle → the answer
//!   **changed**, and the harness says so rather than pretending to know;
//! * the tool agrees but the byte scan no longer does → the **ground truth
//!   moved** (a fixture was edited under both), and neither number is trusted.
//!
//! ## Questions this corpus does not ask
//!
//! A vacuous eval is worse than none, so the corpus also carries an
//! `unanswerable` list: questions the fixtures cannot support, each with the
//! reason. `the_corpus_names_the_questions_the_fixtures_cannot_answer` keeps
//! that list honest. Inventing a number for any of them would be the failure
//! this whole file exists to catch, committed by the file itself.
//!
//! `#![cfg(feature = "mcp")]` because it drives the MCP surface.

#![cfg(feature = "mcp")]

use serde::Deserialize;
use serde_json::Value;

#[path = "support/mcp.rs"]
mod mcp;

use mcp::McpSession;

/// The corpus, embedded rather than read at run time.
///
/// `include_str!` makes a renamed or deleted corpus a COMPILE error. Reading
/// the file at run time would turn the same mistake into an empty corpus and a
/// green suite, which is the silent-instrument failure this harness exists to
/// prevent in the tools it tests.
const CORPUS_JSON: &str = include_str!("golden-answers/mcp-eval.json");

/// Captures the corpus asks about, one test function each so a failure names
/// the capture without reading the case ids.
const BRANCH: &str = "tests/pcap-samples/sipp-branch-scenario.pcapng";
/// Five calls, four of them failed, one of each failure class.
const PROBLEM: &str = "tests/pcap-samples/sip-problem-call.pcap";
/// Two calls with RTP, and — despite the file name — two different codecs.
const G711: &str = "tests/pcap-samples/sip-rtp-g711.pcap";

// ── corpus model ────────────────────────────────────────────────────

/// The whole corpus file.
#[derive(Debug, Deserialize)]
struct Corpus {
    /// Prose header, for a reader opening the JSON directly. Not asserted.
    #[allow(dead_code)]
    about: Vec<String>,
    /// The questions with answers.
    cases: Vec<Case>,
    /// The questions deliberately NOT asked, and why.
    unanswerable: Vec<Unanswerable>,
}

/// One (capture, question, expected answer) triple.
#[derive(Debug, Deserialize)]
struct Case {
    /// Stable identifier, quoted in every failure message.
    id: String,
    /// Capture path, relative to the crate root.
    capture: String,
    /// The question in the words an operator would use. Carried so a failure
    /// reads as "this question is now answered wrongly" rather than as a
    /// field name that disagrees with a literal.
    question: String,
    /// MCP tool to call.
    tool: String,
    /// Arguments for the call.
    arguments: Value,
    /// Where in the reply the answer to `question` lives.
    answer: Locator,
    /// The right answer, derived from the capture.
    expected: Value,
    /// How `expected` is compared to what came back.
    #[serde(rename = "match", default)]
    match_kind: MatchKind,
    /// How `expected` was derived, naming the command. The reason this
    /// corpus is not a set of change-detectors.
    derivation: String,
    /// Whether the harness can re-derive `expected` in-process, which is what
    /// lets a failure say "wrong" rather than "different".
    oracle: Oracle,
    /// The wrong answer a careless reader would give, where one exists.
    #[serde(default)]
    naive: Option<Naive>,
}

/// The answer a careless agent gives instead of the right one.
///
/// Asserted live, not assumed: a trap nobody proves is still set is a trap
/// that quietly stopped existing.
#[derive(Debug, Deserialize)]
struct Naive {
    /// Where the tempting-but-wrong value lives in the same reply.
    answer: Locator,
    /// What that value is.
    value: Value,
    /// Why reading it is the mistake.
    note: String,
}

/// A question the fixtures cannot support, recorded rather than guessed at.
#[derive(Debug, Deserialize)]
struct Unanswerable {
    /// The question.
    question: String,
    /// The capture it would have been asked of.
    capture: String,
    /// Why no number can honestly be pinned for it.
    reason: String,
}

/// How an expected value is compared to the one that came back.
#[derive(Debug, Default, Deserialize, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum MatchKind {
    /// Exact JSON equality. The default, and right for every number.
    #[default]
    Equals,
    /// Substring, for prose whose wording is free to change around a fact
    /// that is not — a hint that must name `404 Not Found`, say.
    Contains,
}

/// Where the answer to a question lives in a tool's reply.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Locator {
    /// A JSON pointer, e.g. `/total_matched`.
    Pointer(String),
    /// The length of the array at a pointer.
    ///
    /// "How many streams?" is a question about a count the reply expresses as
    /// an array, and a pointer cannot ask it.
    Len {
        /// Pointer to the array.
        len: String,
    },
    /// A row looked up by key, then one field of it.
    ///
    /// `aggregate_dialogs` and `top_talkers` answer with rows ordered by
    /// count. Pointing at `/buckets/0/count` would make the case assert the
    /// ORDERING as well as the number, and then a re-ranked reply would look
    /// like a wrong answer. Looking the row up by its key asks only what was
    /// asked.
    Select {
        /// Pointer to the array of rows.
        array: String,
        /// Key/value pairs the row must carry.
        find: serde_json::Map<String, Value>,
        /// The field of the matched row to read.
        field: String,
    },
}

impl Locator {
    /// Pull the value this locator names out of `reply`.
    ///
    /// `None` means the reply does not carry it at all, which is itself a
    /// failure the caller reports — a tool that dropped the field an agent
    /// reads has stopped answering the question.
    fn resolve(&self, reply: &Value) -> Option<Value> {
        match self {
            Self::Pointer(p) => reply.pointer(p).cloned(),
            Self::Len { len } => reply
                .pointer(len)
                .and_then(Value::as_array)
                .map(|a| Value::from(a.len())),
            Self::Select { array, find, field } => reply
                .pointer(array)
                .and_then(Value::as_array)?
                .iter()
                .find(|row| find.iter().all(|(k, v)| row.get(k) == Some(v)))
                .and_then(|row| row.get(field))
                .cloned(),
        }
    }

    /// How the locator reads in a failure message.
    fn describe(&self) -> String {
        match self {
            Self::Pointer(p) => p.clone(),
            Self::Len { len } => format!("length of {len}"),
            Self::Select { array, find, field } => {
                let key = serde_json::to_string(find).unwrap_or_default();
                format!("{array} where {key} -> {field}")
            }
        }
    }
}

// ── the independent oracle ──────────────────────────────────────────

/// How the harness re-derives an expected value from the capture bytes.
///
/// Deliberately crude. It parses nothing: no pcap block structure, no IP, no
/// UDP, no SIP grammar. That is the whole point — an oracle sharing code with
/// the thing under test agrees with it for the same reason the thing is
/// wrong. `std::fs::read` and a substring count share nothing with sipnab's
/// parser except the file on disk.
///
/// The cost is that it only works on uncompressed captures carrying SIP over a
/// datagram transport, where a request line is never split across frames.
/// Every capture in the corpus is one of those, and each case's `derivation`
/// carries a tshark command that confirms the same number by a route that does
/// parse.
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Oracle {
    /// Non-overlapping occurrences of a literal in the capture file.
    ByteLiteral {
        /// The literal, e.g. `REGISTER sip:`.
        literal: String,
    },
    /// Non-overlapping occurrences of a hex byte pattern.
    ///
    /// For RTP: every packet carries its SSRC in the header exactly once, so
    /// counting the four SSRC bytes counts the stream's packets.
    ByteHex {
        /// Even-length hex, e.g. `343da99b`.
        hex: String,
    },
    /// Distinct `Call-ID:` header values in the capture file.
    ///
    /// Long form only. The compact form `i:` is not scanned, and would make
    /// this undercount — which is why the count is cross-checked against
    /// tshark in each case's `derivation` rather than trusted alone.
    DistinctCallIds,
    /// Sum of sub-oracles, for a total assembled from parts.
    Sum {
        /// The parts.
        of: Vec<Oracle>,
    },
    /// No in-process re-derivation for this one.
    ///
    /// The value is still derived — the `derivation` field names the command —
    /// but the harness cannot repeat it cheaply, so a disagreement can only be
    /// reported as a CHANGE.
    Recorded,
}

impl Oracle {
    /// Re-derive the value from `capture`, or `None` for [`Oracle::Recorded`].
    fn derive(&self, capture: &[u8]) -> Option<u64> {
        match self {
            Self::ByteLiteral { literal } => Some(count_occurrences(capture, literal.as_bytes())),
            Self::ByteHex { hex } => Some(count_occurrences(capture, &decode_hex(hex))),
            Self::DistinctCallIds => Some(distinct_call_ids(capture)),
            Self::Sum { of } => of.iter().map(|o| o.derive(capture)).sum(),
            Self::Recorded => None,
        }
    }
}

/// Non-overlapping occurrences of `needle` in `haystack`.
fn count_occurrences(haystack: &[u8], needle: &[u8]) -> u64 {
    assert!(!needle.is_empty(), "an empty needle matches everywhere");
    memchr::memmem::find_iter(haystack, needle).count() as u64
}

/// Bytes of an even-length hex string.
fn decode_hex(hex: &str) -> Vec<u8> {
    assert!(
        hex.len().is_multiple_of(2) && !hex.is_empty(),
        "hex oracle {hex:?} is not an even number of digits"
    );
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex digit"))
        .collect()
}

/// Distinct `Call-ID:` header values in a capture file.
fn distinct_call_ids(capture: &[u8]) -> u64 {
    const HEADER: &[u8] = b"Call-ID:";
    let mut seen: std::collections::BTreeSet<&[u8]> = std::collections::BTreeSet::new();
    for at in memchr::memmem::find_iter(capture, HEADER) {
        let rest = &capture[at + HEADER.len()..];
        let end = rest
            .iter()
            .position(|b| *b == b'\r' || *b == b'\n')
            .unwrap_or(rest.len());
        let value = trim_ascii(&rest[..end]);
        if !value.is_empty() {
            seen.insert(value);
        }
    }
    seen.len() as u64
}

/// `[u8]::trim_ascii` over a borrowed slice, spelled out so the return keeps
/// the input's lifetime rather than the temporary's.
fn trim_ascii(mut b: &[u8]) -> &[u8] {
    while let Some((first, rest)) = b.split_first() {
        if first.is_ascii_whitespace() {
            b = rest;
        } else {
            break;
        }
    }
    while let Some((last, rest)) = b.split_last() {
        if last.is_ascii_whitespace() {
            b = rest;
        } else {
            break;
        }
    }
    b
}

// ── changed, or wrong? ──────────────────────────────────────────────

/// What a comparison found, and therefore what a reader should do about it.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Verdict {
    /// The tool answered the golden, and the oracle (if any) still agrees.
    Agrees,
    /// The tool disagreed and the capture still yields the golden. A defect.
    WrongAnswer,
    /// The tool disagreed and nothing here can re-derive the truth. Might be
    /// a regression, might be an improvement; the harness will not guess.
    AnswerChanged,
    /// The tool still answers the golden but the capture no longer yields it.
    /// The fixture or the oracle moved, so the pass is not evidence.
    GroundTruthMoved,
    /// Both moved, and in the same direction as each other or not at all.
    /// Whatever happened, re-derivation by hand is the only way out.
    AnswerAndGroundTruthMoved,
}

/// Decide the verdict from the two comparisons.
///
/// Split out as a pure function of two booleans on purpose: it is the piece
/// that has to be right for a failure message to mean anything, and it is the
/// piece that would otherwise only ever be exercised by a passing run. The
/// three `a_..._is_reported_as_...` tests below drive it directly.
///
/// # Arguments
/// * `answer_matches` — the tool's value matched `expected`.
/// * `oracle_agrees` — the in-process re-derivation produced `expected`;
///   `None` when the case has no in-process oracle.
fn classify(answer_matches: bool, oracle_agrees: Option<bool>) -> Verdict {
    match (answer_matches, oracle_agrees) {
        (true, None | Some(true)) => Verdict::Agrees,
        (true, Some(false)) => Verdict::GroundTruthMoved,
        (false, None) => Verdict::AnswerChanged,
        (false, Some(true)) => Verdict::WrongAnswer,
        (false, Some(false)) => Verdict::AnswerAndGroundTruthMoved,
    }
}

impl Verdict {
    /// The headline a reader sees, saying which claim the harness is making.
    fn headline(self) -> &'static str {
        match self {
            Self::Agrees => "AGREES",
            Self::WrongAnswer => "WRONG ANSWER",
            Self::AnswerChanged => "ANSWER CHANGED",
            Self::GroundTruthMoved => "GROUND TRUTH MOVED",
            Self::AnswerAndGroundTruthMoved => "ANSWER AND GROUND TRUTH BOTH MOVED",
        }
    }

    /// What the reader should do, which is the part that differs.
    fn guidance(self) -> &'static str {
        match self {
            Self::Agrees => "nothing to do",
            Self::WrongAnswer => {
                "re-deriving this from the capture bytes in this same run STILL gives the \
                 expected value, so the tool's answer is wrong rather than merely different. \
                 Fix the tool; do not move the golden."
            }
            Self::AnswerChanged => {
                "this case has no in-process re-derivation, so the harness cannot tell a \
                 regression from an improvement and does not claim to. Re-derive by hand with \
                 the command in `derivation` below, and only then decide whether the golden or \
                 the tool is what moves."
            }
            Self::GroundTruthMoved => {
                "the tool still answers the golden, but re-deriving from the capture bytes no \
                 longer produces it. A fixture was edited, or the oracle no longer suits it. \
                 The pass is not evidence until someone re-derives."
            }
            Self::AnswerAndGroundTruthMoved => {
                "both the tool's answer and the re-derivation moved away from the golden. Most \
                 likely the fixture was replaced. Re-derive everything about this case before \
                 pinning anything."
            }
        }
    }
}

// ── running the corpus ──────────────────────────────────────────────

/// Parse the embedded corpus.
fn corpus() -> Corpus {
    serde_json::from_str(CORPUS_JSON).expect("tests/golden-answers/mcp-eval.json is valid JSON")
}

/// Read a capture named the way the corpus names it.
fn read_capture(relative: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// Compare one answer, honoring the case's match kind.
fn answer_matches(expected: &Value, actual: &Value, kind: MatchKind) -> bool {
    match kind {
        MatchKind::Equals => expected == actual,
        MatchKind::Contains => match (expected.as_str(), actual.as_str()) {
            (Some(needle), Some(hay)) => hay.contains(needle),
            // A `contains` case whose values are not both strings is a corpus
            // mistake, and reporting it as a mismatch is how it gets noticed.
            _ => false,
        },
    }
}

/// Ask every question the corpus has about one capture, over one session.
///
/// Every case is reported, not just the first: an eval that stops at the first
/// wrong answer hides how much of the surface moved.
fn run_capture(capture: &str) {
    let corpus = corpus();
    let cases: Vec<&Case> = corpus
        .cases
        .iter()
        .filter(|c| c.capture == capture)
        .collect();
    assert!(
        !cases.is_empty(),
        "no corpus case names {capture}, so this test asked nothing. Either the \
         capture was renamed in the corpus and not here, or the cases were deleted."
    );

    let bytes = read_capture(capture);
    let mut session = McpSession::start(capture, &[]);
    let mut failures: Vec<String> = Vec::new();

    for case in &cases {
        let reply = session.ok(&case.tool, case.arguments.clone());
        let oracle = case.oracle.derive(&bytes);
        let oracle_agrees = oracle.map(|v| case.expected.as_u64() == Some(v));

        let Some(actual) = case.answer.resolve(&reply) else {
            failures.push(format!(
                "[{}] MISSING ANSWER\n  question: {}\n  the reply carries nothing at {}, so the \
                 tool no longer answers the question at all\n  reply: {reply}",
                case.id,
                case.question,
                case.answer.describe(),
            ));
            continue;
        };

        let verdict = classify(
            answer_matches(&case.expected, &actual, case.match_kind),
            oracle_agrees,
        );
        if verdict != Verdict::Agrees {
            let rederived = match oracle {
                Some(v) => format!("{v}"),
                None => "not re-derivable in-process".to_string(),
            };
            failures.push(format!(
                "[{}] {}\n  question:   {}\n  asked:      {} {}\n  read at:    {}\n  \
                 expected:   {} ({:?})\n  got:        {}\n  re-derived: {}\n  meaning:    {}\n  \
                 derivation: {}",
                case.id,
                verdict.headline(),
                case.question,
                case.tool,
                case.arguments,
                case.answer.describe(),
                case.expected,
                case.match_kind,
                actual,
                rederived,
                verdict.guidance(),
                case.derivation,
            ));
        }

        // The trap, proved live. Without this the "an agent would answer 50"
        // claim in the corpus is a story rather than a fact about this run.
        if let Some(naive) = &case.naive {
            match naive.answer.resolve(&reply) {
                Some(got) if got == naive.value => {}
                other => failures.push(format!(
                    "[{}] TRAP MOVED\n  the careless reading of this reply was {} at {}, and is \
                     now {:?}\n  note: {}\n  This is not a wrong answer — it says the shape of \
                     the failure mode changed, so update the corpus's `naive` block after \
                     checking the case still discriminates.",
                    case.id,
                    naive.value,
                    naive.answer.describe(),
                    other,
                    naive.note,
                )),
            }
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} golden answers about {capture} did not hold:\n\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n\n"),
    );
}

// ── the eval ────────────────────────────────────────────────────────

/// The capture big enough to exceed one page, and therefore the only one that
/// can spring the trap PB13 names.
#[test]
fn golden_answers_hold_on_the_branch_scenario_capture() {
    run_capture(BRANCH);
}

/// Five calls, four failure classes, one success: per-call answers.
#[test]
fn golden_answers_hold_on_the_problem_call_capture() {
    run_capture(PROBLEM);
}

/// Media answers, where the two calls differ from each other.
#[test]
fn golden_answers_hold_on_the_g711_capture() {
    run_capture(G711);
}

// ── the corpus has to stay a corpus ─────────────────────────────────

/// Every case says how its answer was derived, and names a command.
///
/// The rule this whole file rests on. A case whose `derivation` is a shrug is
/// a change-detector that has been let in, and it will assert a wrong number
/// as confidently as a right one.
#[test]
fn every_case_records_how_its_answer_was_derived() {
    let corpus = corpus();
    let mut offenders = Vec::new();
    for case in &corpus.cases {
        // Naming a command is the testable proxy for "somebody can repeat
        // this". `tshark` covers the capture-derived values; `RFC` covers the
        // two whose ground truth is a specification rather than a file.
        let names_a_route = case.derivation.contains("tshark") || case.derivation.contains("RFC ");
        if !names_a_route || case.derivation.len() < 60 {
            offenders.push(format!(
                "{}: derivation names no command or specification: {:?}",
                case.id, case.derivation
            ));
        }
        if case.question.trim().is_empty() {
            offenders.push(format!("{}: no question", case.id));
        }
    }
    assert!(
        offenders.is_empty(),
        "these cases cannot be re-derived, which makes them change-detectors:\n  {}",
        offenders.join("\n  "),
    );
}

/// A trap case has to name a value that is actually WRONG.
///
/// A `naive` block whose value equals the expected answer discriminates
/// nothing: the careless reading and the careful one agree, so the case would
/// pass whether or not the tool reported its truncation. That is the vacuous
/// eval, and it is caught here rather than shipped.
#[test]
fn every_trap_case_names_an_answer_the_trap_would_get_wrong() {
    let corpus = corpus();
    let mut traps = 0usize;
    let mut offenders = Vec::new();
    for case in &corpus.cases {
        let Some(naive) = &case.naive else { continue };
        traps += 1;
        if naive.value == case.expected {
            offenders.push(format!(
                "{}: the careless reading and the right answer are both {}, so this case \
                 cannot tell them apart",
                case.id, naive.value
            ));
        }
        if naive.note.trim().is_empty() {
            offenders.push(format!("{}: the trap is not explained", case.id));
        }
    }
    assert!(
        offenders.is_empty(),
        "vacuous trap cases:\n  {}",
        offenders.join("\n  ")
    );
    assert!(
        traps >= 4,
        "only {traps} cases carry a trap. The failure PB13 was opened for is a page \
         mistaken for a total, so a corpus that stops asking about it stops testing \
         the thing it was built for."
    );
}

/// The oracles run, and produce the golden answer.
///
/// Separate from the eval on purpose. Inside `run_capture` an oracle that
/// silently returned the wrong number would show up as a moved ground truth
/// only if the tool ALSO disagreed; on a passing run it would never be looked
/// at. Here it is the only thing under test, so a broken instrument fails
/// before it can quietly excuse a broken tool.
#[test]
fn the_independent_oracles_run_and_produce_a_number() {
    let corpus = corpus();
    let mut checked = 0usize;
    let mut offenders = Vec::new();
    for case in &corpus.cases {
        let bytes = read_capture(&case.capture);
        let Some(value) = case.oracle.derive(&bytes) else {
            continue;
        };
        checked += 1;
        if value == 0 {
            offenders.push(format!(
                "{}: the byte scan found nothing at all, which is what a broken oracle and an \
                 empty capture look like alike",
                case.id
            ));
        }
        if case.expected.as_u64() != Some(value) {
            offenders.push(format!(
                "{}: re-deriving from {} gives {value}, but the corpus expects {}. Either the \
                 fixture changed or the recorded answer was never right.",
                case.id, case.capture, case.expected
            ));
        }
    }
    assert!(
        offenders.is_empty(),
        "the independent re-derivation disagrees with the corpus:\n  {}",
        offenders.join("\n  ")
    );
    assert!(
        checked >= 10,
        "only {checked} cases re-derive their answer in-process. Below that, most of a \
         failure report would read ANSWER CHANGED, which is the verdict that tells a \
         reader nothing."
    );
}

/// The corpus spans several captures and several tools.
///
/// One capture and one tool would make this an expensive unit test. The whole
/// claim is about the SURFACE an agent talks to.
#[test]
fn the_corpus_spans_several_captures_and_several_tools() {
    let corpus = corpus();
    let captures: std::collections::BTreeSet<&str> =
        corpus.cases.iter().map(|c| c.capture.as_str()).collect();
    let tools: std::collections::BTreeSet<&str> =
        corpus.cases.iter().map(|c| c.tool.as_str()).collect();
    assert!(
        captures.len() >= 3,
        "the corpus asks about {} capture(s): {captures:?}",
        captures.len()
    );
    assert!(
        tools.len() >= 6,
        "the corpus exercises {} tool(s): {tools:?}",
        tools.len()
    );
    // Every capture the corpus names must have a test function driving it, or
    // its cases are carried and never run.
    let driven: std::collections::BTreeSet<&str> = [BRANCH, PROBLEM, G711].into_iter().collect();
    assert_eq!(
        captures, driven,
        "a capture in the corpus has no test function of its own, so its cases never run"
    );
}

/// The questions the fixtures cannot answer are written down, with reasons.
///
/// "If a fixture is too thin to support a question, say so rather than
/// inventing a number." An empty list here would mean either that every
/// question is answerable — which is not true of these fixtures — or that
/// nobody wrote down the ones that are not.
#[test]
fn the_corpus_names_the_questions_the_fixtures_cannot_answer() {
    let corpus = corpus();
    assert!(
        corpus.unanswerable.len() >= 3,
        "only {} question(s) recorded as unanswerable",
        corpus.unanswerable.len()
    );
    let mut offenders = Vec::new();
    for skipped in &corpus.unanswerable {
        if skipped.reason.len() < 60 {
            offenders.push(format!(
                "{:?}: the reason is too short to be one: {:?}",
                skipped.question, skipped.reason
            ));
        }
        if skipped.question.trim().is_empty() || skipped.capture.trim().is_empty() {
            offenders.push(format!("{skipped:?}: incomplete entry"));
        }
        // A question recorded as unanswerable must not also be answered.
        if corpus
            .cases
            .iter()
            .any(|c| c.question == skipped.question && c.capture == skipped.capture)
        {
            offenders.push(format!(
                "{:?} is listed as unanswerable and also has a golden answer",
                skipped.question
            ));
        }
    }
    assert!(
        offenders.is_empty(),
        "the unanswerable list is not carrying its reasons:\n  {}",
        offenders.join("\n  ")
    );
}

// ── the classifier, driven directly ─────────────────────────────────

/// A disagreement the capture contradicts is reported as a defect.
///
/// The verdict that must not be softened: the tool said something the bytes do
/// not support, in this run, with the re-derivation right beside it.
#[test]
fn a_disagreement_the_oracle_contradicts_is_reported_as_a_wrong_answer() {
    let v = classify(false, Some(true));
    assert_eq!(v, Verdict::WrongAnswer);
    assert!(v.headline().contains("WRONG"), "{}", v.headline());
    assert!(
        v.guidance().contains("do not move the golden"),
        "the guidance must forbid the easy fix: {}",
        v.guidance()
    );
}

/// A disagreement with no oracle is reported as a change, not as a defect.
///
/// The harness must not claim to know which side is wrong when it cannot
/// re-derive the answer. Overclaiming here would teach the next reader to
/// distrust the WRONG ANSWER verdict too.
#[test]
fn a_disagreement_with_no_oracle_is_reported_as_a_change_not_a_defect() {
    let v = classify(false, None);
    assert_eq!(v, Verdict::AnswerChanged);
    assert!(v.headline().contains("CHANGED"), "{}", v.headline());
    assert!(
        !v.headline().contains("WRONG"),
        "a change must not be reported as a defect: {}",
        v.headline()
    );
    assert!(
        v.guidance().contains("cannot tell"),
        "the guidance must admit what it does not know: {}",
        v.guidance()
    );
}

/// A moved oracle is reported even when the tool still agrees.
///
/// The pass that is not evidence. Without this branch a fixture edited under
/// both the tool and the oracle would keep the suite green while nothing in it
/// was still being checked.
#[test]
fn a_moved_oracle_is_reported_even_when_the_tool_still_agrees() {
    assert_eq!(classify(true, Some(false)), Verdict::GroundTruthMoved);
    assert_eq!(
        classify(false, Some(false)),
        Verdict::AnswerAndGroundTruthMoved
    );
    // ...and the two clean cases stay clean, or the harness cries wolf.
    assert_eq!(classify(true, Some(true)), Verdict::Agrees);
    assert_eq!(classify(true, None), Verdict::Agrees);
}
