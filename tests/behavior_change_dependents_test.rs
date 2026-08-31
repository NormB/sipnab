// SPDX-License-Identifier: MIT OR Apache-2.0

//! A deliberate behavior change must be checked against what depended on the
//! old behavior.
//!
//! # The defect this file exists for
//!
//! `search_messages` used to match a chosen list of fields -- the method, the
//! status code, `From`, `To`, `User-Agent` and the body -- so anything in any
//! other header was invisible to it. Measured on the site's own sample
//! capture, it answered `total_matched: 0` for `Subscription-State` while
//! `list_dialogs` with `payload =~` found 3 dialogs in the same store at the
//! same instant. Two surfaces disagreeing about what a capture contains is a
//! defect, and the widening -- scan the whole raw message, the way the filter
//! DSL's `payload` field already did -- was the right fix.
//!
//! I shipped the widening without asking what had depended on the narrow
//! scope. Two things had:
//!
//! 1. **Two golden answers.** `tests/golden-answers/mcp-eval.json` asked "How
//!    many REGISTER requests are in this capture?" through
//!    `search_messages {"query":"REGISTER"}` and expected 1334. After the
//!    widening it returned 2668 -- exactly double, because a 200 OK answering
//!    a REGISTER carries `CSeq: N REGISTER`, so every response matched too.
//!    The entries' own `oracle` field already declared the query that asks the
//!    question: the byte literal `REGISTER sip:`, which is the request line.
//!    The fix moved the QUERY to that literal. The expected values, 1334 and
//!    1135, never changed -- the corpus was right and the query was wrong.
//! 2. **A fixture's premise.** The paging fixture
//!    `search_messages_pages_every_hit_exactly_once` in `src/mcp/server.rs`
//!    builds five dialogs of INVITE plus 200 OK, and its comment said "The 200
//!    OK carries no INVITE token, so each dialog contributes exactly one hit."
//!    A 200 answering an INVITE carries `CSeq: 1 INVITE`. The sentence was
//!    true only of the old field list, and nothing made it false out loud when
//!    the field list went away: it is a comment, and comments do not fail.
//!
//! # What is gated here
//!
//! Four dependents of that one behavior, plus the non-vacuity check that keeps
//! them from passing over nothing:
//!
//! * a golden question about REQUESTS of a method must be asked with the
//!   request-line literal, never the bare method name;
//! * a `byte_literal` oracle and the query on the same entry cannot drift
//!   apart, because the oracle IS the entry's statement of what it means;
//! * the tool description must describe the widened behavior -- a description
//!   narrower than the behavior misleads exactly as badly as a wider one;
//! * the paging fixture must not carry an unretracted claim that a response
//!   lacks the method of the transaction it answers.
//!
//! # A discriminator this file had to get right
//!
//! The obvious form of the fourth rule -- "the fixture body must not contain
//! the phrase `carries no INVITE token`" -- fails on the CORRECTED repository.
//! The fix did not delete the false sentence, it quoted it and retracted it:
//! `This comment used to say "the 200 OK carries no INVITE token", which was
//! true only while ...`. A substring scan cannot tell a claim from its own
//! retraction, and narrowing it away by hand until it went green would have
//! been narrowing until blind. So the rule below asks whether the claim is
//! marked as retracted in the lines around it, and it is driven from BOTH
//! sides: a bare claim must be caught, a retracted one must not be.

#![cfg(feature = "full")]

use std::path::PathBuf;

use regex::Regex;
use serde_json::Value;

/// SIP method names a golden question might ask about.
///
/// A closed list on purpose: matching any bare upper-case word would read "How
/// many SIP messages" as a question about a method named SIP.
const SIP_METHODS: &[&str] = &[
    "INVITE",
    "REGISTER",
    "BYE",
    "ACK",
    "CANCEL",
    "OPTIONS",
    "SUBSCRIBE",
    "NOTIFY",
    "PUBLISH",
    "REFER",
    "INFO",
    "UPDATE",
    "PRACK",
    "MESSAGE",
];

/// MCP tools whose `query` argument is a literal substring scanned over
/// message text, and which therefore have to agree with a `byte_literal`
/// oracle.
///
/// `search_by_time` and `find_correlated` take a window and a Call-ID, not a
/// needle, so a byte literal says nothing about them.
const TEXT_SEARCH_TOOLS: &[&str] = &["search_messages"];

/// Phrases that mark a quoted claim as retracted rather than asserted.
const RETRACTION_MARKERS: &[&str] = &[
    "used to say",
    "used to read",
    "used to claim",
    "was true only",
    "no longer",
];

/// The repository root.
fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The golden-answer corpus, parsed.
fn corpus() -> Value {
    let path = repo().join("tests/golden-answers/mcp-eval.json");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("tests/golden-answers/mcp-eval.json must be readable: {e}"));
    serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("tests/golden-answers/mcp-eval.json must be valid JSON: {e}"))
}

/// Every entry under `cases`.
fn cases(root: &Value) -> Vec<&Value> {
    root["cases"]
        .as_array()
        .expect("the corpus must carry a `cases` array")
        .iter()
        .collect()
}

/// A case's `id`, for failure messages that name the entry.
fn id_of(case: &Value) -> String {
    case["id"].as_str().unwrap_or("<unnamed>").to_string()
}

/// `src/mcp/server.rs`, read whole.
fn server_source() -> String {
    let path = repo().join("src/mcp/server.rs");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("src/mcp/server.rs must be readable: {e}"))
}

/// The `description = "..."` string attached to a `#[tool(name = "<tool>")]`
/// registration, with Rust line continuations folded back into one line.
fn tool_description(src: &str, tool: &str) -> String {
    let anchor = format!("name = \"{tool}\"");
    let at = src
        .find(&anchor)
        .unwrap_or_else(|| panic!("src/mcp/server.rs must register a tool named {tool}"));
    let rest = &src[at..];
    let open = rest
        .find("description = \"")
        .unwrap_or_else(|| panic!("the {tool} registration must carry a description"))
        + "description = \"".len();
    let body = &rest[open..];
    let mut end = None;
    let mut escaped = false;
    for (i, c) in body.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' => escaped = true,
            '"' => {
                end = Some(i);
                break;
            }
            _ => {}
        }
    }
    let end = end.unwrap_or_else(|| panic!("the {tool} description string is never closed"));
    fold_continuations(&body[..end])
}

/// Fold a Rust string literal's escapes: a backslash-newline continuation and
/// the indentation after it collapse to nothing, the rest come through as
/// themselves.
fn fold_continuations(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.peek() {
            Some('\n') => {
                chars.next();
                while chars.peek().is_some_and(|n| *n == ' ' || *n == '\t') {
                    chars.next();
                }
            }
            Some('n') => {
                chars.next();
                out.push(' ');
            }
            Some('"') => {
                chars.next();
                out.push('"');
            }
            Some('\\') => {
                chars.next();
                out.push('\\');
            }
            _ => out.push(c),
        }
    }
    out
}

/// The paging fixture: its doc block, its attributes and its whole body.
fn paging_fixture_source(src: &str) -> String {
    let lines: Vec<&str> = src.lines().collect();
    let decl = lines
        .iter()
        .position(|l| l.contains("fn search_messages_pages_every_hit_exactly_once"))
        .expect(
            "src/mcp/server.rs must still define \
             search_messages_pages_every_hit_exactly_once; if it was renamed, \
             this rule is pointing at nothing",
        );
    let mut start = decl;
    while start > 0 {
        let t = lines[start - 1].trim();
        if t.starts_with("///") || t.starts_with("#[") {
            start -= 1;
        } else {
            break;
        }
    }
    let mut end = decl;
    while end < lines.len() && lines[end].trim_end() != "    }" {
        end += 1;
    }
    assert!(
        end < lines.len(),
        "the paging fixture's closing brace was never found; the extraction \
         would hand every rule below the rest of the file"
    );
    lines[start..=end].join("\n")
}

/// Lines claiming a response carries no method token, EXCLUDING those the
/// surrounding comment marks as retracted.
///
/// The retraction test is the discriminator this file turns on, so it is
/// driven from both sides in
/// `the_paging_fixture_does_not_claim_a_response_lacks_the_method`.
fn unretracted_method_absence_claims(text: &str) -> Vec<String> {
    let methods = SIP_METHODS.join("|");
    let claim = Regex::new(&format!(
        r"(?i)\b(?:carries|carry|contains|contain|holds|hold|has|have)\s+no\s+(?:{methods})\b|\bno\s+(?:{methods})\s+token\b"
    ))
    .expect("the claim pattern must compile");
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if !claim.is_match(line) {
            continue;
        }
        let lo = i.saturating_sub(3);
        let hi = (i + 4).min(lines.len());
        let window = lines[lo..hi].join(" ").to_ascii_lowercase();
        if RETRACTION_MARKERS.iter().any(|m| window.contains(m)) {
            continue;
        }
        out.push((*line).trim().to_string());
    }
    out
}

// ── the golden corpus's dependents ──────────────────────────────────

/// A golden question about REQUESTS of a method is asked with the request
/// line, not the bare method name.
///
/// `search_messages` reads the WHOLE message, so a bare method name also
/// matches the `CSeq` header of every response answering that method: a 200 OK
/// replying to a REGISTER carries `CSeq: N REGISTER` and matches `REGISTER`.
/// That is why `{"query":"REGISTER"}` returned 2668 against 1334 actual
/// requests -- exactly one extra hit per response. The request-line form
/// `REGISTER sip:` cannot appear in a response, because a response's first
/// line is a status line, so it counts requests and only requests.
///
/// The consequence if this regresses: the corpus asks a question about
/// requests, the tool answers about requests plus responses, and the golden
/// value has to be doubled to keep the suite green -- pinning a wrong answer
/// as the right one.
#[test]
fn a_golden_search_query_asks_the_question_the_entry_poses() {
    let methods = SIP_METHODS.join("|");
    let asks_about_requests =
        Regex::new(&format!(r"(?i)\b({methods})\b[^.?]*\brequests?\b")).expect("pattern compiles");

    let root = corpus();
    let mut checked = 0usize;
    let mut wrong = Vec::new();
    for case in cases(&root) {
        if case["tool"].as_str() != Some("search_messages") {
            continue;
        }
        let question = case["question"].as_str().unwrap_or_default();
        let Some(m) = asks_about_requests.captures(question) else {
            continue;
        };
        let method = m[1].to_ascii_uppercase();
        let query = case["arguments"]["query"].as_str().unwrap_or_default();
        checked += 1;
        let id = id_of(case);
        if !query.to_ascii_lowercase().contains("sip:") {
            wrong.push(format!(
                "  {id}: asks about {method} REQUESTS but queries {query:?}, \
                 which is not the request-line form and so also matches the \
                 CSeq of every response"
            ));
            continue;
        }
        if !query.to_ascii_uppercase().starts_with(&method) {
            wrong.push(format!(
                "  {id}: asks about {method} requests but queries {query:?}, \
                 which does not begin with that method"
            ));
        }
    }
    assert!(
        checked >= 2,
        "only {checked} golden question(s) about requests of a method were \
         found on search_messages; the corpus held two when this rule was \
         written, so the match has stopped working and the rule below is \
         scanning nothing"
    );
    assert!(
        wrong.is_empty(),
        "these golden entries ask about requests but do not query for one:\n{}\n\n\
         search_messages reads the whole message, so a bare method name matches \
         `CSeq: N <METHOD>` in every response too. Query the request line.",
        wrong.join("\n")
    );
}

/// A `byte_literal` oracle and the query on the same entry cannot drift apart.
///
/// The oracle is the entry's own statement of what it means: a byte scan of
/// the capture file for that literal is what re-derives the expected value
/// without going through sipnab. When the tool is a text search, the query and
/// the oracle are therefore two spellings of one intent, and the incident was
/// exactly what it looks like when they disagree -- the oracle already said
/// `REGISTER sip:` while the query said `REGISTER`, so the corpus carried the
/// right answer and asked the wrong question, and only the value moved.
///
/// The consequence if this regresses: the eval can fail with the oracle and
/// the tool both correct and no way to see which half is lying.
#[test]
fn a_byte_literal_oracle_and_its_query_cannot_drift_apart() {
    let root = corpus();
    let mut checked = 0usize;
    let mut drifted = Vec::new();
    for case in cases(&root) {
        let tool = case["tool"].as_str().unwrap_or_default();
        if !TEXT_SEARCH_TOOLS.contains(&tool) {
            continue;
        }
        if case["oracle"]["kind"].as_str() != Some("byte_literal") {
            continue;
        }
        let literal = case["oracle"]["literal"].as_str().unwrap_or_default();
        let query = case["arguments"]["query"].as_str().unwrap_or_default();
        checked += 1;
        assert!(
            !literal.is_empty(),
            "{}: a byte_literal oracle with no literal re-derives nothing",
            id_of(case)
        );
        if !query
            .to_ascii_lowercase()
            .contains(&literal.to_ascii_lowercase())
        {
            drifted.push(format!(
                "  {}: oracle literal {literal:?}, query {query:?}",
                id_of(case)
            ));
        }
    }
    assert!(
        checked >= 2,
        "only {checked} entr(y/ies) pair a byte_literal oracle with a text \
         search; two existed when this rule was written, so it has stopped \
         finding its subject"
    );
    assert!(
        drifted.is_empty(),
        "these entries query for something other than the literal their own \
         oracle re-derives:\n{}\n\nThe oracle is the entry's statement of what \
         it means. A query that is not at least that literal asks a different \
         question from the one the expected value answers.",
        drifted.join("\n")
    );
}

// ── the surface's own dependents ────────────────────────────────────

/// The `search_messages` description describes what `search_messages`
/// searches.
///
/// The surface-parity half of the incident. A description that enumerates a
/// closed field list -- method, status, `From`, `To`, `User-Agent`, body --
/// misleads exactly as badly as one wider than the behavior: an agent reading
/// it plans around a scope the tool does not have, and the wrong plan is
/// invisible because both the description and the reply look fine.
///
/// The consequence if this regresses: the tool reads the whole message, the
/// description says it reads six fields, and the agent that believes the
/// description never asks about the header it needed.
#[test]
fn the_search_messages_description_matches_what_it_searches() {
    let src = server_source();
    let desc = tool_description(&src, "search_messages");
    assert!(
        desc.len() > 80,
        "the extracted search_messages description is {} byte(s) long, which \
         is too short to be the real one -- the extraction is broken and the \
         assertions below prove nothing: {desc:?}",
        desc.len()
    );
    let lower = desc.to_ascii_lowercase();
    assert!(
        lower.contains("whole") && lower.contains("message"),
        "the search_messages description does not say it reads the WHOLE \
         message. It does read the whole message -- a description narrower \
         than the behavior sends an agent looking for a header it was told is \
         not searched. Description was: {desc:?}"
    );
    let enumerated: Vec<&str> = ["user-agent", "from`, `to", "method, status"]
        .into_iter()
        .filter(|token| lower.contains(token))
        .collect();
    assert!(
        enumerated.is_empty(),
        "the search_messages description enumerates a closed field list \
         ({enumerated:?}). It scans every byte of the raw message, the same \
         bytes the filter DSL's `payload` field scans; naming individual \
         header fields re-creates the narrow scope in the documentation after \
         it was removed from the code. Description was: {desc:?}"
    );
}

/// The paging fixture does not claim a response lacks the method it answers.
///
/// A `CSeq` header carries the method of the transaction it belongs to, so a
/// 200 OK answering an INVITE carries `CSeq: 1 INVITE`. Any comment saying a
/// response "carries no INVITE token" is false about SIP itself -- it was only
/// ever true of a search that read six chosen fields, and it survived the
/// widening because a comment cannot fail.
///
/// A bare substring scan cannot run this rule: the corrected fixture QUOTES
/// the false sentence in order to retract it. So the scan is retraction-aware,
/// and both directions are exercised here -- an unmarked claim must be caught,
/// a retracted one must not be -- because an exclusion validated from one side
/// is a description of one example, not a discriminator.
///
/// The consequence if this regresses: the fixture's stated reason for its own
/// numbers contradicts the code, and the next person to touch it "fixes" the
/// assertion to match the comment.
#[test]
fn the_paging_fixture_does_not_claim_a_response_lacks_the_method() {
    let bare_claim = "        // The 200 OK carries no INVITE token, so each dialog\n\
                      // contributes exactly one hit.\n";
    assert_eq!(
        unretracted_method_absence_claims(bare_claim).len(),
        1,
        "the scan does not catch the sentence this rule exists for; every \
         assertion below it would pass by seeing nothing"
    );
    let retracted = "        // TWO hits per dialog. This comment used to say the 200 OK\n\
                     // carries no INVITE token, which was true only while the\n\
                     // search read a chosen list of fields.\n";
    assert!(
        unretracted_method_absence_claims(retracted).is_empty(),
        "the scan reads a retraction as a claim, so the corrected fixture can \
         never satisfy this rule and the rule is unfixable by design"
    );

    let src = server_source();
    let fixture = paging_fixture_source(&src);
    assert!(
        fixture.contains("ok200(") && fixture.contains("invite("),
        "the extracted fixture does not build INVITE plus 200 OK dialogs, so \
         it is not the fixture this rule is about: {fixture}"
    );
    let claims = unretracted_method_absence_claims(&fixture);
    assert!(
        claims.is_empty(),
        "the paging fixture asserts a response carries no method token:\n  {}\n\n\
         A CSeq header carries the method of the transaction it answers, so a \
         200 OK replying to an INVITE carries `CSeq: 1 INVITE` and the search \
         matches it. Two hits per dialog, not one.",
        claims.join("\n  ")
    );

    let total = Regex::new(r#"total_matched"\]\s*,\s*(\d+)"#).expect("pattern compiles");
    let found = total
        .captures(&fixture)
        .expect("the paging fixture must assert a total_matched value");
    assert_eq!(
        &found[1], "10",
        "the paging fixture expects total_matched {} over five dialogs of \
         INVITE plus 200 OK. Five would mean the responses are not counted, \
         which is the pre-widening behavior -- the number and the comment have \
         to move together.",
        &found[1]
    );
}

// ── non-vacuity ─────────────────────────────────────────────────────

/// The inputs every rule above reads are real and non-empty.
///
/// Each rule above is a scan, and a scan over an empty set passes. A renamed
/// corpus file, a moved `src/mcp/server.rs`, or a `cases` array emptied by a
/// bad edit would turn all four green while checking nothing -- which is the
/// same failure mode as the incident itself, an answer that looks confident
/// and is about nothing.
#[test]
fn the_inputs_these_rules_read_are_not_empty() {
    let root = corpus();
    let all = cases(&root);
    assert!(
        all.len() >= 8,
        "the golden corpus holds {} case(s); it held 22 when this file was \
         written and every rule above scans it",
        all.len()
    );
    let searches = all
        .iter()
        .filter(|c| c["tool"].as_str() == Some("search_messages"))
        .count();
    assert!(
        searches >= 2,
        "only {searches} golden case(s) use search_messages; two existed when \
         this file was written, and the query rules have no subject without \
         them"
    );
    for case in &all {
        assert!(
            case["id"].as_str().is_some_and(|s| !s.is_empty()),
            "a golden case has no id, so a failure above cannot name it"
        );
    }

    let src = server_source();
    assert!(
        src.len() > 100_000,
        "src/mcp/server.rs read as {} byte(s); the real file is over half a \
         megabyte, so the description and fixture rules are reading a stub",
        src.len()
    );
    assert!(
        src.contains("name = \"search_messages\""),
        "src/mcp/server.rs no longer registers a tool named search_messages"
    );
    assert!(
        src.contains("fn search_messages_pages_every_hit_exactly_once"),
        "src/mcp/server.rs no longer defines the paging fixture this file gates"
    );
}
