// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The regex budget of one filter expression.
//!
//! Every `=~` value is compiled when the expression is parsed, and the regex
//! crate's 1,000,000-byte size limit bounds only the compiled program, not the
//! work done before it. A case-insensitive bracket class such as `(?i)[\D]` is
//! case-folded over the whole Unicode range it covers while the pattern is
//! translated, before the size limit is consulted. Measured on 2026-11-20
//! (optimized build, Jetson AGX Thor, 14 cores): 1 KiB of `(?i)[\D]` took 369 ms to compile, and
//! one 3,862-byte value from the fuzz corpus took 102 ms (0.7 ms without
//! `(?i)`). An expression held up to 512 such comparisons, so one `--filter`,
//! REST `filter` or MCP filter argument could cost seconds of CPU and, with
//! regexes near the size limit, hundreds of megabytes.
//!
//! The same cost made the ClusterFuzzLite corpus merge of `fuzz_filter_dsl`
//! (5,723 inputs, 36 s under the fuzzing sanitizer against a 38 s budget) time
//! out on 2026-11-20. The input that cost most is committed as the seed
//! `fuzz/corpus/filter_dsl/case-folded-classes-4k` and is replayed here.
//!
//! The budget is checked on the pattern text before the regex crate sees it,
//! so a refused expression costs a scan of its text, not a compile.

use std::time::{Duration, Instant};

use chrono::{TimeZone, Utc};

use sipnab::net::TransportProto;
use sipnab::rtp::diagnosis::CaptureMedia;
use sipnab::rtp::quality::MosDelay;
use sipnab::sip::dialog::SipDialog;
use sipnab::sip::dsl::FilterExpr;
use sipnab::sip::parser::parse_sip;

/// Any error a test can return; `?` converts into it.
type TestError = Box<dyn std::error::Error>;

/// Regex comparisons one expression may hold. Mirrors the private constant;
/// the refusal tests assert the parser's message carries this figure.
const MAX_REGEX_COMPARISONS: usize = 8;

/// Pattern bytes, all regexes of one expression together.
const MAX_REGEX_PATTERN_BYTES: usize = 1024;

/// Bracket classes and Unicode classes, all regexes of one expression together.
const MAX_REGEX_CLASSES: usize = 16;

/// The corpus input that cost most in the timed-out merge.
const PRUNE_SEED: &[u8] = include_bytes!("../fuzz/corpus/filter_dsl/case-folded-classes-4k");

/// A refusal must come from a scan of the text, not from a compile. Far above
/// what scanning a few KiB takes even in a debug build on a loaded host, and
/// far below the seconds the same text took to compile before the budget.
const REFUSAL_BOUND: Duration = Duration::from_millis(250);

/// What compiling a whole budget's worth of regexes may take in a debug build
/// on a loaded host. The at-limit expression of
/// `the_costliest_accepted_expression_parses_within_a_bound` compiles sixteen
/// case-folded classes and eight near-limit programs.
const ACCEPTED_BOUND: Duration = Duration::from_secs(10);

// ── Helpers ─────────────────────────────────────────────────────────

/// The parse error for `expr`, or an error naming what was accepted instead.
fn parse_err(expr: &str) -> Result<String, TestError> {
    match FilterExpr::parse(expr) {
        Ok(_) => Err(format!("expression of {} bytes was accepted", expr.len()).into()),
        Err(e) => Ok(e.to_string()),
    }
}

/// The parse error and how long the parse took.
fn timed_err(expr: &str) -> Result<(String, Duration), TestError> {
    let start = Instant::now();
    let message = parse_err(expr)?;
    Ok((message, start.elapsed()))
}

/// The `at position N` figure of a parser message.
fn position(message: &str) -> Result<usize, TestError> {
    let after = message
        .split("at position ")
        .nth(1)
        .ok_or_else(|| format!("no position in: {message}"))?;
    let digits: String = after.chars().take_while(char::is_ascii_digit).collect();
    Ok(digits.parse()?)
}

/// `n` comparisons of `term` joined by `OR`.
fn or_chain(term: &str, n: usize) -> String {
    vec![term; n].join(" OR ")
}

/// A dialog whose User-Agent is `Friendly-Scanner 1.0` and caller `1001`.
fn scanner_dialog() -> Result<SipDialog, TestError> {
    let raw = b"INVITE sip:2002@example.com SIP/2.0\r\n\
        Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bKbudget\r\n\
        From: <sip:1001@example.com>;tag=t1\r\n\
        To: <sip:2002@example.com>\r\n\
        Call-ID: budget@example.com\r\n\
        CSeq: 1 INVITE\r\n\
        User-Agent: Friendly-Scanner 1.0\r\n\
        Content-Length: 0\r\n\r\n";
    let ts = Utc
        .with_ymd_and_hms(2026, 11, 20, 12, 0, 0)
        .single()
        .ok_or("unambiguous fixed timestamp")?;
    let ip = "192.0.2.10".parse()?;
    let msg = parse_sip(raw, ts, ip, ip, 5060, 5060, TransportProto::Udp)?;
    Ok(SipDialog::new(&msg).ok_or("dialog from INVITE")?)
}

/// Whether `expr` parses and matches [`scanner_dialog`].
fn matches_scanner(expr: &str) -> Result<bool, TestError> {
    let filter = FilterExpr::parse(expr)?;
    Ok(filter.matches_dialog(
        &scanner_dialog()?,
        &[],
        CaptureMedia::Absent,
        MosDelay::unknown(),
    ))
}

// ── The regression: what timed out the corpus merge ────────────────

/// The committed prune seed is refused by the budget, quickly.
///
/// Before the budget it compiled its first value, 3,862 bytes (102 ms
/// optimized, 820 ms under the fuzzing sanitizer), and was then refused for
/// trailing input. The byte limit is checked before the class limit, so the
/// byte limit is what names it.
#[test]
fn the_prune_timeout_seed_is_refused_by_the_budget() -> Result<(), TestError> {
    let text = std::str::from_utf8(PRUNE_SEED)?;
    let (message, took) = timed_err(text)?;
    assert!(
        message.contains(&format!("{MAX_REGEX_PATTERN_BYTES} bytes")),
        "the seed must be refused by the pattern byte budget, got: {message}"
    );
    assert!(
        took < REFUSAL_BOUND,
        "refusing the seed took {took:?}; the budget must refuse it before compiling"
    );
    Ok(())
}

/// Sixteen KiB of `(?i)[\D]` — seconds of compile before the budget — is
/// refused before the regex crate sees it.
#[test]
fn an_over_budget_expression_is_refused_before_any_regex_compiles() -> Result<(), TestError> {
    let expr = format!("ua =~ '(?i){}'", "[\\D]".repeat(4096));
    let (message, took) = timed_err(&expr)?;
    assert!(
        message.contains("regex"),
        "the refusal must name the regex budget, got: {message}"
    );
    assert!(
        took < REFUSAL_BOUND,
        "refusing {} bytes of case-folded classes took {took:?}; it must not compile them",
        expr.len()
    );
    Ok(())
}

/// A long chain of class-heavy comparisons stops at the term that goes past
/// the class budget: the terms after it are never compiled.
///
/// Each term holds three case-folded classes, so five terms (15 classes)
/// compile and the sixth is refused. Before the budget all 300 compiled.
#[test]
fn a_chain_of_class_heavy_comparisons_stops_at_the_budget() -> Result<(), TestError> {
    let term = "ua =~ '(?i)[\\D][\\W][\\S]'";
    let expr = or_chain(term, 300);
    let (message, took) = timed_err(&expr)?;
    assert!(
        message.contains(&format!("{MAX_REGEX_CLASSES} character classes")),
        "the refusal must name the class budget, got: {message}"
    );
    let sixth_value = 5 * (term.len() + " OR ".len()) + "ua =~ ".len();
    assert_eq!(
        position(&message)?,
        sixth_value,
        "the sixth term is the one past 16 classes, got: {message}"
    );
    assert!(
        took < ACCEPTED_BOUND,
        "refusing a 300-term chain took {took:?}"
    );
    Ok(())
}

// ── Success: what people write still parses ─────────────────────────

/// A typical case-insensitive scanner filter parses and matches.
#[test]
fn a_typical_case_insensitive_regex_still_matches() -> Result<(), TestError> {
    assert!(
        matches_scanner("ua =~ '(?i)friendly-scanner'")?,
        "the scanner dialog must match its own User-Agent"
    );
    Ok(())
}

/// Exactly the comparison limit is accepted.
#[test]
fn the_comparison_limit_itself_is_accepted() -> Result<(), TestError> {
    let expr = or_chain("ua =~ 'scanner'", MAX_REGEX_COMPARISONS);
    assert!(
        FilterExpr::parse(&expr).is_ok(),
        "{MAX_REGEX_COMPARISONS} regex comparisons must be accepted"
    );
    Ok(())
}

/// Exactly the byte limit, split over several regexes, is accepted.
#[test]
fn the_pattern_byte_limit_itself_is_accepted() -> Result<(), TestError> {
    let per = MAX_REGEX_PATTERN_BYTES / 4;
    let term = format!("ua =~ '{}'", "a".repeat(per));
    let expr = or_chain(&term, 4);
    assert!(
        FilterExpr::parse(&expr).is_ok(),
        "4 regexes of {per} bytes ({MAX_REGEX_PATTERN_BYTES} in all) must be accepted"
    );
    Ok(())
}

/// Exactly the class limit is accepted, case-insensitive included.
#[test]
fn the_class_limit_itself_is_accepted() -> Result<(), TestError> {
    let expr = format!("ua =~ '(?i){}'", "[a-z]".repeat(MAX_REGEX_CLASSES));
    assert!(
        FilterExpr::parse(&expr).is_ok(),
        "{MAX_REGEX_CLASSES} classes must be accepted"
    );
    Ok(())
}

/// Comparisons that are not regexes spend nothing.
#[test]
fn non_regex_comparisons_do_not_spend_the_budget() -> Result<(), TestError> {
    let mut expr = or_chain("ua == '[\\D]'", 100);
    expr.push_str(" OR ");
    expr.push_str(&or_chain("ua =~ 'x'", MAX_REGEX_COMPARISONS));
    assert!(
        FilterExpr::parse(&expr).is_ok(),
        "100 equality comparisons and {MAX_REGEX_COMPARISONS} regexes must be accepted"
    );
    Ok(())
}

/// A literal bracket written `\[` is not a class.
#[test]
fn an_escaped_bracket_is_not_a_class() -> Result<(), TestError> {
    let expr = format!("ua =~ '{}'", "\\[x\\]".repeat(MAX_REGEX_CLASSES * 2));
    assert!(
        FilterExpr::parse(&expr).is_ok(),
        "escaped brackets are literals and must not count as classes"
    );
    Ok(())
}

/// Two parses in a row each get the whole budget.
#[test]
fn every_parse_starts_with_the_whole_budget() -> Result<(), TestError> {
    let expr = or_chain("ua =~ '[0-9]'", MAX_REGEX_COMPARISONS);
    for round in 0..3 {
        assert!(
            FilterExpr::parse(&expr).is_ok(),
            "parse {round} must see a fresh budget"
        );
    }
    Ok(())
}

/// The costliest expression the budget accepts parses in bounded time.
///
/// Eight comparisons, sixteen case-folded `[\D]` classes and regexes as close
/// to the compiled-size limit as `\w{n}` reaches: every limit spent at once.
#[test]
fn the_costliest_accepted_expression_parses_within_a_bound() -> Result<(), TestError> {
    // The largest repetition of `\w` the term compiles with under the size
    // limit.
    let term = |n: usize| format!("ua =~ '(?i)[\\D][\\D]\\w{{{n}}}'");
    let mut n = 1;
    while n < 64 && FilterExpr::parse(&term(n + 1)).is_ok() {
        n += 1;
    }
    let heavy = term(n);
    assert!(
        FilterExpr::parse(&heavy).is_ok(),
        "the heavy term itself must compile: {heavy}"
    );
    let expr = or_chain(&heavy, MAX_REGEX_COMPARISONS);
    let start = Instant::now();
    let parsed = FilterExpr::parse(&expr);
    let took = start.elapsed();
    assert!(
        parsed.is_ok(),
        "the at-limit expression must be accepted: {parsed:?}"
    );
    assert!(
        took < ACCEPTED_BOUND,
        "the costliest accepted expression took {took:?}"
    );
    Ok(())
}

// ── Failure: each limit, one past it ────────────────────────────────

/// One comparison past the limit is refused, and the message names it.
#[test]
fn one_comparison_past_the_limit_is_refused() -> Result<(), TestError> {
    let expr = or_chain("ua =~ 'scanner'", MAX_REGEX_COMPARISONS + 1);
    let message = parse_err(&expr)?;
    assert!(
        message.contains(&format!("{MAX_REGEX_COMPARISONS} regex comparisons")),
        "the refusal must name the comparison limit, got: {message}"
    );
    Ok(())
}

/// One byte past the limit is refused, and the message names it.
#[test]
fn one_pattern_byte_past_the_limit_is_refused() -> Result<(), TestError> {
    let per = MAX_REGEX_PATTERN_BYTES / 4;
    let mut expr = or_chain(&format!("ua =~ '{}'", "a".repeat(per)), 4);
    expr.push_str(" OR ua =~ 'b'");
    let message = parse_err(&expr)?;
    assert!(
        message.contains(&format!("{MAX_REGEX_PATTERN_BYTES} bytes")),
        "the refusal must name the byte limit, got: {message}"
    );
    Ok(())
}

/// One class past the limit is refused, and the message names it.
#[test]
fn one_class_past_the_limit_is_refused() -> Result<(), TestError> {
    let expr = format!("ua =~ '{}'", "[a-z]".repeat(MAX_REGEX_CLASSES + 1));
    let message = parse_err(&expr)?;
    assert!(
        message.contains(&format!("{MAX_REGEX_CLASSES} character classes")),
        "the refusal must name the class limit, got: {message}"
    );
    Ok(())
}

/// A Unicode class `\pL` counts as a class.
#[test]
fn unicode_classes_count_as_classes() -> Result<(), TestError> {
    let expr = format!("ua =~ '(?i){}'", "\\pL".repeat(MAX_REGEX_CLASSES + 1));
    let message = parse_err(&expr)?;
    assert!(
        message.contains(&format!("{MAX_REGEX_CLASSES} character classes")),
        "17 Unicode classes must be refused, got: {message}"
    );
    Ok(())
}

/// The error points at the value that spent past the budget.
#[test]
fn the_refusal_points_at_the_value_past_the_budget() -> Result<(), TestError> {
    let term = "ua =~ 'scanner'";
    let expr = or_chain(term, MAX_REGEX_COMPARISONS + 1);
    let message = parse_err(&expr)?;
    let last_value = expr.rfind("'scanner'").ok_or("value present")?;
    assert_eq!(
        position(&message)?,
        last_value,
        "the caret must sit on the ninth value, got: {message}"
    );
    Ok(())
}

/// A pattern that does not compile is still reported as such, not as budget.
#[test]
fn an_invalid_regex_within_budget_is_still_reported_as_invalid() -> Result<(), TestError> {
    let message = parse_err("ua =~ '(unclosed'")?;
    assert!(
        message.contains("does not compile"),
        "an invalid pattern must keep its own message, got: {message}"
    );
    Ok(())
}

// ── Edge: where the budget is counted ───────────────────────────────

/// The budget spans the whole expression: AND, NOT and parentheses included.
#[test]
fn the_budget_spans_and_not_and_groups() -> Result<(), TestError> {
    let expr = "(ua =~ 'a' AND ua =~ 'b') OR NOT (ua =~ 'c' OR (ua =~ 'd' AND ua =~ 'e')) \
                OR ua =~ 'f' OR ua =~ 'g' OR NOT ua =~ 'h' OR ua =~ 'i'";
    let message = parse_err(expr)?;
    assert!(
        message.contains(&format!("{MAX_REGEX_COMPARISONS} regex comparisons")),
        "nine regexes spread over groups must be refused, got: {message}"
    );
    Ok(())
}

/// `payload =~` (the byte-oriented engine) spends the same budget.
#[test]
fn payload_regexes_spend_the_same_budget() -> Result<(), TestError> {
    let mut expr = or_chain("payload =~ 'INVITE'", MAX_REGEX_COMPARISONS);
    expr.push_str(" OR ua =~ 'x'");
    let message = parse_err(&expr)?;
    assert!(
        message.contains(&format!("{MAX_REGEX_COMPARISONS} regex comparisons")),
        "payload and ua regexes share one budget, got: {message}"
    );
    Ok(())
}

/// Classes are counted across regexes, not per regex.
#[test]
fn classes_are_counted_across_regexes() -> Result<(), TestError> {
    let term = format!("ua =~ '{}'", "[0-9]".repeat(MAX_REGEX_CLASSES / 2));
    let mut expr = or_chain(&term, 2);
    expr.push_str(" OR ua =~ '[x]'");
    let message = parse_err(&expr)?;
    assert!(
        message.contains(&format!("{MAX_REGEX_CLASSES} character classes")),
        "17 classes over three regexes must be refused, got: {message}"
    );
    Ok(())
}

/// A nested class costs one fold per bracket, so each `[` counts.
#[test]
fn a_nested_bracket_counts_once_per_bracket() -> Result<(), TestError> {
    let nested = format!("ua =~ '{}a{}'", "[".repeat(9), "]".repeat(9));
    let mut expr = nested.clone();
    expr.push_str(" OR ");
    expr.push_str(&nested);
    let message = parse_err(&expr)?;
    assert!(
        message.contains(&format!("{MAX_REGEX_CLASSES} character classes")),
        "18 nested brackets must be refused, got: {message}"
    );
    Ok(())
}

/// A bare (unquoted) regex value spends the budget too.
#[test]
fn a_bare_regex_value_spends_the_budget() -> Result<(), TestError> {
    let expr = format!("ua =~ (?i){}", "[\\D]".repeat(MAX_REGEX_CLASSES + 1));
    let message = parse_err(&expr)?;
    assert!(
        message.contains(&format!("{MAX_REGEX_CLASSES} character classes")),
        "a bare value must be counted like a quoted one, got: {message}"
    );
    Ok(())
}

/// A quoted value is counted after its escapes are read: `\'` is one byte.
#[test]
fn bytes_are_counted_on_the_pattern_not_the_quoted_text() -> Result<(), TestError> {
    // 512 escaped quotes are 1024 bytes of text and 512 bytes of pattern.
    let half = "\\'".repeat(MAX_REGEX_PATTERN_BYTES / 2);
    let expr = format!(
        "ua =~ '{half}' OR ua =~ '{}'",
        "a".repeat(MAX_REGEX_PATTERN_BYTES / 2)
    );
    assert!(
        FilterExpr::parse(&expr).is_ok(),
        "1024 bytes of pattern must be accepted although the text is longer"
    );
    Ok(())
}
