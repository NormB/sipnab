// SPDX-License-Identifier: MIT OR Apache-2.0

//! Filter DSL size bounds (VAL1).
//!
//! `MAX_NESTING_DEPTH` counts parentheses, and parentheses are not what makes
//! a parse tree deep. `state == 'Completed' or state == 'Completed' or …`
//! carries no parenthesis at all and still allocates one `Or` node per term,
//! left-associated, so the tree is exactly as deep as the chain is long. Every
//! recursive walk of that tree then has one stack frame per term.
//!
//! Measured on the 0.5.130 debug build before the fix (2026-08-28):
//!
//! - A 4,633-term chain evaluated; a 4,634-term chain aborted the process with
//!   `fatal runtime error: stack overflow` while *evaluating* against dialogs.
//!   The same expression against a capture holding no dialogs survived, which
//!   is what placed the overflow in the evaluator rather than the parser.
//! - A 17,901-term chain that was *rejected for trailing input* — parsed into
//!   a tree, never evaluated — returned an error; at 17,902 terms the process
//!   aborted while **freeing** that tree, because the compiler's drop glue
//!   walks a tree the way it is shaped. So a size cap alone could not fix
//!   this: refusing an oversized expression means dropping it first.
//!
//! Both paths are asserted here, along with the two things a bound like this
//! gets wrong in the other direction: rejecting expressions people actually
//! write, and reporting "too big" in a way the caller cannot tell apart from
//! "malformed".

use std::net::{IpAddr, Ipv4Addr};

use chrono::{TimeZone, Utc};

use sipnab::net::TransportProto;
use sipnab::rtp::diagnosis::CaptureMedia;
use sipnab::rtp::quality::MosDelay;
use sipnab::sip::dialog::SipDialog;
use sipnab::sip::dsl::{AliasThresholds, FilterExpr, expand_alias};
use sipnab::sip::parser::parse_sip;

/// The node cap `sip::dsl` enforces, mirrored here because the constant
/// itself is private.
///
/// Not a duplicated magic number: `size_error_names_the_limit_and_the_size`
/// asserts the parser's own message carries exactly this figure, so moving
/// the constant without moving this one fails that test.
const MAX_EXPRESSION_NODES: usize = 1024;

/// Terms in the largest chain that still fits under the cap.
///
/// An `n`-term chain is `n` leaves joined by `n - 1` combinators, so it costs
/// `2n - 1` nodes. 512 terms is 1023 nodes, one under the cap; 513 is 1025,
/// one over. There is no chain of exactly 1024 nodes — `2n - 1` is always odd
/// — which is why `expression_exactly_at_the_cap_is_accepted` reaches the
/// even figure with a `NOT`.
const TERMS_UNDER_CAP: usize = MAX_EXPRESSION_NODES / 2;

/// Terms in the smallest chain that exceeds it — 513 terms, 1025 nodes.
const TERMS_OVER_CAP: usize = TERMS_UNDER_CAP + 1;

/// Chain length used for the reported P0 and its `and`/mixed variants.
const P0_TERMS: usize = 12_000;

/// Chain length for the drop-path tests.
///
/// Comfortably past the 17,902 terms measured to abort while freeing a
/// rejected tree, so the test fails the way the defect did rather than
/// landing in the margin.
const DROP_TERMS: usize = 100_000;

// ── Helpers ─────────────────────────────────────────────────────────

/// Fixed endpoint address (10.0.0.1) for the sample message.
fn ip() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
}

/// Fixed deterministic timestamp (2024-06-15 12:00:00 UTC).
fn ts() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2024, 6, 15, 12, 0, 0)
        .single()
        .expect("unambiguous fixed timestamp")
}

/// A concrete dialog to evaluate against: `from.user` is `1001`.
fn sample_dialog() -> SipDialog {
    let raw = b"INVITE sip:2002@example.com SIP/2.0\r\n\
        Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKdepth\r\n\
        From: <sip:1001@example.com>;tag=t1\r\n\
        To: <sip:2002@example.com>\r\n\
        Call-ID: depth@example.com\r\n\
        CSeq: 1 INVITE\r\n\
        Content-Length: 0\r\n\r\n";
    let msg = parse_sip(raw, ts(), ip(), ip(), 5060, 5060, TransportProto::Udp)
        .expect("fixed INVITE parses");
    SipDialog::new(&msg).expect("dialog from INVITE")
}

/// Evaluate `filter` against [`sample_dialog`] with no RTP.
fn matches_sample(filter: &FilterExpr) -> bool {
    filter.matches_dialog(
        &sample_dialog(),
        &[],
        CaptureMedia::Absent,
        MosDelay::unknown(),
    )
}

/// An `n`-term chain of `term` joined by `joiner`.
fn chain(term: &str, joiner: &str, n: usize) -> String {
    vec![term; n].join(joiner)
}

/// The parse error for `expr`, or a panic naming what was accepted instead.
fn parse_err(expr: &str) -> String {
    match FilterExpr::parse(expr) {
        Ok(_) => panic!("expression of {} bytes was accepted", expr.len()),
        Err(e) => e.to_string(),
    }
}

// ── The P0: flat chains ─────────────────────────────────────────────

/// A 12,000-term `or` chain — the reported P0 — is refused with an error
/// instead of aborting the process.
///
/// Reaching the assertion at all is half the result: before the fix this
/// killed the whole test binary with `fatal runtime error: stack overflow`,
/// because the tree survived parsing and overflowed in the evaluator.
#[test]
fn or_chain_of_twelve_thousand_terms_is_refused_not_fatal() {
    let expr = chain("state == 'Completed'", " or ", P0_TERMS);
    let err = parse_err(&expr);
    assert!(
        err.contains("exceeds maximum size"),
        "expected the size error, got: {err}"
    );
    // 12,000 leaves + 11,999 `Or` nodes.
    assert!(
        err.contains("23999"),
        "error must report the observed size, got: {err}"
    );
}

/// The same for `and`, which builds the identical shape through the other
/// combinator loop in the parser.
#[test]
fn and_chain_of_twelve_thousand_terms_is_refused_not_fatal() {
    let expr = chain("state == 'Completed'", " and ", P0_TERMS);
    let err = parse_err(&expr);
    assert!(
        err.contains("exceeds maximum size"),
        "expected the size error, got: {err}"
    );
    assert!(
        err.contains("23999"),
        "error must report the observed size, got: {err}"
    );
}

/// A mixed `and`/`or` chain: `AND` binds tighter, so this nests the two
/// loops inside each other rather than exercising either alone.
#[test]
fn mixed_and_or_chain_of_twelve_thousand_terms_is_refused_not_fatal() {
    let mut parts: Vec<String> = Vec::with_capacity(P0_TERMS);
    for i in 0..P0_TERMS {
        let joiner = if i % 2 == 0 { " and " } else { " or " };
        if i > 0 {
            parts.push(joiner.to_string());
        }
        parts.push("state == 'Completed'".to_string());
    }
    let err = parse_err(&parts.concat());
    assert!(
        err.contains("exceeds maximum size"),
        "expected the size error, got: {err}"
    );
}

// ── No regression: the parenthesis guard ────────────────────────────

/// 5,000 nested parentheses still hit the existing depth guard, with the
/// existing message. The size cap is a sibling of that check, not a
/// replacement for it: parens recurse *in the parser*, before any tree
/// exists to count.
#[test]
fn five_thousand_nested_parens_still_hit_the_paren_depth_guard() {
    let expr = format!(
        "{}state == 'Completed'{}",
        "(".repeat(5_000),
        ")".repeat(5_000)
    );
    let err = parse_err(&expr);
    assert!(
        err.contains("exceeds maximum nesting depth of 50"),
        "the paren guard must still fire with its own message, got: {err}"
    );
    assert!(
        !err.contains("exceeds maximum size"),
        "a paren-depth refusal must not be reported as an oversize one: {err}"
    );
}

/// And nesting *within* the paren limit still parses, so the guard above is
/// rejecting depth rather than parentheses as such.
#[test]
fn nesting_within_the_paren_limit_still_parses() {
    let expr = format!("{}state == 'Completed'{}", "(".repeat(50), ")".repeat(50));
    let filter = FilterExpr::parse(&expr).expect("50 levels is the documented limit, not one over");
    assert!(
        !matches_sample(&filter),
        "the sample dialog is not Completed"
    );
}

// ── The boundary, from both sides ───────────────────────────────────

/// An expression one node under the cap is accepted **and evaluates
/// correctly** — a limit that quietly rejects real filters, or accepts them
/// and returns the wrong answer, is a worse defect than the abort.
///
/// The matching term is last, so a `true` result can only come from walking
/// the whole 512-deep left spine first.
#[test]
fn expression_one_node_under_the_cap_is_accepted_and_evaluates() {
    let mut terms: Vec<String> = (0..TERMS_UNDER_CAP - 1)
        .map(|i| format!("from.user == 'no{i}'"))
        .collect();
    terms.push("from.user == '1001'".to_string());
    let filter = FilterExpr::parse(&terms.join(" OR ")).expect("1023 nodes is under the cap");
    assert!(
        matches_sample(&filter),
        "the last term matches from.user 1001"
    );

    // The same shape with nothing matching must evaluate to false, not to
    // "true because something short-circuited".
    let none: Vec<String> = (0..TERMS_UNDER_CAP)
        .map(|i| format!("from.user == 'no{i}'"))
        .collect();
    let filter = FilterExpr::parse(&none.join(" OR ")).expect("1023 nodes is under the cap");
    assert!(!matches_sample(&filter), "no term matches from.user 1001");
}

/// An expression of exactly `MAX_EXPRESSION_NODES` nodes is accepted: the
/// cap is inclusive, so the documented figure is reachable.
///
/// `NOT (…)` adds the one node a chain cannot, because `2n - 1` is always
/// odd and the cap is even.
#[test]
fn expression_exactly_at_the_cap_is_accepted() {
    let inner = chain("from.user == '1001'", " OR ", TERMS_UNDER_CAP);
    let filter =
        FilterExpr::parse(&format!("NOT ({inner})")).expect("exactly 1024 nodes must be accepted");
    assert!(!matches_sample(&filter), "NOT of a matching chain is false");
}

/// One node over the cap is refused, and the message says so.
#[test]
fn expression_one_node_over_the_cap_is_refused() {
    let expr = chain("from.user == '1001'", " OR ", TERMS_OVER_CAP);
    let err = parse_err(&expr);
    assert!(
        err.contains("exceeds maximum size"),
        "expected the size error, got: {err}"
    );
    assert!(
        err.contains("1025"),
        "error must report the observed size (1025), got: {err}"
    );
}

// ── The error a caller has to act on ────────────────────────────────

/// The refusal names both the limit and what was measured, so a caller can
/// tell how far over it went rather than guessing.
#[test]
fn size_error_names_the_limit_and_the_size() {
    let err = parse_err(&chain("state == 'Completed'", " OR ", TERMS_OVER_CAP));
    assert!(
        err.contains(&MAX_EXPRESSION_NODES.to_string()),
        "error must name the limit {MAX_EXPRESSION_NODES}, got: {err}"
    );
    assert!(
        err.contains("1025"),
        "error must name the observed size, got: {err}"
    );
}

/// "Your filter is too big" and "your filter is malformed" are distinct
/// errors. A caller that retries a truncated expression on a syntax error,
/// or gives up on a size error, must not confuse the two.
#[test]
fn size_error_is_distinguishable_from_a_syntax_error() {
    let oversize = parse_err(&chain("state == 'Completed'", " OR ", TERMS_OVER_CAP));
    let syntax = parse_err("from.user ==");
    let unknown_field = parse_err("no_such_field == 'x'");
    let empty = parse_err("   ");

    assert!(oversize.contains("exceeds maximum size"));
    for (label, err) in [
        ("syntax", &syntax),
        ("unknown field", &unknown_field),
        ("empty", &empty),
    ] {
        assert!(
            !err.contains("exceeds maximum size"),
            "a {label} error must not read as an oversize one: {err}"
        );
    }
    assert!(
        !oversize.contains("unexpected"),
        "an oversize error must not read as a syntax one: {oversize}"
    );
}

// ── The drop path ───────────────────────────────────────────────────

/// Building and dropping accepted at-cap expressions repeatedly does not
/// overflow: the destructor is exercised on a real tree, many times, so a
/// per-node cost or a stack cost in `Drop` shows up here.
#[test]
fn dropping_accepted_at_cap_expressions_does_not_overflow() {
    for _ in 0..64 {
        let inner = chain("from.user == '1001'", " OR ", TERMS_UNDER_CAP);
        let filter = FilterExpr::parse(&format!("NOT ({inner})")).expect("at-cap parses");
        drop(filter);
    }
}

/// A 100,000-term chain is refused — and the refusal itself does not abort.
///
/// This is the second, independent overflow: `parse` must build the tree
/// before it can count it, so refusing an oversized expression means
/// **freeing** an oversized tree. Before the iterative destructor, the
/// compiler's drop glue recursed once per level and aborted here at 17,902
/// terms, with no evaluation involved at all.
#[test]
fn dropping_a_refused_oversized_tree_does_not_overflow() {
    let err = parse_err(&chain("state == 'Completed'", " OR ", DROP_TERMS));
    assert!(
        err.contains("exceeds maximum size"),
        "expected the size error, got: {err}"
    );
    // 100,000 leaves + 99,999 combinators.
    assert!(
        err.contains("199999"),
        "error must report the observed size, got: {err}"
    );
}

/// The same size, refused for *syntax* instead — the exact shape that
/// aborted before, since the tree is built and then thrown away without the
/// node cap ever being consulted.
#[test]
fn dropping_a_syntactically_refused_oversized_tree_does_not_overflow() {
    let expr = format!("{} zzz", chain("state == 'Completed'", " OR ", DROP_TERMS));
    let err = parse_err(&expr);
    assert!(
        err.contains("unexpected trailing input"),
        "a malformed tail must still be reported as malformed, got: {err}"
    );
}

// ── Nothing real got caught in the net ──────────────────────────────

/// Every filter expression printed in the documentation still parses, and
/// every one of them is far under the cap.
///
/// Harvested rather than transcribed, so a filter added to the docs is
/// covered without anyone remembering to add it here.
///
/// `docs/design/` and `docs/research/` are excluded: they are planning
/// material, and a plan quotes fields as it proposed them rather than as they
/// shipped. `implementation-plan-v6.md` still shows
/// `--filter "rtp.orphaned == true …"`, and `rtp.orphaned` was deliberately
/// withdrawn — `docs/filter-dsl.md` documents it as a parse error and
/// `src/sip/dsl.rs` has a unit test holding it to that.
#[test]
fn every_documented_filter_expression_still_parses() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files: Vec<std::path::PathBuf> = vec![root.join("README.md")];
    collect_markdown(&root.join("docs"), &mut files);
    files.retain(|p| {
        let s = p.to_string_lossy().replace('\\', "/");
        !s.contains("/docs/design/") && !s.contains("/docs/research/")
    });
    files.sort();

    let mut checked = 0usize;
    let mut widest = (0usize, String::new());
    for path in &files {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        for expr in harvest_filters(&text) {
            let filter = FilterExpr::parse(&expr).unwrap_or_else(|e| {
                panic!(
                    "documented filter in {} fails to parse: {expr:?}: {e}",
                    path.display()
                )
            });
            // It must also *evaluate* — the size cap must not have made a
            // documented filter parse-only.
            let _ = matches_sample(&filter);
            checked += 1;
            let terms = expr.split(" AND ").count() + expr.split(" OR ").count();
            if terms > widest.0 {
                widest = (terms, expr.clone());
            }
        }
    }
    assert!(
        checked >= 40,
        "expected the docs to yield the 43 distinct filter expressions they carry, found \
         {checked} — the harvest, not the DSL, is what broke"
    );
    assert!(
        widest.0 < 16,
        "a documented filter grew past what this bound was sized for: {widest:?}"
    );
}

/// Every diagnostic alias expands to something that parses and fits, with
/// room to spare.
///
/// These are the largest expressions sipnab itself constructs, and the
/// figure the cap is justified against — see the constant's own note in
/// `src/sip/dsl.rs`, whose node counts are pinned by a unit test there.
#[test]
fn every_diagnostic_alias_expansion_parses_and_fits() {
    let thresholds = AliasThresholds::default();
    let aliases = [
        "problems",
        "slow-setup",
        "short-calls",
        "one-way",
        "nat-issues",
        "codec-asym",
        "ptime-asym",
        "payload-asym",
        "duration-asym",
        "late-media",
    ];
    let mut parts = Vec::new();
    for alias in aliases {
        let expansion =
            expand_alias(alias, &thresholds).unwrap_or_else(|| panic!("{alias} is a known alias"));
        let filter = FilterExpr::parse(&expansion)
            .unwrap_or_else(|e| panic!("alias {alias} expands to unparsable DSL: {e}"));
        let _ = matches_sample(&filter);
        parts.push(format!("({expansion})"));
    }
    // And every one of them at once, the way `build_filter_expr` joins the
    // alias flags — the widest expression the product can hand the parser.
    let combined = parts.join(" OR ");
    let filter = FilterExpr::parse(&combined)
        .unwrap_or_else(|e| panic!("all aliases at once must parse: {e}"));
    let _ = matches_sample(&filter);
}

// ── Harvest helpers ─────────────────────────────────────────────────

/// Push every `.md` file under `dir` onto `out`, recursively.
fn collect_markdown(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_markdown(&path, out);
        } else if path.extension().is_some_and(|e| e == "md") {
            out.push(path);
        }
    }
}

/// Every double-quoted `--filter` argument and `expression = ` value in
/// `text`.
///
/// Single-token values are alias names rather than DSL, and are skipped:
/// `--filter codec-asym` resolves through `expand_alias`, which
/// `every_diagnostic_alias_expansion_parses_and_fits` covers.
fn harvest_filters(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for prefix in ["--filter \"", "expression = \""] {
        let mut rest = text;
        while let Some(start) = rest.find(prefix) {
            rest = &rest[start + prefix.len()..];
            let Some(end) = rest.find('"') else { break };
            let candidate = &rest[..end];
            rest = &rest[end..];
            if candidate.contains(' ') {
                out.push(candidate.to_string());
            }
        }
    }
    out
}
