// SPDX-License-Identifier: MIT OR Apache-2.0

//! Cross-surface parity: a quality metric must be reachable from EVERY
//! consumer surface, or from none of them.
//!
//! sipnab exposes the same analysis through MCP, the REST API and the TUI. Work
//! has concentrated on MCP, and a metric that exists on one surface and not the
//! others is a metric whose availability depends on which door a user came
//! through.
//!
//! The drift this was written for is real and was measured, not imagined:
//! `round_trip_delay` is parsed out of the RTCP XR VoIP-metrics block
//! (`src/rtp/rtcp.rs`) and reaches no surface at all — so of the three numbers
//! that decide whether a call was acceptable (jitter, loss, latency), two are
//! first-class and the third stops at the parser.
//!
//! WHY SYMMETRY RATHER THAN PRESENCE. Asserting "every metric must be exposed"
//! would fail today for latency, which is not implemented yet, and a gate that
//! cannot pass gets deleted or muted. Asserting SYMMETRY costs nothing while a
//! metric is absent everywhere, and fails the moment one surface gains it
//! alone — which is precisely when the drift starts and precisely when it is
//! cheap to fix.

use std::collections::BTreeMap;
use std::path::Path;

fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// Source text of a file or a whole directory, with comments removed.
///
/// Comments must go, and the reason is a false positive this gate hit while
/// being written: searching for `rtt` matched `fn cursor_round_trips()` and a
/// comment reading "round_trip holds it to that contract", which would have
/// reported latency as present on a surface that has never exposed it. A gate
/// that reads prose is a gate that agrees with whatever the prose says.
fn code(rel: &str) -> String {
    let root = repo().join(rel);
    let mut files = Vec::new();
    if root.is_dir() {
        let mut stack = vec![root];
        while let Some(dir) = stack.pop() {
            for e in std::fs::read_dir(&dir).expect("read_dir").flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.extension().and_then(|s| s.to_str()) == Some("rs") {
                    files.push(p);
                }
            }
        }
    } else {
        files.push(root);
    }
    let mut out = String::new();
    for f in files {
        for line in std::fs::read_to_string(&f).expect("read").lines() {
            let t = line.trim_start();
            if t.starts_with("//") {
                continue;
            }
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// Does `hay` use `needle` as a whole identifier?
fn uses(hay: &str, needle: &str) -> bool {
    hay.match_indices(needle).any(|(i, _)| {
        let before = hay[..i].chars().next_back();
        let after = hay[i + needle.len()..].chars().next();
        let boundary = |c: Option<char>| !matches!(c, Some(c) if c.is_alphanumeric() || c == '_');
        boundary(before) && boundary(after)
    })
}

/// The metrics that decide whether a call was acceptable, plus the analyses
/// that explain them. Named explicitly because this IS the domain — it is not
/// a list of what happens to be implemented, and an entry absent everywhere is
/// a legitimate state.
const QUALITY_METRICS: &[&str] = &[
    "jitter",
    "loss_pct",
    "mos",
    "round_trip_delay",
    "burst_gap",
    "dtmf",
];

/// Every metric must be reachable from MCP and from the REST API, or from
/// neither. One surface alone is drift.
#[test]
fn every_quality_metric_is_on_both_mcp_and_the_rest_api() {
    let mcp = code("src/mcp");
    let api = code("src/output/api.rs");

    let mut asymmetric = Vec::new();
    let mut both = 0usize;
    let mut seen: BTreeMap<&str, (bool, bool)> = BTreeMap::new();

    for m in QUALITY_METRICS {
        let in_mcp = uses(&mcp, m);
        let in_api = uses(&api, m);
        seen.insert(m, (in_mcp, in_api));
        match (in_mcp, in_api) {
            (true, true) => both += 1,
            (false, false) => {}
            (true, false) => asymmetric.push(format!("`{m}` is on MCP but NOT the REST API")),
            (false, true) => asymmetric.push(format!("`{m}` is on the REST API but NOT MCP")),
        }
    }

    // A scanner that matched nothing would report perfect parity. Two metrics
    // are known to be on both surfaces today; fewer means the reader broke.
    assert!(
        both >= 2,
        "only {both} metrics were found on both surfaces — the source scan or \
         the identifier match stopped working, so this gate is comparing \
         nothing: {seen:?}"
    );

    assert!(
        asymmetric.is_empty(),
        "quality metrics exposed on one surface but not the other:\n  {}\n\n\
         sipnab serves the same analysis through MCP, REST and the TUI. A \
         metric on one surface only means its availability depends on which \
         door the user came through. Add it to the missing surface, or remove \
         it from the one that has it — the response shapes are cheap to change \
         before 1.0 and expensive after.",
        asymmetric.join("\n  ")
    );
}

/// The TUI is held to REACHABILITY, not to the same shape.
///
/// A terminal has finite columns and deliberately shows a subset — the address
/// columns are 11 cells at the demo geometry, which is why they elide. Holding
/// the TUI to every field would either fail permanently or force a bad layout.
/// What matters is that a metric the other surfaces report can be SEEN
/// somewhere in the interface, not that it is on the summary row.
#[test]
fn metrics_the_apis_report_are_reachable_in_the_tui() {
    let mcp = code("src/mcp");
    let api = code("src/output/api.rs");
    let tui = code("src/tui");

    let mut missing = Vec::new();
    let mut checked = 0usize;
    for m in QUALITY_METRICS {
        if uses(&mcp, m) && uses(&api, m) {
            checked += 1;
            if !uses(&tui, m) {
                missing.push(*m);
            }
        }
    }

    assert!(
        checked >= 2,
        "only {checked} metrics were on both APIs, so this gate asserted almost \
         nothing about the TUI"
    );
    assert!(
        missing.is_empty(),
        "these metrics are served by BOTH APIs and appear nowhere in the TUI: \
         {missing:?}\n\nSomeone reading the terminal cannot see what an agent \
         and an HTTP client both can."
    );
}
