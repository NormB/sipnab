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

#[path = "support/source_scan.rs"]
mod source_scan;

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
///
/// `#[cfg(test)]` modules go for the same reason, one level up, and this was
/// measured too. Deleting the TUI's whole DSCP row left this gate GREEN,
/// because two `#[cfg(test)]` fixtures in `src/tui` construct a `ParsedPacket`
/// and name its `dscp` field while setting it to `None`. A gate that reads
/// test code is a gate that agrees with whatever the tests happen to build —
/// and it would have reported a metric as reachable in an interface that had
/// stopped drawing it, which is the exact drift this file exists to catch.
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
        // Depth of the `#[cfg(test)]` module currently being skipped, counted
        // in braces. `None` while reading real code. Brace counting is crude
        // and cannot see a `{` inside a string literal — which is why it is
        // used to SKIP rather than to select: the worst a miscount can do here
        // is drop a few extra lines, and the vacuity floors below
        // (`both >= 2`, `checked >= 2`) fail loudly if it ever drops enough to
        // matter.
        let mut skipping: Option<i32> = None;
        let mut pending_test_mod = false;
        for line in std::fs::read_to_string(&f).expect("read").lines() {
            let t = line.trim_start();
            if let Some(depth) = skipping.as_mut() {
                *depth += i32::try_from(line.matches('{').count()).unwrap_or(0);
                *depth -= i32::try_from(line.matches('}').count()).unwrap_or(0);
                if *depth <= 0 {
                    skipping = None;
                }
                continue;
            }
            if t.starts_with("//") {
                continue;
            }
            if pending_test_mod {
                let opens = i32::try_from(line.matches('{').count()).unwrap_or(0);
                let closes = i32::try_from(line.matches('}').count()).unwrap_or(0);
                if opens > 0 {
                    pending_test_mod = false;
                    if opens - closes > 0 {
                        skipping = Some(opens - closes);
                    }
                    continue;
                }
                // Still between the attribute and the `mod … {` it guards.
                continue;
            }
            if t.starts_with("#[cfg(test)]") {
                pending_test_mod = true;
                continue;
            }
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// The REST API's exposed surface: its handlers PLUS the shared projection
/// they serialise through.
///
/// `api.rs` deliberately names almost no field. It builds its stream and dialog
/// responses out of `crate::output::model::{StreamSummary, DialogSummary}` —
/// its own comment says it projects through the canonical model "so this
/// endpoint cannot drift from the CLI/MCP surfaces". Reading `api.rs` alone
/// therefore reports a metric as ABSENT from REST at the exact moment the
/// shared projection is doing its job, which is the reverse of the truth.
///
/// This bit: adding `round_trip_ms` to `StreamSummary` put latency on REST and
/// MCP in the same commit, and a gate scoped to `api.rs` alone called that
/// asymmetric drift. The scan looks for a metric's name, so the scope has to be
/// every file where the surface's shape is decided.
///
/// `src/output/json.rs` is in scope for the same reason and was missing:
/// `GET /v1/streams/{{ssrc}}` renders through `output::json::stream_to_json`,
/// so `burst_gap` has always been on REST while a scan of `api.rs` +
/// `model.rs` could not see it.
fn rest_surface() -> String {
    format!(
        "{}\n{}\n{}",
        code("src/output/api.rs"),
        code("src/output/model.rs"),
        code("src/output/json.rs")
    )
}

/// The MCP surface's exposed shape: its tools PLUS the shared stream renderer
/// they serialise through.
///
/// The same lesson as [`rest_surface`], learned the same way and by the same
/// file. `src/mcp` named `loss_pct` only inside its own copy of "derive the
/// loss percentage, then score a MOS"; the moment that copy was replaced by a
/// call to the canonical scorer, a scan scoped to `src/mcp` reported loss as
/// ABSENT from MCP — at the exact moment the sharing was doing its job, and
/// while `rtp_stats` was serving the field unchanged through
/// `crate::output::json::stream_to_json`.
///
/// A gate that reads a surface's own file cannot see a surface that delegates.
/// Both surfaces here delegate, to the same renderer, so both scans include it.
fn mcp_surface() -> String {
    format!("{}\n{}", code("src/mcp"), code("src/output/json.rs"))
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
const QUALITY_METRICS: &[Metric] = &[
    Metric::named("jitter"),
    Metric::named("loss_pct"),
    Metric::named("mos"),
    // Latency needs an alias list where the others do not, because it is the
    // one metric no surface can name the same way twice. `round_trip_delay` is
    // the XR wire field; `round_trip_ms` is the resolved figure MCP and REST
    // serialise; `round_trip_for` is the store accessor the TUI renders
    // through, since a terminal shows a value rather than a JSON key.
    //
    // Tracking one spelling made this gate wrong in both directions on the
    // same change: watching only `round_trip_delay`, it reported perfect parity
    // while MCP and REST gained the resolved figure; watching only
    // `round_trip_ms`, it reported the TUI as missing a value that is on screen.
    Metric {
        name: "round_trip",
        aliases: &["round_trip_delay", "round_trip_ms", "round_trip_for"],
    },
    // Burst/gap needs one for the same reason latency does: `burst_gap` is the
    // JSON key both APIs serialise, and `burst_gap_analysis` is the accessor
    // the TUI's loss map renders through — a terminal shows "Bursty / 3 bursts
    // / avg 60ms", not a key. Whole-identifier matching does not see one in the
    // other, so tracking the key alone reported the analysis as unreachable in
    // an interface that has drawn it since the loss map existed.
    Metric {
        name: "burst_gap",
        aliases: &["burst_gap_analysis"],
    },
    Metric::named("dtmf"),
    // QoS marking. Tracked here DELIBERATELY rather than left off the list:
    // it is one of the numbers that decides whether a call was acceptable —
    // unmarked media on a congested link is jitter no amount of bandwidth
    // fixes — so a surface that reports jitter without saying which queue the
    // packets were in is reporting the symptom and withholding the cause.
    //
    // It needs an alias list for the same reason latency does. `dscp` is the
    // JSON key both APIs serialise; the stream carries the pair
    // `dscp_first`/`dscp_last` because a re-marking is the finding and
    // overwriting the original would hide it; and the TUI renders through
    // those and through `dscp_remarked`, since a terminal shows "46 (EF)"
    // rather than a key. Whole-identifier matching sees none of those in
    // `dscp`, so tracking the key alone would report the marking as
    // unreachable in an interface that draws it.
    Metric {
        name: "dscp",
        aliases: &["dscp_first", "dscp_last", "dscp_remarked"],
    },
];

/// A quality metric and every identifier that carries it.
///
/// Most metrics are spelled the same everywhere, so `aliases` is usually just
/// the name. A metric is present on a surface when ANY of its spellings is.
struct Metric {
    name: &'static str,
    aliases: &'static [&'static str],
}

impl Metric {
    const fn named(name: &'static str) -> Self {
        Self { name, aliases: &[] }
    }

    /// Is this metric carried anywhere in `hay`?
    fn carried_by(&self, hay: &str) -> bool {
        uses(hay, self.name) || self.aliases.iter().any(|a| uses(hay, a))
    }
}

/// Every metric must be reachable from MCP and from the REST API, or from
/// neither. One surface alone is drift.
#[test]
fn every_quality_metric_is_on_both_mcp_and_the_rest_api() {
    let mcp = mcp_surface();
    let api = rest_surface();

    let mut asymmetric = Vec::new();
    let mut both = 0usize;
    let mut seen: BTreeMap<&str, (bool, bool)> = BTreeMap::new();

    for m in QUALITY_METRICS {
        let in_mcp = m.carried_by(&mcp);
        let in_api = m.carried_by(&api);
        seen.insert(m.name, (in_mcp, in_api));
        match (in_mcp, in_api) {
            (true, true) => both += 1,
            (false, false) => {}
            (true, false) => {
                asymmetric.push(format!("`{}` is on MCP but NOT the REST API", m.name))
            }
            (false, true) => {
                asymmetric.push(format!("`{}` is on the REST API but NOT MCP", m.name))
            }
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
    let mcp = mcp_surface();
    let api = rest_surface();
    let tui = code("src/tui");

    let mut missing = Vec::new();
    let mut checked = 0usize;
    for m in QUALITY_METRICS {
        if m.carried_by(&mcp) && m.carried_by(&api) {
            checked += 1;
            if !m.carried_by(&tui) {
                missing.push(m.name);
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

/// Only ONE piece of code turns network conditions into a MOS.
///
/// `rtp.mos` in the filter DSL once carried its own scorer — `R = 93.2 -
/// min(jitter,100) - 2.5*loss_pct`, no codec term, no delay term — while the
/// detail view used the G.107 E-model. Identical streams scored up to 1.7 MOS
/// apart, so `--filter "rtp.mos < 3.0"` selected calls the detail view showed
/// as fine. Behavioural tests now pin the two together, but nothing stopped a
/// THIRD scorer appearing beside them, which is how the second one arrived.
///
/// So this reads the source rather than the behaviour: the E-model's R0
/// anchor may appear only where the model itself lives.
#[test]
fn only_one_place_in_the_tree_scores_a_mos() {
    // src/rtp/quality.rs        — the narrowband E-model, the one scorer.
    // src/rtp/emodel_wb.rs      — G.107.1 wideband. A DIFFERENT model on a
    //                             different scale (anchored at 129, not 93.2),
    //                             for codecs G.113 publishes Ie,WB for. It
    //                             mentions 93.2 only to say it is not that.
    const HOMES: [&str; 2] = ["src/rtp/quality.rs", "src/rtp/emodel_wb.rs"];

    let mut strays = Vec::new();
    let mut anchors_seen = 0usize;
    let mut stack = vec![repo().join("src")];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir).expect("read_dir").flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            if p.extension().and_then(|s| s.to_str()) != Some("rs") {
                continue;
            }
            let rel = p
                .strip_prefix(repo())
                .expect("under repo")
                .to_string_lossy()
                .replace('\\', "/");
            let text = std::fs::read_to_string(&p).expect("read");
            for (i, line) in text.lines().enumerate() {
                // Comments may DISCUSS the constant — the fix for this very
                // defect explains the old formula in prose, and a gate that
                // forbade saying "93.2" would forbid explaining the bug.
                let code = line.trim_start();
                if code.starts_with("//") || !code.contains("93.2") {
                    continue;
                }
                anchors_seen += 1;
                if !HOMES.contains(&rel.as_str()) {
                    strays.push(format!("{rel}:{}: {}", i + 1, line.trim()));
                }
            }
        }
    }

    assert!(
        anchors_seen >= 1,
        "the E-model's R0 anchor was found nowhere in src/ — the scan broke, \
         so this gate is checking nothing"
    );
    assert!(
        strays.is_empty(),
        "a second MOS scorer has appeared outside {HOMES:?}:\n  {}\n\n\
         Call crate::rtp::quality::estimate_mos instead. Two scorers means two \
         answers for one stream, and the operator meets them as a filter that \
         disagrees with the display.",
        strays.join("\n  ")
    );
}

/// No surface scores a MOS on the assumed one-way delay.
///
/// The sibling of `only_one_place_in_the_tree_scores_a_mos`, and it exists
/// because that gate passed throughout the defect it was written for. There was
/// exactly one scorer; five of the six surfaces calling it passed no delay, so
/// `estimate_mos` supplied `DEFAULT_ONE_WAY_DELAY_MS` — a domestic 100 ms guess
/// — for every stream. One scorer, one formula, and still two answers: the
/// stream-detail pane scored a call on the path its own RTCP measured while the
/// filter DSL, the call list, the REST and MCP projections, the alert threshold
/// and the browser build all scored the same call as if it were domestic.
///
/// Over a 6635-stream corpus that is 2212 streams whose delay is not the
/// assumption, 22 of them past G.107's `Id` knee at 177.3 ms, and 20 of those
/// wrong by more than a FULL MOS point — worst case reading 4.36 where the
/// truth is 1.00. Those calls reported as excellent everywhere but one pane.
///
/// So the rule is structural, not behavioural: a production caller must supply
/// the delay, either through [`MosDelay`](sipnab::rtp::quality::MosDelay) or by
/// naming it in `estimate_mos_with_delay`. `estimate_mos` itself survives as
/// the documented assumption and the reference the model is pinned against —
/// it is a legitimate thing for a downstream crate to call, and an illegitimate
/// thing for a surface of this one to.
#[test]
fn no_surface_scores_a_mos_on_the_assumed_delay() {
    // Where the assumption is allowed to be named: the model's own home, which
    // defines the wrapper, documents it and doc-tests it.
    const HOME: &str = "src/rtp/quality.rs";

    let mut strays = Vec::new();
    let mut delay_aware = 0usize;
    let mut stack = vec![repo().join("src")];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir).expect("read_dir src").flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            if p.extension().and_then(|s| s.to_str()) != Some("rs") {
                continue;
            }
            let rel = p
                .strip_prefix(repo())
                .expect("under repo")
                .to_string_lossy()
                .replace('\\', "/");
            let text = std::fs::read_to_string(&p).expect("read");
            // Production only. A unit test may legitimately hold the delay term
            // still by naming the assumed wrapper, and `dashboard.rs` does.
            for (i, line) in source_scan::production_source(&text).lines().enumerate() {
                // Prose may DISCUSS the wrapper — most of these files carry a
                // comment explaining why they stopped calling it — and a gate
                // that banned the words would ban the explanation.
                let code = line.split("//").next().unwrap_or("");
                if code.contains("estimate_mos_with_delay(") || code.contains(".score(") {
                    delay_aware += 1;
                }
                if !code.contains("estimate_mos(") {
                    continue;
                }
                // The re-export in `src/lib.rs` is the public API, not a call.
                if code.contains("pub use") || rel == HOME {
                    continue;
                }
                strays.push(format!("{rel}:{}: {}", i + 1, line.trim()));
            }
        }
    }

    // Anti-vacuity. A walk that found nothing, or a rename of the delay-aware
    // entry point, would leave this reporting a clean tree because it read an
    // empty one. Nine sites score a MOS on a resolved delay today.
    assert!(
        delay_aware >= 9,
        "only {delay_aware} delay-aware scoring sites were found in src/ — the \
         scan or the entry-point name broke, so this gate is checking nothing"
    );

    strays.sort();
    assert!(
        strays.is_empty(),
        "a surface has gone back to scoring a MOS on the assumed \
         {assumed} ms path:\n  {}\n\nPass the delay: hold a \
         `crate::rtp::quality::MosDelay` for the store and call `.score(stream)`, \
         or name the figure in `estimate_mos_with_delay`. A surface that assumes \
         the delay reports a long-haul call as excellent, and disagrees with \
         every surface that does not.",
        strays.join("\n  "),
        assumed = sipnab::rtp::quality::DEFAULT_ONE_WAY_DELAY_MS,
    );
}

/// No view may band jitter, loss or MOS with its own numbers.
///
/// Four views did, and disagreed: 25 ms jitter was Good in the stream list and
/// Warning on the dashboard; 0.8% loss was Good in the list and Warning in the
/// loss map. The colour column is the TUI's primary triage signal, so an
/// operator scanning for yellow found a different set of calls depending on
/// which pane they were looking at.
///
/// Two of those files documented an agreement they did not have —
/// "the same bands the dashboard and stream-detail views use" and "loss color
/// bands mirror the stream-detail view" — above numbers that matched neither.
/// Both were written by people who believed it. Neither checked, and a comment
/// cannot check itself, which is what this test is for.
///
/// WHY IT READS EVERY LINE OF `src/tui/`, NOT THE `*_style` FUNCTIONS. Its
/// first version required the word `jitter`, `loss` or `mos` on the comparison
/// itself, which is true of a named style function and false of the loop that
/// paints a sparkline: the stream-detail jitter sparkline banded `if j < 20.0`
/// over a one-letter binding, three hundred lines above the `jitter_style`
/// that called the same 25 ms sample Good. The gate passed, in the same file,
/// while one pane contradicted another. So the second question is not what the
/// comparison is NAMED but what its branch PRODUCES: a band ends in a severity
/// colour, and a scale — `jitter_to_block`, `mos_to_block` — ends in a glyph.
/// Only the colour is a triage verdict an operator can find disagreeing with
/// itself, and only the colour is caught here.
#[test]
fn no_view_carries_its_own_quality_bands() {
    // The literals that used to be band boundaries. A number here is only a
    // finding when it sits in a comparison.
    const SUSPECT: &[&str] = &["20.0", "30.0", "50.0", "0.5", "1.0", "2.0", "5.0", "3.5"];
    // What a band branch produces. `jitter_to_block` compares against 30.0 and
    // 20.0 four lines apart and is not a band, because it yields '▇' — nothing
    // an operator can catch two panes disagreeing about.
    const SEVERITY: &[&str] = &["theme.good", "theme.warning", "theme.bad"];
    // Lines from the comparison in which its branch may land. `if j < 20.0 {`
    // and the `theme.good` it guards are two lines apart after rustfmt; four
    // covers a three-arm `if/else if/else` without reaching the next statement.
    const BRANCH_LINES: usize = 4;

    let mut views: Vec<std::path::PathBuf> = Vec::new();
    let mut stack = vec![repo().join("src/tui")];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir).expect("read_dir src/tui").flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().and_then(|s| s.to_str()) == Some("rs") {
                views.push(p);
            }
        }
    }
    views.sort();

    let mut problems = Vec::new();
    let mut comparisons_seen = 0usize;
    let mut severity_seen = 0usize;
    for view in &views {
        let rel = view
            .strip_prefix(repo())
            .expect("under repo")
            .to_string_lossy()
            .replace('\\', "/");
        let text = std::fs::read_to_string(view).unwrap_or_else(|e| panic!("read {rel}: {e}"));
        let all: Vec<&str> = text.lines().collect();
        let bare = |l: &str| l.split("//").next().unwrap_or("").to_string();
        // Everything from the test MODULE on is assertions ABOUT the bands,
        // not bands. Its first run reported two `assert!(loss_pct > 30.0)`
        // lines, and a gate that cries about its own tests gets skimmed.
        //
        // Cut with the shared rule, not at the text and not at the attribute.
        // Splitting the raw file on `#[cfg(test)]` cut `dashboard.rs` at the
        // line where a COMMENT says the words. Cutting at the first ATTRIBUTE
        // fixed that view and still stopped these dead, because the attribute
        // also guards test-only `use`s and `thread_local!` call counters near
        // the top of a file: 22 lines of `controllers/mod.rs` (of 677
        // production), 163 of `stream_list.rs` (of 450), 249 of
        // `call_flow/prepare.rs` (of 1317), 418 of `call_list.rs` (of 1367).
        // A scanner silenced by its own scaffolding reports clean for the same
        // reason it reports nothing.
        let end = source_scan::production_source(&text).lines().count();
        let lines = &all[..end];
        severity_seen += lines
            .iter()
            .filter(|l| SEVERITY.iter().any(|s| bare(l).contains(s)))
            .count();
        for (i, line) in lines.iter().enumerate() {
            let code = bare(line);
            // A comparison DERIVED from the shared bands is the fix, not the
            // defect — `(bands.mos_warn + bands.mos_bad) / 2.0` is the detail
            // view splitting the shared middle, which it is allowed to do.
            if code.contains("bands.") || code.contains("QualityBands") {
                continue;
            }
            // A band is a comparison against a bare float.
            let compares = code.contains(" >= ")
                || code.contains(" <= ")
                || code.contains(" < ")
                || code.contains(" > ");
            if !compares {
                continue;
            }
            let Some(lit) = SUSPECT.iter().find(|l| code.contains(**l)) else {
                continue;
            };
            comparisons_seen += 1;
            // Either tell is enough. The name catches a style function whose
            // branch is a `Style` rather than a bare colour; the branch catches
            // the sparkline loops, where the value is called `j` or `m` and the
            // name says nothing at all.
            let about_quality = ["jitter", "loss", "mos"]
                .iter()
                .any(|k| code.to_ascii_lowercase().contains(k));
            let end = (i + 1 + BRANCH_LINES).min(lines.len());
            let paints_severity = lines[i..end]
                .iter()
                .any(|l| SEVERITY.iter().any(|s| bare(l).contains(s)));
            if about_quality || paints_severity {
                problems.push(format!("{rel}:{}: bands on a bare {lit}", i + 1));
            }
        }
    }

    // Anti-vacuity, both halves. A walk that found no files, a SUSPECT list
    // that matches nothing, or a `theme.good` renamed out from under SEVERITY
    // each leave a gate that reports nothing because it is looking at nothing.
    assert!(
        views.len() >= 4,
        "the src/tui walk found {} files — the scan broke, so this gate is \
         checking nothing",
        views.len()
    );
    assert!(
        comparisons_seen >= 1,
        "no comparison against any band-boundary literal was found anywhere in \
         src/tui/ — the literal scan is checking nothing"
    );
    assert!(
        severity_seen >= 1,
        "no severity colour ({SEVERITY:?}) appears anywhere in src/tui/ — the \
         theme fields were renamed and the branch half of this gate now finds \
         nothing"
    );

    problems.sort();
    assert!(
        problems.is_empty(),
        "a view is banding quality with its own numbers again. Use \
         `crate::rtp::bands::QualityBands` so every pane agrees about the same \
         stream:\n  {}",
        problems.join("\n  ")
    );
}

/// A limit that refuses legitimate work must say so at a level an operator sees.
///
/// Three fail-closed limits refused real traffic and logged it at `debug!`,
/// which is invisible by default:
///
///   - HMAC skew: every packet from a clock-drifted sender dropped. Presents as
///     "the collector receives nothing" — the hardest symptom to attribute,
///     because the operator suspects routing, the firewall and the sender's
///     config long before a clock.
///   - Peer tracking full: NEW peers refused while inside every rate budget,
///     and `--hep-rate-limit` cannot relieve it because that bounds rate.
///   - TLS handshake eviction: a CLIENT_RANDOM discarded before its ServerHello,
///     so those sessions never decrypt. This one logged NOTHING at all, and
///     reads as a bad keylog.
///
/// The common shape is that the failure is invisible where it happens and
/// indistinguishable from a misconfiguration elsewhere. A `warn!` at the point
/// of refusal is what makes it attributable, so this pins that each site still
/// has one — a future edit that quietly drops back to `debug!` restores a
/// silent failure, which is the defect rather than a style change.
#[test]
fn a_limit_that_refuses_real_work_warns_where_it_refuses() {
    struct Site {
        file: &'static str,
        marker: &'static str,
        what: &'static str,
    }
    let sites = [
        Site {
            file: "src/capture/hep.rs",
            // A phrase unique to the WARNING. An earlier version matched
            // "acceptance window", which is also the wording of the constant's
            // doc comment 250 lines above — so the gate found prose about the
            // limit instead of the diagnostic for it, and reported a fault that
            // was its own.
            marker: "check NTP on the sender",
            what: "HMAC clock skew dropping every packet from a sender",
        },
        Site {
            file: "src/capture/hep.rs",
            marker: "peer tracking is full",
            what: "new peers refused while inside every rate limit",
        },
        Site {
            file: "src/capture/decrypt.rs",
            marker: "waiting for a ServerHello",
            what: "handshakes evicted before pairing, so those sessions never decrypt",
        },
        // The three below refuse data ALREADY CAPTURED rather than refusing to
        // take more in, which is the worse half of the same defect: the packet
        // reached sipnab and sipnab discarded it. Each was a debug! line.
        Site {
            file: "src/sip/dialog_store.rs",
            marker: "Ladders for those calls are now incomplete",
            what: "idle compaction dropping messages that were successfully captured",
        },
        Site {
            file: "src/capture/reassembly.rs",
            marker: "flushed mid-message",
            what: "a SIP/TCP message over 64 KiB cut in half, so it parses as malformed",
        },
        Site {
            // Markers must sit on ONE source line: this gate greps the file,
            // and a Rust string split over a `\` continuation does not contain
            // its own rendered text. The first marker tried here was
            // "will not appear at all", which straddles a continuation and so
            // matched nothing while the warning was present and correct.
            file: "src/capture/parse.rs",
            marker: "RFC 4960 sets no such limit",
            what: "an over-cap SCTP message dropped whole, so its calls never surface",
        },
    ];

    let mut missing = Vec::new();
    for s in &sites {
        let text =
            std::fs::read_to_string(s.file).unwrap_or_else(|e| panic!("read {}: {e}", s.file));
        // The message must exist AND be reachable from a warn!, not a debug!.
        let Some(at) = text.find(s.marker) else {
            missing.push(format!("{}: no diagnostic for {}", s.file, s.what));
            continue;
        };
        let before = &text[at.saturating_sub(600)..at];
        if !before.contains("tracing::warn!") {
            missing.push(format!(
                "{}: the diagnostic for {} is no longer reached from a warn!",
                s.file, s.what
            ));
        }
    }

    assert!(
        missing.is_empty(),
        "a fail-closed limit went quiet again. An operator cannot act on a \
         refusal they cannot see, and each of these presents as a fault \
         somewhere else entirely:\n  {}",
        missing.join("\n  ")
    );
}
