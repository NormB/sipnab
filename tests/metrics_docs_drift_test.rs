// SPDX-License-Identifier: MIT OR Apache-2.0

//! Every metric the exposition emits must be documented, and no documented
//! metric may name a series the exposition never emits.
//!
//! Task #63 started as a documentation entry: `docs/rest-api.md` correctly
//! described five declared-but-unwired metrics. Docs written by hand against
//! a formatter that changes elsewhere drift in both directions — a new metric
//! nobody documents, and a documented metric that was renamed or removed —
//! and only one of those is visible to a reader. This gate reads the
//! formatter and the page and compares them.

#[path = "support/source_scan.rs"]
mod source_scan;

/// The exposition formatter, the single place metric names are written.
const SOURCE: &str = include_str!("../src/output/prometheus.rs");

/// The operator-facing page that tables those names.
const PAGE: &str = include_str!("../docs/rest-api.md");

/// Metric family names appearing in `text`, in first-seen order.
///
/// Bare scanning rather than a parser: names are written as string literals
/// (`"sipnab_dialogs_total"`, `"sipnab_rtp_streams_active {}"`), and the
/// suffixed forms a histogram emits are built with `format!`, so they never
/// appear as literals here.
///
/// # Arguments
/// * `text` — the source or page text to scan.
///
/// # Returns
/// Deduplicated `sipnab_`-prefixed family names.
fn families(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while let Some(hit) = text[i..].find("sipnab_") {
        let start = i + hit;
        let mut end = start;
        while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
            end += 1;
        }
        i = end;
        let name = &text[start..end];
        // `sipnab_` alone, or an identifier that merely starts with it (the
        // crate is called sipnab, so `sipnab_mcp` style words show up in
        // prose), are not metric families: a family always carries a `_`
        // beyond the prefix.
        if name.len() <= "sipnab_".len() {
            continue;
        }
        if !out.iter().any(|n| n == name) {
            out.push(name.to_string());
        }
    }
    out
}

/// The formatter's own emitted names, excluding its `#[cfg(test)]` module
/// (whose fixtures name `_bucket` / `_count` suffixes the page documents as
/// suffixes rather than as families).
///
/// Cut at the test MODULE, via the shared rule. This used to split the raw
/// text on `#[cfg(test)]`, which ends the scan at the first line that merely
/// SPELLS the attribute — a comment, a doc comment, or a test-only `use`. The
/// direction of that failure is the dangerous one: a shorter production text
/// emits fewer families, so `every_emitted_metric_is_documented` reports every
/// remaining name as documented and passes on a page it never compared against
/// the metrics below the cut.
///
/// # Returns
/// Family names the exposition can emit.
fn emitted_families() -> Vec<String> {
    families(source_scan::production_source(SOURCE))
}

/// Every family the formatter emits appears in the REST API page.
#[test]
fn every_emitted_metric_is_documented() {
    let missing: Vec<String> = emitted_families()
        .into_iter()
        .filter(|name| !PAGE.contains(name.as_str()))
        .collect();

    assert!(
        missing.is_empty(),
        "src/output/prometheus.rs emits metrics that docs/rest-api.md never \
         mentions: {missing:?} — a scrape carries a series no operator has \
         been told about"
    );
}

/// Every family the page documents is one the formatter can emit.
///
/// The direction that caught task #63's own regression risk: the page is
/// where an operator picks the series to alert on, so a name that survives a
/// rename in the docs alone sends them to a series that will never exist.
#[test]
fn every_documented_metric_is_emitted() {
    let emitted = emitted_families();
    let phantom: Vec<String> = families(PAGE)
        .into_iter()
        .filter(|name| {
            // Histogram suffixes are documented as part of their family.
            let base = name
                .trim_end_matches("_bucket")
                .trim_end_matches("_count")
                .trim_end_matches("_sum");
            !emitted.iter().any(|e| e == name || e == base)
        })
        .collect();

    assert!(
        phantom.is_empty(),
        "docs/rest-api.md documents metrics the exposition never emits: \
         {phantom:?} — an alert rule written from the page would go no-data \
         forever"
    );
}

/// The five metrics task #63 wired are named on the page, so the fix cannot
/// be reverted in silence.
#[test]
fn the_wired_metrics_stay_documented() {
    for name in [
        "sipnab_capture_packets_total",
        "sipnab_reassembly_timeouts_total",
        "sipnab_responses_total",
        "sipnab_diagnosis_total",
        "sipnab_security_alerts_total",
    ] {
        assert!(
            PAGE.contains(name),
            "{name} must stay documented in docs/rest-api.md"
        );
        assert!(
            emitted_families().iter().any(|e| e == name),
            "{name} must stay in the exposition"
        );
    }
}
