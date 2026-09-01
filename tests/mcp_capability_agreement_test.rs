// SPDX-License-Identifier: MIT OR Apache-2.0

//! What the server ADVERTISES and what the build can DO must be one answer.
//!
//! On 2026-09-01 a `native,hep,api,mcp,mcp-http` build listed `export_vcon`
//! and `validate_vcon` in `tools/list`, complete with input and output
//! schemas, and refused every call to them: the tools were registered
//! unconditionally and only their inner helpers were split on the `vcon`
//! feature. An agent reading `tools/list` — which is the ONLY contract MCP
//! gives it — would plan around a tool that could never run.
//!
//! It survived because the two facts live apart. The router is composed in
//! `server.rs`; the refusal is a `#[cfg(not(feature = "vcon"))]` arm hundreds
//! of lines away in `tools/vcon.rs`. Nothing compared them, and the build I
//! test locally (`full`) carries `vcon`, so locally there was nothing to see.
//!
//! The refusal made a second promise it could not keep. It says to consult
//! `server_capabilities` for what the binary carries — and that report names
//! `native, tui, tls, hep, api, mcp, mcp-http, metrics, audio, plugins` and
//! has never named `vcon`. Its own comment says it reads from `cfg!` so it
//! "cannot claim a feature the binary does not have", which is true and only
//! half the rule: it can silently OMIT a feature the binary does have. An
//! operator following the error's own advice learns nothing.
//!
//! So this file gates the agreement in both directions, and does it from the
//! SOURCE where it can, so that a build carrying the feature still fails when
//! the report cannot name it.

#![cfg(feature = "mcp")]

use parking_lot::RwLock;
use sipnab::mcp::SipnabMcp;
use sipnab::rtp::stream_store::StreamStore;
use sipnab::sip::dialog_store::DialogStore;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;

/// The tools a stock server registers, which is what `tools/list` returns.
fn registered() -> Vec<String> {
    SipnabMcp::new(
        Arc::new(RwLock::new(DialogStore::new(64, false))),
        Arc::new(RwLock::new(StreamStore::new(64))),
    )
    .registered_tool_names()
}

fn repo(rel: &str) -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

/// Every feature name `Cargo.toml` declares.
fn declared_features() -> BTreeSet<String> {
    let src = repo("Cargo.toml");
    let mut out = BTreeSet::new();
    let mut inside = false;
    for line in src.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            inside = line == "[features]";
            continue;
        }
        if !inside || line.starts_with('#') || line.is_empty() {
            continue;
        }
        if let Some((name, _)) = line.split_once('=') {
            out.insert(name.trim().to_string());
        }
    }
    out
}

/// Every feature name `server_capabilities` is able to report.
///
/// Read off the `("name", cfg!(feature = "name"))` pair list in the source
/// rather than from a live call, because a live call can only ever show the
/// features THIS build turned on. The bug being gated is an omission, and an
/// omission is invisible in any single build's output.
fn reportable_features() -> BTreeSet<String> {
    let src = repo("src/mcp/server.rs");
    let at = src
        .find("pub async fn server_capabilities")
        .expect("server.rs has no server_capabilities");
    let body = &src[at..];
    let end = body
        .find("features.sort()")
        .expect("the capability feature list no longer sorts; this scan is reading the wrong code");
    let mut out = BTreeSet::new();
    for line in body[..end].lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("(\"") else {
            continue;
        };
        let Some((name, tail)) = rest.split_once('"') else {
            continue;
        };
        // The pair must actually consult cfg!, or the report is a hand-kept
        // claim rather than a reading of the build.
        if tail.contains("cfg!(feature = ") {
            out.insert(name.to_string());
        }
    }
    out
}

/// Every `.rs` file under `src/`.
fn source_files() -> Vec<PathBuf> {
    fn walk(dir: &std::path::Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    let mut out = Vec::new();
    walk(
        &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut out,
    );
    out.sort();
    out
}

/// The feature sets a line tells an operator to rebuild with.
///
/// `--features a,b` is one instruction naming two features, and both have to
/// be real. A trailing `)` or quote is punctuation, not part of the name.
fn rebuild_targets(line: &str) -> Vec<Vec<String>> {
    const NEEDLE: &str = "--features ";
    let mut out = Vec::new();
    let mut rest = line;
    while let Some(at) = rest.find(NEEDLE) {
        rest = &rest[at + NEEDLE.len()..];
        let raw: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == ',')
            .collect();
        let names: Vec<String> = raw
            .split(',')
            .map(str::trim)
            .filter(|n| !n.is_empty())
            .map(str::to_string)
            .collect();
        if !names.is_empty() {
            out.push(names);
        }
    }
    out
}

/// Tool modules behind a `#[cfg(feature = ..)]`, and the tools each declares.
///
/// Read from the source rather than from the router, because the router can
/// only show what THIS build registered -- and the property under test is
/// about the relationship between the two.
fn gated_tool_modules() -> Vec<(String, Vec<String>)> {
    let modsrc = repo("src/mcp/tools/mod.rs");
    let lines: Vec<&str> = modsrc.lines().collect();
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let line = line.trim();
        if !line.starts_with("#[cfg(") || !line.contains("feature = ") {
            continue;
        }
        let Some(next) = lines.get(i + 1) else {
            continue;
        };
        let Some(name) = next
            .trim()
            .strip_prefix("pub mod ")
            .or_else(|| next.trim().strip_prefix("mod "))
            .and_then(|n| n.strip_suffix(';'))
        else {
            continue;
        };
        let path = format!("src/mcp/tools/{name}.rs");
        let body = repo(&path);
        let mut tools = Vec::new();
        for l in body.lines() {
            let l = l.trim();
            if let Some(rest) = l.strip_prefix("name = \"")
                && let Some((tool, _)) = rest.split_once('"')
            {
                tools.push(tool.to_string());
            }
        }
        if !tools.is_empty() {
            out.push((path, tools));
        }
    }
    out
}

/// Every feature named in a tool module's gate.
fn gating_features() -> BTreeSet<String> {
    let modsrc = repo("src/mcp/tools/mod.rs");
    let lines: Vec<&str> = modsrc.lines().collect();
    let mut out = BTreeSet::new();
    for (i, line) in lines.iter().enumerate() {
        let l = line.trim();
        if !l.starts_with("#[cfg(") {
            continue;
        }
        let Some(next) = lines.get(i + 1) else {
            continue;
        };
        if !next.trim_start().starts_with("pub mod ") && !next.trim_start().starts_with("mod ") {
            continue;
        }
        let mut rest = l;
        while let Some(at) = rest.find("feature = \"") {
            rest = &rest[at + 11..];
            if let Some((name, tail)) = rest.split_once('"') {
                out.insert(name.to_string());
                rest = tail;
            } else {
                break;
            }
        }
    }
    out
}

/// Aggregates, excluded with the reason each one is not a capability.
///
/// Every exclusion is paired with why, because a scanner narrowed until it is
/// green is a scanner narrowed until it is blind.
const NOT_A_CAPABILITY: &[(&str, &str)] = &[
    (
        "default",
        "an alias for whatever the default set happens to be; it expands to \
         features that are reported individually, so naming it would report \
         the same capability twice under two names",
    ),
    (
        "full",
        "an aggregate of every other feature, reported individually; a binary \
         does not carry `full`, it carries what `full` expands to",
    ),
];

/// The tools that exist only in a build carrying the vCon exporter.
const VCON_TOOLS: &[&str] = &["export_vcon", "validate_vcon"];

/// A tool is advertised exactly when this build can run it.
///
/// The defect, stated directly. Both directions are load-bearing: dropping
/// the tools from a build that HAS the exporter would silently remove a
/// published surface, which is the opposite failure and just as quiet.
#[test]
fn the_vcon_tools_are_registered_exactly_when_the_build_can_run_them() {
    let names: BTreeSet<String> = registered().into_iter().collect();
    let have_exporter = cfg!(feature = "vcon");

    for tool in VCON_TOOLS {
        assert_eq!(
            names.contains(*tool),
            have_exporter,
            "{tool} is registered={} on a build where vcon={have_exporter}. A \
             tool in tools/list that always refuses is worse than one that is \
             absent: an agent plans around it, calls it, and gets an error \
             that no argument it could have chosen would have avoided.",
            names.contains(*tool)
        );
    }
}

/// The capability report can NAME every feature the crate declares.
///
/// Source-level on purpose. A live call reports this build's features, so an
/// omission only shows up in a build that has the omitted feature AND someone
/// looking for it. Reading the pair list catches it in every build, including
/// the `full` one used locally.
#[test]
fn the_capability_report_can_name_every_feature_the_crate_declares() {
    let declared = declared_features();
    let reportable = reportable_features();
    let excluded: BTreeSet<&str> = NOT_A_CAPABILITY.iter().map(|(n, _)| *n).collect();

    let missing: Vec<&String> = declared
        .iter()
        .filter(|f| !excluded.contains(f.as_str()))
        .filter(|f| !reportable.contains(*f))
        .collect();

    assert!(
        missing.is_empty(),
        "Cargo.toml declares {missing:?}, and server_capabilities cannot name \
         them in any build. An operator asking what this binary carries gets \
         an answer that is true about what it lists and silent about the \
         rest -- and sipnab's own refusals send them to that report."
    );
}

/// Every exclusion names a feature that still exists.
///
/// The other direction on the allowlist. Without this an entry outlives the
/// feature it excuses and quietly widens the hole it was cut for.
#[test]
fn every_capability_exclusion_names_a_declared_feature() {
    let declared = declared_features();
    for (name, reason) in NOT_A_CAPABILITY {
        assert!(
            declared.contains(*name),
            "NOT_A_CAPABILITY excludes {name:?}, which Cargo.toml no longer \
             declares. Remove the entry."
        );
        assert!(
            reason.len() > 40,
            "{name}'s exclusion must say why it is not a capability, not that \
             it is inconvenient to report"
        );
    }
}

/// The report does not claim a feature this build lacks.
///
/// The direction the existing unit test already covers, restated here so the
/// pair is in one place: a report that over-claims sends an operator looking
/// for a surface that is not there.
#[test]
fn the_capability_report_names_only_features_the_crate_declares() {
    let declared = declared_features();
    let reportable = reportable_features();
    let invented: Vec<&String> = reportable
        .iter()
        .filter(|f| !declared.contains(*f))
        .collect();
    assert!(
        invented.is_empty(),
        "server_capabilities can report {invented:?}, which Cargo.toml does \
         not declare; the name is misspelled or the feature is gone"
    );
}

/// Every feature a rebuild instruction names is real, and answerable.
///
/// The second half of the defect, generalized past `vcon`. sipnab tells an
/// operator to "rebuild with --features X" in a dozen places, and pairs it
/// with "server_capabilities lists what this binary carries". Two ways that
/// sentence lies: X is not a feature at all (a typo, or one that was renamed),
/// or X is real and the report cannot name it -- which is what shipped, and
/// what sent an operator chasing a vCon exporter through a report that has
/// never mentioned vCon.
///
/// Scanned across `src/` rather than the two files the bug happened to touch,
/// because the next one will be somewhere else.
#[test]
fn every_feature_a_rebuild_instruction_names_is_real_and_answerable() {
    let declared = declared_features();
    let reportable = reportable_features();
    let aggregates: BTreeSet<&str> = NOT_A_CAPABILITY.iter().map(|(n, _)| *n).collect();

    let mut checked = 0;
    let mut undeclared = Vec::new();
    let mut unanswerable = Vec::new();

    for path in source_files() {
        let src = std::fs::read_to_string(&path).unwrap_or_default();
        let shown = path
            .strip_prefix(env!("CARGO_MANIFEST_DIR"))
            .unwrap_or(&path)
            .display()
            .to_string();
        for (n, line) in src.lines().enumerate() {
            for names in rebuild_targets(line) {
                for feature in names {
                    checked += 1;
                    let at = format!("  {shown}:{}: --features {feature}", n + 1);
                    if !declared.contains(&feature) {
                        undeclared.push(at);
                    } else if !aggregates.contains(feature.as_str())
                        && !reportable.contains(&feature)
                    {
                        unanswerable.push(at);
                    }
                }
            }
        }
    }

    assert!(
        checked >= 5,
        "only {checked} rebuild instruction(s) found across src/; the scan has \
         stopped matching and this gate proves nothing"
    );
    assert!(
        undeclared.is_empty(),
        "these tell an operator to rebuild with a feature Cargo.toml does not \
         declare, so the command cannot work:\n{}",
        undeclared.join("\n")
    );
    assert!(
        unanswerable.is_empty(),
        "these name a real feature that server_capabilities cannot report, so \
         an operator who follows the advice and asks what this binary carries \
         is told nothing about the thing they are missing:\n{}",
        unanswerable.join("\n")
    );
}

/// A build without the exporter advertises no vCon surface at all.
///
/// Separate from the pair test above because it is the operator-visible
/// claim: not "these two names are absent" but "nothing here mentions vCon".
/// A third vCon tool added later without a feature gate fails here.
#[cfg(not(feature = "vcon"))]
#[test]
fn a_build_without_the_exporter_advertises_no_vcon_tool() {
    let offered: Vec<String> = registered()
        .into_iter()
        .filter(|t| t.to_ascii_lowercase().contains("vcon"))
        .collect();
    assert!(
        offered.is_empty(),
        "this build has no vCon exporter and advertises {offered:?}"
    );
}

/// A build WITH the exporter advertises both tools.
///
/// The paired positive. Without it the fix above could be "register no vCon
/// tools ever", which passes the negative and deletes the feature.
#[cfg(feature = "vcon")]
#[test]
fn a_build_with_the_exporter_advertises_both_vcon_tools() {
    let names: BTreeSet<String> = registered().into_iter().collect();
    for tool in VCON_TOOLS {
        assert!(
            names.contains(*tool),
            "this build carries the vCon exporter and does not advertise \
             {tool}; the feature is unreachable over MCP"
        );
    }
}

/// The scanners read real files.
///
/// Anti-vacuity for every filter above. Each one narrows, and a narrowing
/// that reaches zero exits 0 forever while looking exactly like agreement.
#[test]
fn the_capability_scans_found_plausible_sources() {
    let declared = declared_features();
    let reportable = reportable_features();

    assert!(
        declared.len() >= 10,
        "only {} feature(s) parsed from Cargo.toml; the [features] scan is \
         wrong: {declared:?}",
        declared.len()
    );
    assert!(
        reportable.len() >= 8,
        "only {} feature(s) parsed from the capability list; the pair scan is \
         wrong: {reportable:?}",
        reportable.len()
    );
    for anchor in ["native", "mcp", "hep"] {
        assert!(
            declared.contains(anchor),
            "Cargo.toml scan missed {anchor}, so it is not reading [features]"
        );
        assert!(
            reportable.contains(anchor),
            "capability scan missed {anchor}, so it is not reading the pairs"
        );
    }
    assert!(
        !registered().is_empty(),
        "the router registered no tools at all; every tool assertion above is \
         vacuous"
    );
}

// ── the debt from `stdio_mcp_full_tool_set_and_remaining_tools` ─────────
//
// That test carried a flat list of tool names and a literal count, and both
// assumed the vCon pair was always present. It failed the moment the pair was
// registered honestly -- not because the fix was wrong, but because the
// expectation described one build and was checked against every build. It was
// corrected and nothing was written to keep it corrected, which is the half of
// a fix that gets skipped.

/// Every feature-gated tool module registers all of its tools, or none.
///
/// The general form of the defect this file exists for. `export_vcon` and
/// `validate_vcon` live in one module behind one feature: a build carrying the
/// feature must advertise both, and a build without it must advertise neither.
/// HALF a module is the shape that shipped -- the tools listed, the exporter
/// absent -- and it is invisible to any test that checks one name at a time.
///
/// Deliberately does not consult `cfg!`: the property holds in every build
/// without knowing which features are on, so it cannot rot into a test that
/// only means something under `full`.
#[test]
fn a_feature_gated_tool_module_registers_all_or_none_of_its_tools() {
    let registered: BTreeSet<String> = registered().into_iter().collect();
    let mut modules = 0;

    for (module, tools) in gated_tool_modules() {
        modules += 1;
        let present = tools.iter().filter(|t| registered.contains(*t)).count();
        assert!(
            present == 0 || present == tools.len(),
            "{module} declares {} tool(s) and {present} of them are \
             registered. A feature-gated module is all or nothing: a partly \
             advertised module means the gate is on the registration and not \
             on the code behind it, which is exactly how a tool that cannot \
             run reaches tools/list. Declared: {tools:?}",
            tools.len()
        );
    }
    assert!(
        modules >= 1,
        "no feature-gated tool module found; the scan of \
         src/mcp/tools/mod.rs is wrong and this gate proves nothing"
    );
}

/// Every feature gating a tool module is one the report can name.
///
/// The two halves joined. If a module is hidden behind a feature, the absence
/// of its tools is a question an agent will ask, and `server_capabilities` is
/// the only place that can answer it.
#[test]
fn every_feature_gating_a_tool_module_is_one_the_report_can_name() {
    let reportable = reportable_features();
    let mut checked = 0;
    for feature in gating_features() {
        checked += 1;
        assert!(
            reportable.contains(&feature),
            "tool modules are gated on `{feature}` and server_capabilities \
             cannot name it, so a client that notices the tools are missing \
             has no way to learn why"
        );
    }
    assert!(
        checked >= 1,
        "no gating feature found; the scan is wrong and this proves nothing"
    );
}

/// The stdio test's expected tool set is derived from the build.
///
/// A regression guard on the exact failure. The expectation may not go back to
/// being a flat list: it has to consult `cfg!` for the feature-gated tools, or
/// it asserts a tool set that only one build has while running in all of them.
#[test]
fn the_stdio_tool_set_expectation_is_feature_aware() {
    let src = repo("tests/mcp_stdio_test.rs");
    let at = src.find("MCP tool set drifted").expect(
        "mcp_stdio_test.rs no longer asserts the tool set; this guard \
                 is reading the wrong file",
    );
    // The window above the assertion, where the expectation is built.
    let window = &src[at.saturating_sub(3000)..at];
    assert!(
        window.contains("cfg!(feature ="),
        "the expected MCP tool set is built without consulting `cfg!`, so it \
         describes one build and is checked against every build. That is the \
         failure this guard exists for: the list named the vCon pair \
         unconditionally and broke as soon as they were registered honestly."
    );
    let count_at = src
        .find("MCP tools\"")
        .expect("the tool-count assertion is gone");
    let count_window = &src[count_at.saturating_sub(400)..count_at];
    assert!(
        count_window.contains("cfg!(feature =") || count_window.contains("want"),
        "the expected tool COUNT is a bare literal; it has to move with the \
         feature set the same way the names do"
    );
}
