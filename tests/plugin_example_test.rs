// SPDX-License-Identifier: MIT OR Apache-2.0

//! End-to-end test for the worked plugin example.
//!
//! The host's own unit tests use hand-written WAT fixtures, which prove the
//! host handles a conforming module, a hostile one, and a broken one. They do
//! not prove that the documented way to *write* a plugin actually produces a
//! module this host accepts — and that is the claim the docs make.
//!
//! So this builds `crates/sipnab-plugin-example` for
//! `wasm32-unknown-unknown` exactly as the documentation tells a reader to, and
//! runs the result. If the published build command stops producing a working
//! plugin, this fails.
//!
//! It builds rather than skipping when the artifact is missing. A test that
//! quietly passes when it did nothing is worse than no test: it reports the
//! documented workflow as verified on runs where nothing was verified.

#![cfg(feature = "plugins")]
//
// Every test here is named `wasm_plugin_*` on purpose. The coverage job skips
// them by that prefix: they shell out to `cargo build --target
// wasm32-unknown-unknown`, and a nested build cannot carry the coverage
// harness's instrumentation (wasm32 has no `profiler_builtins`). The prefix is
// the filter, so renaming one out of it silently drops it back into the
// coverage run — keep it.

use std::path::PathBuf;
use std::process::Command;

use sipnab::plugin::{ABI_VERSION, Plugin};

/// Build the example plugin the way the spec's "Writing a plugin" section says
/// to, and return the artifact path.
fn build_example() -> PathBuf {
    // Build exactly once per test binary.
    //
    // Every test here needs the artifact, and libtest runs them in parallel —
    // so the first version fired five concurrent `cargo build`s at the same
    // target directory. They serialise on cargo's package-cache lock, but the
    // artifact check does not: one test can stat the path while another
    // build is still putting it there, which fails as "build reported success
    // but produced no artifact". It passed on Linux and failed on macOS, which
    // is what a race looks like when you only run it twice.
    static ARTIFACT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    ARTIFACT.get_or_init(build_example_once).clone()
}

/// The actual build. Called once, behind [`build_example`]'s `OnceLock`.
fn build_example_once() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let mut cmd = Command::new(env!("CARGO"));
    cmd.current_dir(manifest);

    // Do not inherit the parent run's instrumentation.
    //
    // Under `cargo llvm-cov` the coverage flags arrive through the
    // environment, and a nested build picks them up — but
    // `wasm32-unknown-unknown` ships no `profiler_builtins`, so the build dies
    // with "can't find crate for `profiler_builtins`". The wasm artifact is a
    // plugin under test, not part of the coverage measurement, so it wants a
    // clean build environment rather than the harness's.
    for var in [
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_BUILD_RUSTFLAGS",
        "RUSTDOCFLAGS",
        "LLVM_PROFILE_FILE",
    ] {
        cmd.env_remove(var);
    }

    let out = cmd
        .args([
            "build",
            "--release",
            "--target",
            "wasm32-unknown-unknown",
            "-p",
            "sipnab-plugin-example",
        ])
        .output()
        .expect("spawn cargo");

    assert!(
        out.status.success(),
        "the documented build command failed — if this is a missing target, \
         `rustup target add wasm32-unknown-unknown` is what the docs tell a \
         reader to run:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let path = PathBuf::from(manifest)
        .join("target/wasm32-unknown-unknown/release/sipnab_plugin_example.wasm");
    assert!(
        path.is_file(),
        "build reported success but produced no artifact at {}",
        path.display()
    );
    path
}

/// One dialog in the shape `plugin_input_json` produces: answered, then a BYE
/// two seconds later.
fn short_call_input() -> String {
    serde_json::json!({
        "dialog": { "call_id": "short@example.com", "state": "Completed" },
        "messages": [
            { "index": 0, "is_request": true, "method": "INVITE", "status_code": null,
              "reason": null, "offset_ms": 0, "cseq_number": 1, "cseq_method": "INVITE",
              "headers": {} },
            { "index": 1, "is_request": false, "method": null, "status_code": 200,
              "reason": "OK", "offset_ms": 1000, "cseq_number": 1, "cseq_method": "INVITE",
              "headers": {} },
            { "index": 2, "is_request": true, "method": "BYE", "status_code": null,
              "reason": null, "offset_ms": 3000, "cseq_number": 2, "cseq_method": "BYE",
              "headers": {} }
        ]
    })
    .to_string()
}

/// Same call, torn down after a minute — a normal conversation.
///
/// Built from the same JSON value rather than by string-replacing the short
/// one. The first version patched `"offset_ms": 3000`, which `serde_json`
/// never emits — it writes `"offset_ms":3000` with no space — so the replace
/// silently did nothing and "normal call" was byte-identical to "short call".
/// The test still passed the case it was checking and proved nothing about the
/// case it was named for.
fn normal_call_input() -> String {
    let mut v: serde_json::Value =
        serde_json::from_str(&short_call_input()).expect("fixture is valid JSON");
    v["messages"][2]["offset_ms"] = serde_json::json!(61_000);
    v.to_string()
}

#[test]
fn wasm_plugin_documented_build_produces_a_plugin_this_host_accepts() {
    let path = build_example();
    let plugin = Plugin::load(&path).unwrap_or_else(|e| {
        panic!("the example plugin must load in a stock host (ABI v{ABI_VERSION}): {e}")
    });
    assert_eq!(plugin.name(), "sipnab_plugin_example");
}

#[test]
fn wasm_plugin_detects_a_short_answered_call_and_cites_its_evidence() {
    let plugin = Plugin::load(build_example()).expect("loads");
    let findings = plugin.analyze(&short_call_input()).expect("analyses");

    assert_eq!(findings.len(), 1, "expected one finding, got {findings:?}");
    let f = &findings[0];
    assert_eq!(f.id, "short-answered-call");
    // The answer and the BYE, which is what a reader needs to check the claim.
    assert_eq!(f.evidence, vec![1, 2]);
    assert!(
        f.summary.contains("2.0s"),
        "the summary must state the measured duration, got: {}",
        f.summary
    );
    // Attribution is the host's, from the file stem — never the plugin's own.
    assert_eq!(f.plugin, "sipnab_plugin_example");
}

#[test]
fn wasm_plugin_stays_quiet_on_a_normal_length_call() {
    let plugin = Plugin::load(build_example()).expect("loads");
    let findings = plugin
        .analyze(&normal_call_input())
        .expect("analyses a normal call");
    assert!(
        findings.is_empty(),
        "a 60s call is not a short call; a detection that fires on healthy \
         traffic teaches the reader to ignore it: {findings:?}"
    );
}

/// The example must survive input it did not expect, because a plugin that
/// traps on an odd dialog takes its findings out for every dialog like it.
#[test]
fn wasm_plugin_survives_unexpected_input() {
    let plugin = Plugin::load(build_example()).expect("loads");
    for weird in [
        "{}",
        r#"{"messages":[]}"#,
        r#"{"dialog":{},"messages":[{"index":0}]}"#,
        r#"{"messages":[{"index":0,"offset_ms":0,"status_code":200,"cseq_method":"INVITE","headers":{"X":"}{\"tricky\":1"}}]}"#,
    ] {
        let got = plugin.analyze(weird);
        assert!(
            got.is_ok(),
            "input {weird} produced {got:?}; a plugin must not trap on a shape \
             it did not anticipate"
        );
    }
}

/// The `--plugin` flag itself, end to end through the binary.
///
/// The tests above drive the host API directly, which proves the ABI but not
/// the wiring. This runs the real binary against a real capture and asserts the
/// finding reaches `--json-dialogs` output — the path a user actually takes.
///
/// `sip-over-tcp.pcap` holds a call answered and torn down in 2.2s, which is
/// what the example detects.
#[test]
fn wasm_plugin_flag_puts_findings_in_json_dialogs_output() {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let wasm = build_example();

    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .current_dir(manifest)
        .args([
            "-N",
            "-I",
            "tests/pcap-samples/sip-over-tcp.pcap",
            "--json-dialogs",
            "--no-cli-print",
            "--quiet",
            "--plugin",
        ])
        .arg(&wasm)
        .output()
        .expect("spawn sipnab");
    assert!(
        out.status.success(),
        "sipnab --plugin exited {:?}: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8(out.stdout).expect("utf8");
    let mut seen = 0;
    for line in stdout.lines().filter(|l| l.trim_start().starts_with('{')) {
        let v: serde_json::Value = serde_json::from_str(line).expect("dialog line parses");
        if let Some(findings) = v.get("plugin_findings").and_then(|f| f.as_array()) {
            for f in findings {
                assert_eq!(f["id"], "short-answered-call");
                assert_eq!(f["plugin"], "sipnab_plugin_example");
                assert!(
                    f["evidence"].as_array().is_some_and(|e| !e.is_empty()),
                    "a finding reaching the output must still cite evidence: {f}"
                );
                seen += 1;
            }
        }
    }
    assert_eq!(
        seen, 1,
        "expected exactly one short-call finding from this capture; got {seen}.\n{stdout}"
    );
}
