// SPDX-License-Identifier: MIT OR Apache-2.0

//! Verify that the WASM JS bindings export all required functions.
//!
//! This test reads the generated sipnab.js file and checks that every
//! public API function name is present. Catches stale WASM builds where
//! new Rust functions were added but wasm-pack wasn't re-run.

/// The generated `website/static/wasm/sipnab.js` contains every required
/// public API function name. A missing WASM build is a hard failure: the
/// bundle ships with the site and must exist for this guard to mean anything,
/// so its absence fails loudly instead of silently skipping.
#[test]
fn wasm_js_exports_all_required_functions() {
    let js_path = std::path::Path::new("website/static/wasm/sipnab.js");
    assert!(
        js_path.exists(),
        "WASM build missing: {} not found. The website WASM bundle must be built and \
         present — this export guard cannot run without it, and the published site would \
         ship a stale/absent bundle. Build it with: wasm-pack build --target web \
         --out-dir website/static/wasm --no-typescript -- --no-default-features --features wasm",
        js_path.display()
    );

    let js = std::fs::read_to_string(js_path).expect("Failed to read sipnab.js");

    let required_functions = [
        "load_pcap",
        "get_dialogs",
        "get_call_flow",
        "get_raw_message",
        "filter",
        "export_json",
        "export_csv",
        "export_mermaid",
        "get_streams",
        "get_stream_detail",
        "stream_count",
        "rtp_packet_count",
    ];

    let mut missing = Vec::new();
    for func in &required_functions {
        // Look for the function definition pattern: `funcname(`
        let pattern = format!("{func}(");
        if !js.contains(&pattern) {
            missing.push(*func);
        }
    }

    assert!(
        missing.is_empty(),
        "WASM JS bindings are missing required exports: {missing:?}. \
         Rebuild with: wasm-pack build --target web --out-dir website/static/wasm \
         --no-typescript -- --no-default-features --features wasm"
    );
}

/// Every `getrandom` line in the lockfile that honours the `wasm_js` backend
/// cfg has that feature enabled for the wasm32 target.
///
/// `.cargo/config.toml` sets `--cfg getrandom_backend="wasm_js"` for
/// `wasm32-unknown-unknown`. Rustflags are per-target, so that cfg reaches
/// *every* getrandom in the graph, and any 0.3+ line that sees it without the
/// matching `wasm_js` feature refuses to compile. `Cargo.toml` enabled it on
/// 0.4 only, beneath a comment correctly naming ahash and 0.3 — so the fix
/// never applied to the version ahash actually resolves, and
/// `cargo check --target wasm32-unknown-unknown --lib` failed on main.
///
/// CI did not catch it because its wasm job compiled for the host, where the
/// `cfg(target_arch = "wasm32")` block is inert. That job now targets wasm32;
/// this test is the cheap static half, so a new major line entering the graph
/// fails here in seconds rather than only in the cross-compile.
#[test]
fn every_getrandom_line_enables_the_wasm_js_feature() {
    let lock = std::fs::read_to_string("Cargo.lock").expect("read Cargo.lock");
    let manifest = std::fs::read_to_string("Cargo.toml").expect("read Cargo.toml");

    // Major lines present in the graph. 0.2 predates the backend cfg and
    // ignores it, so only 0.3+ has to opt in.
    let ver_re = regex::Regex::new(r#"(?m)^name = "getrandom"\nversion = "(\d+)\.(\d+)\.\d+""#)
        .expect("version regex");
    let mut needed: Vec<String> = ver_re
        .captures_iter(&lock)
        .map(|c| format!("{}.{}", &c[1], &c[2]))
        .filter(|line| line.as_str() > "0.2")
        .collect();
    needed.sort();
    needed.dedup();

    assert!(
        !needed.is_empty(),
        "no getrandom 0.3+ found in Cargo.lock — extraction broken, or the \
         dependency is gone and this gate should be retired"
    );

    let missing: Vec<&String> = needed
        .iter()
        .filter(|line| {
            // Either the plain name or a `package = "getrandom"` alias, on a
            // line that also carries the feature.
            !manifest
                .lines()
                .any(|l| l.contains(&format!("version = \"{line}\"")) && l.contains("wasm_js"))
        })
        .collect();

    assert!(
        missing.is_empty(),
        "getrandom {missing:?} is in the graph but Cargo.toml does not enable its \
         `wasm_js` feature for wasm32. The rustflag in .cargo/config.toml applies \
         to every getrandom, so this line will fail `cargo build --target \
         wasm32-unknown-unknown --lib` with \"the wasm_js backend requires the \
         wasm_js feature\". Add it under [target.'cfg(target_arch = \"wasm32\")'.dependencies], \
         aliasing with `package = \"getrandom\"` if another major line is already declared."
    );
}
