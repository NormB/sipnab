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
