//! Feature-gate UX: a flag whose subsystem is not compiled in must fail fast
//! with a clear error and exit code 2 — never degrade into a silent no-op.
//! These tests run the real binary, so they exercise the same path a user
//! hits; each is cfg-gated to builds where the relevant feature is ABSENT.
#![cfg(feature = "native")]

#[cfg(any(not(feature = "mcp"), not(feature = "hep")))]
use std::process::Command;

#[cfg(not(feature = "mcp"))]
const FIXTURE: &str = "tests/fixtures/sip_call.pcap";

/// Run the binary and assert it exits with code 2 and an stderr message
/// containing `needle`.
#[cfg(any(not(feature = "mcp"), not(feature = "hep")))]
fn assert_gate_failure(args: &[&str], needle: &str) {
    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(args)
        .env("SIPNAB_LOG", "error")
        .env("NO_COLOR", "1")
        .output()
        .expect("spawn sipnab");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(2),
        "sipnab {args:?} must exit 2 (feature gate), got {:?}; stderr:\n{stderr}",
        out.status.code()
    );
    assert!(
        stderr.contains(needle),
        "stderr must mention '{needle}':\n{stderr}"
    );
}

/// `--mcp` in a build without the mcp feature used to run a plain batch
/// capture — no server, no warning, per-message output on what the user
/// believes is the JSON-RPC channel.
#[cfg(not(feature = "mcp"))]
#[test]
fn mcp_flag_without_mcp_feature_fails_fast() {
    assert_gate_failure(&["--mcp", "-N", "-I", FIXTURE], "mcp");
}

/// `--hep-listen` used to gate only at capture spawn, after config/privilege
/// setup; it must gate early beside --hep-send/--hep-parse with exit 2.
#[cfg(not(feature = "hep"))]
#[test]
fn hep_listen_without_hep_feature_fails_fast() {
    assert_gate_failure(&["-N", "-L", "127.0.0.1:9060"], "hep");
}
