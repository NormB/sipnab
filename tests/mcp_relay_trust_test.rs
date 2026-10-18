// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! What `server_capabilities` reports about relay assertions, end to end.
//!
//! An endpoint a relay asserts over HEP is worth what the HEP listener's
//! authentication makes it worth: `hmac-verified` with `--hep-auth-mode hmac`,
//! `plain-secret` with a shared secret, `port-gated-only` with none. The run
//! decides that once, at startup, from its flags; these tests start the binary
//! with each posture and read what the MCP server says back. Until 2026-10-11
//! the server was built without the posture, so every run reported
//! `port-gated-only`, `--hep-auth-mode hmac` included.
#![cfg(all(feature = "mcp", feature = "hep"))]

#[path = "support/mcp_reference.rs"]
mod mcp_reference;
#[path = "support/mcp.rs"]
mod support;

use support::{McpSession, ok_payload};

/// Any error a test can return; `?` converts into it.
type TestError = Box<dyn std::error::Error>;

/// `server_capabilities.runtime` of a `sipnab --mcp` run listening for HEP
/// with `extra` flags.
fn runtime_listening(extra: &[&str]) -> Result<serde_json::Value, TestError> {
    // Port 0: the kernel picks a port the run holds from the moment it
    // exists. A number reserved and released first could be taken by a
    // parallel test, and sipnab then exited before answering.
    let mut argv = vec!["--mcp", "-N", "--quiet", "-L", "127.0.0.1:0"];
    argv.extend_from_slice(extra);
    let payload = ok_payload(
        &McpSession::start_live(&argv)?.call("server_capabilities", serde_json::json!({}))?,
    )?;
    Ok(payload["runtime"].clone())
}

/// A file holding the HEP shared secret, so the secret is not on the command
/// line.
fn secret_file() -> Result<tempfile::NamedTempFile, TestError> {
    let mut f = tempfile::NamedTempFile::new()?;
    std::io::Write::write_all(&mut f, b"relay-trust-test-secret\n")?;
    Ok(f)
}

/// `--hep-auth-mode hmac` with a secret: an authenticated, replay-resistant path.
#[test]
fn hmac_authentication_is_reported_as_hmac_verified() -> Result<(), TestError> {
    let secret = secret_file()?;
    let path = secret.path().to_str().ok_or("temp path is not UTF-8")?;
    let runtime = runtime_listening(&["--hep-auth-file", path, "--hep-auth-mode", "hmac"])?;
    assert_eq!(runtime["hep_delivery_trust"], "hmac-verified", "{runtime}");
    Ok(())
}

/// A secret with the default `plain` mode: compared byte for byte, replayable.
#[test]
fn a_shared_secret_is_reported_as_plain_secret() -> Result<(), TestError> {
    let secret = secret_file()?;
    let path = secret.path().to_str().ok_or("temp path is not UTF-8")?;
    let runtime = runtime_listening(&["--hep-auth-file", path])?;
    assert_eq!(runtime["hep_delivery_trust"], "plain-secret", "{runtime}");
    Ok(())
}

/// `--hep-auth-mode` defaults to `plain`, but without a secret nothing is
/// checked, so the default mode must not be reported as an authenticated path.
#[test]
fn a_listener_without_a_secret_is_reported_as_port_gated_only() -> Result<(), TestError> {
    let runtime = runtime_listening(&[])?;
    assert_eq!(
        runtime["hep_delivery_trust"], "port-gated-only",
        "{runtime}"
    );
    Ok(())
}

/// `query_relay`, `relay_stats` and `relay_compare` need
/// `--mcp-allow-relay-query`; the runtime block names it as it names every
/// other opt-in, so an agent can check before it is refused.
#[test]
fn the_relay_query_opt_in_is_reported() -> Result<(), TestError> {
    let runtime = runtime_listening(&[])?;
    assert_eq!(runtime["mcp_allow_relay_query"], false, "{runtime}");
    Ok(())
}

/// The guides state what each tool does without claiming it is the only one
/// that does it: three relay tools transmit, and several tools besides
/// `save_findings` change state or write files.
#[test]
fn the_guides_claim_no_tool_is_the_only_one_that_transmits_or_writes() -> Result<(), TestError> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    const CLAIMS: [&str; 3] = [
        "only tool that transmits",
        "only write verb",
        "no mcp tool puts a packet",
    ];
    // The MCP tool reference is an index page plus one page per bundle.
    let mut pages = mcp_reference::pages();
    pages.extend(["docs/cli-reference.md".into(), "docs/mcp-deploy.md".into()]);
    for page in &pages {
        let text = std::fs::read_to_string(root.join(page))?.to_lowercase();
        for claim in CLAIMS {
            assert!(!text.contains(claim), "{page} still says \"{claim}\"");
        }
    }
    let help = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .arg("--help")
        .output()?;
    let help = String::from_utf8_lossy(&help.stdout).to_lowercase();
    assert!(
        help.contains("--mcp-allow-save-findings"),
        "the help was not read"
    );
    for claim in CLAIMS {
        assert!(
            !help.contains(claim),
            "sipnab --help still says \"{claim}\""
        );
    }
    Ok(())
}
