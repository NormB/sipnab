// SPDX-License-Identifier: MIT OR Apache-2.0

//! MCP `export_vcon` names a call's other leg, as the batch export and the
//! REST route do: one container per leg, each carrying the other's uuid in
//! its related-legs attachment.
#![cfg(all(feature = "native", feature = "mcp", feature = "vcon"))]

#[path = "support/mcp.rs"]
mod mcp;
#[path = "support/pcap_build.rs"]
mod pcap_build;

use mcp::{McpSession, TestError};

/// The container `export_vcon` returns for `call_id`.
fn container(session: &mut McpSession, call_id: &str) -> Result<serde_json::Value, TestError> {
    let msg = session.call(
        "export_vcon",
        serde_json::json!({ "call_id": call_id, "media": "omit" }),
    )?;
    assert!(msg.get("error").is_none(), "export_vcon answers: {msg}");
    let text = msg["result"]["content"][0]["text"]
        .as_str()
        .ok_or("text payload")?;
    let page: serde_json::Value = serde_json::from_str(text)?;
    Ok(page["containers"][0]["container"].clone())
}

#[test]
fn export_vcon_names_the_other_leg() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let pcap = dir.path().join("legs.pcap");
    pcap_build::write_two_linked_legs(&pcap)?;
    let cfg = dir.path().join("sipnab.toml");
    std::fs::write(&cfg, "[sip]\nxcid_headers = [\"X-Call-ID\"]\n")?;
    let mut session = McpSession::start(
        pcap.to_str().ok_or("utf-8 path")?,
        &["--config", cfg.to_str().ok_or("utf-8 path")?],
    )?;
    let a = container(&mut session, "a-leg")?;
    let b = container(&mut session, "b-leg")?;
    for (this, other) in [(&a, &b), (&b, &a)] {
        let attachment = this["attachments"]
            .as_array()
            .ok_or("attachments")?
            .iter()
            .find(|x| x["purpose"] == "sipnab-related-legs")
            .ok_or("a related-legs attachment")?;
        let body = &attachment["body"];
        assert_eq!(body["legs"][0]["uuid"], other["uuid"], "{body}");
        assert_eq!(body["legs"][0]["identifier_match"], true, "{body}");
    }
    Ok(())
}
