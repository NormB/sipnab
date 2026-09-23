// SPDX-License-Identifier: MIT OR Apache-2.0

//! Archive passwords on MCP, against the real binary over stdio.
//!
//! MCP takes no password from a tool call (OWASP LLM02:2025, and the MCP
//! specification's rule that credentials never pass through the client). A
//! call that carries one is refused before dispatch and the audit record of
//! the refusal holds no trace of it. The operator's configured password is
//! what opens an archive.
//!
//! The encrypted ZIP and its password are made here, at test time.
#![cfg(all(feature = "mcp", feature = "archive"))]

use std::io::Write;

#[path = "support/mcp.rs"]
mod support;

use support::{McpSession, ok_payload};

const FIRST: &str = "tests/pcap-samples/sip-rtp-g711.pcap";

/// A password nobody wrote down.
fn mint(label: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    label.hash(&mut h);
    std::process::id().hash(&mut h);
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
        .hash(&mut h);
    format!("mcp{:016x}{label}", h.finish())
}

/// A file root holding `evidence.zip`: the SIPp scenario, AES-locked.
fn root_with_locked_zip(tag: &str, password: &str) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!("sipnab-mcp-zip-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("mkdir");
    let pcap = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/pcap-samples/sipp-branch-scenario.pcapng"),
    )
    .expect("fixture");
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .with_aes_encryption(zip::AesMode::Aes256, password);
    w.start_file("calls/scenario.pcapng", opts).expect("start");
    w.write_all(&pcap).expect("write");
    std::fs::write(
        root.join("evidence.zip"),
        w.finish().expect("finish").into_inner(),
    )
    .expect("write zip");
    root
}

fn wait_for_load(session: &mut McpSession) -> serde_json::Value {
    for _ in 0..400 {
        let v = ok_payload(&session.call("capture_status", serde_json::json!({})));
        if v["load"]["done"] == true {
            return v;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    panic!("the load never finished");
}

#[test]
fn a_password_in_a_tool_call_is_refused_and_never_recorded() {
    let password = mint("arg");
    let root = root_with_locked_zip("arg", &password);
    let audit = root.join("audit.jsonl");
    let mut session = McpSession::start(
        FIRST,
        &[
            "--mcp-file-root",
            root.to_str().unwrap_or_default(),
            "--mcp-allow-open-capture",
            "--mcp-audit-file",
            audit.to_str().unwrap_or_default(),
        ],
    );
    let msg = session.call(
        "open_capture",
        serde_json::json!({"filename": "evidence.zip", "archive_password": password}),
    );
    let err = msg["error"]["message"].as_str().unwrap_or_default();
    assert!(err.contains("--archive-password-file"), "{msg}");
    assert!(!msg.to_string().contains(&password), "the reply echoed it");
    drop(session);
    let record = std::fs::read_to_string(&audit).expect("audit file");
    assert!(record.contains("open_capture"), "{record}");
    assert!(
        !record.contains(&password),
        "the audit record holds the password"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn the_operator_s_password_file_opens_the_archive() {
    let password = mint("file");
    let root = root_with_locked_zip("file", &password);
    let pw = root.join("pw");
    std::fs::write(&pw, format!("{password}\n")).expect("write");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&pw, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    }
    let mut session = McpSession::start(
        FIRST,
        &[
            "--mcp-file-root",
            root.to_str().unwrap_or_default(),
            "--mcp-allow-open-capture",
            "--archive-password-file",
            pw.to_str().unwrap_or_default(),
        ],
    );
    let msg = session.call(
        "open_capture",
        serde_json::json!({"filename": "evidence.zip"}),
    );
    assert!(msg["error"].is_null(), "{msg}");
    let status = wait_for_load(&mut session);
    assert!(status["load"]["error"].is_null(), "{status}");
    assert!(
        status["dialog_count"].as_u64().unwrap_or(0) > 100,
        "the scenario's dialogs were read: {status}"
    );
    let _ = std::fs::remove_dir_all(&root);
}
