// SPDX-License-Identifier: MIT OR Apache-2.0

//! `--mcp-tools core` must actually register fewer tools.
//!
//! The failure this file exists for is a profile that parses, is stored, is
//! reported in help, and changes nothing a client can see. Every registered
//! tool's schema is sent on `tools/list` and then carried in the model's
//! context for the whole session, so a `core` profile that still registers
//! fifty tools costs exactly what `full` costs while telling the operator it
//! does not.
//!
//! So every assertion here COUNTS THE ROUTER. A test that read the flag back,
//! or compared against `CORE_TOOLS`, would pass on a build where
//! `with_tool_profile` removed nothing at all — the two sets it compared would
//! both be derived from the same list, and the router would never be asked.

#![cfg(feature = "mcp")]

use parking_lot::RwLock;
use sipnab::mcp::SipnabMcp;
use sipnab::mcp::profile::{CORE_TOOLS, ToolProfile, orphaned_core_tools};
use sipnab::rtp::stream_store::StreamStore;
use sipnab::sip::dialog_store::DialogStore;
use std::sync::Arc;

/// A server with the given profile applied.
fn server(profile: ToolProfile) -> SipnabMcp {
    SipnabMcp::new(
        Arc::new(RwLock::new(DialogStore::new(64, false))),
        Arc::new(RwLock::new(StreamStore::new(64))),
    )
    .with_tool_profile(profile)
}

/// `core` registers strictly fewer tools than `full`.
///
/// The load-bearing assertion, and it is a comparison of two ROUTERS rather
/// than of two lists: both numbers come from asking a built server what it
/// would advertise.
#[test]
fn core_registers_fewer_tools_than_full() {
    let full = server(ToolProfile::Full).registered_tool_names();
    let core = server(ToolProfile::Core).registered_tool_names();

    assert!(
        full.len() > 20,
        "the full router registered only {} tools -- this comparison is \
         reading an empty router, not a profile: {full:?}",
        full.len()
    );
    assert!(
        core.len() < full.len(),
        "core registered {} of {} tools -- the profile changed nothing a \
         client can see",
        core.len(),
        full.len()
    );
    assert_eq!(
        core.len(),
        CORE_TOOLS.len(),
        "core must register exactly the core set: {core:?}"
    );
}

/// `full` is what a server registers when nothing asks otherwise, so an
/// upgrade does not silently take tools away.
#[test]
fn full_is_the_default_and_removes_nothing() {
    let untouched = SipnabMcp::new(
        Arc::new(RwLock::new(DialogStore::new(64, false))),
        Arc::new(RwLock::new(StreamStore::new(64))),
    )
    .registered_tool_names();

    assert_eq!(
        server(ToolProfile::Full).registered_tool_names(),
        untouched,
        "applying the default profile must be indistinguishable from applying \
         none"
    );
    assert_eq!(
        ToolProfile::default(),
        ToolProfile::Full,
        "a server built with no profile registers everything"
    );
}

/// Every name in the core set is a tool the server actually has.
///
/// The rot `core_registers_fewer_tools_than_full` cannot see: rename a tool
/// and the core profile simply stops carrying it — the count still drops, the
/// comparison still passes, and `core` has quietly lost a step of the path it
/// was built around.
#[test]
fn every_core_tool_is_a_registered_tool() {
    let full = server(ToolProfile::Full).registered_tool_names();
    assert!(
        orphaned_core_tools(&full).is_empty(),
        "these core tools are not registered under any name: {:?}. The core \
         profile is built around a path through a call, and a missing step \
         leaves an agent improvising",
        orphaned_core_tools(&full)
    );
}

/// A `core` server carries every core tool and nothing else.
#[test]
fn the_core_router_holds_exactly_the_core_set() {
    let core = server(ToolProfile::Core).registered_tool_names();
    for name in CORE_TOOLS {
        assert!(
            core.iter().any(|r| r == name),
            "core must register {name}: {core:?}"
        );
    }
    for name in &core {
        assert!(
            CORE_TOOLS.contains(&name.as_str()),
            "core registered {name}, which is not in the core set"
        );
    }
}

/// The tools `core` drops are gone from the router, not merely absent from a
/// list somewhere. `shutdown_server` is the one that matters most: a profile
/// that advertised it while claiming to be minimal would be handing a small
/// client the largest hazard on the surface.
#[test]
fn core_drops_the_state_changing_tools() {
    let core = server(ToolProfile::Core).registered_tool_names();
    for name in [
        "shutdown_server",
        "open_capture",
        "export_capture",
        "save_findings",
    ] {
        assert!(
            !core.iter().any(|r| r == name),
            "core must not register {name}: {core:?}"
        );
    }
}

// ── The flag reaches the router ──────────────────────────────────────

/// Tools a spawned `sipnab --mcp` advertises on `tools/list`.
///
/// Drives the real binary because that is the only thing that can prove the
/// FLAG reaches `with_tool_profile`. `core_registers_fewer_tools_than_full`
/// above proves the builder works and would keep passing on a build where
/// `--mcp-tools` was parsed, stored, and never read.
#[cfg(unix)]
fn advertised_tools(profile: &str) -> Vec<String> {
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    let pcap = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/sip_call.pcap")
        .to_string_lossy()
        .into_owned();

    let mut child = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args([
            "-N",
            "-I",
            &pcap,
            "--mcp",
            "--mcp-transport",
            "stdio",
            "--mcp-tools",
            profile,
            "--quiet",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn sipnab --mcp");

    {
        let stdin = child.stdin.as_mut().expect("stdin");
        for msg in [
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "profile-test", "version": "0"}
                }
            }),
            serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
        ] {
            writeln!(stdin, "{}", serde_json::to_string(&msg).expect("serialize")).expect("write");
        }
        stdin.flush().expect("flush");
    }

    let mut stdout = child.stdout.take().expect("stdout");
    let mut reader = BufReader::new(&mut stdout);
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut names = None;
    let mut line = String::new();
    while Instant::now() < deadline {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let v: serde_json::Value = serde_json::from_str(trimmed)
                    .unwrap_or_else(|e| panic!("stdout is the JSON-RPC wire: {e}\n{trimmed}"));
                if v.get("id").and_then(serde_json::Value::as_i64) == Some(2) {
                    names = Some(
                        v["result"]["tools"]
                            .as_array()
                            .unwrap_or_else(|| panic!("tools/list returns an array: {v}"))
                            .iter()
                            .filter_map(|t| t["name"].as_str().map(str::to_string))
                            .collect::<Vec<String>>(),
                    );
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let _ = child.kill();
    let _ = child.wait();

    names.unwrap_or_else(|| panic!("`sipnab --mcp-tools {profile}` never answered tools/list"))
}

/// `--mcp-tools core` reaches the router: a real client sees fewer tools.
///
/// The counts come from `tools/list` on two spawned servers, so a flag that
/// parsed and was never read fails here.
#[cfg(unix)]
#[test]
fn the_flag_changes_what_a_client_is_offered() {
    let full = advertised_tools("full");
    let core = advertised_tools("core");

    assert!(
        full.len() > 20,
        "the full server advertised only {} tools -- this comparison is not \
         reading a real tool list: {full:?}",
        full.len()
    );
    assert!(
        core.len() < full.len(),
        "--mcp-tools core advertised {} of {} tools -- the flag never reached \
         the router",
        core.len(),
        full.len()
    );
    assert_eq!(
        core.len(),
        CORE_TOOLS.len(),
        "a core client is offered exactly the core set: {core:?}"
    );
}
