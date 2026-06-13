#![cfg(all(unix, feature = "api"))]
//! Phase 8.0a regression tests — single-parse / shared-store invariants.
//!
//! Pre-8.0a behavior: in batch mode with `--api`, every SIP/RTP packet was
//! parsed twice — once into a local store via `process_parsed_packet`, then
//! again into a shared `Arc<RwLock<...>>` store via `mirror_to_shared_stores`,
//! producing a measurable throughput penalty and the risk of the two stores
//! diverging.
//!
//! Post-8.0a: batch mode writes to a single `Arc<RwLock<...>>` store from the
//! start; the API server reads from the SAME store. These tests prove the
//! refactor is behavior-preserving by comparing JSON output across the
//! `--api` / no-`--api` boundary on a fixture pcap.

use std::path::PathBuf;
use std::process::Command;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn run_sipnab(args: &[&str]) -> (String, String, i32) {
    let binary = env!("CARGO_BIN_EXE_sipnab");
    let output = Command::new(binary)
        .args(args)
        .env("SIPNAB_LOG", "warn")
        .output()
        .expect("failed to execute sipnab");
    (
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
        output.status.code().unwrap_or(-1),
    )
}

/// Strip volatile JSON fields (timestamps, durations) so two runs of the same
/// pcap produce comparable output. Each `event` line is parsed and a small
/// allowlist of identifying fields is retained.
fn canonicalize_ndjson(s: &str) -> Vec<String> {
    s.lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| {
            let v: serde_json::Value = serde_json::from_str(line).ok()?;
            // Project to fields that should be invariant across runs:
            // - call_id (canonical dialog identifier)
            // - method or status (message type)
            // - from / to (parties)
            // The `time` field is stripped because pcap replay timestamps
            // are deterministic but represented to microseconds and any
            // downstream formatting could vary.
            let proj = serde_json::json!({
                "call_id": v.get("call_id"),
                "method": v.get("method"),
                "status": v.get("status"),
                "from": v.get("from"),
                "to": v.get("to"),
                "src_addr": v.get("src_addr"),
                "dst_addr": v.get("dst_addr"),
            });
            Some(proj.to_string())
        })
        .collect()
}

/// Phase 8.0a — Gate: JSON NDJSON output is identical between batch-only
/// and batch+API modes for the same fixture pcap. This proves the refactor
/// did not lose or duplicate any messages.
#[test]
fn batch_json_output_matches_batch_with_api_json_output() {
    let pcap = fixtures_dir().join("sip_call.pcap");
    let pcap_str = pcap.to_string_lossy().to_string();

    let (stdout_no_api, _, code_a) = run_sipnab(&["-N", "-I", &pcap_str, "--json"]);
    assert_eq!(code_a, 0, "batch-only run failed");

    // With --api on a random port; the server starts but we never query it.
    // The capture still completes because batch mode exits when the pcap is
    // exhausted (the API thread keeps the process alive after — but we use
    // --autostop-duration to bound this in case the API path changed it).
    //
    // Note: with --api set, sipnab keeps the API thread alive indefinitely
    // after the pcap finishes (intentional — clients can query post-mortem).
    // To avoid hanging the test, we rely on the existence of `--api :0` to
    // bind a random port and we invoke with a timeout via `--autostop-duration`.
    let (stdout_with_api, _stderr_b, _code_b) = run_sipnab_with_timeout(
        &[
            "-N",
            "-I",
            &pcap_str,
            "--json",
            "--api",
            "127.0.0.1:0",
            "--autostop",
            "duration:1",
        ],
        std::time::Duration::from_secs(15),
    );

    let canon_a = canonicalize_ndjson(&stdout_no_api);
    let canon_b = canonicalize_ndjson(&stdout_with_api);
    assert!(!canon_a.is_empty(), "no SIP events in batch-only output");
    assert_eq!(
        canon_a, canon_b,
        "JSON output differs between --api and no-api runs:\n  no-api: {:#?}\n  api:    {:#?}",
        canon_a, canon_b
    );
}

/// Run sipnab with a wall-clock timeout. Sends SIGTERM first (graceful)
/// to allow stdout flush; SIGKILLs as a last resort.
fn run_sipnab_with_timeout(args: &[&str], timeout: std::time::Duration) -> (String, String, i32) {
    use std::io::Read;

    let binary = env!("CARGO_BIN_EXE_sipnab");
    let mut child = Command::new(binary)
        .args(args)
        .env("SIPNAB_LOG", "warn")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn sipnab");

    let pid = child.id() as i32;

    let start = std::time::Instant::now();
    let mut sigtermed = false;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if start.elapsed() > timeout {
                    if !sigtermed {
                        // SAFETY: kill(pid, SIGTERM) on a child we own. Process may
                        // have already exited; -1 errno is fine.
                        unsafe {
                            libc::kill(pid, libc::SIGTERM);
                        }
                        sigtermed = true;
                        // Give it up to 3s to flush and exit gracefully.
                        std::thread::sleep(std::time::Duration::from_millis(500));
                    } else if start.elapsed() > timeout + std::time::Duration::from_secs(3) {
                        let _ = child.kill();
                        let _ = child.wait();
                        break;
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(_) => break,
        }
    }

    let mut stdout = String::new();
    let mut stderr = String::new();
    if let Some(mut s) = child.stdout.take() {
        let _ = s.read_to_string(&mut stdout);
    }
    if let Some(mut s) = child.stderr.take() {
        let _ = s.read_to_string(&mut stderr);
    }
    let code = child
        .try_wait()
        .ok()
        .flatten()
        .and_then(|s| s.code())
        .unwrap_or(-9);
    (stdout, stderr, code)
}

/// Sanity check: the same pcap, same flags, two runs produce identical
/// canonicalized JSON. If this fails, parse_path tests aren't meaningful.
#[test]
fn batch_json_output_is_deterministic() {
    let pcap = fixtures_dir().join("sip_call.pcap");
    let pcap_str = pcap.to_string_lossy().to_string();
    let (a, _, _) = run_sipnab(&["-N", "-I", &pcap_str, "--json"]);
    let (b, _, _) = run_sipnab(&["-N", "-I", &pcap_str, "--json"]);
    assert_eq!(canonicalize_ndjson(&a), canonicalize_ndjson(&b));
}
