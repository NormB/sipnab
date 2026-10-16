// SPDX-License-Identifier: MIT OR Apache-2.0

//! `--cores N` refuses every flag its parallel reader does not carry out.
//!
//! The parallel reader rebuilds dialogs and RTP streams per shard and prints
//! the whole-capture views (`--report`, `--json-dialogs`, `--analyze` and the
//! like). It does not print per-message output, decode DTMF, run exec hooks,
//! serve REST or MCP, forward HEP, decrypt, replay, confine itself or act on
//! a source. Each of those flags used to be skipped without a word and the
//! run exited 0, so an empty result read as a finding. Each is now refused
//! with exit 2, naming the flag.

use std::process::Command;

/// The error a test returns.
type TestError = Box<dyn std::error::Error>;

fn fixture(name: &str) -> String {
    format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

/// Exit code and stderr of `sipnab -N -I sip_call.pcap --cores 2 <extra>`.
fn cores_run(extra: &[&str]) -> Result<(i32, String), TestError> {
    let state = tempfile::tempdir()?;
    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(["-N", "-I", &fixture("sip_call.pcap"), "--cores", "2"])
        .args(extra)
        .env("XDG_STATE_HOME", state.path())
        .env("XDG_CONFIG_HOME", state.path())
        .env("HOME", state.path())
        .output()?;
    Ok((
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    ))
}

/// Every flag the parallel reader ignores, with what it needs to parse. The
/// first element is the name the refusal must carry.
const IGNORED: &[&[&str]] = &[
    &["--hexdump"],
    &["--group-by", "call-id"],
    &["--match", "INVITE"],
    &["--from", "1001"],
    &["--to", "1002"],
    &["--contact", "1001"],
    &["--ua", "x"],
    &["--tag", "t"],
    &["--telephone-event"],
    &["--on-dialog-exec", "true"],
    &["--on-quality-exec", "true"],
    &["--wireshark"],
    &["--tshark-filter", "sip"],
    &["--recommend-block", "all"],
    &["--hep-send", "127.0.0.1:9"],
    &["--api", "127.0.0.1:0"],
    &["--evidence-out", "-"],
    &["--srtp-keys", "/nonexistent"],
    &["--dtls-keylog", "/nonexistent"],
    &["--keylog", "/nonexistent"],
    &["--tls-key", "/nonexistent"],
    &["--replay"],
    &["--syslog"],
    &["--relay-compare", "x"],
    &["--sandbox", "best-effort"],
    &["--seccomp", "log"],
    &["--chroot", "/nonexistent"],
    &["--user", "nobody"],
];

#[test]
fn every_flag_the_parallel_reader_ignores_is_refused_by_name() -> Result<(), TestError> {
    let mut accepted = Vec::new();
    for flag in IGNORED {
        let (code, stderr) = cores_run(flag)?;
        if code != 2 || !stderr.contains(flag[0]) {
            accepted.push(format!("{} (exit {code})", flag.join(" ")));
        }
    }
    assert!(
        accepted.is_empty(),
        "--cores 2 did not refuse these by name with exit 2:\n{}",
        accepted.join("\n")
    );
    Ok(())
}

/// The whole-capture views are what `--cores` is for, and they still run.
#[test]
fn the_whole_capture_views_still_run_under_cores() -> Result<(), TestError> {
    for view in [&["--report"][..], &["--json-dialogs"], &["--analyze"]] {
        let (code, stderr) = cores_run(view)?;
        assert_eq!(code, 0, "{view:?}: {stderr}");
    }
    Ok(())
}
