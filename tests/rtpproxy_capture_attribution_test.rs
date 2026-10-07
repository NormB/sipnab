// SPDX-License-Identifier: MIT OR Apache-2.0

//! `--rtpproxy-control` names rtpproxy's media in a capture (RP-WIRE).
//!
//! Written before the flag exists. Until it did, sipnab decoded rtpproxy's
//! control protocol and nothing in the binary called the decoder, so media an
//! rtpproxy relayed was reported as orphaned whatever the capture held.
//!
//! The command and reply shapes are the ones the lab relay (rtpproxy 3.2.0)
//! answered on 2026-09-28: `U` with a Call-ID, answered by `<port> <address>`.
//! Every capture here is built in the test from documentation addresses.

#![cfg(feature = "native")]

use std::path::{Path, PathBuf};
use std::process::Command;

#[path = "support/pcap_build.rs"]
mod pcap_build;

use pcap_build::{udp_frame, write_pcap_or_panic};

const CALL_ID: &str = "rp-wire-e2e@192.0.2.10";
const PROXY_IP: [u8; 4] = [192, 0, 2, 10];
const RELAY_IP: [u8; 4] = [192, 0, 2, 40];
const CONTROL_PORT: u16 = 7722;
const MEDIA_PORT: u16 = 49514;
const PARTY_IP: [u8; 4] = [192, 0, 2, 60];
const PARTY_PORT: u16 = 40000;

/// The proxy's `U` command and the relay's reply on `control_port`, then
/// media on the port the reply names.
fn frames_on(control_port: u16) -> Vec<Vec<u8>> {
    let command = format!("c1 U {CALL_ID} 192.0.2.60 {PARTY_PORT} ftag1\n");
    let reply = format!("c1 {MEDIA_PORT} 192.0.2.40\n");
    let mut frames = vec![
        udp_frame(PROXY_IP, RELAY_IP, 43000, control_port, command.as_bytes()),
        udp_frame(RELAY_IP, PROXY_IP, control_port, 43000, reply.as_bytes()),
    ];
    for seq in 0u16..20 {
        for (src, sport, dst, dport, ssrc) in [
            (PARTY_IP, PARTY_PORT, RELAY_IP, MEDIA_PORT, 0x1111_2222u32),
            (RELAY_IP, MEDIA_PORT, PARTY_IP, PARTY_PORT, 0x3333_4444u32),
        ] {
            let mut rtp = vec![0x80, 0x00];
            rtp.extend_from_slice(&seq.to_be_bytes());
            rtp.extend_from_slice(&(u32::from(seq) * 160).to_be_bytes());
            rtp.extend_from_slice(&ssrc.to_be_bytes());
            rtp.extend_from_slice(&[0xff; 160]);
            frames.push(udp_frame(src, dst, sport, dport, &rtp));
        }
    }
    frames
}

fn capture() -> (tempfile::TempDir, PathBuf) {
    capture_on(CONTROL_PORT)
}

fn capture_on(control_port: u16) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("rtpproxy.pcap");
    write_pcap_or_panic(&path, &frames_on(control_port));
    (dir, path)
}

/// Run sipnab over `path` with `--report`, returning `(success, stdout, stderr)`.
fn run(path: &Path, extra: &[&str]) -> (bool, String, String) {
    let mut args: Vec<String> = vec![
        "-N".into(),
        "-I".into(),
        path.to_string_lossy().into_owned(),
        "--no-cli-print".into(),
        "--report".into(),
    ];
    args.extend(extra.iter().map(|s| (*s).to_owned()));
    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(&args)
        .env("SIPNAB_LOG", "warn")
        .output()
        .expect("run sipnab");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn assert_named(stdout: &str, how: &str) {
    assert!(
        stdout.contains(CALL_ID),
        "{how}: the relay's reply must name the call; report was:\n{stdout}"
    );
    assert!(
        !stdout.contains("Orphaned Streams"),
        "{how}: and its media must stop being orphaned; report was:\n{stdout}"
    );
}

fn assert_not_named(stdout: &str, how: &str) {
    assert!(
        !stdout.contains(CALL_ID),
        "{how}: nothing may name the call; report was:\n{stdout}"
    );
    assert!(
        stdout.contains("Orphaned Streams"),
        "{how}: so its media stays orphaned; report was:\n{stdout}"
    );
}

/// The positive control every refusal below is measured against.
#[test]
fn naming_the_relays_control_socket_names_the_call_its_media_belongs_to() {
    let (_dir, path) = capture();
    let (ok, stdout, stderr) = run(&path, &["--rtpproxy-control", "192.0.2.40:7722"]);
    assert!(ok, "sipnab failed; stderr:\n{stderr}");
    assert_named(&stdout, "--rtpproxy-control 192.0.2.40:7722");
}

/// The same bytes without the flag: sipnab believes only the socket it is
/// told, so nothing is believed and the media is back to orphaned.
#[test]
fn without_the_flag_the_same_capture_names_nothing() {
    let (_dir, path) = capture();
    let (ok, stdout, stderr) = run(&path, &[]);
    assert!(ok, "sipnab failed; stderr:\n{stderr}");
    assert_not_named(&stdout, "no flag");
}

/// rtpproxy's UDP control socket listens on 22222 when started without a
/// port (`rtpproxy.8`; `CPORT` in `rtpp_defines.h`). sipnab still does not
/// assume it (`src/relay/rtpproxy.rs`): a datagram believed at a guessed
/// socket names a call, and anything that can send to that port could send
/// it. Control traffic on 22222 names nothing until `--rtpproxy-control`
/// names that socket.
#[test]
fn the_default_port_is_not_assumed() {
    let (_dir, path) = capture_on(22222);
    let (ok, stdout, stderr) = run(&path, &[]);
    assert!(ok, "sipnab failed; stderr:\n{stderr}");
    assert_not_named(&stdout, "22222, no flag");
    let (ok, stdout, stderr) = run(&path, &["--rtpproxy-control", "192.0.2.40:22222"]);
    assert!(ok, "sipnab failed; stderr:\n{stderr}");
    assert_named(&stdout, "--rtpproxy-control 192.0.2.40:22222");
}

/// Naming a different socket believes none of this relay's datagrams.
#[test]
fn naming_another_socket_names_nothing() {
    let (_dir, path) = capture();
    for other in ["192.0.2.40:7723", "192.0.2.41:7722"] {
        let (ok, stdout, stderr) = run(&path, &["--rtpproxy-control", other]);
        assert!(ok, "sipnab failed; stderr:\n{stderr}");
        assert_not_named(&stdout, other);
    }
}

/// The sharded path reaches the same answer as the single-threaded one.
#[test]
fn the_sharded_path_names_the_call_too() {
    let (_dir, path) = capture();
    let (ok, stdout, stderr) = run(
        &path,
        &["--rtpproxy-control", "192.0.2.40:7722", "--cores", "2"],
    );
    assert!(ok, "sipnab failed; stderr:\n{stderr}");
    assert_named(&stdout, "--cores 2");
}

/// A value that is not an address and port is refused, not ignored.
#[test]
fn a_value_that_is_not_a_socket_address_is_refused() {
    let (_dir, path) = capture();
    for bad in ["192.0.2.40", "relay.example:7722", "7722"] {
        let (ok, _, stderr) = run(&path, &["--rtpproxy-control", bad]);
        assert!(!ok, "{bad:?} must be refused");
        assert!(
            stderr.contains("--rtpproxy-control"),
            "{bad:?}: the refusal names the flag; stderr:\n{stderr}"
        );
    }
}
