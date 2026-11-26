// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Issue #926, end to end: a SIP request larger than the MTU, as IP
//! fragments, through a capture filter and the whole pipeline.
//!
//! A live capture cannot be driven from a test (it needs an interface, a
//! sender and privileges), so the kernel's half is replayed through the one
//! piece that decides it: the capture filter. sipnab applies a filter given
//! after the options to a file it reads with `-I`, through the same
//! `pcap_compile` and `pcap_setfilter` a live handle uses. The generated
//! filter is taken from the library, the exact string a live capture
//! installs, and handed to `-I` that way.
//!
//! Each capture holds the issue's OPTIONS (Call-ID `frag-0a1b2c3d`) and its
//! 200 OK. With every fragment through, the dialog has two messages; with
//! only the first fragment through, it has one, the reply.

#![cfg(feature = "native")]

use std::path::Path;
use std::process::Command;

#[path = "support/pcap_build.rs"]
mod pcap_build;
#[path = "support/run.rs"]
mod run_support;

/// Any error a test can return; `?` converts into it.
type TestError = Box<dyn std::error::Error>;

/// The request's Call-ID.
const CALL_ID: &str = "frag-0a1b2c3d";

/// The clause sipnab's warning tells an operator to add.
const CLAUSE: &str = "(ip[6:2] & 0x1fff != 0) or (ip6[6] = 44)";

/// The sender (`192.0.2.20`) and the capture host (`192.0.2.10`).
const SENDER: [u8; 4] = [192, 0, 2, 20];
const RECEIVER: [u8; 4] = [192, 0, 2, 10];

/// The OPTIONS from the issue's reproduction script, byte for byte.
fn options() -> Vec<u8> {
    let dst = "192.0.2.10";
    let b = "0a1b2c3d";
    format!(
        "OPTIONS sip:t@{dst}:5060 SIP/2.0\r\n\
         Via: SIP/2.0/UDP 192.0.2.20:5060;branch=z9hG4bK{b}\r\n\
         Max-Forwards: 70\r\nFrom: <sip:t@192.0.2.20>;tag={b}\r\nTo: <sip:t@{dst}>\r\n\
         Call-ID: frag-{b}\r\nCSeq: 1 OPTIONS\r\n\
         X-Pad: {}\r\nContent-Length: 0\r\n\r\n",
        "X".repeat(3200)
    )
    .into_bytes()
}

/// The 200 OK the capture host sent back.
fn reply() -> Vec<u8> {
    b"SIP/2.0 200 OK\r\n\
      Via: SIP/2.0/UDP 192.0.2.20:5060;branch=z9hG4bK0a1b2c3d\r\n\
      From: <sip:t@192.0.2.20>;tag=0a1b2c3d\r\nTo: <sip:t@192.0.2.10>;tag=r1\r\n\
      Call-ID: frag-0a1b2c3d\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n"
        .to_vec()
}

/// A UDP header and `payload`, from and to port 5060.
fn udp(payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + payload.len());
    v.extend_from_slice(&5060u16.to_be_bytes());
    v.extend_from_slice(&5060u16.to_be_bytes());
    v.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    v.extend_from_slice(&[0, 0]);
    v.extend_from_slice(payload);
    v
}

/// The IPv4 fragments of `datagram` (UDP header included) at an MTU of 1500.
fn ipv4_fragments(datagram: &[u8]) -> Vec<Vec<u8>> {
    let per = 1480;
    let mut out = Vec::new();
    let mut at = 0;
    while at < datagram.len() {
        let end = (at + per).min(datagram.len());
        let word = ((at / 8) as u16) | if end < datagram.len() { 0x2000 } else { 0 };
        let mut ip: Vec<u8> = vec![0x45, 0];
        ip.extend_from_slice(&((20 + end - at) as u16).to_be_bytes());
        ip.extend_from_slice(&0x0926u16.to_be_bytes());
        ip.extend_from_slice(&word.to_be_bytes());
        ip.extend_from_slice(&[64, 17, 0, 0]);
        ip.extend_from_slice(&SENDER);
        ip.extend_from_slice(&RECEIVER);
        ip.extend_from_slice(&datagram[at..end]);
        out.push(ip);
        at = end;
    }
    out
}

/// The IPv6 fragments of `datagram`, cut after 1448 bytes, between two RFC
/// 3849 addresses.
fn ipv6_fragments(datagram: &[u8]) -> Vec<Vec<u8>> {
    [(0usize, 1448usize, true), (1448, datagram.len(), false)]
        .into_iter()
        .map(|(from, to, more)| {
            let mut body: Vec<u8> = vec![17, 0];
            body.extend_from_slice(&((((from / 8) as u16) << 3) | u16::from(more)).to_be_bytes());
            body.extend_from_slice(&0x0926u32.to_be_bytes());
            body.extend_from_slice(&datagram[from..to]);
            let mut ip: Vec<u8> = vec![0x60, 0, 0, 0];
            ip.extend_from_slice(&(body.len() as u16).to_be_bytes());
            ip.extend_from_slice(&[44, 64]);
            ip.extend_from_slice(&[
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20,
            ]);
            ip.extend_from_slice(&[
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
            ]);
            ip.extend_from_slice(&body);
            ip
        })
        .collect()
}

/// An unfragmented IPv6 UDP datagram from the capture host to the sender.
fn ipv6_reply(payload: &[u8]) -> Vec<u8> {
    let body = udp(payload);
    let mut ip: Vec<u8> = vec![0x60, 0, 0, 0];
    ip.extend_from_slice(&(body.len() as u16).to_be_bytes());
    ip.extend_from_slice(&[17, 64]);
    ip.extend_from_slice(&[
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ]);
    ip.extend_from_slice(&[
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20,
    ]);
    ip.extend_from_slice(&body);
    ip
}

/// `ip` behind an Ethernet header, optionally inside one 802.1Q tag.
fn ethernet(ip: &[u8], vlan: Option<u16>) -> Vec<u8> {
    let et: u16 = if ip[0] >> 4 == 6 { 0x86dd } else { 0x0800 };
    let mut f: Vec<u8> = vec![
        0x00, 0x00, 0x5e, 0x00, 0x53, 0x02, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x01,
    ];
    if let Some(vid) = vlan {
        f.extend_from_slice(&0x8100u16.to_be_bytes());
        f.extend_from_slice(&vid.to_be_bytes());
    }
    f.extend_from_slice(&et.to_be_bytes());
    f.extend_from_slice(ip);
    f
}

/// The issue's capture: three IPv4 fragments of the OPTIONS, then the reply.
fn issue_frames(vlan: Option<u16>) -> Vec<Vec<u8>> {
    let mut frames: Vec<Vec<u8>> = ipv4_fragments(&udp(&options()))
        .iter()
        .map(|ip| ethernet(ip, vlan))
        .collect();
    let mut ok = pcap_build::udp_frame(RECEIVER, SENDER, 5060, 5060, &reply());
    if let Some(vid) = vlan {
        let mut tagged = ok[..12].to_vec();
        tagged.extend_from_slice(&0x8100u16.to_be_bytes());
        tagged.extend_from_slice(&vid.to_be_bytes());
        tagged.extend_from_slice(&ok[12..]);
        ok = tagged;
    }
    frames.push(ok);
    frames
}

/// What one run printed: the message count of the issue's dialog (0 when
/// there is no such dialog) and stderr.
struct Run {
    messages: u64,
    stderr: String,
}

/// Read `frames` with `-I` through `filter` (none when empty) and the extra
/// `args`.
fn run(dir: &Path, frames: &[Vec<u8>], filter: &str, args: &[&str]) -> Result<Run, TestError> {
    let pcap = dir.join("frag.pcap");
    pcap_build::write_pcap(&pcap, frames)?;
    let pcap = pcap.to_str().ok_or("a UTF-8 path")?;
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sipnab"));
    cmd.current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(["-N", "-I", pcap, "--no-cli-print", "--json-dialogs"])
        .args(args)
        .env("SIPNAB_LOG", "warn")
        .env("NO_COLOR", "1");
    for (k, v) in run_support::config_isolation(dir) {
        cmd.env(k, v);
    }
    if !filter.is_empty() {
        cmd.arg(filter);
    }
    let out = cmd.output()?;
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    if !out.status.success() {
        return Err(format!("sipnab exited {:?}: {stderr}", out.status.code()).into());
    }
    let mut messages = 0;
    for line in String::from_utf8(out.stdout)?.lines() {
        let line = line.trim();
        if !line.starts_with('{') {
            continue;
        }
        let v: serde_json::Value = serde_json::from_str(line)?;
        if v["call_id"] == CALL_ID {
            messages = v["msg_count"].as_u64().ok_or("a dialog has msg_count")?;
        }
    }
    Ok(Run { messages, stderr })
}

/// The filter a default live capture installs, from the library.
fn generated() -> String {
    sipnab::app::bootstrap::auto_capture_filter(5060, 5061, &[], true)
}

/// A scratch directory for one test.
fn scratch() -> Result<tempfile::TempDir, TestError> {
    Ok(tempfile::tempdir()?)
}

// ── success ────────────────────────────────────────────────────────────

/// The issue's exact case through the filter a live capture installs:
/// the request is stored. Before the fix the filter passed one fragment of
/// three and the dialog held the reply alone.
#[test]
fn the_generated_filter_keeps_the_issue_926_request() -> Result<(), TestError> {
    let dir = scratch()?;
    let r = run(dir.path(), &issue_frames(None), &generated(), &[])?;
    assert_eq!(r.messages, 2, "request and reply are stored: {}", r.stderr);
    assert!(
        !r.stderr.contains("IP datagram(s)"),
        "nothing incomplete to report: {}",
        r.stderr
    );
    Ok(())
}

/// The same request inside a VLAN tag, through the encapsulated arms.
#[test]
fn the_generated_filter_keeps_a_fragmented_request_inside_a_vlan() -> Result<(), TestError> {
    let dir = scratch()?;
    let r = run(dir.path(), &issue_frames(Some(100)), &generated(), &[])?;
    assert_eq!(r.messages, 2, "request and reply are stored: {}", r.stderr);
    Ok(())
}

/// The same request over IPv6, where `portrange` matched not even the first
/// fragment.
#[test]
fn the_generated_filter_keeps_a_fragmented_ipv6_request() -> Result<(), TestError> {
    let dir = scratch()?;
    let mut frames: Vec<Vec<u8>> = ipv6_fragments(&udp(&options()))
        .iter()
        .map(|ip| ethernet(ip, None))
        .collect();
    frames.push(ethernet(&ipv6_reply(&reply()), None));
    let r = run(dir.path(), &frames, &generated(), &[])?;
    assert_eq!(r.messages, 2, "request and reply are stored: {}", r.stderr);
    Ok(())
}

/// The clause sipnab's warning gives fixes the reporter's own filter.
#[test]
fn the_fixed_operator_filter_keeps_the_request() -> Result<(), TestError> {
    let dir = scratch()?;
    let fixed = format!("(port 5060 or port 5061) or {CLAUSE}");
    let r = run(dir.path(), &issue_frames(None), &fixed, &[])?;
    assert_eq!(r.messages, 2, "request and reply are stored: {}", r.stderr);
    Ok(())
}

/// `--portrange` gates the reassembled datagram on its ports, which the
/// first fragment supplied: the request is inside the range and kept.
#[test]
fn a_reassembled_request_passes_the_portrange_gate() -> Result<(), TestError> {
    let dir = scratch()?;
    let r = run(
        dir.path(),
        &issue_frames(None),
        &generated(),
        &["--portrange", "5060-5061"],
    )?;
    assert_eq!(r.messages, 2, "request and reply are stored: {}", r.stderr);
    Ok(())
}

/// Reading the file with no filter at all reassembles the request: the
/// reporter's control row.
#[test]
fn with_no_filter_the_request_is_reassembled() -> Result<(), TestError> {
    let dir = scratch()?;
    let r = run(dir.path(), &issue_frames(None), "", &[])?;
    assert_eq!(r.messages, 2, "request and reply are stored: {}", r.stderr);
    Ok(())
}

// ── failure: the loss, now visible ─────────────────────────────────────

/// The reporter's filter, used as given, still loses the request: sipnab
/// does not rewrite an operator's filter. What changed is that the run now
/// says so, with the count.
#[test]
fn the_reporters_filter_loses_the_request_and_the_summary_says_so() -> Result<(), TestError> {
    let dir = scratch()?;
    let r = run(
        dir.path(),
        &issue_frames(None),
        "port 5060 or port 5061",
        &[],
    )?;
    assert_eq!(r.messages, 1, "only the reply survives the port filter");
    assert!(
        r.stderr
            .contains("1 IP datagram(s) arrived as a first fragment"),
        "the incomplete datagram is reported: {}",
        r.stderr
    );
    assert!(r.stderr.contains(CLAUSE), "the fix is named: {}", r.stderr);
    Ok(())
}

/// The capture point missed the last fragment: the first one is held,
/// never completes, and is counted at the end of the input.
#[test]
fn a_missing_last_fragment_is_counted_at_the_end_of_the_input() -> Result<(), TestError> {
    let dir = scratch()?;
    let mut frames = issue_frames(None);
    frames.remove(2);
    let r = run(dir.path(), &frames, "", &[])?;
    assert_eq!(r.messages, 1, "the request never completed");
    assert!(
        r.stderr.contains("1 IP datagram(s)"),
        "the loss is reported: {}",
        r.stderr
    );
    Ok(())
}

/// `--no-reassembly` reads each fragment alone, as before.
#[test]
fn without_reassembly_the_request_is_not_rebuilt() -> Result<(), TestError> {
    let dir = scratch()?;
    let r = run(dir.path(), &issue_frames(None), "", &["--no-reassembly"])?;
    assert_eq!(
        r.messages, 1,
        "the reporter's --no-reassembly row: reply only"
    );
    Ok(())
}

// ── edge ───────────────────────────────────────────────────────────────

/// Later fragments with no first fragment name no message: nothing is
/// counted as incomplete.
#[test]
fn later_fragments_alone_are_not_counted() -> Result<(), TestError> {
    let dir = scratch()?;
    let mut frames = issue_frames(None);
    frames.remove(0);
    let r = run(dir.path(), &frames, "", &[])?;
    assert_eq!(r.messages, 1, "the reply alone");
    assert!(
        !r.stderr.contains("IP datagram(s)"),
        "no first fragment, nothing to count: {}",
        r.stderr
    );
    Ok(())
}

/// Fragments that arrive out of order still reassemble through the filter.
#[test]
fn out_of_order_fragments_pass_the_generated_filter_and_reassemble() -> Result<(), TestError> {
    let dir = scratch()?;
    let mut frames = issue_frames(None);
    frames.swap(0, 2);
    let r = run(dir.path(), &frames, &generated(), &[])?;
    assert_eq!(r.messages, 2, "request and reply are stored: {}", r.stderr);
    Ok(())
}
