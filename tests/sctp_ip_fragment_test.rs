// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! SIP over SCTP in an IP-fragmented packet, end to end.
//!
//! A SCTP packet larger than the path MTU travels as IP fragments when the
//! sender does not set Don't Fragment. sipnab reassembled the datagram and
//! then did not read it: the transport re-parse knew UDP and TCP only, so the
//! reassembled SCTP packet reached the SIP parser with its SCTP header and
//! chunk headers still in front of the message, and the message was lost.
//! The capture filter also left SCTP out of the fragment clause, so a live
//! capture dropped the later fragments in the kernel.
//!
//! A live capture cannot be driven from a test (it needs an interface, a
//! sender and privileges). As in tests/ip_fragment_capture_filter_test.rs,
//! the kernel's half is replayed through the capture filter: sipnab applies a
//! filter given after the options to a file it reads with `-I`, through the
//! same `pcap_compile` and `pcap_setfilter` a live handle uses, and the
//! generated filter is the library's, the exact string a live capture
//! installs.
//!
//! Each capture holds an INVITE (Call-ID `sctp-frag-0a1b`) and its 200 OK.
//! With the INVITE stored, the dialog has two messages; without it, one.
//! Names prefixed `s_` are success cases, `f_` cases where the INVITE is not
//! stored, `e_` edge cases.
#![cfg(feature = "native")]

use std::path::Path;
use std::process::Command;

#[path = "support/pcap_build.rs"]
mod pcap_build;
#[path = "support/run.rs"]
mod run_support;

/// Any error a test can return; `?` converts into it.
type TestError = Box<dyn std::error::Error>;

/// The INVITE's Call-ID.
const CALL_ID: &str = "sctp-frag-0a1b";

/// The clause sipnab's warning tells an operator to add.
const CLAUSE: &str = "(ip[6:2] & 0x1fff != 0) or (ip6[6] = 44)";

/// The caller (`192.0.2.20`) and the capture host (`192.0.2.10`).
const CALLER: [u8; 4] = [192, 0, 2, 20];
const CALLEE: [u8; 4] = [192, 0, 2, 10];

/// The caller and the capture host over IPv6 (RFC 3849).
const CALLER6: [u8; 16] = [
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20,
];
const CALLEE6: [u8; 16] = [
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

/// SCTP payload protocol identifier for SIP is not assigned; 0 is
/// "unspecified", which is what SIP stacks send.
const PPID: u32 = 0;

/// An INVITE of about `pad` bytes more than its headers, so it needs
/// fragments at an MTU of 1500.
fn invite(pad: usize) -> Vec<u8> {
    format!(
        "INVITE sip:bob@192.0.2.10 SIP/2.0\r\n\
         Via: SIP/2.0/SCTP 192.0.2.20:5060;branch=z9hG4bKsctp0a1b\r\n\
         Max-Forwards: 70\r\nFrom: <sip:alice@192.0.2.20>;tag=a1\r\n\
         To: <sip:bob@192.0.2.10>\r\nCall-ID: {CALL_ID}\r\nCSeq: 1 INVITE\r\n\
         X-Pad: {}\r\nContent-Length: 0\r\n\r\n",
        "X".repeat(pad)
    )
    .into_bytes()
}

/// The 200 OK to [`invite`].
fn reply() -> Vec<u8> {
    format!(
        "SIP/2.0 200 OK\r\n\
         Via: SIP/2.0/SCTP 192.0.2.20:5060;branch=z9hG4bKsctp0a1b\r\n\
         From: <sip:alice@192.0.2.20>;tag=a1\r\nTo: <sip:bob@192.0.2.10>;tag=b1\r\n\
         Call-ID: {CALL_ID}\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"
    )
    .into_bytes()
}

/// One SCTP chunk: type, flags, value, padded to four bytes.
fn chunk(kind: u8, flags: u8, value: &[u8]) -> Vec<u8> {
    let mut c = vec![kind, flags];
    c.extend_from_slice(&((4 + value.len()) as u16).to_be_bytes());
    c.extend_from_slice(value);
    while c.len() % 4 != 0 {
        c.push(0);
    }
    c
}

/// A DATA chunk with flags `flags` (B = 2, E = 1) carrying `data`.
fn data_chunk(flags: u8, tsn: u32, data: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(12 + data.len());
    v.extend_from_slice(&tsn.to_be_bytes());
    v.extend_from_slice(&0u16.to_be_bytes());
    v.extend_from_slice(&0u16.to_be_bytes());
    v.extend_from_slice(&PPID.to_be_bytes());
    v.extend_from_slice(data);
    chunk(0, flags, &v)
}

/// A SACK chunk, which a sender may bundle ahead of DATA.
fn sack_chunk() -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&1u32.to_be_bytes());
    v.extend_from_slice(&65535u32.to_be_bytes());
    v.extend_from_slice(&[0, 0, 0, 0]);
    chunk(3, 0, &v)
}

/// An SCTP packet from port 5060 to 5060 holding `chunks`.
fn sctp(chunks: &[Vec<u8>]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&5060u16.to_be_bytes());
    v.extend_from_slice(&5060u16.to_be_bytes());
    v.extend_from_slice(&0x0a1b_2c3du32.to_be_bytes());
    v.extend_from_slice(&[0, 0, 0, 0]);
    for c in chunks {
        v.extend_from_slice(c);
    }
    v
}

/// The SCTP packet of one complete (B+E) DATA chunk carrying `msg`.
fn sctp_message(msg: &[u8]) -> Vec<u8> {
    sctp(&[data_chunk(3, 1, msg)])
}

/// The IPv4 fragments of `datagram` with protocol 132, `per` bytes each (a
/// multiple of 8), from `src` to `dst`.
fn ipv4_fragments(datagram: &[u8], per: usize, src: [u8; 4], dst: [u8; 4]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < datagram.len() {
        let end = (at + per).min(datagram.len());
        let word = ((at / 8) as u16) | if end < datagram.len() { 0x2000 } else { 0 };
        let mut ip: Vec<u8> = vec![0x45, 0];
        ip.extend_from_slice(&((20 + end - at) as u16).to_be_bytes());
        ip.extend_from_slice(&0x5c7au16.to_be_bytes());
        ip.extend_from_slice(&word.to_be_bytes());
        ip.extend_from_slice(&[64, 132, 0, 0]);
        ip.extend_from_slice(&src);
        ip.extend_from_slice(&dst);
        ip.extend_from_slice(&datagram[at..end]);
        out.push(ip);
        at = end;
    }
    out
}

/// An unfragmented IPv4 packet with protocol 132.
fn ipv4_whole(datagram: &[u8], src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
    let mut ip: Vec<u8> = vec![0x45, 0];
    ip.extend_from_slice(&((20 + datagram.len()) as u16).to_be_bytes());
    ip.extend_from_slice(&0x5c7bu16.to_be_bytes());
    ip.extend_from_slice(&0x4000u16.to_be_bytes());
    ip.extend_from_slice(&[64, 132, 0, 0]);
    ip.extend_from_slice(&src);
    ip.extend_from_slice(&dst);
    ip.extend_from_slice(datagram);
    ip
}

/// The IPv6 fragments of `datagram` with next header 132, `per` bytes each
/// (a multiple of 8).
fn ipv6_fragments(datagram: &[u8], per: usize) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < datagram.len() {
        let end = (at + per).min(datagram.len());
        let more = end < datagram.len();
        let mut body: Vec<u8> = vec![132, 0];
        body.extend_from_slice(&((((at / 8) as u16) << 3) | u16::from(more)).to_be_bytes());
        body.extend_from_slice(&0x5c7au32.to_be_bytes());
        body.extend_from_slice(&datagram[at..end]);
        out.push(ipv6(44, &body, CALLER6, CALLEE6));
        at = end;
    }
    out
}

/// An IPv6 packet with next header `next` and `body`.
fn ipv6(next: u8, body: &[u8], src: [u8; 16], dst: [u8; 16]) -> Vec<u8> {
    let mut ip: Vec<u8> = vec![0x60, 0, 0, 0];
    ip.extend_from_slice(&(body.len() as u16).to_be_bytes());
    ip.extend_from_slice(&[next, 64]);
    ip.extend_from_slice(&src);
    ip.extend_from_slice(&dst);
    ip.extend_from_slice(body);
    ip
}

/// `ip` behind an Ethernet header, VLAN-tagged when `vlan` is set.
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

/// The reply as one unfragmented SCTP packet over IPv4.
fn reply_frame(vlan: Option<u16>) -> Vec<u8> {
    ethernet(&ipv4_whole(&sctp_message(&reply()), CALLEE, CALLER), vlan)
}

/// The reply over IPv6.
fn reply_frame6() -> Vec<u8> {
    ethernet(&ipv6(132, &sctp_message(&reply()), CALLEE6, CALLER6), None)
}

/// The INVITE as IPv4 fragments of one SCTP packet, then the reply.
fn v4_call(vlan: Option<u16>) -> Vec<Vec<u8>> {
    let mut frames: Vec<Vec<u8>> =
        ipv4_fragments(&sctp_message(&invite(3000)), 1480, CALLER, CALLEE)
            .iter()
            .map(|ip| ethernet(ip, vlan))
            .collect();
    frames.push(reply_frame(vlan));
    frames
}

/// The INVITE as IPv6 fragments of one SCTP packet, then the reply.
fn v6_call() -> Vec<Vec<u8>> {
    let mut frames: Vec<Vec<u8>> = ipv6_fragments(&sctp_message(&invite(3000)), 1448)
        .iter()
        .map(|ip| ethernet(ip, None))
        .collect();
    frames.push(reply_frame6());
    frames
}

/// What one run printed: the message count of the dialog (0 when there is
/// no such dialog) and stderr.
struct Run {
    messages: u64,
    stderr: String,
}

/// Read `frames` with `-I` through `filter` (none when empty) and `args`.
fn run(dir: &Path, frames: &[Vec<u8>], filter: &str, args: &[&str]) -> Result<Run, TestError> {
    let pcap = dir.join("sctp-frag.pcap");
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

/// Assert the INVITE and the reply are both stored.
fn assert_stored(r: &Run, what: &str) {
    assert_eq!(
        r.messages, 2,
        "{what}: INVITE and reply are stored\n{}",
        r.stderr
    );
}

/// Assert only the reply is stored.
fn assert_reply_only(r: &Run, what: &str) {
    assert_eq!(
        r.messages, 1,
        "{what}: only the reply is stored\n{}",
        r.stderr
    );
}

// ── Success: the INVITE is stored ────────────────────────────────────

/// IPv4 fragments of one SCTP packet, read with `-I` and no filter.
#[test]
fn s_v4_fragmented_sctp_invite_is_stored() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let r = run(dir.path(), &v4_call(None), "", &[])?;
    assert_stored(&r, "IPv4, -I");
    Ok(())
}

/// The same through the filter a live capture installs.
#[test]
fn s_v4_fragmented_sctp_invite_passes_the_live_filter() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let r = run(dir.path(), &v4_call(None), &generated(), &[])?;
    assert_stored(&r, "IPv4, live filter");
    Ok(())
}

/// IPv6 fragments of one SCTP packet, read with `-I` and no filter.
#[test]
fn s_v6_fragmented_sctp_invite_is_stored() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let r = run(dir.path(), &v6_call(), "", &[])?;
    assert_stored(&r, "IPv6, -I");
    Ok(())
}

/// IPv6 through the filter a live capture installs.
#[test]
fn s_v6_fragmented_sctp_invite_passes_the_live_filter() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let r = run(dir.path(), &v6_call(), &generated(), &[])?;
    assert_stored(&r, "IPv6, live filter");
    Ok(())
}

/// Inside a VLAN tag, read with `-I`.
#[test]
fn s_vlan_fragmented_sctp_invite_is_stored() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let r = run(dir.path(), &v4_call(Some(100)), "", &[])?;
    assert_stored(&r, "VLAN, -I");
    Ok(())
}

/// Inside a VLAN tag, through the encapsulated arms of the live filter.
#[test]
fn s_vlan_fragmented_sctp_invite_passes_the_live_filter() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let r = run(dir.path(), &v4_call(Some(100)), &generated(), &[])?;
    assert_stored(&r, "VLAN, live filter");
    Ok(())
}

/// A whole SCTP call inside a VLAN tag passes the live filter's
/// encapsulated port arms, which test UDP, TCP and SCTP.
#[test]
fn s_vlan_whole_sctp_call_passes_the_live_filter() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let frames = vec![
        ethernet(
            &ipv4_whole(&sctp_message(&invite(100)), CALLER, CALLEE),
            Some(100),
        ),
        reply_frame(Some(100)),
    ];
    let r = run(dir.path(), &frames, &generated(), &[])?;
    assert_stored(&r, "whole SCTP in a VLAN, live filter");
    Ok(())
}

/// A whole IPv6 SCTP call inside a VLAN tag passes the live filter.
#[test]
fn s_vlan_whole_v6_sctp_call_passes_the_live_filter() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let frames = vec![
        ethernet(
            &ipv6(132, &sctp_message(&invite(100)), CALLER6, CALLEE6),
            Some(100),
        ),
        ethernet(
            &ipv6(132, &sctp_message(&reply()), CALLEE6, CALLER6),
            Some(100),
        ),
    ];
    let r = run(dir.path(), &frames, &generated(), &[])?;
    assert_stored(&r, "whole IPv6 SCTP in a VLAN, live filter");
    Ok(())
}

/// An operator's port filter with the clause sipnab suggests keeps it.
#[test]
fn s_operator_clause_keeps_the_sctp_invite() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let filter = format!("(port 5060) or {CLAUSE}");
    let r = run(dir.path(), &v4_call(None), &filter, &[])?;
    assert_stored(&r, "port 5060 + clause");
    Ok(())
}

/// The fragments in reverse order still reassemble.
#[test]
fn s_reversed_fragments_reassemble() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let mut frames = v4_call(None);
    let reply = frames.pop().ok_or("the reply")?;
    frames.reverse();
    frames.push(reply);
    let r = run(dir.path(), &frames, &generated(), &[])?;
    assert_stored(&r, "reversed fragments");
    Ok(())
}

/// Small fragments (576-byte MTU) reassemble.
#[test]
fn s_many_small_fragments_reassemble() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let mut frames: Vec<Vec<u8>> =
        ipv4_fragments(&sctp_message(&invite(3000)), 552, CALLER, CALLEE)
            .iter()
            .map(|ip| ethernet(ip, None))
            .collect();
    assert!(frames.len() >= 6, "six or more fragments");
    frames.push(reply_frame(None));
    let r = run(dir.path(), &frames, &generated(), &[])?;
    assert_stored(&r, "576-byte MTU");
    Ok(())
}

/// A SACK bundled ahead of the DATA chunk does not hide it.
#[test]
fn s_bundled_sack_before_data_is_read() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let packet = sctp(&[sack_chunk(), data_chunk(3, 1, &invite(3000))]);
    let mut frames: Vec<Vec<u8>> = ipv4_fragments(&packet, 1480, CALLER, CALLEE)
        .iter()
        .map(|ip| ethernet(ip, None))
        .collect();
    frames.push(reply_frame(None));
    let r = run(dir.path(), &frames, "", &[])?;
    assert_stored(&r, "SACK + DATA");
    Ok(())
}

/// A message split into SCTP DATA fragments (B, then E), each packet itself
/// IP-fragmented, goes through SCTP reassembly as an unfragmented one does.
#[test]
fn s_sctp_data_fragments_in_ip_fragments_reassemble() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let msg = invite(5000);
    let (first, last) = msg.split_at(2600);
    let mut frames = Vec::new();
    for (flags, tsn, part) in [(2u8, 7u32, first), (1, 8, last)] {
        for ip in ipv4_fragments(&sctp(&[data_chunk(flags, tsn, part)]), 1480, CALLER, CALLEE) {
            frames.push(ethernet(&ip, None));
        }
    }
    frames.push(reply_frame(None));
    let r = run(dir.path(), &frames, &generated(), &[])?;
    assert_stored(&r, "SCTP B+E inside IP fragments");
    Ok(())
}

/// An IP-fragmented B chunk and an unfragmented E chunk join in the SCTP
/// reassembler.
#[test]
fn s_fragmented_begin_and_whole_end_reassemble() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let msg = invite(3000);
    let (first, last) = msg.split_at(2900);
    let mut frames: Vec<Vec<u8>> =
        ipv4_fragments(&sctp(&[data_chunk(2, 7, first)]), 1480, CALLER, CALLEE)
            .iter()
            .map(|ip| ethernet(ip, None))
            .collect();
    frames.push(ethernet(
        &ipv4_whole(&sctp(&[data_chunk(1, 8, last)]), CALLER, CALLEE),
        None,
    ));
    frames.push(reply_frame(None));
    let r = run(dir.path(), &frames, "", &[])?;
    assert_stored(&r, "fragmented B, whole E");
    Ok(())
}

/// The same SCTP packet stored whole and stored fragmented give the same
/// dialog: one path for both.
#[test]
fn s_fragmented_and_whole_give_the_same_dialog() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let packet = sctp_message(&invite(1000));
    let whole = vec![
        ethernet(&ipv4_whole(&packet, CALLER, CALLEE), None),
        reply_frame(None),
    ];
    let mut cut: Vec<Vec<u8>> = ipv4_fragments(&packet, 512, CALLER, CALLEE)
        .iter()
        .map(|ip| ethernet(ip, None))
        .collect();
    cut.push(reply_frame(None));
    let a = run(dir.path(), &whole, "", &[])?;
    let b = run(dir.path(), &cut, "", &[])?;
    assert_stored(&a, "whole");
    assert_eq!(a.messages, b.messages, "the same count\n{}", b.stderr);
    Ok(())
}

// ── Failure: the INVITE is not stored ────────────────────────────────

/// The reporter's port-only filter drops the later fragments.
#[test]
fn f_port_only_filter_loses_the_sctp_invite() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let r = run(dir.path(), &v4_call(None), "port 5060", &[])?;
    assert_reply_only(&r, "port 5060");
    Ok(())
}

/// A missing last fragment leaves the INVITE incomplete, and the end of the
/// run says so.
#[test]
fn f_missing_last_fragment_is_counted() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let mut frames = v4_call(None);
    let reply = frames.pop().ok_or("the reply")?;
    frames.pop();
    frames.push(reply);
    let r = run(dir.path(), &frames, "", &[])?;
    assert_reply_only(&r, "missing last fragment");
    assert!(
        r.stderr.contains("IP datagram(s)"),
        "the incomplete datagram is reported\n{}",
        r.stderr
    );
    Ok(())
}

/// With reassembly off, the INVITE is not rebuilt.
#[test]
fn f_no_reassembly_does_not_rebuild_it() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let r = run(dir.path(), &v4_call(None), "", &["--no-reassembly"])?;
    assert_reply_only(&r, "--no-reassembly");
    Ok(())
}

/// A fragmented SCTP packet of non-DATA chunks holds no message.
#[test]
fn f_fragmented_control_chunks_hold_no_message() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let heartbeat = chunk(4, 0, &vec![0u8; 3000]);
    let mut frames: Vec<Vec<u8>> = ipv4_fragments(&sctp(&[heartbeat]), 1480, CALLER, CALLEE)
        .iter()
        .map(|ip| ethernet(ip, None))
        .collect();
    frames.push(reply_frame(None));
    let r = run(dir.path(), &frames, "", &[])?;
    assert_reply_only(&r, "HEARTBEAT only");
    Ok(())
}

/// A DATA chunk whose length runs past the datagram is refused.
#[test]
fn f_data_chunk_past_the_datagram_is_refused() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let mut packet = sctp_message(&invite(3000));
    let bad = (packet.len() as u16).saturating_add(64);
    packet[14..16].copy_from_slice(&bad.to_be_bytes());
    let mut frames: Vec<Vec<u8>> = ipv4_fragments(&packet, 1480, CALLER, CALLEE)
        .iter()
        .map(|ip| ethernet(ip, None))
        .collect();
    frames.push(reply_frame(None));
    let r = run(dir.path(), &frames, "", &[])?;
    assert_reply_only(&r, "chunk length past the end");
    Ok(())
}

/// A reassembled datagram shorter than the SCTP common header holds nothing.
#[test]
fn f_truncated_common_header_holds_nothing() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let mut frames: Vec<Vec<u8>> = ipv4_fragments(&[0u8; 10], 8, CALLER, CALLEE)
        .iter()
        .map(|ip| ethernet(ip, None))
        .collect();
    frames.push(reply_frame(None));
    let r = run(dir.path(), &frames, "", &[])?;
    assert_reply_only(&r, "10-byte SCTP datagram");
    Ok(())
}

/// An SCTP DATA fragment (B only) with no E never completes.
#[test]
fn f_begin_without_end_never_completes() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let mut frames: Vec<Vec<u8>> = ipv4_fragments(
        &sctp(&[data_chunk(2, 7, &invite(3000))]),
        1480,
        CALLER,
        CALLEE,
    )
    .iter()
    .map(|ip| ethernet(ip, None))
    .collect();
    frames.push(reply_frame(None));
    let r = run(dir.path(), &frames, "", &[])?;
    assert_reply_only(&r, "B without E");
    Ok(())
}

/// An empty DATA chunk carries no message.
#[test]
fn f_empty_data_chunk_holds_nothing() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let packet = sctp(&[data_chunk(3, 1, &[]), chunk(4, 0, &vec![0u8; 3000])]);
    let mut frames: Vec<Vec<u8>> = ipv4_fragments(&packet, 1480, CALLER, CALLEE)
        .iter()
        .map(|ip| ethernet(ip, None))
        .collect();
    frames.push(reply_frame(None));
    let r = run(dir.path(), &frames, "", &[])?;
    assert_reply_only(&r, "empty DATA chunk");
    Ok(())
}

/// The IPv6 half of the port-only filter loses the later fragments too.
#[test]
fn f_port_only_filter_loses_the_v6_sctp_invite() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let r = run(dir.path(), &v6_call(), "port 5060", &[])?;
    assert_reply_only(&r, "IPv6, port 5060");
    Ok(())
}

/// The fragments alone, with the first missing, store nothing.
#[test]
fn f_missing_first_fragment_stores_nothing() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let mut frames = v4_call(None);
    frames.remove(0);
    let r = run(dir.path(), &frames, "", &[])?;
    assert_reply_only(&r, "missing first fragment");
    Ok(())
}

// ── Edge cases ───────────────────────────────────────────────────────

/// A fragment that arrives twice does not break reassembly.
#[test]
fn e_duplicate_fragment_still_reassembles() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let mut frames = v4_call(None);
    let again = frames.first().ok_or("a first fragment")?.clone();
    frames.insert(1, again);
    let r = run(dir.path(), &frames, "", &[])?;
    assert_stored(&r, "duplicate first fragment");
    Ok(())
}

/// Two fragments, the second only eight bytes long.
#[test]
fn e_tiny_last_fragment_reassembles() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let packet = sctp_message(&invite(1400));
    let per = (packet.len() - 1) / 8 * 8;
    let mut frames: Vec<Vec<u8>> = ipv4_fragments(&packet, per, CALLER, CALLEE)
        .iter()
        .map(|ip| ethernet(ip, None))
        .collect();
    assert_eq!(frames.len(), 2, "two fragments");
    frames.push(reply_frame(None));
    let r = run(dir.path(), &frames, "", &[])?;
    assert_stored(&r, "tiny last fragment");
    Ok(())
}

/// A DATA chunk whose padding is cut off at the end of the datagram is read.
#[test]
fn e_last_chunk_without_padding_is_read() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let mut msg = invite(3000);
    while (16 + msg.len()).is_multiple_of(4) {
        msg.push(b' ');
    }
    let mut packet = sctp_message(&msg);
    let declared = u16::from_be_bytes([packet[14], packet[15]]) as usize;
    packet.truncate(12 + declared);
    assert!(
        !packet.len().is_multiple_of(4),
        "the chunk ends off a 4-byte boundary"
    );
    let mut frames: Vec<Vec<u8>> = ipv4_fragments(&packet, 1480, CALLER, CALLEE)
        .iter()
        .map(|ip| ethernet(ip, None))
        .collect();
    frames.push(reply_frame(None));
    let r = run(dir.path(), &frames, "", &[])?;
    assert_stored(&r, "no padding on the last chunk");
    Ok(())
}

/// UDP packets between the SCTP fragments do not disturb reassembly.
#[test]
fn e_udp_between_sctp_fragments() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let sctp_frags = ipv4_fragments(&sctp_message(&invite(3000)), 1480, CALLER, CALLEE);
    let mut frames = Vec::new();
    // An unfragmented UDP packet, not SIP, after every fragment.
    let other = pcap_build::udp_frame(CALLER, CALLEE, 5062, 5060, b"not sip, small");
    for ip in &sctp_frags {
        frames.push(ethernet(ip, None));
        frames.push(other.clone());
    }
    frames.push(reply_frame(None));
    let r = run(dir.path(), &frames, "", &[])?;
    assert_stored(&r, "interleaved");
    Ok(())
}

/// Over IPv6 with small fragments, through the live filter.
#[test]
fn e_v6_many_small_fragments_pass_the_live_filter() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let mut frames: Vec<Vec<u8>> = ipv6_fragments(&sctp_message(&invite(3000)), 528)
        .iter()
        .map(|ip| ethernet(ip, None))
        .collect();
    frames.push(reply_frame6());
    let r = run(dir.path(), &frames, &generated(), &[])?;
    assert_stored(&r, "IPv6, 528-byte fragments");
    Ok(())
}

/// The live filter's string names protocol 132 in its fragment terms.
#[test]
fn e_the_live_filter_names_sctp_fragments() {
    let f = generated();
    assert!(f.contains("ip[9] = 132"), "IPv4 fragment term: {f}");
    assert!(f.contains("ip6[40] = 132"), "IPv6 fragment term: {f}");
}
