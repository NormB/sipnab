// SPDX-License-Identifier: MIT OR Apache-2.0

//! ICMP media findings must reach the STRUCTURED surfaces, not just stderr.
//!
//! `tests/icmp_media_test` proves each association rule does what it says, and
//! `tests/corpus_icmp_media_test` proves the rules do something on real
//! traffic. Neither notices the failure this file exists for: a finding can be
//! recorded, attributed and printed on stderr while every machine-readable
//! consumer — `--report`, `--json-dialogs`, the REST dialog document, MCP —
//! sees nothing. Measured before this landed, `--report` and `--json-dialogs`
//! carried 0 of 514 corpus findings while stderr carried all of them.
//!
//! Three things are checked, and each one is a way the feature can be present
//! and useless:
//!
//! 1. **The finding arrives.** A capture whose router said "your audio went
//!    nowhere" must say so in the report and in the JSON.
//! 2. **The TIER arrives with it.** `flow` (an exact directed 5-tuple match
//!    against a stream sipnab watched) and `none` (no match at all) are not the
//!    same claim. A consumer that cannot tell them apart presents a guess with
//!    the confidence of a measurement, which is worse than presenting nothing.
//! 3. **The third outcome survives.** A quote that stopped before the ports has
//!    no flow to match — `unkeyed` — which is neither "attributed" nor
//!    "matched nothing". Collapsing it makes #98's two invariants uncheckable
//!    from the output.
//!
//! The captures are built here rather than checked in so the quoted 5-tuple is
//! known exactly: a `flow`-tier match is only meaningful if the test knows the
//! stream it is supposed to match.
#![cfg(feature = "native")]

use std::path::Path;
use std::process::Command;

use serde_json::Value;

#[path = "support/pcap_build.rs"]
mod pcap_build;
#[path = "support/mod.rs"]
mod support;

use pcap_build::write_pcap;
use support::schema::{assert_valid, load_validator};

/// The endpoint sending audio into a black hole.
const SENDER: [u8; 4] = [192, 0, 2, 10];
/// The endpoint that stopped answering on its media port.
const PEER: [u8; 4] = [192, 0, 2, 20];
/// The router that noticed. Never the fault, and never named as the endpoint.
const ROUTER: [u8; 4] = [192, 0, 2, 254];
/// The sender's RTP port. Even, per RFC 3550 §11.
const RTP_SRC: u16 = 40000;
/// The RTP port that did not answer.
const RTP_DST: u16 = 20000;
/// SSRC of the stream the ICMP error is about.
const SSRC: u32 = 0x0BAD_F00D;
/// `Call-ID` of the one call in the built captures.
const CALL_ID: &str = "icmp-media-surfaces@example.com";

/// One RTP datagram: version 2, PCMU, `SSRC`, 160 bytes of payload.
fn rtp_payload(sequence: u16) -> Vec<u8> {
    let mut d = vec![0x80u8, 0x00];
    d.extend_from_slice(&sequence.to_be_bytes());
    d.extend_from_slice(&(u32::from(sequence) * 160).to_be_bytes());
    d.extend_from_slice(&SSRC.to_be_bytes());
    d.extend_from_slice(&[0xAB; 160]);
    d
}

/// The SDP body both sides of the call carry, anchoring media on `addr:port`.
fn sdp(addr: [u8; 4], port: u16) -> String {
    let a = format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3]);
    format!(
        "v=0\r\no=- 1 1 IN IP4 {a}\r\ns=-\r\nc=IN IP4 {a}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n"
    )
}

/// One SIP message as a wire payload.
fn sip(start: &str, extra: &[&str], body: &str) -> Vec<u8> {
    let mut msg = format!("{start}\r\n");
    for h in extra {
        msg.push_str(h);
        msg.push_str("\r\n");
    }
    // Without this the SDP is a body sipnab never reads, so the media endpoint
    // is never linked to the Call-ID and the finding names no call.
    if !body.is_empty() {
        msg.push_str("Content-Type: application/sdp\r\n");
    }
    msg.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    msg.push_str(body);
    msg.into_bytes()
}

/// The IPv4/UDP datagram an ICMP error quotes.
///
/// `quoted_payload_bytes` is how much of the original payload the router
/// echoed back. RFC 792 guarantees only 8 bytes past the IP header — the UDP
/// header and nothing else — and a real router that stops there produces a
/// quote sipnab can key on a flow but not read as RTP.
fn quoted_ipv4_udp(
    src: [u8; 4],
    dst: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
    quoted_payload_bytes: usize,
) -> Vec<u8> {
    let udp_len = (8 + payload.len()) as u16;
    let total_len = 20 + udp_len;
    let mut d = Vec::new();
    d.push(0x45);
    d.push(0x00);
    d.extend_from_slice(&total_len.to_be_bytes());
    d.extend_from_slice(&[0x00, 0x07]);
    d.extend_from_slice(&[0x40, 0x00]);
    d.push(64);
    d.push(17); // UDP
    d.extend_from_slice(&[0x00, 0x00]);
    d.extend_from_slice(&src);
    d.extend_from_slice(&dst);
    d.extend_from_slice(&src_port.to_be_bytes());
    d.extend_from_slice(&dst_port.to_be_bytes());
    d.extend_from_slice(&udp_len.to_be_bytes());
    d.extend_from_slice(&[0x00, 0x00]);
    d.extend_from_slice(&payload[..quoted_payload_bytes.min(payload.len())]);
    d
}

/// An Ethernet/IPv4 ICMP destination-unreachable frame carrying `quoted`.
///
/// `quoted_bytes` truncates the quote itself, which is how the `unkeyed` case
/// is built: cut it to the 20-byte IP header and the ports are simply not
/// there to key on.
fn icmp_unreachable_frame(quoted: &[u8], quoted_bytes: usize) -> Vec<u8> {
    let quoted = &quoted[..quoted_bytes.min(quoted.len())];
    let mut icmp = vec![3u8, 3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    icmp.extend_from_slice(quoted);

    let total_len = (20 + icmp.len()) as u16;
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&[0xAA; 6]);
    pkt.extend_from_slice(&[0xBB; 6]);
    pkt.extend_from_slice(&[0x08, 0x00]);
    pkt.push(0x45);
    pkt.push(0x00);
    pkt.extend_from_slice(&total_len.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x09]);
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.push(64);
    pkt.push(1); // ICMP
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&ROUTER);
    pkt.extend_from_slice(&SENDER);
    pkt.extend_from_slice(&icmp);
    pkt
}

/// One answered call with media, plus one ICMP error about that media.
///
/// `quoted_bytes` is the whole quote's length: 20 keeps only the IP header
/// (the `unkeyed` case), `usize::MAX` keeps all of it.
fn call_with_media_icmp(path: &Path, quoted_bytes: usize) {
    use pcap_build::udp_frame;
    let common = [
        "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-icmp-media",
        "From: <sip:alice@example.com>;tag=a1",
        "To: <sip:bob@example.com>",
        "Contact: <sip:alice@192.0.2.10>",
    ];
    let answered = [
        "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-icmp-media",
        "From: <sip:alice@example.com>;tag=a1",
        "To: <sip:bob@example.com>;tag=b1",
        "Contact: <sip:bob@192.0.2.20>",
    ];
    let call = format!("Call-ID: {CALL_ID}");
    let hdr = |base: &[&str; 4], cseq: &str| -> Vec<String> {
        let mut v: Vec<String> = base.iter().map(|s| (*s).to_string()).collect();
        v.push(call.clone());
        v.push(cseq.to_string());
        v
    };

    fn as_refs(v: &[String]) -> Vec<&str> {
        v.iter().map(String::as_str).collect()
    }

    let invite_h = hdr(&common, "CSeq: 1 INVITE");
    let ok_h = hdr(&answered, "CSeq: 1 INVITE");
    let ack_h = hdr(&answered, "CSeq: 1 ACK");
    let bye_h = hdr(&answered, "CSeq: 2 BYE");
    let bye_ok_h = hdr(&answered, "CSeq: 2 BYE");

    let mut frames: Vec<Vec<u8>> = vec![
        udp_frame(
            SENDER,
            PEER,
            5060,
            5060,
            &sip(
                "INVITE sip:bob@example.com SIP/2.0",
                &as_refs(&invite_h),
                &sdp(SENDER, RTP_SRC),
            ),
        ),
        udp_frame(
            PEER,
            SENDER,
            5060,
            5060,
            &sip("SIP/2.0 200 OK", &as_refs(&ok_h), &sdp(PEER, RTP_DST)),
        ),
        udp_frame(
            SENDER,
            PEER,
            5060,
            5060,
            &sip("ACK sip:bob@example.com SIP/2.0", &as_refs(&ack_h), ""),
        ),
    ];

    // Media the capture actually holds, so the quote below has something to be
    // matched against at the strongest tier.
    for seq in 1..=8u16 {
        frames.push(udp_frame(SENDER, PEER, RTP_SRC, RTP_DST, &rtp_payload(seq)));
    }

    let quoted = quoted_ipv4_udp(SENDER, PEER, RTP_SRC, RTP_DST, &rtp_payload(9), 12);
    frames.push(icmp_unreachable_frame(&quoted, quoted_bytes));

    frames.push(udp_frame(
        PEER,
        SENDER,
        5060,
        5060,
        &sip("BYE sip:alice@example.com SIP/2.0", &as_refs(&bye_h), ""),
    ));
    frames.push(udp_frame(
        SENDER,
        PEER,
        5060,
        5060,
        &sip("SIP/2.0 200 OK", &as_refs(&bye_ok_h), ""),
    ));

    write_pcap(path, &frames);
}

/// Run the built binary and return stdout, failing loudly on a non-zero exit.
fn run_sipnab(args: &[&str]) -> String {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sipnab"));
    cmd.args(args);
    support::deterministic_env(&mut cmd);
    let out = cmd.output().expect("spawn sipnab");
    assert!(
        out.status.success(),
        "sipnab {args:?} exited {:?}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("utf8 stdout")
}

/// The ICMP media section of a `--report`, split into (summary, rows).
fn media_section(report: &str) -> (String, Vec<String>) {
    let (_, section) = report
        .split_once("ICMP (media, capture-wide):")
        .unwrap_or_else(|| panic!("--report carried no ICMP media section:\n{report}"));
    let (summary, table) = section
        .split_once("Description")
        .unwrap_or_else(|| panic!("the section rendered no table:\n{section}"));
    let rows = table
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('-'))
        .map(str::to_string)
        .collect();
    (summary.to_string(), rows)
}

/// `--report` carries the finding, and every row names its tier.
///
/// Before this, a `--report` of a capture holding a media blackhole was
/// byte-identical to one of a capture holding none.
#[test]
fn the_report_carries_the_media_finding_with_its_tier() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pcap = dir.path().join("media-icmp.pcap");
    call_with_media_icmp(&pcap, usize::MAX);

    let report = run_sipnab(&[
        "-N",
        "-I",
        pcap.to_str().expect("utf8 path"),
        "--report",
        "--no-cli-print",
    ]);
    let (summary, rows) = media_section(&report);

    assert_eq!(rows.len(), 1, "one quoted flow, one row:\n{report}");
    let tier = rows[0].split_whitespace().next().unwrap_or("");
    assert_eq!(
        tier, "flow",
        "the quoted 5-tuple IS a stream this capture holds, so nothing weaker \
         may be reported:\n{report}"
    );
    assert!(
        rows[0].contains(&format!("{}:{RTP_DST}", ip(PEER))),
        "the row must name the socket that did not answer:\n{report}"
    );
    assert!(
        !summary.contains(&ip(ROUTER)) || rows[0].contains(&ip(ROUTER)),
        "the reporter belongs in its own column, never as the failed endpoint"
    );
    assert!(
        summary.contains("1 error(s) quoting non-SIP traffic, 1 of them media"),
        "the summary must count the error and class it as media:\n{report}"
    );
}

/// `--json-dialogs` carries the finding, its tier, and the outcome counters.
#[test]
fn json_dialogs_carries_the_media_finding_with_its_tier() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pcap = dir.path().join("media-icmp.pcap");
    call_with_media_icmp(&pcap, usize::MAX);

    let out = run_sipnab(&[
        "-N",
        "-I",
        pcap.to_str().expect("utf8 path"),
        "--json-dialogs",
        "--no-cli-print",
    ]);
    let line = out
        .lines()
        .find(|l| l.contains(CALL_ID))
        .unwrap_or_else(|| panic!("the call is missing from --json-dialogs:\n{out}"));
    let v: Value = serde_json::from_str(line).expect("NDJSON line parses");

    let block = v
        .get("icmp_media")
        .unwrap_or_else(|| panic!("--json-dialogs dropped the media evidence:\n{line}"));
    assert_eq!(block["capture"]["errors"], 1);
    assert_eq!(block["capture"]["media"], 1);
    assert_eq!(block["capture"]["attributed"], 1);
    assert_eq!(block["capture"]["unattributed"], 0);
    assert_eq!(block["capture"]["unkeyed"], 0);

    let findings = block["findings"]
        .as_array()
        .unwrap_or_else(|| panic!("the finding named this call and must be attached:\n{line}"));
    assert_eq!(findings.len(), 1);
    assert_eq!(
        findings[0]["attribution"], "flow",
        "a finding without its tier — or with the wrong one — is worse than no \
         finding:\n{line}"
    );
    assert_eq!(findings[0]["payload"], "rtp");
    assert_eq!(findings[0]["ssrc"], format!("0x{SSRC:08x}"));
    assert_eq!(
        findings[0]["unreachable_endpoint"],
        format!("{}:{RTP_DST}", ip(PEER))
    );
}

/// The emitted document still answers to the call-report schema.
///
/// `additionalProperties: false` means a new field that nobody added to the
/// schema is a validation failure, so this is what stops the wire shape and its
/// contract drifting apart. The schema also `enum`s the tier, so a finding that
/// reached a consumer with an unknown or missing `attribution` fails here.
#[test]
fn the_emitted_document_still_matches_the_call_report_schema() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pcap = dir.path().join("media-icmp.pcap");
    call_with_media_icmp(&pcap, usize::MAX);

    let validator = load_validator("call_report.schema.json");
    let out = run_sipnab(&[
        "-N",
        "-I",
        pcap.to_str().expect("utf8 path"),
        "--json-dialogs",
        "--no-cli-print",
    ]);

    let mut with_findings = 0;
    for (i, line) in out.lines().filter(|l| !l.trim().is_empty()).enumerate() {
        let v: Value = serde_json::from_str(line).expect("NDJSON line parses");
        if !v
            .pointer("/icmp_media/findings")
            .and_then(Value::as_array)
            .is_none_or(Vec::is_empty)
        {
            with_findings += 1;
        }
        assert_valid(&validator, &v, &format!("json-dialogs line {i}"));
    }
    assert!(
        with_findings > 0,
        "no line carried a finding, so the finding shape went unvalidated:\n{out}"
    );
}

/// The schema rejects a finding whose tier was dropped or invented.
///
/// A schema that accepts anything is worthless, and this is the exact
/// corruption the field exists to prevent: a finding that reads as a
/// measurement because nothing says how strong the claim is.
#[test]
fn the_schema_rejects_a_finding_without_a_valid_tier() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pcap = dir.path().join("media-icmp.pcap");
    call_with_media_icmp(&pcap, usize::MAX);

    let validator = load_validator("call_report.schema.json");
    let out = run_sipnab(&[
        "-N",
        "-I",
        pcap.to_str().expect("utf8 path"),
        "--json-dialogs",
        "--no-cli-print",
    ]);
    let good: Value = serde_json::from_str(
        out.lines()
            .find(|l| l.contains(CALL_ID))
            .expect("the call's line"),
    )
    .expect("parses");
    assert!(
        validator.is_valid(&good),
        "sanity: real output must validate"
    );

    // (a) the tier is dropped, the finding survives.
    let mut bad = good.clone();
    bad["icmp_media"]["findings"][0]
        .as_object_mut()
        .expect("finding object")
        .remove("attribution");
    assert!(
        !validator.is_valid(&bad),
        "an untiered finding must be rejected, not passed on to a consumer"
    );

    // (b) a tier nobody defined.
    let mut bad = good.clone();
    bad["icmp_media"]["findings"][0]["attribution"] = Value::String("probably".into());
    assert!(
        !validator.is_valid(&bad),
        "an unknown tier must be rejected: a consumer branching on the five \
         cannot handle a sixth"
    );

    // (c) the three outcomes are required, so one cannot quietly go missing.
    let mut bad = good.clone();
    bad["icmp_media"]["capture"]
        .as_object_mut()
        .expect("capture object")
        .remove("unkeyed");
    assert!(
        !validator.is_valid(&bad),
        "dropping `unkeyed` collapses three outcomes into two"
    );
}

/// A quote that stopped before the ports is its own outcome on every surface.
///
/// It is neither attributed nor "matched nothing": there was no flow to match
/// in the first place. #98 asserts
/// `sum(flow errors) + unkeyed + untracked == errors`, and that is only
/// checkable from the output while the counters stay apart.
#[test]
fn a_quote_too_short_to_key_is_reported_as_unkeyed_not_as_a_miss() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pcap = dir.path().join("unkeyed-icmp.pcap");
    // 20 bytes of quote is the IP header alone: no ports, so no flow.
    call_with_media_icmp(&pcap, 20);

    let out = run_sipnab(&[
        "-N",
        "-I",
        pcap.to_str().expect("utf8 path"),
        "--json-dialogs",
        "--no-cli-print",
    ]);
    let line = out
        .lines()
        .find(|l| l.contains(CALL_ID))
        .unwrap_or_else(|| panic!("the call is missing:\n{out}"));
    let v: Value = serde_json::from_str(line).expect("parses");
    let c = &v["icmp_media"]["capture"];

    assert_eq!(c["errors"], 1, "the error is still counted: {c}");
    assert_eq!(c["unkeyed"], 1, "and counted as unkeyed: {c}");
    assert_eq!(c["flows"], 0, "it reached no flow at all: {c}");
    assert_eq!(c["attributed"], 0);
    assert_eq!(c["unattributed"], 1);

    let n = |k: &str| c[k].as_u64().unwrap_or_else(|| panic!("{k} missing: {c}"));
    assert_eq!(n("attributed") + n("unattributed"), n("errors"));
    assert_eq!(n("unkeyed") + n("untracked_flows"), n("errors"));

    let report = run_sipnab(&[
        "-N",
        "-I",
        pcap.to_str().expect("utf8 path"),
        "--report",
        "--no-cli-print",
    ]);
    assert!(
        report.contains("1 quoted too little to name a flow"),
        "the report must say the error had no flow rather than implying it \
         matched nothing:\n{report}"
    );
}

/// A capture with no ICMP grows neither the section nor the JSON field.
///
/// Absent rather than empty, so "no ICMP" in an output reads as "this capture
/// had none" and stays true.
#[test]
fn a_clean_capture_grows_neither_section_nor_field() {
    let report = run_sipnab(&[
        "-N",
        "-I",
        "tests/fixtures/sip_call.pcap",
        "--report",
        "--no-cli-print",
    ]);
    assert!(
        !report.contains("ICMP (media"),
        "a clean capture must not grow a section:\n{report}"
    );

    let out = run_sipnab(&[
        "-N",
        "-I",
        "tests/fixtures/sip_call.pcap",
        "--json-dialogs",
        "--no-cli-print",
    ]);
    for line in out.lines().filter(|l| !l.trim().is_empty()) {
        let v: Value = serde_json::from_str(line).expect("parses");
        assert!(
            v.get("icmp_media").is_none(),
            "a clean capture must not grow the field: {line}"
        );
    }
}

/// Render an address for comparison against output.
fn ip(a: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3])
}
