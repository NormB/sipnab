// SPDX-License-Identifier: MIT OR Apache-2.0

//! Calls that reuse one media socket pair and one SSRC report one stream per
//! call, on every surface that lists streams, and the `--report` stream table
//! stays aligned when a codec name is longer than its column.
//!
//! Both defects were found by running the proxy guides on real machines. A
//! test tool that replays one recorded media file per call puts the same
//! SSRC on the same ports in every call, and `--report` merged two calls into
//! one stream per direction: 472 packets over 16 s, and a telephone-event
//! stream whose jitter read 324 ms because it spanned the gap between the
//! calls. The same table printed `telephone-event` into an 8-character Codec
//! column, which pushed every later column of that row out of line.
//!
//! The capture is built by [`pcap_build::calls_reusing_media`]: two complete
//! calls eight seconds apart, each with PCMU both ways and a telephone-event
//! stream, identical SSRCs, ports, sequence numbers and RTP timestamps.
#![cfg(feature = "native")]

use std::path::Path;
use std::process::Command;

#[path = "support/pcap_build.rs"]
mod pcap_build;

use pcap_build::{
    REUSED_MEDIA_AUDIO_PACKETS, REUSED_MEDIA_DTMF_PACKETS, REUSED_MEDIA_SSRC_A,
    REUSED_MEDIA_SSRC_B, REUSED_MEDIA_SSRC_DTMF, calls_reusing_media, write_pcap_at,
};

/// Any error a test can return; `?` converts into it.
type TestError = Box<dyn std::error::Error>;

/// The two Call-IDs the capture carries, in order.
const CALLS: [&str; 2] = ["reuse-call-1@test", "reuse-call-2@test"];

/// Write the two-call capture into `dir` and return its path.
fn two_call_capture(dir: &Path) -> Result<String, TestError> {
    let path = dir.join("two-calls-same-media.pcap");
    write_pcap_at(&path, &calls_reusing_media(&CALLS, 8_000), 1)?;
    Ok(path
        .to_str()
        .ok_or("the temp path is not UTF-8")?
        .to_string())
}

/// Run sipnab headless on `pcap` with `extra` and return stdout.
fn run(pcap: &str, extra: &[&str]) -> Result<String, TestError> {
    let mut args = vec!["-N", "-I", pcap, "--no-cli-print"];
    args.extend_from_slice(extra);
    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(&args)
        .env("SIPNAB_LOG", "warn")
        .output()?;
    assert!(
        out.status.success(),
        "sipnab exited {:?}; stderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// The lines of the `RTP Streams:` table: its header, then its data rows,
/// without the dashed rule. Ends at the first blank line.
fn rtp_table(report: &str) -> Result<Vec<&str>, TestError> {
    let mut lines = report.lines().skip_while(|l| *l != "RTP Streams:").skip(1);
    let header = lines.next().ok_or("the report has no RTP Streams table")?;
    let rows: Vec<&str> = lines
        .skip(1) // the dashed rule
        .take_while(|l| !l.trim().is_empty())
        .collect();
    let mut out = vec![header];
    out.extend(rows);
    Ok(out)
}

/// `--report` lists six streams for two calls of three streams each, every
/// one carrying exactly one call's packets.
#[test]
fn the_report_lists_each_calls_streams_separately() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let pcap = two_call_capture(dir.path())?;
    let report = run(&pcap, &["--report"])?;
    let table = rtp_table(&report)?;
    let rows = &table[1..];
    assert_eq!(
        rows.len(),
        6,
        "two calls of three streams each are six streams, not one per \
         direction across both calls:\n{report}"
    );
    // Audio runs one second per call; the ten telephone-event packets span
    // 180 ms, which the Dur column rounds to 0 s.
    for (ssrc, packets, duration) in [
        (REUSED_MEDIA_SSRC_A, REUSED_MEDIA_AUDIO_PACKETS, "1s"),
        (REUSED_MEDIA_SSRC_B, REUSED_MEDIA_AUDIO_PACKETS, "1s"),
        (REUSED_MEDIA_SSRC_DTMF, REUSED_MEDIA_DTMF_PACKETS, "0s"),
    ] {
        let label = format!("0x{ssrc:08x}");
        let mine: Vec<&&str> = rows.iter().filter(|r| r.starts_with(&label)).collect();
        assert_eq!(mine.len(), 2, "one {label} stream per call:\n{report}");
        for row in mine {
            let cells: Vec<&str> = row.split_whitespace().collect();
            // SSRC PT Codec Clock Source Destination Pkts Lost Loss% Jitter Dur Kbps
            assert_eq!(
                cells.get(6).copied(),
                Some(packets.to_string().as_str()),
                "each {label} stream carries one call's packets:\n{report}"
            );
            assert_eq!(
                cells.get(9).copied(),
                Some("0ms"),
                "a stream confined to one call has the jitter of that call, \
                 not of the gap between calls:\n{report}"
            );
            assert_eq!(
                cells.get(10).copied(),
                Some(duration),
                "a stream confined to one call lasts only as long as its media \
                 in that call:\n{report}"
            );
        }
    }
    Ok(())
}

/// `--cores 2` reaches the same six streams: a call's SIP and RTP between
/// the same two hosts are read by one worker, which splits the streams as the
/// single-core reader does, and the merge keeps both sessions.
#[test]
fn the_multi_core_report_lists_each_calls_streams_separately() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let pcap = two_call_capture(dir.path())?;
    let report = run(&pcap, &["--report", "--cores", "2"])?;
    let table = rtp_table(&report)?;
    let mut packets: Vec<&str> = table[1..]
        .iter()
        .filter_map(|r| r.split_whitespace().nth(6))
        .collect();
    packets.sort_unstable();
    assert_eq!(
        packets,
        ["10", "10", "50", "50", "50", "50"],
        "six streams, each with one call's packets:\n{report}"
    );
    Ok(())
}

/// Every row of the `RTP Streams:` table starts each column where the header
/// starts it, including the row whose codec is `telephone-event`.
#[test]
fn the_stream_table_stays_aligned_with_a_long_codec_name() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let pcap = two_call_capture(dir.path())?;
    let report = run(&pcap, &["--report"])?;
    let table = rtp_table(&report)?;
    let header = table[0];
    assert!(
        table[1..].iter().any(|r| r.contains("telephone-event")),
        "the capture must put telephone-event in the table:\n{report}"
    );
    for column in ["Clock", "Source", "Destination", "Pkts", "Jitter", "Kbps"] {
        let at = header
            .find(column)
            .ok_or_else(|| format!("no {column} column in {header:?}"))?;
        for row in &table[1..] {
            let before = row.get(..at).ok_or("row shorter than the header")?;
            assert!(
                before.ends_with(' ') && !row[at..].starts_with(' '),
                "the {column} column starts at byte {at} in the header and \
                 elsewhere in this row:\n{header}\n{row}"
            );
        }
    }
    Ok(())
}

/// `--json-dialogs` gives each call its own three streams, with that call's
/// packet counts, and no stream appears under both calls.
#[test]
fn json_dialogs_binds_each_call_to_its_own_streams() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let pcap = two_call_capture(dir.path())?;
    let out = run(&pcap, &["--json-dialogs"])?;
    let dialogs: Vec<serde_json::Value> = out
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    assert_eq!(dialogs.len(), 2, "two dialogs:\n{out}");
    for d in &dialogs {
        let streams = d["streams"]
            .as_array()
            .ok_or_else(|| format!("no streams array in {d}"))?;
        let mut packets: Vec<u64> = streams
            .iter()
            .filter_map(|s| s["packets"].as_u64())
            .collect();
        packets.sort_unstable();
        assert_eq!(
            packets,
            [
                u64::from(REUSED_MEDIA_DTMF_PACKETS),
                u64::from(REUSED_MEDIA_AUDIO_PACKETS),
                u64::from(REUSED_MEDIA_AUDIO_PACKETS),
            ],
            "call {} holds its own three streams:\n{out}",
            d["call_id"]
        );
    }
    Ok(())
}

/// Packet counts of the streams in `streams`, grouped by the call each is
/// bound to, read from the `associated_dialog` and `packets` fields REST and
/// MCP both serve.
#[cfg(any(feature = "api", all(unix, feature = "mcp")))]
fn packets_by_call(
    streams: &[serde_json::Value],
) -> Result<std::collections::BTreeMap<String, Vec<u64>>, TestError> {
    let mut by_call: std::collections::BTreeMap<String, Vec<u64>> = Default::default();
    for s in streams {
        let call = s["associated_dialog"]
            .as_str()
            .ok_or_else(|| format!("stream bound to no call: {s}"))?;
        let packets = s["packets"]
            .as_u64()
            .ok_or_else(|| format!("stream with no packet count: {s}"))?;
        by_call.entry(call.to_string()).or_default().push(packets);
    }
    for v in by_call.values_mut() {
        v.sort_unstable();
    }
    Ok(by_call)
}

/// What every call in the capture must hold: its own three streams.
#[cfg(any(feature = "api", all(unix, feature = "mcp")))]
fn expected_by_call() -> std::collections::BTreeMap<String, Vec<u64>> {
    CALLS
        .iter()
        .map(|c| {
            (
                (*c).to_string(),
                vec![
                    u64::from(REUSED_MEDIA_DTMF_PACKETS),
                    u64::from(REUSED_MEDIA_AUDIO_PACKETS),
                    u64::from(REUSED_MEDIA_AUDIO_PACKETS),
                ],
            )
        })
        .collect()
}

#[cfg(feature = "api")]
#[path = "support/server.rs"]
mod server;

/// `GET /v1/streams` lists six streams, three bound to each call.
#[cfg(feature = "api")]
#[test]
fn rest_streams_lists_each_calls_streams_separately() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let pcap = two_call_capture(dir.path())?;
    let srv = server::ApiServer::spawn_with_pcap(&pcap, &[])?;
    let resp = srv.get("/v1/streams")?;
    assert_eq!(resp.status, 200, "{}", resp.body);
    let body = resp.json()?;
    let streams = body["streams"]
        .as_array()
        .ok_or_else(|| format!("no streams array: {body}"))?;
    assert_eq!(
        packets_by_call(streams)?,
        expected_by_call(),
        "each call's streams, with that call's packets:\n{body}"
    );
    Ok(())
}

#[cfg(all(unix, feature = "mcp"))]
#[path = "support/mcp.rs"]
mod mcp;

/// MCP `rtp_stats` answers each Call-ID with that call's three streams, and
/// the capture-wide form lists all six.
#[cfg(all(unix, feature = "mcp"))]
#[test]
fn mcp_rtp_stats_reports_each_calls_streams_separately() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let pcap = two_call_capture(dir.path())?;
    let mut session = mcp::McpSession::start(&pcap, &[])?;
    let wide = session.ok("rtp_stats", serde_json::json!({}))?;
    let streams = wide["streams"]
        .as_array()
        .ok_or_else(|| format!("no streams array: {wide}"))?;
    assert_eq!(
        packets_by_call(streams)?,
        expected_by_call(),
        "capture-wide rtp_stats:\n{wide}"
    );
    for call in CALLS {
        let one = session.ok("rtp_stats", serde_json::json!({ "call_id": call }))?;
        let streams = one["streams"]
            .as_array()
            .ok_or_else(|| format!("no streams array: {one}"))?;
        let mut packets: Vec<u64> = streams
            .iter()
            .filter_map(|s| s["packets"].as_u64())
            .collect();
        packets.sort_unstable();
        assert_eq!(
            Some(&packets),
            expected_by_call().get(call),
            "rtp_stats for {call}:\n{one}"
        );
    }
    Ok(())
}
