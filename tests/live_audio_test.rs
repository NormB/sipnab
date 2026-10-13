// SPDX-License-Identifier: MIT OR Apache-2.0

//! Live audio: a `[[vcon.rule]]` with `live_audio = true` serves each matching
//! call's decoded audio over a WebSocket at `/v1/calls/{call_id}/audio`, lists
//! calls in progress at `/v1/calls/live`, and announces each one on the
//! server-sent events of `/v1/calls/live/events`.
//!
//! Driven against a capture read with `-I`, which leaves one call ended (it
//! has a BYE) and one still in progress (it has none), so both ends of the
//! stream are reached: a call that ended is replayed and closed, and a call in
//! progress stays open.
#![cfg(all(feature = "api", feature = "vcon"))]

#[path = "support/pcap_build.rs"]
mod pcap_build;
#[path = "support/server.rs"]
mod server;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::time::Duration;

use server::{ApiServer, TestError};

/// Seconds of audio each call carries: 50 RTP packets per direction per
/// second, 160 samples each.
const SECS: usize = 1;

fn tone(stream: usize, frame: usize, i: usize) -> u8 {
    ((stream * 37 + frame * 3 + i) % 200) as u8
}

/// A capture holding `ended` (with a BYE), `ongoing` (without) and `other`
/// (with a BYE, matched by no live rule).
fn capture(dir: &Path) -> Result<String, TestError> {
    capture_with(dir, None)
}

/// [`capture`], with `header` on the INVITE of `ongoing`.
fn capture_with(dir: &Path, header: Option<&str>) -> Result<String, TestError> {
    capture_full(dir, header, false)
}

/// [`capture_with`], and, with `g729`, a third stream on `ongoing` carrying
/// G.729 (static payload type 18), which sipnab does not decode.
fn capture_full(dir: &Path, header: Option<&str>, g729: bool) -> Result<String, TestError> {
    let leg = |call_id, net: u8, ends, header| {
        pcap_build::g711_leg(
            &pcap_build::G711Leg {
                call_id,
                caller: ([10, net, 0, 1], 20000, 0x1000_0000 | u32::from(net)),
                callee: ([10, net, 0, 2], 30000, 0x2000_0000 | u32::from(net)),
                header,
                start_us: u64::from(net) * 10_000,
                ends,
            },
            SECS,
            tone,
        )
    };
    let mut frames = leg("ended", 1, true, None);
    frames.extend(leg("ongoing", 2, false, header));
    frames.extend(leg("other", 3, true, None));
    if g729 {
        for seq in 0..10u16 {
            let mut rtp = vec![0x80, 18];
            rtp.extend_from_slice(&seq.to_be_bytes());
            rtp.extend_from_slice(&(u32::from(seq) * 160).to_be_bytes());
            rtp.extend_from_slice(&0x0729_0729u32.to_be_bytes());
            rtp.extend_from_slice(&[0x55; 20]);
            frames.push((
                pcap_build::udp_frame([10, 2, 0, 2], [10, 2, 0, 1], 30000, 20000, &rtp),
                40_000 + u64::from(seq) * 20_000,
            ));
        }
    }
    frames.sort_by_key(|(_, at)| *at);
    let path = dir.join("calls.pcap");
    pcap_build::write_pcap_at(&path, &frames, 1)?;
    Ok(path.to_str().ok_or("utf-8 path")?.to_owned())
}

/// A config with a live-audio rule for every call but `other`.
fn config(dir: &Path) -> Result<String, TestError> {
    let path = dir.join("sipnab.toml");
    std::fs::write(
        &path,
        format!(
            "[[vcon.rule]]\nname = \"live\"\nwhen = \"call_id != 'other'\"\ndir = \"{}\"\n\
             live_audio = true\n",
            dir.join("spool").display()
        ),
    )?;
    Ok(path.to_str().ok_or("utf-8 path")?.to_owned())
}

/// A server over the capture with the live rule.
fn serve(dir: &Path, extra: &[&str]) -> Result<ApiServer, TestError> {
    let pcap = capture(dir)?;
    let cfg = config(dir)?;
    let mut args = vec!["--config", cfg.as_str()];
    args.extend_from_slice(extra);
    ApiServer::spawn_with_pcap(&pcap, &args)
}

/// One message a client read: text or binary.
#[derive(Debug)]
enum Message {
    Text(serde_json::Value),
    Binary(Vec<u8>),
    Close(u16),
}

/// A WebSocket client of the audio route.
struct Socket {
    reader: BufReader<TcpStream>,
}

impl Socket {
    /// Open `path` on `addr`. `Err` carries the HTTP status line when the
    /// server did not switch protocols.
    fn open(
        addr: &str,
        path: &str,
        bearer: Option<&str>,
    ) -> Result<Result<Self, String>, TestError> {
        let mut stream = TcpStream::connect(addr)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        let auth = bearer.map_or_else(String::new, |t| format!("Authorization: Bearer {t}\r\n"));
        write!(
            stream,
            "GET {path} HTTP/1.1\r\nHost: {addr}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n{auth}\r\n"
        )?;
        let mut reader = BufReader::new(stream);
        let mut status = String::new();
        reader.read_line(&mut status)?;
        let mut accept = None;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line)?;
            if line == "\r\n" || line.is_empty() {
                break;
            }
            if let Some(v) = line
                .to_ascii_lowercase()
                .strip_prefix("sec-websocket-accept:")
            {
                accept = Some(v.trim().to_owned());
            }
        }
        if !status.contains(" 101 ") {
            return Ok(Err(status.trim().to_owned()));
        }
        assert_eq!(
            accept.as_deref(),
            Some("s3pplmbitxaq9kygzzhzrbk+xoo="),
            "the RFC 6455 accept key"
        );
        Ok(Ok(Self { reader }))
    }

    /// The next message, or `None` when nothing arrives within the timeout.
    fn next(&mut self) -> Result<Option<Message>, TestError> {
        let mut head = [0u8; 2];
        match self.reader.read_exact(&mut head) {
            Ok(()) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Ok(None);
            }
            Err(e) => return Err(e.into()),
        }
        assert_eq!(head[0] & 0x80, 0x80, "a whole frame");
        assert_eq!(head[1] & 0x80, 0, "a server never masks");
        let len = match head[1] & 0x7F {
            126 => {
                let mut b = [0u8; 2];
                self.reader.read_exact(&mut b)?;
                usize::from(u16::from_be_bytes(b))
            }
            127 => {
                let mut b = [0u8; 8];
                self.reader.read_exact(&mut b)?;
                usize::try_from(u64::from_be_bytes(b))?
            }
            n => usize::from(n),
        };
        let mut payload = vec![0u8; len];
        self.reader.read_exact(&mut payload)?;
        Ok(Some(match head[0] & 0x0F {
            0x1 => Message::Text(serde_json::from_slice(&payload)?),
            0x2 => Message::Binary(payload),
            0x8 => Message::Close(u16::from_be_bytes([payload[0], payload[1]])),
            other => return Err(format!("unexpected opcode {other}").into()),
        }))
    }
}

/// Every message until the server closes, or `None` for the close when the
/// stream stays open past the timeout.
fn drain(socket: &mut Socket) -> Result<(Vec<Message>, Option<u16>), TestError> {
    let mut out = Vec::new();
    while let Some(message) = socket.next()? {
        if let Message::Close(code) = message {
            return Ok((out, Some(code)));
        }
        out.push(message);
    }
    Ok((out, None))
}

/// Binary frames per stream index, and the samples in each.
fn frames_by_stream(messages: &[Message]) -> std::collections::BTreeMap<u8, Vec<usize>> {
    let mut by = std::collections::BTreeMap::new();
    for m in messages {
        if let Message::Binary(b) = m {
            by.entry(b[0])
                .or_insert_with(Vec::new)
                .push((b.len() - 1) / 2);
        }
    }
    by
}

/// A call that ended: every RTP packet of both directions arrives as one
/// frame of 160 samples, each stream is announced first, and the server ends
/// the stream and closes.
#[test]
fn an_ended_call_is_replayed_and_closed() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let srv = serve(dir.path(), &[])?;
    let mut socket = Socket::open(&srv.addr, "/v1/calls/ended/audio", None)?
        .map_err(|status| format!("no upgrade: {status}"))?;
    let (messages, close) = drain(&mut socket)?;
    assert_eq!(close, Some(1000), "a normal close at the call's end");
    let streams: Vec<&serde_json::Value> = messages
        .iter()
        .filter_map(|m| match m {
            Message::Text(v) if v["type"] == "stream" => Some(v),
            _ => None,
        })
        .collect();
    assert_eq!(streams.len(), 2, "both directions: {messages:?}");
    for s in &streams {
        assert_eq!(s["codec"], "PCMU");
        assert_eq!(s["rate"], 8000);
        assert_eq!(s["format"], "s16le");
    }
    let by = frames_by_stream(&messages);
    assert_eq!(by.len(), 2);
    for (stream, sizes) in &by {
        assert_eq!(
            sizes.len(),
            SECS * 50,
            "stream {stream}: one frame per packet"
        );
        assert!(
            sizes.iter().all(|n| *n == 160),
            "stream {stream}: 160 samples each"
        );
    }
    let end = messages
        .iter()
        .rev()
        .find_map(|m| match m {
            Message::Text(v) => Some(v),
            _ => None,
        })
        .ok_or("an end message")?;
    assert_eq!(end["type"], "end", "{end}");
    Ok(())
}

/// A call in progress: its audio so far arrives, and the stream stays open.
#[test]
fn a_call_in_progress_stays_open() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let srv = serve(dir.path(), &[])?;
    let mut socket = Socket::open(&srv.addr, "/v1/calls/ongoing/audio", None)?
        .map_err(|status| format!("no upgrade: {status}"))?;
    let (messages, close) = drain(&mut socket)?;
    assert_eq!(close, None, "still open: the call has not ended");
    let by = frames_by_stream(&messages);
    assert_eq!(by.values().map(Vec::len).sum::<usize>(), 2 * SECS * 50);
    Ok(())
}

/// The live list holds the call in progress that a live rule matches, and
/// neither the ended call nor the one no live rule matches.
#[test]
fn the_live_list_holds_calls_in_progress() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let srv = serve(dir.path(), &[])?;
    let resp = srv.get("/v1/calls/live")?;
    assert_eq!(resp.status, 200, "{}", resp.body);
    let body = resp.json()?;
    let ids: Vec<&str> = body["calls"]
        .as_array()
        .ok_or("calls")?
        .iter()
        .filter_map(|c| c["call_id"].as_str())
        .collect();
    assert_eq!(ids, ["ongoing"], "{body}");
    // The fields the OpenAPI document's `LiveCall` names, and no others.
    let call = body["calls"][0].as_object().ok_or("a call object")?;
    let mut keys: Vec<&str> = call.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        ["audio", "call_id", "started", "state", "streams"],
        "{body}"
    );
    assert_eq!(call["audio"], "/v1/calls/ongoing/audio");
    assert_eq!(call["streams"], 2);
    Ok(())
}

/// The events stream announces each call in progress.
#[test]
fn the_events_stream_announces_a_call() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let srv = serve(dir.path(), &[])?;
    let mut stream = TcpStream::connect(&srv.addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    write!(
        stream,
        "GET /v1/calls/live/events HTTP/1.1\r\nHost: {}\r\nAccept: text/event-stream\r\n\r\n",
        srv.addr
    )?;
    let mut reader = BufReader::new(stream);
    let mut seen = String::new();
    let mut line = String::new();
    while reader.read_line(&mut line)? > 0 {
        seen.push_str(&line);
        if line.starts_with("data:") && line.contains("\"ongoing\"") {
            break;
        }
        line.clear();
    }
    assert!(seen.contains("text/event-stream"), "{seen}");
    assert!(seen.contains("event: call"), "{seen}");
    assert!(seen.contains("\"ongoing\""), "{seen}");
    Ok(())
}

/// A call no live rule matches, and a Call-ID the capture does not hold, are
/// not served.
#[test]
fn a_call_no_live_rule_matches_is_not_served() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let srv = serve(dir.path(), &[])?;
    for call in ["other", "nowhere"] {
        let refused = Socket::open(&srv.addr, &format!("/v1/calls/{call}/audio"), None)?;
        let Err(status) = refused else {
            return Err(format!("{call} was served").into());
        };
        assert!(status.contains(" 404 "), "{call}: {status}");
    }
    Ok(())
}

/// A server with an API key serves audio only to a token with the `audio`
/// scope: the static key, which is `full`, is not enough.
#[test]
fn audio_needs_the_audio_scope_when_a_key_is_set() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let key = "k".repeat(40);
    let srv = serve(dir.path(), &["--api-key", &key])?;
    for bearer in [None, Some(key.as_str())] {
        let refused = Socket::open(&srv.addr, "/v1/calls/ended/audio", bearer)?;
        let Err(status) = refused else {
            return Err("served without the audio scope".into());
        };
        assert!(
            status.contains(" 401 ") || status.contains(" 403 "),
            "{status}"
        );
    }
    Ok(())
}

/// A live-audio rule refuses to start on an address other than loopback
/// unless the API has TLS and a key.
#[test]
fn live_audio_off_loopback_needs_tls_and_a_key() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let pcap = capture(dir.path())?;
    let cfg = config(dir.path())?;
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(["-N", "-I", &pcap, "--api", "0.0.0.0:0", "--config", &cfg])
        .output()?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(stderr.contains("live_audio"), "{stderr}");
    assert!(stderr.contains("TLS"), "{stderr}");
    Ok(())
}

/// A call `--content-deny-header` withholds is neither listed nor served.
#[test]
fn a_denied_call_is_not_served() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let pcap = capture_with(dir.path(), Some("X-No-Record: 1"))?;
    let cfg = config(dir.path())?;
    let srv = ApiServer::spawn_with_pcap(
        &pcap,
        &["--config", &cfg, "--content-deny-header", "X-No-Record"],
    )?;
    let body = srv.get("/v1/calls/live")?.json()?;
    assert_eq!(body["calls"], serde_json::json!([]), "{body}");
    let refused = Socket::open(&srv.addr, "/v1/calls/ongoing/audio", None)?;
    let Err(status) = refused else {
        return Err("a denied call was served".into());
    };
    assert!(status.contains(" 404 "), "{status}");
    Ok(())
}

impl Socket {
    /// Send one masked client frame.
    fn send(&mut self, opcode: u8, payload: &[u8]) -> Result<(), TestError> {
        let mask = [1u8, 2, 3, 4];
        let mut frame = vec![0x80 | opcode, 0x80 | u8::try_from(payload.len())?];
        frame.extend_from_slice(&mask);
        frame.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
        self.reader.get_mut().write_all(&frame)?;
        Ok(())
    }

    /// The next pong, skipping audio, or `None`.
    fn pong(&mut self) -> Result<Option<Vec<u8>>, TestError> {
        loop {
            let mut head = [0u8; 2];
            if self.reader.read_exact(&mut head).is_err() {
                return Ok(None);
            }
            let len = match head[1] & 0x7F {
                126 => {
                    let mut b = [0u8; 2];
                    self.reader.read_exact(&mut b)?;
                    usize::from(u16::from_be_bytes(b))
                }
                n => usize::from(n),
            };
            let mut payload = vec![0u8; len];
            self.reader.read_exact(&mut payload)?;
            if head[0] & 0x0F == 0xA {
                return Ok(Some(payload));
            }
        }
    }
}

/// A ping is answered with its payload, and a close is answered with a close.
#[test]
fn the_socket_answers_ping_and_close() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let srv = serve(dir.path(), &[])?;
    let mut socket = Socket::open(&srv.addr, "/v1/calls/ongoing/audio", None)?
        .map_err(|status| format!("no upgrade: {status}"))?;
    socket.send(0x9, b"are-you-there")?;
    assert_eq!(socket.pong()?.as_deref(), Some(&b"are-you-there"[..]));
    socket.send(0x8, &1000u16.to_be_bytes())?;
    let (_, close) = drain(&mut socket)?;
    assert_eq!(close, Some(1000), "a close answered with a close");
    Ok(())
}

/// A request that is not a WebSocket upgrade is told so.
#[test]
fn a_plain_get_of_the_socket_is_a_400() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let srv = serve(dir.path(), &[])?;
    let resp = srv.get("/v1/calls/ended/audio")?;
    assert_eq!(resp.status, 400, "{}", resp.body);
    assert!(resp.body.contains("WebSocket"), "{}", resp.body);
    Ok(())
}

/// The list and the events need the `audio` scope too.
#[test]
fn the_list_and_events_need_the_audio_scope() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let key = "k".repeat(40);
    let srv = serve(dir.path(), &["--api-key", &key])?;
    for path in ["/v1/calls/live", "/v1/calls/live/events"] {
        let resp = srv.get_bearer(path, &key)?;
        assert!(matches!(resp.status, 401 | 403), "{path}: {}", resp.status);
    }
    Ok(())
}

/// A stream whose codec sipnab does not decode is named, and not sent.
#[test]
fn an_undecodable_stream_is_named_and_skipped() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let pcap = capture_full(dir.path(), None, true)?;
    let cfg = config(dir.path())?;
    let srv = ApiServer::spawn_with_pcap(&pcap, &["--config", &cfg])?;
    let mut socket = Socket::open(&srv.addr, "/v1/calls/ongoing/audio", None)?
        .map_err(|status| format!("no upgrade: {status}"))?;
    let (messages, _) = drain(&mut socket)?;
    let skipped: Vec<&serde_json::Value> = messages
        .iter()
        .filter_map(|m| match m {
            Message::Text(v) if v["type"] == "skipped" => Some(v),
            _ => None,
        })
        .collect();
    assert_eq!(skipped.len(), 1, "{messages:?}");
    assert_eq!(skipped[0]["ssrc"], "0x07290729", "{}", skipped[0]);
    assert_eq!(
        frames_by_stream(&messages).len(),
        2,
        "only the PCMU streams are sent"
    );
    Ok(())
}

/// Packets the retention ring dropped before the socket read them are a gap,
/// said so, before the packets that remain.
#[test]
fn packets_dropped_before_reading_are_a_stated_gap() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let pcap = capture(dir.path())?;
    let cfg = config(dir.path())?;
    let mut text = std::fs::read_to_string(&cfg)?;
    text.push_str("\n[limits]\nmax_audio_frames = 10\n");
    std::fs::write(&cfg, text)?;
    let srv = ApiServer::spawn_with_pcap(&pcap, &["--config", &cfg])?;
    let mut socket = Socket::open(&srv.addr, "/v1/calls/ended/audio", None)?
        .map_err(|status| format!("no upgrade: {status}"))?;
    let (messages, _) = drain(&mut socket)?;
    let gaps: Vec<&serde_json::Value> = messages
        .iter()
        .filter_map(|m| match m {
            Message::Text(v) if v["type"] == "gap" => Some(v),
            _ => None,
        })
        .collect();
    assert_eq!(gaps.len(), 2, "one per stream: {messages:?}");
    for gap in gaps {
        assert_eq!(gap["packets"], SECS * 50 - 10, "{gap}");
    }
    for sizes in frames_by_stream(&messages).values() {
        assert_eq!(sizes.len(), 10, "what the ring kept");
    }
    Ok(())
}

/// A client frame that breaks the protocol, here an unmasked one, closes the
/// socket with 1002.
#[test]
fn a_bad_client_frame_closes_with_a_protocol_error() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let srv = serve(dir.path(), &[])?;
    let mut socket = Socket::open(&srv.addr, "/v1/calls/ongoing/audio", None)?
        .map_err(|status| format!("no upgrade: {status}"))?;
    socket.reader.get_mut().write_all(&[0x89, 0x00])?;
    let (_, close) = drain(&mut socket)?;
    assert_eq!(close, Some(1002));
    Ok(())
}
