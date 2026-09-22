// SPDX-License-Identifier: MIT OR Apache-2.0

//! sipnab — SIP & RTP capture, analysis, and security library.
//!
//! The analysis engine behind the `sipnab` program: SIP message parsing, SDP,
//! dialog state tracking, RTP header parsing and quality scoring (MOS,
//! jitter, loss), a filter language for choosing calls, pcap and pcapng
//! reading, and detectors for scanners, fraud and digest leaks.
//!
//! Captured payloads travel as shared [`bytes::Bytes`] views rather than
//! copies, and [`sip::parser::parse_sip_bytes`] keeps a message's `raw` bytes
//! and body in that same buffer. Header values are decoded into owned
//! strings when the message is parsed, and [`sip::parser::parse_sip`] copies a
//! borrowed slice once before parsing it.
//!
//! # Stability
//!
//! **The library API is not stable.** The supported way to use sipnab is the
//! program, `cargo install sipnab`. sipnab releases often, and any release,
//! including a patch release, can rename, move or remove a public item. Pin the
//! exact release you built against:
//!
//! ```toml
//! [dependencies]
//! # Replace N with the patch number of the release you tested.
//! sipnab = { version = "=0.5.N", default-features = false, features = ["native"] }
//! ```
//!
//! Modules marked `#[doc(hidden)]` (`cli`, `tui`, `privilege`,
//! `process_isolation`, `signals`) exist so the program can be built from this
//! crate and are internal even by that standard.
//!
//! # Examples
//!
//! Every example below runs as a test on every `cargo test`, and checks what
//! it shows. [`bytes`] and [`chrono`] are re-exported so callers can use the
//! same buffer and timestamp types without separately pinning dependencies.
//!
//! ## Parse a SIP message and its SDP
//!
//! ```
//! use sipnab::SipMethod;
//! use sipnab::net::TransportProto;
//! use sipnab::sip::parser::parse_sip;
//!
//! let sdp = "v=0\r\n\
//!            o=alice 2890844526 2890844526 IN IP4 192.0.2.10\r\n\
//!            s=-\r\n\
//!            c=IN IP4 192.0.2.10\r\n\
//!            t=0 0\r\n\
//!            m=audio 49170 RTP/AVP 0\r\n\
//!            a=rtpmap:0 PCMU/8000\r\n";
//! let invite = format!(
//!     "INVITE sip:bob@example.com SIP/2.0\r\n\
//!      Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK776asdhds\r\n\
//!      From: \"Alice\" <sip:alice@example.com>;tag=1928301774\r\n\
//!      To: <sip:bob@example.com>\r\n\
//!      Call-ID: a84b4c76e66710@pc33.example.com\r\n\
//!      CSeq: 314159 INVITE\r\n\
//!      Content-Type: application/sdp\r\n\
//!      Content-Length: {}\r\n\r\n{sdp}",
//!     sdp.len()
//! );
//!
//! let msg = parse_sip(
//!     invite.as_bytes(),
//!     chrono::Utc::now(),
//!     "192.0.2.10".parse()?,
//!     "192.0.2.20".parse()?,
//!     5060,
//!     5060,
//!     TransportProto::Udp,
//! )?;
//!
//! assert_eq!(msg.method, Some(SipMethod::Invite));
//! assert_eq!(msg.call_id(), Some("a84b4c76e66710@pc33.example.com"));
//! assert_eq!(msg.from_user().as_deref(), Some("alice"));
//! assert_eq!(msg.cseq(), Some((314159, "INVITE")));
//!
//! let session = msg.sdp().ok_or("the INVITE carries SDP")?;
//! let audio = &session.media[0];
//! assert_eq!((audio.media_type.as_str(), audio.port), ("audio", 49170));
//! assert_eq!(audio.rtpmap[0].encoding, "PCMU");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## Follow a call from INVITE to BYE
//!
//! [`DialogStore`] groups messages by `Call-ID` and tracks each dialog's state.
//!
//! ```
//! use sipnab::net::TransportProto;
//! use sipnab::sip::parser::parse_sip;
//! use sipnab::{DialogState, DialogStore, SipMessage};
//!
//! /// One message on the wire, `secs` seconds into the call. Requests go
//! /// from Alice to Bob, responses come back.
//! fn sip(text: &str, secs: i64) -> Result<SipMessage, Box<dyn std::error::Error>> {
//!     let wire = text.replace('\n', "\r\n");
//!     let (src, dst) = if wire.starts_with("SIP/2.0") {
//!         ("192.0.2.20", "192.0.2.10")
//!     } else {
//!         ("192.0.2.10", "192.0.2.20")
//!     };
//!     let at = chrono::DateTime::from_timestamp(1_700_000_000 + secs, 0).unwrap_or_default();
//!     Ok(parse_sip(wire.as_bytes(), at, src.parse()?, dst.parse()?, 5060, 5060, TransportProto::Udp)?)
//! }
//!
//! let headers = |branch: &str, to_tag: &str, cseq: &str| {
//!     format!(
//!         "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-{branch}\n\
//!          From: <sip:alice@example.com>;tag=a1\n\
//!          To: <sip:bob@example.com>{to_tag}\n\
//!          Call-ID: call-1@example.com\n\
//!          CSeq: {cseq}\n\
//!          Content-Length: 0\n\n"
//!     )
//! };
//! let mut dialogs = DialogStore::new(1000, false);
//! for (secs, start, branch, to_tag, cseq) in [
//!     (0, "INVITE sip:bob@example.com SIP/2.0", "1", "", "1 INVITE"),
//!     (1, "SIP/2.0 180 Ringing", "1", ";tag=b1", "1 INVITE"),
//!     (3, "SIP/2.0 200 OK", "1", ";tag=b1", "1 INVITE"),
//!     (3, "ACK sip:bob@example.com SIP/2.0", "2", ";tag=b1", "1 ACK"),
//!     (60, "BYE sip:bob@example.com SIP/2.0", "3", ";tag=b1", "2 BYE"),
//!     (60, "SIP/2.0 200 OK", "3", ";tag=b1", "2 BYE"),
//! ] {
//!     dialogs.process_message(sip(&format!("{start}\n{}", headers(branch, to_tag, cseq)), secs)?);
//! }
//!
//! let call = dialogs.get("call-1@example.com").ok_or("the call was tracked")?;
//! assert_eq!(call.state(), &DialogState::Completed);
//! assert_eq!(call.final_status_code(), Some(200));
//! assert_eq!(call.messages.len(), 6);
//! assert_eq!(call.from_user.as_deref(), Some("alice"));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## Choose calls with the filter language
//!
//! A [`FilterExpr`] is the same language as `sipnab --filter`; see
//! [the filter language](https://github.com/NormB/sipnab/blob/main/docs/filter-dsl.md).
//!
//! ```
//! use sipnab::sip::dsl::select_dialogs;
//! use sipnab::{DialogStore, FilterExpr, StreamStore};
//! # use sipnab::net::TransportProto;
//! # use sipnab::sip::parser::parse_sip;
//! # use sipnab::SipMessage;
//! # fn sip(text: &str, secs: i64) -> Result<SipMessage, Box<dyn std::error::Error>> {
//! #     let wire = text.replace('\n', "\r\n");
//! #     let (src, dst) = if wire.starts_with("SIP/2.0") { ("192.0.2.20", "192.0.2.10") } else { ("192.0.2.10", "192.0.2.20") };
//! #     let at = chrono::DateTime::from_timestamp(1_700_000_000 + secs, 0).unwrap_or_default();
//! #     Ok(parse_sip(wire.as_bytes(), at, src.parse()?, dst.parse()?, 5060, 5060, TransportProto::Udp)?)
//! # }
//!
//! // Two calls: Bob answers the first, and Carol is busy for the second.
//! let call = |id: &str, to: &str, first_line: &str, to_tag: &str| {
//!     format!(
//!         "{first_line}\nVia: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-{id}\n\
//!          From: <sip:alice@example.com>;tag=a1\nTo: <sip:{to}@example.com>{to_tag}\n\
//!          Call-ID: {id}@example.com\nCSeq: 1 INVITE\nContent-Length: 0\n\n"
//!     )
//! };
//! let mut dialogs = DialogStore::new(1000, false);
//! for (secs, text) in [
//!     (0, call("answered", "bob", "INVITE sip:bob@example.com SIP/2.0", "")),
//!     (2, call("answered", "bob", "SIP/2.0 200 OK", ";tag=b1")),
//!     (5, call("busy", "carol", "INVITE sip:carol@example.com SIP/2.0", "")),
//!     (6, call("busy", "carol", "SIP/2.0 486 Busy Here", ";tag=c1")),
//! ] {
//!     dialogs.process_message(sip(&text, secs)?);
//! }
//! let streams = StreamStore::new(1000);
//!
//! let failed = FilterExpr::parse("state == 'Failed'")?;
//! let chosen = select_dialogs(Some(&failed), &dialogs, &streams);
//! assert_eq!(chosen.dialogs.len(), 1);
//! assert_eq!(chosen.dialogs[0].0.call_id, "busy@example.com");
//!
//! let to_bob = FilterExpr::parse("to.user == 'bob'")?;
//! let chosen = select_dialogs(Some(&to_bob), &dialogs, &streams);
//! assert_eq!(chosen.dialogs.len(), 1);
//! assert_eq!(chosen.dialogs[0].0.call_id, "answered@example.com");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## Read a capture and find its SIP
//!
//! [`PcapReader`] yields a capture's records, pcap or pcapng.
//! [`capture::parse::parse_packet`] decodes one into addresses, ports and a
//! payload, which stays a view into the frame's buffer all the way into
//! [`sip::parser::parse_sip_bytes`].
//!
//! ```
//! use sipnab::PcapReader;
//! use sipnab::capture::Packet;
//! use sipnab::capture::parse::parse_packet;
//! use sipnab::sip::parser::{parse_sip_bytes, starts_sip_message};
//! # /// A one-frame pcap: Ethernet, IPv4, UDP 5060 -> 5060, carrying `sip`.
//! # fn one_frame_pcap(sip: &[u8]) -> Vec<u8> {
//! #     let udp_len = 8 + sip.len();
//! #     let ip_len = 20 + udp_len;
//! #     let mut ip = vec![0x45, 0, (ip_len >> 8) as u8, ip_len as u8, 0, 0, 0x40, 0, 64, 17, 0, 0,
//! #                       192, 0, 2, 10, 192, 0, 2, 20];
//! #     let sum = ip.chunks(2).map(|w| u32::from(u16::from_be_bytes([w[0], w[1]]))).sum::<u32>();
//! #     let sum = !(((sum & 0xffff) + (sum >> 16)) as u16);
//! #     ip[10..12].copy_from_slice(&sum.to_be_bytes());
//! #     let mut frame = vec![0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 1, 0x08, 0x00];
//! #     frame.extend_from_slice(&ip);
//! #     frame.extend_from_slice(&[0x13, 0xc4, 0x13, 0xc4, (udp_len >> 8) as u8, udp_len as u8, 0, 0]);
//! #     frame.extend_from_slice(sip);
//! #     let mut pcap = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0,
//! #                         0xff, 0xff, 0, 0, 1, 0, 0, 0];
//! #     pcap.extend_from_slice(&1_700_000_000u32.to_le_bytes());
//! #     pcap.extend_from_slice(&0u32.to_le_bytes());
//! #     pcap.extend_from_slice(&(frame.len() as u32).to_le_bytes());
//! #     pcap.extend_from_slice(&(frame.len() as u32).to_le_bytes());
//! #     pcap.extend_from_slice(&frame);
//! #     pcap
//! # }
//! # let data = one_frame_pcap(
//! #     b"OPTIONS sip:probe@192.0.2.20 SIP/2.0\r\n\
//! #       Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-options\r\n\
//! #       From: <sip:monitor@example.com>;tag=m1\r\n\
//! #       To: <sip:probe@192.0.2.20>\r\n\
//! #       Call-ID: keepalive-7@example.com\r\n\
//! #       CSeq: 1 OPTIONS\r\n\
//! #       Content-Length: 0\r\n\r\n",
//! # );
//!
//! // let data = std::fs::read("capture.pcap")?;
//! let mut messages = Vec::new();
//! for record in PcapReader::new(&data)? {
//!     let timestamp = chrono::DateTime::from_timestamp(
//!         i64::from(record.timestamp_secs),
//!         record.timestamp_usecs * 1000,
//!     )
//!     .unwrap_or_default();
//!     let caplen = record.data.len();
//!     let frame = Packet::new(
//!         timestamp,
//!         record.data,
//!         caplen,
//!         record.orig_len as usize,
//!         record.interface,
//!         record.link_type as i32,
//!     );
//!
//!     // Frames sipnab does not decode (ARP, a truncated header, an unknown
//!     // link type) are an `Err` each, not the end of the capture.
//!     let Ok(packet) = parse_packet(&frame) else { continue };
//!     // A cheap first-line test keeps RTP and everything else out.
//!     if !starts_sip_message(&packet.payload) {
//!         continue;
//!     }
//!     messages.push(parse_sip_bytes(
//!         &packet.payload,
//!         packet.timestamp,
//!         packet.src_addr,
//!         packet.dst_addr,
//!         packet.src_port,
//!         packet.dst_port,
//!         packet.transport,
//!     )?);
//! }
//!
//! assert_eq!(messages.len(), 1);
//! assert_eq!(messages[0].call_id(), Some("keepalive-7@example.com"));
//! assert_eq!(messages[0].src_addr.to_string(), "192.0.2.10");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## Read an RTP header and score a call's quality
//!
//! ```
//! use sipnab::estimate_mos;
//! use sipnab::rtp::parser::parse_rtp_header;
//!
//! // Version 2, payload type 0 (PCMU), sequence 0x1234, timestamp 1000,
//! // SSRC 0xdeadbeef, then 20 ms of G.711 silence.
//! let mut packet = vec![0x80, 0x00, 0x12, 0x34, 0, 0, 0x03, 0xe8, 0xde, 0xad, 0xbe, 0xef];
//! packet.extend_from_slice(&[0xff; 160]);
//!
//! let header = parse_rtp_header(&packet)?;
//! assert_eq!(header.version, 2);
//! assert_eq!(header.payload_type, 0);
//! assert_eq!((header.sequence, header.timestamp, header.ssrc), (0x1234, 1000, 0xdead_beef));
//! assert_eq!(packet.len() - header.payload_offset, 160);
//!
//! // The E-model MOS: 1.0 to 4.5 from jitter (ms), loss (%) and codec.
//! let clean = estimate_mos(5.0, 0.0, Some("PCMU"));
//! let lossy = estimate_mos(40.0, 5.0, Some("PCMU"));
//! assert!(clean > 4.0, "a clean G.711 call scores near the ceiling: {clean}");
//! assert!(lossy < clean, "loss and jitter lower the score: {lossy}");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! More in the repository: [`docs/library.md`](https://github.com/NormB/sipnab/blob/main/docs/library.md)
//! for the library page and error handling, and
//! [`examples/`](https://github.com/NormB/sipnab/tree/main/examples) for
//! complete programs.

// Every item — public and private, down to fields and consts — must be
// documented, and unwrap/expect are banned on library production paths
// (tests are exempt via clippy.toml). These are crate attributes rather
// than workspace lints so test/bench crates are not covered — see the
// [workspace.lints] comment in Cargo.toml. CI runs clippy with
// `-D warnings`, so both doc lints are hard gates in practice.
#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]
#![warn(clippy::unwrap_used, clippy::expect_used)]
#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
pub mod analysis;
// Operator notes: written into pcapng packet comments, never read back.
// Native because it writes through the pcapng writer and follows frame
// pointers, both of which are libpcap-side.
#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
pub mod annotate;
#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
pub mod app;
#[cfg(any(feature = "api", feature = "mcp"))]
pub mod auth;
pub mod capture;
#[doc(hidden)]
#[cfg(feature = "native")]
pub mod cli;
pub mod config;
#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
pub mod crash;
pub mod crypto;
pub mod cursor;
pub mod error;
pub mod expect;
pub mod llmnr;
pub mod lru;
pub mod names;
pub mod net;
#[cfg(not(target_arch = "wasm32"))]
pub mod pipeline;
#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
pub mod sandbox;
#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
pub mod seccomp;
pub mod stun;
#[cfg(test)]
pub mod test_material;

#[cfg(feature = "plugins")]
pub mod plugin;
/// Byte buffers used by the public parsing API.
pub use bytes;
/// Timestamps used by public messages and capture records.
pub use chrono;

pub use error::{CaptureError, Error, ParseError};
pub mod clock;
#[cfg(feature = "mcp")]
pub mod mcp;
pub mod mermaid;
#[cfg(feature = "native")]
pub mod output;
#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
pub mod parallel;
#[doc(hidden)]
#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
pub mod privilege;
#[doc(hidden)]
#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
pub mod process_isolation;
pub mod provenance;
// One fixed-window limiter for every surface that meters a peer: the HEP
// receiver's packets, the MCP server's tool calls, and the REST API's
// requests. Compiled when any of them is, so a build with none carries no dead
// counter.
//
// `api` joined the list when the REST door stopped carrying its own limiter.
// It was a real break rather than a tidy-up: `--no-default-features --features
// api` stopped compiling, which the full-feature build could not show and the
// pre-push feature matrix did.
#[cfg(any(feature = "hep", feature = "mcp", feature = "api"))]
pub mod rate_limit;
// Native only, alongside `rtpengine`, which together with the MCP surface is
// its only caller: `reconcile` holds a `TransmitPermit`, which is itself
// native-gated, and a browser analyzer has no control plane to reconcile
// against in the first place.
#[cfg(not(target_arch = "wasm32"))]
pub mod relay;
pub mod relay_vocab;
pub mod rtp;
pub mod stats_vocab;
// Native only, exactly as `pipeline` is: this module hands `ng`-derived SDP to
// `pipeline::extract_sdp_links`, so it cannot compile where that does not. It
// would also have nothing to do there — an `ng` control plane reaches sipnab
// over HEP, and `hep` is a native feature, so the browser analyzer can never
// see one.
#[cfg(not(target_arch = "wasm32"))]
pub mod rtpengine;
pub mod security;
#[doc(hidden)]
#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
pub mod signals;
pub mod sip;
pub mod sort;
pub mod text;

#[doc(hidden)]
#[cfg(feature = "tui")]
pub mod tui;

#[cfg(target_arch = "wasm32")]
pub mod wasm;

#[cfg(test)]
pub mod test_utils;

// Convenience re-exports for library consumers
pub use capture::pcap_reader::{PcapReader, decompress_capture};
pub use rtp::quality::estimate_mos;
pub use rtp::stream::{RtpStream, StreamKey};
pub use rtp::stream_store::StreamStore;
pub use sip::SipMethod;
pub use sip::dialog::{DialogState, SipDialog};
pub use sip::dialog_store::DialogStore;
pub use sip::dsl::FilterExpr;
pub use sip::message::SipMessage;

// `docs/library.md` is the page a library consumer reads before writing a
// line against this crate, and until now nothing compiled a word of it. Its
// `PcapReader` snippet used `?` in what a doctest wraps as a `()`-returning
// `main` — E0277, code that has never once built, sitting under a heading
// that says "Crate-root surface". A consumer's first paste failed, and the
// suite stayed green because no target ever read the file.
//
// `#[cfg(doctest)]` is true only while rustdoc collects doctests, so this
// module exists for `cargo test` and for nothing else: it is absent from
// every normal build and from the rendered docs, which keeps the page's
// prose out of the crate root where the Quick Start above already lives.
// Including the file rather than copying its blocks is the point — a mirror
// would need its own drift gate, and a drift gate that can disagree with the
// thing it mirrors is a second source of truth.
#[cfg(doctest)]
#[doc = include_str!("../docs/library.md")]
mod library_md_is_compiled {}
