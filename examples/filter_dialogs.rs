// SPDX-License-Identifier: MIT OR Apache-2.0

//! Compile a filter expression once, then apply it to a whole capture.
//!
//! The cookbook shows the filter DSL from a shell, where `--filter` takes a
//! string you hand the binary. From the library it is a value:
//! [`FilterExpr::parse`] returns a compiled expression that either exists or
//! reports why it does not, and the parse happens **once** rather than per
//! dialog.
//!
//! The part worth copying is [`select_dialogs`]. A filter that reads a media
//! field has to see the streams belonging to each dialog, so "apply a filter"
//! is not a `.filter()` over one store — it is a join across two, plus the
//! per-call media diagnosis the expression may or may not need. That join is
//! this one function, and it is the same one `--report` and `--json-dialogs`
//! call, which is what stops those two surfaces from disagreeing about the
//! same capture. Reaching past it to `DialogStore::iter()` and matching by
//! hand is how a caller ends up with a third answer.
//!
//! Run it:
//!
//! ```sh
//! cargo run --features native --example filter_dialogs -- \
//!     tests/pcap-samples/codec-negotiation.pcap "method == 'INVITE'"
//! ```
//!
//! The inner quotes are the DSL's, not the shell's: a bare `method == INVITE`
//! is a parse error, because an unquoted token there is a field name and the
//! grammar will not silently treat one as a literal. `FilterExpr::parse` says
//! so, with the position and a hint, which is the behavior worth seeing.
//!
//! Omit the expression to select everything, which is what `None` means to
//! `select_dialogs` and is worth seeing as the baseline:
//!
//! ```sh
//! cargo run --features native --example filter_dialogs -- \
//!     tests/pcap-samples/codec-negotiation.pcap
//! ```
//!
//! A bad expression is rejected before a single packet is read — the parse is
//! the first thing this file does with it:
//!
//! ```sh
//! cargo run --features native --example filter_dialogs -- \
//!     tests/pcap-samples/codec-negotiation.pcap 'method =='
//! ```
//!
//! ```text
//! bad filter expression "method ==": unexpected input at position 9
//!   method ==
//!            ^
//! valid operators: ==, !=, <, <=, >, >=, =~ (regex)
//! see docs/filter-dsl.md for fields, values, and diagnostic aliases
//! ```
//!
//! The linking pass this file does before selecting is visible in the codec
//! column. On a capture that negotiated opus:
//!
//! ```sh
//! cargo run --features native --example filter_dialogs -- \
//!     tests/pcap-samples/invite-opus-bye.pcap
//! ```
//!
//! ```text
//! 1 of 1 dialog(s) selected, 2 of 2 stream(s) shown
//!
//! INVITE    Completed   alice -> bob  2 stream(s)  1-1176989@127.0.0.1
//!     ssrc 0eef0001  pt 96  opus        152 pkts
//!     ssrc 0eef0001  pt 96  opus        152 pkts
//! ```
//!
//! The `rtp_quality` example reads that same capture and prints `pt 96  -`
//! with jitter and MOS as `n/a`. Same file, same streams, same crate — the
//! difference is entirely that this one parsed the SDP and told the store
//! what PT 96 meant. A dynamic payload type carries no meaning of its own.
//!
//! [`FilterExpr::parse`]: sipnab::FilterExpr::parse
//! [`select_dialogs`]: sipnab::sip::dsl::select_dialogs

#[cfg(not(target_arch = "wasm32"))]
fn main() {
    use sipnab::capture::Packet;
    use sipnab::capture::parse::parse_packet;
    use sipnab::rtp::is_rtp_packet;
    use sipnab::rtp::parser::parse_rtp_header;
    use sipnab::sip::dsl::select_dialogs;
    use sipnab::sip::parser::{parse_sip, starts_sip_message};
    use sipnab::{DialogStore, FilterExpr, PcapReader, StreamStore};

    let mut args = std::env::args().skip(1);
    let Some(path) = args.next() else {
        eprintln!(
            "usage: filter_dialogs <capture.pcap|.pcapng> [filter-expression]\n\n\
             Try a capture from this repository:\n  \
             cargo run --features native --example filter_dialogs -- \\\n    \
             tests/pcap-samples/codec-negotiation.pcap \"method == 'INVITE'\""
        );
        std::process::exit(2);
    };
    let expression = args.next();

    // Parsed BEFORE the capture is opened. A typo in an expression is a
    // caller error, and reporting it after a minute of reading a large file
    // is a worse answer arrived at more slowly.
    let filter = match expression.as_deref() {
        Some(text) => match FilterExpr::parse(text) {
            Ok(expr) => Some(expr),
            Err(e) => {
                eprintln!("bad filter expression {text:?}: {e}");
                std::process::exit(2);
            }
        },
        None => None,
    };

    let data = match std::fs::read(&path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("cannot read {path}: {e}");
            std::process::exit(1);
        }
    };

    let reader = match PcapReader::new(&data) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{path} is not a capture this crate can read: {e}");
            std::process::exit(1);
        }
    };

    let mut dialogs = DialogStore::new(4096, false);
    let mut streams = StreamStore::new(1024);

    for pkt in reader {
        let timestamp =
            chrono::DateTime::from_timestamp(pkt.timestamp_secs as i64, pkt.timestamp_usecs * 1000)
                .unwrap_or_default();
        let caplen = pkt.data.len();
        let origlen = pkt.orig_len as usize;
        let link_type = pkt.link_type as i32;

        let frame = Packet::new(
            timestamp,
            pkt.data,
            caplen,
            origlen,
            pkt.interface,
            link_type,
        );

        let Ok(parsed) = parse_packet(&frame) else {
            continue;
        };

        // Both stores, from one pass. A media-reading filter needs the RTP
        // side populated, so a run that only fed the dialog store would answer
        // `jitter > 30` with "no matches" on a capture full of jitter.
        if starts_sip_message(&parsed.payload) {
            if let Ok(msg) = parse_sip(
                &parsed.payload,
                parsed.timestamp,
                parsed.src_addr,
                parsed.dst_addr,
                parsed.src_port,
                parsed.dst_port,
                parsed.transport,
            ) {
                dialogs.process_message(msg);
            }
        } else if is_rtp_packet(&parsed.payload)
            && let Ok(rtp) = parse_rtp_header(&parsed.payload)
        {
            streams.process_rtp(&parsed, &rtp, parsed.timestamp);
        }
    }

    // Second pass, and it has to be second. `link_to_dialog_with_sdp` binds
    // the streams that are ALREADY on an endpoint — it records nothing for a
    // stream that arrives later — so linking inside the loop would catch only
    // the media that happened to precede its own SDP offer. The live pipeline
    // solves this differently, with per-endpoint provenance that a stream can
    // claim from after the fact; a one-shot reader of a finished file does not
    // need that machinery, only the right order.
    //
    // It carries the `a=rtpmap` across too, which is what puts a codec and a
    // clock rate on a dynamic payload type. Without this, PT 96 stays
    // ungrounded and every media field in a filter expression reads `n/a` for
    // it — see the `rtp_quality` example, which deliberately omits this step.
    let mut links: Vec<(std::net::IpAddr, u16, String, sipnab::sip::sdp::SdpMedia)> = Vec::new();
    for dialog in dialogs.iter() {
        for msg in &dialog.messages {
            let Some(sdp) = msg.sdp() else { continue };
            for media in &sdp.media {
                // Media-level `c=` wins over the session-level one; that is
                // the SDP rule, and a call that answers on a different
                // interface than it offered relies on it.
                let addr = media
                    .connection
                    .as_ref()
                    .or(sdp.connection.as_ref())
                    .and_then(|c| c.addr.parse::<std::net::IpAddr>().ok());
                if let Some(addr) = addr {
                    links.push((addr, media.port, dialog.call_id.clone(), media.clone()));
                }
            }
        }
    }
    for (addr, port, call_id, media) in &links {
        streams.link_to_dialog_with_sdp(*addr, *port, call_id, media);
    }

    let selection = select_dialogs(filter.as_ref(), &dialogs, &streams);

    println!(
        "{} of {} dialog(s) selected, {} of {} stream(s) shown\n",
        selection.dialogs.len(),
        dialogs.len(),
        selection.streams.len(),
        streams.len(),
    );

    for (dialog, dialog_streams) in &selection.dialogs {
        let from = dialog.from_user.as_deref().unwrap_or("?");
        let to = dialog.to_user.as_deref().unwrap_or("?");
        println!(
            "{:<9} {:<11} {from} -> {to}  {} stream(s)  {}",
            dialog.method.as_str(),
            format!("{:?}", dialog.state()),
            dialog_streams.len(),
            dialog.call_id,
        );

        // The codec column is the receipt for the linking pass. A dynamic
        // payload type prints its name here only because an `a=rtpmap` in
        // this dialog's own SDP reached the stream; without the second pass
        // above it reads `-`, and every codec-dependent number downstream —
        // MOS included — is computed against a clock nobody confirmed.
        for stream in dialog_streams {
            println!(
                "    ssrc {:08x}  pt {:<3} {:<8} {:>6} pkts",
                stream.key.ssrc,
                stream.payload_type,
                stream.codec.as_deref().unwrap_or("-"),
                stream.packet_count,
            );
        }
    }
}

#[cfg(target_arch = "wasm32")]
fn main() {
    eprintln!("This example reads a file named on the command line; wasm32 has neither.");
}
