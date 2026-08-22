// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-stream jitter, loss and MOS — and the one that refuses to answer.
//!
//! [`estimate_mos`] is a pure function of three numbers, so a doctest can
//! demonstrate the arithmetic and this example would be redundant if the
//! arithmetic were the hard part. It is not. The hard part is that **none of
//! the three inputs exists in a packet** — jitter is an accumulation over a
//! stream's whole life, loss is a gap in a sequence you only notice later,
//! and the codec is named by an SDP body in a *different* protocol. Getting
//! them requires running a capture through [`StreamStore`], which is what
//! this file does.
//!
//! The refusal is the reason it prints jitter the long way. `stream.jitter`
//! is always a number; [`StreamStore::measured_jitter_ms`] returns `None`
//! when that number is not evidence — when the payload type is dynamic and no
//! `a=rtpmap` grounded its clock rate, so the "milliseconds" were computed
//! against an assumed clock, or when the stream has not yet converged after a
//! restart. An example that printed `stream.jitter` unconditionally would
//! show a confident figure for a stream sipnab declines to score, which is
//! the failure this API exists to prevent.
//!
//! Run it on a capture whose payload types the RTP/AVP profile names, and
//! every stream scores:
//!
//! ```sh
//! cargo run --features native --example rtp_quality -- \
//!     tests/pcap-samples/rtp-protocol.pcap
//! ```
//!
//! ```text
//! 248 RTP packets across 2 stream(s)
//!
//! ssrc 0a110002  pt 8   PCMA         47 pkts  jitter   1.55 ms  loss   0.0%  MOS 4.36
//! ssrc 0a110001  pt 8   PCMA        201 pkts  jitter   1.68 ms  loss   0.0%  MOS 4.36
//! ```
//!
//! Then run it on one that negotiated a dynamic payload type, and both
//! streams come back unscored:
//!
//! ```sh
//! cargo run --features native --example rtp_quality -- \
//!     tests/pcap-samples/invite-opus-bye.pcap
//! ```
//!
//! That capture's INVITE carries `a=rtpmap:96 opus/48000`, so the codec and
//! clock rate are right there in the file — but **this** example never parses
//! SIP, so nothing ever told the store. PT 96 means whatever the signaling
//! said it means, the store was not listening, and the honest answer is
//! `n/a`. Feeding the SDP in is what the `filter_dialogs` example does, with
//! `StreamStore::link_to_dialog_with_sdp` — the call that carries an
//! `a=rtpmap` onto a dynamic payload type — and that is the whole reason the
//! two stores exist side by side rather than one being enough.
//!
//! [`estimate_mos`]: sipnab::estimate_mos
//! [`StreamStore`]: sipnab::StreamStore
//! [`StreamStore::measured_jitter_ms`]: sipnab::StreamStore::measured_jitter_ms

#[cfg(not(target_arch = "wasm32"))]
fn main() {
    use sipnab::capture::Packet;
    use sipnab::capture::parse::parse_packet;
    use sipnab::rtp::is_rtp_packet;
    use sipnab::rtp::parser::parse_rtp_header;
    use sipnab::{PcapReader, StreamStore, estimate_mos};

    let Some(path) = std::env::args().nth(1) else {
        eprintln!(
            "usage: rtp_quality <capture.pcap|.pcapng>\n\n\
             Try a capture from this repository:\n  \
             cargo run --features native --example rtp_quality -- \\\n    \
             tests/pcap-samples/rtp-protocol.pcap"
        );
        std::process::exit(2);
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

    let mut streams = StreamStore::new(1024);
    let mut rtp_packets = 0_u64;

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

        // `is_rtp_packet` first, and it is not an optimization. RTCP shares
        // the RTP framing closely enough that `parse_rtp_header` accepts a
        // Receiver Report and hands back a header whose "SSRC" is really the
        // report's first word — inventing a one-packet stream per RTCP
        // datagram. The pre-filter rejects payload types 72..=76, which are
        // RTCP's 200..=204 read through the 7-bit field. Skipping it here made
        // this example claim 250 packets across 4 streams for a capture the
        // `sipnab` binary reads as 248 across 2.
        if !is_rtp_packet(&parsed.payload) {
            continue;
        }

        // No port filter and no SDP: past the pre-filter this takes any
        // payload that parses as an RTP header, which is what a capture with
        // no signaling forces you to do. The store records that provenance —
        // a stream found this way has `heuristic` set — and a codec resolved
        // from an `a=rtpmap` would have arrived through the SIP path instead.
        let Ok(rtp) = parse_rtp_header(&parsed.payload) else {
            continue;
        };

        rtp_packets += 1;
        streams.process_rtp(&parsed, &rtp, parsed.timestamp);
    }

    println!(
        "{rtp_packets} RTP packets across {} stream(s)\n",
        streams.len()
    );

    for stream in streams.iter() {
        let loss_pct = stream.loss_percent();
        let codec = stream.codec.as_deref();

        match streams.measured_jitter_ms(&stream.key) {
            Some(jitter_ms) => {
                let mos = estimate_mos(jitter_ms, loss_pct, codec);
                println!(
                    "ssrc {:08x}  pt {:<3} {:<8} {:>6} pkts  jitter {jitter_ms:>6.2} ms  \
                     loss {loss_pct:>5.1}%  MOS {mos:.2}",
                    stream.key.ssrc,
                    stream.payload_type,
                    codec.unwrap_or("-"),
                    stream.packet_count,
                );
            }
            None => println!(
                "ssrc {:08x}  pt {:<3} {:<8} {:>6} pkts  jitter    n/a       \
                 loss {loss_pct:>5.1}%  MOS  n/a  (clock rate not grounded by an \
                 rtpmap, or too few packets since a restart — sipnab declines to \
                 score rather than guess)",
                stream.key.ssrc,
                stream.payload_type,
                codec.unwrap_or("-"),
                stream.packet_count,
            ),
        }
    }
}

#[cfg(target_arch = "wasm32")]
fn main() {
    eprintln!("This example reads a file named on the command line; wasm32 has neither.");
}
