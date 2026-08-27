// SPDX-License-Identifier: MIT OR Apache-2.0

//! A capture file in, one vCon container out — the whole export path.
//!
//! [`docs/vcon.md`](../docs/vcon.md) explains what a sipnab vCon means and what
//! a consumer may not conclude from one. This is the part a page cannot show:
//! a program that runs, against a capture committed to this repository, and
//! prints a container a real conserver accepts.
//!
//! The steps are the same four [`call_summary`](call_summary.rs) walks, plus
//! one:
//!
//! 1. [`PcapReader`] — file bytes to capture records
//! 2. [`Packet`] + [`parse_packet`] — records to addressed frames
//! 3. [`parse_sip`] — frames to messages
//! 4. [`DialogStore`] — messages to calls
//! 5. [`export_dialog`] — ONE call to a container
//!
//! Run it:
//!
//! ```sh
//! cargo run --features vcon --example export_vcon -- \
//!     tests/fixtures/sip_call.pcap
//! ```
//!
//! Or hand it straight to a conserver:
//!
//! ```sh
//! cargo run --features vcon --example export_vcon -- \
//!     tests/fixtures/sip_call.pcap \
//!   | curl -fsS -X POST "$CONSERVER/vcon" \
//!       -H 'Content-Type: application/json' \
//!       -H "Authorization: Bearer $CONSERVER_TOKEN" --data-binary @-
//! ```
//!
//! One container describes ONE dialog. A capture with three calls in it is
//! three containers, and this prints the first — which is a deliberate limit
//! of the format rather than of the example: there is no vCon that means
//! "everything this capture saw".
//!
//! [`DialogStore`]: sipnab::DialogStore
//! [`PcapReader`]: sipnab::PcapReader
//! [`Packet`]: sipnab::capture::Packet
//! [`parse_packet`]: sipnab::capture::parse::parse_packet
//! [`parse_sip`]: sipnab::sip::parser::parse_sip
//! [`export_dialog`]: sipnab::output::vcon::export_dialog

#[cfg(all(feature = "vcon", not(target_arch = "wasm32")))]
fn main() {
    use sipnab::analysis::CaptureFacts;
    use sipnab::capture::Packet;
    use sipnab::capture::parse::parse_packet;
    use sipnab::output::vcon::{ExportContext, export_dialog};
    use sipnab::sip::parser::{parse_sip, starts_sip_message};
    use sipnab::{DialogStore, PcapReader};

    let Some(path) = std::env::args().nth(1) else {
        eprintln!(
            "usage: export_vcon <capture.pcap|.pcapng>\n\n\
             Try the capture this repository ships:\n  \
             cargo run --features vcon --example export_vcon -- \\\n    \
             tests/fixtures/sip_call.pcap"
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

    let mut dialogs = DialogStore::new(4096, false);
    let mut frames = 0_u64;

    for pkt in reader {
        frames += 1;
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
        if !starts_sip_message(&parsed.payload) {
            continue;
        }
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
    }

    let Some(dialog) = dialogs.iter().next() else {
        eprintln!("{path} holds no SIP dialog, so there is nothing to export");
        std::process::exit(1);
    };

    // What the RUN saw, not just this dialog. The container states what the
    // capture missed in two places, and both read from here — an export that
    // passed `CaptureFacts::default()` would claim a clean capture it never
    // measured.
    let facts = CaptureFacts {
        frames_read: frames,
        ..CaptureFacts::default()
    };

    let vcon = export_dialog(
        dialog,
        &ExportContext {
            // From the capture's CONTENT, never a per-process value: the uuid
            // hashes this, so a rotating id mints a fresh identifier every
            // time you reopen the same file and a store sees a new record
            // rather than the same one.
            capture_id: &path,
            facts: &facts,
            // `None` is honest here: this example runs no capture analysis, and
            // the container reports that rather than implying a clean bill.
            max_inline_media_bytes: None,
            analysis: None,
        },
    );

    match vcon.to_json() {
        Ok(json) => println!("{json}"),
        Err(e) => {
            eprintln!("the container did not serialize: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(not(all(feature = "vcon", not(target_arch = "wasm32"))))]
fn main() {
    eprintln!(
        "this example needs the `vcon` feature:\n  \
         cargo run --features vcon --example export_vcon -- <capture.pcap>"
    );
    std::process::exit(2);
}
