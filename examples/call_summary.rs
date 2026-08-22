// SPDX-License-Identifier: MIT OR Apache-2.0

//! A capture file in, one line per call out — the whole library pipeline.
//!
//! [`docs/library.md`](../docs/library.md) shows the bridge from a pcap record
//! to a decoded frame in one compiled snippet. This is the step a doctest
//! cannot take: dialog state is not a property of a packet, it is what you
//! learn by feeding **every** packet of a real capture through
//! [`DialogStore`] in order. A doctest with one INVITE in it can only ever
//! print `Trying`.
//!
//! It is also the shortest honest answer to "what does the crate actually do",
//! because the four steps below are the same four the `sipnab` binary runs:
//!
//! 1. [`PcapReader`] — file bytes to capture records
//! 2. [`Packet`] + [`parse_packet`] — records to addressed, decapsulated frames
//! 3. [`starts_sip_message`] + [`parse_sip`] — frames to [`SipMessage`]
//! 4. [`DialogStore`] — messages to calls
//!
//! Run it:
//!
//! ```sh
//! cargo run --features native --example call_summary -- \
//!     tests/pcap-samples/register-invite-reinvite-bye.pcap
//! ```
//!
//! Cross-check it against the tool, which reads the same capture through the
//! same four steps and reports `229 packets captured, 12 SIP messages`:
//!
//! ```sh
//! cargo run --features native -- -N -I \
//!     tests/pcap-samples/register-invite-reinvite-bye.pcap --portrange 1-65535
//! ```
//!
//! `--portrange 1-65535` is not decoration. The **binary** defaults to
//! 5060-5061 and this capture signals on 5080, so without it the tool prints
//! "No SIP signaling found" for a file holding twelve SIP messages — it says
//! so, in a NOT ANALYZED line, which is the only reason that default is
//! survivable. The **library** applies no port policy at all: nothing in the
//! four steps above filters by port, so this example sees all twelve with no
//! flag. That difference is worth knowing before you conclude the library and
//! the tool disagree about a capture.
//!
//! [`DialogStore`]: sipnab::DialogStore
//! [`PcapReader`]: sipnab::PcapReader
//! [`Packet`]: sipnab::capture::Packet
//! [`parse_packet`]: sipnab::capture::parse::parse_packet
//! [`starts_sip_message`]: sipnab::sip::parser::starts_sip_message
//! [`parse_sip`]: sipnab::sip::parser::parse_sip
//! [`SipMessage`]: sipnab::SipMessage

#[cfg(not(target_arch = "wasm32"))]
fn main() {
    use sipnab::capture::Packet;
    use sipnab::capture::parse::parse_packet;
    use sipnab::sip::parser::{parse_sip, starts_sip_message};
    use sipnab::{DialogStore, PcapReader};

    let Some(path) = std::env::args().nth(1) else {
        eprintln!(
            "usage: call_summary <capture.pcap|.pcapng>\n\n\
             Try a capture from this repository:\n  \
             cargo run --features native --example call_summary -- \\\n    \
             tests/pcap-samples/register-invite-reinvite-bye.pcap"
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

    // `decompress_capture` would go here for a `.pcap.gz`; it is a no-op on
    // bytes that are not gzip, so a real tool calls it unconditionally.
    let reader = match PcapReader::new(&data) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{path} is not a capture this crate can read: {e}");
            std::process::exit(1);
        }
    };

    // 4096 dialogs, no rotation: a bounded store is the library default
    // because a capture can name more Call-IDs than you have memory. `false`
    // means "drop new dialogs when full" rather than evicting old ones — for
    // a one-shot summary, losing the START of the capture is worse.
    let mut dialogs = DialogStore::new(4096, false);

    let mut frames = 0_u64;
    let mut undecodable = 0_u64;
    let mut sip_messages = 0_u64;

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

        // Counted, not swallowed. A capture holds ARP, truncated frames and
        // link types this crate does not decode; a summary that hides how many
        // frames it failed to read is a partial result wearing a clean one's
        // clothes.
        let Ok(parsed) = parse_packet(&frame) else {
            undecodable += 1;
            continue;
        };

        // Cheap first-line sniff before the parse. Every RTP packet in the
        // capture reaches this line, and `parse_sip` on RTP is a wasted
        // allocation plus an `Err` you would have to ignore.
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
            sip_messages += 1;
            dialogs.process_message(msg);
        }
    }

    println!(
        "{frames} frames, {undecodable} undecodable, {sip_messages} SIP messages, \
         {} dialogs\n",
        dialogs.len()
    );

    for d in dialogs.iter() {
        let from = d.from_user.as_deref().unwrap_or("?");
        let to = d.to_user.as_deref().unwrap_or("?");
        let status = match d.final_status_code() {
            Some(code) => format!(" [{code}]"),
            None => String::new(),
        };
        println!(
            "{:<9} {:<11}{status}  {from} -> {to}  ({} messages)  {}",
            d.method.as_str(),
            format!("{:?}", d.state()),
            d.messages.len(),
            d.call_id,
        );
    }
}

#[cfg(target_arch = "wasm32")]
fn main() {
    eprintln!("This example reads a file named on the command line; wasm32 has neither.");
}
