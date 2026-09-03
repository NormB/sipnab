// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fuzz the STUN decoder and the TURN ChannelData framing checks. Both sit on
//! the per-datagram path: `classify_packet` tries `channel_data_payload` and
//! then `stun::parse` on every UDP payload that is not SIP, BEFORE RTP is
//! considered, so every byte reaching them was written by another host.
//! Arbitrary input must be rejected or decoded without panicking or reading
//! past the buffer — the parser trusts the buffer over every declared length,
//! and this is what holds it to that.
//!
//! The accessors are driven on whatever parses, not only the parse: they read
//! the decoded attributes back and are what the pipeline calls next.
//!
//! The tracker half (`note_message`, `note_channel_data`) is deliberately not
//! driven. It keys a process-global table by transaction ID, so a fuzzer that
//! hands it a fresh random ID per iteration measures memory growth rather than
//! parsing, and libFuzzer's RSS limit would report that as a finding.
#![no_main]
use libfuzzer_sys::fuzz_target;
use sipnab::stun::{
    ChannelDataFraming, channel_data_payload, channel_data_payload_framed, is_channel_data,
    is_channel_data_framed, parse,
};

fuzz_target!(|data: &[u8]| {
    if let Some(msg) = parse(data) {
        let _ = msg.method_name();
        let _ = msg.is_binding_request();
        let _ = msg.is_auth_challenge();
        let _ = msg.is_allocate_request();
    }
    // Both framings: the datagram rule requires the frame to account for the
    // whole buffer, the stream rule only that the padded frame fits.
    let _ = channel_data_payload(data);
    let _ = channel_data_payload_framed(data, ChannelDataFraming::Stream);
    let _ = is_channel_data(data);
    let _ = is_channel_data_framed(data, ChannelDataFraming::Stream);
});
