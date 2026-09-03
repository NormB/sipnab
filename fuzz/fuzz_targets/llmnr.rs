// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fuzz the LLMNR decoder. It is claimed during classification before any
//! media check, because an LLMNR query is a DNS-format message whose random
//! transaction ID passes the RTP version bits one time in four — so
//! `is_llmnr_packet` and then `parse_llmnr` see every UDP datagram that
//! touches port 5355, written by whatever host sent it. Arbitrary input must
//! be rejected or decoded without panicking or reading past the buffer; a
//! name that fails to decode ends its section and keeps what was already
//! recovered, and this is what holds the decoder to that.
//!
//! The port pair is driven both ways round, since the check reads it before
//! it reads a byte, and the record-type names are read back for every answer
//! that decodes — that is what the store does next.
#![no_main]
use libfuzzer_sys::fuzz_target;
use sipnab::llmnr::{PORT, is_llmnr_packet, parser::parse_llmnr, parser::rtype_name};

fuzz_target!(|data: &[u8]| {
    let _ = is_llmnr_packet(data, PORT, 40_000);
    let _ = is_llmnr_packet(data, 40_000, PORT);
    if let Ok(msg) = parse_llmnr(data) {
        for answer in &msg.answers {
            let _ = rtype_name(answer.rtype);
        }
    }
});
