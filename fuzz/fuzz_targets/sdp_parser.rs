// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fuzz the SDP body parser — the session-description decoder driven by
//! attacker-supplied SIP message bodies. Arbitrary bytes must parse or error
//! cleanly, never panic.
#![no_main]
use libfuzzer_sys::fuzz_target;
use sipnab::sip::sdp::parse_sdp;

fuzz_target!(|data: &[u8]| {
    let _ = parse_sdp(data);
});
