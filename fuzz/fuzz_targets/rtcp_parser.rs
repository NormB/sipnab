// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fuzz the RTCP compound-packet parser — a network-facing decoder. Arbitrary
//! bytes must be rejected or parsed into reports without panicking or
//! over-reading the compound-packet chain.
#![no_main]
use libfuzzer_sys::fuzz_target;
use sipnab::rtp::rtcp::parse_rtcp;

fuzz_target!(|data: &[u8]| {
    let _ = parse_rtcp(data);
});
