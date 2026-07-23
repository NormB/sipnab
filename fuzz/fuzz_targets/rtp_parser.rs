//! Fuzz the RTP header parser — a network-facing decoder. Arbitrary bytes
//! must be rejected or parsed into a header without panicking or reading past
//! the input (CSRC/extension length fields must be bounds-checked).
#![no_main]
use libfuzzer_sys::fuzz_target;
use sipnab::rtp::parser::parse_rtp_header;

fuzz_target!(|data: &[u8]| {
    let _ = parse_rtp_header(data);
});
