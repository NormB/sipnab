//! Fuzz the HEP (Homer Encapsulation Protocol) parser — the network-facing
//! decoder for captured HEP frames. Arbitrary bytes must be rejected or
//! decoded without panicking or over-reading.
#![no_main]
use libfuzzer_sys::fuzz_target;
use sipnab::capture::hep::parse_hep;

fuzz_target!(|data: &[u8]| {
    let _ = parse_hep(data);
});
