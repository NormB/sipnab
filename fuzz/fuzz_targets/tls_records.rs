// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fuzz the TLS record-layer splitter — a network-facing decoder over
//! captured TLS bytes. Arbitrary input must split into records or error
//! cleanly, never panic or over-read on a malformed record length.
#![no_main]
use libfuzzer_sys::fuzz_target;
use sipnab::capture::tls::parse_tls_records;

fuzz_target!(|data: &[u8]| {
    let _ = parse_tls_records(data);
});
