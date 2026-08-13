// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fuzz the STIR/SHAKEN `Identity` header parser — decodes an attacker-
//! supplied JWT-style header value. Any UTF-8 input must parse or error
//! cleanly, never panic.
#![no_main]
use libfuzzer_sys::fuzz_target;
use sipnab::sip::stir_shaken::parse_identity_header;

/// Capture clock for the parse. Fixed, so a corpus entry that reaches the
/// RFC 8224 freshness branch takes the same path on every run and a crash
/// reproduces from the input alone.
const CAPTURED_AT: i64 = 1_700_000_000;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = parse_identity_header(s, CAPTURED_AT);
    }
});
