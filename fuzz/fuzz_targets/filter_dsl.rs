// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fuzz the filter-DSL parser (`sipnab -F 'expr'`): arbitrary UTF-8 filter
//! strings must parse to an expression or a clean error, never panic.
#![no_main]
use libfuzzer_sys::fuzz_target;
use sipnab::sip::dsl::FilterExpr;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = FilterExpr::parse(s);
    }
});
