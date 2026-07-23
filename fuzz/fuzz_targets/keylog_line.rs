//! Fuzz the NSS-keylog line parser (`--tls-keylog` / `SSLKEYLOGFILE` input):
//! any UTF-8 line must parse to a key entry or a clean error, never panic.
#![no_main]
use libfuzzer_sys::fuzz_target;
use sipnab::capture::tls::parse_keylog_line;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = parse_keylog_line(s);
    }
});
