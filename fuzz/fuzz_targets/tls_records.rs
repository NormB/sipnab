#![no_main]
use libfuzzer_sys::fuzz_target;
use sipnab::capture::tls::parse_tls_records;

fuzz_target!(|data: &[u8]| {
    let _ = parse_tls_records(data);
});
