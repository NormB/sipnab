#![no_main]
use libfuzzer_sys::fuzz_target;
use sipnab::rtp::parser::parse_rtp_header;

fuzz_target!(|data: &[u8]| {
    let _ = parse_rtp_header(data);
});
