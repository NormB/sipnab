#![no_main]
use libfuzzer_sys::fuzz_target;
use sipnab::sip::sdp::parse_sdp;

fuzz_target!(|data: &[u8]| {
    let _ = parse_sdp(data);
});
