#![no_main]
use libfuzzer_sys::fuzz_target;
use sipnab::rtp::rtcp::parse_rtcp;

fuzz_target!(|data: &[u8]| {
    let _ = parse_rtcp(data);
});
