#![no_main]
use libfuzzer_sys::fuzz_target;
use sipnab::capture::hep::parse_hep;

fuzz_target!(|data: &[u8]| {
    let _ = parse_hep(data);
});
