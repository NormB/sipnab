#![no_main]
use libfuzzer_sys::fuzz_target;
use sipnab::sip::stir_shaken::parse_identity_header;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = parse_identity_header(s);
    }
});
