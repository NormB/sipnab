//! Fuzz the SIPREC metadata extractor — a hand-rolled scanner over
//! attacker-supplied XML (`find`-based tag walking, multipart splitting).
//! Both the direct rs-metadata path and the multipart path are driven.
#![no_main]
use libfuzzer_sys::fuzz_target;
use sipnab::sip::siprec::parse_siprec_body;

fuzz_target!(|data: &[u8]| {
    let _ = parse_siprec_body("application/rs-metadata+xml", data);
    let _ = parse_siprec_body("multipart/mixed;boundary=uniqueBoundary", data);
});
