#![no_main]
use libfuzzer_sys::fuzz_target;
use sipnab::rtp::srtp::extract_srtp_keys;
use sipnab::sip::sdp::SdpCrypto;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Split fuzzed string into suite and key_params fields.
        // Use the first newline as a delimiter; if absent, fuzz key_params only.
        let (suite, key_params) = match s.find('\n') {
            Some(pos) => (&s[..pos], &s[pos + 1..]),
            None => ("AES_CM_128_HMAC_SHA1_80", s),
        };
        let crypto = SdpCrypto {
            tag: 1,
            suite: suite.to_string(),
            key_params: key_params.to_string(),
        };
        let _ = extract_srtp_keys(&crypto);
    }
});
