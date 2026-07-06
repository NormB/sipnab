//! Fuzz the DTLS-SRTP handshake observer: record/handshake parsing plus
//! the key-derivation path (a keylog entry with the all-0xAB client
//! random is provided, so a fuzzer-built ClientHello can reach it).
#![no_main]
use libfuzzer_sys::fuzz_target;
use sipnab::capture::dtls::DtlsSrtpExtractor;
use sipnab::capture::tls::KeyLogEntry;
use sipnab::crypto::default_backend;

fuzz_target!(|data: &[u8]| {
    let entries = vec![KeyLogEntry {
        label: "CLIENT_RANDOM".to_string(),
        client_random: vec![0xAB; 32],
        secret: vec![0x44; 48],
    }];
    let mut ex = DtlsSrtpExtractor::new(entries, default_backend());
    if data.is_empty() {
        let _ = ex.process_dtls(&[]);
        return;
    }
    // Feed the input as four datagrams so multi-record handshakes
    // (ClientHello in one packet, ServerHello in a later one) are
    // reachable states, not just single-datagram parses.
    let n = data.len();
    let cuts = [0, n / 4, n / 2, 3 * n / 4, n];
    for w in cuts.windows(2) {
        let _ = ex.process_dtls(&data[w[0]..w[1]]);
    }
});
