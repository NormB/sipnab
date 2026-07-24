// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fuzz the pure-Rust pcap/pcapng file reader — the primary hostile-file
//! surface (`sipnab -I untrusted.pcapng`). Header detection and the block
//! walk must reject/terminate on any input, never panic or spin.
#![no_main]
use libfuzzer_sys::fuzz_target;
use sipnab::PcapReader;

fuzz_target!(|data: &[u8]| {
    if let Ok(reader) = PcapReader::new(data) {
        // Drain the iterator: block walking must terminate (offsets only
        // move forward, bounded by the input length) and never panic.
        for pkt in reader {
            let _ = pkt.data.len();
        }
    }
});
