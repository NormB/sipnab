// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fuzz rtpengine's `ng` control-plane decoder and the bencode parser under
//! it. Both are hostile-input-facing: over HEP the bytes are written by
//! another host, and off the wire they are whatever was captured. Arbitrary
//! input must be rejected or decoded without panicking, over-reading, or
//! recursing without bound — bencode nests, so `llll...` is a stack overflow
//! in any decoder that does not limit depth.
//!
//! `sdp_links_from_ng` is driven too, not just the parser: it is the function
//! the capture path actually calls, and it continues past a decoded message
//! into SDP parsing and link extraction.
#![no_main]
use libfuzzer_sys::fuzz_target;
use sipnab::rtpengine::{bencode, ng, sdp_links_from_ng};

fuzz_target!(|data: &[u8]| {
    let _ = bencode::decode(data);
    let _ = ng::parse(data);
    // The correlation-id half: a reply names its call from this and nothing
    // else, so the path that takes it must be fuzzed with it both present and
    // absent.
    let _ = sdp_links_from_ng(data, None);
    let _ = sdp_links_from_ng(data, Some("fuzz-correlation-id"));
});
