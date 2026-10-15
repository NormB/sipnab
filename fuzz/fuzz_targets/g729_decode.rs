// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fuzz the G.729 decoder: arbitrary RTP payloads and arbitrary frame
//! sequences must decode without panicking, and decoding the same input twice
//! from a fresh decoder must give the same samples.
//!
//! The decoder's tables are user-supplied (never in this repository). When
//! `G729_VECTORS` names a directory filled by `scripts/fetch-g729-vectors.py`,
//! the real tables are imported from it; otherwise, as under ClusterFuzzLite,
//! the target uses pseudo-random tables through
//! `Tables::from_values_unverified`, which exists only under `cfg(fuzzing)`
//! (set by cargo-fuzz); it exercises the same code with arbitrary contents.
#![no_main]
use std::sync::OnceLock;

use g729::{Decoder, FRAME_SAMPLES, Frame, Tables};
use libfuzzer_sys::fuzz_target;

fn tables() -> Option<&'static Tables> {
    static T: OnceLock<Option<Tables>> = OnceLock::new();
    T.get_or_init(|| {
        if let Some(dir) = std::env::var_os("G729_VECTORS") {
            let src = std::path::Path::new(&dir).join("itu-source");
            if let Ok(file) = g729::import_from_itu(&src) {
                if let Ok(t) = Tables::from_bytes(&file) {
                    return Some(t);
                }
            }
        }
        pseudo_random_tables()
    })
    .as_ref()
}

/// Pseudo-random tables, built without the values-hash check. Only a
/// cargo-fuzz build (`cfg(fuzzing)`) has that constructor; a plain
/// `cargo check` of this package, as the pre-push hook runs, compiles the
/// target with no tables to fall back on.
#[cfg(fuzzing)]
fn pseudo_random_tables() -> Option<Tables> {
    let mut seed: u32 = 0x1234_5678;
    let values: Vec<i16> = (0..g729::tables::VALUE_COUNT)
        .map(|_| {
            seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            (seed >> 16) as i16
        })
        .collect();
    Tables::from_values_unverified(&values)
}

/// Without `cfg(fuzzing)` there is no unverified constructor.
#[cfg(not(fuzzing))]
fn pseudo_random_tables() -> Option<Tables> {
    None
}

/// Decode `data` as a sequence of tagged frames.
fn frames(tables: &Tables, data: &[u8], out: &mut Vec<i16>) {
    let mut d = Decoder::new(tables);
    let mut pcm = [0i16; FRAME_SAMPLES];
    let mut rest = data;
    while let Some((&tag, after)) = rest.split_first() {
        rest = after;
        let frame = match tag % 4 {
            0 if rest.len() >= 10 => {
                let Some((b, after)) = rest.split_first_chunk::<10>() else {
                    return;
                };
                rest = after;
                Frame::Voice(b)
            }
            1 if rest.len() >= 2 => {
                let Some((b, after)) = rest.split_first_chunk::<2>() else {
                    return;
                };
                rest = after;
                Frame::Sid(b)
            }
            2 => Frame::NoTx,
            _ => Frame::Erased,
        };
        d.decode(frame, &mut pcm);
        out.extend_from_slice(&pcm);
    }
}

fn rtp(tables: &Tables, data: &[u8], out: &mut Vec<i16>) {
    let mut d = Decoder::new(tables);
    for packet in data.chunks(23) {
        let _ = d.decode_rtp(packet, out);
    }
}

fuzz_target!(|data: &[u8]| {
    let Some(t) = tables() else { return };
    let (mut a, mut b) = (Vec::new(), Vec::new());
    frames(t, data, &mut a);
    frames(t, data, &mut b);
    assert_eq!(a, b, "frame decoding is not deterministic");
    let (mut a, mut b) = (Vec::new(), Vec::new());
    rtp(t, data, &mut a);
    rtp(t, data, &mut b);
    assert_eq!(a, b, "RTP decoding is not deterministic");
});
