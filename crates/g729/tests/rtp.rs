// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! `Decoder::decode_rtp` (RFC 3551 section 4.5.6): 10n octets of frames plus
//! an optional trailing 2-octet SID frame; any other length is refused and
//! decodes nothing.

pub mod common;

use g729::bitstream::{self, SerialFrame};
use g729::{Decoder, Error, FRAME_SAMPLES, Frame};

/// The first frames of SPEECH.BIT, packed as RFC 3551 frames.
fn speech_frames(n: usize) -> Result<Vec<[u8; 10]>, String> {
    let input = common::read_vector("annex-a/SPEECH.BIT")?;
    let mut out = Vec::with_capacity(n);
    for f in bitstream::g192_frames(&input).take(n) {
        match f.map_err(|e| e.to_string())? {
            SerialFrame::Speech(b) => out.push(b),
            other => return Err(format!("SPEECH.BIT: unexpected {other:?}")),
        }
    }
    Ok(out)
}

#[test]
fn a_payload_decodes_like_its_frames_one_by_one() -> common::TestResult {
    let frames = speech_frames(6)?;
    let payload: Vec<u8> = frames.iter().flatten().copied().collect();
    let mut by_rtp = Vec::new();
    let mut d = Decoder::new(common::tables()?);
    assert_eq!(
        d.decode_rtp(&payload[..30], &mut by_rtp),
        Ok(3 * FRAME_SAMPLES)
    );
    assert_eq!(
        d.decode_rtp(&payload[30..], &mut by_rtp),
        Ok(3 * FRAME_SAMPLES)
    );

    let mut one_by_one = Vec::new();
    let mut d = Decoder::new(common::tables()?);
    let mut pcm = [0i16; FRAME_SAMPLES];
    for f in &frames {
        d.decode(Frame::Voice(f), &mut pcm);
        one_by_one.extend_from_slice(&pcm);
    }
    assert_eq!(by_rtp, one_by_one);
    Ok(())
}

#[test]
fn a_trailing_sid_adds_one_frame_and_bad_lengths_decode_nothing() -> common::TestResult {
    let frames = speech_frames(1)?;
    let mut payload: Vec<u8> = frames[0].to_vec();
    payload.extend([0x00, 0x00]);
    let mut d = Decoder::new(common::tables()?);
    let mut out = Vec::new();
    assert_eq!(d.decode_rtp(&payload, &mut out), Ok(2 * FRAME_SAMPLES));
    assert_eq!(out.len(), 2 * FRAME_SAMPLES);
    for len in [1usize, 3, 9, 11, 13, 19, 21, 25] {
        let mut out = Vec::new();
        assert_eq!(
            d.decode_rtp(&vec![0u8; len], &mut out),
            Err(Error::PayloadLength(len)),
            "length {len}"
        );
        assert!(out.is_empty(), "length {len} decoded samples");
    }
    let mut out = Vec::new();
    assert_eq!(d.decode_rtp(&[], &mut out), Ok(0));
    Ok(())
}

/// The largest UDP payload over IPv4 is 65,507 octets; the largest G.729
/// payload within it is 65,502 octets (6,550 frames and a SID frame). It
/// decodes whole, like its frames one by one: 6,551 x 80 = 524,080 samples.
#[test]
fn the_largest_udp_payload_decodes_whole() -> common::TestResult {
    const UDP_PAYLOAD_MAX: usize = 65_507;
    let voice = speech_frames(20)?;
    let frames = (UDP_PAYLOAD_MAX - 2) / 10;
    let mut payload: Vec<u8> = voice
        .iter()
        .cycle()
        .take(frames)
        .flatten()
        .copied()
        .collect();
    payload.extend([0x12, 0x34]);
    assert_eq!(payload.len(), 65_502);

    let mut by_rtp = Vec::new();
    let mut d = Decoder::new(common::tables()?);
    assert_eq!(d.decode_rtp(&payload, &mut by_rtp), Ok(524_080));
    assert_eq!(by_rtp.len(), 524_080);

    let mut one_by_one = Vec::with_capacity(524_080);
    let mut d = Decoder::new(common::tables()?);
    let mut pcm = [0i16; FRAME_SAMPLES];
    let (chunks, sid) = payload.as_chunks::<10>();
    for frame in chunks {
        d.decode(Frame::Voice(frame), &mut pcm);
        one_by_one.extend_from_slice(&pcm);
    }
    let sid = sid.first_chunk::<2>().ok_or("no SID octets")?;
    d.decode(Frame::Sid(sid), &mut pcm);
    one_by_one.extend_from_slice(&pcm);
    assert!(
        by_rtp == one_by_one,
        "the payload decodes unlike its frames"
    );

    // 65,507 octets is neither 10n nor 10n + 2: refused, nothing decoded.
    let mut out = Vec::new();
    let longest = vec![0u8; UDP_PAYLOAD_MAX];
    assert_eq!(
        d.decode_rtp(&longest, &mut out),
        Err(Error::PayloadLength(UDP_PAYLOAD_MAX))
    );
    assert!(out.is_empty());
    Ok(())
}
