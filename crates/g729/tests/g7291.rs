// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! G.729.1 core-layer decoding against the ITU-T G.729.1 test vectors, and
//! property tests of the RTP payload path.
//!
//! The vectors come from the ITU-T G.729.1 Corrigendum 1 (08/2009) software
//! package, fetched by `scripts/fetch-g729-vectors.py` with a pinned sha256
//! and never committed. Each pair is a G.729.1 bitstream and the
//! G.729-format bitstream the same encoder wrote from the same input, which
//! are the evidence for the two facts the core-layer decoder rests on:
//!
//! - O2: the first 160 bits of each G.729.1 frame are the two G.729 frames
//!   of its G.729-format twin.
//! - O1: the first 15 bits of a G.729.1 SID are the G.729 Annex B SID of its
//!   twin, which writes it as a SID frame followed by an untransmitted frame.
//!
//! A missing vector fails the test, naming the fetch command.

pub mod common;

use g729::bitstream::SerialFrame;
use g729::g7291::{
    self, CORE_OCTETS, Decoded, FrameType, PayloadError, SUPERFRAME_SAMPLES, Superframe,
};
use g729::{Decoder, FRAME_SAMPLES};

/// A G.729.1 vector's frames.
fn g7291_vector(name: &str) -> Result<Vec<common::G7291Serial>, String> {
    common::g7291_g192(&common::read_vector(&format!("g7291/{name}"))?, name)
}

/// A G.729-format vector's frames.
fn g729_vector(name: &str) -> Result<Vec<SerialFrame>, String> {
    common::g729_serial(&common::read_vector(&format!("g7291/{name}"))?, name)
}

/// The RTP payload of one G.729.1 serial frame: FT 14 and the SID for a SID,
/// FT 15 for an untransmitted frame, and otherwise the rate its size names
/// and the frame. `None` for a bad frame (the network lost it).
fn rtp_payload(frame: &common::G7291Serial) -> Result<Option<Vec<u8>>, String> {
    if !frame.good {
        return Ok(None);
    }
    let ft = match frame.bits {
        0 => 15,
        15 | 24 | 43 => 14,
        160 => 0,
        bits if bits % 40 == 0 && (240..=640).contains(&bits) => (bits / 40 - 5) as u8,
        bits => return Err(format!("a G.729.1 frame of {bits} bits")),
    };
    let mut payload = vec![0xf0 | ft];
    payload.extend_from_slice(&frame.octets);
    Ok(Some(payload))
}

/// Decode a G.729.1 vector through `Decoder::decode_g7291_rtp`, one payload
/// per frame, with a lost frame decoded as erased and an untransmitted one
/// as untransmitted.
fn decode_through_rtp(frames: &[common::G7291Serial]) -> Result<Vec<i16>, String> {
    let mut decoder = Decoder::new(common::tables()?);
    let mut pcm = Vec::new();
    let mut superframe = [0i16; SUPERFRAME_SAMPLES];
    for frame in frames {
        match rtp_payload(frame)? {
            None => {
                decoder.decode_superframe(Superframe::Erased, &mut superframe);
                pcm.extend_from_slice(&superframe);
            }
            Some(payload) if frame.bits == 0 => {
                // FT 15 decodes nothing; the frame is untransmitted.
                let decoded = decoder
                    .decode_g7291_rtp(&payload, &mut pcm)
                    .map_err(|e| e.to_string())?;
                assert_eq!(decoded.samples, 0, "no data decodes nothing");
                decoder.decode_superframe(Superframe::NoTx, &mut superframe);
                pcm.extend_from_slice(&superframe);
            }
            Some(payload) => {
                let decoded = decoder
                    .decode_g7291_rtp(&payload, &mut pcm)
                    .map_err(|e| e.to_string())?;
                assert_eq!(decoded.samples, SUPERFRAME_SAMPLES, "{} bits", frame.bits);
            }
        }
    }
    Ok(pcm)
}

/// Decode a G.729-format vector frame by frame.
fn decode_g729(frames: &[SerialFrame]) -> Result<Vec<i16>, String> {
    let mut decoder = Decoder::new(common::tables()?);
    let mut pcm = Vec::new();
    let mut samples = [0i16; FRAME_SAMPLES];
    for frame in frames {
        decoder.decode(frame.frame(), &mut samples);
        pcm.extend_from_slice(&samples);
    }
    Ok(pcm)
}

// ── Conformance: the ITU-T G.729.1 vectors ───────────────────────────────

/// O2: every one of the 629 frames of `test1_16k.b32` (32 kbit/s) carries
/// the two frames of `test1_16k.b8` in its first 20 octets.
#[test]
fn o2_every_superframe_s_core_is_its_g729_twin() -> common::TestResult {
    let wide = g7291_vector("test1_16k.b32")?;
    let twin = g729_vector("test1_16k.b8")?;
    assert_eq!((wide.len(), twin.len()), (629, 2 * 629));
    for (i, frame) in wide.iter().enumerate() {
        assert_eq!(frame.bits, 640, "frame {i} is 32 kbit/s");
        let [first, second] = g7291::core_frames(&frame.octets).ok_or("a whole core")?;
        assert_eq!(
            twin[2 * i],
            SerialFrame::Speech(*first),
            "frame {i}, first half"
        );
        assert_eq!(
            twin[2 * i + 1],
            SerialFrame::Speech(*second),
            "frame {i}, second half"
        );
    }
    Ok(())
}

/// Decoding `test1_16k.b32` as RTP payloads at FT 11 gives, sample for
/// sample, what decoding its G.729-format twin gives.
#[test]
fn decoding_the_core_equals_decoding_the_g729_twin() -> common::TestResult {
    let through_rtp = decode_through_rtp(&g7291_vector("test1_16k.b32")?)?;
    let twin = decode_g729(&g729_vector("test1_16k.b8")?)?;
    assert_eq!(through_rtp.len(), 629 * SUPERFRAME_SAMPLES);
    common::compare("test1_16k.b32 core -> test1_16k.b8", &through_rtp, &twin)?;
    Ok(())
}

/// O1, on the vectors with discontinuous transmission: the first 15 bits
/// of each SID are the G.729 SID its twin writes, followed there by an
/// untransmitted frame. The 3-octet SIDs at 12 kbit/s and the 2-octet ones
/// at 8 kbit/s carry the same core, so the two decode to the same samples;
/// and the first 6-octet SID at 32 kbit/s carries its twin's core SID.
#[test]
fn o1_the_core_sid_is_the_g729_sid_of_the_dtx_twin() -> common::TestResult {
    let narrow = g7291_vector("test2_8k.b8")?;
    let enhanced = g7291_vector("test2_8k.b12")?;
    let twin = g729_vector("test2_8k.b729b")?;
    let mut sids = 0;
    for (i, (eight, twelve)) in narrow.iter().zip(&enhanced).enumerate() {
        if eight.bits != 15 {
            continue;
        }
        assert_eq!(twelve.bits, 24, "frame {i}");
        let core = g7291::core_sid(&eight.octets).ok_or("a 2-octet SID")?;
        assert_eq!(g7291::core_sid(&twelve.octets), Some(core), "frame {i}");
        assert_eq!(twin[2 * i], SerialFrame::Sid(core), "frame {i}");
        assert_eq!(twin[2 * i + 1], SerialFrame::NoTx, "frame {i}");
        sids += 1;
    }
    assert_eq!(sids, 20, "the SIDs of test2_8k");
    // The two encoders agree for the first 30 frames: six of speech, a SID,
    // five untransmitted, a SID, seventeen untransmitted. Over them, the
    // G.729.1 SIDs decode as their twin's SID frames and untransmitted ones.
    let leading = 30;
    let through_rtp = decode_through_rtp(&narrow[..leading])?;
    let twin_pcm = decode_g729(&twin[..2 * leading])?;
    common::compare(
        "test2_8k.b8 -> test2_8k.b729b, first 30 frames",
        &through_rtp,
        &twin_pcm,
    )?;
    common::compare(
        "test2_8k.b12 core -> test2_8k.b8 core",
        &decode_through_rtp(&enhanced)?,
        &decode_through_rtp(&narrow)?,
    )?;

    let wide = g7291_vector("test3_16k.b32")?;
    let wide_twin = g729_vector("test3_16k.b729b")?;
    let first = wide
        .iter()
        .position(|f| f.bits == 43)
        .ok_or("test3_16k.b32 holds a SID")?;
    let core = g7291::core_sid(&wide[first].octets).ok_or("a 6-octet SID")?;
    assert_eq!(wide_twin[2 * first], SerialFrame::Sid(core));
    assert_eq!(wide_twin[2 * first + 1], SerialFrame::NoTx);
    Ok(())
}

/// An erased or untransmitted 20 ms frame decodes as two 10 ms frames of the
/// same kind, after speech and after a SID.
#[test]
fn an_erased_or_untransmitted_superframe_is_two_such_frames() -> common::TestResult {
    let speech = g7291_vector("test1_16k.b32")?;
    let core = speech[0]
        .octets
        .first_chunk::<CORE_OCTETS>()
        .ok_or("a core")?;
    let sid = [0x4c, 0x90];
    for (lead, lead_frames) in [
        (
            Superframe::Speech(core),
            vec![
                g729::Frame::Voice(g7291::core_frames(core).ok_or("core")?[0]),
                g729::Frame::Voice(g7291::core_frames(core).ok_or("core")?[1]),
            ],
        ),
        (
            Superframe::Sid(&sid),
            vec![g729::Frame::Sid(&sid), g729::Frame::NoTx],
        ),
    ] {
        for (gap, frame) in [
            (Superframe::Erased, g729::Frame::Erased),
            (Superframe::NoTx, g729::Frame::NoTx),
        ] {
            let mut by_superframe = Decoder::new(common::tables()?);
            let mut by_frame = Decoder::new(common::tables()?);
            let mut superframe = [0i16; SUPERFRAME_SAMPLES];
            let mut got = Vec::new();
            for sf in [lead, gap, gap] {
                by_superframe.decode_superframe(sf, &mut superframe);
                got.extend_from_slice(&superframe);
            }
            let mut samples = [0i16; FRAME_SAMPLES];
            let mut want = Vec::new();
            for f in lead_frames.iter().copied().chain([frame; 4]) {
                by_frame.decode(f, &mut samples);
                want.extend_from_slice(&samples);
            }
            common::compare(&format!("{lead:?} then {gap:?}"), &got, &want)?;
        }
    }
    Ok(())
}

/// A vector that was not fetched fails with the fetch command, never skips.
#[test]
fn a_missing_g7291_vector_fails_naming_the_fetch_command() {
    let missing = g7291_vector("absent.b32").err().unwrap_or_default();
    assert!(missing.contains(common::FETCH), "{missing}");
    assert!(missing.contains("g7291/absent.b32"), "{missing}");
}

// ── Robustness ──────────────────────────────────────────────────────────

/// A deterministic generator (xorshift64), so a failure replays.
struct Random(u64);

impl Random {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next() as u8).collect()
    }
}

/// What `payload` must decode to: 160 samples per whole frame and 160 for a
/// SID, and nothing at all for an empty payload or a reserved frame type.
fn assert_whole_cores_only(decoder: &mut Decoder<'_>, payload: &[u8]) -> common::TestResult {
    let mut pcm: Vec<i16> = Vec::new();
    let result = decoder.decode_g7291_rtp(payload, &mut pcm);
    match g7291::split_rtp(payload) {
        Err(e) => {
            assert_eq!(result, Err(e), "{payload:02x?}");
            assert!(pcm.is_empty(), "a refused payload decodes nothing");
        }
        Ok(split) => {
            let Ok(Decoded {
                samples,
                frames,
                sid,
                frame_type,
                ignored,
            }) = result
            else {
                return Err(format!("{payload:02x?}: {result:?}").into());
            };
            let sid_decodes = split.sid.is_some();
            assert_eq!(frame_type, split.header.frame_type);
            assert_eq!(
                (frames, sid, ignored),
                (split.frame_count(), sid_decodes, split.ignored.len())
            );
            assert_eq!(samples, SUPERFRAME_SAMPLES * (frames + usize::from(sid)));
            assert_eq!(pcm.len(), samples);
            if let FrameType::Speech(rate) = frame_type {
                assert!(rate.frame_octets() >= CORE_OCTETS);
                assert_eq!(frames, (payload.len() - 1) / rate.frame_octets());
            }
        }
    }
    Ok(())
}

#[test]
fn random_payloads_never_panic_and_decode_only_whole_cores() -> common::TestResult {
    let mut decoder = Decoder::new(common::tables()?);
    let mut random = Random(0x0729_1729_0729_1729);
    for _ in 0..20_000 {
        let len = random.below(400);
        let payload = random.bytes(len);
        assert_whole_cores_only(&mut decoder, &payload)?;
    }
    Ok(())
}

#[test]
fn every_header_octet_at_every_length_decodes_only_whole_cores() -> common::TestResult {
    let mut decoder = Decoder::new(common::tables()?);
    let mut random = Random(0x5459_4749);
    for header in 0..=255u8 {
        for len in 0..=170 {
            let mut payload = vec![header];
            payload.extend(random.bytes(len));
            assert_whole_cores_only(&mut decoder, &payload)?;
        }
    }
    Ok(())
}

#[test]
fn every_truncation_of_a_packet_decodes_only_whole_cores() -> common::TestResult {
    let mut decoder = Decoder::new(common::tables()?);
    let mut random = Random(0x3551);
    for ft in [0u8, 1, 5, 11] {
        let octets = g7291::Rate::from_ft(ft).map_or(0, g7291::Rate::frame_octets);
        let mut packet = vec![0x70 | ft];
        packet.extend(random.bytes(3 * octets + 6));
        for cut in 0..=packet.len() {
            assert_whole_cores_only(&mut decoder, &packet[..cut])?;
            let body = cut.saturating_sub(1);
            let expected_frames = body / octets;
            let mut pcm: Vec<i16> = Vec::new();
            let decoded = decoder.decode_g7291_rtp(&packet[..cut], &mut pcm);
            if cut == 0 {
                assert_eq!(decoded, Err(PayloadError::Empty));
            } else {
                let remainder = body % octets;
                let sid = g7291::SID_OCTETS.contains(&remainder);
                assert_eq!(
                    pcm.len(),
                    SUPERFRAME_SAMPLES * (expected_frames + usize::from(sid)),
                    "FT {ft}, {cut} octets"
                );
            }
        }
    }
    Ok(())
}

#[test]
fn a_packet_of_the_largest_udp_payload_decodes_only_whole_cores() -> common::TestResult {
    let mut decoder = Decoder::new(common::tables()?);
    let mut random = Random(0xffff);
    // 65,507 octets: the most one UDP datagram over IPv4 carries.
    for ft in 0..=15u8 {
        let mut payload = vec![ft];
        payload.extend(random.bytes(65_506));
        assert_whole_cores_only(&mut decoder, &payload)?;
    }
    // FT 0: 3,275 frames of 20 octets and a 6-octet SID.
    let mut pcm: Vec<i16> = Vec::new();
    let mut payload = vec![0x00];
    payload.extend(random.bytes(65_506));
    let decoded = decoder.decode_g7291_rtp(&payload, &mut pcm)?;
    assert_eq!((decoded.frames, decoded.sid), (3_275, true));
    assert_eq!(pcm.len(), 3_276 * SUPERFRAME_SAMPLES);
    Ok(())
}
