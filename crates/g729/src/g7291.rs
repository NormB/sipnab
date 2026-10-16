// SPDX-License-Identifier: MIT OR Apache-2.0

//! G.729.1 RTP payloads, read for their core layer.
//!
//! [RFC 4749 section 5](https://www.rfc-editor.org/rfc/rfc4749.html#section-5)
//! packs G.729.1 in RTP: one header octet (MBS in the high 4 bits, FT in the
//! low 4), then zero or more 20 ms frames at the one bit rate FT names.
//! [RFC 5459 section 4](https://www.rfc-editor.org/rfc/rfc5459.html#section-4)
//! adds discontinuous transmission: FT 14 is a SID alone, and a remainder of
//! 2, 3 or 6 octets after the frames is a SID. A remainder of any other size
//! is ignored, and a payload with FT 12 or 13 (reserved) is ignored whole.
//!
//! The first layer of a G.729.1 frame, at 8 kbit/s, is the core layer, which
//! RFC 4749 section 2 calls "bitstream compatible with the ITU-T G.729/G.729A
//! coder": its 160 bits are two consecutive 10 ms G.729 frames, the first 20
//! octets of each G.729.1 frame. The first 15 bits of a G.729.1 SID are the
//! core SID, a G.729 Annex B SID frame (RFC 5459 section 2: "The core SID is
//! the same as the legacy G.729 SID"). This crate's tests measure both on the
//! ITU-T G.729.1 test vectors.
//!
//! This module decodes that core layer with this crate's decoder, to 8 kHz.
//! It is not G.729.1's own decoder: the higher layers (narrowband enhancement
//! at 12 kbit/s, wideband from 14 kbit/s) are skipped, and the core is
//! decoded by the Annex A decoder.

use crate::{Decoder, FRAME_SAMPLES, Frame};

/// Octets of one G.729.1 frame's core layer: two 10-octet G.729 frames.
pub const CORE_OCTETS: usize = 20;

/// Samples one 20 ms G.729.1 frame decodes to at 8 kHz.
pub const SUPERFRAME_SAMPLES: usize = 2 * FRAME_SAMPLES;

/// RTP timestamp units per G.729.1 frame: 20 ms at the 16 kHz RTP clock
/// (RFC 4749 section 4).
pub const TIMESTAMP_UNITS: u32 = 320;

/// The sizes of a SID in octets (RFC 5459 section 4).
pub const SID_OCTETS: [usize; 3] = [2, 3, 6];

/// A G.729.1 bit rate: the frame type FT 0 to 11 (RFC 4749 section 5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Rate(u8);

impl Rate {
    /// The rate frame type `ft` names, or `None` for FT 12 to 15.
    ///
    /// # Panics
    ///
    /// Does not panic.
    ///
    /// # Examples
    ///
    /// ```
    /// use g729::g7291::Rate;
    ///
    /// assert_eq!(Rate::from_ft(11).map(Rate::kbps), Some(32));
    /// assert_eq!(Rate::from_ft(14), None);
    /// ```
    #[must_use]
    pub const fn from_ft(ft: u8) -> Option<Rate> {
        if ft <= 11 { Some(Rate(ft)) } else { None }
    }

    /// The frame type, 0 to 11.
    #[must_use]
    pub const fn ft(self) -> u8 {
        self.0
    }

    /// The bit rate in kbit/s: 8, then 12 to 32 in steps of 2.
    #[must_use]
    pub const fn kbps(self) -> u8 {
        match self.0 {
            0 => 8,
            ft => 10 + 2 * ft,
        }
    }

    /// The size of one 20 ms frame at this rate, in octets: 20, then 30 to
    /// 80 in steps of 5.
    #[must_use]
    pub const fn frame_octets(self) -> usize {
        // 20 ms of `kbps` kbit/s: kbps * 20 / 8 octets.
        self.kbps() as usize * 5 / 2
    }
}

/// What the FT field of a payload header says the payload holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    /// FT 0 to 11: frames at this rate.
    Speech(Rate),
    /// FT 12 or 13: reserved; the whole payload is ignored.
    Reserved(u8),
    /// FT 14: a SID alone.
    Sid,
    /// FT 15: no audio data.
    NoData,
}

impl FrameType {
    /// The frame type of the low 4 bits of `ft`.
    ///
    /// # Panics
    ///
    /// Does not panic.
    #[must_use]
    pub const fn from_ft(ft: u8) -> FrameType {
        match ft & 0x0f {
            14 => FrameType::Sid,
            15 => FrameType::NoData,
            ft => match Rate::from_ft(ft) {
                Some(rate) => FrameType::Speech(rate),
                None => FrameType::Reserved(ft),
            },
        }
    }
}

/// A payload header: MBS and FT (RFC 4749 sections 5.2 and 5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// The maximum bit rate the sender asks to receive. A request to the far
    /// end; it does not affect decoding.
    pub mbs: u8,
    /// What the payload holds.
    pub frame_type: FrameType,
}

impl Header {
    /// The header in `octet`: MBS in the high 4 bits, FT in the low 4.
    ///
    /// # Panics
    ///
    /// Does not panic.
    ///
    /// # Examples
    ///
    /// ```
    /// use g729::g7291::{FrameType, Header};
    ///
    /// let header = Header::from_octet(0xbe);
    /// assert_eq!((header.mbs, header.frame_type), (11, FrameType::Sid));
    /// ```
    #[must_use]
    pub const fn from_octet(octet: u8) -> Header {
        Header {
            mbs: octet >> 4,
            frame_type: FrameType::from_ft(octet),
        }
    }
}

/// An RTP payload, split into its header, its whole frames, its SID and
/// the octets it ignores.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Payload<'a> {
    /// The header.
    pub header: Header,
    /// The whole frames, oldest first, end to end; empty for FT 14 and 15.
    pub frames: &'a [u8],
    /// The SID: FT 14's octets, or the remainder after the frames, when it
    /// is 2, 3 or 6 octets.
    pub sid: Option<&'a [u8]>,
    /// The octets after the header that are neither a whole frame nor a
    /// SID.
    pub ignored: &'a [u8],
}

impl<'a> Payload<'a> {
    /// The size of one frame, or 0 when the payload holds no frames.
    #[must_use]
    pub fn frame_octets(&self) -> usize {
        match self.header.frame_type {
            FrameType::Speech(rate) => rate.frame_octets(),
            _ => 0,
        }
    }

    /// The whole frames, oldest first.
    pub fn frames(&self) -> impl Iterator<Item = &'a [u8]> + use<'a> {
        let size = self.frame_octets().max(1);
        self.frames.chunks_exact(size)
    }

    /// How many whole frames the payload holds.
    #[must_use]
    pub fn frame_count(&self) -> usize {
        match self.frame_octets() {
            0 => 0,
            size => self.frames.len() / size,
        }
    }
}

/// Why a G.729.1 RTP payload holds nothing to decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadError {
    /// The payload has no header octet.
    Empty,
    /// FT is 12 or 13, which RFC 4749 reserves: the whole payload is
    /// ignored.
    Reserved(u8),
}

impl core::fmt::Display for PayloadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Empty => write!(f, "G.729.1 payload is empty: no payload header"),
            Self::Reserved(ft) => {
                write!(f, "G.729.1 payload has reserved frame type {ft}: ignored")
            }
        }
    }
}

/// A standard error, so `?` converts it into `Box<dyn Error>` and the like.
impl core::error::Error for PayloadError {}

/// Split a G.729.1 RTP payload (RFC 4749 section 5, RFC 5459 section 4).
///
/// # Errors
///
/// [`PayloadError::Empty`] for an empty payload, and
/// [`PayloadError::Reserved`] for FT 12 or 13.
///
/// # Panics
///
/// Does not panic.
///
/// # Examples
///
/// ```
/// use g729::g7291::split_rtp;
///
/// // FT 0 (8 kbit/s): two 20-octet frames and a 2-octet SID.
/// let mut payload = vec![0xf0];
/// payload.extend_from_slice(&[0u8; 42]);
/// let split = split_rtp(&payload)?;
/// assert_eq!(split.frame_count(), 2);
/// assert_eq!(split.sid.map(<[u8]>::len), Some(2));
/// # Ok::<(), g729::g7291::PayloadError>(())
/// ```
pub fn split_rtp(payload: &[u8]) -> Result<Payload<'_>, PayloadError> {
    let Some((&octet, body)) = payload.split_first() else {
        return Err(PayloadError::Empty);
    };
    let header = Header::from_octet(octet);
    let (frames, rest) = match header.frame_type {
        FrameType::Reserved(ft) => return Err(PayloadError::Reserved(ft)),
        FrameType::NoData => {
            return Ok(Payload {
                header,
                frames: &[],
                sid: None,
                ignored: body,
            });
        }
        FrameType::Sid => body.split_at(0),
        FrameType::Speech(rate) => {
            let size = rate.frame_octets();
            body.split_at(body.len() - body.len() % size)
        }
    };
    let (sid, ignored) = if SID_OCTETS.contains(&rest.len()) {
        (Some(rest), &rest[rest.len()..])
    } else {
        (None, rest)
    };
    Ok(Payload {
        header,
        frames,
        sid,
        ignored,
    })
}

/// The core layer of one G.729.1 frame: its first 20 octets, as the two
/// 10-octet G.729 frames they are, in order. `None` when `frame` is shorter
/// than 20 octets.
///
/// # Panics
///
/// Does not panic.
///
/// # Examples
///
/// ```
/// use g729::g7291::core_frames;
///
/// let frame = [7u8; 80];
/// let [first, second] = core_frames(&frame).ok_or("a whole core")?;
/// assert_eq!((first, second), (&[7u8; 10], &[7u8; 10]));
/// # Ok::<(), &str>(())
/// ```
#[must_use]
pub fn core_frames(frame: &[u8]) -> Option<[&[u8; 10]; 2]> {
    let core = frame.first_chunk::<CORE_OCTETS>()?;
    let (first, second) = core.split_first_chunk::<10>()?;
    Some([first, second.first_chunk::<10>()?])
}

/// The core SID of a G.729.1 SID of 2, 3 or 6 octets: its first 15 bits, as
/// a 2-octet G.729 Annex B SID frame whose 16th bit is 0. `None` for any
/// other size.
///
/// # Panics
///
/// Does not panic.
///
/// # Examples
///
/// ```
/// use g729::g7291::core_sid;
///
/// assert_eq!(core_sid(&[0xff, 0xff, 0xff]), Some([0xff, 0xfe]));
/// assert_eq!(core_sid(&[0xff; 4]), None);
/// ```
#[must_use]
pub fn core_sid(sid: &[u8]) -> Option<[u8; 2]> {
    if !SID_OCTETS.contains(&sid.len()) {
        return None;
    }
    let &[first, second, ..] = sid else {
        return None;
    };
    Some([first, second & 0xfe])
}

/// One 20 ms G.729.1 frame as the core-layer decoder takes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Superframe<'a> {
    /// A frame's core layer (see [`core_frames`]).
    Speech(&'a [u8; CORE_OCTETS]),
    /// A core SID (see [`core_sid`]).
    Sid(&'a [u8; 2]),
    /// A frame the sender did not send.
    NoTx,
    /// A lost or corrupted frame.
    Erased,
}

/// What [`Decoder::decode_g7291_rtp`] decoded from one payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decoded {
    /// Samples appended.
    pub samples: usize,
    /// What the header said the payload holds.
    pub frame_type: FrameType,
    /// Whole frames decoded.
    pub frames: usize,
    /// Whether a SID was decoded.
    pub sid: bool,
    /// Octets ignored: neither a whole frame nor a SID.
    pub ignored: usize,
}

impl Decoder<'_> {
    /// Decode one 20 ms G.729.1 frame's core layer into 160 samples at
    /// 8 kHz: two G.729 frames.
    ///
    /// A core SID decodes as a SID frame and then an untransmitted frame,
    /// the order the ITU-T G.729.1 test vectors hold the core SID in when
    /// they are written as G.729 frames. An untransmitted or erased frame
    /// is two of the same.
    ///
    /// # Panics
    ///
    /// Does not panic.
    pub fn decode_superframe(
        &mut self,
        frame: Superframe<'_>,
        out: &mut [i16; SUPERFRAME_SAMPLES],
    ) {
        let (first, second) = match frame {
            Superframe::Speech(core) => match core.as_chunks::<10>().0 {
                [first, second] => (Frame::Voice(first), Frame::Voice(second)),
                // A 20-octet core is always two frames.
                _ => (Frame::Erased, Frame::Erased),
            },
            Superframe::Sid(sid) => (Frame::Sid(sid), Frame::NoTx),
            Superframe::NoTx => (Frame::NoTx, Frame::NoTx),
            Superframe::Erased => (Frame::Erased, Frame::Erased),
        };
        let (head, tail) = out.split_at_mut(FRAME_SAMPLES);
        for (frame, half) in [(first, head), (second, tail)] {
            let mut samples = [0i16; FRAME_SAMPLES];
            self.decode(frame, &mut samples);
            half.copy_from_slice(&samples);
        }
    }

    /// Decode a G.729.1 RTP payload's core layer (RFC 4749, RFC 5459):
    /// 160 samples per whole frame, oldest first, then 160 for a SID.
    /// Appends to `out`.
    ///
    /// FT 15 (no data) decodes nothing. Octets that are neither a whole
    /// frame nor a SID are skipped; no sample comes from a partial core.
    ///
    /// # Errors
    ///
    /// [`PayloadError`] for an empty payload or a reserved frame type.
    /// Nothing is decoded then.
    ///
    /// # Panics
    ///
    /// Does not panic.
    pub fn decode_g7291_rtp(
        &mut self,
        payload: &[u8],
        out: &mut impl Extend<i16>,
    ) -> Result<Decoded, PayloadError> {
        let split = split_rtp(payload)?;
        let cores = split
            .frames()
            .filter_map(|frame| frame.first_chunk::<CORE_OCTETS>())
            .map(Superframe::Speech);
        let sid = split.sid.and_then(core_sid);
        let mut decoded = Decoded {
            samples: 0,
            frame_type: split.header.frame_type,
            frames: 0,
            sid: false,
            ignored: split.ignored.len(),
        };
        let mut samples = [0i16; SUPERFRAME_SAMPLES];
        for core in cores {
            self.decode_superframe(core, &mut samples);
            out.extend(samples);
            decoded.frames += 1;
            decoded.samples += SUPERFRAME_SAMPLES;
        }
        if let Some(sid) = &sid {
            self.decode_superframe(Superframe::Sid(sid), &mut samples);
            out.extend(samples);
            decoded.sid = true;
            decoded.samples += SUPERFRAME_SAMPLES;
        }
        Ok(decoded)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec;
    use std::vec::Vec;

    type TestResult = Result<(), PayloadError>;

    /// One G.729.1 payload: the header octet `mbs << 4 | ft`, then `body`.
    fn payload(mbs: u8, ft: u8, body: &[u8]) -> Vec<u8> {
        let mut p = vec![(mbs << 4) | ft];
        p.extend_from_slice(body);
        p
    }

    /// Octets numbered from `start`, so each position is told apart.
    fn numbered(len: usize, start: u8) -> Vec<u8> {
        (0..len).map(|i| start.wrapping_add(i as u8)).collect()
    }

    // ── Payload header: one test per FT value ───────────────────────────

    /// FT `ft` names a rate of `kbps` kbit/s in frames of `octets` octets,
    /// and a payload of one such frame splits into exactly that frame.
    fn assert_rate(ft: u8, kbps: u8, octets: usize) -> TestResult {
        let header = Header::from_octet(0xf0 | ft);
        let FrameType::Speech(rate) = header.frame_type else {
            panic!("FT {ft} is {:?}, not a rate", header.frame_type);
        };
        assert_eq!(rate.ft(), ft);
        assert_eq!(rate.kbps(), kbps, "FT {ft}");
        assert_eq!(rate.frame_octets(), octets, "FT {ft}");
        assert_eq!(Rate::from_ft(ft), Some(rate));
        let frame = numbered(octets, 1);
        let split_bytes = payload(15, ft, &frame);
        let split = split_rtp(&split_bytes)?;
        assert_eq!(split.frame_count(), 1);
        assert_eq!(split.frames().collect::<Vec<_>>(), [&frame[..]]);
        assert_eq!((split.sid, split.ignored), (None, &[][..]));
        Ok(())
    }

    #[test]
    fn ft_0_is_8_kbit_s_in_20_octet_frames() -> TestResult {
        assert_rate(0, 8, 20)
    }

    #[test]
    fn ft_1_is_12_kbit_s_in_30_octet_frames() -> TestResult {
        assert_rate(1, 12, 30)
    }

    #[test]
    fn ft_2_is_14_kbit_s_in_35_octet_frames() -> TestResult {
        assert_rate(2, 14, 35)
    }

    #[test]
    fn ft_3_is_16_kbit_s_in_40_octet_frames() -> TestResult {
        assert_rate(3, 16, 40)
    }

    #[test]
    fn ft_4_is_18_kbit_s_in_45_octet_frames() -> TestResult {
        assert_rate(4, 18, 45)
    }

    #[test]
    fn ft_5_is_20_kbit_s_in_50_octet_frames() -> TestResult {
        assert_rate(5, 20, 50)
    }

    #[test]
    fn ft_6_is_22_kbit_s_in_55_octet_frames() -> TestResult {
        assert_rate(6, 22, 55)
    }

    #[test]
    fn ft_7_is_24_kbit_s_in_60_octet_frames() -> TestResult {
        assert_rate(7, 24, 60)
    }

    #[test]
    fn ft_8_is_26_kbit_s_in_65_octet_frames() -> TestResult {
        assert_rate(8, 26, 65)
    }

    #[test]
    fn ft_9_is_28_kbit_s_in_70_octet_frames() -> TestResult {
        assert_rate(9, 28, 70)
    }

    #[test]
    fn ft_10_is_30_kbit_s_in_75_octet_frames() -> TestResult {
        assert_rate(10, 30, 75)
    }

    #[test]
    fn ft_11_is_32_kbit_s_in_80_octet_frames() -> TestResult {
        assert_rate(11, 32, 80)
    }

    /// FT `ft` is reserved: the whole payload is ignored, whatever follows.
    fn assert_reserved(ft: u8) {
        assert_eq!(Header::from_octet(ft).frame_type, FrameType::Reserved(ft));
        assert_eq!(Rate::from_ft(ft), None);
        for body in [&[][..], &[0u8; 2][..], &[0u8; 20][..], &[0u8; 80][..]] {
            assert_eq!(
                split_rtp(&payload(0, ft, body)),
                Err(PayloadError::Reserved(ft))
            );
        }
    }

    #[test]
    fn ft_12_is_reserved_and_its_payload_ignored() {
        assert_reserved(12);
    }

    #[test]
    fn ft_13_is_reserved_and_its_payload_ignored() {
        assert_reserved(13);
    }

    #[test]
    fn ft_14_is_a_sid_alone() -> TestResult {
        assert_eq!(Header::from_octet(0x0e).frame_type, FrameType::Sid);
        assert_eq!(Rate::from_ft(14), None);
        let sid = numbered(3, 9);
        let split_bytes = payload(0, 14, &sid);
        let split = split_rtp(&split_bytes)?;
        assert_eq!(split.frame_count(), 0);
        assert_eq!(split.sid, Some(&sid[..]));
        Ok(())
    }

    #[test]
    fn ft_15_is_no_data() -> TestResult {
        assert_eq!(Header::from_octet(0xff).frame_type, FrameType::NoData);
        assert_eq!(Rate::from_ft(15), None);
        let alone = split_rtp(&[0xff])?;
        assert_eq!((alone.frame_count(), alone.sid), (0, None));
        // Octets after a no-data header are not audio.
        let trailing_bytes = payload(15, 15, &numbered(22, 0));
        let trailing = split_rtp(&trailing_bytes)?;
        assert_eq!((trailing.frame_count(), trailing.sid), (0, None));
        assert_eq!((trailing.frames, trailing.ignored.len()), (&[][..], 22));
        Ok(())
    }

    // ── Frame split ──────────────────────────────────────────────────────

    /// Every rate, FT 0 to 11; fails unless there are 12.
    fn rates() -> Vec<Rate> {
        let all: Vec<Rate> = (0..12).filter_map(Rate::from_ft).collect();
        assert_eq!(all.len(), 12, "FT 0 to 11 each name a rate");
        all
    }

    #[test]
    fn n_frames_at_each_size_split_into_n_frames() -> TestResult {
        for rate in rates() {
            for n in 0..=6 {
                let body = numbered(n * rate.frame_octets(), 0);
                let split_bytes = payload(0, rate.ft(), &body);
                let split = split_rtp(&split_bytes)?;
                assert_eq!(split.frame_count(), n, "{rate:?} x {n}");
                assert_eq!(split.frames().count(), n, "{rate:?} x {n}");
                assert_eq!(split.frames, &body[..]);
                assert_eq!((split.sid, split.ignored), (None, &[][..]));
            }
        }
        Ok(())
    }

    #[test]
    fn frames_come_oldest_first() -> TestResult {
        let rate = Rate::from_ft(3).ok_or(PayloadError::Empty)?;
        let frames: Vec<Vec<u8>> = (0..4u8).map(|k| vec![k; rate.frame_octets()]).collect();
        let split_bytes = payload(0, 3, &frames.concat());
        let split = split_rtp(&split_bytes)?;
        let got: Vec<&[u8]> = split.frames().collect();
        let want: Vec<&[u8]> = frames.iter().map(Vec::as_slice).collect();
        assert_eq!(got, want);
        Ok(())
    }

    #[test]
    fn a_remainder_of_0_octets_is_neither_sid_nor_ignored() -> TestResult {
        for rate in rates() {
            let split_bytes = payload(0, rate.ft(), &numbered(2 * rate.frame_octets(), 0));
            let split = split_rtp(&split_bytes)?;
            assert_eq!((split.sid, split.ignored.len()), (None, 0), "{rate:?}");
        }
        Ok(())
    }

    #[test]
    fn a_remainder_of_2_3_or_6_octets_is_a_sid() -> TestResult {
        for rate in rates() {
            for remainder in SID_OCTETS {
                let body = numbered(2 * rate.frame_octets() + remainder, 0);
                let split_bytes = payload(0, rate.ft(), &body);
                let split = split_rtp(&split_bytes)?;
                assert_eq!(split.frame_count(), 2, "{rate:?} + {remainder}");
                assert_eq!(split.sid, Some(&body[body.len() - remainder..]));
                assert_eq!(split.ignored.len(), 0);
            }
        }
        Ok(())
    }

    #[test]
    fn a_remainder_of_1_4_5_or_7_octets_is_ignored() -> TestResult {
        for rate in rates() {
            for remainder in [1, 4, 5, 7] {
                let body = numbered(rate.frame_octets() + remainder, 0);
                let split_bytes = payload(0, rate.ft(), &body);
                let split = split_rtp(&split_bytes)?;
                assert_eq!(split.frame_count(), 1, "{rate:?} + {remainder}");
                assert_eq!(split.sid, None, "{rate:?} + {remainder}");
                assert_eq!(split.ignored, &body[body.len() - remainder..]);
            }
        }
        Ok(())
    }

    #[test]
    fn a_sid_alone_comes_with_ft_14() -> TestResult {
        for size in SID_OCTETS {
            let sid = numbered(size, 0x40);
            let alone_bytes = payload(0, 14, &sid);
            let alone = split_rtp(&alone_bytes)?;
            assert_eq!((alone.frame_count(), alone.sid), (0, Some(&sid[..])));
            // Under a rate's FT the same octets are zero frames followed by
            // a SID (RFC 5459 section 4).
            let under_ft0_bytes = payload(0, 0, &sid);
            let under_ft0 = split_rtp(&under_ft0_bytes)?;
            assert_eq!(
                (under_ft0.frame_count(), under_ft0.sid),
                (0, Some(&sid[..]))
            );
        }
        Ok(())
    }

    #[test]
    fn ft_14_of_any_other_size_holds_no_sid() -> TestResult {
        for size in [0, 1, 4, 5, 7, 8, 20] {
            let split_bytes = payload(0, 14, &numbered(size, 0));
            let split = split_rtp(&split_bytes)?;
            assert_eq!(split.sid, None, "{size} octets");
            assert_eq!(split.ignored.len(), size);
        }
        Ok(())
    }

    #[test]
    fn mbs_does_not_change_the_split() -> TestResult {
        let body = numbered(2 * 50 + 3, 0);
        let reference_bytes = payload(0, 5, &body);
        let reference = split_rtp(&reference_bytes)?;
        for mbs in 0..16 {
            let split_bytes = payload(mbs, 5, &body);
            let split = split_rtp(&split_bytes)?;
            assert_eq!(split.header.mbs, mbs);
            assert_eq!(
                (split.frames, split.sid, split.ignored),
                (reference.frames, reference.sid, reference.ignored),
                "MBS {mbs}"
            );
        }
        Ok(())
    }

    #[test]
    fn an_empty_payload_is_refused() {
        assert_eq!(split_rtp(&[]), Err(PayloadError::Empty));
        // One octet is a header, and no longer empty.
        assert!(split_rtp(&[0x00]).is_ok());
    }

    #[test]
    fn a_header_alone_is_zero_frames() -> TestResult {
        for ft in 0..12 {
            let header = [ft];
            let split = split_rtp(&header)?;
            assert_eq!((split.frame_count(), split.sid), (0, None), "FT {ft}");
            assert_eq!(split.ignored.len(), 0);
        }
        Ok(())
    }

    // ── Core extraction ──────────────────────────────────────────────────

    /// The core of one frame of `octets` octets is its first 20.
    fn assert_core_of(octets: usize) {
        let frame = numbered(octets, 1);
        let [first, second] = core_frames(&frame).unwrap_or_else(|| panic!("{octets}: a core"));
        assert_eq!(&first[..], &frame[..10], "{octets}");
        assert_eq!(&second[..], &frame[10..20], "{octets}");
    }

    #[test]
    fn the_core_of_an_8_kbit_s_frame_is_the_whole_frame() {
        assert_core_of(20);
    }

    #[test]
    fn the_core_of_a_12_kbit_s_frame_is_its_first_20_octets() {
        assert_core_of(30);
    }

    #[test]
    fn the_core_of_a_20_kbit_s_frame_is_its_first_20_octets() {
        assert_core_of(50);
    }

    #[test]
    fn the_core_of_a_32_kbit_s_frame_is_its_first_20_octets() {
        assert_core_of(80);
    }

    #[test]
    fn the_core_is_two_g729_frames_in_order() {
        let mut frame = [0u8; 20];
        frame[..10].copy_from_slice(&[0xaa; 10]);
        frame[10..].copy_from_slice(&[0x55; 10]);
        assert_eq!(core_frames(&frame), Some([&[0xaa; 10], &[0x55; 10]]));
    }

    #[test]
    fn the_higher_layers_are_never_read() {
        let mut frame = numbered(80, 3);
        let core = core_frames(&frame).map(|[a, b]| (*a, *b));
        assert!(core.is_some(), "an 80-octet frame has a core");
        for byte in &mut frame[20..] {
            *byte = !*byte;
        }
        assert_eq!(core_frames(&frame).map(|[a, b]| (*a, *b)), core);
        // A frame shorter than a whole core has none.
        for short in 0..20 {
            assert_eq!(core_frames(&frame[..short]), None, "{short} octets");
        }
    }

    // ── SID ──────────────────────────────────────────────────────────────

    #[test]
    fn a_2_octet_sid_alone_is_its_core_sid() -> TestResult {
        let split_bytes = payload(0, 14, &[0xa5, 0x5b]);
        let split = split_rtp(&split_bytes)?;
        assert_eq!(split.sid.and_then(core_sid), Some([0xa5, 0x5a]));
        Ok(())
    }

    #[test]
    fn a_3_octet_sid_alone_carries_its_core_sid_first() -> TestResult {
        let split_bytes = payload(0, 14, &[0x12, 0x35, 0xff]);
        let split = split_rtp(&split_bytes)?;
        assert_eq!(split.sid.and_then(core_sid), Some([0x12, 0x34]));
        Ok(())
    }

    #[test]
    fn a_6_octet_sid_alone_carries_its_core_sid_first() -> TestResult {
        let split_bytes = payload(0, 14, &[0xfe, 0xdd, 1, 2, 3, 4]);
        let split = split_rtp(&split_bytes)?;
        assert_eq!(split.sid.and_then(core_sid), Some([0xfe, 0xdc]));
        Ok(())
    }

    #[test]
    fn a_sid_appended_to_frames_is_found_at_every_size() -> TestResult {
        for ft in [0, 11] {
            let octets = Rate::from_ft(ft).map_or(0, Rate::frame_octets);
            for size in SID_OCTETS {
                let mut body = numbered(3 * octets, 0);
                body.extend_from_slice(&numbered(size, 0x81));
                let split_bytes = payload(0, ft, &body);
                let split = split_rtp(&split_bytes)?;
                assert_eq!(split.frame_count(), 3);
                assert_eq!(split.sid.and_then(core_sid), Some([0x81, 0x82]));
            }
        }
        Ok(())
    }

    #[test]
    fn a_sid_of_another_size_has_no_core_sid() {
        for size in SID_OCTETS {
            assert!(core_sid(&numbered(size, 0)).is_some(), "{size} octets");
        }
        for size in [0, 1, 4, 5, 7, 8, 20] {
            assert_eq!(core_sid(&numbered(size, 0)), None, "{size} octets");
        }
    }

    #[test]
    fn the_core_sid_is_the_first_15_bits() {
        for size in SID_OCTETS {
            let base = vec![0u8; size];
            for bit in 0..size * 8 {
                let mut sid = base.clone();
                sid[bit / 8] |= 0x80 >> (bit % 8);
                let core = core_sid(&sid);
                if bit < 15 {
                    let mut want = [0u8; 2];
                    want[bit / 8] = 0x80 >> (bit % 8);
                    assert_eq!(core, Some(want), "{size} octets, bit {bit}");
                } else {
                    assert_eq!(core, Some([0, 0]), "{size} octets, bit {bit}");
                }
            }
        }
    }
}
