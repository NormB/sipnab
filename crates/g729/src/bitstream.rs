// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bit streams: the fields of an active frame (G.729 Table 8, MSB first) and
//! of a SID frame (Annex B Table B.2, clause B.4.3) as packed in RTP by
//! RFC 3551 section 4.5.6 (Figure 4: 10 octets per frame, 2 octets per
//! comfort-noise frame, a packet being zero or more frames followed by zero
//! or one comfort-noise frame); and the ITU-T G.192 serial format of the
//! test vectors (16-bit little-endian words: a synchronization word, a size
//! word, then one word per bit).

/// The parameters of an active frame (Table 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpeechParams {
    /// L0 (1 bit), L1 (7), L2 (5), L3 (5).
    pub l: [u16; 4],
    /// P1, pitch delay of subframe 1 (8 bits).
    pub p1: u16,
    /// P0, parity of P1 (1 bit).
    pub p0: u16,
    /// P2, relative pitch delay of subframe 2 (5 bits).
    pub p2: u16,
    /// C1, C2: fixed-codebook positions (13 bits each).
    pub c: [u16; 2],
    /// S1, S2: fixed-codebook signs (4 bits each).
    pub s: [u16; 2],
    /// GA1, GA2: first-stage gain indices (3 bits each).
    pub ga: [u16; 2],
    /// GB1, GB2: second-stage gain indices (4 bits each).
    pub gb: [u16; 2],
}

/// The parameters of a SID frame (Table B.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SidParams {
    /// Switched predictor index of the LSF quantizer (1 bit).
    pub switch: u16,
    /// First-stage LSF vector index (5 bits).
    pub stage1: u16,
    /// Second-stage LSF vector index (4 bits).
    pub stage2: u16,
    /// Energy (gain) index (5 bits).
    pub energy: u16,
}

/// MSB-first bit reader.
struct Bits<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Bits<'_> {
    fn take(&mut self, n: usize) -> u16 {
        let mut v = 0u16;
        for _ in 0..n {
            let byte = self.bytes.get(self.at / 8).copied().unwrap_or(0);
            let bit = (byte >> (7 - self.at % 8)) & 1;
            v = (v << 1) | u16::from(bit);
            self.at += 1;
        }
        v
    }
}

impl SpeechParams {
    /// Unpack the 80 bits of an active frame.
    ///
    /// # Panics
    ///
    /// Does not panic.
    ///
    /// # Examples
    ///
    /// ```
    /// use g729::bitstream::SpeechParams;
    ///
    /// // The first bit of the frame is L0; the last 4 bits are GB2.
    /// let mut frame = [0u8; 10];
    /// frame[0] = 0x80;
    /// frame[9] = 0x0f;
    /// let params = SpeechParams::unpack(&frame);
    /// assert_eq!(params.l[0], 1);
    /// assert_eq!(params.gb[1], 15);
    /// ```
    pub fn unpack(frame: &[u8; 10]) -> Self {
        let mut b = Bits {
            bytes: frame,
            at: 0,
        };
        let l = [b.take(1), b.take(7), b.take(5), b.take(5)];
        let p1 = b.take(8);
        let p0 = b.take(1);
        let c1 = b.take(13);
        let s1 = b.take(4);
        let ga1 = b.take(3);
        let gb1 = b.take(4);
        let p2 = b.take(5);
        let c2 = b.take(13);
        let s2 = b.take(4);
        let ga2 = b.take(3);
        let gb2 = b.take(4);
        SpeechParams {
            l,
            p1,
            p0,
            p2,
            c: [c1, c2],
            s: [s1, s2],
            ga: [ga1, ga2],
            gb: [gb1, gb2],
        }
    }
}

impl SidParams {
    /// Unpack the 15 bits of a SID frame (the 16th octet bit is padding).
    ///
    /// # Panics
    ///
    /// Does not panic.
    ///
    /// # Examples
    ///
    /// ```
    /// use g729::bitstream::SidParams;
    ///
    /// // All 15 bits set; the pad bit is ignored.
    /// let params = SidParams::unpack(&[0xff, 0xfe]);
    /// assert_eq!(
    ///     (params.switch, params.stage1, params.stage2, params.energy),
    ///     (1, 31, 15, 31)
    /// );
    /// ```
    pub fn unpack(frame: &[u8; 2]) -> Self {
        let mut b = Bits {
            bytes: frame,
            at: 0,
        };
        SidParams {
            switch: b.take(1),
            stage1: b.take(5),
            stage2: b.take(4),
            energy: b.take(5),
        }
    }
}

/// An RTP payload whose length is neither 10n nor 10n + 2 octets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadLength(pub usize);

/// An RTP payload's 10-octet frames and optional trailing 2-octet SID frame.
pub type RtpFrames<'a> = (&'a [[u8; 10]], Option<&'a [u8; 2]>);

/// Split an RTP payload into its 10-octet frames and optional 2-octet SID.
///
/// # Errors
///
/// [`PayloadLength`] with the payload's length when the length is neither
/// 10n nor 10n + 2 octets.
///
/// # Panics
///
/// Does not panic.
///
/// # Examples
///
/// ```
/// use g729::bitstream::{PayloadLength, split_rtp};
///
/// // Two frames and a SID frame.
/// let payload = [0u8; 22];
/// let (frames, sid) = split_rtp(&payload)?;
/// assert_eq!(frames.len(), 2);
/// assert!(sid.is_some());
///
/// // A SID frame alone.
/// assert_eq!(split_rtp(&[0u8; 2])?.0.len(), 0);
///
/// assert_eq!(split_rtp(&[0u8; 15]), Err(PayloadLength(15)));
/// # Ok::<(), PayloadLength>(())
/// ```
pub fn split_rtp(payload: &[u8]) -> Result<RtpFrames<'_>, PayloadLength> {
    let (frames, rest) = payload.as_chunks::<10>();
    match rest.len() {
        0 => Ok((frames, None)),
        2 => Ok((frames, rest.first_chunk::<2>())),
        _ => Err(PayloadLength(payload.len())),
    }
}

/// One frame of a G.192 serial file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerialFrame {
    /// An active frame, packed MSB first.
    Speech([u8; 10]),
    /// A SID frame: its 15 bits packed MSB first, then a zero pad bit.
    Sid([u8; 2]),
    /// An untransmitted frame.
    NoTx,
    /// An erased frame.
    Erased,
}

impl SerialFrame {
    /// The decoder input for this frame: `Speech` becomes
    /// [`Frame::Voice`](crate::Frame::Voice), `Sid` becomes
    /// [`Frame::Sid`](crate::Frame::Sid), and `NoTx` and `Erased` map to the
    /// variants of the same name.
    ///
    /// # Panics
    ///
    /// Does not panic.
    ///
    /// # Examples
    ///
    /// ```
    /// use g729::Frame;
    /// use g729::bitstream::SerialFrame;
    ///
    /// let serial = SerialFrame::Speech([0; 10]);
    /// assert_eq!(serial.frame(), Frame::Voice(&[0; 10]));
    /// assert_eq!(SerialFrame::Erased.frame(), Frame::Erased);
    /// ```
    pub fn frame(&self) -> crate::Frame<'_> {
        match self {
            Self::Speech(bytes) => crate::Frame::Voice(bytes),
            Self::Sid(bytes) => crate::Frame::Sid(bytes),
            Self::NoTx => crate::Frame::NoTx,
            Self::Erased => crate::Frame::Erased,
        }
    }
}

/// A malformed G.192 file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum G192Error {
    /// The file ends inside a frame (byte offset).
    Truncated {
        /// Offset of the frame.
        at: usize,
    },
    /// A size word other than 80, 16 or 0 under sync 0x6B21.
    Length {
        /// Offset of the frame.
        at: usize,
        /// The size word.
        len: u16,
    },
    /// A bit word other than 0x007F, 0x0081 or 0x0000.
    BitWord {
        /// Offset of the frame.
        at: usize,
        /// The word.
        word: u16,
    },
}

impl core::fmt::Display for G192Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Truncated { at } => write!(f, "G.192 file truncated in the frame at byte {at}"),
            Self::Length { at, len } => write!(f, "G.192 frame at byte {at}: size word {len}"),
            Self::BitWord { at, word } => {
                write!(f, "G.192 frame at byte {at}: bit word {word:#06x}")
            }
        }
    }
}

/// A standard error, so `?` converts it into `Box<dyn Error>` and the like.
impl core::error::Error for G192Error {}

/// Synchronization word of a good frame.
pub const SYNC_GOOD: u16 = 0x6B21;
/// Synchronization word the test vectors use for a bad frame (any word
/// other than [`SYNC_GOOD`] marks one).
pub const SYNC_BAD: u16 = 0x6B20;
const BIT_ZERO: u16 = 0x007F;
const BIT_ONE: u16 = 0x0081;

/// Iterator over the frames of a G.192 file.
#[derive(Debug, Clone)]
pub struct G192Frames<'a> {
    data: &'a [u8],
    at: usize,
}

/// Parse a G.192 file frame by frame.
///
/// Each item is a [`SerialFrame`], or a [`G192Error`] for a malformed
/// frame; after an error the iterator ends. A frame whose synchronization
/// word is not [`SYNC_GOOD`], or that holds a zero bit word, is
/// [`SerialFrame::Erased`]. A good frame of 80 bits is speech, of 16 bits a
/// SID frame, and of 0 bits an untransmitted frame.
///
/// # Panics
///
/// Neither this function nor the iterator panics.
///
/// # Examples
///
/// ```
/// use g729::bitstream::{SYNC_GOOD, SerialFrame, g192_frames};
///
/// // One untransmitted frame: the synchronization word, then size 0.
/// let words = [SYNC_GOOD, 0];
/// let file: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
/// let frames: Vec<_> = g192_frames(&file).collect();
/// assert_eq!(frames, [Ok(SerialFrame::NoTx)]);
/// ```
pub fn g192_frames(data: &[u8]) -> G192Frames<'_> {
    G192Frames { data, at: 0 }
}

impl G192Frames<'_> {
    fn word(&self, k: usize) -> Option<u16> {
        let i = self.at + 2 * k;
        Some(u16::from_le_bytes([
            *self.data.get(i)?,
            *self.data.get(i + 1)?,
        ]))
    }

    fn frame(&self) -> Result<(SerialFrame, usize), G192Error> {
        let at = self.at;
        let (Some(sync), Some(len)) = (self.word(0), self.word(1)) else {
            return Err(G192Error::Truncated { at });
        };
        let n = usize::from(len);
        if self.word(1 + n).is_none() && n > 0 {
            return Err(G192Error::Truncated { at });
        }
        let size = 4 + 2 * n;
        // Any first word other than 0x6B21 marks an erased frame.
        if sync != SYNC_GOOD {
            return Ok((SerialFrame::Erased, size));
        }
        if !matches!(n, 0 | 16 | 80) {
            return Err(G192Error::Length { at, len });
        }
        if n == 0 {
            return Ok((SerialFrame::NoTx, size));
        }
        let mut packed = [0u8; 10];
        let mut erased = false;
        for k in 0..n {
            match self.word(2 + k) {
                Some(BIT_ONE) => packed[k / 8] |= 0x80 >> (k % 8),
                Some(BIT_ZERO) => {}
                Some(0) => erased = true,
                Some(word) => return Err(G192Error::BitWord { at, word }),
                None => return Err(G192Error::Truncated { at }),
            }
        }
        let frame = if erased {
            SerialFrame::Erased
        } else if n == 80 {
            SerialFrame::Speech(packed)
        } else {
            // The 16th bit word is the pad bit; only 15 bits are SID bits.
            SerialFrame::Sid([packed[0], packed[1] & 0xfe])
        };
        Ok((frame, size))
    }
}

impl Iterator for G192Frames<'_> {
    type Item = Result<SerialFrame, G192Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.at >= self.data.len() {
            return None;
        }
        match self.frame() {
            Ok((frame, size)) => {
                self.at += size;
                Some(Ok(frame))
            }
            Err(e) => {
                self.at = self.data.len();
                Some(Err(e))
            }
        }
    }
}
