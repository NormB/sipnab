// SPDX-License-Identifier: MIT OR Apache-2.0

//! Clean-room ITU-T G.729 Annex A decoder with Annex B comfort noise and the G.729.1 core layer.
//!
//! Implements the decoder of Recommendation ITU-T G.729 (06/2012) as reduced
//! by Annex A (clause A.4), with the Annex B (clause B.4) SID decoding and
//! comfort-noise generation behind the `annex-b` feature (on by default). It
//! decodes only; there is no encoder. It also decodes main-body G.729
//! streams, which are interoperable with Annex A (RFC 3551 section 4.5.6).
//! It also decodes the core layer of G.729.1 streams ([`g7291`]): two G.729
//! frames at the start of each 20 ms frame, decoded to 8 kHz; the higher
//! G.729.1 layers are not decoded. Annex D and Annex E are not supported. It
//! is bit-exact with the ITU-T reference decoder on the 16 ITU-T decoder test
//! vectors.
//!
//! # Frames and samples
//!
//! - Audio is 8000 Hz, 16-bit, mono. Each 10 ms frame decodes to
//!   [`FRAME_SAMPLES`] (80) samples.
//! - A speech frame is 10 octets ([`Frame::Voice`]), packed as RFC 3551
//!   section 4.5.6 Figure 4 describes. A SID (comfort-noise) frame is
//!   2 octets ([`Frame::Sid`]).
//! - An RTP payload is zero or more speech frames, optionally followed by one
//!   SID frame: 10n or 10n + 2 octets. [`Decoder::decode_rtp`] decodes one,
//!   and refuses any other length with [`Error::PayloadLength`].
//! - [`bitstream`] also reads the ITU-T G.192 serial files of the test
//!   vectors.
//!
//! # Lost and untransmitted frames
//!
//! The decoder produces 80 samples for every frame it is given, including a
//! frame it did not receive:
//!
//! - [`Frame::Erased`] stands for a lost or corrupted frame. After a speech
//!   frame, the decoder conceals it from the frames before it (G.729 clause
//!   4.4). After a SID or untransmitted frame, it treats it as untransmitted
//!   (Annex B clause B.4.5).
//! - [`Frame::NoTx`] stands for a frame the sender did not send (Annex B
//!   discontinuous transmission). The decoder continues the comfort noise.
//!
//! Without the `annex-b` feature, SID and untransmitted frames are concealed
//! as lost frames.
//!
//! # Getting the tables
//!
//! The decoder needs one table file, which you build once from the ITU-T
//! G.729 software package and load at run time:
//!
//! 1. Download the ITU-T G.729 (06/2012) software package, Release 3, from
//!    <https://www.itu.int/rec/T-REC-G.729-201206-I/en> (a zip of
//!    18,476,968 bytes).
//! 2. Build the table file with `import_from_itu`, from the zip or from a
//!    directory extracted from it; or with this repository's
//!    `import_tables` example; or, for sipnab users, with
//!    `sipnab g729 install`, which downloads the package from itu.int, or
//!    takes `--from <zip>` offline.
//! 3. Load it with `Tables::from_bytes` and give the [`Tables`] to
//!    [`Decoder::new`].
//!
//! ```no_run
//! let table_file = g729::import_from_itu(std::path::Path::new(
//!     "T-REC-G.729-201206-I!!SOFT-ZST-E.zip",
//! ))?;
//! std::fs::write("g729-tables.bin", &table_file)?;
//!
//! let tables = g729::Tables::from_bytes(&std::fs::read("g729-tables.bin")?)?;
//! let mut decoder = g729::Decoder::new(&tables);
//! let mut pcm = Vec::new();
//! decoder.decode_rtp(&[0u8; 20], &mut pcm)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! `Tables::from_bytes` checks the file's layout and the sha256 of its
//! values against [`tables::VALUES_SHA256`], and refuses any other file with
//! a `TableError`:
//!
//! - `TableError::Magic`: the file is not a table file.
//! - `TableError::Version`: a table file of another layout version,
//!   written for another release of this crate. Build it again.
//! - `TableError::Length`: the file is truncated, or has bytes appended.
//! - `TableError::EntryCount`: the header declares another number of
//!   entries than the layout has.
//! - `TableError::EntryNumber`: an entry header carries another entry's
//!   number.
//! - `TableError::Entry`: an entry header declares another value count.
//! - `TableError::ValuesHash`: the layout is right, but the values are not
//!   the pinned ones: the file was changed, or built from another package.
//!
//! `import_from_itu` refuses with an `ImportError`: `ImportError::Io`
//! and `ImportError::Zip` when the path cannot be read;
//! `ImportError::MissingSource` when a needed source file is not in the
//! package (a modified or incomplete copy, or a release whose source files
//! differ; one whose files match imports to the same table file); and
//! `ImportError::ValuesHash` when the values read do not have the pinned
//! sha256. `ImportError::Shape` and `ImportError::UnknownEntry` are not
//! expected from a package whose files match the pinned hashes.
//!
//! `Tables::from_bytes`, `import_from_itu` and their error types need the
//! `std` feature. The decoder itself is `no_std`, has no `unsafe` code, and
//! does not allocate.
//!
//! # Why the tables are not in this crate
//!
//! The trained codebook values of G.729 are published in the reference C code
//! of the ITU-T G.729 software package, and that code's notice keeps its
//! authors' rights. So this crate reads them from your own copy of
//! the package instead of shipping them. Everything in this crate is MIT OR
//! Apache-2.0. This crate's code generates the tables that the
//! Recommendation defines by a formula ([`tables::formula`]). See
//! [PROVENANCE.md](https://github.com/NormB/sipnab/blob/main/crates/g729/PROVENANCE.md)
//! for the verbatim notices, the holders, the package hash and the
//! clean-room record.
#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::missing_errors_doc, clippy::missing_panics_doc)]

#[cfg(feature = "std")]
extern crate std;

/// The README's example compiles as a doctest, so the crate page shows code
/// that builds against this API.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

pub mod basic_op;
pub mod tables;

#[cfg(feature = "std")]
pub mod import;
#[cfg(feature = "std")]
mod table_file;

#[cfg(feature = "std")]
pub use import::{ImportError, import_from_itu};
#[cfg(feature = "std")]
pub use table_file::{FILE_LEN, TableError};
pub use tables::Tables;

pub mod adaptive;
pub mod bitstream;
#[cfg(feature = "annex-b")]
pub mod cng;
pub mod fixed;
pub mod g7291;
pub mod gain;
pub mod lpc;
pub mod lsp;
pub mod plc;
pub mod post_process;
pub mod postfilter;
pub mod synth;

use basic_op::Ctx;
use plc::Decision;

/// Samples per 10 ms frame at 8 kHz.
pub const FRAME_SAMPLES: usize = 80;

/// One frame as received.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Frame<'a> {
    /// An active frame: 10 octets, RFC 3551 Figure 4 packing.
    Voice(&'a [u8; 10]),
    /// An Annex B comfort-noise (SID) frame: 2 octets.
    Sid(&'a [u8; 2]),
    /// An untransmitted frame (Annex B discontinuous transmission).
    NoTx,
    /// A lost or corrupted frame.
    Erased,
}

/// Why [`Decoder::decode_rtp`] refused an RTP payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The payload is neither 10n nor 10n + 2 octets (RFC 3551 section 4.5.6).
    PayloadLength(usize),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::PayloadLength(n) => {
                write!(f, "G.729 payload of {n} octets is neither 10n nor 10n+2")
            }
        }
    }
}

/// A standard error, so `?` converts it into `Box<dyn Error>` and the like.
impl core::error::Error for Error {}

const U_BUFFER_LEN: usize = adaptive::PAST + FRAME_SAMPLES;

/// A G.729 Annex A decoder with Annex B comfort noise.
///
/// All state is fixed-size; decoding allocates nothing.
#[derive(Clone)]
pub struct Decoder<'t> {
    /// The user-supplied tables.
    pub(crate) tables: &'t Tables,
    /// Basic-operator context (overflow indicator).
    pub(crate) ops: Ctx,
    /// LSF quantizer memory (clause 3.2.4).
    pub(crate) lsf_quantizer: lsp::LsfQuantizerMemory,
    /// q_i(previous) of equation (24).
    pub(crate) q_previous: [i16; 10],
    /// Integer delay carried for parity errors and erasures (clause 4.4).
    pub(crate) delay_tracker: adaptive::PitchState,
    /// Generator of equation (96) for erased frames.
    pub(crate) erasure_seed: i16,
    /// Gain predictor memory (clause 3.9.1).
    pub(crate) gain_predictor: gain::GainState,
    /// beta of equation (47), Q14.
    pub(crate) beta: i16,
    /// u(n): past excitation (`adaptive::PAST` samples), then this frame.
    pub(crate) u_buffer: [i16; U_BUFFER_LEN],
    /// The last 10 samples of the reconstructed speech s^(n).
    pub(crate) s_hat_tail: [i16; 10],
    /// Postfilter state (clause A.4.2).
    pub(crate) postfilter: postfilter::AdaptivePostfilter,
    /// Output high-pass state (equation (91)).
    pub(crate) output_highpass: post_process::HighPass,
    /// Whether the previous frame was decoded as active.
    pub(crate) last_frame_active: bool,
    /// Comfort-noise state (Annex B).
    #[cfg(feature = "annex-b")]
    pub(crate) comfort_noise: cng::CngState,
}

impl core::fmt::Debug for Decoder<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Decoder")
            .field("last_frame_active", &self.last_frame_active)
            .finish_non_exhaustive()
    }
}

impl<'t> Decoder<'t> {
    /// A decoder in its initial state (clause 4.3), using `tables`.
    ///
    /// Use one decoder per stream: it carries state from frame to frame.
    ///
    /// # Panics
    ///
    /// Does not panic.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// let tables = g729::Tables::from_bytes(&std::fs::read("g729-tables.bin")?)?;
    /// let decoder = g729::Decoder::new(&tables);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn new(tables: &'t Tables) -> Self {
        Decoder {
            tables,
            ops: Ctx::default(),
            lsf_quantizer: lsp::LsfQuantizerMemory::new(tables),
            q_previous: tables.decoder_initial_previous_lsp(),
            delay_tracker: adaptive::PitchState::new(tables),
            erasure_seed: fixed::ERASURE_SEED,
            gain_predictor: gain::GainState::new(),
            beta: tables::text::PITCH_SHARPENING_MIN,
            u_buffer: [0; U_BUFFER_LEN],
            s_hat_tail: [0; 10],
            postfilter: postfilter::AdaptivePostfilter::new(),
            output_highpass: post_process::HighPass::new(),
            last_frame_active: true,
            #[cfg(feature = "annex-b")]
            comfort_noise: cng::CngState::new(tables),
        }
    }

    /// Decode one frame into 80 samples.
    ///
    /// Decode a frame for every 10 ms of the stream, in order: a received
    /// frame as [`Frame::Voice`] or [`Frame::Sid`], a lost one as
    /// [`Frame::Erased`], and one the sender did not send as
    /// [`Frame::NoTx`].
    ///
    /// # Panics
    ///
    /// Does not panic, for any frame content.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use g729::{Decoder, FRAME_SAMPLES, Frame, Tables};
    ///
    /// let tables = Tables::from_bytes(&std::fs::read("g729-tables.bin")?)?;
    /// let mut decoder = Decoder::new(&tables);
    /// let mut samples = [0i16; FRAME_SAMPLES];
    /// decoder.decode(Frame::Voice(&[0x5a; 10]), &mut samples);
    /// // The next frame was lost.
    /// decoder.decode(Frame::Erased, &mut samples);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn decode(&mut self, frame: Frame<'_>, out: &mut [i16; FRAME_SAMPLES]) {
        match plc::decide(frame, self.last_frame_active) {
            Decision::Voice(fields) => self.decode_voice_frame(fields, out),
            #[cfg(feature = "annex-b")]
            Decision::ComfortNoise { sid, erased } => {
                self.decode_comfort_noise_frame(sid, erased, out)
            }
            #[cfg(not(feature = "annex-b"))]
            Decision::ComfortNoise { .. } => self.decode_voice_frame(None, out),
        }
    }

    /// Decode an RTP payload (RFC 3551 section 4.5.6): 10n octets of frames,
    /// optionally followed by a 2-octet SID frame. Appends 80 samples per
    /// frame to `out` and returns the number of samples appended.
    ///
    /// A payload may hold any number of frames. The payload length bounds
    /// the output: 80 samples per 10 octets, plus 80 for a SID frame. A UDP
    /// payload is at most 65,507 octets, so one call appends at most 524,080
    /// samples (a 65,502-octet payload: 6,550 frames and a SID frame).
    ///
    /// # Errors
    ///
    /// [`Error::PayloadLength`] when the payload is neither 10n nor 10n + 2
    /// octets. Nothing is decoded and nothing is appended to `out`.
    ///
    /// # Panics
    ///
    /// Does not panic.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use g729::{Decoder, Error, FRAME_SAMPLES, Tables};
    ///
    /// let tables = Tables::from_bytes(&std::fs::read("g729-tables.bin")?)?;
    /// let mut decoder = Decoder::new(&tables);
    /// let mut pcm: Vec<i16> = Vec::new();
    /// // Two speech frames and a SID frame.
    /// assert_eq!(decoder.decode_rtp(&[0x5a; 22], &mut pcm)?, 3 * FRAME_SAMPLES);
    /// assert_eq!(decoder.decode_rtp(&[0; 15], &mut pcm), Err(Error::PayloadLength(15)));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn decode_rtp(
        &mut self,
        payload: &[u8],
        out: &mut impl Extend<i16>,
    ) -> Result<usize, Error> {
        let (voice, comfort) =
            bitstream::split_rtp(payload).map_err(|length| Error::PayloadLength(length.0))?;
        let frames = voice
            .iter()
            .map(Frame::Voice)
            .chain(comfort.map(Frame::Sid));
        let mut samples = [0i16; FRAME_SAMPLES];
        let mut appended = 0;
        for frame in frames {
            self.decode(frame, &mut samples);
            out.extend(samples);
            appended += FRAME_SAMPLES;
        }
        Ok(appended)
    }

    /// Clauses 4.1 and 4.4: decode (or conceal) an active frame.
    fn decode_voice_frame(
        &mut self,
        fields: Option<bitstream::SpeechParams>,
        out: &mut [i16; FRAME_SAMPLES],
    ) {
        let tables = self.tables;
        let omega_hat = self
            .lsf_quantizer
            .decode_frame(&mut self.ops, tables, fields.map(|f| f.l));
        let q_current = lsp::lsf_to_lsp(&mut self.ops, tables, &omega_hat);
        let q_first = lsp::interpolate(&mut self.ops, &self.q_previous, &q_current);
        let a_hat = [
            lpc::lsp_to_lp(&mut self.ops, &q_first),
            lpc::lsp_to_lp(&mut self.ops, &q_current),
        ];
        self.q_previous = q_current;
        let mut t1_integer = 0;
        for (subframe, a_subframe) in a_hat.iter().enumerate() {
            let start = adaptive::PAST + 40 * subframe;
            let (t_integer, t_fraction) = match (fields, subframe) {
                (None, _) => self.delay_tracker.erased(),
                (Some(f), 0) => {
                    let t1 = self
                        .delay_tracker
                        .first(f.p1, adaptive::parity_ok(f.p1, f.p0));
                    t1_integer = t1.0;
                    t1
                }
                (Some(f), _) => self.delay_tracker.second(f.p2, t1_integer),
            };
            adaptive::adaptive_vector(
                &mut self.ops,
                tables,
                &mut self.u_buffer,
                start,
                t_integer,
                t_fraction,
            );
            let (c_index, s_index) = match fields {
                None => fixed::random_index(&mut self.erasure_seed),
                Some(f) => (f.c[subframe], f.s[subframe]),
            };
            let (m_positions, pulse_signs) = fixed::pulses(c_index, s_index);
            let mut c_vector = fixed::codevector(tables, &m_positions, &pulse_signs);
            fixed::sharpen(&mut self.ops, &mut c_vector, t_integer, self.beta);
            let g = match fields {
                None => self.gain_predictor.conceal(&mut self.ops, tables),
                Some(f) => self.gain_predictor.decode(
                    &mut self.ops,
                    tables,
                    f.ga[subframe],
                    f.gb[subframe],
                    &c_vector,
                ),
            };
            self.beta = gain::sharpening(tables, g.gp);
            let mut v_vector = [0i16; 40];
            v_vector.copy_from_slice(&self.u_buffer[start..start + 40]);
            let u_vector = synth::excitation(&mut self.ops, &v_vector, &c_vector, g.gp, g.gc);
            self.u_buffer[start..start + 40].copy_from_slice(&u_vector);
            let samples = self.finish_subframe(a_subframe, start, Some(t_integer));
            out[40 * subframe..40 * subframe + 40].copy_from_slice(&samples);
        }
        #[cfg(feature = "annex-b")]
        cng::after_active_frame(self, fields.is_none(), &omega_hat);
        self.u_buffer.copy_within(FRAME_SAMPLES.., 0);
        self.last_frame_active = true;
    }

    /// Clauses 4.1.6 and 4.2: reconstruct, postfilter and high-pass the
    /// subframe starting at `start` of u(n). `t_integer` is the subframe's
    /// integer pitch delay, `None` in a comfort-noise frame (no long-term
    /// postfilter).
    pub(crate) fn finish_subframe(
        &mut self,
        a_subframe: &[i16; 11],
        start: usize,
        t_integer: Option<i16>,
    ) -> [i16; 40] {
        let tables = self.tables;
        let s_hat = self.reconstruct(a_subframe, start);
        let delay = t_integer.unwrap_or(0);
        let input = postfilter::PostfilterInput {
            a_hat: a_subframe,
            s_hat: &s_hat,
            pitch_delay: delay,
            long_term: t_integer.is_some(),
        };
        let sf = self.postfilter.run(&mut self.ops, tables, &input);
        self.output_highpass.process(&mut self.ops, &sf)
    }

    /// Clause 4.1.6: synthesize the subframe starting at `start` of u(n); on
    /// saturation, divide the whole excitation memory by 4 and synthesize
    /// again (clause 5 arithmetic).
    pub(crate) fn reconstruct(&mut self, a_subframe: &[i16; 11], start: usize) -> [i16; 40] {
        let mut u_vector = [0i16; 40];
        u_vector.copy_from_slice(&self.u_buffer[start..start + 40]);
        let (mut s_hat, saturated) =
            synth::synthesize(&mut self.ops, a_subframe, &u_vector, &self.s_hat_tail);
        if saturated {
            self.u_buffer.iter_mut().for_each(|sample| *sample >>= 2);
            u_vector.copy_from_slice(&self.u_buffer[start..start + 40]);
            s_hat = synth::synthesize(&mut self.ops, a_subframe, &u_vector, &self.s_hat_tail).0;
        }
        self.s_hat_tail.copy_from_slice(&s_hat[30..]);
        s_hat
    }
}
