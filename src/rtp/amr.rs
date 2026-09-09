// SPDX-License-Identifier: MIT OR Apache-2.0

//! The AMR and AMR-WB RTP payload header (RFC 4867), read for the frame mode
//! and nothing else.
//!
//! # Why this exists, and where it stops
//!
//! [`crate::rtp::emodel_wb`] can score an AMR-WB stream on the wideband
//! E-model, and has been able to since it was written. It needs one input the
//! codec name does not carry: the **mode**. The nine AMR-WB modes span
//! `Ie,WB` 1 to 41 — about 4.49 down to 3.51 MOS — so "AMR-WB" alone leaves a
//! full MOS point of ambiguity, and a stream scored without the mode is
//! scored by a placeholder.
//!
//! An SDP `a=fmtp` `mode-set` pins the mode only when it names exactly one,
//! which real VoLTE signaling rarely does: the point of AMR is that the sender
//! switches mode per frame under congestion. **What the sender actually did is
//! in the payload**, one frame type per frame, and reading it needs no decoder
//! and no license — which is the whole reason this module can exist in a tree
//! that ships no AMR decoder. See `docs/design/deferred-and-declined.md` §7
//! for that decision.
//!
//! This module reads the frame type. It does not decode speech, does not
//! reassemble frames, and does not attempt AMR-WB+.
//!
//! # The two packings
//!
//! RFC 4867 defines two, and they put the frame type in different places:
//!
//! - **Bandwidth-efficient** (§4.4.1, the DEFAULT): `CMR` 4 bits, `F` 1 bit,
//!   `FT` 4 bits, `Q` 1 bit, then bit-packed speech. The frame type straddles
//!   a byte boundary.
//! - **Octet-aligned** (§4.4.2, signaled by `octet-align=1`): a `CMR` octet,
//!   then one table-of-contents octet per frame carrying `F`, `FT`, `Q` and
//!   two padding bits.
//!
//! Reading a bandwidth-efficient packet as octet-aligned yields a frame type
//! taken from the wrong bits, which is a plausible mode rather than an error —
//! so the packing is an explicit argument with no default, and the caller has
//! to have read the SDP to supply it.
//!
//! # Interleaving is refused rather than guessed
//!
//! With `interleaving` signaled, an `ILL`/`ILP` field sits between the CMR
//! and the first table-of-contents entry, so every offset below is wrong.
//! [`amr_interleaved`] detects it from the same `a=fmtp` line and the readers
//! return `None`, because a frame type read at the wrong offset is
//! indistinguishable from a real one.

/// The eight AMR narrowband modes, in kbit/s, indexed by RFC 4867 frame type.
///
/// The ordering is normative. G.113 publishes no `Ie` for any of them — see
/// [`crate::rtp::emodel_wb`], which declines to borrow GSM-EFR's — so these
/// pin a bitrate for reporting, not an impairment.
pub const AMR_NB_MODES_KBPS: [f64; 8] = [4.75, 5.15, 5.90, 6.70, 7.40, 7.95, 10.2, 12.2];

/// How the frames in an AMR payload are packed.
///
/// No `Default`, deliberately. RFC 4867 §8.1 makes bandwidth-efficient the
/// default *packing*, but a default *here* would let a caller that never read
/// the SDP get an answer anyway, and the wrong packing produces a wrong mode
/// rather than an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Packing {
    /// RFC 4867 §4.4.1 — the frame type straddles the first two octets.
    BandwidthEfficient,
    /// RFC 4867 §4.4.2 — a CMR octet, then one octet per frame.
    OctetAligned,
}

/// Whether an SDP `a=fmtp` parameter string selects octet-aligned packing.
///
/// RFC 4867 §8.1: `octet-align=1` selects it and anything else, including an
/// absent parameter, leaves the bandwidth-efficient default in force.
#[must_use]
pub fn amr_octet_aligned(fmtp: &str) -> bool {
    fmtp_flag(fmtp, "octet-align")
}

/// Whether an SDP `a=fmtp` parameter string switches interleaving on.
///
/// RFC 4867 §8.1 spells this `interleaving=<n>`, where any value present means
/// the ILL/ILP field is in the payload. A caller that sees this must not read
/// a frame type: every offset moves.
#[must_use]
pub fn amr_interleaved(fmtp: &str) -> bool {
    fmtp.split(';').map(str::trim).any(|p| {
        p.strip_prefix("interleaving=")
            .is_some_and(|v| !v.is_empty())
    })
}

/// The frame type of the FIRST frame in an AMR or AMR-WB payload.
///
/// The first frame, not a survey of all of them: a packet may carry several,
/// and this is the value a per-packet observation records. A caller that wants
/// the distribution accumulates these.
///
/// `None` when the payload is too short to hold a table-of-contents entry.
/// The frame type is returned raw — 0 to 15 — because what is a speech mode,
/// a comfort-noise descriptor or a reserved value differs between narrowband
/// and wideband, and this function does not know which it is looking at.
#[must_use]
pub fn amr_frame_type(payload: &[u8], packing: Packing) -> Option<u8> {
    let (a, b) = (*payload.first()?, *payload.get(1)?);
    Some(match packing {
        // CMR octet, then F(1) FT(4) Q(1) P(2).
        Packing::OctetAligned => (b >> 3) & 0x0F,
        // CMR(4) F(1) FT(4) Q(1): three frame-type bits close the first octet
        // and the fourth opens the second.
        Packing::BandwidthEfficient => ((a & 0x07) << 1) | (b >> 7),
    })
}

/// The AMR-WB mode in kbit/s that a payload's first frame was coded at.
///
/// `None` for anything that is not one of the nine speech modes. TS 26.201
/// assigns frame type 9 to the comfort-noise descriptor, 14 to a lost speech
/// frame and 15 to no data, with 10 to 13 reserved; none of them names a
/// bitrate the E-model can score, and returning the slowest mode for a silence
/// descriptor would report a scored impairment for a frame carrying no speech.
#[must_use]
pub fn amr_wb_kbps_from_payload(payload: &[u8], packing: Packing) -> Option<f64> {
    let ft = amr_frame_type(payload, packing)?;
    crate::rtp::emodel_wb::AMR_WB_MODES_KBPS
        .get(usize::from(ft))
        .copied()
}

/// The AMR narrowband mode in kbit/s that a payload's first frame was coded at.
///
/// `None` for anything that is not one of the eight speech modes: RFC 4867
/// §3.3.1 assigns frame type 8 to the AMR comfort-noise descriptor, 9 to 11 to
/// the GSM-EFR, TDMA-EFR and PDC-EFR descriptors, 12 to 14 to future use and
/// 15 to no data.
#[must_use]
pub fn amr_nb_kbps_from_payload(payload: &[u8], packing: Packing) -> Option<f64> {
    let ft = amr_frame_type(payload, packing)?;
    AMR_NB_MODES_KBPS.get(usize::from(ft)).copied()
}

/// Which AMR family a codec name belongs to, or `None` for anything else.
///
/// Matched case-insensitively, because SDP `a=rtpmap` casing is not
/// normalized and several stacks send `amr-wb`.
///
/// **`AMR-WB+` is deliberately not matched.** It is a different payload format
/// (RFC 4352) with a different header, so reading one as AMR-WB would take a
/// frame type out of bits that mean something else — a plausible mode rather
/// than an error, which is the failure mode this module is built to avoid.
#[must_use]
pub fn amr_flavor(codec: Option<&str>) -> Option<AmrFlavor> {
    let codec = codec?;
    if codec.eq_ignore_ascii_case("AMR") {
        Some(AmrFlavor::NarrowBand)
    } else if codec.eq_ignore_ascii_case("AMR-WB") {
        Some(AmrFlavor::WideBand)
    } else {
        None
    }
}

/// The AMR family a stream's codec name names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmrFlavor {
    /// AMR narrowband, RFC 4867 frame types 0-7.
    NarrowBand,
    /// AMR-WB (= G.722.2), TS 26.201 frame types 0-8.
    WideBand,
}

impl AmrFlavor {
    /// Whether `ft` is one of this family's SPEECH modes.
    ///
    /// Everything else — the comfort-noise descriptors, the reserved values,
    /// a lost frame, no data — names no bitrate, and recording one as a mode
    /// would report a scored impairment for a frame carrying no speech.
    #[must_use]
    pub const fn is_speech_frame_type(self, ft: u8) -> bool {
        match self {
            Self::NarrowBand => ft <= 7,
            Self::WideBand => ft <= 8,
        }
    }

    /// The bitrate of one of this family's speech modes.
    #[must_use]
    pub fn mode_kbps(self, ft: u8) -> Option<f64> {
        let table: &[f64] = match self {
            Self::NarrowBand => &AMR_NB_MODES_KBPS,
            Self::WideBand => &crate::rtp::emodel_wb::AMR_WB_MODES_KBPS,
        };
        table.get(usize::from(ft)).copied()
    }
}

/// The packing an SDP media description selects for `payload_type`.
///
/// `None` means "do not read this stream's payload headers", and it has two
/// causes worth keeping apart in the reader's mind even though the answer is
/// the same: interleaving is on, so every offset has moved; or the codec is
/// not one this module reads.
///
/// An absent `a=fmtp` for the payload type is NOT one of those causes. RFC
/// 4867 §8.1 makes bandwidth-efficient the default packing, so silence in the
/// SDP is an answer — the caller has a media description in hand and the
/// negotiation settled on the default.
#[must_use]
pub fn packing_for(fmtp: &[String], payload_type: u8) -> Option<Packing> {
    let params = fmtp.iter().find_map(|line| {
        let (pt, rest) = line.split_once(char::is_whitespace)?;
        (pt.trim().parse::<u8>().ok()? == payload_type).then(|| rest.trim())
    });
    let Some(params) = params else {
        return Some(Packing::BandwidthEfficient);
    };
    if amr_interleaved(params) {
        return None;
    }
    Some(if amr_octet_aligned(params) {
        Packing::OctetAligned
    } else {
        Packing::BandwidthEfficient
    })
}

/// One `name=1` flag out of an `a=fmtp` parameter string.
fn fmtp_flag(fmtp: &str, name: &str) -> bool {
    fmtp.split(';')
        .map(str::trim)
        .any(|p| p.strip_prefix(name).is_some_and(|v| v.trim() == "=1"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtp::emodel_wb::AMR_WB_MODES_KBPS;

    /// Build an octet-aligned payload from RFC 4867 §4.4.2's layout rather
    /// than from this module's arithmetic: a CMR octet, then one
    /// `F(1) FT(4) Q(1) P(2)` octet per frame.
    ///
    /// `F` is set on every entry but the last, which is what a multi-frame
    /// packet looks like on the wire. Two mutations survived while these
    /// helpers always cleared it — a mask one bit too wide swallows `F`, and
    /// with `F` always zero the wrong mask and the right one agree.
    fn octet_aligned_frames(cmr: u8, frames: &[(u8, bool)]) -> Vec<u8> {
        let mut out = vec![cmr << 4];
        for (i, (ft, q)) in frames.iter().enumerate() {
            let more = i + 1 < frames.len();
            out.push((u8::from(more) << 7) | ((ft & 0x0F) << 3) | (u8::from(*q) << 2));
        }
        out.extend_from_slice(&[0x00; 8]);
        out
    }

    /// One frame, octet-aligned.
    fn octet_aligned(cmr: u8, ft: u8, q: bool) -> Vec<u8> {
        octet_aligned_frames(cmr, &[(ft, q)])
    }

    /// The same frames in RFC 4867 §4.4.1's bit-packed layout: `CMR(4)` then
    /// `F(1) FT(4) Q(1)` per frame, so a frame type straddles octet
    /// boundaries and the second entry is not octet-aligned at all.
    fn bandwidth_efficient_frames(cmr: u8, frames: &[(u8, bool)]) -> Vec<u8> {
        let mut bits: Vec<bool> = Vec::new();
        let mut push = |value: u8, width: u8| {
            for i in (0..width).rev() {
                bits.push((value >> i) & 1 == 1);
            }
        };
        push(cmr & 0x0F, 4);
        for (i, (ft, q)) in frames.iter().enumerate() {
            push(u8::from(i + 1 < frames.len()), 1);
            push(ft & 0x0F, 4);
            push(u8::from(*q), 1);
        }
        let mut out = vec![0u8; bits.len().div_ceil(8) + 8];
        for (i, bit) in bits.iter().enumerate() {
            if *bit {
                out[i / 8] |= 1 << (7 - (i % 8));
            }
        }
        out
    }

    /// One frame, bandwidth-efficient.
    fn bandwidth_efficient(cmr: u8, ft: u8, q: bool) -> Vec<u8> {
        bandwidth_efficient_frames(cmr, &[(ft, q)])
    }

    /// A packet carrying more than one frame sets `F` on every entry but the
    /// last, and the FIRST frame's type must still come back.
    ///
    /// This is the case the other tests could not reach. `F` sits immediately
    /// above the frame type in both packings, so any mask that is one bit too
    /// wide reads `F` as part of the mode — and with a single-frame fixture,
    /// where `F` is always zero, the wrong mask and the right one give the
    /// same answer for every frame type.
    #[test]
    fn a_multi_frame_packet_still_names_its_first_frame() {
        for first in 0u8..=8 {
            let frames = [(first, true), (3, false), (5, true)];
            assert_eq!(
                amr_frame_type(&octet_aligned_frames(15, &frames), Packing::OctetAligned),
                Some(first),
                "octet-aligned, three frames, first is {first}"
            );
            assert_eq!(
                amr_frame_type(
                    &bandwidth_efficient_frames(15, &frames),
                    Packing::BandwidthEfficient
                ),
                Some(first),
                "bandwidth-efficient, three frames, first is {first}"
            );
            assert_eq!(
                amr_wb_kbps_from_payload(&octet_aligned_frames(15, &frames), Packing::OctetAligned),
                crate::rtp::emodel_wb::AMR_WB_MODES_KBPS
                    .get(usize::from(first))
                    .copied(),
                "the mode of a multi-frame packet's first frame"
            );
        }
    }

    /// Every AMR-WB speech mode, in the normative order, out of both packings.
    ///
    /// The ordering is the load-bearing part: `mode-set=2` means 12.65 kbit/s,
    /// not the third-fastest mode, and a table sorted by bitrate would score
    /// every stream against the wrong impairment while still returning a
    /// published figure.
    #[test]
    fn every_wideband_speech_mode_decodes_in_order() {
        for (ft, want) in AMR_WB_MODES_KBPS.iter().enumerate() {
            let ft = u8::try_from(ft).expect("nine modes");
            for p in [
                (octet_aligned(15, ft, true), Packing::OctetAligned),
                (
                    bandwidth_efficient(15, ft, true),
                    Packing::BandwidthEfficient,
                ),
            ] {
                assert_eq!(
                    amr_wb_kbps_from_payload(&p.0, p.1),
                    Some(*want),
                    "frame type {ft} under {:?}",
                    p.1
                );
            }
        }
    }

    /// Every AMR narrowband speech mode, in the normative order, out of both
    /// packings.
    #[test]
    fn every_narrowband_speech_mode_decodes_in_order() {
        for (ft, want) in AMR_NB_MODES_KBPS.iter().enumerate() {
            let ft = u8::try_from(ft).expect("eight modes");
            for p in [
                (octet_aligned(15, ft, true), Packing::OctetAligned),
                (
                    bandwidth_efficient(15, ft, true),
                    Packing::BandwidthEfficient,
                ),
            ] {
                assert_eq!(
                    amr_nb_kbps_from_payload(&p.0, p.1),
                    Some(*want),
                    "frame type {ft} under {:?}",
                    p.1
                );
            }
        }
    }

    /// A comfort-noise descriptor is not the slowest speech mode.
    ///
    /// AMR-WB frame type 9 is SID. Reading it as a mode index one past the end
    /// of the table is the failure this asserts against — and the narrowband
    /// table is one shorter, so its SID at 8 would land on the wideband table's
    /// 23.85 if the two were ever confused.
    #[test]
    fn silence_descriptors_carry_no_mode() {
        for packing in [Packing::OctetAligned, Packing::BandwidthEfficient] {
            let wb_sid = match packing {
                Packing::OctetAligned => octet_aligned(15, 9, true),
                Packing::BandwidthEfficient => bandwidth_efficient(15, 9, true),
            };
            assert_eq!(amr_wb_kbps_from_payload(&wb_sid, packing), None);
            let nb_sid = match packing {
                Packing::OctetAligned => octet_aligned(15, 8, true),
                Packing::BandwidthEfficient => bandwidth_efficient(15, 8, true),
            };
            assert_eq!(amr_nb_kbps_from_payload(&nb_sid, packing), None);
        }
    }

    /// Reserved, lost and no-data frame types carry no mode either.
    #[test]
    fn reserved_and_no_data_frame_types_carry_no_mode() {
        for ft in [10u8, 11, 12, 13, 14, 15] {
            for packing in [Packing::OctetAligned, Packing::BandwidthEfficient] {
                let pkt = match packing {
                    Packing::OctetAligned => octet_aligned(15, ft, true),
                    Packing::BandwidthEfficient => bandwidth_efficient(15, ft, true),
                };
                assert_eq!(
                    amr_wb_kbps_from_payload(&pkt, packing),
                    None,
                    "wideband frame type {ft}"
                );
                assert_eq!(
                    amr_nb_kbps_from_payload(&pkt, packing),
                    None,
                    "narrowband frame type {ft}"
                );
            }
        }
    }

    /// The change request bits belong to the RECEIVER's wishes and must not
    /// reach the frame type.
    ///
    /// A CMR of 15 ("no request") sits in the same octet as the frame type in
    /// both packings, and in the bandwidth-efficient one it is adjacent to it.
    /// A mask off by one bit reads 15 as a mode.
    #[test]
    fn the_change_request_does_not_leak_into_the_frame_type() {
        // Every frame type against every change request, not frame type 0
        // alone: a reader that always answered 0 would satisfy the zero case
        // for all sixteen requests and prove nothing about the mask.
        for cmr in 0u8..=15 {
            for ft in 0u8..=15 {
                assert_eq!(
                    amr_frame_type(&octet_aligned(cmr, ft, false), Packing::OctetAligned),
                    Some(ft),
                    "octet-aligned, CMR {cmr}, frame type {ft}"
                );
                assert_eq!(
                    amr_frame_type(
                        &bandwidth_efficient(cmr, ft, false),
                        Packing::BandwidthEfficient
                    ),
                    Some(ft),
                    "bandwidth-efficient, CMR {cmr}, frame type {ft}"
                );
            }
        }
    }

    /// The frame quality bit does not move the frame type either.
    #[test]
    fn the_quality_bit_does_not_move_the_frame_type() {
        for q in [true, false] {
            assert_eq!(
                amr_frame_type(&octet_aligned(15, 5, q), Packing::OctetAligned),
                Some(5)
            );
            assert_eq!(
                amr_frame_type(&bandwidth_efficient(15, 5, q), Packing::BandwidthEfficient),
                Some(5)
            );
        }
    }

    /// Reading one packing as the other yields a DIFFERENT frame type, which
    /// is why `Packing` has no default.
    ///
    /// This is the argument for the explicit argument, made as a measurement
    /// rather than as a warning in a doc comment.
    #[test]
    fn the_two_packings_disagree_when_confused() {
        let pkt = bandwidth_efficient(15, 2, true);
        assert_eq!(
            amr_frame_type(&pkt, Packing::BandwidthEfficient),
            Some(2),
            "read correctly"
        );
        assert_ne!(
            amr_frame_type(&pkt, Packing::OctetAligned),
            Some(2),
            "a bandwidth-efficient packet read as octet-aligned must not \
             happen to give the right answer, or this test proves nothing"
        );
    }

    /// A payload too short to hold a table-of-contents entry has no frame
    /// type, and neither reader invents one.
    #[test]
    fn a_truncated_payload_has_no_frame_type() {
        for packing in [Packing::OctetAligned, Packing::BandwidthEfficient] {
            for short in [vec![], vec![0xF0]] {
                assert_eq!(amr_frame_type(&short, packing), None);
                assert_eq!(amr_wb_kbps_from_payload(&short, packing), None);
                assert_eq!(amr_nb_kbps_from_payload(&short, packing), None);
            }
        }
    }

    /// `octet-align=1` and nothing else selects octet-aligned packing.
    #[test]
    fn octet_align_is_read_from_the_fmtp() {
        assert!(amr_octet_aligned("octet-align=1"));
        assert!(amr_octet_aligned(
            "mode-set=2; octet-align=1; mode-change-period=2"
        ));
        assert!(amr_octet_aligned(" octet-align=1 "));
        // The default is bandwidth-efficient, and these must all leave it.
        assert!(!amr_octet_aligned("octet-align=0"));
        assert!(!amr_octet_aligned("mode-set=0,2,4"));
        assert!(!amr_octet_aligned(""));
        // A parameter that merely ENDS in the name is a different parameter.
        assert!(!amr_octet_aligned("no-octet-align=1"));
    }

    /// Interleaving is detected so the readers can be kept away from a payload
    /// whose offsets have moved.
    #[test]
    fn interleaving_is_detected_from_the_fmtp() {
        assert!(amr_interleaved("interleaving=5"));
        assert!(amr_interleaved("octet-align=1; interleaving=2"));
        assert!(!amr_interleaved("interleaving="));
        assert!(!amr_interleaved("octet-align=1"));
        assert!(!amr_interleaved(""));
    }
}
