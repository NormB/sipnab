// SPDX-License-Identifier: MIT OR Apache-2.0

//! Wideband E-model (ITU-T G.107.1) and the published AMR-WB impairment
//! factors.
//!
//! [`crate::rtp::quality::estimate_mos`] implements the *narrowband* E-model
//! (ITU-T G.107): `Ro = 93.2`, and the Annex B polynomial applied to `R`
//! directly. That model cannot score a wideband codec. Feeding it a wideband
//! `Ie,WB` is not an approximation but a scale error worth 35.8 R-points,
//! because the two models anchor at different points — 93.2 against 129.
//!
//! So AMR-WB is scored here instead, on its own scale, and the scale is
//! reported with the number. A `MOS_CQEW` of 4.42 and a `MOS_CQE` of 4.35 are
//! not comparable and must not be averaged, plotted on one axis, or compared
//! against one threshold.
//!
//! # What is published, and what is not
//!
//! | Codec | Published impairment | Scale |
//! |---|---|---|
//! | AMR-WB (= G.722.2) | Yes — nine modes, two listening contexts | Wideband, G.107.1 |
//! | AMR narrowband | **No value exists** | — |
//! | EVS | SWB mode only | Fullband, G.107.2 |
//!
//! AMR-NB is genuinely absent from G.113: Table I.1 has no row for it, and a
//! whole-document search for "AMR" returns only G.722.2 references. GSM-EFR at
//! 12.2 kbit/s (`Ie = 5`) and TIA IS-641 at 7.4 kbit/s (`Ie = 10`) are
//! algorithmically close relatives at coincident bitrates, and borrowing their
//! values is the exact substitution this module exists to refuse.
//!
//! EVS is published only as `Ie,fb` on the G.107.2 fullband scale, for SWB
//! mode, under diotic presentation. There is no EVS `Ie,WB` and no EVS
//! narrowband `Ie`. G.113's bridge `Ie,fb ≈ Σ Ie,wb + 19` is stated in one
//! direction only; running it backwards to manufacture a wideband EVS value is
//! prohibited interpolation.
//!
//! # Provenance
//!
//! - ITU-T G.113 (09/2024) Appendix IV, Tables IV.1, IV.3, IV.4.
//! - ITU-T G.107.1 (06/2019) as amended by **Corrigendum 1 (01/2020)**.
//!   Cor.1 is a complete-text publication; the 06/2019 text alone carries a
//!   superseded Eq (7-6).
//!
//! G.113's appendices each state *"This appendix does not form an integral
//! part of this Recommendation"* and label their contents *"provisional
//! planning values … intended to be updated regularly"*. These are planning
//! figures for network design, not measurements of a particular call, and
//! operator-facing text should say so. Only G.107.1 Annex A is normative.

/// Listening context, which G.113 tabulates separately and which changes the
/// answer materially.
///
/// This is an explicit input with no default on purpose. At 6.6 kbit/s the two
/// tables differ by 15 R-points — about 0.59 MOS — so silently assuming one
/// would be a larger error than most of the impairments being modeled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListeningContext {
    /// Handset or monaural headset — G.113 Table IV.1.
    Monotic,
    /// Stereo headset or speakerphone — G.113 Table IV.3.
    Diotic,
}

/// The nine AMR-WB modes, in kbit/s, indexed by RFC 4867 mode number.
///
/// The ordering is normative: `mode-set=2` in an SDP `a=fmtp` line means
/// 12.65 kbit/s, not the third-fastest mode.
pub const AMR_WB_MODES_KBPS: [f64; 9] =
    [6.6, 8.85, 12.65, 14.25, 15.85, 18.25, 19.85, 23.05, 23.85];

/// Equipment impairment factor `Ie,WB` for an AMR-WB mode, or `None` where
/// G.113 publishes no value for that mode in that context.
///
/// Note that `Ie,WB` is **not monotonic in bitrate**: 23.85 kbit/s scores 8
/// while the slower 23.05 kbit/s scores 1. That inversion recurs across Tables
/// IV.1, IV.3 and IV.4, so it is published intent rather than a transcription
/// slip. Do not "correct" it, and do not rank modes by impairment.
///
/// Three modes — 19.85, 18.25 and 14.25 — have no diotic value at all.
/// Interpolating them from their neighbors is not defensible when the series
/// they sit in is not even monotonic.
#[must_use]
pub fn amr_wb_ie(kbps: f64, context: ListeningContext) -> Option<f64> {
    // Compared by nearest-tenth key rather than by f64 equality: these arrive
    // from SDP text and RTP payload decoding, and 12.65 does not round-trip.
    let key = (kbps * 100.0).round() as i64;
    let ie = match (context, key) {
        // G.113 (09/2024) Table IV.1 — monotic. All nine modes.
        (ListeningContext::Monotic, 2385) => 8.0,
        (ListeningContext::Monotic, 2305) => 1.0,
        (ListeningContext::Monotic, 1985) => 3.0,
        (ListeningContext::Monotic, 1825) => 5.0,
        (ListeningContext::Monotic, 1585) => 7.0,
        (ListeningContext::Monotic, 1425) => 10.0,
        (ListeningContext::Monotic, 1265) => 13.0,
        (ListeningContext::Monotic, 885) => 26.0,
        (ListeningContext::Monotic, 660) => 41.0,
        // G.113 (09/2024) Table IV.3 — diotic. Six modes; 19.85, 18.25 and
        // 14.25 are absent from the published table.
        (ListeningContext::Diotic, 2385) => 10.0,
        (ListeningContext::Diotic, 2305) => 8.0,
        (ListeningContext::Diotic, 1585) => 17.0,
        (ListeningContext::Diotic, 1265) => 20.0,
        (ListeningContext::Diotic, 885) => 41.0,
        (ListeningContext::Diotic, 660) => 56.0,
        _ => return None,
    };
    Some(ie)
}

/// Packet-loss robustness factor `Bpl,wb` for an AMR-WB mode.
///
/// G.113 Table IV.4 publishes this for **three modes, diotic only, uniform
/// loss only**, and states verbatim that no values are available for
/// non-uniform loss or for the monotic presentation. Six of the nine modes
/// have none.
///
/// The consequence is sharp and worth stating plainly: **AMR-WB under packet
/// loss with a handset is not computable** from published data. That is a
/// finding to report, not a gap to fill with the diotic figure — pairing a
/// Table IV.1 monotic `Ie,WB` with a Table IV.4 diotic `Bpl,wb` silently mixes
/// two listening contexts inside one equation.
#[must_use]
pub fn amr_wb_bpl(kbps: f64, context: ListeningContext) -> Option<f64> {
    if context != ListeningContext::Diotic {
        return None;
    }
    let key = (kbps * 100.0).round() as i64;
    let bpl = match key {
        2385 => 4.9,
        2305 => 4.6,
        1265 => 4.3,
        _ => return None,
    };
    Some(bpl)
}

/// Effective impairment under random packet loss — G.107.1 Eq (7-15).
///
/// The constant is **95**, inherited unrescaled from narrowband G.107
/// Eq (7-29). It is emphatically not 129: the scale anchor and this constant
/// are independent, and substituting one for the other is a plausible-looking
/// error that survives casual review.
#[must_use]
pub fn ie_eff_wb(ie_wb: f64, loss_pct: f64, bpl: f64) -> f64 {
    if loss_pct <= 0.0 {
        return ie_wb;
    }
    ie_wb + (95.0 - ie_wb) * loss_pct / (loss_pct + bpl)
}

/// Wideband R-factor from an effective impairment — G.107.1 Eq (7-1).
///
/// `Is,WB` is 0 by Eq (7-3) and `A` is 0 by Eq (7-16), both of which G.107.1
/// gives as the wideband defaults — the simultaneous-impairment and advantage
/// terms have not been analyzed for the wideband case. `Id,WB` is 0 here
/// because the delay, talker-echo and listener-echo terms of Eq (7-4) need
/// RLR, TELR, WEPL and absolute delay, none of which are recoverable from a
/// passive capture. A capture measures the codec and the loss; it does not
/// measure the handset's echo path.
#[must_use]
pub fn r_wb(ie_eff_wb: f64) -> f64 {
    129.0 - ie_eff_wb
}

/// Wideband R to `MOS_CQEW` — G.107.1 Annex A, Eq (A-1) and (A-2).
///
/// The `R / 1.29` rescale in Eq (A-1) is what makes the narrowband-shaped
/// polynomial applicable. Without it the result clips at 4.5 across the whole
/// usable range; with it applied to a *narrowband* R, every score is too low.
///
/// G.107.1 writes the bracketing cases with strict inequalities, leaving
/// `Rx == 0` and `Rx == 100` formally uncovered. The polynomial is continuous
/// at both — it evaluates to exactly 1 and exactly 4.5 — so the inclusive
/// comparisons used here agree with the Recommendation everywhere it speaks.
#[must_use]
pub fn r_wb_to_mos(r: f64) -> f64 {
    let rx = r / 1.29;
    if rx <= 0.0 {
        return 1.0;
    }
    if rx >= 100.0 {
        return 4.5;
    }
    1.0 + 0.035 * rx + rx * (rx - 60.0) * (100.0 - rx) * 7.0e-6
}

/// `MOS_CQEW` for an AMR-WB stream whose mode is known.
///
/// Returns `None` when G.113 publishes nothing for that mode and context, or
/// when loss is present but no `Bpl,wb` exists for the mode — the two cases
/// where an answer could only be invented.
///
/// The mode must be known. It is not recoverable from the codec name: the nine
/// modes span `Ie,WB` 1 to 41, which is 4.49 down to 3.51 MOS, so "AMR-WB"
/// alone leaves a full MOS point of ambiguity. Pin it from the SDP `a=fmtp`
/// `mode-set` where that names a single mode, or from the RTP payload header.
#[must_use]
pub fn amr_wb_mos(kbps: f64, context: ListeningContext, loss_pct: f64) -> Option<f64> {
    let ie = amr_wb_ie(kbps, context)?;
    let ie_eff = if loss_pct > 0.0 {
        ie_eff_wb(ie, loss_pct, amr_wb_bpl(kbps, context)?)
    } else {
        ie
    };
    Some(r_wb_to_mos(r_wb(ie_eff)))
}

/// The single AMR-WB mode an SDP `a=fmtp` line pins, if it pins exactly one.
///
/// RFC 4867 §8.1 defines `mode-set` as a comma-separated list of permitted
/// mode numbers, indexing [`AMR_WB_MODES_KBPS`]. A single-entry list fixes the
/// bitrate for the session and makes the stream scorable.
///
/// Everything else returns `None`, including a multi-mode set and an absent
/// `mode-set` (which per RFC 4867 permits *all* modes). A sender may switch
/// mode per frame in response to congestion, so a permitted range says what
/// the stream might do, not what it did.
#[must_use]
pub fn amr_wb_kbps_from_fmtp(fmtp: &str) -> Option<f64> {
    let modes = fmtp
        .split(';')
        .map(str::trim)
        .find_map(|p| p.strip_prefix("mode-set="))?;
    let mut it = modes.split(',').map(str::trim).filter(|s| !s.is_empty());
    let only = it.next()?;
    if it.next().is_some() {
        return None;
    }
    let idx: usize = only.parse().ok()?;
    AMR_WB_MODES_KBPS.get(idx).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Within half a thousandth of a MOS point.
    fn close(a: f64, b: f64) -> bool {
        (a - b).abs() < 5e-4
    }

    /// Test vectors computed from G.107.1 Eq (7-1), (7-15), (A-1) and (A-2).
    ///
    /// These pin the whole chain, not just the table lookup: a wrong scale
    /// anchor, a missing `R / 1.29`, or 129 substituted for 95 in Eq (7-15)
    /// each move these numbers.
    #[test]
    fn published_vectors_reproduce() {
        // An unimpaired wideband channel sits at the top of the scale.
        assert!(close(r_wb_to_mos(r_wb(0.0)), 4.5));
        // Ie,WB = 1 (23.05 monotic) -> R = 128 -> Rx = 99.2248
        assert!(close(r_wb_to_mos(r_wb(1.0)), 4.4940));
        // Ie,WB = 8 (23.85 monotic) -> R = 121 -> Rx = 93.7984
        assert!(close(r_wb_to_mos(r_wb(8.0)), 4.4206));
        // Ie,WB = 13 (12.65 monotic) -> R = 116 -> Rx = 89.9225
        assert!(close(r_wb_to_mos(r_wb(13.0)), 4.3371));
        // Ie,WB = 41 (6.6 monotic) -> R = 88 -> Rx = 68.2171
        assert!(close(r_wb_to_mos(r_wb(41.0)), 3.5123));
        // Ie,WB = 56 (6.6 diotic) -> R = 73 -> Rx = 56.5891
        assert!(close(r_wb_to_mos(r_wb(56.0)), 2.9220));
    }

    /// 12.65 diotic under 2% loss, the one mode with a published Bpl,wb that
    /// is also common in the field.
    #[test]
    fn packet_loss_vector_reproduces() {
        let ie_eff = ie_eff_wb(20.0, 2.0, 4.3);
        assert!(
            (ie_eff - 43.8095).abs() < 1e-3,
            "Eq (7-15) with the 95 constant; got {ie_eff}"
        );
        let mos = amr_wb_mos(12.65, ListeningContext::Diotic, 2.0).expect("published");
        assert!(close(mos, 3.4062), "got {mos}");
    }

    /// The spread across modes is the whole reason a single placeholder was
    /// wrong. If this collapses, the table has stopped being consulted.
    #[test]
    fn modes_span_roughly_a_full_mos_point() {
        let best = amr_wb_mos(23.05, ListeningContext::Monotic, 0.0).expect("published");
        let worst = amr_wb_mos(6.6, ListeningContext::Monotic, 0.0).expect("published");
        assert!(
            best - worst > 0.9,
            "AMR-WB modes must span about a full MOS point; got {best} to {worst}"
        );
    }

    /// Listening context changes the answer, so it cannot have a silent default.
    #[test]
    fn listening_context_changes_the_score() {
        let mono = amr_wb_mos(6.6, ListeningContext::Monotic, 0.0).expect("published");
        let dio = amr_wb_mos(6.6, ListeningContext::Diotic, 0.0).expect("published");
        assert!(
            mono - dio > 0.5,
            "Tables IV.1 and IV.3 differ by 15 R-points at 6.6 kbit/s; got \
             {mono} vs {dio}"
        );
    }

    /// The published inversion is preserved rather than smoothed.
    #[test]
    fn the_published_bitrate_inversion_is_not_corrected() {
        let fast = amr_wb_ie(23.85, ListeningContext::Monotic).expect("published");
        let slower = amr_wb_ie(23.05, ListeningContext::Monotic).expect("published");
        assert!(
            fast > slower,
            "G.113 publishes 23.85 -> 8 and 23.05 -> 1; a monotonic table means \
             someone 'fixed' it"
        );
    }

    /// Unpublished combinations must refuse, not interpolate.
    #[test]
    fn unpublished_combinations_return_none() {
        // Three modes have no diotic value.
        for kbps in [19.85, 18.25, 14.25] {
            assert!(
                amr_wb_ie(kbps, ListeningContext::Diotic).is_none(),
                "{kbps} kbit/s has no diotic value in Table IV.3"
            );
            assert!(amr_wb_ie(kbps, ListeningContext::Monotic).is_some());
        }
        // Monotic + loss is not computable: no monotic Bpl,wb is published.
        assert!(
            amr_wb_mos(12.65, ListeningContext::Monotic, 1.0).is_none(),
            "no monotic Bpl,wb exists; borrowing the diotic one mixes contexts"
        );
        // Without loss the same mode scores fine.
        assert!(amr_wb_mos(12.65, ListeningContext::Monotic, 0.0).is_some());
        // Six of nine modes have no Bpl,wb even diotically.
        assert!(amr_wb_mos(15.85, ListeningContext::Diotic, 1.0).is_none());
        // Not an AMR-WB mode at all.
        assert!(amr_wb_ie(13.0, ListeningContext::Monotic).is_none());
    }

    /// RFC 4867 mode numbers index the bitrate list; a range pins nothing.
    #[test]
    fn mode_set_pins_a_bitrate_only_when_unambiguous() {
        assert_eq!(amr_wb_kbps_from_fmtp("mode-set=2"), Some(12.65));
        assert_eq!(
            amr_wb_kbps_from_fmtp("octet-align=1; mode-set=8"),
            Some(23.85)
        );
        assert_eq!(amr_wb_kbps_from_fmtp("mode-set=0"), Some(6.6));
        // A permitted range says what the stream may do, not what it did.
        assert_eq!(amr_wb_kbps_from_fmtp("mode-set=0,2,4,7"), None);
        // Absent mode-set permits every mode.
        assert_eq!(amr_wb_kbps_from_fmtp("octet-align=1"), None);
        // Out of range.
        assert_eq!(amr_wb_kbps_from_fmtp("mode-set=9"), None);
        assert_eq!(amr_wb_kbps_from_fmtp("mode-set=x"), None);
    }

    /// The wideband and narrowband scales must stay distinguishable. If a
    /// wideband Ie is ever fed to the narrowband model this catches it.
    #[test]
    fn the_wideband_scale_is_not_the_narrowband_scale() {
        let wb = r_wb_to_mos(r_wb(0.0));
        let nb = crate::rtp::quality::estimate_mos(0.0, 0.0, Some("PCMU"));
        assert!(
            wb > nb,
            "an unimpaired wideband channel must outscore an unimpaired G.711 \
             one; got {wb} vs {nb}. Equal values mean one scale is being used \
             for both"
        );
    }
}
