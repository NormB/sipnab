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

use crate::rtp::quality::sanitized_loss_pct;

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

/// The listening context every wideband score in this process is read in.
///
/// **A process-wide declaration, for the reason the codec impairment table is
/// one**: `score_amr_wb` is reached by the REST API, the MCP surface, the CLI
/// report and the TUI, and none of them is threaded a config. A context
/// honored on some of those would be two surfaces publishing different MOS for
/// one stream.
static LISTENING_CONTEXT: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

/// Declare the listening context for this process.
///
/// Called once during bootstrap from `[media] listening_context`.
pub fn set_listening_context(context: ListeningContext) {
    LISTENING_CONTEXT.store(
        match context {
            ListeningContext::Monotic => 0,
            ListeningContext::Diotic => 1,
        },
        std::sync::atomic::Ordering::Relaxed,
    );
}

/// The declared listening context, defaulting to monotic.
///
/// **A default, where this module's own tables take an explicit argument, and
/// the difference is deliberate.** `amr_wb_ie` refuses to assume because at
/// 6.6 kbit/s the two tables differ by 15 R-points and a silent assumption
/// would be a larger error than most of the impairments being modeled. What
/// makes a default acceptable HERE is that it is not silent: every score
/// carries the context it was read in, on every surface, so a reader who
/// disagrees can see what to change.
///
/// Monotic, because a capture of mobile voice is a capture of handsets. An
/// operator whose estate is speakerphones or stereo headsets says so in
/// `[media] listening_context`.
#[must_use]
pub fn declared_listening_context() -> ListeningContext {
    if LISTENING_CONTEXT.load(std::sync::atomic::Ordering::Relaxed) == 1 {
        ListeningContext::Diotic
    } else {
        ListeningContext::Monotic
    }
}

impl ListeningContext {
    /// The wire spelling every surface serializes this as.
    ///
    /// One vocabulary in one place, the rule `MosGrounding::as_str` follows.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Monotic => "monotic",
            Self::Diotic => "diotic",
        }
    }

    /// Parse the spelling a config file uses. `None` for anything else, so a
    /// typo is refused rather than silently read as the default.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "monotic" => Some(Self::Monotic),
            "diotic" => Some(Self::Diotic),
            _ => None,
        }
    }
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
///
/// `loss_pct` passes through `sanitized_loss_pct` first — named rather than
/// linked, because it is crate-private and a link from a public item to one
/// resolves to nothing in the published docs — for the same admissible range
/// the narrowband equation uses. A bare `loss_pct <= 0.0` test is not
/// enough on its own: NaN compares false against everything, so it slips past
/// the guard and leaves as a NaN `Ie,eff,WB`, a NaN R and a NaN MOS on a REST
/// field. Bounding it also keeps `loss_pct + bpl` away from the pole at
/// `Ppl = -Bpl`, which `every_publishable_bpl_is_positive` closes from the
/// other side.
#[must_use]
pub fn ie_eff_wb(ie_wb: f64, loss_pct: f64, bpl: f64) -> f64 {
    let loss = sanitized_loss_pct(loss_pct);
    if loss <= 0.0 {
        return ie_wb;
    }
    ie_wb + (95.0 - ie_wb) * loss / (loss + bpl)
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
    // Sanitized HERE and not only inside `ie_eff_wb`, because this is where
    // "is there loss to score" is decided. Asking the raw figure would return
    // `None` for an unpublished mode on the strength of a NaN or an infinity
    // — reporting "not computable under loss" for a stream that, once the
    // figure is bounded, has no loss to compute.
    let loss = sanitized_loss_pct(loss_pct);
    let ie_eff = if loss > 0.0 {
        ie_eff_wb(ie, loss, amr_wb_bpl(kbps, context)?)
    } else {
        ie
    };
    Some(r_wb_to_mos(r_wb(ie_eff)))
}

/// Why a wideband score is not available for a stream.
///
/// A REASON rather than an absent value, because the two cases are opposite
/// confidences and a caller has to be able to say which it has. "G.113
/// publishes nothing for this mode in this context" is a gap in the tables;
/// "the mode is published but this stream lost packets and no `Bpl,wb` exists
/// for it" is a stream sipnab genuinely cannot score, and reporting either as
/// a missing field would leave an operator guessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WidebandUnavailable {
    /// G.113 publishes no `Ie,WB` for this mode in this listening context.
    /// Three of the nine modes have no diotic value at all.
    UnpublishedMode,
    /// The mode is published and the stream lost packets, and G.113 Table IV.4
    /// publishes `Bpl,wb` for three modes, diotic only, uniform loss only.
    /// **AMR-WB under loss on a handset is not computable** from published
    /// data. That is a finding, not a gap to fill with the diotic figure.
    LossNotComputable,
}

impl WidebandUnavailable {
    /// The wire spelling every surface publishes.
    ///
    /// One vocabulary, so REST, MCP, the TUI and the vCon export cannot name
    /// the same refusal three ways. It used to live inside `StreamSummary::of`,
    /// where only that surface could reach it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnpublishedMode => "unpublished_mode",
            Self::LossNotComputable => "loss_not_computable",
        }
    }

    /// A short phrase for a terminal, where a wire token would read as noise.
    #[must_use]
    pub fn note(self) -> &'static str {
        match self {
            Self::UnpublishedMode => "no published Ie,WB for this mode",
            Self::LossNotComputable => "not computable under loss",
        }
    }
}

/// A wideband score, with everything a reader needs to know it is not a
/// narrowband one.
///
/// The scale travels with the number on purpose. `MOS_CQEW` anchors at 129 and
/// `MOS_CQE` at 93.2, so a figure here and one from
/// [`crate::rtp::quality::estimate_mos`] are not comparable, must not be
/// averaged, and must not meet one threshold.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct WidebandScore {
    /// `MOS_CQEW` on the G.107.1 scale.
    pub mos: f64,
    /// The wideband R-factor it was converted from.
    pub r_factor: f64,
    /// The equipment impairment G.113 publishes for this mode and context.
    pub ie_wb: f64,
    /// Which listening context the tables were read in.
    pub context: ListeningContext,
    /// The mode, in kbit/s, the payload headers reported.
    pub mode_kbps: f64,
}

/// What a wideband score amounts to for one stream.
///
/// Three outcomes, not two, and the third is why this is not an `Option`. A
/// G.711 call and an AMR-WB call whose mode nobody publishes both end up with
/// no wideband MOS, and only the second is a finding about the stream. Reported
/// as one absent field they are indistinguishable, and a reader is left
/// guessing which they have.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WidebandVerdict {
    /// Not an AMR-WB stream, or one whose mode was never pinned. Nobody
    /// attempted a wideband score, so there is nothing to report either way.
    NotAttempted,
    /// Scored, on the G.107.1 wideband scale.
    Scored(WidebandScore),
    /// Attempted and refused, with the reason and the inputs it was refused
    /// for.
    ///
    /// The mode and context travel with the refusal because every surface
    /// wants to say them: "no published Ie,WB" is not actionable, and "AMR-WB
    /// 23.85 kbit/s monotic has no published Ie,WB" tells an operator which
    /// table to look in and what to change. Carrying them here also stops each
    /// surface re-deriving the mode it already asked about.
    Unavailable {
        /// Which of the two refusals this is.
        reason: WidebandUnavailable,
        /// The mode, in kbit/s, that was refused.
        mode_kbps: f64,
        /// The listening context the tables were read in.
        context: ListeningContext,
    },
}

/// The wideband verdict for one stream, from what the stream knows.
///
/// **One rule, one place.** REST, MCP, the TUI and the vCon export all need
/// this answer, and they reach it through different types; deciding it in each
/// would be four copies of "is this AMR-WB, and did we pin a mode", which is
/// exactly the shape that drifts. The arguments are the two facts that decide
/// it plus the two the score needs, so nothing here depends on `RtpStream` and
/// every branch is drivable from a test.
///
/// The codec name alone is never enough: the nine AMR-WB modes span a full MOS
/// point, so `mode_kbps` comes from the payload headers or from a single-entry
/// `mode-set`, and its absence means not attempted rather than a default.
#[must_use]
pub fn verdict_for_stream(
    codec: Option<&str>,
    mode_kbps: Option<f64>,
    loss_pct: f64,
    context: ListeningContext,
) -> WidebandVerdict {
    if !matches!(
        crate::rtp::amr::amr_flavor(codec),
        Some(crate::rtp::amr::AmrFlavor::WideBand)
    ) {
        return WidebandVerdict::NotAttempted;
    }
    let Some(kbps) = mode_kbps else {
        return WidebandVerdict::NotAttempted;
    };
    match score_amr_wb(kbps, context, loss_pct) {
        Ok(score) => WidebandVerdict::Scored(score),
        Err(reason) => WidebandVerdict::Unavailable {
            reason,
            mode_kbps: kbps,
            context,
        },
    }
}

/// Score an AMR-WB stream on the wideband scale.
///
/// The mode comes from the RTP payload header ([`crate::rtp::amr`]), because
/// the codec name does not carry it and the nine modes span a full MOS point.
pub fn score_amr_wb(
    mode_kbps: f64,
    context: ListeningContext,
    loss_pct: f64,
) -> Result<WidebandScore, WidebandUnavailable> {
    let ie_wb = amr_wb_ie(mode_kbps, context).ok_or(WidebandUnavailable::UnpublishedMode)?;
    // Sanitized before the "is there loss" decision, for the reason
    // `amr_wb_mos` states: asking the raw figure would refuse a stream on the
    // strength of a NaN, reporting "not computable under loss" for a stream
    // that has no loss to compute once the value is bounded.
    let loss = sanitized_loss_pct(loss_pct);
    let ie_eff = if loss > 0.0 {
        let bpl = amr_wb_bpl(mode_kbps, context).ok_or(WidebandUnavailable::LossNotComputable)?;
        ie_eff_wb(ie_wb, loss, bpl)
    } else {
        ie_wb
    };
    let r_factor = r_wb(ie_eff);
    Ok(WidebandScore {
        mos: r_wb_to_mos(r_factor),
        r_factor,
        ie_wb,
        context,
        mode_kbps,
    })
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
mod verdict_tests {
    use super::*;

    /// A G.711 stream is not a stream that failed to score wideband.
    ///
    /// The distinction is the whole reason this returns three outcomes rather
    /// than an `Option`. "Nobody attempted it" and "it was attempted and there
    /// is no published value" look identical as an absent field, and only one
    /// of them is a finding about the stream.
    #[test]
    fn a_narrowband_codec_is_not_attempted() {
        assert!(matches!(
            verdict_for_stream(Some("PCMU"), None, 0.0, ListeningContext::Monotic),
            WidebandVerdict::NotAttempted
        ));
    }

    /// AMR-WB with no mode pinned is also not attempted.
    ///
    /// The nine modes span a full MOS point, so a score without one would be a
    /// number chosen rather than read. The mode comes from the payload header
    /// or from a single-entry `mode-set`; absent both, there is nothing to
    /// score and nothing to report as unavailable.
    #[test]
    fn amr_wb_without_a_mode_is_not_attempted() {
        assert!(matches!(
            verdict_for_stream(Some("AMR-WB"), None, 0.0, ListeningContext::Monotic),
            WidebandVerdict::NotAttempted
        ));
    }

    /// A published mode with no loss scores, and says which scale it is on.
    #[test]
    fn a_published_mode_scores() {
        let WidebandVerdict::Scored(score) =
            verdict_for_stream(Some("AMR-WB"), Some(12.65), 0.0, ListeningContext::Monotic)
        else {
            panic!("12.65 kbit/s monotic is published");
        };
        assert_eq!(score.mode_kbps, 12.65);
        assert_eq!(score.context, ListeningContext::Monotic);
        assert!(
            (3.0..=4.5).contains(&score.mos),
            "MOS_CQEW out of range: {}",
            score.mos
        );
    }

    /// A mode with no published value in this context is refused BY NAME.
    ///
    /// 19.85 kbit/s is one of the three modes Table IV.3 omits. Written first
    /// against 6.6 kbit/s, which Table IV.3 does publish (56.0) --- the test
    /// went red for the fixture rather than for the behavior, which is the
    /// reason to read the table instead of remembering it.
    #[test]
    fn an_unpublished_mode_is_refused_with_its_reason() {
        assert!(matches!(
            verdict_for_stream(Some("AMR-WB"), Some(19.85), 0.0, ListeningContext::Diotic),
            WidebandVerdict::Unavailable {
                reason: WidebandUnavailable::UnpublishedMode,
                mode_kbps: 19.85,
                context: ListeningContext::Diotic,
            }
        ));
        // And the same mode IS published monotic, so the refusal is about the
        // context rather than about the mode being unknown.
        assert!(matches!(
            verdict_for_stream(Some("AMR-WB"), Some(19.85), 0.0, ListeningContext::Monotic),
            WidebandVerdict::Scored(_)
        ));
    }

    /// Loss on a mode with no `Bpl,wb` is a finding, not a gap to fill.
    #[test]
    fn loss_without_a_published_bpl_is_refused_with_its_own_reason() {
        assert!(matches!(
            verdict_for_stream(Some("AMR-WB"), Some(12.65), 5.0, ListeningContext::Monotic),
            WidebandVerdict::Unavailable {
                reason: WidebandUnavailable::LossNotComputable,
                ..
            }
        ));
    }

    /// The flavor test reads the codec name, so AMR narrowband is never
    /// attempted on the wideband scale.
    ///
    /// G.113 has no AMR-NB row at all. Scoring it here with a wideband table
    /// would be the substitution this module exists to refuse.
    #[test]
    fn amr_narrowband_is_never_scored_on_the_wideband_scale() {
        assert!(matches!(
            verdict_for_stream(Some("AMR"), Some(12.2), 0.0, ListeningContext::Monotic),
            WidebandVerdict::NotAttempted
        ));
    }
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

    /// The process-wide declaration round-trips, and every score reads it.
    ///
    /// Serialized because it WRITES the declaration: two tests reading it
    /// concurrently see each other's value and the score moves underneath
    /// the assertion. The surface tests in `crate::output::model` learned
    /// that the expensive way.
    #[test]
    #[serial_test::serial(listening_context)]
    fn the_declared_context_round_trips() {
        set_listening_context(ListeningContext::Diotic);
        assert_eq!(declared_listening_context(), ListeningContext::Diotic);
        set_listening_context(ListeningContext::Monotic);
        assert_eq!(declared_listening_context(), ListeningContext::Monotic);
    }

    /// A spelling the config does not define is refused rather than read as
    /// the default.
    ///
    /// The negative half. `parse` returning `Monotic` for a typo would leave
    /// an operator who wrote `diotic ` -- or `binaural` -- with handset
    /// figures and nothing saying so, which is the silent assumption this
    /// module opens by refusing.
    #[test]
    fn an_unrecognized_context_is_refused_rather_than_defaulted() {
        assert_eq!(
            ListeningContext::parse("monotic"),
            Some(ListeningContext::Monotic)
        );
        assert_eq!(
            ListeningContext::parse("  DIOTIC "),
            Some(ListeningContext::Diotic)
        );
        assert_eq!(ListeningContext::parse("binaural"), None);
        assert_eq!(ListeningContext::parse(""), None);
    }
    /// A published mode with no loss scores, and the score carries its scale.
    #[test]
    fn a_published_mode_scores_and_says_what_it_read() {
        let s = score_amr_wb(12.65, ListeningContext::Monotic, 0.0)
            .expect("12.65 monotic is published");
        assert!(close(s.mos, 4.3371), "got {}", s.mos);
        assert!(
            (s.ie_wb - 13.0).abs() < f64::EPSILON,
            "Ie,WB is Table IV.1's"
        );
        assert!(close(s.r_factor, r_wb(13.0)));
        assert_eq!(s.context, ListeningContext::Monotic);
        assert!((s.mode_kbps - 12.65).abs() < f64::EPSILON);
    }

    /// A mode G.113 does not publish in that context is refused BY NAME.
    ///
    /// 19.85 has a monotic value and no diotic one. Interpolating it from its
    /// neighbors is not defensible in a series that is not even monotonic.
    #[test]
    fn a_mode_with_no_published_value_is_refused_by_name() {
        assert!(score_amr_wb(19.85, ListeningContext::Monotic, 0.0).is_ok());
        assert_eq!(
            score_amr_wb(19.85, ListeningContext::Diotic, 0.0),
            Err(WidebandUnavailable::UnpublishedMode)
        );
    }

    /// Under loss, a mode with no published `Bpl,wb` is not computable, and
    /// that is a different answer from an unpublished mode.
    ///
    /// 6.6 monotic has an `Ie,WB` and no `Bpl,wb` -- Table IV.4 is diotic only
    /// -- so it scores clean and refuses under loss. The two errors must not
    /// collapse into one: the first says the tables are silent, the second
    /// says this particular stream cannot be scored.
    #[test]
    fn loss_without_a_published_robustness_factor_is_its_own_answer() {
        assert!(score_amr_wb(6.6, ListeningContext::Monotic, 0.0).is_ok());
        assert_eq!(
            score_amr_wb(6.6, ListeningContext::Monotic, 2.0),
            Err(WidebandUnavailable::LossNotComputable)
        );
        // And the one mode that IS computable under loss still is.
        let s =
            score_amr_wb(12.65, ListeningContext::Diotic, 2.0).expect("Table IV.4 publishes it");
        assert!(close(s.mos, 3.4062), "got {}", s.mos);
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

    /// The wideband loss term has the same pole as the narrowband one, at
    /// `Ppl = -Bpl`, and the same NaN path through it.
    ///
    /// `ie_eff_wb` guards `loss_pct <= 0.0`, which a NaN fails — NaN compares
    /// false against everything — so a NaN loss reaches Eq (7-15) and comes
    /// out the far side as a NaN `Ie,eff,WB`, a NaN R and a NaN MOS. Both
    /// scales in this crate must read a loss figure the same way; one rule,
    /// one admissible range.
    #[test]
    fn a_non_finite_wideband_loss_is_treated_as_no_loss() {
        let ie = 8.0;
        let bpl = 4.9;
        let clean = ie_eff_wb(ie, 0.0, bpl);
        for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let got = ie_eff_wb(ie, bad, bpl);
            assert!(got.is_finite(), "loss {bad} produced Ie,eff,WB = {got}");
            assert!(
                (got - clean).abs() < 1e-9,
                "loss {bad} gave {got}, not the no-loss {clean}"
            );
        }
    }

    /// Loss above total is still total, on the wideband scale too. Past 100%
    /// the input is not a percentage of packets any more, and letting it keep
    /// climbing toward the `Ie = 95` asymptote reports a stream as worse than
    /// one that lost everything.
    #[test]
    fn wideband_loss_beyond_total_scores_as_total_loss() {
        let ie = 8.0;
        let bpl = 4.9;
        let total = ie_eff_wb(ie, 100.0, bpl);
        for over in [100.1, 500.0, 1.0e12] {
            let got = ie_eff_wb(ie, over, bpl);
            assert!(
                (got - total).abs() < 1e-9,
                "loss {over}% gave {got}, not the total-loss {total}"
            );
        }
    }

    /// A non-finite loss must not reach the MOS by the other door either.
    ///
    /// `amr_wb_mos` decides for itself whether loss is present, with a second
    /// `loss_pct > 0.0` test rather than the one inside `ie_eff_wb`. An
    /// infinity passes that test, so the guard has to be in the equation, not
    /// in each caller's opinion of whether to call it.
    #[test]
    fn the_amr_wb_wrapper_inherits_the_loss_guard() {
        // 23.85 kbit/s diotic is one of the three modes G.113 Table IV.4
        // publishes a Bpl,wb for, so the loss branch is reachable here.
        let clean =
            amr_wb_mos(23.85, ListeningContext::Diotic, 0.0).expect("23.85 diotic is published");
        for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1.0, -4.9] {
            let mos = amr_wb_mos(23.85, ListeningContext::Diotic, bad)
                .expect("the mode is published; a bad loss must not change that");
            assert!(mos.is_finite(), "loss {bad} produced MOS = {mos}");
            assert!(
                (mos - clean).abs() < 1e-9,
                "loss {bad} scored {mos}, not the no-loss {clean}"
            );
        }
    }

    /// The wideband pole is at `Ppl = -Bpl`, so it is only unreachable while
    /// every `Bpl,wb` this crate can produce is positive.
    ///
    /// Bounding the loss figure to `0.0..=100.0` closes the pole from one
    /// side; this closes it from the other. G.113 Table IV.4 publishes three
    /// figures and all three are robustness factors, which are positive by
    /// construction — but `amr_wb_bpl` is the only thing standing between the
    /// table and a division, so the property is pinned rather than assumed.
    #[test]
    fn every_publishable_bpl_is_positive() {
        let mut published = 0;
        for kbps in AMR_WB_MODES_KBPS {
            for context in [ListeningContext::Diotic, ListeningContext::Monotic] {
                if let Some(bpl) = amr_wb_bpl(kbps, context) {
                    published += 1;
                    assert!(
                        bpl > 0.0 && bpl.is_finite(),
                        "Bpl,wb for {kbps} kbit/s {context:?} is {bpl}; a \
                         non-positive value puts the pole back inside the \
                         admissible loss range"
                    );
                }
            }
        }
        assert_eq!(
            published, 3,
            "G.113 Table IV.4 publishes Bpl,wb for three modes, diotic only"
        );
    }
}
