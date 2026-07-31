// SPDX-License-Identifier: MIT OR Apache-2.0

//! Advanced RTP quality metrics.
//!
//! Extends sipnab's basic jitter/loss tracking with:
//! - **MOS estimation** via a simplified E-model (ITU-T G.107)
//! - **Burst/gap analysis** based on RFC 3611 concepts
//!
//! These metrics give operators a human-meaningful quality score and
//! distinguish between random packet loss (tolerable) and bursty loss
//! (perceptually severe at the same overall rate).

// Index loops read more clearly than iterators in these numeric E-model and
// burst/gap calculations, where the index itself is part of the arithmetic.
#![allow(clippy::needless_range_loop)]

// ── Public types ─────────────────────────────────────────────────────

/// Burst/gap analysis results following RFC 3611 concepts.
///
/// A "burst" is defined as 3 or more consecutive lost packets. A "gap"
/// is the period of received packets between bursts. Bursty loss patterns
/// are perceptually worse than uniformly distributed loss at the same rate.
#[derive(Debug, Clone, serde::Serialize)]
#[non_exhaustive]
pub struct BurstGapAnalysis {
    /// Number of loss bursts detected.
    pub burst_count: u32,
    /// Average burst duration in milliseconds.
    pub burst_duration_ms: f64,
    /// Average gap duration in milliseconds.
    pub gap_duration_ms: f64,
    /// Packet loss rate during bursts (0.0 to 1.0).
    pub burst_loss_rate: f64,
    /// Packet loss rate during gaps (0.0 to 1.0).
    pub gap_loss_rate: f64,
    /// `true` if loss is bursty (worse perceptually than random loss).
    pub is_bursty: bool,
}

// ── MOS estimation ───────────────────────────────────────────────────

/// Estimate Mean Opinion Score using the simplified E-model (ITU-T G.107).
///
/// Produces a score on the standard 1.0-4.5 MOS scale based on jitter,
/// packet loss, and codec type. Assumes a baseline one-way delay of 100ms
/// (typical for well-provisioned VoIP).
///
/// # Arguments
///
/// * `jitter_ms` — measured interarrival jitter in milliseconds.
/// * `loss_pct` — estimated packet loss percentage (0.0-100.0).
/// * `codec` — optional codec name (e.g., `"PCMU"`, `"G729"`, `"opus"`).
///
/// # Returns
///
/// MOS value clamped to the range \[1.0, 4.5\].
///
/// # Examples
///
/// ```
/// use sipnab::estimate_mos;
///
/// // A clean G.711 call scores near the codec ceiling...
/// let clean = estimate_mos(5.0, 0.0, Some("PCMU"));
/// assert!(clean > 4.0, "got {clean}");
///
/// // ...while heavy jitter and loss on G.729 drags the score down.
/// let degraded = estimate_mos(80.0, 15.0, Some("G729"));
/// assert!(degraded < 3.0, "got {degraded}");
/// assert!((1.0..=4.5).contains(&degraded));
/// ```
pub fn estimate_mos(jitter_ms: f64, loss_pct: f64, codec: Option<&str>) -> f64 {
    // Codec-specific equipment impairment factor (Ie)
    let ie = match codec {
        Some("PCMU") | Some("PCMA") => 0.0,   // G.711 baseline
        Some("G729") | Some("G.729") => 10.0, // G.729 compression impairment
        Some("opus") | Some("Opus") => 0.0,   // Opus comparable to G.711
        // PLACEHOLDER, not a measurement. See `mos_grounding`.
        //
        // ITU-T G.113 Table I.1 publishes Ie for a specific list of codecs and
        // sipnab knows three of them. Everything else — AMR, AMR-WB, EVS,
        // G.722, G.726, iLBC — lands here and scores identically to a stream
        // whose codec was never identified at all: `estimate_mos(10.0, 0.0,
        // Some("AMR-WB"))` and `estimate_mos(10.0, 0.0, None)` both return
        // 4.216.
        //
        // For AMR-WB that is wrong by roughly a full MOS point in either
        // direction, since its nine modes genuinely span about 4.49 down to
        // 3.51. Callers that present this number to a human or an agent must
        // consult `mos_grounding` and say so, rather than letting a guess wear
        // the shape of a measurement.
        _ => 5.0,
    };

    // Effective equipment impairment with packet loss (Ie-eff)
    // From G.107 Appendix I: Ie_eff = Ie + (95 - Ie) * Ppl / (Ppl / BurstR + Bpl)
    // Simplified with BurstR=1, Bpl=10 for random loss
    let ie_eff = ie + (95.0 - ie) * loss_pct / (loss_pct + 10.0);

    // Delay impairment (Id) — assume 100ms baseline + jitter contribution
    let delay_ms = 100.0 + jitter_ms;
    let id = if delay_ms > 177.3 {
        0.024 * delay_ms + 0.11 * (delay_ms - 177.3) * (delay_ms - 177.3).sqrt()
    } else {
        0.024 * delay_ms
    };

    // R-factor: R = R0 - Is - Id - Ie_eff + A
    // R0 = 93.2 (default signal-to-noise), Is = 0 (no simultaneous impairment), A = 0
    let r = 93.2 - id - ie_eff;

    // R-factor to MOS conversion (ITU-T G.107 Annex B)
    r_to_mos(r)
}

/// Convert an R-factor to MOS using the standard formula.
///
/// MOS = 1 + 0.035*R + R*(R-60)*(100-R)*7e-6 for R in [0, 100],
/// clamped to [1.0, 4.5].
fn r_to_mos(r: f64) -> f64 {
    if r < 0.0 {
        1.0
    } else if r > 100.0 {
        4.5
    } else {
        // The cubic dips below 1.0 for small positive R (e.g. R≈4.4 at
        // 100% loss on G.711), so the documented floor must be enforced
        // inside the branch too, not only at its edges.
        (1.0 + 0.035 * r + r * (r - 60.0) * (100.0 - r) * 7e-6).clamp(1.0, 4.5)
    }
}

// ── Burst/gap analysis ───────────────────────────────────────────────

/// Analyze a sequence of packet reception results for burst/gap patterns.
///
/// Takes a slice of booleans where `true` = packet received, `false` = packet
/// lost, and the packet interval in milliseconds (typically 20ms for most
/// audio codecs).
///
/// A burst is defined as 3 or more consecutive lost packets. Everything
/// between bursts is a gap.
///
/// # Arguments
///
/// * `received` — ordered sequence of packet reception outcomes.
/// * `ptime_ms` — packet interval in milliseconds (e.g., 20.0 for G.711).
///
/// # Returns
///
/// A `BurstGapAnalysis` with burst counts, average burst/gap durations in
/// milliseconds (interval count times `ptime_ms`), and per-region loss
/// rates as fractions (0.0 to 1.0). An empty `received` slice yields an
/// all-zero result with `is_bursty == false`. Pure function — no side
/// effects.
pub fn analyze_burst_gap(received: &[bool], ptime_ms: f64) -> BurstGapAnalysis {
    if received.is_empty() {
        return BurstGapAnalysis {
            burst_count: 0,
            burst_duration_ms: 0.0,
            gap_duration_ms: 0.0,
            burst_loss_rate: 0.0,
            gap_loss_rate: 0.0,
            is_bursty: false,
        };
    }

    let mut burst_count: u32 = 0;
    let mut burst_packets: u64 = 0; // Total packets in burst regions
    let mut burst_lost: u64 = 0; // Lost packets in burst regions
    let mut gap_packets: u64 = 0; // Total packets in gap regions
    let mut gap_lost: u64 = 0; // Lost packets in gap regions

    // Track consecutive loss runs
    let mut consecutive_lost: u32 = 0;
    let mut in_burst = false;
    let mut current_burst_len: u32 = 0;
    let mut burst_lengths: Vec<u32> = Vec::new();
    let mut gap_lengths: Vec<u32> = Vec::new();
    let mut current_gap_len: u32 = 0;

    for &pkt_received in received {
        if !pkt_received {
            consecutive_lost += 1;
            // Transition to burst when we hit 3 consecutive losses
            if consecutive_lost >= 3 && !in_burst {
                in_burst = true;
                burst_count += 1;
                // The previous consecutive losses are part of this burst;
                // retroactively move them from gap to burst accounting. Those
                // (consecutive_lost - 1) packets were the immediately
                // preceding losses, so by construction they are all still
                // booked to the current gap in every gap counter at once:
                // current_gap_len >= consecutive_lost > retroactive, and both
                // gap_packets and gap_lost include this run's prior losses.
                //
                // Move them as a single unit under one combined guard so a
                // partial subtraction can never desync the three counters
                // (which would corrupt the gap/burst loss rates). The
                // debug_assert pins the invariant in tests.
                let retroactive = consecutive_lost - 1;
                let r64 = retroactive as u64;
                debug_assert!(
                    current_gap_len >= retroactive && gap_lost >= r64 && gap_packets >= r64,
                    "gap counters desynced before burst reclassification: \
                     len={current_gap_len} lost={gap_lost} packets={gap_packets} r={retroactive}"
                );
                if current_gap_len >= retroactive && gap_lost >= r64 && gap_packets >= r64 {
                    current_gap_len -= retroactive;
                    gap_lost -= r64;
                    gap_packets -= r64;
                }
                // Finalize the preceding gap
                if current_gap_len > 0 {
                    gap_lengths.push(current_gap_len);
                    current_gap_len = 0;
                }
                current_burst_len = retroactive;
                burst_lost += retroactive as u64;
                burst_packets += retroactive as u64;
            }
        } else {
            consecutive_lost = 0;
        }

        if in_burst {
            burst_packets += 1;
            current_burst_len += 1;
            if !pkt_received {
                burst_lost += 1;
            }
            // End burst when we see a received packet (the burst was
            // the consecutive loss run; we include the first received
            // packet after the run to close the burst)
            if pkt_received {
                burst_lengths.push(current_burst_len);
                current_burst_len = 0;
                in_burst = false;
                current_gap_len = 0; // gap starts fresh
            }
        } else {
            gap_packets += 1;
            current_gap_len += 1;
            if !pkt_received {
                gap_lost += 1;
            }
        }
    }

    // Finalize any open burst or gap at end of sequence
    if in_burst && current_burst_len > 0 {
        burst_lengths.push(current_burst_len);
    }
    if !in_burst && current_gap_len > 0 {
        gap_lengths.push(current_gap_len);
    }

    let total_burst_len: u32 = burst_lengths.iter().sum();
    let total_gap_len: u32 = gap_lengths.iter().sum();

    let avg_burst_duration = if burst_lengths.is_empty() {
        0.0
    } else {
        (total_burst_len as f64 / burst_lengths.len() as f64) * ptime_ms
    };

    let avg_gap_duration = if gap_lengths.is_empty() {
        0.0
    } else {
        (total_gap_len as f64 / gap_lengths.len() as f64) * ptime_ms
    };

    let burst_loss_rate = if burst_packets > 0 {
        burst_lost as f64 / burst_packets as f64
    } else {
        0.0
    };

    let gap_loss_rate = if gap_packets > 0 {
        gap_lost as f64 / gap_packets as f64
    } else {
        0.0
    };

    BurstGapAnalysis {
        burst_count,
        burst_duration_ms: avg_burst_duration,
        gap_duration_ms: avg_gap_duration,
        burst_loss_rate,
        gap_loss_rate,
        is_bursty: burst_count > 0,
    }
}

// ── Tests ────────────────────────────────────────────────────────────

/// Unit tests for E-model MOS estimation (codec impairments, clamping,
/// monotonic degradation) and burst/gap loss-pattern analysis.
#[cfg(test)]
mod grounding_tests {
    use super::*;

    /// The cellular codecs sipnab cannot ground must say so.
    ///
    /// This is the whole point: they currently score identically to an
    /// unidentified stream, so without this signal a caller cannot tell a
    /// measurement from a placeholder.
    #[test]
    fn cellular_codecs_are_reported_as_ungrounded() {
        for c in ["AMR", "AMR-WB", "EVS", "G722", "G726", "iLBC"] {
            assert_eq!(
                mos_grounding(Some(c)),
                MosGrounding::Unpublished,
                "{c} has no published ITU-T G.113 Ie in sipnab and must not \
                 claim a grounded MOS"
            );
        }
    }

    /// The three sipnab does know are grounded.
    #[test]
    fn known_codecs_are_reported_as_grounded() {
        for c in ["PCMU", "PCMA", "G729", "opus"] {
            assert_eq!(mos_grounding(Some(c)), MosGrounding::Published, "{c}");
        }
    }

    /// An unidentified stream is ungrounded, matching what the score means.
    #[test]
    fn an_unidentified_codec_is_ungrounded() {
        assert_eq!(mos_grounding(None), MosGrounding::Unpublished);
    }

    /// The grounding signal must agree with the scorer.
    ///
    /// If a codec reported Published while falling to the placeholder arm, the
    /// signal would launder the guess instead of exposing it — worse than
    /// having no signal.
    #[test]
    fn grounding_agrees_with_the_score() {
        let placeholder = estimate_mos(10.0, 0.0, None);
        for c in ["PCMU", "PCMA", "G729", "opus"] {
            assert_ne!(
                estimate_mos(10.0, 0.0, Some(c)),
                placeholder,
                "{c} claims Published grounding, so it must not score the same \
                 as an unidentified stream"
            );
        }
        for c in ["AMR", "AMR-WB", "EVS"] {
            assert_eq!(
                estimate_mos(10.0, 0.0, Some(c)),
                placeholder,
                "{c} is Unpublished, so it does score as the placeholder — if \
                 this changes, the grounding table must change with it"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── MOS estimation tests ─────────────────────────────────────────

    /// MOS stays within [1.0, 4.5] even at extreme loss where the raw
    /// G.107 cubic dips below 1.0.
    #[test]
    fn mos_never_dips_below_documented_floor() {
        // 100% loss on G.711 lands R ≈ 4.4, where the raw G.107 cubic
        // evaluates to ~0.99 — the [1.0, 4.5] contract must hold anyway.
        let mos = estimate_mos(0.0, 100.0, Some("PCMU"));
        assert!(
            (1.0..=4.5).contains(&mos),
            "Expected clamped MOS at total loss, got {mos}"
        );
        // sweep the small-R region for any other dip
        for loss in [80.0, 90.0, 95.0, 99.0, 100.0] {
            for jitter in [0.0, 40.0, 200.0] {
                let m = estimate_mos(jitter, loss, Some("PCMU"));
                assert!(
                    (1.0..=4.5).contains(&m),
                    "loss={loss} jitter={jitter} mos={m}"
                );
            }
        }
    }

    /// Clean G.711 (0% loss, 10 ms jitter) scores above 4.0.
    #[test]
    fn mos_g711_perfect_conditions() {
        // G.711, 0% loss, 10ms jitter — should be excellent
        let mos = estimate_mos(10.0, 0.0, Some("PCMU"));
        assert!(mos > 4.0, "Expected MOS > 4.0 for perfect G.711, got {mos}");
    }

    /// G.711 at 5% loss and 50 ms jitter lands in the noticeably degraded
    /// 2.0-3.5 band.
    #[test]
    fn mos_g711_moderate_degradation() {
        // G.711, 5% loss, 50ms jitter — noticeable degradation
        let mos = estimate_mos(50.0, 5.0, Some("PCMU"));
        assert!(
            (2.0..=3.5).contains(&mos),
            "Expected MOS 2.0-3.5 for degraded G.711, got {mos}"
        );
    }

    /// G.729's inherent equipment impairment (Ie=10) scores below G.711 at
    /// identical network conditions.
    #[test]
    fn mos_g729_lower_than_g711() {
        // G.729 has inherent codec impairment
        let mos_g711 = estimate_mos(10.0, 0.0, Some("PCMU"));
        let mos_g729 = estimate_mos(10.0, 0.0, Some("G729"));
        assert!(
            mos_g729 < mos_g711,
            "Expected G.729 MOS ({mos_g729}) < G.711 MOS ({mos_g711})"
        );
    }

    /// Opus and G.711 share Ie=0, so their MOS matches at equal conditions.
    #[test]
    fn mos_opus_comparable_to_g711() {
        let mos_g711 = estimate_mos(10.0, 0.0, Some("PCMU"));
        let mos_opus = estimate_mos(10.0, 0.0, Some("opus"));
        assert!(
            (mos_g711 - mos_opus).abs() < 0.01,
            "Opus and G.711 should have same MOS at same conditions"
        );
    }

    /// PCMA and PCMU (both G.711) produce identical MOS.
    #[test]
    fn mos_pcma_same_as_pcmu() {
        let mos_pcmu = estimate_mos(20.0, 1.0, Some("PCMU"));
        let mos_pcma = estimate_mos(20.0, 1.0, Some("PCMA"));
        assert!(
            (mos_pcmu - mos_pcma).abs() < 0.01,
            "PCMA and PCMU should have same MOS"
        );
    }

    /// An unknown/absent codec gets the moderate Ie=5 impairment, scoring
    /// below G.711.
    #[test]
    fn mos_unknown_codec_moderate_impairment() {
        let mos_unknown = estimate_mos(10.0, 0.0, None);
        let mos_g711 = estimate_mos(10.0, 0.0, Some("PCMU"));
        assert!(
            mos_unknown < mos_g711,
            "Unknown codec MOS ({mos_unknown}) should be less than G.711 ({mos_g711})"
        );
    }

    /// Extreme conditions (100% loss, 500 ms jitter) never push MOS below
    /// the 1.0 floor.
    #[test]
    fn mos_never_below_one() {
        // Extreme conditions: 100% loss, 500ms jitter
        let mos = estimate_mos(500.0, 100.0, None);
        assert!(mos >= 1.0, "MOS should never go below 1.0, got {mos}");
    }

    /// Perfect conditions never push MOS above the 4.5 ceiling.
    #[test]
    fn mos_never_above_four_five() {
        // Perfect conditions
        let mos = estimate_mos(0.0, 0.0, Some("PCMU"));
        assert!(mos <= 4.5, "MOS should never exceed 4.5, got {mos}");
    }

    /// Raising jitter from 5 ms to 200 ms lowers the score (delay
    /// impairment Id grows).
    #[test]
    fn mos_high_jitter_degrades_quality() {
        let mos_low = estimate_mos(5.0, 0.0, Some("PCMU"));
        let mos_high = estimate_mos(200.0, 0.0, Some("PCMU"));
        assert!(
            mos_high < mos_low,
            "High jitter MOS ({mos_high}) should be less than low jitter ({mos_low})"
        );
    }

    /// Raising loss from 0% to 20% lowers the score (Ie-eff grows).
    #[test]
    fn mos_high_loss_degrades_quality() {
        let mos_low = estimate_mos(10.0, 0.0, Some("PCMU"));
        let mos_high = estimate_mos(10.0, 20.0, Some("PCMU"));
        assert!(
            mos_high < mos_low,
            "High loss MOS ({mos_high}) should be less than low loss ({mos_low})"
        );
    }

    // ── Burst/gap analysis tests ─────────────────────────────────────

    /// Ten consecutive losses in otherwise clean traffic are detected as
    /// at least one burst.
    #[test]
    fn burst_detected_consecutive_loss() {
        // 10 consecutive lost packets in a sequence of 100
        let mut received = vec![true; 100];
        for i in 20..30 {
            received[i] = false;
        }

        let analysis = analyze_burst_gap(&received, 20.0);
        assert!(analysis.is_bursty, "10 consecutive losses should be bursty");
        assert!(
            analysis.burst_count >= 1,
            "Should detect at least 1 burst, got {}",
            analysis.burst_count
        );
    }

    /// Isolated single losses (every 50th packet) never form a burst.
    #[test]
    fn no_burst_random_isolated_loss() {
        // Random loss: every 50th packet lost (never more than 1 consecutive)
        let mut received = vec![true; 200];
        for i in (0..200).step_by(50) {
            received[i] = false;
        }

        let analysis = analyze_burst_gap(&received, 20.0);
        assert!(
            !analysis.is_bursty,
            "Isolated single losses should not be bursty"
        );
        assert_eq!(analysis.burst_count, 0);
    }

    /// Two consecutive losses stay below the 3-loss burst threshold.
    #[test]
    fn no_burst_two_consecutive_loss() {
        // 2 consecutive losses is below the burst threshold (3)
        let mut received = vec![true; 50];
        received[10] = false;
        received[11] = false;

        let analysis = analyze_burst_gap(&received, 20.0);
        assert!(
            !analysis.is_bursty,
            "2 consecutive losses should not be a burst"
        );
        assert_eq!(analysis.burst_count, 0);
    }

    /// Exactly three consecutive losses is the minimum counted as one
    /// burst.
    #[test]
    fn burst_exactly_three_consecutive() {
        // Exactly 3 consecutive losses — minimum burst
        let mut received = vec![true; 50];
        received[10] = false;
        received[11] = false;
        received[12] = false;

        let analysis = analyze_burst_gap(&received, 20.0);
        assert!(analysis.is_bursty, "3 consecutive losses should be a burst");
        assert_eq!(analysis.burst_count, 1);
    }

    /// Two separated loss runs are counted as two distinct bursts.
    #[test]
    fn multiple_bursts_detected() {
        let mut received = vec![true; 100];
        // First burst: packets 10-14 lost
        for i in 10..15 {
            received[i] = false;
        }
        // Second burst: packets 50-55 lost
        for i in 50..56 {
            received[i] = false;
        }

        let analysis = analyze_burst_gap(&received, 20.0);
        assert!(analysis.is_bursty);
        assert_eq!(
            analysis.burst_count, 2,
            "Should detect 2 bursts, got {}",
            analysis.burst_count
        );
    }

    /// An empty reception sequence yields the all-zero, non-bursty result.
    #[test]
    fn empty_sequence() {
        let analysis = analyze_burst_gap(&[], 20.0);
        assert!(!analysis.is_bursty);
        assert_eq!(analysis.burst_count, 0);
        assert_eq!(analysis.burst_duration_ms, 0.0);
        assert_eq!(analysis.gap_duration_ms, 0.0);
    }

    /// A loss-free sequence reports no bursts and zero loss rates.
    #[test]
    fn all_received_no_loss() {
        let received = vec![true; 100];
        let analysis = analyze_burst_gap(&received, 20.0);
        assert!(!analysis.is_bursty);
        assert_eq!(analysis.burst_count, 0);
        assert_eq!(analysis.burst_loss_rate, 0.0);
        assert_eq!(analysis.gap_loss_rate, 0.0);
    }

    /// With one clear burst in clean traffic, the burst-region loss rate
    /// exceeds the gap-region loss rate.
    #[test]
    fn burst_loss_rate_higher_than_gap() {
        // Create a clear burst in otherwise clean traffic
        let mut received = vec![true; 200];
        for i in 50..60 {
            received[i] = false;
        }

        let analysis = analyze_burst_gap(&received, 20.0);
        assert!(analysis.is_bursty);
        assert!(
            analysis.burst_loss_rate > analysis.gap_loss_rate,
            "Burst loss rate ({}) should exceed gap loss rate ({})",
            analysis.burst_loss_rate,
            analysis.gap_loss_rate
        );
    }

    /// A 2-packet all-lost sequence is below the burst threshold, so not
    /// bursty.
    #[test]
    fn all_lost_below_threshold_not_bursty() {
        let received = vec![false, false]; // Only 2 lost = below burst threshold of 3
        let result = analyze_burst_gap(&received, 20.0);
        assert_eq!(result.burst_count, 0);
        assert!(!result.is_bursty);
    }

    /// 100 consecutive losses form exactly one burst with ~100% burst loss
    /// rate.
    #[test]
    fn all_lost_single_burst() {
        let received = vec![false; 100]; // 100 consecutive lost
        let result = analyze_burst_gap(&received, 20.0);
        assert_eq!(result.burst_count, 1);
        assert!(result.is_bursty);
        assert!(
            result.burst_loss_rate > 0.99,
            "burst_loss_rate should be ~1.0, got {}",
            result.burst_loss_rate
        );
    }

    /// The retroactive gap→burst reclassification must move the same
    /// packets out of every gap counter as one unit, keeping the partition
    /// consistent. A gap that already holds an isolated loss (so the gap
    /// counters exceed the reclassified count) followed by a 3+ burst
    /// exercises the guard; burst and gap loss rates must stay coherent.
    #[test]
    fn retroactive_reclassification_keeps_accounting_consistent() {
        let mut received = vec![true; 30];
        received[5] = false; // isolated loss — stays in the gap
        for i in 20..24 {
            received[i] = false; // 4 consecutive losses — a burst
        }

        let a = analyze_burst_gap(&received, 20.0);
        assert_eq!(a.burst_count, 1, "the 4-run is one burst");
        assert!(a.is_bursty);
        // Both rates are well-formed fractions, and the burst region carries
        // heavier loss than the gap region (which holds only the lone loss).
        assert!((0.0..=1.0).contains(&a.burst_loss_rate), "{a:?}");
        assert!((0.0..=1.0).contains(&a.gap_loss_rate), "{a:?}");
        assert!(
            a.gap_loss_rate > 0.0,
            "the isolated loss must register in the gap region: {a:?}"
        );
        assert!(
            a.burst_loss_rate > a.gap_loss_rate,
            "burst loss rate ({}) must exceed gap loss rate ({})",
            a.burst_loss_rate,
            a.gap_loss_rate
        );
    }

    /// Burst duration scales with `ptime_ms`: the same loss pattern lasts
    /// longer at 30 ms packets than at 20 ms.
    #[test]
    fn burst_duration_reflects_ptime() {
        let mut received = vec![true; 50];
        for i in 10..16 {
            received[i] = false; // 6 consecutive losses
        }

        let analysis_20ms = analyze_burst_gap(&received, 20.0);
        let analysis_30ms = analyze_burst_gap(&received, 30.0);

        assert!(analysis_20ms.is_bursty);
        assert!(analysis_30ms.is_bursty);
        assert!(
            analysis_30ms.burst_duration_ms > analysis_20ms.burst_duration_ms,
            "30ms ptime burst duration ({}) should exceed 20ms ({})",
            analysis_30ms.burst_duration_ms,
            analysis_20ms.burst_duration_ms
        );
    }
}

/// Whether sipnab has a published impairment value for a codec, or is guessing.
///
/// [`estimate_mos`] always returns a number, because every surface that shows
/// MOS predates this distinction and a sudden `Option` would break the REST
/// schema, the filter DSL's `rtp.mos`, the Prometheus series and the WASM
/// exports at once. So the number stays and the *confidence* is published
/// beside it.
///
/// The distinction is not academic. A caller that renders 4.2 for an AMR-WB
/// stream is showing a placeholder, and an operator reading it during an
/// incident has no way to tell that apart from a real estimate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MosGrounding {
    /// ITU-T G.113 publishes an equipment impairment factor for this codec, so
    /// the MOS is a genuine estimate.
    Published,
    /// No published impairment value. The MOS is a placeholder and means
    /// "unknown", not "about 4.2".
    Unpublished,
}

/// Whether [`estimate_mos`] can ground its answer for `codec`.
///
/// Deliberately keyed on the same names the `match` in [`estimate_mos`] uses,
/// so the two cannot disagree — a codec that scores as known here but falls to
/// the placeholder arm there would be the worst of both.
#[must_use]
pub fn mos_grounding(codec: Option<&str>) -> MosGrounding {
    match codec {
        Some("PCMU") | Some("PCMA") | Some("G729") | Some("G.729") | Some("opus")
        | Some("Opus") => MosGrounding::Published,
        _ => MosGrounding::Unpublished,
    }
}
