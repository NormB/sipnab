// SPDX-License-Identifier: MIT OR Apache-2.0

//! One set of quality bands, for every view that colours a number.
//!
//! Four views banded jitter, loss and MOS independently, and disagreed:
//!
//! | value | stream list | dashboard | loss map | stream detail |
//! |-------|-------------|-----------|----------|---------------|
//! | 25 ms jitter | Good (< 30) | **Warning** (>= 20) | — | — |
//! | 0.8 % loss | Good (< 1.0) | — | **Warning** (>= 0.5) | — |
//!
//! So one stream rendered green in the list and yellow in the detail view of
//! that same stream, in the same session. The colour column is the TUI's
//! primary triage signal, which makes this worse than a tuning disagreement:
//! an operator scanning for yellow finds a different set of calls depending on
//! which pane they happen to be looking at.
//!
//! `loss_map.rs` even documented the agreement it did not have — "the same
//! bands the dashboard and stream-detail views use" — above numbers that
//! matched neither. A comment asserting consistency is not consistency, and it
//! is how four copies stayed unnoticed.
//!
//! The bands live here rather than in `tui/` because they are a judgement about
//! MEDIA, not about rendering: the same question a report, an alert or an
//! export answers when it calls a stream bad. `tui/` decides the colour.

/// Where "good" becomes "warning", and "warning" becomes "bad".
///
/// One value per boundary, named for the thing it bounds. Defaults are the
/// values the stream list shipped with, because that is the view an operator
/// triages from and the one whose numbers the others should have matched.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct QualityBands {
    /// Jitter at or above this is a warning (milliseconds).
    pub jitter_warn_ms: f64,
    /// Jitter at or above this is bad (milliseconds).
    pub jitter_bad_ms: f64,
    /// Loss at or above this is a warning (percent).
    pub loss_warn_pct: f64,
    /// Loss at or above this is bad (percent).
    pub loss_bad_pct: f64,
    /// MOS below this is a warning.
    pub mos_warn: f64,
    /// MOS below this is bad.
    pub mos_bad: f64,
    /// Round trip at or above this is a warning (milliseconds).
    pub rtt_warn_ms: f64,
    /// Round trip at or above this is bad (milliseconds).
    pub rtt_bad_ms: f64,
}

impl Default for QualityBands {
    fn default() -> Self {
        Self {
            jitter_warn_ms: 30.0,
            jitter_bad_ms: 50.0,
            loss_warn_pct: 1.0,
            loss_bad_pct: 5.0,
            mos_warn: 4.0,
            mos_bad: 3.0,
            // Grounded in ITU-T G.114, which is about ONE-WAY delay: up to
            // 150 ms is acceptable for most applications, and above 400 ms is
            // unacceptable for general network planning. A round trip is about
            // twice a one-way, so those become 300 ms and 800 ms here.
            //
            // Doubling is an approximation and worth stating: real paths are
            // asymmetric, so an 800 ms round trip may be 700 ms one way and
            // 100 ms the other. It is the right approximation for a triage
            // colour, and the wrong one to quote as a one-way figure.
            rtt_warn_ms: 300.0,
            rtt_bad_ms: 800.0,
        }
    }
}

/// A verdict about one measured value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Band {
    /// Inside every threshold.
    Good,
    /// Past the warning boundary, short of the bad one.
    Warning,
    /// At or past the bad boundary.
    Bad,
}

impl QualityBands {
    /// Band a jitter measurement.
    #[must_use]
    pub fn jitter(&self, ms: f64) -> Band {
        if ms >= self.jitter_bad_ms {
            Band::Bad
        } else if ms >= self.jitter_warn_ms {
            Band::Warning
        } else {
            Band::Good
        }
    }

    /// Band a loss percentage.
    #[must_use]
    pub fn loss(&self, pct: f64) -> Band {
        if pct >= self.loss_bad_pct {
            Band::Bad
        } else if pct >= self.loss_warn_pct {
            Band::Warning
        } else {
            Band::Good
        }
    }

    /// Band a MOS score. Lower is worse, so the comparison inverts.
    #[must_use]
    pub fn mos(&self, mos: f64) -> Band {
        if mos < self.mos_bad {
            Band::Bad
        } else if mos < self.mos_warn {
            Band::Warning
        } else {
            Band::Good
        }
    }

    /// Band a round-trip measurement.
    ///
    /// Only ever called with a figure somebody actually reported — a missing
    /// round trip has no band, because "not measured" is not a quality verdict
    /// and colouring it green would be the whole defect this was added to fix.
    #[must_use]
    pub fn rtt(&self, ms: f64) -> Band {
        if ms >= self.rtt_bad_ms {
            Band::Bad
        } else if ms >= self.rtt_warn_ms {
            Band::Warning
        } else {
            Band::Good
        }
    }

    /// Reject a band set that cannot be honoured.
    ///
    /// A warn boundary above its bad boundary is not a stricter setting, it is
    /// an unreachable middle: nothing would ever render as a warning, and the
    /// operator who wrote it would see green until the value was already bad.
    /// Refused at startup rather than silently reordered.
    ///
    /// A boundary that is not a finite, non-negative number is refused first,
    /// and for a worse reason: every comparison against `NaN` is false, so a
    /// single `nan` here paints the whole column green and reports a healthy
    /// network. Zero itself is allowed — `loss_warn_pct = 0.0` means "any loss
    /// at all is worth a colour", which is a real setting on a strict network.
    ///
    /// This is the ONLY validator for a band set. `[quality]` keys are checked
    /// through it rather than beside it, because a warn boundary can arrive
    /// from the config file while its bad boundary arrives from the command
    /// line, and a second validator over either half alone would pass the pair
    /// that is actually unreachable.
    pub fn validate(&self) -> Result<(), String> {
        for (key, value) in [
            ("jitter_warn_ms", self.jitter_warn_ms),
            ("jitter_bad_ms", self.jitter_bad_ms),
            ("loss_warn_pct", self.loss_warn_pct),
            ("loss_bad_pct", self.loss_bad_pct),
            ("mos_warn", self.mos_warn),
            ("mos_bad", self.mos_bad),
            ("rtt_warn_ms", self.rtt_warn_ms),
            ("rtt_bad_ms", self.rtt_bad_ms),
        ] {
            if !(value.is_finite() && value >= 0.0) {
                return Err(format!(
                    "{key} ({value}) must be a finite number of 0 or more; a \
                     boundary that is not compares false against every \
                     measurement and paints the column green"
                ));
            }
        }
        if self.jitter_warn_ms > self.jitter_bad_ms {
            return Err(format!(
                "jitter_warn_ms ({}) is above jitter_bad_ms ({}), so no jitter \
                 could ever be a warning",
                self.jitter_warn_ms, self.jitter_bad_ms
            ));
        }
        if self.loss_warn_pct > self.loss_bad_pct {
            return Err(format!(
                "loss_warn_pct ({}) is above loss_bad_pct ({}), so no loss could \
                 ever be a warning",
                self.loss_warn_pct, self.loss_bad_pct
            ));
        }
        if self.rtt_warn_ms > self.rtt_bad_ms {
            return Err(format!(
                "rtt_warn_ms ({}) is above rtt_bad_ms ({}), so no round trip \
                 could ever be a warning",
                self.rtt_warn_ms, self.rtt_bad_ms
            ));
        }
        if self.mos_warn < self.mos_bad {
            return Err(format!(
                "mos_warn ({}) is below mos_bad ({}); MOS bands run downward, so \
                 no score could ever be a warning",
                self.mos_warn, self.mos_bad
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The values that used to disagree now get ONE answer.
    ///
    /// 25 ms was Good in the stream list and Warning on the dashboard; 0.8%
    /// was Good in the stream list and Warning in the loss map. Whatever the
    /// bands are, every view must now say the same thing about them.
    #[test]
    fn the_values_that_used_to_disagree_get_one_answer() {
        let b = QualityBands::default();
        assert_eq!(
            b.jitter(25.0),
            Band::Good,
            "25 ms sat across two views' boundaries"
        );
        assert_eq!(
            b.loss(0.8),
            Band::Good,
            "0.8% sat across two views' boundaries"
        );
    }

    /// Each boundary is inclusive at the bad end, so a value exactly ON a
    /// threshold is the worse verdict. An operator who sets 50 means "50 is
    /// bad", not "50 is fine and 50.1 is bad".
    #[test]
    fn a_value_exactly_on_a_boundary_takes_the_worse_band() {
        let b = QualityBands::default();
        assert_eq!(b.jitter(30.0), Band::Warning);
        assert_eq!(b.jitter(50.0), Band::Bad);
        assert_eq!(b.loss(1.0), Band::Warning);
        assert_eq!(b.loss(5.0), Band::Bad);
        // MOS runs the other way: the boundary itself is the BETTER band.
        assert_eq!(b.mos(4.0), Band::Good);
        assert_eq!(b.mos(3.0), Band::Warning);
    }

    /// Anti-vacuity: the bands still separate genuinely different inputs.
    #[test]
    fn the_bands_still_separate_good_from_bad() {
        let b = QualityBands::default();
        assert_eq!(b.jitter(1.0), Band::Good);
        assert_eq!(b.jitter(40.0), Band::Warning);
        assert_eq!(b.jitter(120.0), Band::Bad);
        assert_eq!(b.mos(4.4), Band::Good);
        assert_eq!(b.mos(2.0), Band::Bad);
    }

    /// An inverted band set is refused rather than quietly reordered.
    #[test]
    fn an_unreachable_middle_is_refused() {
        let bad = QualityBands {
            jitter_warn_ms: 80.0,
            jitter_bad_ms: 50.0,
            ..Default::default()
        };
        let err = bad.validate().expect_err("warn above bad must be refused");
        assert!(
            err.contains("jitter_warn_ms"),
            "the error must name the key: {err}"
        );

        assert!(
            QualityBands::default().validate().is_ok(),
            "the shipped defaults must be a valid band set"
        );
    }

    /// A boundary that is not a finite, non-negative number is refused, by name.
    ///
    /// `NaN` is the dangerous one and the reason this check runs first: every
    /// comparison against it is false, so `jitter(1000.0)` would return `Good`
    /// and the column would report a healthy network in the middle of an
    /// outage. Refusing an unreachable middle while accepting `nan` would
    /// guard the harmless case and pass the harmful one.
    #[test]
    fn a_boundary_that_is_not_a_finite_non_negative_number_is_refused() {
        for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1.0] {
            let b = QualityBands {
                jitter_warn_ms: bad,
                ..Default::default()
            };
            let Err(err) = b.validate() else {
                panic!("{bad} must be refused as a boundary");
            };
            assert!(
                err.contains("jitter_warn_ms"),
                "the error must name the key: {err}"
            );
        }

        // The proof that this refuses the right thing: NaN really does paint
        // an outage green, which is what the check is for.
        let blind = QualityBands {
            jitter_warn_ms: f64::NAN,
            jitter_bad_ms: f64::NAN,
            ..Default::default()
        };
        assert_eq!(
            blind.jitter(10_000.0),
            Band::Good,
            "if NaN did not read as Good, this validation would be arbitrary"
        );
    }

    /// Zero is a setting, not a mistake: "any loss at all is worth a colour".
    #[test]
    fn a_zero_boundary_is_accepted_and_bands_from_zero() {
        let b = QualityBands {
            loss_warn_pct: 0.0,
            ..Default::default()
        };
        assert!(b.validate().is_ok(), "0.0 is a legitimate strict boundary");
        assert_eq!(b.loss(0.0), Band::Warning);
    }
}
