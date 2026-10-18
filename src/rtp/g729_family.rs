// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors
//! The G.729 family: which member a codec name is, and what sipnab says about
//! the audio it decodes from each.
//!
//! - **G.729** (`G729`, static payload type 18, [RFC 3551 section 4.5.6](https://www.rfc-editor.org/rfc/rfc3551.html#section-4.5.6)), with
//!   its Annexes A and B, decodes in full with the `g729` crate.
//! - **G.729.1** (`G7291`, a dynamic payload type, RFC 4749 and RFC 5459)
//!   decodes its core layer only: the first 20 octets of each 20 ms frame are
//!   two G.729 frames, which the same decoder turns into 8 kHz audio. The
//!   layers above 8 kbit/s (narrowband enhancement at 12 kbit/s, wideband
//!   from 14 kbit/s) are not decoded, and every surface that carries the
//!   audio says so ([`g7291_caveat`]).
//!
//! [`g729_variant`] is the one place a codec name is read as a member of the
//! family: the retention gate, the exporter, the live audio routes, the
//! amplitude measurement and the TUI's install offer all ask it.

/// A member of the G.729 family that sipnab decodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum G729Variant {
    /// G.729 with Annexes A and B: `G729`.
    G729,
    /// G.729.1, decoded to its core layer: `G7291`.
    G7291,
}

impl G729Variant {
    /// The codec's name in an export's summary.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::G729 => "G.729",
            Self::G7291 => "G.729.1 core layer",
        }
    }
}

/// Which member of the G.729 family `codec` names, compared without regard
/// to case as SDP encoding names are, or `None` for any other codec.
#[must_use]
pub fn g729_variant(codec: &str) -> Option<G729Variant> {
    if codec.eq_ignore_ascii_case("G729") {
        Some(G729Variant::G729)
    } else if codec.eq_ignore_ascii_case("G7291") {
        Some(G729Variant::G7291)
    } else {
        None
    }
}

/// The G.729.1 bit rates of the frames a stream's decoder has decoded, in
/// kbit/s.
#[cfg(feature = "g729")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct G7291Rates {
    /// Bit `ft` is set when a frame of frame type `ft` (0 to 11) was decoded.
    seen: u16,
}

#[cfg(feature = "g729")]
impl G7291Rates {
    /// Record that frames at `rate` were decoded.
    pub fn record(&mut self, rate: g729::g7291::Rate) {
        self.seen |= 1 << rate.ft();
    }

    /// The rates recorded, in kbit/s, lowest first.
    #[must_use]
    pub fn kbps(&self) -> Vec<u8> {
        // Frame-type order is rate order (RFC 4749 section 5.3).
        (0..16u8)
            .filter(|ft| self.seen & (1 << ft) != 0)
            .filter_map(g729::g7291::Rate::from_ft)
            .map(g729::g7291::Rate::kbps)
            .collect()
    }
}

/// What every surface that carries decoded G.729.1 audio says about it: the
/// audio is the core layer decoded as G.729 at 8 kHz, at what bit rates the
/// stream's frames were sent, and that the layers above 8 kbit/s are not in
/// it.
#[cfg(feature = "g729")]
#[must_use]
pub fn g7291_caveat(rates: &G7291Rates) -> String {
    let kbps: Vec<String> = rates.kbps().iter().map(u8::to_string).collect();
    let sent = match kbps.as_slice() {
        [] => "no speech frame was decoded".to_owned(),
        [one] => format!("the stream's frames were sent at {one} kbit/s"),
        [init @ .., last] => format!(
            "the stream's frames were sent at {} and {last} kbit/s",
            init.join(", ")
        ),
    };
    format!(
        "G.729.1: this audio is the G.729.1 core layer (8 kbit/s) decoded as G.729 at 8 kHz; \
         {sent}; the layers above 8 kbit/s (narrowband enhancement and wideband) are not \
         decoded, so this is not the audio a G.729.1 decoder produces"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `G7291` in any case is G.729.1, `G729` in any case is G.729, and no
    /// other name is either.
    #[test]
    fn the_family_is_read_from_the_encoding_name() {
        for name in ["G729", "g729", "G729"] {
            assert_eq!(g729_variant(name), Some(G729Variant::G729), "{name}");
        }
        for name in ["G7291", "g7291", "G7291"] {
            assert_eq!(g729_variant(name), Some(G729Variant::G7291), "{name}");
        }
        for name in ["G729D", "G729E", "G.729.1", "G7221", "PCMU", "", "G72911"] {
            assert_eq!(g729_variant(name), None, "{name}");
        }
        assert_eq!(G729Variant::G729.label(), "G.729");
        assert_eq!(G729Variant::G7291.label(), "G.729.1 core layer");
    }

    #[cfg(feature = "g729")]
    mod with_the_feature {
        use super::super::*;
        use g729::g7291::Rate;

        type TestResult = Result<(), Box<dyn std::error::Error>>;

        fn rate(ft: u8) -> Result<Rate, String> {
            Rate::from_ft(ft).ok_or_else(|| format!("FT {ft} is not a rate"))
        }

        /// The rates come back once each, lowest first, in kbit/s.
        #[test]
        fn the_rates_seen_are_listed_once_lowest_first() -> TestResult {
            let mut rates = G7291Rates::default();
            assert!(rates.kbps().is_empty());
            for ft in [11, 0, 11, 1, 0] {
                rates.record(rate(ft)?);
            }
            assert_eq!(rates.kbps(), [8, 12, 32]);
            Ok(())
        }

        /// The caveat says what the audio is, names the bit rates, and says
        /// what is not decoded.
        #[test]
        fn the_caveat_names_the_core_layer_and_the_bit_rates() -> TestResult {
            let mut rates = G7291Rates::default();
            rates.record(rate(11)?);
            let one = g7291_caveat(&rates);
            assert_eq!(
                one,
                "G.729.1: this audio is the G.729.1 core layer (8 kbit/s) decoded as G.729 \
                 at 8 kHz; the stream's frames were sent at 32 kbit/s; the layers above \
                 8 kbit/s (narrowband enhancement and wideband) are not decoded, so this is \
                 not the audio a G.729.1 decoder produces"
            );
            rates.record(rate(0)?);
            rates.record(rate(5)?);
            assert!(
                g7291_caveat(&rates).contains("sent at 8, 20 and 32 kbit/s;"),
                "{}",
                g7291_caveat(&rates)
            );
            assert!(
                g7291_caveat(&G7291Rates::default()).contains("no speech frame was decoded;"),
                "{}",
                g7291_caveat(&G7291Rates::default())
            );
            Ok(())
        }
    }
}
