// SPDX-License-Identifier: MIT OR Apache-2.0

//! Rendering relay statistics as text, for the CLI surface (ST7 / C1).
//!
//! The CLI's rendering of the one thing every surface renders: statistics
//! [resolved for the wire](crate::stats_vocab::resolve_for_wire). ST-S1 fixes
//! WHAT each surface must show -- the relay's own name, the value uncoerced,
//! the tier, when it was obtained, and refusals with the relay's own code --
//! and lets each choose its layout. This is the CLI's layout: a header naming
//! the relay and the moment, a column of name/value, and a refusals section.
//!
//! The tier is stated once in the header rather than on every row, because a
//! relay-statistics table is entirely one tier: repeating `[relay_reported]`
//! against every line is noise, and stating it once is what an operator reads.
//! If the rows ever carry more than one tier, each row is annotated instead --
//! the honest fallback, tested.

use chrono::{DateTime, Utc};

use crate::stats_vocab::{NameSource, StatisticTier, TierComparison, WireStatistics};

/// The width the name column is padded to, so values line up.
const NAME_WIDTH: usize = 44;

/// How a relay-statistics reading was obtained (ST4 / C5).
///
/// A figure asked for once, in response to a flag, and a figure a timer keeps
/// asking for are different facts, and the output must say which -- ST4's rule
/// that a polled number carries a statement that it came from a poll. The
/// timestamp already distinguishes two readings; this names WHY a reading
/// exists, so a polled table is never mistaken for a one-shot answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchOrigin {
    /// Fetched once, because a flag asked for it.
    Asked,
    /// Fetched by a repeating timer, every `every_secs` seconds.
    Polled {
        /// The poll interval, in seconds, as the operator configured it.
        every_secs: u64,
    },
}

impl FetchOrigin {
    /// The header phrase naming when and why this reading was obtained.
    fn phrase(self, stamp: &str) -> String {
        match self {
            Self::Asked => format!("asked {stamp}"),
            Self::Polled { every_secs } => format!("polled {stamp}, every {every_secs}s"),
        }
    }
}

/// Render resolved relay statistics as a text block.
///
/// `relay_label` names the relay and where it was asked, e.g.
/// `rtpengine at 127.0.0.1:22222`. `obtained_at` is when the relay answered --
/// element four of ST-S1's rule, the thing that makes a polled figure and a
/// freshly-asked one distinguishable.
#[must_use]
pub fn format_relay_statistics(
    wire: &WireStatistics,
    relay_label: &str,
    obtained_at: DateTime<Utc>,
    origin: FetchOrigin,
) -> String {
    let stamp = obtained_at.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let when = origin.phrase(&stamp);

    // One tier for the whole table, or several? Stated once in the header when
    // uniform, annotated per row when not.
    let tiers: std::collections::BTreeSet<StatisticTier> =
        wire.present.iter().map(|v| v.tier).collect();
    let uniform_tier = if tiers.len() == 1 {
        tiers.iter().next().copied()
    } else {
        None
    };

    let mut out = String::new();
    match uniform_tier {
        Some(tier) => out.push_str(&format!(
            "Relay statistics ({relay_label}, {when}) — {} counts\n",
            tier.as_wire_str()
        )),
        None => out.push_str(&format!("Relay statistics ({relay_label}, {when})\n")),
    }

    if wire.present.is_empty() && wire.refusals.is_empty() {
        out.push_str("  (the relay reported nothing)\n");
        return out;
    }

    for v in &wire.present {
        if uniform_tier.is_some() {
            out.push_str(&format!("  {:<NAME_WIDTH$} {}\n", v.name, v.value));
        } else {
            out.push_str(&format!(
                "  {:<NAME_WIDTH$} {}  [{}]\n",
                v.name,
                v.value,
                v.tier.as_wire_str()
            ));
        }
    }

    if !wire.refusals.is_empty() {
        out.push_str("Refused:\n");
        for r in &wire.refusals {
            out.push_str(&format!("  {:<NAME_WIDTH$} {}\n", r.name, r.code));
        }
    }
    out
}

/// Render the names a relay knows as a text block (ST7 / C3).
///
/// This answers "what can I even ask for?", so it carries NAMES and no values:
/// a value here would make it a different capability wearing C3's flag. The
/// header names the relay, when it was asked, how many names there are, and --
/// the part C3 exists to make honest -- HOW the set was determined, because a
/// list a relay enumerated and a set probed by what did not refuse are not the
/// same claim.
#[must_use]
pub fn format_relay_stat_names(
    names: &[String],
    source: NameSource,
    relay_label: &str,
    obtained_at: DateTime<Utc>,
) -> String {
    let stamp = obtained_at.format("%Y-%m-%dT%H:%M:%SZ");
    let mut out = format!(
        "Statistics {relay_label} knows ({} name{}, asked {stamp}) — {}\n",
        names.len(),
        if names.len() == 1 { "" } else { "s" },
        source.how_determined()
    );
    if names.is_empty() {
        out.push_str("  (the relay named nothing it knows)\n");
        return out;
    }
    for name in names {
        out.push_str(&format!("  {name}\n"));
    }
    out
}

/// Render a relay-vs-capture comparison as a text block (ST7 / C4).
///
/// A comparison, never an aggregate: both figures are shown on their own line
/// with their own tier named, the verdict is a word, and the note travels
/// beneath so the caveat is not dropped at the CLI. The two counts are never
/// summed or differenced here -- the reader sees both and judges the gap.
#[must_use]
pub fn format_relay_comparison(
    comparison: &TierComparison,
    call_id: &str,
    relay_label: &str,
    obtained_at: DateTime<Utc>,
) -> String {
    let stamp = obtained_at.format("%Y-%m-%dT%H:%M:%SZ");
    let relay_name = comparison.relay.name.as_deref().unwrap_or("RTP packets");
    let mut out = format!(
        "Relay vs capture for call {call_id} ({relay_label}, asked {stamp}) — {}\n",
        comparison.verdict.as_wire_str()
    );
    out.push_str(&format!(
        "  {:<NAME_WIDTH$} {}  [{} {}]\n",
        "relay",
        comparison.relay.value,
        comparison.relay.tier.as_wire_str(),
        relay_name,
    ));
    out.push_str(&format!(
        "  {:<NAME_WIDTH$} {}  [{}]\n",
        "sipnab",
        comparison.sipnab.value,
        comparison.sipnab.tier.as_wire_str(),
    ));
    out.push_str(&format!("  note: {}\n", comparison.note));
    out
}
