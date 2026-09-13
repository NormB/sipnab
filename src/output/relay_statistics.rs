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

use crate::stats_vocab::{StatisticTier, WireStatistics};

/// The width the name column is padded to, so values line up.
const NAME_WIDTH: usize = 44;

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
) -> String {
    let stamp = obtained_at.format("%Y-%m-%dT%H:%M:%SZ");

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
            "Relay statistics ({relay_label}, asked {stamp}) — {} counts\n",
            tier.as_wire_str()
        )),
        None => out.push_str(&format!(
            "Relay statistics ({relay_label}, asked {stamp})\n"
        )),
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
