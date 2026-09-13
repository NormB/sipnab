// SPDX-License-Identifier: MIT OR Apache-2.0

//! ST3: the statistics rtpproxy reports, read into the one tier vocabulary.
//!
//! The reply shapes are inline literals captured verbatim from the rtpproxy in
//! the harness (2.1.1-r3): `I` answers five `label: value` lines, `G <name>` a
//! bare number, and `Q` five positional integers. Parsed into `(name, value)`
//! pairs, they feed the same `relay_reported` tierer rtpengine's statistics do
//! -- one adapter, both relays, because RP2 forbids a second relay being a
//! second code path.

#![cfg(feature = "full")]

use sipnab::relay::rtpproxy::{info_statistics, query_statistics};
use sipnab::stats_vocab::{StatisticTier, StatisticValue, lookup, relay_reported};

/// Exactly the bytes the harness rtpproxy sends after the cookie, on a relay
/// that has seen one call.
const INFO_REPLY: &str = "sessions created: 1\nactive sessions: 0\nactive streams: 2\npackets received: 9000\npackets transmitted: 9000\n";

/// A `Q` reply for a live session: `ttl npkts_ina npkts_ino nrelayed ndropped`.
const QUERY_REPLY: &str = "60 3381 3381 6762 0";

/// The `I` reply parses into the relay's own labels, kept verbatim.
#[test]
fn an_info_reply_reads_into_the_relays_own_labels() {
    let pairs = info_statistics(INFO_REPLY);
    let tiered = relay_reported(&pairs);
    assert_eq!(
        tiered.len(),
        5,
        "the I reply has five lines; got {}: {pairs:?}",
        tiered.len()
    );
    for s in &tiered {
        assert_eq!(
            s.tier,
            StatisticTier::RelayReported,
            "{} is the relay's own",
            s.name
        );
        assert!(
            matches!(s.value, StatisticValue::Counted(_)),
            "{} is counted",
            s.name
        );
    }
    // The label is kept with its space -- it is the relay's own name, and
    // `active streams` has no G identifier to normalize to.
    assert_eq!(
        lookup(&tiered, "packets received"),
        StatisticValue::Counted("9000".to_string()),
        "the I reply's own label and value must survive verbatim"
    );
    assert_eq!(
        lookup(&tiered, "active streams"),
        StatisticValue::Counted("2".to_string())
    );
}

/// A line that is not `label: value` is skipped, not guessed at.
///
/// Three malformed shapes, each a distinct way to not be a statistic: no colon
/// at all, an empty value after the colon, and an empty label before it. The
/// last two are why the parser filters empty sides -- `split_once(':')` alone
/// admits `label:` as `(label, "")` and `: value` as `("", value)`, both junk.
#[test]
fn a_line_that_is_not_label_colon_value_is_skipped() {
    let pairs = info_statistics(
        "sessions created: 1\nno colon here\ntrailing colon:\n: leading colon\nactive sessions: 0\n",
    );
    assert_eq!(
        pairs.len(),
        2,
        "only the two well-formed lines are statistics: {pairs:?}"
    );
    assert!(
        pairs.iter().all(|(name, _)| name.contains("sessions")),
        "a malformed line was read as a statistic: {pairs:?}"
    );
    // Specifically: neither empty side survived.
    assert!(
        pairs
            .iter()
            .all(|(name, value)| !name.is_empty() && !value.is_empty()),
        "an empty label or value was kept: {pairs:?}"
    );
}

/// The five `Q` positional fields get the names ST-S2 established, in order.
#[test]
fn a_query_reply_names_its_five_positional_fields() {
    let pairs = query_statistics(QUERY_REPLY).expect("a five-field Q reply parses");
    assert_eq!(
        pairs,
        vec![
            ("ttl".to_string(), "60".to_string()),
            ("npkts_ina".to_string(), "3381".to_string()),
            ("npkts_ino".to_string(), "3381".to_string()),
            ("nrelayed".to_string(), "6762".to_string()),
            ("ndropped".to_string(), "0".to_string()),
        ],
        "the Q fields must be named in the binary's own order"
    );
    // The arithmetic ST-S2 corroborated: nrelayed == npkts_ina + npkts_ino.
    let v = |n: &str| {
        pairs
            .iter()
            .find(|(name, _)| name == n)
            .map(|(_, val)| val.parse::<u64>().unwrap())
            .unwrap()
    };
    assert_eq!(
        v("nrelayed"),
        v("npkts_ina") + v("npkts_ino"),
        "the field labels are wrong if this identity does not hold"
    );
}

/// A `Q` reply that is not exactly five integer fields is REFUSED.
///
/// Labeling four or six positional values by the five known names would name a
/// counter from whatever sat in the position -- the exact mistake the decoder
/// refuses elsewhere.
#[test]
fn a_query_reply_of_the_wrong_arity_is_refused() {
    assert_eq!(
        query_statistics("60 3381 3381"),
        None,
        "three fields is not the Q shape"
    );
    assert_eq!(
        query_statistics("60 3381 3381 6762 0 99"),
        None,
        "six fields is not the Q shape"
    );
    assert_eq!(
        query_statistics(""),
        None,
        "an empty reply is not a Q answer"
    );
    assert_eq!(
        query_statistics("60 3381 notanumber 6762 0"),
        None,
        "a non-integer field means this is not a positional Q reply"
    );
}
