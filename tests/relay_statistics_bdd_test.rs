// SPDX-License-Identifier: MIT OR Apache-2.0

//! Relay statistics: obtainable when asked for, sent for no other reason.
//!
//! Written before the behavior exists. Two requirements that sound opposed
//! and are not:
//!
//! * an API caller or an agent may ask a question that needs statistics, and
//!   must be able to get them
//! * a run nobody asked anything of must put nothing on the network
//!
//! The second is why this is a command rather than a poll. Every other tool
//! sipnab offers answers from bytes it already holds; this one asks a relay a
//! question, which means a packet leaves the host. That is an operator's
//! decision, not a default.

#![cfg(feature = "full")]

use sipnab::relay::types::ReadOnlyCommand;

// ── The command exists, and reads only ───────────────────────────────────────

/// GIVEN the read-only relay surface
/// WHEN statistics are asked for
/// THEN there is a command for it.
#[test]
fn statistics_can_be_asked_for() {
    let c = ReadOnlyCommand::Statistics;
    assert_eq!(c, ReadOnlyCommand::Statistics);
}

/// GIVEN the statistics command
/// WHEN it is compared with the others
/// THEN it is its own command, not a `Query` with a special argument.
///
/// A call-scoped query and a relay-wide statistic answer different questions:
/// one is about a conversation, the other about the box. Overloading `Query`
/// would make "no such call" and "no statistics" the same refusal.
#[test]
fn statistics_is_not_a_query_in_disguise() {
    assert_ne!(
        ReadOnlyCommand::Statistics,
        ReadOnlyCommand::Query {
            call_id: "stats".to_string()
        }
    );
    assert_ne!(
        ReadOnlyCommand::Statistics,
        ReadOnlyCommand::List { limit: 1 }
    );
}

/// GIVEN the read-only surface
/// WHEN every command is enumerated
/// THEN none of them can change the relay.
///
/// The property the type exists for: it is not that sipnab avoids sending a
/// delete, it is that this type cannot express one. Adding a command must not
/// weaken that.
#[test]
fn the_surface_still_cannot_express_a_change() {
    let all = [
        ReadOnlyCommand::List { limit: 32 },
        ReadOnlyCommand::Query {
            call_id: "c".to_string(),
        },
        ReadOnlyCommand::Statistics,
    ];
    for c in &all {
        let rendered = format!("{c:?}").to_lowercase();
        for forbidden in ["delete", "unforce", "record", "offer", "answer"] {
            assert!(!rendered.contains(forbidden), "{c:?} names a mutating verb");
        }
    }
}

// ── Asking is a decision, not a default ──────────────────────────────────────

/// GIVEN a relay decoder
/// WHEN nobody has asked for statistics
/// THEN no statistics command is produced.
///
/// The second requirement, stated as a property of the type rather than of a
/// caller's discipline: a command has to be constructed to be sent, and
/// nothing constructs this one on its own.
#[test]
fn nothing_produces_a_statistics_command_unbidden() {
    // Decoding a captured control message yields an observation, never a
    // command to send. A passive observer that answered a capture by
    // transmitting would be a different kind of tool.
    let observed = sipnab::relay::rtpproxy::decode_command(
        b"29_6976_4 Uc8,101 1-32@172.28.0.21 172.28.0.21 6000 32SIPpTag091;1",
    );
    assert!(
        observed.is_some(),
        "the capture decodes, or this proves nothing"
    );
    // There is no path from a decoded observation to a ReadOnlyCommand, and
    // that is the point: the type system has no such conversion to offer.
}

/// GIVEN the statistics command
/// WHEN it is built
/// THEN it carries no arguments an agent could aim somewhere else.
///
/// `query_relay` already refuses an agent-supplied destination, because an
/// agent that could name the target would turn the MCP surface into a way to
/// send packets anywhere. A statistics command with a host argument would
/// reopen that.
#[test]
fn the_statistics_command_names_no_destination() {
    let rendered = format!("{:?}", ReadOnlyCommand::Statistics);
    for hostish in [".", ":", "@", "/"] {
        assert!(
            !rendered.contains(hostish),
            "the command carries something address-shaped: {rendered}"
        );
    }
}
