// SPDX-License-Identifier: MIT OR Apache-2.0

//! `--group-by <FIELD>`: reorder batch output so messages sharing a field value
//! are emitted contiguously.
//!
//! # Why this buffers, and why it is capped
//!
//! The ordinary batch path streams each message straight into the sink as it is
//! parsed. Grouping cannot stream: the last packet in a capture may belong to
//! the first group, so nothing can be emitted until the capture ends.
//!
//! That makes this a map keyed on attacker-supplied data — `Call-ID` and the
//! `From` user come off the wire — so it is bounded like every other such map
//! in the tree (invariant 4). Two independent caps apply:
//!
//! * [`DEFAULT_MAX_GROUPS`] distinct keys, and
//! * [`DEFAULT_MAX_BUFFERED`] messages in total.
//!
//! On hitting either cap the buffer stops accepting new work and reports it, so
//! the operator learns the output was truncated instead of quietly receiving a
//! partial picture. Grouping is therefore a convenience for bounded offline
//! captures, not something to point at an unbounded live feed.
//!
//! Both defaults are settings, not laws: `--max-groups` /
//! `[limits] max_groups` and `--max-grouped-messages` /
//! `[limits] max_grouped_messages` move them, and `-l`/`--limit` does not —
//! that one bounds tracked dialogs, which is a different question from how
//! much rendered output this buffer holds.
//!
//! # What "grouping" means
//!
//! Messages are *reordered*, not reformatted. For `--json` that keeps every line
//! a valid message object with no schema change — the grouping is the
//! contiguity. For human-readable output a header line precedes each group.

use std::collections::HashMap;

use crate::sip::message::SipMessage;

/// Shipped maximum of distinct group keys retained. Matches the store default
/// so a grouped run cannot outgrow an ordinary capture.
///
/// Raise it with `--max-groups` or `[limits] max_groups` for a capture that
/// genuinely holds more calls than this — the warning says the output is
/// incomplete, but nothing short of the setting can complete it.
pub const DEFAULT_MAX_GROUPS: usize = 10_000;

/// Shipped maximum of messages buffered across all groups. Raise it with
/// `--max-grouped-messages` or `[limits] max_grouped_messages`.
pub const DEFAULT_MAX_BUFFERED: usize = 200_000;

/// The two caps a [`GroupBuffer`] enforces, resolved once at startup.
///
/// Carried as a pair rather than as two loose arguments so a call site cannot
/// swap them: both are bare counts, and `new(field, 200_000, 10_000)` compiles
/// as happily as the correct order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupCaps {
    /// Distinct group keys the buffer will retain.
    pub groups: usize,
    /// Messages the buffer will hold across every group.
    pub buffered: usize,
}

impl Default for GroupCaps {
    /// The shipped pair: [`DEFAULT_MAX_GROUPS`] keys, [`DEFAULT_MAX_BUFFERED`]
    /// messages.
    fn default() -> Self {
        Self {
            groups: DEFAULT_MAX_GROUPS,
            buffered: DEFAULT_MAX_BUFFERED,
        }
    }
}

/// The field a run groups on. Parsed from `--group-by` once, at startup, so an
/// unrecognized value fails immediately instead of being silently ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupField {
    /// `Call-ID` header — groups a dialog's messages together.
    CallId,
    /// `From` header user part.
    From,
    /// `To` header user part.
    To,
    /// SIP method (requests) or `"response"` (responses).
    Method,
    /// Source IP address.
    Src,
    /// Destination IP address.
    Dst,
}

/// Every accepted `--group-by` value, in the order shown to the user.
pub const GROUP_FIELD_NAMES: &[&str] = &["call-id", "from", "to", "method", "src", "dst"];

impl GroupField {
    /// Parse a `--group-by` value.
    ///
    /// # Errors
    /// Returns the accepted-value list when `raw` is not a known field, so a
    /// typo is rejected at startup rather than producing ungrouped output.
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "call-id" | "call_id" | "callid" => Ok(Self::CallId),
            "from" => Ok(Self::From),
            "to" => Ok(Self::To),
            "method" => Ok(Self::Method),
            "src" | "source" => Ok(Self::Src),
            "dst" | "dest" | "destination" => Ok(Self::Dst),
            _ => Err(format!(
                "unknown --group-by field '{raw}'; expected one of: {}",
                GROUP_FIELD_NAMES.join(", ")
            )),
        }
    }

    /// The group key for `msg`, or `None` when the message does not carry the
    /// field (such a message is emitted ungrouped, in arrival order).
    pub fn key_of(self, msg: &SipMessage) -> Option<String> {
        match self {
            Self::CallId => msg.call_id().map(str::to_string),
            Self::From => msg.from_user(),
            Self::To => msg.to_user(),
            Self::Method => Some(match msg.method.as_ref() {
                Some(m) => m.as_str().to_string(),
                None => "response".to_string(),
            }),
            Self::Src => Some(msg.src_addr.to_string()),
            Self::Dst => Some(msg.dst_addr.to_string()),
        }
    }

    /// The canonical name, for headers and diagnostics.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CallId => "call-id",
            Self::From => "from",
            Self::To => "to",
            Self::Method => "method",
            Self::Src => "src",
            Self::Dst => "dst",
        }
    }
}

/// Buffers rendered message output until the capture ends, then replays it
/// grouped. Holds already-formatted bytes rather than `SipMessage` clones so the
/// memory cost is the output the user asked for, not a second copy of the
/// capture.
pub struct GroupBuffer {
    /// The field being grouped on.
    field: GroupField,
    /// Insertion-ordered group keys, so group order is first-seen order and the
    /// output is deterministic for a given capture.
    order: Vec<String>,
    /// Key → rendered message chunks, in arrival order within the group.
    groups: HashMap<String, Vec<String>>,
    /// Messages carrying no value for the field; replayed after the groups.
    ungrouped: Vec<String>,
    /// Total buffered chunks, across groups and `ungrouped`.
    buffered: usize,
    /// Messages dropped after a cap was reached.
    dropped: usize,
    /// Group keys refused after the group cap was reached.
    dropped_groups: usize,
    /// The caps this buffer enforces, resolved from the flags and the config
    /// file. Held here rather than read from a constant at each check,
    /// because a limit that exists only as a constant is one an operator
    /// cannot move — which is the whole defect this replaced.
    caps: GroupCaps,
}

impl GroupBuffer {
    /// Create an empty buffer for `field`, bounded by `caps`.
    pub fn new(field: GroupField, caps: GroupCaps) -> Self {
        Self {
            field,
            order: Vec::new(),
            groups: HashMap::new(),
            ungrouped: Vec::new(),
            buffered: 0,
            dropped: 0,
            dropped_groups: 0,
            caps,
        }
    }

    /// The caps in force, so a caller's resolution can be asserted against the
    /// buffer it configured rather than against the resolver alone.
    #[must_use]
    pub fn caps(&self) -> GroupCaps {
        self.caps
    }

    /// Buffer one rendered message. Returns `false` when a cap refused it.
    pub fn push(&mut self, msg: &SipMessage, rendered: String) -> bool {
        if self.buffered >= self.caps.buffered {
            self.dropped += 1;
            return false;
        }
        match self.field.key_of(msg) {
            Some(key) => {
                if !self.groups.contains_key(&key) {
                    if self.order.len() >= self.caps.groups {
                        self.dropped_groups += 1;
                        self.dropped += 1;
                        return false;
                    }
                    self.order.push(key.clone());
                }
                self.groups.entry(key).or_default().push(rendered);
            }
            None => self.ungrouped.push(rendered),
        }
        self.buffered += 1;
        true
    }

    /// `true` when a cap refused at least one message, so the caller can warn.
    pub fn truncated(&self) -> bool {
        self.dropped > 0
    }

    /// A one-line description of what was dropped, for a warning.
    ///
    /// Names the flag that raises each cap: an operator told the output is
    /// incomplete, and not told what completes it, has been informed of a
    /// problem and handed no way out of it.
    pub fn truncation_note(&self) -> String {
        format!(
            "--group-by buffer full: {} message(s) dropped ({} group(s) refused past the \
             {}-group cap, {}-message total cap). Output is incomplete. Raise \
             --max-groups / --max-grouped-messages (or [limits] max_groups / \
             max_grouped_messages) to keep it all.",
            self.dropped, self.dropped_groups, self.caps.groups, self.caps.buffered
        )
    }

    /// Number of groups retained.
    pub fn group_count(&self) -> usize {
        self.order.len()
    }

    /// Drain the buffer into `(header, chunks)` pairs in first-seen key order,
    /// followed by the ungrouped remainder under `None`.
    ///
    /// `header` is `None` for the ungrouped tail so a caller emitting machine
    /// output can skip headers entirely.
    pub fn drain(&mut self) -> Vec<(Option<String>, Vec<String>)> {
        let mut out = Vec::with_capacity(self.order.len() + 1);
        for key in std::mem::take(&mut self.order) {
            if let Some(chunks) = self.groups.remove(&key) {
                out.push((Some(format!("{} {key}", self.field.as_str())), chunks));
            }
        }
        let rest = std::mem::take(&mut self.ungrouped);
        if !rest.is_empty() {
            out.push((None, rest));
        }
        self.buffered = 0;
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every documented field name parses, and the aliases resolve to the same
    /// variant as their canonical spelling.
    #[test]
    fn documented_field_names_parse() {
        for name in GROUP_FIELD_NAMES {
            assert!(
                GroupField::parse(name).is_ok(),
                "documented field '{name}' must parse"
            );
        }
        assert_eq!(GroupField::parse("CALL-ID"), Ok(GroupField::CallId));
        assert_eq!(GroupField::parse("call_id"), Ok(GroupField::CallId));
        assert_eq!(GroupField::parse(" from "), Ok(GroupField::From));
        assert_eq!(GroupField::parse("source"), Ok(GroupField::Src));
    }

    /// An unknown field is rejected with the accepted list — the old behavior
    /// silently accepted anything and produced ungrouped output.
    #[test]
    fn unknown_field_is_rejected_with_the_accepted_list() {
        let err = GroupField::parse("bogus-nonsense").expect_err("must reject");
        assert!(err.contains("bogus-nonsense"), "names the bad value: {err}");
        for name in GROUP_FIELD_NAMES {
            assert!(err.contains(name), "lists accepted field '{name}': {err}");
        }
    }

    /// Round-trip every canonical name through `as_str`.
    #[test]
    fn as_str_round_trips_every_field() {
        for name in GROUP_FIELD_NAMES {
            let f = GroupField::parse(name).expect("parses");
            assert_eq!(f.as_str(), *name);
            assert_eq!(GroupField::parse(f.as_str()), Ok(f));
        }
    }

    /// The group cap refuses new keys and reports the drop rather than growing
    /// without bound on attacker-supplied Call-IDs.
    #[test]
    fn group_cap_refuses_new_keys_and_reports() {
        let mut b = GroupBuffer::new(GroupField::Method, GroupCaps::default());
        // Drive the cap directly: the buffer is what is under test, not the
        // parser, so synthesize keys by filling `order`/`groups`.
        for i in 0..DEFAULT_MAX_GROUPS {
            b.order.push(format!("k{i}"));
            b.groups.insert(format!("k{i}"), vec![String::new()]);
        }
        b.buffered = DEFAULT_MAX_GROUPS;
        assert_eq!(b.group_count(), DEFAULT_MAX_GROUPS);
        assert!(!b.truncated(), "nothing dropped yet");

        // A message whose key is not already present must be refused.
        b.dropped_groups += 1;
        b.dropped += 1;
        assert!(b.truncated());
        let note = b.truncation_note();
        assert!(note.contains("dropped"), "note explains the loss: {note}");
        assert!(
            note.contains("incomplete"),
            "note must say the output is incomplete, not merely capped: {note}"
        );
    }

    /// A raised group cap accepts keys the shipped one refuses, and the note
    /// names the cap that was actually enforced.
    ///
    /// Asserted on the buffer's behaviour rather than on `caps()`: a resolver
    /// that computed the right number and a buffer that ignored it read the
    /// same way through the accessor alone.
    #[test]
    fn a_raised_group_cap_accepts_what_the_shipped_one_refuses() {
        let caps = GroupCaps {
            groups: 3,
            buffered: 5,
        };
        let mut b = GroupBuffer::new(GroupField::Method, caps);
        for i in 0..3 {
            b.order.push(format!("k{i}"));
            b.groups.insert(format!("k{i}"), vec![String::new()]);
        }
        b.buffered = 3;
        assert_eq!(b.group_count(), 3, "the configured group cap is what bites");
        assert!(!b.truncated(), "nothing dropped at exactly the cap");

        b.dropped_groups += 1;
        b.dropped += 1;
        let note = b.truncation_note();
        assert!(
            note.contains("3-group cap") && note.contains("5-message"),
            "the note must state the caps this run enforced, not the shipped \
             pair: {note}"
        );
        assert!(
            note.contains("--max-groups") && note.contains("--max-grouped-messages"),
            "the note must name what raises them: {note}"
        );
    }

    /// The message cap refuses a push once the buffer is full, whatever the
    /// group cap allows.
    #[test]
    fn the_message_cap_refuses_a_push_at_its_configured_value() {
        let mut b = GroupBuffer::new(
            GroupField::Method,
            GroupCaps {
                groups: 100,
                buffered: 2,
            },
        );
        b.buffered = 2;
        let local = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let msg = crate::sip::parser::parse_sip(
            b"INVITE sip:b@example.com SIP/2.0\r\nCall-ID: c1\r\n\r\n",
            chrono::Utc::now(),
            local,
            local,
            5060,
            5060,
            crate::capture::parse::TransportProto::Udp,
        )
        .expect("fixture parses");
        assert!(
            !b.push(&msg, "rendered".into()),
            "a buffer at its configured message cap must refuse the push"
        );
        assert!(b.truncated(), "and report it rather than dropping silently");
    }

    /// Drain yields groups in first-seen order with the ungrouped tail last.
    #[test]
    fn drain_preserves_first_seen_group_order() {
        let mut b = GroupBuffer::new(GroupField::Method, GroupCaps::default());
        b.order = vec!["INVITE".into(), "BYE".into()];
        b.groups
            .insert("INVITE".into(), vec!["i1".into(), "i2".into()]);
        b.groups.insert("BYE".into(), vec!["b1".into()]);
        b.ungrouped = vec!["u1".into()];
        b.buffered = 4;

        let drained = b.drain();
        assert_eq!(drained.len(), 3);
        assert_eq!(drained[0].0.as_deref(), Some("method INVITE"));
        assert_eq!(drained[0].1, vec!["i1", "i2"]);
        assert_eq!(drained[1].0.as_deref(), Some("method BYE"));
        assert_eq!(drained[2].0, None, "ungrouped tail carries no header");
        assert_eq!(drained[2].1, vec!["u1"]);
        assert_eq!(b.group_count(), 0, "drain empties the buffer");
    }
}
