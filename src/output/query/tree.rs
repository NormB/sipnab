// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The legs of one call across B2BUA, SBC and PBX hops, as a tree.
//!
//! One answer, [`CallTree`], built by [`call_tree`]:
//! `GET /v1/dialogs/{call_id}/tree` serializes it and `--call-tree` prints
//! it. The walk is [`DialogStore::correlation_tree`], which the MCP
//! `get_call_tree` tool also reads: it follows identifier matches, records a
//! timing guess without walking through it, and stops at a leg cap.

use crate::output::ReportFormat;
use crate::sip::dialog_store::DialogStore;

/// One leg of a call tree: a dialog, and how the walk reached it. Follow
/// `call_id` to `/v1/dialogs/{call_id}` for the leg's detail.
#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct CallTreeLeg {
    /// Call-ID of this leg.
    pub call_id: String,
    /// Hops from the root. Zero for the root itself.
    pub depth: u32,
    /// The leg this one was correlated FROM. Null for the root.
    pub parent_call_id: Option<String>,
    /// Confidence of the edge from the parent, 0-100. Null for the root.
    #[cfg_attr(feature = "api", schema(minimum = 0, maximum = 100))]
    pub score: Option<u8>,
    /// Which strategy matched this edge. Null for the root.
    pub strategy: Option<String>,
    /// Whether the edge compared identifiers rather than guessing. Null for
    /// the root, which the caller named rather than the walk matching.
    pub identifier_match: Option<bool>,
    /// Whether the walk continued THROUGH this leg. False on a leg reached
    /// by a timing guess, and on any leg the cap cut the walk short of.
    pub followed: bool,
}

/// The tree of legs reachable from one call across a B2BUA, SBC or PBX.
#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct CallTree {
    /// Version of this response's shape.
    #[cfg_attr(feature = "api", schema(example = 1))]
    pub schema_version: u32,
    /// Call-ID the walk started from, echoed verbatim.
    pub root_call_id: String,
    /// Every leg found, ordered by depth then creation time.
    pub legs: Vec<CallTreeLeg>,
    /// Number of legs returned, root included.
    pub total_legs: usize,
    /// Deepest hop count reached.
    pub max_depth: u32,
    /// True when the row cap stopped the walk before it ran out of legs.
    pub truncated: bool,
    /// How many edges are timing guesses rather than identifier matches.
    pub heuristic_edges: usize,
    /// Total SIP messages across every leg.
    pub total_messages: usize,
    /// Earliest leg creation time in the tree, RFC 3339.
    pub first_activity: Option<String>,
    /// Latest leg update time in the tree, RFC 3339.
    pub last_activity: Option<String>,
    /// WHICH capture this answer came from, and which revision of its
    /// stores, stamped under the locks the answer was built with. A
    /// different `instance` from an earlier answer means a different
    /// capture. The same identity the MCP tool answering this question
    /// carries. `null` when nobody told this server what it is attached to.
    #[cfg_attr(
        feature = "api",
        schema(value_type = Option<crate::output::api::schema::CaptureIdentity>)
    )]
    pub capture_identity: Option<crate::provenance::CaptureEtag>,
}

/// The tree of legs reachable from `call_id`, at most `max_legs` of them.
///
/// `None` when the store holds no dialog with that Call-ID: REST answers 404
/// and `--call-tree` exits 1, so an answer always names a real call.
#[must_use]
pub fn call_tree(
    ds: &DialogStore,
    call_id: &str,
    max_legs: usize,
    capture_identity: Option<crate::provenance::CaptureEtag>,
) -> Option<CallTree> {
    let tree = ds.correlation_tree(call_id, max_legs)?;
    let legs: Vec<CallTreeLeg> = tree
        .legs
        .iter()
        .map(|leg| CallTreeLeg {
            call_id: leg.call_id.clone(),
            depth: leg.depth,
            parent_call_id: leg.parent_call_id.clone(),
            score: leg.score,
            strategy: leg.strategy.map(str::to_string),
            identifier_match: leg.identifier_match,
            followed: leg.followed,
        })
        .collect();
    Some(CallTree {
        schema_version: 1,
        root_call_id: call_id.to_string(),
        total_legs: legs.len(),
        legs,
        max_depth: tree.max_depth,
        truncated: tree.truncated,
        heuristic_edges: tree.heuristic_edges,
        total_messages: tree.total_messages,
        first_activity: tree.first_activity.map(|t| t.to_rfc3339()),
        last_activity: tree.last_activity.map(|t| t.to_rfc3339()),
        capture_identity,
    })
}

/// The tree as a table: a line naming the root, the legs, the depth, the
/// messages and the timing guesses; one row per leg, indented two spaces a
/// hop, with the strategy, the score, whether it was an identifier match or a
/// guess, and whether the walk went on through it; and a line when the cap
/// cut the walk short.
#[must_use]
pub fn render(answer: &CallTree, format: ReportFormat) -> String {
    let mut out = format!(
        "Call tree from {}: {}, depth {}, {}, {}\n",
        answer.root_call_id,
        super::plural(answer.total_legs as u64, "leg"),
        answer.max_depth,
        super::plural(answer.total_messages as u64, "message"),
        super::plural(answer.heuristic_edges as u64, "timing guess"),
    );
    let rows: Vec<Vec<String>> = answer
        .legs
        .iter()
        .map(|leg| {
            let indent = "  ".repeat(usize::try_from(leg.depth).unwrap_or(usize::MAX).min(32));
            vec![
                format!("{indent}{}", leg.call_id),
                leg.strategy.clone().unwrap_or_else(|| "root".to_string()),
                leg.score.map_or_else(|| "-".to_string(), |s| s.to_string()),
                match leg.identifier_match {
                    Some(true) => "identifier".to_string(),
                    Some(false) => "guess".to_string(),
                    None => "-".to_string(),
                },
                if leg.followed { "yes" } else { "no" }.to_string(),
            ]
        })
        .collect();
    out.push_str(&super::table(
        format,
        &["Leg", "Strategy", "Score", "Match", "Followed"],
        &rows,
    ));
    if answer.truncated {
        out.push_str(&format!(
            "The walk stopped at {}; more legs may be reachable.\n",
            super::plural(answer.total_legs as u64, "leg"),
        ));
    }
    out
}
