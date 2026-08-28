// SPDX-License-Identifier: MIT OR Apache-2.0

//! Which tools a run registers: the `core` and `full` profiles.
//!
//! Every registered tool's name, description and JSON schema is sent to the
//! client on `tools/list` and is then carried in the model's context for the
//! whole session. That is a fixed cost paid before the agent has asked
//! anything, and it scales with the surface rather than with the question. At
//! fifty tools it is already the largest single thing this server says.
//!
//! So `core` is not "the tools we like". It is the smallest set that can still
//! answer the question an operator actually arrives with — *what happened on
//! this call, and was it signaling or media* — end to end, without the agent
//! having to work around a missing step. A profile that cannot complete that
//! path is worse than no profile at all: the agent discovers the gap mid-task
//! and improvises, which is how a truncated page becomes a confident verdict.
//!
//! `full` remains the default. Shrinking the surface silently would change
//! what every existing client can do at upgrade time.

/// How much of the tool surface a run registers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ToolProfile {
    /// Every tool the build carries. The default, and what every release
    /// before profiles existed did.
    #[default]
    Full,
    /// The [`CORE_TOOLS`] subset, for a client whose context window makes
    /// fifty schemas expensive.
    Core,
}

impl ToolProfile {
    /// Parse the profile named on the command line.
    ///
    /// # Arguments
    ///
    /// * `name` — `core` or `full`, matched exactly.
    ///
    /// # Returns
    ///
    /// `None` for any other spelling, which the caller reports by name rather
    /// than silently taking a default: an operator who typed `--mcp-tools
    /// minimal` asked for a smaller surface and would otherwise be handed the
    /// largest one.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "core" => Some(Self::Core),
            "full" => Some(Self::Full),
            _ => None,
        }
    }

    /// The name this profile is spelled with on the command line.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Core => "core",
        }
    }
}

/// The `core` profile: one path through a call, from "which calls are there"
/// to "here is the byte that proves it".
///
/// Each entry earns its place by being unreachable from the others:
///
/// * `capture_status` — every prompt on this server opens with it, because
///   every count below it is meaningless without knowing what was captured
///   and whether it is still filling.
/// * `list_dialogs` — the entry point. An agent with no way to enumerate
///   calls cannot start.
/// * `get_dialog` — the messages themselves, which is what a signaling
///   question is ultimately answered from.
/// * `triage_call` — the one tool that says "signaling, media, both or
///   neither" in a single call. Without it an agent reconstructs that verdict
///   from several tools and gets it wrong at the margins.
/// * `rtp_stats` — the media side of that verdict, with the quality figures
///   under it.
/// * `find_problems` — the "show me what is broken" sweep, which is how an
///   operator with no Call-ID starts.
/// * `aggregate_dialogs` — the only way to answer a "how many, by what"
///   question without paging the whole store through the model. Dropping it
///   does not save context, it spends it.
/// * `search_messages` — the free-text way in, for the operator who has a
///   number or a User-Agent and nothing else.
///
/// Deliberately NOT here: everything that answers a follow-up question an
/// agent only reaches after the path above (`compare_dialogs`, `explain_rule`,
/// `get_sdp_timeline`), everything that writes or replaces state
/// (`open_capture`, `export_capture`, `shutdown_server`), and every tool whose
/// job another one on this list already covers less precisely. A `core` client
/// that needs one of them changes the flag; that is a decision, and it is
/// visible.
pub const CORE_TOOLS: &[&str] = &[
    "aggregate_dialogs",
    "capture_status",
    "find_problems",
    "get_dialog",
    "list_dialogs",
    "rtp_stats",
    "search_messages",
    "triage_call",
];

/// Which of `registered` this profile does not carry.
///
/// Takes the names the router actually holds rather than deriving the answer
/// from [`CORE_TOOLS`] alone, so a core name that no longer matches a
/// registered tool removes nothing instead of silently pretending to. A build
/// without the `mcp-http` feature, for instance, registers a different set.
///
/// # Arguments
///
/// * `profile` — the profile the operator asked for.
/// * `registered` — every tool name currently in the router.
///
/// # Returns
///
/// The names to remove, in the order they were given. Empty for
/// [`ToolProfile::Full`], which removes nothing by construction rather than by
/// listing everything.
#[must_use]
pub fn excluded(profile: ToolProfile, registered: &[String]) -> Vec<String> {
    match profile {
        ToolProfile::Full => Vec::new(),
        ToolProfile::Core => registered
            .iter()
            .filter(|name| !CORE_TOOLS.contains(&name.as_str()))
            .cloned()
            .collect(),
    }
}

/// Core names that no registered tool answers to.
///
/// The rot this catches is one-directional and silent: rename a tool and
/// `excluded` keeps working — it removes everything not on the list, and the
/// renamed tool is simply no longer on it — so `core` quietly loses a tool it
/// was built around and nothing fails. Comparing the two sets is the only way
/// to see that.
///
/// # Arguments
///
/// * `registered` — every tool name currently in the router.
///
/// # Returns
///
/// Core names with no matching route, sorted; empty when the profile is
/// intact.
#[must_use]
pub fn orphaned_core_tools(registered: &[String]) -> Vec<&'static str> {
    let mut missing: Vec<&'static str> = CORE_TOOLS
        .iter()
        .filter(|core| !registered.iter().any(|r| r == *core))
        .copied()
        .collect();
    missing.sort_unstable();
    missing
}

/// Tests for profile parsing and the exclusion rule.
#[cfg(test)]
mod tests {
    use super::*;

    /// The two spellings parse and nothing else does.
    #[test]
    fn only_core_and_full_parse() {
        assert_eq!(ToolProfile::parse("core"), Some(ToolProfile::Core));
        assert_eq!(ToolProfile::parse("full"), Some(ToolProfile::Full));
        assert_eq!(
            ToolProfile::parse("minimal"),
            None,
            "an unknown profile must be refused rather than defaulted"
        );
        assert_eq!(
            ToolProfile::parse("Core"),
            None,
            "the flag's vocabulary is exact"
        );
    }

    /// `full` removes nothing, whatever is registered.
    #[test]
    fn full_excludes_nothing() {
        let registered: Vec<String> = ["list_dialogs", "shutdown_server", "export_capture"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        assert!(excluded(ToolProfile::Full, &registered).is_empty());
    }

    /// `core` removes exactly the registered names that are not core, and
    /// keeps the ones that are.
    #[test]
    fn core_excludes_everything_outside_the_core_set() {
        let registered: Vec<String> = ["list_dialogs", "shutdown_server", "triage_call"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let out = excluded(ToolProfile::Core, &registered);
        assert_eq!(out, vec!["shutdown_server".to_string()]);
    }

    /// A core name the router does not carry removes nothing. The profile
    /// filters what is there; it never invents a route to delete.
    #[test]
    fn a_core_name_that_is_not_registered_removes_nothing() {
        let registered: Vec<String> = vec!["shutdown_server".to_string()];
        assert_eq!(
            excluded(ToolProfile::Core, &registered),
            vec!["shutdown_server".to_string()],
            "the one registered non-core name is removed and nothing else"
        );
    }

    /// A renamed core tool is reported, which is the failure `excluded` alone
    /// cannot see.
    #[test]
    fn a_core_name_with_no_route_is_reported_as_orphaned() {
        let registered: Vec<String> = CORE_TOOLS
            .iter()
            .filter(|n| **n != "triage_call")
            .map(|n| (*n).to_string())
            .collect();
        assert_eq!(orphaned_core_tools(&registered), vec!["triage_call"]);

        let all: Vec<String> = CORE_TOOLS.iter().map(|n| (*n).to_string()).collect();
        assert!(
            orphaned_core_tools(&all).is_empty(),
            "an intact profile reports nothing"
        );
    }

    /// The core set carries no duplicate, which would make its size a lie.
    #[test]
    fn the_core_set_has_no_duplicates() {
        let unique: std::collections::BTreeSet<&&str> = CORE_TOOLS.iter().collect();
        assert_eq!(unique.len(), CORE_TOOLS.len(), "duplicate in CORE_TOOLS");
    }
}
