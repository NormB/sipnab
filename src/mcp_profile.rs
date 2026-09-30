// SPDX-License-Identifier: MIT OR Apache-2.0

//! Which tools a run registers: bundles, tool names, and `full`.
//!
//! Outside the `mcp` feature, so the CLI and the config can check the names
//! in every build.
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
//!
//! An operator picks the surface with `--mcp-tools` or `[mcp] tools`: a list of
//! [`BUNDLES`], single tool names, custom bundles from `[mcp.bundles]`, or
//! `full`. Every tool is in exactly one built-in bundle, so the bundles add up
//! to `full` and no tool is reachable only by name. [`resolve`] turns the list
//! into a [`ToolSelection`] and refuses a name it does not know, listing the
//! valid ones: an operator who asked for a smaller surface and mistyped must
//! not be handed the largest one.

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
/// * `get_capture_report` — the capture-level verdict (clean, problems,
///   inconclusive) with the findings behind it, the answer an agent acts on
///   before it opens any one call. Without it a core box could list calls but
///   not say whether the capture as a whole is healthy, so the agent triage
///   in the client examples, run as cookbook recipe 55 deploys, failed with
///   "tool not found" (MCP-CORE-1).
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
    "get_capture_report",
    "get_dialog",
    "list_dialogs",
    "rtp_stats",
    "search_messages",
    "triage_call",
];

/// The built-in bundles, each a group of tools answering one kind of
/// question. Every tool is in exactly one of them.
pub const BUNDLES: &[(&str, &[&str])] = &[
    ("core", CORE_TOOLS),
    (
        "signaling",
        &[
            "await_condition",
            "check_codec_negotiation",
            "compare_dialogs",
            "explain_response_code",
            "explain_rule",
            "find_correlated",
            "generate_repro",
            "generate_wireshark_filter",
            "get_call_tree",
            "get_dialog_report",
            "get_message",
            "get_sdp_timeline",
            "group_dialogs",
            "lint_dialog",
            "render_ladder",
            "search_by_time",
            "tail_dialogs",
            "timeline",
            "validate_filter",
            "validate_message",
        ],
    ),
    (
        "captures",
        &[
            "build_evidence_package",
            "compare_captures",
            "decode_evidence",
            "export_capture",
            "find_in_captures",
            "list_captures",
            "open_capture",
            "save_findings",
            "show_evidence",
        ],
    ),
    (
        "security",
        &[
            "describe_endpoint",
            "diagnose_registration",
            "evaluate_expectations",
            "generate_fail2ban_rule",
            "security_findings",
            "top_talkers",
        ],
    ),
    (
        "media",
        &[
            "explain_attribution",
            "export_audio",
            "media_diagnostics",
            "reconcile_orphans",
        ],
    ),
    (
        "relay",
        &["decode_ng", "query_relay", "relay_compare", "relay_stats"],
    ),
    (
        "tfps",
        &[
            "actions_revert",
            "tfps_ban",
            "tfps_banned",
            "tfps_dropped",
            "tfps_labels",
            "tfps_status",
            "tfps_unban",
        ],
    ),
    (
        "server",
        &[
            "capture_health",
            "hep_senders",
            "runtime_stats",
            "server_capabilities",
            "shutdown_server",
        ],
    ),
    ("vcon", &["export_vcon", "siprec_metadata", "validate_vcon"]),
    (
        "tls",
        &[
            "list_tls_libraries",
            "start_tls_capture",
            "stop_tls_capture",
        ],
    ),
];

/// The name that selects every tool the build carries.
pub const FULL: &str = "full";

/// Which tools a run registers.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ToolSelection {
    /// Every tool the build carries. The default.
    #[default]
    Full,
    /// Only these tools.
    Only {
        /// The names the operator gave, in order, for the handshake to repeat.
        asked: Vec<String>,
        /// The tools they select.
        tools: std::collections::BTreeSet<String>,
    },
}

impl ToolSelection {
    /// Whether this selection keeps `tool`.
    #[must_use]
    pub fn keeps(&self, tool: &str) -> bool {
        match self {
            Self::Full => true,
            Self::Only { tools, .. } => tools.contains(tool),
        }
    }

    /// The names the operator asked for, as they will be repeated to a client.
    #[must_use]
    pub fn asked(&self) -> Vec<String> {
        match self {
            Self::Full => vec![FULL.to_string()],
            Self::Only { asked, .. } => asked.clone(),
        }
    }
}

/// The built-in bundle named `name`.
#[must_use]
pub fn bundle(name: &str) -> Option<&'static [&'static str]> {
    BUNDLES.iter().find(|(n, _)| *n == name).map(|(_, t)| *t)
}

/// Whether `name` is a tool some built-in bundle holds.
#[must_use]
pub fn is_tool(name: &str) -> bool {
    BUNDLES.iter().any(|(_, tools)| tools.contains(&name))
}

/// Turn the operator's list into a selection.
///
/// # Arguments
///
/// * `asked` — names from `--mcp-tools` (comma-split) or `[mcp] tools`: built-in
///   bundles, tool names, custom bundles, or `full`.
/// * `custom` — `[mcp.bundles]`: a name for a list of tool and built-in bundle
///   names.
///
/// # Errors
///
/// A message naming the setting and the offending name when the list is
/// empty, holds an empty or unknown name, or a custom bundle is empty, reuses a
/// built-in name, or names something other than a tool or a built-in bundle.
pub fn resolve(
    asked: &[String],
    custom: &std::collections::BTreeMap<String, Vec<String>>,
) -> Result<ToolSelection, String> {
    use std::collections::BTreeSet;

    let bundle_names = || {
        BUNDLES
            .iter()
            .map(|(n, _)| *n)
            .chain(custom.keys().map(String::as_str))
            .collect::<Vec<_>>()
            .join(", ")
    };
    // A built-in bundle or one tool: the only things a custom bundle may hold.
    let built_in = |name: &str| -> Option<Vec<&'static str>> {
        bundle(name).map(<[_]>::to_vec).or_else(|| {
            BUNDLES
                .iter()
                .flat_map(|(_, t)| t.iter())
                .find(|t| **t == name)
                .map(|t| vec![*t])
        })
    };

    for (name, members) in custom {
        if name == FULL || bundle(name).is_some() || is_tool(name) {
            return Err(format!(
                "[mcp.bundles] {name} reuses a built-in name; give the bundle another name"
            ));
        }
        if members.is_empty() {
            return Err(format!("[mcp.bundles] {name} is empty"));
        }
        for m in members {
            if built_in(m.trim()).is_none() {
                return Err(format!(
                    "[mcp.bundles] {name} names '{m}', which is not a tool or a built-in \
                     bundle ({}); a bundle cannot hold `full` or another custom bundle",
                    BUNDLES
                        .iter()
                        .map(|(n, _)| *n)
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
        }
    }

    if asked.is_empty() {
        return Err(format!(
            "names no tools; name bundles ({}) or {FULL}",
            bundle_names()
        ));
    }
    let mut tools = BTreeSet::new();
    let mut names = Vec::new();
    for raw in asked {
        let name = raw.trim();
        if name.is_empty() {
            return Err("holds an empty name (two commas, or a trailing one)".to_string());
        }
        if name == FULL {
            return Ok(ToolSelection::Full);
        }
        if let Some(found) = built_in(name) {
            tools.extend(found.into_iter().map(str::to_string));
        } else if let Some(members) = custom.get(name) {
            for m in members {
                tools.extend(built_in(m.trim()).into_iter().flatten().map(str::to_string));
            }
        } else {
            return Err(format!(
                "unknown tool or bundle '{name}'; bundles: {}, or {FULL}; tool names are \
                 listed in the MCP tool reference",
                bundle_names()
            ));
        }
        if !names.iter().any(|n| n == name) {
            names.push(name.to_string());
        }
    }
    Ok(ToolSelection::Only {
        asked: names,
        tools,
    })
}

/// Which of `registered` this selection does not keep.
///
/// Takes the names the router actually holds, so a selected name the build
/// does not carry removes nothing instead of pretending to.
#[must_use]
pub fn excluded(selection: &ToolSelection, registered: &[String]) -> Vec<String> {
    registered
        .iter()
        .filter(|name| !selection.keeps(name))
        .cloned()
        .collect()
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

/// Tests for bundle resolution and the exclusion rule.
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn names(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_string()).collect()
    }

    fn only(sel: &ToolSelection) -> Vec<String> {
        match sel {
            ToolSelection::Full => panic!("expected a subset, got full"),
            ToolSelection::Only { tools, .. } => tools.iter().cloned().collect(),
        }
    }

    fn no_custom() -> BTreeMap<String, Vec<String>> {
        BTreeMap::new()
    }

    #[test]
    fn full_selects_everything_even_beside_other_names() {
        assert_eq!(
            resolve(&names(&["full"]), &no_custom()),
            Ok(ToolSelection::Full)
        );
        assert_eq!(
            resolve(&names(&["core", "full"]), &no_custom()),
            Ok(ToolSelection::Full)
        );
    }

    #[test]
    fn core_selects_exactly_the_core_set() {
        let sel = resolve(&names(&["core"]), &no_custom()).expect("core");
        let mut want = names(CORE_TOOLS);
        want.sort();
        assert_eq!(only(&sel), want);
    }

    #[test]
    fn bundles_and_tool_names_combine() {
        let sel = resolve(&names(&["relay", "get_sdp_timeline"]), &no_custom()).expect("ok");
        assert_eq!(
            only(&sel),
            names(&[
                "decode_ng",
                "get_sdp_timeline",
                "query_relay",
                "relay_compare",
                "relay_stats"
            ])
        );
        assert_eq!(sel.asked(), names(&["relay", "get_sdp_timeline"]));
    }

    #[test]
    fn names_are_trimmed_and_repeats_are_harmless() {
        let sel = resolve(
            &names(&[" tls ", "tls", "list_tls_libraries"]),
            &no_custom(),
        )
        .expect("ok");
        assert_eq!(only(&sel).len(), 3);
    }

    #[test]
    fn an_unknown_name_is_refused_with_the_valid_bundles() {
        let e = resolve(&names(&["core", "minimal"]), &no_custom()).expect_err("refused");
        assert!(e.contains("'minimal'"), "{e}");
        for (bundle, _) in BUNDLES {
            assert!(e.contains(bundle), "{bundle} missing from: {e}");
        }
    }

    #[test]
    fn names_are_case_sensitive() {
        assert!(resolve(&names(&["Core"]), &no_custom()).is_err());
    }

    #[test]
    fn an_empty_list_or_an_empty_name_is_refused() {
        assert!(resolve(&[], &no_custom()).is_err());
        let e = resolve(&names(&["core", ""]), &no_custom()).expect_err("empty");
        assert!(e.contains("empty"), "{e}");
    }

    #[test]
    fn a_custom_bundle_holds_tools_and_built_in_bundles() {
        let mut custom = no_custom();
        custom.insert("triage".into(), names(&["tls", "get_sdp_timeline"]));
        let sel = resolve(&names(&["triage"]), &custom).expect("ok");
        assert_eq!(
            only(&sel),
            names(&[
                "get_sdp_timeline",
                "list_tls_libraries",
                "start_tls_capture",
                "stop_tls_capture"
            ])
        );
    }

    #[test]
    fn a_custom_bundle_defined_but_not_asked_for_selects_nothing() {
        let mut custom = no_custom();
        custom.insert("triage".into(), names(&["tls"]));
        let sel = resolve(&names(&["relay"]), &custom).expect("ok");
        assert!(!sel.keeps("start_tls_capture"));
    }

    #[test]
    fn a_custom_bundle_may_not_reuse_a_built_in_or_tool_name() {
        for clash in ["core", "full", "get_dialog"] {
            let mut custom = no_custom();
            custom.insert(clash.into(), names(&["get_dialog"]));
            let e = resolve(&names(&["core"]), &custom).expect_err(clash);
            assert!(e.contains(clash) && e.contains("[mcp.bundles]"), "{e}");
        }
    }

    #[test]
    fn a_custom_bundle_that_is_empty_or_names_the_unknown_is_refused() {
        let mut custom = no_custom();
        custom.insert("mine".into(), Vec::new());
        assert!(resolve(&names(&["core"]), &custom).is_err(), "empty bundle");

        let mut custom = no_custom();
        custom.insert("mine".into(), names(&["no_such_tool"]));
        let e = resolve(&names(&["core"]), &custom).expect_err("unknown member");
        assert!(e.contains("no_such_tool") && e.contains("mine"), "{e}");
    }

    #[test]
    fn a_custom_bundle_may_not_name_another_custom_bundle_or_full() {
        let mut custom = no_custom();
        custom.insert("a".into(), names(&["core"]));
        custom.insert("b".into(), names(&["a"]));
        assert!(resolve(&names(&["b"]), &custom).is_err(), "nested custom");

        let mut custom = no_custom();
        custom.insert("a".into(), names(&["full"]));
        assert!(
            resolve(&names(&["a"]), &custom).is_err(),
            "full inside a bundle"
        );
    }

    #[test]
    fn full_excludes_nothing_and_a_subset_excludes_the_rest() {
        let registered = names(&["list_dialogs", "shutdown_server", "triage_call"]);
        assert!(excluded(&ToolSelection::Full, &registered).is_empty());
        let core = resolve(&names(&["core"]), &no_custom()).expect("core");
        assert_eq!(excluded(&core, &registered), names(&["shutdown_server"]));
    }

    #[test]
    fn every_tool_is_in_exactly_one_built_in_bundle() {
        let mut seen = std::collections::BTreeMap::new();
        for (bundle, tools) in BUNDLES {
            for t in *tools {
                if let Some(first) = seen.insert(*t, *bundle) {
                    panic!("{t} is in both {first} and {bundle}");
                }
            }
        }
    }

    #[test]
    fn bundle_names_are_not_tool_names_or_full() {
        for (bundle, _) in BUNDLES {
            assert!(!is_tool(bundle), "{bundle} is also a tool name");
            assert_ne!(*bundle, FULL);
        }
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
        assert!(orphaned_core_tools(&all).is_empty());
    }

    /// MCP-CORE-1: core carries the capture-level report.
    #[test]
    fn the_core_set_can_answer_whether_the_capture_is_healthy() {
        assert!(CORE_TOOLS.contains(&"get_capture_report"));
    }
}
