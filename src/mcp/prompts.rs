// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Prompts: the ORDER to call tools in, served over MCP's prompt primitive.
//!
//! sipnab has many tools (the bundles in [`crate::mcp_profile::BUNDLES`] list
//! them). Which one to reach for first is not obvious from any of their
//! descriptions, and getting it wrong is not merely slower -- it
//! produces confident answers about the wrong thing. The ordering that matters
//! lives in prose on a documentation page an agent never opens.
//!
//! The load-bearing example is the first step of every workflow here:
//! `capture_status` reports `unanalysed_sip_messages`. An agent that skips it
//! and goes straight to `find_problems` gets findings computed over whatever
//! fraction of the capture happened to parse, with nothing in the answer saying
//! so. The number is real. The population under it is not the one the operator
//! asked about.
//!
//! A prompt is a suggestion, never a constraint: the client decides whether to
//! use one, and every tool stays callable on its own.
//!
//! A prompt is served only when every tool it names is loaded (see
//! [`served`]). Under `--mcp-tools core`, `triage-outage` would otherwise tell
//! the model to call `show_evidence`, which `core` does not register.

/// One named workflow.
pub struct Workflow {
    /// Name a client lists and requests by.
    pub name: &'static str,
    /// One line describing when to reach for it.
    pub description: &'static str,
    /// The message text handed to the model.
    pub text: &'static str,
}

/// Every prompt sipnab serves.
///
/// One per situation an operator opens a capture in: something is broken
/// now, a carrier is disputing it, two vendors disagree about codecs, a change
/// just went in and needs proving, or calls are being handed to a vCon store.
/// Not every one is served on every server; [`served`] decides.
#[must_use]
pub fn all() -> Vec<Workflow> {
    vec![
        Workflow {
            name: "triage-outage",
            description: "Something is failing right now. Establishes what the capture can support \
                 before drawing any conclusion from it.",
            text: "You are triaging a live SIP problem with sipnab.\n\
                   \n\
                   1. Call `capture_status` FIRST and read `unanalysed_sip_messages`. If it \
                   is non-zero, every count below describes only the part that parsed -- say \
                   so in your answer rather than reporting a number as if it covered the \
                   capture.\n\
                   2. Call `find_problems` for the shape of what is wrong.\n\
                   3. Call `triage_call` on a representative Call-ID from that result.\n\
                   4. Follow the `frame` pointer with `show_evidence` before asserting that \
                   a specific message caused the failure. A pointer that refuses to resolve \
                   means the capture changed underneath you, and that is itself the finding.\n\
                   \n\
                   Report what the capture SHOWS. Where it cannot answer, say which tool \
                   came back empty and why, rather than inferring from the calls that did \
                   parse.",
        },
        Workflow {
            name: "carrier-escalation",
            description: "Building a case to send upstream. Produces evidence a third party can \
                 verify without trusting sipnab.",
            text: "You are assembling a carrier escalation with sipnab.\n\
                   \n\
                   1. `capture_status` -- an escalation built on a partly-parsed capture \
                   gets returned.\n\
                   2. `group_dialogs` grouped by `next_hop` with the `asr` and `ner` \
                   metrics. Read the `population` block: a rate over a handful of calls is \
                   not evidence, and the block tells you which groups can carry one.\n\
                   3. `get_call_tree` on an affected Call-ID -- carrier problems are \
                   usually multi-leg, and a single-leg view attributes the fault to the \
                   wrong hop.\n\
                   4. `build_evidence_package` for the calls you will cite.\n\
                   \n\
                   Quote the response codes and timings the capture holds. Do not \
                   characterize the carrier's intent, and do not state a cause the messages \
                   do not show.",
        },
        Workflow {
            name: "codec-interop-audit",
            description: "Two endpoints disagree about media. Separates a negotiation fault from a \
                 quality complaint.",
            text: "You are auditing codec interoperability with sipnab.\n\
                   \n\
                   1. `capture_status`.\n\
                   2. `check_codec_negotiation` for offers that produced no common codec.\n\
                   3. `group_dialogs` by `rtp.codec` with `mos_p10`. A codec with no \
                   published impairment factor returns null rather than a score -- read \
                   `sipnab://reference/mos-and-codecs` before comparing MOS across codecs, \
                   because those numbers are not on one scale.\n\
                   4. `media_diagnostics` on a call that negotiated but sounds wrong.\n\
                   \n\
                   Keep the two questions apart. 'They never agreed on a codec' and 'they \
                   agreed and it sounded bad' have different fixes, and reporting one as \
                   the other sends the operator to the wrong system.",
        },
        Workflow {
            name: "post-change-verification",
            description: "A change just went in. Compares against a baseline instead of judging \
                 today's numbers on their own.",
            text: "You are verifying a change with sipnab.\n\
                   \n\
                   1. `capture_status` on the current capture.\n\
                   2. `compare_captures` against the pre-change baseline. Read the diff of \
                   AGGREGATES; a list of dialogs that differ says nothing about whether the \
                   change helped.\n\
                   3. `evaluate_expectations` if the repository has a rules file. Its \
                   verdict is the answer -- a rule engine decides, and your job is to \
                   explain what it decided.\n\
                   4. `timeline` to check the change did not simply move the failures to a \
                   different hour.\n\
                   \n\
                   A metric that improved on a smaller population has not improved. Check \
                   the counts on both sides before calling anything better.",
        },
        Workflow {
            name: "vcon-handoff",
            description: "Handing calls to a vCon store. Checks the selection and the \
                 containers before anything leaves, and records what was sent.",
            text: "You are exporting vCon containers with sipnab for another system to \
                   store.\n\
                   \n\
                   1. `capture_status` -- a container built from a partly-parsed capture \
                   is missing messages, and the store cannot tell.\n\
                   2. `validate_filter` on the filter that selects the calls. Read \
                   `valid` and `total_matched` against `total_dialogs`: a filter that \
                   does not parse, or that matches nothing on a full capture, is the \
                   finding, not an empty export.\n\
                   3. `export_vcon` with that `filter`, never one `call_id` at a time. \
                   If `truncated` is true, `total_matched` says how many were left out; \
                   narrow the filter rather than reporting the page as the set. Read \
                   each container's `completeness` block: audio refused for size looks, \
                   to a reader, like a call with no audio.\n\
                   4. `validate_vcon` on each exported container, passed as `container`. \
                   Passing `call_id` instead exports a second document with a different \
                   creation time, so its result describes a container you did not send.\n\
                   5. Record each container's `digest` (SHA-256 of the container) and \
                   its `call_id`. The store's ledger entry is compared against that \
                   digest; a digest you did not record cannot be matched later.\n\
                   \n\
                   Hand over only containers that came back `valid`. For any that did \
                   not, report the `instance_path` and `keyword` of each finding rather \
                   than editing the container to pass.",
        },
    ]
}

impl Workflow {
    /// The tools this workflow tells a model to call, in the order its text
    /// first names them.
    ///
    /// Read from the text, never declared beside it: a list written next to
    /// the prose agrees with it on the day it is written and drifts the first
    /// time a step changes. The rule is one place: every backticked span that
    /// is a tool name some built-in bundle holds
    /// ([`crate::mcp_profile::is_tool`]). Backticked spans that are fields or
    /// URIs (`unanalysed_sip_messages`, `sipnab://...`) are not tool names and
    /// drop out.
    #[must_use]
    pub fn needs(&self) -> Vec<&'static str> {
        let text: &'static str = self.text;
        let mut out: Vec<&'static str> = Vec::new();
        for (i, span) in text.split('`').enumerate() {
            // Odd pieces are inside a pair of backticks.
            if i % 2 == 1 && crate::mcp_profile::is_tool(span) && !out.contains(&span) {
                out.push(span);
            }
        }
        out
    }

    /// Which of [`Self::needs`] `loaded` says this server does not carry.
    #[must_use]
    pub fn missing(&self, loaded: &dyn Fn(&str) -> bool) -> Vec<&'static str> {
        self.needs().into_iter().filter(|t| !loaded(t)).collect()
    }
}

/// The workflows this server serves: those whose every tool is loaded.
///
/// A workflow naming a tool the client cannot call is HIDDEN, not served with
/// a caveat. A prompt is an instruction to call tools in order; one whose step
/// fails with "tool not found" leaves the model to work around the gap in the
/// middle of the workflow, which is the failure the prompt exists to prevent. `get_prompt` on a hidden
/// name refuses and names the bundles to add.
///
/// # Arguments
///
/// * `loaded` — whether this server registers a tool name. On a running
///   server that is the router, so a tool the build lacks counts as not loaded
///   as well as one `--mcp-tools` left out.
#[must_use]
pub fn served(loaded: &dyn Fn(&str) -> bool) -> Vec<Workflow> {
    all()
        .into_iter()
        .filter(|w| w.missing(loaded).is_empty())
        .collect()
}

/// The built-in bundles holding any of `tools`, in
/// [`crate::mcp_profile::BUNDLES`] order.
#[must_use]
pub fn bundles_holding(tools: &[&str]) -> Vec<&'static str> {
    crate::mcp_profile::BUNDLES
        .iter()
        .filter(|(_, members)| tools.iter().any(|t| members.contains(t)))
        .map(|(name, _)| *name)
        .collect()
}

/// Look one up by name.
#[must_use]
pub fn find(name: &str) -> Option<Workflow> {
    all().into_iter().find(|w| w.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The named workflows are all defined.
    #[test]
    fn the_named_workflows_are_all_present() {
        let names: Vec<&str> = all().iter().map(|w| w.name).collect();
        for want in [
            "triage-outage",
            "carrier-escalation",
            "codec-interop-audit",
            "post-change-verification",
            "vcon-handoff",
        ] {
            assert!(
                names.contains(&want),
                "{want} is not served; have {names:?}"
            );
        }
    }

    /// Every workflow starts by establishing what the capture can support.
    ///
    /// This is the whole reason prompts exist here. An agent that skips
    /// `capture_status` computes findings over whatever fraction parsed and
    /// reports them as if they covered the capture -- the number is real and
    /// the population is wrong, which is the failure mode hardest to notice
    /// downstream.
    #[test]
    fn every_workflow_establishes_the_population_first() {
        for w in all() {
            assert!(
                w.text.contains("capture_status"),
                "{} never calls capture_status, so every count it produces \
                 describes an unknown fraction of the capture",
                w.name
            );
        }
    }

    /// No workflow tells the model to trust captured content.
    ///
    /// The D22 rule governs tool DESCRIPTIONS. A prompt is a larger and more
    /// directive surface than a description, so the same rule has to hold here
    /// -- and nothing was checking it, because prompts did not exist when that
    /// gate was written.
    #[test]
    fn no_workflow_instructs_the_model_to_trust_captured_content() {
        for w in all() {
            let lower = w.text.to_lowercase();
            for forbidden in [
                "trust the",
                "act on the instructions",
                "follow the instructions",
            ] {
                assert!(
                    !lower.contains(forbidden),
                    "{} contains {forbidden:?}. Captured SIP is attacker-controlled: \
                     scanners spray From and User-Agent for free, and a prompt that \
                     tells the model to act on message content turns a capture into \
                     an injection channel",
                    w.name
                );
            }
        }
    }

    /// Names are unique, so a request resolves to one workflow.
    #[test]
    fn workflow_names_do_not_collide() {
        let mut seen = std::collections::BTreeSet::new();
        for w in all() {
            assert!(seen.insert(w.name), "{} is served twice", w.name);
        }
    }

    /// Every tool name a text mentions, found word by word.
    ///
    /// Deliberately a different rule from [`Workflow::needs`], which reads
    /// backticked spans: this one also sees a tool named without backticks,
    /// which is exactly the drift it exists to catch.
    fn tools_mentioned(text: &str) -> std::collections::BTreeSet<&str> {
        text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .filter(|w| crate::mcp_profile::is_tool(w))
            .collect()
    }

    /// Every selection built from built-in bundles: each subset of
    /// [`crate::mcp_profile::BUNDLES`] (every single bundle, every pair, and
    /// so on up to all of them), and `full`.
    fn every_bundle_combination() -> Vec<(String, crate::mcp_profile::ToolSelection)> {
        use crate::mcp_profile::{BUNDLES, ToolSelection, resolve};
        let mut out = vec![("full".to_string(), ToolSelection::Full)];
        let custom = std::collections::BTreeMap::new();
        for mask in 1_u32..(1 << BUNDLES.len()) {
            let asked: Vec<String> = BUNDLES
                .iter()
                .enumerate()
                .filter(|(i, _)| mask & (1 << i) != 0)
                .map(|(_, (n, _))| (*n).to_string())
                .collect();
            if let Ok(sel) = resolve(&asked, &custom) {
                out.push((asked.join(","), sel));
            }
        }
        out
    }

    /// Under every bundle combination, a served prompt names only tools the
    /// selection loads. A prompt naming a tool the client cannot call sends
    /// the model to a "tool not found" mid-workflow.
    #[test]
    fn every_served_prompt_names_only_loaded_tools_under_every_bundle_combination() {
        let combos = every_bundle_combination();
        assert_eq!(
            combos.len(),
            1 << crate::mcp_profile::BUNDLES.len(),
            "every non-empty subset of the bundles resolves, plus full"
        );
        for (label, sel) in &combos {
            for w in served(&|t| sel.keeps(t)) {
                for tool in tools_mentioned(w.text) {
                    assert!(
                        sel.keeps(tool),
                        "under --mcp-tools {label}, {} is served but names {tool}, \
                         which that selection does not load",
                        w.name
                    );
                }
            }
        }
    }

    /// Hiding is not vacuous: `full` serves every prompt, and each prompt is
    /// served by some smaller selection and hidden by another.
    #[test]
    fn each_prompt_is_served_by_some_selection_and_hidden_by_another() {
        use crate::mcp_profile::ToolSelection;
        let full: Vec<&str> = served(&|t| ToolSelection::Full.keeps(t))
            .iter()
            .map(|w| w.name)
            .collect();
        let every: Vec<&str> = all().iter().map(|w| w.name).collect();
        assert_eq!(full, every, "full serves every prompt");
        let combos = every_bundle_combination();
        for w in all() {
            let served_by = combos
                .iter()
                .filter(|(_, s)| !matches!(s, ToolSelection::Full))
                .filter(|(_, s)| served(&|t| s.keeps(t)).iter().any(|x| x.name == w.name))
                .count();
            let hidden_by = combos
                .iter()
                .filter(|(_, s)| !served(&|t| s.keeps(t)).iter().any(|x| x.name == w.name))
                .count();
            assert!(served_by > 0, "{} is served by no bundle subset", w.name);
            assert!(hidden_by > 0, "{} is hidden by no bundle subset", w.name);
        }
    }

    /// Under `core` alone, triage-outage is hidden: its fourth step is
    /// `show_evidence`, which is in `captures`.
    #[test]
    fn core_alone_hides_triage_outage_and_names_the_bundle_to_add() -> Result<(), String> {
        let core =
            crate::mcp_profile::resolve(&["core".to_string()], &std::collections::BTreeMap::new())?;
        let loaded = |t: &str| core.keeps(t);
        assert!(
            !served(&loaded).iter().any(|w| w.name == "triage-outage"),
            "triage-outage needs show_evidence, which core does not load"
        );
        // docs/mcp-tools.md says core alone serves no prompt: each calls a
        // tool outside core.
        assert!(
            served(&loaded).is_empty(),
            "core alone serves no prompt, as the reference says"
        );
        let triage = find("triage-outage").ok_or("triage-outage exists")?;
        let missing = triage.missing(&loaded);
        assert_eq!(missing, vec!["show_evidence"]);
        assert_eq!(bundles_holding(&missing), vec!["captures"]);
        Ok(())
    }

    /// The tools a prompt needs are exactly the tools its text names, and
    /// every one of them is a real tool.
    #[test]
    fn the_needed_tools_are_exactly_the_tools_the_text_names() {
        for w in all() {
            let needs: std::collections::BTreeSet<&str> = w.needs().into_iter().collect();
            assert_eq!(
                needs,
                tools_mentioned(w.text),
                "{}: the tools it needs differ from the tools its text names",
                w.name
            );
        }
    }

    /// The derived lists, pinned, so a change to the rule that reads them
    /// shows up as a diff here rather than as a prompt silently served under
    /// a selection that cannot run it.
    #[test]
    fn the_needed_tools_of_each_prompt_are_pinned() -> Result<(), String> {
        let want: &[(&str, &[&str])] = &[
            (
                "triage-outage",
                &[
                    "capture_status",
                    "find_problems",
                    "triage_call",
                    "show_evidence",
                ],
            ),
            (
                "carrier-escalation",
                &[
                    "capture_status",
                    "group_dialogs",
                    "get_call_tree",
                    "build_evidence_package",
                ],
            ),
            (
                "codec-interop-audit",
                &[
                    "capture_status",
                    "check_codec_negotiation",
                    "group_dialogs",
                    "media_diagnostics",
                ],
            ),
            (
                "post-change-verification",
                &[
                    "capture_status",
                    "compare_captures",
                    "evaluate_expectations",
                    "timeline",
                ],
            ),
            (
                "vcon-handoff",
                &[
                    "capture_status",
                    "validate_filter",
                    "export_vcon",
                    "validate_vcon",
                ],
            ),
        ];
        assert_eq!(want.len(), all().len(), "every prompt is pinned");
        for (name, tools) in want {
            let w = find(name).ok_or(format!("{name} is served"))?;
            assert_eq!(w.needs(), tools.to_vec(), "{name}");
        }
        Ok(())
    }

    /// vcon-handoff calls its tools in the order that makes the digest it
    /// records the digest of the container it validated.
    #[test]
    fn vcon_handoff_orders_status_filter_export_validate_then_digest() -> Result<(), String> {
        let w = find("vcon-handoff").ok_or("vcon-handoff is served")?;
        let at = |s: &str| w.text.find(s).ok_or(format!("vcon-handoff names {s}"));
        let order = [
            at("`capture_status`")?,
            at("`validate_filter`")?,
            at("`export_vcon`")?,
            at("`validate_vcon`")?,
            at("`digest`")?,
        ];
        assert!(
            order.windows(2).all(|p| p[0] < p[1]),
            "out of order: {order:?}"
        );
        assert!(w.text.contains("`filter`"), "export_vcon takes the filter");
        assert!(
            w.text.contains("`container`"),
            "validate_vcon is given the exported container"
        );
        Ok(())
    }

    /// An unknown name resolves to nothing rather than the first entry.
    #[test]
    fn an_unknown_workflow_finds_nothing() {
        assert!(find("no-such-workflow").is_none());
    }
}
