//! Prompts: the ORDER to call tools in, served over MCP's prompt primitive.
//!
//! sipnab has fifty-one tools. Which one to reach for first is not obvious from
//! any of their descriptions, and getting it wrong is not merely slower -- it
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
/// Four, matching the four situations an operator actually opens a capture in:
/// something is broken now, a carrier is disputing it, two vendors disagree
/// about codecs, or a change just went in and needs proving.
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
    ]
}

/// Look one up by name.
#[must_use]
pub fn find(name: &str) -> Option<Workflow> {
    all().into_iter().find(|w| w.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The four the backlog names are the four served.
    #[test]
    fn the_named_workflows_are_all_present() {
        let names: Vec<&str> = all().iter().map(|w| w.name).collect();
        for want in [
            "triage-outage",
            "carrier-escalation",
            "codec-interop-audit",
            "post-change-verification",
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

    /// An unknown name resolves to nothing rather than the first entry.
    #[test]
    fn an_unknown_workflow_finds_nothing() {
        assert!(find("no-such-workflow").is_none());
    }
}
