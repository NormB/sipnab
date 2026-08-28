// SPDX-License-Identifier: MIT OR Apache-2.0

//! `completion/complete`: the vocabulary, served instead of guessed (PB3).
//!
//! An agent that does not know a Call-ID discovers one by calling
//! `list_dialogs` and reading a page it did not want. An agent that does not
//! know a rule identifier collects `-32602` until it converges. Both are round
//! trips that cost a model call and teach the agent nothing durable, and both
//! are what MCP's completion primitive exists to remove.
//!
//! # What the protocol will let sipnab complete
//!
//! `completion/complete` takes a `ref` that is either a PROMPT or a RESOURCE
//! TEMPLATE. There is no third case: the spec has no way to complete a tool
//! argument, so the backlog's framing of PB3 — "for `call_id`, filter aliases,
//! `security_findings.kinds` and the format enums" — is only reachable through
//! a template whose variable carries the same vocabulary. sipnab's prompts
//! deliberately take no arguments (see [`super::prompts`]), so every completion
//! this server can serve is a template variable, and [`all`] is the whole list.
//!
//! # The values are read, never listed
//!
//! [`Source`] names WHERE a variable's values come from, and the server reads
//! them at the moment it is asked. Nothing here holds a copy. A hardcoded
//! vocabulary would be a second place the truth lives, and the failure mode is
//! the bad one: an agent offered a Call-ID that is not in the capture spends a
//! call proving it, and concludes the capture is wrong rather than the
//! completion.
//!
//! # A template that lists must be readable
//!
//! Every entry here is a URI a client may construct and read. That is why the
//! table is small: a template is a promise that the URI resolves, and one that
//! only completes is a shape a client can build and never use.

/// One conformance rule's catalog entry, by identifier.
///
/// Lives here rather than beside the other resource URIs because it exists FOR
/// the completion: the rule catalog is a fixed vocabulary an agent has to
/// spell exactly, which is precisely the case completions are for.
pub const LINT_RULE_URI_PREFIX: &str = "sipnab://lint/";

/// Most values one completion response may carry.
///
/// The MCP-specified ceiling, restated here because the response type refuses
/// to be built past it: a server that returned more would fail to answer at
/// all rather than answer with too much.
pub const MAX_VALUES: usize = 100;

/// Where a template variable's candidate values are read from.
///
/// Every variant is a LIVE read. None of them is a list written down here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// Call-IDs the loaded capture currently holds.
    ///
    /// The one that moves while the client is typing, and the reason this
    /// module reads rather than stores.
    CallIds,
    /// Identifiers from the conformance rule catalog (`sip::lint::RULES`).
    LintRules,
    /// The reference pages `super::reference::all` serves.
    ReferenceTopics,
    /// Filenames under `--mcp-file-root`.
    CaptureFiles,
}

/// One resource template, and the variable inside it a client can complete.
///
/// One variable per template on purpose. RFC 6570 allows several, and a
/// completion request names exactly one argument, so a template with two
/// variables needs a rule for which values apply to which name — a rule that
/// exists only in the handler and cannot be read off the table.
#[derive(Debug, Clone, Copy)]
pub struct Template {
    /// The RFC 6570 template a client fills in.
    pub uri_template: &'static str,
    /// Name shown in `resources/templates/list`.
    pub name: &'static str,
    /// What reading a URI built from this template returns.
    pub description: &'static str,
    /// MIME type every URI built from this template resolves to.
    pub mime_type: &'static str,
    /// The single variable inside `uri_template`, without the braces.
    pub variable: &'static str,
    /// Where this variable's values are read from.
    pub source: Source,
    /// Whether the template resolves only when `--mcp-file-root` is set.
    ///
    /// Advertising a template whose every URI would be refused is worse than
    /// advertising nothing: it tells an agent the capture files are reachable
    /// and lets it find out otherwise one call at a time.
    pub needs_file_root: bool,
}

/// Every resource template this server serves.
///
/// Ordered by how often an agent needs one. The dialog template comes first
/// because a Call-ID is the argument nearly every other tool takes, and the
/// one an agent cannot know in advance.
#[must_use]
pub fn all() -> Vec<Template> {
    vec![
        Template {
            uri_template: "sipnab://live/dialogs/{call_id}",
            name: "Live dialog by Call-ID",
            description: "One dialog from the loaded capture, rendered exactly as \
                 `list_dialogs` renders it. Complete `call_id` to get the Call-IDs the \
                 capture actually holds right now rather than paging a list to find one.",
            mime_type: "application/json",
            variable: "call_id",
            source: Source::CallIds,
            needs_file_root: false,
        },
        Template {
            uri_template: "sipnab://lint/{rule_id}",
            name: "Conformance rule by identifier",
            description: "The catalog entry behind one conformance rule identifier: its \
                 title, severity, basis, and the RFC section it reads from. The same \
                 entry `explain_rule` answers from.",
            mime_type: "application/json",
            variable: "rule_id",
            source: Source::LintRules,
            needs_file_root: false,
        },
        Template {
            uri_template: "sipnab://reference/{topic}",
            name: "Reference page by topic",
            description: "One of the reference pages `resources/list` names: the filter DSL \
                 grammar, the SIP response-code registry, or the MOS and codec grounding.",
            mime_type: "text/markdown",
            variable: "topic",
            source: Source::ReferenceTopics,
            needs_file_root: false,
        },
        Template {
            uri_template: "sipnab:///{filename}",
            name: "Capture file by name",
            description: "One file under --mcp-file-root, read through the same single-component \
                 check and 8 MiB ceiling as `resources/read`. Only served when a file root \
                 is configured.",
            mime_type: "application/octet-stream",
            variable: "filename",
            source: Source::CaptureFiles,
            needs_file_root: true,
        },
    ]
}

/// Look one up by its exact template string.
///
/// Exact, not prefix. A `ref/resource` carries a template URI, and matching
/// loosely would let `sipnab://live/dialogs` — the concrete list resource —
/// resolve to the per-Call-ID template and complete an argument that URI does
/// not have.
#[must_use]
pub fn find(uri_template: &str) -> Option<Template> {
    all().into_iter().find(|t| t.uri_template == uri_template)
}

/// One completion answer.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Completion {
    /// The values to offer, at most [`MAX_VALUES`] of them.
    pub values: Vec<String>,
    /// How many matched in total, which may exceed what is returned.
    pub total: usize,
    /// Whether `total` exceeds what `values` carries.
    pub has_more: bool,
}

impl Completion {
    /// The answer for an argument nothing completes.
    ///
    /// Empty rather than an error, and this is the spec's rule as well as the
    /// kind one: a client asking to complete something unknown gets "no
    /// suggestions", not a failed request it has to recover from.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }
}

/// Whether `value` is offered when the client has typed `prefix`.
///
/// The ONE matching rule: case-insensitive, and anchored at the START. A
/// substring match would offer a Call-ID for typing its host part, and the
/// client could not then build a URI out of what it was offered.
///
/// Public because the server applies it while READING a large vocabulary
/// rather than after materialising it — the dialog store holds up to
/// `--max-dialogs` entries, and cloning all of them to discard most is work
/// nobody asked for. Two copies of this predicate would let a value one side
/// offered be dropped by the other, and the symptom would be a completion
/// count that disagrees with itself.
#[must_use]
pub fn matches(value: &str, prefix: &str) -> bool {
    prefix.is_empty() || value.to_lowercase().starts_with(&prefix.to_lowercase())
}

/// Narrow a live vocabulary to what the client has typed.
///
/// [`matches()`] decides what is offered; this deduplicates, sorts, and caps at
/// [`MAX_VALUES`]. `total` reports what actually matched, so a client sees
/// that the cap was reached rather than believing it has the whole set.
///
/// Applying [`matches()`] again here is deliberate rather than redundant: a
/// caller that already filtered passes a set this cannot narrow further, and a
/// caller that did not is still answered correctly. One rule, applied wherever
/// the vocabulary arrives from.
///
/// Sorting is not cosmetic: a `HashMap`-ordered answer would put a different
/// hundred in front of the same operator on every call, and the value they saw
/// last time would appear to have left the capture.
#[must_use]
pub fn narrow(values: impl IntoIterator<Item = String>, prefix: &str) -> Completion {
    let mut matched: Vec<String> = values.into_iter().filter(|v| matches(v, prefix)).collect();
    matched.sort_unstable();
    matched.dedup();
    let total = matched.len();
    matched.truncate(MAX_VALUES);
    Completion {
        values: matched,
        total,
        has_more: total > MAX_VALUES,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::live::{DIALOG_URI_PREFIX, Live};

    /// Every template names a variable that appears in it.
    ///
    /// The failure this guards is silent and total: a `variable` that does not
    /// occur in `uri_template` means every completion request for that
    /// template returns nothing, and the client cannot tell that from a
    /// capture with no matching values.
    #[test]
    fn every_template_variable_appears_in_its_template() {
        for t in all() {
            assert!(
                t.uri_template.contains(&format!("{{{}}}", t.variable)),
                "{} declares the variable '{}', which is not in the template",
                t.uri_template,
                t.variable
            );
        }
    }

    /// Template URIs are unique, so a `ref/resource` resolves to one entry.
    #[test]
    fn template_uris_do_not_collide() {
        let mut seen = std::collections::BTreeSet::new();
        for t in all() {
            assert!(
                seen.insert(t.uri_template),
                "{} is served twice",
                t.uri_template
            );
        }
    }

    /// Every source is reachable from some template.
    ///
    /// A `Source` variant no template names is a vocabulary the server can
    /// read and no client can ask for.
    #[test]
    fn every_source_is_reachable() {
        let sources: Vec<Source> = all().iter().map(|t| t.source).collect();
        for want in [
            Source::CallIds,
            Source::LintRules,
            Source::ReferenceTopics,
            Source::CaptureFiles,
        ] {
            assert!(sources.contains(&want), "{want:?} has no template");
        }
    }

    /// The dialog template builds URIs the live view can parse.
    ///
    /// The two are written in different modules, so nothing but a test holds
    /// them to one shape: a template a client fills in must produce a URI
    /// `resources/read` resolves.
    #[test]
    fn the_dialog_template_builds_a_readable_uri() {
        let t = find("sipnab://live/dialogs/{call_id}").expect("the dialog template is served");
        let uri = t.uri_template.replace("{call_id}", "abc@10.0.0.1");
        assert_eq!(
            Live::parse(&uri),
            Some(Live::Dialog("abc@10.0.0.1".to_string())),
            "the template produces a URI the live view does not recognize"
        );
        assert!(uri.starts_with(DIALOG_URI_PREFIX));
    }

    /// An unknown template resolves to nothing rather than the first entry.
    #[test]
    fn an_unknown_template_finds_nothing() {
        assert!(find("sipnab://live/dialogs").is_none());
        assert!(find("sipnab://nope/{x}").is_none());
    }

    /// An empty prefix offers everything.
    #[test]
    fn an_empty_prefix_offers_the_whole_vocabulary() {
        let c = narrow(["b".to_string(), "a".to_string()], "");
        assert_eq!(c.values, vec!["a".to_string(), "b".to_string()]);
        assert_eq!(c.total, 2);
        assert!(!c.has_more);
    }

    /// A prefix narrows, and does so case-insensitively.
    #[test]
    fn a_prefix_narrows_ignoring_case() {
        let vocab = [
            "SIP-3261-20-URI-BRACKETS".to_string(),
            "OBS-3264-6.1-PT-UNDECLARED".to_string(),
        ];
        let c = narrow(vocab.clone(), "sip-");
        assert_eq!(c.values, vec!["SIP-3261-20-URI-BRACKETS".to_string()]);
        let upper = narrow(vocab, "SIP-");
        assert_eq!(upper.values, c.values, "case must not change the answer");
    }

    /// A prefix nothing starts with yields nothing, not everything.
    #[test]
    fn a_prefix_matching_nothing_yields_nothing() {
        let c = narrow(["alpha".to_string()], "zzz");
        assert!(c.values.is_empty());
        assert_eq!(c.total, 0);
    }

    /// Matching is a PREFIX, not a substring.
    ///
    /// A substring match would offer a Call-ID for typing its host part, which
    /// a client cannot then complete into a valid URI.
    #[test]
    fn matching_is_anchored_at_the_start() {
        let c = narrow(["abc@host".to_string()], "host");
        assert!(
            c.values.is_empty(),
            "substring matching would offer a value the typed prefix cannot build"
        );
        assert!(!matches("abc@host", "host"));
    }

    /// `narrow` and `matches` are one rule, not two that agree today.
    ///
    /// The server filters large vocabularies with `matches` while reading them,
    /// so a value one side offers and the other drops would make a completion's
    /// `total` disagree with its own `values`.
    #[test]
    fn narrow_offers_exactly_what_matches_accepts() {
        let vocab: Vec<String> = ["abc@10.0.0.1", "ABX@10.0.0.2", "zzz@10.0.0.3", "", "a"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        for prefix in ["", "a", "A", "ab", "AB", "zzz", "nope"] {
            let mut by_rule: Vec<String> = vocab
                .iter()
                .filter(|v| matches(v, prefix))
                .cloned()
                .collect();
            by_rule.sort_unstable();
            by_rule.dedup();
            assert_eq!(
                narrow(vocab.clone(), prefix).values,
                by_rule,
                "narrow and matches disagree for prefix {prefix:?}"
            );
        }
    }

    /// The cap is enforced and reported rather than silently applied.
    #[test]
    fn past_the_cap_the_answer_says_there_is_more() {
        let many: Vec<String> = (0..MAX_VALUES + 25)
            .map(|i| format!("call-{i:04}"))
            .collect();
        let c = narrow(many, "");
        assert_eq!(c.values.len(), MAX_VALUES);
        assert_eq!(c.total, MAX_VALUES + 25);
        assert!(
            c.has_more,
            "a client told 100 of 125 is a client that knows to narrow; a \
             client told 100 believes it has them all"
        );
    }

    /// Duplicates collapse, so one dialog is offered once.
    #[test]
    fn duplicate_values_are_offered_once() {
        let c = narrow(["a".to_string(), "a".to_string(), "b".to_string()], "");
        assert_eq!(c.values, vec!["a".to_string(), "b".to_string()]);
        assert_eq!(c.total, 2);
    }

    /// The empty answer is empty, which is what an unknown argument gets.
    #[test]
    fn the_empty_answer_carries_nothing() {
        let c = Completion::none();
        assert!(c.values.is_empty());
        assert_eq!(c.total, 0);
        assert!(!c.has_more);
    }
}
