//! Reference material served over MCP's `resources` primitive.
//!
//! An agent that does not know the filter DSL discovers it by guessing and
//! collecting `-32602` until it converges. Every one of those round trips costs
//! a model call and teaches the agent nothing durable. Serving the grammar
//! makes it a single read.
//!
//! **The content is `include_str!` of the published documentation**, not a
//! second copy written for machines. A separate machine-readable grammar is a
//! second thing to keep true, and the one that drifts is always the one no
//! human reads. This way the page a person opens and the bytes an agent reads
//! are the same bytes, and a doc edit updates both.
//!
//! These resources do NOT require `--mcp-file-root`. That flag exists to gate
//! access to CAPTURES -- an operator's traffic. The DSL grammar is published on
//! a website. Gating it behind the capture-access flag would mean an agent
//! running against a live device, with no file root at all, has to guess at
//! syntax it could have read.

/// One piece of reference material.
pub struct Reference {
    /// URI an agent reads it back by.
    pub uri: &'static str,
    /// Short name shown in a resource listing.
    pub name: &'static str,
    /// What question this answers, so an agent can choose without reading all.
    pub description: &'static str,
    /// The bytes.
    pub text: &'static str,
}

/// The filter DSL grammar: fields, operators and the alias vocabulary.
const FILTER_DSL: &str = include_str!("../../docs/filter-dsl.md");
/// The SIP response-code registry sipnab explains from.
const RESPONSE_CODES: &str = include_str!("../../docs/sip-response-codes.md");
/// Which codecs carry a published impairment factor, and what that means for
/// a MOS number.
const MOS_AND_CODECS: &str = include_str!("../../docs/mos-and-codecs.md");

/// Everything served under `sipnab://reference/`.
///
/// Ordered by how often an agent needs it. The DSL comes first because every
/// filtering tool takes an expression in it, so it is the one an agent reaches
/// for before it can ask anything narrower than "all dialogs".
#[must_use]
pub fn all() -> Vec<Reference> {
    vec![
        Reference {
            uri: "sipnab://reference/filter-dsl",
            name: "Filter DSL grammar",
            description: "Fields, operators and alias names accepted by every `filter` parameter. Read \
                 this before composing an expression: an unknown field or a mistyped alias \
                 fails with invalid_params rather than matching nothing.",
            text: FILTER_DSL,
        },
        Reference {
            uri: "sipnab://reference/sip-response-codes",
            name: "SIP response-code registry",
            description: "What each SIP status code means, and which ones sipnab treats as a failure. \
                 The same registry `explain_response_code` answers from.",
            text: RESPONSE_CODES,
        },
        Reference {
            uri: "sipnab://reference/mos-and-codecs",
            name: "MOS and codec grounding",
            description: "Which codecs carry a published impairment factor, and why a MOS score over a \
                 codec without one is withheld rather than estimated. Read this before \
                 comparing MOS across calls that used different codecs.",
            text: MOS_AND_CODECS,
        },
    ]
}

/// Look one up by URI.
#[must_use]
pub fn find(uri: &str) -> Option<Reference> {
    all().into_iter().find(|r| r.uri == uri)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every reference carries content, and a real amount of it.
    ///
    /// `include_str!` of a path that exists but was emptied still compiles, so
    /// the failure this guards is a resource that lists, reads, and returns
    /// nothing -- which an agent cannot tell apart from a grammar with no rules.
    #[test]
    fn every_reference_carries_substantial_content() {
        for r in all() {
            assert!(
                r.text.len() > 500,
                "{} is {} bytes; a reference that short is either empty or a \
                 stub, and an agent reading it learns nothing while the server \
                 reports success",
                r.uri,
                r.text.len()
            );
        }
    }

    /// The DSL reference actually describes the DSL.
    ///
    /// Pins content, not size. Pointing `include_str!` at the wrong file still
    /// yields a large string, and a large wrong answer is worse than an error.
    #[test]
    fn the_dsl_reference_describes_the_filter_language() {
        let dsl = find("sipnab://reference/filter-dsl").expect("the DSL reference is served");
        assert!(
            dsl.text.contains("filter") || dsl.text.contains("DSL"),
            "the filter-dsl resource does not mention filtering; include_str! is \
             pointed at the wrong page"
        );
    }

    /// URIs are unique, so a read resolves to one answer.
    #[test]
    fn reference_uris_do_not_collide() {
        let mut seen = std::collections::BTreeSet::new();
        for r in all() {
            assert!(
                seen.insert(r.uri),
                "{} is served twice; `find` would return whichever came first \
                 and the other becomes unreachable",
                r.uri
            );
        }
    }

    /// An unknown URI resolves to nothing rather than to the first entry.
    #[test]
    fn an_unknown_uri_finds_nothing() {
        assert!(
            find("sipnab://reference/does-not-exist").is_none(),
            "an unknown reference must not fall through to a real one"
        );
    }
}
