// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! What a live relay is holding right now: the Call-IDs it answers a `list`
//! with.
//!
//! [`ask`] puts the question and classifies the answer;
//! `GET /v1/relay/holdings` returns its [`Holdings::body`] and
//! `--relay-holdings` prints the same body under `--json`, or
//! [`Holdings::render`] as a table. The relay's own words are carried as it
//! wrote them, and an answer that is not a clean call list is one of the ST-S4
//! classifications (`unreachable`, `refused`, `suspect`), never an empty list.

use chrono::{DateTime, Utc};
use serde_json::{Value, json};

use crate::output::ReportFormat;
use crate::output::relay_statistics as fmt;
use crate::relay::reconcile::ReadOnlyRelay;
use crate::relay::types::{ControlReply, Enumeration};
use crate::security::transmit_guard::TransmitPermit;
use crate::stats_vocab::StatisticsOutcome;

/// The relay's answer to "what are you holding", or why there is none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Holdings {
    /// The relay answered with its call list.
    Held {
        /// The Call-IDs it returned, and whether it held more.
        calls: Enumeration,
        /// Which relay answered, from [`relay_label`].
        relay: String,
        /// When it was asked.
        obtained_at: DateTime<Utc>,
    },
    /// No clean call list came back.
    NotAnswered {
        /// The ST-S4 classification.
        outcome: StatisticsOutcome,
        /// What happened, naming the relay.
        detail: String,
    },
}

/// How an answer names the relay it came from: `relay (rtpengine at ADDR)`.
///
/// The one label every relay answer on REST carries.
#[must_use]
pub fn relay_label(relay: &dyn ReadOnlyRelay) -> String {
    format!("relay ({})", relay.describe())
}

/// Classify a fetch that brought back no trustworthy reply.
///
/// A reply that arrived and could not be trusted (a mismatched cookie) is
/// `suspect`, the answer's own problem; everything else is `unreachable`.
/// Classified through [`crate::relay::types::fetch_error_outcome`], so every
/// surface draws the same line.
#[must_use]
pub fn fetch_failure(label: &str, e: &anyhow::Error) -> (StatisticsOutcome, String) {
    match crate::relay::types::fetch_error_outcome(e) {
        StatisticsOutcome::Suspect => (
            StatisticsOutcome::Suspect,
            format!("{label}: {e}; the reply was discarded and not read"),
        ),
        _ => (
            StatisticsOutcome::Unreachable,
            format!("{label} did not answer ({e}); asked, nothing came back"),
        ),
    }
}

/// Ask `relay` which calls it holds, up to `max_calls`.
///
/// Transmits one `list` request, which is why it takes the run's permit.
#[must_use]
pub fn ask(
    relay: &dyn ReadOnlyRelay,
    permit: &TransmitPermit,
    max_calls: u32,
    now: DateTime<Utc>,
) -> Holdings {
    let label = relay_label(relay);
    match relay.list(permit, max_calls) {
        Ok(ControlReply::Calls(calls)) => Holdings::Held {
            calls,
            relay: label,
            obtained_at: now,
        },
        Ok(ControlReply::Refused { reason }) => Holdings::NotAnswered {
            outcome: StatisticsOutcome::Refused,
            detail: format!("{label}: {reason}"),
        },
        Ok(_) => Holdings::NotAnswered {
            outcome: StatisticsOutcome::Suspect,
            detail: "the relay answered with something other than a call list".to_string(),
        },
        Err(e) => {
            let (outcome, detail) = fetch_failure(&label, &e);
            Holdings::NotAnswered { outcome, detail }
        }
    }
}

impl Holdings {
    /// Whether the relay answered with a call list.
    #[must_use]
    pub const fn answered(&self) -> bool {
        matches!(self, Self::Held { .. })
    }

    /// The JSON `GET /v1/relay/holdings` returns: the call list wrapped
    /// `outcome: "ok"`, or the classification envelope.
    #[must_use]
    pub fn body(&self) -> Value {
        let text = match self {
            Self::Held {
                calls,
                relay,
                obtained_at,
            } => fmt::relay_rest_ok(
                &json!({
                    "kind": "calls",
                    "call_ids": calls.call_ids,
                    "truncated": calls.truncated,
                    "relay": relay,
                    "obtained_at": obtained_at.to_rfc3339(),
                    "origin": "asked",
                })
                .to_string(),
            ),
            Self::NotAnswered { outcome, detail } => fmt::relay_rest_outcome(*outcome, detail),
        };
        serde_json::from_str(&text).unwrap_or_else(|_| json!({ "outcome": "suspect" }))
    }

    /// The answer as text: which relay, when it was asked, how many calls it
    /// returned and, when that is as many as were asked for, that it may hold
    /// more, then a row per Call-ID. A classification is one line naming it.
    #[must_use]
    pub fn render(&self, format: ReportFormat) -> String {
        match self {
            Self::Held {
                calls,
                relay,
                obtained_at,
            } => {
                let mut out = format!(
                    "Holdings of {}, asked {}\n",
                    super::clean(relay),
                    obtained_at.to_rfc3339()
                );
                let held = calls.call_ids.len() as u64;
                if held == 0 {
                    out.push_str("The relay holds no calls.\n");
                    return out;
                }
                if calls.truncated {
                    out.push_str(&format!(
                        "{} returned, as many as asked for, so the relay may hold more.\n",
                        super::plural(held, "call")
                    ));
                } else {
                    out.push_str(&format!("{} held.\n", super::plural(held, "call")));
                }
                let rows: Vec<Vec<String>> =
                    calls.call_ids.iter().map(|id| vec![id.clone()]).collect();
                out.push_str(&super::table(format, &["Call-ID"], &rows));
                out
            }
            Self::NotAnswered { outcome, detail } => {
                format!("{}: {}\n", outcome.as_wire_str(), super::clean(detail))
            }
        }
    }
}

/// The branches the end-to-end tests in `tests/relay_fetch_end_to_end_test.rs`
/// do not reach: an empty list, the Markdown table, and a reply that is not a
/// call list. A scripted relay answers in memory, so nothing is sent.
#[cfg(test)]
mod tests {
    use super::*;

    type TestError = Box<dyn std::error::Error>;

    /// A relay that answers every `list` with one reply.
    struct Scripted(ControlReply);

    impl ReadOnlyRelay for Scripted {
        fn list(&self, _: &TransmitPermit, _: u32) -> anyhow::Result<ControlReply> {
            Ok(self.0.clone())
        }
        fn query(&self, _: &TransmitPermit, _: &str) -> anyhow::Result<ControlReply> {
            anyhow::bail!("this double answers only list")
        }
        fn statistics(&self, _: &TransmitPermit) -> anyhow::Result<ControlReply> {
            anyhow::bail!("this double answers only list")
        }
        fn call_statistics(&self, _: &TransmitPermit, _: &str) -> anyhow::Result<ControlReply> {
            anyhow::bail!("this double answers only list")
        }
        fn describe(&self) -> String {
            "a relay at 192.0.2.1:22222".to_string()
        }
    }

    fn permit() -> Result<TransmitPermit, TestError> {
        Ok(
            TransmitPermit::for_source(&crate::capture::CaptureSource::Live {
                device: "eth0".to_owned(),
            })
            .ok_or("a live source grants a permit")?,
        )
    }

    fn at() -> Result<DateTime<Utc>, TestError> {
        Ok(DateTime::parse_from_rfc3339("2026-10-25T12:00:00Z")?.with_timezone(&Utc))
    }

    fn listed(ids: &[&str]) -> ControlReply {
        ControlReply::Calls(Enumeration {
            call_ids: ids.iter().map(|s| (*s).to_string()).collect(),
            truncated: false,
        })
    }

    /// A relay holding nothing says so in words, and its body is an empty,
    /// complete list rather than a classification.
    #[test]
    fn an_empty_list_is_said_in_words_and_is_still_an_answer() -> Result<(), TestError> {
        let answer = ask(&Scripted(listed(&[])), &permit()?, 32, at()?);
        assert!(answer.answered());
        let text = answer.render(ReportFormat::Text);
        assert!(text.ends_with("The relay holds no calls.\n"), "{text}");
        assert!(!text.contains("Call-ID"), "no table for no rows: {text}");
        let body = answer.body();
        assert_eq!(body["outcome"], "ok");
        assert_eq!(body["call_ids"], json!([]));
        assert_eq!(body["truncated"], false);
        Ok(())
    }

    /// One call is singular, and Markdown gets a pipe table.
    #[test]
    fn one_call_is_singular_and_markdown_is_a_pipe_table() -> Result<(), TestError> {
        let answer = ask(&Scripted(listed(&["a@192.0.2.10"])), &permit()?, 32, at()?);
        let md = answer.render(ReportFormat::Markdown);
        assert!(md.contains("1 call held.\n"), "{md}");
        assert!(
            md.contains("| Call-ID |\n|---|\n| a@192.0.2.10 |\n"),
            "{md}"
        );
        assert!(
            md.starts_with(
                "Holdings of relay (a relay at 192.0.2.1:22222), asked 2026-10-25T12:00:00+00:00\n"
            ),
            "{md}"
        );
        Ok(())
    }

    /// A reply that is not a call list is `suspect`, never an empty list.
    #[test]
    fn a_reply_that_is_not_a_call_list_is_suspect() -> Result<(), TestError> {
        let answer = ask(
            &Scripted(ControlReply::Statistics(Vec::new())),
            &permit()?,
            32,
            at()?,
        );
        assert!(!answer.answered());
        let body = answer.body();
        assert_eq!(body["outcome"], "suspect");
        assert_eq!(body["responsibility"], "answer");
        assert!(body.get("call_ids").is_none(), "{body}");
        assert!(
            answer
                .render(ReportFormat::Text)
                .starts_with("suspect: the relay answered with something other than a call list"),
        );
        Ok(())
    }
}
