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
        /// Which relay was asked, from [`relay_label`].
        relay: String,
        /// The ST-S4 classification.
        outcome: StatisticsOutcome,
        /// What happened, naming the relay.
        detail: String,
    },
    /// With engine selection: each engine's own answer, default engine first.
    Several {
        /// Each engine's answer, a `Held` or a `NotAnswered`.
        engines: Vec<Holdings>,
        /// When they were asked.
        obtained_at: DateTime<Utc>,
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
    Holdings::from_list_reply(relay.list(permit, max_calls), relay_label(relay), now)
}

impl Holdings {
    /// What a `list` reply says about the holdings of the relay `label`: a
    /// call list is held, a refusal is the relay's own words, any other reply
    /// is `suspect`, and a failed fetch is classified by [`fetch_failure`].
    #[must_use]
    pub fn from_list_reply(
        reply: anyhow::Result<ControlReply>,
        label: String,
        now: DateTime<Utc>,
    ) -> Self {
        match reply {
            Ok(ControlReply::Calls(calls)) => Holdings::Held {
                calls,
                relay: label,
                obtained_at: now,
            },
            Ok(other) => {
                let (outcome, detail) =
                    crate::relay::types::ReplyKind::CallList.unanswered_by(&other, &label);
                Holdings::NotAnswered {
                    relay: label,
                    outcome,
                    detail,
                }
            }
            Err(e) => {
                let (outcome, detail) = fetch_failure(&label, &e);
                Holdings::NotAnswered {
                    relay: label,
                    outcome,
                    detail,
                }
            }
        }
    }
}

/// Ask which calls are held: the one relay, or with engine selection every
/// engine the operator named, all at once, each with its own answer.
#[must_use]
pub fn ask_engines(
    relay: &(dyn ReadOnlyRelay + Sync),
    routing: Option<&crate::relay::engines::EngineRouting>,
    permit: &TransmitPermit,
    max_calls: u32,
    now: DateTime<Utc>,
) -> Holdings {
    let Some(routing) = routing else {
        return ask(relay, permit, max_calls, now);
    };
    // Every engine at once: an engine that does not answer costs one control
    // timeout, not one per engine, and the answers stay in the engines'
    // order.
    let engines = crate::relay::fan_out::ask_each(routing.listing_engines(), |addr| {
        if addr == routing.default_engine() {
            ask(relay, permit, max_calls, now)
        } else {
            ask(routing.relay(addr).as_ref(), permit, max_calls, now)
        }
    });
    Holdings::Several {
        engines,
        obtained_at: now,
    }
}

impl Holdings {
    /// Whether the relay answered with a call list.
    #[must_use]
    pub fn answered(&self) -> bool {
        match self {
            Self::Held { .. } => true,
            Self::NotAnswered { .. } => false,
            Self::Several { engines, .. } => engines.iter().any(Self::answered),
        }
    }

    /// Every Call-ID the answer holds, once each, in Call-ID order, and the
    /// ones two or more engines hold.
    fn union(engines: &[Self]) -> (Vec<String>, Vec<String>) {
        let mut seen: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
        for e in engines {
            if let Self::Held { calls, .. } = e {
                let mut own: Vec<&str> = calls.call_ids.iter().map(String::as_str).collect();
                own.sort_unstable();
                own.dedup();
                for c in own {
                    *seen.entry(c).or_default() += 1;
                }
            }
        }
        let all = seen.keys().map(|c| (*c).to_string()).collect();
        let several = seen
            .iter()
            .filter(|(_, n)| **n > 1)
            .map(|(c, _)| (*c).to_string())
            .collect();
        (all, several)
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
            Self::NotAnswered {
                outcome, detail, ..
            } => fmt::relay_rest_outcome(*outcome, detail),
            Self::Several {
                engines,
                obtained_at,
            } => {
                if !self.answered() {
                    return engines
                        .first()
                        .map_or_else(|| json!({ "outcome": "suspect" }), |first| first.body());
                }
                let (all, several) = Self::union(engines);
                let truncated = engines
                    .iter()
                    .any(|e| matches!(e, Self::Held { calls, .. } if calls.truncated));
                let relays: Vec<String> = engines.iter().map(Self::relay_of).collect();
                let each: Vec<Value> = engines
                    .iter()
                    .map(|e| {
                        let mut b = e.body();
                        b["relay"] = json!(Self::relay_of(e));
                        b
                    })
                    .collect();
                fmt::relay_rest_ok(
                    &json!({
                        "kind": "calls",
                        "call_ids": all,
                        "truncated": truncated,
                        "relay": relays.join(", "),
                        "obtained_at": obtained_at.to_rfc3339(),
                        "origin": "asked",
                        "held_by_several_engines": several,
                        "engines": each,
                    })
                    .to_string(),
                )
            }
        };
        serde_json::from_str(&text).unwrap_or_else(|_| json!({ "outcome": "suspect" }))
    }

    /// [`Self::body`], with `cap_clamped` when the cap asked for was above
    /// the ceiling and lowered to it.
    #[must_use]
    pub fn body_capped(&self, clamp: Option<&crate::relay::scan_cap::CapClamp>) -> Value {
        let mut body = self.body();
        if let (Some(clamp), Some(fields)) = (clamp, body.as_object_mut()) {
            fields.insert("cap_clamped".to_string(), json!(clamp));
        }
        body
    }

    /// [`Self::render`], with the clamp's sentence first when the cap asked
    /// for was above the ceiling and lowered to it.
    #[must_use]
    pub fn render_capped(
        &self,
        format: ReportFormat,
        clamp: Option<&crate::relay::scan_cap::CapClamp>,
    ) -> String {
        match clamp {
            Some(clamp) => format!("{}\n{}", clamp.sentence(), self.render(format)),
            None => self.render(format),
        }
    }

    /// The relay one engine's answer names.
    fn relay_of(engine: &Self) -> String {
        match engine {
            Self::Held { relay, .. } | Self::NotAnswered { relay, .. } => relay.clone(),
            Self::Several { .. } => String::new(),
        }
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
            Self::NotAnswered {
                outcome, detail, ..
            } => {
                format!("{}: {}\n", outcome.as_wire_str(), super::clean(detail))
            }
            Self::Several { engines, .. } => {
                let mut out = String::new();
                for (i, e) in engines.iter().enumerate() {
                    if i > 0 {
                        out.push('\n');
                    }
                    out.push_str(&e.render(format));
                }
                let (_, several) = Self::union(engines);
                if !several.is_empty() {
                    out.push_str(&format!(
                        "\nHeld by several engines: {}\n",
                        several
                            .iter()
                            .map(|c| super::clean(c))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }
                out
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
        assert!(answer.render(ReportFormat::Text).starts_with(&format!(
            "suspect: {}",
            crate::relay::types::ReplyKind::CallList.wrong_kind_reason()
        )),);
        Ok(())
    }

    // ── Several engines ─────────────────────────────────────────────────

    /// An engine with a name, answering `list` with `ids`, or down.
    struct Engine(&'static str, Option<Vec<&'static str>>);

    impl ReadOnlyRelay for Engine {
        fn list(&self, _: &TransmitPermit, _: u32) -> anyhow::Result<ControlReply> {
            match &self.1 {
                Some(ids) => Ok(listed(ids)),
                None => anyhow::bail!("no reply within 2s"),
            }
        }
        fn query(&self, _: &TransmitPermit, _: &str) -> anyhow::Result<ControlReply> {
            anyhow::bail!("holdings only list")
        }
        fn statistics(&self, _: &TransmitPermit) -> anyhow::Result<ControlReply> {
            anyhow::bail!("holdings only list")
        }
        fn describe(&self) -> String {
            self.0.to_string()
        }
    }

    fn routing(
        a: Option<Vec<&'static str>>,
        b: Option<Vec<&'static str>>,
    ) -> Result<crate::relay::engines::EngineRouting, TestError> {
        use crate::relay::engines::{Connect, EngineMap, EngineRouting, EngineRow, EngineRule};
        use std::sync::Arc;
        let rows = vec![
            "203.0.113.5 30000-39999 192.0.2.5:2223".parse::<EngineRow>()?,
            "203.0.113.5 40000-49999 192.0.2.6:2223".parse::<EngineRow>()?,
        ];
        let a_addr: std::net::SocketAddr = "192.0.2.5:2223".parse()?;
        let connect: Connect = Arc::new(move |addr| -> Arc<dyn ReadOnlyRelay + Send + Sync> {
            if addr == a_addr {
                Arc::new(Engine("engine-a", a.clone()))
            } else {
                Arc::new(Engine("engine-b", b.clone()))
            }
        });
        Ok(EngineRouting::new(
            EngineRule::Map(EngineMap::new(rows)?),
            "192.0.2.1:2223".parse()?,
            false,
            connect,
        ))
    }

    /// Several engines: each is listed, the answer holds every Call-ID once,
    /// and a Call-ID two engines hold is named as held by several.
    #[test]
    fn several_engines_are_each_listed_and_a_shared_call_is_named() -> Result<(), TestError> {
        let r = routing(
            Some(vec!["m-1@example.invalid"]),
            Some(vec!["m-1@example.invalid", "b-1@example.invalid"]),
        )?;
        let answer = ask_engines(
            &Engine("engine-d", Some(vec!["d-1@example.invalid"])),
            Some(&r),
            &permit()?,
            32,
            at()?,
        );
        assert!(
            answer.answered(),
            "several engines are each listed and a shared call is named"
        );
        let body = answer.body();
        assert_eq!(
            body["outcome"], "ok",
            "several engines are each listed and a shared call is named"
        );
        assert_eq!(
            body["call_ids"],
            json!([
                "b-1@example.invalid",
                "d-1@example.invalid",
                "m-1@example.invalid"
            ]),
            "several engines are each listed and a shared call is named"
        );
        assert_eq!(
            body["held_by_several_engines"],
            json!(["m-1@example.invalid"]),
            "several engines are each listed and a shared call is named"
        );
        let engines = body["engines"].as_array().ok_or("engines")?;
        assert_eq!(
            engines.len(),
            3,
            "several engines are each listed and a shared call is named"
        );
        assert_eq!(
            engines[0]["relay"], "relay (engine-d)",
            "several engines are each listed and a shared call is named"
        );
        let text = answer.render(ReportFormat::Text);
        assert!(text.contains("Holdings of relay (engine-a)"), "{text}");
        assert!(
            text.contains("Held by several engines: m-1@example.invalid"),
            "{text}"
        );
        Ok(())
    }

    /// One engine down: the others' calls are still the answer, and the
    /// engine that did not answer is named.
    #[test]
    fn one_engine_down_is_named_beside_the_others() -> Result<(), TestError> {
        let r = routing(None, Some(vec!["b-1@example.invalid"]))?;
        let answer = ask_engines(
            &Engine("engine-d", Some(vec![])),
            Some(&r),
            &permit()?,
            32,
            at()?,
        );
        assert!(
            answer.answered(),
            "one engine down is named beside the others"
        );
        let body = answer.body();
        let engines = body["engines"].as_array().ok_or("engines")?;
        assert_eq!(
            engines[1]["relay"], "relay (engine-a)",
            "one engine down is named beside the others"
        );
        assert_eq!(
            engines[1]["outcome"], "unreachable",
            "one engine down is named beside the others"
        );
        assert!(
            answer
                .render(ReportFormat::Text)
                .contains("unreachable: relay (engine-a) did not answer"),
            "one engine down is named beside the others"
        );
        Ok(())
    }

    /// Every engine down is no answer.
    #[test]
    fn every_engine_down_is_no_answer() -> Result<(), TestError> {
        let r = routing(None, None)?;
        let answer = ask_engines(&Engine("engine-d", None), Some(&r), &permit()?, 32, at()?);
        assert!(!answer.answered(), "every engine down is no answer");
        assert_eq!(
            answer.body()["outcome"],
            "unreachable",
            "every engine down is no answer"
        );
        Ok(())
    }

    /// Without engine selection the answer is the one relay's, unchanged.
    #[test]
    fn without_routing_the_answer_is_the_one_relays() -> Result<(), TestError> {
        let one = ask_engines(
            &Scripted(listed(&["a@192.0.2.10"])),
            None,
            &permit()?,
            32,
            at()?,
        );
        let plain = ask(&Scripted(listed(&["a@192.0.2.10"])), &permit()?, 32, at()?);
        assert_eq!(one, plain, "without routing the answer is the one relays");
        assert!(
            one.body().get("engines").is_none(),
            "without routing the answer is the one relays"
        );
        Ok(())
    }

    /// Each engine's holdings in the configured order, the outcome of each,
    /// asked of real fake engines, and how long the question took.
    fn udp_holdings(
        fakes: &[crate::test_engines::FakeEngine],
    ) -> Result<(Vec<String>, std::time::Duration), TestError> {
        use crate::test_engines::{TIMEOUT, client, routing};
        let r = routing(&fakes.iter().collect::<Vec<_>>(), TIMEOUT)?;
        let default = client(r.default_engine(), TIMEOUT);
        let started = std::time::Instant::now();
        let answer = ask_engines(default.as_ref(), Some(&r), &permit()?, 32, at()?);
        let took = started.elapsed();
        let body = answer.body();
        let engines = body["engines"].as_array().ok_or("engines")?;
        Ok((
            engines
                .iter()
                .map(|e| format!("{} {}", e["relay"], e["outcome"]).replace('"', ""))
                .collect(),
            took,
        ))
    }

    /// Engines that answer last first are listed first first.
    #[test]
    fn holdings_keep_the_configured_order_whatever_order_they_answer() -> Result<(), TestError> {
        use crate::test_engines::{FakeEngine, LIST_BODY};
        let late = |ms| FakeEngine::answering(LIST_BODY, std::time::Duration::from_millis(ms));
        let fakes = [late(300)?, late(150)?, late(0)?];
        let (got, _) = udp_holdings(&fakes)?;
        let want: Vec<String> = fakes
            .iter()
            .map(|f| format!("relay ({}) ok", f.describe()))
            .collect();
        assert_eq!(got, want, "every engine answered, in the engines' order");
        Ok(())
    }

    /// Dead engines cost one timeout, and each reads unreachable in its own
    /// place beside the live one.
    #[test]
    fn holdings_with_dead_engines_cost_one_timeout() -> Result<(), TestError> {
        use crate::test_engines::{FakeEngine, all_answered, waited_a_timeout};
        // Asked at once, not in turn: three engines that answer only when
        // all three hold a request. No wall time is read for it.
        let asked = FakeEngine::together_beside_a_live_one(4, 1)?;
        let (got, _) = udp_holdings(&asked)?;
        assert!(
            all_answered(&asked),
            "the engines were asked one after another: {got:?}"
        );
        let fakes = [
            FakeEngine::dead()?,
            FakeEngine::live()?,
            FakeEngine::dead()?,
            FakeEngine::dead()?,
        ];
        let (got, took) = udp_holdings(&fakes)?;
        assert!(
            waited_a_timeout(took),
            "the dead engines were waited for: {took:?}: {got:?}"
        );
        let outcomes: Vec<&str> = got.iter().filter_map(|g| g.rsplit(' ').next()).collect();
        assert_eq!(
            outcomes,
            vec!["unreachable", "ok", "unreachable", "unreachable"],
            "each dead engine unreachable in its own place",
        );
        Ok(())
    }

    const CLAMP: crate::relay::scan_cap::CapClamp = crate::relay::scan_cap::CapClamp {
        requested: 5000,
        ceiling: 1024,
    };

    /// A clamped holdings answer carries `cap_clamped` in its body.
    #[test]
    fn a_clamped_answer_carries_the_clamp_in_its_body() -> Result<(), TestError> {
        let answer = ask(
            &Scripted(listed(&["a@192.0.2.10"])),
            &permit()?,
            1024,
            at()?,
        );
        let body = answer.body_capped(Some(&CLAMP));
        assert_eq!(
            body["outcome"], "ok",
            "A clamped holdings answer carries `cap_clamped` in its body"
        );
        assert_eq!(
            body["cap_clamped"],
            json!({ "requested": 5000, "ceiling": 1024 }),
            "{body}"
        );
        Ok(())
    }

    /// An unclamped answer's body is exactly [`Holdings::body`].
    #[test]
    fn an_unclamped_answer_is_the_plain_body() -> Result<(), TestError> {
        let answer = ask(&Scripted(listed(&["a@192.0.2.10"])), &permit()?, 32, at()?);
        assert_eq!(
            answer.body_capped(None),
            answer.body(),
            "An unclamped answer's body is exactly [`Holdings::body`]"
        );
        assert!(
            answer.body_capped(None).get("cap_clamped").is_none(),
            "An unclamped answer's body is exactly [`Holdings::body`]"
        );
        Ok(())
    }

    /// A clamped answer's text states the clamp.
    #[test]
    fn a_clamped_answer_states_the_clamp_in_text() -> Result<(), TestError> {
        let answer = ask(
            &Scripted(listed(&["a@192.0.2.10"])),
            &permit()?,
            1024,
            at()?,
        );
        let text = answer.render_capped(ReportFormat::Text, Some(&CLAMP));
        assert!(
            text.contains("Asked for 5000 calls; the ceiling is 1024"),
            "{text}"
        );
        assert_eq!(
            answer.render_capped(ReportFormat::Text, None),
            answer.render(ReportFormat::Text),
            "A clamped answer's text states the clamp"
        );
        Ok(())
    }
}
