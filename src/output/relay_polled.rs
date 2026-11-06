// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The latest relay statistics reading `--relay-stats-interval` polled, held
//! so REST and MCP can read it without asking the relay themselves.
//!
//! The poll is the operator's: a headless run with `--relay-stats-interval`
//! asks the relay on a timer and prints each reading. This keeps the newest
//! one, and the newest failure, in a [`PolledStore`]. `GET
//! /v1/relay/stats/polled` and the MCP `relay_stats_polled` tool return
//! [`PolledStore::answer`], so a dashboard or an agent reads what the
//! operator's poll already obtained. Neither starts a poll, and neither
//! transmits: a reader never puts a packet on the network, so neither needs
//! `--api-allow-relay-query` or `--mcp-allow-relay-query`.
//!
//! The answer carries the fields `--relay-stats-interval --json` prints
//! (`relay`, `obtained_at`, `origin: "polled"`, `interval_secs`, `statistics`
//! with each value's tier, `refusals`), plus `outcome` and `age_secs`, so a
//! reader can tell a fresh reading from a stale one when the poll has stopped
//! getting answers.

use chrono::{DateTime, Utc};
use parking_lot::Mutex;

use crate::stats_vocab::WireStatistics;

/// Whether the answer carries a reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub enum PolledOutcome {
    /// The newest reading is in the answer.
    Ok,
    /// A poll runs and has obtained nothing yet.
    NoReadingYet,
    /// This run does not poll.
    NotPolling,
}

/// One counted value, as every relay statistics surface prints it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub struct PolledValue {
    /// The relay's own name for it, unaltered.
    pub name: String,
    /// The value as the relay gave it, never coerced.
    pub value: String,
    /// Always `relay_reported`: the relay's claim about itself.
    pub tier: &'static str,
}

/// One statistic the relay refused, with its own code.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub struct PolledRefusal {
    /// The statistic's name.
    pub name: String,
    /// The relay's refusal code.
    pub code: String,
}

/// The newest attempt, when it failed after the reading it sits beside.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub struct LastPoll {
    /// `unreachable` (asked, nothing came back) or `suspect` (an answer that
    /// could not be trusted).
    pub outcome: &'static str,
    /// When the attempt gave up, RFC 3339.
    pub at: String,
    /// What happened, in the words the run's log uses.
    pub detail: String,
}

/// What `GET /v1/relay/stats/polled` and the MCP `relay_stats_polled` tool
/// return. A field that does not apply is omitted, never null and never 0.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub struct PolledAnswer {
    /// `ok`, `no_reading_yet` or `not_polling`.
    pub outcome: PolledOutcome,
    /// The relay, named as the run's log names it (`ok`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relay: Option<String>,
    /// When the relay answered, RFC 3339 (`ok`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub obtained_at: Option<String>,
    /// Always `polled` (`ok`): a timer's reading, not a one-shot answer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<&'static str>,
    /// The poll's interval in seconds, as the operator configured it (`ok`,
    /// `no_reading_yet`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interval_secs: Option<u64>,
    /// Seconds since the relay answered, on this server's clock (`ok`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub age_secs: Option<i64>,
    /// The relay's counters, each with its tier (`ok`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statistics: Option<Vec<PolledValue>>,
    /// Statistics the relay refused (`ok`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refusals: Option<Vec<PolledRefusal>>,
    /// The newest attempt, when it failed after the reading.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_poll: Option<LastPoll>,
    /// What starts a poll (`not_polling`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Each listed engine's own newest reading, `--rtpengine-control` first,
    /// when the poll asks more than one engine. The fields above are the
    /// first engine's.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engines: Option<Vec<PolledEngine>>,
}

/// One engine's newest reading, in a poll that asks several.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
pub struct PolledEngine {
    /// The engine, named as the run's log names it.
    pub relay: String,
    /// `ok` when it has a reading, else `no_reading_yet`.
    pub outcome: PolledOutcome,
    /// When it answered, RFC 3339 (`ok`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub obtained_at: Option<String>,
    /// Seconds since it answered, on this server's clock (`ok`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub age_secs: Option<i64>,
    /// Its counters, each with its tier (`ok`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statistics: Option<Vec<PolledValue>>,
    /// Statistics it refused (`ok`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refusals: Option<Vec<PolledRefusal>>,
    /// Its newest attempt, when it failed after the reading.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_poll: Option<LastPoll>,
}

impl PolledAnswer {
    /// An answer with `outcome` and every other field absent.
    const fn bare(outcome: PolledOutcome) -> Self {
        Self {
            outcome,
            relay: None,
            obtained_at: None,
            origin: None,
            interval_secs: None,
            age_secs: None,
            statistics: None,
            refusals: None,
            last_poll: None,
            detail: None,
            engines: None,
        }
    }
}

/// One reading the poll obtained.
#[derive(Debug, Clone)]
pub struct PolledReading {
    /// The resolved statistics, as every surface renders them.
    pub wire: WireStatistics,
    /// The relay, named as every relay line names it
    /// (`rtpengine at 127.0.0.1:22222`).
    pub relay: String,
    /// When the relay answered.
    pub obtained_at: DateTime<Utc>,
}

/// One poll that obtained no reading.
#[derive(Debug, Clone)]
pub struct PollFailure {
    /// The relay that obtained no reading, named as [`PolledReading::relay`]
    /// names it.
    pub relay: String,
    /// When the poll gave up.
    pub at: DateTime<Utc>,
    /// The classification every relay surface uses: `unreachable` (asked,
    /// nothing came back) or `suspect` (an answer that could not be trusted).
    pub outcome: &'static str,
    /// What happened, in the words the run's log uses.
    pub detail: String,
}

/// What the poll has obtained from one engine so far.
#[derive(Debug)]
struct EngineState {
    /// The engine, as its readings name it.
    relay: String,
    /// The newest reading.
    latest: Option<PolledReading>,
    /// The newest failure, kept only while it is newer than `latest`.
    failure: Option<PollFailure>,
}

/// What the poll has obtained so far.
#[derive(Debug, Default)]
struct State {
    /// The interval the poll runs at, once it has started.
    every_secs: Option<u64>,
    /// Each engine polled, `--rtpengine-control` first.
    engines: Vec<EngineState>,
}

impl State {
    /// The state of `relay`, added after the others when it is new.
    fn engine(&mut self, relay: &str) -> &mut EngineState {
        let at = match self.engines.iter().position(|e| e.relay == relay) {
            Some(at) => at,
            None => {
                self.engines.push(EngineState {
                    relay: relay.to_string(),
                    latest: None,
                    failure: None,
                });
                self.engines.len() - 1
            }
        };
        &mut self.engines[at]
    }
}

/// The latest polled reading, shared by the poll that writes it and the
/// surfaces that read it.
#[derive(Debug, Default)]
pub struct PolledStore {
    /// Guarded together, so a reader never sees a failure paired with a
    /// reading it is not newer than.
    state: Mutex<State>,
}

impl PolledStore {
    /// The store a run's poll writes and its servers read.
    #[must_use]
    pub fn global() -> &'static std::sync::Arc<Self> {
        static STORE: std::sync::OnceLock<std::sync::Arc<PolledStore>> = std::sync::OnceLock::new();
        STORE.get_or_init(std::sync::Arc::default)
    }

    /// Record that a poll runs, every `every_secs` seconds.
    pub fn start(&self, every_secs: u64) {
        self.state.lock().every_secs = Some(every_secs);
    }

    /// Record that a poll runs, every `every_secs` seconds, over `relays`,
    /// `--rtpengine-control` first, each named as its readings name it.
    pub fn start_engines(&self, every_secs: u64, relays: Vec<String>) {
        let mut state = self.state.lock();
        state.every_secs = Some(every_secs);
        for relay in relays {
            let _ = state.engine(&relay);
        }
    }

    /// Record a reading, which replaces the previous one and any failure.
    pub fn record(&self, reading: PolledReading) {
        let mut state = self.state.lock();
        let relay = reading.relay.clone();
        let engine = state.engine(&relay);
        engine.latest = Some(reading);
        engine.failure = None;
    }

    /// Record a poll that obtained nothing. The reading already held stays.
    pub fn record_failure(&self, failure: PollFailure) {
        let mut state = self.state.lock();
        let relay = failure.relay.clone();
        state.engine(&relay).failure = Some(failure);
    }

    /// The answer REST and MCP return, as of `now`.
    ///
    /// - `outcome: "not_polling"` when no poll runs, with what starts one.
    /// - `outcome: "no_reading_yet"` when a poll runs and has obtained
    ///   nothing, with `interval_secs` and, when its last attempt failed,
    ///   `last_poll`.
    /// - `outcome: "ok"` with the reading in the form every relay statistics
    ///   surface prints, `age_secs` since the relay answered, and `last_poll`
    ///   when a later attempt failed.
    #[must_use]
    pub fn answer(&self, now: DateTime<Utc>) -> PolledAnswer {
        let state = self.state.lock();
        let Some(every_secs) = state.every_secs else {
            return PolledAnswer {
                detail: Some(format!(
                    "No poll runs on this server. A headless run started with \
                     --relay-stats-interval SECONDS and {} polls the relay and keeps \
                     its newest reading here.",
                    crate::cli::RELAY_CONTROL_FLAG
                )),
                ..PolledAnswer::bare(PolledOutcome::NotPolling)
            };
        };
        let stamp = |t: DateTime<Utc>| t.format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let each: Vec<PolledEngine> = state
            .engines
            .iter()
            .map(|e| engine_answer(e, now, &stamp))
            .collect();
        let engines = (each.len() > 1).then_some(each);
        let Some(first) = state.engines.first() else {
            return PolledAnswer {
                interval_secs: Some(every_secs),
                engines,
                ..PolledAnswer::bare(PolledOutcome::NoReadingYet)
            };
        };
        let last_poll = first.failure.as_ref().map(|f| last_poll(f, &stamp));
        let Some(r) = &first.latest else {
            return PolledAnswer {
                interval_secs: Some(every_secs),
                last_poll,
                engines,
                ..PolledAnswer::bare(PolledOutcome::NoReadingYet)
            };
        };
        // The fields and spellings `--relay-stats-interval --json` prints, so a
        // reader parses a polled reading the way it parses an asked one.
        PolledAnswer {
            relay: Some(r.relay.clone()),
            obtained_at: Some(stamp(r.obtained_at)),
            origin: Some("polled"),
            interval_secs: Some(every_secs),
            age_secs: Some((now - r.obtained_at).num_seconds().max(0)),
            statistics: Some(values(r)),
            refusals: Some(refusals(r)),
            last_poll,
            engines,
            ..PolledAnswer::bare(PolledOutcome::Ok)
        }
    }
}

/// A failed attempt, as an answer reports it.
fn last_poll(f: &PollFailure, stamp: &dyn Fn(DateTime<Utc>) -> String) -> LastPoll {
    LastPoll {
        outcome: f.outcome,
        at: stamp(f.at),
        detail: f.detail.clone(),
    }
}

/// A reading's counters, each with its tier.
fn values(r: &PolledReading) -> Vec<PolledValue> {
    r.wire
        .present
        .iter()
        .map(|v| PolledValue {
            name: v.name.clone(),
            value: v.value.clone(),
            tier: v.tier.as_wire_str(),
        })
        .collect()
}

/// A reading's refusals.
fn refusals(r: &PolledReading) -> Vec<PolledRefusal> {
    r.wire
        .refusals
        .iter()
        .map(|x| PolledRefusal {
            name: x.name.clone(),
            code: x.code.clone(),
        })
        .collect()
}

/// One engine's newest reading, as `engines` carries it.
fn engine_answer(
    e: &EngineState,
    now: DateTime<Utc>,
    stamp: &dyn Fn(DateTime<Utc>) -> String,
) -> PolledEngine {
    let last_poll = e.failure.as_ref().map(|f| last_poll(f, stamp));
    match &e.latest {
        Some(r) => PolledEngine {
            relay: e.relay.clone(),
            outcome: PolledOutcome::Ok,
            obtained_at: Some(stamp(r.obtained_at)),
            age_secs: Some((now - r.obtained_at).num_seconds().max(0)),
            statistics: Some(values(r)),
            refusals: Some(refusals(r)),
            last_poll,
        },
        None => PolledEngine {
            relay: e.relay.clone(),
            outcome: PolledOutcome::NoReadingYet,
            obtained_at: None,
            age_secs: None,
            statistics: None,
            refusals: None,
            last_poll,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stats_vocab::{relay_reported, resolve_for_wire};

    type TestError = Box<dyn std::error::Error>;

    /// A reading of two counters, obtained at `at`.
    fn reading(at: DateTime<Utc>) -> PolledReading {
        let pairs = vec![
            ("sessions".to_string(), "3".to_string()),
            ("uptime".to_string(), "134".to_string()),
        ];
        PolledReading {
            wire: resolve_for_wire(&relay_reported(&pairs)),
            relay: "relay at 192.0.2.10:22222".to_string(),
            obtained_at: at,
        }
    }

    /// A fixed instant, so ages are exact.
    fn t0() -> Result<DateTime<Utc>, TestError> {
        Ok(DateTime::parse_from_rfc3339("2026-11-03T12:00:00Z")?.with_timezone(&Utc))
    }

    /// No poll: the answer says so and names the flag that starts one.
    #[test]
    fn without_a_poll_the_answer_says_how_to_start_one() -> Result<(), TestError> {
        let v = serde_json::to_value(PolledStore::default().answer(t0()?))?;
        assert_eq!(v["outcome"], "not_polling", "{v}");
        let detail = v["detail"].as_str().ok_or("a detail")?;
        assert!(detail.contains("--relay-stats-interval"), "{detail}");
        assert!(
            v.get("statistics").is_none(),
            "no reading, no statistics: {v}"
        );
        Ok(())
    }

    /// A poll that has not answered yet is not "no statistics": the answer
    /// says it is waiting, at what interval, and why the last attempt failed.
    #[test]
    fn a_poll_with_no_reading_yet_says_so() -> Result<(), TestError> {
        let store = PolledStore::default();
        store.start(5);
        let v = serde_json::to_value(store.answer(t0()?))?;
        assert_eq!(v["outcome"], "no_reading_yet", "{v}");
        assert_eq!(v["interval_secs"], 5, "{v}");
        assert!(v.get("last_poll").is_none(), "no attempt failed: {v}");
        store.record_failure(PollFailure {
            relay: "relay at 192.0.2.10:22222".to_string(),
            at: t0()?,
            outcome: "unreachable",
            detail: "no reply within 2s".to_string(),
        });
        let v = serde_json::to_value(store.answer(t0()?))?;
        assert_eq!(v["outcome"], "no_reading_yet", "{v}");
        assert_eq!(v["last_poll"]["outcome"], "unreachable", "{v}");
        Ok(())
    }

    /// Every field `--relay-stats-interval --json` prints for a reading is in
    /// the answer with the same value, so one parser reads both.
    #[test]
    fn a_reading_carries_every_field_the_cli_prints() -> Result<(), TestError> {
        use crate::output::relay_statistics::{FetchOrigin, format_relay_statistics_json};
        let r = reading(t0()?);
        let cli: serde_json::Value = serde_json::from_str(&format_relay_statistics_json(
            &r.wire,
            &r.relay,
            r.obtained_at,
            FetchOrigin::Polled { every_secs: 5 },
        ))?;
        let store = PolledStore::default();
        store.start(5);
        store.record(r);
        let ours = serde_json::to_value(store.answer(t0()?))?;
        for (key, value) in cli.as_object().ok_or("the CLI prints an object")? {
            assert_eq!(&ours[key], value, "`{key}` differs from the CLI's: {ours}");
        }
        Ok(())
    }

    /// A reading comes back in the relay statistics form, labeled polled,
    /// with each value's tier and its age; a later failure is reported beside
    /// it and does not erase it, and a later reading clears the failure.
    #[test]
    fn a_reading_is_returned_with_its_tier_and_age() -> Result<(), TestError> {
        let store = PolledStore::default();
        store.start(5);
        store.record(reading(t0()?));
        let later = t0()? + chrono::TimeDelta::seconds(7);
        let v = serde_json::to_value(store.answer(later))?;
        assert_eq!(v["outcome"], "ok", "{v}");
        assert_eq!(v["origin"], "polled", "{v}");
        assert_eq!(v["interval_secs"], 5, "{v}");
        assert_eq!(v["age_secs"], 7, "{v}");
        assert_eq!(v["obtained_at"], "2026-11-03T12:00:00Z", "{v}");
        let stats = v["statistics"].as_array().ok_or("statistics")?;
        let sessions = stats
            .iter()
            .find(|s| s["name"] == "sessions")
            .ok_or("sessions")?;
        assert_eq!(
            sessions["value"], "3",
            "the value as the relay gave it: {v}"
        );
        assert_eq!(sessions["tier"], "relay_reported", "{v}");
        store.record_failure(PollFailure {
            relay: "relay at 192.0.2.10:22222".to_string(),
            at: later,
            outcome: "unreachable",
            detail: "no reply within 2s".to_string(),
        });
        let v = serde_json::to_value(store.answer(later))?;
        assert_eq!(v["outcome"], "ok", "the reading stays: {v}");
        assert_eq!(v["last_poll"]["outcome"], "unreachable", "{v}");
        store.record(reading(later));
        let v = serde_json::to_value(store.answer(later))?;
        assert!(
            v.get("last_poll").is_none(),
            "a newer reading clears it: {v}"
        );
        assert_eq!(v["age_secs"], 0, "{v}");
        Ok(())
    }

    /// A poll over several engines keeps each engine's reading and failure
    /// apart. The top level is the first engine's; `engines` holds each. A
    /// poll over one engine has no `engines`.
    #[test]
    fn each_engines_reading_is_kept_on_its_own() -> Result<(), TestError> {
        let store = PolledStore::default();
        store.start_engines(
            5,
            vec![
                "relay at 192.0.2.10:22222".to_string(),
                "relay at 192.0.2.11:22222".to_string(),
            ],
        );
        store.record(reading(t0()?));
        store.record_failure(PollFailure {
            relay: "relay at 192.0.2.11:22222".to_string(),
            at: t0()?,
            outcome: "unreachable",
            detail: "no reply within 2s".to_string(),
        });
        let v = serde_json::to_value(store.answer(t0()?))?;
        assert_eq!(v["outcome"], "ok", "the first engine answered: {v}");
        assert_eq!(v["relay"], "relay at 192.0.2.10:22222", "{v}");
        assert!(
            v.get("last_poll").is_none(),
            "the other engine's failure is its own: {v}"
        );
        let engines = v["engines"].as_array().ok_or(format!("engines: {v}"))?;
        assert_eq!(engines.len(), 2, "{v}");
        assert_eq!(engines[0]["outcome"], "ok", "{v}");
        assert_eq!(engines[1]["relay"], "relay at 192.0.2.11:22222", "{v}");
        assert_eq!(engines[1]["outcome"], "no_reading_yet", "{v}");
        assert_eq!(engines[1]["last_poll"]["outcome"], "unreachable", "{v}");

        let one = PolledStore::default();
        one.start(5);
        one.record(reading(t0()?));
        let v = serde_json::to_value(one.answer(t0()?))?;
        assert!(v.get("engines").is_none(), "one engine, no engines: {v}");
        Ok(())
    }
}
