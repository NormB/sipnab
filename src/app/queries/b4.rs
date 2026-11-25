// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Batch B4's query arms: see `docs/design/par5-cli-queries.md` for the
//! flags this file owns. Each flag adds one `if` here that calls its core
//! function and hands the answer to [`QueryContext::answer`].

use super::{QueryContext, set_gate_exit};
use crate::output::query::expectations;

/// Render batch B4's queries that this command line asked for.
///
/// # Returns
///
/// `false` when one was asked for and could not be answered or written;
/// `true` otherwise, including when none was asked for.
pub(super) fn render(ctx: &QueryContext<'_>) -> bool {
    render_expect(ctx)
}

/// The exit status of a suite sipnab could not judge for a reason in the
/// invocation, as an unreadable suppression file is for `--lint`.
const USAGE: i32 = 2;

/// `--expect`: the capture judged against the suite, the report the MCP
/// `evaluate_expectations` tool returns, and the suite's exit status
/// recorded for the run to end with.
fn render_expect(ctx: &QueryContext<'_>) -> bool {
    let Some(file) = ctx.cli.gate_args.expect.as_ref() else {
        return true;
    };
    let suppressions = match ctx.lint_suppressions() {
        Ok(suppressions) => suppressions,
        Err(why) => {
            stderr_line!("--expect: {why}");
            set_gate_exit(USAGE);
            return true;
        }
    };
    let judged = crate::expect::evaluate(
        &file.suite.rules,
        &crate::expect::Inputs {
            dialogs: ctx.dialogs,
            streams: ctx.streams,
            thresholds: &ctx.alias,
            suppressions: suppressions.as_ref(),
        },
    );
    let report = match judged {
        Ok(report) => report,
        Err(e) => {
            stderr_line!("--expect {}: {e}", file.path.display());
            set_gate_exit(USAGE);
            return true;
        }
    };
    set_gate_exit(report.exit_code());
    let answer = expectations::ExpectAnswer {
        report,
        capture_identity: ctx.capture_identity(),
    };
    ctx.answer("--expect", &answer, |format| {
        expectations::render(&answer.report, format)
    })
}

/// `--relay-holdings`: what the relay holds, the answer
/// `GET /v1/relay/holdings` returns, asked for `--relay-holdings-max` calls
/// or the shared default.
///
/// # Returns
///
/// The exit code: 0 when the relay answered with its call list and the
/// answer was written; 1 when it did not answer, declined or answered with
/// something that cannot be trusted, or stdout refused the answer.
pub(super) fn relay_holdings(
    cli: &crate::cli::Cli,
    relay: &(dyn crate::relay::reconcile::ReadOnlyRelay + Sync),
    routing: Option<&crate::relay::engines::EngineRouting>,
    permit: &crate::security::transmit_guard::TransmitPermit,
) -> i32 {
    use crate::output::query::relay_holdings::ask_engines;

    let Some(cap) = cli_cap(cli) else {
        return FAILED;
    };
    let answer = ask_engines(relay, routing, permit, cap.cap, chrono::Utc::now());
    let clamp = cap.clamped.as_ref();
    let json = !matches!(super::answer_form(cli), super::AnswerForm::Table(_));
    if !answer.answered() && !json {
        stderr_line!(
            "--relay-holdings: {}",
            answer
                .render_capped(crate::output::ReportFormat::Text, clamp)
                .trim_end()
        );
        return FAILED;
    }
    let written = super::write_answer(
        cli,
        "--relay-holdings",
        &answer.body_capped(clamp),
        |format| answer.render_capped(format, clamp),
    );
    if written && answer.answered() {
        0
    } else {
        FAILED
    }
}

/// `--relay-sessions`: one snapshot of what the relay holds and whether media
/// reaches it, the answer `GET /v1/relay/sessions?scan=true` returns, or with
/// `--relay-sessions-call` the answer for that call alone.
///
/// A CLI run asks before any capture opens, so sipnab has seen no SIP: every
/// call reads `not_seen_ended`, and the answer says the relay may still list
/// a call for about 30 s after it ends.
///
/// # Returns
///
/// The exit code: 0 when the relay answered its `list` and the answer was
/// written; 1 when it did not answer, declined, answered with something that
/// cannot be trusted, or stdout refused the answer.
pub(super) fn relay_sessions(
    cli: &crate::cli::Cli,
    relay: &(dyn crate::relay::reconcile::ReadOnlyRelay + Sync),
    routing: Option<&crate::relay::engines::EngineRouting>,
    permit: &crate::security::transmit_guard::TransmitPermit,
) -> i32 {
    use crate::output::query::relay_sessions::{Routed, SessionsAsk, relay_sessions_routed};

    let Some(cap) = cli_cap(cli) else {
        return FAILED;
    };
    let selected = cli.gate_args.relay_sessions_call.as_deref();
    let ask = SessionsAsk::capped(selected, selected.is_none(), cap);
    // No traffic has been read yet, so no call's SDP or ng offer is known:
    // with an engine rule each call is asked of the default engine, and the
    // answer says so.
    let no_sdp = |_: &str| crate::relay::engines::CallEvidence::default();
    let routed = routing.map(|routing| Routed {
        routing,
        sdp_of: &no_sdp,
    });
    let interval = sessions_interval(cli);
    let answer = sessions_answer(
        &mut || {
            relay_sessions_routed(
                relay,
                routed.as_ref(),
                permit,
                &ask,
                &|_| false,
                &chrono::Utc::now,
            )
        },
        interval,
        &mut std::thread::sleep,
    );
    let json = !matches!(super::answer_form(cli), super::AnswerForm::Table(_));
    if !answer.answered() && !json {
        stderr_line!(
            "--relay-sessions: {}: {}",
            answer.reach,
            answer.detail.as_deref().unwrap_or("")
        );
        return FAILED;
    }
    let written = super::write_answer(cli, "--relay-sessions", &answer.body(), |format| {
        answer.render(format)
    });
    if written && answer.answered() {
        0
    } else {
        FAILED
    }
}

/// The gap between the two snapshots of a rated `--relay-sessions`:
/// `--relay-stats-interval`, or `None` for one snapshot.
fn sessions_interval(cli: &crate::cli::Cli) -> Option<std::time::Duration> {
    cli.rtp_args
        .relay_stats_interval
        .map(std::time::Duration::from_secs)
}

/// The answer `--relay-sessions` prints: one snapshot from `take`, its
/// sockets reading `no_rate_yet`, or, with `interval`, two snapshots
/// `interval` apart (`wait` sleeps between them), the second carrying each
/// RTP socket's rate since the first.
///
/// The run reads no media, so every `captured_rate` reads `not_captured`.
/// A first snapshot whose `list` was not answered is the answer: nothing is
/// asked again.
fn sessions_answer(
    take: &mut dyn FnMut() -> crate::output::query::relay_sessions::RelaySessions,
    interval: Option<std::time::Duration>,
    wait: &mut dyn FnMut(std::time::Duration),
) -> crate::output::query::relay_sessions::RelaySessions {
    let mut memory = crate::relay::rate::RateMemories::default();
    let Some(gap) = interval else {
        // One snapshot: every socket reads `no_rate_yet`, the same answer a
        // first REST or MCP ask gives.
        let mut only = take();
        only.attach_rates(&mut memory, None, crate::relay::rate::monotonic_now());
        return only;
    };
    let mut first = take();
    if !first.answered() {
        return first;
    }
    first.attach_rates(&mut memory, None, crate::relay::rate::monotonic_now());
    wait(gap);
    let mut second = take();
    second.attach_rates(&mut memory, None, crate::relay::rate::monotonic_now());
    second
}

/// The exit status of a relay ask that brought back no call list.
const FAILED: i32 = 1;

/// The cap a CLI relay ask applies: `--relay-holdings-max` by the one rule
/// ([`crate::relay::scan_cap::scan_cap`]). The flag's parser already refuses
/// 0, so `None` (said on stderr) is only reachable from a `Cli` built by
/// hand.
fn cli_cap(cli: &crate::cli::Cli) -> Option<crate::relay::scan_cap::ScanCap> {
    match crate::relay::scan_cap::scan_cap(None, cli.gate_args.relay_holdings_max) {
        Ok(cap) => Some(cap),
        Err(e) => {
            stderr_line!("--relay-holdings-max: {e}");
            None
        }
    }
}

/// `--relay-holdings` and `--relay-sessions` take their cap from
/// `--relay-holdings-max` by the one rule, against a relay that answers in
/// memory. Nothing is sent.
#[cfg(test)]
mod tests {
    use crate::relay::reconcile::ReadOnlyRelay;
    use crate::relay::types::{ControlReply, Enumeration};
    use crate::security::transmit_guard::TransmitPermit;
    use std::sync::Mutex;

    type TestError = Box<dyn std::error::Error>;

    /// Lists `held` Call-IDs whatever the limit; records each ask.
    struct Listing {
        held: usize,
        asked: Mutex<Vec<String>>,
    }

    impl ReadOnlyRelay for Listing {
        fn list(&self, _: &TransmitPermit, limit: u32) -> anyhow::Result<ControlReply> {
            self.asked
                .lock()
                .map_err(|e| anyhow::anyhow!("{e}"))?
                .push(format!("list {limit}"));
            Ok(ControlReply::Calls(Enumeration {
                call_ids: (0..self.held)
                    .map(|n| format!("held-{n:04}@example.invalid"))
                    .collect(),
                truncated: false,
            }))
        }
        fn query(&self, _: &TransmitPermit, c: &str) -> anyhow::Result<ControlReply> {
            self.asked
                .lock()
                .map_err(|e| anyhow::anyhow!("{e}"))?
                .push(format!("query {c}"));
            anyhow::bail!("no such call")
        }
        fn statistics(&self, _: &TransmitPermit) -> anyhow::Result<ControlReply> {
            anyhow::bail!("never asked")
        }
        fn describe(&self) -> String {
            "listing at 192.0.2.10:22222".to_string()
        }
    }

    impl Listing {
        fn new(held: usize) -> Self {
            Self {
                held,
                asked: Mutex::new(Vec::new()),
            }
        }

        fn lists_and_queries(&self) -> Result<(Vec<String>, usize), TestError> {
            let asked = self.asked.lock().map_err(|e| e.to_string())?.clone();
            let lists = asked
                .iter()
                .filter(|a| a.starts_with("list"))
                .cloned()
                .collect();
            let queries = asked.iter().filter(|a| a.starts_with("query")).count();
            Ok((lists, queries))
        }
    }

    fn permit() -> Result<TransmitPermit, TestError> {
        Ok(
            TransmitPermit::for_source(&crate::capture::CaptureSource::Live {
                device: "eth0".to_string(),
            })
            .ok_or("a live source grants a permit")?,
        )
    }

    fn cli(extra: &[&str]) -> Result<crate::cli::Cli, TestError> {
        let mut argv = vec![
            "sipnab",
            "-L",
            "127.0.0.1:0",
            "--rtpengine-control",
            "192.0.2.10:22222",
            "--json",
        ];
        argv.extend_from_slice(extra);
        Ok(crate::cli::Cli::try_parse_from_args(argv)?)
    }

    /// One snapshot of `relay` as `--relay-sessions` takes it.
    fn snapshot_of(
        relay: &Listing,
        permit: &TransmitPermit,
    ) -> crate::output::query::relay_sessions::RelaySessions {
        use crate::output::query::relay_sessions::{SessionsAsk, relay_sessions};
        let cap = crate::relay::scan_cap::ScanCap {
            cap: crate::relay::scan_cap::SCAN_CAP_DEFAULT,
            clamped: None,
        };
        relay_sessions(
            relay,
            permit,
            &SessionsAsk::capped(None, true, cap),
            &|_| false,
            &chrono::Utc::now,
        )
    }

    #[test]
    fn success_a_rated_ask_takes_two_snapshots_the_interval_apart() -> Result<(), TestError> {
        let relay = Listing::new(2);
        let p = permit()?;
        let mut waits = Vec::new();
        let answer = super::sessions_answer(
            &mut || snapshot_of(&relay, &p),
            Some(std::time::Duration::from_secs(3)),
            &mut |d| waits.push(d),
        );
        assert!(answer.answered(), "the second snapshot is the answer");
        assert_eq!(
            waits,
            [std::time::Duration::from_secs(3)],
            "one wait of the interval"
        );
        assert_eq!(
            relay.lists_and_queries()?,
            (vec!["list 32".to_string(), "list 32".to_string()], 4),
            "two lists and two queries per held call, nothing more"
        );
        Ok(())
    }

    #[test]
    fn success_the_interval_is_relay_stats_interval() -> Result<(), TestError> {
        let cli = cli(&["--relay-sessions", "--relay-stats-interval", "5"])?;
        assert_eq!(
            super::sessions_interval(&cli),
            Some(std::time::Duration::from_secs(5)),
            "the flag's seconds"
        );
        Ok(())
    }

    #[test]
    fn failure_without_an_interval_one_snapshot_and_no_wait() -> Result<(), TestError> {
        let relay = Listing::new(2);
        let p = permit()?;
        let mut waited = false;
        let answer = super::sessions_answer(&mut || snapshot_of(&relay, &p), None, &mut |_| {
            waited = true;
        });
        assert!(answer.answered(), "answered");
        assert!(!waited, "no interval, no wait");
        assert_eq!(
            relay.lists_and_queries()?,
            (vec!["list 32".to_string()], 2),
            "one list and its queries"
        );
        assert_eq!(
            super::sessions_interval(&cli(&["--relay-sessions"])?),
            None,
            "no flag, no interval"
        );
        Ok(())
    }

    #[test]
    fn failure_an_unanswered_first_snapshot_is_not_asked_again() -> Result<(), TestError> {
        let relay = Listing::new(2);
        let p = permit()?;
        let mut waited = false;
        let answer = super::sessions_answer(
            &mut || {
                let mut s = snapshot_of(&relay, &p);
                s.reach = "unreachable".to_string();
                s
            },
            Some(std::time::Duration::from_secs(1)),
            &mut |_| waited = true,
        );
        assert!(!answer.answered(), "the failure is the answer");
        assert!(!waited, "no wait after a failure");
        assert_eq!(
            relay.lists_and_queries()?.0.len(),
            1,
            "the relay was asked once"
        );
        Ok(())
    }

    /// `s` with each call answered and holding one RTP socket: the listing
    /// relay answers no query, so the rate tests give its calls a socket.
    fn with_one_rtp_socket(
        mut s: crate::output::query::relay_sessions::RelaySessions,
    ) -> crate::output::query::relay_sessions::RelaySessions {
        use crate::output::query::relay_sessions::{
            Counters, KernelVerdict, SessionSocket, SessionTag,
        };
        for c in &mut s.calls {
            c.outcome = "ok".to_string();
            c.tags = vec![SessionTag {
                tag: "caller-tag-1".to_string(),
                in_dialogue_with: Vec::new(),
                is_media_subscriber: false,
                sockets: vec![SessionSocket {
                    local_address: "192.0.2.11".to_string(),
                    local_port: 30000,
                    media_index: Some(1),
                    kind: "rtp".to_string(),
                    endpoint: None,
                    ingress: Counters {
                        packets: Some(0),
                        bytes: Some(0),
                        errors: None,
                    },
                    egress: Counters::default(),
                    last_packet: None,
                    kernel: KernelVerdict::NotReported,
                    ingress_rate: None,
                    captured_rate: None,
                }],
            }];
        }
        s
    }

    /// The first socket of the first call.
    fn first_socket(
        s: &crate::output::query::relay_sessions::RelaySessions,
    ) -> Result<&crate::output::query::relay_sessions::SessionSocket, TestError> {
        Ok(s.calls
            .first()
            .and_then(|c| c.tags.first())
            .and_then(|t| t.sockets.first())
            .ok_or("no socket")?)
    }

    /// One snapshot gives the answer a first REST or MCP ask gives:
    /// `no_rate_yet` from the relay, `not_captured` from the capture.
    #[test]
    fn success_a_one_shot_answer_reads_no_rate_yet_like_a_first_rest_ask() -> Result<(), TestError>
    {
        let relay = Listing::new(1);
        let p = permit()?;
        let answer = super::sessions_answer(
            &mut || with_one_rtp_socket(snapshot_of(&relay, &p)),
            None,
            &mut |_| {},
        );
        let socket = first_socket(&answer)?;
        assert_eq!(
            socket.ingress_rate,
            Some(crate::relay::rate::RateView::NoRateYet),
            "one answer, no rate yet"
        );
        assert_eq!(
            socket.captured_rate,
            Some(crate::relay::rate::RateView::NotCaptured),
            "the CLI reads no media"
        );
        Ok(())
    }

    #[test]
    fn edge_a_rated_answer_carries_rates_and_no_capture() -> Result<(), TestError> {
        let relay = Listing::new(1);
        let p = permit()?;
        let answer = super::sessions_answer(
            &mut || with_one_rtp_socket(snapshot_of(&relay, &p)),
            Some(std::time::Duration::from_secs(1)),
            &mut |_| {},
        );
        let socket = first_socket(&answer)?;
        assert!(socket.ingress_rate.is_some(), "a relay rate is attached");
        assert_eq!(
            socket.captured_rate,
            Some(crate::relay::rate::RateView::NotCaptured),
            "the CLI reads no media"
        );
        Ok(())
    }

    /// `--relay-sessions` scans up to `--relay-holdings-max`.
    #[test]
    fn cli_sessions_scan_takes_the_flag() -> Result<(), TestError> {
        let relay = Listing::new(5);
        let cli = cli(&["--relay-sessions", "--relay-holdings-max", "3"])?;
        assert_eq!(
            super::relay_sessions(&cli, &relay, None, &permit()?),
            0,
            "`--relay-sessions` scans up to `--relay-holdings-max`"
        );
        assert_eq!(
            relay.lists_and_queries()?,
            (vec!["list 3".to_string()], 3),
            "`--relay-sessions` scans up to `--relay-holdings-max`"
        );
        Ok(())
    }

    /// `--relay-sessions` with a flag above the ceiling asks for 1024 and
    /// queries at most 1024.
    #[test]
    fn cli_sessions_flag_above_the_ceiling_is_clamped() -> Result<(), TestError> {
        let relay = Listing::new(1100);
        let cli = cli(&["--relay-sessions", "--relay-holdings-max", "5000"])?;
        assert_eq!(
            super::relay_sessions(&cli, &relay, None, &permit()?),
            0,
            "`--relay-sessions` with a flag above the ceiling asks for 1024 and queries at most 1024"
        );
        assert_eq!(
            relay.lists_and_queries()?,
            (vec!["list 1024".to_string()], 1024),
            "`--relay-sessions` with a flag above the ceiling asks for 1024 and queries at most 1024"
        );
        Ok(())
    }

    /// `--relay-holdings` with a flag above the ceiling asks for 1024.
    #[test]
    fn cli_holdings_flag_above_the_ceiling_is_clamped() -> Result<(), TestError> {
        let relay = Listing::new(1);
        let cli = cli(&["--relay-holdings", "--relay-holdings-max", "4096"])?;
        assert_eq!(
            super::relay_holdings(&cli, &relay, None, &permit()?),
            0,
            "`--relay-holdings` with a flag above the ceiling asks for 1024"
        );
        assert_eq!(
            relay.lists_and_queries()?,
            (vec!["list 1024".to_string()], 0),
            "`--relay-holdings` with a flag above the ceiling asks for 1024"
        );
        Ok(())
    }

    /// A cap of 0 that bypassed the flag's parser (a `Cli` built by hand)
    /// fails the run and asks the relay nothing, on both flags.
    #[test]
    fn cli_cap_of_zero_asks_nothing() -> Result<(), TestError> {
        for flag in ["--relay-sessions", "--relay-holdings"] {
            let relay = Listing::new(3);
            let mut cli = cli(&[flag])?;
            cli.gate_args.relay_holdings_max = Some(0);
            let code = if flag == "--relay-sessions" {
                super::relay_sessions(&cli, &relay, None, &permit()?)
            } else {
                super::relay_holdings(&cli, &relay, None, &permit()?)
            };
            assert_eq!(code, 1, "{flag}");
            assert_eq!(relay.lists_and_queries()?, (Vec::new(), 0), "{flag}");
        }
        Ok(())
    }
}
