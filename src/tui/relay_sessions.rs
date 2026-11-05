// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The relay sessions view's state and its off-thread snapshot.
//!
//! `H` in the relay view opens it. While it is open it refreshes `list` and the
//! selected call every `--relay-stats-interval`, or every
//! [`DEFAULT_REFRESH_SECS`] when no interval was given, and queries the other
//! held calls only when the scan key is pressed, once per press. Nothing is
//! asked while the view is closed.
//!
//! The snapshot is taken by [`relay_sessions_routed`], the function every
//! other surface uses, on a worker thread, as [`super::relay_stats::spawn_ask`] does:
//! the input and render thread never waits on the relay. The text is rendered
//! by the same functions `--relay-sessions` prints with, so a word cannot
//! differ between surfaces.

use std::sync::Arc;
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

use super::relay_stats::TuiRelayAccess;
use crate::output::query::relay_sessions::{
    RelaySessions, Routed, SessionCall, SessionsAsk, relay_sessions_routed,
};

/// How often the open view refreshes when the run set no
/// `--relay-stats-interval`: `list` plus the selected call, two transactions.
pub const DEFAULT_REFRESH_SECS: u64 = 2;

/// The view's last answer and the snapshot in flight.
#[derive(Default)]
pub struct SessionsCache {
    /// The newest snapshot in which the relay answered its `list`.
    pub answered: Option<RelaySessions>,
    /// The newest snapshot in which it did not, when that is newer than
    /// `answered`. Shown above the kept answer, never in place of it.
    pub failed: Option<RelaySessions>,
    /// When `answered` arrived, for its age.
    pub answered_at: Option<Instant>,
    /// When the last snapshot was started, for the refresh cadence.
    pub asked_at: Option<Instant>,
    /// The channel the worker sends its one snapshot on, while one is in
    /// flight.
    pub rx: Option<Receiver<RelaySessions>>,
    /// Whether the scan key was pressed since the last snapshot started.
    pub scan_requested: bool,
    /// The row under the cursor in the list.
    pub selected: usize,
}

impl SessionsCache {
    /// Whether a snapshot is in flight.
    #[must_use]
    pub fn pending(&self) -> bool {
        self.rx.is_some()
    }

    /// Take a finished snapshot, if one landed. A snapshot the relay answered
    /// replaces the kept answer; one it did not is kept beside it.
    pub fn absorb(&mut self, now: Instant) {
        let Some(snapshot) = self.rx.as_ref().and_then(|rx| rx.try_recv().ok()) else {
            return;
        };
        self.rx = None;
        if snapshot.answered() {
            self.answered = Some(snapshot);
            self.answered_at = Some(now);
            self.failed = None;
        } else {
            self.failed = Some(snapshot);
        }
    }

    /// The Call-ID under the cursor, from the kept answer.
    #[must_use]
    pub fn selected_call(&self) -> Option<String> {
        let rows = self.answered.as_ref()?.rows();
        rows.get(self.selected.min(rows.len().saturating_sub(1)))
            .map(|s| (*s).to_string())
    }

    /// Move the cursor by `delta` rows, clamped to the rows there are.
    pub fn move_cursor(&mut self, delta: isize) {
        let n = self.answered.as_ref().map_or(0, |s| s.rows().len());
        let max = n.saturating_sub(1);
        self.selected = self.selected.saturating_add_signed(delta).min(max);
    }
}

/// Whether the open view is due a refresh: none taken yet, or the interval
/// (`--relay-stats-interval`, else [`DEFAULT_REFRESH_SECS`]) has passed since
/// the last one started. Pure, so the cadence is tested without a clock.
#[must_use]
pub fn refresh_due(asked_at: Option<Instant>, now: Instant, interval_secs: Option<u64>) -> bool {
    let every = Duration::from_secs(interval_secs.unwrap_or(DEFAULT_REFRESH_SECS));
    asked_at.is_none_or(|then| now.saturating_duration_since(then) >= every)
}

/// Take one snapshot on a worker thread and hand back the receiver it will
/// arrive on.
///
/// `sip_ended` answers, for a Call-ID, whether sipnab saw its SIP dialog end;
/// it is read on the worker, never on the caller's thread.
#[must_use]
pub fn spawn_snapshot(
    access: TuiRelayAccess,
    selected: Option<String>,
    scan: bool,
    cap: u32,
    sip_ended: Arc<dyn Fn(&str) -> bool + Send + Sync>,
) -> Receiver<RelaySessions> {
    spawn_snapshot_for(
        access,
        selected,
        scan,
        cap,
        sip_ended,
        Arc::new(|_: &str| Vec::new()),
    )
}

/// [`spawn_snapshot`], with `sdp_of` answering a Call-ID's SDP sightings,
/// which choose its engine when an engine rule is configured. Read on the
/// worker, like `sip_ended`.
#[must_use]
pub fn spawn_snapshot_for(
    access: TuiRelayAccess,
    selected: Option<String>,
    scan: bool,
    cap: u32,
    sip_ended: Arc<dyn Fn(&str) -> bool + Send + Sync>,
    sdp_of: crate::relay::engines::SdpLookup,
) -> Receiver<RelaySessions> {
    let (tx, rx) = std::sync::mpsc::channel();
    let spawned = std::thread::Builder::new()
        .name("relay-sessions".to_owned())
        .spawn(move || {
            let ask = SessionsAsk {
                selected: selected.as_deref(),
                scan,
                cap,
                list_limit: cap,
            };
            let sdp = |c: &str| sdp_of(c);
            let routed = access.routing.as_deref().map(|routing| Routed {
                routing,
                sdp_of: &sdp,
            });
            let snapshot = relay_sessions_routed(
                access.relay.as_ref(),
                routed.as_ref(),
                &access.permit,
                &ask,
                sip_ended.as_ref(),
                &chrono::Utc::now,
            );
            // The receiver is gone when the view closed first: that ordinary
            // race is not an error.
            let _ = tx.send(snapshot);
        });
    // A thread that will not spawn leaves the view on its kept answer.
    let _ = spawned;
    rx
}

/// The list view's text: the kept answer with the cursor, the failure of a
/// newer snapshot above it with the kept answer's age, or a waiting line.
#[must_use]
pub fn compose_list(cache: &SessionsCache, now: Instant) -> String {
    let mut out = String::new();
    if let Some(failed) = &cache.failed {
        out.push_str(&failed.render_status());
        if let Some(at) = cache.answered_at {
            out.push_str(&format!(
                "Showing the last answer, from {} s ago.\n\n",
                now.saturating_duration_since(at).as_secs()
            ));
        }
    }
    match &cache.answered {
        Some(s) => {
            out.push_str(&s.render_status());
            out.push_str(&s.render_rows(Some(cache.selected)));
            out.push_str(
                "\nEnter opens the call under the cursor; a asks every held call once \
                 (up to the cap).\n",
            );
        }
        None if cache.failed.is_none() => out.push_str("asking the relay…\n"),
        None => {}
    }
    out
}

/// The per-call view's text: that call's directions and sockets from the kept
/// answer, or a line saying it is being asked.
#[must_use]
pub fn compose_call(cache: &SessionsCache, call_id: &str) -> String {
    let call = cache
        .answered
        .as_ref()
        .and_then(|s| s.calls.iter().find(|c| c.call_id == call_id));
    match call {
        Some(c) => {
            let mut out = String::new();
            if let Some(failed) = &cache.failed {
                out.push_str(&failed.render_status());
            }
            out.push_str(&c.render());
            out.push_str("\nK compares each relay socket with what this capture saw.\n");
            out
        }
        None => format!("asking the relay about call {call_id}…\n"),
    }
}

/// Which way across a relay socket a capture count is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Way {
    /// Packets the capture saw sent TO the relay socket.
    ToRelay,
    /// Packets the capture saw sent FROM it.
    FromRelay,
}

/// The per-socket comparison: what the relay counted on each socket beside
/// what this capture saw sent to and from it. Two tiers side by side, never
/// subtracted. `captured` answers for a socket and a way, `None` when the
/// capture holds no stream there.
#[must_use]
pub fn compose_socket_compare(
    call: &SessionCall,
    captured: &dyn Fn(&str, u16, Way) -> Option<u64>,
) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "Call {}: relay sockets beside this capture",
        call.call_id
    );
    let _ = writeln!(
        out,
        "relay_reported is what the relay counted; sipnab_measured is what this capture saw.\n"
    );
    let shown =
        |v: Option<u64>, absent: &str| v.map_or_else(|| absent.to_string(), |n| n.to_string());
    for tag in &call.tags {
        for s in &tag.sockets {
            let _ = writeln!(
                out,
                "{} {}:{} ({})",
                tag.tag, s.local_address, s.local_port, s.kind
            );
            let _ = writeln!(
                out,
                "  in:  relay_reported {}  sipnab_measured {}",
                shown(s.ingress.packets, "not reported"),
                shown(
                    captured(&s.local_address, s.local_port, Way::ToRelay),
                    "not captured"
                ),
            );
            let _ = writeln!(
                out,
                "  out: relay_reported {}  sipnab_measured {}",
                shown(s.egress.packets, "not reported"),
                shown(
                    captured(&s.local_address, s.local_port, Way::FromRelay),
                    "not captured"
                ),
            );
        }
    }
    out
}

/// The cadence, the worker and the texts, against relays that answer in
/// memory. Nothing here opens a socket.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::query::relay_sessions::{
        Counters, KernelVerdict, NotQueried, SessionSocket, SessionTag, SipDialog,
    };
    use crate::relay::reconcile::ReadOnlyRelay;
    use crate::relay::types::{ControlReply, Enumeration};
    use crate::security::transmit_guard::TransmitPermit;
    use std::sync::Mutex;
    use std::sync::mpsc::{self, TryRecvError};

    type TestError = Box<dyn std::error::Error>;

    /// A relay whose `list` blocks until the test releases it, recording
    /// that it was asked.
    struct GatedRelay {
        gate: Mutex<mpsc::Receiver<()>>,
        asked: Mutex<Vec<String>>,
    }

    impl ReadOnlyRelay for GatedRelay {
        fn list(&self, _: &TransmitPermit, limit: u32) -> anyhow::Result<ControlReply> {
            self.asked
                .lock()
                .map_err(|e| anyhow::anyhow!("{e}"))?
                .push(format!("list {limit}"));
            self.gate
                .lock()
                .map_err(|e| anyhow::anyhow!("{e}"))?
                .recv()
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            Ok(ControlReply::Calls(Enumeration {
                call_ids: vec!["a@example.invalid".to_string()],
                truncated: false,
            }))
        }
        fn query(&self, _: &TransmitPermit, c: &str) -> anyhow::Result<ControlReply> {
            anyhow::bail!("not asked for {c} in these tests")
        }
        fn statistics(&self, _: &TransmitPermit) -> anyhow::Result<ControlReply> {
            anyhow::bail!("never asked")
        }
        fn describe(&self) -> String {
            "gated".to_string()
        }
    }

    fn access(relay: Arc<GatedRelay>) -> Result<TuiRelayAccess, TestError> {
        let live = crate::capture::CaptureSource::Live {
            device: "eth0".to_string(),
        };
        Ok(TuiRelayAccess {
            relay,
            permit: TransmitPermit::for_source(&live).ok_or("a live source grants a permit")?,
            addr: "192.0.2.10:22222".parse()?,
            routing: None,
        })
    }

    /// The first refresh is due at once; the next after the interval, which
    /// is `--relay-stats-interval` when set and 2 s when not.
    #[test]
    fn a_refresh_is_due_at_open_and_then_every_interval() {
        let t0 = Instant::now();
        assert!(
            refresh_due(None, t0, None),
            "The first refresh is due at once"
        );
        assert!(
            !refresh_due(Some(t0), t0 + Duration::from_millis(1999), None),
            "The first refresh is due at once"
        );
        assert!(
            refresh_due(Some(t0), t0 + Duration::from_secs(2), None),
            "The first refresh is due at once"
        );
        assert!(
            !refresh_due(Some(t0), t0 + Duration::from_secs(4), Some(5)),
            "The first refresh is due at once"
        );
        assert!(
            refresh_due(Some(t0), t0 + Duration::from_secs(5), Some(5)),
            "The first refresh is due at once"
        );
    }

    /// The snapshot is taken on a worker: starting it returns while the relay
    /// has not answered, and the snapshot arrives once it does.
    #[test]
    fn starting_a_snapshot_returns_before_a_slow_relay_answers() -> Result<(), TestError> {
        let (release, gate) = mpsc::channel();
        let relay = Arc::new(GatedRelay {
            gate: Mutex::new(gate),
            asked: Mutex::new(Vec::new()),
        });
        let rx = spawn_snapshot(
            access(Arc::clone(&relay))?,
            None,
            false,
            32,
            Arc::new(|_: &str| false),
        );
        assert!(
            matches!(rx.try_recv(), Err(TryRecvError::Empty)),
            "nothing has arrived while the relay holds its answer"
        );
        release.send(())?;
        let snapshot = rx.recv_timeout(Duration::from_secs(10))?;
        assert!(snapshot.answered(), "The snapshot is taken on a worker");
        assert_eq!(
            snapshot.rows(),
            ["a@example.invalid"],
            "The snapshot is taken on a worker"
        );
        assert_eq!(
            *relay.asked.lock().map_err(|e| e.to_string())?,
            ["list 32"],
            "The snapshot is taken on a worker"
        );
        Ok(())
    }

    /// A snapshot with no rows queried, answered or not.
    fn snapshot(reach: &str, ids: &[&str]) -> RelaySessions {
        RelaySessions {
            relay: "relay (gated)".to_string(),
            obtained_at: "2026-11-04T12:00:00+00:00".to_string(),
            tier: "relay_reported".to_string(),
            reach: reach.to_string(),
            detail: (reach != "ok").then(|| "relay (gated) did not answer".to_string()),
            held: (reach == "ok").then_some(ids.len()),
            list_limit: 32,
            truncated: (reach == "ok").then_some(false),
            scan: false,
            cap: 32,
            calls: Vec::new(),
            not_queried: ids
                .iter()
                .map(|c| NotQueried {
                    call_id: (*c).to_string(),
                    sip_dialog: SipDialog::NotSeenEnded,
                    engine: None,
                })
                .collect(),
            stall_seconds: 2,
            notes: Vec::new(),
            engines: None,
        }
    }

    /// A refresh the relay does not answer keeps the last answer on screen,
    /// says the relay is unreachable, and gives the kept answer's age.
    #[test]
    fn an_unreachable_refresh_keeps_the_last_answer_with_its_age() -> Result<(), TestError> {
        let t0 = Instant::now();
        let mut cache = SessionsCache::default();
        let (tx, rx) = mpsc::channel();
        cache.rx = Some(rx);
        tx.send(snapshot("ok", &["a@example.invalid"]))?;
        cache.absorb(t0);
        let (tx, rx) = mpsc::channel();
        cache.rx = Some(rx);
        tx.send(snapshot("unreachable", &[]))?;
        cache.absorb(t0 + Duration::from_secs(4));
        assert!(
            !cache.pending(),
            "A refresh the relay does not answer keeps the last answer on screen, says the relay is unreachable, and gives the kept answer's age"
        );
        let text = compose_list(&cache, t0 + Duration::from_secs(7));
        assert!(
            text.contains("unreachable: relay (gated) did not answer"),
            "{text}"
        );
        assert!(text.contains("from 7 s ago"), "{text}");
        assert!(text.contains("> a@example.invalid"), "the kept row: {text}");
        Ok(())
    }

    /// The cursor stays on the rows there are, and names the call under it.
    #[test]
    fn the_cursor_is_clamped_and_names_its_call() {
        let mut cache = SessionsCache {
            answered: Some(snapshot("ok", &["b@example.invalid", "a@example.invalid"])),
            ..SessionsCache::default()
        };
        cache.move_cursor(5);
        assert_eq!(
            cache.selected, 1,
            "The cursor stays on the rows there are, and names the call under it"
        );
        assert_eq!(
            cache.selected_call().as_deref(),
            Some("b@example.invalid"),
            "The cursor stays on the rows there are, and names the call under it"
        );
        cache.move_cursor(-9);
        assert_eq!(
            cache.selected_call().as_deref(),
            Some("a@example.invalid"),
            "The cursor stays on the rows there are, and names the call under it"
        );
    }

    /// Each relay socket's counts sit beside what the capture saw on it, two
    /// tiers named and never subtracted; a socket the capture has no stream
    /// on says so instead of 0.
    #[test]
    fn the_socket_compare_sets_two_tiers_side_by_side() {
        let socket = |port: u16, packets_in: u64| SessionSocket {
            local_address: "192.0.2.11".to_string(),
            local_port: port,
            media_index: Some(1),
            kind: "rtp".to_string(),
            endpoint: None,
            ingress: Counters {
                packets: Some(packets_in),
                bytes: None,
                errors: None,
            },
            egress: Counters::default(),
            last_packet: None,
            kernel: KernelVerdict::Userspace,
        };
        let call = SessionCall {
            call_id: "c@example.invalid".to_string(),
            outcome: "ok".to_string(),
            detail: None,
            sip_dialog: SipDialog::NotSeenEnded,
            directions: Vec::new(),
            unjudged: None,
            tags: vec![SessionTag {
                tag: "caller-tag-1".to_string(),
                in_dialogue_with: Vec::new(),
                is_media_subscriber: false,
                sockets: vec![socket(30000, 2250), socket(30002, 0)],
            }],
            engine: None,
        };
        let captured = |_: &str, port: u16, way: Way| match (port, way) {
            (30000, Way::ToRelay) => Some(2249),
            _ => None,
        };
        let text = compose_socket_compare(&call, &captured);
        assert!(
            text.contains("caller-tag-1 192.0.2.11:30000 (rtp)\n  in:  relay_reported 2250  sipnab_measured 2249"),
            "{text}"
        );
        assert!(
            text.contains(
                "192.0.2.11:30002 (rtp)\n  in:  relay_reported 0  sipnab_measured not captured"
            ),
            "{text}"
        );
        assert!(text.contains("out: relay_reported not reported"), "{text}");
        assert!(
            !text.contains("difference") && !text.contains(" 1\n"),
            "{text}"
        );
    }

    /// One engine that lists `m-1@example.invalid` and holds it.
    struct Holder(&'static str);

    impl ReadOnlyRelay for Holder {
        fn list(&self, _: &TransmitPermit, _: u32) -> anyhow::Result<ControlReply> {
            Ok(ControlReply::Calls(Enumeration {
                call_ids: vec!["m-1@example.invalid".to_string()],
                truncated: false,
            }))
        }
        fn query(&self, _: &TransmitPermit, c: &str) -> anyhow::Result<ControlReply> {
            Ok(ControlReply::Call(crate::relay::types::CallView {
                call_id: c.to_string(),
                tags: Vec::new(),
            }))
        }
        fn statistics(&self, _: &TransmitPermit) -> anyhow::Result<ControlReply> {
            anyhow::bail!("never asked")
        }
        fn describe(&self) -> String {
            self.0.to_string()
        }
    }

    /// With an engine rule the view's snapshot lists every engine and asks
    /// the call's own engine, chosen from the SDP the view hands it.
    #[test]
    fn a_snapshot_with_an_engine_rule_asks_the_calls_engine() -> Result<(), TestError> {
        use crate::relay::engines::{
            Connect, EngineMap, EngineRouting, EngineRow, EngineRule, SdpSighting,
        };
        let rows = vec![
            "203.0.113.5 30000-39999 192.0.2.5:2223".parse::<EngineRow>()?,
            "203.0.113.5 40000-49999 192.0.2.6:2223".parse::<EngineRow>()?,
        ];
        let connect: Connect = Arc::new(|_| Arc::new(Holder("engine-b")));
        let live = crate::capture::CaptureSource::Live {
            device: "eth0".to_string(),
        };
        let access = TuiRelayAccess {
            relay: Arc::new(Holder("engine-a")),
            permit: TransmitPermit::for_source(&live).ok_or("a live source grants a permit")?,
            addr: "192.0.2.5:2223".parse()?,
            routing: Some(Arc::new(EngineRouting::new(
                EngineRule::Map(EngineMap::new(rows)?),
                "192.0.2.5:2223".parse()?,
                false,
                connect,
            ))),
        };
        let sdp_of: crate::relay::engines::SdpLookup = Arc::new(|_: &str| {
            vec![SdpSighting {
                at: chrono::DateTime::UNIX_EPOCH,
                from_request: true,
                address: "203.0.113.5".to_string(),
                port: 40010,
            }]
        });
        let rx = spawn_snapshot_for(
            access,
            Some("m-1@example.invalid".to_string()),
            false,
            32,
            Arc::new(|_: &str| false),
            sdp_of,
        );
        let snapshot = rx.recv_timeout(Duration::from_secs(10))?;
        assert_eq!(
            snapshot.engines.as_ref().map(Vec::len),
            Some(2),
            "a snapshot with an engine rule asks the calls engine"
        );
        let engine = snapshot
            .calls
            .first()
            .and_then(|c| c.engine.as_ref())
            .ok_or("the call names its engine")?;
        assert_eq!(
            engine.asked.as_deref(),
            Some("relay (engine-b)"),
            "a snapshot with an engine rule asks the calls engine"
        );
        assert!(engine.held_by_several_engines, "both engines list it");
        Ok(())
    }
}
