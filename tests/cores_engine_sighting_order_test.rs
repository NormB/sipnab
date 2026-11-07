// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The engines a call's ng requests reached are the same at every `--cores`.
//!
//! An `offer` or `delete` captured on its way to an engine is an engine
//! sighting, and the relay surfaces choose which engine to ask about a call
//! from the call's sightings (`sipnab::relay::engines::select`). `--cores N`
//! shards packets by host pair, so the requests of a call sent to two engines,
//! or by two proxies, are recorded on several workers, and the merge at the
//! end of the run joins the workers' tables. `--cores 1` defines the answer:
//! one table fed every request in the order the set is read, file by file in
//! the order of each file's first packet. When the files overlap in time, that
//! order is not timestamp order.
//!
//! Through 0.5.236 the merge ordered a call's sightings by timestamp and
//! applied the table's bounds to that order, so three things depended on which
//! worker owned which host pair: the order of two sightings of one instant,
//! which sightings of a call with more than the per-call bound were kept, and
//! which calls a full table kept. Each fixture below is one of the three.
//!
//! No `--cores N` command-line surface reads the merged table (the relay
//! surfaces refuse a `--cores` run), so both paths are driven through the
//! library: the `--cores` path as `tests/cores_callid_span_test.rs` drives its
//! shard-assignment test, and `--cores 1` as the `-I` reader
//! (`capture::file::capture_files`) feeding the shared per-packet applier
//! (`pipeline::process_packet`) one dialog store.
//!
//! Addresses are RFC 5737 documentation addresses and Call-IDs use
//! `example.com`.

#![cfg(feature = "native")]

#[path = "support/pcap_build.rs"]
mod pcap_build;

use std::net::{IpAddr, SocketAddr};

/// Any error a test can return; `?` converts into it.
type TestError = Box<dyn std::error::Error>;

/// The engines' `listen-ng` port, which `--rtpengine-ng-port` names.
const NG_PORT: u16 = 2223;

/// The proxies that send the requests.
const PROXIES: [[u8; 4]; 3] = [[192, 0, 2, 30], [192, 0, 2, 31], [192, 0, 2, 32]];

/// The engines the requests reach.
const ENGINES: [[u8; 4]; 4] = [
    [198, 51, 100, 10],
    [198, 51, 100, 11],
    [198, 51, 100, 12],
    [198, 51, 100, 13],
];

/// The worker counts compared against one worker.
const CORE_COUNTS: [usize; 3] = [2, 3, 4];

/// Shard assignments tried at each worker count (see
/// `ParallelConfig::shard_assignment`).
const ASSIGNMENTS: u64 = 12;

/// One ng request a proxy sent an engine.
struct Request {
    /// Microseconds after the capture's base second.
    at_us: u64,
    /// Index into [`PROXIES`].
    proxy: usize,
    /// Index into [`ENGINES`].
    engine: usize,
    /// The call it names.
    call: String,
    /// `offer` or `delete`.
    verb: &'static str,
}

impl Request {
    fn new(at_us: u64, proxy: usize, engine: usize, call: &str, verb: &'static str) -> Self {
        Self {
            at_us,
            proxy,
            engine,
            call: call.to_string(),
            verb,
        }
    }

    /// The captured frame, with its own cookie.
    fn frame(&self, cookie: usize) -> Result<Vec<u8>, TestError> {
        let payload = format!(
            "c{cookie} d7:call-id{}:{}7:command{}:{}8:from-tag2:fte",
            self.call.len(),
            self.call,
            self.verb.len(),
            self.verb
        );
        let sport = 40_000 + u16::try_from(self.proxy)?;
        Ok(pcap_build::udp_frame(
            PROXIES[self.proxy],
            ENGINES[self.engine],
            sport,
            NG_PORT,
            payload.as_bytes(),
        ))
    }
}

/// Two captures of one set, and the run's dialog limit, which sizes the
/// engine-sighting table.
struct Fixture {
    /// The capture read first: its first packet is the earlier one.
    first: Vec<Request>,
    /// The capture read second, overlapping the first in time.
    second: Vec<Request>,
    /// `--limit`.
    max_dialogs: usize,
}

impl Fixture {
    /// Every Call-ID the fixture names, sorted.
    fn calls(&self) -> Vec<String> {
        let set: std::collections::BTreeSet<&str> = self
            .first
            .iter()
            .chain(&self.second)
            .map(|r| r.call.as_str())
            .collect();
        set.into_iter().map(str::to_string).collect()
    }

    /// Write both captures to `dir`, returning them in read order (the
    /// order of their first packets), the order `-I` resolution hands the
    /// `--cores` path.
    fn write(&self, dir: &std::path::Path) -> Result<Vec<std::path::PathBuf>, TestError> {
        let mut cookie = 0;
        let mut paths = Vec::new();
        for (name, requests) in [("first.pcap", &self.first), ("second.pcap", &self.second)] {
            let mut frames = Vec::new();
            for r in requests {
                cookie += 1;
                frames.push((r.frame(cookie)?, r.at_us));
            }
            let path = dir.join(name);
            pcap_build::write_pcap_at(&path, &frames, 1)?;
            paths.push(path);
        }
        Ok(paths)
    }
}

const SECOND: u64 = 1_000_000;

/// The request that makes the first capture the one read first.
fn lead() -> Request {
    Request::new(0, 0, 0, "lead@example.com", "offer")
}

/// Calls whose two offers, one in each capture, carry one instant. The
/// first capture's offer is read first, so `--cores 1` holds it first, and
/// the newest offer is the second capture's.
fn ties() -> Fixture {
    let mut first = vec![lead()];
    let mut second = Vec::new();
    for (k, at) in (0..8).zip((1..).map(|s| s * SECOND)) {
        let call = format!("tie-{k}@example.com");
        first.push(Request::new(at, k % 3, k % 4, &call, "offer"));
        second.push(Request::new(at, (k + 1) % 3, (k + 1) % 4, &call, "offer"));
    }
    Fixture {
        first,
        second,
        max_dialogs: 100_000,
    }
}

/// One call with twenty offers, more than the sixteen kept per call: ten in
/// the capture read first, timed after the ten in the capture read second.
/// `--cores 1` forgets the four it read first; a timestamp order forgets the
/// four earliest, which hold the only offer that reached engine 3.
fn many() -> Fixture {
    const CALL: &str = "many@example.com";
    let mut first = vec![lead()];
    let mut second = Vec::new();
    for (k, s) in (0..10).zip(0..) {
        first.push(Request::new((10 + s) * SECOND, 0, k % 2, CALL, "offer"));
        let engine = if k == 2 { 3 } else { 2 };
        second.push(Request::new(
            SECOND / 2 + s * SECOND,
            1 + k % 2,
            engine,
            CALL,
            "offer",
        ));
    }
    Fixture {
        first,
        second,
        max_dialogs: 100_000,
    }
}

/// More sightings than a table sized for four dialogs keeps: 24 calls, each
/// offered in the capture read second and deleted in the one read first.
fn crowded() -> Fixture {
    let mut first = vec![lead()];
    let mut second = Vec::new();
    for (k, s) in (0..24).zip(0..) {
        let call = format!("crowd-{k}@example.com");
        second.push(Request::new(
            SECOND / 2 + s * SECOND,
            k % 3,
            k % 4,
            &call,
            "offer",
        ));
        first.push(Request::new(
            (30 + s) * SECOND,
            (k + 1) % 3,
            k % 4,
            &call,
            "delete",
        ));
    }
    Fixture {
        first,
        second,
        max_dialogs: 4,
    }
}

/// An engine map listing every engine, so a selection names one.
fn rules() -> Result<sipnab::relay::engines::EngineRules, TestError> {
    let rows = ENGINES
        .iter()
        .map(|e| sipnab::relay::engines::NgEngineRow {
            homer_id: None,
            control: SocketAddr::new(IpAddr::from(*e), NG_PORT),
        })
        .collect();
    Ok(sipnab::relay::engines::EngineRules {
        sdp: None,
        ng: sipnab::relay::engines::NgEngineMap::new(rows)?,
    })
}

/// The `--cores` path over `paths` at `cores` workers, grouping host pairs
/// by `assignment`.
fn sharded(
    paths: &[std::path::PathBuf],
    fixture: &Fixture,
    cores: usize,
    assignment: u64,
) -> Result<sipnab::parallel::ReconResult, TestError> {
    let cfg = sipnab::parallel::ParallelConfig {
        cores,
        max_streams: 100_000,
        max_dialogs: fixture.max_dialogs,
        rotate: false,
        max_reassembly: 1024,
        reassembly: true,
        parse_limit: None,
        shard_assignment: assignment,
        portrange: (5060, 5060),
        no_dialog: false,
        dialog_tracking: Default::default(),
        no_rtp: false,
        quiet_bad_parse: false,
        hep_parse: false,
        rtpproxy_control: None,
        ng_control_port: Some(NG_PORT),
        xcid_headers: Vec::new(),
        leg_correlation_window_ms: sipnab::sip::dialog_store::DEFAULT_LEG_CORRELATION_WINDOW_MS,
        retain_audio: false,
        audio_limits: sipnab::rtp::stream_store::AudioLimits::default(),
    };
    let cc = sipnab::capture::CaptureConfig::default();
    Ok(sipnab::parallel::run_offline_parallel_file(
        paths, &cc, cfg,
    )?)
}

/// `--cores 1` over `paths`: the `-I` reader feeding every packet, in read
/// order, to the per-packet applier and one dialog store.
fn single_reader(
    paths: &[std::path::PathBuf],
    fixture: &Fixture,
) -> Result<sipnab::sip::dialog_store::DialogStore, TestError> {
    let (tx, rx) = sipnab::capture::channel::packet_channel_batched(1 << 16);
    let cc = sipnab::capture::CaptureConfig::default();
    sipnab::capture::file::capture_files(paths, &cc, tx, None)?;
    let ds = std::sync::Arc::new(parking_lot::RwLock::new(
        sipnab::sip::dialog_store::DialogStore::new(fixture.max_dialogs, false),
    ));
    let ss = std::sync::Arc::new(parking_lot::RwLock::new(
        sipnab::rtp::stream_store::StreamStore::new(100_000),
    ));
    let opts = sipnab::pipeline::PipelineOptions {
        sip_portrange: Some((5060, 5060)),
        ng_control_port: Some(NG_PORT),
        ..Default::default()
    };
    let mut heuristic = sipnab::rtp::heuristic::RtpHeuristic::new();
    let mut read = 0;
    for packet in rx.try_iter() {
        read += 1;
        let pp = sipnab::capture::decode_captured_frame(&packet)?;
        sipnab::pipeline::process_packet(
            &pp,
            &ds,
            &ss,
            &mut heuristic,
            &opts,
            &mut sipnab::pipeline::MediaDecrypt::default(),
            None,
        );
    }
    assert_eq!(
        read,
        fixture.first.len() + fixture.second.len(),
        "the reader read every request"
    );
    let ds = std::sync::Arc::try_unwrap(ds).map_err(|_| "the store is still shared")?;
    Ok(ds.into_inner())
}

/// What one engine sighting says.
type Sighting = (
    sipnab::relay_vocab::EngineVerb,
    sipnab::relay_vocab::EngineIdentity,
    chrono::DateTime<chrono::Utc>,
    Option<SocketAddr>,
);

/// One call's engine sightings, and the engines chosen from them.
#[derive(Debug, PartialEq)]
struct CallView {
    call: String,
    /// Each sighting's verb, engine, instant and reported `listen-ng`.
    ng: Vec<Sighting>,
    chosen: sipnab::relay::engines::CallEngines,
}

/// The engine address of `ENGINES[i]`.
fn engine(i: usize) -> SocketAddr {
    SocketAddr::new(IpAddr::from(ENGINES[i]), NG_PORT)
}

/// Each Call-ID of the fixture, sorted, with its sightings and the engines
/// chosen from them.
fn engines_of(
    store: &sipnab::sip::dialog_store::DialogStore,
    fixture: &Fixture,
) -> Result<Vec<CallView>, TestError> {
    let rules = rules()?;
    let mut views = Vec::new();
    for call in fixture.calls() {
        let evidence = sipnab::relay::engines::call_sightings(store, &call);
        let chosen = sipnab::relay::engines::select(Some(&rules), engine(0), &evidence);
        views.push(CallView {
            call,
            ng: evidence
                .ng
                .iter()
                .map(|s| (s.verb, s.engine, s.at, s.reported_listen_ng))
                .collect(),
            chosen,
        });
    }
    Ok(views)
}

/// Compare every worker count with one worker on `fixture`, under every
/// assignment in `assignments`, returning the one-worker answer.
fn assert_same_at_every_core_count(
    fixture: &Fixture,
    assignments: std::ops::Range<u64>,
) -> Result<Vec<CallView>, TestError> {
    let dir = tempfile::tempdir()?;
    let paths = fixture.write(dir.path())?;
    let single = engines_of(&single_reader(&paths, fixture)?, fixture)?;
    for cores in CORE_COUNTS {
        for assignment in assignments.clone() {
            let multi = engines_of(
                &sharded(&paths, fixture, cores, assignment)?.dialog_store,
                fixture,
            )?;
            for (one, many) in single.iter().zip(&multi) {
                assert_eq!(
                    many, one,
                    "--cores {cores}, assignment {assignment}, differs from --cores 1"
                );
            }
            assert_eq!(
                multi.len(),
                single.len(),
                "--cores {cores}, assignment {assignment}: one view per call"
            );
        }
    }
    Ok(single)
}

/// The view of `call` in `views`.
fn view<'a>(views: &'a [CallView], call: &str) -> Result<&'a CallView, TestError> {
    Ok(views
        .iter()
        .find(|v| v.call == call)
        .ok_or_else(|| format!("{call} is reported"))?)
}

/// Whether some Call-ID of `fixture` has requests on host pairs that two
/// workers own at `cores`, under assignment 0.
fn splits_a_call(fixture: &Fixture, cores: usize) -> bool {
    fixture.calls().iter().any(|call| {
        let shards: std::collections::BTreeSet<usize> = fixture
            .first
            .iter()
            .chain(&fixture.second)
            .filter(|r| &r.call == call)
            .map(|r| {
                sipnab::parallel::shard_for(
                    IpAddr::from(PROXIES[r.proxy]),
                    IpAddr::from(ENGINES[r.engine]),
                    cores,
                )
            })
            .collect();
        shards.len() > 1
    })
}

/// Each fixture puts one call's requests on two workers at every compared
/// worker count, so each comparison exercises the merge.
#[test]
fn every_fixture_splits_a_call_across_workers() {
    for (name, fixture) in [("ties", ties()), ("many", many()), ("crowded", crowded())] {
        for cores in CORE_COUNTS {
            assert!(
                splits_a_call(&fixture, cores),
                "{name}: no call spans two workers at --cores {cores}"
            );
        }
    }
}

/// Two offers of one instant keep the order they were read in, so the
/// engine chosen is the one the offer read last reached.
#[test]
fn a_tie_in_time_is_ordered_as_read_at_every_core_count() -> Result<(), TestError> {
    let single = assert_same_at_every_core_count(&ties(), 0..1)?;
    let tie = view(&single, "tie-0@example.com")?;
    assert_eq!(
        tie.chosen.current.as_ref().map(|e| e.control).ok(),
        Some(engine(1)),
        "the offer read last, to engine 1, is chosen: {tie:?}"
    );
    Ok(())
}

/// A call with more sightings than are kept per call keeps the same ones at
/// every core count: the ones read last.
#[test]
fn a_call_past_the_per_call_bound_keeps_the_same_sightings() -> Result<(), TestError> {
    let single = assert_same_at_every_core_count(&many(), 0..1)?;
    let call = view(&single, "many@example.com")?;
    assert!(call.ng.len() < 20, "some offers are forgotten: {call:?}");
    assert!(
        call.chosen
            .leftovers
            .iter()
            .any(|l| l.engine == sipnab::relay_vocab::EngineIdentity::ListenNg(engine(3))),
        "the offer to engine 3, read last, is kept: {call:?}"
    );
    Ok(())
}

/// A table past its bound keeps the same calls and sightings at every core
/// count: the ones read last.
#[test]
fn a_full_table_keeps_the_same_calls_at_every_core_count() -> Result<(), TestError> {
    let single = assert_same_at_every_core_count(&crowded(), 0..1)?;
    let forgotten = single.iter().filter(|v| v.ng.is_empty()).count();
    assert!(
        forgotten > 0 && forgotten < single.len(),
        "the table forgot some calls and kept others: {single:#?}"
    );
    Ok(())
}

/// The sightings do not depend on which host pairs share a worker: each
/// assignment is a different grouping, as a change to the shard hash would
/// be one more.
#[test]
fn the_sightings_do_not_depend_on_the_shard_assignment() -> Result<(), TestError> {
    for fixture in [ties(), many(), crowded()] {
        assert_same_at_every_core_count(&fixture, 0..ASSIGNMENTS)?;
    }
    Ok(())
}
