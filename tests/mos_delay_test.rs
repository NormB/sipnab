// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg(feature = "native")]

//! One-way delay is an INPUT to MOS, not a constant.
//!
//! `estimate_mos` computed `delay_ms = 100.0 + jitter_ms` — a fixed 100 ms
//! one-way baseline — and that term feeds `Id` in every MOS sipnab reports:
//! call list, stream detail, dashboard, JSON, REST, MCP and alerts.
//!
//! On an intercontinental or satellite leg the real one-way delay is 150-400 ms.
//! G.107's `Id` has a knee at 177.3 ms, above which the penalty grows with a
//! square-root term, so an assumed 100 ms does not merely shift the answer, it
//! stays on the wrong side of the knee entirely. The reported MOS is then wrong
//! by more than a full point on the number operators escalate on.
//!
//! This tree already reasons carefully about how trustworthy a MOS is:
//! `MosGrounding` says whether G.113 publishes an impairment factor for the
//! codec, and `MosProvenance` distinguishes what sipnab estimated from what an
//! endpoint asserted. The delay term is an unmeasured input standing in for a
//! measurement — the same species of assumption — and it was the one dimension
//! that model did not cover.

use sipnab::rtp::quality::{
    DEFAULT_ONE_WAY_DELAY_MS, estimate_mos, estimate_mos_with_delay, one_way_delay_from_rtt_ms,
};

/// The default is unchanged, so no existing reading moves silently.
#[test]
fn the_default_delay_reproduces_the_old_score() {
    assert_eq!(
        DEFAULT_ONE_WAY_DELAY_MS, 100.0,
        "changing the default silently re-scores every capture ever compared"
    );
    for (jitter, loss, codec) in [
        (5.0, 0.0, Some("PCMU")),
        (30.0, 2.0, Some("G729")),
        (80.0, 15.0, None),
    ] {
        assert_eq!(
            estimate_mos(jitter, loss, codec),
            estimate_mos_with_delay(jitter, loss, codec, DEFAULT_ONE_WAY_DELAY_MS),
            "the uncapped entry point must stay exactly the old function"
        );
    }
}

/// A real long-haul delay scores WORSE than the assumed 100 ms.
///
/// This is the defect: a satellite leg was scored as if it were a LAN.
#[test]
fn a_long_haul_delay_scores_lower_than_the_assumption() {
    let assumed = estimate_mos_with_delay(10.0, 0.0, Some("PCMU"), DEFAULT_ONE_WAY_DELAY_MS);
    let satellite = estimate_mos_with_delay(10.0, 0.0, Some("PCMU"), 300.0);
    assert!(
        satellite < assumed,
        "300 ms one-way must score below the assumed 100 ms; got {satellite} vs {assumed}"
    );
    // The gap is the size of the defect, not a rounding difference: G.107's Id
    // knee at 177.3 ms means a 300 ms path is penalised by the sqrt term the
    // assumption never reaches.
    assert!(
        assumed - satellite > 1.0,
        "the assumption should cost more than a full MOS point on a 300 ms \
         path; got {assumed} vs {satellite}"
    );
}

/// Below the knee the model stays linear, so a short path is barely affected.
#[test]
fn a_lan_path_scores_at_or_above_the_assumption() {
    let lan = estimate_mos_with_delay(10.0, 0.0, Some("PCMU"), 20.0);
    let assumed = estimate_mos_with_delay(10.0, 0.0, Some("PCMU"), DEFAULT_ONE_WAY_DELAY_MS);
    assert!(
        lan >= assumed,
        "a 20 ms path cannot score worse than an assumed 100 ms one; got {lan} vs {assumed}"
    );
}

/// Jitter still contributes on top of whatever the path delay is.
///
/// The old code folded jitter into the same term; keeping that relationship
/// means a jittery long-haul leg is worse than a smooth one, which is the
/// whole point of the term.
#[test]
fn jitter_still_worsens_the_score_at_any_delay() {
    for delay in [20.0, DEFAULT_ONE_WAY_DELAY_MS, 300.0] {
        let smooth = estimate_mos_with_delay(1.0, 0.0, Some("PCMU"), delay);
        let jittery = estimate_mos_with_delay(60.0, 0.0, Some("PCMU"), delay);
        assert!(
            jittery <= smooth,
            "at {delay} ms, jitter must never IMPROVE the score; got {jittery} vs {smooth}"
        );
        // Strictly worse only where there is room to be worse. MOS is defined
        // on 1.0..=5.0, and a 300 ms path is already at the floor before any
        // jitter is added — asserting a strict decrease there would be
        // asserting that the scale extends below its own minimum.
        if smooth > 1.0 {
            assert!(
                jittery < smooth,
                "at {delay} ms, with headroom above the floor, jitter must \
                 lower the score; got {jittery} vs {smooth}"
            );
        }
    }
}

/// A nonsense delay cannot produce a nonsense MOS.
///
/// MOS is defined on 1.0..=5.0. A negative or absurd input is a bug upstream,
/// and returning 7.3 or NaN would launder it into a number an operator reads
/// as a measurement.
#[test]
fn an_absurd_delay_still_yields_a_mos_in_range() {
    for delay in [-50.0, 0.0, 10_000.0, f64::MAX] {
        let mos = estimate_mos_with_delay(10.0, 1.0, Some("PCMU"), delay);
        assert!(
            (1.0..=5.0).contains(&mos) && mos.is_finite(),
            "delay {delay} produced {mos}, which is not a MOS"
        );
    }
}

/// A reported round trip becomes the one-way delay; absent means absent.
///
/// RFC 3611 uses 0 for "not available", and a genuinely zero round trip does
/// not happen on a path with two endpoints — so 0 must not become "0 ms of
/// delay", which would score BETTER than the honest assumption and hand the
/// operator a flattering number for a stream that measured nothing.
#[test]
fn a_reported_round_trip_halves_into_one_way_and_zero_means_unknown() {
    assert_eq!(one_way_delay_from_rtt_ms(600), Some(300.0));
    assert_eq!(one_way_delay_from_rtt_ms(40), Some(20.0));
    assert_eq!(
        one_way_delay_from_rtt_ms(0),
        None,
        "RFC 3611 uses 0 for not-available; treating it as a measurement of \
         zero would score an unmeasured stream better than an honest guess"
    );
}

/// The measured path changes the score — the whole point of measuring.
#[test]
fn a_measured_satellite_round_trip_scores_far_below_the_assumption() {
    let measured = one_way_delay_from_rtt_ms(600).expect("600ms rtt is a measurement");
    let scored = estimate_mos_with_delay(10.0, 0.0, Some("PCMU"), measured);
    let assumed = estimate_mos(10.0, 0.0, Some("PCMU"));
    assert!(
        assumed - scored > 3.0,
        "a 600 ms round trip is a satellite hop: the assumption reports \
         {assumed:.2} where the measurement gives {scored:.2}"
    );
}

/// The operator's figure beats a remote claim, which beats what sipnab derived
/// for itself, which beats the assumption.
///
/// Order matters for a reason that is not aesthetic: the declared value is the
/// only one an attacker on the media path cannot change, and an endpoint's own
/// round trip is the quantity G.114 is about while the echo-derived one is a
/// lower bound anchored on the capture point.
#[test]
fn declared_delay_wins_over_reported_wins_over_derived_wins_over_assumed() {
    use sipnab::rtp::quality::{DelaySource, resolve_one_way_delay};

    assert_eq!(
        resolve_one_way_delay(Some(280.0), Some(600), Some(90.0)),
        (280.0, DelaySource::Declared),
        "an operator who declared 280ms must not be overridden by a packet"
    );
    assert_eq!(
        resolve_one_way_delay(None, Some(600), Some(90.0)),
        (300.0, DelaySource::ReportedByEndpoint),
        "an endpoint's own round trip describes the call; the echo describes a \
         path segment plus a vantage point, so it must not outrank it"
    );
    assert_eq!(
        resolve_one_way_delay(None, None, Some(90.0)),
        (45.0, DelaySource::DerivedFromEcho),
        "with no XR, the figure derived from the RR echo must be used and \
         labelled as derived — never as something an endpoint reported"
    );
    assert_eq!(
        resolve_one_way_delay(None, None, None),
        (DEFAULT_ONE_WAY_DELAY_MS, DelaySource::Assumed),
        "with nothing at all, say so rather than imply a measurement"
    );
    assert_eq!(
        resolve_one_way_delay(None, Some(0), None),
        (DEFAULT_ONE_WAY_DELAY_MS, DelaySource::Assumed),
        "RFC 3611 uses 0 for not-available; it must not read as a 0ms path"
    );
    assert_eq!(
        resolve_one_way_delay(None, None, Some(0.0)),
        (DEFAULT_ONE_WAY_DELAY_MS, DelaySource::Assumed),
        "a derived round trip of zero is the derivation coming up empty, not a \
         path with no delay in it"
    );
    // A nonsense declared value falls through rather than poisoning the score.
    assert_eq!(
        resolve_one_way_delay(Some(f64::NAN), Some(600), None),
        (300.0, DelaySource::ReportedByEndpoint)
    );
    // ...and so does a nonsense derived one, rather than reaching the E-model.
    assert_eq!(
        resolve_one_way_delay(None, None, Some(f64::NAN)),
        (DEFAULT_ONE_WAY_DELAY_MS, DelaySource::Assumed)
    );

    // Each rank must be distinguishable in the output, or an operator cannot
    // tell which of the four remedies is theirs.
    let labels = [
        DelaySource::Declared,
        DelaySource::ReportedByEndpoint,
        DelaySource::DerivedFromEcho,
        DelaySource::Assumed,
    ]
    .map(DelaySource::label);
    let unique: std::collections::BTreeSet<&str> = labels.iter().copied().collect();
    assert_eq!(
        unique.len(),
        labels.len(),
        "two delay sources render the same label: {labels:?}"
    );
    assert!(
        DelaySource::Assumed.is_assumed(),
        "the one stand-in must report itself as one"
    );
    for measured in [
        DelaySource::Declared,
        DelaySource::ReportedByEndpoint,
        DelaySource::DerivedFromEcho,
    ] {
        assert!(
            !measured.is_assumed(),
            "{measured:?} is anchored on something real and must not be \
             caveated as a guess"
        );
    }
}

// ── The echo rank, end to end ────────────────────────────────────────
//
// Everything above tests the resolver in isolation. What follows tests the
// thing an operator meets: a stream carrying nothing but the receiver reports
// RFC 3550 makes mandatory — no XR VoIP-metrics block anywhere, which is the
// shape of essentially all real traffic — must now score on a delay derived
// from that stream's own RTCP rather than on the build-time constant.

use chrono::{DateTime, TimeDelta, Utc};
use sipnab::capture::parse::{ParsedPacket, TransportProto};
use sipnab::rtp::parser::RtpHeader;
use sipnab::rtp::quality::{DelaySource, resolve_one_way_delay};
use sipnab::rtp::rtcp::{ReceiverReport, ReceptionReport, RtcpPacket, RttSource};
use sipnab::rtp::stream::StreamKey;
use sipnab::rtp::stream_store::StreamStore;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// Fixed base timestamp, so the derived round trip is arithmetic rather than
/// a race with the wall clock.
fn ts(offset_ms: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(1_700_000_000, 0).expect("valid base")
        + TimeDelta::milliseconds(offset_ms)
}

/// The 5-tuple every stream in this section uses.
fn key_for(ssrc: u32) -> StreamKey {
    StreamKey {
        ssrc,
        src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 20000),
        dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30000),
    }
}

/// A UDP packet carrying a minimal PCMU RTP payload.
fn rtp_packet(ssrc: u32, seq: u16, at: DateTime<Utc>) -> ParsedPacket {
    let mut payload = Vec::with_capacity(172);
    payload.push(0x80);
    payload.push(0); // PT 0 = PCMU
    payload.extend_from_slice(&seq.to_be_bytes());
    payload.extend_from_slice(&(u32::from(seq) * 160).to_be_bytes());
    payload.extend_from_slice(&ssrc.to_be_bytes());
    payload.extend_from_slice(&[0x7F; 160]);
    ParsedPacket {
        frame: None,
        timestamp: at,
        src_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        dst_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        src_port: 20000,
        dst_port: 30000,
        transport: TransportProto::Udp,
        payload: payload.into(),
        ip_id: None,
        tcp_seq: None,
        tcp_flags: None,
        fragment_offset: None,
        more_fragments: false,
        ip_protocol: 17,
        dscp: None,
        from_hep: false,
    }
}

/// The header matching [`rtp_packet`].
fn rtp_header(ssrc: u32, seq: u16) -> RtpHeader {
    RtpHeader {
        version: 2,
        padding: false,
        extension: false,
        csrc_count: 0,
        marker: false,
        payload_type: 0,
        sequence: seq,
        timestamp: u32::from(seq) * 160,
        ssrc,
        payload_offset: 12,
    }
}

/// A store holding one clean PCMU stream plus ONE plain receiver report.
///
/// `sr_age_ms` is how long before the RR was seen that the SR it echoes went
/// out; `None` builds the RFC 3550 sentinel `last_sr = 0`, the reporter that
/// has heard no SR — which is the same RR in every other respect and yields no
/// round trip at all. Everything the E-model reads apart from the delay term
/// (jitter, loss, codec, packet count) is identical between the two, so a
/// difference in the score can only be the delay.
fn store_with_rr(ssrc: u32, sr_age_ms: Option<i64>, reporter_held_ms: i64) -> StreamStore {
    let mut store = StreamStore::new(16);
    for seq in 0u16..8 {
        let at = ts(i64::from(seq) * 20);
        store.process_rtp(&rtp_packet(ssrc, seq, at), &rtp_header(ssrc, seq), at);
    }
    let seen_at = ts(1_000);
    let last_sr = sr_age_ms.map_or(0, |age| {
        sipnab::rtp::rtcp::compact_ntp_for_test(seen_at - TimeDelta::milliseconds(age))
    });
    store.process_rtcp(
        &[RtcpPacket::ReceiverReport(ReceiverReport {
            ssrc: 0x9999_9999,
            reports: vec![ReceptionReport {
                ssrc,
                fraction_lost: 0,
                cumulative_lost: 0,
                highest_seq: 7,
                jitter: 0,
                last_sr,
                delay_since_sr: (reporter_held_ms as f64 * 65536.0 / 1000.0) as u32,
            }],
        })],
        seen_at,
    );
    store
}

/// Resolve exactly as the stream-detail view does, from a store and a key.
fn resolve_from_store(store: &StreamStore, key: &StreamKey) -> (f64, DelaySource) {
    resolve_one_way_delay(
        None,
        store
            .remote_voip_metrics(key)
            .map(|xr| xr.metrics.round_trip_delay),
        match store.round_trip(key) {
            Some((ms, RttSource::SenderReportEcho)) => Some(ms),
            _ => None,
        },
    )
}

/// A stream with an RR and no XR grounds its delay, and its MOS moves.
///
/// This is the whole defect. XR VoIP-metrics blocks are rare — most stacks
/// never emit one — so before this the delay term fell to
/// `DEFAULT_ONE_WAY_DELAY_MS` on effectively every call sipnab has ever
/// scored, no matter how much RTCP the call carried. The round trip needed to
/// do better was already being derived from the RR's `LSR`/`DLSR` pair and
/// shown in the RTT column beside the MOS; the MOS just did not read it.
#[test]
fn a_stream_with_only_receiver_reports_scores_on_a_derived_delay() {
    let ssrc = 0x0EC4_0EC4;
    let key = key_for(ssrc);
    // The SR went out 500 ms before the RR was seen and the reporter sat on it
    // for 50 ms: a 450 ms round trip, so 225 ms one way — past G.107's 177.3 ms
    // knee, which is where the assumption does its damage, and short of the
    // MOS floor, so the number that comes out is the model's and not a clamp.
    let store = store_with_rr(ssrc, Some(500), 50);

    assert!(
        store.remote_voip_metrics(&key).is_none(),
        "the fixture must carry NO XR block, or this proves nothing about the \
         calls that have none"
    );
    let (rtt_ms, rtt_src) = store
        .round_trip(&key)
        .expect("an RR echoing an SR is a round trip");
    assert_eq!(rtt_src, RttSource::SenderReportEcho);
    assert!((rtt_ms - 450.0).abs() < 5.0, "got {rtt_ms} ms");

    let (one_way, src) = resolve_from_store(&store, &key);
    assert_eq!(
        src,
        DelaySource::DerivedFromEcho,
        "an RR-only stream must no longer fall back to the assumption"
    );
    assert!(
        !src.is_assumed(),
        "a delay anchored on this stream's own RTCP is not a guess"
    );
    assert!(
        (one_way - 225.0).abs() < 5.0,
        "one way is half the derived round trip; got {one_way}"
    );

    // The effect: the score itself moves, and moves DOWN, because the assumed
    // 100 ms sat on the flat side of the Id knee and the real path does not.
    let stream = store.get(&key).expect("stream present");
    let derived_mos = estimate_mos_with_delay(stream.jitter, 0.0, stream.codec.as_deref(), one_way);
    let assumed_mos = estimate_mos(stream.jitter, 0.0, stream.codec.as_deref());
    assert!(
        assumed_mos - derived_mos > 1.0,
        "the assumption reported {assumed_mos:.2} where this stream's own RTCP \
         gives {derived_mos:.2} — if these are equal the delay never reached \
         the E-model"
    );
    assert!(
        derived_mos > 1.0,
        "a floored score would pass this test for the wrong reason; got \
         {derived_mos:.2}"
    );

    // Anti-vacuity: the SAME fixture with the RFC 3550 sentinel `last_sr = 0`
    // — a reporter that has heard no SR — still falls back, so what moved the
    // score is the echo and not the mere presence of a receiver report.
    let sentinel = store_with_rr(ssrc, None, 50);
    assert_eq!(
        resolve_from_store(&sentinel, &key),
        (DEFAULT_ONE_WAY_DELAY_MS, DelaySource::Assumed),
        "an RR with nothing to measure against must still say so"
    );
}

/// The operator reads the moved score, and reads where the delay came from.
///
/// The resolver could be right and the view still show the old number: the
/// stream-detail pane is where this MOS is presented to a human, so the effect
/// is asserted on the rendered cells rather than on the function that feeds
/// them.
#[cfg(feature = "tui")]
#[test]
fn the_stream_detail_view_shows_the_derived_delay_and_a_different_mos() {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use sipnab::tui::Theme;
    use sipnab::tui::stream_detail::{StreamDetailDisplay, render_stream_detail};

    fn render(store: &StreamStore, key: &StreamKey) -> String {
        let theme = Theme::default();
        let mut terminal = Terminal::new(TestBackend::new(120, 40)).expect("test terminal");
        terminal
            .draw(|frame| {
                let area = frame.area();
                render_stream_detail(
                    frame,
                    area,
                    key,
                    store,
                    0,
                    &StreamDetailDisplay {
                        declared_one_way_delay_ms: None,
                        theme: &theme,
                        resolver: &sipnab::names::NameResolver::new(),
                        name_mode: sipnab::names::NameMode::Off,
                        quality_bands: &sipnab::rtp::bands::QualityBands::default(),
                    },
                );
            })
            .expect("render");
        let buf = terminal.backend().buffer();
        let mut out = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                out.push_str(buf.cell((x, y)).map(|c| c.symbol()).unwrap_or(" "));
            }
            out.push('\n');
        }
        out
    }

    /// The `MOS: 4.4` cell, so the two renders are compared on the number and
    /// not on the whole pane.
    fn mos_cell(screen: &str) -> String {
        let at = screen.find("MOS: ").expect("the pane shows a MOS");
        screen[at..].chars().take(9).collect()
    }

    let ssrc = 0x0EC4_7401;
    let key = key_for(ssrc);
    let derived = render(&store_with_rr(ssrc, Some(500), 50), &key);
    let assumed = render(&store_with_rr(ssrc, None, 50), &key);

    assert!(
        derived.contains("delay 225ms from RR echo"),
        "the pane must show the derived figure and say it was derived:\n{derived}"
    );
    assert!(
        !derived.contains("assumed"),
        "a stream whose own RTCP grounded the delay must not be captioned as \
         a guess:\n{derived}"
    );
    assert!(
        assumed.contains("delay 100ms assumed"),
        "the sentinel fixture is the before picture and must still read \
         assumed:\n{assumed}"
    );
    assert_ne!(
        mos_cell(&derived),
        mos_cell(&assumed),
        "the same stream must not render the same MOS with and without a \
         grounded delay — that would mean the pane ignores the resolver"
    );
}

/// The FLAG reaches the resolver, and config fills in when it is absent.
///
/// `--one-way-delay` is the operator's half of the contract, so it is tested
/// through the same parser the binary uses rather than by calling the resolver
/// directly: a value that parses but never reaches `declared_one_way_delay_ms`
/// would satisfy every other test in this file and change nothing a user sees.
#[test]
fn the_one_way_delay_flag_parses_and_beats_config() {
    use sipnab::cli::Cli;
    use sipnab::config::Config;

    let mut cfg = Config::default();
    cfg.media.one_way_delay_ms = Some(120.0);

    // Nothing on the command line: the config value is the declared one.
    let bare = Cli::parse_from_args(["sipnab"]);
    assert_eq!(bare.declared_one_way_delay_ms(&cfg), Some(120.0));

    // And with neither, "undeclared" — NOT the default, which is what lets the
    // resolver fall through to what the far end reported.
    assert_eq!(
        bare.declared_one_way_delay_ms(&Config::default()),
        None,
        "undeclared must stay None, or the RTCP fallback becomes unreachable"
    );

    // The flag wins, the way every other numeric setting here behaves.
    let flagged = Cli::parse_from_args(["sipnab", "--one-way-delay", "280"]);
    assert_eq!(flagged.declared_one_way_delay_ms(&cfg), Some(280.0));
    assert_eq!(
        flagged.declared_one_way_delay_ms(&Config::default()),
        Some(280.0)
    );

    // And it actually moves the score it exists to move.
    let assumed = estimate_mos(10.0, 0.0, Some("PCMU"));
    let declared = estimate_mos_with_delay(
        10.0,
        0.0,
        Some("PCMU"),
        flagged.declared_one_way_delay_ms(&cfg).expect("declared"),
    );
    assert!(
        assumed - declared > 1.0,
        "a declared 280ms satellite path must score well below the 100ms \
         assumption; got {assumed:.2} vs {declared:.2}"
    );
}

// ── One stream, one MOS, every surface ───────────────────────────────
//
// Everything above proves the RESOLVER is right and that one TUI pane reads it.
// What follows proves the other consumers read the same thing, because they did
// not: `estimate_mos` was called with no delay at all from the filter DSL, the
// call-list MOS column, the canonical `StreamSummary` that REST, MCP and the
// TUI's JSON save all project through, the `--on-quality` alert threshold and
// the browser build. One scorer, one formula, and six surfaces reporting a
// domestic 100 ms path for calls whose own RTCP said otherwise.

/// The same stream scores the same MOS on every surface reachable from a test,
/// and that score is NOT the assumption.
///
/// The private scorers — REST's `approximate_mos`, MCP's `stream_mos` — cannot
/// be called from here; both delegate to `MosDelay::score` now, and
/// `no_surface_scores_a_mos_on_the_assumed_delay` in `surface_parity_test` is
/// what keeps them delegating. This is the behavioural half: the surfaces that
/// ARE reachable must agree on a real number rather than agree on a constant.
#[test]
fn one_stream_scores_one_mos_on_every_surface() {
    use sipnab::rtp::quality::MosDelay;

    let ssrc = 0x0EC4_5A11;
    let key = key_for(ssrc);
    // 500 ms since the SR, 50 ms held by the reporter: a 450 ms round trip,
    // 225 ms one way — past the 177.3 ms `Id` knee and short of the MOS floor.
    let store = store_with_rr(ssrc, Some(500), 50);
    let delay = MosDelay::from_capture(&store);
    let stream = store.get(&key).expect("stream present");

    // The filter DSL — `rtp.mos`, and so `--filter` and `--problems`.
    let dsl = sipnab::sip::dsl::stream_mos(stream, delay);
    // The canonical projection: REST `/v1/streams`, MCP `rtp_stats`, the CLI's
    // JSON and the TUI's "save streams as JSON".
    let summary = sipnab::output::model::StreamSummary::of(stream, delay).mos;

    let mut surfaces: Vec<(&str, f64)> = vec![("filter DSL", dsl), ("StreamSummary", summary)];
    surfaces.extend(tui_surfaces(&store));

    let assumed = estimate_mos(
        stream.jitter,
        stream.loss_percent(),
        stream.codec.as_deref(),
    );
    for (name, mos) in &surfaces {
        assert!(
            (mos - dsl).abs() < 1e-9,
            "{name} scored {mos:.4} where the filter DSL scored {dsl:.4}. One \
             stream, one MOS — a surface that disagrees is a surface an \
             operator can catch contradicting the one beside it"
        );
        // Anti-vacuity, and the whole point. A fixture with no RTCP would make
        // every surface agree on the assumption and prove nothing at all.
        assert!(
            assumed - mos > 1.0,
            "{name} reported {mos:.4}, which is the assumed-delay score \
             {assumed:.4} — this stream's own receiver reports put it 225 ms \
             out, so a surface still on the assumption has not moved"
        );
    }
    assert!(
        surfaces.len() >= 2,
        "only {} surfaces were compared, so this gate asserted almost nothing",
        surfaces.len()
    );
}

/// The TUI's own MOS surfaces for `store`: the call-list row and the sparkline
/// drawn inside it.
///
/// A function rather than a `#[cfg]` block inside the test, so the list it
/// extends is mutated on every feature set — a block leaves `surfaces`
/// needlessly `mut` without the TUI, and the warning that follows is the kind
/// a build eventually learns to ignore.
#[cfg(feature = "tui")]
fn tui_surfaces(store: &StreamStore) -> Vec<(&'static str, f64)> {
    let snap = sipnab::tui::dashboard::DashboardSnapshot::from_streams(store, None);
    let row = snap.rows.first().expect("one row");
    let mut out = vec![("TUI call list", row.mos)];
    // The sparkline beside the row too: a pane scoring its trend on a different
    // delay from its own headline is the defect that was closed in the
    // stream-detail view, one view over.
    if let Some(point) = row.trend.first() {
        out.push(("TUI call-list trend", point.mos));
    }
    out
}

/// No TUI compiled in, so it contributes no surface.
#[cfg(not(feature = "tui"))]
fn tui_surfaces(_store: &StreamStore) -> Vec<(&'static str, f64)> {
    Vec::new()
}

/// `rtp.mos < X` now SELECTS a call the assumption would have missed.
///
/// Consistency is not the point on its own — every surface agreeing on a wrong
/// number is still wrong. The point is that `--filter "rtp.mos < 3.5"` returns
/// the calls that were actually bad. This stream's audio is unacceptable on
/// delay alone (ITU-T G.114 puts interactive speech at about 150 ms one way and
/// this is 225 ms), and until the filter read the delay it scored above 4 and
/// was excluded from every triage sweep in the tool.
#[test]
fn a_measured_delay_selects_a_call_the_assumption_would_have_missed() {
    use sipnab::rtp::diagnosis::CaptureMedia;
    use sipnab::rtp::quality::MosDelay;
    use sipnab::sip::dsl::FilterExpr;

    let ssrc = 0x0EC4_5E1E;
    let key = key_for(ssrc);
    let mut store = store_with_rr(ssrc, Some(500), 50);
    let call_id = "delay-selection@example.net";
    store.link_to_dialog(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 20000, call_id);
    let stream = store.get(&key).expect("stream present");
    assert_eq!(
        stream.associated_dialog.as_deref(),
        Some(call_id),
        "the stream must belong to the dialog, or the filter sees no media"
    );

    let measured = MosDelay::from_capture(&store);
    let assumed_only = MosDelay::unknown();

    // A threshold BETWEEN the two scores, derived rather than hard-coded so it
    // cannot drift away from the model.
    let scored = sipnab::sip::dsl::stream_mos(stream, measured);
    let assumed = sipnab::sip::dsl::stream_mos(stream, assumed_only);
    assert!(
        assumed - scored > 1.0,
        "the fixture must straddle a threshold: got {assumed:.2} assumed vs \
         {scored:.2} measured"
    );
    let threshold = (scored + assumed) / 2.0;

    let filter = FilterExpr::parse(&format!("rtp.mos < {threshold:.4}")).expect("parses");
    let mut dialogs = sipnab::sip::dialog_store::DialogStore::new(16, false);
    dialogs.process_message(invite_for(call_id));
    let dialog = dialogs.get(call_id).expect("dialog tracked");
    let streams = [stream];

    assert!(
        filter.matches_dialog(dialog, &streams, CaptureMedia::Observed, measured),
        "`rtp.mos < {threshold:.2}` must select a call whose own RTCP scores it \
         {scored:.2}"
    );
    assert!(
        !filter.matches_dialog(dialog, &streams, CaptureMedia::Observed, assumed_only),
        "the same filter on the assumed 100 ms path must NOT select it — if it \
         does, this test is not measuring the change it exists to measure"
    );

    // And through the production selection path, which resolves the delay for
    // itself from the store rather than being handed it.
    let selection = sipnab::sip::dsl::select_dialogs(Some(&filter), &dialogs, &store);
    assert_eq!(
        selection.dialogs.len(),
        1,
        "`select_dialogs` is what --report and --json-dialogs narrow through; \
         it must select the same call the filter does"
    );
}

/// A parsed INVITE for `call_id`, carrying SDP for the fixture's media endpoint
/// so the dialog and the stream describe one call.
fn invite_for(call_id: &str) -> sipnab::sip::SipMessage {
    let body = "v=0\r\n\
                o=- 0 0 IN IP4 10.0.0.1\r\n\
                s=-\r\n\
                c=IN IP4 10.0.0.1\r\n\
                t=0 0\r\n\
                m=audio 20000 RTP/AVP 0\r\n\
                a=rtpmap:0 PCMU/8000\r\n";
    let mut raw = Vec::new();
    raw.extend_from_slice(b"INVITE sip:b@example.net SIP/2.0\r\n");
    for h in [
        "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-delay".to_string(),
        "From: <sip:a@example.net>;tag=aaa".to_string(),
        "To: <sip:b@example.net>".to_string(),
        format!("Call-ID: {call_id}"),
        "CSeq: 1 INVITE".to_string(),
        "Content-Type: application/sdp".to_string(),
        format!("Content-Length: {}", body.len()),
    ] {
        raw.extend_from_slice(h.as_bytes());
        raw.extend_from_slice(b"\r\n");
    }
    raw.extend_from_slice(b"\r\n");
    raw.extend_from_slice(body.as_bytes());
    sipnab::sip::parser::parse_sip(
        &raw,
        ts(0),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        5060,
        5060,
        sipnab::capture::parse::TransportProto::Udp,
    )
    .expect("INVITE parses")
}
