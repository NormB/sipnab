// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-frame derived-data benchmarks for the TUI (WS4.3).
//!
//! The CallList view recomputes its derived data every frame; `search_frame`
//! models what one frame costs TODAY — the status-bar count pass, the
//! autoscroll row count and the render rows are three separate
//! filter+search+sort passes over the whole store. The ladder benchmark
//! covers the CallFlow side (`prepare_messages`), which WS4.3 memoizes.
//! Baselines live in `benches/BASELINES.md`.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use chrono::{TimeZone, Utc};
use criterion::{Criterion, criterion_group, criterion_main};
use crossterm::event::KeyCode;
use parking_lot::RwLock;
use ratatui::Terminal;
use ratatui::backend::TestBackend;

use sipnab::capture::parse::TransportProto;
use sipnab::names::{NameMode, NameResolver};
use sipnab::rtp::stream_store::StreamStore;
use sipnab::sip::SipMessage;
use sipnab::sip::dialog_store::DialogStore;
use sipnab::sip::parser::parse_sip;
use sipnab::tui::call_flow::{FlowDisplayOptions, prepare_messages};
use sipnab::tui::call_list::displayed_dialogs;
use sipnab::tui::{App, ColorMode, Keymap, SdpDisplayMode, Theme, TimestampMode};

fn addr(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
}

fn sip_msg(raw: &[u8], src: u8, dst: u8, off_ms: i64) -> SipMessage {
    let ts = Utc.with_ymd_and_hms(2024, 6, 15, 12, 0, 0).unwrap()
        + chrono::TimeDelta::milliseconds(off_ms);
    parse_sip(
        raw,
        ts,
        addr(src),
        addr(dst),
        5060,
        5060,
        TransportProto::Udp,
    )
    .expect("parse")
}

fn invite(call_id: &str, cseq: u32, src: u8, dst: u8, off_ms: i64) -> SipMessage {
    let raw = format!(
        "INVITE sip:bob@example.com SIP/2.0\r\n\
         Via: SIP/2.0/UDP 10.0.0.{src}:5060;branch=z9hG4bK{call_id}-{cseq}\r\n\
         From: \"alice\" <sip:alice@example.com>;tag=a{call_id}\r\n\
         To: <sip:bob@example.com>\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: {cseq} INVITE\r\n\
         Content-Length: 0\r\n\r\n"
    );
    sip_msg(raw.as_bytes(), src, dst, off_ms)
}

fn response(call_id: &str, status: u16, cseq: u32, off_ms: i64) -> SipMessage {
    let raw = format!(
        "SIP/2.0 {status} X\r\n\
         Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK{call_id}-{cseq}\r\n\
         From: \"alice\" <sip:alice@example.com>;tag=a{call_id}\r\n\
         To: <sip:bob@example.com>;tag=b{call_id}\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: {cseq} INVITE\r\n\
         Content-Length: 0\r\n\r\n"
    );
    sip_msg(raw.as_bytes(), 2, 1, off_ms)
}

/// A store with `n` established dialogs (INVITE + 200 each).
fn store_with_dialogs(n: usize) -> DialogStore {
    let mut store = DialogStore::new(n + 10, false);
    for i in 0..n {
        let cid = format!("bench-{i}@10.0.0.1");
        store.process_message(invite(&cid, 1, 1, 2, i as i64 * 2));
        store.process_message(response(&cid, 200, 1, i as i64 * 2 + 1));
    }
    store
}

fn bench_displayed_dialogs(c: &mut Criterion) {
    let store = store_with_dialogs(10_000);
    let mut g = c.benchmark_group("tui_derived");
    g.sample_size(20);

    // One pass, no filter/search — the floor.
    g.bench_function("displayed_10k_plain", |b| {
        b.iter(|| {
            displayed_dialogs(
                &store,
                None,
                "",
                sipnab::tui::call_list::SortColumn::Index,
                true,
            )
            .len()
        })
    });

    // One pass with a non-matching query: worst case, the full-text search
    // scans (and today lowercases) every stored message body.
    g.bench_function("displayed_10k_search_miss", |b| {
        b.iter(|| {
            displayed_dialogs(
                &store,
                None,
                "zzz-no-such-string",
                sipnab::tui::call_list::SortColumn::Index,
                true,
            )
            .len()
        })
    });

    g.finish();
}

/// One full CallList frame tick (sync_caches + read-only render + feedback
/// write-back) on a 10k-dialog store with an active non-matching search —
/// the WS4.3 acceptance surface. Today this runs the filter+search+sort
/// pass three times per frame; WS4.3 collapses and caches it.
fn bench_search_frame(c: &mut Criterion) {
    let ds = Arc::new(RwLock::new(store_with_dialogs(10_000)));
    let ss = Arc::new(RwLock::new(StreamStore::new(16)));
    let mut app = App::new(ds, ss, Theme::default(), Keymap::default());
    // Type "/<query>" + Enter: commit a search that misses every dialog.
    app.handle_key(KeyCode::Char('/'));
    for ch in "zzz-no-such-string".chars() {
        app.handle_key(KeyCode::Char(ch));
    }
    app.handle_key(KeyCode::Enter);

    let mut terminal = Terminal::new(TestBackend::new(120, 40)).unwrap();
    let mut g = c.benchmark_group("tui_derived");
    g.sample_size(20);
    g.bench_function("search_frame_10k", |b| {
        b.iter(|| {
            terminal.draw(|f| app.render(f)).unwrap();
        })
    });
    g.finish();
}

fn bench_prepare_ladder(c: &mut Criterion) {
    // One dialog with 200 messages (INVITE + 199 responses).
    let cid = "ladder@10.0.0.1";
    let mut msgs = vec![invite(cid, 1, 1, 2, 0)];
    for i in 0..199u32 {
        msgs.push(response(cid, 180, 1, i as i64 + 1));
    }
    let first_ts = msgs[0].timestamp;
    let theme = Theme::default();
    let resolver = NameResolver::new();
    let folds = HashSet::new();

    let mut g = c.benchmark_group("tui_derived");
    g.sample_size(20);
    g.bench_function("prepare_ladder_200", |b| {
        let opts = FlowDisplayOptions {
            sdp_mode: SdpDisplayMode::None,
            ts_mode: TimestampMode::Absolute,
            color_mode: ColorMode::Method,
            show_rtp: false,
            selected_msg: Some(10),
            theme: &theme,
            resolver: &resolver,
            name_mode: NameMode::Off,
            rtp_segments: &[],
        };
        b.iter(|| {
            prepare_messages(&msgs, first_ts, None, &opts, &folds)
                .1
                .len()
        })
    });
    g.finish();
}

/// One full CallFlow frame tick (sync_caches + read-only render + feedback
/// write-back) on a 200-message dialog — the WS4.3c acceptance surface.
/// Before the ladder cache every frame re-laid-out the whole ladder;
/// with it, repeated frames only run the style stage over cached rows.
fn bench_ladder_frame(c: &mut Criterion) {
    let cid = "ladder-frame@10.0.0.1";
    let mut store = DialogStore::new(100, false);
    store.process_message(invite(cid, 1, 1, 2, 0));
    for i in 0..199i64 {
        store.process_message(response(cid, 180, 1, i + 1));
    }
    let ds = Arc::new(RwLock::new(store));
    let ss = Arc::new(RwLock::new(StreamStore::new(16)));
    let mut app = App::new(ds, ss, Theme::default(), Keymap::default());
    // Enter opens the CallFlow view for the selected (only) dialog.
    app.handle_key(KeyCode::Enter);

    let mut terminal = Terminal::new(TestBackend::new(120, 40)).unwrap();
    let mut g = c.benchmark_group("tui_derived");
    g.sample_size(20);
    g.bench_function("ladder_frame_200", |b| {
        b.iter(|| {
            terminal.draw(|f| app.render(f)).unwrap();
        })
    });
    g.finish();
}

criterion_group!(
    benches,
    bench_displayed_dialogs,
    bench_search_frame,
    bench_prepare_ladder,
    bench_ladder_frame
);
criterion_main!(benches);
