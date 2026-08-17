// SPDX-License-Identifier: MIT OR Apache-2.0

//! The two limits that discard messages sipnab already captured.
//!
//! Every other limit in the dialog store refuses to take something IN: a
//! message over the header cap, a dialog past capacity. Idle compaction is the
//! only one that throws away something already held, and it was the only one
//! with no configuration key — `max_messages_per_dialog` sat under `[limits]`
//! while the two constants that actually shorten a stored ladder did not.
//!
//! # Why this is its own test binary
//!
//! Both knobs are process-wide atomics, set once at startup. The compaction
//! tests in `src/sip/dialog_store.rs` size their fixtures from
//! `keep_messages_per_idle_dialog()` and assert an exact eviction count, so a
//! test that moves that value mid-run would fail them at random depending on
//! thread interleaving. An integration test gets its own process. Anything
//! here that sets a knob must therefore also stay out of the way of anything
//! else here — hence one test per knob, each restoring the default.
//!
//! One knob per test is NOT enough on its own, and the gap cost a red
//! pre-commit run to find. `compact_idle` reads BOTH atomics, so the two tests
//! are not independent even though each writes only one: while
//! `raising_the_keep_limit_keeps_more_of_the_ladder` holds the keep limit at
//! four times the default, the anti-vacuity half of
//! `widening_the_idle_window_spares_a_quiet_dialog` — whose fixture is three
//! times the default — evicts nothing and fails, reporting a compaction bug
//! that is really a thread interleaving. It fails on a busy machine and passes
//! on an idle one, which is the worst kind of gate. `#[serial]` is what makes
//! "one test per knob" actually hold: the tests that move process-global state
//! run one at a time, the way `icmp_quote_test` and friends already do it.
//!
//! # Why the compaction tests are `native`-gated and the config one is not
//!
//! Reading a pcap needs `capture::file`, which only exists under `native`. The
//! pre-push feature matrix builds combinations that EXCLUDE it (`--no-default-
//! features --features tls`), and `--all-features` cannot see those breaks
//! because it always turns `native` on. So the gate goes on the two items that
//! need a capture, not on the file: `zero_is_refused_on_both_retention_keys`
//! reads only `LimitsConfig` and must keep running in every combination.

#[cfg(feature = "native")]
use sipnab::sip::dialog_store::{
    DEFAULT_IDLE_COMPACT_AFTER, DEFAULT_KEEP_MESSAGES_PER_IDLE_DIALOG, DialogStore,
    idle_compact_after, keep_messages_per_idle_dialog, set_idle_compact_after_secs,
    set_keep_messages_per_idle_dialog,
};

#[cfg(feature = "native")]
fn fixture(name: &str) -> String {
    format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

/// A store holding one real dialog, grown past whatever the keep-limit is.
///
/// Returns the store, the Call-ID, the message count it was grown to, and the
/// dialog's own `updated_at`.
///
/// The growth is deliberate: the checked-in fixtures are short calls, and a
/// compaction test over a dialog under the keep-limit evicts nothing and
/// proves nothing. `provenance_surfaces_test.rs` records that exact mistake.
///
/// `updated_at` is returned rather than assumed because a fixture's dialog
/// carries the CAPTURE's clock, not the wall clock. Measuring idleness from
/// `Utc::now()` makes every fixture dialog idle by years, so a window test
/// written that way reports "compacted" under any window and measures nothing.
#[cfg(feature = "native")]
fn store_with_long_dialog(
    target: usize,
) -> (DialogStore, String, usize, chrono::DateTime<chrono::Utc>) {
    use sipnab::capture::parse::parse_packet;
    use sipnab::pipeline::{self, PacketAction, PipelineOptions};
    use sipnab::rtp::heuristic::RtpHeuristic;

    let (tx, rx) = sipnab::capture::channel::packet_channel(1 << 16);
    let owned = vec![std::path::PathBuf::from(fixture("sip_call.pcap"))];
    let reader = std::thread::spawn(move || {
        let cfg = sipnab::capture::CaptureConfig::default();
        let _ = sipnab::capture::file::capture_files(&owned, &cfg, tx, None);
    });
    let mut store = DialogStore::new(10_000, true);
    let mut heuristic = RtpHeuristic::new();
    let opts = PipelineOptions::default();
    while let Ok(pkt) = rx.recv_timeout(std::time::Duration::from_secs(60)) {
        let Ok(pp) = parse_packet(&pkt) else { continue };
        let mut decrypt = pipeline::MediaDecrypt::default();
        if let PacketAction::Sip { msg, .. } =
            pipeline::classify_packet(&pp, &mut heuristic, &opts, &mut decrypt)
        {
            store.process_message(msg);
        }
    }
    let _ = reader.join();

    let call_id = store.iter().next().expect("a dialog").call_id.clone();
    let (grown_to, updated_at) = {
        let d = store.get_mut(&call_id).expect("dialog");
        let seed: Vec<_> = d.messages.clone();
        assert!(
            !seed.is_empty(),
            "fixture produced a dialog with no messages"
        );
        while d.messages.len() <= target {
            d.messages.extend(seed.iter().cloned());
        }
        (d.messages.len(), d.updated_at)
    };
    (store, call_id, grown_to, updated_at)
}

/// Raising `keep_messages_per_idle_dialog` keeps more of the ladder.
///
/// Asserts the EFFECT — how many messages survive a real `compact_idle` — not
/// that the setter wrote to the atomic. A test that only round-trips the
/// getter would pass against a `compact_idle` that ignored the value entirely,
/// which is exactly the defect being fixed: the constant existed, and nothing
/// let an operator reach it.
#[test]
#[cfg(feature = "native")]
#[serial_test::serial(dialog_retention_knobs)]
fn raising_the_keep_limit_keeps_more_of_the_ladder() {
    let raised = DEFAULT_KEEP_MESSAGES_PER_IDLE_DIALOG * 4;
    let (mut store, call_id, grown_to, updated_at) = store_with_long_dialog(raised * 2);

    set_keep_messages_per_idle_dialog(raised);
    assert_eq!(keep_messages_per_idle_dialog(), raised);

    let idle = updated_at + idle_compact_after() + chrono::TimeDelta::minutes(1);
    let stats = store.compact_idle(idle);

    assert!(
        stats.messages_evicted > 0,
        "compaction evicted nothing from a {grown_to}-message dialog, so this \
         test proves nothing about the keep-limit"
    );
    let survived = store.get(&call_id).expect("dialog").messages.len();
    assert_eq!(
        survived, raised,
        "compaction honored neither the raised limit nor the default; it left \
         {survived} messages"
    );
    assert!(
        survived > DEFAULT_KEEP_MESSAGES_PER_IDLE_DIALOG,
        "the raised limit kept no more than the default would have, so the \
         config key does not reach compaction"
    );

    set_keep_messages_per_idle_dialog(DEFAULT_KEEP_MESSAGES_PER_IDLE_DIALOG);
}

/// Raising `idle_compact_after_secs` puts a dialog back OUTSIDE the window.
///
/// The paused-capture case from the field: a dialog quiet for twenty minutes
/// is compacted under the ten-minute default and untouched under a longer one.
/// Same store, same timestamp, opposite outcome.
#[test]
#[cfg(feature = "native")]
#[serial_test::serial(dialog_retention_knobs)]
fn widening_the_idle_window_spares_a_quiet_dialog() {
    let (mut store, call_id, _, updated_at) =
        store_with_long_dialog(DEFAULT_KEEP_MESSAGES_PER_IDLE_DIALOG * 3);
    let before = store.get(&call_id).expect("dialog").messages.len();

    // Twenty minutes of silence: past the ten-minute default, inside an hour.
    let quiet_for = chrono::TimeDelta::minutes(20);
    assert!(
        quiet_for > DEFAULT_IDLE_COMPACT_AFTER,
        "the fixture must be idle under the DEFAULT window or the widened \
         window proves nothing"
    );
    let now = updated_at + quiet_for;

    set_idle_compact_after_secs(chrono::TimeDelta::hours(1).num_seconds());
    assert_eq!(idle_compact_after(), chrono::TimeDelta::hours(1));

    let stats = store.compact_idle(now);
    assert_eq!(
        stats.messages_evicted, 0,
        "a dialog quiet for 20 minutes was compacted against a 1-hour window"
    );
    assert_eq!(
        store.get(&call_id).expect("dialog").messages.len(),
        before,
        "messages were dropped from a dialog inside the idle window"
    );

    // Anti-vacuity: the SAME store at the SAME instant compacts once the
    // window is back to the default. Without this the test above would pass
    // against a `compact_idle` that had stopped working altogether.
    set_idle_compact_after_secs(DEFAULT_IDLE_COMPACT_AFTER.num_seconds());
    let stats = store.compact_idle(now);
    assert!(
        stats.messages_evicted > 0,
        "nothing was evicted under the default window either, so the previous \
         assertion did not measure the window"
    );
}

/// Zero is refused on both keys, and refused for a stated reason.
///
/// `idle_compact_after_secs = 0` reads as "turn compaction off" and would do
/// the exact opposite — compact every dialog on every sweep, including one
/// still being written to. An operator who types it must be told, not obeyed.
#[test]
fn zero_is_refused_on_both_retention_keys() {
    let mut limits = sipnab::config::LimitsConfig::default();
    assert!(limits.validate().is_ok(), "an empty [limits] must be valid");

    limits.idle_compact_after_secs = Some(0);
    let err = limits
        .validate()
        .expect_err("idle_compact_after_secs = 0 must be refused")
        .to_string();
    assert!(
        err.contains("idle_compact_after_secs"),
        "the error must name the key: {err}"
    );

    limits.idle_compact_after_secs = None;
    limits.keep_messages_per_idle_dialog = Some(0);
    let err = limits
        .validate()
        .expect_err("keep_messages_per_idle_dialog = 0 must be refused")
        .to_string();
    assert!(
        err.contains("keep_messages_per_idle_dialog"),
        "the error must name the key: {err}"
    );

    // Anti-vacuity: a sane value on both keys is accepted.
    limits.idle_compact_after_secs = Some(3600);
    limits.keep_messages_per_idle_dialog = Some(200);
    assert!(
        limits.validate().is_ok(),
        "a valid retention pair was refused"
    );
}
