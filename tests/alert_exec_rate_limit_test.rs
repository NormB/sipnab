// SPDX-License-Identifier: MIT OR Apache-2.0

//! `--alert-exec` rate limiting.
//!
//! The alert-exec path spawns `sh -c <operator command>` per fired alert. Its
//! only bound used to be a cap of 100 *concurrent* children, which is not a
//! rate: a detector naming 180 distinct peers — the shape measured on an
//! ordinary 11-second carrier capture and recorded in
//! `docs/design/threat-mitigation-hooks.md` §2 — spawned a process per alert,
//! throttled only by how fast they exited.
//!
//! These tests count *actual spawns* by giving the engine a command that
//! appends one byte to a temp file, so they measure the process behaviour
//! rather than the bookkeeping that is supposed to bound it.

#![cfg(feature = "native")]

use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::time::{Duration, Instant};

use chrono::{DateTime, TimeZone, Utc};

use sipnab::security::alerting::{AlertEngine, AlertRule};

/// Capture time `secs` seconds after a fixed base.
///
/// Every budget the alert engine applies is measured against the packet
/// timestamp, so a test drives time by choosing stamps rather than sleeping.
fn at(secs: i64) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2024, 1, 15, 12, 0, 0)
        .single()
        .expect("unambiguous base timestamp")
        + chrono::Duration::seconds(secs)
}

/// The `n`th distinct source IP, as a detector naming many peers would supply.
fn peer(n: u32) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + n))
}

/// An exec command that appends exactly one byte per invocation to `path`.
///
/// `>>` opens with `O_APPEND`, so concurrent children each contribute one
/// byte and the file length is the spawn count.
fn append_one_byte(path: &Path) -> String {
    format!("printf x >> {}", path.display())
}

/// Number of bytes in `path` once it has stopped growing, i.e. once every
/// spawned child has run. Waits for three consecutive quiet samples so a
/// still-forking engine cannot be mistaken for a finished one, and caps the
/// wait so a hung child fails the test rather than the suite.
fn settled_spawn_count(path: &Path) -> u64 {
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut last = u64::MAX;
    let mut quiet = 0;
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
        let now = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        if now == last {
            quiet += 1;
            if quiet == 3 {
                return now;
            }
        } else {
            quiet = 0;
            last = now;
        }
    }
    panic!("spawn count never settled within 20s (last={last})");
}

/// A temp file that exists and is empty, plus the command that appends to it.
fn spawn_probe() -> (tempfile::NamedTempFile, String) {
    let mut file = tempfile::NamedTempFile::new().expect("create tempfile");
    file.flush().expect("flush");
    let cmd = append_one_byte(file.path());
    (file, cmd)
}

/// A detector that names many distinct peers must not spawn a process per
/// peer. This is the defect: 30 sources, each firing once inside a single
/// capture second, used to spawn 30 shells because the only bound was a
/// *concurrency* cap of 100 and each `printf` exits immediately.
///
/// The bound asserted is the global budget the event-exec path already
/// enforces (`--exec-rate-limit`, default 10/s) and the kill worker already
/// enforces (`DEFAULT_RATE_LIMIT = 10`).
#[test]
fn many_peers_in_one_second_cannot_spawn_a_process_each() {
    let (file, cmd) = spawn_probe();

    // Threshold 1 so every event is eligible; distinct sources so no cooldown
    // suppresses anything. Only a rate limit can hold these back.
    let rule = AlertRule::parse("scanner:1/1s:0s").expect("parse");
    let mut engine = AlertEngine::new(vec![rule], Some(cmd));

    for n in 0..30 {
        engine.fire("scanner", peer(n), "detection=behavioral", at(0));
    }

    let spawned = settled_spawn_count(file.path());
    // Exactly ten, in both directions. Above it the budget is not a budget;
    // below it the operator's command has been silenced under exactly the
    // conditions it exists for, which is the same defect wearing a limiter's
    // clothes.
    assert_eq!(
        spawned, 10,
        "30 peers inside one capture second must run the command 10 times \
         (the global alert-exec budget), not {spawned}"
    );
}

/// One misidentified peer must not spend the whole budget.
///
/// A global-only limiter would let a single busy source consume all 10 of a
/// second's spawns and stay silent about everything else, which is the failure
/// `MAX_PER_DST_PER_MINUTE = 3` exists to prevent on the kill path
/// (`docs/design/threat-mitigation-hooks.md` §5(c)).
#[test]
fn one_peer_cannot_spend_the_whole_budget() {
    let (file, cmd) = spawn_probe();

    // Ten distinct rule names for ONE source: the per-(src, rule) cooldown
    // cannot suppress any of them, so only a per-source exec budget can.
    let rules: Vec<AlertRule> = (0..10)
        .map(|i| AlertRule::parse(&format!("rule{i}:1/1s:0s")).expect("parse"))
        .collect();
    let mut engine = AlertEngine::new(rules, Some(cmd));

    for i in 0..10 {
        engine.fire(&format!("rule{i}"), peer(1), "detection=behavioral", at(0));
    }

    let spawned = settled_spawn_count(file.path());
    assert_eq!(
        spawned, 3,
        "one source fired 10 alerts in one capture minute; it must run the \
         command exactly 3 times (the per-source budget), not {spawned}"
    );
}

/// Spending one peer's budget must not silence the others.
///
/// The point of a per-source cap is that it bounds the damage to the peer the
/// signature was wrong about. If a noisy peer's alerts consumed the global
/// budget, the fix would have replaced one silence with another.
#[test]
fn a_noisy_peer_does_not_silence_the_quiet_ones() {
    let (file, cmd) = spawn_probe();

    let mut rules: Vec<AlertRule> = (0..8)
        .map(|i| AlertRule::parse(&format!("rule{i}:1/1s:0s")).expect("parse"))
        .collect();
    rules.push(AlertRule::parse("quiet-a:1/1s:0s").expect("parse"));
    rules.push(AlertRule::parse("quiet-b:1/1s:0s").expect("parse"));
    let mut engine = AlertEngine::new(rules, Some(cmd));

    // The quiet peer is on the books BEFORE the flood. Letting it arrive
    // afterwards would let a single shared budget pass this test, because a
    // source seen for the first time starts on a fresh count either way.
    engine.fire("quiet-a", peer(2), "quiet", at(0));
    let baseline = settled_spawn_count(file.path());
    assert_eq!(baseline, 1, "the quiet peer's first command must run");

    // The noisy peer burns through its own budget.
    for i in 0..8 {
        engine.fire(&format!("rule{i}"), peer(1), "noisy", at(0));
    }
    let after_noisy = settled_spawn_count(file.path());

    // The quiet peer, same capture second, still gets its command run.
    engine.fire("quiet-b", peer(2), "quiet", at(0));
    let after_quiet = settled_spawn_count(file.path());

    assert!(
        after_quiet > after_noisy,
        "the quiet peer's alert-exec was suppressed by the noisy peer's traffic \
         ({after_noisy} spawns before it fired, {after_quiet} after)"
    );
}

/// The budget is measured in CAPTURE time, so a replay behaves like live.
///
/// Offline a whole capture arrives within milliseconds of wall time. A budget
/// on `Instant::now()` would treat an hour-long file as one instant and clamp
/// the operator's command to a single second's worth of runs for the entire
/// capture — the mirror image of the wall-clock defect already fixed in this
/// engine's windows and cooldowns.
#[test]
fn the_exec_budget_follows_capture_time_not_wall_time() {
    let (file, cmd) = spawn_probe();

    let rule = AlertRule::parse("scanner:1/1s:0s").expect("parse");
    let mut engine = AlertEngine::new(vec![rule], Some(cmd));

    // 20 peers, one per capture minute. Every one is inside its own global
    // second AND its own per-source minute, so all 20 must run.
    for n in 0..20 {
        engine.fire("scanner", peer(n), "spread out", at(i64::from(n) * 60));
    }

    let spawned = settled_spawn_count(file.path());
    assert_eq!(
        spawned, 20,
        "alerts one capture minute apart are not a burst; all 20 commands must run"
    );
}

/// A capture stamp that goes backwards must not refill the budget.
///
/// Packet stamps are attacker-influenced on a live interface and simply
/// out-of-order on a merged or replayed capture. Rolling the window on a
/// backwards jump would hand an attacker a budget reset per crafted packet.
#[test]
fn a_backwards_capture_stamp_does_not_refill_the_budget() {
    let (file, cmd) = spawn_probe();

    let rules: Vec<AlertRule> = (0..10)
        .map(|i| AlertRule::parse(&format!("rule{i}:1/1s:0s")).expect("parse"))
        .collect();
    let mut engine = AlertEngine::new(rules, Some(cmd));

    // Alternate "now" and "an hour ago". The backwards stamps must not roll
    // either window; the peer still gets its 3 per minute and no more.
    for i in 0..10 {
        let when = if i % 2 == 0 { at(3600) } else { at(0) };
        engine.fire(&format!("rule{i}"), peer(1), "replayed", when);
    }

    let spawned = settled_spawn_count(file.path());
    assert!(
        spawned <= 3,
        "backwards capture stamps refilled the per-source budget: {spawned} spawns"
    );
}

/// A suppressed exec is counted and reportable, not merely warned about.
///
/// A silently dropped action is the defect the rate limit is being added to
/// fix; a rate limit that drops silently just moves it. The run must be able
/// to say how many operator commands it swallowed, and why.
#[test]
fn suppressed_execs_are_counted_by_reason() {
    let (file, cmd) = spawn_probe();

    let rule = AlertRule::parse("scanner:1/1s:0s").expect("parse");
    let mut engine = AlertEngine::new(vec![rule], Some(cmd));

    for n in 0..30 {
        engine.fire("scanner", peer(n), "detection=behavioral", at(0));
    }
    let spawned = settled_spawn_count(file.path());

    let drops = engine.exec_drops();
    assert_eq!(
        engine.exec_spawned() + drops.total(),
        30,
        "every fired alert must be accounted for as either a spawn or a drop"
    );
    assert_eq!(
        engine.exec_spawned(),
        spawned,
        "the spawn counter must match the processes that actually ran"
    );
    assert!(
        drops.rate_limited > 0,
        "30 alerts in one capture second must record global rate-limit drops"
    );
}

/// The alert itself still fires when its exec is suppressed.
///
/// This is the direction the failure must take: the operator's *action* is
/// rate limited, the *evidence* is not. The alert is logged, exposed on the
/// JSON channel and kept in the findings buffer regardless.
#[test]
fn a_suppressed_exec_does_not_suppress_the_alert() {
    let (file, cmd) = spawn_probe();

    let rule = AlertRule::parse("scanner:1/1s:0s").expect("parse");
    let mut engine = AlertEngine::new(vec![rule], Some(cmd));

    let mut fired = 0;
    for n in 0..30 {
        if engine.fire("scanner", peer(n), "detection=behavioral", at(0)) {
            fired += 1;
        }
    }
    let _ = settled_spawn_count(file.path());

    assert_eq!(
        fired, 30,
        "every alert must still fire; only the exec is capped"
    );
    assert_eq!(
        engine.iter_findings(&[], None, 1000).len(),
        30,
        "every alert must still be recorded in the findings buffer"
    );
    assert!(
        engine.exec_drops().total() > 0,
        "the run must know that it swallowed commands"
    );
}

/// Setting the global budget to zero disables it, matching
/// `--exec-rate-limit 0` on the event-exec path. The per-source cap still
/// applies, so an unlimited global budget is not an unlimited fork rate.
#[test]
fn a_zero_global_budget_is_unlimited_but_per_source_still_caps() {
    let (file, cmd) = spawn_probe();

    let rule = AlertRule::parse("scanner:1/1s:0s").expect("parse");
    let mut engine = AlertEngine::new(vec![rule], Some(cmd));
    engine.set_exec_rate_limit(0);

    // 30 distinct peers, one alert each, all in the same capture second.
    // With no global cap every one is inside its own per-source budget.
    for n in 0..30 {
        engine.fire("scanner", peer(n), "detection=behavioral", at(0));
    }

    let spawned = settled_spawn_count(file.path());
    assert_eq!(
        spawned, 30,
        "a zero global budget must not limit; got {spawned} spawns"
    );
    assert_eq!(
        engine.exec_drops().rate_limited,
        0,
        "no global drops when the global budget is disabled"
    );
}
