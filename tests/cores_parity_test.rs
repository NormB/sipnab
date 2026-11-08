// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! `--cores N` gives the answer `--cores 1` gives, under the store limits and
//! on the relay control plane.
//!
//! `--cores 1` defines the answer: one reader feeds every packet, in read
//! order, to one dialog store and one stream store, which apply `--limit`,
//! `--max-streams`, rotation and idle compaction as the packets arrive.
//! `--cores N` shards packets by host pair over N workers and merges their
//! stores at the end. Each test here runs one capture at `--cores 1` and at
//! several other worker counts and compares whole outputs: the report, the
//! per-dialog JSON, a call's report, and the retention and retry lines a run
//! prints on standard error.
//!
//! Every fixture is checked to spread its traffic over more than one worker
//! at each compared count (`sipnab::parallel::shard_for`), so a comparison
//! exercises the merge rather than a run that stayed on one worker.
//!
//! The whole file needs `native`: `--cores` is the `parallel` module, which
//! only that feature builds, and every test here runs it.
#![cfg(feature = "native")]

#[path = "support/cores_parity_captures.rs"]
mod captures;

use captures::{Frame, Leg, SECOND};

/// Any error a test can return; `?` converts into it.
type TestError = Box<dyn std::error::Error>;

/// Host pairs, as (one end, the other end).
type Pairs = Vec<([u8; 4], [u8; 4])>;

/// The worker counts compared against `--cores 1`.
const CORE_COUNTS: [usize; 3] = [2, 4, 8];

/// What one run printed.
struct Run {
    /// Standard output.
    stdout: String,
    /// Standard error.
    stderr: String,
}

/// Write `frames` as a capture named `name` in `dir`.
fn write(
    dir: &std::path::Path,
    name: &str,
    frames: &[Frame],
) -> Result<std::path::PathBuf, TestError> {
    let path = dir.join(name);
    std::fs::write(&path, captures::pcap(frames))?;
    Ok(path)
}

/// `sipnab -N` over `inputs` at `cores` with `args`.
fn run(inputs: &[std::path::PathBuf], cores: usize, args: &[&str]) -> Result<Run, TestError> {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"));
    cmd.arg("-N");
    for input in inputs {
        cmd.arg("-I").arg(input);
    }
    let out = cmd
        .args(["--cores", &cores.to_string()])
        .args(args)
        .output()?;
    let stderr = String::from_utf8(out.stderr)?;
    assert!(
        out.status.success(),
        "--cores {cores} {args:?} failed: {stderr}"
    );
    Ok(Run {
        stdout: String::from_utf8(out.stdout)?,
        stderr,
    })
}

/// The `--report` from the dialog table's header on: the dialogs, the RTP
/// streams and the relay-named calls, without the run banner.
fn report(inputs: &[std::path::PathBuf], cores: usize, args: &[&str]) -> Result<String, TestError> {
    let mut all = vec!["--report"];
    all.extend_from_slice(args);
    let stdout = run(inputs, cores, &all)?.stdout;
    let start = stdout
        .find("Call-ID ")
        .ok_or_else(|| format!("--cores {cores} printed no report:\n{stdout}"))?;
    Ok(stdout[start..].to_string())
}

/// The per-dialog JSON, one line per dialog.
fn json_dialogs(
    inputs: &[std::path::PathBuf],
    cores: usize,
    args: &[&str],
) -> Result<String, TestError> {
    let mut all = vec!["--json-dialogs", "--no-cli-print"];
    all.extend_from_slice(args);
    Ok(run(inputs, cores, &all)?.stdout)
}

/// The lines of standard error that contain `marker`, with the log prefix
/// (timestamp and level) cut off at the marker's own module path.
fn stderr_lines(
    inputs: &[std::path::PathBuf],
    cores: usize,
    args: &[&str],
    marker: &str,
) -> Result<Vec<String>, TestError> {
    // A view, because `--cores` refuses a run that prints none; only
    // standard error is read.
    let mut all = vec!["--report"];
    all.extend_from_slice(args);
    let stderr = run(inputs, cores, &all)?.stderr;
    Ok(stderr
        .lines()
        .filter_map(|l| l.find(marker).map(|at| l[at..].to_string()))
        .collect())
}

/// The workers `pairs` land on at `n` workers, as a set.
fn workers_of(pairs: &[([u8; 4], [u8; 4])], n: usize) -> std::collections::BTreeSet<usize> {
    pairs
        .iter()
        .map(|(a, b)| {
            sipnab::parallel::shard_for(std::net::IpAddr::from(*a), std::net::IpAddr::from(*b), n)
        })
        .collect()
}

/// The most of `pairs` any one worker owns at `n` workers.
fn heaviest_worker(pairs: &[([u8; 4], [u8; 4])], n: usize) -> usize {
    let mut load = vec![0usize; n];
    for (a, b) in pairs {
        load[sipnab::parallel::shard_for(
            std::net::IpAddr::from(*a),
            std::net::IpAddr::from(*b),
            n,
        )] += 1;
    }
    load.into_iter().max().unwrap_or(0)
}

/// Assert that `pairs` spread over more than one worker at every compared
/// count, so the comparison reaches the merge.
fn assert_spread(pairs: &[([u8; 4], [u8; 4])]) {
    for n in CORE_COUNTS {
        assert!(
            workers_of(pairs, n).len() > 1,
            "the fixture's host pairs all land on one worker at --cores {n}: {pairs:?}"
        );
    }
}

/// The first host pair `candidate(i)` makes that lands on another worker
/// than `fixed` at every compared count.
fn pair_apart_from(
    fixed: &[([u8; 4], [u8; 4])],
    candidate: impl Fn(u8) -> ([u8; 4], [u8; 4]),
) -> ([u8; 4], [u8; 4]) {
    (1u8..=250)
        .map(&candidate)
        .find(|pair| {
            CORE_COUNTS
                .iter()
                .all(|&n| fixed.iter().all(|f| workers_of(&[*f, *pair], n).len() == 2))
        })
        .unwrap_or_else(|| candidate(0))
}

/// Assert `output` at `--cores 1` equals it at every compared count.
fn assert_same_at_every_count(
    what: &str,
    output: impl Fn(usize) -> Result<String, TestError>,
) -> Result<String, TestError> {
    let single = output(1)?;
    for n in CORE_COUNTS {
        let multi = output(n)?;
        assert_eq!(
            multi, single,
            "{what} at --cores {n} differs from --cores 1"
        );
    }
    Ok(single)
}

// ── --max-streams ────────────────────────────────────────────────────

/// One RTP stream on each of twelve host pairs, one after another.
fn twelve_streams() -> (Pairs, Vec<Frame>) {
    let mut pairs = Vec::new();
    let mut frames = Vec::new();
    for i in 0u8..12 {
        let (a, b) = ([198, 51, 100, 10 + i], [203, 0, 113, 10 + i]);
        pairs.push((a, b));
        frames.extend(captures::rtp_stream(
            (a, 6000),
            (b, 7000),
            0x1000 + u32::from(i),
            0,
            0,
            10,
            u64::from(i) * SECOND,
        ));
    }
    (pairs, frames)
}

/// The cap the stream tests use: the most streams any one worker holds at a
/// compared count, so no worker alone reaches it, and below the twelve the
/// capture holds, so the run as a whole does.
fn stream_cap(pairs: &[([u8; 4], [u8; 4])]) -> Result<usize, TestError> {
    let cap = CORE_COUNTS
        .iter()
        .map(|&n| heaviest_worker(pairs, n))
        .max()
        .ok_or("compared counts")?;
    assert!(
        cap < pairs.len(),
        "every stream on one worker: no cap to test"
    );
    Ok(cap)
}

/// The RTP rows of a report: one line per stream.
fn rtp_rows(report: &str) -> Vec<&str> {
    report.lines().filter(|l| l.starts_with("0x")).collect()
}

/// Over `--max-streams`, the report lists the streams `--cores 1` keeps.
#[test]
fn streams_over_the_cap_are_the_same_at_every_core_count() -> Result<(), TestError> {
    let (pairs, frames) = twelve_streams();
    assert_spread(&pairs);
    let cap = stream_cap(&pairs)?.to_string();
    let dir = tempfile::tempdir()?;
    let input = [write(dir.path(), "streams.pcap", &frames)?];
    assert_same_at_every_count("the report", |n| {
        report(&input, n, &["--max-streams", &cap])
    })?;
    Ok(())
}

/// The merged store holds no more streams than `--max-streams`, as the
/// single store does.
#[test]
fn the_merged_stream_store_holds_no_more_than_the_cap() -> Result<(), TestError> {
    let (pairs, frames) = twelve_streams();
    let cap = stream_cap(&pairs)?;
    let dir = tempfile::tempdir()?;
    let input = [write(dir.path(), "streams.pcap", &frames)?];
    for n in CORE_COUNTS {
        let held = rtp_rows(&report(&input, n, &["--max-streams", &cap.to_string()])?).len();
        assert!(
            held <= cap,
            "--cores {n} holds {held} streams over --max-streams {cap}"
        );
    }
    Ok(())
}

/// Exactly at `--max-streams`, nothing is evicted at any count.
#[test]
fn streams_exactly_at_the_cap_are_all_kept() -> Result<(), TestError> {
    let (_, frames) = twelve_streams();
    let dir = tempfile::tempdir()?;
    let input = [write(dir.path(), "streams.pcap", &frames)?];
    let single = assert_same_at_every_count("the report", |n| {
        report(&input, n, &["--max-streams", "12"])
    })?;
    assert_eq!(rtp_rows(&single).len(), 12, "{single}");
    Ok(())
}

/// One stream past `--max-streams` evicts the oldest, the first pair's.
#[test]
fn one_stream_past_the_cap_evicts_the_oldest_at_every_core_count() -> Result<(), TestError> {
    let (_, frames) = twelve_streams();
    let dir = tempfile::tempdir()?;
    let input = [write(dir.path(), "streams.pcap", &frames)?];
    let single = assert_same_at_every_count("the report", |n| {
        report(&input, n, &["--max-streams", "11"])
    })?;
    let rows = rtp_rows(&single);
    assert_eq!(rows.len(), 11, "{single}");
    assert!(
        !single.contains("0x00001000"),
        "the oldest stream survived the cap:\n{single}"
    );
    Ok(())
}

/// The one difference `--max-streams` leaves, pinned: a stream evicted at
/// the cap and then sent to again is opened afresh by `--cores 1`, holding
/// the packets after its return, while a worker that kept it whole holds one
/// stream of all its packets, which the merge evicts whole at the cap.
#[test]
fn a_stream_evicted_then_resumed_is_the_documented_difference() -> Result<(), TestError> {
    let (pairs, mut frames) = twelve_streams();
    let cap = stream_cap(&pairs)?;
    // The first stream again, after every other stream began.
    frames.extend(captures::rtp_stream(
        ([198, 51, 100, 10], 6000),
        ([203, 0, 113, 10], 7000),
        0x1000,
        0,
        10,
        7,
        20 * SECOND,
    ));
    let dir = tempfile::tempdir()?;
    let input = [write(dir.path(), "resumed.pcap", &frames)?];
    let cap = cap.to_string();
    let single = report(&input, 1, &["--max-streams", &cap])?;
    let resumed = rtp_rows(&single)
        .into_iter()
        .find(|r| r.starts_with("0x00001000"))
        .ok_or_else(|| format!("--cores 1 reopens the first stream:\n{single}"))?;
    assert!(
        resumed.split_whitespace().nth(3) == Some("7"),
        "--cores 1 counts only the packets after its return: {resumed}"
    );
    for n in CORE_COUNTS {
        let multi = report(&input, n, &["--max-streams", &cap])?;
        assert!(
            !multi.contains("0x00001000"),
            "--cores {n} evicts the first stream whole:\n{multi}"
        );
    }
    Ok(())
}

// ── overlapping files ───────────────────────────────────────────────

/// A call's duration runs to its newest message, which on a set of files
/// that overlap in time is not the last one READ: the same at every core
/// count.
#[test]
fn a_calls_duration_runs_to_its_newest_message_at_every_core_count() -> Result<(), TestError> {
    let first = leg(0);
    let other = Leg {
        caller: first.callee,
        callee: pair_apart_from(&[(first.caller, first.callee)], |i| {
            (first.callee, [192, 0, 2, i])
        })
        .1,
    };
    let early = vec![
        (
            0,
            captures::request(first, "INVITE", "overlap@example.com", 1, ""),
        ),
        (
            2_500_000,
            captures::request(first, "BYE", "overlap@example.com", 2, ""),
        ),
    ];
    let late = vec![(
        900_000,
        captures::response(other, 200, "INVITE", "overlap@example.com", 1, ""),
    )];
    let dir = tempfile::tempdir()?;
    // The second file starts later, so it is read second, although its one
    // message is older than the first file's last.
    let set = [
        write(dir.path(), "late.pcap", &late)?,
        write(dir.path(), "early.pcap", &early)?,
    ];
    let single = assert_same_at_every_count("the dialogs", |n| json_dialogs(&set, n, &[]))?;
    let v: serde_json::Value = serde_json::from_str(single.lines().next().ok_or("one dialog")?)?;
    assert_eq!(v["duration_sec"].as_f64(), Some(2.5), "{single}");
    Ok(())
}

// ── --limit ──────────────────────────────────────────────────────────

/// The leg of call `i`: each call on a host pair of its own.
fn leg(i: u8) -> Leg {
    Leg {
        caller: [198, 51, 100, 30 + i],
        callee: [203, 0, 113, 30 + i.wrapping_mul(37) % 200],
    }
}

/// `calls` answered calls one second apart, each on its own pair.
fn calls(count: u8) -> (Pairs, Vec<Frame>) {
    let mut pairs = Vec::new();
    let mut frames = Vec::new();
    for i in 0..count {
        let l = leg(i);
        pairs.push((l.caller, l.callee));
        frames.extend(captures::answered_call(
            l,
            &format!("cap-{i}@example.com"),
            u64::from(i) * SECOND,
        ));
    }
    (pairs, frames)
}

/// The retention line a run prints on standard error.
const RETENTION: &str = "retention:";

/// Under `--no-rotate`, the count of dialogs refused is the number of
/// refused Call-IDs, and the same at every core count.
#[test]
fn refused_dialogs_are_counted_once_per_call_id_at_every_core_count() -> Result<(), TestError> {
    let (pairs, frames) = calls(6);
    assert_spread(&pairs);
    let dir = tempfile::tempdir()?;
    let input = [write(dir.path(), "calls.pcap", &frames)?];
    let limit = CORE_COUNTS
        .iter()
        .map(|&n| heaviest_worker(&pairs, n))
        .max()
        .ok_or("compared counts")?;
    assert!(limit < 6, "every call on one worker: no cap to test");
    let args = ["--limit", &limit.to_string(), "--no-rotate"];
    let lines = assert_same_at_every_count("the retention line", |n| {
        Ok(stderr_lines(&input, n, &args, RETENTION)?.join("\n"))
    })?;
    assert!(
        lines.contains(&format!("{} new dialog(s) refused", 6 - limit)),
        "one refusal per Call-ID past the cap, not one per message: {lines}"
    );
    Ok(())
}

/// Exactly at `--limit`, nothing is refused and nothing rotates.
#[test]
fn dialogs_exactly_at_the_limit_are_all_kept() -> Result<(), TestError> {
    let (_, frames) = calls(6);
    let dir = tempfile::tempdir()?;
    let input = [write(dir.path(), "calls.pcap", &frames)?];
    let single = assert_same_at_every_count("the dialogs", |n| {
        json_dialogs(&input, n, &["--limit", "6", "--no-rotate"])
    })?;
    assert_eq!(single.lines().count(), 6, "{single}");
    assert!(
        stderr_lines(&input, 1, &["--limit", "6", "--no-rotate"], RETENTION)?.is_empty(),
        "nothing is refused at exactly the limit"
    );
    Ok(())
}

/// The capture for the rotation tests: call 0, then `limit` more calls, then
/// call 0's teardown.
fn reused_after_rotation(limit: u8) -> (Pairs, Vec<Frame>) {
    let (mut pairs, mut frames) = calls(limit + 1);
    let first = leg(0);
    let at = u64::from(limit + 2) * SECOND;
    frames.push((
        at,
        captures::request(first, "BYE", "cap-0@example.com", 2, ""),
    ));
    frames.push((
        at + 1_000,
        captures::response(first, 200, "BYE", "cap-0@example.com", 2, ""),
    ));
    pairs.dedup();
    (pairs, frames)
}

/// The `--limit` the rotation tests use, and its capture: the most calls one
/// worker holds at a compared count, which is fewer than the capture holds.
fn rotation_fixture() -> Result<(u8, Vec<Frame>), TestError> {
    for limit in 3u8..10 {
        let (pairs, frames) = reused_after_rotation(limit);
        let heaviest = CORE_COUNTS
            .iter()
            .map(|&n| heaviest_worker(&pairs, n))
            .max()
            .ok_or("compared counts")?;
        if heaviest <= usize::from(limit) && workers_of(&pairs, 2).len() > 1 {
            return Ok((limit, frames));
        }
    }
    Err("no limit keeps every worker under the cap".into())
}

/// A Call-ID rotated out and then seen again is opened again, with the
/// messages after its return, at every core count.
#[test]
fn a_call_rotated_out_and_seen_again_is_reopened_at_every_core_count() -> Result<(), TestError> {
    let (limit, frames) = rotation_fixture()?;
    let dir = tempfile::tempdir()?;
    let input = [write(dir.path(), "rotation.pcap", &frames)?];
    let limit = limit.to_string();
    let single = assert_same_at_every_count("the dialogs", |n| {
        json_dialogs(&input, n, &["--limit", &limit, "--rotate"])
    })?;
    let reopened = single
        .lines()
        .find(|l| l.contains("\"call_id\":\"cap-0@example.com\""))
        .ok_or_else(|| format!("--cores 1 did not reopen cap-0:\n{single}"))?;
    assert!(
        reopened.contains("\"method\":\"BYE\"") && reopened.contains("\"msg_count\":2"),
        "the reopened dialog holds only the teardown: {reopened}"
    );
    Ok(())
}

/// Rotation discards the same number of dialogs at every core count.
#[test]
fn rotation_counts_the_same_discards_at_every_core_count() -> Result<(), TestError> {
    let (limit, frames) = rotation_fixture()?;
    let dir = tempfile::tempdir()?;
    let input = [write(dir.path(), "rotation.pcap", &frames)?];
    let limit = limit.to_string();
    let args = ["--limit", limit.as_str(), "--rotate"];
    let lines = assert_same_at_every_count("the retention line", |n| {
        Ok(stderr_lines(&input, n, &args, RETENTION)?.join("\n"))
    })?;
    assert!(
        lines.contains("oldest dialog(s) discarded at capacity by rotation"),
        "rotation discarded nothing: {lines}"
    );
    Ok(())
}

// ── idle compaction ──────────────────────────────────────────────────

/// The call that goes idle, and the call whose traffic carries the capture
/// clock past the idle limit while it is idle.
fn idle_legs() -> (Leg, Leg) {
    let idle = ([198, 51, 100, 70], [203, 0, 113, 70]);
    let filler = pair_apart_from(&[idle], |i| ([198, 51, 100, 70], [203, 0, 113, i]));
    (
        Leg {
            caller: idle.0,
            callee: idle.1,
        },
        Leg {
            caller: filler.0,
            callee: filler.1,
        },
    )
}

/// Call `idle-0` with `infos` INFO exchanges (5 + 2 x `infos` messages) in
/// its first minute, then call `filler-0` at `filler_at`, then `reuse` more
/// INFO exchanges on `idle-0` at `reuse_at`.
fn idle_then_reused(infos: u32, filler_at: u64, reuse: u32, reuse_at: u64) -> Vec<Frame> {
    let (idle, filler) = idle_legs();
    let mut frames = captures::answered_call(idle, "idle-0@example.com", 0);
    frames.extend(captures::infos(
        idle,
        "idle-0@example.com",
        2,
        infos,
        SECOND,
        SECOND,
    ));
    frames.extend(captures::answered_call(
        filler,
        "filler-0@example.com",
        filler_at,
    ));
    frames.extend(captures::infos(
        idle,
        "idle-0@example.com",
        2 + infos,
        reuse,
        reuse_at,
        SECOND,
    ));
    frames
}

/// When `idle-0`'s last message before going idle was sent, for a capture
/// built by [`idle_then_reused`] with `infos` exchanges.
fn idle_since(infos: u32) -> u64 {
    // The last exchange starts at (infos) seconds and its 200 OK half a
    // second later.
    u64::from(infos) * SECOND + SECOND / 2
}

/// `idle-0`'s line of the per-dialog JSON.
fn idle_dialog(dialogs: &str) -> Result<&str, TestError> {
    dialogs
        .lines()
        .find(|l| l.contains("\"call_id\":\"idle-0@example.com\""))
        .ok_or_else(|| format!("no idle-0 dialog:\n{dialogs}").into())
}

/// The messages a dialog line says it holds.
fn msg_count(line: &str) -> Result<u64, TestError> {
    let v: serde_json::Value = serde_json::from_str(line)?;
    v["msg_count"].as_u64().ok_or_else(|| "no msg_count".into())
}

/// A call idle past the limit, compacted, then used again keeps the same
/// messages at every core count.
#[test]
fn a_dialog_compacted_while_idle_then_reused_is_the_same_at_every_core_count()
-> Result<(), TestError> {
    let (idle, filler) = idle_legs();
    assert_spread(&[(idle.caller, idle.callee), (filler.caller, filler.callee)]);
    let since = idle_since(15);
    let frames = idle_then_reused(15, since + 630 * SECOND, 3, since + 640 * SECOND);
    let dir = tempfile::tempdir()?;
    let input = [write(dir.path(), "idle.pcap", &frames)?];
    let single = assert_same_at_every_count("the dialogs", |n| json_dialogs(&input, n, &[]))?;
    assert_eq!(
        msg_count(idle_dialog(&single)?)?,
        20 + 6,
        "compacted to 20 while idle, then six more: {single}"
    );
    Ok(())
}

/// The call's own report, which lists the messages it kept, is the same at
/// every core count.
#[test]
fn the_reused_dialogs_call_report_is_the_same_at_every_core_count() -> Result<(), TestError> {
    let since = idle_since(15);
    let frames = idle_then_reused(15, since + 630 * SECOND, 3, since + 640 * SECOND);
    let dir = tempfile::tempdir()?;
    let input = [write(dir.path(), "idle.pcap", &frames)?];
    assert_same_at_every_count("the call report", |n| {
        Ok(run(
            &input,
            n,
            &["--call-report", "idle-0@example.com", "--no-cli-print"],
        )?
        .stdout)
    })?;
    Ok(())
}

/// The same capture split over two files, read by one reader thread per
/// file, keeps the same messages as `--cores 1`.
#[test]
fn compaction_over_a_two_file_set_is_the_same_at_every_core_count() -> Result<(), TestError> {
    let since = idle_since(15);
    let frames = idle_then_reused(15, since + 630 * SECOND, 3, since + 640 * SECOND);
    let (first, second) = frames.split_at(5 + 30);
    let dir = tempfile::tempdir()?;
    let set = [
        write(dir.path(), "a.pcap", first)?,
        write(dir.path(), "b.pcap", second)?,
    ];
    let single = assert_same_at_every_count("the dialogs", |n| json_dialogs(&set, n, &[]))?;
    assert_eq!(msg_count(idle_dialog(&single)?)?, 26, "{single}");
    Ok(())
}

/// A call left idle past the limit and never used again is compacted by the
/// next sweep at every core count.
#[test]
fn a_dialog_left_idle_is_compacted_by_a_later_sweep_at_every_core_count() -> Result<(), TestError> {
    let since = idle_since(15);
    let frames = idle_then_reused(15, since + 630 * SECOND, 0, 0);
    let dir = tempfile::tempdir()?;
    let input = [write(dir.path(), "idle.pcap", &frames)?];
    let single = assert_same_at_every_count("the dialogs", |n| json_dialogs(&input, n, &[]))?;
    assert_eq!(msg_count(idle_dialog(&single)?)?, 20, "{single}");
    Ok(())
}

/// A sweep follows the packet that made it due, so a call's own message that
/// enters a new sweep interval after a long silence lands before that sweep:
/// the call is not idle when it runs, and nothing is compacted.
#[test]
fn a_dialogs_own_message_lands_before_the_sweep_it_starts() -> Result<(), TestError> {
    let (idle, _) = idle_legs();
    let mut frames = captures::answered_call(idle, "idle-0@example.com", 0);
    frames.extend(captures::infos(
        idle,
        "idle-0@example.com",
        2,
        15,
        SECOND,
        SECOND,
    ));
    // 700 s later, on an interval boundary, with nothing in between.
    frames.extend(captures::infos(
        idle,
        "idle-0@example.com",
        17,
        1,
        715 * SECOND,
        SECOND,
    ));
    let dir = tempfile::tempdir()?;
    let input = [write(dir.path(), "idle.pcap", &frames)?];
    let single = assert_same_at_every_count("the dialogs", |n| json_dialogs(&input, n, &[]))?;
    assert_eq!(msg_count(idle_dialog(&single)?)?, 37, "{single}");
    Ok(())
}

/// Idle EXACTLY the limit at the sweep before its reuse is not idle past it:
/// nothing is compacted at any core count.
#[test]
fn a_dialog_idle_exactly_the_limit_is_not_compacted() -> Result<(), TestError> {
    let since = idle_since(15);
    // The filler's INVITE lands on a sweep boundary exactly 600 s after the
    // idle call's last message; the reuse follows inside the same interval.
    let frames = idle_then_reused(15, since + 600 * SECOND, 3, since + 601 * SECOND);
    let dir = tempfile::tempdir()?;
    let input = [write(dir.path(), "idle.pcap", &frames)?];
    let single = assert_same_at_every_count("the dialogs", |n| json_dialogs(&input, n, &[]))?;
    assert_eq!(msg_count(idle_dialog(&single)?)?, 35 + 6, "{single}");
    Ok(())
}

/// A dialog of exactly the keep limit, idle and reused, is not compacted.
#[test]
fn a_dialog_of_exactly_the_keep_limit_is_not_compacted() -> Result<(), TestError> {
    // 5 + 2 x 7 = 19 messages, plus one INFO request = 20 before going idle.
    let (idle, filler) = idle_legs();
    let mut frames = captures::answered_call(idle, "idle-0@example.com", 0);
    frames.extend(captures::infos(
        idle,
        "idle-0@example.com",
        2,
        7,
        SECOND,
        SECOND,
    ));
    frames.push((
        8 * SECOND,
        captures::request(idle, "INFO", "idle-0@example.com", 9, ""),
    ));
    frames.extend(captures::answered_call(
        filler,
        "filler-0@example.com",
        640 * SECOND,
    ));
    frames.extend(captures::infos(
        idle,
        "idle-0@example.com",
        10,
        1,
        650 * SECOND,
        SECOND,
    ));
    let dir = tempfile::tempdir()?;
    let input = [write(dir.path(), "idle.pcap", &frames)?];
    let single = assert_same_at_every_count("the dialogs", |n| json_dialogs(&input, n, &[]))?;
    assert_eq!(msg_count(idle_dialog(&single)?)?, 22, "{single}");
    Ok(())
}

/// One message over the keep limit, idle and reused, is compacted to the
/// limit at every core count.
#[test]
fn a_dialog_one_over_the_keep_limit_is_compacted_at_every_core_count() -> Result<(), TestError> {
    // 5 + 2 x 8 = 21 messages before going idle.
    let (idle, filler) = idle_legs();
    let mut frames = captures::answered_call(idle, "idle-0@example.com", 0);
    frames.extend(captures::infos(
        idle,
        "idle-0@example.com",
        2,
        8,
        SECOND,
        SECOND,
    ));
    frames.extend(captures::answered_call(
        filler,
        "filler-0@example.com",
        640 * SECOND,
    ));
    frames.extend(captures::infos(
        idle,
        "idle-0@example.com",
        10,
        1,
        650 * SECOND,
        SECOND,
    ));
    let dir = tempfile::tempdir()?;
    let input = [write(dir.path(), "idle.pcap", &frames)?];
    let single = assert_same_at_every_count("the dialogs", |n| json_dialogs(&input, n, &[]))?;
    assert_eq!(msg_count(idle_dialog(&single)?)?, 20 + 2, "{single}");
    Ok(())
}

/// The last sweep of a run, not the run's last packet, decides what idle
/// compaction keeps: a call idle just past the limit at the last packet but
/// not at the last sweep is kept whole.
#[test]
fn the_last_sweep_not_the_last_packet_decides_compaction() -> Result<(), TestError> {
    let (idle, filler) = idle_legs();
    let since = idle_since(15);
    let mut frames = captures::answered_call(idle, "idle-0@example.com", 0);
    frames.extend(captures::infos(
        idle,
        "idle-0@example.com",
        2,
        15,
        SECOND,
        SECOND,
    ));
    // A sweep at exactly 600 s of idleness (not past the limit), then a
    // packet 3 s later inside the same five-second interval, so no sweep
    // follows it.
    let sweep = since + 600 * SECOND;
    frames.extend(captures::answered_call(
        filler,
        "filler-0@example.com",
        sweep,
    ));
    frames.push((
        sweep + 3 * SECOND,
        captures::request(filler, "BYE", "filler-0@example.com", 2, ""),
    ));
    let dir = tempfile::tempdir()?;
    let input = [write(dir.path(), "idle.pcap", &frames)?];
    let single = assert_same_at_every_count("the dialogs", |n| json_dialogs(&input, n, &[]))?;
    assert_eq!(msg_count(idle_dialog(&single)?)?, 35, "{single}");
    Ok(())
}

// ── relay control on two host pairs ─────────────────────────────────

/// The relay mirroring its control plane, the collector, the media address
/// the relay allocates, and the party sending media to it.
const RELAY: [u8; 4] = [192, 0, 2, 40];
const HOMER: [u8; 4] = [192, 0, 2, 60];
const RELAY_MEDIA: [u8; 4] = [203, 0, 113, 40];
/// The party sending media to the rtpengine relay, on a host pair apart
/// from the relay's control pair.
fn party() -> [u8; 4] {
    pair_apart_from(&[(RELAY, HOMER)], |i| ([198, 51, 100, i], RELAY_MEDIA)).0
}

/// The party sending media to the rtpproxy relay, on a host pair apart from
/// the proxy's control pair.
fn rtpproxy_party() -> [u8; 4] {
    pair_apart_from(&[(PROXY.0, RELAY)], |i| ([198, 51, 100, i], RELAY_MEDIA)).0
}

/// rtpengine's `ng` offers on one host pair naming media that runs on
/// another: call one's offer, two seconds of opus to the relay's port, then
/// call two's offer for the same port and two more seconds of the same SSRC.
fn ng_two_pairs() -> Vec<Frame> {
    let mut frames = vec![captures::ng_offer_over_hep(
        RELAY,
        HOMER,
        "relay-1@example.com",
        "c1",
        RELAY_MEDIA,
        30_000,
        0,
    )];
    frames.extend(captures::rtp_stream(
        (party(), 6000),
        (RELAY_MEDIA, 30_000),
        0xabcd_0001,
        96,
        0,
        100,
        10_000,
    ));
    frames.push(captures::ng_offer_over_hep(
        RELAY,
        HOMER,
        "relay-2@example.com",
        "c2",
        RELAY_MEDIA,
        30_000,
        3 * SECOND,
    ));
    frames.extend(captures::rtp_stream(
        (party(), 6000),
        (RELAY_MEDIA, 30_000),
        0xabcd_0001,
        96,
        100,
        100,
        3 * SECOND + 10_000,
    ));
    frames
}

/// The relay's control pair and the media pair land on different workers.
fn assert_relay_pairs_split(control: ([u8; 4], [u8; 4])) {
    let media = if control.0 == RELAY {
        party()
    } else {
        rtpproxy_party()
    };
    assert_spread(&[control, (media, RELAY_MEDIA)]);
}

/// SDP an `ng` offer carries on one host pair names the codec and the call
/// of media on another, the same at every core count.
#[test]
fn ng_offer_sdp_on_another_host_pair_is_learned_at_every_core_count() -> Result<(), TestError> {
    assert_relay_pairs_split((RELAY, HOMER));
    let dir = tempfile::tempdir()?;
    let input = [write(dir.path(), "ng.pcap", &ng_two_pairs())?];
    let single = assert_same_at_every_count("the report", |n| report(&input, n, &[]))?;
    assert!(
        single.contains("OPUS") || single.contains("opus"),
        "{single}"
    );
    Ok(())
}

/// A second call's offer for the same relay port starts that call's own
/// stream at every core count.
#[test]
fn a_relay_port_renegotiated_by_another_call_splits_the_stream_at_every_core_count()
-> Result<(), TestError> {
    assert_relay_pairs_split((RELAY, HOMER));
    let dir = tempfile::tempdir()?;
    let input = [write(dir.path(), "ng.pcap", &ng_two_pairs())?];
    for n in std::iter::once(1).chain(CORE_COUNTS) {
        let text = report(&input, n, &[])?;
        assert_eq!(
            rtp_rows(&text).len(),
            2,
            "--cores {n}: one stream per call on the renegotiated port:\n{text}"
        );
    }
    Ok(())
}

/// The rtpproxy proxy and the relay's media address.
const PROXY: ([u8; 4], u16) = ([192, 0, 2, 10], 43_000);

/// rtpproxy's `U` command and reply on the proxy's pair naming media on the
/// party's pair, for two calls on one relay port.
fn rtpproxy_two_pairs() -> Vec<Frame> {
    let mut frames = captures::rtpproxy_update(
        PROXY,
        RELAY,
        "c1",
        "rp-1@example.com",
        RELAY_MEDIA,
        30_000,
        0,
    );
    frames.extend(captures::rtp_stream(
        (rtpproxy_party(), 6000),
        (RELAY_MEDIA, 30_000),
        0xabcd_0002,
        0,
        0,
        100,
        10_000,
    ));
    frames.extend(captures::rtpproxy_update(
        PROXY,
        RELAY,
        "c2",
        "rp-2@example.com",
        RELAY_MEDIA,
        30_000,
        3 * SECOND,
    ));
    frames.extend(captures::rtp_stream(
        (rtpproxy_party(), 6000),
        (RELAY_MEDIA, 30_000),
        0xabcd_0002,
        0,
        100,
        100,
        3 * SECOND + 10_000,
    ));
    frames
}

/// The media an rtpproxy reply names on one host pair is attributed, and a
/// second call on the same port split off, the same at every core count.
#[test]
fn rtpproxy_links_on_another_host_pair_are_learned_at_every_core_count() -> Result<(), TestError> {
    assert_relay_pairs_split((PROXY.0, RELAY));
    let dir = tempfile::tempdir()?;
    let input = [write(dir.path(), "rtpproxy.pcap", &rtpproxy_two_pairs())?];
    let args = ["--rtpproxy-control", captures::RTPPROXY_CONTROL];
    let single = assert_same_at_every_count("the report", |n| report(&input, n, &args))?;
    assert!(single.contains("rp-2@example.com"), "{single}");
    assert_eq!(rtp_rows(&single).len(), 2, "{single}");
    Ok(())
}

// ── relay control retries ───────────────────────────────────────────

/// The retry warning a run prints on standard error, from where it names
/// the relay.
const RETRIED: &str = "rtpproxy at ";

/// The second proxy talking to the same relay control socket.
fn other_proxy() -> ([u8; 4], u16) {
    let pair = pair_apart_from(&[(PROXY.0, RELAY)], |i| ([192, 0, 2, i], RELAY));
    (pair.0, 43_000)
}

/// Two proxies that happen to use one cookie are two commands, not a retry,
/// at every core count.
#[test]
fn one_cookie_from_two_proxies_is_not_a_retry_at_every_core_count() -> Result<(), TestError> {
    assert_spread(&[(PROXY.0, RELAY), (other_proxy().0, RELAY)]);
    let frames = vec![
        captures::rtpproxy_info(PROXY, RELAY, "7", 0),
        captures::rtpproxy_info(other_proxy(), RELAY, "7", SECOND),
    ];
    let dir = tempfile::tempdir()?;
    let input = [write(dir.path(), "cookies.pcap", &frames)?];
    let args = ["--rtpproxy-control", captures::RTPPROXY_CONTROL];
    let lines = assert_same_at_every_count("the retry lines", |n| {
        Ok(stderr_lines(&input, n, &args, RETRIED)?.join("\n"))
    })?;
    assert!(lines.is_empty(), "no proxy sent a command twice: {lines}");
    Ok(())
}

/// A proxy's retry is a retry however many commands OTHER proxies sent to
/// the socket in between, at every core count: each proxy's window is its
/// own.
#[test]
fn a_retry_after_other_proxies_fill_the_window_is_a_retry_at_every_core_count()
-> Result<(), TestError> {
    assert_spread(&[(PROXY.0, RELAY), (other_proxy().0, RELAY)]);
    let mut frames = vec![captures::rtpproxy_info(PROXY, RELAY, "k", 0)];
    for i in 0..4096u64 {
        frames.push(captures::rtpproxy_info(
            other_proxy(),
            RELAY,
            &format!("o{i}"),
            SECOND + i * 100,
        ));
    }
    frames.push(captures::rtpproxy_info(PROXY, RELAY, "k", 2 * SECOND));
    let dir = tempfile::tempdir()?;
    let input = [write(dir.path(), "window.pcap", &frames)?];
    let args = ["--rtpproxy-control", captures::RTPPROXY_CONTROL];
    let lines = assert_same_at_every_count("the retry lines", |n| {
        Ok(stderr_lines(&input, n, &args, RETRIED)?.join("\n"))
    })?;
    assert!(
        lines.contains("1 of 4098 control commands were retried"),
        "the proxy's own resend is a retry: {lines}"
    );
    Ok(())
}

// ── idleness measured from the newest message ────────────────────────

/// `idle-0` over two files: the first holds its 35 messages to
/// [`idle_since`]`(15)`, the newest; the second, read after it because its
/// first packet is later than the first file's, holds an INFO exchange of
/// `idle-0` stamped 1 s and 1.5 s on the filler's host pair (so the call is
/// split over workers), then the filler call at `filler_at`. The last message
/// of `idle-0` read is therefore 14 s older than its newest.
fn idle_with_an_older_message_read_last(
    dir: &std::path::Path,
    filler_at: u64,
) -> Result<[std::path::PathBuf; 2], TestError> {
    let (idle, filler) = idle_legs();
    assert_spread(&[(idle.caller, idle.callee), (filler.caller, filler.callee)]);
    let mut first = captures::answered_call(idle, "idle-0@example.com", 0);
    first.extend(captures::infos(
        idle,
        "idle-0@example.com",
        2,
        15,
        SECOND,
        SECOND,
    ));
    let mut second = captures::infos(filler, "idle-0@example.com", 17, 1, SECOND, SECOND);
    second.extend(captures::answered_call(
        filler,
        "filler-0@example.com",
        filler_at,
    ));
    Ok([
        write(dir, "first.pcap", &first)?,
        write(dir, "second.pcap", &second)?,
    ])
}

/// `idle-0`'s message count over `set`, the same at every core count.
fn idle_messages_kept(set: &[std::path::PathBuf; 2]) -> Result<u64, TestError> {
    let single = assert_same_at_every_count("the dialogs", |n| json_dialogs(set, n, &[]))?;
    msg_count(idle_dialog(&single)?)
}

/// Quiet EXACTLY the idle limit since its newest message when a sweep runs,
/// and longer since the last message read: not idle past the limit, so
/// nothing is compacted at any core count.
#[test]
fn quiet_exactly_the_limit_since_the_newest_message_is_not_compacted() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let set = idle_with_an_older_message_read_last(dir.path(), idle_since(15) + 600 * SECOND)?;
    assert_eq!(
        idle_messages_kept(&set)?,
        37,
        "exactly 600 s from the newest message: all 37 messages kept"
    );
    Ok(())
}

/// One millisecond longer, and the sweep compacts it to the keep limit at
/// every core count.
#[test]
fn quiet_a_millisecond_past_the_limit_since_the_newest_message_is_compacted()
-> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let set =
        idle_with_an_older_message_read_last(dir.path(), idle_since(15) + 600 * SECOND + 1_000)?;
    assert_eq!(
        idle_messages_kept(&set)?,
        20,
        "600.001 s from the newest message: compacted to the keep limit, 20"
    );
    Ok(())
}

/// Quiet 590 s since its newest message and 604 s since the last message
/// read: not idle, because idleness is measured from the newest message.
#[test]
fn quiet_past_the_limit_only_since_the_last_message_read_is_not_compacted() -> Result<(), TestError>
{
    let dir = tempfile::tempdir()?;
    let set = idle_with_an_older_message_read_last(dir.path(), idle_since(15) + 590 * SECOND)?;
    assert_eq!(
        idle_messages_kept(&set)?,
        37,
        "590 s from the newest message: all 37 messages kept"
    );
    Ok(())
}
