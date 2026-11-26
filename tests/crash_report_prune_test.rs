// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! FILE-2 (c): the crash-report directory keeps the newest 20 reports.
//!
//! Each crash writes one `sipnab-crash-YYYYMMDD-HHMMSS-<pid>-<seq>.log`
//! file, and before this rule nothing removed the old ones: a service that
//! crashed in a restart loop filled its state directory. After a report is
//! written, sipnab now removes its own older reports so that the newest 20
//! remain, the one just written always among them.
//!
//! The tests drive the public `sipnab::crash::write_crash_report` against a
//! private temporary directory seeded with reports whose modification times
//! are set explicitly, and two tests run the real binary through
//! `--panic-selftest`. Names prefixed `s_` are success cases, `f_` are
//! entries sipnab must refuse to remove (or directories it must refuse to
//! write into), and `e_` are edge cases.
#![cfg(all(unix, feature = "native"))]

use std::collections::BTreeSet;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

type TestError = Box<dyn std::error::Error>;

/// How many reports the directory keeps (`MAX_CRASH_REPORTS` in
/// src/crash.rs, cited in docs/run-as-a-service.md).
const KEEP: usize = 20;

/// The modification time `secs` seconds after the epoch.
fn at(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

/// The base of the seeded reports' modification times (September 2020).
const BASE: u64 = 1_600_000_000;

/// The name sipnab gives a report written at `stamp` (`YYYYMMDD-HHMMSS`)
/// by process `pid` as its `seq`-th report.
fn report_name(stamp: &str, pid: u64, seq: u64) -> String {
    format!("sipnab-crash-{stamp}-{pid}-{seq}.log")
}

/// The name of seeded report `i`: one second of 2020-01-01 per report.
fn old_name(i: u64) -> String {
    report_name(&format!("20200101-{i:06}"), 4242, 0)
}

/// Write `contents` to `dir/name` and set its modification time.
fn put(dir: &Path, name: &str, contents: &str, mtime: SystemTime) -> Result<(), TestError> {
    let path = dir.join(name);
    std::fs::write(&path, contents)?;
    std::fs::File::options()
        .write(true)
        .open(&path)?
        .set_modified(mtime)?;
    Ok(())
}

/// Seed `n` reports, report `i` modified at `BASE + i` (so a higher `i`
/// is newer). Returns their names, oldest first.
fn seed(dir: &Path, n: u64) -> Result<Vec<String>, TestError> {
    let mut names = Vec::new();
    for i in 0..n {
        let name = old_name(i);
        put(dir, &name, &format!("old report {i}"), at(BASE + i))?;
        names.push(name);
    }
    Ok(names)
}

/// Every entry name in `dir`, lossily as UTF-8.
fn names(dir: &Path) -> Result<BTreeSet<String>, TestError> {
    let mut out = BTreeSet::new();
    for entry in std::fs::read_dir(dir)? {
        out.insert(entry?.file_name().to_string_lossy().into_owned());
    }
    Ok(out)
}

/// The entries of `dir` that are regular files with UTF-8 names of the form
/// `sipnab-crash-*.log`.
fn reports(dir: &Path) -> Result<BTreeSet<String>, TestError> {
    let mut out = BTreeSet::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        if entry.file_type()?.is_file()
            && name.starts_with("sipnab-crash-")
            && name.ends_with(".log")
        {
            out.insert(name);
        }
    }
    Ok(out)
}

/// Write one report into `dir` the way the panic hook does and return its
/// file name.
fn write_new(dir: &Path) -> Result<String, TestError> {
    let path = sipnab::crash::write_crash_report(dir, "new report")?;
    let name = path
        .file_name()
        .ok_or("the report path has no file name")?
        .to_string_lossy()
        .into_owned();
    Ok(name)
}

/// The names in `want` that `have` lacks, and the ones it holds beyond
/// them, for an assertion message.
fn diff(have: &BTreeSet<String>, want: &BTreeSet<String>) -> String {
    let missing: Vec<_> = want.difference(have).collect();
    let extra: Vec<_> = have.difference(want).collect();
    format!("missing {missing:?}, unexpected {extra:?}")
}

/// Seed `seeded` reports, write one, and check that the directory then
/// holds exactly the newest `KEEP - 1` seeded reports plus the new one
/// (all of them when fewer were seeded).
fn check_kept_newest(seeded: u64) -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let old = seed(dir.path(), seeded)?;
    let new = write_new(dir.path())?;
    let keep_old = old.len().min(KEEP - 1);
    let mut want: BTreeSet<String> = old[old.len() - keep_old..].iter().cloned().collect();
    want.insert(new.clone());
    let have = names(dir.path())?;
    assert_eq!(
        have,
        want,
        "{seeded} seeded + {new}: {}",
        diff(&have, &want)
    );
    Ok(())
}

/// Seed 25 reports and a decoy at the oldest time of all, write one, and
/// check that the decoy is still there and does not count: the 19 newest
/// seeded reports and the new one remain beside it.
fn check_decoy_kept(decoy: &str) -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let old = seed(dir.path(), 25)?;
    put(dir.path(), decoy, "not a report", at(1))?;
    let new = write_new(dir.path())?;
    let mut want: BTreeSet<String> = old[25 - (KEEP - 1)..].iter().cloned().collect();
    want.insert(new);
    want.insert(decoy.to_owned());
    let have = names(dir.path())?;
    assert_eq!(have, want, "decoy {decoy:?}: {}", diff(&have, &want));
    assert_eq!(
        std::fs::read_to_string(dir.path().join(decoy))?,
        "not a report",
        "decoy {decoy:?} keeps its contents"
    );
    Ok(())
}

// ── Success ─────────────────────────────────────────────────────────

/// 25 older reports and a new one: the newest 20 remain.
#[test]
fn s_twenty_five_old_reports_leave_the_newest_twenty() -> Result<(), TestError> {
    check_kept_newest(25)
}

/// 19 older reports and a new one make 20: nothing is removed.
#[test]
fn s_nineteen_old_reports_are_all_kept() -> Result<(), TestError> {
    check_kept_newest(19)
}

/// 20 older reports and a new one make 21: the oldest one goes.
#[test]
fn s_twenty_old_reports_lose_the_oldest_one() -> Result<(), TestError> {
    check_kept_newest(20)
}

/// An empty directory ends with the one new report.
#[test]
fn s_an_empty_directory_keeps_the_one_new_report() -> Result<(), TestError> {
    check_kept_newest(0)
}

/// A directory the report creates ends with that one report.
#[test]
fn s_a_new_nested_directory_keeps_the_one_new_report() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let sub = dir.path().join("state").join("sipnab");
    let new = write_new(&sub)?;
    let have = names(&sub)?;
    assert_eq!(
        have,
        BTreeSet::from([new.clone()]),
        "only {new} in the new directory"
    );
    Ok(())
}

/// The oldest by modification time go first, even when their names carry
/// later timestamps (a clock that was set back).
#[test]
fn s_the_oldest_by_modification_time_go_first_whatever_the_names_say() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    // Report i is named with second 99 - i, so the name order is the
    // reverse of the time order.
    let mut old = Vec::new();
    for i in 0..25u64 {
        let name = report_name(&format!("20200101-{:06}", 99 - i), 4242, 0);
        put(dir.path(), &name, "old", at(BASE + i))?;
        old.push(name);
    }
    let new = write_new(dir.path())?;
    let mut want: BTreeSet<String> = old[6..].iter().cloned().collect();
    want.insert(new);
    let have = names(dir.path())?;
    assert_eq!(have, want, "time order rules: {}", diff(&have, &want));
    Ok(())
}

/// 100 older reports and a new one: the newest 20 remain.
#[test]
fn s_a_hundred_old_reports_leave_twenty() -> Result<(), TestError> {
    check_kept_newest(100)
}

/// 30 reports written one after another: the last 20 written remain.
#[test]
fn s_thirty_writes_in_a_row_keep_the_last_twenty() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let mut written = Vec::new();
    for _ in 0..30 {
        written.push(write_new(dir.path())?);
    }
    let want: BTreeSet<String> = written[10..].iter().cloned().collect();
    let have = names(dir.path())?;
    assert_eq!(have, want, "the last 20 writes: {}", diff(&have, &want));
    Ok(())
}

/// Reports of other processes (other pids in the name) are pruned too.
#[test]
fn s_reports_of_other_processes_are_pruned() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let mut old = Vec::new();
    for i in 0..25u64 {
        let name = report_name(&format!("20200101-{i:06}"), 1000 + i, 0);
        put(dir.path(), &name, "old", at(BASE + i))?;
        old.push(name);
    }
    let new = write_new(dir.path())?;
    let mut want: BTreeSet<String> = old[6..].iter().cloned().collect();
    want.insert(new);
    let have = names(dir.path())?;
    assert_eq!(have, want, "other pids: {}", diff(&have, &want));
    Ok(())
}

/// Files of other names in the directory stay while reports are pruned.
#[test]
fn s_other_files_in_the_directory_are_kept() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    seed(dir.path(), 25)?;
    put(dir.path(), "notes.txt", "mine", at(1))?;
    put(dir.path(), "sipnab.state", "mine", at(1))?;
    write_new(dir.path())?;
    let have = names(dir.path())?;
    assert!(
        have.contains("notes.txt") && have.contains("sipnab.state"),
        "other files kept: {have:?}"
    );
    assert_eq!(
        reports(dir.path())?.len(),
        KEEP,
        "20 reports beside them: {have:?}"
    );
    Ok(())
}

/// The new report survives its own pruning and holds what was written, even
/// when it is the oldest by time (40 reports dated a day ahead).
#[test]
fn s_the_new_report_exists_and_holds_its_contents() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let ahead = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 86_400;
    for i in 0..40u64 {
        put(dir.path(), &old_name(i), "ahead", at(ahead + i))?;
    }
    let path = sipnab::crash::write_crash_report(dir.path(), "the panic text")?;
    assert_eq!(
        std::fs::read_to_string(&path)?,
        "the panic text",
        "the new report at {} is whole",
        path.display()
    );
    Ok(())
}

/// The reports that remain are not rewritten.
#[test]
fn s_the_kept_reports_are_unchanged() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let old = seed(dir.path(), 25)?;
    write_new(dir.path())?;
    for (i, name) in old.iter().enumerate().skip(6) {
        let path = dir.path().join(name);
        assert_eq!(
            std::fs::read_to_string(&path)?,
            format!("old report {i}"),
            "{name} keeps its contents"
        );
        assert_eq!(
            std::fs::metadata(&path)?.modified()?,
            at(BASE + i as u64),
            "{name} keeps its modification time"
        );
    }
    Ok(())
}

/// A subdirectory of another name is left alone.
#[test]
fn s_a_normal_subdirectory_is_kept() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    seed(dir.path(), 25)?;
    std::fs::create_dir(dir.path().join("archive"))?;
    put(&dir.path().join("archive"), "x", "x", at(1))?;
    write_new(dir.path())?;
    assert!(
        dir.path().join("archive").join("x").is_file(),
        "the subdirectory and its file stay"
    );
    assert_eq!(reports(dir.path())?.len(), KEEP, "20 reports remain");
    Ok(())
}

// ── Failure: entries sipnab must not remove, directories it refuses ──

/// A symbolic link named like a report is not removed, and neither is the
/// file it points at.
#[test]
fn f_a_symlink_named_like_a_report_is_kept() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let outside = tempfile::tempdir()?;
    let target = outside.path().join("victim.log");
    std::fs::write(&target, "victim")?;
    seed(dir.path(), 25)?;
    let link = report_name("19700101-000000", 1, 0);
    std::os::unix::fs::symlink(&target, dir.path().join(&link))?;
    write_new(dir.path())?;
    assert!(
        std::fs::symlink_metadata(dir.path().join(&link))?
            .file_type()
            .is_symlink(),
        "the link {link} stays"
    );
    assert_eq!(
        std::fs::read_to_string(&target)?,
        "victim",
        "the link's target stays"
    );
    assert_eq!(reports(dir.path())?.len(), KEEP, "20 real reports remain");
    Ok(())
}

/// A directory named like a report is not removed.
#[test]
fn f_a_directory_named_like_a_report_is_kept() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    seed(dir.path(), 25)?;
    let sub = report_name("19700101-000000", 1, 0);
    std::fs::create_dir(dir.path().join(&sub))?;
    write_new(dir.path())?;
    assert!(dir.path().join(&sub).is_dir(), "the directory {sub} stays");
    assert_eq!(reports(dir.path())?.len(), KEEP, "20 real reports remain");
    Ok(())
}

/// A socket named like a report is not removed.
#[test]
fn f_a_socket_named_like_a_report_is_kept() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    seed(dir.path(), 25)?;
    let sock = report_name("19700101-000000", 1, 0);
    let _listener = std::os::unix::net::UnixListener::bind(dir.path().join(&sock))?;
    write_new(dir.path())?;
    assert!(
        names(dir.path())?.contains(&sock),
        "the socket {sock} stays"
    );
    assert_eq!(reports(dir.path())?.len(), KEEP, "20 real reports remain");
    Ok(())
}

/// A compressed report (`.log.gz`) is not one sipnab wrote.
#[test]
fn f_a_compressed_report_is_kept() -> Result<(), TestError> {
    check_decoy_kept("sipnab-crash-20200101-000000-1-0.log.gz")
}

/// A date of seven digits is not a report name.
#[test]
fn f_a_short_date_is_kept() -> Result<(), TestError> {
    check_decoy_kept("sipnab-crash-2020010-000000-1-0.log")
}

/// A date of nine digits is not a report name.
#[test]
fn f_a_long_date_is_kept() -> Result<(), TestError> {
    check_decoy_kept("sipnab-crash-202001011-000000-1-0.log")
}

/// A time of five digits is not a report name.
#[test]
fn f_a_short_time_is_kept() -> Result<(), TestError> {
    check_decoy_kept("sipnab-crash-20200101-00000-1-0.log")
}

/// Letters in the pid are not a report name.
#[test]
fn f_letters_in_the_pid_are_kept() -> Result<(), TestError> {
    check_decoy_kept("sipnab-crash-20200101-000000-abc-0.log")
}

/// A name without the sequence field is not a report name.
#[test]
fn f_a_missing_sequence_is_kept() -> Result<(), TestError> {
    check_decoy_kept("sipnab-crash-20200101-000000-1.log")
}

/// An empty pid field is not a report name.
#[test]
fn f_an_empty_pid_is_kept() -> Result<(), TestError> {
    check_decoy_kept("sipnab-crash-20200101-000000--0.log")
}

/// A signed pid is not a report name.
#[test]
fn f_a_signed_pid_is_kept() -> Result<(), TestError> {
    check_decoy_kept("sipnab-crash-20200101-000000-+1-0.log")
}

/// The prefix in capitals is not a report name.
#[test]
fn f_an_uppercase_prefix_is_kept() -> Result<(), TestError> {
    check_decoy_kept("SIPNAB-CRASH-20200101-000000-1-0.log")
}

/// Text before the prefix is not a report name.
#[test]
fn f_an_extra_prefix_is_kept() -> Result<(), TestError> {
    check_decoy_kept("old-sipnab-crash-20200101-000000-1-0.log")
}

/// Another extension is not a report name.
#[test]
fn f_another_extension_is_kept() -> Result<(), TestError> {
    check_decoy_kept("sipnab-crash-20200101-000000-1-0.txt")
}

/// A fifth numeric field is not a report name.
#[test]
fn f_an_extra_field_is_kept() -> Result<(), TestError> {
    check_decoy_kept("sipnab-crash-20200101-000000-1-0-7.log")
}

/// Digits outside ASCII are not a report name.
#[test]
fn f_non_ascii_digits_are_kept() -> Result<(), TestError> {
    check_decoy_kept("sipnab-crash-20200101-000000-\u{0661}\u{0662}-0.log")
}

/// A sequence number beyond the 64-bit range is not one sipnab wrote.
#[test]
fn f_a_sequence_beyond_sixty_four_bits_is_kept() -> Result<(), TestError> {
    check_decoy_kept("sipnab-crash-20200101-000000-1-18446744073709551616.log")
}

/// A name that is not UTF-8 is not removed.
///
/// Not on macOS: APFS refuses to create a file whose name is not valid
/// UTF-8 (`EILSEQ`, "Illegal byte sequence"), so there such a name cannot
/// be in the report directory and the fixture cannot be written.
#[cfg(not(target_os = "macos"))]
#[test]
fn f_a_name_that_is_not_utf8_is_kept() -> Result<(), TestError> {
    use std::os::unix::ffi::OsStrExt as _;
    let dir = tempfile::tempdir()?;
    seed(dir.path(), 25)?;
    let raw = std::ffi::OsStr::from_bytes(b"sipnab-crash-20200101-000000-1-0\xff.log");
    let path = dir.path().join(raw);
    std::fs::write(&path, "not a report")?;
    std::fs::File::options()
        .write(true)
        .open(&path)?
        .set_modified(at(1))?;
    write_new(dir.path())?;
    assert!(path.is_file(), "the non-UTF-8 name stays");
    assert_eq!(reports(dir.path())?.len(), KEEP, "20 real reports remain");
    Ok(())
}

/// A report directory reached through a symbolic link is refused, and the
/// reports in its target are all left.
#[test]
fn f_a_symlinked_report_directory_is_refused_and_nothing_is_removed() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let real = dir.path().join("real");
    std::fs::create_dir(&real)?;
    seed(&real, 25)?;
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&real, &link)?;
    let result = sipnab::crash::write_crash_report(&link, "boom");
    assert!(
        result.is_err(),
        "a symlinked directory is refused: {result:?}"
    );
    assert_eq!(reports(&real)?.len(), 25, "all 25 reports remain");
    Ok(())
}

/// A world-writable report directory without the sticky bit is refused,
/// and its reports are all left.
#[test]
fn f_a_world_writable_report_directory_is_refused_and_nothing_is_removed() -> Result<(), TestError>
{
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir()?;
    seed(dir.path(), 25)?;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777))?;
    let result = sipnab::crash::write_crash_report(dir.path(), "boom");
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
    assert!(
        result.is_err(),
        "a world-writable directory is refused: {result:?}"
    );
    assert_eq!(reports(dir.path())?.len(), 25, "all 25 reports remain");
    Ok(())
}

/// A report directory path that is a regular file is refused, and the
/// reports beside it are all left.
#[test]
fn f_a_report_directory_that_is_a_file_is_refused() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    seed(dir.path(), 25)?;
    let file = dir.path().join("not-a-dir");
    std::fs::write(&file, "x")?;
    let result = sipnab::crash::write_crash_report(&file, "boom");
    assert!(
        result.is_err(),
        "a file as the directory is refused: {result:?}"
    );
    assert_eq!(reports(dir.path())?.len(), 25, "all 25 reports remain");
    Ok(())
}

// ── Edge ────────────────────────────────────────────────────────────

/// Reports with equal modification times go in the order of their names'
/// timestamps, oldest first.
#[test]
fn e_equal_times_remove_the_oldest_names() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let mut old = Vec::new();
    for i in 0..25u64 {
        let name = old_name(i);
        put(dir.path(), &name, "old", at(BASE))?;
        old.push(name);
    }
    let new = write_new(dir.path())?;
    let mut want: BTreeSet<String> = old[6..].iter().cloned().collect();
    want.insert(new);
    let have = names(dir.path())?;
    assert_eq!(have, want, "equal times: {}", diff(&have, &want));
    Ok(())
}

/// With equal times and timestamps, the sequence numbers compare as
/// numbers: 2 is older than 10.
#[test]
fn e_equal_times_and_stamps_compare_the_sequence_as_a_number() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    for seq in 2..=21u64 {
        put(
            dir.path(),
            &report_name("20200101-000000", 4242, seq),
            "old",
            at(BASE),
        )?;
    }
    write_new(dir.path())?;
    let have = names(dir.path())?;
    let oldest = report_name("20200101-000000", 4242, 2);
    let ten = report_name("20200101-000000", 4242, 10);
    assert!(!have.contains(&oldest), "{oldest} goes first: {have:?}");
    assert!(have.contains(&ten), "{ten} stays: {have:?}");
    assert_eq!(have.len(), KEEP, "20 remain: {have:?}");
    Ok(())
}

/// With equal times, timestamps and sequences, the pids compare as numbers.
#[test]
fn e_equal_times_stamps_and_sequences_compare_the_pid_as_a_number() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    for pid in 2..=21u64 {
        put(
            dir.path(),
            &report_name("20200101-000000", pid, 0),
            "old",
            at(BASE),
        )?;
    }
    write_new(dir.path())?;
    let have = names(dir.path())?;
    let oldest = report_name("20200101-000000", 2, 0);
    let ten = report_name("20200101-000000", 10, 0);
    assert!(!have.contains(&oldest), "{oldest} goes first: {have:?}");
    assert!(have.contains(&ten), "{ten} stays: {have:?}");
    assert_eq!(have.len(), KEEP, "20 remain: {have:?}");
    Ok(())
}

/// Reports dated after now (a clock set forward) do not push out the
/// report just written.
#[test]
fn e_reports_dated_in_the_future_never_remove_the_new_one() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let future = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 86_400;
    let mut old = Vec::new();
    for i in 0..25u64 {
        let name = report_name(&format!("20991231-{i:06}"), 4242, 0);
        put(dir.path(), &name, "future", at(future + i))?;
        old.push(name);
    }
    let new = write_new(dir.path())?;
    let mut want: BTreeSet<String> = old[6..].iter().cloned().collect();
    want.insert(new);
    let have = names(dir.path())?;
    assert_eq!(have, want, "future reports: {}", diff(&have, &want));
    Ok(())
}

/// Decoys do not count toward the 20: 25 of them and no reports are all
/// kept beside the new report.
#[test]
fn e_decoys_do_not_count_toward_twenty() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let mut want = BTreeSet::new();
    for i in 0..25u64 {
        let name = format!("sipnab-crash-20200101-{i:06}-1-0.log.gz");
        put(dir.path(), &name, "decoy", at(BASE + i))?;
        want.insert(name);
    }
    want.insert(write_new(dir.path())?);
    let have = names(dir.path())?;
    assert_eq!(have, want, "decoys only: {}", diff(&have, &want));
    Ok(())
}

/// Reports modified at the epoch itself go first.
#[test]
fn e_reports_at_the_epoch_go_first() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    seed(dir.path(), 20)?;
    let zero = report_name("19700101-000000", 1, 0);
    put(dir.path(), &zero, "epoch", UNIX_EPOCH)?;
    write_new(dir.path())?;
    let have = names(dir.path())?;
    assert!(!have.contains(&zero), "{zero} goes: {have:?}");
    assert!(
        !have.contains(&old_name(0)),
        "the oldest seeded goes: {have:?}"
    );
    assert_eq!(have.len(), KEEP, "20 remain: {have:?}");
    Ok(())
}

/// A report without write permission is still removed: removal depends on
/// the directory, which sipnab owns.
#[test]
fn e_a_read_only_report_is_still_removed() -> Result<(), TestError> {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir()?;
    let old = seed(dir.path(), 25)?;
    std::fs::set_permissions(
        dir.path().join(&old[0]),
        std::fs::Permissions::from_mode(0o400),
    )?;
    write_new(dir.path())?;
    let have = names(dir.path())?;
    assert!(!have.contains(&old[0]), "{} goes: {have:?}", old[0]);
    assert_eq!(have.len(), KEEP, "20 remain: {have:?}");
    Ok(())
}

/// Empty report files count as reports.
#[test]
fn e_empty_report_files_count() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    for i in 0..25u64 {
        put(dir.path(), &old_name(i), "", at(BASE + i))?;
    }
    write_new(dir.path())?;
    assert_eq!(reports(dir.path())?.len(), KEEP, "20 remain");
    Ok(())
}

/// A hard link named like a report is a regular file and counts; removing
/// it leaves the file's other name.
#[test]
fn e_a_hard_link_named_like_a_report_counts() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    seed(dir.path(), 25)?;
    let keep = dir.path().join("keep-me.txt");
    put(dir.path(), "keep-me.txt", "linked", at(1))?;
    let link = report_name("19700101-000000", 1, 0);
    std::fs::hard_link(&keep, dir.path().join(&link))?;
    write_new(dir.path())?;
    let have = names(dir.path())?;
    assert!(
        !have.contains(&link),
        "the oldest name {link} goes: {have:?}"
    );
    assert_eq!(
        std::fs::read_to_string(&keep)?,
        "linked",
        "the other name keeps the contents"
    );
    assert_eq!(reports(dir.path())?.len(), KEEP, "20 remain: {have:?}");
    Ok(())
}

/// A report inside a subdirectory is not touched: the prune reads one
/// directory, not a tree.
#[test]
fn e_a_report_in_a_subdirectory_is_not_touched() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    seed(dir.path(), 25)?;
    let sub = dir.path().join("older");
    std::fs::create_dir(&sub)?;
    let nested = report_name("19700101-000000", 1, 0);
    put(&sub, &nested, "nested", at(1))?;
    write_new(dir.path())?;
    assert!(sub.join(&nested).is_file(), "{nested} in older/ stays");
    assert_eq!(reports(dir.path())?.len(), KEEP, "20 remain");
    Ok(())
}

/// 21 older reports and a new one make 22: the two oldest go.
#[test]
fn e_twenty_one_old_reports_lose_the_two_oldest() -> Result<(), TestError> {
    check_kept_newest(21)
}

/// Leading zeros in the pid and the sequence still make a report name.
#[test]
fn e_leading_zeros_in_pid_and_sequence_are_reports() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    seed(dir.path(), 20)?;
    let zeros = "sipnab-crash-19700101-000000-007-00.log";
    put(dir.path(), zeros, "zeros", at(1))?;
    write_new(dir.path())?;
    let have = names(dir.path())?;
    assert!(
        !have.contains(zeros),
        "{zeros} is a report and goes: {have:?}"
    );
    assert_eq!(have.len(), KEEP, "20 remain: {have:?}");
    Ok(())
}

/// The largest 64-bit sequence number is still a report name.
#[test]
fn e_the_largest_sixty_four_bit_sequence_is_a_report() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    seed(dir.path(), 20)?;
    let big = report_name("19700101-000000", 1, u64::MAX);
    put(dir.path(), &big, "big", at(1))?;
    write_new(dir.path())?;
    let have = names(dir.path())?;
    assert!(!have.contains(&big), "{big} is a report and goes: {have:?}");
    assert_eq!(have.len(), KEEP, "20 remain: {have:?}");
    Ok(())
}

/// The date and time fields are digits, not a checked calendar date: a
/// name sipnab could not have dated is still its pattern.
#[test]
fn e_digits_that_are_not_a_calendar_date_are_reports() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    seed(dir.path(), 20)?;
    let odd = report_name("99999999-999999", 1, 0);
    put(dir.path(), &odd, "odd", at(1))?;
    write_new(dir.path())?;
    let have = names(dir.path())?;
    assert!(!have.contains(&odd), "{odd} is a report and goes: {have:?}");
    assert_eq!(have.len(), KEEP, "20 remain: {have:?}");
    Ok(())
}

/// A group-writable report directory is accepted and pruned.
#[test]
fn e_a_group_writable_report_directory_is_pruned() -> Result<(), TestError> {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir()?;
    seed(dir.path(), 25)?;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o770))?;
    write_new(dir.path())?;
    assert_eq!(reports(dir.path())?.len(), KEEP, "20 remain");
    Ok(())
}

// ── The real binary ─────────────────────────────────────────────────

/// Run `sipnab --panic-selftest` with `[crash] report_dir = dir`, ended at
/// a deadline. Returns `(exit code, stderr)`.
fn selftest(dir: &Path) -> Result<(Option<i32>, String), TestError> {
    use std::io::Read as _;
    use std::process::{Command, Stdio};
    use std::time::Instant;
    let home = tempfile::tempdir()?;
    let config = home.path().join("crash.toml");
    std::fs::write(
        &config,
        format!("[crash]\nreport_dir = \"{}\"\n", dir.display()),
    )?;
    let mut child = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .arg("-f")
        .arg(&config)
        .arg("--panic-selftest")
        .envs(run_support::config_isolation(home.path()))
        .env("SIPNAB_LOG", "off")
        .env("NO_COLOR", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .tied_to_test()
        .spawn()?;
    let deadline = Instant::now() + test_timeout(30);
    let status = loop {
        if let Some(st) = child.try_wait()? {
            break Some(st);
        }
        if Instant::now() >= deadline {
            child.kill()?;
            let _ = child.wait()?;
            break None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        pipe.read_to_string(&mut stderr)?;
    }
    Ok((status.and_then(|st| st.code()), stderr))
}

#[path = "support/run.rs"]
mod run_support;

include!("support/timeout.rs");
include!("support/child_lifetime.rs");

/// A crash of the real binary into a directory of 25 older reports leaves
/// the newest 19 of them and its own.
#[test]
fn s_a_crash_of_the_binary_prunes_to_twenty() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let old = seed(dir.path(), 25)?;
    let (code, stderr) = selftest(dir.path())?;
    assert_eq!(code, Some(101), "the selftest exits 101:\n{stderr}");
    assert!(
        stderr.contains("crash report written to"),
        "stderr names the report:\n{stderr}"
    );
    let have = reports(dir.path())?;
    assert_eq!(have.len(), KEEP, "20 remain: {have:?}\n{stderr}");
    let kept_old: BTreeSet<String> = old[6..].iter().cloned().collect();
    assert!(
        kept_old.is_subset(&have),
        "the newest 19 seeded stay: {}",
        diff(&have, &kept_old)
    );
    Ok(())
}

/// A crash of the real binary into a directory of 3 older reports removes
/// none of them.
#[test]
fn s_a_crash_of_the_binary_keeps_a_short_history() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let old: BTreeSet<String> = seed(dir.path(), 3)?.into_iter().collect();
    let (code, stderr) = selftest(dir.path())?;
    assert_eq!(code, Some(101), "the selftest exits 101:\n{stderr}");
    let have = reports(dir.path())?;
    assert_eq!(have.len(), 4, "3 old and the new one: {have:?}\n{stderr}");
    assert!(
        old.is_subset(&have),
        "all 3 old stay: {}",
        diff(&have, &old)
    );
    Ok(())
}
