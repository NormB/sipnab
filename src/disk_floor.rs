// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The free-disk floor of a run's outputs (`--min-free-disk`).
//!
//! A multi-day capture fills its disk one record at a time, and nothing used
//! to look: the first sign was a failed write, after which `-O`, the vCon
//! spool and the audit trail all stopped at once. This module watches the
//! free space of every directory a run writes into and says so before that
//! happens.
//!
//! * Without the flag, a directory whose free space falls under
//!   [`DEFAULT_WARN_FLOOR`] gets one warning per crossing, and the run goes
//!   on.
//! * `--min-free-disk SIZE` sets the floor and STOPS the capture when a
//!   directory falls under it. The run ends as a stop signal ends it, its
//!   outputs closed, and exits [`crate::signals::LOW_DISK_EXIT_CODE`].
//! * `--min-free-disk 0` turns the check off, warning included.
//!
//! Each directory is opened once, before the capture opens, and read with
//! `fstatvfs(3)` on that descriptor: a `--chroot` run or one that dropped its
//! privileges no longer reaches the path it was given, but the descriptor
//! still names the same file system. The check runs before the capture opens
//! and then every [`CHECK_INTERVAL`] on one thread of its own, never per
//! packet.

use std::path::{Path, PathBuf};

/// The floor a run without `--min-free-disk` warns at: 1 GiB.
pub const DEFAULT_WARN_FLOOR: u64 = 1_073_741_824;

/// How often the watch thread reads the free space: the interval of the
/// receive loop's sweep (`app::batch::SWEEP_INTERVAL`).
pub const CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// One KiB, the smallest unit `--min-free-disk` takes.
const KIB: u64 = 1024;

/// A `--min-free-disk` value. A type of its own, not `u64`: the flag takes a
/// size with a unit, never a bare count, and it keeps the text as given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinFreeDisk {
    /// The floor in bytes.
    pub bytes: u64,
    /// The value as the command line gave it, such as `2G`.
    pub given: String,
}

/// Parse a size: `0`, or a whole number followed by a binary unit (`K`, `M`,
/// `G`, `T`, or `KiB` .. `TiB`, any case).
///
/// # Errors
///
/// The reason the value is refused, for clap to print after the flag's name.
pub fn parse_size(value: &str) -> Result<u64, String> {
    if value.is_empty() {
        return Err("the value is empty; give a size such as 2G or 500M".to_string());
    }
    let digits_end = value
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(value.len());
    let (digits, unit) = value.split_at(digits_end);
    if digits.is_empty() {
        return Err(format!(
            "'{value}' does not start with a whole number; give a size such as 2G or 500M"
        ));
    }
    let too_large = || format!("'{value}' is too large; the largest is 16777215T");
    let number: u64 = digits.parse().map_err(|_| too_large())?;
    let multiplier = match unit.to_ascii_lowercase().as_str() {
        "" if number == 0 => return Ok(0),
        "" => {
            return Err(format!(
                "'{value}' has no unit; say it, such as {value}M or {value}G (1G = 1024 MiB)"
            ));
        }
        "k" | "kib" => KIB,
        "m" | "mib" => KIB * KIB,
        "g" | "gib" => KIB * KIB * KIB,
        "t" | "tib" => KIB * KIB * KIB * KIB,
        "kb" | "mb" | "gb" | "tb" => {
            return Err(format!(
                "'{value}': the units are binary (1K = 1024 bytes); \
                 write K, M, G or T, or KiB, MiB, GiB or TiB"
            ));
        }
        _ if unit.starts_with('.') || unit.starts_with(',') => {
            return Err(format!(
                "'{value}' is not a whole number; give a smaller unit instead, such as 1536M"
            ));
        }
        _ => {
            return Err(format!(
                "'{unit}' is not a unit; write K, M, G or T (binary: 1K = 1024 bytes)"
            ));
        }
    };
    number.checked_mul(multiplier).ok_or_else(too_large)
}

/// clap's parser for `--min-free-disk`: [`parse_size`], as a [`MinFreeDisk`].
///
/// # Errors
///
/// [`parse_size`]'s.
pub fn parse_min_free_disk(value: &str) -> Result<MinFreeDisk, String> {
    parse_size(value).map(|bytes| MinFreeDisk {
        bytes,
        given: value.to_string(),
    })
}

/// What a run does about free disk space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Floor {
    /// `--min-free-disk 0`: nothing is checked.
    Off,
    /// No flag: warn below this many free bytes, and go on.
    Warn(u64),
    /// `--min-free-disk SIZE`: stop the capture below this many free bytes.
    Stop(u64),
}

impl Floor {
    /// The floor `--min-free-disk` asks for: `None` when the flag is absent.
    #[must_use]
    pub fn from_flag(flag: Option<u64>) -> Self {
        match flag {
            None => Floor::Warn(DEFAULT_WARN_FLOOR),
            Some(0) => Floor::Off,
            Some(bytes) => Floor::Stop(bytes),
        }
    }

    /// The floor in bytes; `None` when the check is off.
    #[must_use]
    pub fn bytes(self) -> Option<u64> {
        match self {
            Floor::Off => None,
            Floor::Warn(b) | Floor::Stop(b) => Some(b),
        }
    }
}

/// The free bytes a `statvfs` result gives an unprivileged writer:
/// `f_bavail` blocks of `f_frsize` bytes, saturating rather than wrapping.
#[must_use]
pub fn free_bytes(bavail: u64, frsize: u64) -> u64 {
    bavail.saturating_mul(frsize)
}

/// The free space a directory must regain, after it fell under `floor`,
/// before the run says it recovered: the floor plus a tenth. Without the
/// margin a directory that hovers at the floor would warn and recover every
/// [`CHECK_INTERVAL`].
#[must_use]
pub fn recovery_level(floor: u64) -> u64 {
    floor.saturating_add(floor / 10)
}

/// `dirs` with each directory once, the first occurrence kept.
fn dedup_in_order(dirs: impl IntoIterator<Item = PathBuf>) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    for d in dirs {
        if !out.contains(&d) {
            out.push(d);
        }
    }
    out
}

/// The directories to watch for the output files `outputs`: the directory
/// each one is written into, once each, in order. `-` (standard output) and
/// empty values name no directory, and neither does a directory that does
/// not exist: sipnab refuses that output when it opens it, and a low-disk
/// stop must not hide that refusal.
#[must_use]
pub fn watched_dirs<P: AsRef<Path>>(outputs: &[P]) -> Vec<PathBuf> {
    dedup_in_order(outputs.iter().filter_map(|p| {
        let p = p.as_ref();
        if p.as_os_str().is_empty() || p == Path::new("-") {
            return None;
        }
        let dir = match p.parent() {
            Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
            _ => PathBuf::from("."),
        };
        dir.is_dir().then_some(dir)
    }))
}

/// The directories vCon rules write into, watched as they are, not as the
/// parent of a file. A rule directory is created at the rule's first write,
/// so one that does not exist yet is watched through its nearest ancestor
/// that does: the file system it will be created on.
#[must_use]
pub fn watched_rule_dirs<P: AsRef<Path>>(dirs: &[P]) -> Vec<PathBuf> {
    dedup_in_order(dirs.iter().filter_map(|d| {
        let d = d.as_ref();
        if d.as_os_str().is_empty() {
            return None;
        }
        let relative_base = Path::new(".");
        d.ancestors()
            .map(|a| {
                if a.as_os_str().is_empty() {
                    relative_base
                } else {
                    a
                }
            })
            .find(|a| a.is_dir())
            .map(Path::to_path_buf)
    }))
}

/// One directory under watch.
#[derive(Debug)]
pub struct Watched {
    /// The directory, as the run was given it.
    pub dir: PathBuf,
    /// The directory, opened before the capture opened; `None` when it could
    /// not be opened, with the reason in `open_error`.
    handle: Option<std::fs::File>,
    /// Why the directory could not be opened.
    open_error: Option<String>,
    /// Whether the last reading was under the floor.
    below: bool,
    /// Whether the last reading failed (said once, until a reading works).
    failed: bool,
}

/// What one check found worth saying.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// `dir` fell under the floor: `free` bytes left.
    Low {
        /// The directory.
        dir: PathBuf,
        /// Its free bytes.
        free: u64,
        /// The floor.
        floor: u64,
        /// Whether the floor is `--min-free-disk`'s, which stops the run.
        stop: bool,
    },
    /// `dir` is back above the floor's recovery level.
    Recovered {
        /// The directory.
        dir: PathBuf,
        /// Its free bytes.
        free: u64,
        /// The floor.
        floor: u64,
    },
    /// The free space of `dir` cannot be read; it is not checked until it can.
    Unreadable {
        /// The directory.
        dir: PathBuf,
        /// Why.
        error: String,
    },
}

/// The free-disk watch of one run.
#[derive(Debug)]
pub struct DiskWatch {
    /// The floor.
    floor: Floor,
    /// The directories, each with its own crossing state.
    watched: Vec<Watched>,
}

impl DiskWatch {
    /// Open each of `dirs` for the watch. A directory that will not open is
    /// kept, and reported [`Event::Unreadable`] by the first check.
    #[must_use]
    pub fn open(floor: Floor, dirs: Vec<PathBuf>) -> Self {
        let watched = dirs
            .into_iter()
            .map(|dir| {
                let (handle, open_error) = match std::fs::File::open(&dir) {
                    Ok(f) => (Some(f), None),
                    Err(e) => (None, Some(e.to_string())),
                };
                Watched {
                    dir,
                    handle,
                    open_error,
                    below: false,
                    failed: false,
                }
            })
            .collect();
        DiskWatch { floor, watched }
    }

    /// Whether there is nothing to check: the floor is off or no output is
    /// written to a directory.
    #[must_use]
    pub fn is_idle(&self) -> bool {
        self.floor == Floor::Off || self.watched.is_empty()
    }

    /// The directories under watch, in order.
    pub fn dirs(&self) -> impl Iterator<Item = &Path> {
        self.watched.iter().map(|w| w.dir.as_path())
    }

    /// One check, reading each directory's free bytes through `probe`.
    pub fn check_with(
        &mut self,
        probe: &mut dyn FnMut(&Watched) -> std::io::Result<u64>,
    ) -> Vec<Event> {
        let Some(floor) = self.floor.bytes() else {
            return Vec::new();
        };
        let stop = matches!(self.floor, Floor::Stop(_));
        let mut events = Vec::new();
        for w in &mut self.watched {
            let free = match probe(w) {
                Ok(free) => {
                    w.failed = false;
                    free
                }
                Err(e) => {
                    if !w.failed {
                        w.failed = true;
                        events.push(Event::Unreadable {
                            dir: w.dir.clone(),
                            error: e.to_string(),
                        });
                    }
                    continue;
                }
            };
            if !w.below && free < floor {
                w.below = true;
                events.push(Event::Low {
                    dir: w.dir.clone(),
                    free,
                    floor,
                    stop,
                });
            } else if w.below && free >= recovery_level(floor) {
                w.below = false;
                events.push(Event::Recovered {
                    dir: w.dir.clone(),
                    free,
                    floor,
                });
            }
        }
        events
    }

    /// One check of the real free space, through `fstatvfs(3)`.
    pub fn check(&mut self) -> Vec<Event> {
        self.check_with(&mut probe_free)
    }
}

/// The free bytes of a watched directory, from its descriptor.
///
/// # Errors
///
/// The directory did not open, or `fstatvfs` failed.
pub fn probe_free(w: &Watched) -> std::io::Result<u64> {
    let Some(file) = w.handle.as_ref() else {
        return Err(std::io::Error::other(
            w.open_error
                .clone()
                .unwrap_or_else(|| "not opened".to_string()),
        ));
    };
    fstatvfs_free(file)
}

/// `fstatvfs(3)` of `file`: the bytes an unprivileged writer may still use.
#[cfg(unix)]
fn fstatvfs_free(file: &std::fs::File) -> std::io::Result<u64> {
    use std::os::fd::AsRawFd as _;
    // SAFETY: `statvfs` is plain data, so all zeroes is a valid value; the
    // call gets a descriptor that is open for as long as `file` is borrowed
    // and a pointer to a `statvfs` of the right size, which it fills in.
    let (rc, st) = unsafe {
        let mut st: libc::statvfs = std::mem::zeroed();
        let rc = libc::fstatvfs(file.as_raw_fd(), &raw mut st);
        (rc, st)
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    #[allow(clippy::useless_conversion)] // the field widths differ by platform
    Ok(free_bytes(u64::from(st.f_bavail), u64::from(st.f_frsize)))
}

/// No free-space call off Unix: every directory reads as unreadable, once.
#[cfg(not(unix))]
fn fstatvfs_free(_file: &std::fs::File) -> std::io::Result<u64> {
    Err(std::io::Error::other(
        "free disk space is not read on this platform",
    ))
}

/// A byte count for a person: `1.5 GiB`, `512.0 MiB`, `100 B`.
#[must_use]
pub fn human(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["KiB", "MiB", "GiB", "TiB"];
    if bytes < KIB {
        return format!("{bytes} B");
    }
    #[allow(clippy::cast_precision_loss)] // one decimal place is shown
    let mut v = bytes as f64 / KIB as f64;
    let mut unit = UNITS[0];
    for u in &UNITS[1..] {
        if v < 1024.0 {
            break;
        }
        v /= 1024.0;
        unit = u;
    }
    format!("{v:.1} {unit}")
}

/// How loud a line is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// A crossing, or a directory that cannot be read.
    Warn,
    /// A recovery.
    Info,
}

/// What the run does about one check's events: the lines to log, and the
/// reason to stop, when a `--min-free-disk` floor was crossed.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Verdict {
    /// Lines for the log, in order.
    pub lines: Vec<(Severity, String)>,
    /// The stop reason, printed on stderr as the run ends.
    pub stop: Option<String>,
}

/// The [`Verdict`] of `events`.
#[must_use]
pub fn verdict(events: &[Event]) -> Verdict {
    let mut v = Verdict::default();
    for e in events {
        match e {
            Event::Low {
                dir,
                free,
                floor,
                stop: true,
            } => {
                let line = format!(
                    "stopping the capture: free disk space under {} is {free} bytes ({}), \
                     below --min-free-disk {floor} bytes ({})",
                    dir.display(),
                    human(*free),
                    human(*floor)
                );
                v.lines.push((Severity::Warn, line.clone()));
                if v.stop.is_none() {
                    v.stop = Some(format!(
                        "sipnab stopped: free disk space under {} is {free} bytes ({}), \
                         below --min-free-disk {floor} bytes ({}); exit 4",
                        dir.display(),
                        human(*free),
                        human(*floor)
                    ));
                }
            }
            Event::Low {
                dir,
                free,
                floor,
                stop: false,
            } => v.lines.push((
                Severity::Warn,
                format!(
                    "free disk space under {} is {free} bytes ({}), below {floor} bytes ({}); \
                     outputs written there fail when it fills. --min-free-disk SIZE stops the \
                     capture at a floor of your choosing, --min-free-disk 0 turns this off",
                    dir.display(),
                    human(*free),
                    human(*floor)
                ),
            )),
            Event::Recovered { dir, free, floor } => v.lines.push((
                Severity::Info,
                format!(
                    "free disk space under {} is back to {free} bytes ({}), above the floor of \
                     {floor} bytes",
                    dir.display(),
                    human(*free)
                ),
            )),
            Event::Unreadable { dir, error } => v.lines.push((
                Severity::Warn,
                format!(
                    "cannot read the free disk space under {}: {error}; it is not checked \
                     until it can be read",
                    dir.display()
                ),
            )),
        }
    }
    v
}

/// The directories this run writes into: `-O` (every `--split` file sits
/// beside it), `--mcp-audit-file`, `--tui-audit-file`, `--evidence-out PATH`
/// and each vCon rule's directory.
#[must_use]
pub fn run_output_dirs(
    cli: &crate::cli::Cli,
    rules: &[crate::app::batch::VconRule],
) -> Vec<PathBuf> {
    let files: Vec<&str> = [
        cli.capture_args.output.as_deref(),
        cli.mcp_args.mcp_audit_file.as_deref(),
        cli.security_args.tui_audit_file.as_deref(),
        cli.security_args.evidence_out.as_deref(),
    ]
    .into_iter()
    .flatten()
    .collect();
    let rule_dirs: Vec<&Path> = rules.iter().map(|r| r.dir.as_path()).collect();
    dedup_in_order(
        watched_dirs(&files)
            .into_iter()
            .chain(watched_rule_dirs(&rule_dirs)),
    )
}

/// Apply one check's [`Verdict`] in the running process: its lines to the log,
/// its stop to [`crate::signals::request_low_disk_stop`]. Returns whether it
/// asked for the stop.
fn apply(v: Verdict) -> bool {
    for (sev, line) in v.lines {
        match sev {
            Severity::Warn => tracing::warn!("{line}"),
            Severity::Info => tracing::info!("{line}"),
        }
    }
    match v.stop {
        Some(reason) => {
            crate::signals::request_low_disk_stop(reason);
            true
        }
        None => false,
    }
}

/// The first check of this run, before the capture opens: each directory is
/// opened here, so the watch still reaches it after a `--chroot` or the
/// privilege drop. Returns the watch for [`watch_during_run`]; `None` when
/// there is nothing to watch.
///
/// # Errors
///
/// Below a `--min-free-disk` floor now, the run must not start: the reason
/// is already on stderr, and the error is the code to exit with,
/// [`crate::signals::LOW_DISK_EXIT_CODE`] (row `--min-free-disk` of
/// `early_exit`).
pub fn start(
    cli: &crate::cli::Cli,
    rules: &[crate::app::batch::VconRule],
) -> Result<Option<DiskWatch>, i32> {
    let floor = Floor::from_flag(cli.capture_args.min_free_disk.as_ref().map(|m| m.bytes));
    if floor == Floor::Off {
        return Ok(None);
    }
    let mut watch = DiskWatch::open(floor, run_output_dirs(cli, rules));
    if watch.is_idle() {
        return Ok(None);
    }
    let first = verdict(&watch.check());
    if let Some(reason) = first.stop.clone() {
        // The run has not started: nothing to stop, so no stop request. The
        // reason goes to stderr itself, since it explains the exit code.
        for (_, line) in &first.lines {
            tracing::warn!("{line}");
        }
        stderr_line!("{reason}");
        return Err(crate::signals::LOW_DISK_EXIT_CODE);
    }
    let _ = apply(first);
    Ok(Some(watch))
}

/// Check `watch` every [`CHECK_INTERVAL`] for the rest of the run, on a
/// thread of its own. Called after the launch, so the thread never exists at
/// the privilege drop. Below a `--min-free-disk` floor, the thread asks for
/// the stop through [`crate::signals::request_low_disk_stop`] and ends.
pub fn watch_during_run(mut watch: DiskWatch) {
    let spawned = std::thread::Builder::new()
        .name("disk-floor".to_string())
        .spawn(move || {
            while !crate::signals::shutdown_requested() {
                std::thread::sleep(CHECK_INTERVAL);
                if apply(verdict(&watch.check())) {
                    break;
                }
            }
        });
    if let Err(e) = spawned {
        tracing::warn!("free disk space is not watched during the run: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The error a test returns.
    type TestError = Box<dyn std::error::Error>;

    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    const TIB: u64 = 1024 * GIB;

    /// A watch over `dirs` (not opened: the probe supplies every reading).
    fn watch(floor: Floor, dirs: &[&str]) -> DiskWatch {
        DiskWatch::open(floor, dirs.iter().map(PathBuf::from).collect())
    }

    /// One check where every directory reads `free`.
    fn check_all(w: &mut DiskWatch, free: u64) -> Vec<Event> {
        w.check_with(&mut |_| Ok(free))
    }

    // --- success -----------------------------------------------------------

    #[test]
    fn s_parse_takes_gibibytes() {
        assert_eq!(parse_size("2G"), Ok(2 * GIB), "2G is two GiB");
    }

    #[test]
    fn s_parse_takes_the_long_unit_names() {
        assert_eq!(parse_size("2GiB"), Ok(2 * GIB), "GiB");
        assert_eq!(parse_size("3MiB"), Ok(3 * MIB), "MiB");
        assert_eq!(parse_size("4KiB"), Ok(4 * KIB), "KiB");
        assert_eq!(parse_size("1TiB"), Ok(TIB), "TiB");
    }

    #[test]
    fn s_parse_takes_mebibytes() {
        assert_eq!(parse_size("500M"), Ok(500 * MIB), "500M");
    }

    #[test]
    fn s_parse_takes_kibibytes() {
        assert_eq!(parse_size("64K"), Ok(64 * KIB), "64K");
    }

    #[test]
    fn s_parse_takes_tebibytes() {
        assert_eq!(parse_size("1T"), Ok(TIB), "1T");
    }

    #[test]
    fn s_parse_ignores_the_case_of_the_unit() {
        assert_eq!(parse_size("2g"), Ok(2 * GIB), "g");
        assert_eq!(parse_size("2gib"), Ok(2 * GIB), "gib");
        assert_eq!(parse_size("2GIB"), Ok(2 * GIB), "GIB");
    }

    #[test]
    fn s_parse_takes_zero_without_a_unit() {
        assert_eq!(parse_size("0"), Ok(0), "0 turns the check off");
        assert_eq!(parse_size("0G"), Ok(0), "0G is 0 too");
    }

    #[test]
    fn s_the_flag_parser_gives_the_size_as_its_own_type() {
        assert_eq!(
            parse_min_free_disk("2G"),
            Ok(MinFreeDisk {
                bytes: 2 * GIB,
                given: "2G".to_string()
            }),
            "the flag's value, with its text"
        );
        assert!(
            parse_min_free_disk("500").is_err(),
            "and refuses what parse_size refuses"
        );
    }

    #[test]
    fn s_no_flag_warns_at_the_default_floor() {
        assert_eq!(
            Floor::from_flag(None),
            Floor::Warn(DEFAULT_WARN_FLOOR),
            "no flag: warn at 1 GiB"
        );
        assert_eq!(DEFAULT_WARN_FLOOR, GIB, "the default floor is 1 GiB");
    }

    #[test]
    fn s_a_flag_stops_at_its_floor() {
        assert_eq!(
            Floor::from_flag(Some(5 * GIB)),
            Floor::Stop(5 * GIB),
            "the flag stops"
        );
    }

    #[test]
    fn s_a_dir_above_the_floor_says_nothing() {
        let mut w = watch(Floor::Warn(GIB), &["/a"]);
        assert!(
            check_all(&mut w, 2 * GIB).is_empty(),
            "above the floor: no event"
        );
        assert!(
            check_all(&mut w, 2 * GIB).is_empty(),
            "still above: no event"
        );
    }

    #[test]
    fn s_a_crossing_below_warns_once() {
        let mut w = watch(Floor::Warn(GIB), &["/a"]);
        let first = check_all(&mut w, MIB);
        assert_eq!(
            first,
            vec![Event::Low {
                dir: "/a".into(),
                free: MIB,
                floor: GIB,
                stop: false
            }],
            "the crossing is reported"
        );
        assert!(
            check_all(&mut w, MIB).is_empty(),
            "the same crossing is not reported again"
        );
        assert!(
            check_all(&mut w, KIB).is_empty(),
            "nor when it falls further"
        );
    }

    #[test]
    fn s_a_stop_floor_crossing_asks_for_the_stop() {
        let mut w = watch(Floor::Stop(GIB), &["/out"]);
        let events = check_all(&mut w, MIB);
        assert_eq!(
            events,
            vec![Event::Low {
                dir: "/out".into(),
                free: MIB,
                floor: GIB,
                stop: true
            }],
            "a --min-free-disk floor stops"
        );
        let v = verdict(&events);
        assert!(v.stop.is_some(), "a stop reason: {v:?}");
        let reason = v.stop.unwrap_or_default();
        assert!(
            reason.contains("/out"),
            "the reason names the directory: {reason}"
        );
        assert!(reason.contains("--min-free-disk"), "and the flag: {reason}");
    }

    #[test]
    fn s_recovery_is_reported_once() {
        let mut w = watch(Floor::Warn(GIB), &["/a"]);
        let _ = check_all(&mut w, MIB);
        let back = check_all(&mut w, 2 * GIB);
        assert_eq!(
            back,
            vec![Event::Recovered {
                dir: "/a".into(),
                free: 2 * GIB,
                floor: GIB
            }],
            "the recovery is reported"
        );
        assert!(check_all(&mut w, 2 * GIB).is_empty(), "once");
    }

    #[test]
    fn s_watched_dirs_are_the_parents_of_the_outputs() -> Result<(), TestError> {
        let tmp = tempfile::tempdir()?;
        let a = tmp.path().join("a");
        let b = tmp.path().join("b");
        std::fs::create_dir(&a)?;
        std::fs::create_dir(&b)?;
        let got = watched_dirs(&[a.join("x.pcap"), b.join("audit.jsonl")]);
        assert_eq!(got, vec![a, b], "each output's directory, in order");
        Ok(())
    }

    #[test]
    fn s_a_real_directory_reads_its_free_space() -> Result<(), TestError> {
        let tmp = tempfile::tempdir()?;
        let mut w = DiskWatch::open(Floor::Warn(1), vec![tmp.path().to_path_buf()]);
        let mut seen = None;
        let events = w.check_with(&mut |x| {
            let r = probe_free(x);
            seen = Some(r.as_ref().map(|_| ()).map_err(ToString::to_string));
            r
        });
        assert_eq!(seen, Some(Ok(())), "fstatvfs reads a temp directory");
        assert!(
            events.is_empty(),
            "a temp directory has more than 1 byte free: {events:?}"
        );
        Ok(())
    }

    #[test]
    fn s_the_warning_names_the_dir_the_free_bytes_and_the_floor() {
        let v = verdict(&[Event::Low {
            dir: "/var/cap".into(),
            free: 1000,
            floor: GIB,
            stop: false,
        }]);
        assert_eq!(v.stop, None, "a warning floor does not stop");
        let (sev, line) = &v.lines[0];
        assert_eq!(*sev, Severity::Warn, "a crossing is a warning");
        assert!(line.contains("/var/cap"), "names the directory: {line}");
        assert!(line.contains("1000 bytes"), "names the free bytes: {line}");
        assert!(line.contains("1073741824 bytes"), "names the floor: {line}");
        assert!(
            line.contains("--min-free-disk"),
            "says how to change it: {line}"
        );
    }

    #[test]
    fn s_a_recovery_is_an_info_line() {
        let v = verdict(&[Event::Recovered {
            dir: "/a".into(),
            free: 2 * GIB,
            floor: GIB,
        }]);
        assert_eq!(v.lines.len(), 1, "one line");
        assert_eq!(v.lines[0].0, Severity::Info, "a recovery is info");
        assert!(
            v.lines[0].1.contains("/a"),
            "names the directory: {}",
            v.lines[0].1
        );
        assert_eq!(v.stop, None, "a recovery does not stop");
    }

    #[test]
    fn s_human_sizes_read_as_binary_units() {
        assert_eq!(human(100), "100 B", "bytes");
        assert_eq!(human(512 * MIB), "512.0 MiB", "MiB");
        assert_eq!(human(GIB + GIB / 2), "1.5 GiB", "GiB");
        assert_eq!(human(2 * TIB), "2.0 TiB", "TiB");
    }

    // --- failure -----------------------------------------------------------

    /// The refusal of `value`; a failed assertion naming what was accepted.
    fn refused(value: &str) -> String {
        let r = parse_size(value);
        assert!(r.is_err(), "{value:?} must be refused, was taken as {r:?}");
        r.err().unwrap_or_default()
    }

    #[test]
    fn f_parse_refuses_an_empty_value() {
        assert!(
            refused("").contains("empty"),
            "says it is empty: {}",
            refused("")
        );
    }

    #[test]
    fn f_parse_refuses_a_bare_non_zero_number() {
        let e = refused("500");
        assert!(e.contains("unit"), "asks for a unit: {e}");
    }

    #[test]
    fn f_parse_refuses_a_negative_number() {
        let e = refused("-1G");
        assert!(e.contains("whole number"), "says what it takes: {e}");
    }

    #[test]
    fn f_parse_refuses_decimal_units_as_ambiguous() {
        for v in ["2GB", "500MB", "1TB", "64kB"] {
            let e = refused(v);
            assert!(e.contains("1024"), "{v}: says the units are binary: {e}");
        }
    }

    #[test]
    fn f_parse_refuses_a_fraction() {
        let e = refused("1.5G");
        assert!(
            e.contains("whole number"),
            "says it takes a whole number: {e}"
        );
    }

    #[test]
    fn f_parse_refuses_an_unknown_unit() {
        let e = refused("2X");
        assert!(e.contains("'X'"), "names the unit: {e}");
    }

    #[test]
    fn f_parse_refuses_a_value_that_overflows() {
        let e = refused("16777216T");
        assert!(e.contains("too large"), "says it is too large: {e}");
        let e = refused("99999999999999999999999G");
        assert!(e.contains("too large"), "a number past u64 too: {e}");
    }

    #[test]
    fn f_parse_refuses_whitespace() {
        for v in [" 2G", "2G ", "2 G", " "] {
            let _ = refused(v);
        }
    }

    #[test]
    fn f_parse_refuses_a_unit_alone() {
        let e = refused("G");
        assert!(e.contains("whole number"), "a unit is not a number: {e}");
    }

    #[test]
    fn f_parse_refuses_a_plus_sign() {
        let e = refused("+2G");
        assert!(e.contains("whole number"), "a sign is not a digit: {e}");
    }

    #[test]
    fn f_an_unreadable_dir_is_reported_once() {
        let mut w = watch(Floor::Warn(GIB), &["/a"]);
        let mut fail = |_: &Watched| Err(std::io::Error::other("no such thing"));
        let first = w.check_with(&mut fail);
        assert_eq!(
            first,
            vec![Event::Unreadable {
                dir: "/a".into(),
                error: "no such thing".into()
            }],
            "a failed reading is reported"
        );
        assert!(w.check_with(&mut fail).is_empty(), "once");
    }

    #[test]
    fn f_a_dir_that_does_not_open_is_unreadable() -> Result<(), TestError> {
        let tmp = tempfile::tempdir()?;
        let gone = tmp.path().join("not-there");
        let mut w = DiskWatch::open(Floor::Warn(1), vec![gone.clone()]);
        let events = w.check();
        assert!(
            matches!(&events[..], [Event::Unreadable { dir, .. }] if *dir == gone),
            "a directory that did not open is reported: {events:?}"
        );
        Ok(())
    }

    #[test]
    fn f_an_unreadable_dir_warns_and_does_not_stop() {
        let v = verdict(&[Event::Unreadable {
            dir: "/a".into(),
            error: "denied".into(),
        }]);
        assert_eq!(v.stop, None, "a stop needs a reading under the floor");
        assert_eq!(v.lines[0].0, Severity::Warn, "warned");
        assert!(
            v.lines[0].1.contains("denied"),
            "with the reason: {}",
            v.lines[0].1
        );
        assert!(
            v.lines[0].1.contains("/a"),
            "and the directory: {}",
            v.lines[0].1
        );
    }

    // --- edge --------------------------------------------------------------

    #[test]
    fn e_zero_turns_the_check_off() {
        assert_eq!(Floor::from_flag(Some(0)), Floor::Off, "0 is off");
        let mut w = watch(Floor::Off, &["/a"]);
        assert!(w.is_idle(), "an off floor has nothing to do");
        let mut probed = 0;
        let events = w.check_with(&mut |_| {
            probed += 1;
            Ok(0)
        });
        assert!(events.is_empty(), "off: no event at 0 bytes free");
        assert_eq!(probed, 0, "off: nothing is read");
    }

    #[test]
    fn e_no_output_dir_is_idle() {
        let w = watch(Floor::Stop(GIB), &[]);
        assert!(
            w.is_idle(),
            "a run that writes nothing has nothing to watch"
        );
        let w = watch(Floor::Stop(GIB), &["/a"]);
        assert!(!w.is_idle(), "a run that writes somewhere is watched");
    }

    #[test]
    fn e_free_exactly_at_the_floor_is_not_below() {
        let mut w = watch(Floor::Stop(GIB), &["/a"]);
        assert!(
            check_all(&mut w, GIB).is_empty(),
            "at the floor is not under it"
        );
    }

    #[test]
    fn e_one_byte_under_the_floor_is_below() {
        let mut w = watch(Floor::Stop(GIB), &["/a"]);
        assert_eq!(
            check_all(&mut w, GIB - 1).len(),
            1,
            "one byte under is under"
        );
    }

    #[test]
    fn e_recovery_needs_the_margin() {
        assert_eq!(recovery_level(1000), 1100, "a tenth above the floor");
        assert_eq!(recovery_level(u64::MAX), u64::MAX, "saturates");
        let mut w = watch(Floor::Warn(1000), &["/a"]);
        let _ = check_all(&mut w, 999);
        assert!(
            check_all(&mut w, 1000).is_empty(),
            "at the floor: not yet recovered"
        );
        assert!(
            check_all(&mut w, 1099).is_empty(),
            "under the margin: not yet"
        );
        assert_eq!(check_all(&mut w, 1100).len(), 1, "at the margin: recovered");
    }

    #[test]
    fn e_hovering_at_the_floor_warns_once() {
        let mut w = watch(Floor::Warn(1000), &["/a"]);
        let mut events = 0;
        for free in [999, 1001, 999, 1050, 998, 1099, 990] {
            events += check_all(&mut w, free).len();
        }
        assert_eq!(events, 1, "one warning while it hovers inside the margin");
    }

    #[test]
    fn e_two_outputs_in_one_dir_watch_it_once() -> Result<(), TestError> {
        let tmp = tempfile::tempdir()?;
        let got = watched_dirs(&[tmp.path().join("a.pcap"), tmp.path().join("b.jsonl")]);
        assert_eq!(got, vec![tmp.path().to_path_buf()], "one directory, once");
        Ok(())
    }

    #[test]
    fn e_standard_output_is_not_a_directory() {
        let got = watched_dirs(&["-", ""]);
        assert!(
            got.is_empty(),
            "`-` and an empty value name no directory: {got:?}"
        );
    }

    #[test]
    fn e_a_bare_file_name_watches_the_current_dir() {
        let got = watched_dirs(&["capture.pcap"]);
        assert_eq!(
            got,
            vec![PathBuf::from(".")],
            "a bare name is in the current directory"
        );
    }

    #[test]
    fn e_a_missing_dir_watches_its_nearest_existing_ancestor() -> Result<(), TestError> {
        let tmp = tempfile::tempdir()?;
        let deep = tmp.path().join("x").join("y");
        assert_eq!(
            watched_dirs(&[deep.join("out.pcap")]),
            Vec::<PathBuf>::new(),
            "an output file in a missing directory is not watched: its open refuses it"
        );
        assert_eq!(
            watched_rule_dirs(std::slice::from_ref(&deep)),
            vec![tmp.path().to_path_buf()],
            "a rule directory not made yet"
        );
        assert_eq!(
            watched_rule_dirs(&[tmp.path()]),
            vec![tmp.path().to_path_buf()],
            "a rule directory that exists is itself"
        );
        Ok(())
    }

    #[test]
    fn e_the_largest_value_that_fits() {
        assert_eq!(
            parse_size("16777215T"),
            Ok(16_777_215 * TIB),
            "the largest whole TiB under 16 EiB"
        );
    }

    #[test]
    fn e_free_bytes_saturate() {
        assert_eq!(free_bytes(10, 4096), 40960, "blocks times size");
        assert_eq!(free_bytes(u64::MAX, 4096), u64::MAX, "saturates");
        assert_eq!(free_bytes(0, 4096), 0, "a full disk");
    }

    #[test]
    fn e_each_dir_has_its_own_crossing_state() {
        let mut w = watch(Floor::Warn(1000), &["/a", "/b"]);
        let mut readings = |a: u64, b: u64| {
            w.check_with(&mut |x: &Watched| Ok(if x.dir == Path::new("/a") { a } else { b }))
        };
        assert_eq!(readings(10, 5000).len(), 1, "only /a crosses");
        let both = readings(10, 10);
        assert_eq!(
            both,
            vec![Event::Low {
                dir: "/b".into(),
                free: 10,
                floor: 1000,
                stop: false
            }],
            "then only /b, /a having been reported"
        );
    }

    #[test]
    fn e_a_failed_reading_then_a_good_one_reports_a_later_failure_again() {
        let mut w = watch(Floor::Warn(1000), &["/a"]);
        let fail = |_: &Watched| -> std::io::Result<u64> { Err(std::io::Error::other("e")) };
        assert_eq!(w.check_with(&mut { fail }).len(), 1, "first failure");
        assert!(
            check_all(&mut w, 5000).is_empty(),
            "a good reading says nothing"
        );
        assert_eq!(
            w.check_with(&mut { fail }).len(),
            1,
            "a new failure is said again"
        );
    }

    #[test]
    fn e_a_stop_names_only_the_first_crossing() {
        let v = verdict(&[
            Event::Low {
                dir: "/a".into(),
                free: 1,
                floor: 9,
                stop: true,
            },
            Event::Low {
                dir: "/b".into(),
                free: 2,
                floor: 9,
                stop: true,
            },
        ]);
        assert!(v.stop.is_some(), "a stop: {v:?}");
        let reason = v.stop.unwrap_or_default();
        assert!(reason.contains("/a"), "the first directory: {reason}");
        assert_eq!(v.lines.len(), 2, "both crossings are logged");
    }
}
