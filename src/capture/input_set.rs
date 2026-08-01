// SPDX-License-Identifier: MIT OR Apache-2.0

//! Resolve `-I` arguments into an ordered list of capture files.
//!
//! `-I` accepts a file, a directory, or a glob, and may be repeated. This
//! module turns whatever was given into the exact sequence of files to read.
//!
//! # Ordering is the hard part
//!
//! Files are ordered by their **first packet's timestamp**, never by name.
//!
//! That is not fussiness about tidy output. `tcpdump -C 100 -W 10` writes a
//! ring buffer — `tg.pcap0` through `tg.pcap9` — and then *wraps*, overwriting
//! the oldest file in place. A real captured set measured while writing this
//! ran `tg.pcap7`, `tg.pcap8`, `tg.pcap9`, `tg.pcap0` … `tg.pcap6` in time
//! order: the numeric suffix says where tcpdump was in its cycle, not when the
//! packets arrived.
//!
//! So neither lexicographic nor natural-numeric filename order reconstructs
//! that capture, and replaying it by name feeds sipnab thirty-five seconds of
//! traffic before the thirty-four seconds preceding it. Every timing
//! derivation assumes monotonic timestamps — post-dial delay, setup time,
//! retransmission detection, and the RFC 3261 Timer B/C/H bounds in the
//! signalling diagnosis — so a mis-ordered set does not merely look odd, it
//! produces confident wrong findings.
//!
//! # Identifying a capture file
//!
//! By **opening it**, not by its extension. Two reasons, both from real files:
//!
//! - `tg.pcap0` has the extension `pcap0`. So do the other nine. An extension
//!   allowlist misses every file tcpdump's ring buffer produces.
//! - `SIP_CALL_RTP_G711` has no extension at all and is a perfectly good pcap.
//!
//! Since the first packet has to be read anyway to order the set, the open
//! doubles as the test, and it accepts exactly what libpcap accepts rather
//! than what this module remembered to list.
//!
//! # Named files fail; discovered files are skipped
//!
//! A file named directly on the command line that cannot be read is an error:
//! the operator asked for that file. A file *discovered* by expanding a
//! directory or glob is skipped with a warning, because directories contain
//! other things — a README, a NetMon capture libpcap cannot open, a partial
//! file still being written. Aborting a 900 MB analysis over one stray file in
//! the directory would be the wrong call, and silently ignoring an explicitly
//! named one would be worse.
//!
//! "With a warning" is load-bearing and applies to every way a candidate can
//! disappear, not just to a file that fails to open: a directory entry that
//! cannot be read, a glob match that cannot be stat'd, and a symlink with no
//! target are each named in a `Skipping ...` line. A file that vanishes from
//! the set silently is indistinguishable from traffic that was never captured.
//!
//! # `--input-name` and the shape of `-I`
//!
//! The pattern filters every **discovered** path — from a directory walk and
//! from a glob alike. Against a file named directly it is a contradiction with
//! no silent resolution available (dropping the file loses a capture the
//! operator named; ignoring the pattern leaves them believing they filtered),
//! so that combination is refused with an error.

use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::path::{Path, PathBuf};

/// How to expand a `-I` argument that names a directory.
#[derive(Debug, Clone, Default)]
pub struct ResolveOptions {
    /// Descend into subdirectories. Off by default.
    ///
    /// Both defaults are wrong for somebody, so this picks the one whose
    /// failure is loud. Recursing by default can silently pull in an
    /// `archive/` or `old/` subdirectory and analyse several times the traffic
    /// the operator pointed at, and nothing in the output would say so.
    /// Refusing to recurse produces an obviously short answer instead.
    pub recursive: bool,
    /// Filename pattern applied to directory contents, e.g. `tg.pcap[0-4]`.
    ///
    /// Matched against the file name alone, so it behaves the same at every
    /// depth when [`Self::recursive`] is set.
    pub name_glob: Option<String>,
}

/// One resolved capture file and the timestamp it starts at.
#[derive(Debug, Clone)]
pub struct ResolvedInput {
    /// Path to the capture file.
    pub path: PathBuf,
    /// Epoch seconds of the first packet, used for ordering.
    ///
    /// `None` for a file that opened but holds no packets. Those sort last:
    /// an empty file has no position in a timeline, and putting it first would
    /// let it define the start of the capture window.
    pub first_packet: Option<f64>,
}

/// Expand and order `-I` arguments into the files to read.
///
/// # Errors
///
/// When a spec names nothing, when an explicitly named file cannot be opened
/// as a capture, when a glob pattern is malformed, or when the whole set
/// resolves to no readable file.
pub fn resolve(specs: &[String], opts: &ResolveOptions) -> Result<Vec<ResolvedInput>> {
    if specs.is_empty() {
        bail!("no capture input given");
    }

    // Compiled once, and here rather than inside the directory walk, so a
    // malformed pattern fails the run whatever shape the -I argument has
    // instead of only when a directory happens to be expanded.
    let name_pat = opts
        .name_glob
        .as_deref()
        .map(|g| glob::Pattern::new(g).with_context(|| format!("bad filename pattern '{g}'")))
        .transpose()?;

    // (path, explicitly named). Named files must fail loudly; discovered ones
    // are skipped. A path reached both ways counts as named — the stricter
    // treatment is the one the operator asked for.
    let mut candidates: Vec<(PathBuf, bool)> = Vec::new();
    // Canonical path -> index into `candidates`, so the upgrade to "explicitly
    // named" is looked up by the SAME key the dedup uses. Searching
    // `candidates` by raw `PathBuf` missed whenever a file was reached under
    // two spellings — `-I dir` yielding `dir/a.pcap` and `-I dir/./a.pcap` —
    // and the file the operator named was then skipped with a warning rather
    // than failing the run, the exact inversion of the contract above.
    let mut seen: BTreeMap<PathBuf, usize> = BTreeMap::new();

    for spec in specs {
        let found = expand_one(spec, opts, name_pat.as_ref())?;
        for (path, explicit) in found {
            let key = path.canonicalize().unwrap_or_else(|_| path.clone());
            match seen.entry(key) {
                Entry::Vacant(slot) => {
                    slot.insert(candidates.len());
                    candidates.push((path, explicit));
                }
                Entry::Occupied(slot) => {
                    if explicit {
                        candidates[*slot.get()].1 = true;
                    }
                }
            }
        }
    }

    let mut resolved: Vec<ResolvedInput> = Vec::new();
    for (path, explicit) in candidates {
        match first_packet_time(&path) {
            Ok(first_packet) => resolved.push(ResolvedInput { path, first_packet }),
            Err(e) if explicit => {
                return Err(e).with_context(|| {
                    format!("cannot read capture '{}' named with -I", path.display())
                });
            }
            Err(e) => {
                tracing::warn!(
                    "Skipping '{}': not a readable capture ({e:#})",
                    path.display()
                );
            }
        }
    }

    if resolved.is_empty() {
        bail!(
            "no readable capture files in {}",
            specs
                .iter()
                .map(|s| format!("'{s}'"))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    // Chronological, with the path as a tie-break so a set of files sharing a
    // first-packet timestamp still resolves to one deterministic order rather
    // than whatever the directory happened to yield.
    resolved.sort_by(|a, b| {
        match (a.first_packet, b.first_packet) {
            (Some(x), Some(y)) => x.partial_cmp(&y).unwrap_or(std::cmp::Ordering::Equal),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        }
        .then_with(|| a.path.cmp(&b.path))
    });

    warn_on_overlap(&resolved);
    Ok(resolved)
}

/// Expand one `-I` argument. Returns `(path, explicitly_named)` pairs.
fn expand_one(
    spec: &str,
    opts: &ResolveOptions,
    name_pat: Option<&glob::Pattern>,
) -> Result<Vec<(PathBuf, bool)>> {
    // A glob is identified by its metacharacters. Checked before the
    // filesystem, because a path containing them may also happen to exist.
    if spec.contains('*') || spec.contains('?') || spec.contains('[') {
        let mut out = Vec::new();
        for entry in glob::glob(spec).with_context(|| format!("bad glob pattern '{spec}'"))? {
            // A glob match that cannot be stat'd — most often a component of
            // its own path is not readable. Dropping it left the operator with
            // a short set and no reason for it.
            let path = match entry {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(
                        "Skipping '{}' matched by '{spec}': {}",
                        e.path().display(),
                        e.error()
                    );
                    continue;
                }
            };
            // A glob over a tree of per-host subdirectories matches the
            // DIRECTORIES: `-I '/caps/*'` used to keep only `path.is_file()`
            // and so resolved to nothing while saying nothing. The directory
            // was discovered rather than named, so one that yields no capture
            // is a warning and not the end of the run.
            if path.is_dir() {
                match expand_dir(&path, opts, name_pat) {
                    Ok(found) => out.extend(found),
                    Err(e) => tracing::warn!(
                        "Skipping directory '{}' matched by '{spec}': {e:#}",
                        path.display()
                    ),
                }
                continue;
            }
            if !path.is_file() {
                tracing::warn!(
                    "Skipping '{}' matched by '{spec}': not a file or a directory",
                    path.display()
                );
                continue;
            }
            if let Some(pat) = name_pat
                && !name_matches(pat, &path)
            {
                continue;
            }
            out.push((path, false));
        }
        if out.is_empty() {
            match opts.name_glob.as_deref() {
                Some(g) => bail!("glob '{spec}' matched no files named '{g}'"),
                None => bail!("glob '{spec}' matched no files"),
            }
        }
        return Ok(out);
    }

    let path = PathBuf::from(spec);
    if path.is_dir() {
        return expand_dir(&path, opts, name_pat);
    }
    if path.exists() {
        // A directly named file is not filtered — see the module docs. Saying
        // so is the point: applying the pattern would drop a capture the
        // operator named, and ignoring it would leave them believing they had
        // filtered something.
        if let Some(pat) = name_pat
            && !name_matches(pat, &path)
        {
            bail!(
                "-I '{spec}' names a file directly, which --input-name '{pat}' does not \
                 match; --input-name filters only files found in a directory or by a \
                 glob. Drop one of the two."
            );
        }
        return Ok(vec![(path, true)]);
    }
    bail!("'{spec}' does not exist")
}

/// Whether a discovered path satisfies the `--input-name` pattern.
///
/// Matched against the file name alone, so it behaves the same at every depth
/// of a recursive walk and for every shape of `-I`.
fn name_matches(pat: &glob::Pattern, path: &Path) -> bool {
    path.file_name()
        .is_some_and(|n| pat.matches(&n.to_string_lossy()))
}

/// List the files in a directory, honouring recursion and the name glob.
fn expand_dir(
    dir: &Path,
    opts: &ResolveOptions,
    name_pat: Option<&glob::Pattern>,
) -> Result<Vec<(PathBuf, bool)>> {
    // walkdir rather than a hand-rolled read_dir recursion: it carries the
    // symlink-loop protection, which a directory of captures can genuinely
    // hit when someone symlinks `latest -> .`.
    let walker = walkdir::WalkDir::new(dir)
        .max_depth(if opts.recursive { usize::MAX } else { 1 })
        .follow_links(false);

    let mut out = Vec::new();
    for entry in walker {
        // An unreadable subdirectory yields an error here, not fewer files.
        // Discarding it produced a short set with nothing to explain it.
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                let at = e.path().unwrap_or(dir).display().to_string();
                tracing::warn!("Skipping '{at}': cannot read directory entry ({e})");
                continue;
            }
        };

        // Classify by the TARGET, not by the link. `follow_links(false)` is
        // kept — it is the loop protection above — but it makes walkdir report
        // a symlink's OWN type, so `entry.file_type().is_file()` is false for a
        // symlinked capture and it vanished from the set. Capture directories
        // commonly symlink to storage. `Path::is_file` follows, which is also
        // what the glob branch has always used.
        let path = entry.path();
        if !path.is_file() {
            report_unusable_entry(&entry, opts);
            continue;
        }
        if let Some(pat) = name_pat
            && !name_matches(pat, path)
        {
            continue;
        }
        out.push((path.to_path_buf(), false));
    }

    if out.is_empty() {
        match opts.name_glob.as_deref() {
            Some(g) => bail!("no files matching '{g}' in '{}'", dir.display()),
            None => bail!("no files in '{}'", dir.display()),
        }
    }
    Ok(out)
}

/// Warn about a walked entry that is not a file, when its absence is a loss.
///
/// A plain subdirectory is not one: reaching into it is what `--recursive`
/// decides, and the walk already reflects that choice. A **broken** symlink and
/// a symlinked subdirectory under `--recursive` are, because in both cases
/// something that looks like part of the capture set contributes nothing.
fn report_unusable_entry(entry: &walkdir::DirEntry, opts: &ResolveOptions) {
    if entry.depth() == 0 || !entry.path_is_symlink() {
        return;
    }
    let path = entry.path();
    if !path.exists() {
        tracing::warn!("Skipping '{}': symlink with no target", path.display());
    } else if opts.recursive && path.is_dir() {
        tracing::warn!(
            "Skipping '{}': symlinked directory, not descended (following it \
             risks a loop); name it with its own -I to read it",
            path.display()
        );
    }
}

/// Epoch seconds of the first packet, or `None` for a capture with no packets.
///
/// Doubles as the "is this a capture file" test — see the module docs. Uses
/// the same opener as the read path, so gzip members are handled identically
/// and a mixed compressed/uncompressed set needs no special case here.
fn first_packet_time(path: &Path) -> Result<Option<f64>> {
    let (mut cap, _gz_guard) = super::file::open_offline(path)?;
    match cap.next_packet() {
        Ok(pkt) => {
            let ts = pkt.header.ts;
            #[allow(clippy::cast_precision_loss)]
            Ok(Some(ts.tv_sec as f64 + ts.tv_usec as f64 / 1_000_000.0))
        }
        // A capture that opens but yields nothing is legitimate — a rotated
        // file that never received a packet. It is not an error.
        Err(pcap::Error::NoMorePackets) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Warn when consecutive files overlap in time.
///
/// A clean ring buffer hands over cleanly: each file starts after the previous
/// one ends. Overlap means the set is not one sequence — most often two
/// capture runs, or the same traffic collected on two interfaces, mixed into
/// one directory. sipnab will still read it, and the result will double-count
/// packets that appear twice, so this says so rather than letting the totals
/// quietly disagree with reality.
fn warn_on_overlap(resolved: &[ResolvedInput]) {
    for (i, j) in same_instant_pairs(resolved) {
        tracing::warn!(
            "'{}' and '{}' start at the same instant — if these are two captures of \
             the same traffic, packets present in both are counted twice",
            resolved[i].path.display(),
            resolved[j].path.display()
        );
    }
}

/// How close two first-packet times have to be to count as the same instant.
///
/// One millisecond, and the two bounds it sits between are far away in both
/// directions. Below it: two captures of the same traffic — a second `tcpdump`
/// run, or the same call collected on two interfaces — see each packet within
/// the host's timestamping jitter of each other, microseconds apart, never on
/// the same bit pattern. Above it: consecutive members of a real `tcpdump -C -W`
/// ring buffer are seconds to minutes apart, so no clean handover comes close.
///
/// Explicitly **not** `f64::EPSILON`, which was the original test. `f64::EPSILON`
/// is 2.2e-16 — the gap between 1.0 and its successor — while these are epoch
/// seconds of magnitude 1.5e9, where one ULP is already ~2.4e-7. As an absolute
/// tolerance it degenerated to exact bit equality, and the warning below had
/// therefore never fired.
const SAME_INSTANT_SECS: f64 = 1e-3;

/// Indices of consecutive files whose first packets fall at the same instant.
///
/// Split out of [`warn_on_overlap`] so the comparison itself is testable.
///
/// This is the half of "overlap" that can be had without reading anything: a
/// file's END time is not known until its last packet has been read, so the
/// previous-end-against-next-start test lives in
/// [`super::file::capture_files`], where the packets stream past anyway. Two
/// files that START together is the shape the duplicated-capture case takes,
/// and catching it here reports it before the analysis rather than after.
fn same_instant_pairs(resolved: &[ResolvedInput]) -> Vec<(usize, usize)> {
    let starts: Vec<(usize, f64)> = resolved
        .iter()
        .enumerate()
        .filter_map(|(i, r)| r.first_packet.map(|t| (i, t)))
        .collect();
    let mut pairs = Vec::new();
    for pair in starts.windows(2) {
        let (i, a) = pair[0];
        let (j, b) = pair[1];
        if (b - a).abs() < SAME_INSTANT_SECS {
            pairs.push((i, j));
        }
    }
    pairs
}

#[cfg(test)]
mod tests {
    use super::*;

    fn samples() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/pcap-samples")
    }

    fn spec(p: &Path) -> String {
        p.to_string_lossy().into_owned()
    }

    /// A single file still resolves to exactly itself. This is the
    /// overwhelmingly common case and must not change shape.
    #[test]
    fn a_single_file_resolves_to_itself() {
        let f = samples().join("sip-rtp-g711.pcap");
        let out = resolve(&[spec(&f)], &ResolveOptions::default()).expect("resolve");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].path, f);
        assert!(out[0].first_packet.is_some());
    }

    /// Extension-free and odd-suffix files are captures too, which is why the
    /// probe opens the file instead of reading its name.
    #[test]
    fn a_capture_without_a_pcap_extension_is_accepted() {
        let f = samples().join("SIP_CALL_RTP_G711");
        assert_eq!(f.extension(), None, "fixture must have no extension");
        let out = resolve(&[spec(&f)], &ResolveOptions::default()).expect("resolve");
        assert_eq!(out.len(), 1);
    }

    /// Repeating -I builds one ordered set.
    #[test]
    fn repeated_specs_combine() {
        let a = samples().join("sip-rtp-g711.pcap");
        let b = samples().join("sip-rtp-g729a.pcap");
        let out = resolve(&[spec(&a), spec(&b)], &ResolveOptions::default()).expect("resolve");
        assert_eq!(out.len(), 2);
    }

    /// The same file named twice is read once. Reading it twice would double
    /// every dialog and stream count in the report.
    #[test]
    fn the_same_file_twice_is_read_once() {
        let a = samples().join("sip-rtp-g711.pcap");
        let out = resolve(&[spec(&a), spec(&a)], &ResolveOptions::default()).expect("resolve");
        assert_eq!(out.len(), 1, "duplicates must collapse, got {out:?}");
    }

    /// A glob expands internally, because the shell does not when the pattern
    /// is quoted — and in an MCP config or an SSH command line there is no
    /// shell at all.
    #[test]
    fn a_glob_expands_without_a_shell() {
        let pattern = format!("{}/sip-rtp-*.pcap", samples().display());
        let out = resolve(&[pattern], &ResolveOptions::default()).expect("resolve");
        assert!(
            out.len() >= 3,
            "sip-rtp-g711/g722/g729a at least, got {}",
            out.len()
        );
    }

    /// A directory resolves to the captures inside it, skipping whatever else
    /// is there — including the NetMon file libpcap cannot open.
    #[test]
    fn a_directory_resolves_to_its_captures() {
        let out = resolve(&[spec(&samples())], &ResolveOptions::default()).expect("resolve");
        assert!(
            out.len() > 20,
            "sample dir has many captures, got {}",
            out.len()
        );
        assert!(
            !out.iter().any(|r| r.path.ends_with("c07-sip-r2.cap")),
            "the NetMon capture cannot be opened by libpcap and must be skipped, \
             not carried into the read set"
        );
    }

    /// Naming that same unreadable file directly is an error, because the
    /// operator asked for it specifically.
    #[test]
    fn an_explicitly_named_unreadable_file_is_an_error() {
        let f = samples().join("c07-sip-r2.cap");
        let err = resolve(&[spec(&f)], &ResolveOptions::default())
            .expect_err("NetMon must not resolve silently");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("cannot read capture"),
            "the error must name the file and say it was requested: {msg}"
        );
    }

    /// The name glob narrows a directory.
    #[test]
    fn a_name_glob_narrows_a_directory() {
        let opts = ResolveOptions {
            name_glob: Some("sip-rtp-g7*.pcap".to_string()),
            ..Default::default()
        };
        let out = resolve(&[spec(&samples())], &opts).expect("resolve");
        assert!(!out.is_empty());
        assert!(
            out.iter().all(|r| r
                .path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("sip-rtp-g7")),
            "every match must satisfy the pattern: {out:?}"
        );
    }

    /// Recursion is off unless asked for.
    #[test]
    fn recursion_is_opt_in() {
        let root = tempfile::tempdir().expect("tempdir");
        let sub = root.path().join("archive");
        std::fs::create_dir(&sub).expect("mkdir");
        std::fs::copy(
            samples().join("sip-rtp-g711.pcap"),
            root.path().join("top.pcap"),
        )
        .expect("copy");
        std::fs::copy(
            samples().join("sip-rtp-g729a.pcap"),
            sub.join("buried.pcap"),
        )
        .expect("copy");

        let shallow = resolve(&[spec(root.path())], &ResolveOptions::default()).expect("resolve");
        assert_eq!(
            shallow.len(),
            1,
            "the subdirectory must stay out unless asked for: {shallow:?}"
        );

        let deep = resolve(
            &[spec(root.path())],
            &ResolveOptions {
                recursive: true,
                ..Default::default()
            },
        )
        .expect("resolve");
        assert_eq!(deep.len(), 2, "recursive must reach the subdirectory");
    }

    /// Ordering follows the packets, not the names. Built to mirror the
    /// wrapped ring buffer that motivated this: the file whose name sorts
    /// first holds the LATER traffic.
    #[test]
    fn ordering_is_chronological_not_alphabetical() {
        let root = tempfile::tempdir().expect("tempdir");
        // sip-rtp-g711.pcap is from 2016; register-invite-reinvite-bye is not.
        // Whichever is older, name them so that alphabetical order is the
        // OPPOSITE of chronological, then assert resolve() ignores the names.
        let a = samples().join("sip-rtp-g711.pcap");
        let b = samples().join("sip-register.pcap");
        let ta = first_packet_time(&a).expect("open").expect("packets");
        let tb = first_packet_time(&b).expect("open").expect("packets");
        let (older, newer) = if ta < tb { (&a, &b) } else { (&b, &a) };

        // "zzz" holds the older traffic, "aaa" the newer.
        let zzz = root.path().join("zzz-first-in-time.pcap");
        let aaa = root.path().join("aaa-second-in-time.pcap");
        std::fs::copy(older, &zzz).expect("copy");
        std::fs::copy(newer, &aaa).expect("copy");

        let out = resolve(&[spec(root.path())], &ResolveOptions::default()).expect("resolve");
        assert_eq!(out.len(), 2);
        assert_eq!(
            out[0].path, zzz,
            "the file holding the EARLIER packets must be read first even though \
             its name sorts last; got {out:?}"
        );
    }

    /// A gzip member sits in the same set as a plain one, ordered by content.
    #[test]
    fn compressed_and_uncompressed_mix_in_one_set() {
        use std::io::Write;
        let root = tempfile::tempdir().expect("tempdir");

        std::fs::copy(
            samples().join("sip-rtp-g711.pcap"),
            root.path().join("plain.pcap"),
        )
        .expect("copy");

        let raw = std::fs::read(samples().join("sip-register.pcap")).expect("read");
        let gz_path = root.path().join("squeezed.pcap.gz");
        let mut enc = flate2::write::GzEncoder::new(
            std::fs::File::create(&gz_path).expect("create"),
            flate2::Compression::fast(),
        );
        enc.write_all(&raw).expect("compress");
        enc.finish().expect("finish");

        let out = resolve(&[spec(root.path())], &ResolveOptions::default()).expect("resolve");
        assert_eq!(out.len(), 2, "both members must resolve: {out:?}");
        assert!(
            out.iter().all(|r| r.first_packet.is_some()),
            "the gzip member must be probed through the decompressor, not skipped: {out:?}"
        );
    }

    /// A glob matching nothing is an error rather than an empty analysis.
    #[test]
    fn a_glob_matching_nothing_is_an_error() {
        let pattern = format!("{}/definitely-no-such-*.pcap", samples().display());
        let err = resolve(&[pattern], &ResolveOptions::default()).expect_err("must fail");
        assert!(format!("{err:#}").contains("matched no files"));
    }

    /// Resolve a real capture directory named by `SIPNAB_CORPUS`.
    ///
    /// Skipped unless the variable is set, because the corpus this was built
    /// against is ~921 MB of real traffic that cannot live in the repository.
    /// It is kept as a test rather than a one-off script because the case it
    /// covers is the one no synthetic fixture reproduces convincingly: a
    /// `tcpdump -C 100 -W 10` ring buffer that has **wrapped**, where
    /// `tg.pcap7` holds older packets than `tg.pcap0`.
    ///
    /// Run with:
    /// `SIPNAB_CORPUS=/path/to/pcaps cargo test --features full corpus`
    #[test]
    fn corpus_directory_resolves_in_timestamp_order() {
        let Ok(dir) = std::env::var("SIPNAB_CORPUS") else {
            eprintln!("SIPNAB_CORPUS not set — skipping");
            return;
        };
        let out = resolve(std::slice::from_ref(&dir), &ResolveOptions::default())
            .unwrap_or_else(|e| panic!("resolve '{dir}': {e:#}"));
        assert!(
            out.len() > 1,
            "corpus needs several files, got {}",
            out.len()
        );

        // The ordering contract, stated as the property rather than a fixed
        // sequence: every file starts at or after the one before it.
        for pair in out.windows(2) {
            let (a, b) = (&pair[0], &pair[1]);
            if let (Some(ta), Some(tb)) = (a.first_packet, b.first_packet) {
                assert!(
                    ta <= tb,
                    "out of order: '{}' starts at {ta} but follows '{}' at {tb}",
                    b.path.display(),
                    a.path.display()
                );
            }
        }

        // And the reason it matters: if the set were ordered by name it would
        // be wrong. Report that rather than silently passing on a tidy corpus.
        let by_name: Vec<_> = {
            let mut v = out.clone();
            v.sort_by(|a, b| a.path.cmp(&b.path));
            v
        };
        let name_order_differs = by_name
            .iter()
            .zip(out.iter())
            .any(|(a, b)| a.path != b.path);
        eprintln!(
            "corpus: {} files, filename order {} chronological order",
            out.len(),
            if name_order_differs {
                "DIFFERS from"
            } else {
                "matches"
            }
        );
    }

    /// A capture reached through a symlink inside a directory must be read.
    ///
    /// Capture directories commonly symlink to storage. `follow_links(false)`
    /// keeps the symlink-loop protection, but it also makes walkdir report the
    /// LINK's own type, so classifying with `entry.file_type().is_file()`
    /// dropped every symlinked capture with nothing said. The glob branch has
    /// always classified with `path.is_file()`, which follows; the two must
    /// agree.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_capture_in_a_directory_is_not_dropped() {
        let store = tempfile::tempdir().expect("tempdir");
        let view = tempfile::tempdir().expect("tempdir");
        let real = store.path().join("real.pcap");
        std::fs::copy(samples().join("sip-rtp-g711.pcap"), &real).expect("copy");
        std::os::unix::fs::symlink(&real, view.path().join("link.pcap")).expect("symlink");

        let out = resolve(&[spec(view.path())], &ResolveOptions::default()).expect("resolve");
        assert_eq!(
            out.len(),
            1,
            "a symlinked capture is a capture; it must not vanish because \
             walkdir reported the link's own type: {out:?}"
        );
    }

    /// The same, one level up: `-I` given a symlink that IS the capture
    /// directory.
    #[cfg(unix)]
    #[test]
    fn a_capture_directory_reached_through_a_symlink_resolves() {
        let store = tempfile::tempdir().expect("tempdir");
        let outer = tempfile::tempdir().expect("tempdir");
        std::fs::copy(
            samples().join("sip-rtp-g711.pcap"),
            store.path().join("real.pcap"),
        )
        .expect("copy");
        let link = outer.path().join("latest");
        std::os::unix::fs::symlink(store.path(), &link).expect("symlink");

        let out = resolve(&[spec(&link)], &ResolveOptions::default()).expect("resolve");
        assert_eq!(
            out.len(),
            1,
            "'-I latest' where latest -> /storage: {out:?}"
        );
    }

    /// An explicitly named unreadable file stays an error even when the same
    /// file was already reached by expanding a directory under a different
    /// spelling.
    ///
    /// The dedup set is keyed on the CANONICAL path; the explicit-flag upgrade
    /// used to search the candidate list by raw `PathBuf`. Two spellings of one
    /// file therefore deduped but failed to upgrade, and the file the operator
    /// named was skipped with a warning instead of failing the run — exactly
    /// backwards from the contract in the module docs.
    #[test]
    fn an_explicitly_named_file_reached_by_another_spelling_still_fails_loudly() {
        let root = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(root.path().join("sub")).expect("mkdir");
        std::fs::copy(
            samples().join("sip-rtp-g711.pcap"),
            root.path().join("good.pcap"),
        )
        .expect("copy");
        std::fs::copy(
            samples().join("c07-sip-r2.cap"),
            root.path().join("bad.cap"),
        )
        .expect("copy");

        // Same file, different spelling: `<root>/sub/../bad.cap` is not equal
        // to `<root>/bad.cap` as a `Path` (`..` is a component), but both
        // canonicalize to the same file.
        let spelled = root.path().join("sub").join("..").join("bad.cap");
        assert_ne!(
            spelled.as_path(),
            root.path().join("bad.cap").as_path(),
            "the two spellings must differ as Paths or this test proves nothing"
        );

        let err = resolve(
            &[spec(root.path()), spec(&spelled)],
            &ResolveOptions::default(),
        )
        .expect_err("an explicitly named unreadable capture must fail the run");
        assert!(
            format!("{err:#}").contains("cannot read capture"),
            "got {err:#}"
        );
    }

    /// Two captures starting 100 microseconds apart are the same instant.
    ///
    /// The old test was `(b - a).abs() < f64::EPSILON` — an ABSOLUTE epsilon of
    /// 2.2e-16 applied to epoch seconds of magnitude 1.5e9, where one ULP is
    /// ~2.4e-7. It degenerated to exact bit equality, so the check never fired
    /// on anything a real pair of captures produces.
    #[test]
    fn two_captures_starting_microseconds_apart_are_the_same_instant() {
        let at = |t: f64| ResolvedInput {
            path: PathBuf::from(format!("cap-{t}")),
            first_packet: Some(t),
        };
        let set = [at(1_767_225_600.0), at(1_767_225_600.000_1)];
        assert_eq!(
            same_instant_pairs(&set),
            vec![(0, 1)],
            "two captures of the same traffic on two interfaces start within \
             the host's timestamping jitter, not on the same bit pattern"
        );
    }

    /// A ring buffer handing over cleanly is not an overlap.
    ///
    /// The tolerance has to be far below the gap between consecutive members of
    /// a real `tcpdump -C -W` set, which is seconds to minutes.
    #[test]
    fn a_clean_ring_buffer_handover_is_not_the_same_instant() {
        let at = |t: f64| ResolvedInput {
            path: PathBuf::from(format!("cap-{t}")),
            first_packet: Some(t),
        };
        let set = [
            at(1_767_225_600.0),
            at(1_767_225_635.5),
            at(1_767_225_671.25),
        ];
        assert!(
            same_instant_pairs(&set).is_empty(),
            "35 seconds apart is a handover, not a duplicate capture"
        );
    }

    /// `--input-name` applies to files discovered by a GLOB, not only to files
    /// discovered in a directory.
    ///
    /// It used to be read in exactly one place, `expand_dir`, so
    /// `-I '/caps/*.pcap' --input-name 'keep-*'` was accepted by clap and did
    /// nothing: the operator believes they filtered and did not.
    #[test]
    fn the_name_glob_applies_to_a_glob_spec() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::copy(
            samples().join("sip-rtp-g711.pcap"),
            dir.path().join("keep-me.pcap"),
        )
        .expect("copy");
        std::fs::copy(
            samples().join("sip-register.pcap"),
            dir.path().join("skip-me.pcap"),
        )
        .expect("copy");

        let opts = ResolveOptions {
            name_glob: Some("keep-*".to_string()),
            ..Default::default()
        };
        let out = resolve(&[format!("{}/*.pcap", dir.path().display())], &opts).expect("resolve");
        assert_eq!(out.len(), 1, "the filter must narrow a glob too: {out:?}");
        assert!(out[0].path.ends_with("keep-me.pcap"), "{out:?}");
    }

    /// `--input-name` against a directly named file is a contradiction, and it
    /// is reported rather than resolved either way.
    ///
    /// Dropping the file would lose a capture the operator named; ignoring the
    /// pattern would leave them believing they filtered. Both are silent, so
    /// neither is allowed.
    #[test]
    fn the_name_glob_cannot_silently_ignore_an_explicitly_named_file() {
        let f = samples().join("sip-rtp-g711.pcap");
        let opts = ResolveOptions {
            name_glob: Some("tg.pcap*".to_string()),
            ..Default::default()
        };
        let err = resolve(&[spec(&f)], &opts).expect_err("the combination must be refused");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("--input-name") && msg.contains("tg.pcap*"),
            "the error must name the pattern that does not match: {msg}"
        );
    }

    /// A glob matching DIRECTORIES expands them instead of dropping them.
    ///
    /// `-I '/caps/*'` over a tree of per-host subdirectories used to yield
    /// nothing and say nothing, because the glob branch kept only
    /// `path.is_file()`.
    #[test]
    fn a_glob_matching_directories_expands_them() {
        let root = tempfile::tempdir().expect("tempdir");
        for (sub, sample) in [
            ("host-a", "sip-rtp-g711.pcap"),
            ("host-b", "sip-register.pcap"),
        ] {
            let dir = root.path().join(sub);
            std::fs::create_dir(&dir).expect("mkdir");
            std::fs::copy(samples().join(sample), dir.join("cap.pcap")).expect("copy");
        }

        let out = resolve(
            &[format!("{}/*", root.path().display())],
            &ResolveOptions::default(),
        )
        .expect("a glob over per-host directories must resolve their captures");
        assert_eq!(out.len(), 2, "both subdirectories must contribute: {out:?}");
    }

    /// An unreadable subdirectory must not take the readable files with it.
    ///
    /// The walk used to `filter_map(Result::ok)`, so a permission-denied
    /// subdirectory yielded fewer files with nothing said. The files that ARE
    /// readable still resolve; the warning is asserted end to end in
    /// `tests/multi_input_test.rs`, where the operator would actually see it.
    #[cfg(unix)]
    #[test]
    fn an_unreadable_subdirectory_does_not_hide_the_readable_files() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().expect("tempdir");
        std::fs::copy(
            samples().join("sip-rtp-g711.pcap"),
            root.path().join("top.pcap"),
        )
        .expect("copy");
        let locked = root.path().join("locked");
        std::fs::create_dir(&locked).expect("mkdir");
        std::fs::copy(
            samples().join("sip-register.pcap"),
            locked.join("buried.pcap"),
        )
        .expect("copy");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).expect("chmod");

        let out = resolve(
            &[spec(root.path())],
            &ResolveOptions {
                recursive: true,
                ..Default::default()
            },
        );
        // Restore before asserting so a failure still leaves a removable dir.
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).expect("chmod");

        let out = out.expect("resolve");
        assert_eq!(
            out.len(),
            1,
            "the readable file must still resolve: {out:?}"
        );
    }

    /// A directory holding no capture at all is an error, not silence.
    #[test]
    fn a_directory_with_no_captures_is_an_error() {
        let root = tempfile::tempdir().expect("tempdir");
        std::fs::write(root.path().join("README.md"), "not a capture").expect("write");
        let err = resolve(&[spec(root.path())], &ResolveOptions::default()).expect_err("must fail");
        assert!(
            format!("{err:#}").contains("no readable capture"),
            "got {err:#}"
        );
    }
}
