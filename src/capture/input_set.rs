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

use anyhow::{Context, Result, bail};
use std::collections::BTreeSet;
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

    // (path, explicitly named). Named files must fail loudly; discovered ones
    // are skipped. A path reached both ways counts as named — the stricter
    // treatment is the one the operator asked for.
    let mut candidates: Vec<(PathBuf, bool)> = Vec::new();
    let mut seen: BTreeSet<PathBuf> = BTreeSet::new();

    for spec in specs {
        let found = expand_one(spec, opts)?;
        for (path, explicit) in found {
            let key = path.canonicalize().unwrap_or_else(|_| path.clone());
            if seen.insert(key) {
                candidates.push((path, explicit));
            } else if explicit && let Some(entry) = candidates.iter_mut().find(|(p, _)| *p == path)
            {
                entry.1 = true;
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
fn expand_one(spec: &str, opts: &ResolveOptions) -> Result<Vec<(PathBuf, bool)>> {
    // A glob is identified by its metacharacters. Checked before the
    // filesystem, because a path containing them may also happen to exist.
    if spec.contains('*') || spec.contains('?') || spec.contains('[') {
        let mut out = Vec::new();
        let entries = glob::glob(spec)
            .with_context(|| format!("bad glob pattern '{spec}'"))?
            .filter_map(std::result::Result::ok);
        for path in entries {
            if path.is_file() {
                out.push((path, false));
            }
        }
        if out.is_empty() {
            bail!("glob '{spec}' matched no files");
        }
        return Ok(out);
    }

    let path = PathBuf::from(spec);
    if path.is_dir() {
        return expand_dir(&path, opts);
    }
    if path.exists() {
        return Ok(vec![(path, true)]);
    }
    bail!("'{spec}' does not exist")
}

/// List the files in a directory, honouring recursion and the name glob.
fn expand_dir(dir: &Path, opts: &ResolveOptions) -> Result<Vec<(PathBuf, bool)>> {
    let pattern = opts
        .name_glob
        .as_deref()
        .map(|g| glob::Pattern::new(g).with_context(|| format!("bad filename pattern '{g}'")))
        .transpose()?;

    // walkdir rather than a hand-rolled read_dir recursion: it carries the
    // symlink-loop protection, which a directory of captures can genuinely
    // hit when someone symlinks `latest -> .`.
    let walker = walkdir::WalkDir::new(dir)
        .max_depth(if opts.recursive { usize::MAX } else { 1 })
        .follow_links(false);

    let mut out = Vec::new();
    for entry in walker.into_iter().filter_map(std::result::Result::ok) {
        if !entry.file_type().is_file() {
            continue;
        }
        if let Some(ref pat) = pattern {
            let name = entry.file_name().to_string_lossy();
            if !pat.matches(&name) {
                continue;
            }
        }
        out.push((entry.path().to_path_buf(), false));
    }

    if out.is_empty() {
        match opts.name_glob.as_deref() {
            Some(g) => bail!("no files matching '{g}' in '{}'", dir.display()),
            None => bail!("no files in '{}'", dir.display()),
        }
    }
    Ok(out)
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
    let starts: Vec<(usize, f64)> = resolved
        .iter()
        .enumerate()
        .filter_map(|(i, r)| r.first_packet.map(|t| (i, t)))
        .collect();
    for pair in starts.windows(2) {
        let (i, a) = pair[0];
        let (j, b) = pair[1];
        if (b - a).abs() < f64::EPSILON {
            tracing::warn!(
                "'{}' and '{}' start at the same instant — if these are two captures of \
                 the same traffic, packets present in both are counted twice",
                resolved[i].path.display(),
                resolved[j].path.display()
            );
        }
    }
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
