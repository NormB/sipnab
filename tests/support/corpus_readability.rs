// SPDX-License-Identifier: MIT OR Apache-2.0

//! Counting the captures a corpus sweep did not read.
//!
//! `support/corpus.rs` answers "did the corpus gates run at all". This answers
//! the question underneath it: of the captures they ran against, how many did
//! anything actually open?
//!
//! Every corpus suite walks the root the same way — take each regular file, try
//! to open it, `continue` on the `Err`. A file the reader refuses therefore
//! contributes nothing to the totals and says nothing on the way out, so the
//! binary reports `ok` having measured one capture fewer than anybody reading
//! its output believes. Measured: a merged pcapng sat in the corpus entirely
//! unread while all fourteen corpus binaries passed. The pure-Rust reader added
//! in 0.5.118 opens that one class and does nothing for the next.
//!
//! Three decisions follow, and `corpus_readability_gate_test` gates all three:
//!
//! 1. **A count, not a per-file warning.** A warning printed during a passing
//!    run is not read — the same defect at a lower volume. This tree has paid
//!    for that once already, with a skip notice libtest captured and discarded.
//!    So the sweep ends in an assertion.
//! 2. **The count is printed whether or not it is zero.** "1 unread" is only
//!    legible against runs that say "0 unread"; a number that appears solely on
//!    failure leaves a passing run claiming nothing about how much of the
//!    corpus it read.
//! 3. **Both read paths, not just the harness one.** [`probe`] opens each
//!    capture the way the corpus suites do *and* the way the product does. A
//!    gate that proved only the suites' own reader would have been blind to
//!    RDR1, whose file libpcap refused and `PcapReader` accepted — which is the
//!    one defect it exists because of.
//!
//! Lives in its own support file rather than in `support/corpus.rs` because it
//! reaches `capture::merged`, which is `native`-only, and `support/corpus.rs`
//! is included by binaries that build without that feature. A `#[cfg]` there
//! would make the gate quietly weaker in exactly the builds nobody watches.
#![allow(dead_code)]

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Once;

/// Files larger than this are never opened by any corpus suite.
///
/// Every one of them applies the same cap, because the corpus root holds a
/// multi-gigabyte archive that is not a capture and the pure-Rust reader works
/// from a whole-file slice. A *capture* above the cap is not "skipped for a
/// good reason", it is unread, so [`survey`] counts it rather than inheriting
/// the suites' silence about it.
pub const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;

/// How many unread captures the corpus gate tolerates.
///
/// Zero, and changing it is a decision someone has to write down here.
/// Measured 2026-08-20 against a 138-file corpus: 121 captures, 121 read. A
/// floor raised to whatever the last run happened to measure is not a ratchet,
/// it is a record of defeat — the count means something only while "unread" is
/// a state the suite refuses to be in.
pub const UNREAD_FLOOR: usize = 0;

/// The fragment every sweep report carries, for tests and for `grep`.
pub const REPORT_MARKER: &str = "CORPUS READABILITY:";

/// Why one capture contributed nothing to a corpus sweep.
///
/// Kept apart on purpose: from a suite's totals alone these are
/// indistinguishable, and "opened it, found nothing" wants a different response
/// from "never opened it".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unread {
    /// The bytes never reached a reader — permissions, a file that vanished
    /// mid-walk, a bad sector. Not any reader's verdict on the content.
    Unfetchable(String),
    /// Above [`MAX_FILE_BYTES`], so nothing in the tree ever opens it.
    TooLarge(u64),
    /// A reader refused it, and which one. This is the RDR1 class and every
    /// future one.
    Refused(String),
    /// A reader accepted it and then yielded no packets. A bare pcap global
    /// header is a valid capture by every check that exists and still puts zero
    /// packets into every total.
    NoPackets,
}

impl Unread {
    /// One clause naming the state, for the report and the failure message.
    #[must_use]
    pub fn reason(&self) -> String {
        match self {
            Self::Unfetchable(e) => format!("could not be read from disk: {e}"),
            Self::TooLarge(bytes) => format!(
                "{bytes} bytes, over the {} MiB cap every corpus suite applies, so nothing \
                 ever opens it",
                MAX_FILE_BYTES / (1024 * 1024)
            ),
            Self::Refused(e) => format!("refused: {e}"),
            Self::NoPackets => "opened, then yielded no packets".to_string(),
        }
    }
}

/// What one sweep of the corpus root found.
#[derive(Debug, Default)]
pub struct Survey {
    /// The root swept, so the report says what it measured.
    pub root: PathBuf,
    /// Regular files walked, captures and otherwise.
    pub files: usize,
    /// Files that are neither named like a capture nor open with one's magic —
    /// the logs, scripts and archives that live beside the captures.
    pub not_captures: usize,
    /// Captures every reader opened, that yielded at least one packet.
    pub read: usize,
    /// Packets those captures yielded, so an empty sweep cannot look busy.
    pub packets: u64,
    /// Captures that contributed nothing, as `(name relative to the root,
    /// why)`. Names and reasons only: the corpus is real traffic and carries
    /// PII in every packet, so nothing derived from a packet is ever printed.
    pub unread: Vec<(String, Unread)>,
}

impl Survey {
    /// Captures found, read or not.
    #[must_use]
    pub fn captures(&self) -> usize {
        self.read + self.unread.len()
    }

    /// The one-line verdict.
    #[must_use]
    pub fn report_line(&self) -> String {
        format!(
            "{REPORT_MARKER} {} — {} file(s) walked, {} capture(s): {} read ({} packets), \
             {} unread, {} not captures.",
            self.root.display(),
            self.files,
            self.captures(),
            self.read,
            self.packets,
            self.unread.len(),
            self.not_captures
        )
    }

    /// Write the verdict, and a line per unread capture, to the process's real
    /// stderr — at most once per test binary.
    ///
    /// # Side effects
    /// Writes to [`std::io::stderr`] directly. NOT `eprintln!`: libtest swaps
    /// the print machinery's sink per test and throws the buffer away when the
    /// test passes, so a report written that way is emitted on precisely the
    /// runs nobody needed it on. The detail lines deliberately omit
    /// [`REPORT_MARKER`], which keeps "one report per binary" checkable by
    /// counting the marker.
    pub fn announce(&self) {
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            let mut err = std::io::stderr();
            let _ = writeln!(err, "{}", self.report_line());
            for (name, why) in &self.unread {
                let _ = writeln!(err, "  unread: {name} — {}", why.reason());
            }
        });
    }

    /// Report the sweep, then hold it to [`UNREAD_FLOOR`].
    ///
    /// # Panics
    /// When the sweep found no captures at all, or when the unread count is
    /// anything other than [`UNREAD_FLOOR`].
    pub fn assert_every_capture_was_read(&self) {
        self.announce();

        // Without this the gate is satisfied by an empty directory, which is
        // the same missing measurement one level up: nought unread out of
        // nought captures is not evidence that anything was read. A corpus
        // root that is misspelled, unmounted or newly emptied lands here.
        assert!(
            self.captures() > 0,
            "{} holds no captures at all, so \"nothing went unread\" is vacuous: \
             {} file(s) were walked and every one was classified as a non-capture.",
            self.root.display(),
            self.files
        );

        let detail: Vec<String> = self
            .unread
            .iter()
            .map(|(name, why)| format!("{name} ({})", why.reason()))
            .collect();
        // Equality, not `<=`. Both directions are failures and the ratchet only
        // works while both are: above the floor, captures are going unread
        // again; below it, the floor is headroom the next regression can hide
        // in. `assert_eq!` also says so at a floor of zero, where clippy is
        // right that `<=` and `>=` are absurd comparisons on a `usize`.
        assert_eq!(
            self.unread.len(),
            UNREAD_FLOOR,
            "{} of the {} capture(s) under {} went unread, against a floor of \
             {UNREAD_FLOOR}. Above the floor: each of these contributed nothing to \
             every corpus suite in the tree while all of them reported `ok` — fix \
             the read path or retire the file, because raising the floor puts the \
             silence back. Below it: lower the floor in the same commit that earned \
             it. Unread: {detail:?}",
            self.unread.len(),
            self.captures(),
            self.root.display()
        );
    }
}

/// Every regular file under `root`, recursively, in sorted order.
///
/// Recursive because `SIPNAB_CORPUS` names a tree, and a capture in a
/// subdirectory nothing descends into is unread in exactly the sense this
/// module is about.
#[must_use]
pub fn walk(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            match entry.file_type() {
                Ok(t) if t.is_dir() => stack.push(path),
                Ok(t) if t.is_file() => out.push(path),
                _ => {}
            }
        }
    }
    out.sort();
    out
}

/// Does `path` claim to be a capture by its name?
///
/// Name and magic are both needed and neither subsumes the other. A file
/// truncated before its header carries no magic to recognise and would be waved
/// through as "not a capture" — the most silent outcome on offer — while the
/// corpus's ring-buffer members (`.pcap0` … `.pcap9`) and its epoch-suffixed
/// rotations carry magic and nothing name-shaped at all.
///
/// A trailing `.gz` is stripped first, so `.pcap.gz` counts. A bare `.gz` does
/// not: telling a gzipped capture from a gzipped log needs the file inflated,
/// and inflating every unknown archive in the root to find out is a cost this
/// gate should not impose on a directory that holds a multi-gigabyte one.
#[must_use]
pub fn named_like_a_capture(path: &Path) -> bool {
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let stem = name.strip_suffix(".gz").unwrap_or(&name);
    let Some((_, ext)) = stem.rsplit_once('.') else {
        return false;
    };
    let ext = ext.to_ascii_lowercase();
    ext == "cap" || ext.starts_with("pcap")
}

/// Do these opening bytes carry a capture's magic number?
///
/// Classic pcap in both byte orders and both timestamp resolutions, and
/// pcapng's Section Header Block. Gzip is deliberately absent — see
/// [`named_like_a_capture`].
#[must_use]
pub fn capture_magic(head: &[u8]) -> bool {
    let Some(first4) = head.get(..4) else {
        return false;
    };
    matches!(
        first4,
        // Classic pcap: µs and ns resolution, little- and big-endian.
        [0xd4, 0xc3, 0xb2, 0xa1]
            | [0xa1, 0xb2, 0xc3, 0xd4]
            | [0x4d, 0x3c, 0xb2, 0xa1]
            | [0xa1, 0xb2, 0x3c, 0x4d]
            // pcapng Section Header Block.
            | [0x0a, 0x0d, 0x0d, 0x0a]
    )
}

/// Open one capture through every reader that claims it, and say what came of
/// it.
///
/// # Returns
/// The packet count on success; the reason nothing was read otherwise.
fn probe(path: &Path, size: u64) -> Result<u64, Unread> {
    use sipnab::capture::pcap_reader::{PcapReader, decompress_capture};

    if size > MAX_FILE_BYTES {
        return Err(Unread::TooLarge(size));
    }

    // 1. The corpus suites' own path. Deliberately theirs and not a private
    //    one: a gate proving some *other* reader can open the corpus proves
    //    nothing about the fourteen binaries whose silence it exists to break.
    let data = std::fs::read(path).map_err(|e| Unread::Unfetchable(e.to_string()))?;
    let inflated = decompress_capture(&data)
        .map_err(|e| Unread::Refused(format!("decompress_capture: {e}")))?;
    let reader =
        PcapReader::new(&inflated).map_err(|e| Unread::Refused(format!("PcapReader: {e}")))?;
    let packets = reader.count() as u64;
    if packets == 0 {
        return Err(Unread::NoPackets);
    }

    // 2. The product's path, for the files where the two differ. `PcapReader`
    //    has always taken the link type per packet, so it reads a merged
    //    pcapng that libpcap refuses outright — which is why the suites were
    //    green over RDR1's file and `sipnab -r` on it was not. Mirroring
    //    `capture::file`'s own routing decision is the point: delete the merged
    //    arm from the product and this gate goes red instead of the operator
    //    finding out.
    if sipnab::capture::merged::is_merged(path) {
        let mut merged = sipnab::capture::merged::MergedPcapNg::open(path)
            .map_err(|e| Unread::Refused(format!("MergedPcapNg: {e:#}")))?;
        let mut frames = 0u64;
        while merged.next_frame().is_some() {
            frames += 1;
        }
        if frames == 0 {
            return Err(Unread::NoPackets);
        }
    }

    Ok(packets)
}

/// Sweep `root` once and account for every file under it.
///
/// # Returns
/// A [`Survey`]: what was read, what was not, and why not.
#[must_use]
pub fn survey(root: &Path) -> Survey {
    let mut out = Survey {
        root: root.to_path_buf(),
        ..Survey::default()
    };

    for path in walk(root) {
        out.files += 1;
        let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        // Sixteen bytes: enough for any magic here, and cheap against a file
        // that turns out to be a multi-gigabyte archive.
        let mut head = [0u8; 16];
        let head_len = std::fs::File::open(&path)
            .and_then(|mut f| std::io::Read::read(&mut f, &mut head))
            .unwrap_or(0);

        if !capture_magic(&head[..head_len]) && !named_like_a_capture(&path) {
            out.not_captures += 1;
            continue;
        }

        let name = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .into_owned();
        match probe(&path, size) {
            Ok(packets) => {
                out.read += 1;
                out.packets += packets;
            }
            Err(why) => out.unread.push((name, why)),
        }
    }

    out
}
