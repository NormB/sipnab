//! Finding the TLS libraries a host is **actually using**.
//!
//! A host may carry OpenSSL and wolfSSL at once, and typically does — measured
//! on the development box: 56 processes mapping `libssl.so.3`, 8 mapping
//! `libwolfssl.so.42.2.0`, and two *different* builds of GnuTLS side by side.
//! So "which TLS library is this machine running" has no single answer, and
//! making the operator name one means capturing one and silently missing the
//! rest.
//!
//! The question this module answers is narrower and answerable: **which shared
//! objects are mapped into a running process right now**. That is read from
//! `/proc/<pid>/maps` rather than guessed from the filesystem, because a
//! library present on disk and a library in use are different facts, and only
//! the second one can produce traffic.
//!
//! Identity is the **device and inode**, never the path. One file is reachable
//! through a `libssl.so.3` symlink, a versioned real name, and a different
//! mount path inside a container, and probing each of those separately would
//! install three probe sets on one function. Conversely two builds of one
//! flavour genuinely are two targets: their symbol offsets differ, so a probe
//! computed from one and installed on the other reads the wrong address.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Which TLS implementation a mapped object is.
///
/// Only the ones sipnab can name a write symbol for. GnuTLS is mapped on this
/// very host and is deliberately absent: `gnutls_record_send` has a different
/// signature, and classifying it without a verified symbol would install a
/// probe that reads whatever the second argument register happens to hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Flavour {
    /// OpenSSL, and the ABI-compatible forks that keep its symbol names.
    OpenSsl,
    /// wolfSSL, whose native API prefixes the same call.
    WolfSsl,
}

impl Flavour {
    /// The write symbol to probe for this flavour.
    ///
    /// Both take `(ssl, buf, len)`, which is why one banded probe shape serves
    /// both — the flavour changes the **name**, not the argument positions.
    #[must_use]
    pub fn write_symbol(self) -> &'static str {
        match self {
            Self::OpenSsl => "SSL_write",
            Self::WolfSsl => "wolfSSL_write",
        }
    }

    /// How to describe this in operator-facing output.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::OpenSsl => "OpenSSL",
            Self::WolfSsl => "wolfSSL",
        }
    }
}

/// One TLS library in use on this host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsLibrary {
    /// Path **as the mapping process sees it**, which is not necessarily a
    /// path sipnab can open. See [`TlsLibrary::probe_path`].
    pub path: PathBuf,
    /// The mapped file's inode, which is its identity.
    pub inode: u64,
    /// Which implementation it is, and so which symbol to resolve.
    pub flavour: Flavour,
    /// Processes mapping it, ascending. Evidence for the operator, and the
    /// reason a library with an empty list is never returned.
    pub pids: Vec<u32>,
}

impl TlsLibrary {
    /// A path that names **this** file from sipnab's own mount namespace.
    ///
    /// The path in `/proc/<pid>/maps` is resolved in the *mapping* process's
    /// namespace, and a uprobe is installed with a path resolved in
    /// *sipnab's*. When those namespaces differ the same string names a
    /// different file, and the probe attaches to the wrong one while looking
    /// entirely successful.
    ///
    /// Not hypothetical — measured on the development host, where three
    /// distinct files share the path `/usr/lib/aarch64-linux-gnu/libssl.so.3`:
    /// the host's (inode 21143) and one per container (14166752, 146539451).
    /// Probing the bare path attaches to the host copy and captures nothing
    /// from either container.
    ///
    /// So the inode arbitrates. `/proc/<pid>/root/…` reaches into the mapping
    /// process's filesystem and is checked first; the bare path is accepted
    /// only when it resolves to the same inode. Returns `None` when neither
    /// does, because refusing beats probing a file that merely has the right
    /// name.
    #[must_use]
    pub fn probe_path(&self) -> Option<PathBuf> {
        self.probe_path_under(Path::new("/proc"))
    }

    /// [`Self::probe_path`], with the `/proc` root injectable for tests.
    #[must_use]
    pub fn probe_path_under(&self, proc_root: &Path) -> Option<PathBuf> {
        let relative = self.path.strip_prefix("/").unwrap_or(&self.path);
        for pid in &self.pids {
            let candidate = proc_root.join(pid.to_string()).join("root").join(relative);
            if inode_of(&candidate) == Some(self.inode) {
                return Some(candidate);
            }
        }
        // A process that exited between the walk and now takes its
        // `/proc/<pid>/root` with it, so the direct path is still worth trying.
        (inode_of(&self.path) == Some(self.inode)).then(|| self.path.clone())
    }
}

/// The inode of `path`, or `None` if it cannot be read.
fn inode_of(path: &Path) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).ok().map(|m| m.ino())
}

/// Device and inode: the identity of a mapped file, independent of its path.
type FileId = (String, u64);

/// Classify a mapped object by its file name.
///
/// Matches a **basename prefix**, and the prefix is what keeps the two apart:
/// `libwolfssl.so.42` does not *begin* with `libssl`, so it cannot be claimed
/// by the OpenSSL rule. A `contains` match would claim it and then resolve
/// `SSL_write` in a library exporting `wolfSSL_write` — which is why the order
/// of the list below is **not** what protects against that, and mutating the
/// order proves it: the tests stay green. The prefix does the work.
///
/// The prefix must be followed by `.` or `-`, so `libssl.so.3` and
/// `libssl.so.1.1` classify while `libssl-helper.so` is left alone.
#[must_use]
pub fn classify(path: &Path) -> Option<Flavour> {
    let name = path.file_name()?.to_str()?;
    for (prefix, flavour) in [
        ("libwolfssl", Flavour::WolfSsl),
        ("libssl", Flavour::OpenSsl),
    ] {
        if let Some(rest) = name.strip_prefix(prefix)
            && rest.starts_with(['.', '-'])
        {
            return Some(flavour);
        }
    }
    None
}

/// Pull the file-backed mappings out of one `/proc/<pid>/maps`.
///
/// Yields `(device, inode, path)` for mappings that name a real file. Anonymous
/// mappings carry inode 0 and no path; a mapping whose file has been replaced
/// or removed is marked `(deleted)` by the kernel and is skipped, because the
/// path no longer names the bytes that are executing — a probe installed
/// through it would attach to the *replacement*.
fn file_mappings(maps: &str) -> Vec<(String, u64, PathBuf)> {
    let mut out = Vec::new();
    for line in maps.lines() {
        // address perms offset dev inode [pathname]
        let mut cols = line.split_whitespace();
        let (_addr, _perms, _off) = (cols.next(), cols.next(), cols.next());
        let Some(dev) = cols.next() else { continue };
        let Some(inode) = cols.next().and_then(|s| s.parse::<u64>().ok()) else {
            continue;
        };
        if inode == 0 {
            continue;
        }
        // The path may contain spaces, so take the remainder rather than one
        // column. `(deleted)` is a kernel-appended suffix, not part of it.
        let rest = cols.collect::<Vec<_>>().join(" ");
        if rest.is_empty() || rest.ends_with("(deleted)") || !rest.starts_with('/') {
            continue;
        }
        out.push((dev.to_string(), inode, PathBuf::from(rest)));
    }
    out
}

/// Merge one process's mappings into the accumulating set.
///
/// Separated from the `/proc` walk so the merging rules are testable without a
/// live process table.
fn absorb(found: &mut BTreeMap<FileId, TlsLibrary>, pid: u32, maps: &str) {
    for (dev, inode, path) in file_mappings(maps) {
        let Some(flavour) = classify(&path) else {
            continue;
        };
        let entry = found.entry((dev, inode)).or_insert_with(|| TlsLibrary {
            path,
            inode,
            flavour,
            pids: Vec::new(),
        });
        // Each mapping of one file appears several times per process — the
        // code segment, the read-only data, the relocated GOT. One pid.
        if !entry.pids.contains(&pid) {
            entry.pids.push(pid);
        }
    }
}

/// Every TLS library currently mapped by a process under `proc_root`.
///
/// Ordering is by device and inode, which is stable across runs on one host —
/// so the probe names derived from position do not shuffle between captures.
///
/// Unreadable processes are skipped rather than reported: `/proc` races with
/// process exit constantly, and a pid that vanished mid-walk is normal.
/// Insufficient privilege is *not* silently skipped — the caller checks for an
/// empty result, which is the only outcome that matters and cannot be missed.
#[must_use]
pub fn discover_in(proc_root: &Path) -> Vec<TlsLibrary> {
    let mut found: BTreeMap<FileId, TlsLibrary> = BTreeMap::new();
    let Ok(entries) = std::fs::read_dir(proc_root) else {
        return Vec::new();
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        if let Ok(maps) = std::fs::read_to_string(entry.path().join("maps")) {
            absorb(&mut found, pid, &maps);
        }
    }
    found.into_values().collect()
}

/// Every TLS library currently mapped, on this host.
#[must_use]
pub fn discover() -> Vec<TlsLibrary> {
    discover_in(Path::new("/proc"))
}

/// Narrow a discovered set to the flavours an operator asked for.
///
/// An empty selection means "whatever is there", which is the default: the
/// point of discovery is that the operator should not have to know.
#[must_use]
pub fn select(libs: Vec<TlsLibrary>, want: &[Flavour]) -> Vec<TlsLibrary> {
    if want.is_empty() {
        return libs;
    }
    libs.into_iter()
        .filter(|l| want.contains(&l.flavour))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verbatim shapes from `/proc/<pid>/maps` on the development host.
    const OPENSSL_MAPS: &str = "\
aaaad4c00000-aaaad4c10000 r-xp 00000000 fd:01 21143 /usr/lib/aarch64-linux-gnu/libssl.so.3
aaaad4c10000-aaaad4c20000 r--p 00010000 fd:01 21143 /usr/lib/aarch64-linux-gnu/libssl.so.3
ffff8c000000-ffff8c021000 rw-p 00000000 00:00 0
ffff90000000-ffff90200000 r-xp 00000000 fd:01 9911 /usr/lib/aarch64-linux-gnu/libc.so.6
";

    const WOLFSSL_MAPS: &str = "\
aaaab1200000-aaaab1290000 r-xp 00000000 fd:01 6311876 /usr/lib/aarch64-linux-gnu/libwolfssl.so.42.2.0
";

    /// The requirement, stated as a test: a host running both gets both.
    #[test]
    fn a_host_running_both_flavours_yields_both() {
        let mut found = BTreeMap::new();
        absorb(&mut found, 100, OPENSSL_MAPS);
        absorb(&mut found, 101, WOLFSSL_MAPS);

        let libs: Vec<_> = found.into_values().collect();
        let mut flavours: Vec<_> = libs.iter().map(|l| l.flavour).collect();
        flavours.sort_unstable();
        assert_eq!(flavours, vec![Flavour::OpenSsl, Flavour::WolfSsl]);
        assert_eq!(
            libs.iter()
                .map(|l| l.flavour.write_symbol())
                .collect::<Vec<_>>()
                .len(),
            2
        );
    }

    /// `libwolfssl` contains `libssl`, so a substring match claims it and then
    /// resolves `SSL_write` in a library that exports `wolfSSL_write`.
    #[test]
    fn a_substring_match_would_misclassify_wolfssl_and_a_prefix_does_not() {
        assert_eq!(
            classify(Path::new("/usr/lib/libwolfssl.so.42.2.0")),
            Some(Flavour::WolfSsl)
        );
        assert_eq!(
            classify(Path::new("/usr/lib/libssl.so.3")),
            Some(Flavour::OpenSsl)
        );
        // Both of these CONTAIN "libssl" and neither begins with it. A
        // `contains` rule would return OpenSsl for both.
        assert_eq!(
            classify(Path::new("/usr/lib/mylibssl.so.3")),
            None,
            "a substring rule would claim this"
        );
        assert_eq!(
            classify(Path::new("/opt/vendor/libwolfssl.so")),
            Some(Flavour::WolfSsl),
            "and would claim this as OpenSSL, probing a symbol it does not export"
        );
        assert_eq!(
            Flavour::WolfSsl.write_symbol(),
            "wolfSSL_write",
            "the flavour decides the symbol, not the argument positions"
        );
    }

    /// 56 processes map `libssl.so.3` here. That is one probe target.
    #[test]
    fn one_library_mapped_by_many_processes_is_one_target() {
        let mut found = BTreeMap::new();
        for pid in 1..=56 {
            absorb(&mut found, pid, OPENSSL_MAPS);
        }
        let libs: Vec<_> = found.into_values().collect();
        assert_eq!(libs.len(), 1, "same device and inode is the same file");
        assert_eq!(libs[0].pids.len(), 56, "but every process is recorded");
    }

    /// Two builds of one flavour coexist here (GnuTLS 30.37.1 and 30.40.3 were
    /// both mapped). Their symbol offsets differ, so they are two targets.
    #[test]
    fn two_builds_of_one_flavour_are_two_targets() {
        let a = "a-b r-xp 0 fd:01 111 /usr/lib/libssl.so.3\n";
        let b = "a-b r-xp 0 fd:01 222 /usr/lib/libssl.so.1.1\n";
        let mut found = BTreeMap::new();
        absorb(&mut found, 1, a);
        absorb(&mut found, 2, b);
        assert_eq!(
            found.len(),
            2,
            "an offset computed from one and installed on the other reads the \
             wrong address"
        );
    }

    /// The same inode reached by a symlink and by its real name is one file.
    #[test]
    fn one_inode_under_two_names_is_one_target() {
        let mut found = BTreeMap::new();
        absorb(&mut found, 1, "a-b r-xp 0 fd:01 777 /usr/lib/libssl.so.3\n");
        absorb(
            &mut found,
            2,
            "a-b r-xp 0 fd:01 777 /usr/lib/libssl.so.3.0.17\n",
        );
        assert_eq!(found.len(), 1, "identity is device and inode, not the path");
    }

    #[test]
    fn non_tls_and_anonymous_mappings_are_ignored() {
        let mut found = BTreeMap::new();
        absorb(&mut found, 1, OPENSSL_MAPS);
        let libs: Vec<_> = found.into_values().collect();
        assert_eq!(libs.len(), 1, "libc and the anonymous mapping are not TLS");
        assert!(classify(Path::new("/usr/lib/libc.so.6")).is_none());
    }

    /// The kernel marks a replaced file `(deleted)`. The path now names the
    /// replacement, and a probe installed through it attaches to the wrong
    /// bytes — a package upgrade during a capture is exactly this.
    #[test]
    fn a_deleted_mapping_is_not_probed() {
        let mut found = BTreeMap::new();
        absorb(
            &mut found,
            1,
            "a-b r-xp 0 fd:01 555 /usr/lib/libssl.so.3 (deleted)\n",
        );
        assert!(found.is_empty());
    }

    #[test]
    fn selection_narrows_and_an_empty_selection_keeps_everything() {
        let mut found = BTreeMap::new();
        absorb(&mut found, 1, OPENSSL_MAPS);
        absorb(&mut found, 2, WOLFSSL_MAPS);
        let all: Vec<_> = found.into_values().collect();

        assert_eq!(select(all.clone(), &[]).len(), 2, "default is everything");
        let only = select(all, &[Flavour::WolfSsl]);
        assert_eq!(only.len(), 1);
        assert_eq!(only[0].flavour, Flavour::WolfSsl);
    }

    /// A `/proc` that yields nothing must yield nothing, not panic — an
    /// unprivileged sipnab reads no `maps` at all.
    #[test]
    fn an_unreadable_proc_yields_nothing_rather_than_failing() {
        assert!(discover_in(Path::new("/nonexistent/proc")).is_empty());
    }

    /// The container case, which is the one that silently captures nothing.
    ///
    /// Two files, one path string. The probe must reach the one the process
    /// actually mapped, and the inode is what decides.
    #[test]
    fn a_containerised_library_is_probed_through_the_process_root() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let root = tmp.path();

        // The "container" copy, reachable only via /proc/4242/root.
        let inside = root.join("4242/root/usr/lib/libssl.so.3");
        std::fs::create_dir_all(inside.parent().unwrap()).unwrap();
        std::fs::write(&inside, b"container copy").unwrap();
        let want = inode_of(&inside).expect("just written");

        let lib = TlsLibrary {
            path: PathBuf::from("/usr/lib/libssl.so.3"),
            inode: want,
            flavour: Flavour::OpenSsl,
            pids: vec![4242],
        };
        assert_eq!(
            lib.probe_path_under(root),
            Some(inside),
            "the bare path names the host's copy, which this process never mapped"
        );
    }

    /// The same file under a different inode is a different file, and probing
    /// it would report another process's TLS traffic as this one's.
    #[test]
    fn a_path_whose_inode_disagrees_is_refused_rather_than_probed() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let root = tmp.path();
        let inside = root.join("4242/root/usr/lib/libssl.so.3");
        std::fs::create_dir_all(inside.parent().unwrap()).unwrap();
        std::fs::write(&inside, b"some other build").unwrap();

        let lib = TlsLibrary {
            path: PathBuf::from("/usr/lib/libssl.so.3"),
            // Deliberately not the inode of anything present.
            inode: u64::MAX,
            flavour: Flavour::OpenSsl,
            pids: vec![4242],
        };
        assert_eq!(
            lib.probe_path_under(root),
            None,
            "refusing beats probing a file that merely has the right name"
        );
    }

    /// The real `/proc` on whatever machine this runs on.
    ///
    /// Asserts only what must hold **everywhere**, because a build container
    /// with no TLS process is a legitimate host and finding nothing there is
    /// the correct answer. What it does prove is that the parser survives a
    /// genuine `maps` file: thousands of lines, spaces in paths, anonymous
    /// mappings, `[stack]` and `[vdso]` pseudo-entries.
    #[test]
    fn the_real_proc_parses_without_inventing_anything() {
        for lib in discover() {
            assert!(
                lib.path.is_absolute(),
                "a relative path cannot be probed: {}",
                lib.path.display()
            );
            assert!(
                !lib.pids.is_empty(),
                "a library is only reported because a process maps it"
            );
            assert!(
                classify(&lib.path).is_some(),
                "every reported library classified: {}",
                lib.path.display()
            );
        }
    }
}
