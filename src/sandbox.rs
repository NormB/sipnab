// SPDX-License-Identifier: MIT OR Apache-2.0

//! Landlock: bounding which paths this process can reach.
//!
//! # The threat
//!
//! sipnab's own parsers are safe Rust. libpcap is C, it touches every
//! untrusted byte first, and it runs in the address space holding TLS key
//! material, bearer tokens and a pre-drop `CAP_NET_RAW` socket. The privilege
//! drop stops that address space reaching *other users'* files; it does
//! nothing about the ones this user can already read. Landlock closes that:
//! after it installs, a libpcap defect cannot open the keylog of another run,
//! cannot read `/etc/shadow`, and cannot write outside the output directory.
//!
//! # Why Landlock and not seccomp, and why not yet both
//!
//! [`docs/design/syscall-sandbox.md`](../../docs/design/syscall-sandbox.md)
//! §8 sequences the two, and the reason is the failure mode. A seccomp filter
//! needs a syscall allowlist derived from a real run, and a mis-derived list
//! kills the process — on a capture box, during the incident the capture was
//! started for. Landlock needs no enumeration at all: it names paths, its
//! degradation is a weaker ruleset, and a rule that is wrong denies an open
//! rather than ending the run. Nothing here can send `SIGSYS`.
//!
//! # Landlock is per-THREAD, which decides where it installs
//!
//! `landlock_restrict_self` enforces on the calling thread. Threads created
//! afterwards inherit the domain; threads that already exist do not. The
//! design document proposed installing after the servers bind, and that would
//! have left the one thread this exists for outside the sandbox: the capture
//! thread is spawned in `bootstrap`, before the servers start, and it is the
//! thread running libpcap.
//!
//! So it installs BEFORE the capture thread. That costs nothing, because
//! every path a run needs is knowable by then — the input set and the output
//! directory come from the command line, and the writer that opens files
//! lazily still opens them under the directory named at startup. Sockets are
//! unaffected at any ABI: this ruleset governs the filesystem only, and
//! deliberately (see `handled_access_fs`).
//!
//! # Degradation, and never silence
//!
//! A sandbox that quietly did not install looks exactly like one that did, and
//! that is the failure mode every security control in this project has had.
//! So every outcome is a value ([`LandlockStatus`]) rather than a bool, every
//! refusal carries its reason, and the caller reports the whole posture.
//! `--require-sandbox` is how an operator says they would rather not capture
//! than capture unsandboxed; without the flag, an unavailable sandbox never
//! stops a capture.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

// ── The ABI, which is knowledge rather than code ────────────────────────────

/// Landlock filesystem access rights present since ABI 1 (Linux 5.13).
///
/// Bits 0..=12: execute, write_file, read_file, read_dir, remove_dir,
/// remove_file, make_char, make_dir, make_reg, make_sock, make_fifo,
/// make_block, make_sym.
pub const ACCESS_FS_ABI1: u64 = (1 << 13) - 1;

/// `LANDLOCK_ACCESS_FS_EXECUTE`, ABI 1.
pub const ACCESS_FS_EXECUTE: u64 = 1 << 0;
/// `LANDLOCK_ACCESS_FS_WRITE_FILE`, ABI 1.
pub const ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
/// `LANDLOCK_ACCESS_FS_READ_FILE`, ABI 1.
pub const ACCESS_FS_READ_FILE: u64 = 1 << 2;
/// `LANDLOCK_ACCESS_FS_READ_DIR`, ABI 1.
pub const ACCESS_FS_READ_DIR: u64 = 1 << 3;
/// `LANDLOCK_ACCESS_FS_REMOVE_DIR`, ABI 1.
pub const ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
/// `LANDLOCK_ACCESS_FS_REMOVE_FILE`, ABI 1.
pub const ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
/// `LANDLOCK_ACCESS_FS_MAKE_DIR`, ABI 1.
pub const ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
/// `LANDLOCK_ACCESS_FS_MAKE_REG`, ABI 1.
pub const ACCESS_FS_MAKE_REG: u64 = 1 << 8;

/// `LANDLOCK_ACCESS_FS_REFER`, ABI 2 (Linux 5.19). **Never handled** — see
/// [`handled_access_fs`].
pub const ACCESS_FS_REFER: u64 = 1 << 13;

/// `LANDLOCK_ACCESS_FS_TRUNCATE`, ABI 3 (Linux 6.2).
pub const ACCESS_FS_TRUNCATE: u64 = 1 << 14;

/// `LANDLOCK_ACCESS_FS_IOCTL_DEV`, ABI 5 (Linux 6.10). **Never handled** — see
/// [`handled_access_fs`].
pub const ACCESS_FS_IOCTL_DEV: u64 = 1 << 15;

/// The rights that mean anything on a regular file.
///
/// Landlock rejects a rule granting a directory-only right on a file, with
/// `EINVAL` — not silently, but at `landlock_add_rule`, which fails the whole
/// install. `READ_DIR`, the `MAKE_*` set, the `REMOVE_*` set and `REFER` all
/// describe operations on a directory's contents and have no meaning on a
/// file.
///
/// This was found by running on a kernel that has Landlock, and could not have
/// been found without one: every unit test here passes with or without the
/// mask, and the child-role gates granted a DIRECTORY. It took a run with
/// `-I capture.pcap` — a rule on a regular file, which is what an ordinary
/// invocation produces — to fail.
pub const ACCESS_FS_FILE_APPLICABLE: u64 = ACCESS_FS_EXECUTE
    | ACCESS_FS_WRITE_FILE
    | ACCESS_FS_READ_FILE
    | ACCESS_FS_TRUNCATE
    | ACCESS_FS_IOCTL_DEV;

/// The newest ABI this code knows how to use.
///
/// A kernel reporting more is clamped to this rather than trusted to mean
/// something here: an unknown right left out of `handled_access_fs` is a right
/// this ruleset does not govern, which is the safe direction. Extending it is
/// a deliberate edit, not a runtime inference.
pub const MAX_KNOWN_ABI: u32 = 5;

/// Which filesystem rights this ruleset GOVERNS at a given kernel ABI.
///
/// Landlock's rule is that anything named here and not granted by a path rule
/// is denied, and anything NOT named here is unrestricted. So this is the
/// security boundary, and two rights are deliberately outside it:
///
/// **`REFER` (ABI 2) is not handled, and the omission is the strict choice.**
/// When a ruleset does not handle `REFER`, the kernel denies every
/// cross-directory rename and link outright, for backward compatibility. That
/// is safe here because this tree performs exactly one rename —
/// `write_container_atomically`, whose staging file is created with
/// `with_file_name` and is therefore a sibling. A same-directory rename is not
/// a cross-directory one and stays permitted.
///
/// **`IOCTL_DEV` (ABI 5) is not handled.** It governs ioctls on character and
/// block devices, which a capture legitimately touches, and denying them would
/// trade a hardening gain for a broken run on hardware nobody here can test.
#[must_use]
pub fn handled_access_fs(abi: u32) -> u64 {
    if abi == 0 {
        return 0;
    }
    let mut handled = ACCESS_FS_ABI1;
    if abi >= 3 {
        handled |= ACCESS_FS_TRUNCATE;
    }
    handled
}

/// The rights a read-only path is granted at a given ABI.
#[must_use]
pub fn read_access(abi: u32) -> u64 {
    if abi == 0 {
        return 0;
    }
    ACCESS_FS_READ_FILE | ACCESS_FS_READ_DIR
}

/// The rights a writable directory is granted at a given ABI.
///
/// `TRUNCATE` is granted exactly when it is handled. Handling it without
/// granting it would deny `O_TRUNC`, which is what `File::create` does — the
/// output writer would fail on its first open, in a way that reads as a
/// permission problem with no permission having changed.
#[must_use]
pub fn write_access(abi: u32) -> u64 {
    if abi == 0 {
        return 0;
    }
    let mut access = ACCESS_FS_READ_FILE
        | ACCESS_FS_READ_DIR
        | ACCESS_FS_WRITE_FILE
        | ACCESS_FS_MAKE_REG
        | ACCESS_FS_MAKE_DIR
        | ACCESS_FS_REMOVE_FILE
        | ACCESS_FS_REMOVE_DIR;
    if handled_access_fs(abi) & ACCESS_FS_TRUNCATE != 0 {
        access |= ACCESS_FS_TRUNCATE;
    }
    access
}

/// The rights a loadable plugin needs: read, and execute for the mapping
/// `dlopen` makes.
#[must_use]
pub fn execute_access(abi: u32) -> u64 {
    if abi == 0 {
        return 0;
    }
    ACCESS_FS_READ_FILE | ACCESS_FS_EXECUTE
}

/// Bytes of `struct landlock_ruleset_attr` to pass at a given ABI.
///
/// The struct grew: one `__u64` through ABI 3, a second for network rules at
/// ABI 4. The kernel rejects a size it does not know with `E2BIG`, so the size
/// is negotiated rather than assumed. Only the first field is ever set here —
/// this ruleset governs the filesystem — but the size must still match what
/// the running kernel expects.
#[must_use]
pub fn ruleset_attr_size(abi: u32) -> usize {
    if abi >= 4 { 16 } else { 8 }
}

// ── What a run asks for, and what it got ────────────────────────────────────

/// How much the operator wants a sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SandboxMode {
    /// No sandbox. The default, so no existing run changes behavior.
    #[default]
    Off,
    /// Install what this kernel supports, and capture either way.
    BestEffort,
    /// Install it or refuse to capture.
    Required,
}

/// What actually happened, in a shape a report can carry.
///
/// A value rather than a bool, because "no sandbox" has several causes and an
/// operator needs to tell them apart: a kernel without Landlock is a fact
/// about the host, and a ruleset that failed to install is a fact about this
/// run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LandlockStatus {
    /// Nobody asked. Not a failure and never reported as one.
    Disabled,
    /// Enforced, at this ABI, over this many path rules.
    Enforced {
        /// The ABI the ruleset was built against.
        abi: u32,
        /// How many path rules it carries.
        rules: usize,
    },
    /// This kernel cannot do it, with the reason it gave.
    Unsupported {
        /// Why, in words an operator can act on.
        reason: String,
    },
    /// The kernel can, and this run could not, with the reason.
    Failed {
        /// Which step failed and how.
        reason: String,
    },
}

impl LandlockStatus {
    /// A stable code for machine-readable surfaces.
    ///
    /// A code rather than the prose below, following the discipline the rest
    /// of the report already uses: a consumer keying on an English sentence
    /// breaks the first time the sentence improves.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Enforced { .. } => "enforced",
            Self::Unsupported { .. } => "unsupported",
            Self::Failed { .. } => "failed",
        }
    }

    /// Whether a path sandbox is actually in force.
    #[must_use]
    pub fn is_enforced(&self) -> bool {
        matches!(self, Self::Enforced { .. })
    }
}

/// The line a run prints about its own posture.
///
/// Always printed when a sandbox was asked for, including — especially — when
/// there is none. The whole argument for this module is that silence and
/// success are indistinguishable from outside, and an operator who asked for a
/// sandbox and got nothing must be told by the run rather than by an incident.
#[must_use]
pub fn startup_line(status: &LandlockStatus) -> String {
    match status {
        LandlockStatus::Disabled => {
            "path sandbox off; `--sandbox best-effort` bounds which files this process \
             can reach"
                .to_string()
        }
        LandlockStatus::Enforced { abi, rules } => format!(
            "path sandbox ENFORCED (Landlock ABI {abi}, {rules} path rule(s)). \
             Reads and writes outside those paths now fail with EACCES. \
             Sockets are not bounded: this ruleset governs the filesystem only."
        ),
        LandlockStatus::Unsupported { reason } | LandlockStatus::Failed { reason } => format!(
            "path sandbox NOT active: {reason}. The capture is running \
             unsandboxed; `--sandbox required` refuses instead of continuing."
        ),
    }
}

/// The `Enforced` arm of [`requirement_verdict`] cannot be reached: the
/// function returns `Ok` for it before the match. A string rather than a
/// `panic!`, because production code here must not be able to end a run —
/// which is the whole premise of shipping Landlock before seccomp.
fn unreachable_enforced() -> String {
    "a sandbox is in force".to_string()
}

/// Whether a run may continue, given what the operator asked for.
///
/// Pure, so both arms are drivable without a kernel. `Required` is the only
/// mode that can refuse, and it refuses on anything short of enforcement —
/// including `Disabled`, which under `Required` means the caller never
/// attempted an install and is a wiring bug rather than an operator choice.
///
/// # Errors
///
/// Returns the sentence to print when the run must not continue.
pub fn requirement_verdict(mode: SandboxMode, status: &LandlockStatus) -> Result<(), String> {
    if mode != SandboxMode::Required || status.is_enforced() {
        return Ok(());
    }
    // The reason alone, not the whole startup line: the caller has already
    // printed that, and nesting one sentence inside another produced a
    // doubled period and told an operator the same thing twice.
    let because = match status {
        LandlockStatus::Disabled => "no install was attempted".to_string(),
        LandlockStatus::Enforced { .. } => unreachable_enforced(),
        LandlockStatus::Unsupported { reason } | LandlockStatus::Failed { reason } => {
            reason.clone()
        }
    };
    Err(format!(
        "`--sandbox required` was given and no path sandbox is in force: \
         {because}. Refusing to capture. Use `--sandbox best-effort` to \
         capture without one."
    ))
}

// ── The plan: which paths, with which access ────────────────────────────────

/// What a run needs to reach, before any of it is turned into kernel rules.
///
/// Taken as data rather than read from the CLI here, so every branch below is
/// drivable from a test without a command line, a filesystem layout or a
/// kernel. The caller in `bootstrap` fills it from what the run was asked to
/// do.
#[derive(Debug, Clone, Default)]
pub struct SandboxPaths {
    /// Captures being read: `-I`, a directory, or a glob's matches.
    pub inputs: Vec<PathBuf>,
    /// Directories written to: `-O`'s parent, `--split` siblings, the vCon
    /// export directory.
    pub output_dirs: Vec<PathBuf>,
    /// Files read for the life of the run: the TLS keylog, signing keys.
    pub read_files: Vec<PathBuf>,
    /// Where a crash report may be written.
    pub crash_dir: Option<PathBuf>,
    /// A plugin that will be `dlopen`ed, which needs execute as well as read.
    pub plugins: Vec<PathBuf>,
    /// Resolver configuration, only when reverse DNS is on.
    pub resolver_files: Vec<PathBuf>,
}

/// One path and the access it is granted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathRule {
    /// The path the rule is anchored at.
    pub path: PathBuf,
    /// The Landlock access bits granted beneath it.
    pub access: u64,
}

/// Turn a run's paths into the rules a ruleset will carry.
///
/// Three things happen here and each has a reason a test pins:
///
/// **A path that does not exist is dropped, not fatal.** `landlock_add_rule`
/// needs an open descriptor, and a run naming an output directory that is
/// created later, or a keylog the producer has not written yet, is ordinary.
/// Refusing to start over it would trade a capture for a rule.
///
/// **Duplicates are merged, keeping the union of their access.** The same
/// directory can arrive as an input and as an output. Two rules on one path
/// are not additive in the kernel — the last one wins — so merging here is
/// what stops a read-only rule silently revoking a write.
///
/// **An empty plan is refused by the caller, not silently installed.** A
/// ruleset that handles the filesystem and grants nothing denies everything,
/// which would break the run rather than bound it.
#[must_use]
pub fn plan_rules(paths: &SandboxPaths, abi: u32) -> Vec<PathRule> {
    let mut merged: BTreeMap<PathBuf, u64> = BTreeMap::new();
    let mut add = |path: &Path, access: u64| {
        if access == 0 {
            return;
        }
        // `metadata()` follows symlinks, which is what the kernel will do when
        // the rule is added: a dangling link cannot be opened either. The file
        // type is needed as well as the existence, so this is one call rather
        // than `exists()` plus `is_dir()`.
        let Ok(meta) = path.metadata() else {
            return;
        };
        // A directory-only right on a regular file is EINVAL at
        // `landlock_add_rule`, and that failure takes the whole install with
        // it. Masking here rather than at the syscall keeps the rule the plan
        // describes and what the kernel receives the same thing.
        let access = if meta.is_dir() {
            access
        } else {
            access & ACCESS_FS_FILE_APPLICABLE
        };
        if access == 0 {
            return;
        }
        *merged.entry(path.to_path_buf()).or_insert(0) |= access;
    };

    for p in &paths.inputs {
        add(p, read_access(abi));
    }
    for p in &paths.read_files {
        add(p, read_access(abi));
    }
    for p in &paths.resolver_files {
        add(p, read_access(abi));
    }
    for p in &paths.plugins {
        add(p, execute_access(abi));
    }
    for p in &paths.output_dirs {
        add(p, write_access(abi));
    }
    if let Some(dir) = &paths.crash_dir {
        add(dir, write_access(abi));
    }

    merged
        .into_iter()
        .map(|(path, access)| PathRule { path, access })
        .collect()
}

// ── The three syscalls ──────────────────────────────────────────────────────

/// `landlock_create_ruleset`, `landlock_add_rule`, `landlock_restrict_self`.
///
/// Numbers rather than a crate. glibc ships no wrappers for these, so any
/// binding is `syscall(2)` underneath; this tree already reaches for
/// `libc::syscall` the same way for `perf_event_open`
/// (`src/capture/uprobe/perf.rs`). 444/445/446 come from the generic syscall
/// table and were read out of `asm-generic/unistd.h` on aarch64 and
/// `asm/unistd_64.h` on x86_64 rather than remembered.
#[cfg(target_os = "linux")]
const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
/// `landlock_add_rule(2)`, from the same table.
#[cfg(target_os = "linux")]
const SYS_LANDLOCK_ADD_RULE: libc::c_long = 445;
/// `landlock_restrict_self(2)`, from the same table.
#[cfg(target_os = "linux")]
const SYS_LANDLOCK_RESTRICT_SELF: libc::c_long = 446;

/// `LANDLOCK_CREATE_RULESET_VERSION`: ask the kernel what it supports instead
/// of creating anything.
#[cfg(target_os = "linux")]
const CREATE_RULESET_VERSION: u32 = 1 << 0;

/// `LANDLOCK_RULE_PATH_BENEATH`.
#[cfg(target_os = "linux")]
const RULE_PATH_BENEATH: libc::c_int = 1;

/// `struct landlock_ruleset_attr`.
///
/// Only `handled_access_fs` is ever set. `handled_access_net` exists from ABI
/// 4 and stays zero deliberately: Landlock's network rules cover TCP bind and
/// connect only, which would not cover the HEP UDP listener or the pre-drop
/// raw socket — a partial network bound reported as "sandboxed" would claim
/// more than it does.
#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Default)]
struct RulesetAttr {
    /// Filesystem rights this ruleset governs.
    handled_access_fs: u64,
    /// Network rights, ABI 4 and later. Always zero here.
    handled_access_net: u64,
}

/// `struct landlock_path_beneath_attr`.
///
/// **Packed, and that is not a style choice.** The kernel's definition carries
/// `__attribute__((packed))`, so the struct is twelve bytes: a `__u64`
/// followed by an `__s32` with no tail padding. A naturally-aligned Rust
/// struct would be sixteen and the kernel would read the parent descriptor out
/// of padding.
#[cfg(target_os = "linux")]
#[repr(C, packed)]
struct PathBeneathAttr {
    /// Rights granted beneath `parent_fd`.
    allowed_access: u64,
    /// An `O_PATH` descriptor for the directory or file the rule anchors at.
    parent_fd: libc::c_int,
}

/// Ask the kernel which Landlock ABI it supports.
///
/// # Errors
///
/// The status to report when there is none, already worded for an operator.
#[cfg(target_os = "linux")]
pub fn kernel_abi() -> Result<u32, LandlockStatus> {
    // SAFETY: the version query takes a null attribute and a zero size by
    // definition; it creates nothing and returns a version or a negative
    // errno.
    let rc = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            std::ptr::null::<RulesetAttr>(),
            0usize,
            CREATE_RULESET_VERSION,
        )
    };
    if rc > 0 {
        return Ok(u32::try_from(rc)
            .unwrap_or(MAX_KNOWN_ABI)
            .min(MAX_KNOWN_ABI));
    }
    let err = std::io::Error::last_os_error();
    Err(LandlockStatus::Unsupported {
        reason: match err.raw_os_error() {
            Some(libc::ENOSYS) => "this kernel has no Landlock (needs 5.13 or newer)".to_string(),
            Some(libc::EOPNOTSUPP) => {
                "Landlock is compiled in but disabled; add it to the kernel's \
                 lsm= list to enable it"
                    .to_string()
            }
            _ => format!("the kernel refused a Landlock version query: {err}"),
        },
    })
}

/// Without Linux there is no Landlock, and saying so is the whole contract.
///
/// # Errors
///
/// Always, with the reason.
#[cfg(not(target_os = "linux"))]
pub fn kernel_abi() -> Result<u32, LandlockStatus> {
    Err(LandlockStatus::Unsupported {
        reason: "Landlock is a Linux facility and this is not Linux".to_string(),
    })
}

/// Build the ruleset, add every rule, and enforce it on this thread.
///
/// Returns what happened rather than a bool, and never panics: this runs on
/// the startup path of a capture, and the whole design premise is that a
/// hardening feature must not be able to end a run.
///
/// # Side effects
///
/// On success the CALLING THREAD and every thread it creates afterwards are
/// confined to `rules` for the rest of the process's life. A Landlock domain
/// cannot be removed or widened. Threads that already exist keep the access
/// they had, which is why the caller installs before the capture thread
/// starts.
#[cfg(target_os = "linux")]
#[must_use]
pub fn install(paths: &SandboxPaths) -> LandlockStatus {
    let abi = match kernel_abi() {
        Ok(abi) => abi,
        Err(status) => return status,
    };

    // `landlock_restrict_self` requires no-new-privs without CAP_SYS_ADMIN.
    // Read it back here rather than trusting that an earlier step set it: it
    // ran in another function, and a control asserted at a distance is a
    // control assumed.
    // SAFETY: PR_GET_NO_NEW_PRIVS takes no output pointer and returns the flag.
    let nnp = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
    if nnp != 1 {
        return LandlockStatus::Failed {
            reason: "PR_SET_NO_NEW_PRIVS is not set, which Landlock requires \
                     without CAP_SYS_ADMIN"
                .to_string(),
        };
    }

    let rules = plan_rules(paths, abi);
    if rules.is_empty() {
        // A ruleset that governs the filesystem and grants nothing denies
        // everything. Refusing here turns a broken capture into a reported
        // non-install.
        return LandlockStatus::Failed {
            reason: "no readable path to grant, so a ruleset would deny every \
                     file this run needs"
                .to_string(),
        };
    }

    let attr = RulesetAttr {
        handled_access_fs: handled_access_fs(abi),
        handled_access_net: 0,
    };
    // SAFETY: `attr` outlives the call and the size is the one this ABI
    // expects, negotiated above.
    let ruleset_fd = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            std::ptr::from_ref(&attr),
            ruleset_attr_size(abi),
            0u32,
        )
    };
    let ruleset_fd = match libc::c_int::try_from(ruleset_fd) {
        Ok(fd) if fd >= 0 => fd,
        _ => {
            return LandlockStatus::Failed {
                reason: format!(
                    "landlock_create_ruleset failed: {}",
                    std::io::Error::last_os_error()
                ),
            };
        }
    };
    // Every return below closes it. A leaked descriptor on the startup path
    // would survive the whole run.
    let close_ruleset = || {
        // SAFETY: `ruleset_fd` was returned by the kernel and is closed once.
        unsafe { libc::close(ruleset_fd) };
    };

    let mut added = 0usize;
    for rule in &rules {
        let Ok(cpath) = std::ffi::CString::new(rule.path.as_os_str().as_encoded_bytes()) else {
            // A NUL inside a path cannot be opened by anyone; skipping it is
            // the same outcome as a path that does not exist.
            continue;
        };
        // SAFETY: `cpath` is NUL-terminated and outlives the call.
        let parent_fd = unsafe { libc::open(cpath.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if parent_fd < 0 {
            // Unreadable now means unreachable later; the rule would have
            // granted access to something this process cannot open anyway.
            continue;
        }
        let beneath = PathBeneathAttr {
            allowed_access: rule.access,
            parent_fd,
        };
        // SAFETY: `beneath` outlives the call; the kernel copies it.
        let rc = unsafe {
            libc::syscall(
                SYS_LANDLOCK_ADD_RULE,
                ruleset_fd,
                RULE_PATH_BENEATH,
                std::ptr::from_ref(&beneath),
                0u32,
            )
        };
        // SAFETY: opened just above, closed exactly once.
        unsafe { libc::close(parent_fd) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            close_ruleset();
            return LandlockStatus::Failed {
                reason: format!(
                    "landlock_add_rule failed for {}: {err}",
                    rule.path.display()
                ),
            };
        }
        added += 1;
    }

    if added == 0 {
        close_ruleset();
        return LandlockStatus::Failed {
            reason: "every path rule was rejected, so the ruleset would deny \
                     every file this run needs"
                .to_string(),
        };
    }

    // SAFETY: the ruleset descriptor is valid and this thread is the one being
    // confined.
    let rc = unsafe { libc::syscall(SYS_LANDLOCK_RESTRICT_SELF, ruleset_fd, 0u32) };
    let err = std::io::Error::last_os_error();
    close_ruleset();
    if rc != 0 {
        return LandlockStatus::Failed {
            reason: format!("landlock_restrict_self failed: {err}"),
        };
    }
    LandlockStatus::Enforced { abi, rules: added }
}

/// Off Linux there is nothing to install, and the caller is told which.
#[cfg(not(target_os = "linux"))]
#[must_use]
pub fn install(paths: &SandboxPaths) -> LandlockStatus {
    let _ = paths;
    match kernel_abi() {
        Ok(_) => LandlockStatus::Failed {
            reason: "unreachable: a non-Linux build reported a Landlock ABI".to_string(),
        },
        Err(status) => status,
    }
}

#[cfg(test)]
mod abi_tests {
    use super::*;

    /// A kernel that reports no Landlock governs nothing, and every access
    /// helper agrees.
    ///
    /// Zero is not a small ruleset, it is the absence of one. A helper
    /// returning rights at ABI 0 would build a ruleset the kernel cannot
    /// create, and the failure would surface as a syscall error rather than as
    /// the "this kernel cannot" the operator needs to read.
    #[test]
    fn abi_zero_governs_nothing() {
        assert_eq!(handled_access_fs(0), 0);
        assert_eq!(read_access(0), 0);
        assert_eq!(write_access(0), 0);
        assert_eq!(execute_access(0), 0);
    }

    /// ABI 1 governs the thirteen rights Linux 5.13 shipped.
    #[test]
    fn abi_one_governs_the_original_thirteen_rights() {
        assert_eq!(handled_access_fs(1), 0x1fff);
        assert_eq!(handled_access_fs(1).count_ones(), 13);
    }

    /// And not truncate, which arrived two ABIs later.
    ///
    /// The negative half matters more than the positive: governing a right the
    /// kernel does not know makes `landlock_create_ruleset` fail with EINVAL,
    /// so an over-broad mask is a sandbox that never installs.
    #[test]
    fn abi_one_does_not_govern_truncate() {
        assert_eq!(handled_access_fs(1) & ACCESS_FS_TRUNCATE, 0);
    }

    /// ABI 2 adds nothing here, because `REFER` is deliberately not governed.
    ///
    /// Leaving it out is the STRICT choice, not the lax one: a ruleset that
    /// does not handle `REFER` makes the kernel deny every cross-directory
    /// rename outright. This tree performs one rename, and its staging file is
    /// built with `with_file_name`, so it is a sibling and stays permitted.
    #[test]
    fn abi_two_adds_nothing_because_refer_is_deliberately_ungoverned() {
        assert_eq!(handled_access_fs(2), handled_access_fs(1));
    }

    /// ABI 3 adds truncate.
    #[test]
    fn abi_three_governs_truncate() {
        assert_ne!(handled_access_fs(3) & ACCESS_FS_TRUNCATE, 0);
        assert_eq!(
            handled_access_fs(3),
            handled_access_fs(1) | ACCESS_FS_TRUNCATE
        );
    }

    /// ABI 4 adds network rules, which this ruleset does not use, so the
    /// filesystem mask is unchanged.
    #[test]
    fn abi_four_governs_the_same_filesystem_rights_as_three() {
        assert_eq!(handled_access_fs(4), handled_access_fs(3));
    }

    /// ABI 5 adds `IOCTL_DEV`, which stays ungoverned on purpose: it covers
    /// ioctls on character and block devices, which a capture legitimately
    /// makes.
    #[test]
    fn abi_five_does_not_govern_ioctls_on_devices() {
        assert_eq!(handled_access_fs(5) & ACCESS_FS_IOCTL_DEV, 0);
        assert_eq!(handled_access_fs(5), handled_access_fs(3));
    }

    /// A kernel newer than this code is clamped rather than believed.
    ///
    /// `kernel_abi` caps what it returns, so a right introduced after this was
    /// written is never governed by inference. An ungoverned right is
    /// unrestricted, which is the safe direction to be wrong in.
    #[test]
    fn an_abi_newer_than_this_code_knows_governs_no_more_than_the_newest_known() {
        for abi in [MAX_KNOWN_ABI, MAX_KNOWN_ABI + 1, 99, u32::MAX] {
            assert_eq!(
                handled_access_fs(abi),
                handled_access_fs(MAX_KNOWN_ABI),
                "ABI {abi} governs something this code has never reasoned about"
            );
        }
    }

    /// `REFER` is ungoverned at every ABI, not merely at the ones tested above.
    #[test]
    fn refer_is_never_governed() {
        for abi in 0..=8 {
            assert_eq!(
                handled_access_fs(abi) & ACCESS_FS_REFER,
                0,
                "ABI {abi} governs REFER, which would change rename semantics"
            );
        }
    }

    /// So is `IOCTL_DEV`.
    #[test]
    fn ioctl_dev_is_never_governed() {
        for abi in 0..=8 {
            assert_eq!(handled_access_fs(abi) & ACCESS_FS_IOCTL_DEV, 0, "ABI {abi}");
        }
    }

    /// A writable path may truncate exactly when truncate is governed.
    ///
    /// Both directions, because each is a different bug. Granting it where it
    /// is not governed is harmless noise; NOT granting it where it is governed
    /// denies `O_TRUNC`, which is what `File::create` does — the output writer
    /// would fail on its first open, reading as a permission problem with no
    /// permission having changed.
    #[test]
    fn a_writable_path_may_truncate_exactly_when_truncate_is_governed() {
        for abi in 1..=MAX_KNOWN_ABI {
            let governed = handled_access_fs(abi) & ACCESS_FS_TRUNCATE != 0;
            let granted = write_access(abi) & ACCESS_FS_TRUNCATE != 0;
            assert_eq!(governed, granted, "ABI {abi}");
        }
    }

    /// A read-only path is granted no write right.
    #[test]
    fn read_access_grants_no_write_right() {
        for abi in 1..=MAX_KNOWN_ABI {
            let write_bits = ACCESS_FS_WRITE_FILE
                | ACCESS_FS_MAKE_REG
                | ACCESS_FS_MAKE_DIR
                | ACCESS_FS_REMOVE_FILE
                | ACCESS_FS_REMOVE_DIR
                | ACCESS_FS_TRUNCATE;
            assert_eq!(read_access(abi) & write_bits, 0, "ABI {abi}");
        }
    }

    /// A plugin is granted read and execute, and nothing else.
    #[test]
    fn execute_access_is_read_plus_execute_and_nothing_more() {
        for abi in 1..=MAX_KNOWN_ABI {
            assert_eq!(
                execute_access(abi),
                ACCESS_FS_READ_FILE | ACCESS_FS_EXECUTE,
                "ABI {abi}"
            );
        }
    }

    /// Every right granted is a right the ruleset governs.
    ///
    /// The invariant that ties the four functions together. Granting a right
    /// outside `handled_access_fs` is not an error the kernel reports — it is
    /// simply ignored — so a grant that drifts outside the mask becomes a
    /// permission nobody has and nothing says so.
    #[test]
    fn every_granted_right_is_one_the_ruleset_governs() {
        for abi in 1..=MAX_KNOWN_ABI {
            let governed = handled_access_fs(abi);
            for (name, granted) in [
                ("read", read_access(abi)),
                ("write", write_access(abi)),
                ("execute", execute_access(abi)),
            ] {
                assert_eq!(
                    granted & !governed,
                    0,
                    "ABI {abi}: {name} grants a right the ruleset does not govern"
                );
            }
        }
    }

    /// The attribute struct is one `__u64` before ABI 4.
    #[test]
    fn the_attribute_is_eight_bytes_before_abi_four() {
        for abi in [1, 2, 3] {
            assert_eq!(ruleset_attr_size(abi), 8, "ABI {abi}");
        }
    }

    /// And two from ABI 4, where the network field arrived.
    ///
    /// The size is what the kernel validates: too large is `E2BIG`, so passing
    /// the modern size to an older kernel would fail every install on Debian
    /// 12.
    #[test]
    fn the_attribute_is_sixteen_bytes_from_abi_four() {
        for abi in [4, 5, 99] {
            assert_eq!(ruleset_attr_size(abi), 16, "ABI {abi}");
        }
    }
}

#[cfg(test)]
mod plan_tests {
    use super::*;

    /// A directory that exists, so a rule for it is not dropped.
    fn dir(root: &Path, name: &str) -> PathBuf {
        let p = root.join(name);
        std::fs::create_dir_all(&p).expect("create the fixture directory");
        p
    }

    /// A file that exists, for the same reason.
    fn file(root: &Path, name: &str) -> PathBuf {
        let p = root.join(name);
        std::fs::write(&p, b"x").expect("write the fixture file");
        p
    }

    fn rule<'a>(rules: &'a [PathRule], path: &Path) -> Option<&'a PathRule> {
        rules.iter().find(|r| r.path == path)
    }

    /// A capture being read is granted read, and not write.
    #[test]
    fn an_input_capture_is_granted_read_and_not_write() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let input = file(tmp.path(), "in.pcap");
        let rules = plan_rules(
            &SandboxPaths {
                inputs: vec![input.clone()],
                ..SandboxPaths::default()
            },
            3,
        );
        let r = rule(&rules, &input).expect("the input is planned");
        // READ_FILE alone: a capture is a regular file, and READ_DIR on one is
        // EINVAL at `landlock_add_rule`.
        assert_eq!(r.access, ACCESS_FS_READ_FILE);
        assert_eq!(r.access & ACCESS_FS_WRITE_FILE, 0);
    }

    /// An output directory is granted write.
    #[test]
    fn an_output_directory_is_granted_write() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let out = dir(tmp.path(), "out");
        let rules = plan_rules(
            &SandboxPaths {
                output_dirs: vec![out.clone()],
                ..SandboxPaths::default()
            },
            3,
        );
        let r = rule(&rules, &out).expect("the output is planned");
        assert_ne!(r.access & ACCESS_FS_WRITE_FILE, 0);
        assert_ne!(r.access & ACCESS_FS_MAKE_REG, 0);
    }

    /// A path that does not exist is dropped, and dropping it is not fatal.
    ///
    /// `landlock_add_rule` needs an open descriptor, and a run naming an
    /// output directory something creates later, or a keylog whose producer
    /// has not started, is ordinary. Refusing to start over it would trade a
    /// capture for a rule.
    #[test]
    fn a_path_that_does_not_exist_is_dropped_rather_than_fatal() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let real = file(tmp.path(), "real.pcap");
        let rules = plan_rules(
            &SandboxPaths {
                inputs: vec![real.clone(), tmp.path().join("absent.pcap")],
                ..SandboxPaths::default()
            },
            3,
        );
        assert_eq!(rules.len(), 1, "only the path that exists is planned");
        assert_eq!(rules[0].path, real);
    }

    /// One path arriving twice keeps the union of its access.
    ///
    /// Two rules on one path are not additive in the kernel, so a read-only
    /// rule added after a writable one would silently revoke the write. The
    /// merge is what stops that, and this is the case that produces it: a
    /// directory that is both read from and written to.
    #[test]
    fn one_path_arriving_twice_keeps_the_union_of_its_access() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let both = dir(tmp.path(), "both");
        let rules = plan_rules(
            &SandboxPaths {
                inputs: vec![both.clone()],
                output_dirs: vec![both.clone()],
                ..SandboxPaths::default()
            },
            3,
        );
        assert_eq!(rules.len(), 1, "one path is one rule");
        let r = &rules[0];
        assert_ne!(r.access & ACCESS_FS_WRITE_FILE, 0, "the write survived");
        assert_ne!(r.access & ACCESS_FS_READ_FILE, 0, "so did the read");
    }

    /// A plan naming nothing that exists produces no rules.
    ///
    /// The caller turns that into a reported non-install rather than creating
    /// a ruleset that governs the filesystem and grants nothing, which would
    /// deny every file the run needs.
    #[test]
    fn a_plan_with_nothing_readable_produces_no_rules() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let rules = plan_rules(
            &SandboxPaths {
                inputs: vec![tmp.path().join("nope")],
                output_dirs: vec![tmp.path().join("also-nope")],
                ..SandboxPaths::default()
            },
            3,
        );
        assert!(rules.is_empty());
    }

    /// The crash directory is planned like an output, because it is one.
    #[test]
    fn the_crash_directory_is_granted_write() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let crash = dir(tmp.path(), "crash");
        let rules = plan_rules(
            &SandboxPaths {
                crash_dir: Some(crash.clone()),
                ..SandboxPaths::default()
            },
            3,
        );
        let r = rule(&rules, &crash).expect("the crash directory is planned");
        assert_eq!(r.access, write_access(3));
    }

    /// A plugin is granted execute and an input is not.
    ///
    /// The pair is the point. `dlopen` needs the execute right, and granting
    /// it to every readable path would let a dropped payload run from the
    /// capture directory.
    #[test]
    fn a_plugin_is_granted_execute_and_an_input_is_not() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let plugin = file(tmp.path(), "plugin.so");
        let input = file(tmp.path(), "in.pcap");
        let rules = plan_rules(
            &SandboxPaths {
                plugins: vec![plugin.clone()],
                inputs: vec![input.clone()],
                ..SandboxPaths::default()
            },
            3,
        );
        assert_ne!(
            rule(&rules, &plugin).expect("plugin planned").access & ACCESS_FS_EXECUTE,
            0
        );
        assert_eq!(
            rule(&rules, &input).expect("input planned").access & ACCESS_FS_EXECUTE,
            0
        );
    }

    /// The resolver files are read-only, and only when the caller asks.
    #[test]
    fn resolver_files_are_read_only_and_only_when_named() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let resolv = file(tmp.path(), "resolv.conf");
        let without = plan_rules(&SandboxPaths::default(), 3);
        assert!(without.is_empty(), "nothing is planned by default");
        let with = plan_rules(
            &SandboxPaths {
                resolver_files: vec![resolv.clone()],
                ..SandboxPaths::default()
            },
            3,
        );
        assert_eq!(
            rule(&with, &resolv).expect("planned").access,
            ACCESS_FS_READ_FILE,
            "a resolver file is a file, so only the file-applicable half applies"
        );
    }

    /// The rule list is ordered, so one plan produces one ruleset.
    ///
    /// A `BTreeMap` rather than a hash: an install whose rule order varies run
    /// to run cannot be compared between runs, and a report naming "5 rules"
    /// should mean the same five every time.
    #[test]
    fn the_rule_list_is_in_a_stable_order() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let a = file(tmp.path(), "a.pcap");
        let b = file(tmp.path(), "b.pcap");
        let c = file(tmp.path(), "c.pcap");
        let forwards = plan_rules(
            &SandboxPaths {
                inputs: vec![a.clone(), b.clone(), c.clone()],
                ..SandboxPaths::default()
            },
            3,
        );
        let backwards = plan_rules(
            &SandboxPaths {
                inputs: vec![c, b, a],
                ..SandboxPaths::default()
            },
            3,
        );
        assert_eq!(forwards, backwards);
    }

    /// A rule on a regular file carries no directory-only right.
    ///
    /// Landlock rejects one with `EINVAL` at `landlock_add_rule`, and that
    /// takes the whole install down: a single `-I capture.pcap` would leave
    /// every run reporting a sandbox that never installed. Found by running on
    /// a kernel that has Landlock; no unit test here could have found it,
    /// because the mask changes nothing about the values until the kernel sees
    /// them.
    #[test]
    fn a_rule_on_a_file_carries_no_directory_only_right() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let f = file(tmp.path(), "capture.pcap");
        let rules = plan_rules(
            &SandboxPaths {
                // Asked for as an OUTPUT, which grants the widest set, so the
                // mask has something to remove.
                output_dirs: vec![f.clone()],
                ..SandboxPaths::default()
            },
            3,
        );
        let r = rule(&rules, &f).expect("planned");
        let directory_only = ACCESS_FS_READ_DIR
            | ACCESS_FS_MAKE_REG
            | ACCESS_FS_MAKE_DIR
            | ACCESS_FS_REMOVE_FILE
            | ACCESS_FS_REMOVE_DIR;
        assert_eq!(
            r.access & directory_only,
            0,
            "a file rule granting a directory right is EINVAL, not a wider grant"
        );
        assert_ne!(r.access & ACCESS_FS_WRITE_FILE, 0, "the file half survives");
    }

    /// And a rule on a directory keeps them.
    ///
    /// The positive control. A mask applied to both would leave the output
    /// directory unable to create the file the writer opens, which is the
    /// failure the mask exists to avoid trading for.
    #[test]
    fn a_rule_on_a_directory_keeps_the_directory_rights() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let d = dir(tmp.path(), "out");
        let rules = plan_rules(
            &SandboxPaths {
                output_dirs: vec![d.clone()],
                ..SandboxPaths::default()
            },
            3,
        );
        assert_eq!(
            rule(&rules, &d).expect("planned").access,
            write_access(3),
            "a directory keeps every right the ABI grants a writable path"
        );
    }

    /// A file whose only requested right is directory-only is dropped.
    ///
    /// The rule would grant nothing, and adding a zero-access rule is the
    /// same `EINVAL`. Dropping it keeps the ruleset installable.
    #[test]
    fn a_file_left_with_no_applicable_right_is_dropped() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let f = file(tmp.path(), "plain");
        // READ_DIR alone, which no file can have.
        let rules = plan_rules(
            &SandboxPaths {
                resolver_files: vec![f.clone()],
                ..SandboxPaths::default()
            },
            0,
        );
        assert!(
            rules.is_empty(),
            "a rule with no applicable right must not reach the kernel"
        );
    }

    /// At ABI 0 a plan grants nothing, whatever it names.
    ///
    /// The guard against building a ruleset for a kernel that cannot hold one:
    /// every access helper returns zero, and a rule granting zero access is
    /// not added at all.
    #[test]
    fn a_plan_at_abi_zero_grants_nothing() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let input = file(tmp.path(), "in.pcap");
        let out = dir(tmp.path(), "out");
        let rules = plan_rules(
            &SandboxPaths {
                inputs: vec![input],
                output_dirs: vec![out],
                ..SandboxPaths::default()
            },
            0,
        );
        assert!(rules.is_empty());
    }
}

#[cfg(test)]
mod reporting_tests {
    use super::*;

    fn unsupported() -> LandlockStatus {
        LandlockStatus::Unsupported {
            reason: "this kernel has no Landlock (needs 5.13 or newer)".to_string(),
        }
    }

    fn failed() -> LandlockStatus {
        LandlockStatus::Failed {
            reason: "landlock_restrict_self failed: Operation not permitted".to_string(),
        }
    }

    /// A sandbox nobody asked for is not a failure.
    ///
    /// Reporting the default as a fault would train an operator to ignore the
    /// line on every run, which is the state that makes a real
    /// non-installation invisible.
    #[test]
    fn a_disabled_sandbox_is_not_reported_as_a_failure() {
        let line = startup_line(&LandlockStatus::Disabled);
        assert!(!line.contains("NOT active"), "{line}");
        assert!(
            line.contains("--sandbox"),
            "the line must say how to turn it on: {line}"
        );
    }

    /// An enforced sandbox names its ABI and its rule count.
    ///
    /// Both, because either alone can be a lie: an ABI with no rules governs
    /// nothing, and a rule count without an ABI does not say which rights were
    /// available to grant.
    #[test]
    fn the_startup_line_names_the_abi_and_the_rule_count() {
        let line = startup_line(&LandlockStatus::Enforced { abi: 5, rules: 7 });
        assert!(line.contains("ENFORCED"), "{line}");
        assert!(line.contains('5'), "the ABI is missing: {line}");
        assert!(line.contains('7'), "the rule count is missing: {line}");
    }

    /// And says what it does NOT bound, in the same breath.
    ///
    /// An operator reading "sandboxed" will assume the network is included.
    /// Landlock's network rules cover TCP bind and connect only, which would
    /// miss the HEP UDP listener and the pre-drop raw socket entirely, so this
    /// ruleset governs no sockets and the line says so rather than letting the
    /// word imply it.
    #[test]
    fn the_enforced_line_says_what_it_does_not_bound() {
        let line = startup_line(&LandlockStatus::Enforced { abi: 4, rules: 3 });
        assert!(
            line.contains("Sockets are not bounded"),
            "the line lets 'sandboxed' imply a network guarantee: {line}"
        );
    }

    /// An unsupported kernel is reported with the reason, not as silence.
    #[test]
    fn the_startup_line_says_why_when_the_kernel_cannot() {
        let line = startup_line(&unsupported());
        assert!(line.contains("NOT active"), "{line}");
        assert!(line.contains("5.13"), "the reason is missing: {line}");
    }

    /// A failed install reads differently from an unsupported kernel.
    ///
    /// One is a fact about the host and the other a fact about this run, and
    /// an operator needs to tell them apart before deciding whether to change
    /// the kernel or the command line.
    #[test]
    fn a_failed_install_carries_its_own_reason() {
        let line = startup_line(&failed());
        assert!(line.contains("restrict_self"), "{line}");
        assert_ne!(line, startup_line(&unsupported()));
    }

    /// Every status has a distinct, stable code.
    ///
    /// A machine surface keys on this rather than on the sentence, so two
    /// statuses sharing a code would make them indistinguishable to everything
    /// downstream.
    #[test]
    fn every_status_has_a_distinct_code() {
        let codes = [
            LandlockStatus::Disabled.code(),
            LandlockStatus::Enforced { abi: 1, rules: 1 }.code(),
            unsupported().code(),
            failed().code(),
        ];
        let unique: std::collections::BTreeSet<_> = codes.iter().collect();
        assert_eq!(unique.len(), codes.len(), "{codes:?}");
        for c in codes {
            assert!(!c.is_empty());
        }
    }

    /// Only enforcement counts as enforcement.
    #[test]
    fn only_the_enforced_status_reports_itself_as_enforced() {
        assert!(LandlockStatus::Enforced { abi: 1, rules: 1 }.is_enforced());
        for other in [LandlockStatus::Disabled, unsupported(), failed()] {
            assert!(!other.is_enforced(), "{other:?}");
        }
    }

    /// `--require-sandbox` refuses when nothing is in force.
    ///
    /// All three non-enforced statuses, including `Disabled`: under `Required`
    /// that means the caller never attempted an install, which is a wiring bug
    /// and exactly the case a "required" flag must not pass.
    #[test]
    fn requiring_a_sandbox_refuses_when_none_is_in_force() {
        for status in [LandlockStatus::Disabled, unsupported(), failed()] {
            let verdict = requirement_verdict(SandboxMode::Required, &status);
            let err = verdict.expect_err(&format!("{status:?} must refuse"));
            assert!(err.contains("--sandbox required"), "{err}");
            assert!(err.contains("Refusing to capture"), "{err}");
        }
    }

    /// And accepts when one is.
    #[test]
    fn requiring_a_sandbox_accepts_enforcement() {
        assert!(
            requirement_verdict(
                SandboxMode::Required,
                &LandlockStatus::Enforced { abi: 3, rules: 4 }
            )
            .is_ok()
        );
    }

    /// Best effort captures either way.
    ///
    /// The standing rule in this tree: never refuse to capture because a
    /// hardening feature was unavailable. Trading a capture for a sandbox
    /// nobody asked to require turns a hardening gap into an outage.
    #[test]
    fn best_effort_captures_whatever_the_kernel_offers() {
        for status in [
            LandlockStatus::Disabled,
            unsupported(),
            failed(),
            LandlockStatus::Enforced { abi: 1, rules: 2 },
        ] {
            assert!(
                requirement_verdict(SandboxMode::BestEffort, &status).is_ok(),
                "{status:?}"
            );
        }
    }

    /// And an off sandbox never refuses, whatever the status says.
    #[test]
    fn an_off_sandbox_never_refuses() {
        for status in [LandlockStatus::Disabled, unsupported(), failed()] {
            assert!(
                requirement_verdict(SandboxMode::Off, &status).is_ok(),
                "{status:?}"
            );
        }
    }

    /// The default mode is off, so no existing run changes behavior.
    #[test]
    fn the_default_mode_is_off() {
        assert_eq!(SandboxMode::default(), SandboxMode::Off);
    }
}
