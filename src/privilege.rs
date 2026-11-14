// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Privilege separation for sipnab.
//!
//! After opening capture devices (which require root or `CAP_NET_RAW`),
//! sipnab drops privileges to an unprivileged user before processing
//! any packets. This limits the blast radius of potential exploits in
//! packet-parsing code.
//!
//! Call sequence:
//! 1. Call [`block_privilege_escalation()`] — no preconditions, so it happens
//!    once at the top of the run rather than as part of the drop
//! 2. Open capture devices (requires root/`CAP_NET_RAW`)
//! 3. Open key files, bind API/metrics ports
//! 4. Call [`drop_privileges()`]
//! 5. Begin packet processing (unprivileged)

use anyhow::{Result, bail};

/// The account sipnab drops to when neither `--user` nor `[privilege] user`
/// names one. The one place this default lives: the drop itself and the
/// kill worker's `run_as` both read it.
pub const DEFAULT_DROP_USER: &str = "nobody";

/// The user this process dropped privileges to, set once by a drop that
/// succeeded. Empty when no drop happened (`--no-priv-drop`, not root, or the
/// macOS skip), so a report can tell "we shed root" from "we never had it".
static DROPPED_TO: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// The user a successful [`drop_privileges`] switched this process to, or
/// `None` when no drop happened.
///
/// Read by the output-file error reports: a file created after the drop is
/// created by THIS user, and a permission failure is only explainable by
/// naming it.
pub fn dropped_to() -> Option<&'static str> {
    DROPPED_TO.get().map(String::as_str)
}

/// Drop privileges to an unprivileged user after capture devices are opened.
///
/// When `no_priv_drop` is `true`, privilege dropping is skipped entirely
/// (useful for debugging or environments where the process intentionally
/// runs as non-root from the start).
///
/// When the process is not running as root, the call is a no-op since
/// there are no elevated privileges to shed.
///
/// This drops uid, gid and the supplementary groups, and nothing else.
/// `PR_SET_NO_NEW_PRIVS` is [`block_privilege_escalation()`]'s job and is not
/// implied by calling this — precisely because both of the early returns above
/// would otherwise skip it.
///
/// [`resolve_drop_target`] then [`drop_to`]. A run that chroots between the
/// two must call them separately: the lookup reads the password database,
/// which the new root normally does not hold.
///
/// # Errors
///
/// Returns an error if the target user cannot be resolved, or if any of the
/// underlying syscalls (`setgroups`, `setgid`, `setuid`) fail.
pub fn drop_privileges(target_user: Option<&str>, no_priv_drop: bool) -> Result<()> {
    match resolve_drop_target(target_user, no_priv_drop)? {
        Some(target) => drop_to(&target),
        None => Ok(()),
    }
}

/// The account a privilege drop switches to, looked up in the password
/// database.
///
/// Resolved apart from the drop so the lookup can happen while the database
/// is reachable: `--chroot` enters a root that normally has no `/etc/passwd`,
/// and a lookup made there finds no user (OPS-8). The supplementary groups
/// need no lookup, because the drop clears them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DropTarget {
    /// The account's name, for the log line and [`dropped_to`].
    user: String,
    /// Its uid.
    uid: u32,
    /// Its primary gid.
    gid: u32,
}

impl DropTarget {
    /// The account's name.
    #[must_use]
    pub fn user(&self) -> &str {
        &self.user
    }

    /// The account's uid.
    #[must_use]
    pub fn uid(&self) -> u32 {
        self.uid
    }

    /// The account's primary gid.
    #[must_use]
    pub fn gid(&self) -> u32 {
        self.gid
    }
}

/// The account [`drop_to`] will switch to, or `None` when no drop happens
/// (see [`drop_is_skipped`]).
///
/// # Errors
///
/// The user does not exist, or its name holds a NUL byte.
pub fn resolve_drop_target(
    target_user: Option<&str>,
    no_priv_drop: bool,
) -> Result<Option<DropTarget>> {
    if drop_is_skipped(target_user, no_priv_drop, is_root()) {
        return Ok(None);
    }
    let user = target_user.unwrap_or(DEFAULT_DROP_USER);
    let (uid, gid) = resolve_user(user)?;
    Ok(Some(DropTarget {
        user: user.to_string(),
        uid,
        gid,
    }))
}

/// Switch to `target`, resolved earlier by [`resolve_drop_target`]. Makes no
/// lookup, so it works inside a chroot.
///
/// # Errors
///
/// Any of `setgroups`, `setgid` or `setuid` fails, or the process does not hold
/// the target's ids afterwards.
pub fn drop_to(target: &DropTarget) -> Result<()> {
    let DropTarget { user, uid, gid } = target;
    let (uid, gid) = (*uid, *gid);

    // Groups first, and as ONE step — see `drop_group_credentials` for why the
    // two halves cannot be separated or reordered on macOS.
    drop_group_credentials(gid)?;

    // Drop UID last: once the root UID is gone the group calls above would be
    // refused, so their order relative to this one is not a preference.
    set_uid(uid)?;

    // PR_SET_NO_NEW_PRIVS used to be set here, which meant it was set only on
    // the branch that got this far. See `block_privilege_escalation` for why it
    // is no longer part of the drop.

    tracing::info!(
        "Dropped privileges to user '{}' (uid={}, gid={})",
        user,
        uid,
        gid
    );

    // Verify we actually dropped
    verify_dropped(uid, gid)?;

    // Recorded only after the verification, so `dropped_to()` never names a
    // user the process is not actually running as. A second drop in one
    // process (none exists today) keeps the first name: `set` is first-wins.
    let _ = DROPPED_TO.set(user.clone());

    Ok(())
}

/// Whether [`drop_privileges`] keeps the current credentials, logging why.
///
/// `--no-priv-drop` skips the drop, and so does a process that is not root,
/// since it has nothing to shed. On macOS a root process with no `--user` also
/// keeps root: dropping to 'nobody' (uid 65534) strands the process without a
/// launchd per-user session, which crashes CoreAudio and other user-context
/// frameworks the moment they are invoked (e.g., pressing P to play RTP audio
/// in the TUI). macOS's security model relies on TCC and the app sandbox
/// rather than uid-based privilege separation, so the drop buys little there.
pub fn drop_is_skipped(target_user: Option<&str>, no_priv_drop: bool, root: bool) -> bool {
    let skip = drop_skip(target_user, no_priv_drop, root);
    match skip {
        Some(DropSkip::Disabled) => tracing::info!("Privilege drop disabled (--no-priv-drop)"),
        Some(DropSkip::NotRoot) => {
            tracing::debug!("Not running as root, skipping privilege drop");
        }
        Some(DropSkip::MacosWithoutUser) => tracing::warn!(
            "Running as root on macOS without --user; skipping privilege drop \
             to avoid breaking CoreAudio and other per-user services. \
             Pass --user <name> to opt in, or run without sudo."
        ),
        None => {}
    }
    skip.is_some()
}

/// Why a privilege drop is skipped. See [`drop_is_skipped`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropSkip {
    /// `--no-priv-drop`.
    Disabled,
    /// The process is not root, so it has nothing to shed.
    NotRoot,
    /// Root on macOS with no `--user`.
    MacosWithoutUser,
}

/// Why [`drop_is_skipped`] skips the drop, or `None` when the drop happens.
/// Pure, and logs nothing, so a step that only needs to know whether the run
/// will drop can ask without repeating the reason in the log.
#[must_use]
pub fn drop_skip(target_user: Option<&str>, no_priv_drop: bool, root: bool) -> Option<DropSkip> {
    if no_priv_drop {
        return Some(DropSkip::Disabled);
    }
    if !root {
        return Some(DropSkip::NotRoot);
    }
    #[cfg(target_os = "macos")]
    if target_user.is_none() {
        return Some(DropSkip::MacosWithoutUser);
    }
    #[cfg(not(target_os = "macos"))]
    let _ = target_user;
    None
}

/// The capability names [`CAPTURE_CAP_NAMES`] holds. A macro so the `setcap`
/// argument below is built from the same text at compile time.
macro_rules! capture_cap_names {
    () => {
        "cap_net_raw,cap_net_admin"
    };
}

/// The Linux capabilities a live capture needs, in `setcap` spelling:
/// `CAP_NET_RAW` to open the packet socket and `CAP_NET_ADMIN` to put the
/// interface into promiscuous mode.
///
/// The container image's `Dockerfile` grants exactly these to the binary,
/// permitted only (`+p`), and `tests/container_image_test.rs` holds it to
/// this constant.
pub const CAPTURE_CAP_NAMES: &str = capture_cap_names!();

/// [`CAPTURE_CAP_NAMES`] in the effective+permitted file-capability sets
/// (`+ep`), the form `--setup-caps` installs on a host.
#[cfg(target_os = "linux")]
const CAPTURE_CAPS: &str = concat!(capture_cap_names!(), "+ep");

/// [`CAPTURE_CAP_NAMES`] as a capability bit mask: `CAP_NET_ADMIN` is bit 12
/// and `CAP_NET_RAW` bit 13 (`linux/capability.h`).
pub const CAPTURE_CAP_MASK: u64 = (1 << 12) | (1 << 13);

/// The effective set to install so the process can use the capture
/// capabilities it is permitted, or `None` when nothing changes.
///
/// Adds `permitted & CAPTURE_CAP_MASK` to `effective`. Nothing outside the
/// mask is raised, and nothing that is not permitted: `capset(2)` refuses an
/// effective bit that is not in the permitted set.
#[must_use]
pub fn capture_effective(effective: u64, permitted: u64) -> Option<u64> {
    let want = effective | (permitted & CAPTURE_CAP_MASK);
    (want != effective).then_some(want)
}

/// `struct __user_cap_header_struct` for `capget(2)` and `capset(2)`.
#[cfg(target_os = "linux")]
#[repr(C)]
pub(crate) struct CapHeader {
    /// [`CAP_VERSION_3`].
    pub(crate) version: u32,
    /// 0 for the calling thread.
    pub(crate) pid: libc::c_int,
}

/// `struct __user_cap_data_struct`: 32 bits of each set. Version 3 uses two,
/// low bits first.
#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct CapData {
    /// The effective set.
    pub(crate) effective: u32,
    /// The permitted set.
    pub(crate) permitted: u32,
    /// The inheritable set.
    pub(crate) inheritable: u32,
}

/// `_LINUX_CAPABILITY_VERSION_3`: two [`CapData`], 64 capability bits.
#[cfg(target_os = "linux")]
pub(crate) const CAP_VERSION_3: u32 = 0x2008_0522;

/// Raise the capture capabilities this thread is permitted into its
/// effective set, and return the new effective set, or `None` when nothing
/// changed.
///
/// A binary with permitted-only file capabilities (`setcap ...+p`, as the
/// container image's binary has) starts with them permitted and not
/// effective, and a socket call checks the effective set. The image does not
/// use `+ep` because an effective bit makes `execve` fail with `EPERM` when
/// the bounding set lacks any named capability, and Docker's default set
/// lacks `CAP_NET_ADMIN`. A binary from `--setup-caps` (`+ep`), and root,
/// already hold them effective, and this changes nothing.
///
/// Capability sets belong to a thread. Call this before any thread is
/// started, so every later thread inherits the raised set.
///
/// # Errors
///
/// `capget(2)` or `capset(2)` fails. On platforms other than Linux this is a
/// no-op that returns `Ok(None)`.
pub fn raise_capture_capabilities() -> Result<Option<u64>> {
    #[cfg(target_os = "linux")]
    {
        let mut header = CapHeader {
            version: CAP_VERSION_3,
            pid: 0,
        };
        let mut data = [CapData::default(); 2];
        // SAFETY: capget(2) writes exactly two version-3 data structs, laid
        // out as the kernel declares them (repr(C), three u32), into `data`,
        // which lives on this frame for the call.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_capget,
                std::ptr::addr_of_mut!(header),
                data.as_mut_ptr(),
            )
        };
        if rc != 0 {
            bail!("capget failed: {}", std::io::Error::last_os_error());
        }
        let join = |lo: u32, hi: u32| u64::from(lo) | (u64::from(hi) << 32);
        let effective = join(data[0].effective, data[1].effective);
        let permitted = join(data[0].permitted, data[1].permitted);
        let Some(want) = capture_effective(effective, permitted) else {
            return Ok(None);
        };
        // The truncating casts are the split into the low and high 32 bits.
        data[0].effective = want as u32;
        data[1].effective = (want >> 32) as u32;
        header.version = CAP_VERSION_3;
        header.pid = 0;
        // SAFETY: capset(2) reads one header and two version-3 data structs,
        // laid out as above and live for the call. The permitted and
        // inheritable sets are written back as read; only effective bits
        // that are already permitted are added.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_capset,
                std::ptr::addr_of_mut!(header),
                data.as_ptr(),
            )
        };
        if rc != 0 {
            bail!("capset failed: {}", std::io::Error::last_os_error());
        }
        Ok(Some(want))
    }
    #[cfg(not(target_os = "linux"))]
    Ok(None)
}

/// Build the `setcap` command (program + args) that grants `CAPTURE_CAPS` to
/// `exe`. When `as_root` is false the call is wrapped in `sudo` so it can
/// elevate (prompting for a password on the controlling terminal if needed).
///
/// Factored out from `setup_capabilities` so the command shape is unit-testable
/// without actually invoking the privileged `setcap`.
#[cfg(target_os = "linux")]
fn setcap_command(exe: &str, as_root: bool) -> (String, Vec<String>) {
    if as_root {
        (
            "setcap".to_string(),
            vec![CAPTURE_CAPS.to_string(), exe.to_string()],
        )
    } else {
        (
            "sudo".to_string(),
            vec![
                "setcap".to_string(),
                CAPTURE_CAPS.to_string(),
                exe.to_string(),
            ],
        )
    }
}

/// Grant this binary the capabilities required for live capture so it can run
/// without sudo, then return. Intended to back `sipnab --setup-caps`.
///
/// Resolves the running executable's real path (following symlinks so a PATH
/// symlink isn't targeted instead of the real file), then runs `setcap`. When
/// not already root it re-runs the command through `sudo`, which may prompt for
/// a password on the terminal.
///
/// # Errors
///
/// Returns an error if the executable path can't be resolved, `setcap`/`sudo`
/// can't be spawned (e.g. `libcap2-bin` not installed), or `setcap` exits
/// non-zero.
#[cfg(target_os = "linux")]
pub fn setup_capabilities() -> Result<()> {
    let exe = std::env::current_exe()
        .map_err(|e| anyhow::anyhow!("cannot resolve own executable path: {e}"))?;
    let exe_str = setcap_target(&exe)?;

    let root = is_root();
    if !root {
        tracing::info!(
            "Not root — elevating via sudo to set capabilities (may prompt for a password)"
        );
    }
    let (program, args) = setcap_command(&exe_str, root);

    let status = std::process::Command::new(&program).args(&args).status();
    setcap_outcome(&program, &exe_str, status)
}

/// The path `setcap` should be pointed at for the executable at `exe`.
///
/// Follows symlinks so setcap targets the real binary, not a symlink in PATH —
/// a file capability on a symlink grants nothing. A path that cannot be
/// canonicalized is used as given, so `setcap` itself reports what is wrong.
///
/// # Errors
///
/// The path is not valid UTF-8, so it cannot be handed on as an argument
/// without being mangled.
#[cfg(target_os = "linux")]
fn setcap_target(exe: &std::path::Path) -> Result<String> {
    let exe = std::fs::canonicalize(exe).unwrap_or_else(|_| exe.to_path_buf());
    exe.to_str()
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("executable path is not valid UTF-8"))
}

/// What running `program` to grant capabilities on `exe` came to.
///
/// Separate from [`setup_capabilities`] so the verdict is testable without
/// running the privileged command: spawning `setcap`/`sudo` is the part no
/// test may do, and turning its result into an answer is the part that can be
/// wrong.
///
/// # Errors
///
/// The command could not be spawned (the message names the package that ships
/// `setcap`), or it exited non-zero.
#[cfg(target_os = "linux")]
fn setcap_outcome(
    program: &str,
    exe: &str,
    status: std::io::Result<std::process::ExitStatus>,
) -> Result<()> {
    let status = status.map_err(|e| {
        anyhow::anyhow!(
            "failed to run '{program}' (is 'setcap' installed? on Debian: \
             'sudo apt install libcap2-bin'): {e}"
        )
    })?;

    if !status.success() {
        bail!("setcap failed (exit {:?}) on {}", status.code(), exe);
    }

    tracing::info!(
        "Granted {} on {} — live capture now works without sudo",
        CAPTURE_CAPS,
        exe
    );
    Ok(())
}

/// On non-Linux platforms, file capabilities don't exist; the equivalent is
/// running under sudo (or a BPF-device group on macOS).
#[cfg(not(target_os = "linux"))]
pub fn setup_capabilities() -> Result<()> {
    bail!(
        "--setup-caps is Linux-only (setcap / file capabilities are not available \
         on this platform). Run sipnab under sudo for live capture instead."
    )
}

/// Whether a secret file may be read, by OpenSSH's rule for private keys.
///
/// Refused only when the file is a regular file owned by the user running
/// sipnab AND any group or other permission bit is set. So:
///
/// - `chmod 644` or `chmod 640` on your own file is refused. Other users can
///   read it.
/// - A file another user owns is accepted whatever its mode: a Kubernetes
///   secret mount is `root 0644`, and a systemd credential is `0400` with an
///   ACL. Its owner decided who reads it.
/// - A pipe, a FIFO or a device is accepted: `<(pass show pcaps)` and
///   `/dev/stdin` stat as a pipe, and a pipe's mode says nothing about who
///   can read what passes through it.
///
/// The one copy of this rule. The archive password file and the vCon
/// forwarder's auth file both reach it through [`open_private_file`].
///
/// Returns the refusal's text, naming the mode, or `None` to proceed.
#[must_use]
pub fn permission_refusal(owner: u32, me: u32, mode: u32, regular: bool) -> Option<String> {
    if regular && owner == me && mode & 0o077 != 0 {
        return Some(format!(
            "can be read or written by other users (mode {:04o}); chmod 600 it",
            mode & 0o7777
        ));
    }
    None
}

/// The user running this process.
#[cfg(unix)]
#[must_use]
pub fn current_uid() -> u32 {
    // SAFETY: getuid takes no arguments, cannot fail, and touches no memory.
    unsafe { libc::getuid() }
}

/// Open a file that holds a secret, after [`permission_refusal`].
///
/// The check is made on the descriptor that is returned, not on the path, so
/// nothing can swap the file between the check and the read.
///
/// # Arguments
///
/// * `path` — the secret file.
/// * `what` — the flag that named it, quoted at the start of every error.
///
/// # Errors
///
/// When the file cannot be opened or stat'd, or fails [`permission_refusal`].
/// The text names the path and the mode, never the contents.
pub fn open_private_file(path: &std::path::Path, what: &str) -> Result<std::fs::File, String> {
    let shown = path.display();
    let file = std::fs::File::open(path).map_err(|e| format!("{what} '{shown}': {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = file
            .metadata()
            .map_err(|e| format!("{what} '{shown}': {e}"))?;
        if let Some(why) = permission_refusal(
            meta.uid(),
            current_uid(),
            meta.mode(),
            meta.file_type().is_file(),
        ) {
            return Err(format!("{what} '{shown}' {why}"));
        }
    }
    Ok(file)
}

/// The bytes of a secret file, at most `limit` of them, by
/// [`permission_refusal`]: [`open_private_file`]'s rule, for a file that may
/// have been read before the privilege drop.
///
/// A file in the advance read (`crate::secret_files`) is judged by the owner
/// and mode it had then, against the user this process runs as NOW. After a
/// root run's drop that is the dropped user, which is who used to open the
/// file itself, so the advance read changes no verdict: a file the dropped
/// user owns with group or other bits is still refused, and a root-only
/// (`0600`) file, which the dropped user could not open, is now read
/// (OPS-11). Any other file is opened now, by [`open_private_file`].
///
/// # Errors
///
/// As [`open_private_file`], or the error the advance read met, with the
/// same text. Never the contents.
pub fn read_private_file(
    path: &std::path::Path,
    what: &str,
    limit: u64,
) -> Result<Vec<u8>, String> {
    use std::io::Read as _;
    let shown = path.display();
    #[cfg(unix)]
    if let Some(found) = crate::secret_files::advance(path) {
        let found = found.map_err(|e| format!("{what} '{shown}': {e}"))?;
        if let Some(why) = permission_refusal(found.owner, current_uid(), found.mode, true) {
            return Err(format!("{what} '{shown}' {why}"));
        }
        let mut bytes = found.bytes;
        bytes.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
        return Ok(bytes);
    }
    let file = open_private_file(path, what)?;
    let mut bytes = Vec::new();
    file.take(limit)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("{what} '{shown}': {e}"))?;
    Ok(bytes)
}

/// Check if the current process is running as root (UID 0).
pub fn is_root() -> bool {
    // SAFETY: getuid() is always safe — it reads kernel state and cannot fail.
    unsafe { libc::getuid() == 0 }
}

/// Whether key material is resident in unswappable memory, and why not.
///
/// Reported rather than assumed: the limit that governs this (`RLIMIT_MEMLOCK`)
/// is commonly 64 KiB on stock systems, so "we tried" and "it worked" are
/// genuinely different outcomes and the operator has to be able to tell them
/// apart. Claiming hardening that did not happen is the failure mode
/// [`disable_core_dumps`] was rewritten to remove.
#[derive(Debug, PartialEq, Eq)]
pub enum MemoryLock {
    /// Pages are locked; key material cannot be written to swap.
    Locked,
    /// Pages are NOT locked, for this reason.
    Unlocked(String),
}

/// Lock this process's pages into RAM so key material cannot reach swap.
///
/// `zeroize` clears a secret from memory when it is dropped. It cannot clear a
/// copy the kernel already wrote to the swap device, which persists after the
/// process exits and is readable by anyone who can read that device or a later
/// forensic image — a weaker attacker than the one `PR_SET_DUMPABLE` defends
/// against, who needs root and live ptrace. `disable_core_dumps` exists because
/// "a crash writes those keys to a file on disk"; swap writes them to disk with
/// no crash required, which is the same exposure by a quieter route.
///
/// `MCL_FUTURE` as well as `MCL_CURRENT`, because the secrets that matter are
/// read from the key log AFTER this runs.
///
/// Not fatal on failure, unlike core dumps. `RLIMIT_MEMLOCK` is an environment
/// property an operator often cannot change, and refusing to capture at all
/// would trade a confidentiality control the deployment may not need for the
/// availability it definitely does. The outcome is returned so the caller can
/// say plainly which of the two happened.
pub fn lock_key_memory() -> MemoryLock {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: mlockall takes a flags word and touches no memory we own.
        let rc = unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) };
        memory_lock_outcome(if rc == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        MemoryLock::Unlocked("locking pages is implemented on Linux only".to_string())
    }
}

/// What an `mlockall` result means for the operator.
///
/// Separate from [`lock_key_memory`] because which branch a given host takes
/// depends on its `RLIMIT_MEMLOCK`, so a test of the call alone can only ever
/// see one of them.
#[cfg(target_os = "linux")]
fn memory_lock_outcome(result: std::io::Result<()>) -> MemoryLock {
    match result {
        Ok(()) => MemoryLock::Locked,
        Err(err) => MemoryLock::Unlocked(format!(
            "mlockall failed: {err}. Key material can be written to swap, where \
             it outlives this process and zeroize cannot reach it. Raise \
             RLIMIT_MEMLOCK (ulimit -l, or LimitMEMLOCK= in the systemd unit)."
        )),
    }
}

/// Disable core dumps to protect sensitive key material in memory.
///
/// When decryption keys (TLS, SRTP, DTLS) are loaded, a core dump could
/// expose them. This function prevents that by disabling dumpability on
/// Linux (`PR_SET_DUMPABLE`) or zeroing the core file size limit on macOS
/// (`RLIMIT_CORE`).
///
/// # Why a failure here is fatal
///
/// It used to warn and return `Ok(())`, and then log "Core dumps disabled
/// (decryption active)" whether or not the syscall had done anything — so a
/// refused `PR_SET_DUMPABLE` produced a warning AND a confident success line,
/// and the caller's `exit(1)` could never be reached. An operator reading that
/// log could not tell hardening from its absence.
///
/// The caller already treats an error as fatal, and that is the right reading:
/// this runs only when TLS/SRTP/DTLS key material has been loaded into this
/// process, and only when the operator did NOT pass `--allow-coredump`. Both
/// halves of that condition are explicit requests. Continuing anyway means a
/// later crash writes those keys to a file on disk that any local user with
/// the right permissions can read — silently, long after the run that failed
/// to harden itself has been forgotten. `--allow-coredump` is the escape hatch
/// for anyone who has decided that trade is fine.
///
/// # Errors
///
/// The `prctl` (Linux) or `setrlimit` (macOS) failing, or being built for a
/// platform with neither.
pub fn disable_core_dumps() -> Result<()> {
    if let Err(e) = make_undumpable() {
        bail!(
            "{e}. Decryption keys are resident in this process and a crash \
             would write them to a core file; pass --allow-coredump to run anyway"
        );
    }
    tracing::info!("Core dumps disabled (decryption active)");
    Ok(())
}

/// Make this process undumpable: `PR_SET_DUMPABLE` on Linux, a zero
/// `RLIMIT_CORE` on macOS.
///
/// The mechanism alone, without [`disable_core_dumps`]'s reason or its log
/// line. The scanner-kill worker process needs it too, and holds no key
/// material: it is undumpable so no other process of the same user can take
/// its send descriptors through `/proc/<pid>/fd` or `ptrace`, and a message
/// about decryption would describe a process that is not decrypting anything.
///
/// # Errors
///
/// The `prctl` (Linux) or `setrlimit` (macOS) failing, or being built for a
/// platform with neither. The message names the call.
pub fn make_undumpable() -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: prctl with PR_SET_DUMPABLE is a simple flag toggle;
        // the trailing arguments are unused but required by the syscall ABI.
        unsafe {
            if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
                let e = std::io::Error::last_os_error();
                return Err(std::io::Error::new(
                    e.kind(),
                    format!("prctl(PR_SET_DUMPABLE, 0) failed: {e}"),
                ));
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        // SAFETY: setrlimit with RLIMIT_CORE and a zeroed rlimit struct
        // disables core dumps. The struct is valid for the duration of the call.
        unsafe {
            let rlimit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::setrlimit(libc::RLIMIT_CORE, &rlimit) != 0 {
                let e = std::io::Error::last_os_error();
                return Err(std::io::Error::new(
                    e.kind(),
                    format!("setrlimit(RLIMIT_CORE, 0) failed: {e}"),
                ));
            }
        }
    }

    // Neither arm compiled in: nothing was done, so nothing may be claimed.
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    return Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "making a process undumpable is not implemented for this platform",
    ));

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Ok(())
}

/// Resolve a username to its UID and primary GID via the system password database.
///
/// Uses the reentrant `getpwnam_r` (caller-owned `passwd` + scratch buffer)
/// rather than `getpwnam`, which returns a pointer into a shared static buffer
/// that a concurrent `getpwnam`/`getpwuid` on another thread can overwrite
/// between the lookup and reading the fields. Production resolution happens once
/// at single-threaded startup, but the reentrant call is correct regardless.
fn resolve_user(username: &str) -> Result<(u32, u32)> {
    // Initial scratch-buffer size for the string fields; grow on ERANGE.
    // SAFETY: `sysconf` takes no pointers and only reads a system constant.
    let initial: usize = match unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) } {
        n if n > 0 => n as usize,
        _ => 16_384,
    };
    resolve_user_with_buffer(username, initial)
}

/// [`resolve_user`], starting from a scratch buffer of `initial` bytes.
///
/// The starting size is an argument because it comes from `sysconf`, and on
/// every real host it is large enough that the ERANGE growth below never runs.
/// A test hands in one byte to prove the growth does.
fn resolve_user_with_buffer(username: &str, initial: usize) -> Result<(u32, u32)> {
    let c_user = std::ffi::CString::new(username)
        .map_err(|_| anyhow::anyhow!("Username '{}' contains a null byte", username))?;

    let mut buf_len = initial;

    loop {
        // SAFETY: `libc::passwd` is a plain-old-data C struct for which
        // all-zero bytes is a valid (if meaningless) value; `getpwnam_r`
        // below overwrites it before any field is read.
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut buf = vec![0 as libc::c_char; buf_len];
        let mut result: *mut libc::passwd = std::ptr::null_mut();

        // SAFETY: `getpwnam_r` writes the entry into our owned `pwd` and the
        // string fields into our owned `buf`; on success `result` is set to
        // `&pwd`. We copy out only the scalar uid/gid before `pwd` drops.
        //
        // `_r` makes this reentrant with respect to its own buffers, but that
        // is NOT the same as being safe to call first from a multithreaded
        // process: the FIRST such call in a process makes glibc `dlopen` the
        // NSS backends from `/etc/nsswitch.conf`, and that loader work can
        // deadlock against concurrent thread creation. See `nss_preload` in
        // this file's test module. In production this call happens during
        // privilege drop, before any thread is spawned, which is why the
        // deadlock has only ever been seen in the test harness.
        let ret = unsafe {
            libc::getpwnam_r(
                c_user.as_ptr(),
                &mut pwd,
                buf.as_mut_ptr(),
                buf_len,
                &mut result,
            )
        };

        if ret == libc::ERANGE && buf_len < (1 << 20) {
            buf_len *= 2; // buffer too small — retry larger
            continue;
        }
        // "Not found" arrives two ways, both POSIX-sanctioned: glibc's files
        // backend returns 0 with a null result, while NSS modules such as
        // sss/systemd surface ENOENT (or ESRCH) as the return value.
        if result.is_null() && (ret == 0 || ret == libc::ENOENT || ret == libc::ESRCH) {
            bail!(
                "User '{}' not found. Create it with \
                 'useradd -r -s /usr/sbin/nologin {}' or use --user <name>",
                username,
                username
            );
        }
        if ret != 0 {
            bail!(
                "Failed to resolve user '{}': {}",
                username,
                std::io::Error::from_raw_os_error(ret)
            );
        }
        return Ok((pwd.pw_uid, pwd.pw_gid));
    }
}

/// Surrender the group credentials: supplementary list first, then the GID.
///
/// # Why these are one function and not two calls
///
/// The order is load-bearing, and on macOS it is load-bearing in a way that is
/// invisible from the call site. Splitting them, or swapping them, produces a
/// process that reads as unprivileged and is not — so the sequence is expressed
/// as one operation that cannot be performed out of order rather than as two
/// steps with a comment asking the next reader to keep them in line.
///
/// On **Linux**, `setgroups(0, NULL)` empties the supplementary list, and
/// `setgid` afterwards sets the real and effective GID. Either order would end
/// in the same state, so nothing here is obvious.
///
/// On **macOS it is not**. Darwin stores the effective GID as element zero of
/// the group vector — `bsd/sys/ucred.h` carries `#define cr_gid cr_groups[0]`
/// — and `setgroups_internal()` refuses to leave that vector empty:
///
/// ```text
/// if (ngrp < 1) { ngrp = 1; newgroups[0] = 0; }
/// ```
///
/// So `setgroups(0, NULL)` on macOS does **not** clear the list. It writes a
/// list of exactly one entry whose value is GID 0 — wheel. The immediately
/// following `setgid` is what overwrites that entry, via
/// `kauth_cred_change_egid()`. Reverse the two and a macOS process finishes the
/// drop holding **egid 0 while its uid reads `nobody`**: root by group, wearing
/// an unprivileged uid.
///
/// This is also why `getgroups()` reports 1 rather than 0 on macOS after a
/// correct drop — that one entry is the new egid, which POSIX explicitly allows
/// an implementation to include in the list.
///
/// # Measured, not merely read
///
/// Confirmed on a real macOS host, 2026-08-05, by a probe performing this exact
/// sequence as root:
///
/// ```text
/// before setgroups:         ngroups=16  egid=0           list=[0 1 2 3 4 5 8 ...]
/// after setgroups(0,NULL):  ngroups=1   egid=0           list=[0]
/// after setgid(nobody):     ngroups=1   egid=4294967294  list=[4294967294]
/// after setuid(nobody):     ngroups=1   egid=4294967294  list=[4294967294]
/// ```
///
/// Two things that reading the source alone would have left as inference. The
/// second line shows the call writing GID 0 rather than emptying the vector.
/// The third shows `setgid` CHANGING THE LIST — which is the `cr_gid` aliasing
/// demonstrated rather than quoted, and the reason reversing these two would
/// leave the process at egid 0 with an unprivileged uid.
///
/// Note also that `nobody` is GID 4294967294 there and 65534 on Linux, so the
/// tests resolve the account rather than hard-coding either.
///
/// # Errors
///
/// Either syscall failing, named individually. Neither is advisory: a process
/// that could not shed its groups must not continue as though it had.
fn drop_group_credentials(gid: u32) -> Result<()> {
    drop_supplementary_groups()?;
    set_gid(gid)?;
    Ok(())
}

/// Clear the supplementary group list.
///
/// Call this through [`drop_group_credentials`], never directly: on macOS this
/// call leaves GID 0 in the group vector and only the `setgid` that follows
/// removes it. See that function for the citation.
fn drop_supplementary_groups() -> Result<()> {
    // SAFETY: a null pointer is valid when ngroups is 0. What the call MEANS is
    // platform-specific — an empty list on Linux, a one-entry list holding GID 0
    // on Darwin — but neither reads nor writes memory through the pointer.
    unsafe {
        if libc::setgroups(0, std::ptr::null()) != 0 {
            bail!("setgroups failed: {}", std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Set the real and effective GID.
fn set_gid(gid: u32) -> Result<()> {
    // SAFETY: setgid changes the process group ID. We call it while still
    // running as root (before dropping UID), so it has permission to succeed.
    unsafe {
        if libc::setgid(gid) != 0 {
            bail!(
                "setgid({}) failed: {}",
                gid,
                std::io::Error::last_os_error()
            );
        }
    }
    Ok(())
}

/// Set the real and effective UID.
fn set_uid(uid: u32) -> Result<()> {
    // SAFETY: setuid changes the process user ID. After this call, the
    // process permanently loses root privileges (on Linux, all saved-set
    // UIDs are also changed when called by root).
    unsafe {
        if libc::setuid(uid) != 0 {
            bail!(
                "setuid({}) failed: {}",
                uid,
                std::io::Error::last_os_error()
            );
        }
    }
    Ok(())
}

/// Give up, for the rest of this process's life, the ability to gain
/// privileges through `execve` — Linux `PR_SET_NO_NEW_PRIVS`.
///
/// # Why this is not part of `drop_privileges`
///
/// It has no precondition. `drop_privileges` has two, and both are early
/// returns: `--no-priv-drop`, and "this process is not root, so there is
/// nothing to shed". Setting the flag from inside that function meant it was
/// set only on the branch that reached the bottom — so `sipnab --setup-caps`,
/// the install the documentation recommends, ran a whole capture without it.
/// That install grants `cap_net_raw,cap_net_admin+ep` on the binary and runs
/// as an ordinary user, so there is no uid to drop and this flag is the ONLY
/// thing between a bug in the parser and a setuid binary on the filesystem.
///
/// So it is called once, unconditionally, from the top of the run, and the
/// function that drops uids is left doing only that.
///
/// # What it does and does not stop
///
/// It stops `execve` GRANTING privilege: setuid and setgid bits are ignored,
/// as are file capabilities, and the flag is inherited by every child. It does
/// not block `execve` itself, does not affect this process's own capabilities
/// (file capabilities are applied at the exec that started it, before this
/// call), and cannot be undone.
///
/// Event hooks (`--on-dialog-exec`, `--on-quality-exec`, `--alert-exec`) run
/// under it, so a hook that relies on a setuid helper — `sudo`, `ping` — will
/// find that helper unprivileged. That was already true of every run started
/// as root, which is the deployment those hooks were written against; this
/// call extends it to the unprivileged install. A hook needing privilege must
/// get it some other way (a socket to a privileged daemon, `systemd-run`,
/// or a service the hook talks to rather than becomes).
///
/// # Errors
///
/// Returns an error when the flag could not be set. The caller decides what
/// that is worth: sipnab's own startup warns and continues, because a `prctl`
/// that old kernels lack is not a reason to refuse to capture. What it must
/// not do — and what this function used to do — is report success.
///
/// On platforms other than Linux there is no equivalent mechanism, and this is
/// a no-op that says so rather than claiming to have hardened anything.
pub fn block_privilege_escalation() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        // Before the flag is set, so the status the process started with
        // survives for the permission hint (`status_before_block`).
        let _ = STATUS_BEFORE_BLOCK.set(std::fs::read_to_string("/proc/self/status").ok());
        set_no_new_privs()?;
        tracing::debug!("PR_SET_NO_NEW_PRIVS set: exec can no longer grant privileges");
    }

    #[cfg(not(target_os = "linux"))]
    tracing::debug!(
        "no execve privilege-escalation block on this platform \
         (PR_SET_NO_NEW_PRIVS is Linux-only); a setuid binary exec'd from here \
         still gains its owner's privileges"
    );

    Ok(())
}

/// `/proc/self/status` as it read before [`block_privilege_escalation`] set
/// `NoNewPrivs` on this process; `None` inside when it could not be read.
static STATUS_BEFORE_BLOCK: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();

/// This process's `/proc/self/status` as it started: before
/// [`block_privilege_escalation`] set `NoNewPrivs`, or now when it has not.
///
/// The permission hint of a refused capture reads `NoNewPrivs` to tell an
/// operator that systemd's `NoNewPrivileges=yes` made file capabilities
/// ineffective. sipnab sets the flag on itself at startup, before the
/// capture opens, so the status read when the capture failed always says
/// `NoNewPrivs: 1` and cannot tell the two apart.
///
/// # Side effects
///
/// Reads `/proc/self/status` when no status was recorded.
#[must_use]
pub fn status_before_block() -> Option<String> {
    status_for_hint(STATUS_BEFORE_BLOCK.get().cloned(), || {
        std::fs::read_to_string("/proc/self/status").ok()
    })
}

/// [`status_before_block`] with its inputs as arguments: the status
/// `recorded` before the block, if one was recorded, else `current`.
fn status_for_hint(
    recorded: Option<Option<String>>,
    current: impl FnOnce() -> Option<String>,
) -> Option<String> {
    recorded.unwrap_or_else(current)
}

/// Set the `PR_SET_NO_NEW_PRIVS` flag to prevent regaining privileges via
/// exec of setuid/setgid binaries (Linux only).
///
/// Reads the flag back with `PR_GET_NO_NEW_PRIVS` rather than trusting the
/// return code. The two are not the same claim: one says the syscall was
/// accepted, the other says the process is actually carrying the flag, and it
/// is the second that the rest of this module's guarantees rest on. One extra
/// syscall, once per run.
///
/// # Errors
///
/// The `prctl` failing, or the flag reading back clear afterwards.
#[cfg(target_os = "linux")]
fn set_no_new_privs() -> Result<()> {
    // SAFETY: prctl with PR_SET_NO_NEW_PRIVS is a one-way flag —
    // once set, it cannot be unset. Trailing args are unused.
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            bail!(
                "prctl(PR_SET_NO_NEW_PRIVS, 1) failed: {}",
                std::io::Error::last_os_error()
            );
        }
    }
    // SAFETY: the read form takes no pointers and cannot fail for a flag the
    // kernel just accepted; a negative return is treated as "not set" below.
    let readback = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
    if readback != 1 {
        bail!(
            "prctl(PR_SET_NO_NEW_PRIVS, 1) reported success but the flag reads \
             back as {readback}, so exec can still grant privileges"
        );
    }
    Ok(())
}

/// Chroot to the specified directory after initialization.
///
/// After `chroot()`, the process calls `chdir("/")` so that the working
/// directory is relative to the new root. This should be called after
/// capture devices and key files are opened but before packet processing.
///
/// # Errors
///
/// Returns an error if `chroot()` or `chdir("/")` fails.
pub fn do_chroot(dir: &std::path::Path) -> Result<()> {
    let dir_str = dir
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("chroot path is not valid UTF-8"))?;
    let dir_c = std::ffi::CString::new(dir_str)
        .map_err(|_| anyhow::anyhow!("chroot path contains null byte"))?;

    // SAFETY: chroot changes the root directory of the process. The CString
    // is valid for the duration of the call.
    unsafe {
        if libc::chroot(dir_c.as_ptr()) != 0 {
            bail!(
                "chroot({}) failed: {}",
                dir.display(),
                std::io::Error::last_os_error()
            );
        }
        if libc::chdir(c"/".as_ptr()) != 0 {
            bail!(
                "chdir(/) after chroot failed: {}",
                std::io::Error::last_os_error()
            );
        }
    }

    tracing::info!("Chrooted to {}", dir.display());
    Ok(())
}

/// Verify that the process is now running with the expected UID and GID.
fn verify_dropped(expected_uid: u32, expected_gid: u32) -> Result<()> {
    // SAFETY: getuid/getgid/geteuid/getegid are always safe read-only syscalls.
    let held = unsafe {
        (
            libc::getuid(),
            libc::getgid(),
            libc::geteuid(),
            libc::getegid(),
        )
    };
    check_dropped_ids(expected_uid, expected_gid, held)
}

/// The comparison [`verify_dropped`] makes, with the ids the kernel reported
/// — `(uid, gid, euid, egid)` — as an argument.
///
/// Separate because the case it exists for cannot be produced on demand: real
/// ids dropped with effective ids left behind needs a setuid binary or a
/// broken drop, and the test suite has neither. With the ids as input, every
/// divergence can be handed in and each refusal checked.
fn check_dropped_ids(
    expected_uid: u32,
    expected_gid: u32,
    (actual_uid, actual_gid, euid, egid): (u32, u32, u32, u32),
) -> Result<()> {
    if actual_uid != expected_uid || actual_gid != expected_gid {
        bail!(
            "Privilege drop verification failed: expected uid={}/gid={}, got uid={}/gid={}",
            expected_uid,
            expected_gid,
            actual_uid,
            actual_gid
        );
    }

    // The EFFECTIVE ids decide what the kernel permits, and they are what an
    // attacker who gets code execution inherits.
    //
    // `setuid()` called by root sets real, effective and saved together, so
    // with the current sequence this cannot diverge — which is exactly why it
    // is worth asserting rather than assuming. The check costs two syscalls
    // once per process, and it is the line that would catch a future edit
    // switching to `setresuid`, adding a `seteuid` step, or reordering the
    // drop. A privilege drop that silently half-happened would leave every
    // parser in this program running with more authority than it was ever
    // meant to have.
    if euid != expected_uid || egid != expected_gid {
        bail!(
            "Privilege drop verification failed: real ids are correct but \
             EFFECTIVE ids are not — expected euid={}/egid={}, got euid={}/egid={}. \
             The process still holds privileges it was asked to give up.",
            expected_uid,
            expected_gid,
            euid,
            egid
        );
    }
    Ok(())
}

/// Load every configured NSS backend before the test harness spawns a thread.
///
/// The first `getpwnam_r` in a process makes glibc `dlopen` the modules named
/// in `/etc/nsswitch.conf`. When that happens on a process that is ALREADY
/// multithreaded, `dl_open_worker` reaches `update_tls_slotinfo`, which waits
/// for every thread to arrive at a safe point — while those threads may
/// themselves be blocked inside the dynamic loader on the very lock this
/// `dlopen` holds. The process then deadlocks with every thread sleeping at
/// roughly 0% CPU, which looks like a hang with no cause.
///
/// This is not hypothetical. The suite wedged twice — once for twenty minutes,
/// once left running for over a day — and a live capture showed ten of fourteen
/// threads in `futex_wait` on `_rtld_global`, with the holder inside
/// `_dl_open("libnss_sss.so.2")`, called from
/// `tests::resolve_user_nonexistent_returns_error` below.
///
/// Running before `main` removes the race rather than narrowing it: the loader
/// work happens on the initial thread, when no other thread exists to wait for.
///
/// **The probe name must not resolve.** A lookup that succeeds short-circuits
/// the nsswitch chain at the first backend that answers, leaving every later
/// module unloaded and the race exactly as it was.
///
/// Test builds only. A library has no business doing work at load time, and
/// production resolves users during privilege drop, before any thread exists.
#[cfg(all(test, target_os = "linux"))]
mod nss_preload {
    /// Walks the whole nsswitch chain for a name nothing can resolve.
    ///
    /// Errors are deliberately ignored: the lookup is expected to fail, and the
    /// only thing being bought is the module load it performs on the way.
    ///
    /// # Safety
    ///
    /// Only the dynamic loader may call it, through the `.init_array` entry
    /// below, once, on the initial thread before `main`, when no other thread
    /// exists. Called later from Rust, `getpwnam_r` would race the threads that
    /// the test harness has started, which is the deadlock this exists to avoid.
    unsafe extern "C" fn preload_nss_backends() {
        let probe = c"sipnab-nss-preload-definitely-absent";
        // SAFETY: `libc::passwd` is a plain-old-data C struct of scalars and
        // raw pointers, for which all-zero bytes is a valid (if meaningless)
        // value. `getpwnam_r` below overwrites it before any field is read,
        // and no field is read here at all.
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut buf = [0 as libc::c_char; 1024];
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: called by the dynamic loader on the initial thread before
        // `main`, so nothing else can observe or race these locals. `pwd` and
        // `buf` are owned here and outlive the call; `getpwnam_r` writes only
        // into them and into `result`. A zeroed `libc::passwd` is valid POD
        // input, and the return value is intentionally discarded.
        unsafe {
            libc::getpwnam_r(
                probe.as_ptr(),
                &mut pwd,
                buf.as_mut_ptr(),
                buf.len(),
                &mut result,
            );
        }
    }

    /// ELF `.init_array`: run by the loader before `main`. This is the same
    /// mechanism the `ctor` crate provides, written directly to avoid adding a
    /// dependency for six lines.
    #[used]
    #[unsafe(link_section = ".init_array")]
    static PRELOAD_NSS: unsafe extern "C" fn() = preload_nss_backends;
}

#[cfg(test)]
mod tests {
    //! Privilege-drop no-op paths, user resolution, chroot failure, and the
    //! `setcap` command-shape tests (none of which require root).
    use super::*;

    type TestError = Box<dyn std::error::Error>;

    /// A root run with a drop user drops: no reason to skip.
    #[cfg(not(target_os = "macos"))]
    #[test]
    fn a_root_run_with_a_user_is_not_skipped() {
        assert_eq!(
            drop_skip(Some("nobody"), false, true),
            None,
            "root with a user drops"
        );
        assert_eq!(
            drop_skip(None, false, true),
            None,
            "root drops to the default user"
        );
    }

    /// A run that is not root has nothing to drop.
    #[test]
    fn a_run_that_is_not_root_skips_the_drop_as_not_root() {
        assert_eq!(
            drop_skip(Some("nobody"), false, false),
            Some(DropSkip::NotRoot),
            "not root, nothing to drop"
        );
    }

    /// `--no-priv-drop` is the reason given whether or not the run is root,
    /// and `drop_is_skipped` agrees with `drop_skip` on every input.
    #[test]
    fn no_priv_drop_is_the_reason_before_root_is_asked() {
        assert_eq!(
            drop_skip(None, true, true),
            Some(DropSkip::Disabled),
            "--no-priv-drop as root"
        );
        assert_eq!(
            drop_skip(None, true, false),
            Some(DropSkip::Disabled),
            "--no-priv-drop is named before not-root"
        );
        for user in [None, Some("nobody")] {
            for no_drop in [false, true] {
                for root in [false, true] {
                    assert_eq!(
                        drop_is_skipped(user, no_drop, root),
                        drop_skip(user, no_drop, root).is_some(),
                        "{user:?} {no_drop} {root}"
                    );
                }
            }
        }
    }

    /// The status recorded before the block wins over the current one, which
    /// says `NoNewPrivs: 1` because sipnab set it.
    #[test]
    fn the_hint_reads_the_status_recorded_before_the_block() {
        let got = super::status_for_hint(Some(Some("NoNewPrivs:\t0\n".into())), || {
            Some("NoNewPrivs:\t1\n".into())
        });
        assert_eq!(
            got.as_deref(),
            Some("NoNewPrivs:\t0\n"),
            "the recorded status wins"
        );
    }

    /// Nothing recorded (a caller that never blocked): the current status
    /// is the truth, because nothing in this process changed it.
    #[test]
    fn without_a_recorded_status_the_hint_reads_the_current_one() {
        let got = super::status_for_hint(None, || Some("NoNewPrivs:\t1\n".into()));
        assert_eq!(
            got.as_deref(),
            Some("NoNewPrivs:\t1\n"),
            "nothing recorded: the current status"
        );
    }

    /// A status that could not be read before the block stays unread: the
    /// current one would carry the flag sipnab set, so it is no substitute.
    #[test]
    fn an_unreadable_recorded_status_is_not_replaced_by_the_current_one() {
        let got = super::status_for_hint(Some(None), || Some("NoNewPrivs:\t1\n".into()));
        assert_eq!(got, None, "an unreadable recorded status stays unread");
    }
    /// A secret file you own that your group or other users can read is
    /// refused, naming the mode, and the same file at 0600 opens. This is the
    /// one rule every secret file sipnab reads goes through.
    #[cfg(unix)]
    #[test]
    fn an_own_group_readable_secret_file_is_refused_and_a_private_one_opens()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("secret");
        std::fs::write(&path, "Authorization: Bearer x\n")?;
        for mode in [0o640, 0o604, 0o644] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))?;
            match open_private_file(&path, "--some-secret-file") {
                Ok(_) => return Err(format!("mode {mode:o} was accepted").into()),
                Err(e) => assert!(
                    e.starts_with("--some-secret-file '")
                        && e.contains(&format!("(mode {mode:04o})"))
                        && e.contains("chmod 600"),
                    "{e}"
                ),
            }
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        assert!(open_private_file(&path, "--some-secret-file").is_ok());
        Ok(())
    }

    /// A normal (non-root) test process reports `is_root() == false`.
    #[test]
    fn is_root_returns_false_for_normal_user() -> Result<(), TestError> {
        // CI and dev machines run as non-root
        assert!(!is_root());
        Ok(())
    }

    /// The drop is skipped when `--no-priv-drop` is set or the process is not
    /// root, whatever user was named; a root process with a named user drops.
    #[test]
    fn the_drop_is_skipped_only_by_the_flag_or_a_non_root_process() -> Result<(), TestError> {
        assert!(drop_is_skipped(Some("nobody"), true, true));
        assert!(drop_is_skipped(Some("nobody"), false, false));
        assert!(drop_is_skipped(None, true, false));
        assert!(!drop_is_skipped(Some("nobody"), false, true));
        Ok(())
    }

    /// A root process with no `--user` drops to the default user on Linux;
    /// on macOS it keeps root, so CoreAudio keeps its per-user session.
    #[test]
    fn a_root_process_without_a_user_drops_except_on_macos() -> Result<(), TestError> {
        assert_eq!(
            drop_is_skipped(None, false, true),
            cfg!(target_os = "macos")
        );
        Ok(())
    }

    /// `no_priv_drop == true` returns `Ok` without touching any syscall.
    #[test]
    fn no_priv_drop_flag_skips_immediately() -> Result<(), TestError> {
        // Should return Ok without touching any syscalls
        assert!(drop_privileges(None, true).is_ok());
        Ok(())
    }

    /// When not root, `drop_privileges` is a no-op that returns `Ok`.
    #[test]
    fn non_root_skips_privilege_drop() -> Result<(), TestError> {
        // When not root, drop_privileges is a no-op
        assert!(drop_privileges(None, false).is_ok());
        Ok(())
    }

    /// A drop that did not happen records no user, so an output-file error
    /// never blames a privilege drop that never ran. The recording side needs
    /// root to reach (`set_uid`); a non-root test process cannot drive it.
    #[test]
    fn a_skipped_drop_records_no_user() -> Result<(), TestError> {
        if is_root() {
            stderr_line!("skipped: running as root, a drop would really happen");
            return Ok(());
        }
        assert!(drop_privileges(None, true).is_ok());
        assert!(drop_privileges(Some("nobody"), false).is_ok());
        assert_eq!(dropped_to(), None);
        Ok(())
    }

    /// `nobody` resolves to a non-zero uid or gid on Linux and macOS.
    #[test]
    fn resolve_user_nobody_succeeds() -> Result<(), TestError> {
        // "nobody" exists on both Linux and macOS
        let (uid, gid) =
            resolve_user("nobody").map_err(|e| format!("nobody user should exist: {e:?}"))?;
        // On macOS nobody is typically uid 65534, on Linux it varies,
        // but it should always be non-zero
        assert!(uid > 0 || gid > 0, "nobody should have non-zero uid or gid");
        Ok(())
    }

    /// An unknown username errors with a "not found" message suggesting
    /// `--user`.
    #[test]
    fn resolve_user_nonexistent_returns_error() -> Result<(), TestError> {
        let result = resolve_user("nonexistent_user_xyz123");
        assert!(result.is_err());
        let msg = result.err().ok_or("expected an error, got Ok")?.to_string();
        assert!(
            msg.contains("not found"),
            "Error should mention 'not found', got: {msg}"
        );
        assert!(
            msg.contains("--user"),
            "Error should suggest --user flag, got: {msg}"
        );
        Ok(())
    }

    /// Locking must actually lock, not merely return success.
    ///
    /// Asserts the EFFECT the kernel reports — `VmLck` in `/proc/self/status`
    /// counts kilobytes this process has pinned — rather than the return value,
    /// because a function that returns `Locked` while pinning nothing is
    /// exactly the "claims hardening it did not do" failure this is meant to
    /// close. Skips rather than fails where `RLIMIT_MEMLOCK` forbids it, since
    /// that is an environment limit and not a defect: the point is that a
    /// SUCCESSFUL return implies pinned pages.
    #[cfg(target_os = "linux")]
    #[test]
    fn locking_key_memory_pins_pages_the_kernel_reports() -> Result<(), TestError> {
        fn vmlck_kb() -> u64 {
            std::fs::read_to_string("/proc/self/status")
                .ok()
                .and_then(|s| {
                    s.lines()
                        .find(|l| l.starts_with("VmLck:"))
                        .and_then(|l| l.split_whitespace().nth(1)?.parse().ok())
                })
                .unwrap_or(0)
        }

        let before = vmlck_kb();
        match lock_key_memory() {
            MemoryLock::Locked => {
                let after = vmlck_kb();
                assert!(
                    after > before,
                    "lock_key_memory reported Locked but the kernel pinned nothing \
                     (VmLck {before} kB -> {after} kB); key material could still \
                     reach swap"
                );
                // SAFETY: releasing what this test pinned; no memory is freed.
                unsafe { libc::munlockall() };
            }
            MemoryLock::Unlocked(reason) => {
                assert!(
                    reason.contains("RLIMIT_MEMLOCK") || reason.contains("mlockall"),
                    "a refusal must name what to change, not just fail: {reason}"
                );
            }
        }
        Ok(())
    }

    /// `disable_core_dumps` never panics regardless of permission outcome.
    #[test]
    fn disable_core_dumps_does_not_panic() -> Result<(), TestError> {
        // May or may not succeed depending on permissions, but must not panic
        let _ = disable_core_dumps();
        Ok(())
    }

    /// `root` resolves to uid 0.
    #[test]
    fn resolve_user_root_is_uid_zero() -> Result<(), TestError> {
        let (uid, _gid) = resolve_user("root").map_err(|e| format!("root should exist: {e:?}"))?;
        assert_eq!(uid, 0, "root must resolve to uid 0");
        Ok(())
    }

    /// As non-root, requesting a target user is still a no-op `Ok`.
    #[test]
    fn drop_privileges_with_target_user_non_root_is_noop() -> Result<(), TestError> {
        // As a non-root process, requesting a target user is still a no-op Ok
        // (the actual setuid path requires root and is exercised separately).
        assert!(drop_privileges(Some("nobody"), false).is_ok());
        Ok(())
    }

    #[cfg(target_os = "linux")]
    /// When already root, the `setcap` command runs directly (no `sudo`) with
    /// the executable as the final argument.
    #[test]
    fn setcap_command_root_is_direct() -> Result<(), TestError> {
        let (prog, args) = setcap_command("/usr/local/bin/sipnab", true);
        assert_eq!(prog, "setcap");
        assert_eq!(
            args,
            vec![
                CAPTURE_CAPS.to_string(),
                "/usr/local/bin/sipnab".to_string()
            ]
        );
        // The executable must be the final argument setcap operates on.
        assert_eq!(
            args.last().ok_or("a last element")?,
            "/usr/local/bin/sipnab"
        );
        Ok(())
    }

    #[cfg(target_os = "linux")]
    /// When not root, the command is wrapped in `sudo setcap ...`.
    #[test]
    fn setcap_command_non_root_wraps_sudo() -> Result<(), TestError> {
        let (prog, args) = setcap_command("/home/u/.cargo/bin/sipnab", false);
        assert_eq!(prog, "sudo");
        assert_eq!(args[0], "setcap");
        assert_eq!(args[1], CAPTURE_CAPS);
        assert_eq!(
            args.last().ok_or("a last element")?,
            "/home/u/.cargo/bin/sipnab"
        );
        Ok(())
    }

    #[cfg(target_os = "linux")]
    /// `CAPTURE_CAPS` requests `cap_net_raw` + `cap_net_admin` in the `+ep`
    /// sets.
    #[test]
    fn capture_caps_cover_raw_and_admin() -> Result<(), TestError> {
        // CAP_NET_RAW opens the socket; CAP_NET_ADMIN enables promiscuous mode.
        assert!(CAPTURE_CAPS.contains("cap_net_raw"));
        assert!(CAPTURE_CAPS.contains("cap_net_admin"));
        // Effective + permitted file-capability sets.
        assert!(CAPTURE_CAPS.ends_with("+ep"));
        Ok(())
    }

    /// The `setcap` argument and the mask name the same two capabilities, by
    /// their numbers in `linux/capability.h`.
    #[test]
    fn the_capture_mask_is_the_named_capabilities() -> Result<(), TestError> {
        const NUMBERS: &[(&str, u32)] = &[("cap_net_admin", 12), ("cap_net_raw", 13)];
        let mut mask = 0u64;
        for name in CAPTURE_CAP_NAMES.split(',') {
            let (_, bit) = NUMBERS
                .iter()
                .find(|(n, _)| *n == name)
                .ok_or_else(|| format!("{name} has no number in this table"))?;
            mask |= 1 << bit;
        }
        assert_eq!(
            mask, CAPTURE_CAP_MASK,
            "the mask raised at startup is not the set the Dockerfile grants"
        );
        #[cfg(target_os = "linux")]
        assert_eq!(
            CAPTURE_CAPS,
            format!("{CAPTURE_CAP_NAMES}+ep"),
            "--setup-caps grants another set than the image"
        );
        Ok(())
    }

    /// SUCCESS: a container's non-root user with `+p` file capabilities and
    /// `--cap-add NET_RAW --cap-add NET_ADMIN` starts permitted both and
    /// effective neither; both are raised.
    #[test]
    fn permitted_capture_caps_are_raised_into_effective() {
        assert_eq!(
            capture_effective(0, 0x3000),
            Some(0x3000),
            "both permitted capture capabilities must become effective"
        );
    }

    /// EDGE: Docker's default set holds `CAP_NET_RAW` and not
    /// `CAP_NET_ADMIN`, so only the one permitted is raised, and an effective
    /// bit already held outside the mask is kept.
    #[test]
    fn only_the_permitted_capture_cap_is_raised() {
        assert_eq!(
            capture_effective(0, 0x2000),
            Some(0x2000),
            "CAP_NET_RAW alone, as under Docker's default set"
        );
        assert_eq!(
            capture_effective(1 << 21, (1 << 21) | 0x1000),
            Some((1 << 21) | 0x1000),
            "an effective bit already held is kept beside CAP_NET_ADMIN"
        );
    }

    /// FAILURE: a capability that is not permitted is never raised, and one
    /// outside the capture mask is never raised even when permitted.
    #[test]
    fn nothing_beyond_the_permitted_capture_caps_is_raised() {
        assert_eq!(capture_effective(0, 0), None, "nothing permitted");
        assert_eq!(
            capture_effective(0, 1 << 21),
            None,
            "CAP_SYS_ADMIN is outside the mask"
        );
        assert_eq!(
            capture_effective(0, !CAPTURE_CAP_MASK),
            None,
            "every capability but the capture ones"
        );
    }

    /// EDGE: root, and a host binary with `+ep` from `--setup-caps`, already
    /// hold both effective, so there is nothing to change.
    #[test]
    fn effective_capture_caps_already_held_change_nothing() {
        assert_eq!(
            capture_effective(0x3000, 0x3000),
            None,
            "a +ep binary already holds both"
        );
        assert_eq!(capture_effective(u64::MAX, u64::MAX), None, "root");
    }

    /// EDGE: raising is idempotent. The set a first raise installs asks for
    /// no second change, for every combination of the two capabilities.
    #[test]
    fn a_second_raise_changes_nothing() {
        for permitted in [0x1000, 0x2000, 0x3000] {
            let raised = capture_effective(0, permitted);
            assert_eq!(raised, Some(permitted), "first raise of {permitted:#x}");
            assert_eq!(
                capture_effective(permitted, permitted),
                None,
                "second raise of {permitted:#x}"
            );
        }
    }

    /// EDGE: `CAP_NET_ADMIN` permitted without `CAP_NET_RAW` (a bounding set
    /// that dropped `NET_RAW` alone) raises that one bit and not its neighbor.
    #[test]
    fn net_admin_alone_is_raised_without_net_raw() {
        assert_eq!(
            capture_effective(0, 0x1000),
            Some(0x1000),
            "CAP_NET_ADMIN alone"
        );
        assert_eq!(
            capture_effective(0x1000, 0x3000),
            Some(0x3000),
            "CAP_NET_RAW joins an effective CAP_NET_ADMIN"
        );
    }

    /// EDGE: capability bits above 31, which live in the second 32-bit word
    /// of the kernel's structure, pass through unchanged, and the mask's
    /// neighbors (bits 11 and 14) are never raised.
    #[test]
    fn bits_outside_the_mask_pass_through_in_both_words() {
        let high = 1u64 << 40;
        assert_eq!(
            capture_effective(high, high | 0x3000),
            Some(high | 0x3000),
            "an effective high bit is kept beside the raise"
        );
        assert_eq!(
            capture_effective(0, high),
            None,
            "a permitted high bit is not raised"
        );
        assert_eq!(
            capture_effective(0, (1 << 11) | (1 << 14)),
            None,
            "the bits next to the mask are not raised"
        );
    }

    /// The live call on this test process: afterwards the effective set is
    /// what it was plus the permitted capture capabilities, whatever this
    /// process holds. Unprivileged, that is no change at all.
    #[cfg(target_os = "linux")]
    #[test]
    fn raising_changes_only_the_permitted_capture_caps() -> Result<(), TestError> {
        fn set(status: &str, name: &str) -> Result<u64, TestError> {
            let hex = status
                .lines()
                .find_map(|l| l.strip_prefix(name)?.strip_prefix(':'))
                .ok_or_else(|| format!("{name} missing"))?;
            Ok(u64::from_str_radix(hex.trim(), 16)?)
        }
        let thread_status = || std::fs::read_to_string("/proc/thread-self/status");
        let before = thread_status()?;
        let (eff, prm) = (set(&before, "CapEff")?, set(&before, "CapPrm")?);
        let raised = raise_capture_capabilities()?;
        let after = thread_status()?;
        let want = eff | (prm & CAPTURE_CAP_MASK);
        assert_eq!(
            set(&after, "CapEff")?,
            want,
            "effective {eff:#x} with permitted {prm:#x} should become {want:#x}"
        );
        assert_eq!(
            set(&after, "CapPrm")?,
            prm,
            "the permitted set is untouched"
        );
        assert_eq!(
            raised,
            (want != eff).then_some(want),
            "the return value reports the change, or none"
        );
        Ok(())
    }

    /// `chroot` without `CAP_SYS_CHROOT` errors rather than silently succeeds,
    /// and the message names the directory it failed on.
    #[test]
    fn do_chroot_without_root_fails_and_names_the_directory() -> Result<(), TestError> {
        // chroot(2) requires CAP_SYS_CHROOT; as a normal user this must error
        // rather than silently succeed (covers the error path of do_chroot).
        if is_root() {
            skip_loudly(
                "do_chroot_without_root_fails_and_names_the_directory",
                "the process IS root, so chroot(2) succeeds; this gate asserts the unprivileged failure path",
            );
            return Ok(());
        }
        let result = do_chroot(std::path::Path::new("/tmp"));
        let msg = result.err().ok_or("non-root chroot must fail")?.to_string();
        assert!(
            msg.contains("chroot") && msg.contains("/tmp"),
            "the operator has to be told which directory could not be entered, \
             got: {msg}"
        );
        Ok(())
    }

    // ── The failure path: every step reports, none of them warns ──────────
    //
    // `drop_privileges` is called once, after the capture handle is open and
    // before a single packet is parsed. If any step of it fails and the
    // function returns `Ok` anyway, the whole program keeps running as root
    // through every parser in it — the exact opposite of what the call is for.
    // The four tests below pin each step's failure to an `Err`, and they run
    // unprivileged because "cannot do this" is precisely the unprivileged
    // case. Turning any `bail!` in this module into a `tracing::warn!` fails
    // one of them.

    /// Announce a skipped root-gated test on the real stderr.
    ///
    /// Not `eprintln!`: libtest replaces the print machinery's sink per test
    /// and discards the buffer when the test passes, so a skip announced that
    /// way is emitted and never seen — which is how a suite ends up green
    /// while proving nothing. See `tests/support/corpus.rs` for the same
    /// defect and the same fix.
    fn skip_loudly(test: &str, reason: &str) {
        use std::io::Write as _;
        let _ = writeln!(
            std::io::stderr(),
            "NOTICE: privilege test `{test}` did NOT run — {reason}."
        );
    }

    /// Names the one test a child process of this binary is to run; see
    /// [`in_own_process`].
    const OWN_PROCESS: &str = "SIPNAB_PRIVILEGE_TEST_IN_OWN_PROCESS";

    /// What [`in_own_process`] does in this process.
    #[derive(Debug, PartialEq, Eq)]
    enum OwnProcess {
        /// The process every test shares: start a child for the test.
        Start,
        /// The child started for this test: run the body.
        RunBody,
        /// A child started for another test: fail, and start nothing.
        Refuse,
    }

    /// The role of this process for the test named `test`, given the value
    /// of [`OWN_PROCESS`] in its environment.
    fn own_process_role(named: Option<&std::ffi::OsStr>, test: &str) -> OwnProcess {
        match named {
            None => OwnProcess::Start,
            Some(named) if named == test => OwnProcess::RunBody,
            Some(_) => OwnProcess::Refuse,
        }
    }

    /// A child never starts a child: a process started for one test that
    /// reaches another fails there, so a wrong name cannot start a chain of
    /// processes.
    #[test]
    fn a_process_started_for_one_test_starts_no_other() {
        use std::ffi::OsStr;
        assert_eq!(
            own_process_role(None, "a"),
            OwnProcess::Start,
            "the shared process starts a child"
        );
        assert_eq!(
            own_process_role(Some(OsStr::new("a")), "a"),
            OwnProcess::RunBody,
            "the child named for the test runs its body"
        );
        assert_eq!(
            own_process_role(Some(OsStr::new("b")), "a"),
            OwnProcess::Refuse,
            "a child named for another test starts nothing"
        );
        assert_eq!(
            own_process_role(Some(OsStr::new("")), "a"),
            OwnProcess::Refuse,
            "an empty name is still a child"
        );
    }

    /// Run `body`, the body of the test named `test`, in a process of its
    /// own: this test binary, started again to run that one test.
    ///
    /// For a body that calls `setgroups`, `setgid` or `setuid`, which glibc
    /// carries out by signaling every other thread of the process; see
    /// `no_test_changes_credentials_in_the_shared_process`. The child runs
    /// the same test function, finds its own name in the environment and
    /// runs `body`; this process passes when the child ran exactly that test
    /// and it passed. The child's output goes to the real standard error, so
    /// a skip it announces is seen.
    fn in_own_process(
        test: &str,
        body: impl FnOnce() -> Result<(), TestError>,
    ) -> Result<(), TestError> {
        use std::io::Write as _;
        match own_process_role(std::env::var_os(OWN_PROCESS).as_deref(), test) {
            OwnProcess::Start => {}
            OwnProcess::RunBody => return body(),
            OwnProcess::Refuse => {
                return Err(format!(
                    "`{test}` ran in a process started for another test; it starts no third process"
                )
                .into());
            }
        }
        let module = module_path!()
            .split_once("::")
            .map_or(module_path!(), |(_, module)| module);
        let child = std::process::Command::new(std::env::current_exe()?)
            .args(["--exact", &format!("{module}::{test}")])
            .args(["--nocapture", "--test-threads=1"])
            .env(OWN_PROCESS, test)
            .output()?;
        let said = format!(
            "{}{}",
            String::from_utf8_lossy(&child.stdout),
            String::from_utf8_lossy(&child.stderr)
        );
        for notice in said.lines().filter(|l| l.starts_with("NOTICE:")) {
            let _ = writeln!(std::io::stderr(), "{notice}");
        }
        assert!(
            child.status.success(),
            "`{test}` failed in its own process ({}): {said}",
            child.status
        );
        assert!(
            said.contains("test result: ok. 1 passed;"),
            "the child process must run exactly the test `{test}`: {said}"
        );
        Ok(())
    }

    /// The functions of this module that call `setgroups`, `setgid` or
    /// `setuid`.
    const CREDENTIAL_CALLS: [&str; 4] = [
        "drop_supplementary_groups",
        "set_gid",
        "set_uid",
        "drop_group_credentials",
    ];

    /// The name of each test of this module whose body calls one of
    /// [`CREDENTIAL_CALLS`] and does not hand that body to `in_own_process`.
    ///
    /// `source` is this file's text. A test is the text from one `#[test]`
    /// line to the next; comment lines are not read.
    fn credential_tests_run_in_the_shared_process(source: &str) -> Vec<String> {
        let tests = source
            .split_once("\nmod tests {")
            .map_or("", |(_, tests)| tests);
        let mut found = Vec::new();
        for test in tests.split("\n    #[test]\n").skip(1) {
            let code: Vec<&str> = test
                .lines()
                .filter(|l| !l.trim_start().starts_with("//"))
                .collect();
            let name = code
                .iter()
                .find_map(|l| l.trim_start().strip_prefix("fn "))
                .and_then(|l| l.split('(').next())
                .unwrap_or("a test with no name");
            let calls = CREDENTIAL_CALLS
                .iter()
                .any(|f| code.iter().any(|l| l.contains(&format!("{f}("))));
            let own_process = code.iter().any(|l| l.contains("in_own_process("));
            if calls && !own_process {
                found.push(name.to_string());
            }
        }
        found
    }

    /// **No test changes the credentials of the process the other tests
    /// share.**
    ///
    /// glibc carries out `setgroups`, `setgid` and `setuid` by sending a
    /// signal to every other thread of the process, so that each thread makes
    /// the call. A thread that is in a blocking call with a timeout at that
    /// moment gets `EINTR`: on 2026-11-13 a read with a 3 s timeout in one
    /// test ended after 501 ms, with `Interrupted system call`, when another
    /// test called `set_gid`. A test that makes such a call hands its body to
    /// `in_own_process`.
    #[test]
    fn no_test_changes_credentials_in_the_shared_process() {
        let found = credential_tests_run_in_the_shared_process(include_str!("privilege.rs"));
        assert!(
            found.is_empty(),
            "these tests call setgroups, setgid or setuid in the process every \
             other test runs in; hand their bodies to `in_own_process`: {found:?}"
        );
    }

    /// The rule reads a test's code and not its comments, and names the test.
    #[test]
    fn the_credential_rule_names_a_test_that_calls_in_the_shared_process() {
        let call = format!("        {}(0)?;\n", CREDENTIAL_CALLS[1]);
        let source = format!(
            "\nmod tests {{\n    #[test]\n    fn calls_here() {{\n{call}    }}\n\
             \n    #[test]\n    fn only_a_comment() {{\n        // {call}    }}\n\
             \n    #[test]\n    fn calls_in_a_child() {{\n        in_own_process(\"x\", || {{\n{call}        }})\n    }}\n}}\n"
        );
        assert_eq!(
            credential_tests_run_in_the_shared_process(&source),
            vec!["calls_here".to_string()],
            "one test calls in the shared process: {source}"
        );
    }

    /// A non-root process cannot clear its supplementary groups, and
    /// `drop_supplementary_groups` must say so rather than return `Ok`.
    ///
    /// This is the first step of the drop. A caller that treated its failure
    /// as advisory would go on to `setgid`/`setuid` while still carrying every
    /// group the invoking user had — the classic incomplete drop, where the
    /// process looks unprivileged by uid and still holds group-granted access
    /// to the capture device, key files and everything else.
    #[test]
    fn drop_supplementary_groups_reports_failure_instead_of_returning_ok() -> Result<(), TestError>
    {
        in_own_process(
            "drop_supplementary_groups_reports_failure_instead_of_returning_ok",
            || -> Result<(), TestError> {
                if is_root() {
                    skip_loudly(
                        "drop_supplementary_groups_reports_failure_instead_of_returning_ok",
                        "the process IS root, so setgroups(2) succeeds; this gate asserts the failure path",
                    );
                    return Ok(());
                }
                let msg = drop_supplementary_groups()
                    .err()
                    .ok_or("setgroups(0, NULL) needs CAP_SETGID and must fail here")?
                    .to_string();
                assert!(
                    msg.contains("setgroups"),
                    "the failure must name the syscall that refused, got: {msg}"
                );
                Ok(())
            },
        )
    }

    /// `set_gid` reports a refused `setgid` rather than returning `Ok`.
    ///
    /// GID 0 is neither this process's real nor its saved GID, so the kernel
    /// refuses. A silent `Ok` here would leave the process in the group it
    /// started in while the caller believed it had shed them.
    #[test]
    fn set_gid_reports_a_refused_setgid_rather_than_returning_ok() -> Result<(), TestError> {
        in_own_process(
            "set_gid_reports_a_refused_setgid_rather_than_returning_ok",
            || -> Result<(), TestError> {
                if is_root() {
                    skip_loudly(
                        "set_gid_reports_a_refused_setgid_rather_than_returning_ok",
                        "the process IS root, so setgid(0) succeeds; this gate asserts the failure path",
                    );
                    return Ok(());
                }
                let msg = set_gid(0)
                    .err()
                    .ok_or("an unprivileged process cannot setgid(0)")?
                    .to_string();
                assert!(
                    msg.contains("setgid"),
                    "the failure must name the syscall that refused, got: {msg}"
                );
                Ok(())
            },
        )
    }

    /// `set_uid` reports a refused `setuid` rather than returning `Ok`.
    #[test]
    fn set_uid_reports_a_refused_setuid_rather_than_returning_ok() -> Result<(), TestError> {
        in_own_process(
            "set_uid_reports_a_refused_setuid_rather_than_returning_ok",
            || -> Result<(), TestError> {
                if is_root() {
                    skip_loudly(
                        "set_uid_reports_a_refused_setuid_rather_than_returning_ok",
                        "the process IS root, so setuid(0) succeeds; this gate asserts the failure path",
                    );
                    return Ok(());
                }
                let msg = set_uid(0)
                    .err()
                    .ok_or("an unprivileged process cannot setuid(0)")?
                    .to_string();
                assert!(
                    msg.contains("setuid"),
                    "the failure must name the syscall that refused, got: {msg}"
                );
                Ok(())
            },
        )
    }

    /// The post-drop verification rejects ids that are not the ones asked for.
    ///
    /// `verify_dropped` is the last line of defense: it is what would catch a
    /// future edit that reordered the drop, switched to `setresuid`, or
    /// dropped only the real ids. Asking it to confirm a drop to uid 0 from a
    /// process that is not uid 0 is the cheapest way to prove it actually
    /// compares rather than always returning `Ok`.
    #[test]
    fn verify_dropped_rejects_ids_that_are_not_the_ones_requested() -> Result<(), TestError> {
        // SAFETY: getuid/getgid are read-only syscalls that cannot fail.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        // Pick a target this process demonstrably does not have.
        let (wrong_uid, wrong_gid) = (uid.wrapping_add(1), gid.wrapping_add(1));
        let msg = verify_dropped(wrong_uid, wrong_gid)
            .err()
            .ok_or("the process does not hold those ids")?
            .to_string();
        assert!(
            msg.contains("verification failed"),
            "the message must say the verification failed, got: {msg}"
        );
        assert!(
            msg.contains(&wrong_uid.to_string()) && msg.contains(&uid.to_string()),
            "the message must carry both the expected and the actual uid so the \
             operator can see which half of the drop did not happen, got: {msg}"
        );
        Ok(())
    }

    /// The verification accepts the ids the process actually holds, so the
    /// rejection above is a real comparison and not a blanket failure.
    #[test]
    fn verify_dropped_accepts_the_ids_the_process_actually_holds() -> Result<(), TestError> {
        // SAFETY: getuid/getgid are read-only syscalls that cannot fail.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        assert!(
            verify_dropped(uid, gid).is_ok(),
            "a process already holding the target ids has completed the drop"
        );
        Ok(())
    }

    /// A username containing a null byte is rejected before it reaches
    /// `getpwnam_r`, which would otherwise see a silently truncated name.
    #[test]
    fn resolve_user_rejects_a_username_with_an_interior_null_byte() -> Result<(), TestError> {
        let msg = resolve_user("root\0nobody")
            .err()
            .ok_or("a null byte cannot cross the C boundary")?
            .to_string();
        assert!(
            msg.contains("null byte"),
            "the failure must name the null byte rather than report 'not found', \
             got: {msg}"
        );
        Ok(())
    }

    /// A chroot path containing a null byte is rejected before `chroot(2)`,
    /// for the same reason: C would stop at the null and confine the process
    /// somewhere other than the operator named.
    #[test]
    fn do_chroot_rejects_a_path_with_an_interior_null_byte() -> Result<(), TestError> {
        use std::os::unix::ffi::OsStrExt as _;
        let path = std::path::Path::new(std::ffi::OsStr::from_bytes(b"/tmp\0/evil"));
        let msg = do_chroot(path)
            .err()
            .ok_or("a null byte cannot cross the C boundary")?
            .to_string();
        assert!(
            msg.contains("null byte"),
            "the failure must name the null byte rather than report an errno from \
             a truncated path, got: {msg}"
        );
        Ok(())
    }
    // ── Pieces of the drop that run unprivileged once their inputs are ────
    // ── arguments rather than syscalls ──────────────────────────────────
    //
    // The drop itself needs root, so its happy path is out of reach here (the
    // integration suite runs it under sudo where sudo exists). What is not out
    // of reach is every DECISION it makes: the comparison `verify_dropped`
    // applies to the ids the kernel reports, the order the group calls run
    // in, the scratch buffer's growth, and what `--setup-caps` makes of the
    // command it spawns.

    /// The drop is refused when the EFFECTIVE uid was not dropped even though
    /// the real one was -- the half an attacker who gets code execution
    /// actually inherits.
    #[test]
    fn a_drop_that_left_the_effective_uid_behind_is_refused() -> Result<(), TestError> {
        let msg = check_dropped_ids(65534, 65534, (65534, 65534, 0, 65534))
            .err()
            .ok_or("euid 0 is still root")?
            .to_string();
        assert!(msg.contains("EFFECTIVE"), "{msg}");
        assert!(
            msg.contains("expected euid=65534/egid=65534, got euid=0/egid=65534"),
            "both sides of the comparison are named: {msg}"
        );
        Ok(())
    }

    /// egid 0 under an unprivileged uid is exactly what reversing the two
    /// group calls produces on macOS -- root by group, wearing `nobody`.
    #[test]
    fn an_effective_gid_of_zero_under_an_unprivileged_uid_is_refused() -> Result<(), TestError> {
        let msg = check_dropped_ids(65534, 65534, (65534, 65534, 65534, 0))
            .err()
            .ok_or("egid 0 is wheel")?
            .to_string();
        assert!(msg.contains("got euid=65534/egid=0"), "{msg}");
        Ok(())
    }

    /// A real gid that was not dropped fails the first comparison, and says
    /// which half is wrong.
    #[test]
    fn a_real_gid_that_was_not_dropped_is_refused() -> Result<(), TestError> {
        let msg = check_dropped_ids(65534, 65534, (65534, 0, 65534, 65534))
            .err()
            .ok_or("gid 0 was not given up")?
            .to_string();
        assert!(
            msg.contains("expected uid=65534/gid=65534, got uid=65534/gid=0"),
            "{msg}"
        );
        Ok(())
    }

    /// All four ids matching is a completed drop.
    #[test]
    fn a_drop_whose_four_ids_all_match_is_accepted() -> Result<(), TestError> {
        assert!(check_dropped_ids(65534, 65534, (65534, 65534, 65534, 65534)).is_ok());
        Ok(())
    }

    /// Groups go first, and a failure there stops the sequence before the GID
    /// is touched. The order is load-bearing on macOS (see
    /// `drop_group_credentials`); if the two calls were swapped, an
    /// unprivileged caller would see `setgid` refuse first instead.
    #[test]
    fn group_credentials_are_surrendered_supplementary_list_first() -> Result<(), TestError> {
        in_own_process(
            "group_credentials_are_surrendered_supplementary_list_first",
            || -> Result<(), TestError> {
                if is_root() {
                    skip_loudly(
                        "group_credentials_are_surrendered_supplementary_list_first",
                        "the process IS root, so setgroups(2) succeeds; this gate asserts which step refuses first",
                    );
                    return Ok(());
                }
                let msg = drop_group_credentials(0)
                    .err()
                    .ok_or("an unprivileged process cannot shed its groups")?
                    .to_string();
                assert!(
                    msg.starts_with("setgroups failed"),
                    "the supplementary list is the FIRST step to refuse: {msg}"
                );
                Ok(())
            },
        )
    }

    /// Setting the ids a process already holds is permitted at any privilege
    /// level, and each call reports that success rather than inventing a
    /// failure -- the success arm of each syscall wrapper.
    ///
    /// The ids come from the kernel's own report in `/proc/self/status` (the
    /// first column of `Uid:`/`Gid:` is the real id), which needs no `unsafe`.
    #[cfg(target_os = "linux")]
    #[test]
    fn setting_the_ids_the_process_already_holds_succeeds_and_changes_nothing()
    -> Result<(), TestError> {
        in_own_process(
            "setting_the_ids_the_process_already_holds_succeeds_and_changes_nothing",
            || -> Result<(), TestError> {
                let status = std::fs::read_to_string("/proc/self/status")
                    .map_err(|e| format!("procfs is mounted: {e:?}"))?;
                let real = |key: &str| -> Result<u32, String> {
                    status
                        .lines()
                        .find(|l| l.starts_with(key))
                        .and_then(|l| l.split_whitespace().nth(1))
                        .and_then(|v| v.parse().ok())
                        .ok_or_else(|| format!("no {key} line in /proc/self/status"))
                };
                let (uid, gid) = (real("Uid:")?, real("Gid:")?);
                set_gid(gid)
                    .map_err(|e| format!("setgid to the real gid is always permitted: {e:?}"))?;
                set_uid(uid)
                    .map_err(|e| format!("setuid to the real uid is always permitted: {e:?}"))?;
                assert!(
                    verify_dropped(uid, gid).is_ok(),
                    "and the process holds exactly the ids it held before"
                );
                Ok(())
            },
        )
    }

    /// `getpwnam_r` answers ERANGE when the scratch buffer cannot hold the
    /// entry's strings. The lookup must grow the buffer and retry, not report
    /// a user that exists as unresolvable.
    #[test]
    fn a_scratch_buffer_too_small_for_the_entry_grows_until_it_fits() -> Result<(), TestError> {
        let (uid, _gid) = resolve_user_with_buffer("root", 1)
            .map_err(|e| format!("a one-byte buffer is grown, not fatal: {e:?}"))?;
        assert_eq!(uid, 0);
        Ok(())
    }

    // ── --setup-caps, minus the privileged command ───────────────────────

    /// A PATH symlink is followed, so `setcap` lands on the real binary --
    /// file capabilities on a symlink do nothing.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_setcap_target_is_the_real_binary_behind_a_symlink() -> Result<(), TestError> {
        let dir = tempfile::tempdir().map_err(|e| format!("tempdir: {e:?}"))?;
        let real = dir.path().join("sipnab-real");
        std::fs::write(&real, b"").map_err(|e| format!("write: {e:?}"))?;
        let link = dir.path().join("sipnab");
        std::os::unix::fs::symlink(&real, &link).map_err(|e| format!("symlink: {e:?}"))?;

        let target = setcap_target(&link).map_err(|e| format!("a UTF-8 path: {e:?}"))?;
        let canonical = std::fs::canonicalize(&real).map_err(|e| format!("canonicalize: {e:?}"))?;
        assert_eq!(std::path::Path::new(&target), canonical.as_path());
        Ok(())
    }

    /// A path that cannot be canonicalized is used as given, rather than
    /// failing before `setcap` can say what is wrong with it.
    #[cfg(target_os = "linux")]
    #[test]
    fn an_uncanonicalizable_setcap_target_is_used_as_given() -> Result<(), TestError> {
        let dir = tempfile::tempdir().map_err(|e| format!("tempdir: {e:?}"))?;
        let absent = dir.path().join("not-here");
        assert_eq!(
            setcap_target(&absent).map_err(|e| format!("still a UTF-8 path: {e:?}"))?,
            absent.display().to_string()
        );
        Ok(())
    }

    /// `setcap` takes a C string; a path that is not UTF-8 is refused with a
    /// reason instead of being mangled on the way.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_setcap_target_that_is_not_utf8_is_refused() -> Result<(), TestError> {
        use std::os::unix::ffi::OsStrExt as _;
        let path = std::path::Path::new(std::ffi::OsStr::from_bytes(b"/nonexistent/\xff\xfe"));
        let msg = setcap_target(path)
            .err()
            .ok_or("not representable as &str")?
            .to_string();
        assert!(msg.contains("not valid UTF-8"), "{msg}");
        Ok(())
    }

    /// A command that could not be spawned is reported with the remedy for
    /// the usual cause: the package that ships `setcap` is not installed.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_setcap_that_cannot_be_spawned_names_the_package_to_install() -> Result<(), TestError> {
        let spawn = Err(std::io::Error::from(std::io::ErrorKind::NotFound));
        let msg = setcap_outcome("setcap", "/usr/bin/sipnab", spawn)
            .err()
            .ok_or("nothing ran")?
            .to_string();
        assert!(msg.contains("failed to run 'setcap'"), "{msg}");
        assert!(msg.contains("libcap2-bin"), "{msg}");
        Ok(())
    }

    /// A non-zero exit is a failure naming the code and the binary, never a
    /// success -- the capability was not granted.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_setcap_that_exits_non_zero_is_a_failure_naming_the_code() -> Result<(), TestError> {
        use std::os::unix::process::ExitStatusExt as _;
        let msg = setcap_outcome(
            "sudo",
            "/usr/bin/sipnab",
            Ok(std::process::ExitStatus::from_raw(1 << 8)),
        )
        .err()
        .ok_or("exit 1 granted nothing")?
        .to_string();
        assert_eq!(msg, "setcap failed (exit Some(1)) on /usr/bin/sipnab");

        let killed = setcap_outcome(
            "sudo",
            "/usr/bin/sipnab",
            Ok(std::process::ExitStatus::from_raw(9)),
        )
        .err()
        .ok_or("a killed setcap granted nothing")?
        .to_string();
        assert!(
            killed.contains("exit None"),
            "no code for a signal: {killed}"
        );
        Ok(())
    }

    /// A zero exit is the grant.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_setcap_that_exits_zero_is_the_grant() -> Result<(), TestError> {
        use std::os::unix::process::ExitStatusExt as _;
        assert!(
            setcap_outcome(
                "setcap",
                "/usr/bin/sipnab",
                Ok(std::process::ExitStatus::from_raw(0))
            )
            .is_ok()
        );
        Ok(())
    }

    // ── What a refused mlockall is reported as ───────────────────────────

    /// A refused lock names the limit to raise; a granted one says Locked.
    /// Which of the two this host produces depends on its `RLIMIT_MEMLOCK`,
    /// so the mapping is pinned here with the outcome as an argument.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_refused_memory_lock_names_the_limit_to_raise() -> Result<(), TestError> {
        assert_eq!(memory_lock_outcome(Ok(())), MemoryLock::Locked);
        match memory_lock_outcome(Err(std::io::Error::from_raw_os_error(libc::ENOMEM))) {
            MemoryLock::Unlocked(reason) => {
                assert!(reason.starts_with("mlockall failed:"), "{reason}");
                assert!(reason.contains("RLIMIT_MEMLOCK"), "{reason}");
                assert!(
                    reason.contains(&std::io::Error::from_raw_os_error(libc::ENOMEM).to_string()),
                    "the kernel's own reason is kept: {reason}"
                );
            }
            MemoryLock::Locked => return Err("a refusal must not read as locked".into()),
        }
        Ok(())
    }
}
