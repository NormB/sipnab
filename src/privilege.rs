// SPDX-License-Identifier: MIT OR Apache-2.0

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
/// # Errors
///
/// Returns an error if the target user cannot be resolved, or if any of the
/// underlying syscalls (`setgroups`, `setgid`, `setuid`) fail.
pub fn drop_privileges(target_user: Option<&str>, no_priv_drop: bool) -> Result<()> {
    if no_priv_drop {
        tracing::info!("Privilege drop disabled (--no-priv-drop)");
        return Ok(());
    }

    // Only drop if running as root
    if !is_root() {
        tracing::debug!("Not running as root, skipping privilege drop");
        return Ok(());
    }

    // On macOS, dropping to 'nobody' (uid 65534) strands the process without
    // a launchd per-user session, which crashes CoreAudio and other user-
    // context frameworks the moment they are invoked (e.g., pressing P to
    // play RTP audio in the TUI). macOS's security model relies on TCC and
    // the app sandbox rather than uid-based privilege separation, so the
    // drop buys little here. Require an explicit --user to opt in.
    #[cfg(target_os = "macos")]
    if target_user.is_none() {
        tracing::warn!(
            "Running as root on macOS without --user; skipping privilege drop \
             to avoid breaking CoreAudio and other per-user services. \
             Pass --user <name> to opt in, or run without sudo."
        );
        return Ok(());
    }

    let user = target_user.unwrap_or("nobody");

    // Resolve user to UID/GID
    let (uid, gid) = resolve_user(user)?;

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

    Ok(())
}

/// Linux capabilities a live capture needs: `CAP_NET_RAW` to open the packet
/// socket and `CAP_NET_ADMIN` to put the interface into promiscuous mode.
/// Both are placed in the effective+permitted file-capability sets (`+ep`).
#[cfg(target_os = "linux")]
const CAPTURE_CAPS: &str = "cap_net_raw,cap_net_admin+ep";

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
    // Follow symlinks so setcap targets the real binary, not a symlink in PATH.
    let exe = std::fs::canonicalize(&exe).unwrap_or(exe);
    let exe_str = exe
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("executable path is not valid UTF-8"))?;

    let root = is_root();
    if !root {
        tracing::info!(
            "Not root — elevating via sudo to set capabilities (may prompt for a password)"
        );
    }
    let (program, args) = setcap_command(exe_str, root);

    let status = std::process::Command::new(&program)
        .args(&args)
        .status()
        .map_err(|e| {
            anyhow::anyhow!(
                "failed to run '{program}' (is 'setcap' installed? on Debian: \
                 'sudo apt install libcap2-bin'): {e}"
            )
        })?;

    if !status.success() {
        bail!("setcap failed (exit {:?}) on {}", status.code(), exe_str);
    }

    tracing::info!(
        "Granted {} on {} — live capture now works without sudo",
        CAPTURE_CAPS,
        exe_str
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

/// Check if the current process is running as root (UID 0).
pub fn is_root() -> bool {
    // SAFETY: getuid() is always safe — it reads kernel state and cannot fail.
    unsafe { libc::getuid() == 0 }
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
    #[cfg(target_os = "linux")]
    {
        // SAFETY: prctl with PR_SET_DUMPABLE is a simple flag toggle;
        // the trailing arguments are unused but required by the syscall ABI.
        unsafe {
            if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
                bail!(
                    "prctl(PR_SET_DUMPABLE, 0) failed: {}. Decryption keys are \
                     resident in this process and a crash would write them to a \
                     core file; pass --allow-coredump to run anyway",
                    std::io::Error::last_os_error()
                );
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
                bail!(
                    "setrlimit(RLIMIT_CORE, 0) failed: {}. Decryption keys are \
                     resident in this process and a crash would write them to a \
                     core file; pass --allow-coredump to run anyway",
                    std::io::Error::last_os_error()
                );
            }
        }
    }

    // Neither arm compiled in: nothing was done, so nothing may be claimed.
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    bail!(
        "disabling core dumps is not implemented for this platform, so \
         decryption keys resident in this process could still reach a core \
         file; pass --allow-coredump to run anyway"
    );

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        tracing::info!("Core dumps disabled (decryption active)");
        Ok(())
    }
}

/// Resolve a username to its UID and primary GID via the system password database.
///
/// Uses the reentrant `getpwnam_r` (caller-owned `passwd` + scratch buffer)
/// rather than `getpwnam`, which returns a pointer into a shared static buffer
/// that a concurrent `getpwnam`/`getpwuid` on another thread can overwrite
/// between the lookup and reading the fields. Production resolution happens once
/// at single-threaded startup, but the reentrant call is correct regardless.
fn resolve_user(username: &str) -> Result<(u32, u32)> {
    let c_user = std::ffi::CString::new(username)
        .map_err(|_| anyhow::anyhow!("Username '{}' contains a null byte", username))?;

    // Initial scratch-buffer size for the string fields; grow on ERANGE.
    // SAFETY: `sysconf` takes no pointers and only reads a system constant.
    let mut buf_len: usize = match unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) } {
        n if n > 0 => n as usize,
        _ => 16_384,
    };

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
    let (actual_uid, actual_gid, euid, egid) = unsafe {
        (
            libc::getuid(),
            libc::getgid(),
            libc::geteuid(),
            libc::getegid(),
        )
    };

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

    /// A normal (non-root) test process reports `is_root() == false`.
    #[test]
    fn is_root_returns_false_for_normal_user() {
        // CI and dev machines run as non-root
        assert!(!is_root());
    }

    /// `no_priv_drop == true` returns `Ok` without touching any syscall.
    #[test]
    fn no_priv_drop_flag_skips_immediately() {
        // Should return Ok without touching any syscalls
        assert!(drop_privileges(None, true).is_ok());
    }

    /// When not root, `drop_privileges` is a no-op that returns `Ok`.
    #[test]
    fn non_root_skips_privilege_drop() {
        // When not root, drop_privileges is a no-op
        assert!(drop_privileges(None, false).is_ok());
    }

    /// `nobody` resolves to a non-zero uid or gid on Linux and macOS.
    #[test]
    fn resolve_user_nobody_succeeds() {
        // "nobody" exists on both Linux and macOS
        let (uid, gid) = resolve_user("nobody").expect("nobody user should exist");
        // On macOS nobody is typically uid 65534, on Linux it varies,
        // but it should always be non-zero
        assert!(uid > 0 || gid > 0, "nobody should have non-zero uid or gid");
    }

    /// An unknown username errors with a "not found" message suggesting
    /// `--user`.
    #[test]
    fn resolve_user_nonexistent_returns_error() {
        let result = resolve_user("nonexistent_user_xyz123");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("not found"),
            "Error should mention 'not found', got: {msg}"
        );
        assert!(
            msg.contains("--user"),
            "Error should suggest --user flag, got: {msg}"
        );
    }

    /// `disable_core_dumps` never panics regardless of permission outcome.
    #[test]
    fn disable_core_dumps_does_not_panic() {
        // May or may not succeed depending on permissions, but must not panic
        let _ = disable_core_dumps();
    }

    /// `root` resolves to uid 0.
    #[test]
    fn resolve_user_root_is_uid_zero() {
        let (uid, _gid) = resolve_user("root").expect("root should exist");
        assert_eq!(uid, 0, "root must resolve to uid 0");
    }

    /// As non-root, requesting a target user is still a no-op `Ok`.
    #[test]
    fn drop_privileges_with_target_user_non_root_is_noop() {
        // As a non-root process, requesting a target user is still a no-op Ok
        // (the actual setuid path requires root and is exercised separately).
        assert!(drop_privileges(Some("nobody"), false).is_ok());
    }

    #[cfg(target_os = "linux")]
    /// When already root, the `setcap` command runs directly (no `sudo`) with
    /// the executable as the final argument.
    #[test]
    fn setcap_command_root_is_direct() {
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
        assert_eq!(args.last().unwrap(), "/usr/local/bin/sipnab");
    }

    #[cfg(target_os = "linux")]
    /// When not root, the command is wrapped in `sudo setcap ...`.
    #[test]
    fn setcap_command_non_root_wraps_sudo() {
        let (prog, args) = setcap_command("/home/u/.cargo/bin/sipnab", false);
        assert_eq!(prog, "sudo");
        assert_eq!(args[0], "setcap");
        assert_eq!(args[1], CAPTURE_CAPS);
        assert_eq!(args.last().unwrap(), "/home/u/.cargo/bin/sipnab");
    }

    #[cfg(target_os = "linux")]
    /// `CAPTURE_CAPS` requests `cap_net_raw` + `cap_net_admin` in the `+ep`
    /// sets.
    #[test]
    fn capture_caps_cover_raw_and_admin() {
        // CAP_NET_RAW opens the socket; CAP_NET_ADMIN enables promiscuous mode.
        assert!(CAPTURE_CAPS.contains("cap_net_raw"));
        assert!(CAPTURE_CAPS.contains("cap_net_admin"));
        // Effective + permitted file-capability sets.
        assert!(CAPTURE_CAPS.ends_with("+ep"));
    }

    /// `chroot` without `CAP_SYS_CHROOT` errors rather than silently succeeds,
    /// and the message names the directory it failed on.
    #[test]
    fn do_chroot_without_root_fails_and_names_the_directory() {
        // chroot(2) requires CAP_SYS_CHROOT; as a normal user this must error
        // rather than silently succeed (covers the error path of do_chroot).
        if is_root() {
            skip_loudly(
                "do_chroot_without_root_fails_and_names_the_directory",
                "the process IS root, so chroot(2) succeeds; this gate asserts the unprivileged failure path",
            );
            return;
        }
        let result = do_chroot(std::path::Path::new("/tmp"));
        let msg = result.expect_err("non-root chroot must fail").to_string();
        assert!(
            msg.contains("chroot") && msg.contains("/tmp"),
            "the operator has to be told which directory could not be entered, \
             got: {msg}"
        );
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

    /// A non-root process cannot clear its supplementary groups, and
    /// `drop_supplementary_groups` must say so rather than return `Ok`.
    ///
    /// This is the first step of the drop. A caller that treated its failure
    /// as advisory would go on to `setgid`/`setuid` while still carrying every
    /// group the invoking user had — the classic incomplete drop, where the
    /// process looks unprivileged by uid and still holds group-granted access
    /// to the capture device, key files and everything else.
    #[test]
    fn drop_supplementary_groups_reports_failure_instead_of_returning_ok() {
        if is_root() {
            skip_loudly(
                "drop_supplementary_groups_reports_failure_instead_of_returning_ok",
                "the process IS root, so setgroups(2) succeeds; this gate asserts the failure path",
            );
            return;
        }
        let msg = drop_supplementary_groups()
            .expect_err("setgroups(0, NULL) needs CAP_SETGID and must fail here")
            .to_string();
        assert!(
            msg.contains("setgroups"),
            "the failure must name the syscall that refused, got: {msg}"
        );
    }

    /// `set_gid` reports a refused `setgid` rather than returning `Ok`.
    ///
    /// GID 0 is neither this process's real nor its saved GID, so the kernel
    /// refuses. A silent `Ok` here would leave the process in the group it
    /// started in while the caller believed it had shed them.
    #[test]
    fn set_gid_reports_a_refused_setgid_rather_than_returning_ok() {
        if is_root() {
            skip_loudly(
                "set_gid_reports_a_refused_setgid_rather_than_returning_ok",
                "the process IS root, so setgid(0) succeeds; this gate asserts the failure path",
            );
            return;
        }
        let msg = set_gid(0)
            .expect_err("an unprivileged process cannot setgid(0)")
            .to_string();
        assert!(
            msg.contains("setgid"),
            "the failure must name the syscall that refused, got: {msg}"
        );
    }

    /// `set_uid` reports a refused `setuid` rather than returning `Ok`.
    #[test]
    fn set_uid_reports_a_refused_setuid_rather_than_returning_ok() {
        if is_root() {
            skip_loudly(
                "set_uid_reports_a_refused_setuid_rather_than_returning_ok",
                "the process IS root, so setuid(0) succeeds; this gate asserts the failure path",
            );
            return;
        }
        let msg = set_uid(0)
            .expect_err("an unprivileged process cannot setuid(0)")
            .to_string();
        assert!(
            msg.contains("setuid"),
            "the failure must name the syscall that refused, got: {msg}"
        );
    }

    /// The post-drop verification rejects ids that are not the ones asked for.
    ///
    /// `verify_dropped` is the last line of defence: it is what would catch a
    /// future edit that reordered the drop, switched to `setresuid`, or
    /// dropped only the real ids. Asking it to confirm a drop to uid 0 from a
    /// process that is not uid 0 is the cheapest way to prove it actually
    /// compares rather than always returning `Ok`.
    #[test]
    fn verify_dropped_rejects_ids_that_are_not_the_ones_requested() {
        // SAFETY: getuid/getgid are read-only syscalls that cannot fail.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        // Pick a target this process demonstrably does not have.
        let (wrong_uid, wrong_gid) = (uid.wrapping_add(1), gid.wrapping_add(1));
        let msg = verify_dropped(wrong_uid, wrong_gid)
            .expect_err("the process does not hold those ids")
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
    }

    /// The verification accepts the ids the process actually holds, so the
    /// rejection above is a real comparison and not a blanket failure.
    #[test]
    fn verify_dropped_accepts_the_ids_the_process_actually_holds() {
        // SAFETY: getuid/getgid are read-only syscalls that cannot fail.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        assert!(
            verify_dropped(uid, gid).is_ok(),
            "a process already holding the target ids has completed the drop"
        );
    }

    /// A username containing a null byte is rejected before it reaches
    /// `getpwnam_r`, which would otherwise see a silently truncated name.
    #[test]
    fn resolve_user_rejects_a_username_with_an_interior_null_byte() {
        let msg = resolve_user("root\0nobody")
            .expect_err("a null byte cannot cross the C boundary")
            .to_string();
        assert!(
            msg.contains("null byte"),
            "the failure must name the null byte rather than report 'not found', \
             got: {msg}"
        );
    }

    /// A chroot path containing a null byte is rejected before `chroot(2)`,
    /// for the same reason: C would stop at the null and confine the process
    /// somewhere other than the operator named.
    #[test]
    fn do_chroot_rejects_a_path_with_an_interior_null_byte() {
        use std::os::unix::ffi::OsStrExt as _;
        let path = std::path::Path::new(std::ffi::OsStr::from_bytes(b"/tmp\0/evil"));
        let msg = do_chroot(path)
            .expect_err("a null byte cannot cross the C boundary")
            .to_string();
        assert!(
            msg.contains("null byte"),
            "the failure must name the null byte rather than report an errno from \
             a truncated path, got: {msg}"
        );
    }
}
