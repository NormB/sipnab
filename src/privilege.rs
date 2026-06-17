//! Privilege separation for sipnab.
//!
//! After opening capture devices (which require root or `CAP_NET_RAW`),
//! sipnab drops privileges to an unprivileged user before processing
//! any packets. This limits the blast radius of potential exploits in
//! packet-parsing code.
//!
//! Call sequence:
//! 1. Open capture devices (requires root/`CAP_NET_RAW`)
//! 2. Open key files, bind API/metrics ports
//! 3. Call [`drop_privileges()`]
//! 4. Begin packet processing (unprivileged)

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

    // Drop supplementary groups
    drop_supplementary_groups()?;

    // Drop GID first (must happen before UID drop — once we lose root UID,
    // we can no longer change groups)
    set_gid(gid)?;

    // Drop UID last
    set_uid(uid)?;

    // Prevent regaining privileges (Linux only)
    #[cfg(target_os = "linux")]
    set_no_new_privs()?;

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

/// Build the `setcap` command (program + args) that grants [`CAPTURE_CAPS`] to
/// `exe`. When `as_root` is false the call is wrapped in `sudo` so it can
/// elevate (prompting for a password on the controlling terminal if needed).
///
/// Factored out from [`setup_capabilities`] so the command shape is unit-testable
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
/// Failures are logged as warnings but do not cause an error return,
/// because this is a defense-in-depth measure, not a hard requirement.
pub fn disable_core_dumps() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: prctl with PR_SET_DUMPABLE is a simple flag toggle;
        // the trailing arguments are unused but required by the syscall ABI.
        unsafe {
            if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
                tracing::warn!(
                    "prctl(PR_SET_DUMPABLE, 0) failed: {}",
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
                tracing::warn!(
                    "setrlimit(RLIMIT_CORE, 0) failed: {}",
                    std::io::Error::last_os_error()
                );
            }
        }
    }

    tracing::info!("Core dumps disabled (decryption active)");
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
    let c_user = std::ffi::CString::new(username)
        .map_err(|_| anyhow::anyhow!("Username '{}' contains a null byte", username))?;

    // Initial scratch-buffer size for the string fields; grow on ERANGE.
    let mut buf_len: usize = match unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) } {
        n if n > 0 => n as usize,
        _ => 16_384,
    };

    loop {
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut buf = vec![0 as libc::c_char; buf_len];
        let mut result: *mut libc::passwd = std::ptr::null_mut();

        // SAFETY: `getpwnam_r` writes the entry into our owned `pwd` and the
        // string fields into our owned `buf`; on success `result` is set to
        // `&pwd`. No shared static state is involved, so the call is
        // thread-safe. We copy out only the scalar uid/gid before `pwd` drops.
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
        if ret != 0 {
            bail!(
                "Failed to resolve user '{}': {}",
                username,
                std::io::Error::from_raw_os_error(ret)
            );
        }
        if result.is_null() {
            bail!(
                "User '{}' not found. Create it with \
                 'useradd -r -s /usr/sbin/nologin {}' or use --user <name>",
                username,
                username
            );
        }
        return Ok((pwd.pw_uid, pwd.pw_gid));
    }
}

/// Clear all supplementary groups.
fn drop_supplementary_groups() -> Result<()> {
    // SAFETY: setgroups(0, NULL) clears the supplementary group list.
    // A null pointer is valid when ngroups is 0.
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

/// Set the `PR_SET_NO_NEW_PRIVS` flag to prevent regaining privileges via
/// exec of setuid/setgid binaries (Linux only).
#[cfg(target_os = "linux")]
fn set_no_new_privs() -> Result<()> {
    // SAFETY: prctl with PR_SET_NO_NEW_PRIVS is a one-way flag —
    // once set, it cannot be unset. Trailing args are unused.
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            tracing::warn!(
                "prctl(PR_SET_NO_NEW_PRIVS) failed: {}",
                std::io::Error::last_os_error()
            );
            // Non-fatal — warn but continue
        }
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
    // SAFETY: getuid/getgid are always safe read-only syscalls.
    let (actual_uid, actual_gid) = unsafe { (libc::getuid(), libc::getgid()) };

    if actual_uid != expected_uid || actual_gid != expected_gid {
        bail!(
            "Privilege drop verification failed: expected uid={}/gid={}, got uid={}/gid={}",
            expected_uid,
            expected_gid,
            actual_uid,
            actual_gid
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_root_returns_false_for_normal_user() {
        // CI and dev machines run as non-root
        assert!(!is_root());
    }

    #[test]
    fn no_priv_drop_flag_skips_immediately() {
        // Should return Ok without touching any syscalls
        assert!(drop_privileges(None, true).is_ok());
    }

    #[test]
    fn non_root_skips_privilege_drop() {
        // When not root, drop_privileges is a no-op
        assert!(drop_privileges(None, false).is_ok());
    }

    #[test]
    fn resolve_user_nobody_succeeds() {
        // "nobody" exists on both Linux and macOS
        let (uid, gid) = resolve_user("nobody").expect("nobody user should exist");
        // On macOS nobody is typically uid 65534, on Linux it varies,
        // but it should always be non-zero
        assert!(uid > 0 || gid > 0, "nobody should have non-zero uid or gid");
    }

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

    #[test]
    fn disable_core_dumps_does_not_panic() {
        // May or may not succeed depending on permissions, but must not panic
        let _ = disable_core_dumps();
    }

    #[test]
    fn resolve_user_root_is_uid_zero() {
        let (uid, _gid) = resolve_user("root").expect("root should exist");
        assert_eq!(uid, 0, "root must resolve to uid 0");
    }

    #[test]
    fn drop_privileges_with_target_user_non_root_is_noop() {
        // As a non-root process, requesting a target user is still a no-op Ok
        // (the actual setuid path requires root and is exercised separately).
        assert!(drop_privileges(Some("nobody"), false).is_ok());
    }

    #[cfg(target_os = "linux")]
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
    #[test]
    fn setcap_command_non_root_wraps_sudo() {
        let (prog, args) = setcap_command("/home/u/.cargo/bin/sipnab", false);
        assert_eq!(prog, "sudo");
        assert_eq!(args[0], "setcap");
        assert_eq!(args[1], CAPTURE_CAPS);
        assert_eq!(args.last().unwrap(), "/home/u/.cargo/bin/sipnab");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn capture_caps_cover_raw_and_admin() {
        // CAP_NET_RAW opens the socket; CAP_NET_ADMIN enables promiscuous mode.
        assert!(CAPTURE_CAPS.contains("cap_net_raw"));
        assert!(CAPTURE_CAPS.contains("cap_net_admin"));
        // Effective + permitted file-capability sets.
        assert!(CAPTURE_CAPS.ends_with("+ep"));
    }

    #[test]
    fn do_chroot_without_root_fails() {
        // chroot(2) requires CAP_SYS_CHROOT; as a normal user this must error
        // rather than silently succeed (covers the error path of do_chroot).
        let result = do_chroot(std::path::Path::new("/tmp"));
        assert!(result.is_err(), "non-root chroot should fail");
    }
}
