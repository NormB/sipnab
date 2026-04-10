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
        log::info!("Privilege drop disabled (--no-priv-drop)");
        return Ok(());
    }

    // Only drop if running as root
    if !is_root() {
        log::debug!("Not running as root, skipping privilege drop");
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

    log::info!(
        "Dropped privileges to user '{}' (uid={}, gid={})",
        user,
        uid,
        gid
    );

    // Verify we actually dropped
    verify_dropped(uid, gid)?;

    Ok(())
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
                log::warn!(
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
                log::warn!(
                    "setrlimit(RLIMIT_CORE, 0) failed: {}",
                    std::io::Error::last_os_error()
                );
            }
        }
    }

    log::info!("Core dumps disabled (decryption active)");
    Ok(())
}

/// Resolve a username to its UID and primary GID via the system password database.
fn resolve_user(username: &str) -> Result<(u32, u32)> {
    let c_user = std::ffi::CString::new(username)
        .map_err(|_| anyhow::anyhow!("Username '{}' contains a null byte", username))?;

    // SAFETY: getpwnam is given a valid C string and returns a pointer to
    // a static passwd struct (or null). We read and copy the fields
    // immediately, so the borrow does not escape.
    unsafe {
        let pw = libc::getpwnam(c_user.as_ptr());
        if pw.is_null() {
            bail!(
                "User '{}' not found. Create it with \
                 'useradd -r -s /usr/sbin/nologin {}' or use --user <name>",
                username,
                username
            );
        }
        Ok(((*pw).pw_uid, (*pw).pw_gid))
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
            log::warn!(
                "prctl(PR_SET_NO_NEW_PRIVS) failed: {}",
                std::io::Error::last_os_error()
            );
            // Non-fatal — warn but continue
        }
    }
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
}
