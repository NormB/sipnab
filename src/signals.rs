// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Signal handling for sipnab.
//!
//! Installs handlers for SIGINT, SIGTERM and SIGHUP (graceful shutdown) and
//! SIGUSR1 (log/pcap rotation). Uses `libc::sigaction()` with atomic flags for
//! async-signal-safe operation.
//!
//! SIGHUP stops the run the way SIGTERM does, and the process then exits
//! [`HANGUP_EXIT_CODE`] instead of 0. It is not a reload: the secret files
//! and the drop user are read before the privilege drop and the chroot, and a
//! process that has dropped to `nobody` cannot read them again. Exiting
//! non-zero is what makes systemd's `Restart=on-failure` restart the packaged
//! service. An exit by the signal's default action counts as clean to
//! systemd, which left the service stopped with `Result=success` (OPS-5).

use std::sync::atomic::{AtomicBool, Ordering};

/// The two requests a signal can make, and the rules for reading them.
///
/// The process has one instance, [`FLAGS`], which the handlers write. The
/// type exists so the rules can be tested on an instance no other test
/// shares.
struct SignalFlags {
    /// Set when SIGINT or SIGTERM is received, or on [`request_shutdown`].
    shutdown: AtomicBool,
    /// Set when SIGUSR1 is received (rotation trigger).
    rotate: AtomicBool,
    /// Set when SIGHUP is received: the stop it requests ends in
    /// [`HANGUP_EXIT_CODE`].
    hangup: AtomicBool,
}

impl SignalFlags {
    /// Both flags clear.
    const fn new() -> Self {
        SignalFlags {
            shutdown: AtomicBool::new(false),
            rotate: AtomicBool::new(false),
            hangup: AtomicBool::new(false),
        }
    }

    /// Whether shutdown was requested. Reading does not clear it.
    fn shutdown_requested(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }

    /// Request shutdown.
    fn request_shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    /// Whether rotation was requested since the last read; clears it.
    fn rotation_requested(&self) -> bool {
        self.rotate.swap(false, Ordering::SeqCst)
    }

    /// Request rotation.
    fn request_rotation(&self) {
        self.rotate.store(true, Ordering::SeqCst);
    }

    /// Request the stop SIGHUP asks for: shutdown, ending in
    /// [`HANGUP_EXIT_CODE`].
    fn request_hangup(&self) {
        self.hangup.store(true, Ordering::SeqCst);
        self.request_shutdown();
    }

    /// The status to exit with when the run would exit `code`: a run that
    /// would succeed exits [`HANGUP_EXIT_CODE`] after SIGHUP, and any other
    /// code is kept, since it already says the run failed.
    fn exit_code(&self, code: i32) -> i32 {
        if code == 0 && self.hangup.load(Ordering::SeqCst) {
            HANGUP_EXIT_CODE
        } else {
            code
        }
    }
}

/// The exit status of a run stopped by SIGHUP: 128 + 1, the status a shell
/// reports for a process the signal ended. Not 0, so a supervisor that
/// restarts on failure restarts it.
pub const HANGUP_EXIT_CODE: i32 = 128 + libc::SIGHUP;

/// The process's flags, written by the signal handlers.
static FLAGS: SignalFlags = SignalFlags::new();

/// Returns `true` if a shutdown signal (SIGINT/SIGTERM) has been received.
pub fn shutdown_requested() -> bool {
    FLAGS.shutdown_requested()
}

/// Programmatically request a shutdown (e.g., when the TUI exits).
///
/// Sets the same flag as the SIGINT/SIGTERM handler so all threads
/// that check `shutdown_requested` will see it.
pub fn request_shutdown() {
    FLAGS.request_shutdown();
}

/// Request the stop SIGHUP requests: shutdown, ending in
/// [`HANGUP_EXIT_CODE`].
///
/// For a hang-up the process learns of without the signal: the TUI calls it
/// when its terminal reports that it has gone, which a process whose
/// terminal is not its controlling terminal sees with no SIGHUP at all.
pub fn request_hangup() {
    FLAGS.request_hangup();
}

/// The status the process exits with when the run would exit `code`.
///
/// Every exit of a run goes through this, through
/// `capture::archive::release_run_and_exit` or the end of `main`: after
/// SIGHUP a run that would exit 0 exits [`HANGUP_EXIT_CODE`].
#[must_use]
pub fn exit_code(code: i32) -> i32 {
    FLAGS.exit_code(code)
}

/// Returns `true` if a rotation signal (SIGUSR1) has been received,
/// and atomically resets the flag to `false`.
pub fn rotation_requested() -> bool {
    FLAGS.rotation_requested()
}

/// Install signal handlers for SIGINT, SIGTERM, SIGHUP and SIGUSR1.
///
/// - SIGINT / SIGTERM: sets the shutdown flag for graceful exit.
/// - SIGHUP: the same stop, then exit [`HANGUP_EXIT_CODE`].
/// - SIGUSR1: sets the rotation flag for log/pcap rotation.
///
/// # Safety
///
/// Uses `libc::sigaction()` which is safe to call from a single-threaded
/// context during initialization. The handlers only perform atomic writes,
/// which are async-signal-safe.
pub fn install_handlers() {
    // SAFETY: sigaction() is called once during single-threaded initialization before
    // any threads are spawned. The handlers only perform atomic store operations,
    // which are async-signal-safe per POSIX.1-2008 §2.4.3.
    unsafe {
        let mut sa_shutdown: libc::sigaction = std::mem::zeroed();
        sa_shutdown.sa_sigaction = shutdown_handler as *const () as usize;
        sa_shutdown.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&mut sa_shutdown.sa_mask);
        libc::sigaction(libc::SIGINT, &sa_shutdown, std::ptr::null_mut());
        libc::sigaction(libc::SIGTERM, &sa_shutdown, std::ptr::null_mut());

        let mut sa_rotate: libc::sigaction = std::mem::zeroed();
        sa_rotate.sa_sigaction = rotate_handler as *const () as usize;
        sa_rotate.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&mut sa_rotate.sa_mask);
        libc::sigaction(libc::SIGUSR1, &sa_rotate, std::ptr::null_mut());

        let mut sa_hangup: libc::sigaction = std::mem::zeroed();
        sa_hangup.sa_sigaction = hangup_handler as *const () as usize;
        sa_hangup.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&mut sa_hangup.sa_mask);
        libc::sigaction(libc::SIGHUP, &sa_hangup, std::ptr::null_mut());
    }
    tracing::debug!("Signal handlers installed (SIGINT, SIGTERM, SIGHUP, SIGUSR1)");
}

/// Signal handler for SIGINT and SIGTERM.
extern "C" fn shutdown_handler(_sig: libc::c_int) {
    FLAGS.request_shutdown();
}

/// Signal handler for SIGHUP.
extern "C" fn hangup_handler(_sig: libc::c_int) {
    FLAGS.request_hangup();
}

/// Signal handler for SIGUSR1.
extern "C" fn rotate_handler(_sig: libc::c_int) {
    FLAGS.request_rotation();
}

#[cfg(test)]
mod tests {
    use super::*;

    // Each test reads its own `SignalFlags`. The process-wide instance is
    // shared by every test in this binary, and the test harness runs tests in
    // parallel: one test resetting it while another expected it set made both
    // fail intermittently.

    /// Both flags read `false` before any signal.
    #[test]
    fn default_flags_are_false() {
        let flags = SignalFlags::new();
        assert!(!flags.shutdown_requested());
        assert!(!flags.rotation_requested());
    }

    /// A shutdown request is observable and, unlike rotation, stays set
    /// after it is read.
    #[test]
    fn shutdown_flag_set_and_read() {
        let flags = SignalFlags::new();
        flags.request_shutdown();
        assert!(flags.shutdown_requested());
        assert!(flags.shutdown_requested(), "a read must not clear shutdown");
    }

    /// The rotation flag is read-once: the first read after a signal returns
    /// `true` and clears it; the next returns `false`.
    #[test]
    fn rotation_flag_resets_on_read() {
        let flags = SignalFlags::new();
        flags.request_rotation();
        assert!(flags.rotation_requested());
        assert!(!flags.rotation_requested());
    }

    /// A hangup requests the same shutdown SIGTERM does, and turns a
    /// successful exit into 129; a failing exit keeps its own code.
    #[test]
    fn a_hangup_stops_the_run_and_exits_129() {
        let flags = SignalFlags::new();
        assert_eq!(flags.exit_code(0), 0, "no signal: the run's own code");
        flags.request_hangup();
        assert!(flags.shutdown_requested(), "a hangup requests shutdown");
        assert!(!flags.rotation_requested(), "a hangup is not a rotation");
        assert_eq!(
            flags.exit_code(0),
            129,
            "a successful run hung up exits 128 + 1"
        );
        assert_eq!(flags.exit_code(2), 2, "a failure keeps its own code");
    }

    /// SIGTERM's stop exits with the run's own code.
    #[test]
    fn a_plain_shutdown_keeps_the_exit_code() {
        let flags = SignalFlags::new();
        flags.request_shutdown();
        assert_eq!(
            flags.exit_code(0),
            0,
            "SIGTERM ends a successful run with 0"
        );
    }

    /// The two flags are independent: rotation does not request shutdown,
    /// and shutdown does not request rotation.
    #[test]
    fn the_flags_do_not_set_each_other() {
        let rotate = SignalFlags::new();
        rotate.request_rotation();
        assert!(!rotate.shutdown_requested());
        let stop = SignalFlags::new();
        stop.request_shutdown();
        assert!(!stop.rotation_requested());
    }
}
