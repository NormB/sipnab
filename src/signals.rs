// SPDX-License-Identifier: MIT OR Apache-2.0

//! Signal handling for sipnab.
//!
//! Installs handlers for SIGINT, SIGTERM (graceful shutdown) and SIGUSR1
//! (log/pcap rotation). Uses `libc::sigaction()` with atomic flags for
//! async-signal-safe operation.

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
}

impl SignalFlags {
    /// Both flags clear.
    const fn new() -> Self {
        SignalFlags {
            shutdown: AtomicBool::new(false),
            rotate: AtomicBool::new(false),
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
}

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

/// Returns `true` if a rotation signal (SIGUSR1) has been received,
/// and atomically resets the flag to `false`.
pub fn rotation_requested() -> bool {
    FLAGS.rotation_requested()
}

/// Install signal handlers for SIGINT, SIGTERM, and SIGUSR1.
///
/// - SIGINT / SIGTERM: sets the shutdown flag for graceful exit.
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
    }
    tracing::debug!("Signal handlers installed (SIGINT, SIGTERM, SIGUSR1)");
}

/// Signal handler for SIGINT and SIGTERM.
extern "C" fn shutdown_handler(_sig: libc::c_int) {
    FLAGS.request_shutdown();
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
