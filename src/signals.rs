//! Signal handling for sipnab.
//!
//! Installs handlers for SIGINT, SIGTERM (graceful shutdown) and SIGUSR1
//! (log/pcap rotation). Uses `libc::sigaction()` with atomic flags for
//! async-signal-safe operation.

use std::sync::atomic::{AtomicBool, Ordering};

/// Global flag: set to `true` when SIGINT or SIGTERM is received.
static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Global flag: set to `true` when SIGUSR1 is received (rotation trigger).
static ROTATE_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Returns `true` if a shutdown signal (SIGINT/SIGTERM) has been received.
pub fn shutdown_requested() -> bool {
    SHUTDOWN_REQUESTED.load(Ordering::SeqCst)
}

/// Programmatically request a shutdown (e.g., when the TUI exits).
///
/// Sets the same flag as the SIGINT/SIGTERM handler so all threads
/// that check [`shutdown_requested`] will see it.
pub fn request_shutdown() {
    SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
}

/// Returns `true` if a rotation signal (SIGUSR1) has been received,
/// and atomically resets the flag to `false`.
pub fn rotation_requested() -> bool {
    ROTATE_REQUESTED.swap(false, Ordering::SeqCst)
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
    log::debug!("Signal handlers installed (SIGINT, SIGTERM, SIGUSR1)");
}

/// Signal handler for SIGINT and SIGTERM.
extern "C" fn shutdown_handler(_sig: libc::c_int) {
    SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
}

/// Signal handler for SIGUSR1.
extern "C" fn rotate_handler(_sig: libc::c_int) {
    ROTATE_REQUESTED.store(true, Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_flags_are_false() {
        // Reset flags for a clean test
        SHUTDOWN_REQUESTED.store(false, Ordering::SeqCst);
        ROTATE_REQUESTED.store(false, Ordering::SeqCst);

        assert!(!shutdown_requested());
        assert!(!rotation_requested());
    }

    #[test]
    fn shutdown_flag_set_and_read() {
        SHUTDOWN_REQUESTED.store(false, Ordering::SeqCst);

        assert!(!shutdown_requested());
        SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
        assert!(shutdown_requested());

        // Cleanup
        SHUTDOWN_REQUESTED.store(false, Ordering::SeqCst);
    }

    #[test]
    fn rotation_flag_resets_on_read() {
        ROTATE_REQUESTED.store(false, Ordering::SeqCst);

        assert!(!rotation_requested());
        ROTATE_REQUESTED.store(true, Ordering::SeqCst);
        // First read returns true and resets
        assert!(rotation_requested());
        // Second read returns false
        assert!(!rotation_requested());
    }
}
