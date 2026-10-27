// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors
//
// Included textually with `include!`, for the reason `timeout.rs` gives.

/// Every item a reader thread still holds for a child that has exited: what it
/// forwarded before the exit and what it forwards after.
///
/// Returns once `rx`'s sender hangs up, which a line-reader thread does at end
/// of file, or once `bound` has passed, whichever is first.
#[allow(dead_code)]
fn drain_closed<T>(rx: &std::sync::mpsc::Receiver<T>, bound: std::time::Duration) -> Vec<T> {
    let deadline = std::time::Instant::now() + bound;
    let mut out = Vec::new();
    loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return out;
        }
        // A quiet gap is not the end: a reader on a loaded host forwards the
        // last lines of a child that has already exited whenever it is next
        // scheduled. Only a hang-up says there is nothing more.
        match rx.recv_timeout(left) {
            Ok(item) => out.push(item),
            Err(_) => return out,
        }
    }
}
