// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The headings that open the fixed parts of a how-to page.
//!
//! `howto_sections_test.rs` requires these headings on every task page, and
//! `how_to_headings_stay_task_first` in `docs_drift_test.rs` leaves them out
//! of its count of goal-first headings. Both read the predicates here, so a
//! heading one gate demands is never one the other refuses.

/// True when a heading opens the prerequisites of a task.
pub fn is_prerequisites(title: &str) -> bool {
    let title = title.to_lowercase();
    ["before you start", "what you need", "prerequisites"]
        .iter()
        .any(|opening| title.starts_with(opening))
}

/// True when a heading opens the check that the task worked.
pub fn is_verify(title: &str) -> bool {
    let title = title.to_lowercase();
    title == "verify"
        || ["verify ", "check that ", "check it worked"]
            .iter()
            .any(|opening| title.starts_with(opening))
}

/// True when a heading opens the failures of a task and their fixes.
pub fn is_troubleshoot(title: &str) -> bool {
    let title = title.to_lowercase();
    title.starts_with("troubleshoot")
        || (title.starts_with("when ") && title.contains(" does not "))
}

/// True for a heading that opens any of the three parts.
#[allow(dead_code, reason = "each test binary uses the predicates it needs")]
pub fn is_part(title: &str) -> bool {
    is_prerequisites(title) || is_verify(title) || is_troubleshoot(title)
}
