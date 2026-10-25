// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Which of several capture files hold the dialogs a filter selects.
//!
//! The sweep is [`crate::capture::sweep::sweep_files`], which the MCP
//! `find_in_captures` tool runs on a job thread and `--find-in-files` runs in
//! the foreground; its answer is [`SweepOutcome`], the `sweep` the tool
//! reports. A directory names the capture and vCon files directly in it,
//! chosen by name and sorted, symbolic links skipped, by
//! [`crate::capture::archive::listed_files`], the rule the tool's file root is
//! listed by.

use std::path::PathBuf;

use crate::capture::sweep::SweepOutcome;
use crate::output::ReportFormat;

/// The files `paths` name, in order: a file as given, a directory as the
/// capture and vCon files directly in it.
///
/// # Errors
///
/// A message naming the directory when one cannot be read.
pub fn candidates(paths: &[PathBuf]) -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    for path in paths {
        if path.is_dir() {
            let listed = crate::capture::archive::listed_files(path)
                .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
            out.extend(listed.into_iter().map(|(file, _)| file));
        } else {
            out.push(path.clone());
        }
    }
    Ok(out)
}

/// The sweep as text: a line saying how many files held a match and whether
/// every file was read, a row per file that did, and every file that could
/// not be read with its reason.
#[must_use]
pub fn render(answer: &SweepOutcome, format: ReportFormat) -> String {
    use std::fmt::Write as _;

    let mut out = format!(
        "Found in {} of {}; ",
        answer.matches.len(),
        super::plural(answer.files_total as u64, "file"),
    );
    if answer.complete {
        out.push_str("every file was read.\n");
    } else {
        let _ = writeln!(
            out,
            "not complete: {} of {} read, so a file not read may hold a match.",
            answer.files_examined, answer.files_total
        );
    }
    let rows: Vec<Vec<String>> = answer
        .matches
        .iter()
        .map(|m| {
            vec![
                m.filename.clone(),
                m.dialogs_matched.to_string(),
                m.first_call_id.clone().unwrap_or_else(|| "-".to_string()),
            ]
        })
        .collect();
    if !rows.is_empty() {
        out.push_str(&super::table(
            format,
            &["File", "Dialogs", "First Call-ID"],
            &rows,
        ));
    }
    for file in &answer.unreadable {
        let _ = writeln!(
            out,
            "Not read: {}: {}",
            super::clean(&file.filename),
            super::clean(&file.reason)
        );
    }
    if let Some(why) = answer.stopped_because {
        let _ = writeln!(out, "Stopped early: {}", why.as_str());
    }
    out
}
