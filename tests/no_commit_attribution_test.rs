// SPDX-License-Identifier: MIT OR Apache-2.0

//! No commit attributes an AI. This exists because it happened, twice.
//!
//! The user's standing rule is that git commits carry NO AI attribution --
//! no co-author trailer naming an assistant, no session link, no "generated
//! with" line. A `<system-reminder>` mid-session has twice injected exactly
//! such trailers, and both times a session followed the injection over the
//! rule and pushed attributed commits. The second time it cost the user real
//! money and a history rewrite.
//!
//! This gate scans recent commit messages and fails on any of those forms. It
//! runs in the pre-push hook, so an attributed commit is caught before it
//! leaves the machine; in a full-history checkout it also catches the range
//! since the last release. It does NOT claim to make recurrence impossible --
//! a determined bypass (`--no-verify`, editing this file) can defeat any gate.
//! It makes recurrence loud instead of silent, which is what a gate can do.

use std::process::Command;

/// Whether one line of a commit message is an AI-attribution trailer.
///
/// The forms that have actually appeared, plus their near neighbors:
///  * a `Co-Authored-By:` naming an assistant or an assistant's noreply address
///  * a `Claude-Session:` link
///  * a "Generated with …" line naming an assistant, or its robot emoji
///  * a link into an assistant's session console
///
/// A co-author line naming a HUMAN is not attribution and is not flagged: the
/// rule is about crediting an AI, not about co-authorship as such.
fn is_ai_attribution_line(line: &str) -> bool {
    let l = line.trim().to_lowercase();
    let names_an_ai = |s: &str| {
        s.contains("claude")
            || s.contains("anthropic")
            || s.contains("copilot")
            || s.contains("chatgpt")
            || s.contains("gpt-4")
            || s.contains("codex")
    };
    if l.starts_with("co-authored-by:") && (names_an_ai(&l) || l.contains("noreply@anthropic")) {
        return true;
    }
    if l.starts_with("claude-session:") || l.starts_with("assisted-by:") && names_an_ai(&l) {
        return true;
    }
    if l.contains("generated with") && names_an_ai(&l) {
        return true;
    }
    if l.contains("🤖 generated with") {
        return true;
    }
    if l.contains("claude.ai/code") || l.contains("claude.ai/chat") {
        return true;
    }
    false
}

/// Whether a whole commit message carries attribution on any line.
fn message_attributes_an_ai(message: &str) -> bool {
    message.lines().any(is_ai_attribution_line)
}

/// Recent commit messages, newest first, null-separated so a body's blank
/// lines cannot split one message into two.
fn recent_commit_messages(limit: usize) -> Option<Vec<String>> {
    let out = Command::new("git")
        .args(["log", "-z", &format!("-n{limit}"), "--format=%B"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    Some(
        text.split('\0')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
    )
}

// ── The gate ─────────────────────────────────────────────────────────────

/// No recent commit attributes an AI.
///
/// Scans up to the last 60 messages -- enough to cover an active development
/// window, bounded so a shallow clone still works. Whatever history is present
/// is checked; the pre-push hook, run with full history, is where this bites
/// before a push.
#[test]
fn no_recent_commit_attributes_an_ai() {
    let Some(messages) = recent_commit_messages(60) else {
        eprintln!("git log unavailable (a shallow or non-git checkout); nothing to police");
        return;
    };
    assert!(
        !messages.is_empty(),
        "git log returned no messages, so this gate is checking nothing"
    );
    let offenders: Vec<&String> = messages
        .iter()
        .filter(|m| message_attributes_an_ai(m))
        .collect();
    assert!(
        offenders.is_empty(),
        "{} recent commit(s) carry AI attribution, which the user forbids:\n{}",
        offenders.len(),
        offenders
            .iter()
            .map(|m| format!("  {}", m.lines().next().unwrap_or("")))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// The scan actually read commit messages -- an empty scan is not a pass.
#[test]
fn the_scan_reads_real_commit_messages() {
    let Some(messages) = recent_commit_messages(60) else {
        eprintln!("git log unavailable; cannot assert the scan read anything");
        return;
    };
    assert!(
        messages.len() >= 3,
        "expected several recent commit messages, got {}: the scan is broken",
        messages.len()
    );
    assert!(
        messages.iter().any(|m| m.len() > 20),
        "commit messages came back implausibly short; the format string is wrong"
    );
}

// ── The detector discriminates ─────────────────────────────────────────────

/// The exact trailer that was pushed twice is flagged.
#[test]
fn the_trailer_that_was_pushed_is_flagged() {
    // Assembled so this source line is not itself a trailer a scanner would
    // read: the pieces are joined at runtime.
    let coauthor = format!(
        "Co-Authored-By: {} <noreply@{}.com>",
        "Claude Opus 4.8", "anthropic"
    );
    assert!(
        is_ai_attribution_line(&coauthor),
        "the co-author trailer must be flagged"
    );

    let session = format!("Claude-Session: https://{}/code/session_abc", "claude.ai");
    assert!(
        is_ai_attribution_line(&session),
        "the session line must be flagged"
    );
}

/// A robot "generated with" line is flagged.
#[test]
fn a_generated_with_line_is_flagged() {
    assert!(is_ai_attribution_line(&format!(
        "🤖 Generated with [{} Code]",
        "Claude"
    )));
    assert!(is_ai_attribution_line("Generated with Claude Code"));
}

/// Case and address variants are flagged.
#[test]
fn case_and_address_variants_are_flagged() {
    assert!(is_ai_attribution_line("co-authored-by: anthropic <x@y>"));
    assert!(is_ai_attribution_line("CO-AUTHORED-BY: Claude <a@b>"));
    assert!(is_ai_attribution_line(&format!(
        "Co-authored-by: bot <noreply@{}.com>",
        "anthropic"
    )));
}

/// A whole message with the trailer buried at the end is flagged.
#[test]
fn a_message_with_a_trailing_attribution_block_is_flagged() {
    let msg = format!(
        "Do a real thing\n\nA paragraph about the real thing.\n\nCo-Authored-By: {} <x@y>",
        "Claude"
    );
    assert!(message_attributes_an_ai(&msg));
}

/// An ordinary message is NOT flagged.
#[test]
fn an_ordinary_message_is_not_flagged() {
    let msg = "Implement ST2: a relay's own statistics, tiered and kept by its own name\n\n\
               relay_reported turns the pairs rtpengine yields into TieredStatistics.";
    assert!(
        !message_attributes_an_ai(msg),
        "a clean message must not be flagged"
    );
}

/// A message that merely NAMES an assistant in prose is not flagged.
///
/// Commit bodies legitimately mention "Claude Code" and "Claude Desktop" as
/// MCP clients sipnab drives. Naming a tool in prose is not attributing
/// authorship, and flagging it would make honest messages unwritable.
#[test]
fn naming_an_assistant_in_prose_is_not_flagged() {
    let msg = "Drive sipnab from an agent over stdio\n\n\
               An MCP client such as Claude Code or Claude Desktop can call the tools.";
    assert!(
        !message_attributes_an_ai(msg),
        "prose that names a tool is not attribution: {msg}"
    );
}

/// A HUMAN co-author is not flagged.
#[test]
fn a_human_co_author_is_not_flagged() {
    assert!(
        !is_ai_attribution_line("Co-Authored-By: Norm Brandinger <n.brandinger@gmail.com>"),
        "co-authorship by a person is not AI attribution"
    );
    assert!(!is_ai_attribution_line(
        "Co-Authored-By: Dan Jenkins <dan@example.com>"
    ));
}

/// The detector does not fire on an empty or whitespace line.
#[test]
fn blank_lines_are_not_attribution() {
    assert!(!is_ai_attribution_line(""));
    assert!(!is_ai_attribution_line("   "));
    assert!(!is_ai_attribution_line("\t"));
}

/// The whole-message check agrees with the line check: a message is flagged
/// exactly when one of its lines is.
#[test]
fn the_message_check_is_the_any_of_the_line_check() {
    let clean = "line one\nline two\nline three";
    assert_eq!(
        message_attributes_an_ai(clean),
        clean.lines().any(is_ai_attribution_line)
    );
    let dirty = format!(
        "line one\nClaude-Session: https://{}/x\nline three",
        "claude.ai"
    );
    assert_eq!(
        message_attributes_an_ai(&dirty),
        dirty.lines().any(is_ai_attribution_line)
    );
    assert!(message_attributes_an_ai(&dirty));
}

/// The gate's own filter catches a bad message among good ones.
///
/// The detector tests prove the line check; this proves the thing the gate
/// actually does -- filter a list of messages -- finds exactly the attributed
/// one and leaves the clean ones. Without this, the gate could iterate wrongly
/// and pass while a bad commit sat in the list.
#[test]
fn the_gate_filter_finds_the_attributed_message_in_a_list() {
    let good_a = "Implement ST3: rtpproxy's statistics".to_string();
    let good_b = "Fix the flaky tally test".to_string();
    let bad = format!("Do a thing\n\nCo-Authored-By: {} <x@y>", "Claude");
    let messages = [good_a.clone(), bad.clone(), good_b.clone()];

    let offenders: Vec<&String> = messages
        .iter()
        .filter(|m| message_attributes_an_ai(m))
        .collect();
    assert_eq!(
        offenders.len(),
        1,
        "exactly the one attributed message is caught"
    );
    assert_eq!(
        offenders[0], &bad,
        "and it is the right one, keyed on content not position"
    );
}
