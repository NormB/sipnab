// SPDX-License-Identifier: MIT OR Apache-2.0

//! Nothing in this repository names the machines it is developed on.
//!
//! sipnab is a packet analyzer developed against a private lab, and the lab is
//! not the reader's. A page that says `opensips-1.goes.com` or `10.0.0.40` is
//! two failures at once: it publishes the maintainer's own network, and it
//! hands the reader a hostname they cannot resolve in place of the example they
//! needed. The first cannot be undone -- this repository is public, so a
//! private name reaching `main` is disclosed the moment it is pushed, and
//! removing it later leaves it in the history.
//!
//! Seven classes leaked before this file existed, and each one has ten tests:
//!
//! | Class | What leaked |
//! |---|---|
//! | A | The aarch64 development host, including inside sample JSON output |
//! | B | The lab's VMs and containers, and the host under them |
//! | C | The lab's DNS domain, as a fully qualified hostname |
//! | D | The lab's LAN, in prose and in a rendered social-preview image |
//! | E | An account name, and the path to a private capture corpus |
//! | F | A tracked gate transcript, carrying a worktree path verbatim |
//! | G | Sample output addressed to domains somebody really owns |
//!
//! Class H is a rule rather than a leak: no commit message or tracked file
//! credits an AI assistant as an author. It shares this file because it shares
//! the message check the commit-msg hook and CI run.
//!
//! # Why each class gets controls and not just a scan
//!
//! A scan that finds nothing is indistinguishable from a scan that looks at
//! nothing. Every class therefore carries POSITIVE controls -- the rule is
//! shown to flag the exact string that leaked, and a variant of it -- and
//! NEGATIVE controls, which are the half that decides whether anyone keeps the
//! gate: a rule that flags `Jetson AGX Thor` while trying to catch `thor-02`
//! gets suppressed within a week, and then catches nothing at all.
//!
//! # No exception, not even for a runner label
//!
//! Workflows reached the self-hosted runner with `runs-on: [self-hosted,
//! <host>]`, and that label was allowlisted as functional. The runner also
//! carries a hardware label, `jetson`, so since 2026-10-07 the workflows use
//! that and the host label is scanned like every other line. B6 holds the
//! self-hosted jobs to the hardware label.

use std::collections::BTreeSet;
use std::net::Ipv6Addr;
use std::path::{Path, PathBuf};
use std::process::Command;

#[path = "support/executable.rs"]
mod executable;

type TestError = Box<dyn std::error::Error>;

// -- Harness ---------------------------------------------------------

fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// Extensions whose bytes are not prose and must not be scanned as prose.
///
/// A capture fixture holds arbitrary wire bytes and a PNG holds arbitrary
/// anything, so a substring match against either is noise. Excluded by TYPE
/// rather than by a UTF-8 test, so a fixture that happens to decode cleanly
/// does not silently enter the scan.
const BINARY_EXT: &[&str] = &[
    "pcap", "pcapng", "png", "jpg", "jpeg", "gif", "ico", "gz", "xz", "zst", "bin", "wav", "woff",
    "woff2", "ttf", "otf", "pdf", "wasm", "o", "a",
];

/// Third-party bundles, whose identifiers collide with these names by chance.
///
/// A minified bundle names its locals `n`, `e` and, sooner or later, `norm2`.
/// It is vendored rather than written here, so a match in it is a coincidence
/// and a rewrite of it would be a fork.
fn is_vendored(rel: &str) -> bool {
    rel.ends_with(".min.js") || rel.ends_with(".min.css")
}

/// Every tracked text file, as (repo-relative path, contents).
///
/// Through `git ls-files` rather than by walking: an untracked scratch file is
/// not published and is not this gate's business, and walking would pull in
/// `target/` and every worktree artefact besides.
fn tracked_text() -> Result<Vec<(String, String)>, TestError> {
    let out = Command::new("git")
        .args(["ls-files"])
        .current_dir(repo())
        .output()
        .map_err(|e| {
            format!("git ls-files -- the scan is over what is tracked, not what is present: {e}")
        })?;
    assert!(
        out.status.success(),
        "git ls-files failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let mut files = Vec::new();
    for rel in String::from_utf8_lossy(&out.stdout).lines() {
        let ext = PathBuf::from(rel)
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if BINARY_EXT.contains(&ext.as_str()) || is_vendored(rel) {
            continue;
        }
        // A file the index names and the tree lacks is a deletion in flight,
        // not a violation.
        if let Ok(text) = std::fs::read_to_string(repo().join(rel)) {
            files.push((rel.to_string(), text));
        }
    }
    Ok(files)
}

/// Surfaces a reader of the project sees.
///
/// Wider than `docs/`: the changelog, the readme, the generated site, the
/// benchmark baselines and the bench harness's readme are all read by people
/// who do not have the lab.
fn is_published(rel: &str) -> bool {
    rel.starts_with("docs/")
        || rel.starts_with("website/")
        || rel.starts_with("benches/")
        || rel.starts_with("bench/")
        || rel == "README.md"
        || rel == "CHANGELOG.md"
}

/// Prose a reader takes a value out of: pages, readme, changelog.
///
/// Narrower than [`is_published`] by two directories, and the difference is
/// deliberate. A benchmark's SDP body and the live-capture harness's
/// `10.0.0.0/24 dev veth` are fixtures and real routes, not examples anyone
/// copies.
fn is_prose(rel: &str) -> bool {
    rel.starts_with("docs/")
        || rel.starts_with("website/")
        || rel == "README.md"
        || rel == "CHANGELOG.md"
}

/// A workflow line that selects a self-hosted runner, which B6 holds to the
/// hardware label.
fn is_runner_label(line: &str) -> bool {
    let l = line.trim();
    (l.contains("runs-on:") || l.contains("labels:")) && l.contains("self-hosted")
}

/// Every `path:line: text` where `hit` holds, over files `keep` admits.
///
/// This file is skipped throughout: the gate names what it bans, so scanning
/// itself reports every rule as a violation of itself. By path rather than by
/// a marker comment, because a marker is something a future rule forgets.
fn scan(
    files: &[(String, String)],
    keep: impl Fn(&str) -> bool,
    hit: impl Fn(&str) -> bool,
) -> Vec<String> {
    let mut found = Vec::new();
    for (rel, text) in files {
        if rel == "tests/private_identity_test.rs" || !keep(rel) {
            continue;
        }
        for (i, line) in text.lines().enumerate() {
            if hit(line) {
                let excerpt: String = line.trim().chars().take(110).collect();
                found.push(format!("{rel}:{}: {excerpt}", i + 1));
            }
        }
    }
    found
}

/// Report at most `n` hits, then say how many were withheld.
///
/// A gate that prints 900 lines is read as carefully as one that prints none,
/// and the count is the part that says how big the job is.
fn capped(found: &[String], n: usize) -> String {
    let mut s = found
        .iter()
        .take(n)
        .map(|l| format!("  {l}"))
        .collect::<Vec<_>>()
        .join("\n");
    if found.len() > n {
        s.push_str(&format!("\n  ... and {} more", found.len() - n));
    }
    s
}

/// A match that does not fire inside a longer word.
fn word(line: &str, needle: &str) -> bool {
    let bytes = line.as_bytes();
    let boundary =
        |c: Option<&u8>| !matches!(c, Some(b) if b.is_ascii_alphanumeric() || *b == b'_');
    line.match_indices(needle).any(|(i, _)| {
        boundary(bytes.get(i.wrapping_sub(1)).filter(|_| i > 0))
            && boundary(bytes.get(i + needle.len()))
    })
}

/// How many files a predicate admits, for the anti-vacuity tests.
fn corpus_size(files: &[(String, String)], keep: impl Fn(&str) -> bool) -> usize {
    files
        .iter()
        .filter(|(r, _)| r != "tests/private_identity_test.rs" && keep(r))
        .count()
}

/// The contributing guide, which is where a writer meets these rules first.
fn contributing() -> Result<String, TestError> {
    Ok(std::fs::read_to_string(repo().join("CONTRIBUTING.md"))
        .map_err(|e| format!("CONTRIBUTING.md is where a contributor is told the rules: {e}"))?
        .to_ascii_lowercase())
}

/// Does the scan reach this file at all?
fn reaches(files: &[(String, String)], rel: &str) -> bool {
    files.iter().any(|(r, _)| r == rel)
}

// -- The rules, as predicates the controls can exercise ---------------
//
// Extracted so a test can hand each rule a line and check the verdict. A rule
// that only ever runs over the tree can be proven clean and never proven to
// work: the tree is clean, so every rule passes -- including one that returns
// `false` unconditionally.

mod rule {
    use super::word;

    /// A. The aarch64 development host, in both spellings.
    pub fn lab_host(line: &str) -> bool {
        word(line, "thor-02") || word(line, "thor02")
    }

    /// A. A bare lowercase `thor` is the box; `Thor` is the board.
    pub fn bare_host(line: &str) -> bool {
        word(line, "thor") && !line.contains("Thor")
    }

    /// B. The lab's VMs, containers and the host under them.
    pub const LAB_MACHINES: &[&str] = &["opensips-1", "nas2", "miner1", "norm2"];

    pub fn lab_machine(line: &str) -> bool {
        LAB_MACHINES.iter().any(|m| word(line, m))
    }

    /// C. The lab's DNS domain.
    pub fn private_domain(line: &str) -> bool {
        line.contains("goes.com")
    }

    /// D. The lab's LAN, `10.0.0.0/24`.
    ///
    /// Not RFC 1918 as a class: `10.0.2.15` is QEMU's default guest address and
    /// belongs in sample output.
    pub fn lab_address(line: &str) -> bool {
        line.split("10.0.0.")
            .skip(1)
            .any(|rest| rest.chars().next().is_some_and(|c| c.is_ascii_digit()))
    }

    /// E. Accounts on the machines this project is developed on.
    pub const PRIVATE_ACCOUNTS: &[&str] = &["gator"];

    /// E. Where a home directory lives, on the systems this is developed on.
    ///
    /// Lowercase, because [`account_path`] matches against a lowercased line:
    /// `corpus_path` hands it one, and `/Users` is the macOS spelling.
    pub const HOME_ROOTS: &[&str] = &["/home", "/users", "/var/home", "/export/home"];

    /// E. A path under a real account's home directory.
    ///
    /// The rule is the ACCOUNT, not the shape: `/home/user/capture.pcap` in a
    /// synopsis is a placeholder every reader substitutes.
    ///
    /// It used to be the account under ONE root. `/home/{a}` was the only form
    /// this matched, so `E1` reported the tree clean while three occurrences
    /// under two other roots sat in it -- `/Users/<account>` in
    /// `scripts/fix-line-anchors.py` and `scripts/fix-tables.py`, and
    /// `~<account>` in `docs/design/backlog.md`. Every one names the account
    /// exactly as loudly as the form that was banned.
    ///
    /// Enumerating roots cannot be the whole answer -- a fifth will appear --
    /// which is why `two_part_reference_test::
    /// no_tracked_file_names_a_private_account_outside_the_gate_that_bans_it`
    /// exists beside it and matches the NAME at a word boundary with no path
    /// shape at all. That one is the superset and cannot be slipped past by
    /// inventing a prefix; this one keeps the specific, actionable message
    /// about paths, which is the form that actually gets pasted in.
    pub fn account_path(line: &str) -> bool {
        let low = line.to_ascii_lowercase();
        PRIVATE_ACCOUNTS.iter().any(|a| {
            HOME_ROOTS
                .iter()
                .any(|r| ends_a_name(&low, &format!("{r}/{a}")))
                || ends_a_name(&low, &format!("~{a}"))
        })
    }

    /// `needle` occurs in `hay` and is not the start of a longer name.
    ///
    /// Without the trailing boundary the tilde form matches any LONGER
    /// account name that starts the same way, and the rule then accuses a
    /// different account -- the shape of false positive that gets a gate
    /// suppressed.
    fn ends_a_name(hay: &str, needle: &str) -> bool {
        let bytes = hay.as_bytes();
        hay.match_indices(needle).any(|(i, _)| {
            !matches!(bytes.get(i + needle.len()), Some(c) if c.is_ascii_alphanumeric() || *c == b'_')
        })
    }

    /// E. The location of a private capture corpus.
    pub fn corpus_path(line: &str) -> bool {
        let l = line.to_ascii_lowercase();
        (l.contains("/pcaps") || l.contains("/captures/")) && account_path(&l)
    }

    /// F. A transcript or editor artefact, by filename.
    pub fn transcript_file(rel: &str) -> bool {
        rel.ends_with(".log")
            || rel.ends_with(".bak")
            || rel.ends_with(".orig")
            || rel.ends_with(".rej")
            || rel.ends_with(".swp")
            || rel.ends_with('~')
    }

    /// G. Top-level domains that resolve, so an address at one reaches somebody.
    ///
    /// The rule runs this way round on purpose. RFC 2606 reserves `.test`,
    /// `.example`, `.invalid` and `.localhost` precisely so a document can
    /// carry an address that cannot reach anyone, and a SIP `Call-ID` like
    /// `call-NNNN@sipnab.bench` is not a mailbox at all. Listing the domains
    /// that DO resolve keeps both out without an allowlist that grows one
    /// fixture at a time.
    pub const REAL_TLDS: &[&str] = &[
        "com", "net", "org", "io", "dev", "edu", "gov", "mil", "info", "biz", "co", "uk", "de",
        "fr", "nl", "eu", "ca", "au", "jp", "cn", "ru", "ch", "se", "no", "it", "es", "us",
    ];

    /// G. Identities that are published on purpose.
    pub const PUBLISHED_IDENTITIES: &[&str] = &[
        "n.brandinger@gmail.com",
        "noreply@github.com",
        "security@sipnab.com",
    ];

    /// G. Is this address one that reaches a real mailbox?
    pub fn live_address(addr: &str) -> bool {
        let low = addr.to_ascii_lowercase();
        let domain = low.split('@').nth(1).unwrap_or_default().to_string();
        let tld = domain.rsplit('.').next().unwrap_or_default();
        let reserved = ["example.com", "example.org", "example.net"]
            .iter()
            .any(|e| domain == *e || domain.ends_with(&format!(".{e}")));
        !PUBLISHED_IDENTITIES.contains(&low.as_str()) && !reserved && REAL_TLDS.contains(&tld)
    }

    /// H. A line that credits an AI assistant as an author of the work.
    ///
    /// Four forms, case-insensitive: a `Co-Authored-By:` trailer naming Claude
    /// or Anthropic, a "Generated with Claude Code" line (bracketed as a link
    /// or not), the assistant's noreply address, and a `Claude-Session:`
    /// trailer. A bare "Claude" is not one of them: Claude Code and Claude
    /// Desktop are MCP clients the MCP documentation has to name.
    pub fn ai_attribution(line: &str) -> bool {
        let l = line.to_ascii_lowercase();
        (l.contains("co-authored-by:") && (l.contains("claude") || l.contains("anthropic")))
            || l.contains("generated with [claude code]")
            || l.contains("generated with claude code")
            || l.contains("noreply@anthropic.com")
            || l.contains("claude-session:")
    }
}

/// What to write instead, per class. Named in the failure and checked by it.
mod guidance {
    pub const HOST: &str = "Name what the machine IS -- `the aarch64 self-hosted runner`, \
                            `Jetson AGX Thor, 14 cores` -- never which box it was.";
    pub const MACHINE: &str = "Name the role: `the x86_64 OpenSIPS VM`, `the aarch64 host`.";
    pub const DOMAIN: &str = "RFC 2606 reserves example.com for exactly this.";
    pub const ADDRESS: &str = "RFC 5737 reserves 192.0.2.0/24, 198.51.100.0/24 and \
                               203.0.113.0/24 for documentation.";
    pub const PATH: &str = "Write `$HOME`, `/srv/pcaps`, or a path relative to the repository.";
    pub const TRANSCRIPT: &str = "Untrack it and add the pattern to .gitignore.";
    pub const MAILBOX: &str = "RFC 2606 reserves .test, .example and .invalid for addresses \
                               that cannot reach anyone.";
    pub const AI_ATTRIBUTION: &str = "Delete the line. Commits and files carry no AI \
                                      attribution: no Co-Authored-By naming an assistant, no \
                                      `Generated with` line, no session trailer. Naming an MCP \
                                      client such as Claude Code or Claude Desktop is fine.";
}

// -- Messages: commit messages and pull request descriptions ----------
//
// A commit message is published the moment the commit is pushed, and it
// reaches `main`: this repository's squash merges build the commit message
// from the branch's commit messages, and its title from the commit (one
// commit) or the pull request title. A pull request description stays on the
// pull request page, and it is public from the moment the pull request is
// opened. Neither is a tracked file, so nothing above reads them. The descriptions of #389 and #393 named the development host and were
// edited by hand on 2026-10-07 to remove it.

/// The line git writes above the diff that `git commit -v` appends.
const SCISSORS: &str = "# ------------------------ >8 ------------------------";

/// One private identity in a message: 1-based line number, class, the line.
type Finding = (usize, &'static str, String);

/// A rule over one line of text.
type LineRule = fn(&str) -> bool;

/// Every line of a commit message or pull request description that names a
/// private identity, with its class.
///
/// The classes are the ones a message can carry: A and B (the host and the
/// lab's machines), C (the domain), D (the LAN) and E (account and corpus
/// paths). Not G: a `Signed-off-by:` or `Reported-by:` trailer carries a real
/// address on purpose.
///
/// Every line is read, `#` lines included. git removes `#` lines only from a
/// message written in an editor; `git commit -m` and `-F` keep them, and a
/// pull request description is published with its Markdown headings, which
/// start with `#`.
///
/// Reading stops at the scissors line, because `git commit -v` appends the
/// staged diff below it and git removes everything from that line down before
/// it makes the commit. One gap remains: git removes that part only when the
/// message is edited in an editor, so a scissors line typed into a
/// `git commit -m` message keeps the lines below it in the commit, unchecked
/// by the hook. CI reads committed messages with [`Scissors::Read`], which
/// closes that gap for every commit in a pull request.
fn message_findings(text: &str) -> Vec<Finding> {
    message_findings_from(text, Scissors::Cut)
}

/// What the scan does at a scissors line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scissors {
    /// Stop there: the message is being written, and git removes the line
    /// and everything below it (the commit-msg hook).
    Cut,
    /// Read on: the text is already published as it stands, a committed
    /// message read back from git or a pull request's text, and nothing
    /// removes the lines below it (CI).
    Read,
}

/// [`message_findings`], with the scissors line handled as `scissors` says.
fn message_findings_from(text: &str, scissors: Scissors) -> Vec<Finding> {
    let classes: [(&'static str, LineRule); 6] = [
        ("A", |l| rule::lab_host(l) || rule::bare_host(l)),
        ("B", rule::lab_machine),
        ("C", rule::private_domain),
        ("D", rule::lab_address),
        ("E", |l| rule::account_path(l) || rule::corpus_path(l)),
        ("H", rule::ai_attribution),
    ];
    let mut found = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if scissors == Scissors::Cut && line == SCISSORS {
            break;
        }
        for (class, hit) in classes {
            if hit(line) {
                found.push((i + 1, class, line.to_string()));
            }
        }
    }
    found
}

/// The replacement text for a class `message_findings` reports.
fn guidance_for(class: &str) -> &'static str {
    match class {
        "A" => guidance::HOST,
        "B" => guidance::MACHINE,
        "C" => guidance::DOMAIN,
        "D" => guidance::ADDRESS,
        "H" => guidance::AI_ATTRIBUTION,
        _ => guidance::PATH,
    }
}

/// The `#[ignore]`d test the commit-msg hook runs, by exact name.
const MESSAGE_TEST: &str = "message_in_sipnab_scan_message_names_no_private_identity";

/// The script that runs [`MESSAGE_TEST`] over one message file.
const MESSAGE_SCRIPT: &str = "scripts/check-message-identity.sh";

/// The message in the file `SIPNAB_SCAN_MESSAGE` names carries no private
/// identity.
///
/// Ignored, so the suite does not run it: it has no input there. The
/// commit-msg hook runs it through `scripts/check-message-identity.sh`, and
/// `message_script_refuses_a_planted_message_and_passes_a_clean_one` runs it
/// on every suite run. An unset variable or an unreadable file is a failure,
/// not a pass: a check that read nothing must not report a clean message.
#[test]
#[ignore = "needs a message file in SIPNAB_SCAN_MESSAGE; the commit-msg hook runs it through scripts/check-message-identity.sh"]
fn message_in_sipnab_scan_message_names_no_private_identity() -> Result<(), TestError> {
    let path = std::env::var("SIPNAB_SCAN_MESSAGE").map_err(|_| {
        "SIPNAB_SCAN_MESSAGE is not set, so there is no message to check. Run \
         scripts/check-message-identity.sh <file> instead of this test directly."
    })?;
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read the message in {path}: {e}"))?;
    // `SIPNAB_MESSAGE_WHOLE=1` reads past a scissors line (CI, over text that
    // is already published). Unset or empty, the scan stops there (the
    // commit-msg hook). Any other value is an error, not a guess at a mode.
    let scissors = match std::env::var("SIPNAB_MESSAGE_WHOLE").as_deref() {
        Err(_) | Ok("") => Scissors::Cut,
        Ok("1") => Scissors::Read,
        Ok(other) => {
            return Err(format!(
                "SIPNAB_MESSAGE_WHOLE is '{other}'; set it to 1 or leave it unset"
            )
            .into());
        }
    };
    let found = message_findings_from(&text, scissors);
    let report: Vec<String> = found
        .iter()
        .map(|(n, class, line)| {
            format!(
                "  line {n}: class {class}: {}\n    {}",
                line.trim(),
                guidance_for(class)
            )
        })
        .collect();
    assert!(
        found.is_empty(),
        "the message in {path} names a private identity. A commit message is \
         published when the commit is pushed, and a pull request description \
         is public from the moment the pull request is opened.\n{}",
        report.join("\n")
    );
    Ok(())
}

/// M1. One planted line per class is found, with its class and line number.
#[test]
fn m1_message_findings_reports_each_class_with_its_line() -> Result<(), TestError> {
    for (planted, class) in [
        ("Measured on thor-02 overnight", "A"),
        ("the numbers on thor are lower", "A"),
        ("Copied the capture from nas2", "B"),
        ("Reached opensips-1.goes.com over TLS", "C"),
        ("The relay at 10.0.0.40 answered", "D"),
        ("Ran against /home/gator/pcaps", "E"),
        ("Co-Authored-By: Claude <noreply@anthropic.com>", "H"),
    ] {
        let message = format!("Fix the parser\n\nFirst paragraph.\n{planted}\n");
        let found = message_findings(&message);
        assert!(
            found
                .iter()
                .any(|(n, c, l)| *n == 4 && *c == class && l == planted),
            "class {class} on line 4 was not reported for {planted:?}: {found:?}"
        );
    }
    Ok(())
}

/// M2. A clean message has no findings.
#[test]
fn m2_a_clean_message_has_no_findings() -> Result<(), TestError> {
    let message = "Read HEP v1/v2 in the captagent layout\n\n\
                   Measured on Jetson AGX Thor, 14 cores, against 192.0.2.40.\n\
                   See https://sipnab.com and opensips.example.com.\n";
    assert_eq!(message_findings(message), Vec::<Finding>::new());
    Ok(())
}

/// M3. A `#` line is scanned.
///
/// git strips `#` lines only when the message was written in an editor. With
/// `git commit -m` or `-F` it keeps them, and a pull request description is
/// never stripped: its Markdown headings start with `#` and are published on
/// the pull request page as written.
#[test]
fn m3_a_heading_line_is_scanned() -> Result<(), TestError> {
    let message = "Fix the parser\n\n## Tested on thor-02\n\nBody.\n";
    let found = message_findings(message);
    assert!(
        found.iter().any(|(n, c, _)| *n == 3 && *c == "A"),
        "a Markdown heading naming the host must be found: {found:?}"
    );
    Ok(())
}

/// M4. Nothing below the scissors line is scanned.
///
/// `git commit -v` appends the staged diff below this line and git removes
/// it before the commit is made, so a host name in the diff is not part of
/// the message.
#[test]
fn m4_nothing_below_the_scissors_line_is_scanned() -> Result<(), TestError> {
    let message = format!(
        "Fix the parser\n\nBody.\n{SCISSORS}\n# Do not modify or remove the line above.\n\
         -measured on thor-02\n+measured on the aarch64 host\n"
    );
    let found = message_findings(&message);
    assert!(
        found.is_empty(),
        "the diff below the scissors line is not the message: {found:?}"
    );
    // The same host name above the line is found, so the cut is what spares it.
    let above = format!("Fix the parser\n\nmeasured on thor-02\n{SCISSORS}\n");
    assert!(
        !message_findings(&above).is_empty(),
        "a host name above the scissors line must still be found"
    );
    Ok(())
}

/// M5. Trailers are not flagged: they carry real addresses on purpose.
#[test]
fn m5_trailers_carrying_real_addresses_are_not_flagged() -> Result<(), TestError> {
    let message = "Fix the parser\n\nBody.\n\n\
                   Signed-off-by: Someone <someone@example.org>\n\
                   Reported-by: A Person <person@real-company.com>\n";
    assert_eq!(message_findings(message), Vec::<Finding>::new());
    Ok(())
}

/// Run `scripts/check-message-identity.sh` on one message.
///
/// The script is driven for real -- its argument handling, the absolute path
/// it hands on, its exit codes and its output -- but with
/// `SIPNAB_MESSAGE_TEST_BIN` pointing at THIS test binary instead of letting
/// it run cargo. Running cargo from inside a cargo test would rebuild the crate
/// whenever the outer run was built differently: CI's suite is
/// `cargo test --all-features`, which is not `--features full`, and coverage
/// and sanitizer runs change the compiler flags. The cargo line itself is
/// driven by the commit-msg hook on every commit.
fn run_message_script(message: &str, tag: &str) -> Result<(i32, String), TestError> {
    run_message_script_with(message, tag, std::env::current_exe()?.as_os_str())
}

/// [`run_message_script`] with `bin` run in place of the test binary.
fn run_message_script_with(
    message: &str,
    tag: &str,
    bin: &std::ffi::OsStr,
) -> Result<(i32, String), TestError> {
    run_message_script_env(message, tag, bin, &[])
}

/// [`run_message_script_with`] with `envs` set for the script.
fn run_message_script_env(
    message: &str,
    tag: &str,
    bin: &std::ffi::OsStr,
    envs: &[(&str, &str)],
) -> Result<(i32, String), TestError> {
    let dir = std::env::temp_dir().join(format!(
        "sipnab-message-identity-{}-{tag}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir)?;
    let file = dir.join("message.txt");
    std::fs::write(&file, message)?;
    let out = Command::new("bash")
        .arg(repo().join(MESSAGE_SCRIPT))
        .arg(&file)
        .env("SIPNAB_MESSAGE_TEST_BIN", bin)
        .env_remove("SIPNAB_SCAN_MESSAGE")
        .env_remove("SIPNAB_MESSAGE_FEATURES")
        .env_remove("SIPNAB_MESSAGE_WHOLE")
        .envs(envs.iter().copied())
        .current_dir(repo())
        .output()
        .map_err(|e| format!("bash {MESSAGE_SCRIPT}: {e}"))?;
    std::fs::remove_dir_all(&dir)?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    Ok((out.status.code().unwrap_or(-1), text))
}

/// M6. The script refuses a planted message, names the class, and passes a
/// clean one.
///
/// It also pins the coupling the ignore-hygiene gate reads: this file spawns
/// [`MESSAGE_TEST`] with `"--ignored"`, through the script, on every suite run.
#[test]
fn message_script_refuses_a_planted_message_and_passes_a_clean_one() -> Result<(), TestError> {
    let script = std::fs::read_to_string(repo().join(MESSAGE_SCRIPT))
        .map_err(|e| format!("{MESSAGE_SCRIPT}: {e}"))?;
    assert!(
        script.contains("--ignored") && script.contains(MESSAGE_TEST),
        "{MESSAGE_SCRIPT} must run {MESSAGE_TEST} with \"--ignored\""
    );

    let (rc, out) = run_message_script("Fix the parser\n\nMeasured on thor-02.\n", "planted")?;
    assert_eq!(rc, 1, "a planted host name must fail the script:\n{out}");
    assert!(
        out.contains("line 3: class A") && out.contains(guidance::HOST),
        "the failure must name the line, the class and the replacement:\n{out}"
    );

    let (rc, out) =
        run_message_script("Fix the parser\n\nMeasured on the aarch64 host.\n", "clean")?;
    assert_eq!(rc, 0, "a clean message must pass the script:\n{out}");
    assert!(out.is_empty(), "the script is quiet on success:\n{out}");
    Ok(())
}

/// M7. A run that checked nothing is not a pass.
///
/// libtest exits 0 when an `--exact` filter matches no test, which is what a
/// renamed test does. `true` stands in for that run: it exits 0 and prints no
/// `1 passed`, and the script must report the message as not checked.
#[test]
fn message_script_refuses_a_run_that_checked_nothing() -> Result<(), TestError> {
    let (rc, out) = run_message_script_with(
        "Fix the parser\n\nMeasured on thor-02.\n",
        "vacuous",
        std::ffi::OsStr::new("true"),
    )?;
    assert_eq!(
        rc, 2,
        "a run that did not execute the test must fail:\n{out}"
    );
    assert!(out.contains("NOT CHECKED"), "and say so:\n{out}");
    Ok(())
}

/// Run `scripts/check-message-identity.sh` with a stand-in `cargo` first on
/// `PATH`, and return the script's exit code, its output and the arguments it
/// passed to cargo.
///
/// The cargo line cannot be run from inside this suite (see
/// [`run_message_script`]), so the CONVERSION the script performs -- from
/// `SIPNAB_MESSAGE_FEATURES` to cargo's feature flags -- is what is tested.
/// The stand-in records its arguments one per line and reports one passed
/// test, which is what a clean run prints. `features` of `None` leaves the
/// variable unset, which is the commit-msg hook's path.
fn run_message_script_cargo_args(
    features: Option<&str>,
    tag: &str,
) -> Result<(i32, String, Vec<String>), TestError> {
    let dir = std::env::temp_dir().join(format!(
        "sipnab-message-features-{}-{tag}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir)?;
    let args_file = dir.join("cargo-args.txt");
    executable::write_executable(
        &dir.join("cargo"),
        &format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\necho 'test result: ok. 1 passed; 0 failed'\n",
            args_file.display()
        ),
    )?;
    let message = dir.join("message.txt");
    std::fs::write(&message, "Fix the parser\n")?;
    let path = format!(
        "{}:{}",
        dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut cmd = Command::new("bash");
    cmd.arg(repo().join(MESSAGE_SCRIPT))
        .arg(&message)
        .env("PATH", path)
        .env_remove("SIPNAB_MESSAGE_TEST_BIN")
        .env_remove("SIPNAB_SCAN_MESSAGE")
        .env_remove("SIPNAB_MESSAGE_FEATURES")
        .env_remove("SIPNAB_MESSAGE_WHOLE")
        .current_dir(repo());
    if let Some(f) = features {
        cmd.env("SIPNAB_MESSAGE_FEATURES", f);
    }
    let out = cmd
        .output()
        .map_err(|e| format!("bash {MESSAGE_SCRIPT}: {e}"))?;
    let args: Vec<String> = std::fs::read_to_string(&args_file)
        .unwrap_or_default()
        .lines()
        .map(str::to_string)
        .collect();
    std::fs::remove_dir_all(&dir)?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    Ok((out.status.code().unwrap_or(-1), text, args))
}

/// The two arguments that follow `flag` in a recorded cargo command line.
fn flag_value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    let at = args.iter().position(|a| a == flag)?;
    args.get(at + 1).map(String::as_str)
}

/// M8. With `SIPNAB_MESSAGE_FEATURES` unset, the script builds with
/// `--features full`.
///
/// That is the commit-msg hook's path: the pre-commit hook has just built
/// `private_identity_test` with `--features full`, and the same features reuse
/// that binary instead of rebuilding the crate.
#[test]
fn m8_the_message_script_defaults_to_the_hooks_features() -> Result<(), TestError> {
    let (rc, out, args) = run_message_script_cargo_args(None, "default")?;
    assert_eq!(rc, 0, "the stand-in cargo reports a pass:\n{out}");
    assert_eq!(
        flag_value(&args, "--features"),
        Some("full"),
        "unset, the script must build with --features full: {args:?}"
    );
    assert!(
        !args.iter().any(|a| a == "--no-default-features"),
        "unset, the script must keep the default features: {args:?}"
    );
    Ok(())
}

/// M9. `SIPNAB_MESSAGE_FEATURES=none` builds with no features at all.
///
/// The pull-request-text workflow sets it: `private_identity_test` uses
/// nothing from the crate, so a cold runner need not build `full` (and the
/// system libraries `full` links) to read a pull request's text.
#[test]
fn m9_the_message_script_builds_without_features_when_told_none() -> Result<(), TestError> {
    let (rc, out, args) = run_message_script_cargo_args(Some("none"), "none")?;
    assert_eq!(rc, 0, "the stand-in cargo reports a pass:\n{out}");
    assert!(
        args.iter().any(|a| a == "--no-default-features"),
        "none must turn the default features off: {args:?}"
    );
    assert_eq!(
        flag_value(&args, "--features"),
        None,
        "none must name no feature: {args:?}"
    );
    Ok(())
}

/// M10. A feature list builds with exactly that list, defaults off.
#[test]
fn m10_the_message_script_builds_a_named_feature_list() -> Result<(), TestError> {
    let (rc, out, args) = run_message_script_cargo_args(Some("native,hep"), "list")?;
    assert_eq!(rc, 0, "the stand-in cargo reports a pass:\n{out}");
    assert!(
        args.iter().any(|a| a == "--no-default-features"),
        "a named list must turn the default features off: {args:?}"
    );
    assert_eq!(
        flag_value(&args, "--features"),
        Some("native,hep"),
        "the named list must reach cargo unchanged: {args:?}"
    );
    Ok(())
}

/// M11. A value that is not a feature list is refused before cargo runs.
///
/// Exit 2, "could not check": a typo must not quietly fall back to another
/// feature set, and nothing but feature names may reach the command line.
#[test]
fn m11_the_message_script_refuses_a_malformed_feature_list() -> Result<(), TestError> {
    let (rc, out, args) = run_message_script_cargo_args(Some("full $(id)"), "bad")?;
    assert_eq!(
        rc, 2,
        "a malformed feature list must not be checked:\n{out}"
    );
    assert!(
        out.contains("SIPNAB_MESSAGE_FEATURES"),
        "the refusal must name the variable:\n{out}"
    );
    assert!(args.is_empty(), "cargo must not run: {args:?}");
    Ok(())
}

/// M13. In whole-message mode the scissors line does not end the scan.
///
/// CI reads a commit message from `git log --format=%B`, which is the message
/// as committed: git already removed the `git commit -v` diff when it made the
/// commit, and nothing downstream removes anything else. A scissors line still
/// present there was typed into the message, and the lines below it are
/// published with it, so CI must read them.
#[test]
fn m13_whole_message_mode_reads_past_the_scissors_line() -> Result<(), TestError> {
    let message = format!("Fix the parser\n\nBody.\n{SCISSORS}\nMeasured on thor-02\n");
    assert!(
        message_findings_from(&message, Scissors::Cut).is_empty(),
        "the editor mode stops at the scissors line"
    );
    let found = message_findings_from(&message, Scissors::Read);
    assert!(
        found.iter().any(|(n, c, _)| *n == 5 && *c == "A"),
        "whole-message mode must find the host name below the scissors line: {found:?}"
    );
    Ok(())
}

/// M14. `SIPNAB_MESSAGE_WHOLE=1` reaches the check through the script, and any
/// other value is refused rather than read as one mode or the other.
#[test]
fn m14_the_message_script_reads_the_whole_message_when_told() -> Result<(), TestError> {
    let message = format!("Fix the parser\n\nBody.\n{SCISSORS}\nMeasured on thor-02\n");
    let bin = std::env::current_exe()?;
    let (rc, out) = run_message_script_env(&message, "cut", bin.as_os_str(), &[])?;
    assert_eq!(rc, 0, "unset, the scan stops at the scissors line:\n{out}");
    let (rc, out) = run_message_script_env(
        &message,
        "whole",
        bin.as_os_str(),
        &[("SIPNAB_MESSAGE_WHOLE", "1")],
    )?;
    assert_eq!(rc, 1, "whole, the line below the scissors is read:\n{out}");
    assert!(out.contains("line 5: class A"), "and named:\n{out}");
    let (rc, out) = run_message_script_env(
        &message,
        "badwhole",
        bin.as_os_str(),
        &[("SIPNAB_MESSAGE_WHOLE", "yes")],
    )?;
    assert_eq!(rc, 2, "a value other than 1 is not a mode:\n{out}");
    Ok(())
}

/// The workflow that checks what a pull request publishes.
const PR_TEXT_WORKFLOW: &str = ".github/workflows/pr-text.yml";

/// The name of the job in [`PR_TEXT_WORKFLOW`] that checks what lands on
/// `main`. It is the status context branch protection requires, so renaming
/// it silently drops the requirement.
const PR_TEXT_REQUIRED_JOB: &str = "Commit messages and PR title name no private identity";

/// The lines of the job `id` under `jobs:` in a workflow, or `None`.
fn workflow_job<'a>(wf: &'a str, id: &str) -> Option<Vec<&'a str>> {
    let head = format!("  {id}:");
    let mut lines = wf.lines().skip_while(|l| *l != head);
    let first = lines.next()?;
    let mut block = vec![first];
    block.extend(
        lines.take_while(|l| {
            l.is_empty() || l.starts_with("    ") || l.trim_start().starts_with('#')
        }),
    );
    Some(block)
}

/// M12. CI checks what a pull request puts on `main` -- its title and every
/// commit message in its range -- and passes each value it reads from the
/// event as data.
///
/// This repository's squash merges take the commit title from the commit
/// (one commit) or the pull request title, and the body from the branch's
/// commit messages (`squash_merge_commit_message = COMMIT_MESSAGES`); rebase
/// merges keep the commit messages; merge commits carry the branch name and
/// the title. The commit-msg hook checks a message only on the machine that
/// wrote it, so this job reads them again from the range itself. It runs on
/// `edited` because the title can change after the last push.
///
/// The title, the branch name and the two SHAs come from the event, and the
/// first two are written by whoever opens the pull request. `${{ }}` is
/// substituted as text before the shell reads a `run:` script, so any of them
/// placed there would run as code. The only lines allowed to name them are
/// `env:` entries, where the runner hands them to the shell as values.
#[test]
fn m12_ci_checks_the_title_and_every_commit_message_in_the_range() -> Result<(), TestError> {
    let wf = std::fs::read_to_string(repo().join(PR_TEXT_WORKFLOW))
        .map_err(|e| format!("{PR_TEXT_WORKFLOW}: {e}"))?;
    let trigger = wf
        .lines()
        .find(|l| l.trim_start().starts_with("types:"))
        .ok_or_else(|| format!("{PR_TEXT_WORKFLOW} names no pull_request types"))?;
    for t in ["opened", "edited", "reopened", "synchronize"] {
        assert!(
            trigger.contains(t),
            "{PR_TEXT_WORKFLOW} must run on `{t}`: {trigger}"
        );
    }
    assert!(
        wf.lines().any(|l| l.trim() == "permissions:")
            && wf.lines().any(|l| l.trim() == "contents: read")
            && !wf.contains(": write"),
        "{PR_TEXT_WORKFLOW} must grant contents: read and nothing more"
    );

    let allowed = [
        "PR_TITLE: ${{ github.event.pull_request.title }}",
        "PR_BODY: ${{ github.event.pull_request.body }}",
        "BASE_SHA: ${{ github.event.pull_request.base.sha }}",
        "HEAD_SHA: ${{ github.event.pull_request.head.sha }}",
        "HEAD_REF: ${{ github.head_ref }}",
        "PR_NUMBER: ${{ github.event.pull_request.number }}",
        "group: pr-text-${{ github.event.pull_request.number }}",
    ];
    let unsafe_lines: Vec<&str> = wf
        .lines()
        .filter(|l| l.contains("github.event.pull_request") || l.contains("github.head_ref"))
        .filter(|l| !allowed.contains(&l.trim()))
        .collect();
    assert!(
        unsafe_lines.is_empty(),
        "{PR_TEXT_WORKFLOW} names an event value outside its env entries, where \
         it would be substituted into a script:\n  {}",
        unsafe_lines.join("\n  ")
    );

    let job = workflow_job(&wf, "commits")
        .ok_or_else(|| format!("{PR_TEXT_WORKFLOW} has no `commits` job"))?;
    let has = |want: &str| job.iter().any(|l| l.trim() == want);
    let runs = |want: &str| job.iter().any(|l| l.trim_start().starts_with(want));
    assert!(
        has(&format!("name: {PR_TEXT_REQUIRED_JOB}")),
        "the required job must be named `{PR_TEXT_REQUIRED_JOB}`: branch \
         protection requires that context by name"
    );
    for env in [
        "PR_TITLE: ${{ github.event.pull_request.title }}",
        "BASE_SHA: ${{ github.event.pull_request.base.sha }}",
        "HEAD_SHA: ${{ github.event.pull_request.head.sha }}",
        "HEAD_REF: ${{ github.head_ref }}",
        "SIPNAB_MESSAGE_FEATURES: none",
        "SIPNAB_MESSAGE_WHOLE: '1'",
        "fetch-depth: 0",
    ] {
        assert!(has(env), "the `commits` job must carry `{env}`");
    }
    assert!(
        runs(r#"git rev-list --reverse "$BASE_SHA..$HEAD_SHA""#),
        "the `commits` job must walk every commit in base..head"
    );
    assert!(
        runs(r#"git log -1 --format=%B "$sha""#),
        "the `commits` job must read each commit's message as committed"
    );
    assert!(
        runs(&format!("bash {MESSAGE_SCRIPT} ")),
        "the `commits` job must run {MESSAGE_SCRIPT}, the rule the hook runs"
    );
    assert!(
        !job.iter()
            .any(|l| l.trim_start().starts_with("continue-on-error")),
        "the `commits` job is the one that blocks, so it must fail"
    );

    // The description stays on the pull request page and is public from the
    // moment the pull request is opened, so a red check cannot unpublish it:
    // it is reported, and the job passes.
    let advisory = workflow_job(&wf, "description")
        .ok_or_else(|| format!("{PR_TEXT_WORKFLOW} has no `description` job"))?;
    assert!(
        advisory
            .iter()
            .any(|l| l.trim() == "PR_BODY: ${{ github.event.pull_request.body }}"),
        "the `description` job must read the body through env"
    );
    assert!(
        advisory.iter().any(|l| l.contains("::warning")),
        "the `description` job must report a finding as a warning"
    );
    let run_line = advisory
        .iter()
        .find(|l| {
            l.trim_start()
                .starts_with(&format!("bash {MESSAGE_SCRIPT} "))
        })
        .ok_or("the `description` job must run the script")?;
    assert!(
        run_line.contains("&& rc=0 || rc=$?"),
        "the `description` job must not let the script's exit end the step: {run_line}"
    );
    let exits: Vec<&&str> = advisory
        .iter()
        .filter(|l| {
            let t = l.trim_start();
            !t.starts_with('#') && t.contains("exit ") && !t.contains("exit 0")
        })
        .collect();
    assert!(
        exits.is_empty(),
        "the `description` job is advisory and must not fail: {exits:?}"
    );
    // Passing by itself, not failing and being ignored: `continue-on-error`
    // leaves a failed check on the pull request, which reads as a broken
    // build rather than as a note about the description.
    assert!(
        !advisory
            .iter()
            .any(|l| l.trim_start().starts_with("continue-on-error")),
        "the `description` job must pass with a warning, not fail and be ignored"
    );
    Ok(())
}

/// M15. The checks run main's code, and read the pull request only as data.
///
/// The `commits` job becomes a required check, so a pull request must not be
/// able to weaken the rule that judges it. On `pull_request` GitHub runs the
/// workflow file, the script and the test from the pull request itself. On
/// `pull_request_target` it runs the base branch's workflow file, and each job
/// checks out the base commit, so the script, the test and Cargo.lock are
/// main's. The pull request's commits are fetched as objects and read with
/// `git rev-list` and `git log`; nothing switches the tree to them, and
/// nothing from them is built or run.
///
/// `pull_request_target` runs with a write token unless the workflow says
/// otherwise, and a cache written there can be restored by a later run on
/// `main`, so the workflow grants `contents: read` at its top level and uses
/// no cache.
#[test]
fn m15_ci_runs_mains_code_and_reads_the_pull_request_as_data() -> Result<(), TestError> {
    let wf = std::fs::read_to_string(repo().join(PR_TEXT_WORKFLOW))
        .map_err(|e| format!("{PR_TEXT_WORKFLOW}: {e}"))?;
    let lines: Vec<&str> = wf.lines().collect();
    let top = |l: &&str| !l.starts_with(' ') && !l.starts_with('#') && !l.is_empty();

    // The trigger: pull_request_target and not pull_request.
    assert!(
        lines.iter().any(|l| {
            let t = l.trim();
            t == "pull_request_target:" || t.starts_with("pull_request_target: # zizmor")
        }),
        "{PR_TEXT_WORKFLOW} must run on pull_request_target, so the base \
         branch's workflow file is the one that runs"
    );
    assert!(
        !lines.iter().any(|l| l.trim() == "pull_request:"),
        "{PR_TEXT_WORKFLOW} must not run on pull_request, where the pull \
         request's own workflow, script and test would judge it"
    );

    // Workflow-level permissions, and no job widens them.
    let at = lines
        .iter()
        .position(|l| *l == "permissions:")
        .ok_or_else(|| format!("{PR_TEXT_WORKFLOW} has no top-level permissions"))?;
    let block: Vec<&str> = lines[at + 1..]
        .iter()
        .take_while(|l| !top(l))
        .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
        .copied()
        .collect();
    assert_eq!(
        block,
        vec!["  contents: read"],
        "{PR_TEXT_WORKFLOW} must grant contents: read and nothing else at the top"
    );
    assert_eq!(
        lines.iter().filter(|l| l.trim() == "permissions:").count(),
        1,
        "no job in {PR_TEXT_WORKFLOW} may restate permissions"
    );

    // Every checkout is the base branch, and nothing switches to the PR.
    // Under pull_request_target, actions/checkout with no `ref:` checks out
    // the base branch's latest commit: main's code. Naming any ref is
    // refused, the base SHA included: OpenSSF Scorecard's Dangerous-Workflow
    // check reports any checkout ref built from `github.event.pull_request`
    // as an untrusted checkout, and the default already is the trusted one.
    let checkouts = lines
        .iter()
        .filter(|l| l.contains("uses: actions/checkout@"))
        .count();
    assert!(checkouts >= 2, "both jobs check out the repository");
    let refs: Vec<&&str> = lines
        .iter()
        .filter(|l| l.trim_start().starts_with("ref:"))
        .collect();
    assert!(
        refs.is_empty(),
        "no checkout in {PR_TEXT_WORKFLOW} may name a ref; the pull_request_target \
         default is the base branch: {refs:?}"
    );
    for verb in [
        "git checkout",
        "git switch",
        "git reset",
        "git restore",
        "git worktree",
        "git merge",
        "git cherry-pick",
        "git am",
    ] {
        assert!(
            !wf.contains(verb),
            "{PR_TEXT_WORKFLOW} must never put the pull request's tree on disk: `{verb}`"
        );
    }
    assert!(
        !wf.contains("actions/cache"),
        "{PR_TEXT_WORKFLOW} must use no cache: a cache saved from a \
         pull_request_target run is restorable on main"
    );

    // The PR's commits are fetched as data, and the fetched head is the one
    // the event names.
    let job = workflow_job(&wf, "commits")
        .ok_or_else(|| format!("{PR_TEXT_WORKFLOW} has no `commits` job"))?;
    let has = |want: &str| job.iter().any(|l| l.trim() == want);
    assert!(
        has(r#"git fetch --no-tags origin "+refs/pull/${PR_NUMBER}/head:refs/remotes/pr/head""#),
        "the `commits` job must fetch the pull request's head as a remote ref"
    );
    assert!(
        has("PR_NUMBER: ${{ github.event.pull_request.number }}"),
        "the pull request number must reach the shell through env"
    );
    let fetch = job
        .iter()
        .position(|l| l.trim_start().starts_with("git fetch "))
        .ok_or("no fetch")?;
    let verify = job
        .iter()
        .position(|l| {
            l.trim()
                == r#"if [ "$(git rev-parse --verify 'refs/remotes/pr/head^{commit}')" != "$HEAD_SHA" ]; then"#
        })
        .ok_or("the `commits` job must check the fetched head against HEAD_SHA")?;
    let walk = job
        .iter()
        .position(|l| l.trim_start().starts_with("git rev-list "))
        .ok_or("no rev-list")?;
    assert!(
        fetch < verify && verify < walk,
        "the fetched head must be verified after the fetch and before any \
         message is read"
    );
    Ok(())
}

// -- Class A: the aarch64 development host ---------------------------

/// A1. No tracked file names the aarch64 development host.
///
/// Every tracked file, not only the pages: the repository is public, so a
/// source comment, a test or a workflow comment is as published as `docs/`.
/// Until 2026-10-07 this scanned `docs/`, `website/`, the benches, README and
/// CHANGELOG, and 63 lines elsewhere named the host.
#[test]
fn a1_no_published_page_names_the_development_host() -> Result<(), TestError> {
    let files = tracked_text()?;
    let found = scan(&files, |_| true, rule::lab_host);
    assert!(
        found.is_empty(),
        "a published page names the maintainer's aarch64 host. This repository \
         is public, so the name is disclosed the moment it is pushed.\n{}\n\n{}",
        capped(&found, 25),
        guidance::HOST
    );
    Ok(())
}

/// A2. The rule flags the exact name that leaked.
#[test]
fn a2_the_host_rule_flags_the_name_that_leaked() -> Result<(), TestError> {
    assert!(
        rule::lab_host("## 2026-08-15 - thor-02 (aarch64, 14 cores), rustc 1.97.1"),
        "the benchmark heading that leaked must be caught if it returns"
    );
    Ok(())
}

/// A3. It flags the undashed spelling, which reads as a different word.
#[test]
fn a3_the_host_rule_flags_the_undashed_spelling() -> Result<(), TestError> {
    assert!(
        rule::lab_host("measured on thor02 overnight"),
        "`thor02` names the same machine as `thor-02`"
    );
    Ok(())
}

/// A4. It flags the name inside sample JSON, which is how it actually leaked.
///
/// `docs/vcon.md` published `"node": "thor-02"` inside example containers --
/// the hostname was in the documented OUTPUT FORMAT, not in a sentence about
/// the lab, which is why reading the prose would never have found it.
#[test]
fn a4_the_host_rule_flags_it_inside_sample_output() -> Result<(), TestError> {
    assert!(
        rule::lab_host(r#"    "node": "thor-02","#),
        "the leak was inside a JSON sample, not in prose"
    );
    assert!(
        rule::lab_host(r#""sip_user_agent": "sipnab/0.5.124 (observer; node thor-02)""#),
        "and inside a User-Agent string in the same document"
    );
    Ok(())
}

/// A5. It spares the hardware, which a benchmark cannot do without.
#[test]
fn a5_the_host_rule_spares_the_hardware_it_runs_on() -> Result<(), TestError> {
    for legitimate in [
        "- **Host:** NVIDIA Jetson Thor devboard (aarch64), 14 cores, PREEMPT_RT",
        "meaningful on Jetson AGX Thor",
        "aarch64 binary runs on Jetson AGX Thor (or equivalent ARM64)",
    ] {
        assert!(
            !rule::lab_host(legitimate) && !rule::bare_host(legitimate),
            "a benchmark that cannot say what it ran on is not a benchmark: {legitimate}"
        );
    }
    Ok(())
}

/// A6. The bare lowercase form is the box, and is caught.
#[test]
fn a6_a_lowercase_bare_name_is_the_box_not_the_board() -> Result<(), TestError> {
    assert!(
        rule::bare_host("shares thor's kernel - so it has no BTF either"),
        "`thor's kernel` names a machine"
    );
    assert!(
        rule::bare_host(r#"the initial "+8.3% on thor" compared a build"#),
        "`on thor` names a machine"
    );
    Ok(())
}

/// A1's scan reaches what was outside it before: source, tests, workflow
/// comments and the contributing guide.
#[test]
fn a1_scan_reaches_source_tests_and_workflows() -> Result<(), TestError> {
    let files = tracked_text()?;
    for rel in [
        "src/app/batch.rs",
        "tests/vcon_forward_test.rs",
        ".github/workflows/ci.yml",
        "CONTRIBUTING.md",
    ] {
        assert!(reaches(&files, rel), "class A does not scan {rel}");
    }
    assert!(
        rule::lab_host("    # thor-02 is ONE runner and runs one job at a time"),
        "a workflow comment naming the host must be caught"
    );
    Ok(())
}

/// A7. No tracked file carries the bare lowercase form either.
#[test]
fn a7_no_published_page_carries_the_bare_lowercase_form() -> Result<(), TestError> {
    let files = tracked_text()?;
    let found = scan(&files, |_| true, rule::bare_host);
    assert!(
        found.is_empty(),
        "a published page names the host rather than the hardware:\n{}\n\n{}",
        capped(&found, 25),
        guidance::HOST
    );
    Ok(())
}

/// A8. The scan reaches the generated mirrors, where the leak also lands.
///
/// `docs/vcon.md` is mirrored into `website/content/docs/vcon.md` and into
/// `website/static/llms-full.txt`. Fixing the source and forgetting the mirror
/// leaves the leak on the site, which is the copy the public actually reads.
#[test]
fn a8_the_scan_reaches_the_generated_site_mirrors() -> Result<(), TestError> {
    let files = tracked_text()?;
    for mirror in [
        "website/content/docs/vcon.md",
        "website/static/llms-full.txt",
    ] {
        assert!(
            reaches(&files, mirror),
            "the scan does not read {mirror}, a generated copy of a page that leaked"
        );
        assert!(is_published(mirror), "{mirror} must count as published");
    }
    Ok(())
}

/// A9. The scan reaches the pages this class actually leaked on.
#[test]
fn a9_the_scan_reaches_the_pages_this_class_leaked_on() -> Result<(), TestError> {
    let files = tracked_text()?;
    for surface in [
        "CHANGELOG.md",
        "benches/BASELINES.md",
        "docs/vcon.md",
        "docs/mcp-tools.md",
        "docs/design/live-fanout.md",
    ] {
        assert!(
            reaches(&files, surface) && is_published(surface),
            "{surface} carried this leak and must be in the scan"
        );
    }
    Ok(())
}

/// A10. The guide tells a writer what to put in a benchmark heading.
#[test]
fn a10_the_guide_names_the_hardware_alternative() -> Result<(), TestError> {
    let guide = contributing()?;
    assert!(
        guide.contains("hostname") && guide.contains("jetson agx thor"),
        "CONTRIBUTING.md must show the hardware form, or a writer meets this \
         rule for the first time as a rejected commit"
    );
    assert!(
        guidance::HOST.contains("aarch64 self-hosted runner"),
        "the failure message must carry the replacement, not just the refusal"
    );
    Ok(())
}

// -- Class B: the lab's VMs, containers and host ----------------------

/// B1. No published page names a lab VM or container.
#[test]
fn b1_no_published_page_names_a_lab_machine() -> Result<(), TestError> {
    let files = tracked_text()?;
    let found = scan(&files, is_published, rule::lab_machine);
    assert!(
        found.is_empty(),
        "a published page names a machine in the lab:\n{}\n\n{}",
        capped(&found, 25),
        guidance::MACHINE
    );
    Ok(())
}

/// B2. The rule flags the name that leaked, in the heading form it leaked in.
#[test]
fn b2_the_machine_rule_flags_the_baseline_heading() -> Result<(), TestError> {
    assert!(
        rule::lab_machine("## 2026-07-06 - opensips-1, rustc 1.96, WS5f result"),
        "five benchmark headings named this VM"
    );
    Ok(())
}

/// B3. It flags the other machines in the same family.
#[test]
fn b3_the_machine_rule_flags_the_rest_of_the_family() -> Result<(), TestError> {
    for host in ["nas2", "miner1", "norm2"] {
        assert!(
            rule::lab_machine(&format!("copied from {host} overnight")),
            "{host} is a machine in the same lab"
        );
    }
    Ok(())
}

/// B4. It does not fire inside a longer identifier.
///
/// The boundary is what keeps this rule usable: `opensips-1` must not match
/// inside `opensips-1234`, and `norm2` must not match inside `normalize2`.
#[test]
fn b4_the_machine_rule_does_not_fire_inside_a_longer_word() -> Result<(), TestError> {
    for benign in [
        "opensips-1234 is a different thing entirely",
        "let normalize2 = normalize(x);",
        "miner1234",
    ] {
        assert!(
            !rule::lab_machine(benign),
            "a substring match would make this rule unusable: {benign}"
        );
    }
    Ok(())
}

/// B5. It spares the software the project integrates with.
///
/// `opensips` and `OpenSIPS` are a project sipnab decodes; only the numbered
/// instance is a machine.
#[test]
fn b5_the_machine_rule_spares_the_software_it_names() -> Result<(), TestError> {
    for benign in [
        "OpenSIPS answered and rtpengine anchored media for it",
        "a packaged opensips on the VM",
        "docs/internals/opensips.md",
    ] {
        assert!(
            !rule::lab_machine(benign),
            "the software is not the machine: {benign}"
        );
    }
    Ok(())
}

/// B6. Every self-hosted job reaches the runner by its hardware label, and
/// at least one does, so the check is not vacuous.
#[test]
fn b6_self_hosted_jobs_reach_the_runner_by_hardware_label() -> Result<(), TestError> {
    let files = tracked_text()?;
    let mut labels = Vec::new();
    let mut named = Vec::new();
    for (rel, text) in &files {
        if !rel.starts_with(".github/") {
            continue;
        }
        for (i, line) in text.lines().enumerate() {
            if is_runner_label(line) {
                labels.push(format!("{rel}:{}", i + 1));
                if !word(line, "jetson") || rule::lab_host(line) || rule::lab_machine(line) {
                    named.push(format!("{rel}:{}: {}", i + 1, line.trim()));
                }
            }
        }
    }
    assert!(
        !labels.is_empty(),
        "no workflow reaches the self-hosted runner, so this checks nothing"
    );
    assert!(
        named.is_empty(),
        "a self-hosted job does not use the hardware label `jetson`, or names a machine:\n{}",
        named.join("\n")
    );
    Ok(())
}

/// B8. The exception is recognized by shape, not by the hostname it carries.
///
/// So relabelling the runner does not silently widen the exception to whatever
/// the new label is called somewhere else.
#[test]
fn b8_the_exception_is_recognized_by_shape() -> Result<(), TestError> {
    assert!(
        is_runner_label("    runs-on: [self-hosted, thor-02]"),
        "the label form must be recognized"
    );
    assert!(
        !is_runner_label("thor-02 has no BTF, so the backend is unavailable"),
        "prose about the same machine is not a runner label"
    );
    assert!(
        !is_runner_label("    runs-on: ubuntu-latest"),
        "a hosted runner is not the exception"
    );
    Ok(())
}

/// B9. `harness/` and `demos/` keep the name, because there it is a service.
///
/// A compose service called `opensips-1` is something a reader brings up on
/// their own machine. Banning it there would be renaming their container to
/// protect a hostname that is not theirs.
#[test]
fn b9_a_compose_service_name_is_not_a_machine() -> Result<(), TestError> {
    let files = tracked_text()?;
    let harness: Vec<&(String, String)> = files
        .iter()
        .filter(|(rel, _)| rel.starts_with("harness/") || rel.starts_with("demos/"))
        .collect();
    assert!(
        !harness.is_empty(),
        "the harness tree vanished, and with it the reason this exclusion exists"
    );
    assert!(
        harness.iter().all(|(rel, _)| !is_published(rel)),
        "harness/ and demos/ must stay outside the published set, or the \
         service name becomes a violation"
    );
    Ok(())
}

/// The invented machine name CONTRIBUTING.md shows as the thing not to write.
///
/// Invented, not taken from the lab: CONTRIBUTING.md publishes to sipnab.com as
/// `website/content/docs/contributing.md`, and A1, B1 and D1 ban every real lab
/// name and address from `website/`. The guide used to show `opensips-1`
/// itself, which this test required, so the guide could not publish.
const FICTIONAL_HOST: &str = "sbc-east-2";

/// B10. The guide names the role form to use instead.
///
/// It shows a machine name to avoid in the same table row as the role form
/// that replaces it, and that name is invented: no lab machine, host or
/// address appears anywhere in the guide.
#[test]
fn b10_the_guide_names_the_role_alternative() -> Result<(), TestError> {
    let guide = contributing()?;
    let row = guide.lines().find(|line| word(line, FICTIONAL_HOST));
    assert!(
        row.is_some_and(|line| line.contains("what the machine is")),
        "CONTRIBUTING.md must show an invented machine name ({FICTIONAL_HOST}) \
         in the row that gives the role form, or the rule is abstract and gets \
         guessed at"
    );
    let real: Vec<&str> = guide
        .lines()
        .filter(|line| rule::lab_host(line) || rule::lab_machine(line) || rule::lab_address(line))
        .collect();
    assert!(
        real.is_empty(),
        "CONTRIBUTING.md publishes to the site, so its examples must be \
         invented, not lab machines or lab addresses:\n{}",
        real.join("\n")
    );
    assert!(
        guidance::MACHINE.contains("x86_64 OpenSIPS VM"),
        "the failure message must carry the role form"
    );
    Ok(())
}

// -- Class C: the lab's DNS domain ------------------------------------

/// C1. No file anywhere names the lab's DNS domain.
///
/// Repo-wide rather than published-only: a domain in a harness config is as
/// disclosed as a domain in a page, and unlike a service name it is not
/// something a reader reproduces.
#[test]
fn c1_no_file_names_the_private_domain() -> Result<(), TestError> {
    let files = tracked_text()?;
    let found = scan(&files, |_| true, rule::private_domain);
    assert!(
        found.is_empty(),
        "the lab's DNS domain is in the tree:\n{}\n\n{}",
        capped(&found, 25),
        guidance::DOMAIN
    );
    Ok(())
}

/// C2. The rule flags the fully qualified form that leaked.
#[test]
fn c2_the_domain_rule_flags_the_fqdn_that_leaked() -> Result<(), TestError> {
    assert!(
        rule::private_domain("`opensips-1.goes.com` (Debian 13, kernel 6.12.101, x86_64)"),
        "the FQDN in the backlog must be caught if it returns"
    );
    Ok(())
}

/// C3. It flags the domain with a port, and in a URL.
#[test]
fn c3_the_domain_rule_flags_it_with_a_port_or_in_a_url() -> Result<(), TestError> {
    assert!(rule::private_domain(
        "`opensips-1.goes.com:5063`, returned both"
    ));
    assert!(rule::private_domain(
        "https://git.goes.com/user/vcon-backend"
    ));
    Ok(())
}

/// C4. It flags a bare subdomain nobody has used yet.
///
/// The class is the domain, not the one host that happened to leak: the next
/// one will be a different label under the same zone.
#[test]
fn c4_the_domain_rule_flags_a_subdomain_not_yet_used() -> Result<(), TestError> {
    assert!(rule::private_domain("ns1.goes.com"));
    assert!(rule::private_domain("mail.goes.com"));
    Ok(())
}

/// C5. It spares words that merely contain the label.
#[test]
fn c5_the_domain_rule_spares_ordinary_prose() -> Result<(), TestError> {
    for benign in [
        "everything goes, and the commit lands",
        "it goes; completion follows",
        "whatever goes wrong here",
    ] {
        assert!(
            !rule::private_domain(benign),
            "the rule must not fire on prose: {benign}"
        );
    }
    Ok(())
}

/// C6. The repo-wide scan really is repo-wide.
#[test]
fn c6_the_domain_scan_covers_more_than_the_published_set() -> Result<(), TestError> {
    let files = tracked_text()?;
    let all = corpus_size(&files, |_| true);
    let published = corpus_size(&files, is_published);
    assert!(
        all > published,
        "the repo-wide scan ({all}) covers no more than the published one \
         ({published}), so `keep` has stopped widening it"
    );
    Ok(())
}

/// C7. The scan reaches configuration, where a domain would sit if it returned.
#[test]
fn c7_the_domain_scan_reaches_configuration() -> Result<(), TestError> {
    let files = tracked_text()?;
    let config = files
        .iter()
        .filter(|(rel, _)| {
            rel.ends_with(".yml") || rel.ends_with(".yaml") || rel.ends_with(".toml")
        })
        .count();
    assert!(
        config > 10,
        "only {config} configuration files are in the scan, too few for this \
         tree -- the binary or vendored filter has widened"
    );
    Ok(())
}

/// C8. A reserved example domain is never flagged.
#[test]
fn c8_reserved_example_domains_are_not_flagged() -> Result<(), TestError> {
    for benign in [
        "opensips.example.com runs a packaged OpenSIPS",
        "sip:alice@example.org",
        "host.example.net",
    ] {
        assert!(
            !rule::private_domain(benign),
            "RFC 2606 names are the fix, not the violation: {benign}"
        );
    }
    Ok(())
}

/// C9. The replacement the sweep used is itself a reserved name.
#[test]
fn c9_the_replacement_is_a_reserved_name() -> Result<(), TestError> {
    let files = tracked_text()?;
    let used = files
        .iter()
        .any(|(_, text)| text.contains("opensips.example.com"));
    assert!(
        used,
        "the sweep replaced the FQDN with `opensips.example.com`; if that has \
         gone, check that whatever replaced it is also reserved"
    );
    Ok(())
}

/// C10. The guide names the reserved-domain rule.
#[test]
fn c10_the_guide_names_the_reserved_domain_rule() -> Result<(), TestError> {
    let guide = contributing()?;
    assert!(
        guide.contains("rfc 2606") || guide.contains("example.com"),
        "CONTRIBUTING.md must point at the reserved domains"
    );
    assert!(guidance::DOMAIN.contains("example.com"));
    Ok(())
}

// -- Class D: the lab's LAN -------------------------------------------

/// D1. No prose page carries an address from the lab's LAN.
#[test]
fn d1_no_prose_page_carries_a_lab_address() -> Result<(), TestError> {
    let files = tracked_text()?;
    let found = scan(&files, is_prose, rule::lab_address);
    assert!(
        found.is_empty(),
        "a prose page carries an address from the lab's own LAN:\n{}\n\n{}",
        capped(&found, 25),
        guidance::ADDRESS
    );
    Ok(())
}

/// D2. The rule flags the relay and endpoint addresses that leaked.
#[test]
fn d2_the_address_rule_flags_the_addresses_that_leaked() -> Result<(), TestError> {
    assert!(rule::lab_address(
        "0x0a0a0a0a   10.0.0.60:40001          10.0.0.40:38156          10       0s"
    ));
    assert!(rule::lab_address("`--hep-allow 10.0.0.40` exited with"));
    Ok(())
}

/// D3. It flags one embedded in a URL-encoded Call-ID.
///
/// `%40` is `@`, so `test-call-1%4010.0.0.1` puts a digit immediately before
/// the address. A word-boundary sweep walked straight past it, and that is
/// exactly where one survived the first pass of the cleanup.
#[test]
fn d3_the_address_rule_flags_one_inside_an_encoded_call_id() -> Result<(), TestError> {
    assert!(
        rule::lab_address("\"http://127.0.0.1:8080/v1/dialogs/test-call-1%4010.0.0.1/vcon\""),
        "an address glued to a percent-escape is still an address"
    );
    Ok(())
}

/// D4. It spares QEMU's default guest network.
///
/// `10.0.2.15` is what every `qemu-system-*` guest gets, so it belongs in
/// sample output and says nothing about this lab.
#[test]
fn d4_the_address_rule_spares_the_qemu_guest_range() -> Result<(), TestError> {
    for benign in ["10.0.2.15:5060", "sip:1001@10.0.2.20", "10.0.2.2"] {
        assert!(
            !rule::lab_address(benign),
            "RFC 1918 as a class is not the rule: {benign}"
        );
    }
    Ok(())
}

/// D5. It spares the documentation ranges the sweep moved everything to.
#[test]
fn d5_the_address_rule_spares_the_documentation_ranges() -> Result<(), TestError> {
    for benign in [
        "192.0.2.40:38156",
        "198.51.100.20",
        "203.0.113.1",
        "127.0.0.1",
    ] {
        assert!(
            !rule::lab_address(benign),
            "the fix must not be a violation"
        );
    }
    Ok(())
}

/// D6. It needs a digit after the prefix, and the network itself counts.
#[test]
fn d6_the_address_rule_needs_a_digit_after_the_prefix() -> Result<(), TestError> {
    assert!(
        !rule::lab_address("version 10.0.0. is not an address"),
        "a prefix with nothing after it is not an address"
    );
    assert!(
        rule::lab_address("10.0.0.0/24 dev veth"),
        "but the network itself is one"
    );
    Ok(())
}

/// D7. Fixtures are deliberately out of scope, and stay that way.
///
/// The addresses under `tests/` are wire data that snapshots and
/// expected-output tests are pinned to. Rewriting them would churn the suite
/// and publish nothing, so the rule runs over prose and the exclusion is
/// asserted rather than assumed.
#[test]
fn d7_fixtures_are_outside_the_address_rule() -> Result<(), TestError> {
    assert!(!is_prose("tests/snapshots/foo.snap"));
    assert!(!is_prose("benches/parser_bench.rs"));
    assert!(!is_prose("bench/live-capture.sh"));
    assert!(is_prose("docs/rtpengine.md"));
    assert!(is_prose("CHANGELOG.md"));
    Ok(())
}

/// D8. Published IPv6 literals are RFC 3849 documentation addresses.
///
/// A positive assertion over the addresses that ARE there, so it cannot pass by
/// finding nothing. The bound is deliberate: a literal counts only when its
/// first group is four hex digits and it parses, because anything looser
/// matched `f64::E`, a MAC's `02:00:` and a shell expansion -- and a gate that
/// cries about `f64::E` gets skimmed. The cost is that a leak written `fd12::5`
/// goes unseen; the prefixes that appear in documents are written long.
#[test]
fn d8_published_ipv6_literals_are_documentation_addresses() -> Result<(), TestError> {
    let files = tracked_text()?;
    let mut checked = 0usize;
    let mut found = Vec::new();

    for (rel, text) in &files {
        if rel == "tests/private_identity_test.rs" || !is_published(rel) {
            continue;
        }
        for (i, line) in text.lines().enumerate() {
            for tok in line.split(|c: char| !(c.is_ascii_hexdigit() || c == ':')) {
                let first = tok.split(':').next().unwrap_or_default();
                if first.len() != 4 {
                    continue;
                }
                let Ok(addr) = tok.parse::<Ipv6Addr>() else {
                    continue;
                };
                let low = tok.to_ascii_lowercase();
                if addr.is_loopback()
                    || addr.is_unspecified()
                    || addr.is_multicast()
                    || low.starts_with("fe80:")
                {
                    continue;
                }
                checked += 1;
                if !low.starts_with("2001:db8") {
                    found.push(format!("{rel}:{}: {tok}", i + 1));
                }
            }
        }
    }

    assert!(
        checked > 0,
        "the IPv6 scan found no global literal on any published page, so it \
         proved nothing"
    );
    assert!(
        found.is_empty(),
        "a published page carries a global IPv6 address outside RFC 3849's \
         2001:db8::/32 ({checked} literal(s) checked):\n{}",
        capped(&found, 25)
    );
    Ok(())
}

/// D9. The rendered social-preview image is in scope too.
///
/// `website/og-image.svg` is a picture of a terminal, and it carried two LAN
/// addresses as text. An SVG is markup, so it is scanned; a PNG would not be,
/// which is worth knowing before somebody exports one.
#[test]
fn d9_the_social_preview_image_is_scanned() -> Result<(), TestError> {
    let files = tracked_text()?;
    assert!(
        reaches(&files, "website/og-image.svg"),
        "the social-preview image is markup and carried two LAN addresses; it \
         must stay in the scan. If it became a PNG, its text left the scan with \
         it -- check the brief instead."
    );
    assert!(
        !BINARY_EXT.contains(&"svg"),
        "SVG must not be treated as binary, or the image's text stops being read"
    );
    Ok(())
}

/// D10. The guide names the documentation ranges.
#[test]
fn d10_the_guide_names_the_documentation_ranges() -> Result<(), TestError> {
    let guide = contributing()?;
    assert!(
        guide.contains("rfc 5737") && guide.contains("192.0.2.0/24"),
        "CONTRIBUTING.md must name the ranges, not just forbid the LAN"
    );
    assert!(guide.contains("2001:db8"), "and the IPv6 one");
    Ok(())
}

// -- Class E: accounts and the private capture corpus -----------------

/// E1. No file carries a path under a real account's home directory.
#[test]
fn e1_no_file_carries_an_account_path() -> Result<(), TestError> {
    let files = tracked_text()?;
    let found = scan(&files, |_| true, rule::account_path);
    assert!(
        found.is_empty(),
        "an absolute home-directory path is in the tree. It names the account \
         and it runs on one machine:\n{}\n\n{}",
        capped(&found, 25),
        guidance::PATH
    );
    Ok(())
}

/// E2. The rule flags the corpus path that leaked, in a command.
#[test]
fn e2_the_account_rule_flags_the_command_that_leaked() -> Result<(), TestError> {
    assert!(rule::account_path(
        "$BIN -N -I /home/gator/pcaps --cores 1 --no-cli-print"
    ));
    assert!(rule::account_path(
        "`/home/gator/pcaps` - 15 files, 1,383 MB, 4,532,272 packets"
    ));
    Ok(())
}

/// E3. It flags a checkout path as well as a corpus path.
#[test]
fn e3_the_account_rule_flags_a_checkout_path() -> Result<(), TestError> {
    assert!(rule::account_path(
        "hardcoded `root = /home/gator/Development/sipnab`, so everywhere else"
    ));
    Ok(())
}

/// E4. It spares a placeholder every reader substitutes.
///
/// The rule is the ACCOUNT, not the shape. Banning `/home/user/capture.pcap`
/// would churn a dozen synopses to say nothing.
#[test]
fn e4_the_account_rule_spares_a_placeholder() -> Result<(), TestError> {
    for benign in [
        "sipnab -I /home/user/capture.pcap",
        "/home/<you>/pcaps",
        "$HOME/pcaps",
        "/srv/pcaps",
    ] {
        assert!(
            !rule::account_path(benign),
            "a placeholder is not a disclosure: {benign}"
        );
    }
    Ok(())
}

/// E5. Nothing names where the private capture corpus lives.
///
/// The corpus is real signaling from real people. It is never committed, which
/// this repo already gets right -- but a path to it is the one part of it a
/// public page can still disclose.
#[test]
fn e5_nothing_locates_the_private_capture_corpus() -> Result<(), TestError> {
    let files = tracked_text()?;
    let found = scan(&files, |_| true, rule::corpus_path);
    assert!(
        found.is_empty(),
        "a tracked file names the location of the private capture corpus:\n{}\n\n\
         Name the capability, not the address.",
        capped(&found, 25)
    );
    Ok(())
}

/// E6. The corpus rule flags both spellings that appeared.
#[test]
fn e6_the_corpus_rule_flags_both_forms() -> Result<(), TestError> {
    assert!(rule::corpus_path(
        "the corpus at /home/gator/pcaps carries PII"
    ));
    assert!(rule::corpus_path(
        "export CORPUS=/home/gator/captures/x.pcap"
    ));
    Ok(())
}

/// E7. The corpus rule spares a corpus that is not under an account.
///
/// The capability to point sipnab at a corpus is the whole point of the bench
/// harness; only this corpus's address is the problem.
#[test]
fn e7_the_corpus_rule_spares_a_neutral_location() -> Result<(), TestError> {
    for benign in [
        "st_try parse_args --bin /srv/pcaps/x.pcap",
        "-I $PCAP_CORPUS --cores 4",
        "point it at a directory of captures",
    ] {
        assert!(
            !rule::corpus_path(benign),
            "the capability stays; only the address goes: {benign}"
        );
    }
    Ok(())
}

/// E8. The scan reaches shell and Python, where these paths actually sat.
#[test]
fn e8_the_account_scan_reaches_scripts() -> Result<(), TestError> {
    let files = tracked_text()?;
    for surface in [
        "bench/live-capture.sh",
        "scripts/rfc-links.py",
        "bench/README.md",
        ".gitignore",
    ] {
        assert!(
            reaches(&files, surface),
            "{surface} carried an account path and must be in the scan"
        );
    }
    Ok(())
}

/// E8b. The rule reaches every home root the account has actually appeared
/// under, not just the Linux one.
///
/// Each string below was in the tree on 2026-08-31 and each walked past the
/// `/home/{account}` form of this rule.
#[test]
fn e8b_the_account_rule_reaches_the_other_home_roots() -> Result<(), TestError> {
    for leaked in [
        "# /Users/gator/Development/sipnab: `git ls-files` ran with `cwd=` a path",
        "  Only Rust was added, user-local under `~gator`; no system package changed.",
        "/var/home/gator/pcaps",
        "/export/home/gator/captures/x.pcap",
    ] {
        assert!(
            rule::account_path(leaked),
            "the account is named just as loudly under a root the rule did not \
             list: {leaked}"
        );
    }
    Ok(())
}

/// E8c. Widening it did not make it fire on a different account, or on prose.
///
/// The half that decides whether anyone keeps the gate. Before the trailing
/// boundary was added the tilde form matched any longer account name that
/// starts the same way, and the tree already contains `aggregator`,
/// `navigator` and `investigator`.
#[test]
fn e8c_the_widened_account_rule_still_spares_the_words_around_it() -> Result<(), TestError> {
    for benign in [
        "/home/gatorade/pcaps",
        "user-local under `~gatorade`",
        "and every aggregator downstream of journald",
        "navigator.clipboard.writeText",
        "/Users/user/capture.pcap",
        "$HOME/pcaps",
    ] {
        assert!(
            !rule::account_path(benign),
            "a rule that cries about a different account, or about ordinary \
             English, gets suppressed and then catches nothing: {benign}"
        );
    }
    Ok(())
}

/// E9. The account list is not empty, which is how this class goes vacuous.
#[test]
fn e9_the_account_list_is_not_empty() -> Result<(), TestError> {
    assert!(
        !rule::PRIVATE_ACCOUNTS.is_empty(),
        "with no accounts listed, `account_path` returns false for everything \
         and both scans above pass by proving nothing"
    );
    assert!(
        rule::PRIVATE_ACCOUNTS
            .iter()
            .all(|a| !a.is_empty() && !a.contains('/')),
        "an account is a name, not a path fragment"
    );
    Ok(())
}

/// E10. The guide names the corpus rule and the path alternatives.
#[test]
fn e10_the_guide_names_the_corpus_rule() -> Result<(), TestError> {
    let guide = contributing()?;
    assert!(guide.contains("$home"), "CONTRIBUTING.md must name `$HOME`");
    assert!(
        guide.contains("corpora") || guide.contains("corpus"),
        "and must say that capture corpora live outside the tree"
    );
    Ok(())
}

// -- Class F: tracked transcripts -------------------------------------

/// F1. No log, backup or editor artefact is tracked.
///
/// A gate log is the densest form of this leak: a verbatim transcript of one
/// run on one machine, absolute paths and all, committed by accident rather
/// than by decision. `.git-docsgate.log` was tracked and carried a worktree
/// path under the maintainer's home directory.
#[test]
fn f1_no_transcript_or_backup_file_is_tracked() -> Result<(), TestError> {
    let out = Command::new("git")
        .args(["ls-files"])
        .current_dir(repo())
        .output()
        .map_err(|e| format!("git ls-files: {e}"))?;
    let bad: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|f| rule::transcript_file(f))
        .map(str::to_string)
        .collect();
    assert!(
        bad.is_empty(),
        "a transcript or backup file is tracked:\n{}\n\n{}",
        capped(&bad, 25),
        guidance::TRANSCRIPT
    );
    Ok(())
}

/// F2. The rule flags the file that leaked.
#[test]
fn f2_the_transcript_rule_flags_the_file_that_leaked() -> Result<(), TestError> {
    assert!(
        rule::transcript_file(".git-docsgate.log"),
        "the gate log that was tracked must be caught if it returns"
    );
    Ok(())
}

/// F3. It flags the editor and merge artefacts too.
#[test]
fn f3_the_transcript_rule_flags_editor_and_merge_artefacts() -> Result<(), TestError> {
    for f in [
        "src/pipeline.rs.bak",
        "docs/x.md.orig",
        "a.rej",
        ".x.swp",
        "notes~",
    ] {
        assert!(rule::transcript_file(f), "{f} is a working artefact");
    }
    Ok(())
}

/// Real files in this tree whose names contain `log` without being one.
///
/// Real, and checked to be real by `f4b`. A negative control that names a file
/// nobody has proves the rule spares an imaginary tree: the first version of
/// this list invented a backup script under `scripts/` that had never existed,
/// and `every_cited_script_exists` caught it -- which is the same lesson this
/// whole file is about, arriving from the other direction. That gate reads doc
/// comments too, so this sentence does not spell the path either.
const LOGGY_BUT_NOT_LOGS: &[&str] = &[
    "CHANGELOG.md",
    "docs/design/backlog.md",
    "docs/design/dialog-tracking-modes.md",
    "src/output/dialog_report.rs",
];

/// F4. It spares source files whose names merely contain the words.
#[test]
fn f4_the_transcript_rule_spares_source_files() -> Result<(), TestError> {
    for f in LOGGY_BUT_NOT_LOGS {
        assert!(!rule::transcript_file(f), "{f} is source, not a transcript");
    }
    Ok(())
}

/// F4b. Those files exist, so the control is about this tree.
#[test]
fn f4b_the_negative_controls_name_files_that_exist() -> Result<(), TestError> {
    for f in LOGGY_BUT_NOT_LOGS {
        assert!(
            repo().join(f).exists(),
            "{f} does not exist, so sparing it proves nothing about this tree. \
             Name a file that is really here."
        );
    }
    Ok(())
}

/// F5. `.gitignore` carries the pattern, so the next one is never staged.
///
/// The gate catches a tracked transcript; the ignore rule stops it becoming
/// one. Without both, the fix lasts until the next run writes the file again.
#[test]
fn f5_gitignore_carries_the_transcript_pattern() -> Result<(), TestError> {
    let ignore = std::fs::read_to_string(repo().join(".gitignore"))
        .map_err(|e| format!(".gitignore: {e}"))?;
    assert!(
        ignore.contains("*.log"),
        ".gitignore must ignore transcripts, or the gate is the only thing \
         standing between a run and a commit"
    );
    Ok(())
}

/// F6. The hooks write their logs outside the worktree.
///
/// `pre-commit` writes `.git/sipnab-pre-commit-*.log`, which a commit cannot
/// reach. That is the correct arrangement and worth pinning: a hook that writes
/// its log into the worktree instead is one `git add -A` away from publishing
/// it.
#[test]
fn f6_the_hooks_write_their_logs_outside_the_worktree() -> Result<(), TestError> {
    let hook = std::fs::read_to_string(repo().join(".githooks/pre-commit"))
        .map_err(|e| format!("pre-commit: {e}"))?;
    assert!(
        hook.contains("git rev-parse --git-dir") || hook.contains(".git/"),
        "the pre-commit hook must write its transcript under .git/, where a \
         commit cannot reach it"
    );
    Ok(())
}

/// F7. The scan is over what is tracked, not over the tree.
///
/// An untracked log on somebody's machine is invisible here -- which is right,
/// because it is also invisible to everyone else. Pinned so nobody "improves"
/// the scan into walking the tree, which would read `target/` and every
/// worktree artefact besides.
#[test]
fn f7_the_scan_is_over_what_is_tracked() -> Result<(), TestError> {
    let files = tracked_text()?;
    assert!(
        !files.iter().any(|(rel, _)| rel.starts_with("target/")),
        "the scan is reading build output, which means it walked the tree \
         instead of asking git what is tracked"
    );
    Ok(())
}

/// F8. A renamed transcript still fails on its contents.
///
/// Defense in depth: the filename rule is the cheap one, and the path rule is
/// what makes renaming it to `notes.md` not a way through.
#[test]
fn f8_a_renamed_transcript_still_fails_on_its_contents() -> Result<(), TestError> {
    let line = "  Full output: /home/gator/Development/sipnab/.git/worktrees/agent-a5e/x.log";
    assert!(
        rule::account_path(line),
        "renaming a transcript must not make its contents acceptable"
    );
    Ok(())
}

/// F9. The transcript patterns are not empty.
#[test]
fn f9_the_transcript_rule_has_patterns_to_match() -> Result<(), TestError> {
    assert!(
        rule::transcript_file("x.log") && rule::transcript_file("x~"),
        "with no patterns the rule returns false for everything and F1 passes \
         by proving nothing"
    );
    Ok(())
}

/// F10. The guide says not to commit them.
#[test]
fn f10_the_guide_says_not_to_commit_transcripts() -> Result<(), TestError> {
    let guide = contributing()?;
    assert!(
        guide.contains("gate log") || guide.contains("scratch file"),
        "CONTRIBUTING.md must say a transcript is not committed"
    );
    assert!(guidance::TRANSCRIPT.contains(".gitignore"));
    Ok(())
}

// -- Class G: addresses that reach a real person ----------------------

/// G1. The only email addresses in the tree are published identities.
///
/// `Cargo.toml` carries the maintainer's on purpose -- a crate has to name
/// someone, and it is already on crates.io. Any OTHER address is somebody who
/// did not choose to be in this repository.
#[test]
fn g1_no_address_reaches_a_real_mailbox() -> Result<(), TestError> {
    let files = tracked_text()?;
    let addr = regex::Regex::new(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")?;
    let mut found = Vec::new();
    for (rel, text) in &files {
        if rel == "tests/private_identity_test.rs" {
            continue;
        }
        for (i, line) in text.lines().enumerate() {
            for m in addr.find_iter(line) {
                if rule::live_address(m.as_str()) {
                    found.push(format!("{rel}:{}: {}", i + 1, m.as_str()));
                }
            }
        }
    }
    assert!(
        found.is_empty(),
        "an address at a domain somebody owns is in the tree:\n{}\n\n{}",
        capped(&found, 25),
        guidance::MAILBOX
    );
    Ok(())
}

/// G2. The rule flags the sample-output URI that leaked.
///
/// `1002@carrier.net` appeared ten times in `src/output/call_report.rs` -- as
/// fixture data AND in the expected output beside it, so it was in sample
/// output a reader could copy.
#[test]
fn g2_the_mailbox_rule_flags_the_sample_uri_that_leaked() -> Result<(), TestError> {
    assert!(rule::live_address("1002@carrier.net"));
    Ok(())
}

/// G3. It flags the fixture address that leaked.
#[test]
fn g3_the_mailbox_rule_flags_the_fixture_that_leaked() -> Result<(), TestError> {
    assert!(rule::live_address("evil@attacker.com"));
    Ok(())
}

/// G4. It spares RFC 2606's reserved TLDs, which are the fix.
#[test]
fn g4_the_mailbox_rule_spares_reserved_tlds() -> Result<(), TestError> {
    for benign in [
        "evil@attacker.test",
        "alice@real.test",
        "1002@carrier.example",
        "user@host.invalid",
    ] {
        assert!(
            !rule::live_address(benign),
            "a reserved name cannot reach anyone, which is the point: {benign}"
        );
    }
    Ok(())
}

/// G5. It spares subdomains of the reserved example domains.
///
/// `deploy@web01.example.com` is a deployment example, and an allowlist that
/// only knew the bare domain flagged it.
#[test]
fn g5_the_mailbox_rule_spares_reserved_subdomains() -> Result<(), TestError> {
    for benign in [
        "deploy@web01.example.com",
        "ops@ci.example.org",
        "a@b.example.net",
    ] {
        assert!(!rule::live_address(benign), "{benign} is reserved too");
    }
    Ok(())
}

/// G6. It spares a SIP Call-ID, which is not a mailbox.
///
/// `call-NNNN@sipnab.bench` has the shape and none of the meaning. The rule
/// runs off REAL top-level domains for this reason: `.bench` resolves nowhere.
#[test]
fn g6_the_mailbox_rule_spares_a_sip_call_id() -> Result<(), TestError> {
    for benign in [
        "call-NNNN@sipnab.bench",
        "a84b4c76e66710@pc33.atlanta.invalid",
        "3848276298220188511@fixture.test",
    ] {
        assert!(
            !rule::live_address(benign),
            "a Call-ID is not an address: {benign}"
        );
    }
    Ok(())
}

/// G7. The published identities are spared, and the list is not empty.
#[test]
fn g7_the_published_identities_are_spared() -> Result<(), TestError> {
    for published in rule::PUBLISHED_IDENTITIES {
        assert!(
            !rule::live_address(published),
            "{published} is published deliberately"
        );
    }
    assert!(
        !rule::PUBLISHED_IDENTITIES.is_empty(),
        "a crate has to name a maintainer; an empty list means the manifest \
         address is about to be reported as a leak"
    );
    Ok(())
}

/// G8. The real-TLD list is what makes the rule decidable, and is populated.
#[test]
fn g8_the_real_tld_list_is_populated() -> Result<(), TestError> {
    assert!(
        rule::REAL_TLDS.len() > 10,
        "with a short list, an address at an unlisted TLD is silently allowed"
    );
    for must in ["com", "net", "org"] {
        assert!(
            rule::REAL_TLDS.contains(&must),
            "`{must}` is where a leaked address will be"
        );
    }
    Ok(())
}

/// G9. The scan reaches source, not only documentation.
///
/// Both addresses in this class leaked from `src/`, inside test fixtures -- a
/// documentation-only scan would have found neither.
#[test]
fn g9_the_mailbox_scan_reaches_source_files() -> Result<(), TestError> {
    let files = tracked_text()?;
    for surface in ["src/output/call_report.rs", "src/sip/message.rs"] {
        assert!(
            reaches(&files, surface),
            "{surface} carried a live address and must be in the scan"
        );
    }
    let rust = files.iter().filter(|(r, _)| r.ends_with(".rs")).count();
    assert!(rust > 50, "only {rust} Rust files in the scan is too few");
    Ok(())
}

/// G10. The guide names the reserved names a fixture should use.
#[test]
fn g10_the_guide_names_the_reserved_fixture_domains() -> Result<(), TestError> {
    let guide = contributing()?;
    assert!(
        guide.contains(".test") || guide.contains(".invalid"),
        "CONTRIBUTING.md must name the reserved forms a fixture should use"
    );
    assert!(guidance::MAILBOX.contains(".test"));
    Ok(())
}

// -- Class H: AI attribution -----------------------------------------
//
// sipnab names Claude where a page is about MCP: Claude Code and Claude
// Desktop are MCP clients, `claude mcp add` is how one is pointed at sipnab,
// and a model name appears in an MCP example. What is refused is crediting an
// assistant as an author of the work: a `Co-Authored-By:` line naming Claude
// or Anthropic, a "Generated with Claude Code" line, the assistant's noreply
// address, and a `Claude-Session:` trailer. The rule is case-insensitive,
// because git and GitHub treat trailer keys that way.

/// The gates that define the class H forms, and so must spell them.
///
/// This file is skipped by [`scan`] for every class. `tests/no_commit_attribution_test.rs`
/// is the older gate over recent commit messages: its predicate and its
/// positive controls are the forbidden forms, written out so a reader can see
/// what it refuses. Each entry is checked by `h7` to exist and to be a gate.
const AI_ATTRIBUTION_GATES: &[&str] = &["tests/no_commit_attribution_test.rs"];

/// Every class H line in `files`, outside [`AI_ATTRIBUTION_GATES`].
///
/// One function for the tree scan and for `h8`, so the planted-line control
/// exercises the same scan the tree gets.
fn ai_attribution_findings(files: &[(String, String)]) -> Vec<String> {
    scan(
        files,
        |rel| !AI_ATTRIBUTION_GATES.contains(&rel),
        rule::ai_attribution,
    )
}

/// H1. No tracked file credits an AI assistant as an author.
#[test]
fn h1_no_tracked_file_attributes_the_work_to_an_ai() -> Result<(), TestError> {
    let files = tracked_text()?;
    let found = ai_attribution_findings(&files);
    assert!(
        found.is_empty(),
        "a tracked file credits an AI assistant as an author:\n{}\n\n{}",
        capped(&found, 25),
        guidance::AI_ATTRIBUTION
    );
    Ok(())
}

/// H2. The rule flags each trailer form, in any case.
#[test]
fn h2_the_ai_attribution_rule_flags_each_trailer_form() -> Result<(), TestError> {
    for line in [
        "Co-Authored-By: Claude <noreply@anthropic.com>",
        "Co-Authored-By: Claude Opus 4.5 (1M context) <noreply@anthropic.com>",
        "co-authored-by: claude <someone@example.org>",
        "CO-AUTHORED-BY: Anthropic Assistant <a@example.org>",
        "Claude-Session: https://example.test/session/abc",
        "claude-session: abc",
    ] {
        assert!(rule::ai_attribution(line), "not flagged: {line:?}");
    }
    Ok(())
}

/// H3. It flags the "Generated with" line, with and without its link.
#[test]
fn h3_the_ai_attribution_rule_flags_the_generated_with_line() -> Result<(), TestError> {
    for line in [
        "Generated with [Claude Code](https://claude.com/claude-code)",
        "\u{1F916} Generated with [Claude Code](https://claude.com/claude-code)",
        "Generated with Claude Code",
        "generated with claude code",
    ] {
        assert!(rule::ai_attribution(line), "not flagged: {line:?}");
    }
    Ok(())
}

/// H4. It flags the assistant's noreply address wherever it appears.
#[test]
fn h4_the_ai_attribution_rule_flags_the_noreply_address() -> Result<(), TestError> {
    for line in [
        "Signed-off-by: x <noreply@anthropic.com>",
        "contact NOREPLY@ANTHROPIC.COM",
    ] {
        assert!(rule::ai_attribution(line), "not flagged: {line:?}");
    }
    Ok(())
}

/// H5. It spares Claude named as an MCP client, a command or a model.
///
/// These are the uses the MCP documentation needs, and the half that decides
/// whether the gate is kept: a rule that flags "connect Claude Code to
/// sipnab's MCP server" would be suppressed.
#[test]
fn h5_the_ai_attribution_rule_spares_mcp_documentation() -> Result<(), TestError> {
    for line in [
        "Connect Claude Code to sipnab's MCP server:",
        "claude mcp add sipnab -- sipnab --mcp-stdio",
        "Claude Desktop reads `claude_desktop_config.json` at startup.",
        "| Claude Desktop | stdio | yes |",
        "Tested with claude-opus-4-5 as the model behind the MCP client.",
        "An MCP client such as Claude Code generated with `--json` output in mind",
        "the Anthropic API is not called by sipnab",
    ] {
        assert!(!rule::ai_attribution(line), "flagged MCP prose: {line:?}");
    }
    Ok(())
}

/// H6. It spares a human co-author and a project's own "Generated with".
#[test]
fn h6_the_ai_attribution_rule_spares_human_trailers() -> Result<(), TestError> {
    for line in [
        "Co-Authored-By: A Person <person@example.org>",
        "Co-Authored-By: Norm Brandinger <n.brandinger@gmail.com>",
        "Generated with sipnab 0.5.200",
        "Reported-by: Someone <someone@example.org>",
    ] {
        assert!(
            !rule::ai_attribution(line),
            "flagged a human line: {line:?}"
        );
    }
    Ok(())
}

/// H7. The exempt gates exist, are gates, and are the only exemption.
///
/// An exemption that outlives its file, or that names a file which is not a
/// gate, is a hole: the scan would skip whatever later appears at that path.
#[test]
fn h7_the_exempt_files_are_the_gates_that_define_the_forms() -> Result<(), TestError> {
    let files = tracked_text()?;
    for rel in AI_ATTRIBUTION_GATES {
        let (_, text) = files
            .iter()
            .find(|(r, _)| r == rel)
            .ok_or(format!("{rel} is exempt from class H but is not tracked"))?;
        assert!(
            text.contains("#[test]") && text.to_ascii_lowercase().contains("co-authored-by"),
            "{rel} is exempt from class H but is not a gate over these forms"
        );
    }
    assert_eq!(AI_ATTRIBUTION_GATES.len(), 1, "the exemption list grew");
    Ok(())
}

/// H8. A planted line in a tracked file is reported with its path and line,
/// and the exempt gate is the only file whose lines are not.
#[test]
fn h8_a_planted_line_in_a_file_is_reported() -> Result<(), TestError> {
    let files = vec![
        (
            AI_ATTRIBUTION_GATES[0].to_string(),
            "// Co-Authored-By: Claude <noreply@anthropic.com>\n".to_string(),
        ),
        (
            "src/planted.rs".to_string(),
            "fn a() {}\n// Co-Authored-By: Claude <noreply@anthropic.com>\n".to_string(),
        ),
        (
            "docs/mcp.md".to_string(),
            "Connect Claude Code to sipnab's MCP server.\n".to_string(),
        ),
    ];
    let found = ai_attribution_findings(&files);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].starts_with("src/planted.rs:2: "), "{found:?}");
    Ok(())
}

/// H9. The message script refuses a planted trailer, names class H, and
/// passes the same message without it.
#[test]
fn h9_the_message_script_refuses_an_ai_trailer() -> Result<(), TestError> {
    let (rc, out) = run_message_script(
        "Fix the parser\n\nBody.\n\nCo-Authored-By: Claude <noreply@anthropic.com>\n",
        "ai-trailer",
    )?;
    assert_eq!(
        rc, 1,
        "an AI co-author trailer must fail the script:\n{out}"
    );
    assert!(
        out.contains("line 5: class H") && out.contains(guidance::AI_ATTRIBUTION),
        "the failure must name the line, the class and the replacement:\n{out}"
    );
    let (rc, out) = run_message_script(
        "Fix the parser\n\nConnect Claude Code to sipnab's MCP server.\n",
        "ai-clean",
    )?;
    assert_eq!(rc, 0, "an MCP client name must pass the script:\n{out}");
    Ok(())
}

/// H10. The guide names the rule.
#[test]
fn h10_the_guide_names_the_ai_attribution_rule() -> Result<(), TestError> {
    let guide = contributing()?;
    assert!(
        guide.contains("co-authored-by") && guide.contains("claude code"),
        "CONTRIBUTING.md must say that no AI attribution is accepted and that \
         naming an MCP client is"
    );
    Ok(())
}

// -- Structural: the scan itself --------------------------------------

/// The scan reads a real corpus, and the files it exists to cover.
///
/// Every rule above passes by finding nothing, which is also what they do if
/// `git ls-files` fails, if the binary filter swallows the tree, or if
/// `is_published` stops matching. A clean-looking gate and a broken one are
/// indistinguishable, so the corpus is asserted rather than assumed.
#[test]
fn the_scan_reads_the_files_it_claims_to_cover() -> Result<(), TestError> {
    let files = tracked_text()?;
    assert!(
        files.len() > 300,
        "the scan read {} tracked text files, far short of this tree",
        files.len()
    );

    let names: BTreeSet<&str> = files.iter().map(|(r, _)| r.as_str()).collect();
    for must in [
        "README.md",
        "CHANGELOG.md",
        "CONTRIBUTING.md",
        "docs/rtpengine.md",
        "docs/vcon.md",
        "benches/BASELINES.md",
        ".github/workflows/ci.yml",
    ] {
        assert!(
            names.contains(must),
            "the scan did not read {must}, a surface it exists to cover"
        );
    }

    let published = corpus_size(&files, is_published);
    assert!(
        published > 100,
        "only {published} files count as published -- `is_published` has \
         stopped matching"
    );
    Ok(())
}

// -- The guide and the gate say the same thing ------------------------

/// Every class the gate enforces is named in the contributing guide.
///
/// Owed to the failure that added the guide's table: the two are now coupled,
/// and a coupling nothing checks is a coupling that lasts until the next
/// change. A rule added here without a row there is a rule a contributor meets
/// for the first time as a rejected commit -- which is the cost this whole file
/// exists to avoid paying twice.
#[test]
fn the_guide_names_every_class_the_gate_enforces() -> Result<(), TestError> {
    let guide = contributing()?;
    // Each class, and a string from the guide that can only be there because
    // somebody wrote that row.
    for (class, clause) in [
        ("A hostnames", "hostname"),
        // An invented name, not a lab one: see FICTIONAL_HOST.
        ("B lab machines", FICTIONAL_HOST),
        ("C private domain", "example.com"),
        ("D addresses", "rfc 5737"),
        ("E accounts", "$home"),
        ("F transcripts", "gitignore"),
        ("G mailboxes", ".test"),
        ("H AI attribution", "co-authored-by"),
    ] {
        assert!(
            guide.contains(clause),
            "class {class} is enforced but CONTRIBUTING.md does not mention \
             `{clause}`, so a writer cannot know the rule before tripping it"
        );
    }
    Ok(())
}

/// The guide promises nothing the gate does not enforce.
///
/// The other direction, and the one that rots quietly: a row telling writers
/// that something is checked, when nothing checks it, is worse than silence --
/// it is a promise that reads as a guarantee. Each rule named below is invoked,
/// so deleting the rule breaks this test rather than leaving the guide lying.
#[test]
fn the_guide_promises_nothing_the_gate_does_not_enforce() -> Result<(), TestError> {
    assert!(
        rule::lab_host("thor-02"),
        "the guide promises hostnames are caught"
    );
    assert!(
        rule::lab_machine("opensips-1"),
        "the guide names opensips-1 as a machine to avoid"
    );
    assert!(
        rule::private_domain("x.goes.com"),
        "the guide promises the private domain is caught"
    );
    assert!(
        rule::lab_address("10.0.0.40"),
        "the guide promises the LAN is caught"
    );
    assert!(
        rule::account_path("/home/gator/pcaps"),
        "the guide promises account paths are caught"
    );
    assert!(
        rule::transcript_file("x.log"),
        "the guide promises transcripts are caught"
    );
    assert!(
        rule::live_address("a@real-domain.com"),
        "the guide promises live mailboxes are caught"
    );
    assert!(
        rule::ai_attribution("Co-Authored-By: Claude <noreply@anthropic.com>"),
        "the guide promises AI attribution is caught"
    );
    Ok(())
}
