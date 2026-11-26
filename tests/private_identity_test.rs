// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

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
//! Class I is a rule for commit messages only: no trailer names an email
//! address, apart from GitHub's noreply alias and GitHub's service addresses,
//! which name no person. A commit carries an address only in its author and
//! committer fields.
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
//! self-hosted jobs to a hardware label.
//!
//! The x86_64 self-hosted runner added on 2026-10-27 is registered with the
//! name of the host under it as a label, and with GitHub's default
//! architecture label `X64`. It is this repository's only x86_64 self-hosted
//! runner, so `X64` selects it without publishing the host's name, and B6
//! admits `X64` beside `jetson` and nothing else. A bare `[self-hosted]`
//! names no pool and stays refused.

#[path = "../src/test_scratch.rs"]
mod test_scratch;

use std::collections::BTreeSet;
use std::net::Ipv6Addr;
use std::path::{Path, PathBuf};
use std::process::Command;

#[path = "support/tracked.rs"]
mod tracked;

#[path = "support/ai_attribution.rs"]
mod ai_attribution;
#[path = "support/executable.rs"]
mod executable;
#[path = "support/pipefail_scan.rs"]
mod pipefail_scan;

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
    // The scan is over what is tracked, not what is present.
    let listed = tracked::ls_files(repo(), &[])?;

    let mut files = Vec::new();
    for rel in listed.iter().map(String::as_str) {
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

    /// G and I. An email address as a commit message can carry one.
    ///
    /// Wider than G1's pattern over the tracked files in one way: the local
    /// part may hold `[` and `]`, as a GitHub bot's alias does
    /// (`49699333+dependabot[bot]@users.noreply.github.com`). G1's pattern
    /// cannot start a match at `]@`, so it would also pass `x]@real-company.com`.
    /// The domain ends in a label of letters, so a version pin such as
    /// `serde@1.0.200` is not an address.
    pub const MESSAGE_ADDRESS: &str =
        r#"[^\s<>()"',;:@]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}"#;

    /// G and I. The script that holds GitHub's noreply rule, `_NOREPLY`.
    pub const DCO_SCRIPT: &str = "scripts/check-dco.py";

    /// G and I. The `_NOREPLY` pattern of `source`, the text of
    /// [`DCO_SCRIPT`], anchored and without case, as a Rust pattern.
    ///
    /// The definition is read only in the form the script writes it: the
    /// `_NOREPLY = re.compile(` line, the raw string alone on the next line,
    /// then `re.IGNORECASE,`. Any other form gives `None`, and with no rule no
    /// address is an alias, so a noreply sign-off is refused and the tests
    /// that pass one fail by name (i_e28).
    pub fn dco_noreply_pattern(source: &str) -> Option<String> {
        let mut lines = source
            .lines()
            .map(str::trim)
            .skip_while(|l| *l != "_NOREPLY = re.compile(");
        lines.next()?;
        let raw = lines.next()?.strip_prefix("r\"")?.strip_suffix("\",")?;
        (lines.next()? == "re.IGNORECASE,").then(|| format!("(?i)^(?:{raw})$"))
    }

    /// G and I. The noreply rule, read from [`DCO_SCRIPT`]; `None` when it
    /// cannot be read or does not compile.
    pub fn noreply() -> Option<&'static regex::Regex> {
        static RE: std::sync::OnceLock<Option<regex::Regex>> = std::sync::OnceLock::new();
        RE.get_or_init(|| {
            let source = std::fs::read_to_string(super::repo().join(DCO_SCRIPT)).ok()?;
            regex::Regex::new(&dco_noreply_pattern(&source)?).ok()
        })
        .as_ref()
    }

    /// G and I. Addresses of GitHub's own services, which name no person:
    /// Dependabot signs its commits `Signed-off-by: dependabot[bot]
    /// <support@github.com>`. Exact addresses only.
    pub const GITHUB_SERVICE_ADDRESSES: &[&str] = &["support@github.com"];

    /// G. The published identities a message body may name. The maintainer's
    /// address, published in `Cargo.toml`, is not one: in a commit it belongs
    /// only in the author and committer fields.
    pub const MESSAGE_IDENTITIES: &[&str] = &["noreply@github.com", "security@sipnab.com"];

    /// The compiled `pattern`, or `None` if it does not compile. Every caller
    /// fails closed on `None`: a rule that cannot read a line refuses it.
    /// i_e22 compiles both patterns, so a broken one fails the suite.
    fn compiled(
        pattern: &'static str,
        cell: &'static std::sync::OnceLock<Option<regex::Regex>>,
    ) -> Option<&'static regex::Regex> {
        cell.get_or_init(|| regex::Regex::new(pattern).ok())
            .as_ref()
    }

    /// G and I. Every address in `text`, or `None` when the pattern does not
    /// compile.
    pub fn addresses(text: &str) -> Option<Vec<&str>> {
        static RE: std::sync::OnceLock<Option<regex::Regex>> = std::sync::OnceLock::new();
        Some(
            compiled(MESSAGE_ADDRESS, &RE)?
                .find_iter(text)
                .map(|m| m.as_str())
                .collect(),
        )
    }

    /// I. Is this an address a trailer may name: GitHub's alias for an
    /// account, or one of GitHub's service addresses?
    pub fn names_no_person(addr: &str) -> bool {
        noreply().is_some_and(|re| re.is_match(addr))
            || GITHUB_SERVICE_ADDRESSES.contains(&addr.to_ascii_lowercase().as_str())
    }

    /// G in a message: a line that names an address at a domain somebody
    /// owns, other than GitHub's and the project's published ones.
    pub fn message_address(line: &str) -> bool {
        names_a_mailbox(addresses(line))
    }

    /// G, over the addresses one line holds; `None`, a pattern that did not
    /// compile, refuses the line.
    pub fn names_a_mailbox(found: Option<Vec<&str>>) -> bool {
        let Some(found) = found else {
            return true;
        };
        found.iter().any(|a| {
            let low = a.to_ascii_lowercase();
            !names_no_person(&low)
                && !MESSAGE_IDENTITIES.contains(&low.as_str())
                && (live_address(&low) || PUBLISHED_IDENTITIES.contains(&low.as_str()))
        })
    }

    /// I. A trailer, as git unfolds it, that names any address other than
    /// one that names no person.
    pub fn trailer_address(trailer: &str) -> bool {
        names_an_address(addresses(trailer))
    }

    /// I, over the addresses one trailer holds; `None`, a pattern that did
    /// not compile, refuses the trailer.
    pub fn names_an_address(found: Option<Vec<&str>>) -> bool {
        found.is_none_or(|found| found.iter().any(|a| !names_no_person(a)))
    }

    /// [`compiled`], for the test that a broken pattern gives `None`.
    pub fn compiles(pattern: &'static str) -> bool {
        static RE: std::sync::OnceLock<Option<regex::Regex>> = std::sync::OnceLock::new();
        compiled(pattern, &RE).is_some()
    }

    /// H. A line that credits an AI assistant as an author of the work.
    ///
    /// The shared detector, `tests/support/ai_attribution.rs`: a credit
    /// trailer naming any AI assistant (behind a leading `#` too), a
    /// "generated with" or "generated by" line naming one, the vendor's
    /// noreply address, a session trailer or a session-console link. This
    /// copy used to name Claude and Anthropic only. A bare product name is
    /// not one of them: Claude Code and Claude Desktop are MCP clients the
    /// MCP documentation has to name.
    pub fn ai_attribution(line: &str) -> bool {
        crate::ai_attribution::is_ai_attribution_line(line)
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
    pub const MESSAGE_MAILBOX: &str = "Delete the address, or write one at a reserved domain \
                                       (example.com, or a .test or .invalid name). A commit \
                                       message carries no personal data: an address belongs \
                                       only in the commit's author and committer fields.";
    pub const TRAILER_ADDRESS: &str = "Delete the address from the trailer. A trailer is \
                                       published on main with the commit, and this project's \
                                       policy allows an email address only in the commit's \
                                       author and committer fields. A trailer names a person \
                                       by name alone, or by GitHub's noreply alias \
                                       (ID+login@users.noreply.github.com), the form a DCO \
                                       sign-off takes (CONTRIBUTING.md, \"Signing off \
                                       commits\"). A commit the owner authored and committed \
                                       needs no sign-off.";
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
/// lab's machines), C (the domain), D (the LAN), E (account and corpus
/// paths), G (an address at a domain somebody owns, held to
/// [`rule::message_address`]) and H (AI attribution). Class I, an address in
/// a trailer, depends on where the trailer block is, which is not a property
/// of one line: [`trailer_findings`] reads it, and [`all_message_findings`]
/// joins the two.
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
    let classes: [(&'static str, LineRule); 7] = [
        ("A", |l| rule::lab_host(l) || rule::bare_host(l)),
        ("B", rule::lab_machine),
        ("C", rule::private_domain),
        ("D", rule::lab_address),
        ("E", |l| rule::account_path(l) || rule::corpus_path(l)),
        ("G", rule::message_address),
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

/// The trailers of a message, as `git interpret-trailers --parse` reads them.
fn message_trailers(text: &str, scissors: Scissors) -> Result<Vec<String>, TestError> {
    message_trailers_with(std::ffi::OsStr::new("git"), text, scissors)
}

/// The comment character the whole-message mode gives git: a control
/// character no message line starts with, so no `#` line and no scissors line
/// is a comment. A message stored whole keeps both, as published.
const NO_COMMENT_CHAR: &str = "\u{1}";

/// The `git interpret-trailers` command [`message_trailers`] runs.
///
/// `--parse` prints each trailer on one line, folded lines joined, and
/// nothing else. `--no-divider` reads past a `---` line, as `git commit`
/// does: Dependabot's message bodies hold one. In the editor mode git's own
/// comment handling applies, the way `git commit` removes `#` lines and
/// everything below a scissors line from a message it opened in an editor.
///
/// No configuration is read -- no system or global file, no `-c` from a
/// parent, and no repository, because the command runs in `/` with
/// `GIT_DIR` removed -- so a `trailer.*` setting on one machine cannot change
/// the verdict there (i_e17).
fn trailer_command(git: &std::ffi::OsStr, scissors: Scissors) -> Command {
    let mut cmd = Command::new(git);
    if scissors == Scissors::Read {
        cmd.arg("-c")
            .arg(format!("core.commentChar={NO_COMMENT_CHAR}"));
    }
    cmd.args(["interpret-trailers", "--parse", "--no-divider"])
        .current_dir("/")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_CONFIG_PARAMETERS")
        .env_remove("GIT_CONFIG_COUNT")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    cmd
}

/// [`message_trailers`], with the git program named. A git that does not
/// start or fails is an error, never an empty list: a message nobody read is
/// not a clean message.
fn message_trailers_with(
    git: &std::ffi::OsStr,
    text: &str,
    scissors: Scissors,
) -> Result<Vec<String>, TestError> {
    use std::io::Write as _;
    let mut child = trailer_command(git, scissors)
        .spawn()
        .map_err(|e| format!("`git interpret-trailers` did not start: {e}"))?;
    // git reads all of its input before it writes, so writing first cannot
    // stall on a full output pipe.
    child
        .stdin
        .take()
        .ok_or("`git interpret-trailers` has no standard input")?
        .write_all(text.as_bytes())
        .map_err(|e| format!("cannot hand the message to `git interpret-trailers`: {e}"))?;
    let out = child
        .wait_with_output()
        .map_err(|e| format!("`git interpret-trailers` did not finish: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "`git interpret-trailers` failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        )
        .into());
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_string)
        .collect())
}

/// The 1-based line on which each trailer starts, in order.
///
/// git prints a trailer as `key: value`, with the key as written, the
/// spacing around the separator dropped and folded lines joined. Trailers sit
/// at the end of the message, so they are matched from the last line up: the
/// last trailer to the last line that starts with its key and a separator,
/// the one before it above that line. A body line that starts with the same
/// key is never reached (i_e15). In the editor mode the lines below a
/// scissors line are not read, as git does not read them.
fn trailer_lines(
    text: &str,
    scissors: Scissors,
    trailers: &[String],
) -> Result<Vec<usize>, TestError> {
    let lines: Vec<&str> = text
        .lines()
        .take_while(|l| scissors == Scissors::Read || *l != SCISSORS)
        .collect();
    let mut placed = Vec::with_capacity(trailers.len());
    let mut above = lines.len();
    for trailer in trailers.iter().rev() {
        let key = trailer.split(':').next().unwrap_or_default();
        let at = (0..above).rev().find(|&i| {
            lines[i]
                .strip_prefix(key)
                .is_some_and(|rest| rest.trim_start_matches([' ', '\t']).starts_with(':'))
        });
        let Some(i) = at else {
            return Err(format!(
                "git reads the trailer {trailer:?}, but no line above line {} starts with \
                 its key, so its line is unknown",
                above + 1
            )
            .into());
        };
        placed.push(i + 1);
        above = i;
    }
    placed.reverse();
    Ok(placed)
}

/// Every trailer of a message that names an address (class I), with its line.
fn trailer_findings(text: &str, scissors: Scissors) -> Result<Vec<Finding>, TestError> {
    let trailers = message_trailers(text, scissors)?;
    let lines = trailer_lines(text, scissors, &trailers)?;
    Ok(lines
        .into_iter()
        .zip(trailers)
        .filter(|(_, t)| rule::trailer_address(t))
        .map(|(n, t)| (n, "I", t))
        .collect())
}

/// Every finding in a message: the line classes and the trailer class I, in
/// line order. The check the commit-msg hook, pre-push and CI run.
fn all_message_findings(text: &str, scissors: Scissors) -> Result<Vec<Finding>, TestError> {
    let mut found = message_findings_from(text, scissors);
    found.extend(trailer_findings(text, scissors)?);
    found.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));
    Ok(found)
}

/// The replacement text for a class `message_findings` reports.
fn guidance_for(class: &str) -> &'static str {
    match class {
        "A" => guidance::HOST,
        "B" => guidance::MACHINE,
        "C" => guidance::DOMAIN,
        "D" => guidance::ADDRESS,
        "G" => guidance::MESSAGE_MAILBOX,
        "H" => guidance::AI_ATTRIBUTION,
        "I" => guidance::TRAILER_ADDRESS,
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
    let found = all_message_findings(&text, scissors)?;
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

/// M5. A trailer naming an address is refused, a reserved one included.
///
/// This test said the opposite until 2026-11-25: trailers were thought to
/// carry real addresses on purpose. A trailer is published on `main` with its
/// commit, so the owner's rule since then is that an address appears only in
/// the author and committer fields (class I).
#[test]
fn m5_trailers_carrying_addresses_are_refused() -> Result<(), TestError> {
    let message = "Fix the parser\n\nBody.\n\n\
                   Signed-off-by: Someone <someone@example.org>\n\
                   Reported-by: A Person <person@real-company.com>\n";
    let found: Vec<(usize, &str)> = all_message_findings(message, Scissors::Cut)?
        .into_iter()
        .map(|(n, c, _)| (n, c))
        .collect();
    assert_eq!(
        found,
        vec![(5, "I"), (6, "G"), (6, "I")],
        "both trailers name an address; the second is also at a real domain"
    );
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
    replace_own_binary_when_told()?;
    run_message_script_with(message, tag, own_binary()?.as_os_str())
}

/// A path that executes THIS test binary for as long as this process lives.
///
/// On Linux that is `/proc/<pid>/exe`: it names the inode this process runs,
/// so it still executes after a build has renamed a new binary over the file,
/// where `std::env::current_exe()` returns `<path> (deleted)`, a path that
/// does not exist (see
/// [`m6b_the_message_script_runs_after_the_test_binary_is_replaced_on_disk`]).
/// Elsewhere there is no such link, and the file's path is used.
fn own_binary() -> Result<PathBuf, TestError> {
    if cfg!(target_os = "linux") {
        Ok(PathBuf::from(format!("/proc/{}/exe", std::process::id())))
    } else {
        Ok(std::env::current_exe()?)
    }
}

/// Set in the environment of a copy of this binary that
/// [`m6b_the_message_script_runs_after_the_test_binary_is_replaced_on_disk`]
/// starts: the copy then replaces its own file before running the script.
const REPLACE_OWN_BINARY: &str = "SIPNAB_IDENTITY_TEST_REPLACE_OWN_BINARY";

/// When [`REPLACE_OWN_BINARY`] is `1`, replace this binary's file on disk with
/// a copy of itself, as a concurrent `cargo` build into the same target
/// directory does when it relinks the test binary: a new file is renamed over
/// the old path, and the running process keeps the old, now unlinked, inode.
fn replace_own_binary_when_told() -> Result<(), TestError> {
    static REPLACED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if std::env::var(REPLACE_OWN_BINARY).as_deref() != Ok("1")
        || REPLACED.swap(true, std::sync::atomic::Ordering::SeqCst)
    {
        // Once per process: after the first time the file is already gone
        // from under `current_exe()`, which is the state under test.
        return Ok(());
    }
    let exe = std::env::current_exe()?;
    let fresh = exe.with_extension("relinked");
    // `cp` writes the copy, so this process never holds it open for writing
    // (see tests/support/executable.rs).
    let status = Command::new("cp").arg(&exe).arg(&fresh).status()?;
    if !status.success() {
        return Err(format!("cp {} {}: {status}", exe.display(), fresh.display()).into());
    }
    std::fs::rename(&fresh, &exe)?;
    Ok(())
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
    let dir = test_scratch::ScratchDir::new(&format!("sipnab-message-identity-{tag}-"))
        .map_err(|e| format!("scratch dir: {e}"))?;
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

/// M6b. The script still runs this test binary after the file it was started
/// from has been replaced on disk.
///
/// Under the pre-commit hook, M6 exited 2, "the check failed before it read
/// the message", and passed when run alone. Reproduced by replacing the test
/// binary on disk while M6 runs: `std::env::current_exe()` then reads
/// `/proc/self/exe` as `<path> (deleted)`, the script cannot execute that
/// path, and it reports the check as not run. Any build into the same target
/// directory that relinks the binary while the suite runs does this.
///
/// A copy of this binary is started on M6 alone, told to replace its own file
/// first ([`REPLACE_OWN_BINARY`]), and M6 must still pass in it.
#[cfg(target_os = "linux")]
#[test]
fn m6b_the_message_script_runs_after_the_test_binary_is_replaced_on_disk() -> Result<(), TestError>
{
    let dir = tempfile::tempdir()?;
    let copy = dir.path().join("private_identity_test");
    // Copied by `cp`, so no writable descriptor of ours can make the copy
    // busy when it is executed.
    let status = Command::new("cp")
        .arg(std::env::current_exe()?)
        .arg(&copy)
        .status()?;
    assert!(status.success(), "copying the test binary: {status}");
    let out = Command::new(&copy)
        .args([
            "--exact",
            "message_script_refuses_a_planted_message_and_passes_a_clean_one",
        ])
        .env(REPLACE_OWN_BINARY, "1")
        .current_dir(repo())
        .output()?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.status.success() && text.contains("test result: ok. 1 passed"),
        "M6 must pass in a test binary whose file was replaced while it ran:\n{text}"
    );
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

/// More bytes than a Linux pipe holds (64 KiB), so a writer feeding a reader
/// that stops early is still writing when the reader exits.
const PAST_A_PIPE_BUFFER: usize = 1 << 20;

/// Run the script with a stand-in test binary that prints `output` and exits
/// with `code`, and return the script's exit code and output.
///
/// The stand-in is a shell script that `cat`s a file, so the output can be any
/// size and is exactly what the test wrote.
fn run_message_script_on_output(
    output: &str,
    code: i32,
    tag: &str,
) -> Result<(i32, String), TestError> {
    let dir = tempfile::tempdir()?;
    let printed = dir.path().join("printed.txt");
    std::fs::write(&printed, output)?;
    let bin = dir.path().join("stand-in-test-binary");
    executable::write_executable(
        &bin,
        &format!("#!/bin/sh\ncat '{}'\nexit {code}\n", printed.display()),
    )?;
    run_message_script_with("Fix the parser\n", tag, bin.as_os_str())
}

/// libtest's report of a failed run of [`MESSAGE_TEST`], with `findings` as
/// the lines of the test's own panic message and `after` printed after the
/// backtrace note.
fn failed_message_test_output(findings: &str, after: &str) -> String {
    format!(
        "\nrunning 1 test\ntest {MESSAGE_TEST} ... FAILED\n\nfailures:\n\n\
         ---- {MESSAGE_TEST} stdout ----\n\n\
         thread '{MESSAGE_TEST}' (1) panicked at tests/private_identity_test.rs:1:1:\n\
         {findings}\n\
         note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace\n\
         {after}\n\nfailures:\n    {MESSAGE_TEST}\n\n\
         test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 103 filtered out\n"
    )
}

/// M7b. A message with findings fails the script with exit 1 however long
/// the list of findings is.
///
/// Coverage on pull request #601 failed M6 with "the check failed before it
/// read the message" although the output named the finding. The script fed
/// the findings to `grep -q` through a pipe under `set -o pipefail`: `grep -q`
/// exits at its first match, the `printf` writing to it then dies of SIGPIPE
/// (exit 141) while it still has output to write, and pipefail fails the
/// pipeline although `grep` matched. With a short list the race is lost about
/// once in a few thousand runs on a loaded host (measured 2026-11-02: one in
/// 2400 with every core busy); with more output than a pipe holds it is lost
/// every time, so this test does not depend on timing.
#[test]
fn message_script_reports_a_long_list_of_findings() -> Result<(), TestError> {
    let line = "  line 3: class A: Measured on the host.\n    Name what the machine IS.";
    let mut findings = String::from("the message in message.txt names a private identity.");
    while findings.len() < PAST_A_PIPE_BUFFER {
        findings.push('\n');
        findings.push_str(line);
    }
    let (rc, out) =
        run_message_script_on_output(&failed_message_test_output(&findings, ""), 101, "long")?;
    assert_eq!(
        rc,
        1,
        "a message with findings must fail with exit 1:\n{}",
        &out[..out.len().min(2000)]
    );
    assert!(
        out.starts_with("the message in message.txt names a private identity."),
        "the script must print the findings: {}",
        &out[..out.len().min(2000)]
    );
    Ok(())
}

/// M7c. The findings are read correctly when more output follows them than a
/// pipe holds.
///
/// The script cuts the findings out of the test's output with an `awk` that
/// exits at the backtrace note. Fed through a pipe under `set -o pipefail`,
/// the writer died of SIGPIPE once `awk` had exited, and `set -e` ended the
/// script with exit 141 before it reported anything.
#[test]
fn message_script_reads_findings_followed_by_long_output() -> Result<(), TestError> {
    let after = "x".repeat(79).repeat(PAST_A_PIPE_BUFFER / 79 + 1);
    let output = failed_message_test_output(
        "the message in message.txt names a private identity.\n  line 3: class A: planted",
        &after,
    );
    let (rc, out) = run_message_script_on_output(&output, 101, "trailing")?;
    assert_eq!(
        rc,
        1,
        "a message with findings must fail with exit 1:\n{}",
        &out[..out.len().min(2000)]
    );
    assert!(
        out.contains("line 3: class A") && !out.contains("xxxx"),
        "the script must print the findings and nothing after the note:\n{}",
        &out[..out.len().min(2000)]
    );
    Ok(())
}

/// M7d. A clean run passes when more output follows libtest's summary than a
/// pipe holds.
///
/// The script looks for `test result: ok. 1 passed` with `grep -q` on a pipe
/// under `set -o pipefail`, the same race as M7b: a match followed by more
/// output read as "NOT CHECKED".
#[test]
fn message_script_passes_a_clean_run_followed_by_long_output() -> Result<(), TestError> {
    let after = "y".repeat(79).repeat(PAST_A_PIPE_BUFFER / 79 + 1);
    let output = format!(
        "\nrunning 1 test\ntest {MESSAGE_TEST} ... ok\n\n\
         test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 103 filtered out\n{after}\n"
    );
    let (rc, out) = run_message_script_on_output(&output, 0, "clean-long")?;
    assert_eq!(
        rc,
        0,
        "a clean run must pass:\n{}",
        &out[..out.len().min(2000)]
    );
    assert!(out.is_empty(), "the script is quiet on success");
    Ok(())
}

/// M7e. The script never decides from a pipe into a reader that can stop
/// before the writer is done.
///
/// M7b to M7d drive the three places the race bit. This holds the rest of the
/// script to the same rule: `grep -q` exits at its first match and `awk`
/// at `exit`, and under `set -o pipefail` the writer's SIGPIPE then fails the
/// pipeline. The script reads captured text from a here-string instead, which
/// no writer process feeds. The rule is tests/support/pipefail_scan.rs, the
/// one tests/pipefail_early_exit_test.rs applies to every tracked script.
#[test]
fn message_script_never_pipes_into_a_reader_that_stops_early() -> Result<(), TestError> {
    let script = std::fs::read_to_string(repo().join(MESSAGE_SCRIPT))
        .map_err(|e| format!("{MESSAGE_SCRIPT}: {e}"))?;
    let offenders = pipefail_scan::scan_shell_file(&script);
    assert!(
        offenders.is_empty(),
        "{MESSAGE_SCRIPT} pipes into a reader that can stop reading before the \
         writer is done; under pipefail the writer's SIGPIPE fails the \
         pipeline. Read a here-string instead: {offenders:?}"
    );
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
    let dir = test_scratch::ScratchDir::new(&format!("sipnab-message-features-{tag}-"))
        .map_err(|e| format!("scratch dir: {e}"))?;
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
    let bin = own_binary()?;
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

/// The labels a self-hosted job may select its runner by: the four aarch64
/// runners' `jetson`, `overflow` on the two of them that run at the lowest
/// priority, and the x86_64 runner's `X64`. Each names a pool, never a
/// machine.
const HARDWARE_LABELS: &[&str] = &["jetson", "overflow", "X64"];

/// Whether a runner-label line selects its runner by a hardware label and
/// names no machine.
fn runner_label_is_hardware(line: &str) -> bool {
    HARDWARE_LABELS.iter().any(|l| word(line, l))
        && !rule::lab_host(line)
        && !rule::lab_machine(line)
}

/// B6. Every self-hosted job reaches the runner by a hardware label, and
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
                if !runner_label_is_hardware(line) {
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
        "a self-hosted job does not use a hardware label ({HARDWARE_LABELS:?}), or names a machine:\n{}",
        named.join("\n")
    );
    Ok(())
}

/// B7. The hardware-label rule admits the two pools and refuses a bare
/// `self-hosted`, a host's name, and a hardware label beside a host's name.
#[test]
fn b7_the_hardware_label_rule_refuses_a_bare_or_named_runner() {
    assert!(
        runner_label_is_hardware("    runs-on: [self-hosted, jetson]"),
        "`runs-on: [self-hosted, jetson]` must be admitted"
    );
    assert!(
        runner_label_is_hardware("    runs-on: [self-hosted, X64]"),
        "`runs-on: [self-hosted, X64]` must be admitted"
    );
    assert!(
        runner_label_is_hardware("    runs-on: [self-hosted, overflow]"),
        "`runs-on: [self-hosted, overflow]` must be admitted"
    );
    assert!(
        runner_label_is_hardware(
            r#"    runs-on: ${{ matrix.os == 'ubuntu-latest' && fromJSON('["self-hosted","jetson"]') || 'macos-latest' }}"#
        ),
        "a conditional runs-on that selects [self-hosted, jetson] must be admitted"
    );
    assert!(
        !runner_label_is_hardware("    runs-on: [self-hosted]"),
        "`runs-on: [self-hosted]` must be refused"
    );
    assert!(
        !runner_label_is_hardware("    runs-on: self-hosted"),
        "`runs-on: self-hosted` must be refused"
    );
    assert!(
        !runner_label_is_hardware("    runs-on: [self-hosted, thor-02]"),
        "`runs-on: [self-hosted, thor-02]` must be refused"
    );
    assert!(
        !runner_label_is_hardware("    runs-on: [self-hosted, jetson, thor-02]"),
        "`runs-on: [self-hosted, jetson, thor-02]` must be refused"
    );
    assert!(
        !runner_label_is_hardware("    runs-on: [self-hosted, x64]"),
        "`runs-on: [self-hosted, x64]` must be refused"
    );
}

/// B8. The exception is recognized by shape, not by the hostname it carries.
///
/// So relabeling the runner does not silently widen the exception to whatever
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
    let listed = tracked::ls_files(repo(), &[])?;
    let bad: Vec<String> = listed
        .iter()
        .map(String::as_str)
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

/// H6b. It flags a credit naming any AI assistant, behind a leading `#` too.
///
/// This rule named Claude and Anthropic only, so these passed the commit-msg
/// hook and CI's pull-request check, which both run it. It now delegates to
/// the shared detector in `tests/support/ai_attribution.rs`.
#[test]
fn h6b_the_ai_attribution_rule_flags_every_assistant() -> Result<(), TestError> {
    for line in [
        "Co-Authored-By: GitHub Copilot <copilot@example.invalid>",
        "# Co-Authored-By: GitHub Copilot <copilot@example.invalid>",
        "Co-authored-by: Gemini <gemini@example.invalid>",
        "Assisted-by: Cursor",
        "Generated with GitHub Copilot",
    ] {
        assert!(rule::ai_attribution(line), "not flagged: {line:?}");
    }
    for line in [
        "Co-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>",
        "Co-authored-by: aikido-autofix[bot] <119856028+aikido-autofix[bot]@users.noreply.github.com>",
    ] {
        assert!(
            !rule::ai_attribution(line),
            "flagged an update bot: {line:?}"
        );
    }
    Ok(())
}

/// One commit made in a scratch repository through this tree's real
/// commit-msg hook and message script, with `SIPNAB_MESSAGE_TEST_BIN` pointing
/// at this test binary. `args` follow `git commit`; `editor` is a shell
/// command git runs as `GIT_EDITOR`, or `None` for `:`. `staged` is the
/// content of the one file staged for the commit.
///
/// Returns whether the commit was made, and the message git stored.
fn commit_through_the_hook(
    args: &[&str],
    editor: Option<&str>,
    staged: &str,
) -> Result<(bool, String), TestError> {
    let dir = tempfile::Builder::new()
        .prefix("sipnab-commit-msg-hook-")
        .tempdir()?;
    let root = dir.path();
    std::fs::create_dir_all(root.join(".githooks"))?;
    std::fs::create_dir_all(root.join("scripts"))?;
    std::fs::copy(
        repo().join(".githooks/commit-msg"),
        root.join(".githooks/commit-msg"),
    )?;
    std::fs::copy(repo().join(MESSAGE_SCRIPT), root.join(MESSAGE_SCRIPT))?;
    std::fs::copy(
        repo().join("scripts/lib-commit-mode.sh"),
        root.join("scripts/lib-commit-mode.sh"),
    )?;
    let git = |extra: &[&str]| -> Result<std::process::Output, TestError> {
        let mut cmd = Command::new("git");
        cmd.current_dir(root);
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("GIT_") {
                cmd.env_remove(key);
            }
        }
        Ok(cmd
            .env("SIPNAB_MESSAGE_TEST_BIN", own_binary()?)
            .env("GIT_EDITOR", editor.unwrap_or(":"))
            .env_remove("SIPNAB_MESSAGE_WHOLE")
            .env_remove("SIPNAB_HOOK_ANY_TREE")
            .args(extra)
            .output()?)
    };
    for setup in [
        &["init", "-q"][..],
        &["config", "user.email", "t@example.invalid"],
        &["config", "user.name", "t"],
        &["config", "commit.gpgsign", "false"],
        &["config", "core.hooksPath", ".githooks"],
    ] {
        let out = git(setup)?;
        assert!(
            out.status.success(),
            "git {setup:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    std::fs::write(root.join("staged.txt"), staged)?;
    let add = git(&["add", "staged.txt"])?;
    assert!(add.status.success(), "git add failed");
    let mut commit = vec!["commit", "-q"];
    commit.extend_from_slice(args);
    let made = git(&commit)?.status.success();
    let stored = if made {
        String::from_utf8_lossy(&git(&["log", "-1", "--format=%B"])?.stdout).into_owned()
    } else {
        String::new()
    };
    Ok((made, stored))
}

/// The line git writes above the diff `git commit -v` appends, as a string.
fn scissors_line() -> String {
    SCISSORS.to_string()
}

/// H6c. `git commit -m` stores everything after a scissors line, so the hook
/// must read it.
///
/// The hook stopped at the scissors line, as git does when the message is
/// edited. With `-m` there is no editing and git keeps the line and all that
/// follows, so a credit placed below it reached the commit.
#[test]
fn h6c_a_credit_below_a_scissors_line_in_a_dash_m_commit_is_refused() -> Result<(), TestError> {
    let below = format!(
        "{}\nCo-Authored-By: Claude <noreply@anthropic.com>",
        scissors_line()
    );
    let (made, stored) =
        commit_through_the_hook(&["-m", "Fix the parser", "-m", &below], None, "x\n")?;
    assert!(
        !made,
        "a -m commit carrying a credit below a scissors line was accepted, and git \
         stored it:\n{stored}"
    );
    Ok(())
}

/// H6d. Negative control: an edited `-v` commit whose staged diff holds a
/// credit line passes, because git cuts the diff off at the scissors line and
/// stores only the message above it.
#[test]
fn h6d_an_edited_verbose_commit_is_judged_on_what_git_stores() -> Result<(), TestError> {
    let editor = "sh -c 'printf \"Fix the parser\\n\\nBody.\\n\" | cat - \"$1\" > \"$1.new\" && mv \"$1.new\" \"$1\"' editor";
    let (made, stored) = commit_through_the_hook(
        &["-v"],
        Some(editor),
        "Co-Authored-By: Claude <noreply@anthropic.com>\n",
    )?;
    assert!(made, "an edited commit with a clean message was refused");
    assert!(
        stored.starts_with("Fix the parser")
            && !stored.to_ascii_lowercase().contains("co-authored"),
        "git stored more than the edited message:\n{stored}"
    );
    Ok(())
}

/// H6e. Edge: a credit behind a leading `#`, naming an assistant other than
/// Claude, in a `-m` commit, where git keeps `#` lines.
#[test]
fn h6e_a_hashed_credit_in_a_dash_m_commit_is_refused() -> Result<(), TestError> {
    let (made, stored) = commit_through_the_hook(
        &[
            "-m",
            "Fix the parser",
            "-m",
            "# Co-Authored-By: GitHub Copilot <copilot@example.invalid>",
        ],
        None,
        "x\n",
    )?;
    assert!(
        !made,
        "a -m commit carrying a hashed Copilot credit was accepted:\n{stored}"
    );
    Ok(())
}

/// Whether `scripts/lib-commit-mode.sh` says a `git` run with `args` edits
/// the commit message: the one case in which git strips it and cuts it at a
/// scissors line, so the commit-msg hook may stop reading there.
fn commit_edits_message(args: &str) -> Result<bool, TestError> {
    let out = Command::new("sh")
        .arg("-c")
        .arg(format!(
            ". '{}'\ncommit_edits_message {args}",
            repo().join("scripts/lib-commit-mode.sh").display()
        ))
        .output()?;
    match out.status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        other => Err(format!(
            "commit_edits_message {args}: exit {other:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        )
        .into()),
    }
}

/// H6f. The hook's reading mode follows git's own rule for when it cuts.
///
/// Edited (an editor runs, so git strips the message and cuts at a scissors
/// line): a bare `git commit`, `-v`, `--amend`, and `-e` even beside `-m`.
/// Not edited (git stores every line): `-m`, a combined `-am`, `-F`,
/// `--no-edit`, and anything that is not `git commit`, which the hook reads
/// whole because it cannot tell.
#[test]
fn h6f_the_commit_mode_follows_when_git_cuts_the_message() -> Result<(), TestError> {
    for args in [
        "git commit",
        "git commit -v",
        "git commit --amend",
        "git commit -m x -e",
        "git -C /tmp commit --verbose",
    ] {
        assert!(commit_edits_message(args)?, "edited: {args}");
    }
    for args in [
        "git commit -m x",
        "git commit -am x",
        "git commit -qm x",
        "git commit -F msg.txt",
        "git commit --message=x",
        "git commit --amend --no-edit",
        "git merge topic",
        "",
    ] {
        assert!(!commit_edits_message(args)?, "not edited: {args}");
    }
    Ok(())
}

/// A repository whose commits are signed with a fresh SSH key that
/// `allowed` lists, so the pre-push hook's signature gate passes them.
struct SignedRepo {
    _dir: tempfile::TempDir,
    root: PathBuf,
    allowed: PathBuf,
}

impl SignedRepo {
    fn new() -> Result<Self, TestError> {
        let dir = tempfile::Builder::new()
            .prefix("sipnab-pre-push-message-")
            .tempdir()?;
        let root = dir.path().join("r");
        std::fs::create_dir(&root)?;
        let key = dir.path().join("key");
        let keygen = Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-C", "t", "-f"])
            .arg(&key)
            .stdin(std::process::Stdio::null())
            .output()?;
        assert!(keygen.status.success(), "ssh-keygen failed");
        let public = std::fs::read_to_string(key.with_extension("pub"))?;
        let allowed = dir.path().join("allowed_signers");
        std::fs::write(&allowed, format!("t@example.invalid {public}"))?;
        let repo = Self {
            _dir: dir,
            root,
            allowed,
        };
        for args in [
            &["init", "-q", "-b", "main"][..],
            &["config", "user.name", "t"],
            &["config", "user.email", "t@example.invalid"],
            &["config", "gpg.format", "ssh"],
            &["config", "commit.gpgsign", "true"],
        ] {
            repo.git(args)?;
        }
        repo.git(&[
            "config",
            "user.signingkey",
            &key.with_extension("pub").to_string_lossy(),
        ])?;
        Ok(repo)
    }

    fn git(&self, args: &[&str]) -> Result<String, TestError> {
        let mut cmd = Command::new("git");
        cmd.current_dir(&self.root);
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("GIT_") {
                cmd.env_remove(key);
            }
        }
        let out = cmd.args(args).output()?;
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
    }

    /// Commit with `message` (git's `-F`, so every line is kept) and return
    /// the commit's sha.
    fn commit(&self, message: &str) -> Result<String, TestError> {
        let file = self.root.join(".git").join("msg.txt");
        std::fs::write(&file, message)?;
        self.git(&[
            "commit",
            "-q",
            "--allow-empty",
            "-F",
            &file.to_string_lossy(),
        ])?;
        self.git(&["rev-parse", "HEAD"])
    }

    /// The shipped pre-push hook, pushing `main` from `local` over `remote`,
    /// with no `cargo` on `PATH`: a push that passes every gate before the
    /// cargo ones stops at "cargo not found".
    fn pre_push(&self, local: &str, remote: &str) -> Result<(bool, String), TestError> {
        use std::io::Write as _;
        let mut cmd = Command::new("/bin/sh");
        cmd.arg(repo().join(".githooks/pre-push"))
            .arg("origin")
            .arg("https://example.invalid/r.git")
            .current_dir(&self.root);
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("GIT_") {
                cmd.env_remove(key);
            }
        }
        let mut child = cmd
            .env_remove("SKIP_FMT_HOOK")
            .env("PATH", "/usr/bin:/bin")
            .env("SIPNAB_HOOK_ANY_TREE", "1")
            .env("SIPNAB_ALLOWED_SIGNERS", &self.allowed)
            .env("SIPNAB_MESSAGE_TEST_BIN", own_binary()?)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()?;
        if let Some(mut stdin) = child.stdin.take() {
            writeln!(stdin, "refs/heads/main {local} refs/heads/main {remote}")?;
        }
        let out = child.wait_with_output()?;
        let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&out.stderr));
        Ok((out.status.success(), text))
    }
}

/// H6g. The pre-push hook refuses an outgoing commit whose message credits an
/// AI assistant, naming the commit, before any cargo gate.
///
/// Before this, pre-push read outgoing messages only for their test-count
/// claim, so a credit that got past the commit-msg hook (made with
/// `--no-verify`, or before the hook knew the form) left the machine.
#[test]
fn h6g_pre_push_refuses_an_outgoing_ai_credit() -> Result<(), TestError> {
    assert!(
        !std::path::Path::new("/usr/bin/cargo").exists()
            && !std::path::Path::new("/bin/cargo").exists(),
        "this test needs a PATH without cargo; /usr/bin or /bin has one"
    );
    let r = SignedRepo::new()?;
    let base = r.commit("base\n")?;
    r.git(&["update-ref", "refs/remotes/origin/main", &base])?;
    let bad =
        r.commit("Fix the parser\n\n# Co-Authored-By: GitHub Copilot <copilot@example.invalid>\n")?;
    let (ok, out) = r.pre_push(&bad, &base)?;
    assert!(!ok, "the push of an AI credit was allowed:\n{out}");
    assert!(
        out.contains(&bad[..7]) && out.contains("class H"),
        "the refusal must name the commit and the class:\n{out}"
    );
    assert!(
        !out.contains("cargo not found"),
        "the message gate runs before the cargo gates:\n{out}"
    );
    Ok(())
}

/// H6h. Negative control and edge: a clean outgoing commit passes the message
/// gate (and stops later, at "cargo not found"), and so does a credit that is
/// already on the remote, because that commit is not this push's.
#[test]
fn h6h_pre_push_judges_only_the_commits_it_sends() -> Result<(), TestError> {
    let r = SignedRepo::new()?;
    let old = r.commit("Old work\n\nCo-Authored-By: GitHub Copilot <copilot@example.invalid>\n")?;
    r.git(&["update-ref", "refs/remotes/origin/main", &old])?;
    let clean = r.commit("Fix the parser\n\nBody.\n")?;
    let (ok, out) = r.pre_push(&clean, &old)?;
    assert!(!ok, "with no cargo the hook still stops, later:\n{out}");
    assert!(
        out.contains("cargo not found") && !out.contains("class H"),
        "a clean push must pass the message gate, and the commit already on the \
         remote must not be judged:\n{out}"
    );
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

// -- Class I: an address in a commit message trailer -------------------
//
// A trailer is published on `main` with its commit, and the project's policy
// keeps personal data out of commit messages: an email address may appear only
// in a commit's author and committer fields. So no trailer names an address,
// not even a reserved one, with two exceptions that name no person: GitHub's
// noreply alias for an account, the form a contributor's DCO sign-off takes
// (CONTRIBUTING.md, "Signing off commits"), and `support@github.com`, the
// address Dependabot signs its commits with. A trailer is what
// `git interpret-trailers --parse` reads as one. The commits on `main` that
// already carry an address in a sign-off stay, by the owner's decision of
// 2026-11-25: the hook, pre-push and CI read only new messages.
//
// In the body of a message an address is held to class G: one at a domain
// somebody owns is refused, a reserved one (`example.com`, `.invalid`, `.test`)
// is accepted. Unlike the tracked-file scan, a message may not carry the
// maintainer's address either.

/// The address classes (G and I) of every finding in `message`, by line.
fn address_classes(
    message: &str,
    scissors: Scissors,
) -> Result<Vec<(usize, &'static str)>, TestError> {
    Ok(all_message_findings(message, scissors)?
        .into_iter()
        .filter(|(_, c, _)| *c == "G" || *c == "I")
        .map(|(n, c, _)| (n, c))
        .collect())
}

/// Asserts `message` holds no address finding, in either scissors mode.
fn assert_no_address(message: &str) -> Result<(), TestError> {
    for scissors in [Scissors::Cut, Scissors::Read] {
        let found = address_classes(message, scissors)?;
        assert!(
            found.is_empty(),
            "{message:?} ({scissors:?}) must carry no address finding: {found:?}"
        );
    }
    Ok(())
}

/// Asserts `message`, read whole, holds exactly the `want` address findings.
fn assert_addresses(message: &str, want: &[(usize, &str)]) -> Result<(), TestError> {
    for scissors in [Scissors::Cut, Scissors::Read] {
        let found = address_classes(message, scissors)?;
        assert_eq!(
            found, want,
            "{message:?} ({scissors:?}): the address findings differ"
        );
    }
    Ok(())
}

/// A DCO sign-off with a numeric noreply alias, the form CONTRIBUTING.md asks for.
const NOREPLY_SIGN_OFF: &str =
    "Signed-off-by: A Contributor <12345+contrib-login@users.noreply.github.com>";

/// I-S1. A message with no trailer block and no address passes.
#[test]
fn i_s01_a_message_without_trailers_passes() -> Result<(), TestError> {
    assert_no_address("Fix the parser\n\nThe header folding was read twice.\n")
}

/// I-S2. A DCO sign-off naming a numeric GitHub noreply alias passes.
#[test]
fn i_s02_a_noreply_sign_off_passes() -> Result<(), TestError> {
    assert_no_address(&format!("Fix the parser\n\nBody.\n\n{NOREPLY_SIGN_OFF}\n"))
}

/// I-S3. The older noreply form, without the numeric ID, passes.
#[test]
fn i_s03_an_older_noreply_alias_passes() -> Result<(), TestError> {
    assert_no_address(
        "Fix the parser\n\nBody.\n\nSigned-off-by: A Contributor <contrib@users.noreply.github.com>\n",
    )
}

/// I-S4. Dependabot's own sign-off passes: it names GitHub's service, not a person.
#[test]
fn i_s04_dependabots_sign_off_passes() -> Result<(), TestError> {
    assert_no_address(
        "build(deps): bump serde from 1.0.1 to 1.0.2\n\nBumps serde.\n\n\
         Signed-off-by: dependabot[bot] <support@github.com>\n",
    )
}

/// I-S5. A bot co-author named by its noreply alias, brackets and all, passes.
#[test]
fn i_s05_a_bot_noreply_co_author_passes() -> Result<(), TestError> {
    assert_no_address(
        "Fix the parser\n\nBody.\n\nCo-authored-by: dependabot[bot] \
         <49699333+dependabot[bot]@users.noreply.github.com>\n",
    )
}

/// I-S6. An `example.com` address in the body passes.
#[test]
fn i_s06_a_reserved_address_in_the_body_passes() -> Result<(), TestError> {
    assert_no_address("Fix the parser\n\nReproduce with alice@example.com as the caller.\n")
}

/// I-S7. An `.invalid` address in the body passes.
#[test]
fn i_s07_an_invalid_tld_address_in_the_body_passes() -> Result<(), TestError> {
    assert_no_address("Fix the parser\n\nThe From header was <sip:bob@host.example.invalid>.\n")
}

/// I-S8. A trailer that names a person without an address passes.
#[test]
fn i_s08_a_trailer_without_an_address_passes() -> Result<(), TestError> {
    assert_no_address(
        "Fix the parser\n\nBody.\n\nReviewed-by: A Reviewer\nReported-by: Another Person\n",
    )
}

/// I-S9. Reference trailers -- an issue number, a URL -- pass.
#[test]
fn i_s09_reference_trailers_pass() -> Result<(), TestError> {
    assert_no_address(
        "Fix the parser\n\nBody.\n\nFixes: #123\nRefs: https://github.com/NormB/sipnab/issues/1\n",
    )
}

/// I-S10. A merge message, with git's conflict comment lines, passes.
#[test]
fn i_s10_a_merge_message_passes() -> Result<(), TestError> {
    assert_no_address(
        "Merge origin/main into fix/header-folding\n\n# Conflicts:\n#\tsrc/parser.rs\n",
    )
}

/// I-S11. A fixup message passes.
#[test]
fn i_s11_a_fixup_message_passes() -> Result<(), TestError> {
    assert_no_address("fixup! Fix the parser\n")
}

/// I-S12. A SIP Call-ID in the body is not a mailbox and passes.
#[test]
fn i_s12_a_call_id_in_the_body_passes() -> Result<(), TestError> {
    assert_no_address("Fix the parser\n\nThe Call-ID call-1234@sipnab.bench was split.\n")
}

/// I-S13. A `Key: value` line inside a body paragraph is not a trailer.
///
/// git reads a paragraph as a trailer block when every line is a trailer, or
/// a quarter of them are and one is a trailer git writes itself
/// (`Signed-off-by:`). One `Cc:` line among prose is neither, so a reserved
/// address there is body text.
#[test]
fn i_s13_a_key_value_line_inside_prose_is_body_text() -> Result<(), TestError> {
    assert_no_address(
        "Fix the parser\n\nThe report came in as\nCc: someone@example.com\nwith no other detail.\n",
    )
}

/// I-S14. The project's published contact address in the body passes.
#[test]
fn i_s14_the_security_contact_in_the_body_passes() -> Result<(), TestError> {
    assert_no_address("Fix the parser\n\nReport the next one to security@sipnab.com.\n")
}

/// I-F1. A sign-off naming an address at a real domain is refused.
#[test]
fn i_f01_a_real_address_in_a_sign_off_is_refused() -> Result<(), TestError> {
    assert_addresses(
        "Fix the parser\n\nBody.\n\nSigned-off-by: A Person <a.person@real-company.com>\n",
        &[(5, "G"), (5, "I")],
    )
}

/// I-F2. A sign-off naming a reserved address is refused: trailers carry none.
#[test]
fn i_f02_a_reserved_address_in_a_sign_off_is_refused() -> Result<(), TestError> {
    assert_addresses(
        "Fix the parser\n\nBody.\n\nSigned-off-by: A Person <person@example.com>\n",
        &[(5, "I")],
    )
}

/// I-F3. Two trailers with addresses are both refused, each on its own line.
#[test]
fn i_f03_two_trailers_with_addresses_are_both_refused() -> Result<(), TestError> {
    assert_addresses(
        "Fix the parser\n\nBody.\n\nReported-by: One <one@example.org>\n\
         Reviewed-by: Two\nSigned-off-by: Three <three@example.net>\n",
        &[(5, "I"), (7, "I")],
    )
}

/// I-F4. A human co-author's address is refused.
#[test]
fn i_f04_a_co_author_address_is_refused() -> Result<(), TestError> {
    assert_addresses(
        "Fix the parser\n\nBody.\n\nCo-Authored-By: A Person <a.person@example.com>\n",
        &[(5, "I")],
    )
}

/// I-F5. An AI co-author trailer is refused as class H and for its address.
#[test]
fn i_f05_an_ai_co_author_is_refused_twice() -> Result<(), TestError> {
    let message = "Fix the parser\n\nBody.\n\nCo-Authored-By: Claude <noreply@anthropic.com>\n";
    let found = all_message_findings(message, Scissors::Read)?;
    for class in ["H", "I"] {
        assert!(
            found.iter().any(|(n, c, _)| *n == 5 && *c == class),
            "an AI co-author must be refused as class {class} on line 5: {found:?}"
        );
    }
    Ok(())
}

/// I-F6. An address on a folded trailer's continuation line is refused at the key line.
#[test]
fn i_f06_an_address_on_a_folded_line_is_refused() -> Result<(), TestError> {
    let message = "Fix the parser\n\nBody.\n\nReported-by: A Person\n <person@example.org>\n";
    assert_addresses(message, &[(5, "I")])?;
    let found = all_message_findings(message, Scissors::Read)?;
    assert!(
        found
            .iter()
            .any(|(_, c, l)| *c == "I" && l == "Reported-by: A Person <person@example.org>"),
        "the finding must show the trailer as git unfolds it: {found:?}"
    );
    Ok(())
}

/// I-F7. The project's published addresses may not sign off a commit.
///
/// The maintainer's address is published in `Cargo.toml`, and the security
/// contact on the site, so the tracked-file scan spares them. In a trailer they
/// are personal data on `main` like any other.
#[test]
fn i_f07_published_identities_are_refused_in_a_trailer() -> Result<(), TestError> {
    for addr in rule::PUBLISHED_IDENTITIES {
        if *addr == "noreply@github.com" {
            continue;
        }
        let message = format!("Fix the parser\n\nBody.\n\nSigned-off-by: Someone <{addr}>\n");
        let found = address_classes(&message, Scissors::Read)?;
        assert!(
            found.contains(&(5, "I")),
            "a sign-off naming {addr} must be refused as class I: {found:?}"
        );
    }
    Ok(())
}

/// I-F8. The maintainer's address is refused in the body of a message.
#[test]
fn i_f08_the_maintainers_address_is_refused_in_the_body() -> Result<(), TestError> {
    let maintainer = rule::PUBLISHED_IDENTITIES
        .iter()
        .find(|a| a.ends_with("@gmail.com"))
        .ok_or("PUBLISHED_IDENTITIES names no maintainer address")?;
    assert_addresses(
        &format!("Fix the parser\n\nAsk {maintainer} for the capture.\n"),
        &[(3, "G")],
    )
}

/// I-F9. An address at a real domain in the body is refused.
#[test]
fn i_f09_a_real_address_in_the_body_is_refused() -> Result<(), TestError> {
    assert_addresses(
        "Fix the parser\n\nThe report came from someone@real-company.com.\n",
        &[(3, "G")],
    )
}

/// I-F10. An address at a reserved TLD is refused in a trailer.
#[test]
fn i_f10_a_test_tld_address_in_a_trailer_is_refused() -> Result<(), TestError> {
    assert_addresses(
        "Fix the parser\n\nBody.\n\nReported-by: A Person <person@lab.test>\n",
        &[(5, "I")],
    )
}

/// I-F11. A trailer block right after the subject is read.
#[test]
fn i_f11_a_trailer_block_after_the_subject_is_read() -> Result<(), TestError> {
    assert_addresses("Fix the parser\n\nCc: someone@example.net\n", &[(3, "I")])
}

/// I-F12. An address that only resembles a noreply alias is refused.
#[test]
fn i_f12_a_noreply_lookalike_is_refused() -> Result<(), TestError> {
    for addr in [
        "12345+contrib@noreply.github.com",
        "12345+contrib@users.noreply.github.com.example.org",
        "someone@github.com",
    ] {
        let message = format!("Fix the parser\n\nBody.\n\nSigned-off-by: Someone <{addr}>\n");
        let found = address_classes(&message, Scissors::Read)?;
        assert!(
            found.contains(&(5, "I")),
            "{addr} is not GitHub's alias and must be refused: {found:?}"
        );
    }
    Ok(())
}

/// I-F13. A bare address, without angle brackets, is refused.
#[test]
fn i_f13_a_bare_address_in_a_trailer_is_refused() -> Result<(), TestError> {
    assert_addresses(
        "Fix the parser\n\nBody.\n\nCc: someone@example.com\n",
        &[(5, "I")],
    )
}

/// I-F14. A `mailto:` link in a trailer is refused.
#[test]
fn i_f14_a_mailto_link_in_a_trailer_is_refused() -> Result<(), TestError> {
    assert_addresses(
        "Fix the parser\n\nBody.\n\nLink: mailto:someone@example.com\n",
        &[(5, "I")],
    )
}

/// I-F15. A sign-off makes a mixed paragraph a trailer block, as git reads it.
#[test]
fn i_f15_a_sign_off_makes_a_mixed_paragraph_a_trailer_block() -> Result<(), TestError> {
    assert_addresses(
        "Fix the parser\n\nas reported\nCc: someone@example.com\nSigned-off-by: A Person\n",
        &[(4, "I")],
    )
}

/// I-F16. The message script refuses a trailer address and names class I.
#[test]
fn i_f16_the_message_script_refuses_a_trailer_address() -> Result<(), TestError> {
    let (code, out) = run_message_script(
        "Fix the parser\n\nBody.\n\nSigned-off-by: A Person <person@example.com>\n",
        "trailer-address",
    )?;
    assert_eq!(code, 1, "a trailer address must be refused: {out}");
    assert!(
        out.contains("line 5: class I:"),
        "the refusal must name the line and class I: {out}"
    );
    assert!(
        out.contains("noreply"),
        "the refusal must say which form a sign-off takes: {out}"
    );
    Ok(())
}

/// I-S15. The message script passes a noreply sign-off.
#[test]
fn i_s15_the_message_script_passes_a_noreply_sign_off() -> Result<(), TestError> {
    let (code, out) = run_message_script(
        &format!("Fix the parser\n\nBody.\n\n{NOREPLY_SIGN_OFF}\n"),
        "noreply-sign-off",
    )?;
    assert_eq!(code, 0, "a noreply sign-off must pass: {out}");
    Ok(())
}

/// I-E1. In an editor, nothing below the scissors line is read.
#[test]
fn i_e01_the_editor_mode_stops_at_the_scissors_line() -> Result<(), TestError> {
    let message = format!(
        "Fix the parser\n\nBody.\n{SCISSORS}\n\nSigned-off-by: A Person <person@example.com>\n"
    );
    let found = address_classes(&message, Scissors::Cut)?;
    assert!(
        found.is_empty(),
        "below the scissors line is not the message: {found:?}"
    );
    Ok(())
}

/// I-E2. A message stored whole is read past the scissors line.
#[test]
fn i_e02_the_whole_message_mode_reads_past_the_scissors_line() -> Result<(), TestError> {
    let message = format!(
        "Fix the parser\n\nBody.\n{SCISSORS}\n\nSigned-off-by: A Person <person@example.com>\n"
    );
    let found = address_classes(&message, Scissors::Read)?;
    assert_eq!(
        found,
        vec![(6, "I")],
        "git stores this trailer, so it is read"
    );
    Ok(())
}

/// I-E3. In an editor, a `#` comment line in the trailer block is not a trailer.
#[test]
fn i_e03_a_comment_line_is_not_a_trailer_in_the_editor() -> Result<(), TestError> {
    let message = "Fix the parser\n\nBody.\n\nReviewed-by: A Reviewer\n# Signed-off-by: A Person <person@example.com>\n";
    let found = address_classes(message, Scissors::Cut)?;
    assert!(found.is_empty(), "git removes the comment line: {found:?}");
    Ok(())
}

/// I-E4. CRLF line ends do not hide a trailer.
#[test]
fn i_e04_crlf_line_ends_do_not_hide_a_trailer() -> Result<(), TestError> {
    assert_addresses(
        "Fix the parser\r\n\r\nBody.\r\n\r\nSigned-off-by: A Person <person@example.com>\r\n",
        &[(5, "I")],
    )
}

/// I-E5. Of two trailers with one key, the one with the address is named.
#[test]
fn i_e05_the_finding_names_the_right_one_of_two_like_trailers() -> Result<(), TestError> {
    assert_addresses(
        &format!(
            "Fix the parser\n\nBody.\n\n{NOREPLY_SIGN_OFF}\nSigned-off-by: A Person <person@example.com>\n"
        ),
        &[(6, "I")],
    )
}

/// I-E6. Two trailers with one key and an address each are named on their lines.
#[test]
fn i_e06_two_like_trailers_are_named_on_their_lines() -> Result<(), TestError> {
    assert_addresses(
        "Fix the parser\n\nBody.\n\nSigned-off-by: One <one@example.com>\n\
         Signed-off-by: Two <two@example.com>\n",
        &[(5, "I"), (6, "I")],
    )
}

/// I-E7. A one-line message that looks like a trailer is a subject, not a trailer.
#[test]
fn i_e07_a_subject_shaped_like_a_trailer_is_not_a_trailer() -> Result<(), TestError> {
    assert_no_address("Signed-off-by: A Person <person@example.com>\n")
}

/// I-E8. An empty message has no finding and no error.
#[test]
fn i_e08_an_empty_message_has_no_finding() -> Result<(), TestError> {
    assert_no_address("")
}

/// I-E9. A `---` line does not end the message: Dependabot's bodies hold one.
#[test]
fn i_e09_a_divider_line_does_not_end_the_message() -> Result<(), TestError> {
    assert_addresses(
        "build(deps): bump serde\n\nBumps serde.\n\n---\nupdated-dependencies:\n\
         - dependency-name: serde\n...\n\nSigned-off-by: A Person <person@example.com>\n",
        &[(10, "I")],
    )
}

/// I-E10. Letter case changes nothing: the key and the address are read in any case.
#[test]
fn i_e10_letter_case_does_not_hide_a_trailer_address() -> Result<(), TestError> {
    assert_addresses(
        "Fix the parser\n\nBody.\n\nSIGNED-OFF-BY: A Person <PERSON@EXAMPLE.COM>\n",
        &[(5, "I")],
    )
}

/// I-E11. A noreply alias in mixed case is still GitHub's alias.
#[test]
fn i_e11_a_mixed_case_noreply_alias_passes() -> Result<(), TestError> {
    assert_no_address(
        "Fix the parser\n\nBody.\n\nSigned-off-by: A Contributor <12345+Contrib@Users.NoReply.GitHub.com>\n",
    )
}

/// I-E12. A name outside ASCII does not move the finding off its line.
#[test]
fn i_e12_a_name_outside_ascii_keeps_its_line() -> Result<(), TestError> {
    assert_addresses(
        "Fix the parser\n\nCorrigé.\n\nReviewed-by: Jürgen Müller\n\
         Signed-off-by: Zoë Ångström <zoe@example.com>\n",
        &[(6, "I")],
    )
}

/// I-E13. A version pin is not an address.
#[test]
fn i_e13_a_version_pin_is_not_an_address() -> Result<(), TestError> {
    assert_no_address(
        "Fix the parser\n\nBody.\n\nBumps: serde@1.0.200\nBumps: npm:left-pad@1.3.0\n",
    )
}

/// I-E14. Separator spacing does not hide a trailer.
#[test]
fn i_e14_space_before_the_separator_does_not_hide_a_trailer() -> Result<(), TestError> {
    assert_addresses(
        "Fix the parser\n\nBody.\n\nSigned-off-by : A Person <person@example.com>\n",
        &[(5, "I")],
    )
}

/// I-E15. A trailer key that also starts a body line is placed on the trailer.
#[test]
fn i_e15_a_key_repeated_in_the_body_is_placed_on_the_trailer() -> Result<(), TestError> {
    assert_addresses(
        "Fix the parser\n\nCc: is how the report was copied\nto the list.\n\n\
         Cc: someone@example.com\n",
        &[(6, "I")],
    )
}

/// I-E16. A check that could not run git refuses rather than passes.
#[test]
fn i_e16_a_missing_git_is_an_error_not_a_pass() {
    let missing = std::ffi::OsStr::new("/nonexistent/sipnab-no-such-git");
    let got = message_trailers_with(missing, "Fix\n\nCc: a@example.com\n", Scissors::Read);
    assert!(
        got.is_err(),
        "a git that did not start must be an error: {got:?}"
    );
}

/// I-E19. A git that reads the message and fails is an error, not a pass.
#[test]
fn i_e19_a_failing_git_is_an_error_not_a_pass() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let git = dir.path().join("failing-git");
    executable::write_executable(
        &git,
        "#!/bin/sh\ncat > /dev/null\necho refused >&2\nexit 3\n",
    )?;
    let got = message_trailers_with(git.as_os_str(), "Fix\n\nCc: a@example.com\n", Scissors::Cut);
    let err = got.err().ok_or("a git that exited 3 must be an error")?;
    assert!(
        err.to_string().contains("refused"),
        "the error must carry git's own message: {err}"
    );
    Ok(())
}

/// I-E20. A trailer git reports that no line holds is an error, not a pass.
#[test]
fn i_e20_a_trailer_with_no_line_is_an_error() {
    let got = trailer_lines(
        "Fix the parser\n\nBody.\n",
        Scissors::Read,
        &["Signed-off-by: A Person <person@example.com>".to_string()],
    );
    assert!(
        got.is_err(),
        "a trailer that no line starts must not be dropped: {got:?}"
    );
}

/// I-E21. In an editor, a like line below the scissors line does not take the finding.
#[test]
fn i_e21_a_like_line_below_the_scissors_does_not_take_the_finding() -> Result<(), TestError> {
    let message = format!(
        "Fix the parser\n\nSigned-off-by: A Person <person@example.com>\n{SCISSORS}\n\
         Signed-off-by: Below\n"
    );
    assert_eq!(
        address_classes(&message, Scissors::Cut)?,
        vec![(3, "I")],
        "the trailer git reads is on line 3, above the scissors line"
    );
    Ok(())
}

/// I-E22. Both address patterns compile.
///
/// The rules fail closed on a pattern that does not compile, refusing every
/// line, so a broken pattern must fail here by name rather than as a refusal
/// of every message.
#[test]
fn i_e22_the_address_patterns_compile() -> Result<(), TestError> {
    regex::Regex::new(rule::MESSAGE_ADDRESS)
        .map_err(|e| format!("{} does not compile: {e}", rule::MESSAGE_ADDRESS))?;
    assert!(
        rule::noreply().is_some(),
        "the noreply rule must be read from {} and compile",
        rule::DCO_SCRIPT
    );
    Ok(())
}

/// I-E27. The noreply rule is the DCO check's own, read from its script.
///
/// The owner's decision of 2026-11-18 sets every sign-off address to a GitHub
/// noreply address, and the required DCO check enforces it. A trailer may name
/// exactly the addresses that check accepts, so the rule has one source:
/// `_NOREPLY` in scripts/check-dco.py. No second copy can drift from it.
#[test]
fn i_e27_the_noreply_rule_is_read_from_the_dco_script() -> Result<(), TestError> {
    let source = std::fs::read_to_string(repo().join(rule::DCO_SCRIPT))?;
    let pattern = rule::dco_noreply_pattern(&source)
        .ok_or_else(|| format!("no `_NOREPLY` pattern found in {}", rule::DCO_SCRIPT))?;
    assert!(
        pattern.starts_with("(?i)^(?:") && pattern.ends_with(")$"),
        "the pattern must be anchored and without case: {pattern}"
    );
    assert!(
        pattern.contains(r"@users\.noreply\.github\.com"),
        "the pattern must be GitHub's noreply domain: {pattern}"
    );
    Ok(())
}

/// I-E28. A changed `_NOREPLY` that the reader does not recognize gives no rule.
///
/// Then no address is an alias and every noreply sign-off is refused, which
/// fails I-S2 and I-E22 by name instead of passing an address.
#[test]
fn i_e28_an_unrecognized_noreply_definition_gives_no_rule() {
    let good = "_NOREPLY = re.compile(\n    r\"x@users\\.noreply\\.github\\.com\",\n    re.IGNORECASE,\n)\n";
    assert_eq!(
        rule::dco_noreply_pattern(good).as_deref(),
        Some(r"(?i)^(?:x@users\.noreply\.github\.com)$"),
        "the reader must take the raw string as written"
    );
    for (source, why) in [
        ("", "no definition"),
        (
            "_NOREPLY = re.compile(\n    r\"x@users\\.noreply\\.github\\.com\",\n)\n",
            "no IGNORECASE: the rule would differ in letter case",
        ),
        (
            "_NOREPLY = re.compile(\n    \"x@users\\\\.noreply\\\\.github\\\\.com\",\n    re.IGNORECASE,\n)\n",
            "not a raw string: the escapes would differ",
        ),
        (
            "_NOREPLY = re.compile(r\"x@users\\.noreply\\.github\\.com\", re.IGNORECASE)\n",
            "a one-line form the reader does not know",
        ),
    ] {
        assert_eq!(
            rule::dco_noreply_pattern(source),
            None,
            "{why} must give no rule"
        );
    }
}

/// I-E29. The noreply rule agrees with the DCO check's documented forms.
#[test]
fn i_e29_the_noreply_rule_takes_the_dco_forms_and_no_other() {
    for (addr, alias) in [
        ("12345+contrib-login@users.noreply.github.com", true),
        ("contrib@users.noreply.github.com", true),
        ("49699333+dependabot[bot]@users.noreply.github.com", true),
        ("12345+Contrib@Users.NoReply.GitHub.com", true),
        ("-contrib@users.noreply.github.com", false),
        ("12345+contrib@noreply.github.com", false),
        ("contrib@users.noreply.github.com.example.org", false),
        ("x12345+contrib@users.noreply.github.com", false),
    ] {
        assert_eq!(
            rule::noreply().is_some_and(|re| re.is_match(addr)),
            alias,
            "{addr}: alias {alias} expected"
        );
    }
}

/// I-E23. A pattern that does not compile refuses, never passes.
#[test]
fn i_e23_a_pattern_that_does_not_compile_refuses() {
    assert!(
        !rule::compiles("(unclosed"),
        "a broken pattern must compile to nothing"
    );
    assert!(
        rule::names_a_mailbox(None),
        "a body line the pattern could not read must be refused"
    );
    assert!(
        rule::names_an_address(None),
        "a trailer the pattern could not read must be refused"
    );
    assert!(
        !rule::names_a_mailbox(Some(Vec::new())),
        "a line with no address is not refused"
    );
    assert!(
        !rule::names_an_address(Some(Vec::new())),
        "a trailer with no address is not refused"
    );
}

/// I-E17. The trailer parse reads no git configuration.
///
/// `trailer.*` settings change which lines git reads as trailers, and a
/// commit-msg hook runs with the repository's `GIT_DIR` set. The verdict must
/// be the same on every machine, so the command reads no system, global or
/// repository configuration and runs outside any repository.
#[test]
fn i_e17_the_trailer_parse_reads_no_git_configuration() {
    let cmd = trailer_command(std::ffi::OsStr::new("git"), Scissors::Read);
    let envs: Vec<(String, Option<String>)> = cmd
        .get_envs()
        .map(|(k, v)| {
            (
                k.to_string_lossy().into_owned(),
                v.map(|v| v.to_string_lossy().into_owned()),
            )
        })
        .collect();
    for (key, want) in [
        ("GIT_CONFIG_NOSYSTEM", Some("1")),
        ("GIT_CONFIG_GLOBAL", Some("/dev/null")),
        ("GIT_DIR", None),
        ("GIT_WORK_TREE", None),
        ("GIT_CONFIG_PARAMETERS", None),
        ("GIT_CONFIG_COUNT", None),
    ] {
        assert!(
            envs.iter().any(|(k, v)| k == key && v.as_deref() == want),
            "the trailer parse must set {key} to {want:?}: {envs:?}"
        );
    }
    assert_eq!(
        cmd.get_current_dir(),
        Some(Path::new("/")),
        "the trailer parse must run outside any repository"
    );
}

/// I-E18. Each mode reads `#` lines the way git stores the message.
///
/// In an editor git removes a `#` line, so the paragraph below is the `Cc:`
/// line alone: a trailer block. Stored whole, the `#` line stays, and a
/// paragraph of one prose line and one `Cc:` line, with no trailer git writes
/// itself, is body text, where a reserved address is accepted.
#[test]
fn i_e18_each_mode_reads_hash_lines_as_git_stores_them() -> Result<(), TestError> {
    let message = "Fix the parser\n\nBody.\n\n# a note\nCc: someone@example.com\n";
    assert_eq!(
        address_classes(message, Scissors::Cut)?,
        vec![(6, "I")],
        "in an editor the comment goes and the Cc line is a trailer"
    );
    assert_eq!(
        address_classes(message, Scissors::Read)?,
        vec![],
        "stored whole, the paragraph is body text"
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
        ("I trailer addresses", "git interpret-trailers --parse"),
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
    assert!(
        rule::trailer_address("Signed-off-by: Someone <someone@example.com>"),
        "the guide promises an address in a trailer is caught, a reserved one included"
    );
    assert!(
        !rule::trailer_address("Signed-off-by: A <12345+login@users.noreply.github.com>"),
        "the guide promises a noreply sign-off passes"
    );
    assert!(
        rule::message_address("Ask someone@real-domain.com for it"),
        "the guide promises an address at a real domain in a message is caught"
    );
    Ok(())
}
