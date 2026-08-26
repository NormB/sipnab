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
//! # Why each class gets controls and not just a scan
//!
//! A scan that finds nothing is indistinguishable from a scan that looks at
//! nothing. Every class therefore carries POSITIVE controls -- the rule is
//! shown to flag the exact string that leaked, and a variant of it -- and
//! NEGATIVE controls, which are the half that decides whether anyone keeps the
//! gate: a rule that flags `Jetson AGX Thor` while trying to catch `thor-02`
//! gets suppressed within a week, and then catches nothing at all.
//!
//! # The one exception, and it is functional
//!
//! `runs-on: [self-hosted, thor-02]` is a GitHub runner LABEL, not prose: it is
//! how a workflow reaches the one machine that can run it, and renaming it here
//! would not rename it on the box. It is allowlisted, confined to `.github/`,
//! and class B fails if the allowlist stops matching anything -- an exception
//! nobody uses is one that will be spent on something else.

use std::collections::BTreeSet;
use std::net::Ipv6Addr;
use std::path::{Path, PathBuf};
use std::process::Command;

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
fn tracked_text() -> Vec<(String, String)> {
    let out = Command::new("git")
        .args(["ls-files"])
        .current_dir(repo())
        .output()
        .expect("git ls-files -- the scan is over what is tracked, not what is present");
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
    files
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

/// The one permitted occurrence: a workflow reaching its self-hosted runner.
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
            if hit(line) && !is_runner_label(line) {
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
fn contributing() -> String {
    std::fs::read_to_string(repo().join("CONTRIBUTING.md"))
        .expect("CONTRIBUTING.md is where a contributor is told the rules")
        .to_ascii_lowercase()
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

    /// E. A path under a real account's home directory.
    ///
    /// The rule is the ACCOUNT, not the shape: `/home/user/capture.pcap` in a
    /// synopsis is a placeholder every reader substitutes.
    pub fn account_path(line: &str) -> bool {
        PRIVATE_ACCOUNTS
            .iter()
            .any(|a| line.contains(&format!("/home/{a}")))
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
}

// -- Class A: the aarch64 development host ---------------------------

/// A1. No published page names the aarch64 development host.
#[test]
fn a1_no_published_page_names_the_development_host() {
    let files = tracked_text();
    let found = scan(&files, is_published, rule::lab_host);
    assert!(
        found.is_empty(),
        "a published page names the maintainer's aarch64 host. This repository \
         is public, so the name is disclosed the moment it is pushed.\n{}\n\n{}",
        capped(&found, 25),
        guidance::HOST
    );
}

/// A2. The rule flags the exact name that leaked.
#[test]
fn a2_the_host_rule_flags_the_name_that_leaked() {
    assert!(
        rule::lab_host("## 2026-08-15 - thor-02 (aarch64, 14 cores), rustc 1.97.1"),
        "the benchmark heading that leaked must be caught if it returns"
    );
}

/// A3. It flags the undashed spelling, which reads as a different word.
#[test]
fn a3_the_host_rule_flags_the_undashed_spelling() {
    assert!(
        rule::lab_host("measured on thor02 overnight"),
        "`thor02` names the same machine as `thor-02`"
    );
}

/// A4. It flags the name inside sample JSON, which is how it actually leaked.
///
/// `docs/vcon.md` published `"node": "thor-02"` inside example containers --
/// the hostname was in the documented OUTPUT FORMAT, not in a sentence about
/// the lab, which is why reading the prose would never have found it.
#[test]
fn a4_the_host_rule_flags_it_inside_sample_output() {
    assert!(
        rule::lab_host(r#"    "node": "thor-02","#),
        "the leak was inside a JSON sample, not in prose"
    );
    assert!(
        rule::lab_host(r#""sip_user_agent": "sipnab/0.5.124 (observer; node thor-02)""#),
        "and inside a User-Agent string in the same document"
    );
}

/// A5. It spares the hardware, which a benchmark cannot do without.
#[test]
fn a5_the_host_rule_spares_the_hardware_it_runs_on() {
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
}

/// A6. The bare lowercase form is the box, and is caught.
#[test]
fn a6_a_lowercase_bare_name_is_the_box_not_the_board() {
    assert!(
        rule::bare_host("shares thor's kernel - so it has no BTF either"),
        "`thor's kernel` names a machine"
    );
    assert!(
        rule::bare_host(r#"the initial "+8.3% on thor" compared a build"#),
        "`on thor` names a machine"
    );
}

/// A7. No published page carries the bare lowercase form either.
#[test]
fn a7_no_published_page_carries_the_bare_lowercase_form() {
    let files = tracked_text();
    let found = scan(&files, is_published, rule::bare_host);
    assert!(
        found.is_empty(),
        "a published page names the host rather than the hardware:\n{}\n\n{}",
        capped(&found, 25),
        guidance::HOST
    );
}

/// A8. The scan reaches the generated mirrors, where the leak also lands.
///
/// `docs/vcon.md` is mirrored into `website/content/docs/vcon.md` and into
/// `website/static/llms-full.txt`. Fixing the source and forgetting the mirror
/// leaves the leak on the site, which is the copy the public actually reads.
#[test]
fn a8_the_scan_reaches_the_generated_site_mirrors() {
    let files = tracked_text();
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
}

/// A9. The scan reaches the pages this class actually leaked on.
#[test]
fn a9_the_scan_reaches_the_pages_this_class_leaked_on() {
    let files = tracked_text();
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
}

/// A10. The guide tells a writer what to put in a benchmark heading.
#[test]
fn a10_the_guide_names_the_hardware_alternative() {
    let guide = contributing();
    assert!(
        guide.contains("hostname") && guide.contains("jetson agx thor"),
        "CONTRIBUTING.md must show the hardware form, or a writer meets this \
         rule for the first time as a rejected commit"
    );
    assert!(
        guidance::HOST.contains("aarch64 self-hosted runner"),
        "the failure message must carry the replacement, not just the refusal"
    );
}

// -- Class B: the lab's VMs, containers and host ----------------------

/// B1. No published page names a lab VM or container.
#[test]
fn b1_no_published_page_names_a_lab_machine() {
    let files = tracked_text();
    let found = scan(&files, is_published, rule::lab_machine);
    assert!(
        found.is_empty(),
        "a published page names a machine in the lab:\n{}\n\n{}",
        capped(&found, 25),
        guidance::MACHINE
    );
}

/// B2. The rule flags the name that leaked, in the heading form it leaked in.
#[test]
fn b2_the_machine_rule_flags_the_baseline_heading() {
    assert!(
        rule::lab_machine("## 2026-07-06 - opensips-1, rustc 1.96, WS5f result"),
        "five benchmark headings named this VM"
    );
}

/// B3. It flags the other machines in the same family.
#[test]
fn b3_the_machine_rule_flags_the_rest_of_the_family() {
    for host in ["nas2", "miner1", "norm2"] {
        assert!(
            rule::lab_machine(&format!("copied from {host} overnight")),
            "{host} is a machine in the same lab"
        );
    }
}

/// B4. It does not fire inside a longer identifier.
///
/// The boundary is what keeps this rule usable: `opensips-1` must not match
/// inside `opensips-1234`, and `norm2` must not match inside `normalize2`.
#[test]
fn b4_the_machine_rule_does_not_fire_inside_a_longer_word() {
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
}

/// B5. It spares the software the project integrates with.
///
/// `opensips` and `OpenSIPS` are a project sipnab decodes; only the numbered
/// instance is a machine.
#[test]
fn b5_the_machine_rule_spares_the_software_it_names() {
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
}

/// B6. The runner-label exception still matches something.
///
/// An allowlist that matches nothing is either an exception somebody spent on
/// something else, or a dead rule that will be read as permission the next time
/// the string appears.
#[test]
fn b6_the_runner_label_exception_is_still_in_use() {
    let files = tracked_text();
    let mut labels = Vec::new();
    for (rel, text) in &files {
        if !rel.starts_with(".github/") {
            continue;
        }
        for (i, line) in text.lines().enumerate() {
            if is_runner_label(line) && (rule::lab_host(line) || rule::lab_machine(line)) {
                labels.push(format!("{rel}:{}", i + 1));
            }
        }
    }
    assert!(
        !labels.is_empty(),
        "no workflow reaches the self-hosted runner by label any more, so the \
         hostname exception is permission nobody is using. Delete it, or find \
         out what happened to the runner."
    );
}

/// B7. The exception is confined to workflows.
#[test]
fn b7_the_runner_label_exception_is_confined_to_workflows() {
    let files = tracked_text();
    let outside = scan(
        &files,
        |rel| !rel.starts_with(".github/"),
        |line| is_runner_label(line) && (rule::lab_host(line) || rule::lab_machine(line)),
    );
    assert!(
        outside.is_empty(),
        "the runner-label exception is being used outside .github/, which is \
         not what it is for:\n{}",
        capped(&outside, 25)
    );
}

/// B8. The exception is recognized by shape, not by the hostname it carries.
///
/// So relabelling the runner does not silently widen the exception to whatever
/// the new label is called somewhere else.
#[test]
fn b8_the_exception_is_recognized_by_shape() {
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
}

/// B9. `harness/` and `demos/` keep the name, because there it is a service.
///
/// A compose service called `opensips-1` is something a reader brings up on
/// their own machine. Banning it there would be renaming their container to
/// protect a hostname that is not theirs.
#[test]
fn b9_a_compose_service_name_is_not_a_machine() {
    let files = tracked_text();
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
}

/// B10. The guide names the role form to use instead.
#[test]
fn b10_the_guide_names_the_role_alternative() {
    assert!(
        contributing().contains("opensips-1"),
        "CONTRIBUTING.md must show the machine names it is asking writers to \
         avoid, or the rule is abstract and gets guessed at"
    );
    assert!(
        guidance::MACHINE.contains("x86_64 OpenSIPS VM"),
        "the failure message must carry the role form"
    );
}

// -- Class C: the lab's DNS domain ------------------------------------

/// C1. No file anywhere names the lab's DNS domain.
///
/// Repo-wide rather than published-only: a domain in a harness config is as
/// disclosed as a domain in a page, and unlike a service name it is not
/// something a reader reproduces.
#[test]
fn c1_no_file_names_the_private_domain() {
    let files = tracked_text();
    let found = scan(&files, |_| true, rule::private_domain);
    assert!(
        found.is_empty(),
        "the lab's DNS domain is in the tree:\n{}\n\n{}",
        capped(&found, 25),
        guidance::DOMAIN
    );
}

/// C2. The rule flags the fully qualified form that leaked.
#[test]
fn c2_the_domain_rule_flags_the_fqdn_that_leaked() {
    assert!(
        rule::private_domain("`opensips-1.goes.com` (Debian 13, kernel 6.12.101, x86_64)"),
        "the FQDN in the backlog must be caught if it returns"
    );
}

/// C3. It flags the domain with a port, and in a URL.
#[test]
fn c3_the_domain_rule_flags_it_with_a_port_or_in_a_url() {
    assert!(rule::private_domain(
        "`opensips-1.goes.com:5063`, returned both"
    ));
    assert!(rule::private_domain(
        "https://git.goes.com/user/vcon-backend"
    ));
}

/// C4. It flags a bare subdomain nobody has used yet.
///
/// The class is the domain, not the one host that happened to leak: the next
/// one will be a different label under the same zone.
#[test]
fn c4_the_domain_rule_flags_a_subdomain_not_yet_used() {
    assert!(rule::private_domain("ns1.goes.com"));
    assert!(rule::private_domain("mail.goes.com"));
}

/// C5. It spares words that merely contain the label.
#[test]
fn c5_the_domain_rule_spares_ordinary_prose() {
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
}

/// C6. The repo-wide scan really is repo-wide.
#[test]
fn c6_the_domain_scan_covers_more_than_the_published_set() {
    let files = tracked_text();
    let all = corpus_size(&files, |_| true);
    let published = corpus_size(&files, is_published);
    assert!(
        all > published,
        "the repo-wide scan ({all}) covers no more than the published one \
         ({published}), so `keep` has stopped widening it"
    );
}

/// C7. The scan reaches configuration, where a domain would sit if it returned.
#[test]
fn c7_the_domain_scan_reaches_configuration() {
    let files = tracked_text();
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
}

/// C8. A reserved example domain is never flagged.
#[test]
fn c8_reserved_example_domains_are_not_flagged() {
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
}

/// C9. The replacement the sweep used is itself a reserved name.
#[test]
fn c9_the_replacement_is_a_reserved_name() {
    let files = tracked_text();
    let used = files
        .iter()
        .any(|(_, text)| text.contains("opensips.example.com"));
    assert!(
        used,
        "the sweep replaced the FQDN with `opensips.example.com`; if that has \
         gone, check that whatever replaced it is also reserved"
    );
}

/// C10. The guide names the reserved-domain rule.
#[test]
fn c10_the_guide_names_the_reserved_domain_rule() {
    let guide = contributing();
    assert!(
        guide.contains("rfc 2606") || guide.contains("example.com"),
        "CONTRIBUTING.md must point at the reserved domains"
    );
    assert!(guidance::DOMAIN.contains("example.com"));
}

// -- Class D: the lab's LAN -------------------------------------------

/// D1. No prose page carries an address from the lab's LAN.
#[test]
fn d1_no_prose_page_carries_a_lab_address() {
    let files = tracked_text();
    let found = scan(&files, is_prose, rule::lab_address);
    assert!(
        found.is_empty(),
        "a prose page carries an address from the lab's own LAN:\n{}\n\n{}",
        capped(&found, 25),
        guidance::ADDRESS
    );
}

/// D2. The rule flags the relay and endpoint addresses that leaked.
#[test]
fn d2_the_address_rule_flags_the_addresses_that_leaked() {
    assert!(rule::lab_address(
        "0x0a0a0a0a   10.0.0.60:40001          10.0.0.40:38156          10       0s"
    ));
    assert!(rule::lab_address("`--hep-allow 10.0.0.40` exited with"));
}

/// D3. It flags one embedded in a URL-encoded Call-ID.
///
/// `%40` is `@`, so `test-call-1%4010.0.0.1` puts a digit immediately before
/// the address. A word-boundary sweep walked straight past it, and that is
/// exactly where one survived the first pass of the cleanup.
#[test]
fn d3_the_address_rule_flags_one_inside_an_encoded_call_id() {
    assert!(
        rule::lab_address("\"http://127.0.0.1:8080/v1/dialogs/test-call-1%4010.0.0.1/vcon\""),
        "an address glued to a percent-escape is still an address"
    );
}

/// D4. It spares QEMU's default guest network.
///
/// `10.0.2.15` is what every `qemu-system-*` guest gets, so it belongs in
/// sample output and says nothing about this lab.
#[test]
fn d4_the_address_rule_spares_the_qemu_guest_range() {
    for benign in ["10.0.2.15:5060", "sip:1001@10.0.2.20", "10.0.2.2"] {
        assert!(
            !rule::lab_address(benign),
            "RFC 1918 as a class is not the rule: {benign}"
        );
    }
}

/// D5. It spares the documentation ranges the sweep moved everything to.
#[test]
fn d5_the_address_rule_spares_the_documentation_ranges() {
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
}

/// D6. It needs a digit after the prefix, and the network itself counts.
#[test]
fn d6_the_address_rule_needs_a_digit_after_the_prefix() {
    assert!(
        !rule::lab_address("version 10.0.0. is not an address"),
        "a prefix with nothing after it is not an address"
    );
    assert!(
        rule::lab_address("10.0.0.0/24 dev veth"),
        "but the network itself is one"
    );
}

/// D7. Fixtures are deliberately out of scope, and stay that way.
///
/// The addresses under `tests/` are wire data that snapshots and
/// expected-output tests are pinned to. Rewriting them would churn the suite
/// and publish nothing, so the rule runs over prose and the exclusion is
/// asserted rather than assumed.
#[test]
fn d7_fixtures_are_outside_the_address_rule() {
    assert!(!is_prose("tests/snapshots/foo.snap"));
    assert!(!is_prose("benches/parser_bench.rs"));
    assert!(!is_prose("bench/live-capture.sh"));
    assert!(is_prose("docs/rtpengine.md"));
    assert!(is_prose("CHANGELOG.md"));
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
fn d8_published_ipv6_literals_are_documentation_addresses() {
    let files = tracked_text();
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
}

/// D9. The rendered social-preview image is in scope too.
///
/// `website/og-image.svg` is a picture of a terminal, and it carried two LAN
/// addresses as text. An SVG is markup, so it is scanned; a PNG would not be,
/// which is worth knowing before somebody exports one.
#[test]
fn d9_the_social_preview_image_is_scanned() {
    let files = tracked_text();
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
}

/// D10. The guide names the documentation ranges.
#[test]
fn d10_the_guide_names_the_documentation_ranges() {
    let guide = contributing();
    assert!(
        guide.contains("rfc 5737") && guide.contains("192.0.2.0/24"),
        "CONTRIBUTING.md must name the ranges, not just forbid the LAN"
    );
    assert!(guide.contains("2001:db8"), "and the IPv6 one");
}

// -- Class E: accounts and the private capture corpus -----------------

/// E1. No file carries a path under a real account's home directory.
#[test]
fn e1_no_file_carries_an_account_path() {
    let files = tracked_text();
    let found = scan(&files, |_| true, rule::account_path);
    assert!(
        found.is_empty(),
        "an absolute home-directory path is in the tree. It names the account \
         and it runs on one machine:\n{}\n\n{}",
        capped(&found, 25),
        guidance::PATH
    );
}

/// E2. The rule flags the corpus path that leaked, in a command.
#[test]
fn e2_the_account_rule_flags_the_command_that_leaked() {
    assert!(rule::account_path(
        "$BIN -N -I /home/gator/pcaps --cores 1 --no-cli-print"
    ));
    assert!(rule::account_path(
        "`/home/gator/pcaps` - 15 files, 1,383 MB, 4,532,272 packets"
    ));
}

/// E3. It flags a checkout path as well as a corpus path.
#[test]
fn e3_the_account_rule_flags_a_checkout_path() {
    assert!(rule::account_path(
        "hardcoded `root = /home/gator/Development/sipnab`, so everywhere else"
    ));
}

/// E4. It spares a placeholder every reader substitutes.
///
/// The rule is the ACCOUNT, not the shape. Banning `/home/user/capture.pcap`
/// would churn a dozen synopses to say nothing.
#[test]
fn e4_the_account_rule_spares_a_placeholder() {
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
}

/// E5. Nothing names where the private capture corpus lives.
///
/// The corpus is real signaling from real people. It is never committed, which
/// this repo already gets right -- but a path to it is the one part of it a
/// public page can still disclose.
#[test]
fn e5_nothing_locates_the_private_capture_corpus() {
    let files = tracked_text();
    let found = scan(&files, |_| true, rule::corpus_path);
    assert!(
        found.is_empty(),
        "a tracked file names the location of the private capture corpus:\n{}\n\n\
         Name the capability, not the address.",
        capped(&found, 25)
    );
}

/// E6. The corpus rule flags both spellings that appeared.
#[test]
fn e6_the_corpus_rule_flags_both_forms() {
    assert!(rule::corpus_path(
        "the corpus at /home/gator/pcaps carries PII"
    ));
    assert!(rule::corpus_path(
        "export CORPUS=/home/gator/captures/x.pcap"
    ));
}

/// E7. The corpus rule spares a corpus that is not under an account.
///
/// The capability to point sipnab at a corpus is the whole point of the bench
/// harness; only this corpus's address is the problem.
#[test]
fn e7_the_corpus_rule_spares_a_neutral_location() {
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
}

/// E8. The scan reaches shell and Python, where these paths actually sat.
#[test]
fn e8_the_account_scan_reaches_scripts() {
    let files = tracked_text();
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
}

/// E9. The account list is not empty, which is how this class goes vacuous.
#[test]
fn e9_the_account_list_is_not_empty() {
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
}

/// E10. The guide names the corpus rule and the path alternatives.
#[test]
fn e10_the_guide_names_the_corpus_rule() {
    let guide = contributing();
    assert!(guide.contains("$home"), "CONTRIBUTING.md must name `$HOME`");
    assert!(
        guide.contains("corpora") || guide.contains("corpus"),
        "and must say that capture corpora live outside the tree"
    );
}

// -- Class F: tracked transcripts -------------------------------------

/// F1. No log, backup or editor artefact is tracked.
///
/// A gate log is the densest form of this leak: a verbatim transcript of one
/// run on one machine, absolute paths and all, committed by accident rather
/// than by decision. `.git-docsgate.log` was tracked and carried a worktree
/// path under the maintainer's home directory.
#[test]
fn f1_no_transcript_or_backup_file_is_tracked() {
    let out = Command::new("git")
        .args(["ls-files"])
        .current_dir(repo())
        .output()
        .expect("git ls-files");
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
}

/// F2. The rule flags the file that leaked.
#[test]
fn f2_the_transcript_rule_flags_the_file_that_leaked() {
    assert!(
        rule::transcript_file(".git-docsgate.log"),
        "the gate log that was tracked must be caught if it returns"
    );
}

/// F3. It flags the editor and merge artefacts too.
#[test]
fn f3_the_transcript_rule_flags_editor_and_merge_artefacts() {
    for f in [
        "src/pipeline.rs.bak",
        "docs/x.md.orig",
        "a.rej",
        ".x.swp",
        "notes~",
    ] {
        assert!(rule::transcript_file(f), "{f} is a working artefact");
    }
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
fn f4_the_transcript_rule_spares_source_files() {
    for f in LOGGY_BUT_NOT_LOGS {
        assert!(!rule::transcript_file(f), "{f} is source, not a transcript");
    }
}

/// F4b. Those files exist, so the control is about this tree.
#[test]
fn f4b_the_negative_controls_name_files_that_exist() {
    for f in LOGGY_BUT_NOT_LOGS {
        assert!(
            repo().join(f).exists(),
            "{f} does not exist, so sparing it proves nothing about this tree. \
             Name a file that is really here."
        );
    }
}

/// F5. `.gitignore` carries the pattern, so the next one is never staged.
///
/// The gate catches a tracked transcript; the ignore rule stops it becoming
/// one. Without both, the fix lasts until the next run writes the file again.
#[test]
fn f5_gitignore_carries_the_transcript_pattern() {
    let ignore = std::fs::read_to_string(repo().join(".gitignore")).expect(".gitignore");
    assert!(
        ignore.contains("*.log"),
        ".gitignore must ignore transcripts, or the gate is the only thing \
         standing between a run and a commit"
    );
}

/// F6. The hooks write their logs outside the worktree.
///
/// `pre-commit` writes `.git/sipnab-pre-commit-*.log`, which a commit cannot
/// reach. That is the correct arrangement and worth pinning: a hook that writes
/// its log into the worktree instead is one `git add -A` away from publishing
/// it.
#[test]
fn f6_the_hooks_write_their_logs_outside_the_worktree() {
    let hook = std::fs::read_to_string(repo().join(".githooks/pre-commit")).expect("pre-commit");
    assert!(
        hook.contains("git rev-parse --git-dir") || hook.contains(".git/"),
        "the pre-commit hook must write its transcript under .git/, where a \
         commit cannot reach it"
    );
}

/// F7. The scan is over what is tracked, not over the tree.
///
/// An untracked log on somebody's machine is invisible here -- which is right,
/// because it is also invisible to everyone else. Pinned so nobody "improves"
/// the scan into walking the tree, which would read `target/` and every
/// worktree artefact besides.
#[test]
fn f7_the_scan_is_over_what_is_tracked() {
    let files = tracked_text();
    assert!(
        !files.iter().any(|(rel, _)| rel.starts_with("target/")),
        "the scan is reading build output, which means it walked the tree \
         instead of asking git what is tracked"
    );
}

/// F8. A renamed transcript still fails on its contents.
///
/// Defence in depth: the filename rule is the cheap one, and the path rule is
/// what makes renaming it to `notes.md` not a way through.
#[test]
fn f8_a_renamed_transcript_still_fails_on_its_contents() {
    let line = "  Full output: /home/gator/Development/sipnab/.git/worktrees/agent-a5e/x.log";
    assert!(
        rule::account_path(line),
        "renaming a transcript must not make its contents acceptable"
    );
}

/// F9. The transcript patterns are not empty.
#[test]
fn f9_the_transcript_rule_has_patterns_to_match() {
    assert!(
        rule::transcript_file("x.log") && rule::transcript_file("x~"),
        "with no patterns the rule returns false for everything and F1 passes \
         by proving nothing"
    );
}

/// F10. The guide says not to commit them.
#[test]
fn f10_the_guide_says_not_to_commit_transcripts() {
    let guide = contributing();
    assert!(
        guide.contains("gate log") || guide.contains("scratch file"),
        "CONTRIBUTING.md must say a transcript is not committed"
    );
    assert!(guidance::TRANSCRIPT.contains(".gitignore"));
}

// -- Class G: addresses that reach a real person ----------------------

/// G1. The only email addresses in the tree are published identities.
///
/// `Cargo.toml` carries the maintainer's on purpose -- a crate has to name
/// someone, and it is already on crates.io. Any OTHER address is somebody who
/// did not choose to be in this repository.
#[test]
fn g1_no_address_reaches_a_real_mailbox() {
    let files = tracked_text();
    let addr = regex::Regex::new(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}").unwrap();
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
}

/// G2. The rule flags the sample-output URI that leaked.
///
/// `1002@carrier.net` appeared ten times in `src/output/call_report.rs` -- as
/// fixture data AND in the expected output beside it, so it was in sample
/// output a reader could copy.
#[test]
fn g2_the_mailbox_rule_flags_the_sample_uri_that_leaked() {
    assert!(rule::live_address("1002@carrier.net"));
}

/// G3. It flags the fixture address that leaked.
#[test]
fn g3_the_mailbox_rule_flags_the_fixture_that_leaked() {
    assert!(rule::live_address("evil@attacker.com"));
}

/// G4. It spares RFC 2606's reserved TLDs, which are the fix.
#[test]
fn g4_the_mailbox_rule_spares_reserved_tlds() {
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
}

/// G5. It spares subdomains of the reserved example domains.
///
/// `deploy@web01.example.com` is a deployment example, and an allowlist that
/// only knew the bare domain flagged it.
#[test]
fn g5_the_mailbox_rule_spares_reserved_subdomains() {
    for benign in [
        "deploy@web01.example.com",
        "ops@ci.example.org",
        "a@b.example.net",
    ] {
        assert!(!rule::live_address(benign), "{benign} is reserved too");
    }
}

/// G6. It spares a SIP Call-ID, which is not a mailbox.
///
/// `call-NNNN@sipnab.bench` has the shape and none of the meaning. The rule
/// runs off REAL top-level domains for this reason: `.bench` resolves nowhere.
#[test]
fn g6_the_mailbox_rule_spares_a_sip_call_id() {
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
}

/// G7. The published identities are spared, and the list is not empty.
#[test]
fn g7_the_published_identities_are_spared() {
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
}

/// G8. The real-TLD list is what makes the rule decidable, and is populated.
#[test]
fn g8_the_real_tld_list_is_populated() {
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
}

/// G9. The scan reaches source, not only documentation.
///
/// Both addresses in this class leaked from `src/`, inside test fixtures -- a
/// documentation-only scan would have found neither.
#[test]
fn g9_the_mailbox_scan_reaches_source_files() {
    let files = tracked_text();
    for surface in ["src/output/call_report.rs", "src/sip/message.rs"] {
        assert!(
            reaches(&files, surface),
            "{surface} carried a live address and must be in the scan"
        );
    }
    let rust = files.iter().filter(|(r, _)| r.ends_with(".rs")).count();
    assert!(rust > 50, "only {rust} Rust files in the scan is too few");
}

/// G10. The guide names the reserved names a fixture should use.
#[test]
fn g10_the_guide_names_the_reserved_fixture_domains() {
    let guide = contributing();
    assert!(
        guide.contains(".test") || guide.contains(".invalid"),
        "CONTRIBUTING.md must name the reserved forms a fixture should use"
    );
    assert!(guidance::MAILBOX.contains(".test"));
}

// -- Structural: the scan itself --------------------------------------

/// The scan reads a real corpus, and the files it exists to cover.
///
/// Every rule above passes by finding nothing, which is also what they do if
/// `git ls-files` fails, if the binary filter swallows the tree, or if
/// `is_published` stops matching. A clean-looking gate and a broken one are
/// indistinguishable, so the corpus is asserted rather than assumed.
#[test]
fn the_scan_reads_the_files_it_claims_to_cover() {
    let files = tracked_text();
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
fn the_guide_names_every_class_the_gate_enforces() {
    let guide = contributing();
    // Each class, and a string from the guide that can only be there because
    // somebody wrote that row.
    for (class, clause) in [
        ("A hostnames", "hostname"),
        ("B lab machines", "opensips-1"),
        ("C private domain", "example.com"),
        ("D addresses", "rfc 5737"),
        ("E accounts", "$home"),
        ("F transcripts", "gitignore"),
        ("G mailboxes", ".test"),
    ] {
        assert!(
            guide.contains(clause),
            "class {class} is enforced but CONTRIBUTING.md does not mention \
             `{clause}`, so a writer cannot know the rule before tripping it"
        );
    }
}

/// The guide promises nothing the gate does not enforce.
///
/// The other direction, and the one that rots quietly: a row telling writers
/// that something is checked, when nothing checks it, is worse than silence --
/// it is a promise that reads as a guarantee. Each rule named below is invoked,
/// so deleting the rule breaks this test rather than leaving the guide lying.
#[test]
fn the_guide_promises_nothing_the_gate_does_not_enforce() {
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
}
