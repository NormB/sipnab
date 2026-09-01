// SPDX-License-Identifier: MIT OR Apache-2.0

//! Every `--flag` a document names must be a flag the program actually has.
//!
//! `docs/design/testing-matrix.md` is already pinned to clap by
//! `coverage_matrix_test`. Prose is not, and prose is where a flag gets
//! *claimed*. The distinction matters because a claim is read by a person who
//! then acts on it, and nothing failed when the claim was written.
//!
//! The defect that produced this file was mine. Validating 0.5.130 I grepped
//! `sipnab --help` for a strictness flag, saw a hit, and wrote "`--fail`
//! already exists as a precedent for opting into strictness" into a findings
//! document. There is no `--fail`. My pattern had matched `--fail2ban`, a flag
//! about a completely different thing. A prefix match on a flag name reads as
//! a confirmation and is not one — which is why
//! [`a_flag_reference_is_matched_as_a_whole_word_not_a_prefix`] exists as a
//! test of the matcher rather than as a comment about it.

// Gated on `full`, matching `coverage_matrix_test`, and the reason is the
// defect that put it here: clap's flag set is FEATURE-DEPENDENT. Under
// `native,hep,api,mcp,mcp-http` the flags behind `tls`, `vcon`, `plugins` and
// `audio` do not exist, so every document naming one was reported as a phantom
// claim. The documentation describes the full-featured binary, so that is the
// only build this gate can judge it against. `native` alone was the first fix
// -- it made the file COMPILE under a narrow combo, which is a different
// question from whether its comparison MEANS anything there.
#![cfg(feature = "full")]

use clap::CommandFactory;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// The repository root.
fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every long flag the program actually has, derived from clap.
///
/// Derived, never listed: a fixture copy of this set would agree with a binary
/// that had drifted out from under it, which is the failure this whole file is
/// about.
fn clap_long_flags() -> BTreeSet<String> {
    let cmd = sipnab::cli::Cli::command();
    let mut flags: BTreeSet<String> = cmd
        .get_arguments()
        .filter_map(|a| a.get_long().map(|l| format!("--{l}")))
        .collect();
    // clap synthesizes these and does not return them from `get_arguments()`,
    // but `--help` prints them and prose legitimately names them.
    flags.insert("--help".into());
    flags.insert("--version".into());
    flags
}

/// Pull every long flag that a document attributes to **sipnab** out of it.
///
/// Two narrowings, both learned by measurement rather than assumed:
///
/// 1. **Code spans only.** Bare `--foo` in prose is routinely part of a
///    sentence about a flag a *different* tool has, and nothing distinguishes
///    those from a claim about sipnab.
/// 2. **Only spans that invoke sipnab, and only up to the first pipe or
///    separator.** The first version of this gate skipped step 2 and
///    immediately reported `--release` (cargo), `--data-binary` (curl) and
///    `--listen-ng` (rtpengine) as flags sipnab lacks. It was right that the
///    program has no such flags and wrong that any document claimed it did.
///    A gate demanding a fix its own rule makes impossible gets deleted, so
///    the rule had to narrow instead.
fn flags_in(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for chunk in code_spans(text) {
        let chunk = chunk.as_str();
        for segment in chunk.split(['|', ';']).flat_map(|s| s.split("&&")) {
            let mut tokens = segment.split_whitespace().peekable();
            // Skip a leading `sudo` and any VAR=value environment prefix.
            while let Some(t) = tokens.peek() {
                if *t == "sudo" || (t.contains('=') && !t.starts_with('-')) {
                    tokens.next();
                } else {
                    break;
                }
            }
            // sipnab must be the COMMAND. `cargo bench --bench sipnab -- --runs`
            // and `curl https://sipnab.com --data-binary` both mention sipnab
            // and neither says anything about sipnab's flags; requiring the
            // command position is what separates them.
            let Some(cmd) = tokens.next() else { continue };
            let is_sipnab =
                cmd == "sipnab" || cmd.ends_with("/sipnab") || cmd.ends_with("/sipnab.exe");
            if !is_sipnab {
                continue;
            }
            for tok in tokens {
                let tok = tok.trim_end_matches([',', '.', ';', ':', ')', ']', '\'', '"']);
                let Some(rest) = tok.strip_prefix("--") else {
                    continue;
                };
                let name = rest.split('=').next().unwrap_or(rest);
                if name.is_empty() || !name.starts_with(|c: char| c.is_ascii_lowercase()) {
                    continue;
                }
                if name
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
                {
                    out.insert(format!("--{name}"));
                }
            }
        }
    }
    out
}

/// Every code span in a document: fenced blocks AND inline spans.
///
/// Fenced blocks are where worked examples live — `docs/real-world-captures.md`
/// is 32 of them and zero inline command spans, so an extractor that read only
/// inline spans reported it as containing no flags at all, and its own
/// anti-vacuity floor is what caught that.
fn code_spans(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_fence = false;
    let mut fenced = String::new();
    for line in text.lines() {
        if line.trim_start().starts_with("```") {
            if in_fence {
                out.push(std::mem::take(&mut fenced));
            }
            in_fence = !in_fence;
            continue;
        }
        if in_fence {
            fenced.push_str(line);
            fenced.push('\n');
        } else {
            for span in line.split('`').skip(1).step_by(2) {
                out.push(span.to_string());
            }
        }
    }
    out
}

/// Flag references that are deliberately NOT claims that the flag exists.
///
/// Each entry states why, and both directions are enforced below: an entry
/// with no reason is refused, and an entry that exempts nothing is refused. An
/// unexplained exemption list is how a gate like this rots — it becomes the
/// place failures go to be silenced.
const NOT_A_CLAIM: &[(&str, &str, &str)] = &[
    (
        "docs/examples.md",
        "--features",
        "the sentence is explicitly telling the reader this invocation does NOT \
     exist: \"There is no `sipnab --features tls` invocation; pass \
     `--features` to `cargo build`\". Naming the non-existent form is the \
     point of the paragraph.",
    ),
    (
        "website/content/docs/cookbook.md",
        "--features",
        "the generated mirror of docs/examples.md, carrying the same sentence \
     verbatim. Exempted separately because scripts/build-site-pages.py copies \
     the prose, so the two must be kept in step or the site half fails alone.",
    ),
];

/// Every `.md` under `dir`, recursively, skipping nothing.
fn markdown_under(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(markdown_under(&p));
        } else if p.extension().is_some_and(|x| x == "md") {
            out.push(p);
        }
    }
    out.sort();
    out
}

/// Collect (file, flag) pairs naming a flag the program does not have.
fn unknown_flag_claims(roots: &[&str]) -> (Vec<(String, String)>, usize, usize) {
    unknown_flag_claims_excluding(roots, &[])
}

/// As [`unknown_flag_claims`], skipping any path under one of `excluded`.
fn unknown_flag_claims_excluding(
    roots: &[&str],
    excluded: &[&str],
) -> (Vec<(String, String)>, usize, usize) {
    let have = clap_long_flags();
    let mut bad = Vec::new();
    let mut files = 0usize;
    let mut seen = 0usize;
    for root in roots {
        for path in markdown_under(&repo().join(root)) {
            let rel_path = path.strip_prefix(repo()).unwrap_or(&path).to_path_buf();
            if excluded.iter().any(|e| rel_path.starts_with(e)) {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            files += 1;
            for flag in flags_in(&text) {
                seen += 1;
                if !have.contains(&flag) {
                    let rel = path
                        .strip_prefix(repo())
                        .unwrap_or(&path)
                        .display()
                        .to_string();
                    let exempt = NOT_A_CLAIM
                        .iter()
                        .any(|(f, g, _)| *f == rel && *g == flag.as_str());
                    if !exempt {
                        bad.push((rel, flag));
                    }
                }
            }
        }
    }
    (bad, files, seen)
}

/// Flags named in the task-facing documentation must exist.
#[test]
fn every_flag_named_in_prose_docs_exists_in_the_binary() {
    // `docs/design/` and `docs/research/` are deliberately outside this scan.
    // They are planning documents: they describe flags that were PROPOSED, and
    // some were deliberately withdrawn. `implementation-plan-v6.md` shows a
    // `rtp.orphaned` filter that `docs/filter-dsl.md` records as removed, and
    // `pcapng-metadata.md` names a `--to-pcapng` that was never built. Holding
    // a design document to the shipped binary would demand it be rewritten
    // every time a plan changed, which is the opposite of what it is for.
    let (bad, files, seen) =
        unknown_flag_claims_excluding(&["docs"], &["docs/design", "docs/research"]);
    assert!(
        files >= 20 && seen >= 200,
        "scanned {files} file(s) and {seen} flag reference(s) under docs/ — the \
         extractor stopped matching, so this gate is checking almost nothing"
    );
    assert!(
        bad.is_empty(),
        "these documents name a flag the program does not have:\n{}\n\
         Either the flag was renamed and the prose was not, or the prose \
         invented it. A reader cannot tell the difference.",
        bad.iter()
            .map(|(f, g)| format!("  {f}: {g}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// The same rule for the website copy, which is what the public reads.
#[test]
fn every_flag_named_on_the_website_exists_in_the_binary() {
    let (bad, files, _) = unknown_flag_claims(&["website/content"]);
    assert!(
        files >= 10,
        "scanned {files} file(s) under website/content — the walk is not \
         reaching the pages"
    );
    assert!(
        bad.is_empty(),
        "the published site names a flag the program does not have:\n{}",
        bad.iter()
            .map(|(f, g)| format!("  {f}: {g}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// A flag reference must match a whole flag, never a prefix of a longer one.
///
/// This is the exact shape of the error that produced this file: `--fail`
/// "found" in a tree whose only match was `--fail2ban`. The extractor is
/// therefore tested against that pair by name, so a future rewrite that
/// reintroduces prefix matching fails here rather than in a report.
#[test]
fn a_flag_reference_is_matched_as_a_whole_word_not_a_prefix() {
    let have = clap_long_flags();
    assert!(
        have.contains("--fail2ban"),
        "this test is anchored on --fail2ban and the program no longer has it; \
         re-anchor it on another flag with a shared prefix rather than deleting it"
    );
    assert!(
        !have.contains("--fail"),
        "the program now has a real --fail; re-anchor this test, because the \
         pair it was written against no longer demonstrates the trap"
    );

    // The extractor must read `--fail2ban` as itself, and must not report a
    // bare `--fail` for it.
    let got = flags_in("run it with `sipnab -N -I x.pcap --fail2ban` to emit jail lines");
    assert!(
        got.contains("--fail2ban"),
        "extractor lost --fail2ban entirely: {got:?}"
    );
    assert!(
        !got.contains("--fail"),
        "extractor reported a bare --fail from text whose only flag is \
         --fail2ban: {got:?}. That is the prefix match this gate exists to \
         prevent."
    );

    // And a genuine `--fail` in prose must be reported as unknown rather than
    // silently satisfied by --fail2ban's presence in the binary.
    let claimed = flags_in("pass `sipnab --fail` to make it strict");
    assert!(
        claimed.contains("--fail") && !have.contains("--fail"),
        "a document naming `--fail` must be extracted as --fail and judged \
         against the real flag set; got {claimed:?}"
    );
}

/// The extractor must actually read code spans, not everything or nothing.
///
/// Both failure directions are silent: an extractor that returns nothing lets
/// every document pass, and one that returns every `--`-prefixed word floods
/// the gate with other tools' flags until someone deletes it.
#[test]
fn the_flag_extractor_reads_sipnab_invocations_and_nothing_else() {
    let got = flags_in("use `sipnab --quiet` here; tcpdump takes --immediate-mode instead");
    assert!(
        got.contains("--quiet"),
        "extractor missed a backticked flag: {got:?}"
    );
    assert!(
        !got.contains("--immediate-mode"),
        "extractor picked up an unbackticked flag belonging to another tool: \
         {got:?}. Prose about tcpdump would then fail this gate forever."
    );

    let whole_line = flags_in("`sipnab -N -I x.pcap --json-dialogs --no-cli-print`");
    assert!(
        whole_line.contains("--json-dialogs") && whole_line.contains("--no-cli-print"),
        "extractor read only part of a command-line code span: {whole_line:?}"
    );
    assert_eq!(
        flags_in("`sipnab --limit=10`"),
        BTreeSet::from(["--limit".to_string()]),
        "a --flag=value reference must name --flag"
    );
    assert!(
        flags_in("no flags here at all").is_empty(),
        "extractor invented a flag from text containing none"
    );
    // A pipeline's downstream flags belong to the downstream program.
    let piped = flags_in("`sipnab -N --json | jq --raw-output .call_id`");
    assert!(
        piped.contains("--json") && !piped.contains("--raw-output"),
        "extractor crossed a pipe and claimed jq's flags for sipnab: {piped:?}"
    );
    // A code span that never runs sipnab says nothing about sipnab.
    assert!(
        flags_in("`cargo build --release --features full`").is_empty(),
        "extractor read another program's command line as sipnab's"
    );
    // sipnab as an ARGUMENT is not sipnab as the command. Both of these
    // mention sipnab and neither documents a sipnab flag.
    assert!(
        flags_in("`cargo bench --bench sipnab -- --runs 5`").is_empty(),
        "extractor claimed cargo's --runs for sipnab"
    );
    assert!(
        flags_in("`curl https://sipnab.com/x --data-binary @f`").is_empty(),
        "extractor claimed curl's --data-binary for sipnab"
    );
    // A leading sudo or env prefix must not hide the command.
    assert!(
        flags_in("`sudo sipnab -d eth0 --portrange 5060-5061`").contains("--portrange"),
        "extractor lost a flag behind a leading sudo"
    );
    assert!(
        flags_in("`RUST_LOG=debug sipnab --quiet`").contains("--quiet"),
        "extractor lost a flag behind an environment prefix"
    );
}

/// The clap side must be derived, and must be a real program's worth of flags.
///
/// A gate comparing documents against an empty or tiny flag set would report
/// every documented flag as unknown, get judged noisy, and be deleted. Pinning
/// a floor and a few known names makes "the derivation broke" a distinct
/// outcome from "the docs are wrong".
#[test]
fn the_binary_flag_set_is_derived_from_clap_and_is_not_a_stub() {
    let have = clap_long_flags();
    assert!(
        have.len() >= 100,
        "clap yielded only {} long flag(s); the derivation is broken, and every \
         comparison against it would be meaningless",
        have.len()
    );
    for known in ["--json", "--quiet", "--no-cli-print", "--help", "--version"] {
        assert!(
            have.contains(known),
            "clap derivation is missing {known}, a flag the program certainly \
             has — the extraction is reading the wrong thing"
        );
    }
}

/// A documented flag that is one edit away from a real one is a typo, and
/// saying so is worth more than "unknown flag".
///
/// The two failures differ in what the reader should do: a typo is fixed in
/// the document, while a genuinely absent flag means the feature moved or was
/// never built. A gate that cannot tell them apart makes the reader do the
/// diagnosis the gate already had the information to do.
#[test]
fn an_unknown_documented_flag_is_reported_as_a_typo_when_it_is_one() {
    /// Levenshtein distance, capped: we only care about 0, 1 or "more".
    fn within_one(a: &str, b: &str) -> bool {
        if a == b {
            return true;
        }
        let (a, b) = if a.len() > b.len() { (b, a) } else { (a, b) };
        if b.len() - a.len() > 1 {
            return false;
        }
        let (av, bv): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
        let mut i = 0;
        let mut j = 0;
        let mut slack = 1i32;
        while i < av.len() && j < bv.len() {
            if av[i] == bv[j] {
                i += 1;
                j += 1;
                continue;
            }
            slack -= 1;
            if slack < 0 {
                return false;
            }
            if av.len() == bv.len() {
                i += 1;
            }
            j += 1;
        }
        slack - ((bv.len() - j) as i32) >= 0
    }

    // The classifier itself must work, or its verdicts are noise.
    assert!(within_one("--quiet", "--quie"), "deletion not detected");
    assert!(within_one("--quiet", "--quiett"), "insertion not detected");
    assert!(
        within_one("--quiet", "--qulet"),
        "substitution not detected"
    );
    assert!(
        !within_one("--fail", "--fail2ban"),
        "--fail and --fail2ban are 5 edits apart and must NOT be called a typo; \
         treating them as one would have excused the very error this file \
         records"
    );

    let have = clap_long_flags();
    let (bad, _, _) = unknown_flag_claims(&["docs", "website/content"]);
    let typos: Vec<String> = bad
        .iter()
        .filter_map(|(f, g)| {
            have.iter()
                .find(|real| within_one(g, real))
                .map(|real| format!("  {f}: {g} — did you mean {real}?"))
        })
        .collect();
    assert!(
        typos.is_empty(),
        "documented flags that look like typos of real ones:\n{}",
        typos.join("\n")
    );
}

/// The real-world captures page is worked examples, so its flags must be real.
///
/// Every command block on that page was executed when it was written. This
/// gate is what keeps that true after a flag is renamed, without needing to
/// run 32 commands against an 8.8 GB corpus that is not in the repository.
#[test]
fn every_flag_in_the_real_world_captures_page_exists() {
    let path = repo().join("docs/real-world-captures.md");
    if !path.exists() {
        return; // page not present in this checkout
    }
    let text = std::fs::read_to_string(&path).expect("read real-world-captures.md");
    let have = clap_long_flags();
    let named = flags_in(&text);
    assert!(
        named.len() >= 10,
        "only {} flag(s) found on a page of worked examples — the extractor is \
         not reading its command blocks",
        named.len()
    );
    let bad: Vec<&String> = named.iter().filter(|f| !have.contains(*f)).collect();
    assert!(
        bad.is_empty(),
        "docs/real-world-captures.md names flags the program does not have: \
         {bad:?}. Every command block on that page was run when it was written; \
         if a flag was renamed since, the examples no longer execute."
    );
}

/// Every exemption must state a reason, and must exempt something real.
///
/// Both halves matter and they fail in opposite directions. A blank reason
/// turns the table into a silencer. A stale entry — one whose flag now exists,
/// or whose file no longer names it — leaves a hole that quietly excuses a
/// future regression at that exact spot.
#[test]
fn every_exemption_states_a_reason_and_still_exempts_something() {
    assert!(
        !NOT_A_CLAIM.is_empty(),
        "the exemption table is empty; delete the mechanism rather than \
         leaving an untested one in place"
    );
    let have = clap_long_flags();
    for (file, flag, reason) in NOT_A_CLAIM {
        assert!(
            reason.trim().len() >= 20,
            "{file}: {flag} is exempted with no real reason. An exemption \
             without a stated reason is a silenced failure."
        );
        assert!(
            !have.contains(*flag),
            "{file} exempts {flag}, but the program now HAS that flag — the \
             entry is stale and is excusing nothing. Delete it."
        );
        let text = std::fs::read_to_string(repo().join(file))
            .unwrap_or_else(|e| panic!("exemption names {file}, which cannot be read: {e}"));
        assert!(
            flags_in(&text).contains(*flag),
            "{file} no longer names {flag} in a sipnab invocation; the \
             exemption is stale and must be deleted"
        );
    }
}

/// The design-doc exclusion must remain narrow.
///
/// An exclusion list is the other way a gate like this dies: widen it far
/// enough and it passes by reading nothing. This pins the excluded roots by
/// name and asserts the scan still covers the great majority of the tree.
#[test]
fn the_design_doc_exclusion_stays_narrow() {
    let all = markdown_under(&repo().join("docs")).len();
    let excluded = markdown_under(&repo().join("docs/design")).len()
        + markdown_under(&repo().join("docs/research")).len();
    assert!(all > 0, "no markdown found under docs/ at all");
    let scanned = all - excluded;
    assert!(
        scanned * 2 > all,
        "the exclusion now hides {excluded} of {all} documents, more than half \
         the tree. A gate that reads a minority of its corpus is not measuring \
         the corpus."
    );
    let (_, files, _) = unknown_flag_claims_excluding(&["docs"], &["docs/design", "docs/research"]);
    assert_eq!(
        files, scanned,
        "the scan visited {files} file(s) but {scanned} are in scope — the \
         exclusion is dropping more than the two roots it names"
    );
}
