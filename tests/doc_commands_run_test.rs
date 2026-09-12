// SPDX-License-Identifier: MIT OR Apache-2.0

//! Every sipnab command in the documentation is RUN, or says why it cannot be.
//!
//! # Why this exists
//!
//! Before it, three gates watched the documented commands and none of them
//! executed one. `doc_example_coverage_test` counts examples per flag,
//! `docs_drift_test` checks that every flag named in prose exists in the CLI,
//! and `config_examples_test` parses the TOML samples. A command could name
//! only real flags, in a combination sipnab refuses, and every gate stayed
//! green.
//!
//! An example nobody executed is a claim. A copied command that fails is worse
//! than no example, because the reader blames themselves first.
//!
//! # The bargain
//!
//! Each invocation lands in exactly one bucket. Either it RUNS here, against a
//! capture that ships with the repository, or it is one of the three things
//! this process cannot do: open a live interface, become root, or start a
//! server that never exits. A command that fits no bucket FAILS the test rather
//! than being skipped, because a silent fourth category is how a gate stops
//! covering what it claims to.
//!
//! # What counts as a failure
//!
//! A USAGE error, not a non-zero exit. Plenty of documented commands exit
//! non-zero for honest reasons -- `--problems` on a clean capture, a filter
//! that matches nothing. What must never happen is sipnab refusing the command
//! line itself: an argument it does not know, a value it will not take, a
//! combination it forbids. clap writes those as a bare `error: ` line, which is
//! distinguishable from sipnab's own runtime errors because those go through
//! tracing and carry a timestamp.

#![cfg(feature = "full")]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Repository root.
fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// The capture substituted for a documented placeholder path.
///
/// Chosen because it is the one the homepage's own demos read: seven dialogs,
/// RTP in both directions, loss on one of them. A command that only works on an
/// empty capture is not being tested by it.
const FIXTURE: &str = "tests/pcap-samples/Asterisk_ZFONE_XLITE.pcap";

/// The Call-ID of the INVITE dialog in [`FIXTURE`].
///
/// Substituted for the documented placeholders (`<call-id>`, `abc123@host`) so
/// a `--call-report` example produces a report rather than "no such call". The
/// point of running these is to exercise what the page shows, and a command
/// that only ever hits the not-found path exercises less than it looks like.
const FIXTURE_CALL_ID: &str = "ZDYzOWVlNjEwM2NjZTBjNzliNmM1ZTNiOGZjNWFhN2E.";

/// What this test does with one documented invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Plan {
    /// Runs against a capture that ships with the repository.
    Reads,
    /// Runs, with a device name that cannot exist substituted for the one the
    /// page names. The arguments are still parsed in full, and capture then
    /// fails at open with "No such device exists" -- which is not a usage
    /// error, so a typo in a live-capture example is still caught. `sudo` is
    /// stripped: a test suite must never escalate, and sudo is not what makes
    /// the flags valid.
    ReadsFakeDevice,
    /// Runs under a wall-clock bound and is killed if it is still alive.
    /// Servers do not exit; clap refuses in milliseconds. A process still
    /// running after the bound necessarily got past argument parsing.
    Bounded,
    /// Not run: the example is a shell program rather than one invocation -- a
    /// loop, or a command substitution feeding the next argument. Running it
    /// would be testing the shell.
    ShellProgram,
    /// Not run: it would execute a command of its own (`--on-dialog-exec`,
    /// `--on-quality-exec`) or attach to the kernel (`--uprobe-tls`). A
    /// documentation gate must not run `curl` at a stranger's endpoint or load
    /// probes into the machine running the suite.
    SideEffects,
}

impl Plan {
    const fn is_run(self) -> bool {
        matches!(self, Self::Reads | Self::ReadsFakeDevice | Self::Bounded)
    }

    const fn why(self) -> &'static str {
        match self {
            Self::Reads => "runs against a fixture",
            Self::ReadsFakeDevice => "runs with a device name that cannot exist",
            Self::Bounded => "runs under a wall-clock bound",
            Self::ShellProgram => "is a shell program, not one invocation",
            Self::SideEffects => "would exec a command or attach to the kernel",
        }
    }
}

/// One documented invocation.
#[derive(Debug, Clone)]
struct Invocation {
    page: String,
    line: usize,
    text: String,
}

/// Every `sipnab …` line inside a shell block in `docs/*.md`.
///
/// Backslash continuations are joined first, so a command split over five lines
/// is one invocation rather than five fragments that parse as nothing.
fn documented_invocations() -> Vec<Invocation> {
    let fence = regex::Regex::new(r"^```(bash|sh|shell|console)\s*$").expect("regex");
    let starts = regex::Regex::new(r"^(sudo\s+)?([A-Z_][A-Z0-9_]*=\S+\s+)*(\./)?sipnab(\s|$)")
        .expect("regex");
    let mut out = Vec::new();
    let mut pages: Vec<PathBuf> = std::fs::read_dir(repo().join("docs"))
        .expect("docs/ is readable")
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "md"))
        .collect();
    pages.sort();
    assert!(
        pages.len() >= 20,
        "only {} page(s) under docs/ — the walk is not reading the tree",
        pages.len()
    );
    for page in pages {
        let name = page
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("?")
            .to_owned();
        let text = std::fs::read_to_string(&page).expect("a readable page");
        let lines: Vec<&str> = text.lines().collect();
        let mut inside = false;
        let mut i = 0;
        while i < lines.len() {
            let l = lines[i];
            if l.starts_with("```") {
                inside = if inside { false } else { fence.is_match(l) };
                i += 1;
                continue;
            }
            if inside {
                // Join the continuation before deciding what this line is.
                let mut joined = l.trim().to_owned();
                let start = i;
                while joined.ends_with('\\') && i + 1 < lines.len() {
                    joined.pop();
                    i += 1;
                    joined.push(' ');
                    joined.push_str(lines[i].trim());
                }
                if starts.is_match(&joined) {
                    out.push(Invocation {
                        page: name.clone(),
                        line: start + 1,
                        text: joined,
                    });
                }
            }
            i += 1;
        }
    }
    out
}

/// What to do with one documented invocation.
///
/// Ordered by what MUST win. A command that both names a device and installs an
/// exec hook is not run, because the hook is the dangerous half.
fn classify(cmd: &str) -> Plan {
    // Never run, whatever else it says.
    let side_effects =
        regex::Regex::new(r"(^|\s)(--on-[a-z-]+-exec|--uprobe-tls|--uprobe-backend)(\s|=|$)")
            .expect("regex");
    if side_effects.is_match(cmd) {
        return Plan::SideEffects;
    }
    // `$(…)`, `$VAR`, or a line that opens a loop: the shell is doing the work.
    let shell_var = regex::Regex::new(r"\$[A-Za-z_(]").expect("regex");
    if shell_var.is_match(cmd) || cmd.contains("; do") || cmd.contains("; then") {
        return Plan::ShellProgram;
    }
    let serves =
        regex::Regex::new(r"(^|\s)(--api|--mcp|--metrics-only|-L|--hep-listen|--watch)(\s|=|$)")
            .expect("regex");
    if serves.is_match(cmd) {
        return Plan::Bounded;
    }
    let device = regex::Regex::new(r"(^|\s)(-d|--device)(\s|=)").expect("regex");
    if device.is_match(cmd) || cmd.starts_with("sudo ") {
        return Plan::ReadsFakeDevice;
    }
    Plan::Reads
}

/// A device name no host has. Long and self-describing so that if it ever DOES
/// appear in somebody's `ip link` output, the reason is obvious.
const FAKE_DEVICE: &str = "sipnab-doc-gate-no-such-device";

/// Drop a trailing shell redirection: it is the shell's argument, not sipnab's.
///
/// `> report.md`, `2>dtmf.log`, `>> log`, `2>/dev/null`. Only OUTSIDE quotes,
/// so a `--filter "a > b"` keeps its operator.
fn strip_redirection(cmd: &str) -> String {
    let mut out = String::new();
    let mut quote: Option<char> = None;
    let mut chars = cmd.chars().peekable();
    while let Some(c) = chars.next() {
        match (quote, c) {
            (Some(q), ch) if ch == q => {
                quote = None;
                out.push(ch);
            }
            (Some(_), ch) => out.push(ch),
            (None, '\'' | '"') => {
                quote = Some(c);
                out.push(c);
            }
            // `2>` and `>`: everything from here belongs to the shell. A `>`
            // that is part of a placeholder like `<call-id>` never reaches this
            // arm, because it is preceded by `<` inside one word.
            (None, '>') => {
                if out.ends_with('2') && out.len() >= 2 {
                    out.pop();
                }
                while chars.peek().is_some() {
                    chars.next();
                }
            }
            (None, ch) => out.push(ch),
        }
    }
    out.trim().to_owned()
}

/// Flags whose value is an INPUT file the documentation only gestures at.
///
/// Each gets a real file, because a command that fails on a missing
/// `ci.sipnablint` is failing on this test's setup rather than on anything the
/// page got wrong. Named explicitly rather than guessed from the shape of the
/// value: a list is auditable and a heuristic is not.
const INPUT_FILE_FLAGS: &[&str] = &[
    "--lint-suppress-file",
    "--hosts",
    "--srtp-key-file",
    "--keylog",
    "--config",
];

/// Flags whose value is something this test writes.
const OUTPUT_PATH_FLAGS: &[&str] = &[
    "-O",
    "--output",
    "--wav-out",
    "--vcon-out",
    "--export-vcon-dir",
    "--mcp-audit-file",
];

/// One documented command, ready to run: its argv and the environment the
/// example set in front of it.
///
/// Named rather than returned as a nested tuple, which clippy reads as a very
/// complex type and a reader reads as two anonymous halves.
struct Prepared {
    argv: Vec<String>,
    env: Vec<(String, String)>,
}

/// Build the argv actually run, with every substitution this test declares.
fn prepare(cmd: &str, sandbox: &Path, n: usize) -> Option<Prepared> {
    // `sudo` is the shell's word, not sipnab's argument, and this suite must
    // never escalate. Dropping it leaves the flags, which are what is under
    // test.
    let cmd = cmd.strip_prefix("sudo ").unwrap_or(cmd);
    // A pipeline's later stages are jq's business, not sipnab's.
    let head = cmd.split(" | ").next().unwrap_or(cmd).trim();
    let head = head.trim_end_matches(';');
    let head = strip_redirection(head);
    let head = head.as_str();
    let mut env = Vec::new();
    let mut rest = head;
    // Leading VAR=value assignments belong to the environment, not to argv.
    let assign = regex::Regex::new(r"^([A-Z_][A-Z0-9_]*)=(\S+)\s+").expect("regex");
    while let Some(c) = assign.captures(rest) {
        env.push((c[1].to_owned(), c[2].to_owned()));
        rest = &rest[c[0].len()..];
    }
    let mut argv: Vec<String> = shell_words(rest)?;
    if argv.is_empty() {
        return None;
    }
    argv[0] = env!("CARGO_BIN_EXE_sipnab").to_owned();

    let fixture = repo().join(FIXTURE).display().to_string();
    for i in 1..argv.len() {
        let prev = argv[i - 1].clone();
        if prev == "-I" || prev == "--input" {
            if !repo().join(&argv[i]).exists() {
                argv[i].clone_from(&fixture);
            }
        } else if INPUT_FILE_FLAGS.contains(&prev.as_str()) {
            let p = sandbox.join(format!("in-{n}"));
            std::fs::write(&p, "").expect("the sandbox is writable");
            argv[i] = p.display().to_string();
        } else if OUTPUT_PATH_FLAGS.contains(&prev.as_str()) {
            argv[i] = sandbox.join(format!("out-{n}")).display().to_string();
        } else if prev == "--call-report" || prev == "--export-vcon" {
            argv[i] = FIXTURE_CALL_ID.to_owned();
        } else if prev == "-d" || prev == "--device" {
            // The page's interface, replaced by one that cannot exist. Opening
            // the real one would capture traffic on whoever runs this suite,
            // and the flags parse identically either way.
            argv[i] = FAKE_DEVICE.to_owned();
        }
    }
    let names_device = argv.iter().any(|a| a == "-d" || a == "--device");
    if !names_device && !argv.iter().any(|a| a == "-I" || a == "--input") {
        argv.push("-I".to_owned());
        argv.push(fixture);
    }
    // Never open a TUI from a test: it would take the terminal.
    if !argv.iter().any(|a| a == "-N" || a == "--no-tui") {
        argv.push("-N".to_owned());
    }
    Some(Prepared { argv, env })
}

/// A small POSIX-ish word split: quotes respected, no expansion.
///
/// Not `shlex`: one more dependency for one call site, and the documented
/// commands use nothing more exotic than quoting. A construct this cannot split
/// returns `None` and the caller reports it rather than guessing.
fn shell_words(s: &str) -> Option<Vec<String>> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut any = false;
    for ch in s.chars() {
        match (quote, ch) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), c) => cur.push(c),
            (None, '\'' | '"') => {
                quote = Some(ch);
                any = true;
            }
            (None, c) if c.is_whitespace() => {
                if !cur.is_empty() || any {
                    out.push(std::mem::take(&mut cur));
                    any = false;
                }
            }
            (None, '$' | '`' | '(' | ')') => return None,
            (None, c) => cur.push(c),
        }
    }
    if quote.is_some() {
        return None;
    }
    if !cur.is_empty() || any {
        out.push(cur);
    }
    Some(out)
}

/// clap's refusal, told apart from sipnab's own runtime errors.
///
/// clap writes a bare `error: …` to stderr. sipnab's errors go through tracing
/// and carry a timestamp, so the two are distinguishable without parsing either.
fn usage_error(stderr: &str) -> Option<String> {
    stderr
        .lines()
        .map(|l| {
            // Strip ANSI so a colored line is still recognizable.
            regex::Regex::new(r"\x1b\[[0-9;]*m")
                .expect("regex")
                .replace_all(l, "")
                .into_owned()
        })
        .find(|l| {
            let t = l.trim_start();
            t.starts_with("error: ") || t.starts_with("error:")
        })
        .map(|l| l.trim().to_owned())
}

/// Every documented command runs, or is one of two named exceptions.
#[test]
fn every_documented_command_runs_or_says_why_not() {
    let all = documented_invocations();
    assert!(
        all.len() >= 200,
        "only {} documented sipnab invocation(s) found — the extractor stopped \
         matching, so a green run here proves nothing",
        all.len()
    );

    let sandbox = std::env::temp_dir().join(format!(
        "sipnab-doc-commands-{}-{}",
        std::process::id(),
        all.len()
    ));
    std::fs::create_dir_all(&sandbox).expect("a sandbox directory");

    let mut tally: BTreeMap<Plan, usize> = BTreeMap::new();
    let mut unsplittable = Vec::new();
    let mut failures = Vec::new();
    // Servers are spawned together and judged after ONE wait, so 24 of them
    // cost one bound rather than 24.
    let mut pending: Vec<(Invocation, std::process::Child)> = Vec::new();
    let mut ran = 0_usize;

    for (n, inv) in all.iter().enumerate() {
        let plan = classify(&inv.text);
        *tally.entry(plan).or_default() += 1;
        if !plan.is_run() {
            continue;
        }
        let Some(Prepared { argv, env }) = prepare(&inv.text, &sandbox, n) else {
            unsplittable.push(inv.clone());
            continue;
        };
        let mut c = Command::new(&argv[0]);
        c.args(&argv[1..]).current_dir(repo());
        for (k, v) in env {
            c.env(k, v);
        }
        ran += 1;
        if plan == Plan::Bounded {
            c.stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());
            match c.spawn() {
                Ok(child) => pending.push((inv.clone(), child)),
                Err(e) => failures.push(format!("{}:{} could not spawn: {e}", inv.page, inv.line)),
            }
            continue;
        }
        let out = c.output().expect("the binary under test is runnable");
        if let Some(err) = usage_error(&String::from_utf8_lossy(&out.stderr)) {
            failures.push(format!(
                "{}:{}\n    {}\n    -> {}",
                inv.page, inv.line, inv.text, err
            ));
        }
    }

    // One bound for every server. clap refuses in milliseconds, so a process
    // still alive here necessarily parsed its arguments.
    if !pending.is_empty() {
        std::thread::sleep(std::time::Duration::from_millis(1500));
    }
    for (inv, mut child) in pending {
        let still_running = matches!(child.try_wait(), Ok(None));
        if still_running {
            let _ = child.kill();
        }
        let out = child
            .wait_with_output()
            .expect("a spawned child is waitable");
        if still_running {
            continue; // Got past parsing, which is all this can prove.
        }
        if let Some(err) = usage_error(&String::from_utf8_lossy(&out.stderr)) {
            failures.push(format!(
                "{}:{}\n    {}\n    -> {}",
                inv.page, inv.line, inv.text, err
            ));
        }
    }

    // Remove the sandbox before asserting, so a failure does not leave it behind.
    let _ = std::fs::remove_dir_all(&sandbox);

    // Reported, not merely asserted. A reader of a green run should be able to
    // see how much of the documentation it actually executed, because the
    // difference between "343 ran" and "3 ran, 349 skipped" is the difference
    // between a gate and a decoration.
    println!(
        "documented sipnab invocations: {} total, {ran} executed, {} not run — {:?}",
        all.len(),
        all.len() - ran,
        tally
    );

    assert!(
        unsplittable.is_empty(),
        "these documented commands could not be split into words, so they were \
         neither run nor declared unrunnable. Either simplify the example or \
         teach this test the construct:\n{}",
        unsplittable
            .iter()
            .map(|i| format!("  {}:{} {}", i.page, i.line, i.text))
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert!(
        failures.is_empty(),
        "{} documented command(s) sipnab refuses. A reader copying one of these \
         gets an error and assumes they typed it wrong:\n\n{}",
        failures.len(),
        failures.join("\n\n")
    );
    assert!(
        ran * 10 >= all.len() * 9,
        "only {ran} of {} documented invocation(s) ran — under nine in ten. A \
         classifier that quietly widened would make this gate cover almost \
         nothing. Tally: {tally:?}",
        all.len()
    );
}

/// Nothing is left un-run without a stated reason.
///
/// The bucket names are the whole point: "skipped" without a reason is where a
/// gate goes to stop working.
#[test]
fn nothing_is_left_unrun_without_a_reason() {
    let all = documented_invocations();
    let mut unrun = 0;
    for inv in &all {
        let plan = classify(&inv.text);
        assert!(
            !plan.why().is_empty(),
            "{}:{} has no stated plan",
            inv.page,
            inv.line
        );
        if !plan.is_run() {
            unrun += 1;
        }
    }
    assert!(
        unrun > 0,
        "every documented command was classified as runnable, which cannot be \
         right: the docs show exec hooks and uprobe capture, and this suite \
         must run neither"
    );
    assert!(
        unrun * 10 < all.len(),
        "{unrun} of {} documented invocations are not run — more than one in \
         ten. The classifier has widened.",
        all.len()
    );
}

/// The two never-run buckets are the two that would do something to the host.
///
/// Not a style rule. A gate that ran `--on-quality-exec 'curl -X POST
/// http://hook/quality'` would POST to a stranger's endpoint on every test run,
/// and one that ran `--uprobe-tls` would load probes into whatever machine is
/// building sipnab.
#[test]
fn the_never_run_buckets_are_the_dangerous_ones() {
    for cmd in [
        "sipnab -N -d eth0 --on-dialog-exec '/usr/local/bin/call-logger'",
        "sipnab -N -I trunk.pcap --on-quality-exec 'curl -m 30 -X POST http://hook/quality'",
        "sipnab -N --uprobe-tls",
        "sipnab -N --uprobe-tls --uprobe-backend bpf --portrange 0-65535",
    ] {
        assert_eq!(
            classify(cmd),
            Plan::SideEffects,
            "{cmd:?} would be RUN by this gate"
        );
    }
    // And the ordinary ones are not swept up with them.
    assert_eq!(classify("sipnab -N -I capture.pcap --json"), Plan::Reads);
    assert_eq!(
        classify("sudo sipnab -d eth0 --portrange 5060-5061"),
        Plan::ReadsFakeDevice
    );
    assert_eq!(classify("sipnab --api 127.0.0.1:8080"), Plan::Bounded);
}

/// The usage-error detector fires on a real refusal and not on ordinary output.
///
/// Without this, a detector that matched nothing would certify every command.
#[test]
fn the_usage_error_detector_discriminates() {
    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(["--definitely-not-a-flag"])
        .current_dir(repo())
        .output()
        .expect("runnable");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        usage_error(&stderr).is_some(),
        "sipnab refused an unknown flag and the detector did not see it. \
         stderr was:\n{stderr}"
    );

    let ok = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(["-N", "-q", "-I", FIXTURE])
        .current_dir(repo())
        .output()
        .expect("runnable");
    let ok_err = String::from_utf8_lossy(&ok.stderr);
    assert!(
        usage_error(&ok_err).is_none(),
        "a perfectly good command was read as a usage error, so this gate would \
         fail on working documentation. stderr was:\n{ok_err}"
    );
}
