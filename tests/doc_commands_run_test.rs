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

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use clap::CommandFactory;

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
    /// Not run: it acts on the HOST. `--on-dialog-exec` / `--on-quality-exec`
    /// run a command of their own; `--uprobe-tls` attaches to the kernel;
    /// `--setup-caps` re-invokes through sudo and runs `setcap` on the binary;
    /// `--wireshark` launches a GUI. A documentation gate must not `curl` a
    /// stranger's endpoint, load probes, escalate privilege, or open a window
    /// on whatever machine runs the suite. `--setup-caps` was missed at first,
    /// and the gate ran `sudo setcap` four times before this caught it.
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
            Self::SideEffects => "acts on the host: exec, kernel probe, sudo, or a GUI",
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
    let side_effects = regex::Regex::new(
        r"(^|\s)(--on-[a-z-]+-exec|--uprobe-tls|--uprobe-backend|--setup-caps|--wireshark)(\s|=|$)",
    )
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
        regex::Regex::new(r"(^|\s)(--api|--mcp|--metrics|-L|--hep-listen)(\s|=|$)").expect("regex");
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

/// The one flag in this file that is deliberately NOT a sipnab flag: the probe
/// `the_usage_error_detector_discriminates` hands the binary to watch clap
/// refuse it. Held in exactly one place, so the check that every other flag
/// named here is real can exempt it without exempting anything else.
const DELIBERATE_NON_FLAG: &str = "--definitely-not-a-flag";

/// Flags whose address sipnab BINDS. Rewritten to `127.0.0.1:0`.
///
/// The documentation binds `0.0.0.0:9100`, `0.0.0.0:9060`, `0.0.0.0:8731` --
/// correct for an operator, and a real listener on every interface of whatever
/// machine runs this suite, on ports other software already uses.
const BIND_FLAGS: &[&str] = &["--api", "--mcp-bind", "--metrics", "-L", "--hep-listen"];

/// Flags naming a destination sipnab TRANSMITS to. Rewritten to `127.0.0.1:9`,
/// the discard port, so nothing leaves the host and no name is resolved.
///
/// `--hep-send homer.example.com:9060` resolves a real domain and sends HEP to
/// it, and `--rtpengine-control` would query any relay a developer happens to
/// run on the documented port.
const SEND_FLAGS: &[&str] = &["-H", "--hep-send", "--rtpengine-control"];

/// Flags whose address value only FILTERS what sipnab accepts. Left as the page
/// wrote them: rewriting an allowlist would test a different command.
const ADDRESS_FILTER_FLAGS: &[&str] = &["--hep-allow", "--mcp-allowed-host"];

/// Where a bind is sent.
const LOOPBACK_BIND: &str = "127.0.0.1:0";

/// Where a transmission is sent.
const LOOPBACK_DISCARD: &str = "127.0.0.1:9";

/// Drop a trailing shell redirection or comment: the shell's, not sipnab's.
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
            // A `#` at a word boundary, outside quotes, begins a shell comment;
            // the rest of the line is the shell's, not sipnab's. Without this,
            // `--report  # RFC 2833 / telephone-event` handed sipnab `#`, `RFC`,
            // `2833`, `/` and the rest as trailing BPF-filter arguments, and the
            // `/` read as a path escaping the sandbox.
            (None, '#') if out.is_empty() || out.ends_with(char::is_whitespace) => {
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
///
/// Two of the original entries, `--hosts` and `--srtp-key-file`, were never
/// sipnab flags: typed from memory, and a list is only auditable if something
/// audits it. `every_flag_this_gate_names_is_one_the_cli_defines` does now.
const INPUT_FILE_FLAGS: &[&str] = &[
    "--lint-suppress-file",
    "--srtp-keys",
    "--keylog",
    "--config",
];

/// One documented command, ready to run: its argv and the environment the
/// example set in front of it.
///
/// Named rather than returned as a nested tuple, which clippy reads as a very
/// complex type and a reader reads as two anonymous halves.
struct Prepared {
    argv: Vec<String>,
    env: Vec<(String, String)>,
    /// The directory the command runs in: its own, inside the sandbox.
    ///
    /// Never the repository. A documented `--run-provenance-file runs.jsonl`
    /// is a RELATIVE path, and relative to the repository root it wrote beside
    /// the source on every test run until this existed.
    cwd: PathBuf,
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

    let cwd = sandbox.join(format!("cmd-{n}"));
    std::fs::create_dir_all(&cwd).expect("a per-command directory in the sandbox");
    let paths = path_flags();
    let fixture = repo().join(FIXTURE).display().to_string();
    for i in 1..argv.len() {
        let prev = argv[i - 1].clone();
        if prev == "-I" || prev == "--input" {
            // Resolved against the repository and made ABSOLUTE, because the
            // command no longer runs from the repository root.
            let in_repo = repo().join(&argv[i]);
            if !argv[i].starts_with('/') && in_repo.exists() {
                argv[i] = in_repo.display().to_string();
            } else {
                argv[i].clone_from(&fixture);
            }
        } else if INPUT_FILE_FLAGS.contains(&prev.as_str()) {
            let p = cwd.join("input");
            std::fs::write(&p, "").expect("the sandbox is writable");
            argv[i] = p.display().to_string();
        } else if let Some(&is_dir) = paths.get(prev.as_str()) {
            let in_repo = repo().join(&argv[i]);
            if !argv[i].starts_with('/') && in_repo.exists() {
                // A read-only input the repository really has, such as
                // `--mcp-file-root tests/pcap-samples`.
                argv[i] = in_repo.display().to_string();
            } else {
                // Everything else lands in this command's own directory, by
                // the file name the page used, so `/var/log/sipnab-mcp.jsonl`
                // and `./redact-map.json` both stay inside the sandbox.
                let name = Path::new(&argv[i])
                    .file_name()
                    .map_or_else(|| "path".to_owned(), |f| f.to_string_lossy().into_owned());
                let target = cwd.join(name);
                if is_dir {
                    std::fs::create_dir_all(&target).expect("a directory in the sandbox");
                }
                argv[i] = target.display().to_string();
            }
        } else if BIND_FLAGS.contains(&prev.as_str()) {
            argv[i] = LOOPBACK_BIND.to_owned();
        } else if SEND_FLAGS.contains(&prev.as_str()) {
            argv[i] = LOOPBACK_DISCARD.to_owned();
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
    Some(Prepared { argv, env, cwd })
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
        let Some(Prepared { argv, env, cwd }) = prepare(&inv.text, &sandbox, n) else {
            unsplittable.push(inv.clone());
            continue;
        };
        let mut c = Command::new(&argv[0]);
        c.args(&argv[1..]).current_dir(&cwd);
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
        .args([DELIBERATE_NON_FLAG])
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

// ── The documentation runs somewhere it cannot touch the repository ────

/// The flags whose value is a filesystem path, read from the CLI definition.
///
/// Derived rather than listed. The first version of this gate kept a hand list
/// of six output flags, the documentation used eighteen more, and
/// `--run-provenance-file runs.jsonl` and `--redact-map ./redact-map.json`
/// wrote straight into the repository root on every test run -- beside the
/// source, untracked, and appended to each time. A list only covers the flags
/// somebody remembered.
///
/// `-I` / `--input` is excluded: an input is resolved against the repository
/// or replaced by the fixture, never sent to the sandbox.
fn path_flags() -> &'static BTreeMap<String, bool> {
    static FLAGS: std::sync::OnceLock<BTreeMap<String, bool>> = std::sync::OnceLock::new();
    FLAGS.get_or_init(derive_path_flags)
}

/// The walk behind [`path_flags`].
fn derive_path_flags() -> BTreeMap<String, bool> {
    let mut out = BTreeMap::new();
    for arg in sipnab::cli::Cli::command().get_arguments() {
        let Some(names) = arg.get_value_names() else {
            continue;
        };
        // Split each value name into word tokens and match one exactly.
        // "PROFILE" contains "FILE" as a substring; it is not a file. A value
        // name may be `FILE|DIR|GLOB` or `ADDR[:PORT-RANGE]`, so the separators
        // are every non-letter.
        let tokens: Vec<String> = names
            .iter()
            .flat_map(|n| {
                n.to_string()
                    .to_uppercase()
                    .split(|c: char| !c.is_ascii_alphabetic())
                    .filter(|t| !t.is_empty())
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .collect();
        let is_path = tokens
            .iter()
            .any(|t| matches!(t.as_str(), "FILE" | "DIR" | "PATH" | "OUTPUT"));
        if !is_path || arg.get_long() == Some("input") {
            continue;
        }
        let is_dir = tokens.iter().any(|t| t == "DIR");
        if let Some(long) = arg.get_long() {
            out.insert(format!("--{long}"), is_dir);
        }
        if let Some(short) = arg.get_short() {
            out.insert(format!("-{short}"), is_dir);
        }
    }
    out
}

/// No argument handed to sipnab names a path outside the sandbox or the
/// repository's own read-only inputs.
///
/// Checked on every runnable documented invocation, so a flag the derivation
/// misses surfaces here by name instead of as a file somebody finds later in
/// `/var/log` or the repository root.
#[test]
fn no_argument_names_a_path_outside_the_sandbox_or_the_repository() {
    let sandbox = std::env::temp_dir().join(format!("sipnab-doc-paths-{}", std::process::id()));
    std::fs::create_dir_all(&sandbox).expect("a sandbox directory");
    let binary = env!("CARGO_BIN_EXE_sipnab");
    let mut escapes = Vec::new();
    let mut checked = 0_usize;
    for (n, inv) in documented_invocations().iter().enumerate() {
        if !classify(&inv.text).is_run() {
            continue;
        }
        let Some(p) = prepare(&inv.text, &sandbox, n) else {
            continue;
        };
        checked += 1;
        if !p.cwd.starts_with(&sandbox) {
            escapes.push(format!(
                "{}:{} runs in {}, outside the sandbox",
                inv.page,
                inv.line,
                p.cwd.display()
            ));
        }
        for token in &p.argv[1..] {
            let value = token.split_once('=').map_or(token.as_str(), |(_, v)| v);
            if !value.starts_with('/') {
                continue;
            }
            let inside = Path::new(value).starts_with(&sandbox)
                || Path::new(value).starts_with(repo())
                || value == binary;
            if !inside {
                escapes.push(format!("{}:{} hands sipnab {value}", inv.page, inv.line));
            }
        }
    }
    let _ = std::fs::remove_dir_all(&sandbox);
    assert!(checked >= 200, "only {checked} invocation(s) were prepared");
    assert!(
        escapes.is_empty(),
        "{} documented invocation(s) would read or write outside the sandbox \
         and the repository's inputs:\n{}",
        escapes.len(),
        escapes.join("\n")
    );
}

/// The path flags come from the CLI, and they include the ones that leaked.
#[test]
fn the_path_flags_are_read_from_the_cli_not_listed_by_hand() {
    let flags = path_flags();
    assert!(
        flags.len() >= 25,
        "only {} path-taking flag(s) derived from the CLI: {:?}. The value-name \
         scan stopped matching, and everything it misses runs unsandboxed.",
        flags.len(),
        flags.keys().collect::<Vec<_>>()
    );
    for leaked in [
        "--run-provenance-file",
        "--redact-map",
        "--tui-audit-file",
        "--mcp-audit-file",
        "--export-vcon-dir",
        "--output",
        "-O",
    ] {
        assert!(
            flags.contains_key(leaked),
            "{leaked} takes a path and is not in the derived set"
        );
    }
    assert_eq!(
        flags.get("--export-vcon-dir"),
        Some(&true),
        "a DIR flag must be marked as one"
    );
    assert!(
        !flags.contains_key("--input") && !flags.contains_key("-I"),
        "the input flag is resolved against the repository, never sandboxed"
    );
}

/// A documented example that writes a relative file writes it in the sandbox.
///
/// The effect, not the argv: the very line that left `runs.jsonl` in the
/// repository root, run through the same preparation the gate uses.
#[test]
fn a_documented_relative_output_lands_in_the_sandbox_not_the_repository() {
    let doc = std::fs::read_to_string(repo().join("docs/examples.md")).expect("examples.md");
    let line = doc
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with("sipnab ") && l.contains("--run-provenance-file runs.jsonl"))
        .expect("docs/examples.md no longer carries the runs.jsonl example this pins");

    let before = std::fs::metadata(repo().join("runs.jsonl"))
        .ok()
        .and_then(|m| m.modified().ok());
    let sandbox = std::env::temp_dir().join(format!("sipnab-doc-relative-{}", std::process::id()));
    std::fs::create_dir_all(&sandbox).expect("a sandbox directory");
    let p = prepare(line, &sandbox, 0).expect("the example splits into words");
    let out = Command::new(&p.argv[0])
        .args(&p.argv[1..])
        .current_dir(&p.cwd)
        .output()
        .expect("runnable");
    let written_in_sandbox = std::fs::read_dir(&p.cwd)
        .map(|d| {
            d.flatten()
                .any(|e| e.file_name().to_string_lossy().contains("runs"))
        })
        .unwrap_or(false);
    let after = std::fs::metadata(repo().join("runs.jsonl"))
        .ok()
        .and_then(|m| m.modified().ok());
    let _ = std::fs::remove_dir_all(&sandbox);

    assert!(
        written_in_sandbox,
        "the provenance record did not appear in the sandbox. stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        before, after,
        "running the documented example touched runs.jsonl in the repository \
         root, which is the defect this exists to prevent"
    );
}

// ── Every flag this gate names by hand is one sipnab has ───────────────

/// Every long and short name the CLI accepts, from clap.
fn cli_flag_names() -> BTreeSet<String> {
    let mut names = BTreeSet::from(["--help".to_owned(), "--version".to_owned()]);
    for arg in sipnab::cli::Cli::command().get_arguments() {
        if let Some(long) = arg.get_long() {
            names.insert(format!("--{long}"));
        }
        if let Some(aliases) = arg.get_all_aliases() {
            names.extend(aliases.into_iter().map(|a| format!("--{a}")));
        }
        if let Some(short) = arg.get_short() {
            names.insert(format!("-{short}"));
        }
    }
    names
}

/// Every flag name written inside a string literal in this file's code.
///
/// Comments are skipped: prose may discuss a flag that no longer exists. What
/// the gate actually MATCHES and SUBSTITUTES on is in its literals and regexes,
/// and that is where five invented names sat.
fn flag_names_this_file_uses() -> BTreeSet<String> {
    let src = std::fs::read_to_string(repo().join("tests/doc_commands_run_test.rs"))
        .expect("this test's own source");
    let code: String = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    let literal = regex::Regex::new(r#"r?"((?:[^"\\]|\\.)*)""#).expect("regex");
    let long = regex::Regex::new(r"(?:^|[\s|(=\[`])(--[a-z][a-z0-9-]*[a-z0-9])(?:[\s|)=\]`]|$)")
        .expect("regex");
    let short = regex::Regex::new(r"(?:^|[\s|(\[`])(-[A-Za-z])(?:[\s|)=\]`]|$)").expect("regex");
    let mut out = BTreeSet::new();
    for lit in literal.captures_iter(&code) {
        let body = lit.get(1).map_or("", |m| m.as_str());
        for re in [&long, &short] {
            for c in re.captures_iter(body) {
                out.insert(c[1].to_owned());
            }
        }
    }
    out
}

/// Every flag name this gate matches or substitutes on is one the CLI defines.
///
/// The defect this pays for: `--hosts`, `--srtp-key-file`, `--metrics-only`,
/// `--watch` and `--wav-out` were all in this file, typed from memory, and none
/// was ever a sipnab flag. A pattern that names a flag nothing accepts matches
/// nothing, so it failed silently -- and `--metrics`, which does start a
/// listener, was missing from the server pattern the whole time.
#[test]
fn every_flag_this_gate_names_is_one_the_cli_defines() {
    let real = cli_flag_names();
    assert!(
        real.len() >= 150 && real.contains("--input"),
        "only {} CLI flag name(s) read from clap: the walk is broken",
        real.len()
    );
    let used = flag_names_this_file_uses();
    assert!(
        used.contains("--call-report") && used.contains("-O"),
        "the literal scan found {used:?}, which misses flags this file plainly \
         uses: it is not reading the code"
    );
    let invented: Vec<&String> = used
        .iter()
        .filter(|f| f.as_str() != DELIBERATE_NON_FLAG && !real.contains(f.as_str()))
        .collect();
    assert!(
        invented.is_empty(),
        "this gate names flag(s) sipnab does not have: {invented:?}. A pattern \
         on a flag nothing accepts matches nothing and says so to nobody."
    );
}

/// Every input-file flag takes a path, per the CLI.
///
/// Being a real flag is not enough: writing an empty file for a flag whose
/// value is a mode or a number would hand sipnab a path where it expects
/// something else, and the refusal would read as a documentation error.
#[test]
fn every_input_file_flag_takes_a_path() {
    let paths = path_flags();
    for f in INPUT_FILE_FLAGS {
        assert!(
            paths.contains_key(*f),
            "INPUT_FILE_FLAGS names {f}, which the CLI does not declare as \
             taking a file or directory"
        );
    }
}

/// The only non-flag in this file is the detector's probe, held in one place.
///
/// The check above exempts exactly that name. If the exemption could be used
/// twice, a real typo spelled like a probe would pass it.
#[test]
fn the_only_non_flag_in_this_file_is_the_detectors_probe() {
    let src = std::fs::read_to_string(repo().join("tests/doc_commands_run_test.rs"))
        .expect("this test's own source");
    let code: String = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(
        code.matches(&format!("\"{DELIBERATE_NON_FLAG}\"")).count(),
        1,
        "{DELIBERATE_NON_FLAG} must be spelled as a literal exactly once -- in \
         its constant -- so the exemption covers one probe and no typo"
    );
    let real = cli_flag_names();
    let non_flags: Vec<String> = flag_names_this_file_uses()
        .into_iter()
        .filter(|f| !real.contains(f))
        .collect();
    assert_eq!(
        non_flags,
        vec![DELIBERATE_NON_FLAG.to_owned()],
        "the non-flags named in this file must be exactly the detector's probe"
    );
    assert!(
        !real.contains(DELIBERATE_NON_FLAG),
        "{DELIBERATE_NON_FLAG} became a real flag, so the detector test would \
         watch clap ACCEPT it"
    );
}

// ── ...and cannot reach the network either ──────────────────────────────

/// Every flag whose value is a network address or host, from clap.
///
/// Matched on the value NAME exactly (`ADDR`, `HOST`), not as a substring:
/// `--mcp-transport <TRANSPORT>` contains "PORT" and is not an address.
fn address_flags() -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for arg in sipnab::cli::Cli::command().get_arguments() {
        let Some(names) = arg.get_value_names() else {
            continue;
        };
        if !names.iter().any(|n| {
            let n = n.to_string();
            n == "ADDR" || n == "HOST"
        }) {
            continue;
        }
        if let Some(long) = arg.get_long() {
            out.insert(format!("--{long}"));
        }
        if let Some(short) = arg.get_short() {
            out.insert(format!("-{short}"));
        }
    }
    out
}

/// Every address flag is classified as a bind, a send, or a filter.
///
/// The three tables are hand-written because meaning is not in the CLI
/// definition -- `ADDR` names a bind, a destination and an allowlist alike. So
/// the tables are audited against clap in both directions: a new address flag
/// fails here until someone decides what it does, and a table entry that is
/// not an address flag fails too.
#[test]
fn every_address_flag_is_classified_as_a_bind_a_send_or_a_filter() {
    let derived = address_flags();
    assert!(
        derived.contains("--api") && derived.contains("--hep-send") && derived.len() >= 8,
        "only {} address flag(s) derived from the CLI: {derived:?}",
        derived.len()
    );
    let mut seen = BTreeMap::new();
    for (table, flags) in [
        ("BIND_FLAGS", BIND_FLAGS),
        ("SEND_FLAGS", SEND_FLAGS),
        ("ADDRESS_FILTER_FLAGS", ADDRESS_FILTER_FLAGS),
    ] {
        for f in flags {
            assert!(
                derived.contains(*f),
                "{table} names {f}, which the CLI does not declare as taking an address"
            );
            if let Some(other) = seen.insert(*f, table) {
                panic!("{f} is in both {other} and {table}");
            }
        }
    }
    let unclassified: Vec<&String> = derived
        .iter()
        .filter(|f| !seen.contains_key(f.as_str()))
        .collect();
    assert!(
        unclassified.is_empty(),
        "these address flags are in no table, so a documented command using one \
         would run with the page's own address: {unclassified:?}"
    );
}

/// No documented command, as run, binds anything but loopback or transmits
/// anywhere but the discard port.
#[test]
fn no_documented_command_binds_publicly_or_transmits_off_the_host() {
    let sandbox = std::env::temp_dir().join(format!("sipnab-doc-addrs-{}", std::process::id()));
    std::fs::create_dir_all(&sandbox).expect("a sandbox directory");
    let mut offenses = Vec::new();
    let mut addressed = 0_usize;
    for (n, inv) in documented_invocations().iter().enumerate() {
        if !classify(&inv.text).is_run() {
            continue;
        }
        let Some(p) = prepare(&inv.text, &sandbox, n) else {
            continue;
        };
        for pair in p.argv.windows(2) {
            let (flag, value) = (pair[0].as_str(), pair[1].as_str());
            let expected = if BIND_FLAGS.contains(&flag) {
                LOOPBACK_BIND
            } else if SEND_FLAGS.contains(&flag) {
                LOOPBACK_DISCARD
            } else {
                continue;
            };
            addressed += 1;
            if value != expected {
                offenses.push(format!("{}:{} runs {flag} {value}", inv.page, inv.line));
            }
        }
    }
    let _ = std::fs::remove_dir_all(&sandbox);
    assert!(
        addressed >= 10,
        "only {addressed} bind or send argument(s) seen across the documentation, \
         which names at least a dozen: the check is not reaching them"
    );
    assert!(
        offenses.is_empty(),
        "these documented commands would bind publicly or transmit off the \
         host when run:\n{}",
        offenses.join("\n")
    );
}

// ── Three defects this gate shipped, each with a test that would have caught it ──

/// A trailing shell comment is not handed to sipnab as arguments.
///
/// `sipnab ... --report  # RFC 2833 / telephone-event` ran with `#`, `RFC`,
/// `2833`, `/` and the rest as trailing BPF-filter positionals, and the bare
/// `/` read as a path escaping the sandbox. `strip_redirection` drops a `#`
/// that begins a word, the way the shell does.
#[test]
fn a_trailing_shell_comment_is_not_passed_as_arguments() {
    let stripped =
        strip_redirection("sipnab -N -I capture.pcap --report  # RFC 2833 / telephone-event");
    assert_eq!(
        stripped, "sipnab -N -I capture.pcap --report",
        "the comment survived into the command line"
    );
    // A `#` INSIDE a word (a fragment identifier, say) is not a comment.
    assert_eq!(
        strip_redirection("sipnab show-frame cap.pcap#5@abcd"),
        "sipnab show-frame cap.pcap#5@abcd",
        "a # mid-word is not a comment and must be kept"
    );
    // A `#` inside quotes is literal.
    assert_eq!(
        strip_redirection(r#"sipnab --filter "a # b""#),
        r#"sipnab --filter "a # b""#,
        "a quoted # is not a comment"
    );
}

/// A value-name containing FILE as a substring is not a path flag.
///
/// `--capture-profile <PROFILE>` and `--mcp-tools <PROFILE>` take a named
/// profile, not a path. "PROFILE".contains("FILE") is true, so the first
/// version of `path_flags` replaced their values with sandbox paths and sipnab
/// refused `/tmp/.../signaling` and `/tmp/.../core` as invalid profiles.
#[test]
fn a_profile_flag_is_not_mistaken_for_a_path() {
    let paths = path_flags();
    for not_a_path in ["--capture-profile", "--mcp-tools"] {
        assert!(
            !paths.contains_key(not_a_path),
            "{not_a_path} takes a PROFILE, not a path, but path_flags lists it \
             -- its value would be replaced with a sandbox path sipnab refuses"
        );
    }
    // The real path flags are still found.
    for is_a_path in ["--output", "--mcp-file-root", "--run-provenance-file"] {
        assert!(
            paths.contains_key(is_a_path),
            "{is_a_path} is a path flag and went missing"
        );
    }
}

/// A command that escalates privilege or opens a GUI is never run.
///
/// `--setup-caps` re-invokes sipnab through sudo and runs `setcap
/// cap_net_raw,cap_net_admin+ep` on the binary; `--wireshark` launches a GUI.
/// Both were classified `Reads` at first, and on a host with passwordless sudo
/// the gate ran `sudo setcap` four times -- granting the debug binary the very
/// capability whose absence the capture-probe tests then measured.
#[test]
fn a_privilege_escalation_or_gui_launch_is_never_run() {
    for cmd in [
        "sipnab --setup-caps",
        "sudo sipnab --setup-caps",
        "sipnab -N -I capture.pcap --wireshark",
    ] {
        assert_eq!(
            classify(cmd),
            Plan::SideEffects,
            "{cmd:?} would be RUN by this gate, and it acts on the host"
        );
    }
    // An ordinary read beside them is not swept up.
    assert_eq!(classify("sipnab -N -I capture.pcap --report"), Plan::Reads);
}
