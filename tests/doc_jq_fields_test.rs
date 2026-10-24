// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Every field the docs tell a reader to `jq` must exist in the output the
//! same block produces.
//!
//! This gate exists because of a specific failure. `cli-reference.md` shipped
//!
//! ```text
//! sipnab -N -I capture.pcap --json | jq -r '.user_agent // empty' | sort -u
//! ```
//!
//! as the recipe for "distinct User-Agents". The NDJSON field is `ua`, so the
//! pipeline matched nothing, and `// empty` swallowed the miss: a reader got
//! zero lines and concluded the capture held no User-Agents. Nothing failed,
//! nothing warned, and the answer was wrong. That is worse than a broken
//! command, which at least announces itself.
//!
//! Prose review cannot catch this — `.user_agent` reads perfectly well. Only
//! running it against real output can, which is what this does: no `jq`
//! binary is required, because the check is "does this key exist in what the
//! documented mode emits", and that is answerable from the JSON itself.

#![cfg(feature = "native")]

use std::collections::BTreeSet;
use std::path::Path;

/// The error a fallible test returns: any error, boxed, so `?` works on
/// I/O, parse and JSON errors alike.
type TestError = Box<dyn std::error::Error>;

/// A documented pipeline: the output mode a block invokes, and the fields its
/// `jq` reads from it.
#[derive(Debug)]
struct Recipe {
    doc: String,
    mode: Mode,
    fields: BTreeSet<String>,
    /// The block's own `sipnab` command, up to its first pipe: what a
    /// [`Mode::Query`] recipe is checked against.
    command: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Mode {
    /// A one-shot query flag (`--timeline` and the rest of the family): one
    /// JSON answer, whose shape depends on the flag and its arguments, so the
    /// block's own command is run rather than a fixed one.
    Query(&'static str),
    /// `--json`: one object per SIP message.
    Messages,
    /// `--json-dialogs`: one object per dialog.
    Dialogs,
    /// `--json-stun`: one object per STUN/TURN transaction or TURN allocation.
    Stun,
    /// `--json-analyze`: one object for the whole capture analysis.
    Analyze,
}

/// Fields that are legitimately absent from a flat key scan.
///
/// `jq` reaches into nested objects and arrays. Since 0.5.131 the harvester
/// walks objects AND the object elements of arrays to depth 3, so most nested
/// readers now resolve on their own and this list is much shorter than the
/// behavior it once compensated for.
///
/// What remains is the residue the harvester cannot see from a sample run:
/// a field that is OPTIONAL and absent from every fixture, or one whose name
/// differs by surface. Each entry says which, because an unexplained
/// allowance is indistinguishable from a silenced failure.
const NESTED_OR_DERIVED: &[&str] = &[
    "mos",               // inside .streams[] / .rtp
    "ssrc",              // inside .streams[]
    "dialogs",           // a wrapper the REST API returns, not NDJSON
    "streams",           // present on dialogs, read as an array
    "associated_dialog", // stream-scoped
    "duration_sec",      // dialog-scoped, name varies by surface
    "from_user",         // dialog-scoped
    "severity",          // inside .findings[] of --json-analyze, an ARRAY element
    "to_user",           // dialog-scoped
    "state",             // dialog-scoped
    // OPTIONAL and absent from every fixture: `src/output/json.rs:221`
    // declares `burst_gap: Option<BurstGapAnalysis>` on a stream, filled at
    // `:909` from `stream.burst_gap_analysis()`. It appears only when a stream
    // has enough loss to analyze, and none of the committed captures do — so
    // the harvester cannot learn it from a sample however deep it walks. The
    // field is real; verified in the source, and observed on real traffic.
    "burst_gap",
    // A line of `--report --json`, not of the per-message `--json` stream
    // this gate harvests, and only on a run that read a stored vCon
    // container (src/output/dialog_report.rs `VCON_CONTAINERS_JSON_KEY`).
    // tests/vcon_directory_report_test.rs runs the documented command shape
    // and reads the key from the real output.
    "sipnab_vcon_containers",
];

/// Pull `sipnab ... --json* ... | jq '...'` pairs out of fenced blocks.
fn recipes() -> Result<Vec<Recipe>, TestError> {
    let mut out = Vec::new();
    let docs = std::fs::read_dir("docs").map_err(|e| format!("docs/ must exist: {e}"))?;
    for entry in docs.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("md") {
            continue;
        }
        let text = std::fs::read_to_string(&path).map_err(|e| format!("read doc: {e}"))?;
        let name = path
            .file_name()
            .ok_or("a doc path has a file name")?
            .to_string_lossy()
            .to_string();

        for block in text.split("```").skip(1).step_by(2) {
            if !block.contains("sipnab") || !block.contains("jq") {
                continue;
            }
            // Every longer flag must be tested before `--json`, which is a
            // prefix of all of them. Getting this order wrong is not a
            // near-miss: a `--json-stun` recipe checked against `--json`'s key
            // set reports every one of its real fields as missing, which is
            // how this gate first met `--json-stun` and `--json-analyze`.
            let query = query_flags().into_iter().find(|q| {
                block
                    .split_whitespace()
                    .any(|w| w.split('=').next() == Some(*q))
            });
            let mode = if let Some(flag) = query {
                Mode::Query(flag)
            } else if block.contains("--json-dialogs") {
                Mode::Dialogs
            } else if block.contains("--json-stun") {
                Mode::Stun
            } else if block.contains("--json-analyze") {
                Mode::Analyze
            } else if block.contains("--json") {
                Mode::Messages
            } else {
                continue;
            };

            let mut fields = BTreeSet::new();
            for (i, _) in block.match_indices(".") {
                let rest = &block[i + 1..];
                let end = rest
                    .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                    .unwrap_or(rest.len());
                if end == 0 {
                    continue;
                }
                let word = &rest[..end];
                // Only bare `.field` reads directly after a quote, space, or
                // pipe — not `foo.bar` inside a filename or a URL.
                let prev = block[..i].chars().next_back().unwrap_or(' ');
                if matches!(prev, '\'' | '"' | ' ' | '|' | '(' | '[')
                    && word.chars().next().is_some_and(|c| c.is_ascii_lowercase())
                    && !NESTED_OR_DERIVED.contains(&word)
                {
                    fields.insert(word.to_string());
                }
            }
            if !fields.is_empty() {
                let command = block
                    .lines()
                    .find(|l| l.trim_start().starts_with("sipnab "))
                    .map(|l| l.split(" | ").next().unwrap_or(l).trim().to_string());
                out.push(Recipe {
                    doc: name.clone(),
                    mode,
                    fields,
                    command,
                });
            }
        }
    }
    Ok(out)
}

/// Fixtures whose UNION exercises the conditional fields.
///
/// One successful call is not enough, and assuming it was produced a false
/// alarm the first time this ran: `signaling_diagnosis` is emitted only for a
/// dialog that FAILED, so a clean capture made three accurate doc lines look
/// broken. A gate that reports correct documentation as wrong is worse than no
/// gate — it trains readers to edit working text. Every fixture here earns its
/// place by contributing a field the others do not.
const FIXTURES: &[&str] = &[
    "tests/pcap-samples/sip-rtp-g711.pcap", // answered call with RTP
    "tests/pcap-samples/sip-auth-failure.pcapng", // failed: signaling_diagnosis
    "tests/pcap-samples/sip-problem-call.pcap", // failed with a final status
    "tests/pcap-samples/sip-register.pcap", // non-INVITE dialog
];

/// Captures that actually hold STUN and TURN. The SIP fixtures above carry
/// none, so `--json-stun` over them emits nothing and the gate would pass
/// vacuously — which is the failure mode its own assertion below guards.
const STUN_FIXTURES: &[&str] = &[
    "tests/fixtures/stun_nat_probe.pcap", // an unanswered probe and an answered one
    "tests/fixtures/turn_relay.pcap",     // an Allocate, a ChannelBind, a lapsed allocation
];

/// Every one-shot query flag the CLI declares, from the registry itself, so a
/// new query flag's recipes are checked without editing this file.
fn query_flags() -> Vec<&'static str> {
    use clap::Parser as _;
    sipnab::cli::Cli::try_parse_from(["sipnab"])
        .map(|cli| cli.one_shots().iter().map(|s| s.name).collect())
        .unwrap_or_default()
}

/// `line` split into words the way a POSIX shell splits it, for the quoting a
/// documented command uses: single and double quotes, no expansion.
fn shell_words(line: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote: Option<char> = None;
    let mut started = false;
    for c in line.chars() {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => word.push(c),
            None if c == '\'' || c == '"' => {
                quote = Some(c);
                started = true;
            }
            None if c.is_whitespace() => {
                if started || !word.is_empty() {
                    words.push(std::mem::take(&mut word));
                    started = false;
                }
            }
            None => word.push(c),
        }
    }
    if started || !word.is_empty() {
        words.push(word);
    }
    words
}

/// Keys a query recipe's own command emits: the block's `sipnab` command run
/// as written (from the repository root, which is where the documented
/// sample paths resolve), its JSON lines harvested.
fn keys_for_command(command: &str) -> Result<BTreeSet<String>, TestError> {
    let words = shell_words(command);
    let args = words.get(1..).ok_or("a command names sipnab")?;
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(args)
        .env("NO_COLOR", "1")
        .output()
        .map_err(|e| format!("run sipnab: {e}"))?;
    assert!(
        out.status.success(),
        "the documented command `{command}` failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mut keys = BTreeSet::new();
    for line in String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| l.starts_with('{'))
    {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
            harvest(&v, 3, &mut keys);
        }
    }
    assert!(
        !keys.is_empty(),
        "the documented command `{command}` printed no JSON object"
    );
    Ok(keys)
}

/// The keys of `v`, walking objects and the object elements of arrays to
/// `depth`: see [`keys_for`] for why to depth 3.
fn harvest(v: &serde_json::Value, depth: usize, keys: &mut BTreeSet<String>) {
    if depth == 0 {
        return;
    }
    match v {
        serde_json::Value::Object(obj) => {
            keys.extend(obj.keys().cloned());
            for child in obj.values() {
                harvest(child, depth - 1, keys);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                harvest(item, depth, keys);
            }
        }
        _ => {}
    }
}

/// Top-level keys the given mode emits across every fixture.
fn keys_for(mode: Mode) -> Result<BTreeSet<String>, TestError> {
    let flag = match mode {
        Mode::Query(flag) => return Err(format!("{flag}: a query runs its own command").into()),
        Mode::Messages => "--json",
        Mode::Dialogs => "--json-dialogs",
        Mode::Stun => "--json-stun",
        Mode::Analyze => "--json-analyze",
    };
    // `--json-analyze` emits one object per RUN, so it needs a capture with
    // findings in it; `--json-stun` needs one with STUN in it.
    let fixtures: &[&str] = match mode {
        Mode::Messages | Mode::Dialogs | Mode::Query(_) => FIXTURES,
        Mode::Stun | Mode::Analyze => STUN_FIXTURES,
    };
    let mut keys = BTreeSet::new();
    for pcap in fixtures {
        assert!(Path::new(pcap).exists(), "fixture missing: {pcap}");
        let mut args = vec!["-N", "-I", *pcap, flag];
        if mode != Mode::Messages {
            args.push("--no-cli-print");
        }
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
            .args(&args)
            .output()
            .map_err(|e| format!("run sipnab: {e}"))?;
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines().filter(|l| l.starts_with('{')) {
            let v: serde_json::Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(_) => continue,
            };
            // Walk objects AND the object elements of arrays, to a bounded
            // depth. Arrays were the hole: the walk descended one level into
            // nested OBJECTS only, so `.streams[].loss_pct` — a real field of
            // a real array — was reported as nonexistent, and any page reading
            // into an array of objects failed against correct documentation.
            // `docs/real-world-captures.md` was the first page to do so and is
            // what exposed it.
            //
            // Depth 3 reaches dialog -> streams[] -> quality_intervals[],
            // which is the deepest shape any documented recipe reads. It is a
            // deliberate widening: a name valid at one depth now satisfies a
            // read at another, so this gate proves a field EXISTS somewhere in
            // the document rather than that a given path resolves. That is
            // still the failure worth catching — a reader pasting a recipe
            // that names a field nothing emits gets a confidently empty
            // answer — and a path-precise version would have to model jq.
            harvest(&v, 3, &mut keys);
        }
    }
    assert!(
        !keys.is_empty(),
        "{flag} produced no JSON objects across {} fixtures; the gate would \
         pass vacuously",
        fixtures.len()
    );
    Ok(keys)
}

/// Every documented `jq` field exists in the output its own block produces.
#[test]
fn documented_jq_fields_exist_in_the_output() -> Result<(), TestError> {
    let recipes = recipes()?;
    assert!(
        recipes.len() >= 3,
        "found only {} doc pipelines to check — the extractor stopped matching, \
         which would let this gate pass while checking nothing",
        recipes.len()
    );

    let messages = keys_for(Mode::Messages)?;
    let dialogs = keys_for(Mode::Dialogs)?;
    let stun = keys_for(Mode::Stun)?;
    let analyze = keys_for(Mode::Analyze)?;

    let mut bad = Vec::new();
    for r in &recipes {
        let own;
        let keys = match r.mode {
            Mode::Query(flag) => {
                let command = r
                    .command
                    .as_deref()
                    .ok_or_else(|| format!("{}: a {flag} recipe names no sipnab command", r.doc))?;
                own = keys_for_command(command)?;
                &own
            }
            Mode::Messages => &messages,
            Mode::Dialogs => &dialogs,
            Mode::Stun => &stun,
            Mode::Analyze => &analyze,
        };
        for f in &r.fields {
            if !keys.contains(f) {
                bad.push(format!(
                    "{}: `.{f}` is not a field of {} output",
                    r.doc,
                    match r.mode {
                        Mode::Query(flag) => flag,
                        Mode::Messages => "--json",
                        Mode::Dialogs => "--json-dialogs",
                        Mode::Stun => "--json-stun",
                        Mode::Analyze => "--json-analyze",
                    }
                ));
            }
        }
    }
    assert!(
        bad.is_empty(),
        "documented jq recipes read fields that do not exist. A reader pastes \
         these and gets a confidently empty answer:\n  {}",
        bad.join("\n  ")
    );
    Ok(())
}

/// The shell splitter reads the quoting the documented commands use.
#[test]
fn shell_words_reads_single_and_double_quotes() {
    assert_eq!(
        shell_words(r#"sipnab -I a.pcap --filter 'state == Failed' --x="a b" ''"#),
        vec![
            "sipnab",
            "-I",
            "a.pcap",
            "--filter",
            "state == Failed",
            "--x=a b",
            ""
        ]
    );
}

/// Every query flag the registry declares is found, so a recipe for one is
/// checked against its own command and not against `--json`'s messages.
#[test]
fn the_query_flags_come_from_the_registry() {
    assert!(query_flags().contains(&"--timeline"), "{:?}", query_flags());
}
