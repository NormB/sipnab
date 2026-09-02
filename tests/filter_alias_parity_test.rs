// SPDX-License-Identifier: MIT OR Apache-2.0

//! One filter language, resolved once, whichever flag asks for it.
//!
//! `docs/cli-reference.md` says `--export-vcon-when` takes "the language
//! `--filter` already speaks". It did not: `--filter problems` exited 0 and
//! `--export-vcon-when problems` exited 1 with *"not a valid filter
//! expression: unexpected input at position 0"*, because `--filter` was
//! resolved through `build_filter_expr(cli, config)` -- the one path that
//! expands the ten diagnostic aliases and honors the operator's `[diagnosis]`
//! thresholds -- while `vcon_selection` parsed the raw string at selection
//! time.
//!
//! That is a divergence between two surfaces of one language, and the fix is
//! not a second expansion site. It is routing the flag through the resolution
//! that already exists, so there is one place where a filter becomes a
//! `FilterExpr` and no second place to keep in step.
//!
//! Expanding with a default `Config` was considered and rejected:
//! `alias_thresholds` reads each flag, then the `[diagnosis]` key, then the
//! built-in, so a default would silently ignore an operator's tuning for
//! exactly the people who configured it.

#![cfg(feature = "vcon")]

use std::path::PathBuf;
use std::process::Command;

const FIXTURE: &str = "website/static/demos/sample-call.pcap";

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn bin() -> PathBuf {
    let mut p = std::env::current_exe().expect("current exe");
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join("sipnab")
}

/// Run sipnab and return (exit code, stderr).
fn run(args: &[&str]) -> (i32, String) {
    let out = Command::new(bin())
        .args(args)
        .current_dir(repo())
        .output()
        .expect("run sipnab");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Every alias `--filter` accepts, `--export-vcon-when` accepts too.
///
/// The operator-visible statement. An alias is part of the filter language, so
/// a flag documented as taking that language takes all of it.
#[test]
fn every_alias_filter_accepts_export_vcon_when_accepts() {
    let fixture = repo().join(FIXTURE);
    let fixture = fixture.to_str().expect("fixture path");
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("alias_parity");

    let mut diverged = Vec::new();
    let mut checked = 0;
    for alias in sipnab::sip::dsl::DIAGNOSTIC_ALIASES {
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("out dir");

        let (filter_code, _) = run(&[
            "-N",
            "-I",
            fixture,
            "--no-cli-print",
            "--filter",
            alias,
            "--json-dialogs",
        ]);
        let (vcon_code, vcon_err) = run(&[
            "-N",
            "-I",
            fixture,
            "--no-cli-print",
            "--export-vcon-when",
            alias,
            "--export-vcon-dir",
            dir.to_str().expect("dir"),
        ]);
        checked += 1;
        if filter_code == 0 && vcon_code != 0 {
            diverged.push(format!(
                "  {alias:?}: --filter exits 0, --export-vcon-when exits \
                 {vcon_code}: {}",
                vcon_err.lines().last().unwrap_or("").trim()
            ));
        }
    }
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        checked >= 8,
        "only {checked} alias(es) exercised; DIAGNOSTIC_ALIASES has shrunk and \
         this gate proves little"
    );
    assert!(
        diverged.is_empty(),
        "these aliases are part of the filter language and one flag refuses \
         them, though cli-reference.md says it speaks that language:\n{}",
        diverged.join("\n")
    );
}

/// A raw DSL expression still works on both.
///
/// The paired half: accepting aliases must not come at the cost of the
/// expressions the flag already took, which is what a second parse path would
/// risk.
#[test]
fn a_raw_expression_still_works_on_both_surfaces() {
    let fixture = repo().join(FIXTURE);
    let fixture = fixture.to_str().expect("fixture path");
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("alias_raw");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("out dir");

    let expr = "state == 'Completed'";
    let (filter_code, _) = run(&[
        "-N",
        "-I",
        fixture,
        "--no-cli-print",
        "--filter",
        expr,
        "--json-dialogs",
    ]);
    let (vcon_code, err) = run(&[
        "-N",
        "-I",
        fixture,
        "--no-cli-print",
        "--export-vcon-when",
        expr,
        "--export-vcon-dir",
        dir.to_str().expect("dir"),
    ]);
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(filter_code, 0, "--filter refused a raw expression");
    assert_eq!(
        vcon_code, 0,
        "--export-vcon-when refused a raw expression: {err}"
    );
}

/// A genuinely malformed expression is still refused, on both.
///
/// The anti-vacuity half. If the flag started accepting everything, the gate
/// above would pass for the wrong reason -- and an operator's typo would
/// produce an empty directory they read as "nothing matched".
#[test]
fn a_malformed_expression_is_refused_by_both() {
    let fixture = repo().join(FIXTURE);
    let fixture = fixture.to_str().expect("fixture path");
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("alias_bad");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("out dir");

    let bad = "state ==== nonsense((";
    let (filter_code, _) = run(&[
        "-N",
        "-I",
        fixture,
        "--no-cli-print",
        "--filter",
        bad,
        "--json-dialogs",
    ]);
    let (vcon_code, _) = run(&[
        "-N",
        "-I",
        fixture,
        "--no-cli-print",
        "--export-vcon-when",
        bad,
        "--export-vcon-dir",
        dir.to_str().expect("dir"),
    ]);
    let _ = std::fs::remove_dir_all(&dir);

    assert_ne!(filter_code, 0, "--filter accepted a malformed expression");
    assert_ne!(
        vcon_code, 0,
        "--export-vcon-when accepted a malformed expression, so a typo now \
         yields an empty directory a reader takes for 'nothing matched'"
    );
}

// ── the four owed ───────────────────────────────────────────────────
//
// Two tests failed getting here: the parity gate above, and
// `line_citations_point_at_the_code_they_name` when the refactor moved the
// functions its citations named. The class is wider than the one flag: a
// filter expression on the command line must become a `FilterExpr` in ONE
// place, because a second place is a second set of thresholds and a second
// set of aliases to keep in step.

/// Every CLI flag that takes a filter expression is resolved in the plan.
///
/// The class gate. `--filter` and `--export-vcon-when` are the two today, and
/// a third added later must not bring its own `FilterExpr::parse` -- that is
/// exactly how these two diverged, and the divergence was invisible because
/// each surface worked when tested alone.
///
/// Deliberately NOT a ban on `FilterExpr::parse` everywhere: the TUI parses an
/// expression the operator types interactively, and wasm and expectations have
/// their own entry points. The rule is about flags, whose value the plan
/// already sees.
#[test]
fn every_cli_filter_flag_is_resolved_in_the_plan() {
    let cli = std::fs::read_to_string(repo().join("src/cli.rs")).expect("read cli.rs");
    let plan =
        std::fs::read_to_string(repo().join("src/app/bootstrap.rs")).expect("read bootstrap");

    // Flags whose doc comment says they take the filter language.
    let lines: Vec<&str> = cli.lines().collect();
    let mut flags = Vec::new();
    for (i, l) in lines.iter().enumerate() {
        let t = l.trim();
        if !t.starts_with("///") {
            continue;
        }
        let mentions_dsl = t.contains("filter expression")
            || t.contains("language `--filter` already speaks")
            || t.contains("filter-dsl");
        if !mentions_dsl {
            continue;
        }
        if let Some(field) = lines[i..]
            .iter()
            .take(25)
            .find_map(|c| c.trim().strip_prefix("pub "))
            .and_then(|c| c.split(':').next())
        {
            flags.push(field.to_string());
        }
    }
    flags.sort();
    flags.dedup();

    assert!(
        flags.len() >= 2,
        "only {} filter-bearing flag(s) found; the scan is wrong: {flags:?}",
        flags.len()
    );
    for f in &flags {
        assert!(
            plan.contains(f.as_str()),
            "`--{}` takes a filter expression and the plan never mentions it, \
             so it is resolved somewhere else -- with its own aliases and its \
             own thresholds. Resolve it in bootstrap.rs beside the others.",
            f.replace('_', "-")
        );
    }
}

/// A malformed predicate fails the run before the capture opens.
///
/// The flag's own doc promises this, and it is the difference between a typo
/// and a silent empty directory the operator reads as "nothing matched".
#[test]
fn a_malformed_predicate_fails_before_writing_anything() {
    let fixture = repo().join(FIXTURE);
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("alias_earlyfail");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("out dir");

    let (code, _) = run(&[
        "-N",
        "-I",
        fixture.to_str().expect("fixture"),
        "--no-cli-print",
        "--export-vcon-when",
        "state ==== nonsense((",
        "--export-vcon-dir",
        dir.to_str().expect("dir"),
    ]);
    let written = std::fs::read_dir(&dir).map(|d| d.count()).unwrap_or(0);
    let _ = std::fs::remove_dir_all(&dir);

    assert_ne!(code, 0, "a malformed predicate exited 0");
    assert_eq!(
        written, 0,
        "the run refused the predicate and still wrote {written} file(s); a \
         partially populated directory is worse than none"
    );
}

/// One alias selects the same dialogs through either flag.
///
/// Exit parity is not enough: both surfaces could accept the alias and resolve
/// it to different predicates, which is precisely what two expansion sites
/// with two threshold sources would produce.
#[test]
fn both_surfaces_select_the_same_dialogs_for_one_alias() {
    let fixture = repo().join(FIXTURE);
    let fixture = fixture.to_str().expect("fixture");
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("alias_same_set");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("out dir");

    // `--filter` reports rows; `--export-vcon-when` writes one container per
    // selected dialog. The COUNTS must agree.
    let out = Command::new(bin())
        .args([
            "-N",
            "-I",
            fixture,
            "--no-cli-print",
            "--filter",
            "problems",
            "--json-dialogs",
        ])
        .current_dir(repo())
        .output()
        .expect("run sipnab");
    let rows = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| l.trim_start().starts_with('{'))
        .count();

    let (code, err) = run(&[
        "-N",
        "-I",
        fixture,
        "--no-cli-print",
        "--export-vcon-when",
        "problems",
        "--export-vcon-dir",
        dir.to_str().expect("dir"),
    ]);
    let containers = std::fs::read_dir(&dir)
        .map(|d| {
            d.filter_map(Result::ok)
                .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
                .count()
        })
        .unwrap_or(0);
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(code, 0, "--export-vcon-when problems failed: {err}");
    assert_eq!(
        rows, containers,
        "`--filter problems` selected {rows} dialog(s) and \
         `--export-vcon-when problems` wrote {containers} container(s). Both \
         accept the alias and they do not agree on what it means, which is \
         two expansions rather than one."
    );
}

/// The resolver reads the operator's thresholds, not the built-ins.
///
/// The reason expanding with a default `Config` was rejected.
/// `alias_thresholds` reads each flag, then the `[diagnosis]` key, then the
/// built-in, so a resolver that skipped config would give the same answer for
/// a tuned deployment as an untuned one -- silently, and only for the people
/// who bothered to configure it.
#[test]
fn the_resolver_reads_configured_thresholds() {
    let plan =
        std::fs::read_to_string(repo().join("src/app/bootstrap.rs")).expect("read bootstrap");
    let at = plan
        .find("fn build_vcon_filter_expr")
        .expect("the vcon resolver is gone");
    let body = &plan[at..at + 900.min(plan.len() - at)];

    assert!(
        body.contains("alias_thresholds(config)"),
        "the vcon resolver does not read `alias_thresholds(config)`, so a \
         configured `[diagnosis]` threshold changes what `--filter` matches \
         and not what `--export-vcon-when` matches:\n{body}"
    );
    assert!(
        body.contains("expand_alias"),
        "the vcon resolver does not expand aliases at all"
    );
}

// ── the two owed for the fuzz build ─────────────────────────────────
//
// The push was blocked because `fuzz/` would not compile: `export_vcon` has a
// `#[cfg(not(feature = "vcon"))]` stub whose own comment says "both doors keep
// one signature", and threading the new parameter through the real one left
// the stub behind. pre-commit builds `full`, which has the feature, so nothing
// before the push could see it.

/// Both arms of a cfg-split function take the same parameters.
///
/// A feature-gated pair is one function with two doors. When they drift, the
/// build that uses the OTHER door fails -- and it fails wherever that feature
/// set is built first, which here was the fuzz targets at push time rather
/// than anything a commit gate runs.
#[test]
fn both_arms_of_a_cfg_split_function_share_one_signature() {
    let src = std::fs::read_to_string(repo().join("src/app/batch.rs")).expect("read batch.rs");
    let lines: Vec<&str> = src.lines().collect();

    // Collect (name, params) for every `fn` directly under a `#[cfg(...feature...)]`.
    let mut arms: std::collections::BTreeMap<String, Vec<(usize, Vec<String>)>> =
        std::collections::BTreeMap::new();
    for (i, l) in lines.iter().enumerate() {
        if !l.trim_start().starts_with("#[cfg(") || !l.contains("feature") {
            continue;
        }
        let Some(sig) = lines.get(i + 1) else {
            continue;
        };
        let Some(rest) = sig.trim_start().strip_prefix("fn ") else {
            continue;
        };
        let Some(name) = rest.split('(').next() else {
            continue;
        };
        // Parameter NAMES, stripped of a leading underscore so an unused arm
        // compares equal to a used one.
        let mut params = Vec::new();
        for l2 in lines.iter().skip(i + 2).take(30) {
            let t = l2.trim();
            if t.starts_with(')') || t.starts_with("->") || t == "{" {
                break;
            }
            if let Some(p) = t.split(':').next() {
                let p = p.trim().trim_start_matches('_');
                if !p.is_empty() && p.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                    params.push(p.to_string());
                }
            }
        }
        arms.entry(name.to_string())
            .or_default()
            .push((i + 2, params));
    }

    let paired: Vec<_> = arms.iter().filter(|(_, v)| v.len() >= 2).collect();
    assert!(
        !paired.is_empty(),
        "no cfg-split function pair found in batch.rs; the scan is wrong and \
         this gate proves nothing"
    );
    for (name, variants) in paired {
        let first = &variants[0].1;
        for (line, params) in &variants[1..] {
            assert_eq!(
                first, params,
                "`fn {name}` has cfg-split arms with different parameters, so \
                 whichever build uses the other arm fails to compile. Second \
                 arm at line {line}."
            );
        }
    }
}

/// The scan actually found the pair this failure was about.
///
/// Anti-vacuity with a name attached: if `export_vcon` stops being cfg-split,
/// the gate above still passes while checking one fewer thing, and the reason
/// it exists is gone with no notice.
#[test]
fn the_cfg_split_scan_covers_the_pair_that_broke_the_build() {
    let src = std::fs::read_to_string(repo().join("src/app/batch.rs")).expect("read batch.rs");
    assert!(
        src.contains("#[cfg(feature = \"vcon\")]")
            && src.contains("#[cfg(not(feature = \"vcon\"))]"),
        "batch.rs no longer splits on the vcon feature; the pair this gate was \
         written for is gone and the scan may now cover nothing"
    );
    let stubs = src.matches("fn export_vcon(").count();
    assert!(
        stubs >= 2,
        "expected export_vcon to have both a real arm and a stub; found \
         {stubs}"
    );
}
