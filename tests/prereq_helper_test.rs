// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The shared prerequisite helper, `src/test_prereq.rs`.
//!
//! A test that needs something from its environment (passwordless sudo, a
//! tool on `PATH`, a kernel feature) used to look for it and `return Ok(())`
//! when it was missing. libtest and nextest then reported `ok` for a test that
//! tested nothing. The helper makes that decision in one place:
//!
//! - a required prerequisite that is missing fails the test, naming it;
//! - an environment-optional one that is missing skips the test with a notice
//!   on the real stderr and one line in the skip ledger, so a skip is visible
//!   and counted;
//! - `SIPNAB_REQUIRE_PREREQS` turns named optional prerequisites into required
//!   ones, so CI fails when a prerequisite it installs goes missing.
//!
//! The tests are named `success_`, `failure_` and `edge_` by the case they
//! cover.

#[path = "../src/test_prereq.rs"]
mod test_prereq;
#[path = "../src/test_scratch.rs"]
mod test_scratch;

use std::path::PathBuf;

use test_prereq::{Context, Need, PrereqError, Verdict};

type TestError = Box<dyn std::error::Error>;

const OPTIONAL: Need = Need::Optional("the case needs a host that has it");

/// A context with no require list and no ledger, for the test `test`.
fn context(test: &str) -> Context {
    Context {
        binary: "prereq_helper_test".to_owned(),
        test: test.to_owned(),
        require: None,
        ledger: None,
    }
}

/// Run `check_in` with `ctx`, returning its result and what it wrote to
/// stderr.
fn checked(
    ctx: &Context,
    prereq: &str,
    need: Need,
    probe: Result<u32, String>,
) -> (Result<Option<u32>, PrereqError>, String) {
    let mut err = Vec::new();
    let result = test_prereq::check_in(ctx, &mut err, prereq, need, probe);
    (result, String::from_utf8_lossy(&err).into_owned())
}

// ---- verdict: the one rule ----

#[test]
fn success_a_present_required_prerequisite_runs() {
    assert_eq!(
        test_prereq::verdict(true, "sudo", Need::Required, None),
        Verdict::Run,
        "a required prerequisite that is present lets the test run"
    );
}

#[test]
fn success_a_present_optional_prerequisite_runs() {
    assert_eq!(
        test_prereq::verdict(true, "sudo", OPTIONAL, None),
        Verdict::Run,
        "an optional prerequisite that is present lets the test run"
    );
}

#[test]
fn success_a_present_prerequisite_runs_whatever_the_require_list_says() {
    assert_eq!(
        test_prereq::verdict(true, "sudo", OPTIONAL, Some("all")),
        Verdict::Run,
        "the require list changes only what happens when a prerequisite is missing"
    );
}

#[test]
fn failure_a_missing_required_prerequisite_fails() {
    assert_eq!(
        test_prereq::verdict(false, "sudo", Need::Required, None),
        Verdict::Fail,
        "a required prerequisite that is missing fails the test"
    );
}

#[test]
fn success_a_missing_optional_prerequisite_skips() {
    assert_eq!(
        test_prereq::verdict(false, "sudo", OPTIONAL, None),
        Verdict::Skip,
        "an optional prerequisite that is missing skips the test"
    );
}

#[test]
fn failure_a_missing_optional_prerequisite_the_require_list_names_fails() {
    assert_eq!(
        test_prereq::verdict(false, "sudo", OPTIONAL, Some("tshark,sudo")),
        Verdict::Fail,
        "a prerequisite the require list names is required"
    );
}

#[test]
fn failure_the_require_list_all_makes_every_optional_prerequisite_required() {
    assert_eq!(
        test_prereq::verdict(false, "landlock", OPTIONAL, Some("all")),
        Verdict::Fail,
        "`all` names every prerequisite"
    );
}

#[test]
fn success_a_require_list_that_names_another_prerequisite_still_skips() {
    assert_eq!(
        test_prereq::verdict(false, "sudo", OPTIONAL, Some("tshark,editcap")),
        Verdict::Skip,
        "a list that does not name the prerequisite leaves it optional"
    );
}

#[test]
fn failure_a_missing_required_prerequisite_fails_with_an_empty_require_list() {
    assert_eq!(
        test_prereq::verdict(false, "git", Need::Required, Some("")),
        Verdict::Fail,
        "an empty require list cannot make a required prerequisite optional"
    );
}

// ---- listed: reading the require list ----

#[test]
fn success_listed_finds_a_name_among_commas() {
    assert!(
        test_prereq::listed("sudo", "tshark,sudo,landlock"),
        "a comma-separated list names its middle item"
    );
}

#[test]
fn success_listed_finds_a_name_among_spaces() {
    assert!(
        test_prereq::listed("landlock", "sudo landlock"),
        "a space-separated list names its items"
    );
}

#[test]
fn edge_listed_ignores_surrounding_whitespace() {
    assert!(
        test_prereq::listed("sudo", "  tshark ,  sudo  "),
        "spaces around an item do not hide it"
    );
}

#[test]
fn edge_listed_matches_whole_names_only() {
    assert!(
        !test_prereq::listed("sudo", "sudoers,pseudo"),
        "a name that only contains the prerequisite's name does not name it"
    );
}

#[test]
fn edge_listed_is_case_sensitive() {
    assert!(
        !test_prereq::listed("sudo", "SUDO"),
        "prerequisite names are lower case and compared exactly"
    );
}

#[test]
fn edge_listed_finds_nothing_in_an_empty_list() {
    assert!(
        !test_prereq::listed("sudo", ""),
        "an empty list names nothing"
    );
}

#[test]
fn edge_listed_finds_nothing_in_a_list_of_separators() {
    assert!(
        !test_prereq::listed("sudo", " , ,, "),
        "separators alone name nothing"
    );
}

#[test]
fn edge_listed_all_is_a_whole_item_only() {
    assert!(
        test_prereq::listed("editcap", "sudo,all"),
        "`all` anywhere in the list names every prerequisite"
    );
    assert!(
        !test_prereq::listed("editcap", "allx"),
        "`allx` is not `all`"
    );
}

// ---- check_in: the decision with its side effects ----

#[test]
fn success_check_in_hands_back_what_the_probe_found() -> Result<(), TestError> {
    let (result, err) = checked(&context("t"), "sudo", Need::Required, Ok(7));
    assert_eq!(
        result?,
        Some(7),
        "a present prerequisite returns the probe's value"
    );
    assert!(err.is_empty(), "a test that runs prints no notice: {err}");
    Ok(())
}

#[test]
fn success_check_in_skips_with_a_notice_naming_the_test_and_the_prerequisite()
-> Result<(), TestError> {
    let (result, err) = checked(
        &context("a_root_run_reads_its_input"),
        "sudo",
        OPTIONAL,
        Err("sudo -n true exited 1".to_owned()),
    );
    assert_eq!(
        result?, None,
        "an optional prerequisite that is missing skips"
    );
    assert!(
        err.contains("a_root_run_reads_its_input"),
        "the notice names the test: {err}"
    );
    assert!(
        err.contains("`sudo`"),
        "the notice names the prerequisite: {err}"
    );
    assert!(
        err.contains(test_prereq::NOTICE_MARKER),
        "the notice carries the marker: {err}"
    );
    Ok(())
}

#[test]
fn success_check_in_notice_gives_the_probe_answer_and_the_reason() -> Result<(), TestError> {
    let (_, err) = checked(
        &context("t"),
        "sudo",
        Need::Optional("hosts without passwordless sudo cannot run it"),
        Err("sudo -n true exited 1".to_owned()),
    );
    assert!(
        err.contains("sudo -n true exited 1"),
        "the notice says why the probe found nothing: {err}"
    );
    assert!(
        err.contains("hosts without passwordless sudo cannot run it"),
        "the notice gives the reason the prerequisite is optional: {err}"
    );
    assert!(
        err.contains(test_prereq::REQUIRE_VAR),
        "the notice says how to make the skip a failure: {err}"
    );
    Ok(())
}

#[test]
fn success_check_in_notice_is_one_line() -> Result<(), TestError> {
    let (_, err) = checked(
        &context("t"),
        "sudo",
        OPTIONAL,
        Err("line one\nline two".to_owned()),
    );
    assert_eq!(
        err.lines().count(),
        1,
        "the notice is one line, even when the probe's answer has two: {err:?}"
    );
    assert!(err.ends_with('\n'), "the notice ends its line: {err:?}");
    Ok(())
}

#[test]
fn failure_check_in_refuses_a_missing_required_prerequisite_by_name() -> Result<(), TestError> {
    let (result, err) = checked(
        &context("the_page_formats_without_warnings"),
        "groff",
        Need::Required,
        Err("groff is not on PATH".to_owned()),
    );
    let Err(e) = result else {
        return Err("a required prerequisite that is missing must be an error".into());
    };
    let text = e.to_string();
    assert!(
        text.contains("`groff`"),
        "the error names the prerequisite: {text}"
    );
    assert!(
        text.contains("the_page_formats_without_warnings"),
        "the error names the test: {text}"
    );
    assert!(
        text.contains("groff is not on PATH"),
        "the error gives the probe's answer: {text}"
    );
    assert!(
        err.is_empty(),
        "a failure is the error, not a notice: {err}"
    );
    Ok(())
}

#[test]
fn failure_check_in_refuses_an_optional_prerequisite_the_require_list_names()
-> Result<(), TestError> {
    let mut ctx = context("t");
    ctx.require = Some("sudo".to_owned());
    let (result, _) = checked(&ctx, "sudo", OPTIONAL, Err("no sudo".to_owned()));
    let Err(e) = result else {
        return Err("a named optional prerequisite that is missing must be an error".into());
    };
    assert!(
        e.to_string().contains(test_prereq::REQUIRE_VAR),
        "the error says the require list made it required: {e}"
    );
    Ok(())
}

#[test]
fn failure_check_in_writes_no_ledger_line_for_a_failure() -> Result<(), TestError> {
    let dir = test_scratch::ScratchDir::new("sipnab-prereq-ledger-")?;
    let ledger = dir.path().join("skips.tsv");
    let mut ctx = context("t");
    ctx.ledger = Some(ledger.clone());
    let (result, _) = checked(&ctx, "git", Need::Required, Err("no git".to_owned()));
    assert!(
        result.is_err(),
        "a required prerequisite that is missing fails"
    );
    assert!(
        !ledger.exists(),
        "a failure is not a skip and is not counted as one"
    );
    Ok(())
}

#[test]
fn success_check_in_appends_one_ledger_line_per_skip() -> Result<(), TestError> {
    let dir = test_scratch::ScratchDir::new("sipnab-prereq-ledger-")?;
    let ledger = dir.path().join("skips.tsv");
    let mut ctx = context("first_test");
    ctx.ledger = Some(ledger.clone());
    checked(&ctx, "sudo", OPTIONAL, Err("no".to_owned())).0?;
    ctx.test = "second_test".to_owned();
    checked(&ctx, "landlock", OPTIONAL, Err("no".to_owned())).0?;
    let text = std::fs::read_to_string(&ledger)?;
    assert_eq!(text.lines().count(), 2, "two skips are two lines: {text}");
    assert!(
        text.lines()
            .next()
            .is_some_and(|l| l.contains("first_test") && l.contains("sudo")),
        "the first line is the first skip: {text}"
    );
    Ok(())
}

#[test]
fn success_check_in_keeps_ledger_lines_already_there() -> Result<(), TestError> {
    let dir = test_scratch::ScratchDir::new("sipnab-prereq-ledger-")?;
    let ledger = dir.path().join("skips.tsv");
    std::fs::write(&ledger, "earlier\tline\tsudo\twhy\n")?;
    let mut ctx = context("t");
    ctx.ledger = Some(ledger.clone());
    checked(&ctx, "sudo", OPTIONAL, Err("no".to_owned())).0?;
    let text = std::fs::read_to_string(&ledger)?;
    assert!(
        text.starts_with("earlier\t"),
        "the ledger is appended to, not replaced: {text}"
    );
    assert_eq!(text.lines().count(), 2, "one line was added: {text}");
    Ok(())
}

#[test]
fn success_check_in_writes_no_ledger_line_when_the_test_runs() -> Result<(), TestError> {
    let dir = test_scratch::ScratchDir::new("sipnab-prereq-ledger-")?;
    let ledger = dir.path().join("skips.tsv");
    let mut ctx = context("t");
    ctx.ledger = Some(ledger.clone());
    checked(&ctx, "sudo", OPTIONAL, Ok(1)).0?;
    assert!(!ledger.exists(), "a test that runs is not a skip");
    Ok(())
}

#[test]
fn failure_a_skip_that_cannot_be_counted_fails() -> Result<(), TestError> {
    let dir = test_scratch::ScratchDir::new("sipnab-prereq-ledger-")?;
    let mut ctx = context("t");
    // A directory where the ledger file should be: the append cannot open it.
    ctx.ledger = Some(dir.path().to_path_buf());
    let (result, _) = checked(&ctx, "sudo", OPTIONAL, Err("no".to_owned()));
    let Err(e) = result else {
        return Err("a skip the ledger cannot record must not pass uncounted".into());
    };
    assert!(
        matches!(e, PrereqError::Uncounted { .. }),
        "the error is the ledger's, not a missing prerequisite: {e:?}"
    );
    assert!(
        e.to_string().contains(test_prereq::LEDGER_VAR),
        "the error names the ledger variable: {e}"
    );
    Ok(())
}

#[test]
fn success_check_in_counts_skips_in_the_process() -> Result<(), TestError> {
    let before = test_prereq::skipped();
    checked(&context("t"), "sudo", OPTIONAL, Err("no".to_owned())).0?;
    assert!(
        test_prereq::skipped() > before,
        "a skip raises the process's skip count"
    );
    Ok(())
}

// ---- ledger_line / parse ----

#[test]
fn success_a_ledger_line_has_four_tab_separated_fields() {
    let line = test_prereq::ledger_line("bin", "test", "sudo", "why");
    assert_eq!(
        line, "bin\ttest\tsudo\twhy",
        "binary, test, prerequisite, reason"
    );
}

#[test]
fn edge_a_ledger_line_replaces_tabs_and_newlines_in_its_fields() {
    let line = test_prereq::ledger_line("bin", "one\ttwo", "su\ndo", "a\r\nreason");
    assert_eq!(
        line.split('\t').count(),
        4,
        "a tab in a field cannot add a field: {line:?}"
    );
    assert!(
        !line.contains('\n') && !line.contains('\r'),
        "one line: {line:?}"
    );
}

#[test]
fn edge_a_ledger_line_keeps_an_empty_reason_as_an_empty_field() {
    let line = test_prereq::ledger_line("bin", "test", "sudo", "");
    assert_eq!(
        line.split('\t').count(),
        4,
        "four fields, the last empty: {line:?}"
    );
}

// ---- Context::from_values ----

#[test]
fn success_the_context_reads_the_require_list_and_ledger() {
    let ctx = Context::from_values(
        "bin",
        Some("worker-3".to_owned()),
        Some("sudo".into()),
        Some("/x/skips.tsv".into()),
    );
    assert_eq!(ctx.test, "worker-3", "the test name is the thread's name");
    assert_eq!(
        ctx.require.as_deref(),
        Some("sudo"),
        "the require list is read"
    );
    assert_eq!(
        ctx.ledger,
        Some(PathBuf::from("/x/skips.tsv")),
        "the ledger is read"
    );
}

#[test]
fn edge_the_context_names_an_unnamed_thread() {
    let ctx = Context::from_values("bin", None, None, None);
    assert_eq!(
        ctx.test,
        test_prereq::UNNAMED_TEST,
        "a thread without a name"
    );
}

#[test]
fn edge_the_main_thread_is_not_a_test_name() {
    let ctx = Context::from_values("bin", Some("main".to_owned()), None, None);
    assert_eq!(
        ctx.test,
        test_prereq::UNNAMED_TEST,
        "libtest names a test's thread after the test; `main` is not one"
    );
}

#[test]
fn edge_an_empty_ledger_variable_is_no_ledger() {
    let ctx = Context::from_values("bin", None, None, Some("".into()));
    assert_eq!(ctx.ledger, None, "an empty variable is unset");
}

#[test]
fn edge_an_empty_require_variable_is_no_list() {
    let ctx = Context::from_values("bin", None, Some("".into()), None);
    assert_eq!(ctx.require, None, "an empty variable is unset");
}

#[test]
fn success_the_context_takes_the_running_tests_name_from_its_thread() {
    let ctx = Context::from_env();
    assert_eq!(
        ctx.test, "success_the_context_takes_the_running_tests_name_from_its_thread",
        "libtest runs each test on a thread named after it"
    );
    assert_eq!(ctx.binary, "prereq_helper_test", "the binary is this crate");
}

// ---- the probes ----

#[test]
fn success_on_path_finds_a_tool_that_is_there() -> Result<(), TestError> {
    let dir = test_scratch::ScratchDir::new("sipnab-prereq-path-")?;
    let tool = dir.path().join("probe-tool");
    std::fs::write(&tool, "")?;
    let found = test_prereq::on_path_in("probe-tool", Some(dir.path().as_os_str()))?;
    assert_eq!(found, tool, "the tool is found where it is");
    Ok(())
}

#[test]
fn failure_on_path_reports_a_tool_that_is_not_there() -> Result<(), TestError> {
    let dir = test_scratch::ScratchDir::new("sipnab-prereq-path-")?;
    let Err(why) = test_prereq::on_path_in("probe-tool", Some(dir.path().as_os_str())) else {
        return Err("a tool that is not there is not found".into());
    };
    assert!(
        why.contains("probe-tool"),
        "the answer names the tool: {why}"
    );
    assert!(
        why.contains("PATH"),
        "the answer says where it looked: {why}"
    );
    Ok(())
}

#[test]
fn edge_on_path_with_no_path_finds_nothing() {
    assert!(
        test_prereq::on_path_in("sh", None).is_err(),
        "with PATH unset no tool is on it"
    );
}

#[test]
fn edge_on_path_skips_a_directory_with_the_tools_name() -> Result<(), TestError> {
    let dir = test_scratch::ScratchDir::new("sipnab-prereq-path-")?;
    std::fs::create_dir(dir.path().join("probe-tool"))?;
    assert!(
        test_prereq::on_path_in("probe-tool", Some(dir.path().as_os_str())).is_err(),
        "a directory is not a tool"
    );
    Ok(())
}

#[test]
fn edge_on_path_takes_the_first_of_two() -> Result<(), TestError> {
    let first = test_scratch::ScratchDir::new("sipnab-prereq-path-")?;
    let second = test_scratch::ScratchDir::new("sipnab-prereq-path-")?;
    std::fs::write(first.path().join("probe-tool"), "")?;
    std::fs::write(second.path().join("probe-tool"), "")?;
    let path = std::env::join_paths([first.path(), second.path()])?;
    let found = test_prereq::on_path_in("probe-tool", Some(&path))?;
    assert_eq!(found, first.path().join("probe-tool"), "PATH order is kept");
    Ok(())
}

#[test]
fn success_a_present_file_is_found() -> Result<(), TestError> {
    let dir = test_scratch::ScratchDir::new("sipnab-prereq-file-")?;
    let file = dir.path().join("there");
    std::fs::write(&file, "x")?;
    assert_eq!(
        test_prereq::path_exists(&file)?,
        file,
        "an existing path is found"
    );
    Ok(())
}

#[test]
fn failure_a_missing_file_is_named() -> Result<(), TestError> {
    let dir = test_scratch::ScratchDir::new("sipnab-prereq-file-")?;
    let file = dir.path().join("not-there");
    let Err(why) = test_prereq::path_exists(&file) else {
        return Err("a path that does not exist is not found".into());
    };
    assert!(
        why.contains("not-there"),
        "the answer names the path: {why}"
    );
    Ok(())
}

#[test]
fn success_an_env_variable_that_is_set_is_read() {
    assert_eq!(
        test_prereq::env_value("SIPNAB_X", Some("v".into())),
        Ok("v".to_owned()),
        "a set variable is its value"
    );
}

#[test]
fn failure_an_env_variable_that_is_unset_is_named() -> Result<(), TestError> {
    let Err(why) = test_prereq::env_value("SIPNAB_X", None) else {
        return Err("an unset variable is missing".into());
    };
    assert!(
        why.contains("SIPNAB_X"),
        "the answer names the variable: {why}"
    );
    Ok(())
}

#[test]
fn edge_an_env_variable_set_to_nothing_is_missing() {
    assert!(
        test_prereq::env_value("SIPNAB_X", Some("".into())).is_err(),
        "an empty variable names nothing"
    );
}

// ---- present: the bool form for an `if` ----

#[test]
fn success_decide_hands_back_what_the_probe_found() {
    assert_eq!(
        test_prereq::decide("git", Need::Required, Ok(5)),
        Some(5),
        "a present prerequisite returns the probe's value"
    );
}

#[test]
fn success_present_is_true_for_a_present_prerequisite() {
    assert!(
        test_prereq::present("git", Need::Required, Ok(())),
        "a present prerequisite runs"
    );
}

#[test]
fn failure_present_panics_on_a_missing_required_prerequisite() -> Result<(), TestError> {
    // catch_unwind: the panic is the behavior under test; `present` has no
    // error to return, so a failure is a panic that names the prerequisite.
    let caught = std::panic::catch_unwind(|| {
        test_prereq::present("groff", Need::Required, Err("absent".to_owned()))
    });
    let Err(payload) = caught else {
        return Err("a missing required prerequisite must fail the test".into());
    };
    let text = payload
        .downcast_ref::<String>()
        .cloned()
        .unwrap_or_default();
    assert!(
        text.contains("`groff`"),
        "the panic names the prerequisite: {text}"
    );
    assert!(
        text.contains("missing"),
        "the panic says it is missing, not unknown: {text}"
    );
    Ok(())
}

#[test]
fn success_not_root_runs_an_unprivileged_test() {
    assert!(
        test_prereq::not_root(false),
        "an ordinary user runs the case"
    );
}

// The root side is driven through the probe and `check_in`, not through
// `not_root(true)`: that would write a real skip into the suite's ledger.

#[test]
fn edge_the_root_probe_reports_root_as_missing() -> Result<(), TestError> {
    let Err(why) = test_prereq::root_probe(true) else {
        return Err("a root process lacks the non-root prerequisite".into());
    };
    assert!(why.contains("root"), "the answer says why: {why}");
    Ok(())
}

#[test]
fn success_the_root_probe_passes_an_ordinary_user() {
    assert_eq!(
        test_prereq::root_probe(false),
        Ok(()),
        "an ordinary user has it"
    );
}

#[test]
fn edge_a_root_run_skips_under_the_non_root_need() -> Result<(), TestError> {
    let (result, err) = {
        let mut sink = Vec::new();
        let r = test_prereq::check_in(
            &context("t"),
            &mut sink,
            "non-root",
            test_prereq::NON_ROOT,
            test_prereq::root_probe(true).map(|()| 0u32),
        );
        (r, String::from_utf8_lossy(&sink).into_owned())
    };
    assert_eq!(result?, None, "root skips a case it cannot build");
    assert!(err.contains("`non-root`"), "with a notice naming it: {err}");
    Ok(())
}

#[test]
fn failure_a_prerequisite_name_not_in_the_list_fails() -> Result<(), TestError> {
    let (result, err) = checked(&context("t"), "sudoo", OPTIONAL, Err("no".to_owned()));
    let Err(e) = result else {
        return Err("a misspelled name would never match a require list, so it must fail".into());
    };
    assert!(
        matches!(e, PrereqError::Unknown { .. }),
        "the error is the unknown name: {e:?}"
    );
    assert!(e.to_string().contains("`sudoo`"), "the error names it: {e}");
    assert!(
        err.is_empty(),
        "no notice for a name that is refused: {err}"
    );
    Ok(())
}

#[test]
fn failure_a_prerequisite_name_not_in_the_list_fails_even_when_present() {
    let (result, _) = checked(&context("t"), "sudoo", Need::Required, Ok(1));
    assert!(
        matches!(result, Err(PrereqError::Unknown { .. })),
        "the name is checked before the probe's answer, so a typo shows on every host"
    );
}

#[test]
fn edge_the_prerequisite_names_in_use_are_lower_case_words() {
    for name in test_prereq::KNOWN {
        assert!(
            !name.is_empty()
                && name
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
            "a prerequisite name a require list can carry: {name:?}"
        );
    }
    assert!(
        !test_prereq::KNOWN.is_empty(),
        "the list of names is not empty"
    );
}
