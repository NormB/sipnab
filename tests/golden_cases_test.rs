// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The `.trycmd` golden runner's rules: how a case file is read, how a
//! command line is split, how expected output matches, and how a case runs.
//!
//! RUSTSEC-2026-0542 (humantime unmaintained) reached the tree only through
//! the `trycmd` dev-dependency, which `tests/cli_goldens.rs` used to run the
//! 98 goldens under `tests/cli/`. `tests/support/golden_cases.rs` replaces it
//! with the subset of the format those goldens use, read strictly: a file
//! with no case, an unclosed fence, an unknown fence or an unregistered
//! program is an error, never a skipped case.

#[path = "support/golden_cases.rs"]
mod golden_cases;

use golden_cases::{
    Runner, Status, line_matches, normalize, output_matches, overwrite, parse, split_command,
    status_ok,
};
use std::path::PathBuf;
use std::time::Duration;

fn lines(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| (*s).to_string()).collect()
}

fn sh_runner() -> Runner {
    Runner {
        bins: vec![("sh".to_string(), PathBuf::from("/bin/sh"))],
        env: vec![("GOLDEN_TEST_VAR".to_string(), "pinned".to_string())],
        cwd: PathBuf::from(env!("CARGO_MANIFEST_DIR")),
        deadline: Duration::from_secs(60),
    }
}

// ---------------------------------------------------------------- parse: success

#[test]
fn success_one_case_in_one_fence() -> Result<(), String> {
    let cases = parse("```\n$ sipnab --version\nsipnab v[..]\n```\n")?;
    assert_eq!(cases.len(), 1, "one case: {cases:?}");
    assert_eq!(
        cases[0].argv,
        ["sipnab", "--version"],
        "the command is split"
    );
    assert_eq!(
        cases[0].expected,
        lines(&["sipnab v[..]"]),
        "the output lines follow it"
    );
    assert_eq!(
        cases[0].status,
        Status::Success,
        "no status line means success"
    );
    Ok(())
}

#[test]
fn success_two_cases_in_one_fence() -> Result<(), String> {
    let cases = parse("```\n$ a\none\n$ b\ntwo\n```\n")?;
    assert_eq!(cases.len(), 2, "two cases: {cases:?}");
    assert_eq!(cases[1].argv, ["b"], "the second command");
    assert_eq!(
        cases[0].expected,
        lines(&["one"]),
        "the first output ends at the next command"
    );
    Ok(())
}

#[test]
fn success_two_fences() -> Result<(), String> {
    let cases = parse("```\n$ a\n```\ntext\n```\n$ b\nx\n```\n")?;
    assert_eq!(
        cases.iter().map(|c| c.argv[0].as_str()).collect::<Vec<_>>(),
        ["a", "b"],
        "both fences"
    );
    Ok(())
}

#[test]
fn success_a_status_line_after_the_command() -> Result<(), String> {
    let cases = parse("```\n$ a\n? failed\nout\n```\n")?;
    assert_eq!(cases[0].status, Status::Failed, "? failed");
    assert_eq!(
        cases[0].expected,
        lines(&["out"]),
        "the status line is not output"
    );
    Ok(())
}

#[test]
fn success_a_numeric_status() -> Result<(), String> {
    let cases = parse("```\n$ a\n? 2\n```\n")?;
    assert_eq!(cases[0].status, Status::Code(2), "? 2");
    Ok(())
}

#[test]
fn success_console_and_trycmd_fences() -> Result<(), String> {
    for fence in ["```console", "```trycmd"] {
        let cases = parse(&format!("{fence}\n$ a\n```\n"))?;
        assert_eq!(cases.len(), 1, "{fence} holds a case");
    }
    Ok(())
}

#[test]
fn success_the_case_line_is_one_based() -> Result<(), String> {
    let cases = parse("text\n```\n$ a\n```\n")?;
    assert_eq!(cases[0].line, 3, "the $ line is line 3");
    Ok(())
}

#[test]
fn success_an_empty_expected_output() -> Result<(), String> {
    let cases = parse("```\n$ a\n```\n")?;
    assert!(
        cases[0].expected.is_empty(),
        "no output lines: {:?}",
        cases[0].expected
    );
    Ok(())
}

// ---------------------------------------------------------------- parse: failure

#[test]
fn failure_a_file_with_no_case() {
    let err = parse("just text\n").expect_err("no case is an error");
    assert!(err.contains("no `$ ` command"), "it says why: {err}");
}

#[test]
fn failure_an_unclosed_fence() {
    let err = parse("```\n$ a\nout\n").expect_err("an unclosed fence is an error");
    assert!(err.contains("not closed"), "it says why: {err}");
}

#[test]
fn failure_an_unknown_fence() {
    let err = parse("```bash\n$ a\n```\n").expect_err("an unknown fence is an error");
    assert!(err.contains("bash"), "it names the fence: {err}");
}

#[test]
fn failure_a_fence_with_output_but_no_command() {
    let err = parse("```\nout\n```\n").expect_err("output before any command is an error");
    assert!(
        err.contains("before any `$ ` command"),
        "it says why: {err}"
    );
}

#[test]
fn failure_an_unknown_status() {
    let err = parse("```\n$ a\n? maybe\n```\n").expect_err("an unknown status is an error");
    assert!(err.contains("maybe"), "it names it: {err}");
}

#[test]
fn failure_an_empty_command() {
    let err = parse("```\n$ \n```\n").expect_err("an empty command is an error");
    assert!(err.contains("empty"), "it says why: {err}");
}

#[test]
fn failure_an_unterminated_quote_names_the_line() {
    let err = parse("```\n$ a 'b\n```\n").expect_err("a bad command is an error");
    assert!(err.contains("line 2"), "it names the line: {err}");
}

#[test]
fn failure_a_closing_fence_with_an_info_string() {
    let err = parse("```\n$ a\n```text\n").expect_err("a fence cannot close with an info string");
    assert!(err.contains("closing fence"), "it says why: {err}");
}

#[test]
fn failure_output_in_a_second_fence_before_its_command() {
    let err = parse("```\n$ a\n```\n```\nout\n```\n")
        .expect_err("the earlier fence's case does not own it");
    assert!(
        err.contains("before any `$ ` command"),
        "it says why: {err}"
    );
}

// ---------------------------------------------------------------- parse: edge

#[test]
fn edge_text_outside_fences_is_ignored() -> Result<(), String> {
    let cases = parse("# title\n$ not a case\n```\n$ a\n```\nmore\n")?;
    assert_eq!(cases.len(), 1, "only the fenced command: {cases:?}");
    Ok(())
}

#[test]
fn edge_a_status_line_later_in_the_output_is_output() -> Result<(), String> {
    let cases = parse("```\n$ a\nx\n? 2\n```\n")?;
    assert_eq!(
        cases[0].status,
        Status::Success,
        "the status line must follow the command"
    );
    assert_eq!(
        cases[0].expected,
        lines(&["x", "? 2"]),
        "a later ? line is output"
    );
    Ok(())
}

#[test]
fn edge_blank_output_lines_are_kept() -> Result<(), String> {
    let cases = parse("```\n$ a\n\nx\n\n```\n")?;
    assert_eq!(
        cases[0].expected,
        lines(&["", "x", ""]),
        "blank lines are output"
    );
    Ok(())
}

#[test]
fn edge_crlf_files_parse() -> Result<(), String> {
    let cases = parse("```\r\n$ a b\r\nx\r\n```\r\n")?;
    assert_eq!(cases[0].argv, ["a", "b"], "no carriage return in argv");
    assert_eq!(
        cases[0].expected,
        lines(&["x"]),
        "no carriage return in output"
    );
    Ok(())
}

#[test]
fn edge_the_output_range_covers_the_expected_lines() -> Result<(), String> {
    let cases = parse("```\n$ a\n? 2\nx\ny\n```\n")?;
    assert_eq!(
        cases[0].output_lines,
        3..5,
        "lines 4 and 5 (0-based 3..5) are the output"
    );
    Ok(())
}

#[test]
fn edge_a_dollar_without_space_is_output() -> Result<(), String> {
    let cases = parse("```\n$ a\n$x\n```\n")?;
    assert_eq!(
        cases[0].expected,
        lines(&["$x"]),
        "`$x` is output, not a command"
    );
    Ok(())
}

// ---------------------------------------------------------------- split_command

#[test]
fn success_split_plain_words() -> Result<(), String> {
    assert_eq!(
        split_command("a  b\tc")?,
        ["a", "b", "c"],
        "whitespace separates"
    );
    Ok(())
}

#[test]
fn success_split_single_quotes() -> Result<(), String> {
    assert_eq!(
        split_command("a 'b c' d")?,
        ["a", "b c", "d"],
        "single quotes group"
    );
    Ok(())
}

#[test]
fn success_split_double_quotes() -> Result<(), String> {
    assert_eq!(
        split_command("--filter \"state == 'Failed'\"")?,
        ["--filter", "state == 'Failed'"],
        "double quotes group and keep single quotes"
    );
    Ok(())
}

#[test]
fn success_split_adjacent_quoted_parts_join() -> Result<(), String> {
    assert_eq!(
        split_command("a'b'\"c\"d")?,
        ["abcd"],
        "adjacent parts make one word"
    );
    Ok(())
}

#[test]
fn failure_split_unterminated_single_quote() {
    assert!(
        split_command("a 'b").is_err(),
        "an open single quote is an error"
    );
}

#[test]
fn failure_split_unterminated_double_quote() {
    assert!(
        split_command("a \"b").is_err(),
        "an open double quote is an error"
    );
}

#[test]
fn failure_split_trailing_backslash() {
    assert!(
        split_command("a \\").is_err(),
        "a trailing backslash is an error"
    );
}

#[test]
fn edge_split_backslash_escapes_outside_quotes() -> Result<(), String> {
    assert_eq!(split_command("a\\ b")?, ["a b"], "an escaped space joins");
    Ok(())
}

#[test]
fn edge_split_backslash_is_literal_in_single_quotes() -> Result<(), String> {
    assert_eq!(
        split_command("'a\\b'")?,
        ["a\\b"],
        "no escapes in single quotes"
    );
    Ok(())
}

#[test]
fn edge_split_escaped_quote_in_double_quotes() -> Result<(), String> {
    assert_eq!(
        split_command("\"a\\\"b\"")?,
        ["a\"b"],
        "\\\" inside double quotes"
    );
    Ok(())
}

#[test]
fn edge_split_empty_quotes_are_a_word() -> Result<(), String> {
    assert_eq!(split_command("a ''")?, ["a", ""], "'' is an empty argument");
    Ok(())
}

// ---------------------------------------------------------------- line_matches

#[test]
fn success_a_literal_line() {
    assert!(line_matches("abc", "abc"), "equal lines match");
}

#[test]
fn success_a_wildcard_in_the_middle() {
    assert!(
        line_matches("sipnab v[..] (x)", "sipnab v0.5.261 (x)"),
        "[..] covers the version"
    );
}

#[test]
fn success_two_wildcards() {
    assert!(
        line_matches(
            "[..]: [..] fail",
            "Nov 17 12:00:00 host sipnab[42]: banned fail"
        ),
        "two wildcards"
    );
}

#[test]
fn failure_a_literal_mismatch() {
    assert!(
        !line_matches("abc", "abx"),
        "a different line does not match"
    );
}

#[test]
fn failure_a_wildcard_with_a_wrong_suffix() {
    assert!(
        !line_matches("v[..] (x)", "v1 (y)"),
        "the text after [..] must match"
    );
}

#[test]
fn failure_a_wildcard_with_a_wrong_prefix() {
    assert!(
        !line_matches("a[..]", "ba"),
        "the text before [..] is anchored"
    );
}

#[test]
fn failure_a_longer_actual_line() {
    assert!(
        !line_matches("abc", "abcd"),
        "a literal line is anchored at the end"
    );
}

#[test]
fn failure_the_text_after_the_last_wildcard_is_anchored_at_the_end() {
    assert!(!line_matches("a[..]b", "abc"), "`b` must end the line");
}

#[test]
fn failure_prefix_and_suffix_cannot_overlap() {
    assert!(
        !line_matches("ab[..]ba", "aba"),
        "the two literal ends need their own characters"
    );
}

#[test]
fn failure_a_literal_between_wildcards_must_appear() {
    assert!(
        !line_matches("a[..]x[..]b", "ab"),
        "the middle literal is required"
    );
}

#[test]
fn edge_middle_literals_match_in_order() {
    assert!(line_matches("a[..]x[..]y[..]b", "a1x2y3b"), "in order");
    assert!(
        !line_matches("a[..]y[..]x[..]b", "a1x2y3b"),
        "and only in order"
    );
}

#[test]
fn edge_a_wildcard_matches_empty() {
    assert!(line_matches("a[..]b", "ab"), "[..] may match nothing");
}

#[test]
fn edge_a_lone_wildcard_matches_any_line() {
    assert!(
        line_matches("[..]", "") && line_matches("[..]", "anything"),
        "[..] alone matches any line"
    );
}

#[test]
fn edge_other_bracket_words_are_literal() {
    assert!(
        line_matches("[CRITICAL] x", "[CRITICAL] x"),
        "[CRITICAL] is text"
    );
    assert!(
        !line_matches("[CRITICAL] x", "[WARN] x"),
        "and only matches itself"
    );
}

#[test]
fn edge_a_suffix_that_repeats_matches_the_end() {
    assert!(
        line_matches("[..]ab", "abab"),
        "the suffix is matched at the end"
    );
}

// ---------------------------------------------------------------- output_matches and normalize

#[test]
fn success_output_lines_match() {
    assert!(
        output_matches(&lines(&["a", "b"]), "a\nb\n"),
        "two lines and the final newline"
    );
}

#[test]
fn success_an_ellipsis_matches_several_lines() {
    assert!(
        output_matches(&lines(&["a", "...", "z"]), "a\nb\nc\nz\n"),
        "... covers b and c"
    );
}

#[test]
fn failure_a_missing_line() {
    assert!(
        !output_matches(&lines(&["a", "b"]), "a\n"),
        "a missing line fails"
    );
}

#[test]
fn failure_an_extra_line() {
    assert!(
        !output_matches(&lines(&["a"]), "a\nb\n"),
        "an extra line fails"
    );
}

#[test]
fn failure_empty_expected_output_against_output() {
    assert!(
        !output_matches(&[], "x\n"),
        "an empty golden never pins output it does not hold"
    );
}

#[test]
fn failure_an_ellipsis_cannot_skip_a_mismatch_after_it() {
    assert!(
        !output_matches(&lines(&["a", "...", "z"]), "a\nb\ny\n"),
        "the line after ... still has to match"
    );
}

#[test]
fn edge_an_ellipsis_matches_no_lines() {
    assert!(
        output_matches(&lines(&["a", "...", "z"]), "a\nz\n"),
        "... may match nothing"
    );
}

#[test]
fn edge_a_trailing_ellipsis_matches_the_rest() {
    assert!(
        output_matches(&lines(&["a", "..."]), "a\nb\nc\n"),
        "a final ... matches the tail"
    );
}

#[test]
fn edge_normalize_drops_one_final_newline() {
    assert_eq!(
        normalize("a\n\n"),
        lines(&["a", ""]),
        "only one final newline is dropped"
    );
}

#[test]
fn success_a_backslash_in_the_output_reads_as_a_slash() {
    assert!(
        output_matches(
            &lines(&["\"to\":\"/\"PCMU/\"\""]),
            "\"to\":\"\\\"PCMU\\\"\"\n"
        ),
        "trycmd's path rule"
    );
}

#[test]
fn failure_a_backslash_in_the_golden_never_matches() {
    assert!(
        !output_matches(&lines(&["a\\b"]), "a\\b\n"),
        "goldens hold no backslash; output never keeps one"
    );
}

#[test]
fn edge_overwrite_writes_slashes() -> Result<(), String> {
    let text = "```\n$ a\n```\n";
    let cases = parse(text)?;
    assert_eq!(
        overwrite(text, &cases, &[Some("a\\b\n".to_string())]),
        "```\n$ a\na/b\n```\n",
        "as trycmd wrote"
    );
    Ok(())
}

#[test]
fn edge_normalize_crlf() {
    assert_eq!(
        normalize("a\r\nb\r\n"),
        lines(&["a", "b"]),
        "CRLF becomes LF"
    );
}

#[test]
fn edge_normalize_empty() {
    assert!(normalize("").is_empty(), "no output is no lines");
}

#[test]
fn success_a_trailing_blank_expected_line_is_not_compared() {
    assert!(
        output_matches(&lines(&["a", ""]), "a\n"),
        "the blank line before the fence is layout"
    );
}

#[test]
fn edge_trailing_blank_actual_lines_are_not_compared() {
    assert!(
        output_matches(&lines(&["a"]), "a\n\n\n"),
        "trailing blank output lines are not compared"
    );
}

#[test]
fn failure_an_inner_blank_line_is_compared() {
    assert!(
        !output_matches(&lines(&["a", "b"]), "a\n\nb\n"),
        "a blank line inside the output counts"
    );
}

#[test]
fn edge_output_without_a_final_newline_matches() {
    assert!(
        output_matches(&lines(&["a"]), "a"),
        "a missing final newline is not a difference"
    );
}

// ---------------------------------------------------------------- status_ok

#[test]
fn success_status_success_needs_zero() {
    assert!(status_ok(&Status::Success, Some(0)), "0 is success");
}

#[test]
fn failure_status_success_refuses_non_zero() {
    assert!(!status_ok(&Status::Success, Some(1)), "1 is not success");
}

#[test]
fn failure_status_success_refuses_a_signal() {
    assert!(
        !status_ok(&Status::Success, None),
        "a killed process is not success"
    );
}

#[test]
fn edge_status_failed_takes_any_non_zero_exit() {
    assert!(status_ok(&Status::Failed, Some(3)), "3 is failed");
    assert!(!status_ok(&Status::Failed, Some(0)), "0 is not failed");
}

#[test]
fn edge_status_code_is_exact() {
    assert!(
        status_ok(&Status::Code(2), Some(2)) && !status_ok(&Status::Code(2), Some(1)),
        "? 2 needs 2"
    );
}

// ---------------------------------------------------------------- overwrite

#[test]
fn success_overwrite_replaces_a_cases_output() -> Result<(), String> {
    let text = "```\n$ a\nold\n```\n";
    let cases = parse(text)?;
    assert_eq!(
        overwrite(text, &cases, &[Some("new\n".to_string())]),
        "```\n$ a\nnew\n```\n",
        "replaced"
    );
    Ok(())
}

#[test]
fn edge_overwrite_keeps_a_case_given_none() -> Result<(), String> {
    let text = "```\n$ a\n[..]\n$ b\nold\n```\n";
    let cases = parse(text)?;
    let out = overwrite(text, &cases, &[None, Some("x\ny\n".to_string())]);
    assert_eq!(
        out, "```\n$ a\n[..]\n$ b\nx\ny\n```\n",
        "the matching case keeps its wildcard"
    );
    Ok(())
}

#[test]
fn edge_overwrite_fills_an_empty_case() -> Result<(), String> {
    let text = "```\n$ a\n```\n";
    let cases = parse(text)?;
    assert_eq!(
        overwrite(text, &cases, &[Some("x\n".to_string())]),
        "```\n$ a\nx\n```\n",
        "filled"
    );
    Ok(())
}

#[test]
fn edge_overwrite_keeps_the_status_line() -> Result<(), String> {
    let text = "```\n$ a\n? 2\nold\n```\n";
    let cases = parse(text)?;
    assert_eq!(
        overwrite(text, &cases, &[Some("n\n".to_string())]),
        "```\n$ a\n? 2\nn\n```\n",
        "status kept"
    );
    Ok(())
}

// ---------------------------------------------------------------- the runner

#[test]
fn success_the_runner_merges_stdout_and_stderr_in_order() -> Result<(), String> {
    let case = &parse("```\n$ sh -c 'echo out; echo err >&2; echo out2'\n```\n")?[0];
    let (output, code) = sh_runner().run_case(case)?;
    assert_eq!(
        (output.as_str(), code),
        ("out\nerr\nout2\n", Some(0)),
        "one stream, in write order"
    );
    Ok(())
}

#[test]
fn success_the_runner_sets_the_pinned_environment() -> Result<(), String> {
    let case = &parse("```\n$ sh -c 'echo $GOLDEN_TEST_VAR'\n```\n")?[0];
    let (output, _) = sh_runner().run_case(case)?;
    assert_eq!(output, "pinned\n", "the runner's env reaches the command");
    Ok(())
}

#[test]
fn success_the_runner_runs_in_its_working_directory() -> Result<(), String> {
    // A directory that is not the test process's own working directory.
    let scratch = tempfile::tempdir().map_err(|e| e.to_string())?;
    let dir = scratch.path().to_path_buf();
    std::fs::write(dir.join("marker"), "").map_err(|e| e.to_string())?;
    let mut runner = sh_runner();
    runner.cwd = dir.clone();
    let case = &parse("```\n$ sh -c 'test -f marker && echo here'\n```\n")?[0];
    let result = runner.run_case(case);
    assert_eq!(
        result?.0, "here\n",
        "relative paths resolve against the runner's cwd"
    );
    Ok(())
}

#[test]
fn failure_run_files_reports_a_wrong_exit_status() -> Result<(), String> {
    let scratch = tempfile::tempdir().map_err(|e| e.to_string())?;
    let dir = scratch.path().to_path_buf();
    let file = dir.join("c.trycmd");
    std::fs::write(&file, "```\n$ sh -c 'exit 2'\n```\n").map_err(|e| e.to_string())?;
    let failures = sh_runner().run_files(std::slice::from_ref(&file), false);
    assert_eq!(
        failures.len(),
        1,
        "a non-zero exit with no status line fails: {failures:?}"
    );
    assert!(
        failures[0].contains("exit Some(2)"),
        "it names the exit: {failures:?}"
    );
    Ok(())
}

#[test]
fn success_run_files_accepts_the_status_a_case_names() -> Result<(), String> {
    let scratch = tempfile::tempdir().map_err(|e| e.to_string())?;
    let dir = scratch.path().to_path_buf();
    let file = dir.join("d.trycmd");
    std::fs::write(&file, "```\n$ sh -c 'exit 2'\n? 2\n```\n").map_err(|e| e.to_string())?;
    let failures = sh_runner().run_files(std::slice::from_ref(&file), false);
    assert!(failures.is_empty(), "`? 2` expects exit 2: {failures:?}");
    Ok(())
}

#[test]
fn failure_the_runner_reports_the_exit_code() -> Result<(), String> {
    let case = &parse("```\n$ sh -c 'exit 3'\n```\n")?[0];
    let (_, code) = sh_runner().run_case(case)?;
    assert_eq!(code, Some(3), "the exit code comes back");
    Ok(())
}

#[test]
fn failure_an_unregistered_program_is_refused() -> Result<(), String> {
    let case = &parse("```\n$ ls\n```\n")?[0];
    let err = sh_runner()
        .run_case(case)
        .expect_err("ls is not registered");
    assert!(err.contains("ls"), "it names the program: {err}");
    Ok(())
}

#[test]
fn failure_a_case_past_its_deadline_is_ended() -> Result<(), String> {
    let mut runner = sh_runner();
    runner.deadline = Duration::from_secs(1);
    let case = &parse("```\n$ sh -c 'sleep 30'\n```\n")?[0];
    let started = std::time::Instant::now();
    let err = runner.run_case(case).expect_err("a hung case fails");
    assert!(err.contains("deadline"), "it says why: {err}");
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "it did not wait for the sleep"
    );
    Ok(())
}

#[test]
fn edge_a_name_maps_to_its_registered_path() -> Result<(), String> {
    let mut runner = sh_runner();
    runner
        .bins
        .push(("sipnab".to_string(), PathBuf::from("/bin/sh")));
    let case = &parse("```\n$ sipnab -c 'echo d'\n```\n")?[0];
    assert_eq!(
        runner.run_case(case)?.0,
        "d\n",
        "the name runs the registered path"
    );
    Ok(())
}

#[test]
fn edge_a_process_left_holding_the_pipe_is_ended_at_the_deadline() -> Result<(), String> {
    let mut runner = sh_runner();
    runner.deadline = Duration::from_secs(1);
    let case = &parse("```\n$ sh -c 'sleep 30 & echo started'\n```\n")?[0];
    let started = std::time::Instant::now();
    let err = runner
        .run_case(case)
        .expect_err("a background process holding the output fails the case");
    assert!(err.contains("deadline"), "it says why: {err}");
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "it did not wait for the sleep"
    );
    Ok(())
}

#[test]
fn edge_run_files_reports_a_mismatch_with_the_file_and_line() -> Result<(), String> {
    let scratch = tempfile::tempdir().map_err(|e| e.to_string())?;
    let dir = scratch.path().to_path_buf();
    let file = dir.join("a.trycmd");
    std::fs::write(&file, "```\n$ sh -c 'echo actual'\nexpected\n```\n")
        .map_err(|e| e.to_string())?;
    let failures = sh_runner().run_files(std::slice::from_ref(&file), false);
    assert_eq!(failures.len(), 1, "one failure: {failures:?}");
    assert!(
        failures[0].contains("a.trycmd:2") && failures[0].contains("actual"),
        "file, line, output: {failures:?}"
    );
    Ok(())
}

#[test]
fn edge_run_files_overwrite_rewrites_and_passes() -> Result<(), String> {
    let scratch = tempfile::tempdir().map_err(|e| e.to_string())?;
    let dir = scratch.path().to_path_buf();
    let file = dir.join("b.trycmd");
    std::fs::write(&file, "```\n$ sh -c 'echo actual'\n```\n").map_err(|e| e.to_string())?;
    let failures = sh_runner().run_files(std::slice::from_ref(&file), true);
    let text = std::fs::read_to_string(&file).map_err(|e| e.to_string())?;
    assert!(
        failures.is_empty(),
        "overwrite reports no failure: {failures:?}"
    );
    assert_eq!(
        text, "```\n$ sh -c 'echo actual'\nactual\n```\n",
        "the case now holds the output"
    );
    Ok(())
}

#[test]
fn edge_run_files_with_no_files_is_a_failure() {
    let failures = sh_runner().run_files(&[], false);
    assert_eq!(
        failures.len(),
        1,
        "no case files is a failure, never a pass: {failures:?}"
    );
}
