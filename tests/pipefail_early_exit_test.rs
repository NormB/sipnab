// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! No pipe under `pipefail` feeds a reader that can stop before its writer is
//! done.
//!
//! `grep -q` exits at its first match, `head` after its count, `awk` at
//! `exit`, `sed` at `q`. The command still writing into the pipe then dies of
//! SIGPIPE (status 141), and `pipefail` makes the pipeline fail although the
//! reader found what it looked for. When the writer has less to say than a pipe
//! holds, the race is lost rarely: one run in 2400 on a loaded host, measured
//! on 2026-11-02 in `scripts/check-message-identity.sh`. When it has more, it
//! is lost every time.
//!
//! The rule lives once, in [`tests/support/pipefail_scan.rs`]. This file holds
//! three things to it:
//!
//! * the matcher, case by case (`success_*`, `failure_*`, `edge_*`);
//! * every tracked shell script, git hook and workflow `run:` block
//!   ([`success_no_tracked_shell_feeds_an_early_reader_under_pipefail`]);
//! * the race itself, with a writer that prints more than a pipe holds after
//!   the match: each old form fails every run and each replacement passes
//!   every run (`*_race_*`).
//!
//! `tests/split_debuginfo_test.rs` and `tests/private_identity_test.rs` hold
//! their own scripts to the same matcher.

use std::path::Path;
use std::process::Command;

#[path = "support/tracked.rs"]
mod tracked;

#[path = "support/pipefail_scan.rs"]
mod pipefail_scan;

use pipefail_scan::{
    early_exit_reader, is_shell_path, is_workflow_path, scan_shell, scan_shell_file, scan_workflow,
};

type TestError = Box<dyn std::error::Error>;

fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// The 1-based lines a pipefail shell flags in `text`.
fn flagged(text: &str) -> Vec<usize> {
    scan_shell(text, true).iter().map(|f| f.line).collect()
}

/// Assert that a shell with `pipefail` on or off flags exactly the lines
/// `want` in `text`.
#[track_caller]
fn expect_scan(text: &str, pipefail: bool, want: &[usize]) {
    let found = scan_shell(text, pipefail);
    let lines: Vec<usize> = found.iter().map(|f| f.line).collect();
    assert_eq!(
        lines, want,
        "lines flagged with pipefail {pipefail} in:\n{text}\nfindings: {found:?}"
    );
}

/// Assert that a pipefail shell flags exactly the lines `want` in `text`.
#[track_caller]
fn expect_flagged(text: &str, want: &[usize]) {
    expect_scan(text, true, want);
}

/// Assert that a whole shell file, read from its shebang, flags `want`.
#[track_caller]
fn expect_file(text: &str, want: &[usize]) {
    let found = scan_shell_file(text);
    let lines: Vec<usize> = found.iter().map(|f| f.line).collect();
    assert_eq!(
        lines, want,
        "lines flagged in the file:\n{text}\nfindings: {found:?}"
    );
}

/// Assert that a workflow flags exactly the file lines `want`.
#[track_caller]
fn expect_workflow(wf: &str, want: &[usize]) {
    let got = scan_workflow(wf).map(|f| f.iter().map(|f| f.line).collect::<Vec<_>>());
    assert_eq!(
        got,
        Ok(want.to_vec()),
        "lines flagged in the workflow:\n{wf}"
    );
}

/// Assert the readers a pipefail shell names in `text`.
#[track_caller]
fn expect_readers(text: &str, want: &[&str]) {
    let got: Vec<String> = scan_shell(text, true)
        .into_iter()
        .map(|f| f.reader)
        .collect();
    assert_eq!(got, want, "readers named in:\n{text}");
}

/// Assert what the reader predicate says about one command line.
#[track_caller]
fn expect_reader(line: &str, want: Option<&str>) {
    let words: Vec<&str> = line.split_whitespace().collect();
    assert_eq!(
        early_exit_reader(&words).as_deref(),
        want,
        "the reader `{line}` runs"
    );
}

/// Assert whether the gate reads `path` as shell.
#[track_caller]
fn expect_shell_path(path: &str, first_line: &str, want: bool) {
    assert_eq!(
        is_shell_path(path, first_line),
        want,
        "is {path} (first line `{first_line}`) shell"
    );
}

// ---------------------------------------------------------------------------
// FAILURE: a form that can lose the race is flagged.
// ---------------------------------------------------------------------------

#[test]
fn failure_grep_q_after_a_pipe_is_flagged() {
    expect_flagged("git cat-file -p \"$sha\" | grep -q -- 'SIG'\n", &[1]);
}

#[test]
fn failure_grep_q_in_an_option_cluster_is_flagged() {
    for cluster in ["-qE", "-Fxq", "-iq", "-qs", "-Eqx"] {
        expect_flagged(&format!("ls | grep {cluster} foo\n"), &[1]);
    }
}

#[test]
fn failure_grep_long_quiet_options_are_flagged() {
    for opt in [
        "--quiet",
        "--silent",
        "--files-with-matches",
        "--files-without-match",
    ] {
        expect_flagged(&format!("ls | grep {opt} foo\n"), &[1]);
    }
}

#[test]
fn failure_grep_max_count_in_every_spelling_is_flagged() {
    for opt in [
        "-m1",
        "-m 1",
        "--max-count=1",
        "--max-count 1",
        "-Em1",
        "-m0",
    ] {
        expect_flagged(&format!("out=$(ls | grep {opt} foo)\n"), &[1]);
    }
}

#[test]
fn failure_grep_files_with_matches_is_flagged() {
    // `-l` and `-L` stop at the first match too: measured with GNU grep 3.11,
    // 141 from a writer past a pipe's capacity.
    expect_flagged("ls | grep -l x | cat\nls | grep -L x | cat\n", &[1, 2]);
}

#[test]
fn failure_head_in_every_count_spelling_is_flagged() {
    for opt in ["", "-1", "-n1", "-n 1", "-c 400", "--lines=3", "--bytes 9"] {
        expect_flagged(&format!("v=$(seq 9 | head {opt})\n"), &[1]);
    }
}

#[test]
fn failure_awk_exit_in_a_main_rule_is_flagged() {
    let text = "u=$(dwarfdump --uuid \"$1\" | awk '/^UUID:/ { print $2; exit }')\n";
    expect_flagged(text, &[1]);
    expect_readers(text, &["awk exit"]);
}

#[test]
fn failure_awk_exit_in_begin_or_a_function_is_flagged() {
    expect_flagged("ls | awk 'BEGIN { exit 0 }'\n", &[1]);
    expect_flagged("ls | awk 'function f() { exit 1 } { f() }'\n", &[1]);
    expect_flagged("ls | gawk '{ nextfile }'\n", &[1]);
}

#[test]
fn failure_sed_quit_in_every_spelling_is_flagged() {
    for script in [
        "q",
        "5q",
        "'/x/{p;q}'",
        "-e 's/a/b/' -e q",
        "'s/a/b/;Q'",
        "-n '1{p;q2}'",
    ] {
        expect_flagged(&format!("ls | sed {script}\n"), &[1]);
    }
}

#[test]
fn failure_a_pipe_continued_on_the_next_line_is_flagged() {
    expect_flagged("ip -4 addr show |\n  grep -q 'inet '\n", &[2]);
    expect_flagged("ip -4 addr show \\\n  | grep -q 'inet '\n", &[2]);
    expect_flagged("ip addr |\n  # only IPv4\n  grep -q inet\n", &[3]);
}

#[test]
fn failure_a_pipe_inside_command_substitution_is_flagged() {
    expect_flagged("x=$(cmd | head -1)\n", &[1]);
    expect_flagged("echo \"binary: $(\"$B\" --version | head -1)\"\n", &[1]);
    expect_flagged("x=`cmd | head -1`\n", &[1]);
    expect_flagged("x=$(a $(b | grep -q c) d)\n", &[1]);
}

#[test]
fn failure_a_pipe_in_if_and_negation_is_flagged() {
    let text = "if cmd | grep -q x; then\n  :\nfi\nif ! cmd | grep -q y; then :; fi\n\
                while cmd | grep -q z; do :; done\n";
    expect_flagged(text, &[1, 4, 5]);
}

#[test]
fn failure_a_while_read_loop_that_breaks_is_flagged() {
    expect_flagged(
        "find . | while read -r f; do\n  [ -x \"$f\" ] && break\ndone\n",
        &[1],
    );
    expect_flagged("cmd | while IFS= read -r l; do\n  exit 3\ndone\n", &[1]);
}

#[test]
fn failure_a_single_read_after_a_pipe_is_flagged() {
    expect_flagged("cmd | read -r first\n", &[1]);
    expect_flagged("cmd | { read -r first; echo \"$first\"; }\n", &[1]);
    expect_flagged("cmd | (read -r first)\n", &[1]);
}

#[test]
fn failure_a_wrapped_reader_is_flagged() {
    for wrapper in [
        "LC_ALL=C",
        "env",
        "env -i LANG=C",
        "command",
        "nice -n 5",
        "timeout 5",
        "stdbuf -oL",
    ] {
        expect_flagged(&format!("ls | {wrapper} grep -q x\n"), &[1]);
    }
}

#[test]
fn failure_a_reader_in_the_middle_of_a_pipeline_is_flagged() {
    let text = "printf '%s\\n' \"$out\" | head -20 | sed 's/^/  /'\n";
    expect_flagged(text, &[1]);
    expect_readers(text, &["head"]);
}

#[test]
fn failure_a_pipe_with_stderr_is_flagged() {
    expect_flagged("cmd |& grep -q x\n", &[1]);
}

#[test]
fn failure_a_pipe_in_process_substitution_is_flagged() {
    expect_flagged("diff <(cmd | head -5) other\n", &[1]);
}

#[test]
fn failure_a_pipe_in_a_case_arm_is_flagged() {
    expect_flagged(
        "case $x in\n  a|b) cmd | grep -q y ;;\n  *) : ;;\nesac\n",
        &[2],
    );
}

#[test]
fn failure_a_status_discarded_by_or_true_is_still_flagged() {
    // One rule, without exceptions by context: the pipeline below cannot fail
    // the script, but the same text one edit later can, and the form that
    // reads all its input costs nothing.
    expect_flagged("x=$(ls | head -1) || true\n", &[1]);
}

#[test]
fn failure_a_nested_bash_c_with_pipefail_is_flagged() {
    expect_scan("bash -c 'set -o pipefail; ls | grep -q x'\n", false, &[1]);
    expect_scan("bash -eo pipefail -c 'ls | head -1'\n", false, &[1]);
    expect_scan(
        "bash --noprofile --norc -e -o pipefail -c 'ls | head -1'\n",
        false,
        &[1],
    );
}

#[test]
fn failure_set_euo_pipefail_turns_the_rule_on() {
    for set in [
        "set -euo pipefail",
        "set -Eeuo pipefail",
        "set -o pipefail",
        "set -e -o pipefail",
        "set -o errexit -o pipefail",
        "set -eou pipefail",
        "shopt -so pipefail",
        "shopt -s -o pipefail",
    ] {
        expect_file(
            &format!("#!/usr/bin/env bash\n{set}\nls | grep -q x\n"),
            &[3],
        );
    }
}

#[test]
fn failure_a_sourced_library_is_read_as_pipefail() {
    // No shebang: the file is sourced, and the scripts that source these
    // libraries run with pipefail.
    expect_file(
        "# SPDX-License-Identifier: MIT OR Apache-2.0\nf() { ls | grep -q x; }\n",
        &[2],
    );
}

#[test]
fn failure_a_shebang_with_pipefail_turns_the_rule_on() {
    expect_file("#!/bin/bash -eo pipefail\nls | head -1\n", &[2]);
}

#[test]
fn failure_an_unquoted_heredoc_runs_its_substitutions() {
    expect_flagged(
        "cat <<EOF\nversion: $(cmd --version | head -1)\nEOF\n",
        &[2],
    );
}

#[test]
fn failure_a_workflow_step_with_shell_bash_is_pipefail() {
    let wf = "jobs:\n  a:\n    steps:\n      - name: x\n        shell: bash\n        run: |\n          echo hi\n          ls | grep -q x\n";
    expect_workflow(wf, &[8]);
}

#[test]
fn failure_a_workflow_block_that_sets_pipefail_is_scanned() {
    let wf = "jobs:\n  a:\n    steps:\n      - run: |\n          set -euo pipefail\n          v=$(ls | head -1)\n      - name: y\n        run: ls | grep -q x\n";
    expect_workflow(wf, &[6]);
}

#[test]
fn failure_a_composite_action_step_is_scanned() {
    let action = "runs:\n  using: composite\n  steps:\n    - name: v\n      shell: bash\n      run: cargo nextest --version | grep -qF \"x\"\n";
    expect_workflow(action, &[6]);
}

#[test]
fn failure_workflow_defaults_are_refused_rather_than_guessed() {
    let wf =
        "defaults:\n  run:\n    shell: bash\njobs:\n  a:\n    steps:\n      - run: ls | head -1\n";
    let got = scan_workflow(wf);
    assert!(
        matches!(&got, Err(e) if e.contains("defaults")),
        "defaults.run.shell must be refused, not silently ignored: {got:?}"
    );
}

#[test]
fn failure_the_pre_fix_release_gate_lines_are_flagged() {
    // The three release-path lines this sweep changed, as they were at
    // 47f2630b5. The gate must see each of them.
    let old = "set -euo pipefail\n\
        if ! git cat-file -p \"$sha\" | grep -q -- '-----BEGIN SSH SIGNATURE-----'; then\n\
        \techo x\nfi\n\
        if ! out=$(git verify-tag \"$sha\" 2>&1) \\\n\
        \t|| ! printf '%s\\n' \"$out\" | grep -q '^Good \"git\" signature for '; then\n\
        \texit 1\nfi\n\
        if ! \"$bin\" --version | grep -q 'bpf'; then\n    exit 3\nfi\n";
    expect_flagged(old, &[2, 6, 9]);
}

// ---------------------------------------------------------------------------
// SUCCESS: a form that reads all of its input is not flagged.
// ---------------------------------------------------------------------------

#[test]
fn success_a_here_string_has_no_writer_to_kill() {
    expect_flagged("grep -q '^Good' <<<\"$out\"\n", &[]);
    expect_flagged(
        "if ! grep -qx \"$T\" <<<\"$(rustup target list)\"; then :; fi\n",
        &[],
    );
}

#[test]
fn success_a_reader_given_a_file_has_no_pipe() {
    expect_flagged(
        "grep -q x file.txt\nhead -1 file\nawk '{exit}' f\nsed q f\n",
        &[],
    );
}

#[test]
fn success_readers_that_read_to_the_end_are_not_flagged() {
    let text = "ls | grep x\nls | grep -c x\nls | grep -v x | wc -l\nls | tail -1\nls | sort -u\n\
                ls | cut -d: -f1\nls | xargs grep -q x\nls | tee log\nls | grep -s x\n";
    expect_flagged(text, &[]);
}

#[test]
fn success_sed_without_a_quit_reads_to_the_end() {
    expect_flagged(
        "ls | sed -n 1p\nls | sed -n '1,20p'\nls | sed 's/^/  /'\nls | sed -n '/x/{p}'\n",
        &[],
    );
}

#[test]
fn success_awk_that_exits_only_in_end_reads_to_the_end() {
    let text = "v=$(printf '%s\\n' \"$b\" | awk '$1 == s { v = $2; f = 1 } END { if (!f) exit 3; print v }')\n\
                ls | awk '/^UUID:/ && !f { print $2; f = 1 }'\nls | awk 'NR==1'\n";
    expect_flagged(text, &[]);
}

#[test]
fn success_head_with_a_negative_count_reads_to_the_end() {
    expect_flagged(
        "ls | head -n -1\nls | head -c -5\nls | head --lines=-2\n",
        &[],
    );
}

#[test]
fn success_a_while_read_loop_without_break_reads_to_the_end() {
    let text = "ls | while IFS= read -r f; do\n  echo \"$f\"\n  for x in a; do break; done\ndone\n";
    expect_flagged(text, &[]);
}

#[test]
fn success_a_shell_without_pipefail_is_not_flagged() {
    // Without pipefail a pipeline's status is its last command's, so the
    // writer's 141 is never seen.
    expect_scan("ls | grep -q x\n", false, &[]);
    expect_file("#!/bin/sh\nset -eu\nls | grep -q x\n", &[]);
    expect_file("#!/bin/bash -eu\nls | head -1\n", &[]);
}

#[test]
fn success_set_plus_o_pipefail_turns_the_rule_off_until_it_is_on_again() {
    expect_flagged(
        "set -o pipefail\nset +o pipefail\nls | head -1\nset -o pipefail\nls | head -1\n",
        &[5],
    );
}

#[test]
fn success_pipefail_set_in_a_subshell_does_not_leak() {
    expect_file(
        "#!/usr/bin/env bash\n( set -o pipefail; true )\nx=$(set -o pipefail)\nls | head -1\n",
        &[],
    );
}

#[test]
fn success_or_and_and_are_not_pipes() {
    expect_flagged(
        "cmd || grep -q x f\ncmd && head -1 f\n[ -n \"$a\" ] || exit 1\n",
        &[],
    );
}

#[test]
fn success_a_workflow_step_on_the_default_shell_is_not_pipefail() {
    // GitHub runs a step with no `shell:` as `bash -e {0}`: no pipefail.
    let wf = "jobs:\n  a:\n    steps:\n      - name: x\n        run: |\n          ls | grep -q x\n";
    expect_workflow(wf, &[]);
}

#[test]
fn success_workflow_shell_overrides_are_honored() {
    expect_workflow(
        "jobs:\n  a:\n    steps:\n      - shell: sh\n        run: ls | grep -q x\n",
        &[],
    );
    expect_workflow(
        "jobs:\n  a:\n    steps:\n      - shell: python\n        run: |\n          import x | y\n",
        &[],
    );
    expect_workflow(
        "jobs:\n  a:\n    steps:\n      - shell: bash -e -o pipefail {0}\n        run: ls | head -1\n",
        &[5],
    );
    expect_workflow(
        "jobs:\n  a:\n    steps:\n      - shell: bash -e {0}\n        run: ls | head -1\n",
        &[],
    );
}

#[test]
fn success_the_fixed_release_gate_lines_are_not_flagged() {
    let new = "set -euo pipefail\n\
        tag=$(git cat-file -p \"$sha\")\n\
        if ! grep -q -- '-----BEGIN SSH SIGNATURE-----' <<<\"$tag\"; then\n\techo x\nfi\n\
        if ! out=$(git verify-tag \"$sha\" 2>&1) \\\n\
        \t|| ! grep -q '^Good \"git\" signature for ' <<<\"$out\"; then\n\texit 1\nfi\n";
    expect_flagged(new, &[]);
}

#[test]
fn success_the_scanner_selects_shell_and_workflow_files() {
    expect_shell_path("tools/x.sh", "#!/usr/bin/env bash", true);
    expect_shell_path("tools/lib-x.sh", "# SPDX-License-Identifier: MIT", true);
    expect_shell_path(".githooks/pre-push", "#!/bin/sh", true);
    expect_shell_path("tests/fixtures/probe-curl-stub", "#!/bin/sh", true);
    expect_shell_path("ops/oss-fuzz/build.sh.shim", "#!/bin/bash -eu", true);
    expect_shell_path("docs/homer.md", "#!/bin/sh", false);
    expect_shell_path("src/main.rs", "//! x", false);
    expect_shell_path("tools/x.py", "#!/usr/bin/env python3", false);
    for (path, want) in [
        (".github/workflows/ci.yml", true),
        (".github/actions/nextest/action.yml", true),
        (".github/dependabot.yml", false),
        (".github/ISSUE_TEMPLATE/bug_report.yml", false),
    ] {
        assert_eq!(is_workflow_path(path), want, "is {path} a workflow");
    }
}

#[test]
fn success_the_reader_predicate_names_the_reader() {
    expect_reader("grep -q x", Some("grep -q"));
    expect_reader("/usr/bin/head -1", Some("head"));
    expect_reader("sed 5q", Some("sed q"));
    expect_reader("grep x", None);
    expect_reader("cat", None);
}

// ---------------------------------------------------------------------------
// EDGE: text that only looks like a pipe, and positions that must stay exact.
// ---------------------------------------------------------------------------

#[test]
fn edge_a_comment_is_not_code() {
    expect_flagged("# cmd | grep -q x\nls # | head -1\n  #ls | head\n", &[]);
}

#[test]
fn edge_a_hash_inside_a_word_is_not_a_comment() {
    expect_flagged("echo ${#a} a#b | grep -q y\n", &[1]);
}

#[test]
fn edge_quoted_strings_that_contain_pipes_are_not_pipes() {
    let text = "echo 'a | grep -q b'\necho \"c | head -1\"\nprintf '%s' $'x | head'\n\
                msg=\"use cmd | grep -q at your peril\"\n";
    expect_flagged(text, &[]);
}

#[test]
fn edge_an_escaped_pipe_is_not_a_pipe() {
    expect_flagged("echo a \\| grep -q b\ngrep 'a\\|b' f\n", &[]);
}

#[test]
fn edge_a_quoted_heredoc_body_is_data() {
    expect_flagged(
        "cat <<'EOF'\nls | grep -q x\n$(ls | head -1)\nEOF\nls | head -1\n",
        &[5],
    );
}

#[test]
fn edge_heredoc_forms_end_where_bash_ends_them() {
    // `<<-` strips leading tabs from the delimiter line; a delimiter that is
    // not alone on its line does not end the body; two bodies follow one line.
    expect_flagged("cat <<-EOF\n\tls | grep -q x\n\tEOF\nls | head -1\n", &[4]);
    expect_flagged("cat <<'EOF'\nEOF not yet\nls | head -1\nEOF\n", &[]);
    expect_flagged(
        "cat <<'A' <<'B'\nls | head\nA\nls | head\nB\nls | head -1\n",
        &[6],
    );
}

#[test]
fn edge_case_patterns_are_not_pipes() {
    // The alternatives name readers on purpose: read as pipes, `|head)` and
    // `|read)` would each be flagged.
    expect_flagged(
        "case \"$x\" in\n  tail|head) echo one ;;\n  (d|read) echo two ;;\n  @(f|head)) : ;;\nesac\n",
        &[],
    );
}

#[test]
fn edge_a_comment_between_case_arms_is_not_a_pattern() {
    // Read as a pattern, the comment would end at its `)` and leave
    // `ls | head -1` behind as code.
    expect_flagged(
        "case \"$x\" in\n  # old: a) ls | head -1\n  b) : ;;\nesac\n",
        &[],
    );
}

#[test]
fn edge_conditional_and_arithmetic_bars_are_not_pipes() {
    let text = "[[ $x =~ ^(a|b)$ ]] && echo y\nn=$(( a | b ))\n(( m |= 4 ))\n\
                v=${var//|/,}\narr=(a '|' b)\n";
    expect_flagged(text, &[]);
}

#[test]
fn edge_grep_arguments_are_parsed_not_matched() {
    // `-q` here is a pattern, not an option.
    expect_flagged(
        "ls | grep -e -q f\nls | grep -- -q\nls | grep -e-q f\n",
        &[],
    );
    // GNU grep permutes options, so a `-q` after the pattern still counts.
    expect_flagged("ls | grep pattern -q\n", &[1]);
}

#[test]
fn edge_awk_and_sed_text_that_spells_exit_or_q_is_not_a_quit() {
    let text = "ls | awk '{ print \"exit\" }'\nls | awk '/exit/'\nls | awk '{ exit_code = 1 }'\n\
                ls | awk '{ x = 4 / 2; y = 1 } # exit\n'\nls | sed 's/q/Q/'\nls | sed '/q/d'\n\
                ls | sed 'y/q/Q/'\nls | sed -n '\\,q,p'\nls | sed 's/a/b/g;s/q//'\n";
    expect_flagged(text, &[]);
}

#[test]
fn edge_line_numbers_survive_heredocs_continuations_and_strings() {
    expect_flagged(
        "cat <<EOF\none\ntwo\nEOF\necho 'multi\nline'\nls \\\n  -l\nls | head -1\n",
        &[9],
    );
}

#[test]
fn edge_workflow_lines_map_to_the_file() {
    let wf = "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: x@y\n\
              \n      - name: s\n        shell: bash\n        run: |\n          # comment\n\n          echo ok\n\
              \n          ls | head -1\n      - name: t\n        shell: bash\n        run: ls | grep -q y\n";
    expect_workflow(wf, &[15, 18]);
}

#[test]
fn edge_workflow_folded_and_quoted_runs_are_read() {
    // A finding names the reader's line: `| head -1` sits on line 7.
    expect_workflow(
        "jobs:\n  a:\n    steps:\n      - shell: bash\n        run: >-\n          ls\n          | head -1\n",
        &[7],
    );
    expect_workflow(
        "jobs:\n  a:\n    steps:\n      - shell: bash\n        run: 'ls | grep -q ''x'''\n",
        &[5],
    );
}

#[test]
fn edge_workflow_expressions_are_not_pipes() {
    let wf = "jobs:\n  a:\n    steps:\n      - shell: bash\n        run: |\n          echo \"${{ inputs.a || 'b' }}\"\n          echo ${{ github.ref }} | tee x\n";
    expect_workflow(wf, &[]);
}

#[test]
fn edge_a_shell_key_belongs_to_its_own_step() {
    // The `shell: bash` of the first step must not leak into the second.
    let wf = "jobs:\n  a:\n    steps:\n      - name: one\n        shell: bash\n        run: echo 1\n      - name: two\n        run: ls | head -1\n";
    expect_workflow(wf, &[]);
}

#[test]
fn edge_redirections_and_functions_do_not_hide_a_reader() {
    let text = "f() {\n  cmd 2>/dev/null | grep -q x 2>&1\n}\nfunction g {\n  cmd >&2 | head -1 >/dev/null\n}\n";
    expect_flagged(text, &[2, 5]);
}

#[test]
fn edge_a_break_in_a_nested_loop_does_not_end_the_reader() {
    expect_flagged(
        "ls | while read -r f; do\n  for x in 1 2; do break; done\ndone\n",
        &[],
    );
    expect_flagged(
        "ls | while read -r f; do\n  for x in 1 2; do :; done\n  break\ndone\n",
        &[1],
    );
}

#[test]
fn edge_brackets_heredoc_strings_and_backticks_inside_double_quotes() {
    // A `$( )` inside double quotes is code; a backtick inside single quotes
    // is not.
    expect_flagged(
        "echo \"$(ls | head -1)\"\necho '`ls | head -1`'\necho \"`ls | head -1`\"\n",
        &[1, 3],
    );
}

// ---------------------------------------------------------------------------
// The gate.
// ---------------------------------------------------------------------------

/// Sites that are provably safe, by path and exact line text, each with the
/// reason no writer can be killed there. An entry no finding matches fails the
/// gate, so the list cannot outlive the line it excuses.
const ALLOWED: &[(&str, &str, &str)] = &[];

/// Tracked files the scanner does not read as shell that mention `pipefail`,
/// each with why that is not a pipefail shell the gate misses. A new carrier
/// fails the gate until it is scanned or reviewed here.
const REVIEWED_PIPEFAIL_MENTIONS: &[(&str, &str)] = &[
    (
        "tests/private_identity_test.rs",
        "doc comments describing the race; it runs check-message-identity.sh, which the gate scans",
    ),
    (
        "tests/split_debuginfo_test.rs",
        "doc comments describing the race; it runs split-debuginfo.sh, which the gate scans",
    ),
    (
        "tests/dev_docs_drift_test.rs",
        "a link-count ratchet comment that names this gate's two files",
    ),
    (
        "tests/tag_signature_gate_test.rs",
        "doc comments describing the race; it runs tag-signature-check.sh, which the gate scans",
    ),
    (
        "tests/pipefail_early_exit_test.rs",
        "this gate: its cases are shell text by design",
    ),
    ("tests/support/pipefail_scan.rs", "the matcher itself"),
    (
        "scripts/tests/test_fuzz_workflow_input.py",
        "runs a fuzz.yml `shell: bash` run block, which the gate scans as pipefail",
    ),
];

/// Text formats that describe shell rather than run it.
fn is_prose(path: &str) -> bool {
    [
        ".md", ".txt", ".html", ".svg", ".json", ".toml", ".cast", ".tape",
    ]
    .iter()
    .any(|ext| path.ends_with(ext))
        || path.starts_with("docs/")
        || path.starts_with("website/")
}

fn tracked_files() -> Result<Vec<String>, TestError> {
    tracked::ls_files(repo(), &[])
}

#[test]
fn success_no_tracked_shell_feeds_an_early_reader_under_pipefail() -> Result<(), TestError> {
    let mut found: Vec<(String, usize, String, String)> = Vec::new();
    let mut errors = Vec::new();
    let mut unreviewed = Vec::new();
    let (mut shells, mut workflows) = (0usize, 0usize);
    for path in tracked_files()? {
        let full = repo().join(&path);
        let Ok(text) = std::fs::read_to_string(&full) else {
            continue; // binary or not checked out
        };
        let first = text.lines().next().unwrap_or("");
        let findings = if is_workflow_path(&path) {
            workflows += 1;
            match scan_workflow(&text) {
                Ok(f) => f,
                Err(e) => {
                    errors.push(format!("{path}: {e}"));
                    continue;
                }
            }
        } else if is_shell_path(&path, first) {
            shells += 1;
            scan_shell_file(&text)
        } else {
            if text.contains("pipefail")
                && !is_prose(&path)
                && !REVIEWED_PIPEFAIL_MENTIONS.iter().any(|(p, _)| *p == path)
            {
                unreviewed.push(path.clone());
            }
            continue;
        };
        let lines: Vec<&str> = text.lines().collect();
        for f in findings {
            let line_text = lines.get(f.line - 1).map_or("", |l| l.trim()).to_owned();
            found.push((path.clone(), f.line, f.reader, line_text));
        }
    }

    let stale: Vec<_> = ALLOWED
        .iter()
        .filter(|(p, l, _)| !found.iter().any(|(fp, _, _, fl)| fp == p && fl == l))
        .collect();
    let offenders: Vec<String> = found
        .iter()
        .filter(|(p, _, _, l)| !ALLOWED.iter().any(|(ap, al, _)| ap == p && al == l))
        .map(|(p, n, r, l)| format!("{p}:{n}: `{r}` after a pipe: {l}"))
        .collect();
    let stale_reviews: Vec<_> = REVIEWED_PIPEFAIL_MENTIONS
        .iter()
        .filter(|(p, _)| {
            std::fs::read_to_string(repo().join(p)).map_or(true, |t| !t.contains("pipefail"))
        })
        .collect();

    assert!(
        shells > 50 && workflows > 15,
        "the scan found {shells} shells and {workflows} workflows"
    );
    assert!(
        errors.is_empty(),
        "files the scanner cannot read: {errors:#?}"
    );
    assert!(
        offenders.is_empty(),
        "under pipefail, these pipes feed a reader that can stop before the writer \
         is done; the writer then dies of SIGPIPE (141) and the pipeline fails although \
         the reader matched. Read a here-string, a file, or a captured variable instead, \
         or use a reader that reads to the end (see CONTRIBUTING.md, \"Shell and \
         pipefail\"):\n{}",
        offenders.join("\n")
    );
    assert!(
        stale.is_empty(),
        "allowlist entries no finding matches: {stale:?}"
    );
    assert!(
        unreviewed.is_empty(),
        "files mention pipefail but are not scanned as shell or workflow: {unreviewed:?}"
    );
    assert!(
        stale_reviews.is_empty(),
        "reviewed carriers that no longer mention pipefail: {stale_reviews:?}"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// The race, induced: a writer that prints far more than a pipe holds AFTER
// the line the reader stops at.
// ---------------------------------------------------------------------------

/// How many times each form runs. Every old form must fail every run and
/// every replacement must pass every run; the outcome does not depend on
/// timing, because the writer still has data when the reader exits.
const RUNS: usize = 200;

/// Run `form` [`RUNS`] times under `set -euo pipefail` with `produce` printing
/// `MATCH` and then 1 MiB, sixteen times a pipe's capacity on Linux, and
/// return how many runs succeeded. 256 KiB was not enough: mawk 1.3.4 reads
/// that far ahead before it acts on `exit`, and the old awk form passed 192
/// of 200 runs (measured 2026-11-08; 0 of 100 at 1 MiB).
fn race(form: &str) -> Result<usize, TestError> {
    let script = format!(
        "set -euo pipefail\n\
         FILLER=$(printf '%*s' 1048576 '')\n\
         produce() {{ printf 'MATCH\\n'; printf '%s\\n' \"$FILLER\"; }}\n\
         ok=0\n\
         for _ in $(seq {RUNS}); do\n\
           if ( {form} ) >/dev/null 2>&1; then ok=$((ok + 1)); fi\n\
         done\n\
         echo \"$ok\"\n"
    );
    let out = Command::new("/bin/bash")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .args(["--noprofile", "--norc", "-c", &script])
        .output()?;
    if !out.status.success() {
        return Err(format!(
            "the race harness failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )
        .into());
    }
    Ok(String::from_utf8(out.stdout)?.trim().parse()?)
}

/// The old and the new form of each reader this sweep replaced.
const FORMS: &[(&str, &str, &str)] = &[
    (
        "grep -q",
        "produce | grep -q MATCH",
        "out=$(produce); grep -q MATCH <<<\"$out\"",
    ),
    (
        "grep -m1",
        "v=$(produce | grep -m1 MATCH)",
        "v=$(produce | grep MATCH); v=${v%%$'\\n'*}; [ \"$v\" = MATCH ]",
    ),
    (
        "head -1",
        "v=$(produce | head -1)",
        "v=$(produce | sed -n 1p); [ \"$v\" = MATCH ]",
    ),
    (
        "awk exit",
        "v=$(produce | awk '/MATCH/ { print; exit }')",
        "v=$(produce | awk '/MATCH/ && !f { print; f = 1 }'); [ \"$v\" = MATCH ]",
    ),
    (
        "sed q",
        "v=$(produce | sed -n '/MATCH/{p;q}')",
        "v=$(produce | sed -n '/MATCH/p')",
    ),
];

fn form(name: &str) -> Result<(&'static str, &'static str), TestError> {
    FORMS
        .iter()
        .find(|(n, _, _)| *n == name)
        .map(|(_, old, new)| (*old, *new))
        .ok_or_else(|| format!("no form named {name} in FORMS").into())
}

fn assert_old_form_loses(name: &str) -> Result<(), TestError> {
    let (old, _) = form(name)?;
    assert!(
        !flagged(&format!("{old}\n")).is_empty(),
        "the gate must flag the old {name} form"
    );
    let ok = race(old)?;
    assert_eq!(
        ok, 0,
        "the old {name} form passed {ok} of {RUNS} runs; the writer was not killed"
    );
    Ok(())
}

fn assert_new_form_wins(name: &str) -> Result<(), TestError> {
    let (_, new) = form(name)?;
    assert!(
        flagged(&format!("{new}\n")).is_empty(),
        "the gate must accept the new {name} form"
    );
    let ok = race(new)?;
    assert_eq!(
        ok, RUNS,
        "the new {name} form passed only {ok} of {RUNS} runs"
    );
    Ok(())
}

#[test]
fn failure_race_grep_q_on_a_pipe_loses_every_run() -> Result<(), TestError> {
    assert_old_form_loses("grep -q")
}

#[test]
fn failure_race_grep_m1_on_a_pipe_loses_every_run() -> Result<(), TestError> {
    assert_old_form_loses("grep -m1")
}

#[test]
fn failure_race_head_on_a_pipe_loses_every_run() -> Result<(), TestError> {
    assert_old_form_loses("head -1")
}

#[test]
fn failure_race_awk_exit_on_a_pipe_loses_every_run() -> Result<(), TestError> {
    assert_old_form_loses("awk exit")
}

#[test]
fn failure_race_sed_q_on_a_pipe_loses_every_run() -> Result<(), TestError> {
    assert_old_form_loses("sed q")
}

#[test]
fn success_race_a_here_string_wins_every_run() -> Result<(), TestError> {
    assert_new_form_wins("grep -q")
}

#[test]
fn success_race_grep_reading_to_the_end_wins_every_run() -> Result<(), TestError> {
    assert_new_form_wins("grep -m1")
}

#[test]
fn success_race_sed_n_1p_wins_every_run() -> Result<(), TestError> {
    assert_new_form_wins("head -1")
}

#[test]
fn success_race_awk_with_a_flag_wins_every_run() -> Result<(), TestError> {
    assert_new_form_wins("awk exit")
}

#[test]
fn success_race_sed_without_q_wins_every_run() -> Result<(), TestError> {
    assert_new_form_wins("sed q")
}
