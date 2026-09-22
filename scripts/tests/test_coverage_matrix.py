"""What the surface-coverage matrix counts as a test driving a sipnab flag.

`e2e` is the strongest tier the matrix gives, and it means "a test passed this
flag to the sipnab binary". These fixtures pin the two ways the tier can lie:

- Crediting a FOREIGN tool's arguments. A test that runs tshark with
  `-T fields -e frame.comment` passes `-T` and `-e` to tshark. When sipnab's
  own writer tests began doing that, the matrix cited `src/capture/writer.rs`
  as end-to-end evidence for sipnab's `--text-dump` (`-T`), `--match` (`-e`)
  and `--count` (`-n`), none of which that file ever passes to sipnab.
- Missing sipnab run through the shared harness. `tests/support/run.rs`
  spawns the binary, so a test calling it drives sipnab even though its own
  file has no `Command::new`; such a file was reported as a mere mention.
"""

from conftest import load

cm = load("coverage-matrix")


def classify(files, token, short=""):
    """`cm.classify` over fixture files named relative to the repository."""
    return cm.classify(
        token,
        {cm.ROOT / rel: cm.strip_comments(text) for rel, text in files.items()},
        short,
    )


TSHARK_ONLY = """
#[test]
fn a_comment_reaches_wireshark() {
    let out = std::process::Command::new("tshark")
        .args(["-r", path, "-T", "fields", "-e", "frame.comment", "-n"])
        .output()
        .expect("run tshark");
    assert!(out.status.success());
}
"""


def test_a_foreign_tools_arguments_are_not_evidence_for_a_sipnab_flag():
    """tshark's `-T` is not sipnab's `--text-dump`, however the file spells it."""
    tier, where = classify({"src/capture/writer.rs": TSHARK_ONLY}, "--text-dump", "-T")
    assert tier != "e2e", (tier, where)
    tier, where = classify({"src/capture/writer.rs": TSHARK_ONLY}, "--match", "-e")
    assert tier != "e2e", (tier, where)


TSHARK_BOUND = """
#[test]
fn a_comment_reaches_wireshark() {
    let mut tshark = std::process::Command::new("tshark");
    tshark.args(["-r", path, "-T", "fields"]);
    let sipnab = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(["-N", "--json"])
        .output();
}
"""


def test_a_foreign_command_built_in_steps_is_still_foreign():
    """`let mut t = Command::new("tshark"); t.args([..])` is tshark's list too."""
    tier, where = classify({"tests/both_test.rs": TSHARK_BOUND}, "--text-dump", "-T")
    assert tier != "e2e", (tier, where)


TSHARK_LIST_FIRST = """
#[test]
fn a_comment_reaches_wireshark() {
    let fields = ["-r", path, "-T", "fields", "-e", "frame.comment"];
    let out = std::process::Command::new("tshark").args(fields).output();
}
"""


def test_a_file_that_starts_only_other_programs_does_not_run_sipnab():
    """A list built before the command is out of reach of the statement
    check, so this is the file-level rule alone: `Command::new` is not a
    sipnab launcher."""
    tier, where = classify({"src/capture/writer.rs": TSHARK_LIST_FIRST}, "--text-dump", "-T")
    assert tier != "e2e", (tier, where)


SUDO_WRAPPER = """
#[test]
fn a_failed_drop_aborts() {
    let out = Command::new("sudo")
        .args(["-n", env!("CARGO_BIN_EXE_sipnab"), "-N", "--user", "nobody"])
        .output()
        .expect("spawn sipnab under sudo");
}
"""


def test_a_wrapper_that_launches_sipnab_hands_it_its_arguments():
    """`sudo -n <sipnab> --user nobody` gives sipnab `--user`: a wrapper is
    not a foreign tool when its own list names the sipnab binary."""
    assert classify({"tests/privilege_drop_test.rs": SUDO_WRAPPER}, "--user") == (
        "e2e",
        ["tests/privilege_drop_test.rs"],
    )


SHELL_PAREN = """
#[test]
fn a_shell_step_then_sipnab() {
    let sh = std::process::Command::new("sh").arg("-c").arg("exit)").args(["-n", "5"]).status();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab")).arg("--json").output();
}
"""


def test_a_bracket_inside_a_string_does_not_end_the_foreign_statement():
    """The `)` in `"exit)"` is text, so the shell's `-n` after it is still the
    shell's and not sipnab's `--count`."""
    tier, where = classify({"tests/shell_test.rs": SHELL_PAREN}, "--count", "-n")
    assert tier != "e2e", (tier, where)


BOTH = """
#[test]
fn json_then_wireshark() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(["-N", "-I", path, "--json"])
        .output()
        .expect("run sipnab");
    let shark = std::process::Command::new("tshark")
        .args(["-r", path, "-T", "fields", "-e", "frame.comment"])
        .output()
        .expect("run tshark");
}
"""


def test_a_file_running_both_is_credited_only_for_what_sipnab_was_given():
    """The same file is e2e for sipnab's `--json` and not for tshark's `-T`."""
    assert classify({"tests/both_test.rs": BOTH}, "--json") == (
        "e2e",
        ["tests/both_test.rs"],
    )
    tier, where = classify({"tests/both_test.rs": BOTH}, "--text-dump", "-T")
    assert tier != "e2e", (tier, where)


HELPER = """
#[path = "support/run.rs"]
mod run_support;

#[test]
fn notes_reach_the_copy() {
    let (_out, _err, code) = run_support::run(&["-F", "-N", "--notes", notes], None);
    assert_eq!(code, Some(0));
}
"""


def test_sipnab_run_through_the_shared_harness_is_end_to_end():
    """`run_support::run` spawns the binary, so its argument list is e2e."""
    assert classify({"tests/annotate_cli_test.rs": HELPER}, "--notes") == (
        "e2e",
        ["tests/annotate_cli_test.rs"],
    )


BESIDE_THE_TEST = """
fn sipnab_bin() -> std::path::PathBuf {
    let mut p = std::env::current_exe().expect("test binary path");
    p.pop();
    p.join("sipnab")
}

#[test]
fn the_endpoint_answers() {
    let child = Command::new(sipnab_bin()).args(["-N", "--jitter-warn-ms", "12"]).spawn();
}
"""


def test_sipnab_found_beside_the_test_binary_is_end_to_end():
    """tests/metrics_headless_test.rs and tests/sandbox_test.rs find the
    binary from `current_exe()` rather than `CARGO_BIN_EXE_sipnab`."""
    assert classify({"tests/metrics_headless_test.rs": BESIDE_THE_TEST}, "--jitter-warn-ms") == (
        "e2e",
        ["tests/metrics_headless_test.rs"],
    )


MENTION = """
#[test]
fn the_help_names_it() {
    assert!(help_text().contains("--notes"));
    let unrelated = ["--notes"];
}
"""


def test_a_mention_in_a_file_that_never_runs_sipnab_stays_a_mention():
    """No launcher at all: an argument-shaped literal is still only a mention."""
    tier, _ = classify({"tests/help_test.rs": MENTION}, "--notes")
    assert tier == "referenced"
