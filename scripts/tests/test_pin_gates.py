# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors
"""scripts/pin-gates.py: the gates that count tracked files, run alone, against the index.

On 2026-11-12 one pull request spent three runs of the pre-commit hook, about
25 minutes of the host's build slot each, finding five count pins one hook run
at a time: a new workflow, script and page change what `git ls-files` lists,
and the tests that count them are among 16,000 others at the end of the hook.
The script runs only those tests, the way the hook runs them, in about two
minutes. These tests hold its list to the tree and its command to the hook's.
"""

import pathlib
import re

import pytest
from conftest import load

REPO = pathlib.Path(__file__).resolve().parent.parent.parent

pg = load("pin-gates")
pt = load("parallel-tests")

COUNT_PIN = "    const EXPECTED_PAGES: usize = 12;\n"
# The command name is written in two halves: tests/support_selftest.rs refuses a
# quoted `ls-` + `files` in any script, since every real call goes through the shared reader.
LISTING = "ls-" + "files"
INDEX_READ = f'    let out = Command::new("git").args(["{LISTING}", "-z"]).output()?;\n'
TRACKED = '#[path = "support/tracked.rs"]\nmod tracked;\n'


# ── the list file ───────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "text, run, excluded",
    [
        ("", [], {}),
        ("docs_drift_test\n", ["docs_drift_test"], {}),
        ("docs_drift_test\nsite_journey_test\n", ["docs_drift_test", "site_journey_test"], {}),
        ("# a comment\n\ndocs_drift_test\n", ["docs_drift_test"], {}),
        ("docs_drift_test  # counts pages\n", ["docs_drift_test"], {}),
        ("  docs_drift_test  \n", ["docs_drift_test"], {}),
        ("!crate_package_test runs cargo package\n", [], {"crate_package_test": "runs cargo package"}),
        ("a_test\n!b_test slow: 90 s\n", ["a_test"], {"b_test": "slow: 90 s"}),
        ("!b_test   two  spaces kept\n", [], {"b_test": "two  spaces kept"}),
        ("a_test\r\nb2_test\r\n", ["a_test", "b2_test"], {}),
        ("a_test", ["a_test"], {}),
        ("#only\n#comments\n", [], {}),
    ],
)
def test_a_list_is_read(text, run, excluded):
    got_run, got_excluded, problems = pg.parse_list(text)
    assert (got_run, got_excluded, problems) == (run, excluded, [])


@pytest.mark.parametrize(
    "text, word",
    [
        ("Docs_Drift\n", "not a test binary name"),
        ("docs-drift-test\n", "not a test binary name"),
        ("tests/docs_drift_test.rs\n", "not a test binary name"),
        ("a_test b_test\n", "not a test binary name"),
        ("a_test\na_test\n", "twice"),
        ("a_test\n!a_test slow\n", "twice"),
        ("!a_test slow\n!a_test slower\n", "twice"),
        ("!a_test\n", "no reason"),
        ("!a_test   \n", "no reason"),
        ("!\n", "not a test binary name"),
        ("! a_test reason\n", "not a test binary name"),
        ("a_test\n!b_test # only a comment\n", "no reason"),
    ],
)
def test_a_list_that_is_wrong_is_refused(text, word):
    _run, _excluded, problems = pg.parse_list(text)
    assert len(problems) == 1 and word in problems[0], problems
    assert "line " in problems[0], "the problem names the line"


# ── which tests are pin gates ───────────────────────────────────────────────


@pytest.mark.parametrize(
    "source, is_gate",
    [
        (COUNT_PIN, True),
        (INDEX_READ, True),
        (TRACKED, True),
        ("const EXPECTED_WIKI_LINKS: usize = 2638;", True),
        ("    const EXPECTED_CODE_LINKS: usize =\n        853;", True),
        (f'.args(["{LISTING}"])', True),
        ('mod t {\n    #[path = "../support/tracked.rs"]\n    mod tracked;\n}', True),
        ("const EXPECTED_TEMPLATES: usize = 4; // and more\n" + INDEX_READ, True),
        ("fn a() {}\n", False),
        ('const EXPECTED: &str = "x";', False),
        ("const EXPECTED_NAME: &str = \"usize\";", False),
        ("let expected_pages: usize = 3;", False),
        ("const MAX_PAGES: usize = 3;", False),
        ("// see ls_files in the hook\n", False),
        ('#[path = "support/markdown.rs"]\nmod markdown;', False),
        ("", False),
    ],
)
def test_a_pin_gate_is_known_by_its_source(source, is_gate):
    assert (pg.derived({"some_test": source}) == {"some_test"}) is is_gate


def test_derived_names_every_gate_and_only_gates():
    sources = {"a_test": COUNT_PIN, "b_test": "fn b() {}", "c_test": INDEX_READ, "d_test": TRACKED}
    assert pg.derived(sources) == {"a_test", "c_test", "d_test"}
    assert pg.derived({}) == set()


@pytest.mark.parametrize(
    "run, excluded, sources, words",
    [
        (["a_test"], {}, {"a_test": COUNT_PIN}, []),
        (["a_test"], {"b_test": "slow"}, {"a_test": COUNT_PIN, "b_test": INDEX_READ}, []),
        # A test that is no pin gate by its source may be listed: the list is a floor.
        (["a_test", "plain_test"], {}, {"a_test": COUNT_PIN, "plain_test": "fn p() {}"}, []),
        ([], {}, {"plain_test": "fn p() {}"}, []),
        ([], {}, {"a_test": COUNT_PIN}, ["a_test", "neither run nor excluded"]),
        (["a_test"], {}, {"a_test": COUNT_PIN, "new_test": INDEX_READ}, ["new_test", "neither run nor excluded"]),
        (["a_test", "gone_test"], {}, {"a_test": COUNT_PIN}, ["gone_test", "no tests/gone_test.rs"]),
        (["a_test"], {"gone_test": "slow"}, {"a_test": COUNT_PIN}, ["gone_test", "no tests/gone_test.rs"]),
        (["a_test"], {"plain_test": "slow"}, {"a_test": COUNT_PIN, "plain_test": "fn p() {}"}, ["plain_test", "is no pin gate"]),
    ],
)
def test_the_list_is_held_to_the_tree(run, excluded, sources, words):
    problems = pg.drift(run, excluded, sources)
    if not words:
        assert problems == []
    else:
        assert len(problems) == 1, problems
        for word in words:
            assert word in problems[0], problems


def test_the_committed_list_agrees_with_the_tree():
    """The gate itself: a new test that counts tracked files joins the list, or is excluded with a reason."""
    run, excluded, problems = pg.parse_list((REPO / pg.LIST).read_text(encoding="utf-8"))
    assert problems == []
    assert pg.drift(run, excluded, pg.sources(REPO)) == []
    assert len(run) >= 9, run
    for name in (
        "docs_drift_test",
        "dev_docs_drift_test",
        "site_journey_test",
        "link_integrity_test",
        "us_spelling_test",
        "owed_bulk_edit_gates_test",
        "workflow_supply_chain_test",
        "client_snippets_test",
        "error_reference_test",
    ):
        assert name in run, f"{name} holds a pin a pull request met on 2026-11-12 and must be run"
    for name, reason in excluded.items():
        assert len(reason) >= 20, f"{name} is excluded with no real reason: {reason!r}"


# ── the index ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "porcelain, found",
    [
        ("", []),
        ("M  docs/a.md\0", []),
        (" M docs/a.md\0A  scripts/new.py\0", []),
        ("?? scripts/new.py\0", ["scripts/new.py"]),
        ("M  a\0?? b c.md\0?? d/\0", ["b c.md", "d/"]),
        ("R  new.md\0old.md\0?? x\0", ["x"]),
        # The old name of a rename is a bare path; one that begins like a status is still a path.
        ("R  new.md\0?? was-named-so.md\0", []),
        ("?? ?? odd\0", ["?? odd"]),
        ("!! target/\0", []),
        ("D  gone.md\0", []),
        ("?? é.md\0", ["é.md"]),
        ("C  copy.md\0orig.md\0", []),
        ("?? a\0?? b\0?? c\0", ["a", "b", "c"]),
    ],
)
def test_untracked_paths_are_read_from_git_status(porcelain, found):
    assert pg.untracked(porcelain) == found


# ── the command is the hook's ───────────────────────────────────────────────


def test_the_selection_names_each_binary_to_cargo():
    """`--test NAME` is cargo's selection, so only these binaries are built.

    A nextest filterset (`-E 'binary(=...)'`) selects what is RUN and still
    builds every test target of the package: the first trial of this script
    held the quick slot for 498 s compiling, on 2026-11-13, and ran nothing.
    """
    assert pg.selection(["a_test"]) == ["--test", "a_test"]
    assert pg.selection(["a_test", "b_test"]) == ["--test", "a_test", "--test", "b_test"]
    with pytest.raises(ValueError):
        pg.selection([])


@pytest.mark.parametrize("jobs", [None, 1, 4])
def test_the_command_is_the_suite_command_for_the_listed_binaries(jobs):
    command = pg.command(["a_test", "b_test"], jobs)
    assert command == pt.nextest_command(
        pg.CARGO_ARGS, ["--test", "a_test", "--test", "b_test", "--no-tests", "fail"], [], jobs
    )
    assert command[:4] == ["nextest", "run", "--profile", pt.PROFILE]
    assert ("--test-threads" in command) is (jobs is not None)
    assert "-E" not in command and "--tests" not in command, "a filterset alone builds every test target"


def test_the_cargo_arguments_are_the_hooks():
    """One feature set: the binaries the hook built are the ones this runs, with no rebuild."""
    hook = (REPO / ".githooks" / "pre-commit").read_text(encoding="utf-8")
    line = re.search(r"python3 scripts/parallel-tests\.py [^\n]*\\\n\s*-- ([^>\n]+?) >", hook)
    assert line, "the pre-commit hook no longer runs scripts/parallel-tests.py in the form read here"
    assert line.group(1).split() == pg.CARGO_ARGS


def test_the_environment_is_the_hooks():
    hook = (REPO / ".githooks" / "pre-commit").read_text(encoding="utf-8")
    removed = re.search(r"env ((?:-u [A-Z_]+ )+)python3 scripts/parallel-tests\.py", hook)
    assert removed, "the pre-commit hook no longer removes variables in the form read here"
    assert sorted(re.findall(r"-u ([A-Z_]+)", removed.group(1))) == sorted(pg.REMOVED_ENV)
    env = pg.suite_env({"PATH": "/bin", "SIPNAB_CORPUS": "/c", "SIPNAB_VCON_DATASETS": "", "HOME": "/h"})
    assert env == {"PATH": "/bin", "HOME": "/h"}
    assert pg.suite_env({}) == {}


# ── the whole run, with nextest and git stood in ────────────────────────────


def run_main(monkeypatch, capsys, argv, porcelain="", rc=0, list_text=None):
    calls = []
    monkeypatch.setattr(pg, "git_status", lambda repo: porcelain)
    monkeypatch.setattr(pg, "run", lambda command, env: calls.append(command) or rc)
    if list_text is not None:
        monkeypatch.setattr(pg, "read_list", lambda repo: list_text)
    code = pg.main(argv)
    out = capsys.readouterr()
    return code, calls, out.out, out.err


def test_a_clean_index_runs_the_gates(monkeypatch, capsys):
    code, calls, _out, err = run_main(monkeypatch, capsys, [])
    assert code == 0 and len(calls) == 1
    assert "docs_drift_test" in calls[0] and calls[0][calls[0].index("docs_drift_test") - 1] == "--test"
    assert "pin-gates: running" in err


def test_the_status_of_the_run_is_returned(monkeypatch, capsys):
    code, calls, _out, _err = run_main(monkeypatch, capsys, [], rc=100)
    assert code == 100 and len(calls) == 1


def test_untracked_files_stop_the_run(monkeypatch, capsys):
    code, calls, _out, err = run_main(monkeypatch, capsys, [], porcelain="?? scripts/new.py\0M  docs/a.md\0")
    assert code == 2 and calls == []
    assert "scripts/new.py" in err and "git add" in err and "docs/a.md" not in err


def test_untracked_files_are_allowed_when_asked(monkeypatch, capsys):
    code, calls, _out, err = run_main(monkeypatch, capsys, ["--allow-untracked"], porcelain="?? scratch.txt\0")
    assert code == 0 and len(calls) == 1
    assert "scratch.txt" in err, "the run still says what the gates cannot see"


def test_a_list_that_drifted_stops_the_run(monkeypatch, capsys):
    code, calls, _out, err = run_main(monkeypatch, capsys, [], list_text="docs_drift_test\n")
    assert code == 2 and calls == []
    assert "neither run nor excluded" in err


def test_a_list_that_does_not_parse_stops_the_run(monkeypatch, capsys):
    code, calls, _out, err = run_main(monkeypatch, capsys, [], list_text="Not-A-Name\n")
    assert code == 2 and calls == []
    assert "not a test binary name" in err


def test_list_prints_the_binaries_and_runs_nothing(monkeypatch, capsys):
    code, calls, out, _err = run_main(monkeypatch, capsys, ["--list"], porcelain="?? x\0")
    assert code == 0 and calls == []
    names = out.split()
    assert "docs_drift_test" in names and all(re.fullmatch(r"[a-z0-9_]+", n) for n in names)


def test_jobs_reach_the_command(monkeypatch, capsys):
    _code, calls, _out, _err = run_main(monkeypatch, capsys, ["--jobs", "3"])
    assert calls[0][calls[0].index("--test-threads") + 1] == "3"


# ── the pre-check: the hook's own steps, with the source gates for the suite ──
#
# In the week to 2026-11-21 hook runs failed on gates that read only the source
# tree (the policy-doc sentence rule, the wasm-reach test, the crypto-literal
# test, the assert-message count) and on clippy, none of which this script ran:
# one agent's run reran the 25-minute hook six times. `--hook` runs the hook
# itself with SIPNAB_GATE_PRECHECK=1, which replaces the full suite with the
# source gates below and leaves out the script tests, so every other step is
# the hook's own and cannot drift from it.

RUNS_BINARY = '    let bin = env!("CARGO_BIN_EXE_sipnab");\n'
USES_CRATE = "use sipnab::sip::parse;\n"
READS_TREE = 'fn t() { let _ = std::fs::read_to_string("SECURITY.md"); }\n'


def reader(files):
    return files.get


@pytest.mark.parametrize(
    "rel, text, found",
    [
        # success: each way a file pulls another one in
        ("tests/a_test.rs", '#[path = "support/run.rs"]\nmod run_support;\n', ["tests/support/run.rs"]),
        ("tests/a_test.rs", '#[path = "../src/test_prereq.rs"]\nmod test_prereq;\n', ["src/test_prereq.rs"]),
        ("tests/a_test.rs", "mod support;\n", ["tests/support.rs", "tests/support/mod.rs"]),
        ("tests/support/mod.rs", "pub mod tracked;\n", ["tests/support/tracked.rs", "tests/support/tracked/mod.rs"]),
        ("tests/support/mod.rs", '#[path = "../../src/test_prereq.rs"]\npub mod test_prereq;\n', ["src/test_prereq.rs"]),
        ("tests/support/run.rs", "mod inner;\n", ["tests/support/run/inner.rs", "tests/support/run/inner/mod.rs"]),
        ("tests/a_test.rs", '#[path = "support/run.rs"]\n#[allow(dead_code)]\nmod run_support;\n', ["tests/support/run.rs"]),
        ("tests/a_test.rs", '#[path="support/x.rs"] mod x;\n', ["tests/support/x.rs"]),
        ("tests/a_test.rs", 'pub(crate) mod helper;\n', ["tests/helper.rs", "tests/helper/mod.rs"]),
        # edge: what is no module inclusion
        ("tests/a_test.rs", "mod inline {\n    fn f() {}\n}\n", []),
        ("tests/a_test.rs", '//! include it with `#[path = "support/fuzz.rs"] mod fuzz;`.\n', []),
        ("tests/a_test.rs", '// mod support;\n', []),
        ("tests/a_test.rs", '#[path = "support/run.rs"]\nfn not_a_module() {}\nmod later;\n', ["tests/later.rs", "tests/later/mod.rs"]),
        ("tests/a_test.rs", '#[path = "support/run.rs"]\n// the runner\nmod run_support;\n', ["tests/support/run.rs"]),
        ("tests/a_test.rs", "", []),
    ],
)
def test_the_files_a_source_includes(rel, text, found):
    assert pg.includes(rel, text) == found


@pytest.mark.parametrize(
    "files, gate",
    [
        # success: a test that reads the tree and no more is a source gate
        ({"tests/a_test.rs": READS_TREE}, True),
        ({"tests/a_test.rs": '#[path = "support/markdown.rs"]\nmod markdown;\n' + READS_TREE,
          "tests/support/markdown.rs": "pub fn h() {}\n"}, True),
        ({"tests/a_test.rs": "mod support;\n", "tests/support/mod.rs": "pub mod scan;\n",
          "tests/support/scan.rs": READS_TREE}, True),
        ({"tests/a_test.rs": "// links nothing of sipnab::sip, it only says so\n" + READS_TREE}, True),
        ({"tests/a_test.rs": '#[path = "support/missing.rs"]\nmod missing;\n'}, True),
        # failure: a test that runs or links sipnab is no source gate
        ({"tests/a_test.rs": RUNS_BINARY}, False),
        ({"tests/a_test.rs": USES_CRATE}, False),
        ({"tests/a_test.rs": "extern crate sipnab;\n"}, False),
        ({"tests/a_test.rs": "fn f() { sipnab::run(); }\n"}, False),
        ({"tests/a_test.rs": '#[path = "support/run.rs"]\nmod run_support;\n', "tests/support/run.rs": RUNS_BINARY}, False),
        ({"tests/a_test.rs": "mod support;\n", "tests/support/mod.rs": "pub mod deep;\n",
          "tests/support/deep.rs": USES_CRATE}, False),
        ({"tests/a_test.rs": '#[path = "../src/x.rs"]\nmod x;\n', "src/x.rs": USES_CRATE}, False),
        # edge: a cycle of includes ends
        ({"tests/a_test.rs": "mod support;\n", "tests/support/mod.rs": '#[path = "mod.rs"]\nmod again;\n'}, True),
        ({"tests/a_test.rs": "fn f() { let s = \"not_sipnab::x\"; }\n"}, True),
    ],
)
def test_a_source_gate_is_known_by_what_it_reaches(files, gate):
    assert pg.is_source_gate("a_test", reader(files)) is gate


def test_source_gates_names_every_source_gate_and_only_those():
    files = {
        "tests/a_test.rs": READS_TREE,
        "tests/b_test.rs": RUNS_BINARY,
        "tests/c_test.rs": "mod support;\n",
        "tests/support/mod.rs": USES_CRATE,
        "tests/d_test.rs": READS_TREE,
    }
    assert pg.source_gates(["a_test", "b_test", "c_test", "d_test"], reader(files)) == {"a_test", "d_test"}
    assert pg.source_gates([], reader(files)) == set()


@pytest.mark.parametrize(
    "text, skipped, words",
    [
        # success
        ("", {}, []),
        ("!slow_test runs the hook harness, 110 s\n", {"slow_test": "runs the hook harness, 110 s"}, []),
        ("# why\n!slow_test runs a shell, 50 s\n", {"slow_test": "runs a shell, 50 s"}, []),
        # failure: every line names a binary the pre-check leaves to the hook
        ("slow_test\n", {}, ["line 1", "leaves to the hook"]),
        ("!slow_test\n", {}, ["no reason"]),
        ("!Slow\n", {}, ["not a test binary name"]),
    ],
)
def test_the_skip_list_is_read(text, skipped, words):
    got, problems = pg.parse_skip_list(text)
    assert got == skipped
    assert len(problems) == (1 if words else 0), problems
    for word in words:
        assert word in problems[0], problems


@pytest.mark.parametrize(
    "skipped, gates, names, words",
    [
        ({"a_test": "slow"}, {"a_test", "b_test"}, {"a_test", "b_test"}, []),
        ({}, set(), set(), []),
        ({"gone_test": "slow"}, {"a_test"}, {"a_test"}, ["gone_test", "no tests/gone_test.rs"]),
        ({"b_test": "slow"}, {"a_test"}, {"a_test", "b_test"}, ["b_test", "no source gate"]),
    ],
)
def test_the_skip_list_is_held_to_the_tree(skipped, gates, names, words):
    problems = pg.skip_drift(skipped, gates, names)
    assert len(problems) == (1 if words else 0), problems
    for word in words:
        assert word in problems[0], problems


@pytest.mark.parametrize(
    "run, gates, skipped, chosen",
    [
        (["b_test"], {"a_test"}, {}, ["a_test", "b_test"]),
        (["a_test"], {"a_test"}, {}, ["a_test"]),
        ([], {"a_test", "z_test"}, {"z_test": "slow"}, ["a_test"]),
        # A pin gate that is skipped as a source gate still runs: the pin list is a floor.
        (["z_test"], {"z_test"}, {"z_test": "slow"}, ["z_test"]),
        ([], set(), {}, []),
    ],
)
def test_the_precheck_runs_the_pin_gates_and_the_source_gates(run, gates, skipped, chosen):
    assert pg.precheck_binaries(run, gates, skipped) == chosen


def test_the_committed_skip_list_agrees_with_the_tree():
    read = pg.tree_reader(REPO)
    names = set(pg.sources(REPO))
    gates = pg.source_gates(sorted(names), read)
    skipped, problems = pg.parse_skip_list((REPO / pg.SKIP_LIST).read_text(encoding="utf-8"))
    assert problems == []
    assert pg.skip_drift(skipped, gates, names) == []
    for name, reason in skipped.items():
        assert len(reason) >= 20, f"{name} is skipped with no real reason: {reason!r}"


@pytest.mark.parametrize(
    "name",
    [
        # The gates that failed hook runs in the week to 2026-11-21, none of which pin-gates ran.
        "security_policy_doc_test",
        "attribute_attachment_test",
        "hardcoded_crypto_material_test",
        "rust_style_test",
        "lint_suppression_test",
    ],
)
def test_the_gates_that_failed_hook_runs_are_in_the_precheck(name):
    names = sorted(pg.sources(REPO))
    run, _excluded, _problems = pg.parse_list((REPO / pg.LIST).read_text(encoding="utf-8"))
    skipped, _ = pg.parse_skip_list((REPO / pg.SKIP_LIST).read_text(encoding="utf-8"))
    chosen = pg.precheck_binaries(run, pg.source_gates(names, pg.tree_reader(REPO)), skipped)
    assert name in chosen, f"{name} failed hook runs and must run in the pre-check"


def run_precheck(monkeypatch, capsys, argv, porcelain="", rc=0):
    hooks = []
    monkeypatch.setattr(pg, "git_status", lambda repo: porcelain)
    monkeypatch.setattr(pg, "run_hook", lambda env: hooks.append(env) or rc)
    code, calls, out, err = run_main(monkeypatch, capsys, argv, porcelain=porcelain, rc=rc)
    return code, calls, hooks, out, err


def test_source_gates_runs_the_precheck_set(monkeypatch, capsys):
    code, calls, _out, err = run_main(monkeypatch, capsys, ["--source-gates"])
    assert code == 0 and len(calls) == 1
    chosen = [calls[0][i + 1] for i, word in enumerate(calls[0]) if word == "--test"]
    assert "security_policy_doc_test" in chosen and "docs_drift_test" in chosen
    assert "pin-gates: running" in err and "source gates" in err


def test_source_gates_list_prints_and_runs_nothing(monkeypatch, capsys):
    code, calls, out, _err = run_main(monkeypatch, capsys, ["--source-gates", "--list"])
    assert code == 0 and calls == []
    assert "rust_style_test" in out.split() and "docs_drift_test" in out.split()


def test_source_gates_refuses_an_untracked_file(monkeypatch, capsys):
    code, calls, _out, err = run_main(monkeypatch, capsys, ["--source-gates"], porcelain="?? new.rs\0")
    assert code == 2 and calls == [] and "new.rs" in err


def test_hook_runs_the_hook_in_precheck_mode(monkeypatch, capsys):
    code, calls, hooks, _out, _err = run_precheck(monkeypatch, capsys, ["--hook"])
    assert code == 0 and calls == [] and len(hooks) == 1
    assert hooks[0]["SIPNAB_GATE_PRECHECK"] == "1"


def test_hook_returns_the_hooks_status(monkeypatch, capsys):
    code, _calls, hooks, _out, _err = run_precheck(monkeypatch, capsys, ["--hook"], rc=1)
    assert code == 1 and len(hooks) == 1


def test_hook_refuses_an_untracked_file_before_any_step(monkeypatch, capsys):
    code, _calls, hooks, _out, err = run_precheck(monkeypatch, capsys, ["--hook"], porcelain="?? new.md\0")
    assert code == 2 and hooks == [] and "new.md" in err


def test_hook_drops_the_git_variables_of_a_calling_hook(monkeypatch, capsys):
    monkeypatch.setenv("GIT_INDEX_FILE", "/x/index")
    _code, _calls, hooks, _out, _err = run_precheck(monkeypatch, capsys, ["--hook"])
    assert "GIT_INDEX_FILE" not in hooks[0], "the hook refuses the pre-check under git commit, by this variable"


def test_source_gates_with_nothing_to_run_is_refused_not_passed(monkeypatch, capsys):
    monkeypatch.setattr(pg, "sources", lambda repo: {})
    monkeypatch.setattr(pg, "read_skip_list", lambda repo: "")
    code, calls, _out, err = run_main(monkeypatch, capsys, ["--source-gates"], list_text="")
    assert code == 2 and calls == []
    assert "no test binary to run" in err


def test_hook_and_source_gates_are_one_choice(monkeypatch, capsys):
    with pytest.raises(SystemExit):
        run_precheck(monkeypatch, capsys, ["--hook", "--source-gates"])
