# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""The command line .githooks/pre-push uses of scripts/tag-push-proof.py.

Since TAG-PUSH-GATE-RUNS-FROM-TAG-COMMIT a tag push runs origin/main's copy
of tag-push-proof.py from the hook of the tagged commit, which may be older
than main. main's copy must therefore keep the three forms that hook calls,
and the exit statuses it branches on, with the same meaning. These tests pin
both sides: the forms the hook holds, and the script's answers to them.
"""

import ast
import os
import pathlib
import re
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent.parent
HOOK = (REPO / ".githooks/pre-push").read_text()
PROOF = REPO / "scripts/tag-push-proof.py"
PROOF_TEXT = PROOF.read_text()
ZERO = "0" * 40

# The forms the hook calls, as `python3 "$TAG_PROOF" <args>`: stdin only,
# `--delivery-hint <0|1> <HEAD>` and `--tag-ci <commit>`.
CALLS = re.findall(r'python3 "\$TAG_PROOF"([^)|]*)', HOOK)


def constant(name):
    """A module-level constant of tag-push-proof.py, read without importing it."""
    for node in ast.parse(PROOF_TEXT).body:
        if isinstance(node, ast.Assign) and any(getattr(t, "id", None) == name for t in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError(f"tag-push-proof.py has no constant {name}")


def env(tmp_path):
    """No gh on PATH and no user config: every GitHub question is unanswered."""
    e = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    gh = bin_dir / "gh"
    gh.write_text("#!/bin/sh\nexit 1\n")
    gh.chmod(0o755)
    e.update(PATH=f"{bin_dir}:/usr/bin:/bin", GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1", HOME=str(tmp_path))
    return e


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "repo"
    r.mkdir()
    e = env(tmp_path)
    for args in (["init", "-q"], ["-c", "user.name=E", "-c", "user.email=e@example.com", "commit", "-q",
                                   "--allow-empty", "-m", "c"]):
        subprocess.run(["git", *args], cwd=r, env=e, check=True, capture_output=True, timeout=60)
    sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=r, env=e, check=True, capture_output=True,
                         text=True, timeout=60).stdout.strip()
    return r, sha, e


def run(repo_env, *args, stdin=""):
    r, _sha, e = repo_env
    return subprocess.run(["python3", str(PROOF), *args], cwd=r, env=e, input=stdin, capture_output=True,
                          text=True, timeout=120)


# ---------------------------------------------------------------- success


def test_success_the_hook_calls_three_forms():
    shapes = sorted(c.split()[0] if c.split()[0].startswith("--") else "<stdin>" for c in CALLS)
    assert shapes == ["--delivery-hint", "--tag-ci", "<stdin>"], f"the hook's calls changed: {CALLS}"


def test_success_the_stdin_form_is_read(repo):
    _r, sha, _e = repo
    p = run(repo, stdin=f"refs/tags/v1 {sha} refs/tags/v1 {ZERO}\n")
    assert p.returncode in (0, 1, constant("PENDING_EXIT")), f"stdin form: {p.returncode} {p.stderr}"
    assert "usage:" not in p.stderr, f"stdin form read as a usage error: {p.stderr}"


def test_success_the_tag_ci_form_is_read(repo):
    _r, sha, _e = repo
    p = run(repo, "--tag-ci", sha)
    assert p.returncode in constant("TAG_CI_EXIT").values(), f"--tag-ci: {p.returncode} {p.stderr}"


def test_success_the_delivery_hint_form_is_read(repo):
    _r, sha, _e = repo
    for pending in ("0", "1"):
        p = run(repo, "--delivery-hint", pending, sha, stdin=f"refs/tags/v1 {sha} refs/tags/v1 {ZERO}\n")
        assert p.returncode == 0, f"--delivery-hint {pending}: {p.returncode} {p.stderr}"


def test_success_tag_ci_exit_meanings_are_pinned():
    assert constant("TAG_CI_EXIT") == {"green": 0, "head": 10, "none": 3, "not_green": 4, "unreadable": 5}, \
        "the hook branches on these statuses; an older hook running main's copy reads them so"


def test_success_the_pending_status_is_three():
    assert constant("PENDING_EXIT") == 3, "the hook reads 3 from the stdin form as `pending`"


def test_success_usage_lists_every_form_the_hook_calls():
    usage = constant("USAGE")
    for form in ("< <pre-push stdin>", "--tag-ci", "--delivery-hint"):
        assert form in usage, f"USAGE lost {form!r}"


def test_success_the_hook_picks_before_its_first_call():
    pick = HOOK.index('sh "$TAG_PROOF_PICK" "$TAG_PROOF" "$TAG_PROOF_COPY"')
    first = HOOK.index('python3 "$TAG_PROOF"')
    assert pick < first, "the copy must be picked before the first proof call"


def test_success_the_exit_trap_removes_the_copy():
    assert "trap 'gate_flush; tag_proof_cleanup' EXIT" in HOOK, "the gate-cache trap must also remove the copy"
    assert "trap tag_proof_cleanup EXIT" in HOOK, "the copy is removed on exits before the gate-cache trap"


def test_success_signals_remove_the_copy():
    for sig, rc in (("HUP", 129), ("INT", 130), ("TERM", 143)):
        assert f"trap 'tag_proof_cleanup; exit {rc}' {sig}" in HOOK, f"{sig} must remove the copy"


def test_success_the_copy_lives_in_the_git_dir():
    assert 'TAG_PROOF_COPY="$(git rev-parse --absolute-git-dir' in HOOK, "the copy goes in the git dir"
    assert "sipnab-tag-proof-main.$$.py" in HOOK, "one copy per hook process"


def test_success_the_picker_runs_only_for_a_push_that_names_a_tag():
    block = HOOK[HOOK.index('case "$PUSH_REFS" in\n*refs/tags/*)'):]
    assert block.index("TAG_PROOF_PICK=") < block.index("esac"), "the picker sits inside the tag case"


# ---------------------------------------------------------------- failure


def test_failure_an_unknown_form_is_a_usage_error(repo):
    p = run(repo, "--no-such-form", "x")
    assert p.returncode == 2 and "usage:" in p.stderr, f"{p.returncode} {p.stderr}"


def test_failure_tag_ci_with_a_short_sha_is_a_usage_error(repo):
    _r, sha, _e = repo
    p = run(repo, "--tag-ci", sha[:12])
    assert p.returncode == 2, f"a short sha must not be judged: {p.returncode}"


def test_failure_delivery_hint_with_a_bad_flag_is_a_usage_error(repo):
    _r, sha, _e = repo
    p = run(repo, "--delivery-hint", "2", sha)
    assert p.returncode == 2, f"--delivery-hint 2: {p.returncode}"


def test_failure_stdin_form_without_github_is_not_a_pass(repo):
    _r, sha, _e = repo
    p = run(repo, stdin=f"refs/tags/v1 {sha} refs/tags/v1 {ZERO}\n")
    assert p.returncode != 0, f"with gh failing the stdin form must not skip the gates: {p.stdout}"


def test_failure_tag_ci_without_github_is_not_green(repo):
    _r, sha, _e = repo
    p = run(repo, "--tag-ci", sha)
    assert p.returncode not in (0, 10), f"with gh failing --tag-ci must not pass: {p.returncode} {p.stdout}"


def test_failure_an_unreadable_ref_line_is_not_a_pass(repo):
    p = run(repo, stdin="refs/tags/v1 only-three fields\n")
    assert p.returncode != 0, f"a bad line must not skip the gates: {p.stdout}"


def test_failure_the_hook_never_runs_the_proof_through_a_shell_variable_without_a_file_check():
    # Each call site checks the file exists first; a missing copy must not be run.
    assert HOOK.count('if [ -f "$TAG_PROOF" ]; then') >= 2, "the stdin and hint calls check the file"


def test_failure_a_picker_error_keeps_the_checkouts_copy():
    # The path is replaced only when the picker exits 0 (`&&`).
    i = HOOK.index('sh "$TAG_PROOF_PICK"')
    assert HOOK[i:i + 200].count("&& TAG_PROOF=") == 1, "the path must change only on the picker's success"


def test_failure_the_tag_ci_unknown_status_blocks():
    block = HOOK[HOOK.index('TAG_CI_OUT=$(python3 "$TAG_PROOF" --tag-ci'):]
    block = block[:block.index("esac")]
    assert "*)" in block and "exit 1" in block, "an unlisted --tag-ci status must block"


def test_failure_no_environment_knob_selects_the_copy():
    pick = (REPO / "scripts/pick-tag-proof.sh").read_text()
    assert not re.search(r"\$\{?SIPNAB_[A-Z_]*", pick), "the picker must read no SIPNAB_ variable"


def test_failure_the_picker_names_no_verdict():
    pick = (REPO / "scripts/pick-tag-proof.sh").read_text()
    assert "TREE_PROVEN" not in pick and "exit 1" not in pick, "the picker must not decide a verdict"


# ---------------------------------------------------------------- edge


def test_edge_every_call_passes_the_copy_by_one_variable():
    assert HOOK.count('python3 "$TAG_PROOF"') == 3, "three calls, all through $TAG_PROOF"
    assert "scripts/tag-push-proof.py\" " not in HOOK.split("TAG_PROOF_COPY=\"\"")[1], \
        "no call after the pick names the checkout's file directly"


def test_edge_the_tag_ci_form_takes_a_full_sha_only():
    assert re.search(r'--tag-ci "\$commit"', HOOK), "the hook passes the resolved commit"


def test_edge_delivery_hint_reads_head_or_empty(repo):
    _r, sha, _e = repo
    p = run(repo, "--delivery-hint", "0", "", stdin=f"refs/tags/v1 {sha} refs/tags/v1 {ZERO}\n")
    assert p.returncode == 0, f"an empty HEAD is a valid third argument: {p.returncode} {p.stderr}"


def test_edge_stdin_form_with_no_lines(repo):
    p = run(repo, stdin="")
    assert p.returncode != 2, f"an empty push is not a usage error: {p.stderr}"


def test_edge_the_script_runs_from_outside_the_scripts_dir(repo, tmp_path):
    # The hook runs a copy from the git dir; nothing may load a sibling file.
    copy = tmp_path / "elsewhere.py"
    copy.write_text(PROOF_TEXT)
    r, sha, e = repo
    p = subprocess.run(["python3", str(copy), "--tag-ci", sha], cwd=r, env=e, capture_output=True, text=True,
                       timeout=120)
    assert p.returncode in constant("TAG_CI_EXIT").values(), f"a copy elsewhere: {p.returncode} {p.stderr}"


def test_edge_the_script_imports_only_the_standard_library():
    tree = ast.parse(PROOF_TEXT)
    names = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    names |= {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
    assert names <= {"__future__", "dataclasses", "json", "os", "re", "subprocess", "sys"}, \
        f"a copy run from the git dir cannot import {names}"


def test_edge_annotated_tag_object_in_stdin_form(repo):
    r, sha, e = repo
    subprocess.run(["git", "-c", "user.name=E", "-c", "user.email=e@example.com", "tag", "-a", "-m", "t", "v1"],
                   cwd=r, env=e, check=True, capture_output=True, timeout=60)
    obj = subprocess.run(["git", "rev-parse", "refs/tags/v1"], cwd=r, env=e, check=True, capture_output=True,
                         text=True, timeout=60).stdout.strip()
    p = run(repo, stdin=f"refs/tags/v1 {obj} refs/tags/v1 {ZERO}\n")
    assert p.returncode != 2, f"an annotated tag object is a valid stdin sha: {p.stderr}"


def test_edge_the_pick_line_is_printed_before_the_proof_line():
    i = HOOK.index('[ -z "$TAG_PROOF_PICKED" ] || printf')
    j = HOOK.index('printf \'%s\\n\' "$TAG_PROOF_LINE"')
    assert i < j, "the line that names the copy comes before the verdict it gives"


def test_edge_cleanup_is_a_no_op_without_a_copy():
    body = HOOK[HOOK.index("tag_proof_cleanup() {"):]
    body = body[:body.index("}")]
    assert '[ -z "$TAG_PROOF_COPY" ] ||' in body, "a branch push has no copy to remove"


def test_edge_the_release_train_fetches_main_before_the_tag_push():
    train = (REPO / "scripts/release-train.py").read_text()
    body = train[train.index("def tag_and_push"):]
    body = body[:body.index("\ndef ")]
    assert body.index('"fetch", "origin", "main"') < body.index('"push", "origin"'), \
        "origin/main must be fresh before the tag push, or the picker falls back"
