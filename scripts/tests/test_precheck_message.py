# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""`pin-gates.py --hook --message FILE` runs the commit-msg checks first.

git runs .githooks/commit-msg only after .githooks/pre-commit has passed, so
one bad line of a commit message cost a whole hook round: on 2026-11-23 a
commit waited more than an hour for the build slot, passed every pre-commit
gate (4569 script tests), and was then refused because its message named the
build host. The pre-check now takes the message file and runs the REAL
commit-msg hook on it before anything else, so that refusal comes in seconds.
"""

import os
import pathlib
import re

import pytest
from conftest import load

pg = load("pin-gates")
REPO = pathlib.Path(__file__).resolve().parents[2]
GOOD = "Fix a thing\n\nThe thing is fixed; tests cover it.\n"


def planted_message():
    """The message tests/private_identity_test.rs plants to prove the script
    refuses it. A private name may appear in that file alone (its own scans
    exempt it), so this test reads it from there rather than holding a copy."""
    source = (REPO / "tests/private_identity_test.rs").read_text(encoding="utf-8")
    found = re.findall(r'run_message_script\("((?:\\.|[^"\\])*)", "planted"\)', source)
    assert len(found) == 1, "the planted message moved in tests/private_identity_test.rs: update this test"
    return found[0].encode().decode("unicode_escape")


def drive(monkeypatch, capsys, argv, porcelain="", msg_rc=None, hook_rc=0):
    """Run main with the index and the pre-commit hook stubbed; the commit-msg
    hook is stubbed too when msg_rc is given, else it is the real one."""
    order = []
    monkeypatch.setattr(pg, "git_status", lambda repo: porcelain)
    monkeypatch.setattr(pg, "run_hook", lambda env: order.append(("hook", env)) or hook_rc)
    if msg_rc is not None:
        monkeypatch.setattr(pg, "run_message_checks", lambda path, env: order.append(("msg", path, env)) or msg_rc)
    code = pg.main(argv)
    out, err = capsys.readouterr()
    return code, order, out, err


def message(tmp_path, text, name="msg.txt"):
    path = tmp_path / name
    path.write_text(text)
    return path


# ── success ─────────────────────────────────────────────────────────────────


def test_success_the_message_is_checked_before_the_hook(monkeypatch, capsys, tmp_path):
    code, order, _out, _err = drive(monkeypatch, capsys, ["--hook", "--message", str(message(tmp_path, GOOD))], msg_rc=0)
    assert code == 0, order
    assert [step[0] for step in order] == ["msg", "hook"], order


def test_success_a_good_message_passes_the_real_commit_msg_hook(monkeypatch, capsys, tmp_path):
    code, order, _out, err = drive(monkeypatch, capsys, ["--hook", "--message", str(message(tmp_path, GOOD))])
    assert code == 0, err
    assert [step[0] for step in order] == ["hook"], "the pre-check ran after the message passed"


def test_success_the_run_says_it_checks_the_message_first(monkeypatch, capsys, tmp_path):
    path = message(tmp_path, GOOD)
    _code, _order, _out, err = drive(monkeypatch, capsys, ["--hook", "--message", str(path)], msg_rc=0)
    assert f"running .githooks/commit-msg on {path} first" in err, err


def test_success_a_relative_message_path_is_the_callers(monkeypatch, capsys, tmp_path):
    message(tmp_path, GOOD)
    monkeypatch.chdir(tmp_path)
    _code, order, _out, _err = drive(monkeypatch, capsys, ["--hook", "--message", "msg.txt"], msg_rc=0)
    assert order[0][1] == str(tmp_path / "msg.txt"), order[0]


def test_success_the_message_file_is_left_as_it_was(monkeypatch, capsys, tmp_path):
    path = message(tmp_path, GOOD)
    drive(monkeypatch, capsys, ["--hook", "--message", str(path)])
    assert path.read_text() == GOOD, "the check reads the message, never rewrites it"


# ── failure ─────────────────────────────────────────────────────────────────


def test_failure_a_message_naming_the_host_stops_before_the_hook(monkeypatch, capfd, tmp_path):
    # capfd: the hook is a child process and writes to the descriptors.
    code, order, out, err = drive(monkeypatch, capfd, ["--hook", "--message", str(message(tmp_path, planted_message()))])
    assert code != 0, out + err
    assert order == [], "the pre-commit hook never started"
    assert "names a private identity" in out + err, out + err


def test_failure_the_commit_msg_status_is_returned(monkeypatch, capsys, tmp_path):
    code, order, _out, err = drive(monkeypatch, capsys, ["--hook", "--message", str(message(tmp_path, GOOD))], msg_rc=1)
    assert code == 1 and [step[0] for step in order] == ["msg"], order
    assert "fails the commit-msg checks" in err, err


def test_failure_a_missing_message_file_is_refused(monkeypatch, capsys, tmp_path):
    code, order, _out, err = drive(monkeypatch, capsys, ["--hook", "--message", str(tmp_path / "none.txt")], msg_rc=0)
    assert code == 2 and order == [], order
    assert "none.txt" in err, err


def test_failure_a_directory_is_not_a_message(monkeypatch, capsys, tmp_path):
    code, order, _out, err = drive(monkeypatch, capsys, ["--hook", "--message", str(tmp_path)], msg_rc=0)
    assert code == 2 and order == [], order
    assert "not a file" in err, err


def test_failure_message_without_hook_is_refused(monkeypatch, capsys, tmp_path):
    with pytest.raises(SystemExit) as exit_info:
        drive(monkeypatch, capsys, ["--message", str(message(tmp_path, GOOD))], msg_rc=0)
    assert exit_info.value.code == 2, "argparse refuses it"


def test_failure_message_with_source_gates_is_refused(monkeypatch, capsys, tmp_path):
    with pytest.raises(SystemExit) as exit_info:
        drive(monkeypatch, capsys, ["--source-gates", "--message", str(message(tmp_path, GOOD))], msg_rc=0)
    assert exit_info.value.code == 2, "the message goes with the pre-check alone"


def test_failure_a_bad_message_is_reported_before_an_untracked_file(monkeypatch, capsys, tmp_path):
    code, order, _out, err = drive(
        monkeypatch, capsys, ["--hook", "--message", str(message(tmp_path, GOOD))], porcelain="?? new.rs\0", msg_rc=1
    )
    assert code == 1 and [step[0] for step in order] == ["msg"], order
    assert "new.rs" not in err, "the message comes first, before every other check"


# ── edge ────────────────────────────────────────────────────────────────────


def test_edge_without_a_message_no_commit_msg_check_runs(monkeypatch, capsys):
    code, order, _out, _err = drive(monkeypatch, capsys, ["--hook"], msg_rc=0)
    assert code == 0 and [step[0] for step in order] == ["hook"], order


def test_edge_the_commit_msg_hook_gets_no_git_variables(monkeypatch, capsys, tmp_path):
    monkeypatch.setenv("GIT_INDEX_FILE", "/x/index")
    _code, order, _out, _err = drive(monkeypatch, capsys, ["--hook", "--message", str(message(tmp_path, GOOD))], msg_rc=0)
    assert not any(key.startswith("GIT_") for key in order[0][2]), "a calling git's variables stay out"


def test_edge_the_commit_msg_hook_is_not_told_it_is_the_precheck(monkeypatch, capsys, tmp_path):
    _code, order, _out, _err = drive(monkeypatch, capsys, ["--hook", "--message", str(message(tmp_path, GOOD))], msg_rc=0)
    assert "SIPNAB_GATE_PRECHECK" not in order[0][2], "commit-msg runs as git runs it"


def test_edge_an_empty_message_reaches_the_real_hook(monkeypatch, capsys, tmp_path):
    code, order, out, err = drive(monkeypatch, capsys, ["--hook", "--message", str(message(tmp_path, ""))])
    assert code == 0 and [step[0] for step in order] == ["hook"], out + err


def test_edge_the_real_hook_is_the_repositorys(monkeypatch):
    calls = []

    class Done:
        returncode = 0

    monkeypatch.setattr(pg.subprocess, "run", lambda cmd, **kw: calls.append((cmd, kw)) or Done())
    assert pg.run_message_checks("/m.txt", {"A": "1"}) == 0
    cmd, kw = calls[0]
    assert cmd == ["bash", ".githooks/commit-msg", "/m.txt"] and kw["cwd"] == pg.REPO, calls
    assert kw["env"] == {"A": "1"}, kw


def test_edge_a_message_path_with_spaces_is_one_argument(monkeypatch, capsys, tmp_path):
    path = message(tmp_path, GOOD, name="my msg.txt")
    _code, order, _out, _err = drive(monkeypatch, capsys, ["--hook", "--message", str(path)], msg_rc=0)
    assert order[0][1] == str(path), order[0]
    assert os.path.isfile(order[0][1]), order[0]
