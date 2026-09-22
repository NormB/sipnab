"""The YANG gate checks what it says, and says when it cannot.

``scripts/check-yang.py`` wraps two tools this repository does not ship --
libyang's ``yanglint`` and ``pyang`` -- so its own logic is exercised here
against stand-ins that record how they were called and answer as told. What
these pin is the part a real tool cannot test: that a missing tool is reported
as NOT CHECKED rather than as a pass, that CI's ``SIPNAB_YANG_REQUIRED=1``
turns that into a failure, that any warning fails, and that a second revision
is held to the first.

The tools themselves run for real in the gate in ``.githooks/pre-push`` and in
CI, which installs both.
"""

import pathlib
import stat

from conftest import load

check_yang = load("check-yang")

MODULE_TEXT = "module sipnab-diagnosis { }\n"


def stand_in(tmp: pathlib.Path, name: str, output: str = "", fail_on: str = "") -> pathlib.Path:
    """An executable that logs its argv and answers as told.

    It prints ``output`` and exits 0, or -- with ``fail_on`` -- prints a
    rejection and exits 1 whenever that text appears in its arguments.
    """
    log = tmp / f"{name}.log"
    script = tmp / name
    body = f'#!/bin/sh\necho "$@" >> "{log}"\n'
    if fail_on:
        body += f'case "$*" in *{fail_on}*) echo "rejected: $*"; exit 1;; esac\n'
    if output:
        body += f'printf "%s" "{output}"\n'
    body += "exit 0\n"
    script.write_text(body)
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return script


def calls(tmp: pathlib.Path, name: str) -> list[str]:
    """Every argv the stand-in was called with, one line each."""
    log = tmp / f"{name}.log"
    return log.read_text().splitlines() if log.exists() else []


def module_dir(tmp: pathlib.Path, *revisions: str) -> pathlib.Path:
    """A `yang/` holding one file per revision date."""
    d = tmp / "yang"
    d.mkdir()
    for rev in revisions:
        (d / f"sipnab-diagnosis@{rev}.yang").write_text(MODULE_TEXT)
    return d


def tools(monkeypatch, tmp, yanglint=None, pyang=None):
    """Point the gate at stand-ins, with CI's switch off."""
    monkeypatch.setenv("YANGLINT_BIN", str(yanglint or stand_in(tmp, "yanglint")))
    monkeypatch.setenv("PYANG_BIN", str(pyang or stand_in(tmp, "pyang")))
    monkeypatch.delenv("SIPNAB_YANG_REQUIRED", raising=False)


def test_a_missing_tool_is_not_checked_rather_than_passed(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("YANGLINT_BIN", str(tmp_path / "absent"))
    monkeypatch.setenv("PYANG_BIN", str(stand_in(tmp_path, "pyang")))
    monkeypatch.delenv("SIPNAB_YANG_REQUIRED", raising=False)
    rc = check_yang.check(module_dir(tmp_path, "2026-09-21"))
    out = capsys.readouterr().out
    assert rc == 2, out
    first = out.splitlines()[0]
    assert first.startswith("NOT CHECKED") and "yanglint" in first, out


def test_ci_turns_a_missing_tool_into_a_failure(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("YANGLINT_BIN", str(stand_in(tmp_path, "yanglint")))
    monkeypatch.setenv("PYANG_BIN", str(tmp_path / "absent"))
    monkeypatch.setenv("SIPNAB_YANG_REQUIRED", "1")
    rc = check_yang.check(module_dir(tmp_path, "2026-09-21"))
    out = capsys.readouterr().out
    assert rc == 1, out
    assert "pyang" in out and "SIPNAB_YANG_REQUIRED" in out, out


def test_a_clean_module_passes_and_both_tools_saw_it(tmp_path, monkeypatch, capsys):
    tools(monkeypatch, tmp_path)
    rc = check_yang.check(module_dir(tmp_path, "2026-09-21"))
    out = capsys.readouterr().out
    assert rc == 0, out
    assert any(
        "-Werror" in c and "--lint" in c and c.endswith("sipnab-diagnosis@2026-09-21.yang")
        for c in calls(tmp_path, "pyang")
    ), calls(tmp_path, "pyang")
    assert any(
        c.endswith("sipnab-diagnosis@2026-09-21.yang") for c in calls(tmp_path, "yanglint")
    ), calls(tmp_path, "yanglint")


def test_any_warning_is_a_failure(tmp_path, monkeypatch, capsys):
    tools(monkeypatch, tmp_path, yanglint=stand_in(tmp_path, "yanglint", output="libyang warn: x"))
    rc = check_yang.check(module_dir(tmp_path, "2026-09-21"))
    out = capsys.readouterr().out
    assert rc == 1, out
    assert "libyang warn: x" in out, out


def test_one_revision_is_held_to_no_earlier_one(tmp_path, monkeypatch, capsys):
    tools(monkeypatch, tmp_path)
    assert check_yang.check(module_dir(tmp_path, "2026-09-21")) == 0
    assert not any("--check-update-from" in c for c in calls(tmp_path, "pyang"))


def test_a_new_revision_is_held_to_the_previous_one(tmp_path, monkeypatch, capsys):
    tools(monkeypatch, tmp_path, pyang=stand_in(tmp_path, "pyang", fail_on="--check-update-from"))
    rc = check_yang.check(module_dir(tmp_path, "2026-09-21", "2027-01-05"))
    out = capsys.readouterr().out
    assert rc == 1, out
    update = [c for c in calls(tmp_path, "pyang") if "--check-update-from" in c]
    assert len(update) == 1, update
    older = update[0].index("sipnab-diagnosis@2026-09-21.yang")
    newer = update[0].index("sipnab-diagnosis@2027-01-05.yang")
    assert older < newer, update
    # The newest revision is the one linted and compiled.
    assert any(
        "--lint" in c and "2027-01-05" in c for c in calls(tmp_path, "pyang")
    ), calls(tmp_path, "pyang")


def test_no_module_at_all_is_a_failure(tmp_path, monkeypatch, capsys):
    tools(monkeypatch, tmp_path)
    assert check_yang.check(module_dir(tmp_path)) == 1, capsys.readouterr().out
