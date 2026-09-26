"""The smoke script's check helpers report each check once, truthfully.

`expect` and `expect_exit` in scripts/lib/smoke-expect.sh counted a missing
line as a failure and then printed `ok` for the same check anyway, so a log
read top to bottom showed a FAIL line followed by `ok   <label>`. The exit
code was still right; the log was not. Found 2026-09-24 by the EX4 agent
(backlog EX4b).
"""

import pathlib
import subprocess

LIB = pathlib.Path(__file__).resolve().parent.parent / "lib" / "smoke-expect.sh"


def run(snippet: str, tmp_path) -> tuple[str, str]:
    script = f'FAILED=0\nWORK="{tmp_path}"\n. "{LIB}"\n{snippet}\necho "FAILED=$FAILED"\n'
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=True)
    return r.stdout, r.stderr


def test_a_missing_line_is_a_failure_and_not_also_ok(tmp_path):
    out, err = run('expect "prints two" "one" "two" -- printf "one\\n"', tmp_path)
    assert "FAIL: prints two did not print 'two'" in err
    assert "ok   prints two" not in out
    assert "FAILED=1" in out


def test_expect_exit_with_a_missing_line_is_not_also_ok(tmp_path):
    out, err = run('expect_exit "exits 3" 3 "gone" -- bash -c "echo here; exit 3"', tmp_path)
    assert "did not print 'gone'" in err
    assert "ok   exits 3" not in out
    assert "FAILED=1" in out


def test_a_passing_check_still_says_ok(tmp_path):
    out, err = run('expect "prints one" "one" -- printf "one\\n"', tmp_path)
    assert "ok   prints one" in out
    assert "FAILED=0" in out
    assert err == ""


def test_a_wrong_exit_is_one_failure(tmp_path):
    out, err = run('expect "runs" "x" -- false', tmp_path)
    assert "FAIL: runs exited non-zero" in err
    assert "ok   runs" not in out
    assert "FAILED=1" in out
