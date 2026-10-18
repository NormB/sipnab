# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""scripts/memcheck-verdict.py: the rule the weekly Valgrind job applies."""

import subprocess
import sys

import pytest

from conftest import SCRIPTS, load

verdict = load("memcheck-verdict")
SCRIPT = SCRIPTS / "memcheck-verdict.py"

CLEAN = """\
==7== HEAP SUMMARY:
==7==     in use at exit: 35,678 bytes in 20 blocks
==7==   total heap usage: 433,604 allocs, 433,584 frees, 17,955,617 bytes allocated
==7==
==7== LEAK SUMMARY:
==7==    definitely lost: 0 bytes in 0 blocks
==7==    indirectly lost: 0 bytes in 0 blocks
==7==      possibly lost: 124 bytes in 2 blocks
==7==    still reachable: 35,554 bytes in 18 blocks
==7==         suppressed: 0 bytes in 0 blocks
==7==
==7== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)
"""

ALL_FREED = """\
==7== HEAP SUMMARY:
==7==     in use at exit: 0 bytes in 0 blocks
==7==   total heap usage: 10 allocs, 10 frees, 1,024 bytes allocated
==7==
==7== All heap blocks were freed -- no leaks are possible
==7==
==7== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)
"""


def leaked(definite="0 bytes in 0 blocks", indirect="0 bytes in 0 blocks"):
    return (CLEAN.replace("definitely lost: 0 bytes in 0 blocks", f"definitely lost: {definite}")
                 .replace("indirectly lost: 0 bytes in 0 blocks", f"indirectly lost: {indirect}"))


def test_a_clean_log_passes():
    assert verdict.judge(CLEAN) == []


def test_all_heap_blocks_freed_passes():
    assert verdict.judge(ALL_FREED) == []


def test_possibly_lost_and_still_reachable_alone_pass():
    # Interior pointers into live hash tables and thread handles: not a leak.
    assert verdict.judge(CLEAN) == []


def test_definitely_lost_fails():
    problems = verdict.judge(leaked(definite="4,096 bytes in 1 blocks"))
    assert problems == ["definitely lost: 4,096 bytes in 1 blocks"]


def test_indirectly_lost_fails():
    problems = verdict.judge(leaked(indirect="64 bytes in 2 blocks"))
    assert problems == ["indirectly lost: 64 bytes in 2 blocks"]


@pytest.mark.parametrize("kind", ["Invalid read of size 8", "Invalid write of size 4",
                                  "Invalid free() / delete / delete[] / realloc()",
                                  "Mismatched free() / delete / delete []"])
def test_a_memory_error_fails_even_with_no_leak(kind):
    text = f"==7== {kind}\n==7==    at 0x1234: f (a.rs:1)\n" + CLEAN
    assert verdict.judge(text) == [kind]


def test_a_log_with_no_summary_is_an_instrument_failure():
    with pytest.raises(verdict.NotJudged):
        verdict.judge("==7== Memcheck, a memory error detector\n")


def test_a_log_cut_off_after_the_heap_summary_is_an_instrument_failure():
    with pytest.raises(verdict.NotJudged):
        verdict.judge(CLEAN.split("==7== LEAK SUMMARY:")[0])


def run(tmp_path, logs):
    paths = []
    for name, text in logs.items():
        p = tmp_path / f"{name}.log"
        p.write_text(text)
        paths.append(str(p))
    return subprocess.run([sys.executable, "-I", str(SCRIPT), *paths],
                          capture_output=True, text=True)


def test_cli_passes_when_every_log_is_clean(tmp_path):
    r = run(tmp_path, {"a": CLEAN, "b": ALL_FREED})
    assert r.returncode == 0, r.stdout + r.stderr
    assert "2 log(s), 0 with a leak or memory error" in r.stdout


def test_cli_fails_and_names_the_leaking_log(tmp_path):
    r = run(tmp_path, {"clean": CLEAN, "leaky": leaked(definite="16 bytes in 1 blocks")})
    assert r.returncode == 1
    assert "leaky.log: definitely lost: 16 bytes in 1 blocks" in r.stdout


def test_cli_exits_2_on_an_unjudgeable_log(tmp_path):
    r = run(tmp_path, {"cut": "==7== Memcheck\n"})
    assert r.returncode == 2


def test_cli_exits_2_on_no_logs():
    r = subprocess.run([sys.executable, "-I", str(SCRIPT)], capture_output=True, text=True)
    assert r.returncode == 2
