# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors
"""The pre-commit hook's step log, and scripts/hook-steps.py, which prints it.

The hook writes one line per step to `<git-dir>/sipnab-pre-commit-steps.log`:
run, step, whole seconds, exit status, separated by tabs, and a last line
`total` for the run. A table of where a hook run spent its time was made by
hand on 2026-11-13 from one run's output; the log makes it a read of a file.

These tests run the REAL hook in scripts/lib-hook-sandbox.sh's sandbox (the
fixture of test_gate_cache_hooks.py). test_hook_steps_table.py drives the pure
functions of the script with logs written there.
"""
import os
import pathlib
import re
import signal
import subprocess
import time

from conftest import load
from test_gate_cache_hooks import git, junit, pc  # noqa: F401 - pc is the sandbox fixture

hs = load("hook-steps")

REPO = pathlib.Path(__file__).resolve().parents[2]
LOG_NAME = "sipnab-pre-commit-steps.log"
CLIPPY = "Clippy (CI's exact scope)"
HEADING = re.compile(r"^  (\S.*?)\.\.\. ", re.M)
# A one-line notice in the shape of a heading, for two steps the sandbox does
# not have (scripts/prose-gates.sh is not copied into it): not a timed step.
NOTICES = {"Vale/Codespell"}


def printed(out: str) -> list:
    """The step headings a run printed: those after "Running pre-commit
    checks", since the lines before it (the own-tree check, the
    prerequisites) come before the pass stamp is read and are not steps."""
    steps = out.split("Running pre-commit checks...", 1)[1]
    return [name for name in HEADING.findall(steps) if name not in NOTICES]


def log_of(sb) -> pathlib.Path:
    return sb.tree / ".git" / LOG_NAME


def lines_of(sb):
    return [line.split("\t") for line in log_of(sb).read_text().splitlines()]


def rows_of(sb):
    """The step lines: every line of the log that is not a note."""
    return [fields for fields in lines_of(sb) if not is_note(fields)]


def is_note(fields) -> bool:
    return len(fields) == 3 and fields[1] == "nextest"


def notes_of(sb):
    return [fields for fields in lines_of(sb) if is_note(fields)]


def ran(sb, **extra):
    rc, out = sb.run(**extra)
    return rc, out, rows_of(sb)


# ── the hook writes the log ───────────────────────────────────────────────


def test_success_a_passing_run_writes_one_line_per_step_it_printed(pc):  # noqa: F811
    rc, out, rows = ran(pc)
    assert rc == 0, out
    names = printed(out)
    assert len(names) >= 15, out
    assert [r[1] for r in rows] == [*names, "total"], rows


def test_success_every_line_has_four_fields_and_whole_seconds(pc):  # noqa: F811
    _, _, rows = ran(pc)
    assert all(len(r) == 4 for r in rows), rows
    assert all(re.fullmatch(r"\d+", r[2]) for r in rows), rows


def test_success_every_step_of_a_passing_run_ended_0(pc):  # noqa: F811
    _, _, rows = ran(pc)
    assert {r[3] for r in rows} == {"0"}, rows


def test_success_one_run_has_one_run_name_with_its_start_time(pc):  # noqa: F811
    _, _, rows = ran(pc)
    assert len({r[0] for r in rows}) == 1, rows
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ\.\d+", rows[0][0]), rows[0]


def test_success_a_slow_step_shows_its_seconds_and_the_total_holds_them(pc):  # noqa: F811
    (pc.harness / "sleep-clippy").write_text("2\n")
    _, _, rows = ran(pc)
    by = {r[1]: int(r[2]) for r in rows}
    assert by[CLIPPY] >= 2, rows
    assert by["total"] >= by[CLIPPY], rows


def test_success_the_total_is_at_least_the_sum_of_the_steps_less_rounding(pc):  # noqa: F811
    _, _, rows = ran(pc)
    steps = [int(r[2]) for r in rows if r[1] != "total"]
    total = int(rows[-1][2])
    # Each step is cut to whole seconds, and so is the total: the total can
    # be at most one second under the sum.
    assert total >= sum(steps) - 1, rows


def test_success_a_second_run_appends_under_a_name_of_its_own(pc):  # noqa: F811
    ran(pc)
    # No wait between the two: the run name holds the process number as well.
    (pc.tree / "src/lib.rs").write_text("pub fn prod() -> u8 { 2 }\n")
    git(pc.tree, "add", "src/lib.rs")
    _, _, rows = ran(pc)
    names = list(dict.fromkeys(r[0] for r in rows))
    assert len(names) == 2, names
    assert [r[1] for r in rows].count("total") == 2, rows


def test_success_the_hook_prints_each_step_name_as_before(pc):  # noqa: F811
    _, out, _ = ran(pc)
    for name in ("Formatting", CLIPPY, "Tests", "Script tests", "Developer-docs coupling"):
        assert f"  {name}... " in out, out


def test_failure_a_failed_step_is_the_last_step_line_with_its_status(pc):  # noqa: F811
    pc.switch("fail-clippy")
    rc, out, rows = ran(pc)
    assert rc == 1, out
    assert rows[-2][1:] == [CLIPPY, rows[-2][2], "1"], rows
    assert rows[-1][1] == "total" and rows[-1][3] == "1", rows


def test_failure_the_steps_before_a_failed_one_ended_0(pc):  # noqa: F811
    (pc.harness / "canned-junit.xml").write_text(junit(("sipnab::bin1", "t1", False), ("sipnab::bin1", "t2", True)))
    rc, out, rows = ran(pc)
    assert rc == 1, out
    assert [r[1] for r in rows] == ["Formatting", CLIPPY, "Tests", "total"], rows
    assert [r[3] for r in rows] == ["0", "0", "1", "1"], rows


def test_failure_no_step_after_the_failed_one_is_in_the_log(pc):  # noqa: F811
    pc.switch("fail-clippy")
    _, _, rows = ran(pc)
    assert "Tests" not in [r[1] for r in rows], rows


def test_failure_a_log_that_cannot_be_written_does_not_fail_the_hook(pc):  # noqa: F811
    log_of(pc).mkdir()
    rc, out = pc.run()
    assert rc == 0, out
    assert "All pre-commit checks passed." in out, out


def test_failure_a_log_that_cannot_be_written_prints_no_error_line(pc):  # noqa: F811
    log_of(pc).mkdir()
    _, out = pc.run()
    assert LOG_NAME not in out and "Is a directory" not in out, out


def test_failure_a_killed_run_has_step_lines_and_no_total(pc):  # noqa: F811
    (pc.harness / "sleep-clippy").write_text("120\n")
    env = pc.env(SIPNAB_HOOK_ANY_TREE="1")
    p = subprocess.Popen(["bash", str(pc.hook)], cwd=pc.tree, env=env, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, start_new_session=True)
    try:
        # The hook closes a step when the next one starts: the formatting line
        # is in the log once the hook is inside the Vale step or later.
        deadline = time.monotonic() + 240
        while time.monotonic() < deadline and not (log_of(pc).is_file() and log_of(pc).read_text()):
            time.sleep(0.05)
    finally:
        os.killpg(p.pid, signal.SIGKILL)
        p.wait(30)
    rows = rows_of(pc)
    assert rows and "total" not in [r[1] for r in rows], rows


def test_edge_a_run_that_a_stamp_skips_writes_no_line(pc):  # noqa: F811
    ran(pc)
    before = log_of(pc).read_text()
    rc, out = pc.run()
    assert rc == 0 and "PASSED before on these exact inputs" in out, out
    assert log_of(pc).read_text() == before


def test_edge_a_cached_step_is_in_the_log_with_status_0(pc):  # noqa: F811
    ran(pc)
    (pc.tree / "docs/guide.md").write_text("# Guide\n")
    git(pc.tree, "add", "docs/guide.md")
    rc, out, rows = ran(pc)
    assert rc == 0, out
    last = [r for r in rows if r[0] == rows[-1][0]]
    assert [CLIPPY, "0"] in [[r[1], r[3]] for r in last], last


def test_edge_a_long_log_is_cut_to_its_newest_lines_before_the_run(pc):  # noqa: F811
    old = "".join(f"2026-01-01T00:00:00Z.{i}\tOld\t1\t0\n" for i in range(5000))
    log_of(pc).write_text(old)
    _, _, rows = ran(pc)
    olds = [r for r in rows if r[1] == "Old"]
    assert len(olds) == 2000, len(olds)
    assert olds[-1][0] == "2026-01-01T00:00:00Z.4999" and olds[0][0] == "2026-01-01T00:00:00Z.3000"


def test_edge_a_log_at_the_limit_is_left_whole(pc):  # noqa: F811
    old = "".join(f"2026-01-01T00:00:00Z.{i}\tOld\t1\t0\n" for i in range(4000))
    log_of(pc).write_text(old)
    _, _, rows = ran(pc)
    assert len([r for r in rows if r[1] == "Old"]) == 4000


def test_edge_the_log_cut_leaves_no_file_beside_the_log(pc):  # noqa: F811
    log_of(pc).write_text("r\tOld\t1\t0\n" * 5000)
    ran(pc)
    assert [p.name for p in (pc.tree / ".git").glob(LOG_NAME + "*")] == [LOG_NAME]


def test_edge_no_step_name_holds_a_tab_or_is_empty(pc):  # noqa: F811
    _, _, rows = ran(pc)
    assert all(r[1].strip() and r[1] == r[1].strip() for r in rows), rows


def test_edge_every_step_heading_in_the_hook_goes_through_step():
    hook = (REPO / ".githooks/pre-commit").read_text()
    bare = [line for line in hook.splitlines() if re.match(r'\s*echo -n "  \S.*\.\.\. "', line)]
    assert bare == [], bare
    assert len(re.findall(r'^\s*step "[^"\t]+"$', hook, re.M)) >= 20


def test_edge_the_table_script_reads_what_the_hook_wrote(pc):  # noqa: F811
    _, out, _ = ran(pc)
    rows, bad = hs.parse(log_of(pc).read_text())
    assert bad == 0
    assert [r.step for r in rows][:-1] == printed(out)


# ── the nextest Summary line of a passing suite ───────────────────────────
#
# Two passing runs could not be compared by their totals: the hook kept a
# summary only for a failed run. A passing suite now leaves a note, a line of
# three fields: the run, `nextest`, nextest's Summary line.

SUMMARY = "Summary [ 337.143s] 16257 tests run: 16257 passed (5 slow, 3 leaky), 48 skipped"


def summary(sb, text):
    (sb.harness / "nextest-summary").write_text(text)


def test_success_a_passing_run_notes_the_nextest_summary_line(pc):  # noqa: F811
    summary(pc, f"------------\n     {SUMMARY}\n")
    rc, out = pc.run()
    assert rc == 0, out
    assert [n[2] for n in notes_of(pc)] == [SUMMARY], lines_of(pc)


def test_success_the_note_carries_the_name_of_its_run(pc):  # noqa: F811
    rc, out, rows = ran(pc)
    assert rc == 0, out
    assert [n[0] for n in notes_of(pc)] == [rows[0][0]], lines_of(pc)


def test_success_the_note_is_written_inside_the_tests_step(pc):  # noqa: F811
    ran(pc)
    names = [fields[1] for fields in lines_of(pc)]
    assert names.index("nextest") + 1 == names.index("Tests"), names


def test_success_the_default_sandbox_summary_counts_its_tests(pc):  # noqa: F811
    ran(pc)
    assert re.fullmatch(r"Summary \[ +0\.004s\] (\d+) tests run: \1 passed, 0 skipped", notes_of(pc)[0][2]), notes_of(pc)


def test_failure_a_failed_suite_leaves_no_note(pc):  # noqa: F811
    (pc.harness / "canned-junit.xml").write_text(junit(("sipnab::bin1", "t1", False)))
    rc, out = pc.run()
    assert rc == 1, out
    assert notes_of(pc) == [], lines_of(pc)


def test_failure_a_run_that_fails_before_the_suite_leaves_no_note(pc):  # noqa: F811
    pc.switch("fail-clippy")
    rc, out = pc.run()
    assert rc == 1, out
    assert notes_of(pc) == [], lines_of(pc)


def test_edge_a_run_without_a_summary_line_passes_and_leaves_no_note(pc):  # noqa: F811
    (pc.harness / "nextest-summary").unlink()
    rc, out = pc.run()
    assert rc == 0, out
    assert notes_of(pc) == [] and rows_of(pc)[-1][1] == "total", lines_of(pc)


def test_edge_a_tab_in_the_summary_does_not_add_a_field(pc):  # noqa: F811
    summary(pc, "     Summary [ 1.0s] 2 tests\trun: 2 passed, 0 skipped\n")
    ran(pc)
    assert [n[2] for n in notes_of(pc)] == ["Summary [ 1.0s] 2 tests run: 2 passed, 0 skipped"], lines_of(pc)


def test_edge_the_last_summary_line_is_the_one_noted(pc):  # noqa: F811
    summary(pc, "     Summary [ 1.0s] 1 test run: 1 passed, 0 skipped\n     Summary [ 2.0s] 2 tests run: 2 passed, 0 skipped\n")
    ran(pc)
    assert [n[2] for n in notes_of(pc)] == ["Summary [ 2.0s] 2 tests run: 2 passed, 0 skipped"], lines_of(pc)


def test_edge_the_table_script_does_not_count_the_note_as_a_bad_line(pc):  # noqa: F811
    ran(pc)
    text = log_of(pc).read_text()
    assert "\tnextest\t" in text, text
    _, bad = hs.parse(text)
    assert bad == 0


def test_edge_the_table_prints_the_note_under_the_run(pc):  # noqa: F811
    summary(pc, f"     {SUMMARY}\n")
    ran(pc)
    out = subprocess.run(["python3", str(REPO / "scripts/hook-steps.py"), "--log", str(log_of(pc))],
                         capture_output=True, text=True, check=False)
    assert out.returncode == 0, out.stderr
    assert out.stdout.rstrip().endswith(f"nextest: {SUMMARY}"), out.stdout
