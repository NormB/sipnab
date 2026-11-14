# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors
"""scripts/hook-steps.py: reading the pre-commit hook's step log.

The pure functions and `main`, driven by logs written here. The tests that
run the hook itself, and so write a real log, are in test_hook_steps.py.
"""
import pathlib
import subprocess

import pytest
from conftest import load

hs = load("hook-steps")

REPO = pathlib.Path(__file__).resolve().parents[2]
LOG_NAME = "sipnab-pre-commit-steps.log"

RUN_A = "2026-11-13T04:00:00Z.100"
RUN_B = "2026-11-13T05:00:00Z.200"
LOG = (f"{RUN_A}\tFormatting\t3\t0\n{RUN_A}\tTests\t735\t0\n{RUN_A}\tScript tests\t252\t0\n{RUN_A}\ttotal\t1191\t0\n"
       f"{RUN_B}\tFormatting\t5\t0\n{RUN_B}\tTests\t40\t1\n{RUN_B}\ttotal\t47\t1\n")


def parsed(text=LOG):
    return hs.parse(text)[0]


def test_success_parse_reads_every_line():
    rows, bad = hs.parse(LOG)
    assert (len(rows), bad) == (7, 0)
    assert rows[1] == hs.Row(RUN_A, "Tests", 735, 0)


def test_success_runs_keeps_the_order_of_the_log():
    assert list(hs.runs(parsed())) == [RUN_A, RUN_B]


def test_success_the_table_of_a_run_has_a_line_per_step():
    lines = hs.table(RUN_A, hs.runs(parsed())[RUN_A]).splitlines()
    assert [line.split()[0] for line in lines[2:5]] == ["Formatting", "Tests", "Script"]


def test_success_the_table_shows_seconds_and_the_share_of_the_total():
    text = hs.table(RUN_A, hs.runs(parsed())[RUN_A])
    line = next(line for line in text.splitlines() if line.startswith("Tests"))
    assert line.split() == ["Tests", "735", "61.7%", "0"], line


def test_success_the_table_names_the_time_outside_every_step():
    text = hs.table(RUN_A, hs.runs(parsed())[RUN_A])
    line = next(line for line in text.splitlines() if line.startswith("(outside the steps)"))
    assert line.split()[-2:] == ["201", "16.9%"], line


def test_success_the_table_ends_with_the_total():
    last = hs.table(RUN_A, hs.runs(parsed())[RUN_A]).splitlines()[-1]
    assert last.split() == ["total", "1191", "100.0%", "0"], last


def test_success_the_table_starts_with_the_run_name_and_result():
    first = hs.table(RUN_A, hs.runs(parsed())[RUN_A]).splitlines()[0]
    assert first == f"run {RUN_A}: passed in 1191 s"


def test_success_main_prints_the_last_run_by_default(tmp_path, capsys):
    log = tmp_path / "steps.log"
    log.write_text(LOG)
    assert hs.main(["--log", str(log)]) == 0
    out = capsys.readouterr().out
    assert RUN_B in out and RUN_A not in out


def test_success_main_prints_the_last_n_runs_oldest_first(tmp_path, capsys):
    log = tmp_path / "steps.log"
    log.write_text(LOG)
    assert hs.main(["--log", str(log), "--runs", "2"]) == 0
    out = capsys.readouterr().out
    assert out.index(RUN_A) < out.index(RUN_B)


def test_success_the_mean_is_over_the_runs_that_passed(tmp_path, capsys):
    log = tmp_path / "steps.log"
    third = LOG.replace(RUN_A, "2026-11-13T06:00:00Z.300").split(RUN_B)[0].replace("\t735\t", "\t535\t")
    log.write_text(LOG + third)
    assert hs.main(["--log", str(log), "--mean", "10"]) == 0
    out = capsys.readouterr().out
    line = next(line for line in out.splitlines() if line.startswith("Tests"))
    assert line.split() == ["Tests", "635", "735", "2"], out


def test_success_the_mean_says_how_many_runs_it_read(tmp_path, capsys):
    log = tmp_path / "steps.log"
    log.write_text(LOG)
    hs.main(["--log", str(log), "--mean", "10"])
    assert capsys.readouterr().out.splitlines()[0] == "mean of 1 run that passed (1 that did not is left out)"


def test_success_the_default_log_is_in_the_git_directory_of_the_checkout():
    assert hs.default_log() == hs.git_dir() / LOG_NAME
    assert hs.git_dir().is_dir()


def test_failure_a_failed_run_says_which_step_failed():
    first = hs.table(RUN_B, hs.runs(parsed())[RUN_B]).splitlines()[0]
    assert first == f"run {RUN_B}: FAILED at Tests (exit status 1) after 47 s"


def test_failure_a_run_with_no_total_is_named_as_not_ended():
    rows = parsed(f"{RUN_A}\tFormatting\t3\t0\n{RUN_A}\tVale\t9\t0\n")
    lines = hs.table(RUN_A, rows).splitlines()
    assert lines[0] == f"run {RUN_A}: NOT ENDED (no total line: the hook was killed, or is running); 12 s in its steps"
    assert not [line for line in lines if line.startswith("total")]


def test_failure_a_run_with_no_total_shows_no_share():
    rows = parsed(f"{RUN_A}\tFormatting\t3\t0\n")
    line = next(line for line in hs.table(RUN_A, rows).splitlines() if line.startswith("Formatting"))
    assert line.split() == ["Formatting", "3", "-", "0"], line


def test_failure_a_missing_log_is_exit_1_with_the_path(tmp_path, capsys):
    assert hs.main(["--log", str(tmp_path / "none.log")]) == 1
    assert str(tmp_path / "none.log") in capsys.readouterr().err


def test_failure_an_empty_log_is_exit_1(tmp_path, capsys):
    log = tmp_path / "steps.log"
    log.write_text("")
    assert hs.main(["--log", str(log)]) == 1
    assert "holds no step line" in capsys.readouterr().err


@pytest.mark.parametrize("line", [
    "only-three\tfields\t3",
    f"{RUN_A}\tTests\tfast\t0",
    f"{RUN_A}\tTests\t3\tok",
    f"{RUN_A}\tTests\t-3\t0",
    f"{RUN_A}\t\t3\t0",
    f"{RUN_A}\tTests\t3\t0\textra",
    "\tTests\t3\t0",
    "plain text",
])
def test_failure_a_line_that_is_not_a_step_line_is_counted_and_left_out(line):
    rows, bad = hs.parse(LOG + line + "\n")
    assert (len(rows), bad) == (7, 1), line


def test_failure_the_table_says_how_many_lines_it_could_not_read(tmp_path, capsys):
    log = tmp_path / "steps.log"
    log.write_text(LOG + "torn li")
    assert hs.main(["--log", str(log)]) == 0
    assert "1 line of the log is not a step line and was left out" in capsys.readouterr().err


def test_failure_a_runs_count_below_1_is_exit_2(tmp_path, capsys):
    log = tmp_path / "steps.log"
    log.write_text(LOG)
    assert hs.main(["--log", str(log), "--runs", "0"]) == 2
    assert hs.main(["--log", str(log), "--mean", "0"]) == 2
    capsys.readouterr()


def test_failure_the_mean_with_no_run_that_passed_is_exit_1(tmp_path, capsys):
    log = tmp_path / "steps.log"
    log.write_text(f"{RUN_B}\tTests\t40\t1\n{RUN_B}\ttotal\t47\t1\n")
    assert hs.main(["--log", str(log), "--mean", "5"]) == 1
    assert "no run that passed" in capsys.readouterr().err


def test_edge_blank_lines_are_not_counted_as_bad():
    rows, bad = hs.parse("\n" + LOG + "\n\n")
    assert (len(rows), bad) == (7, 0)


def test_edge_a_total_of_0_seconds_gives_no_division(tmp_path):
    rows = parsed(f"{RUN_A}\tFormatting\t0\t0\n{RUN_A}\ttotal\t0\t0\n")
    line = next(line for line in hs.table(RUN_A, rows).splitlines() if line.startswith("Formatting"))
    assert line.split() == ["Formatting", "0", "-", "0"], line


def test_edge_steps_longer_than_the_total_show_no_negative_rest():
    rows = parsed(f"{RUN_A}\tFormatting\t3\t0\n{RUN_A}\tVale\t3\t0\n{RUN_A}\ttotal\t5\t0\n")
    line = next(line for line in hs.table(RUN_A, rows).splitlines() if line.startswith("(outside the steps)"))
    assert line.split()[-2:] == ["0", "0.0%"], line


def test_edge_lines_of_two_runs_that_interleave_are_kept_apart():
    text = (f"{RUN_A}\tFormatting\t3\t0\n{RUN_B}\tFormatting\t5\t0\n{RUN_A}\ttotal\t4\t0\n{RUN_B}\ttotal\t6\t0\n")
    by = hs.runs(parsed(text))
    assert [len(by[RUN_A]), len(by[RUN_B])] == [2, 2]


def test_edge_a_step_that_ran_twice_in_a_run_has_two_lines():
    rows = parsed(f"{RUN_A}\tTests\t3\t0\n{RUN_A}\tTests\t4\t0\n{RUN_A}\ttotal\t8\t0\n")
    assert len([line for line in hs.table(RUN_A, rows).splitlines() if line.startswith("Tests")]) == 2


def test_edge_a_long_step_name_keeps_the_columns_apart():
    name = "No unwrap/expect/panic in production and a good deal more text"
    rows = parsed(f"{RUN_A}\t{name}\t3\t0\n{RUN_A}\ttotal\t3\t0\n")
    line = next(line for line in hs.table(RUN_A, rows).splitlines() if line.startswith(name))
    assert line[len(name):].split() == ["3", "100.0%", "0"] and line[len(name)] == " ", line


def test_edge_a_long_step_name_moves_every_line_so_the_columns_stay_in_line():
    name = "No unwrap/expect/panic in production and a good deal more text"
    rows = parsed(f"{RUN_A}\t{name}\t3\t0\n{RUN_A}\tVale\t4\t0\n{RUN_A}\ttotal\t7\t0\n")
    lines = hs.table(RUN_A, rows).splitlines()[1:]
    ends = {line.index("%") if "%" in line else line.index("share") + len("share") - 1 for line in lines}
    assert len(ends) == 1, lines


def test_edge_a_passed_run_older_than_the_newest_n_is_not_called_left_out(tmp_path, capsys):
    log = tmp_path / "steps.log"
    log.write_text("".join(f"r{i}\tTests\t{i}\t0\nr{i}\ttotal\t{i}\t0\n" for i in range(1, 5)))
    hs.main(["--log", str(log), "--mean", "2"])
    assert capsys.readouterr().out.splitlines()[0] == "mean of 2 runs that passed"


def test_edge_more_runs_asked_for_than_the_log_holds_prints_them_all(tmp_path, capsys):
    log = tmp_path / "steps.log"
    log.write_text(LOG)
    assert hs.main(["--log", str(log), "--runs", "50"]) == 0
    assert capsys.readouterr().out.count("run 2026-") == 2


def test_edge_the_mean_takes_only_the_newest_n_runs_that_passed(tmp_path, capsys):
    log = tmp_path / "steps.log"
    runs = "".join(f"r{i}\tTests\t{i * 100}\t0\nr{i}\ttotal\t{i * 100}\t0\n" for i in range(1, 5))
    log.write_text(runs)
    hs.main(["--log", str(log), "--mean", "2"])
    line = next(line for line in capsys.readouterr().out.splitlines() if line.startswith("Tests"))
    assert line.split() == ["Tests", "350", "400", "2"], line


def test_edge_the_mean_leaves_out_a_run_that_did_not_end(tmp_path, capsys):
    log = tmp_path / "steps.log"
    log.write_text(LOG + "r9\tTests\t9000\t0\n")
    hs.main(["--log", str(log), "--mean", "10"])
    out = capsys.readouterr().out
    assert out.splitlines()[0] == "mean of 1 run that passed (2 that did not are left out)"


def test_edge_the_script_runs_as_a_program(tmp_path):
    log = tmp_path / "steps.log"
    log.write_text(LOG)
    r = subprocess.run(["python3", str(REPO / "scripts/hook-steps.py"), "--log", str(log)],
                       capture_output=True, text=True, timeout=60, check=False)
    assert r.returncode == 0 and r.stdout.splitlines()[-1].split() == ["total", "47", "100.0%", "1"], r


# ── notes: the nextest Summary line of a suite that passed ────────────────

NOTE_A = "Summary [ 337.143s] 16257 tests run: 16257 passed (5 slow, 3 leaky), 48 skipped"
NOTED = LOG.replace(f"{RUN_A}\tTests\t735\t0\n", f"{RUN_A}\tnextest\t{NOTE_A}\n{RUN_A}\tTests\t735\t0\n")


def test_success_a_note_is_read_with_its_run():
    assert hs.notes(NOTED) == {RUN_A: [f"nextest: {NOTE_A}"]}


def test_success_a_note_is_not_a_step_and_not_a_bad_line():
    rows, bad = hs.parse(NOTED)
    assert (len(rows), bad) == (7, 0)
    assert "nextest" not in [r.step for r in rows]


def test_success_the_newest_run_with_a_note_ends_with_it(tmp_path, capsys):
    log = tmp_path / "steps.log"
    log.write_text(LOG + f"{RUN_B}\tnextest\tSummary [ 1.0s] 2 tests run: 2 passed, 0 skipped\n")
    assert hs.main(["--log", str(log)]) == 0
    assert capsys.readouterr().out.splitlines()[-1] == "nextest: Summary [ 1.0s] 2 tests run: 2 passed, 0 skipped"


def test_success_each_run_of_several_shows_its_own_note(tmp_path, capsys):
    log = tmp_path / "steps.log"
    log.write_text(NOTED)
    assert hs.main(["--log", str(log), "--runs", "2"]) == 0
    first, second = capsys.readouterr().out.split("\n\n")
    assert first.splitlines()[-1] == f"nextest: {NOTE_A}" and "nextest" not in second


@pytest.mark.parametrize(
    "line",
    [
        f"{RUN_A}\tother\ttext\n",
        f"{RUN_A}\tnextest\t\n",
        f"{RUN_A}\tnextest\t  \n",
        f"\tnextest\t{NOTE_A}\n",
        f"{RUN_A}\tnextest\n",
        f"{RUN_A}\tnextest\ta\tb\n",
        f"{RUN_A}\tnextest\t{NOTE_A}\textra\tfield\n",
        f"   \tnextest\t{NOTE_A}\n",
        f"{RUN_A}\tNextest\t{NOTE_A}\n",
        f"{RUN_A}\t nextest\t{NOTE_A}\n",
    ],
)
def test_failure_a_three_field_line_that_is_not_a_note_is_a_bad_line(line):
    rows, bad = hs.parse(LOG + line)
    assert (len(rows), bad) == (7, 1)
    assert hs.notes(LOG + line) == {}


def test_success_the_notes_of_two_runs_are_kept_apart():
    text = NOTED + f"{RUN_B}\tnextest\tSummary [ 1.0s] 2 tests run: 2 passed, 0 skipped\n"
    assert hs.notes(text) == {
        RUN_A: [f"nextest: {NOTE_A}"],
        RUN_B: ["nextest: Summary [ 1.0s] 2 tests run: 2 passed, 0 skipped"],
    }


def test_success_two_notes_of_one_run_print_in_log_order(tmp_path, capsys):
    log = tmp_path / "steps.log"
    log.write_text(LOG + f"{RUN_B}\tnextest\tfirst\n{RUN_B}\tnextest\tsecond\n")
    assert hs.main(["--log", str(log)]) == 0
    assert capsys.readouterr().out.splitlines()[-2:] == ["nextest: first", "nextest: second"]


def test_success_the_newest_run_alone_does_not_show_an_older_runs_note(tmp_path, capsys):
    log = tmp_path / "steps.log"
    log.write_text(NOTED)
    assert hs.main(["--log", str(log), "--runs", "1"]) == 0
    out = capsys.readouterr().out
    assert out.startswith(f"run {RUN_B}") and "nextest" not in out, out


def test_success_a_note_keeps_its_brackets_and_inner_spaces():
    assert hs.notes(f"{RUN_A}\tnextest\tSummary [   0.004s] 2 tests run\n") == {RUN_A: ["nextest: Summary [   0.004s] 2 tests run"]}


def test_edge_the_text_of_a_note_loses_the_spaces_around_it():
    assert hs.notes(f"{RUN_A}\tnextest\t  {NOTE_A}  \n") == {RUN_A: [f"nextest: {NOTE_A}"]}


def test_edge_a_note_of_a_run_without_a_step_line_is_not_printed(tmp_path, capsys):
    log = tmp_path / "steps.log"
    log.write_text(LOG + "2026-11-13T06:00:00Z.300\tnextest\tSummary of a run with no step\n")
    assert hs.main(["--log", str(log), "--runs", "5"]) == 0
    assert "no step" not in capsys.readouterr().out


def test_edge_a_note_does_not_change_the_table_of_its_run():
    assert hs.table(RUN_A, hs.runs(hs.parse(NOTED)[0])[RUN_A]) == hs.table(RUN_A, hs.runs(parsed())[RUN_A])


def test_edge_a_log_without_a_note_prints_the_table_alone(tmp_path, capsys):
    log = tmp_path / "steps.log"
    log.write_text(LOG)
    assert hs.main(["--log", str(log)]) == 0
    assert "nextest" not in capsys.readouterr().out


def test_edge_the_mean_table_leaves_notes_out(tmp_path, capsys):
    log = tmp_path / "steps.log"
    log.write_text(NOTED)
    assert hs.main(["--log", str(log), "--mean", "5"]) == 0
    assert "nextest" not in capsys.readouterr().out


def test_edge_a_step_named_nextest_with_four_fields_is_a_step():
    rows, bad = hs.parse(f"{RUN_A}\tnextest\t3\t0\n")
    assert bad == 0 and rows == [hs.Row(RUN_A, "nextest", 3, 0)]


def test_edge_a_log_of_notes_alone_holds_no_step_line(tmp_path, capsys):
    log = tmp_path / "steps.log"
    log.write_text(f"{RUN_A}\tnextest\t{NOTE_A}\n")
    assert hs.main(["--log", str(log)]) == 1
    assert "holds no step line" in capsys.readouterr().err
