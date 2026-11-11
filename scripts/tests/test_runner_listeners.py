# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""scripts/runner-listeners.py: one Runner.Listener per runner directory, and
no unit whose restart count climbs.

On 2026-11-10 two self-hosted runners each had two listeners: the unit's
supervisor had exited on 2026-11-02, the unit's KillMode=process left
run-helper.sh and Runner.Listener running outside the unit, and
Restart=always started a second supervisor about every 4 minutes (NRestarts
1342 and 1345). When GitHub accepted the second session, each job got two
workers writing one log file and failed in 2 s.

The script reports that state and changes nothing: it reads `ps` and
`systemctl show`. No test here runs either; the tests give it text, or files
of text, or a PATH whose `ps` and `systemctl` are stubs.
"""

import json
import pathlib
import subprocess
import sys

import pytest

from conftest import SCRIPTS, load

rl = load("runner-listeners")

R1 = "/home/ci/actions-runner"
R2 = "/home/ci/actions-runner-2"
R3 = "/home/ci/actions-runner-3"


@pytest.fixture(autouse=True)
def _no_real_commands(monkeypatch):
    """A test that reaches a real command or sleeps, in this process, fails."""

    class Refuse:
        def __init__(self, what):
            self.what = what

        def __getattr__(self, name):
            def refuse(*args, **kwargs):
                raise AssertionError(f"a test reached the real {self.what}.{name}: {args!r}")
            return refuse

    monkeypatch.setattr(rl, "subprocess", Refuse("subprocess"))
    monkeypatch.setattr(rl, "time", Refuse("time"))


def chain(runner_dir, run_sh, helper, listener, parent=1):
    """The three processes of one healthy runner, as `ps` lines."""
    return (f"{run_sh:>7} {parent:>7} /bin/bash {runner_dir}/run.sh\n"
            f"{helper:>7} {run_sh:>7} /bin/bash {runner_dir}/run-helper.sh\n"
            f"{listener:>7} {helper:>7} {runner_dir}/bin/Runner.Listener run\n")


def unit(name, runner_dir, main_pid, restarts=0, kill_mode="process", state="active"):
    return {"Id": name, "WorkingDirectory": runner_dir, "MainPID": str(main_pid),
            "NRestarts": str(restarts), "KillMode": kill_mode, "ActiveState": state}


def procs(text):
    return rl.parse_ps(text)


HEALTHY = chain(R1, 1887, 1414162, 1414166) + chain(R2, 3499012, 3499019, 3499023)
UNITS = [unit("gh-runner-ci.service", R1, 1887, kill_mode="control-group"),
         unit("gh-runner-ci-2.service", R2, 3499012)]


# ---- reading `ps` ----------------------------------------------------------


def test_ps_lines_become_pid_parent_and_arguments():
    out = procs("   1887       1 /bin/bash /home/ci/actions-runner/run.sh\n")
    assert out == [rl.Proc(1887, 1, "/bin/bash /home/ci/actions-runner/run.sh")]


def test_blank_lines_in_ps_are_skipped():
    assert len(procs("\n" + HEALTHY + "\n\n")) == 6


def test_a_process_with_no_arguments_column_is_kept_with_empty_arguments():
    assert procs("  12   1\n") == [rl.Proc(12, 1, "")]


def test_arguments_keep_their_inner_spaces():
    assert procs("5 1 a  b   c\n")[0].args == "a  b   c"


@pytest.mark.parametrize("bad", ["PID PPID COMMAND\n", "12 x /bin/true\n", "x 1 /bin/true\n", "12\n"])
def test_a_ps_line_that_is_not_two_numbers_and_text_is_refused(bad):
    with pytest.raises(ValueError):
        procs(bad)


def test_one_bad_row_among_good_ones_is_refused_not_skipped():
    """A skipped row could be the second listener."""
    with pytest.raises(ValueError):
        procs(HEALTHY + "garbage row\n")


def test_empty_ps_output_is_refused():
    with pytest.raises(ValueError):
        procs("")


# ---- which processes are a directory's listeners ---------------------------


def test_the_listener_of_a_directory_is_found_by_its_program_path():
    assert [p.pid for p in rl.listeners_in(procs(HEALTHY), R1)] == [1414166]


def test_a_directory_whose_name_starts_another_is_not_confused_with_it():
    """actions-runner is a prefix of actions-runner-2."""
    assert [p.pid for p in rl.listeners_in(procs(HEALTHY), R2)] == [3499023]
    assert len(rl.listeners_in(procs(HEALTHY), R1)) == 1


def test_a_trailing_slash_on_the_directory_changes_nothing():
    assert [p.pid for p in rl.listeners_in(procs(HEALTHY), R1 + "/")] == [1414166]


def test_run_sh_and_run_helper_are_not_listeners():
    ps = f"1 0 /bin/bash {R1}/run.sh\n2 1 /bin/bash {R1}/run-helper.sh\n"
    assert rl.listeners_in(procs(ps), R1) == []


def test_a_command_that_only_mentions_the_listener_path_is_not_a_listener():
    ps = f"9 1 grep {R1}/bin/Runner.Listener\n10 1 tail -f {R1}/bin/Runner.Listener.log\n"
    assert rl.listeners_in(procs(ps), R1) == []


def test_a_runner_worker_is_not_a_listener():
    ps = f"9 1 {R1}/bin/Runner.Worker spawnclient 1 2\n"
    assert rl.listeners_in(procs(ps), R1) == []


def test_a_listener_with_other_arguments_is_still_a_listener():
    ps = f"9 1 {R1}/bin/Runner.Listener run --once\n10 1 {R1}/bin/Runner.Listener\n"
    assert [p.pid for p in rl.listeners_in(procs(ps), R1)] == [9, 10]


# ---- ancestry --------------------------------------------------------------


def test_a_listener_descends_from_its_units_main_process():
    assert rl.descends_from(procs(HEALTHY), 1414166, 1887)


def test_a_process_descends_from_itself():
    assert rl.descends_from(procs(HEALTHY), 1887, 1887)


def test_a_listener_does_not_descend_from_another_runners_supervisor():
    assert not rl.descends_from(procs(HEALTHY), 1414166, 3499012)


def test_a_process_whose_parent_is_gone_descends_from_nothing_else():
    ps = f"50 49 {R1}/bin/Runner.Listener run\n60 1 /bin/bash {R1}/run.sh\n"
    assert not rl.descends_from(procs(ps), 50, 60)


def test_a_parent_loop_in_the_process_table_ends():
    ps = "5 6 a\n6 5 b\n7 1 c\n"
    assert not rl.descends_from(procs(ps), 5, 7)


# ---- reading `systemctl show` ----------------------------------------------


def test_show_output_becomes_a_dictionary():
    out = rl.parse_show("MainPID=1887\nNRestarts=0\nKillMode=control-group\n")
    assert out == {"MainPID": "1887", "NRestarts": "0", "KillMode": "control-group"}


def test_a_value_that_holds_an_equals_sign_is_kept_whole():
    assert rl.parse_show("ExecStart={ path=/x/run.sh ; argv[]=/x/run.sh }\n")["ExecStart"] == "{ path=/x/run.sh ; argv[]=/x/run.sh }"


def test_show_output_with_no_key_value_line_is_refused():
    with pytest.raises(ValueError):
        rl.parse_show("Failed to connect to bus\n")


# ---- one listener per directory --------------------------------------------


def findings(ps_text, units=UNITS, dirs=(R1, R2)):
    return rl.listener_findings(list(dirs), units, procs(ps_text))


def test_two_healthy_runners_have_no_finding():
    assert findings(HEALTHY) == []


def test_four_healthy_runners_have_no_finding():
    ps = HEALTHY + chain(R3, 4194147, 4194216, 4194243)
    units = UNITS + [unit("gh-runner-ci-3.service", R3, 4194147)]
    assert findings(ps, units, (R1, R2, R3)) == []


def test_a_directory_with_no_listener_is_reported():
    out = findings(chain(R1, 1887, 1414162, 1414166))
    assert len(out) == 1
    assert R2 in out[0] and "no Runner.Listener" in out[0]


def test_two_listeners_in_one_directory_are_reported_with_both_pids():
    ps = HEALTHY + chain(R2, 700, 701, 702)
    out = findings(ps)
    assert any("2 Runner.Listener processes" in f and "702" in f and "3499023" in f and R2 in f for f in out), out


def test_three_listeners_in_one_directory_are_counted():
    ps = HEALTHY + chain(R2, 700, 701, 702) + chain(R2, 800, 801, 802)
    assert any("3 Runner.Listener processes" in f for f in findings(ps))


def test_the_orphan_of_2026_11_10_is_reported_as_outside_its_unit():
    """The unit's supervisor is new; the listener from 11-02 hangs off PID 1
    through a helper whose own parent has exited."""
    ps = (chain(R1, 1887, 1414162, 1414166)
          + f"1414300 1 /bin/bash {R2}/run-helper.sh\n1414305 1414300 {R2}/bin/Runner.Listener run\n"
          + f"3499012 1 /bin/bash {R2}/run.sh\n")
    out = findings(ps)
    assert len(out) == 1, out
    assert "1414305" in out[0] and "outside gh-runner-ci-2.service" in out[0] and "3499012" in out[0]


def test_an_orphan_beside_the_units_own_listener_gives_both_findings():
    ps = HEALTHY + f"1414300 1 /bin/bash {R2}/run-helper.sh\n1414305 1414300 {R2}/bin/Runner.Listener run\n"
    out = findings(ps)
    assert len(out) == 2, out
    assert any("2 Runner.Listener processes" in f for f in out)
    assert any("1414305" in f and "outside" in f for f in out)
    assert not any("3499023" in f and "outside" in f for f in out)


def test_a_listener_in_a_directory_no_unit_claims_is_not_called_outside_a_unit():
    out = rl.listener_findings([R1], [], procs(chain(R1, 1887, 1414162, 1414166)))
    assert out == []


def test_a_stopped_unit_with_a_listener_still_running_is_reported():
    """MainPID=0: the unit has no process, so the listener is not the unit's."""
    units = [UNITS[0], unit("gh-runner-ci-2.service", R2, 0, state="inactive")]
    out = findings(HEALTHY, units)
    assert len(out) == 1 and "3499023" in out[0] and "outside gh-runner-ci-2.service" in out[0], out


def test_each_bad_directory_gets_its_own_finding():
    out = findings(f"1 0 /sbin/init\n")
    assert len(out) == 2 and R1 in out[0] and R2 in out[1]


def test_no_runner_directory_at_all_is_refused_not_passed():
    with pytest.raises(ValueError):
        rl.listener_findings([], UNITS, procs(HEALTHY))


def test_a_unit_whose_main_pid_is_not_a_number_is_refused():
    bad = [unit("gh-runner-ci.service", R1, "n/a")]
    with pytest.raises(ValueError):
        rl.listener_findings([R1], bad, procs(HEALTHY))


# ---- restart counts --------------------------------------------------------


def restarts(before, after, secs=300):
    return rl.restart_findings(before, after, secs)


def test_a_count_that_does_not_move_is_not_reported():
    assert restarts({"a.service": 5}, {"a.service": 5}) == []


def test_a_count_that_rises_is_reported_with_both_values_and_the_time():
    out = restarts({"a.service": 1342}, {"a.service": 1343}, 240)
    assert len(out) == 1
    assert "a.service" in out[0] and "1342" in out[0] and "1343" in out[0] and "240 s" in out[0]


def test_a_count_that_fell_is_a_restarted_unit_not_a_climb():
    assert restarts({"a.service": 1342}, {"a.service": 0}) == []


def test_a_unit_seen_for_the_first_time_is_not_reported():
    assert restarts({}, {"a.service": 7}) == []


def test_a_unit_that_disappeared_is_not_reported():
    assert restarts({"a.service": 7}, {}) == []


def test_only_the_climbing_unit_is_reported_among_several():
    out = restarts({"a.service": 0, "b.service": 5, "c.service": 9},
                   {"a.service": 0, "b.service": 6, "c.service": 9})
    assert len(out) == 1 and "b.service" in out[0]


def test_a_high_count_that_stands_still_is_not_reported():
    """NRestarts 5 since a restart hours ago is history, not a climb."""
    assert restarts({"a.service": 1345}, {"a.service": 1345}) == []


def test_restart_counts_come_from_the_units_properties():
    assert rl.restart_counts([unit("a.service", R1, 1, restarts=5)]) == {"a.service": 5}


def test_a_restart_count_that_is_not_a_number_is_refused():
    with pytest.raises(ValueError):
        rl.restart_counts([unit("a.service", R1, 1, restarts="")])


# ---- notes -----------------------------------------------------------------


def test_a_unit_with_kill_mode_process_gets_a_note_not_a_finding():
    notes = rl.notes(UNITS)
    assert len(notes) == 1 and "gh-runner-ci-2.service" in notes[0] and "KillMode=process" in notes[0]


def test_a_unit_with_kill_mode_control_group_gets_no_note():
    assert rl.notes([UNITS[0]]) == []


# ---- only commands that read -----------------------------------------------


@pytest.mark.parametrize("argv", [
    ["ps", "-eo", "pid=,ppid=,args="],
    ["systemctl", "show", "gh-runner-ci.service", "-p", "MainPID"],
    ["systemctl", "list-units", "--all", "--plain", "--no-legend", "gh-runner-ci*.service"],
])
def test_the_reading_commands_are_allowed(argv):
    rl.check_read_only(argv)


@pytest.mark.parametrize("argv", [
    ["systemctl", "restart", "gh-runner-ci.service"],
    ["systemctl", "stop", "gh-runner-ci.service"],
    ["systemctl", "kill", "gh-runner-ci.service"],
    ["systemctl", "edit", "gh-runner-ci.service"],
    ["systemctl", "daemon-reload"],
    ["systemctl", "--user", "show", "x"],
    ["kill", "1414166"],
    ["pkill", "Runner.Listener"],
    ["sudo", "systemctl", "show", "x"],
    ["ps"],
    [],
])
def test_every_other_command_is_refused_before_it_runs(argv):
    with pytest.raises(PermissionError):
        rl.check_read_only(argv)


def test_the_script_never_signals_a_process_or_writes_a_unit():
    """The source has no call that signals, and no path under a systemd
    directory."""
    src = (SCRIPTS / "runner-listeners.py").read_text()
    for needle in ("os.kill", "signal.", "send_signal", ".terminate(", ".kill(", "/etc/systemd", "daemon-reload"):
        assert needle not in src, needle


def test_every_command_the_script_runs_goes_through_the_read_only_check():
    src = (SCRIPTS / "runner-listeners.py").read_text()
    assert src.count("subprocess.run(") == 1
    body = src[src.index("def read_command("):]
    assert body.index("check_read_only(argv)") < body.index("subprocess.run(")


# ---- the script as a program -----------------------------------------------

STUB = """#!{python}
import os, pathlib, sys
d = pathlib.Path(os.environ["STUB_DIR"])
name = pathlib.Path(sys.argv[0]).name
with open(d / "calls.log", "a") as log:
    log.write(name + " " + " ".join(sys.argv[1:]) + "\\n")
if name == "ps":
    body = (d / "ps.txt").read_text()
elif sys.argv[1] == "list-units":
    body = (d / "units.txt").read_text()
elif sys.argv[1] == "show":
    n = len([c for c in (d / "calls.log").read_text().splitlines() if c.startswith("systemctl show " + sys.argv[2] + " ")])
    f = d / (sys.argv[2] + ".show." + str(n))
    if not f.exists():
        f = d / (sys.argv[2] + ".show.1")
    body = f.read_text()
else:
    sys.exit(97)
if body.startswith("FAIL"):
    sys.stderr.write("stub: failed\\n")
    sys.exit(1)
sys.stdout.write(body)
"""


def show_text(u):
    return "".join(f"{k}={v}\n" for k, v in u.items())


def program(tmp_path, ps_text, units, *args, second=None, dirs=(R1, R2)):
    """Run the script with stub `ps` and `systemctl`. `second` holds the
    units' properties at the second read, when they differ."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name in ("ps", "systemctl"):
        f = bin_dir / name
        f.write_text(STUB.format(python=sys.executable))
        f.chmod(0o755)
    (tmp_path / "ps.txt").write_text(ps_text)
    (tmp_path / "units.txt").write_text("".join(f"{u['Id']} loaded active running x\n" for u in units)
                                        if units != "FAIL" else "FAIL")
    if units != "FAIL":
        for u in units:
            (tmp_path / f"{u['Id']}.show.1").write_text(show_text(u))
        for u in second or []:
            (tmp_path / f"{u['Id']}.show.2").write_text(show_text(u))
    argv = [sys.executable, str(SCRIPTS / "runner-listeners.py"), "--unit-glob", "gh-runner-ci*.service"]
    for d in dirs:
        argv += ["--runner-dir", d]
    p = subprocess.run(argv + list(args), capture_output=True, text=True, timeout=60,
                       env={"PATH": str(bin_dir), "STUB_DIR": str(tmp_path)})
    calls = (tmp_path / "calls.log").read_text().splitlines() if (tmp_path / "calls.log").exists() else []
    return p.returncode, p.stdout + p.stderr, calls


def test_program_healthy_runners_exit_0(tmp_path):
    rc, out, _ = program(tmp_path, HEALTHY, UNITS, "--interval", "0")
    assert rc == 0, out
    assert "2 runner directories" in out and "exactly one Runner.Listener each" in out


def test_program_two_listeners_exit_1_and_name_the_directory(tmp_path):
    rc, out, _ = program(tmp_path, HEALTHY + chain(R2, 700, 701, 702), UNITS, "--interval", "0")
    assert rc == 1, out
    assert "2 Runner.Listener processes" in out and R2 in out


def test_program_a_missing_listener_exits_1(tmp_path):
    rc, out, _ = program(tmp_path, chain(R1, 1887, 1414162, 1414166), UNITS, "--interval", "0")
    assert (rc, "no Runner.Listener" in out) == (1, True), out


def test_program_a_climbing_restart_count_exits_1(tmp_path):
    later = [UNITS[0], unit("gh-runner-ci-2.service", R2, 3499012, restarts=3)]
    rc, out, _ = program(tmp_path, HEALTHY, UNITS, "--interval", "0.01", second=later)
    assert rc == 1, out
    assert "gh-runner-ci-2.service" in out and "NRestarts rose from 0 to 3" in out


def test_program_a_steady_restart_count_exits_0(tmp_path):
    units = [UNITS[0], unit("gh-runner-ci-2.service", R2, 3499012, restarts=5)]
    rc, out, _ = program(tmp_path, HEALTHY, units, "--interval", "0.01")
    assert rc == 0, out
    assert "NRestarts did not rise" in out


def test_program_with_no_interval_says_the_restart_counts_were_not_judged(tmp_path):
    rc, out, _ = program(tmp_path, HEALTHY, UNITS, "--interval", "0")
    assert (rc, "NRestarts not judged" in out) == (0, True), out


def test_program_an_unreadable_ps_exits_2(tmp_path):
    rc, out, _ = program(tmp_path, "FAIL", UNITS, "--interval", "0")
    assert (rc, "could not read" in out) == (2, True), out


def test_program_an_unreadable_unit_list_exits_2(tmp_path):
    rc, out, _ = program(tmp_path, HEALTHY, "FAIL", "--interval", "0")
    assert (rc, "could not read" in out) == (2, True), out


def test_program_no_unit_found_exits_2_not_0(tmp_path):
    rc, out, _ = program(tmp_path, HEALTHY, [], "--interval", "0")
    assert (rc, "no unit matches" in out) == (2, True), out


def test_program_runs_only_ps_and_systemctl_show_and_list_units(tmp_path):
    _, _, calls = program(tmp_path, HEALTHY, UNITS, "--interval", "0.01")
    assert calls, calls
    for c in calls:
        assert c.startswith(("ps -eo ", "systemctl show ", "systemctl list-units ")), c


def test_program_prints_the_kill_mode_note_and_still_exits_0(tmp_path):
    rc, out, _ = program(tmp_path, HEALTHY, UNITS, "--interval", "0")
    assert rc == 0 and "note: gh-runner-ci-2.service" in out and "KillMode=process" in out, out


def test_program_state_file_reports_a_climb_since_the_last_run(tmp_path):
    state = tmp_path / "state.json"
    state.write_text(json.dumps({"at": 1.0, "units": {"gh-runner-ci-2.service": 1342}}))
    units = [UNITS[0], unit("gh-runner-ci-2.service", R2, 3499012, restarts=1345)]
    rc, out, _ = program(tmp_path, HEALTHY, units, "--state", str(state))
    assert rc == 1, out
    assert "NRestarts rose from 1342 to 1345" in out
    assert json.loads(state.read_text())["units"]["gh-runner-ci-2.service"] == 1345


def test_program_state_file_first_run_records_and_exits_0(tmp_path):
    state = tmp_path / "state.json"
    rc, out, _ = program(tmp_path, HEALTHY, UNITS, "--state", str(state))
    assert rc == 0, out
    assert json.loads(state.read_text())["units"] == {"gh-runner-ci.service": 0, "gh-runner-ci-2.service": 0}


def test_program_a_state_file_that_is_not_json_exits_2_and_is_left_alone(tmp_path):
    state = tmp_path / "state.json"
    state.write_text("not json")
    rc, out, _ = program(tmp_path, HEALTHY, UNITS, "--state", str(state))
    assert (rc, "could not read" in out, state.read_text()) == (2, True, "not json"), out
