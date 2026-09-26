# SPDX-License-Identifier: MIT OR Apache-2.0
"""The cookbook output gate in scripts/check-cookbook.py.

Every cookbook command the checker EXECUTES must have its output pinned by a
trycmd golden under tests/cli/cookbook/, or be named in OUTPUT_UNPINNED with
the reason it cannot be. These drive the pure pieces of that rule: the
command -> golden spelling, the `$` line round trip, and the comparison that
decides what is missing, stale or exempt.
"""

from pathlib import Path

from conftest import load

cc = load("check-cookbook")

CALL_IDS = ["1-1966@10.0.2.20", "1-1968@10.0.2.20"]


def golden(argv):
    return cc.golden_case(argv, CALL_IDS)


# ---- the golden spelling ---------------------------------------------------


def test_the_capture_placeholder_becomes_the_repo_relative_fixture():
    _key, argv = golden(["-N", "-I", "capture.pcap", "--report"])
    assert argv == ["-N", "-I", cc.GOLDEN_FIXTURE, "--report"]
    assert cc.GOLDEN_FIXTURE == "tests/pcap-samples/sip-rtp-g711.pcap"


def test_a_placeholder_call_id_becomes_the_fixtures_first_call_id():
    _key, argv = golden(["-N", "-I", "x.pcap", "--call-report", "abc123@host"])
    assert argv[-1] == CALL_IDS[0]


def test_every_output_path_lands_in_the_cases_own_directory():
    key, argv = golden(
        [
            "-N", "-I", "capture.pcap",
            "--export-vcon-dir", "./out",
            "--redact-map", "./redact-map.json",
            "-O", "one.pcap",
            "--run-provenance-file", "runs.jsonl",
        ]
    )
    assert argv[argv.index("--export-vcon-dir") + 1] == f"{key}/out"
    assert argv[argv.index("--redact-map") + 1] == f"{key}/redact-map.json"
    assert argv[argv.index("-O") + 1] == f"{key}/one.pcap"
    assert argv[argv.index("--run-provenance-file") + 1] == f"{key}/runs.jsonl"


def test_evidence_to_stdout_is_not_redirected():
    _key, argv = golden(["-N", "-I", "c.pcap", "--evidence-out", "-"])
    assert argv[-1] == "-"


def test_the_key_is_stable_and_distinguishes_commands():
    a1, _ = golden(["-N", "-I", "capture.pcap", "--report"])
    a2, _ = golden(["-N", "-I", "other.pcap", "--report"])
    b, _ = golden(["-N", "-I", "capture.pcap", "--json"])
    assert a1 == a2, "two placeholder names for the same fixture are one case"
    assert a1 != b


def test_the_run_mode_and_the_golden_share_one_substitution():
    # RUN mode is the same function with the absolute fixture and a temp dir.
    subbed, replaced = cc.substitute(
        ["-I", "c.pcap", "--export-vcon-dir", "./out"],
        fixture="/abs/f.pcap", outdir=Path("/tmp/x"), call_ids=CALL_IDS,
    )
    assert replaced
    assert subbed == ["-I", "/abs/f.pcap", "--export-vcon-dir", "/tmp/x/out"]


# ---- the `$` line round trip -------------------------------------------------


def test_a_rendered_command_parses_back_to_the_same_argv():
    argv = [
        "-N", "-I", "f.pcap",
        "--filter", "state == 'Failed'",
        "--tshark-filter", 'sip.Method == "INVITE"',
        "-e", "INVITE",
        "--both", "it's \"mixed\"",
    ]
    line = cc.render_command(argv)
    assert line.startswith("sipnab ")
    assert cc.parse_golden_text(f"```\n$ {line}\n```\n") == [argv]


def test_a_quote_free_filter_reads_the_way_the_cookbook_writes_it():
    line = cc.render_command(["--filter", "state == 'Failed'"])
    assert line == "sipnab --filter \"state == 'Failed'\""


def test_a_golden_parser_sees_every_command_in_a_file():
    text = "```\n$ sipnab -N\nout\n$ sipnab --json\n? 1\n```\n"
    assert cc.parse_golden_text(text) == [["-N"], ["--json"]]


# ---- the comparison --------------------------------------------------------


def ex(inv, argv):
    return cc.Executed(recipe="r", inv=inv, argv=tuple(argv))


def test_an_executed_command_with_no_golden_is_missing():
    gaps = cc.golden_gaps([ex("sipnab -N -I c.pcap", ["-N"])], goldens={}, unpinned={})
    assert [e.inv for e in gaps.missing] == ["sipnab -N -I c.pcap"]
    assert gaps.pinned == 0


def test_a_golden_covers_every_occurrence_of_its_command():
    runs = [ex("sipnab a", ["-N"]), ex("sipnab b", ["-N"])]
    gaps = cc.golden_gaps(runs, goldens={("-N",): Path("k.trycmd")}, unpinned={})
    assert gaps.missing == [] and gaps.stale == []
    assert gaps.pinned == 1, "one distinct command, one golden"


def test_a_golden_no_executed_command_produces_is_stale():
    gaps = cc.golden_gaps([], goldens={("--gone",): Path("old.trycmd")}, unpinned={})
    assert gaps.stale == [Path("old.trycmd")]


def test_a_reason_exempts_the_command_it_names():
    runs = [ex("sipnab -N --fail2ban", ["-N", "--fail2ban"])]
    gaps = cc.golden_gaps(runs, goldens={}, unpinned={"--fail2ban": "syslog date"})
    assert gaps.missing == []
    assert [(e.inv, r) for e, r in gaps.exempt] == [("sipnab -N --fail2ban", "syslog date")]


def test_a_reason_that_exempts_nothing_is_reported():
    gaps = cc.golden_gaps([], goldens={}, unpinned={"--gone": "a reason"})
    assert gaps.unused_reasons == ["--gone"]


def test_a_reason_beside_a_golden_is_reported_as_contradictory():
    runs = [ex("sipnab -N --x", ["-N", "--x"])]
    gaps = cc.golden_gaps(
        runs, goldens={("-N", "--x"): Path("k.trycmd")}, unpinned={"--x": "why"}
    )
    assert gaps.contradictory == ["--x"]


# ── TUI commands with no terminal (TTY-EXIT-1) ───────────────────────────

REFUSAL = (
    "sipnab: the terminal UI could not start: No such device or address "
    "(os error 6). It needs a terminal; add -N for a run without one."
)


def test_a_tui_command_that_reached_the_tui_and_was_refused_counts_as_run():
    # With no terminal the TUI refuses and sipnab exits 1. For a command the
    # table already says opens the TUI, that refusal proves the arguments
    # parsed and the capture opened: everything up to the terminal worked.
    assert cc.reached_the_tui("sipnab -I capture.pcap", 1, REFUSAL)


def test_a_tui_command_that_failed_for_another_reason_still_fails():
    assert not cc.reached_the_tui(
        "sipnab -I capture.pcap", 2, "error: unexpected argument '--bogus'"
    )
    assert not cc.reached_the_tui("sipnab -I capture.pcap", 1, "Error: cannot open capture")


def test_the_refusal_does_not_excuse_a_command_the_table_does_not_name():
    # A -N command that somehow reached the TUI is a defect, not a pass.
    assert not cc.reached_the_tui("sipnab -N -I capture.pcap --report", 1, REFUSAL)


def test_exit_zero_is_not_how_a_tui_command_passes_any_more():
    # Before the fix the TUI exited 0 having drawn nothing; the checker read
    # that as success. Only the explicit refusal counts now.
    assert not cc.reached_the_tui("sipnab -I capture.pcap", 0, "")
