# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors
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


def test_a_vcon_placeholder_becomes_the_committed_container():
    _key, argv = golden(["-N", "-I", "call.vcon.json", "--analyze"])
    assert argv == ["-N", "-I", cc.GOLDEN_VCON_FIXTURE, "--analyze"]
    assert cc.GOLDEN_VCON_FIXTURE == "tests/fixtures/vcon/sip-rtp-g711-1966.vcon.json"
    assert (cc.REPO / cc.GOLDEN_VCON_FIXTURE).is_file()


def test_the_run_mode_reads_the_container_by_its_absolute_path():
    subbed, replaced = cc.substitute(
        ["-I", "call.vcon.json", "--analyze"],
        fixture="/abs/f.pcap", outdir=Path("/tmp/x"), call_ids=CALL_IDS,
        vcon_fixture="/abs/c.vcon.json",
    )
    assert replaced
    assert subbed == ["-I", "/abs/c.vcon.json", "--analyze"]


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


# ── Flags that imply -N (the CLI's own list) ─────────────────────────────
#
# Owed: the checker took any command without -N for a TUI command, so a
# recipe such as `sipnab -I capture.pcap --count-by method` -- headless,
# because --count-by implies -N -- would have been excused from its golden
# and its refusal to start a TUI accepted as a pass. The rule now reads the
# CLI's list of implying flags from .config/implies-no-tui.txt.


def test_a_query_flag_without_n_does_not_open_the_tui():
    assert not cc.opens_the_tui(["-I", "capture.pcap", "--count-by", "method"])


def test_every_listed_implying_flag_is_headless_without_n():
    assert cc.IMPLIES_NO_TUI, "the implies-N list is empty"
    for flag, unless in cc.IMPLIES_NO_TUI:
        assert not cc.opens_the_tui(["-I", "capture.pcap", flag, "x"]), flag


def test_a_bare_capture_or_a_non_implying_flag_opens_the_tui():
    assert cc.opens_the_tui(["-I", "capture.pcap"])
    assert cc.opens_the_tui(["-I", "encrypted.pcap", "--keylog", "k.log"])


def test_n_or_no_tui_never_opens_the_tui():
    assert not cc.opens_the_tui(["-N", "-I", "capture.pcap"])
    assert not cc.opens_the_tui(["--no-tui", "-I", "capture.pcap"])


def test_an_implying_flag_given_with_equals_is_headless():
    assert not cc.opens_the_tui(["-I", "capture.pcap", "--count-by=method"])


def test_mcp_over_http_is_the_listed_exception():
    implies = cc.read_implies_no_tui("--mcp unless --mcp-transport http\n")
    assert implies == [("--mcp", ("--mcp-transport", "http"))]
    assert not cc.opens_the_tui(["-I", "c.pcap", "--mcp"], implies)
    assert not cc.opens_the_tui(["--mcp", "--mcp-transport", "stdio"], implies)
    assert cc.opens_the_tui(["--mcp", "--mcp-transport", "http"], implies)
    assert cc.opens_the_tui(["--mcp", "--mcp-transport=http"], implies)


def test_the_listing_parser_skips_comments_and_blanks():
    text = "# header\n\n--count-by\n  --talkers  \n# --not-a-flag\n"
    assert cc.read_implies_no_tui(text) == [("--count-by", None), ("--talkers", None)]


def test_the_cli_list_names_the_query_family():
    names = {flag for flag, _ in cc.IMPLIES_NO_TUI}
    for flag in ("--count-by", "--timeline", "--talkers", "--call-report", "--export-vcon"):
        assert flag in names, flag


def test_a_headless_query_refused_by_a_tui_is_not_excused():
    # A command that implies -N and still printed the TUI refusal is a defect.
    assert not cc.reached_the_tui("sipnab -I capture.pcap --count-by method", 1, REFUSAL)


def test_a_headless_query_without_a_golden_is_missing_not_exempt():
    runs = [ex("sipnab -I capture.pcap --count-by method",
               ["-I", cc.GOLDEN_FIXTURE, "--count-by", "method"])]
    gaps = cc.golden_gaps(runs, goldens={}, unpinned=cc.OUTPUT_UNPINNED)
    assert [e.inv for e in gaps.missing] == ["sipnab -I capture.pcap --count-by method"]
    assert gaps.exempt == []


def test_a_tui_command_is_exempt_by_the_rule_not_by_a_table_entry():
    runs = [ex("sipnab -I capture.pcap", ["-I", cc.GOLDEN_FIXTURE])]
    gaps = cc.golden_gaps(runs, goldens={}, unpinned={})
    assert gaps.missing == []
    assert [e.inv for e, _ in gaps.exempt] == ["sipnab -I capture.pcap"]
