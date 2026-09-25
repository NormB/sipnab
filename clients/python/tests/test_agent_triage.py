"""The agent triage: two MCP answers about one capture, read as one verdict.

`get_capture_report` says what is wrong and `list_dialogs` says what is
there. An agent that reads only the first cannot tell a clean capture from a
report that missed a failed call, and one that reads only the second counts
failures with no reason attached. The verdict is triage.py's, so the two
programs cannot disagree about one capture; what this adds is the check that
the two answers describe the same capture, and the calls to look at next.
"""

import asyncio
import importlib.util
import pathlib
import sys

CLIENTS = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(CLIENTS))


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, CLIENTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


at = _load("agent_triage")


def report(findings=(), dialogs=5, **extra) -> dict:
    out = {
        "schema_version": 1,
        "frames_read": 23,
        "dialogs_examined": dialogs,
        "streams_examined": 0,
        "complete": True,
        "findings": list(findings),
    }
    out.update(extra)
    return out


def finding(kind, severity, *evidence, omitted=0) -> dict:
    return {
        "kind": kind,
        "severity": severity,
        "unit": "call",
        "occurrences": len(evidence) + omitted,
        "evidence": [{"call_id": c, "note": n} for c, n in evidence],
        "evidence_omitted": omitted,
    }


BUSY = finding("request_failure", "minor", ("busy@x", "Busy Here"))
ROWS = [
    {"call_id": "ok@x", "state": "Completed"},
    {"call_id": "busy@x", "state": "Failed"},
]


def test_a_named_failure_is_a_problem_with_the_call_to_look_at_next():
    result, lines = at.agent_verdict(ROWS, 2, report([BUSY], dialogs=2))
    assert result == "problems"
    assert lines == [
        "problems: 23 frame(s), 2 dialog(s), 0 stream(s)",
        "  minor  request_failure  1 call(s)",
        "    busy@x  Busy Here",
        "summary: 2 dialog(s) listed: 1 Completed, 1 Failed",
        "next: triage_call busy@x",
    ]


def test_states_are_counted_largest_first_then_by_name():
    rows = [{"call_id": f"f{i}", "state": "Failed"} for i in range(3)] + ROWS[:1]
    _, lines = at.agent_verdict(rows, 4, report([], dialogs=4))
    assert "summary: 4 dialog(s) listed: 3 Failed, 1 Completed" in lines


def test_a_failed_call_no_finding_names_turns_clean_into_inconclusive():
    # The report says clean and the listing holds a failure: one of the two
    # answers is wrong, and "clean" would be the agent picking one.
    result, lines = at.agent_verdict(ROWS, 2, report([], dialogs=2))
    assert result == "inconclusive"
    assert "unexplained: busy@x is Failed and no finding names it" in lines


def test_evidence_the_report_omitted_is_not_called_unexplained():
    # With evidence_omitted > 0 the report counted calls it did not name, so
    # a Failed row it does not name may be one of them.
    other = finding("server_failure", "major", ("x@x", "Decline"), omitted=1)
    rows = ROWS + [{"call_id": "x@x", "state": "Failed"}]
    result, lines = at.agent_verdict(rows, 3, report([other], dialogs=3))
    assert result == "problems"
    assert not [line for line in lines if line.startswith("unexplained:")]


def test_answers_about_different_captures_are_inconclusive():
    result, lines = at.agent_verdict(ROWS, 2, report([BUSY], dialogs=5))
    assert result == "inconclusive"
    assert lines[0] == (
        "inconclusive: get_capture_report examined 5 dialog(s) and list_dialogs "
        "holds 2, so the two answers are not about one capture"
    )


def test_a_listing_that_lost_rows_while_paging_is_inconclusive():
    result, lines = at.agent_verdict(ROWS[:1], 2, report([], dialogs=2))
    assert result == "inconclusive"
    assert lines[0] == "inconclusive: list_dialogs reported 2 dialog(s) and paging returned 1"


def test_an_empty_capture_stays_inconclusive_as_triage_says():
    result, lines = at.agent_verdict([], 0, report([], dialogs=0, frames_read=10))
    assert result == "inconclusive"
    assert lines[-1] == "summary: no dialog listed"


def test_the_exit_status_is_triage_exit_status():
    # The module agent_triage imported, not sys.modules["triage"]: another
    # test file loads its own copy of triage.py under that name.
    assert at.EXIT is at.triage.EXIT
    assert at.EXIT == {"clean": 0, "problems": 1, "inconclusive": 2}


class FakeCall:
    """A tool caller answering from a script, recording what it was asked."""

    def __init__(self, answers: dict):
        self.answers = {k: list(v) for k, v in answers.items()}
        self.asked = []

    async def __call__(self, name, arguments):
        self.asked.append((name, arguments))
        return self.answers[name].pop(0)


def test_dialogs_are_paged_with_the_cursor_until_there_is_none():
    call = FakeCall(
        {
            "list_dialogs": [
                {"dialogs": ROWS[:1], "total_matched": 2, "next_cursor": "c1"},
                {"dialogs": ROWS[1:], "total_matched": 2, "next_cursor": None},
            ]
        }
    )
    rows, total = asyncio.run(at.all_dialogs(call, page=1))
    assert (rows, total) == (ROWS, 2)
    assert call.asked[1][1]["cursor"] == "c1"
    assert call.asked[0][1]["limit"] == 1


def test_a_cursor_with_an_empty_page_stops_rather_than_spinning():
    call = FakeCall(
        {"list_dialogs": [{"dialogs": [], "total_matched": 2, "next_cursor": "c1"}]}
    )
    rows, total = asyncio.run(at.all_dialogs(call, page=1))
    assert (rows, total) == ([], 2)
