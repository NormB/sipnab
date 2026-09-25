"""The triage program: one capture in, one machine verdict out.

The verdict has three values because a capture has three answers, and the
third is the one a pipeline most needs kept apart: "clean" and "nothing was
there to judge" print the same empty findings list.
"""

import importlib.util
import pathlib
import sys

CLIENTS = pathlib.Path(__file__).resolve().parent.parent


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, CLIENTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


tr = _load("triage")


def analysis(**extra) -> dict:
    out = {
        "schema_version": 1,
        "frames_read": 23,
        "dialogs_examined": 5,
        "streams_examined": 0,
        "complete": True,
        "findings": [],
    }
    out.update(extra)
    return out


BUSY = {
    "kind": "request_failure",
    "severity": "minor",
    "occurrences": 1,
    "unit": "call",
    "evidence": [
        {
            "call_id": "busy-3a2b1c@192.0.2.30",
            "endpoints": ["192.0.2.30:5060 -> 192.0.2.40"],
            "counts": {"status_code": 486},
            "note": "Busy Here",
        }
    ],
    "evidence_omitted": 0,
}


def test_a_capture_with_dialogs_and_no_findings_is_clean():
    verdict, lines = tr.verdict(analysis())
    assert verdict == "clean"
    assert lines == ["clean: 23 frame(s), 5 dialog(s), 0 stream(s)"]
    assert tr.EXIT[verdict] == 0


def test_findings_are_problems_and_each_names_its_evidence():
    verdict, lines = tr.verdict(analysis(findings=[BUSY]))
    assert verdict == "problems"
    assert tr.EXIT[verdict] == 1
    assert lines == [
        "problems: 23 frame(s), 5 dialog(s), 0 stream(s)",
        "  minor  request_failure  1 call(s)",
        "    busy-3a2b1c@192.0.2.30  Busy Here",
    ]


def test_evidence_with_no_call_or_note_falls_back_to_endpoints_and_counts():
    blind = {
        "kind": "sip_discarded_by_portrange",
        "severity": "blind",
        "occurrences": 10,
        "unit": "message",
        "evidence": [{"endpoints": ["port 5080"], "counts": {"messages": 10}}],
        "evidence_omitted": 3,
    }
    _, lines = tr.verdict(analysis(complete=False, findings=[blind]))
    assert "    port 5080  messages=10" in lines
    assert "    ... and 3 more" in lines


def test_a_capture_with_nothing_to_examine_is_inconclusive_not_clean():
    verdict, lines = tr.verdict(analysis(frames_read=43, dialogs_examined=0))
    assert verdict == "inconclusive"
    assert tr.EXIT[verdict] == 2
    assert lines[0] == (
        "inconclusive: 43 frame(s) and no SIP dialog or RTP stream to judge, "
        "so an empty finding list proves nothing"
    )


def test_an_incomplete_analysis_is_inconclusive_even_with_findings():
    verdict, lines = tr.verdict(analysis(complete=False, findings=[BUSY]))
    assert verdict == "inconclusive"
    assert lines[0] == (
        "inconclusive: sipnab did not analyze all of the capture "
        "(23 frame(s), 5 dialog(s), 0 stream(s))"
    )
    assert "  minor  request_failure  1 call(s)" in lines


def test_a_capture_with_only_media_findings_is_still_judged():
    ice = dict(BUSY, kind="ice_role_conflict", unit="pair", evidence=[])
    verdict, _ = tr.verdict(analysis(dialogs_examined=0, findings=[ice]))
    assert verdict == "problems"
