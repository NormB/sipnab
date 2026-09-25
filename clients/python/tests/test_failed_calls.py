"""Failed calls grouped by their final response code, and the calls that
answered and were never acknowledged.

Recipe 3's shell histogram counts every response inside a failed call, so a
`100 Trying` before the `486` is counted too. This groups each failed call
once, under its final code, and names the calls in each group. A missing
`ACK` never makes a call fail, so it is read from the capture's findings
rather than from the grouping.
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


fc = _load("failed_calls")

AGGREGATE = {
    "group_by": "response_code",
    "buckets": [{"value": "486", "count": 2}, {"value": "603", "count": 1}],
    "other_count": 0,
    "total_matched": 3,
}

NO_ACK = {
    "kind": "ack_missing",
    "severity": "major",
    "occurrences": 1,
    "unit": "call",
    "evidence": [
        {
            "call_id": "noack-5d4c3b@192.0.2.70",
            "counts": {"answer_transmissions": 11},
            "note": "31.5s elapsed with no ACK",
        }
    ],
    "evidence_omitted": 0,
}


def test_each_code_is_one_group_naming_its_calls():
    calls = {"486": (["a@x", "b@x"], 2), "603": (["c@x"], 1)}
    lines = fc.render(AGGREGATE, calls, {"findings": []})
    assert lines[:6] == [
        "3 failed call(s), by final response code:",
        "  486  2 call(s)",
        "    a@x",
        "    b@x",
        "  603  1 call(s)",
        "    c@x",
    ]


def test_a_group_larger_than_the_page_says_how_many_it_did_not_list():
    calls = {"486": (["a@x"], 2), "603": (["c@x"], 1)}
    lines = fc.render(AGGREGATE, calls, {"findings": []})
    assert "    ... and 1 more" in lines


def test_buckets_folded_past_top_n_are_reported_not_dropped():
    agg = dict(AGGREGATE, other_count=4, total_matched=7)
    lines = fc.render(agg, {"486": (["a@x", "b@x"], 2), "603": (["c@x"], 1)}, {"findings": []})
    assert "  other codes  4 call(s)" in lines


def test_an_answered_call_never_acknowledged_is_named_with_its_wait():
    lines = fc.render(AGGREGATE, {"486": ([], 2), "603": ([], 1)}, {"findings": [NO_ACK]})
    assert lines[-2:] == [
        "1 call(s) answered and never acknowledged:",
        "  noack-5d4c3b@192.0.2.70  31.5s elapsed with no ACK, answer sent 11 time(s)",
    ]


def test_no_missing_ack_says_what_the_silence_depends_on():
    lines = fc.render(AGGREGATE, {"486": ([], 2), "603": ([], 1)}, {"findings": []})
    assert lines[-1] == (
        "0 call(s) answered and never acknowledged "
        "(a call counts once its answer has waited sipnab's --ack-timeout)"
    )


def test_no_failed_call_is_said_rather_than_printed_as_an_empty_table():
    empty = {"group_by": "response_code", "buckets": [], "other_count": 0, "total_matched": 0}
    lines = fc.render(empty, {}, {"findings": []})
    assert lines[0] == "0 failed call(s)"
