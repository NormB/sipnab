"""An aggregate cut to a byte budget before it reaches a model.

sipnab bounds the NUMBER of buckets (`--mcp-max-rows`) and the length of
each capture-derived value (256 bytes, then a marker), never the answer as a
whole: which budget applies is a property of the model reading it. The cut
happens here, and it drops whole buckets into `other_count`, never part of
a string, so the result is valid JSON under every budget and its counts
still add up to `total_matched`.
"""

import importlib.util
import json
import pathlib
import sys

import pytest

CLIENTS = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(CLIENTS))


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, CLIENTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


ag = _load("aggregate_for_model")

FENCE = "⟦untrusted-capture-data⟧"


def answer(*counts, other=0, value=lambda i: f"v{i}") -> dict:
    buckets = [{"value": value(i), "count": c} for i, c in enumerate(counts)]
    return {
        "group_by": "ua",
        "buckets": buckets,
        "other_count": other,
        "distinct_values": len(counts) + (1 if other else 0),
        "total_matched": sum(counts) + other,
    }


def size(text: str) -> int:
    return len(text.encode("utf-8"))


def test_an_answer_within_the_budget_is_passed_whole():
    text, omitted = ag.bound(answer(3, 2, 1), "state == 'Failed'", 10_000)
    doc = json.loads(text)
    assert omitted == 0
    assert [b["count"] for b in doc["buckets"]] == [3, 2, 1]
    assert doc["filter"] == "state == 'Failed'"
    assert doc["omitted_buckets"] == 0


def test_the_smallest_buckets_go_into_other_count_and_the_total_holds():
    full, _ = ag.bound(answer(5, 4, 3, 2, 1), None, 10_000)
    text, omitted = ag.bound(answer(5, 4, 3, 2, 1), None, size(full) - 1)
    doc = json.loads(text)
    assert omitted >= 1
    assert sum(b["count"] for b in doc["buckets"]) + doc["other_count"] == doc["total_matched"] == 15
    assert doc["omitted_buckets"] == omitted
    assert [b["count"] for b in doc["buckets"]] == [5, 4, 3, 2, 1][: 5 - omitted]


@pytest.mark.parametrize("budget", range(150, 400, 7))
def test_every_budget_gives_valid_json_within_it_keeping_all_it_can(budget):
    a = answer(9, 8, 7, 6, 5, 4, value=lambda i: FENCE + "x" * (10 * i) + FENCE)
    text, omitted = ag.bound(a, "method == 'INVITE'", budget)
    assert size(text) <= budget
    json.loads(text)
    if omitted:
        # One more bucket would not have fit: the cut is the smallest one.
        kept = 6 - omitted
        wider, _ = ag.bound(a, "method == 'INVITE'", 10_000)
        doc = json.loads(wider)
        doc["buckets"] = doc["buckets"][: kept + 1]
        doc["other_count"] = sum([9, 8, 7, 6, 5, 4][kept + 1 :])
        doc["omitted_buckets"] = omitted - 1
        assert size(ag.encode(doc)) > budget


def test_the_budget_is_bytes_not_characters():
    # A fence character is one character and three bytes: a character count
    # would let a fenced answer through at nearly three times its budget.
    a = answer(1, value=lambda i: FENCE * 20)
    text, _ = ag.bound(a, None, 10_000)
    assert size(text) > len(text)
    # A budget of the answer's length in characters fits it by characters
    # and not by bytes, so the one bucket must go.
    tight, omitted = ag.bound(a, None, len(text))
    assert omitted == 1 and size(tight) <= len(text)


def test_a_budget_too_small_for_the_frame_is_refused_by_name():
    with pytest.raises(ValueError, match=r"is \d+ byte\(s\) with no bucket at all, over the 20-byte budget"):
        ag.bound(answer(1), None, 20)


def test_buckets_that_do_not_add_up_are_refused_rather_than_passed_on():
    bad = answer(3, 2)
    bad["total_matched"] = 9
    with pytest.raises(ValueError, match="do not add up"):
        ag.bound(bad, None, 10_000)
