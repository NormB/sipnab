# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""Which runners the `features` job of ci.yml asks for.

The job ran on `[self-hosted, overflow]` for every event. Two runners carry
that label, each group builds every combination from nothing, and on
2026-11-11 the run for a push to main (run 42977445618) had its two groups
queued for 34 and 68 minutes behind pull request and Dependabot runs.

`runner_labels` in scripts/check-feature-matrix.py is the rule: a push to
main asks for every aarch64 runner on the host, anything else for the
overflow pair. `runs_on_expression` renders that rule as the GitHub
expression the workflow carries, and these tests hold the workflow to it by
evaluating the expression the workflow actually has.
"""
import json
import pathlib
import re

import pytest
from conftest import load

REPO = pathlib.Path(__file__).resolve().parent.parent.parent
CI = REPO / ".github/workflows/ci.yml"

fm = load("check-feature-matrix")

MAIN = ["self-hosted", "jetson"]
OVERFLOW = ["self-hosted", "overflow"]

EXPRESSION = re.compile(
    r"^\$\{\{ github\.event_name == '([^']*)' && github\.ref == '([^']*)' "
    r"&& fromJSON\('(\[[^']*\])'\) \|\| fromJSON\('(\[[^']*\])'\) \}\}$"
)


def evaluate(expression, event_name, ref):
    """What GitHub makes of `A == 'x' && B == 'y' && fromJSON(T) || fromJSON(E)`.

    GitHub compares strings without regard to case, and an empty array is
    false, so an empty T falls through to E.
    """
    m = EXPRESSION.match(expression)
    assert m, f"not the shape runs_on_expression renders: {expression}"
    event, wanted_ref, then, otherwise = m.groups()
    then, otherwise = json.loads(then), json.loads(otherwise)
    hit = event_name.casefold() == event.casefold() and ref.casefold() == wanted_ref.casefold()
    return then if hit and then else otherwise


def workflow_runs_on():
    job = CI.read_text().split("\n  features:\n", 1)[1]
    job = re.split(r"\n  [a-z0-9_-]+:\n", job, maxsplit=1)[0]
    lines = re.findall(r"(?m)^    runs-on: (.*)$", job)
    assert len(lines) == 1, f"the features job has {len(lines)} runs-on lines"
    return lines[0]


# -- The rule: success ------------------------------------------------------

@pytest.mark.parametrize("event_name,ref", [
    ("push", "refs/heads/main"),
    ("PUSH", "refs/heads/main"),
    ("push", "refs/heads/MAIN"),
    ("Push", "Refs/Heads/Main"),
])
def test_a_push_to_main_asks_for_every_aarch64_runner(event_name, ref):
    assert fm.runner_labels(event_name, ref) == MAIN, (event_name, ref)


@pytest.mark.parametrize("event_name,ref", [
    ("pull_request", "refs/pull/754/merge"),
    ("pull_request", "refs/pull/1/merge"),
    ("pull_request", "refs/pull/755/head"),
    ("pull_request_target", "refs/heads/main"),
    ("merge_group", "refs/heads/gh-readonly-queue/main/pr-1-abc"),
    ("workflow_dispatch", "refs/heads/main"),
    ("schedule", "refs/heads/main"),
    ("push", "refs/heads/ci/runner-listeners"),
    ("push", "refs/heads/dependabot/cargo/bpf/aya-ebpf-0.3.0"),
    ("push", "refs/tags/v0.5.246"),
])
def test_anything_else_asks_for_the_overflow_pair(event_name, ref):
    assert fm.runner_labels(event_name, ref) == OVERFLOW, (event_name, ref)


def test_the_two_answers_are_different_lists():
    assert fm.MAIN_RUNNER != fm.OVERFLOW_RUNNER, "main would wait in the queue it waits in today"
    assert fm.MAIN_RUNNER == MAIN and fm.OVERFLOW_RUNNER == OVERFLOW, (fm.MAIN_RUNNER, fm.OVERFLOW_RUNNER)


def test_the_rule_returns_a_copy_a_caller_cannot_change():
    fm.runner_labels("push", "refs/heads/main").append("x")
    fm.runner_labels("pull_request", "refs/pull/1/merge").append("x")
    assert fm.runner_labels("push", "refs/heads/main") == MAIN, "the main list was changed by a caller"
    assert fm.runner_labels("pull_request", "refs/pull/1/merge") == OVERFLOW, "the overflow list was changed"


# -- The rule: what is NOT main ---------------------------------------------

@pytest.mark.parametrize("event_name,ref", [
    ("push", "refs/heads/main2"),
    ("push", "refs/heads/mai"),
    ("push", "refs/heads/main/x"),
    ("push", "refs/heads/x/main"),
    ("push", "main"),
    ("push", "heads/main"),
    ("push", "refs/tags/main"),
    ("push", "refs/remotes/origin/main"),
    ("push", " refs/heads/main"),
    ("push", "refs/heads/main "),
    ("push", "refs/heads/main\n"),
    ("push", ""),
    ("", "refs/heads/main"),
    ("", ""),
    ("pushed", "refs/heads/main"),
    ("pus", "refs/heads/main"),
    (" push", "refs/heads/main"),
    ("push ", "refs/heads/main"),
    ("refs/heads/main", "push"),
])
def test_a_near_miss_is_not_a_push_to_main(event_name, ref):
    assert fm.runner_labels(event_name, ref) == OVERFLOW, (event_name, ref)


@pytest.mark.parametrize("event_name,ref", [
    (None, "refs/heads/main"),
    ("push", None),
    (1, "refs/heads/main"),
    ("push", ["refs/heads/main"]),
])
def test_a_value_that_is_not_text_is_refused(event_name, ref):
    with pytest.raises(TypeError):
        fm.runner_labels(event_name, ref)


# -- The expression the workflow carries ------------------------------------

def test_the_expression_has_the_shape_these_tests_evaluate():
    assert EXPRESSION.match(fm.runs_on_expression()), fm.runs_on_expression()


def test_the_workflow_carries_the_rendered_expression():
    assert workflow_runs_on() == fm.runs_on_expression(), (
        "ci.yml's features job does not ask for the runners runner_labels gives; "
        "its runs-on line is: " + workflow_runs_on()
    )


CASES = [
    ("push", "refs/heads/main"),
    ("PUSH", "refs/heads/MAIN"),
    ("pull_request", "refs/pull/754/merge"),
    ("pull_request", "refs/heads/main"),
    ("push", "refs/heads/other"),
    ("push", "refs/tags/v0.5.246"),
    ("push", "refs/heads/main2"),
    ("workflow_dispatch", "refs/heads/main"),
    ("schedule", "refs/heads/main"),
    ("merge_group", "refs/heads/main"),
    ("", ""),
    ("push", ""),
]


@pytest.mark.parametrize("event_name,ref", CASES)
def test_the_workflows_expression_gives_what_the_rule_gives(event_name, ref):
    assert evaluate(workflow_runs_on(), event_name, ref) == fm.runner_labels(event_name, ref), (event_name, ref)


@pytest.mark.parametrize("event_name,ref", CASES)
def test_the_rendered_expression_gives_what_the_rule_gives(event_name, ref):
    assert evaluate(fm.runs_on_expression(), event_name, ref) == fm.runner_labels(event_name, ref), (event_name, ref)


def test_an_expression_with_an_empty_main_list_would_fall_through():
    """Why the main list must not be empty: `&& [] || X` is X for every event."""
    broken = fm.runs_on_expression().replace(json.dumps(MAIN, separators=(",", ":")), "[]")
    assert broken != fm.runs_on_expression(), "the main list is not in the expression as compact JSON"
    assert evaluate(broken, "push", "refs/heads/main") == OVERFLOW
    assert fm.MAIN_RUNNER, "an empty main list makes the expression choose overflow for main"


def test_the_expression_is_one_plain_yaml_scalar():
    """It sits on a YAML line after `runs-on: `, unquoted.

    A plain scalar ends at `: ` or ` #` and cannot span lines, and one that
    starts with a quote or a bracket is not plain.
    """
    e = fm.runs_on_expression()
    assert e.startswith("${{ ") and e.endswith(" }}"), e
    assert "\n" not in e and ": " not in e and " #" not in e, e


def test_every_label_is_a_plain_word():
    for label in fm.MAIN_RUNNER + fm.OVERFLOW_RUNNER:
        assert re.fullmatch(r"[A-Za-z0-9_-]+", label), f"{label!r} would need quoting inside fromJSON('...')"
    assert fm.MAIN_RUNNER[0] == "self-hosted" and fm.OVERFLOW_RUNNER[0] == "self-hosted", (
        "a list without self-hosted could be matched by a hosted runner label"
    )


def test_the_job_still_passes_the_overflow_pool_to_the_script():
    """The pool names what the machine can run, and all four runners are one host."""
    job = CI.read_text().split("\n  features:\n", 1)[1]
    assert "--pool overflow" in job.split("\n  crate-package:\n", 1)[0], "the features job no longer names its pool"


def test_no_other_job_in_any_workflow_asks_for_the_overflow_label_directly():
    """One place decides who uses the overflow pair: the features job's expression."""
    found = []
    for wf in sorted((REPO / ".github/workflows").glob("*.yml")):
        for n, line in enumerate(wf.read_text().splitlines(), 1):
            if re.match(r"\s*runs-on:.*\boverflow\b", line):
                found.append(f"{wf.name}:{n}")
    assert len(found) == 1 and found[0].startswith("ci.yml:"), found


def test_the_evaluator_refuses_an_expression_of_another_shape():
    with pytest.raises(AssertionError):
        evaluate("${{ github.ref == 'refs/heads/main' && 'a' || 'b' }}", "push", "refs/heads/main")
    with pytest.raises(AssertionError):
        evaluate("[self-hosted, overflow]", "push", "refs/heads/main")
