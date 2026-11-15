# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""Which runners the `features` job of ci.yml asks for.

The job ran on `[self-hosted, overflow]` for every event. Two runners carry
that label, each group builds every combination from nothing, and on
2026-11-11 the run for a push to main (run 42977445618) had its two groups
queued for 34 and 68 minutes behind pull request and Dependabot runs.

`runner_labels` in scripts/check-feature-matrix.py is the rule: a push to
main asks for every aarch64 runner on the host, and so does a pull request
from a `release/` branch of this repository; anything else asks for the
overflow pair. `runs_on_expression` renders that rule as the GitHub
expression the workflow carries, and these tests hold the workflow to it by
evaluating the expression the workflow actually has.

The release pull request was added on 2026-11-15: release PR #808's two
Features jobs queued from 2026-11-14 23:15Z while another pull request's job
held one of the overflow pair (backlog OVERFLOW-RUNNERS-HAVE-NO-RELEASE-
PRIORITY). The four runners are capacity, not priority: GitHub documents no
order among queued jobs for self-hosted runners.
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
HERE = "NormB/sipnab"

EXPRESSION = re.compile(
    r"^\$\{\{ \(github\.event_name == '([^']*)' && github\.ref == '([^']*)' "
    r"\|\| github\.event_name == '([^']*)' && startsWith\(github\.head_ref, '([^']*)'\) "
    r"&& github\.event\.pull_request\.head\.repo\.full_name == github\.repository\) "
    r"&& fromJSON\('(\[[^']*\])'\) \|\| fromJSON\('(\[[^']*\])'\) \}\}$"
)


def evaluate(expression, event_name, ref, head_ref="", head_repo=None, repository=HERE):
    """What GitHub makes of
    `(A == 'x' && B == 'y' || C == 'z' && startsWith(D, 'p') && E == F) && fromJSON(T) || fromJSON(E)`.

    `&&` binds tighter than `||`. GitHub compares strings and `startsWith`
    without regard to case, a missing value (`head.repo` of a deleted fork,
    or of an event that is not a pull request) equals no string, and an empty
    array is false, so an empty T falls through to E.
    """
    m = EXPRESSION.match(expression)
    assert m, f"not the shape runs_on_expression renders: {expression}"
    event, wanted_ref, pull_event, prefix, then, otherwise = m.groups()
    then, otherwise = json.loads(then), json.loads(otherwise)
    main = event_name.casefold() == event.casefold() and ref.casefold() == wanted_ref.casefold()
    release = (
        event_name.casefold() == pull_event.casefold()
        and head_ref.casefold().startswith(prefix.casefold())
        and head_repo is not None
        and head_repo.casefold() == repository.casefold()
    )
    return then if (main or release) and then else otherwise


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


PR = "refs/pull/808/merge"


@pytest.mark.parametrize("head_ref,head_repo,repository", [
    ("release/0.5.256", HERE, HERE),
    ("release/0.6.0", HERE, HERE),
    ("release/x", HERE, HERE),
    ("Release/0.5.256", HERE, HERE),
    ("RELEASE/0.5.256", HERE, HERE),
    ("release/0.5.256", "normb/sipnab", HERE),
    ("release/0.5.256", HERE, "NORMB/SIPNAB"),
    ("release/", HERE, HERE),
])
def test_a_release_pull_request_of_this_repository_asks_for_every_aarch64_runner(head_ref, head_repo, repository):
    assert fm.runner_labels("pull_request", PR, head_ref, head_repo, repository) == MAIN, (head_ref, head_repo)


def test_the_release_pull_request_of_0_5_256_would_have_had_four_runners():
    # PR #808: head release/0.5.256 in NormB/sipnab, its Features jobs queued
    # for the overflow pair from 2026-11-14 23:15Z.
    assert fm.runner_labels("pull_request", "refs/pull/808/merge", "release/0.5.256", HERE, HERE) == MAIN


@pytest.mark.parametrize("head_repo", [
    "someone/sipnab",
    "NormB/sipnab-fork",
    "NormB/sipna",
    "xNormB/sipnab",
    "NormB/sipnab ",
    "",
    None,
])
def test_a_release_branch_of_a_fork_never_reaches_the_four_runners(head_repo):
    # A fork's pull request runs code nobody here wrote; its `release/`
    # branch name is the fork's choice. None is a fork that was deleted.
    assert fm.runner_labels("pull_request", PR, "release/0.5.256", head_repo, HERE) == OVERFLOW, head_repo


@pytest.mark.parametrize("head_ref", [
    "releases/0.5.256",
    "release-0.5.256",
    "release0.5.256",
    "release",
    "x/release/0.5.256",
    " release/0.5.256",
    "release\\0.5.256",
    "fix/release-records-any-run",
    "dependabot/cargo/release/x",
    "",
])
def test_a_branch_that_is_not_a_release_branch_asks_for_the_overflow_pair(head_ref):
    assert fm.runner_labels("pull_request", PR, head_ref, HERE, HERE) == OVERFLOW, head_ref


@pytest.mark.parametrize("event_name", [
    "push",
    "pull_request_target",
    "pull_request_review",
    "merge_group",
    "workflow_dispatch",
    "pull",
    "",
])
def test_a_release_branch_outside_a_pull_request_asks_for_the_overflow_pair(event_name):
    assert fm.runner_labels(event_name, "refs/heads/release/0.5.256", "release/0.5.256", HERE, HERE) == OVERFLOW


def test_the_release_branch_rule_names_the_prefix_once():
    assert fm.RELEASE_EVENT == "pull_request"
    assert fm.RELEASE_PREFIX == "release/"
    assert fm.RELEASE_PREFIX in fm.runs_on_expression()


@pytest.mark.parametrize("arguments", [
    ("pull_request", PR, None, HERE, HERE),
    ("pull_request", PR, "release/0.5.256", HERE, None),
    ("pull_request", PR, "release/0.5.256", 1, HERE),
    ("pull_request", PR, ["release/0.5.256"], HERE, HERE),
])
def test_a_pull_request_value_that_is_not_text_is_refused(arguments):
    # The message, so a call with the wrong number of arguments does not pass.
    with pytest.raises(TypeError, match="the text GitHub gives a workflow"):
        fm.runner_labels(*arguments)


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
    ("push", "refs/heads/main", "", None, HERE),
    ("PUSH", "refs/heads/MAIN", "", None, HERE),
    ("pull_request", "refs/pull/754/merge", "fix/x", HERE, HERE),
    ("pull_request", "refs/heads/main", "", None, HERE),
    ("push", "refs/heads/other", "", None, HERE),
    ("push", "refs/tags/v0.5.246", "", None, HERE),
    ("push", "refs/heads/main2", "", None, HERE),
    ("workflow_dispatch", "refs/heads/main", "", None, HERE),
    ("schedule", "refs/heads/main", "", None, HERE),
    ("merge_group", "refs/heads/main", "", None, HERE),
    ("", "", "", None, HERE),
    ("push", "", "", None, HERE),
    ("pull_request", "refs/pull/808/merge", "release/0.5.256", HERE, HERE),
    ("pull_request", "refs/pull/808/merge", "Release/0.5.256", "normb/SIPNAB", HERE),
    ("pull_request", "refs/pull/900/merge", "release/0.5.256", "someone/sipnab", HERE),
    ("pull_request", "refs/pull/900/merge", "release/0.5.256", None, HERE),
    ("pull_request", "refs/pull/808/merge", "releases/0.5.256", HERE, HERE),
    ("push", "refs/heads/release/0.5.256", "release/0.5.256", HERE, HERE),
    ("pull_request_target", "refs/heads/main", "release/0.5.256", HERE, HERE),
]


@pytest.mark.parametrize("event_name,ref,head_ref,head_repo,repository", CASES)
def test_the_workflows_expression_gives_what_the_rule_gives(event_name, ref, head_ref, head_repo, repository):
    case = (event_name, ref, head_ref, head_repo, repository)
    assert evaluate(workflow_runs_on(), *case) == fm.runner_labels(*case), case


@pytest.mark.parametrize("event_name,ref,head_ref,head_repo,repository", CASES)
def test_the_rendered_expression_gives_what_the_rule_gives(event_name, ref, head_ref, head_repo, repository):
    case = (event_name, ref, head_ref, head_repo, repository)
    assert evaluate(fm.runs_on_expression(), *case) == fm.runner_labels(*case), case


def test_the_cases_reach_both_answers_through_both_branches():
    main = [c for c in CASES if fm.runner_labels(*c) == MAIN]
    assert any(c[0].casefold() == "push" for c in main), "a push to main"
    assert any(c[0] == "pull_request" for c in main), "a release pull request"
    assert sum(1 for c in CASES if fm.runner_labels(*c) == OVERFLOW) >= 12, "the near misses"


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
