# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""A closed pull request's CI run ends when the pull request closes.

CI's runs were grouped by `github.ref` with cancel-in-progress, so a new push
to a pull request ended the run before it. Closing a pull request started no
run, so nothing entered the group, and the run went on: on 2026-11-14 two
Dependabot pull requests closed at about 22:5xZ kept their CI runs
(43649960687 and 43650219749) going until a person canceled them at
00:11Z on 2026-11-15, holding the two `overflow` runners the release pull
request's jobs waited for (backlog OVERFLOW-RUNNERS-HAVE-NO-RELEASE-PRIORITY).

ci.yml now groups a pull request's runs by its number, and
.github/workflows/pr-closed.yml, started by the `closed` action, enters that
same group with cancel-in-progress: GitHub cancels the run in progress. A
concurrency group is one name space for the repository ("concurrency group
names must be unique across workflows to avoid canceling in-progress jobs or
runs from other workflows", GitHub's concurrency page), and the name is read
without regard to case.
"""

import pathlib
import re

import pytest
from conftest import load

REPO = pathlib.Path(__file__).resolve().parents[2]
WORKFLOWS = REPO / ".github" / "workflows"
CI = WORKFLOWS / "ci.yml"
CLOSED = WORKFLOWS / "pr-closed.yml"

rerun = load("rerun-not-acquired")


def text(path):
    return path.read_text(encoding="utf-8")


def code(path):
    """The workflow without its comment lines."""
    return "\n".join(line for line in text(path).split("\n") if not line.lstrip().startswith("#"))


def top(path, key):
    """The block of the top-level `key:` (its own line and the indented
    lines under it), without comments."""
    lines = code(path).split("\n")
    out = []
    inside = False
    for line in lines:
        if re.match(rf"{re.escape(key)}:", line):
            inside = True
            out.append(line)
            continue
        if inside:
            if line and not line.startswith(" "):
                break
            out.append(line)
    assert out, f"{path.name} has no top-level `{key}:`"
    return "\n".join(out).rstrip("\n")


def value(block, key):
    m = re.search(rf"(?m)^\s+{re.escape(key)}: (.+)$", block)
    assert m, f"no `{key}:` in\n{block}"
    return m.group(1).strip()


def workflow_name(path):
    m = re.search(r"(?m)^name: (.+)$", text(path))
    assert m, f"{path.name} has no name"
    return m.group(1).strip()


def expand(template, workflow, number, ref):
    """What GitHub makes of the group templates these workflows use.

    `github.event.pull_request.number || github.ref` is the number when the
    event has a pull request and the ref when it has none (a push).
    """
    values = {
        "github.workflow": workflow,
        "github.event.pull_request.number": "" if number is None else str(number),
        "github.ref": ref,
    }

    def one(match):
        parts = [p.strip() for p in match.group(1).split("||")]
        for part in parts:
            assert part in values, f"the test cannot evaluate `{part}`"
            if values[part]:
                return values[part]
        return ""

    out = re.sub(r"\$\{\{\s*(.*?)\s*\}\}", one, template)
    assert "${{" not in out, out
    return out


def ci_group(number=None, ref="refs/heads/main"):
    return expand(value(top(CI, "concurrency"), "group"), workflow_name(CI), number, ref)


def closed_group(number):
    return expand(value(top(CLOSED, "concurrency"), "group"), workflow_name(CLOSED), number, f"refs/pull/{number}/merge")


# ---------------------------------------------------------------- success


@pytest.mark.parametrize("number", [1, 9, 10, 808, 809, 9999, 123456])
def test_the_closed_event_enters_the_group_of_the_pull_requests_ci_run(number):
    assert closed_group(number).casefold() == ci_group(number, f"refs/pull/{number}/merge").casefold()


def test_the_closed_workflow_cancels_what_runs_in_its_group():
    assert value(top(CLOSED, "concurrency"), "cancel-in-progress") == "true"


def test_the_closed_workflow_starts_only_on_a_closed_pull_request_to_main():
    on = top(CLOSED, "on")
    assert re.search(r"(?m)^  pull_request:$", on), on
    assert value(on, "types") == "[closed]", on
    assert value(on, "branches") == "[main]", on
    assert len(re.findall(r"(?m)^  [a-z_]+:", on)) == 1, f"one trigger only:\n{on}"


def test_a_push_to_main_keeps_its_group():
    assert ci_group(None, "refs/heads/main") == "ci-CI-refs/heads/main"


def test_a_pull_requests_runs_still_cancel_each_other():
    assert ci_group(808, "refs/pull/808/merge") == ci_group(808, "refs/pull/808/merge")
    assert value(top(CI, "concurrency"), "cancel-in-progress") == "${{ github.ref != 'refs/heads/main' }}"


def test_the_closed_workflow_asks_for_no_permission():
    assert top(CLOSED, "permissions") == "permissions: {}"


def test_the_closed_workflow_has_one_short_job_on_a_hosted_runner():
    jobs = top(CLOSED, "jobs")
    assert len(re.findall(r"(?m)^  [a-z0-9_-]+:$", jobs)) == 1, jobs
    assert value(jobs, "runs-on") == "ubuntu-24.04", jobs
    assert int(value(jobs, "timeout-minutes")) <= 5, jobs


def test_a_run_the_group_canceled_is_not_rerun():
    # The canceled CI run triggers rerun-not-acquired.yml (it reads every CI
    # run that ends without success). A job the group canceled carries no
    # "not acquired" annotation, so the rule leaves the run alone.
    run = {"status": "completed", "conclusion": "cancelled", "run_attempt": 1}
    jobs = [
        {"id": 1, "name": "Check", "status": "completed", "conclusion": "success", "steps": [{"name": "x"}]},
        {"id": 2, "name": "Features (group 0, aarch64)", "status": "completed", "conclusion": "cancelled", "steps": [{"name": "x"}]},
        {"id": 3, "name": "Features (group 1, aarch64)", "status": "completed", "conclusion": "cancelled", "steps": []},
    ]
    annotations = {
        2: [{"message": "Canceling since a higher priority waiting request for ci-CI-808 exists"}],
        3: [{"message": "Canceling since a higher priority waiting request for ci-CI-808 exists"}],
    }
    verdict, reason = rerun.decide(run, jobs, annotations)
    assert verdict == "leave", reason


def test_a_run_the_group_canceled_while_its_jobs_were_queued_is_not_rerun():
    # The shape that depends on the annotation alone: every job the group
    # canceled was still waiting for a runner, so none has a step.
    run = {"status": "completed", "conclusion": "cancelled", "run_attempt": 1}
    jobs = [
        {"id": 1, "name": "Check", "status": "completed", "conclusion": "success", "steps": [{"name": "x"}]},
        {"id": 2, "name": "Features (group 0, aarch64)", "status": "completed", "conclusion": "cancelled", "steps": []},
        {"id": 3, "name": "Features (group 1, aarch64)", "status": "completed", "conclusion": "cancelled", "steps": []},
    ]
    annotations = {
        2: [{"message": "Canceling since a higher priority waiting request for ci-CI-808 exists"}],
        3: [{"message": "Canceling since a higher priority waiting request for ci-CI-808 exists"}],
    }
    verdict, reason = rerun.decide(run, jobs, annotations)
    assert verdict == "leave", reason
    assert reason.startswith("not only jobs that never started: Features (group 0, aarch64)"), reason


# ---------------------------------------------------------------- failure


@pytest.mark.parametrize("number,other", [(808, 809), (1, 10), (80, 808), (8, 88)])
def test_closing_one_pull_request_does_not_enter_another_ones_group(number, other):
    assert closed_group(number).casefold() != ci_group(other, f"refs/pull/{other}/merge").casefold()


@pytest.mark.parametrize("number", [1, 808])
def test_closing_a_pull_request_never_enters_mains_group(number):
    assert closed_group(number).casefold() != ci_group(None, "refs/heads/main").casefold()


def test_the_closed_workflow_does_not_name_its_group_by_its_own_name():
    # Its `github.workflow` is its own name, not CI's: the group must name CI.
    group = value(top(CLOSED, "concurrency"), "group")
    assert "github.workflow" not in group, group
    assert workflow_name(CLOSED) != workflow_name(CI)
    assert group.startswith(f"ci-{workflow_name(CI)}-"), group


def test_ci_itself_does_not_start_on_a_closed_pull_request():
    on = top(CI, "on")
    assert "types:" not in on, f"CI's pull_request trigger has its default actions, without closed:\n{on}"


def test_the_closed_workflow_never_runs_with_the_base_repositorys_secrets():
    whole = code(CLOSED)
    assert "pull_request_target" not in whole
    assert "secrets." not in whole
    assert "github.token" not in whole and "GITHUB_TOKEN" not in whole


def test_the_closed_workflow_checks_out_nothing_and_calls_no_action():
    whole = code(CLOSED)
    assert "uses:" not in whole, "no code of the pull request or of an action runs"


def test_the_closed_workflow_writes_no_pull_request_text_into_a_command():
    # A title or a branch name in `run:` would be shell text from the
    # pull request's author.
    whole = code(CLOSED)
    for field in ("github.event.pull_request.title", "github.head_ref", "github.event.pull_request.body"):
        assert field not in whole, field
    run = re.findall(r"(?m)^\s+run: (.*)$", whole)
    assert run and all("${{" not in r for r in run), run


@pytest.mark.parametrize(
    "template",
    [
        "ci-${{ github.workflow }}-${{ github.ref }}",
        "ci-${{ github.workflow }}-${{ github.head_ref }}",
    ],
)
def test_a_group_by_ref_alone_would_not_be_shared_with_the_closed_event(template):
    # Why ci.yml names the number: a group of another shape is the one the
    # closed event cannot be shown to share. The old group is not the one in
    # ci.yml any more.
    assert value(top(CI, "concurrency"), "group") != template


def test_the_evaluator_refuses_a_value_it_does_not_know():
    with pytest.raises(AssertionError):
        expand("ci-${{ github.sha }}", "CI", 1, "refs/pull/1/merge")


# ------------------------------------------------------------------- edge


def test_the_group_names_the_number_before_the_ref():
    assert value(top(CI, "concurrency"), "group") == (
        "ci-${{ github.workflow }}-${{ github.event.pull_request.number || github.ref }}"
    )


def test_the_closed_group_is_the_ci_group_with_the_workflow_name_written_out():
    assert value(top(CLOSED, "concurrency"), "group") == "ci-CI-${{ github.event.pull_request.number }}"


def test_ci_is_named_ci():
    assert workflow_name(CI) == "CI", "the closed workflow writes this name into its group"


def test_a_merged_pull_request_closes_too():
    # GitHub sends `closed` for a merge as for a close without one; one
    # action covers both, and the workflow does not test `merged`.
    assert "merged" not in code(CLOSED)


def test_the_closed_workflow_has_a_name_that_says_what_it_does():
    assert "closed pull request" in workflow_name(CLOSED).casefold(), workflow_name(CLOSED)


def test_the_closed_workflow_says_why_it_exists():
    head = text(CLOSED).split("\non:", 1)[0]
    for needed in ("43649960687", "concurrency", "cancel"):
        assert needed in head, needed


def test_the_workflows_page_lists_the_closed_workflow():
    page = text(REPO / "docs" / "internals" / "build-ci-release.md")
    assert "| `pr-closed.yml` |" in page
    count = len(sorted(WORKFLOWS.glob("*.yml")))
    words = {19: "nineteen", 20: "twenty", 21: "twenty-one"}
    assert f"## The {words[count]} workflows" in page, count


def test_the_job_prints_the_number_from_the_environment():
    jobs = top(CLOSED, "jobs")
    assert value(jobs, "NUMBER") == "${{ github.event.pull_request.number }}", jobs


@pytest.mark.parametrize("number", [0, 7])
def test_a_small_number_is_not_the_prefix_of_another_group(number):
    assert closed_group(number) != closed_group(number * 10 + 1)
