# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""The tag gate accepts the merged pull request's head when the tree is the same.

The v0.5.238 tag waited 37 minutes (TAG-GATE-WAITS-FOR-MERGE-CI): release PR
#701 merged at 13:55:22Z as 26bfa26a8, and the pre-push tag gate refused the
tag until every workflow run on 26bfa26a8 finished. Those runs re-proved a
tree that PR #701's head f151b38d8 had already proved.

scripts/tag-push-proof.py's `tag_ci` is the one rule. The tag CI gate passes
when the tagged commit's own runs are all green (the rule the hook has always
applied), OR when all of these hold for a merged pull request whose merge
commit it is:

* the tagged commit is on main;
* the head has the same tree as the tagged commit;
* every check main requires concluded `success` on the head (`decide`'s rule);
* every workflow run on the head, the newest of each name and not scheduled,
  completed with `success`, so the macOS leg, which `CI success` leaves out,
  still gates the release;
* no workflow run on the tagged commit itself has concluded red.

Anything else falls back to the tagged commit's own runs: unreadable, pending,
neutral, skipped, missing or failed means wait or refuse.
"""

import json
import pathlib

import pytest
from conftest import load

tp = load("tag-push-proof")

C = "c" * 40  # the tagged merge commit
H = "8" * 40  # the merged pull request's head
H2 = "9" * 40
REQ = ["CI success", "Commit messages and PR title name no private identity", "license/cla"]
REPO = pathlib.Path(__file__).resolve().parents[2]


def run(rid, name, status="completed", conclusion="success", event="push", sha=C):
    return tp.Run(id=rid, name=name, status=status, conclusion=conclusion, event=event, head_sha=sha)


def head_green(sha=H):
    return [
        run(11, "CI", event="pull_request", sha=sha),
        run(12, "Quality", event="pull_request", sha=sha),
        run(13, "PR text", event="pull_request", sha=sha),
    ]


def required_green():
    return tp.Checks(
        runs=[("CI success", "t", "success"), ("Commit messages and PR title name no private identity", "t", "success")],
        statuses=[("license/cla", "success")],
    )


PENDING_OWN = [run(1, "CI", status="in_progress", conclusion=None), run(2, "Quality", status="queued", conclusion=None)]


def tag_ci(
    own=PENDING_OWN,
    contains=True,
    required=REQ,
    heads=((701, H, True),),
    checks=None,
    head_runs=None,
):
    checks = {H: required_green(), H2: required_green()} if checks is None else checks
    head_runs = {H: head_green(H), H2: head_green(H2)} if head_runs is None else head_runs
    return tp.tag_ci(C, own, contains, required, list(heads), checks, head_runs)


# ── SUCCESS ────────────────────────────────────────────────────────────────


def test_a_commit_whose_own_runs_are_green_passes_without_a_pull_request():
    v = tp.tag_ci(C, [run(1, "CI"), run(2, "Quality")], None, None, [], {}, {})
    assert v.state == "green" and v.via is None, v


def test_a_merge_commit_with_ci_in_flight_is_proven_by_its_pr_head_on_the_same_tree():
    v = tag_ci()
    assert v.state == "head" and v.via == (701, H), v


def test_the_head_proof_line_names_the_pr_the_head_and_the_same_tree():
    line = tag_ci().line
    assert "PR #701" in line and H[:9] in line and "same tree" in line, line


def test_the_head_proof_line_counts_the_required_checks_and_the_workflow_runs():
    line = tag_ci().line
    assert "3 required checks" in line and "3 workflow runs" in line, line


def test_a_merge_commit_with_no_runs_yet_is_proven_by_its_pr_head():
    v = tag_ci(own=[])
    assert v.state == "head", v


def test_a_canceled_run_on_the_merge_commit_is_not_a_red_verdict():
    v = tag_ci(own=[run(1, "CI", conclusion="cancelled")])
    assert v.state == "head", v


def test_a_required_context_met_by_a_commit_status_on_the_head_counts():
    checks = {H: tp.Checks(runs=[("CI success", "t", "success")], statuses=[
        ("Commit messages and PR title name no private identity", "success"), ("license/cla", "success")])}
    assert tag_ci(checks=checks).state == "head"


def test_a_canceled_head_run_superseded_by_a_newer_pass_still_proves():
    runs = head_green() + [run(5, "Quality", conclusion="cancelled", event="pull_request", sha=H)]
    assert tag_ci(head_runs={H: runs}).state == "head"


def test_a_scheduled_run_on_the_head_is_set_aside():
    runs = head_green() + [run(20, "ClusterFuzzLite", status="in_progress", conclusion=None, event="schedule", sha=H)]
    assert tag_ci(head_runs={H: runs}).state == "head"


def test_a_scheduled_failure_on_the_merge_commit_does_not_refuse_the_head():
    own = PENDING_OWN + [run(9, "ClusterFuzzLite", conclusion="failure", event="schedule")]
    assert tag_ci(own=own).state == "head"


def test_the_second_merged_pr_proves_when_the_first_is_on_another_tree():
    v = tag_ci(heads=((700, H2, False), (701, H, True)))
    assert v.state == "head" and v.via == (701, H), v


def test_own_runs_superseded_by_a_newer_pass_are_green():
    v = tp.tag_ci(C, [run(1, "Quality", conclusion="cancelled"), run(2, "Quality"), run(3, "CI")], None, None, [], {}, {})
    assert v.state == "green", v


def test_gh_run_list_json_is_read_into_runs():
    text = json.dumps([{"databaseId": 7, "headSha": C, "status": "completed", "conclusion": "success",
                        "name": "CI", "event": "push"}])
    assert tp.parse_runs(text) == [run(7, "CI")]


# ── FAILURE: anything not proven falls back to the commit's own runs ────────


def test_a_failed_own_run_with_no_pull_request_is_not_green():
    v = tp.tag_ci(C, [run(1, "CI", conclusion="failure")], None, None, [], {}, {})
    assert v.state == "not_green" and "completed/failure/CI" in v.line, v


def test_a_failed_run_on_the_merge_commit_refuses_the_head_proof():
    v = tag_ci(own=[run(1, "CI", conclusion="failure")])
    assert v.state == "not_green" and "red on" in v.line, v


def test_a_timed_out_run_on_the_merge_commit_refuses_the_head_proof():
    v = tag_ci(own=[run(1, "CI", conclusion="timed_out")])
    assert v.state == "not_green", v


def test_a_head_on_another_tree_proves_nothing():
    v = tag_ci(heads=((701, H, False),))
    assert v.state == "not_green" and "no merged pull request" in v.line, v


def test_a_failed_required_check_on_the_head_proves_nothing():
    checks = {H: tp.Checks(runs=[("CI success", "t", "failure")], statuses=[("license/cla", "success")])}
    v = tag_ci(checks=checks)
    assert v.state == "not_green" and "CI success: failure" in v.line, v


def test_a_missing_required_check_on_the_head_proves_nothing():
    checks = {H: tp.Checks(runs=[("CI success", "t", "success")], statuses=[("license/cla", "success")])}
    v = tag_ci(checks=checks)
    assert v.state == "not_green" and "missing" in v.line, v


def test_a_required_check_still_running_on_the_head_proves_nothing():
    checks = {H: tp.Checks(runs=[("CI success", None, "in_progress")], statuses=[("license/cla", "success")])}
    assert tag_ci(checks=checks).state == "not_green"


def test_a_neutral_required_check_on_the_head_proves_nothing():
    checks = {H: tp.Checks(runs=[("CI success", "t", "neutral")], statuses=[("license/cla", "success")])}
    assert tag_ci(checks=checks).state == "not_green"


def test_a_skipped_required_check_on_the_head_proves_nothing():
    checks = {H: tp.Checks(runs=[("CI success", "t", "skipped")], statuses=[("license/cla", "success")])}
    assert tag_ci(checks=checks).state == "not_green"


def test_a_failed_macos_leg_on_the_head_proves_nothing_though_ci_success_passed():
    # CI success leaves check-macos out, but a failed job fails the CI run.
    runs = [run(11, "CI", conclusion="failure", event="pull_request", sha=H)] + head_green()[1:]
    v = tag_ci(head_runs={H: runs})
    assert v.state == "not_green" and "completed/failure/CI" in v.line, v


def test_a_workflow_still_running_on_the_head_proves_nothing():
    runs = head_green() + [run(30, "Docker", status="in_progress", conclusion=None, event="pull_request", sha=H)]
    assert tag_ci(head_runs={H: runs}).state == "not_green"


def test_a_head_with_no_workflow_runs_proves_nothing():
    assert tag_ci(head_runs={H: []}).state == "not_green"


def test_a_commit_not_on_main_is_not_proven_by_a_head():
    v = tag_ci(contains=False)
    assert v.state == "not_green" and "not on origin/main" in v.line, v


def test_ancestry_that_could_not_be_read_proves_nothing():
    assert tag_ci(contains=None).state == "not_green"


def test_required_checks_that_could_not_be_read_prove_nothing():
    assert tag_ci(required=None).state == "not_green"


def test_no_required_checks_prove_nothing():
    assert tag_ci(required=[]).state == "not_green"


def test_head_checks_that_could_not_be_read_prove_nothing():
    assert tag_ci(checks={H: None}).state == "not_green"


def test_head_runs_that_could_not_be_read_prove_nothing():
    assert tag_ci(head_runs={H: None}).state == "not_green"


def test_own_runs_that_could_not_be_read_are_unreadable():
    v = tag_ci(own=None)
    assert v.state == "unreadable", v


# ── EDGE ───────────────────────────────────────────────────────────────────


def test_a_merge_commit_with_only_scheduled_runs_is_proven_by_its_head():
    v = tag_ci(own=[run(1, "ClusterFuzzLite", event="schedule")])
    assert v.state == "head", v


def test_only_scheduled_runs_and_no_head_means_no_runs():
    v = tp.tag_ci(C, [run(1, "ClusterFuzzLite", event="schedule")], None, None, [], {}, {})
    assert v.state == "none", v


def test_no_runs_and_no_head_means_no_runs():
    assert tp.tag_ci(C, [], None, None, [], {}, {}).state == "none"


def test_runs_of_another_commit_are_not_counted_for_this_one():
    v = tp.tag_ci(C, [run(1, "CI", conclusion="failure", sha=H2), run(2, "CI")], None, None, [], {}, {})
    assert v.state == "green", v


def test_head_runs_of_another_commit_do_not_prove_the_head():
    assert tag_ci(head_runs={H: head_green(H2)}).state == "not_green"


def test_the_newest_run_by_id_wins_whatever_the_list_order():
    v = tp.tag_ci(C, [run(9, "CI"), run(3, "CI", conclusion="failure")], None, None, [], {}, {})
    assert v.state == "green", v


def test_a_completed_run_with_no_conclusion_is_not_green():
    v = tp.tag_ci(C, [run(1, "CI", conclusion=None)], None, None, [], {}, {})
    assert v.state == "not_green", v


def test_a_queued_run_on_the_merge_commit_is_pending_not_red():
    assert tag_ci(own=[run(1, "CI", status="queued", conclusion=None)]).state == "head"


def test_a_canceled_rerun_after_a_failure_leaves_no_red_verdict_on_the_merge_commit():
    own = [run(1, "CI", conclusion="failure"), run(2, "CI", conclusion="cancelled")]
    assert tag_ci(own=own).state == "head"


def test_of_two_same_tree_heads_the_first_proven_one_is_named():
    v = tag_ci(heads=((701, H, True), (702, H2, True)))
    assert v.via == (701, H), v


def test_a_run_with_no_id_or_event_is_read_as_the_jq_rule_read_it():
    # The jq rule this replaced read `.databaseId // 0` and kept a run whose
    # event was missing, since null is not "schedule".
    text = json.dumps([{"headSha": C, "status": "completed", "conclusion": "success", "name": "CI"}])
    assert tp.parse_runs(text) == [tp.Run(0, "CI", "completed", "success", "", C)]

@pytest.mark.parametrize("text", ["not json", "{}", '[{"databaseId": 1}]', ""])
def test_gh_output_that_is_not_a_run_list_is_unreadable(text):
    assert tp.parse_runs(text) is None


def test_a_head_proof_is_not_looked_for_when_the_commits_own_runs_are_green():
    asked = []

    def gh(path, jq=None, paginate=False):
        asked.append(path)
        return 1, ""

    def runs(sha):
        return 0, json.dumps([{"databaseId": 1, "headSha": C, "status": "completed", "conclusion": "success",
                               "name": "CI", "event": "push"}])

    v = tp.gather_tag_ci("o/r", C, gh, runs)
    assert v.state == "green" and asked == [], (v, asked)


def gh_world(own_runs, head_runs, tree_c="t1", tree_h="t1"):
    answers = {
        "repos/o/r/rules/branches/main": (0, "\n".join(REQ[:2]) + "\n"),
        "repos/o/r/branches/main/protection": (1, "Branch not protected"),
        "repos/o/r/compare/": (0, "behind\n"),
        f"repos/o/r/commits/{C}/pulls": (0, f"701\t{H}\n"),
        f"repos/o/r/git/commits/{C}": (0, tree_c + "\n"),
        f"repos/o/r/git/commits/{H}": (0, tree_h + "\n"),
        f"repos/o/r/commits/{H}/check-runs": (0, "CI success\tt\tsuccess\nCommit messages and PR title name no private identity\tt\tsuccess\n"),
        f"repos/o/r/commits/{H}/status": (0, ""),
    }

    def gh(path, jq=None, paginate=False):
        for prefix, ans in answers.items():
            if path.startswith(prefix):
                return ans
        return 1, ""

    def runs(sha):
        rows = own_runs if sha == C else head_runs
        return 0, json.dumps([{"databaseId": r.id, "headSha": r.head_sha, "status": r.status,
                               "conclusion": r.conclusion, "name": r.name, "event": r.event} for r in rows])

    return gh, runs


def test_gather_reads_every_answer_from_github_and_proves_by_the_head():
    gh, runs = gh_world(PENDING_OWN, head_green())
    v = tp.gather_tag_ci("o/r", C, gh, runs)
    assert v.state == "head" and v.via == (701, H), v


def test_gather_with_different_trees_falls_back_to_the_pending_own_runs():
    gh, runs = gh_world(PENDING_OWN, head_green(), tree_h="t2")
    assert tp.gather_tag_ci("o/r", C, gh, runs).state == "not_green"


def test_gather_without_a_github_repository_judges_only_the_own_runs():
    _gh, runs = gh_world(PENDING_OWN, head_green())
    v = tp.gather_tag_ci(None, C, None, runs)
    assert v.state == "not_green" and "not a GitHub repository" in v.line, v


def test_gather_with_run_list_failing_is_unreadable():
    gh, _runs = gh_world(PENDING_OWN, head_green())
    assert tp.gather_tag_ci("o/r", C, gh, lambda sha: (1, "offline")).state == "unreadable"


def test_gh_answering_with_something_that_is_not_a_run_list_refuses():
    gh, _runs = gh_world(PENDING_OWN, head_green())
    v = tp.gather_tag_ci("o/r", C, gh, lambda sha: (0, "<html>rate limited</html>"))
    assert v.state == "not_green" and "not a run list" in v.line, v

@pytest.mark.parametrize("state,code", [("green", 0), ("head", 10), ("none", 3), ("not_green", 4), ("unreadable", 5)])
def test_each_verdict_has_its_own_exit_status(state, code):
    assert tp.TAG_CI_EXIT[state] == code


# ── The proofs the head path relies on, held to the workflow ───────────────


def _ci():
    return (REPO / ".github/workflows/ci.yml").read_text()


def test_ci_success_needs_the_code_scanning_job_the_head_proof_relies_on():
    # The tag gate accepts "no analysis of the merge commit yet" only under a
    # head proof, because CI success on that same tree needed this job.
    text = _ci()
    block = text[text.index("  ci-success:"):]
    needs = block[block.index("needs:"):block.index("runs-on:")]
    assert "code-scanning-clean" in needs, needs


def test_the_macos_leg_runs_on_pull_requests_so_the_head_carries_its_verdict():
    text = _ci()
    block = text[text.index("  check-macos:"):text.index("\n  test:")]
    assert "\n    if:" not in block and "continue-on-error" not in block, block
    assert "pull_request:" in text[: text.index("jobs:")]
