# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""A workflow that skips every job on a merge does not hold up the tag proof.

The 0.5.259 release train stopped at 2026-11-16 03:37:58Z: "GitHub's proof for
the merge commit 9da517eb2 did not resolve in 300 s"
(TAG-PROOF-REFUSES-SKIPPED-PR-CLOSED-RUN). scripts/tag-push-proof.py's
`runs_verdict` takes a merged pull request's head as proof of its merge commit
only when every workflow run on the head completed with `success`. Since #816,
.github/workflows/pr-closed.yml starts on every `closed` event and skips its
one job when the pull request was merged, so every merged head carries a
completed/skipped run (on #822's head 9fa6d949d: run 43798824671), the head
proof never passed, and every release waited for main's whole CI on the
merge.

The same night the merge commit's own runs refused too: run 43802486875 of
.github/workflows/rerun-not-acquired.yml ("Re-run jobs no runner took", event
`workflow_run`) completed as skipped on 9da517eb2, since that workflow skips
its only job when the CI run it watches succeeded. It starts only after main's
CI on the merge ends, which is why earlier releases, tagged on the head proof
or before that run, never met it.

The rule, in one place (`skipped_by_design`): a run does not count when it
completed as `skipped`, and its workflow FILE, as GitHub's run record names
it, is a key of SKIPPED_BY_DESIGN whose value is the run's event. The path
is read from GitHub for skipped runs only (`with_paths`); a name is not
enough, since any workflow can take any name. Nothing else changes: a skipped
run of any other workflow, and a canceled, failed, pending or missing run of
any workflow, this one included, still refuses.

The cases fall in three groups: success, failure, edge.
"""

import json
import pathlib
import re

from conftest import load

tp = load("tag-push-proof")

C = "c" * 40  # the merge commit
H = "8" * 40  # the merged pull request's head
H2 = "9" * 40
REQ = ["CI success", "Commit messages and PR title name no private identity", "license/cla"]
REPO = pathlib.Path(__file__).resolve().parents[2]
PR_CLOSED = ".github/workflows/pr-closed.yml"
PR_CLOSED_NAME = "Cancel CI of a closed pull request"
RERUN = ".github/workflows/rerun-not-acquired.yml"
RERUN_NAME = "Re-run jobs no runner took"
# Each excused file, and the `if:` each of its jobs must carry for the run to
# be skipped by design.
SKIP_CONDITIONS = {
    PR_CLOSED: r"if: github\.event\.pull_request\.merged == false\s*$",
    RERUN: r"if: >-\s*\n\s*github\.event_name == 'workflow_dispatch'\s*\n\s*\|\| "
           r"github\.event\.workflow_run\.conclusion != 'success'\s*$",
}


def run(rid, name, status="completed", conclusion="success", event="pull_request", sha=H, path=None):
    return tp.Run(id=rid, name=name, status=status, conclusion=conclusion, event=event, head_sha=sha, path=path)


def closed_run(rid=20, sha=H, status="completed", conclusion="skipped", event="pull_request", path=PR_CLOSED,
               name=PR_CLOSED_NAME):
    return run(rid, name, status=status, conclusion=conclusion, event=event, sha=sha, path=path)


def rerun_run(rid=30, sha=C, status="completed", conclusion="skipped", event="workflow_run", path=RERUN,
              name=RERUN_NAME):
    return run(rid, name, status=status, conclusion=conclusion, event=event, sha=sha, path=path)


def own_green_with_rerun():
    """9da517eb2's own runs as they stood: main's CI green, the re-run
    workflow skipped."""
    return [run(1, "CI", event="push", sha=C), run(2, "Quality", event="push", sha=C), rerun_run()]


def head_green(sha=H):
    return [run(11, "CI", sha=sha), run(12, "Quality", sha=sha), run(13, "Pull request text", sha=sha)]


def required_green():
    return tp.Checks(
        runs=[("CI success", "t", "success"), ("Commit messages and PR title name no private identity", "t", "success")],
        statuses=[("license/cla", "success")],
    )


def pending_own():
    return [run(1, "CI", status="in_progress", conclusion=None, event="push", sha=C)]


def tag_ci(head_runs, own=None, heads=((822, H, True),)):
    own = pending_own() if own is None else own
    checks = {H: required_green(), H2: required_green()}
    return tp.tag_ci(C, own, True, REQ, list(heads), checks, head_runs)


def as_json(rows):
    return json.dumps([{"databaseId": r.id, "headSha": r.head_sha, "status": r.status, "conclusion": r.conclusion,
                        "name": r.name, "event": r.event} for r in rows])


def gh_world(own_runs, head_runs, paths=None, path_rc=0):
    """GitHub as gather_tag_ci reads it. `paths` maps a run id to the
    workflow file GitHub's run record names; `asked` lists every path asked."""
    paths = {20: PR_CLOSED, 30: RERUN} if paths is None else paths
    answers = {
        "repos/o/r/rules/branches/main": (0, "\n".join(REQ[:2]) + "\n"),
        "repos/o/r/branches/main/protection": (1, "Branch not protected"),
        "repos/o/r/compare/": (0, "behind\n"),
        f"repos/o/r/commits/{C}/pulls": (0, f"822\t{H}\n"),
        f"repos/o/r/git/commits/{C}": (0, "t1\n"),
        f"repos/o/r/git/commits/{H}": (0, "t1\n"),
        f"repos/o/r/commits/{H}/check-runs": (
            0, "CI success\tt\tsuccess\nCommit messages and PR title name no private identity\tt\tsuccess\n"),
        f"repos/o/r/commits/{H}/status": (0, ""),
    }
    asked = []

    def gh(path, jq=None, paginate=False):
        asked.append(path)
        m = re.fullmatch(r"repos/o/r/actions/runs/(\d+)", path)
        if m:
            rid = int(m.group(1))
            return (path_rc, paths[rid] + "\n") if rid in paths else (1, "Not Found")
        for prefix, ans in answers.items():
            if path.startswith(prefix):
                return ans
        return 1, ""

    def runs(sha):
        return 0, as_json(own_runs if sha == C else head_runs)

    return gh, runs, asked


def run_paths_asked(asked):
    return [p for p in asked if "/actions/runs/" in p]


# ── SUCCESS ────────────────────────────────────────────────────────────────


def test_a_merged_head_with_the_skipped_close_run_is_green():
    state, _lines = tp.runs_verdict(head_green() + [closed_run()], H)
    assert state == "green", state


def test_the_skipped_close_run_is_not_counted_among_the_judged_runs():
    _state, lines = tp.runs_verdict(head_green() + [closed_run()], H)
    assert len(lines) == 3 and not any(PR_CLOSED_NAME in line for line in lines), lines


def test_the_head_proves_the_merge_commit_with_the_skipped_close_run():
    v = tag_ci({H: head_green() + [closed_run()]})
    assert v.state == "head" and v.via == (822, H), v


def test_the_head_proof_line_counts_only_the_judged_runs():
    v = tag_ci({H: head_green() + [closed_run()]})
    assert "all 3 workflow runs" in v.line, v.line


def test_the_close_run_skipped_on_a_merge_is_skipped_by_design():
    assert tp.skipped_by_design(closed_run()) is True, "the exact shape is excused"


def test_gather_proves_by_the_head_when_github_names_the_close_workflow():
    gh, runs, _asked = gh_world(pending_own(), head_green() + [closed_run()])
    v = tp.gather_tag_ci("o/r", C, gh, runs)
    assert v.state == "head" and v.via == (822, H), v


def test_gather_asks_for_the_workflow_file_of_the_skipped_run_only():
    gh, runs, asked = gh_world(pending_own(), head_green() + [closed_run()])
    tp.gather_tag_ci("o/r", C, gh, runs)
    assert run_paths_asked(asked) == ["repos/o/r/actions/runs/20"], asked


def test_the_0_5_259_head_as_github_listed_it_proves_its_merge_commit():
    # #822's head 9fa6d949d as `gh run list --commit` listed it at 03:4xZ.
    names = ["Pull request text", "OSV-Scanner", "CodeQL Advanced", "Docker", "Reproducible build", "Quality", "CI"]
    rows = [run(100 + i, n) for i, n in enumerate(names)]
    rows.append(run(99, "Certificate expiry", event="push"))
    rows.append(closed_run(rid=20))
    gh, runs, _asked = gh_world(pending_own(), rows)
    v = tp.gather_tag_ci("o/r", C, gh, runs)
    assert v.state == "head" and "all 8 workflow runs" in v.line, v


def test_ready_says_yes_for_a_merge_whose_head_has_the_skipped_close_run():
    gh, runs, _asked = gh_world(pending_own(), head_green() + [closed_run()])
    ok, lines = tp.ready("o/r", C, {}, gh, runs)
    assert ok is True, lines


def test_with_paths_fills_the_workflow_file_of_a_skipped_run():
    gh, _runs, _asked = gh_world([], [])
    got = tp.with_paths("o/r", [closed_run(path=None)], gh)
    assert got[0].path == PR_CLOSED, got


def test_with_paths_does_not_ask_about_a_successful_run():
    gh, _runs, asked = gh_world([], [])
    got = tp.with_paths("o/r", head_green(), gh)
    assert got == head_green() and asked == [], (got, asked)


def test_the_merge_commits_own_runs_with_a_skipped_close_run_are_green():
    own = [run(1, "CI", event="push", sha=C), closed_run(sha=C)]
    assert tp.runs_verdict(own, C)[0] == "green", "excused on the commit too"


def test_a_successful_close_run_counts_as_a_green_run():
    state, lines = tp.runs_verdict(head_green() + [closed_run(conclusion="success")], H)
    assert state == "green" and len(lines) == 4, (state, lines)


def test_the_newest_ci_run_is_still_judged_beside_the_close_run():
    rows = [run(5, "CI", conclusion="failure"), run(15, "CI"), closed_run()]
    assert tp.runs_verdict(rows, H)[0] == "green", "newest CI run is green"


def test_every_job_of_each_excused_workflow_carries_its_skip_condition():
    # The excuse holds only while the workflow skips EVERY job by that rule.
    for path, condition in SKIP_CONDITIONS.items():
        text = (REPO / path).read_text(encoding="utf-8")
        jobs = len(re.findall(r"^\s+runs-on:", text, re.M))
        skips = len(re.findall(r"^\s+" + condition, text, re.M))
        assert jobs >= 1 and skips == jobs, (path, jobs, skips)


def test_the_excused_files_are_the_close_and_rerun_workflows_with_their_events():
    assert tp.SKIPPED_BY_DESIGN == {PR_CLOSED: "pull_request", RERUN: "workflow_run"}, tp.SKIPPED_BY_DESIGN


def test_every_excused_workflow_file_exists_and_starts_on_its_event():
    for path, event in tp.SKIPPED_BY_DESIGN.items():
        text = (REPO / path).read_text(encoding="utf-8")
        assert re.search(rf"^on:\s*\n\s+{event}:", text, re.M), (path, event)


def test_the_merge_commits_own_runs_with_the_skipped_rerun_are_green():
    state, lines = tp.runs_verdict(own_green_with_rerun(), C)
    assert state == "green" and len(lines) == 2, (state, lines)


def test_the_rerun_run_skipped_after_a_green_ci_is_skipped_by_design():
    assert tp.skipped_by_design(rerun_run()) is True, "the exact shape is excused"


def test_gather_passes_the_merge_commit_on_its_own_runs_with_the_skipped_rerun():
    gh, runs, asked = gh_world(own_green_with_rerun(), head_green())
    v = tp.gather_tag_ci("o/r", C, gh, runs)
    assert v.state == "green" and run_paths_asked(asked) == ["repos/o/r/actions/runs/30"], (v, asked)


def test_the_head_proof_holds_with_a_skipped_rerun_run_on_the_head():
    v = tag_ci({H: head_green() + [rerun_run(sha=H)]})
    assert v.state == "head" and v.via == (822, H), v


def test_a_head_with_both_excused_runs_is_green():
    state, lines = tp.runs_verdict(head_green() + [closed_run(), rerun_run(sha=H)], H)
    assert state == "green" and len(lines) == 3, (state, lines)


# ── FAILURE ────────────────────────────────────────────────────────────────


def test_a_skipped_run_of_another_workflow_file_still_refuses():
    rows = head_green() + [run(21, "Docker", conclusion="skipped", path=".github/workflows/docker.yml")]
    assert tp.runs_verdict(rows, H)[0] == "not_green", "another file is not excused"


def test_a_skipped_run_named_like_the_close_workflow_from_another_file_refuses():
    rows = head_green() + [closed_run(path=".github/workflows/other.yml")]
    assert tp.runs_verdict(rows, H)[0] == "not_green", "the name is not enough"


def test_a_skipped_run_whose_file_is_unknown_refuses():
    assert tp.runs_verdict(head_green() + [closed_run(path=None)], H)[0] == "not_green", "no path, no excuse"


def test_gather_refuses_when_github_does_not_answer_for_the_run_record():
    gh, runs, _asked = gh_world(pending_own(), head_green() + [closed_run()], path_rc=1)
    v = tp.gather_tag_ci("o/r", C, gh, runs)
    assert v.state == "not_green", v


def test_gather_refuses_when_the_run_record_is_missing():
    gh, runs, _asked = gh_world(pending_own(), head_green() + [closed_run()], paths={})
    assert tp.gather_tag_ci("o/r", C, gh, runs).state == "not_green"


def test_a_canceled_close_run_refuses():
    assert tp.runs_verdict(head_green() + [closed_run(conclusion="cancelled")], H)[0] == "not_green"


def test_a_failed_close_run_refuses():
    assert tp.runs_verdict(head_green() + [closed_run(conclusion="failure")], H)[0] == "not_green"


def test_a_timed_out_close_run_refuses():
    assert tp.runs_verdict(head_green() + [closed_run(conclusion="timed_out")], H)[0] == "not_green"


def test_a_close_run_in_progress_refuses():
    rows = head_green() + [closed_run(status="in_progress", conclusion=None)]
    assert tp.runs_verdict(rows, H)[0] == "not_green", "pending"


def test_a_queued_close_run_refuses():
    rows = head_green() + [closed_run(status="queued", conclusion=None)]
    assert tp.runs_verdict(rows, H)[0] == "not_green", "pending"


def test_a_head_with_only_the_close_run_has_nothing_to_prove_it():
    assert tp.runs_verdict([closed_run()], H)[0] == "none", "a missing CI run is not a pass"


def test_a_failed_run_beside_the_close_run_refuses():
    rows = [run(11, "CI", conclusion="failure"), run(12, "Quality"), closed_run()]
    assert tp.runs_verdict(rows, H)[0] == "not_green"


def test_a_skipped_ci_run_beside_the_close_run_refuses():
    rows = [run(11, "CI", conclusion="skipped", path=".github/workflows/ci.yml"), closed_run()]
    assert tp.runs_verdict(rows, H)[0] == "not_green"


def test_a_skipped_close_run_from_a_push_event_refuses():
    assert tp.runs_verdict(head_green() + [closed_run(event="push")], H)[0] == "not_green", "event"


def test_a_red_run_on_the_merge_commit_still_refuses_the_head_proof():
    own = [run(1, "CI", conclusion="failure", event="push", sha=C)]
    v = tag_ci({H: head_green() + [closed_run()]}, own=own)
    assert v.state == "not_green" and "red on" in v.line, v


def test_a_path_with_a_suffix_is_not_the_close_workflow():
    assert tp.skipped_by_design(closed_run(path=PR_CLOSED + ".bak")) is False, "suffix"


def test_a_path_with_a_ref_is_not_the_close_workflow():
    assert tp.skipped_by_design(closed_run(path=PR_CLOSED + "@refs/heads/x")) is False, "ref"


def test_an_empty_answer_for_the_run_record_refuses():
    gh, runs, _asked = gh_world(pending_own(), head_green() + [closed_run()], paths={20: ""})
    assert tp.gather_tag_ci("o/r", C, gh, runs).state == "not_green"


def test_without_a_github_repository_no_run_record_is_read_and_nothing_is_excused():
    own = [run(1, "CI", event="push", sha=C), closed_run(sha=C, path=None)]
    asked = []

    def gh(path, jq=None, paginate=False):
        asked.append(path)
        return 1, ""

    v = tp.gather_tag_ci(None, C, gh, lambda sha: (0, as_json(own)))
    assert v.state == "not_green" and asked == [], (v, asked)


def test_a_head_whose_close_run_failed_does_not_prove_the_merge_commit():
    v = tag_ci({H: head_green() + [closed_run(conclusion="failure")]})
    assert v.state == "not_green" and "workflow runs not_green" in v.line, v


def test_a_skipped_rerun_run_from_a_pull_request_event_refuses():
    assert tp.runs_verdict(own_green_with_rerun()[:2] + [rerun_run(event="pull_request")], C)[0] == "not_green"


def test_a_skipped_close_run_from_a_workflow_run_event_refuses():
    assert tp.runs_verdict(head_green() + [closed_run(event="workflow_run")], H)[0] == "not_green"


def test_a_skipped_run_named_like_the_rerun_workflow_from_another_file_refuses():
    rows = own_green_with_rerun()[:2] + [rerun_run(path=".github/workflows/other.yml")]
    assert tp.runs_verdict(rows, C)[0] == "not_green", "the name is not enough"


def test_a_failed_rerun_run_refuses():
    assert tp.runs_verdict(own_green_with_rerun()[:2] + [rerun_run(conclusion="failure")], C)[0] == "not_green"


def test_a_canceled_rerun_run_refuses():
    assert tp.runs_verdict(own_green_with_rerun()[:2] + [rerun_run(conclusion="cancelled")], C)[0] == "not_green"


def test_a_rerun_run_in_progress_refuses():
    rows = own_green_with_rerun()[:2] + [rerun_run(status="in_progress", conclusion=None)]
    assert tp.runs_verdict(rows, C)[0] == "not_green", "pending"


def test_gather_refuses_the_own_runs_when_the_rerun_record_does_not_answer():
    gh, runs, _asked = gh_world(own_green_with_rerun(), [], paths={20: PR_CLOSED})
    v = tp.gather_tag_ci("o/r", C, gh, runs)
    assert v.state != "green", v


# ── EDGE ───────────────────────────────────────────────────────────────────


def test_a_commit_with_only_the_rerun_run_has_nothing_to_prove_it():
    assert tp.runs_verdict([rerun_run()], C)[0] == "none", "a missing CI run is not a pass"


def test_a_rerun_run_without_an_event_is_not_excused():
    assert tp.skipped_by_design(rerun_run(event="")) is False, "no event"


def test_a_run_without_a_path_or_an_event_is_not_excused():
    assert tp.skipped_by_design(rerun_run(path=None, event="")) is False, "neither"


def test_an_older_failed_close_run_is_still_judged_under_a_newer_skipped_one():
    # The excused run is set aside BEFORE the newest-of-each-name pick, so it
    # cannot hide an older run of the same name.
    rows = head_green() + [closed_run(rid=19, conclusion="failure", path=PR_CLOSED), closed_run(rid=20)]
    assert tp.runs_verdict(rows, H)[0] == "not_green"


def test_a_newer_excused_run_does_not_hide_an_older_run_of_another_file_with_its_name():
    rows = head_green() + [run(19, PR_CLOSED_NAME, conclusion="failure", path=".github/workflows/x.yml"),
                           closed_run(rid=20)]
    assert tp.runs_verdict(rows, H)[0] == "not_green"


def test_unreadable_runs_stay_unreadable():
    assert tp.runs_verdict(None, H) == ("unreadable", []), "None"


def test_a_completed_run_without_a_conclusion_is_not_excused():
    assert tp.skipped_by_design(closed_run(conclusion=None)) is False, "no conclusion"


def test_a_skipped_conclusion_on_a_run_not_completed_is_not_excused():
    # GitHub sends a conclusion only once a run completes; a record that says
    # otherwise is not trusted to excuse anything.
    assert tp.skipped_by_design(closed_run(status="in_progress")) is False, "status decides too"


def test_a_run_without_a_path_is_not_excused():
    assert tp.skipped_by_design(closed_run(path=None)) is False, "no path"


def test_a_path_in_another_case_is_not_the_close_workflow():
    assert tp.skipped_by_design(closed_run(path=".github/workflows/PR-closed.yml")) is False, "case"


def test_with_paths_of_unreadable_runs_is_unreadable():
    gh, _runs, asked = gh_world([], [])
    assert tp.with_paths("o/r", None, gh) is None and asked == [], asked


def test_with_paths_does_not_ask_about_a_run_without_an_id():
    gh, _runs, asked = gh_world([], [])
    got = tp.with_paths("o/r", [closed_run(rid=0, path=None)], gh)
    assert got[0].path is None and asked == [], (got, asked)


def test_with_paths_strips_the_line_end_of_the_answer():
    gh, _runs, _asked = gh_world([], [], paths={20: PR_CLOSED + "  "})
    assert tp.with_paths("o/r", [closed_run(path=None)], gh)[0].path == PR_CLOSED


def test_a_parsed_run_has_no_path_until_github_names_one():
    text = json.dumps([{"databaseId": 3, "headSha": H, "status": "completed", "conclusion": "skipped",
                        "name": PR_CLOSED_NAME, "event": "pull_request"}])
    assert tp.parse_runs(text)[0].path is None, "parse_runs reads no path"


def test_a_run_built_with_six_fields_has_no_path():
    assert tp.Run(1, "CI", "completed", "success", "push", H).path is None, "default"


def test_the_first_proving_head_is_used_when_another_head_has_a_failed_close_run():
    v = tag_ci({H: head_green() + [closed_run()], H2: head_green(H2) + [closed_run(sha=H2, conclusion="failure")]},
               heads=((822, H, True), (823, H2, True)))
    assert v.state == "head" and v.via == (822, H), v


def test_a_second_head_proves_when_the_first_heads_close_run_failed():
    v = tag_ci({H: head_green() + [closed_run(conclusion="failure")], H2: head_green(H2) + [closed_run(sha=H2)]},
               heads=((822, H, True), (823, H2, True)))
    assert v.state == "head" and v.via == (823, H2), v


def test_a_close_run_of_another_commit_does_not_count_for_this_one():
    state, lines = tp.runs_verdict(head_green() + [closed_run(sha=H2, conclusion="failure")], H)
    assert state == "green" and len(lines) == 3, (state, lines)


def test_gather_reads_nothing_more_once_the_commits_own_runs_are_green():
    own = [run(1, "CI", event="push", sha=C), closed_run(sha=C)]
    gh, runs, asked = gh_world(own, head_green())
    v = tp.gather_tag_ci("o/r", C, gh, runs)
    assert v.state == "green" and asked == ["repos/o/r/actions/runs/20"], (v, asked)


def test_gather_asks_about_each_skipped_run_once():
    rows = head_green() + [closed_run(rid=20), run(21, "Docker", conclusion="skipped")]
    gh, runs, asked = gh_world(pending_own(), rows, paths={20: PR_CLOSED, 21: ".github/workflows/docker.yml"})
    v = tp.gather_tag_ci("o/r", C, gh, runs)
    assert sorted(run_paths_asked(asked)) == ["repos/o/r/actions/runs/20", "repos/o/r/actions/runs/21"], asked
    assert v.state == "not_green", v
