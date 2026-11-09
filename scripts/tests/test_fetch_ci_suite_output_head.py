# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""The site's test count may come from the merged pull request's head.

On 0.5.238 the Pages deploy waited 39 minutes for CI's push run of the merge
commit to upload `suite-output`, although the release pull request's head had
already run the same suite on the same tree. RELEASE-FAST C: ci.yml uploads
`suite-output` on pull requests too, and fetch-ci-suite-output.py takes it
from a merged pull request's head when GitHub reports the same tree for the
head and the commit being deployed (`read_pr_heads` in
scripts/tag-push-proof.py, the rule the tag gate uses).

The commit's own run still decides when it has finished: if it completed
without the artifact, its suite failed on that tree, and no head can stand in.
"""

from conftest import load

fetch = load("fetch-ci-suite-output")

OWN_RUNNING = {"id": 1, "status": "in_progress", "conclusion": None}
OWN_FAILED = {"id": 1, "status": "completed", "conclusion": "failure"}
HEAD_DONE = {"id": 2, "status": "completed", "conclusion": "success"}
HEAD_RUNNING = {"id": 3, "status": "in_progress", "conclusion": None}


def head(run, names, number=706, sha="8" * 40):
    return {"number": number, "sha": sha, "run": run, "names": names}


# ── SUCCESS ────────────────────────────────────────────────────────────────

def test_the_heads_artifact_is_used_while_the_commits_own_run_is_still_going():
    action, run_id, why = fetch.choose(OWN_RUNNING, [], [head(HEAD_DONE, ["suite-output"])])
    assert (action, run_id) == ("download", 2)
    assert "#706" in why and "same tree" in why


def test_the_heads_artifact_is_used_before_the_commit_has_any_run():
    assert fetch.choose(None, [], [head(HEAD_DONE, ["suite-output"])])[:2] == ("download", 2)


def test_the_commits_own_artifact_is_preferred_when_both_exist():
    assert fetch.choose(OWN_RUNNING, ["suite-output"], [head(HEAD_DONE, ["suite-output"])])[:2] == ("download", 1)


def test_without_heads_the_old_rule_holds():
    assert fetch.choose(OWN_RUNNING, ["suite-output"], [])[:2] == ("download", 1)


# ── FAILURE ────────────────────────────────────────────────────────────────

def test_a_finished_own_run_without_the_artifact_fails_even_if_a_head_has_one():
    action, _, why = fetch.choose(OWN_FAILED, [], [head(HEAD_DONE, ["suite-output"])])
    assert action == "fail" and "1" in why


def test_a_head_run_without_the_artifact_is_not_a_source():
    assert fetch.choose(OWN_RUNNING, [], [head(HEAD_DONE, ["coverage"])])[0] == "wait"


def test_only_same_tree_heads_are_read(monkeypatch):
    calls = []

    def gh(path, jq=None):
        calls.append(path)
        if path.endswith("/pulls"):
            return 0, ""
        return 1, ""

    monkeypatch.setattr(fetch, "_tag_push_proof", lambda: type("M", (), {
        "read_pr_heads": staticmethod(lambda repo, sha, g: [(706, "8" * 40, False)])}))
    assert fetch.head_sources("o/r", "c" * 40, gh) == []
    assert not any("head_sha=" + "8" * 40 in c for c in calls)


def test_an_unreadable_pull_request_lookup_means_no_heads(monkeypatch):
    monkeypatch.setattr(fetch, "_tag_push_proof", lambda: type("M", (), {
        "read_pr_heads": staticmethod(lambda repo, sha, g: [])}))
    assert fetch.head_sources("o/r", "c" * 40, lambda p, j=None: (1, "")) == []


# ── EDGE ───────────────────────────────────────────────────────────────────

def test_a_head_still_running_means_wait():
    assert fetch.choose(OWN_RUNNING, [], [head(HEAD_RUNNING, [])])[0] == "wait"


def test_no_own_run_and_no_heads_means_wait():
    assert fetch.choose(None, [], [])[0] == "wait"


def test_the_first_head_with_the_artifact_is_chosen():
    hs = [head(HEAD_RUNNING, []), head(HEAD_DONE, ["suite-output"], number=707)]
    action, run_id, why = fetch.choose(None, [], hs)
    assert (action, run_id) == ("download", 2) and "#707" in why


def test_a_same_tree_head_contributes_its_newest_ci_run(monkeypatch):
    monkeypatch.setattr(fetch, "_tag_push_proof", lambda: type("M", (), {
        "read_pr_heads": staticmethod(lambda repo, sha, g: [(706, "8" * 40, True)])}))
    monkeypatch.setattr(fetch, "head_run", lambda repo, sha: {"id": 9, "status": "completed"})
    monkeypatch.setattr(fetch, "live_artifacts", lambda repo, run_id: ["suite-output"])
    [src] = fetch.head_sources("o/r", "c" * 40, None)
    assert (src["number"], src["run"]["id"], src["names"]) == (706, 9, ["suite-output"])


def test_ci_uploads_the_suite_output_on_pull_requests_too():
    import pathlib
    ci = (pathlib.Path(__file__).resolve().parents[2] / ".github/workflows/ci.yml").read_text()
    step = ci[ci.index("- name: Hand the suite output to the site build"):]
    step = step[: step.index("if-no-files-found")]
    assert "if: github.event_name == 'push'" not in step
