# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""A tag's proof that GitHub cannot give yet is named as that (RELEASE-TRAIN-TAG-RACE).

Measured on 0.5.243: release PR #734 merged as 88f46bb83 at 07:27:34Z and
scripts/release-train.py pushed the tag at 07:27:35Z. The pre-push hook asked
scripts/tag-push-proof.py, and GitHub's commits/<sha>/pulls did not list #734
for the merge commit yet, so the answer was "on 88f46bb83, CI success:
missing, ... license/cla: missing" and the full gates ran. The
release-delivery test then refused the push, and the hook's text pointed at
CHANGELOG.md. The same query, made by hand at 07:32Z, found the proof.

Three rules are held here:

* `decide` and `tag_ci` say "not found yet" when no merged pull request is
  listed for a commit on main whose own checks do not prove it, and `decide`
  marks that answer `pending` (exit status 3 from the hook's query);
* `ready` is the hook's two queries in one call, for the release train to
  poll before it pushes;
* `delivery_hint` is the text the hook prints when the release-delivery test
  refuses a push: for a tag it names the pending proof and a checkout that is
  not at the tagged commit, and it names CHANGELOG.md only for a branch.
"""

from conftest import load

tp = load("tag-push-proof")

C1 = "1" * 40
H1 = "8" * 40
T1 = "a" * 40
Z = "0" * 40
REQ = ["CI success", "license/cla"]
MERGE_ONLY = tp.Checks(runs=[], statuses=[])


def ref(remote="refs/tags/v0.5.243", local=T1, commit=C1):
    return tp.Ref(local_ref=remote, local_sha=local, remote_ref=remote, remote_sha=Z, commit=commit)


def green():
    return tp.Checks(runs=[("CI success", "2026-11-10T07:20:00Z", "success")], statuses=[("license/cla", "success")])


# ── decide: the proof is pending ───────────────────────────────────────────


def test_success_a_merge_commit_with_no_pull_request_listed_yet_is_pending():
    proof = tp.decide([ref()], {C1: True}, {C1: MERGE_ONLY}, REQ, {C1: []})
    assert not proof.skip and proof.pending, proof


def test_success_the_pending_line_says_not_found_yet_and_to_push_again():
    line = tp.decide([ref()], {C1: True}, {C1: MERGE_ONLY}, REQ, {C1: []}).line
    assert "the proof is not found yet" in line and "push again" in line, line


def test_success_the_pending_line_still_names_the_commit_and_each_unmet_check():
    line = tp.decide([ref()], {C1: True}, {C1: MERGE_ONLY}, REQ, {C1: []}).line
    assert "111111111" in line and "CI success: missing" in line and "license/cla: missing" in line, line


def test_success_a_proven_commit_is_not_pending():
    proof = tp.decide([ref()], {C1: True}, {C1: green()}, REQ, {})
    assert proof.skip and not proof.pending


def test_failure_a_listed_head_with_a_failed_check_is_refused_not_pending():
    bad = tp.Checks(runs=[("CI success", "t", "failure")], statuses=[("license/cla", "success")])
    proof = tp.decide([ref()], {C1: True}, {C1: MERGE_ONLY, H1: bad}, REQ, {C1: [(734, H1, True)]})
    assert not proof.skip and not proof.pending and "not found yet" not in proof.line, proof


def test_failure_a_listed_head_on_another_tree_is_refused_not_pending():
    proof = tp.decide([ref()], {C1: True}, {C1: MERGE_ONLY, H1: green()}, REQ, {C1: [(734, H1, False)]})
    assert not proof.skip and not proof.pending and "not found yet" not in proof.line, proof


def test_failure_a_commit_not_on_main_is_refused_not_pending():
    proof = tp.decide([ref()], {C1: False}, {C1: MERGE_ONLY}, REQ, {C1: []})
    assert not proof.skip and not proof.pending and "is not on origin/main" in proof.line


def test_failure_unreadable_checks_are_refused_not_pending():
    proof = tp.decide([ref()], {C1: True}, {C1: None}, REQ, {C1: []})
    assert not proof.skip and not proof.pending and "could not be read" in proof.line


def test_edge_no_heads_argument_at_all_is_pending_like_an_empty_list():
    proof = tp.decide([ref()], {C1: True}, {C1: MERGE_ONLY}, REQ)
    assert proof.pending


def test_edge_of_two_tagged_commits_one_pending_makes_the_push_pending():
    c2 = "2" * 40
    refs = [ref(), ref(remote="refs/tags/v0.5.244", local="b" * 40, commit=c2)]
    proof = tp.decide(refs, {C1: True, c2: True}, {C1: green(), c2: MERGE_ONLY}, REQ, {c2: []})
    assert not proof.skip and proof.pending and "222222222" in proof.line


# ── The exit status the hook reads ─────────────────────────────────────────


def test_success_a_proof_exits_0():
    assert tp.exit_status(tp.Proof(True, "x")) == 0


def test_failure_a_refusal_exits_1():
    assert tp.exit_status(tp.Proof(False, "x")) == 1


def test_edge_a_pending_proof_exits_3():
    assert tp.exit_status(tp.Proof(False, "x", pending=True)) == tp.PENDING_EXIT == 3


def test_edge_a_proof_outranks_a_pending_flag():
    assert tp.exit_status(tp.Proof(True, "x", pending=True)) == 0


# ── tag_ci: the same answer from the tag CI gate ───────────────────────────


def run(rid, name, status="completed", conclusion="success", event="push", sha=C1):
    return tp.Run(id=rid, name=name, status=status, conclusion=conclusion, event=event, head_sha=sha)


def test_success_the_tag_ci_gate_says_not_found_yet_when_no_pull_request_is_listed():
    v = tp.tag_ci(C1, [run(1, "CI", status="in_progress", conclusion=None)], True, REQ, [], {}, {})
    assert v.state == "not_green" and "the proof is not found yet" in v.line, v


def test_failure_a_listed_head_on_another_tree_keeps_the_tag_ci_gates_tree_message():
    v = tp.tag_ci(C1, [run(1, "CI", status="in_progress", conclusion=None)], True, REQ, [(734, H1, False)], {}, {})
    assert "no merged pull request head has the tree" in v.line and "not found yet" not in v.line, v


def test_edge_no_runs_and_no_pull_request_listed_is_the_none_state_with_the_not_yet_reason():
    v = tp.tag_ci(C1, [], True, REQ, [], {}, {})
    assert v.state == "none" and "the proof is not found yet" in v.line, v


def test_edge_a_red_run_on_the_commit_is_reported_before_the_missing_pull_request():
    v = tp.tag_ci(C1, [run(1, "CI", conclusion="failure")], True, REQ, [], {}, {})
    assert "red on 111111111 itself" in v.line and "not found yet" not in v.line, v


# ── ready: the hook's two queries, for the release train to poll ───────────


def world(pulls=True, head_run_status="completed", own_status="in_progress", tree_h="t1"):
    """GitHub just after a release pull request merged: the merge commit's own
    runs are in flight; its head H1 passed everything."""
    answers = {
        "repos/o/r/rules/branches/main": (0, "CI success\nlicense/cla\n"),
        "repos/o/r/branches/main/protection": (1, "Branch not protected"),
        "repos/o/r/compare/": (0, "identical\n"),
        f"repos/o/r/commits/{C1}/check-runs": (0, ""),
        f"repos/o/r/commits/{C1}/status": (0, ""),
        f"repos/o/r/commits/{C1}/pulls": (0, f"734\t{H1}\n" if pulls else ""),
        f"repos/o/r/git/commits/{C1}": (0, "t1\n"),
        f"repos/o/r/git/commits/{H1}": (0, f"{tree_h}\n"),
        f"repos/o/r/commits/{H1}/check-runs": (0, "CI success\t2026-11-10T07:20:00Z\tsuccess\n"),
        f"repos/o/r/commits/{H1}/status": (0, "license/cla\tsuccess\n"),
    }

    def gh(path, jq=None, paginate=False):
        for prefix, (rc, out) in answers.items():
            if path.startswith(prefix):
                return rc, out
        return 1, ""

    def run_list(sha):
        import json
        if sha == C1:
            rows = [{"databaseId": 5, "headSha": C1, "status": own_status,
                     "conclusion": "success" if own_status == "completed" else None, "name": "CI", "event": "push"}]
        else:
            rows = [{"databaseId": 4, "headSha": H1, "status": head_run_status,
                     "conclusion": "success" if head_run_status == "completed" else None,
                     "name": "CI", "event": "pull_request"}]
        return 0, json.dumps(rows)

    return gh, run_list


def test_success_ready_when_the_head_proves_both_of_the_hooks_queries():
    ok, lines = tp.ready("o/r", C1, {}, *world())
    assert ok, lines


def test_success_ready_names_the_pull_request_in_both_lines():
    _ok, lines = tp.ready("o/r", C1, {}, *world())
    assert len(lines) == 2 and all("PR #734" in line for line in lines), lines


def test_success_ready_when_the_commits_own_checks_and_runs_are_green():
    gh, _ = world(own_status="completed")

    def own_green(path, jq=None, paginate=False):
        if path.startswith(f"repos/o/r/commits/{C1}/check-runs"):
            return 0, "CI success\t2026-11-10T07:40:00Z\tsuccess\n"
        if path.startswith(f"repos/o/r/commits/{C1}/status"):
            return 0, "license/cla\tsuccess\n"
        return gh(path, jq, paginate)

    ok, lines = tp.ready("o/r", C1, {}, own_green, world(own_status="completed")[1])
    assert ok and "PR #" not in lines[0], lines


def test_failure_not_ready_while_github_lists_no_pull_request_for_the_merge_commit():
    ok, lines = tp.ready("o/r", C1, {}, *world(pulls=False))
    assert not ok and "the proof is not found yet" in lines[0] and "the proof is not found yet" in lines[1], lines


def test_failure_not_ready_while_a_workflow_on_the_head_is_still_running():
    # `decide` is satisfied by the required checks; the tag CI gate also needs
    # every workflow run on the head, and the hook would refuse the push.
    ok, lines = tp.ready("o/r", C1, {}, *world(head_run_status="in_progress"))
    assert not ok and "tree gates are skipped" in lines[0] and "workflow runs not_green" in lines[1], lines


def test_failure_not_ready_when_the_head_has_another_tree():
    ok, _lines = tp.ready("o/r", C1, {}, *world(tree_h="t2"))
    assert not ok


def test_failure_not_ready_when_origin_is_not_github():
    ok, lines = tp.ready(None, C1, {}, *world())
    assert not ok and "not a GitHub repository" in lines[0], lines


def test_failure_not_ready_when_the_run_list_cannot_be_read():
    gh, _ = world()
    ok, lines = tp.ready("o/r", C1, {}, gh, lambda sha: (1, ""))
    assert not ok, lines


def test_edge_not_ready_under_no_cache_because_the_hook_would_run_every_gate():
    ok, lines = tp.ready("o/r", C1, {"SIPNAB_GATE_NO_CACHE": "1"}, *world())
    assert not ok and "SIPNAB_GATE_NO_CACHE" in lines[0], lines


def cli(*args, stdin=""):
    import pathlib
    import subprocess
    import sys
    script = pathlib.Path(__file__).resolve().parents[1] / "tag-push-proof.py"
    return subprocess.run([sys.executable, str(script), *args], input=stdin, capture_output=True, text=True,
                          timeout=60, check=False)


def test_failure_ready_with_an_abbreviated_commit_is_a_usage_error():
    out = cli("--ready", "88f46bb83")
    assert out.returncode == 2 and "--ready <40-hex commit>" in out.stderr, out


def test_edge_ready_with_no_commit_is_a_usage_error():
    assert cli("--ready").returncode == 2


def test_edge_ready_reports_through_main_with_exit_1_when_not_ready(monkeypatch, capsys):
    monkeypatch.setattr(tp, "ready", lambda repo, commit, env, gh, run_list: (False, ["a", "b"]))
    monkeypatch.setattr(tp.sys, "argv", ["tag-push-proof.py", "--ready", C1])
    assert tp.main() == 1
    assert capsys.readouterr().out == "a\nb\n"


def test_success_ready_reports_through_main_with_exit_0_when_ready(monkeypatch, capsys):
    seen = []
    monkeypatch.setattr(tp, "ready", lambda repo, commit, env, gh, run_list: (seen.append(commit) or True, ["a"]))
    monkeypatch.setattr(tp.sys, "argv", ["tag-push-proof.py", "--ready", C1])
    assert tp.main() == 0 and seen == [C1]


# ── delivery_hint: what the hook says when the release-delivery test refuses ─

HEAD_OLD = "4" * 40


def test_success_a_branch_push_keeps_the_changelog_hint():
    text = "\n".join(tp.delivery_hint([], False, HEAD_OLD))
    assert "[Unreleased] section in CHANGELOG.md" in text and "work sits past the last tag" in text, text


def test_success_a_tag_push_from_another_checkout_names_both_commits_and_the_command():
    text = "\n".join(tp.delivery_hint([C1], False, HEAD_OLD))
    assert "this checkout is at 444444444" in text and "111111111" in text, text
    assert f"git checkout --detach {C1}" in text, text


def test_success_a_tag_push_from_another_checkout_does_not_name_the_changelog():
    assert "CHANGELOG" not in "\n".join(tp.delivery_hint([C1], False, HEAD_OLD))


def test_success_a_tag_push_with_a_pending_proof_says_so_and_to_push_again():
    text = "\n".join(tp.delivery_hint([C1], True, C1))
    assert "proof is not found yet" in text and "push again" in text and "CHANGELOG" not in text, text


def test_failure_a_tag_push_at_the_tagged_commit_with_its_proof_names_the_test_not_the_changelog():
    text = "\n".join(tp.delivery_hint([C1], False, C1))
    assert "refused the tagged commit" in text and "release_delivery_test" in text and "CHANGELOG" not in text, text


def test_failure_a_pending_proof_and_another_checkout_names_both_causes():
    # 0.5.243's first attempt: both were true at once.
    text = "\n".join(tp.delivery_hint([C1], True, HEAD_OLD))
    assert "this checkout is at 444444444" in text and "proof is not found yet" in text, text


def test_failure_another_checkout_without_a_pending_proof_does_not_mention_the_proof():
    assert "proof" not in "\n".join(tp.delivery_hint([C1], False, HEAD_OLD))


def test_failure_a_branch_push_never_gets_the_pending_text_whatever_the_flag():
    text = "\n".join(tp.delivery_hint([], True, HEAD_OLD))
    assert "CHANGELOG.md" in text and "proof" not in text, text


def test_edge_an_unknown_head_claims_no_mismatch():
    text = "\n".join(tp.delivery_hint([C1], False, ""))
    assert "this checkout is at" not in text and "refused the tagged commit" not in text, text


def test_edge_of_two_tags_the_one_the_checkout_is_not_at_is_named():
    c2 = "2" * 40
    text = "\n".join(tp.delivery_hint([C1, c2], False, C1))
    assert "the pushed tag marks 222222222" in text and f"git checkout --detach {c2}" in text, text


def test_edge_every_hint_starts_with_the_push_blocked_headline():
    for args in (([], False, ""), ([C1], False, HEAD_OLD), ([C1], True, C1), ([C1], False, C1), ([C1], False, "")):
        assert tp.delivery_hint(*args)[0].startswith("Push blocked: "), args


def test_success_the_hint_command_reads_the_pushed_tags_from_stdin(tmp_path):
    # In a repository where the pushed sha is not an object, the tag's commit
    # is the pushed sha itself: the command line is what is tested here.
    out = cli("--delivery-hint", "0", HEAD_OLD, stdin=f"refs/tags/v1 {C1} refs/tags/v1 {Z}\n")
    assert out.returncode == 0 and "this checkout is at 444444444" in out.stdout, out


def test_success_the_hint_command_passes_the_pending_flag():
    out = cli("--delivery-hint", "1", C1, stdin=f"refs/tags/v1 {C1} refs/tags/v1 {Z}\n")
    assert out.returncode == 0 and "proof is not found yet" in out.stdout, out


def test_failure_the_hint_command_refuses_a_flag_that_is_not_0_or_1():
    assert cli("--delivery-hint", "yes", C1, stdin="").returncode == 2


def test_edge_the_hint_command_accepts_an_empty_head():
    out = cli("--delivery-hint", "0", "", stdin=f"refs/tags/v1 {C1} refs/tags/v1 {Z}\n")
    assert out.returncode == 0 and "refused this tag push" in out.stdout, out


def test_success_an_annotated_tag_is_resolved_to_the_commit_it_marks():
    line = f"refs/tags/v1 {T1} refs/tags/v1 {Z}\n"
    assert tp.pushed_tag_commits(line, {T1: C1}.get) == [C1]


def test_failure_a_push_that_also_updates_a_branch_has_no_tag_commits():
    text = f"refs/tags/v1 {T1} refs/tags/v1 {Z}\nrefs/heads/main {C1} refs/heads/main {Z}\n"
    assert tp.pushed_tag_commits(text, {T1: C1}.get) == []


def test_failure_a_malformed_ref_line_has_no_tag_commits():
    assert tp.pushed_tag_commits("refs/tags/v1 only-two\n", {}.get) == []


def test_edge_a_deleted_tag_marks_no_commit():
    assert tp.pushed_tag_commits(f"(delete) {Z} refs/tags/v1 {C1}\n", {}.get) == []


def test_edge_two_tags_on_one_commit_name_it_once():
    text = f"refs/tags/v1 {T1} refs/tags/v1 {Z}\nrefs/tags/v2 {'b' * 40} refs/tags/v2 {Z}\n"
    assert tp.pushed_tag_commits(text, lambda sha: C1) == [C1]


def test_edge_a_sha_git_cannot_resolve_stands_for_itself():
    assert tp.pushed_tag_commits(f"refs/tags/v1 {T1} refs/tags/v1 {Z}\n", lambda sha: None) == [T1]


def test_edge_an_empty_push_has_no_tag_commits():
    assert tp.pushed_tag_commits("", {}.get) == []


def test_edge_ready_asks_git_and_gh_from_the_scripts_own_checkout_not_the_callers_directory(monkeypatch, tmp_path):
    # The release train runs it from whatever directory the operator is in.
    # Measured from /tmp: git found no origin, and `gh run list` no repository.
    import os
    monkeypatch.chdir(tmp_path)
    where = []
    monkeypatch.setattr(tp, "_git", lambda *args: where.append(os.getcwd()) or "https://github.com/o/r.git")
    monkeypatch.setattr(tp, "ready", lambda repo, commit, env, gh, run_list: (where.append(os.getcwd()) or True, []))
    monkeypatch.setattr(tp.sys, "argv", ["tag-push-proof.py", "--ready", C1])
    assert tp.main() == 0
    assert where == [tp.HERE, tp.HERE], where
