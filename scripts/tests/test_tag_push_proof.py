# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""A push of tags only skips the tree gates when GitHub already proved the commit.

The 0.5.237 tag push spent 1,269 s re-running clippy, rustdoc, the fuzz and
BPF clippy runs, vale and codespell on a commit that had already passed every
required check as a pull request and was merged to main. The tree gates judge
a tree; a tag names a tree CI has judged. scripts/tag-push-proof.py's `decide`
is the one rule: the push skips the tree gates only when every ref it updates
is a tag, every tagged commit is on main, and every required check of that
commit concluded `success`. Anything it cannot establish means the full gates.
"""

import pytest
from conftest import load

tp = load("tag-push-proof")

Z = "0" * 40
C1 = "1" * 40
C2 = "2" * 40
T1 = "a" * 40
REQ = ["CI success", "license/cla"]


def ref(remote="refs/tags/v0.5.237", local=T1, commit=C1):
    return tp.Ref(local_ref=remote, local_sha=local, remote_ref=remote, remote_sha=Z, commit=commit)


def green(*extra_runs, statuses=(("license/cla", "success"),)):
    return tp.Checks(runs=[("CI success", "2026-11-08T04:00:00Z", "success"), *extra_runs], statuses=list(statuses))


def decide(refs, contains=None, checks=None, required=REQ):
    commits = {r.commit for r in refs if r.commit}
    contains = {c: True for c in commits} if contains is None else contains
    checks = {c: green() for c in commits} if checks is None else checks
    return tp.decide(refs, contains, checks, required)


# ── SUCCESS ────────────────────────────────────────────────────────────────


def test_a_tag_on_a_merged_green_commit_skips_the_tree_gates():
    proof = decide([ref()])
    assert proof.skip, proof.line


def test_the_line_names_the_commit_the_check_count_and_main():
    line = decide([ref()]).line
    assert "1111111" in line and "2 required checks" in line and "origin/main" in line, line


def test_two_tags_on_two_proven_commits_skip_and_both_are_named():
    proof = decide([ref(commit=C1), ref(remote="refs/tags/v0.5.238", local="b" * 40, commit=C2)])
    assert proof.skip and "1111111" in proof.line and "2222222" in proof.line, proof.line


def test_an_annotated_tag_is_judged_by_the_commit_it_marks():
    proof = decide([ref(local=T1, commit=C1)], contains={C1: True}, checks={C1: green()})
    assert proof.skip and "aaaaaaa" not in proof.line


def test_a_required_context_met_by_a_commit_status_counts():
    checks = {C1: tp.Checks(runs=[("CI success", "t", "success")], statuses=[("license/cla", "success")])}
    assert decide([ref()], checks=checks).skip


def test_only_the_latest_run_of_a_name_counts_when_it_passed():
    checks = {C1: green(("CI success", "2026-11-08T03:00:00Z", "failure"))}
    assert decide([ref()], checks=checks).skip


# ── FAILURE: anything not proven runs the full gates ───────────────────────


def test_a_branch_in_the_push_runs_the_full_gates():
    proof = decide([ref(remote="refs/heads/main")])
    assert not proof.skip and "refs/heads/main" in proof.line


def test_a_tag_pushed_with_a_branch_runs_the_full_gates():
    assert not decide([ref(), ref(remote="refs/heads/release/0.5.238", commit=C2)]).skip


def test_a_commit_not_on_main_runs_the_full_gates():
    proof = decide([ref()], contains={C1: False})
    assert not proof.skip and "not on origin/main" in proof.line


def test_ancestry_that_could_not_be_established_runs_the_full_gates():
    proof = decide([ref()], contains={C1: None})
    assert not proof.skip and "could not tell" in proof.line


def test_check_runs_that_could_not_be_read_run_the_full_gates():
    assert not decide([ref()], checks={C1: None}).skip


def test_a_required_list_that_could_not_be_read_runs_the_full_gates():
    assert not decide([ref()], required=None).skip


def test_no_required_checks_proves_nothing():
    assert not decide([ref()], required=[]).skip


def test_a_missing_required_check_runs_the_full_gates_and_is_named():
    checks = {C1: tp.Checks(runs=[("CI success", "t", "success")], statuses=[])}
    proof = decide([ref()], checks=checks)
    assert not proof.skip and "license/cla: missing" in proof.line, proof.line


def test_a_failed_required_check_runs_the_full_gates():
    checks = {C1: tp.Checks(runs=[("CI success", "t", "failure")], statuses=[("license/cla", "success")])}
    proof = decide([ref()], checks=checks)
    assert not proof.skip and "CI success: failure" in proof.line


@pytest.mark.parametrize("conclusion", ["neutral", "skipped", "cancelled", "timed_out", "action_required"])
def test_a_conclusion_other_than_success_runs_the_full_gates(conclusion):
    checks = {C1: tp.Checks(runs=[("CI success", "t", conclusion)], statuses=[("license/cla", "success")])}
    assert not decide([ref()], checks=checks).skip


def test_a_required_check_still_running_runs_the_full_gates():
    checks = {C1: green(("CI success", None, "in_progress"))}
    assert not decide([ref()], checks=checks).skip


def test_a_later_failure_overrides_an_earlier_success():
    checks = {C1: green(("CI success", "2026-11-08T05:00:00Z", "failure"))}
    assert not decide([ref()], checks=checks).skip


def test_a_pending_status_runs_the_full_gates():
    checks = {C1: green(statuses=(("license/cla", "pending"),))}
    assert not decide([ref()], checks=checks).skip


def test_one_unproven_tag_among_proven_ones_runs_the_full_gates():
    refs = [ref(commit=C1), ref(remote="refs/tags/v0.5.238", local="b" * 40, commit=C2)]
    assert not decide(refs, contains={C1: True, C2: False}).skip


def test_a_tagged_commit_that_could_not_be_resolved_runs_the_full_gates():
    assert not decide([ref(commit=None)], contains={}, checks={}).skip


# ── EDGE ───────────────────────────────────────────────────────────────────


def test_an_empty_push_runs_the_full_gates():
    assert not decide([]).skip


def test_a_push_that_only_deletes_tags_proves_nothing_and_runs_the_full_gates():
    assert not decide([ref(local=Z, commit=None)], contains={}, checks={}).skip


def test_a_deletion_beside_a_proven_tag_does_not_block_the_skip():
    refs = [ref(), ref(remote="refs/tags/v0.0.1", local=Z, commit=None)]
    assert decide(refs).skip


def test_any_tag_name_counts_as_a_tag():
    assert decide([ref(remote="refs/tags/nightly-2026-11-08")]).skip


def test_a_ref_that_only_starts_like_a_tag_is_not_one():
    assert not decide([ref(remote="refs/tagsx/v1")]).skip


def test_two_tags_on_one_commit_ask_about_it_once():
    asked = []

    class Spy(dict):
        def get(self, k, d=None):
            asked.append(k)
            return super().get(k, d)

    refs = [ref(), ref(remote="refs/tags/v0.5.237-rc", local="c" * 40)]
    proof = tp.decide(refs, Spy({C1: True}), {C1: green()}, REQ)
    assert proof.skip and asked == [C1]


def test_a_context_is_matched_by_its_exact_name():
    checks = {C1: tp.Checks(runs=[("ci success", "t", "success")], statuses=[("license/cla", "success")])}
    assert not decide([ref()], checks=checks).skip


# ── Reading the inputs ─────────────────────────────────────────────────────


def test_pushed_refs_are_read_from_the_hooks_stdin():
    text = f"refs/tags/v1 {T1} refs/tags/v1 {Z}\n\nrefs/heads/x {C2} refs/heads/x {C1}\n"
    assert tp.parse_refs(text) == [
        ("refs/tags/v1", T1, "refs/tags/v1", Z),
        ("refs/heads/x", C2, "refs/heads/x", C1),
    ]


def test_a_malformed_ref_line_is_refused():
    assert tp.parse_refs("refs/tags/v1 only-two\n") is None


@pytest.mark.parametrize(
    "url",
    ["https://github.com/NormB/sipnab.git", "github.com:NormB/sipnab.git", "ssh://github.com/NormB/sipnab"],
)
def test_the_github_repository_is_read_from_the_remote_url(url):
    assert tp.github_repo(url) == "NormB/sipnab"


def test_a_remote_that_is_not_github_has_no_repository():
    assert tp.github_repo("https://gitlab.example.com/a/b.git") is None


def gh_stub(answers):
    """A gh runner: maps an API path to (exit status, output)."""

    def run(path, jq=None, paginate=False):
        for prefix, (rc, out) in answers.items():
            if path.startswith(prefix):
                return rc, out
        return 1, ""

    return run


def test_main_contains_a_commit_that_compare_reports_behind_or_identical():
    for status in ("behind", "identical"):
        gh = gh_stub({"repos/o/r/compare/": (0, f'"{status}"')})
        assert tp.on_main("o/r", C1, gh) is True


def test_main_does_not_contain_a_commit_that_compare_reports_ahead_or_diverged():
    for status in ("ahead", "diverged"):
        gh = gh_stub({"repos/o/r/compare/": (0, f'"{status}"')})
        assert tp.on_main("o/r", C1, gh) is False


def test_a_failed_gh_call_is_an_unknown_answer():
    gh = gh_stub({})
    assert tp.on_main("o/r", C1, gh) is None
    assert tp.read_checks("o/r", C1, gh) is None
    assert tp.read_required("o/r", gh) is None


def test_the_required_list_joins_rulesets_and_branch_protection():
    gh = gh_stub({
        "repos/o/r/rules/branches/main": (0, "CI success\nlicense/cla\n"),
        "repos/o/r/branches/main/protection": (0, "CI success\n"),
    })
    assert tp.read_required("o/r", gh) == ["CI success", "license/cla"]


def test_an_unprotected_branch_adds_no_contexts_rather_than_failing():
    gh = gh_stub({
        "repos/o/r/rules/branches/main": (0, "CI success\n"),
        "repos/o/r/branches/main/protection": (1, "gh: Branch not protected (HTTP 404)"),
    })
    assert tp.read_required("o/r", gh) == ["CI success"]


def test_check_runs_and_statuses_are_read_as_tab_separated_rows():
    gh = gh_stub({
        f"repos/o/r/commits/{C1}/check-runs": (0, "CI success\t2026-11-08T04:00:00Z\tsuccess\nlint\t~\tin_progress\n"),
        f"repos/o/r/commits/{C1}/status": (0, "license/cla\tsuccess\n"),
    })
    checks = tp.read_checks("o/r", C1, gh)
    assert checks.runs == [("CI success", "2026-11-08T04:00:00Z", "success"), ("lint", None, "in_progress")]
    assert checks.statuses == [("license/cla", "success")]


def proving_gh():
    """A GitHub on which C1 is on main and passed both required checks."""
    return gh_stub({
        "repos/o/r/rules/branches/main": (0, "CI success\nlicense/cla\n"),
        "repos/o/r/branches/main/protection": (1, "Branch not protected"),
        "repos/o/r/compare/": (0, "behind\n"),
        f"repos/o/r/commits/{C1}/check-runs": (0, "CI success\t2026-11-08T04:00:00Z\tsuccess\n"),
        f"repos/o/r/commits/{C1}/status": (0, "license/cla\tsuccess\n"),
    })


def test_no_cache_turns_the_skip_off():
    assert tp.main_decision([ref()], {}, "o/r", proving_gh()).skip is True
    assert tp.main_decision([ref()], {"SIPNAB_GATE_NO_CACHE": "1"}, "o/r", proving_gh()).skip is False


# ── A merge commit is proven by its pull request's head, on the same tree ───
#
# Measured on v0.5.237: its commit b255c4f28 is the merge of PR #694, and two of
# main's required contexts (the PR-text check and license/cla) run on the PR's
# head 8ae7313e2, never on the merge commit. Both commits have tree 6644a32b9.
# Without this, the rule failed closed on every real release.

H1 = "8" * 40
PR_ONLY = tp.Checks(runs=[("CI success", "t", "success")], statuses=[])


def test_a_merge_commit_is_proven_by_its_pr_head_on_the_same_tree():
    proof = tp.decide([ref()], {C1: True}, {C1: PR_ONLY, H1: green()}, REQ, {C1: [(694, H1, True)]})
    assert proof.skip and "PR #694" in proof.line and "888888888" in proof.line, proof.line


def test_a_pr_head_on_another_tree_proves_nothing():
    proof = tp.decide([ref()], {C1: True}, {C1: PR_ONLY, H1: green()}, REQ, {C1: [(694, H1, False)]})
    assert not proof.skip and "license/cla: missing" in proof.line


def test_a_pr_head_with_a_failed_check_proves_nothing():
    bad = tp.Checks(runs=[("CI success", "t", "failure")], statuses=[("license/cla", "success")])
    proof = tp.decide([ref()], {C1: True}, {C1: PR_ONLY, H1: bad}, REQ, {C1: [(694, H1, True)]})
    assert not proof.skip


def test_a_pr_head_whose_checks_could_not_be_read_proves_nothing():
    proof = tp.decide([ref()], {C1: True}, {C1: PR_ONLY, H1: None}, REQ, {C1: [(694, H1, True)]})
    assert not proof.skip


def test_a_commit_green_on_its_own_needs_no_pull_request():
    proof = tp.decide([ref()], {C1: True}, {C1: green()}, REQ, {})
    assert proof.skip and "PR #" not in proof.line


def test_the_merged_pull_request_and_both_trees_are_read_from_github():
    gh = gh_stub({
        f"repos/o/r/commits/{C1}/pulls": (0, f"694\t{H1}\n"),
        f"repos/o/r/git/commits/{C1}": (0, "6644a32b9\n"),
        f"repos/o/r/git/commits/{H1}": (0, "6644a32b9\n"),
    })
    assert tp.read_pr_heads("o/r", C1, gh) == [(694, H1, True)]


def test_a_pr_head_on_a_different_tree_is_read_as_such():
    gh = gh_stub({
        f"repos/o/r/commits/{C1}/pulls": (0, f"694\t{H1}\n"),
        f"repos/o/r/git/commits/{C1}": (0, "aaaa\n"),
        f"repos/o/r/git/commits/{H1}": (0, "bbbb\n"),
    })
    assert tp.read_pr_heads("o/r", C1, gh) == [(694, H1, False)]


def test_a_failed_pull_request_lookup_offers_no_head():
    assert tp.read_pr_heads("o/r", C1, gh_stub({})) == []
