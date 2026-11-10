#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors
"""May a push of tags only skip the pre-push hook's tree gates?

    tag-push-proof.py < <pre-push stdin>
    tag-push-proof.py --tag-ci <commit>
    tag-push-proof.py --ready <commit>
    tag-push-proof.py --delivery-hint <0|1> <HEAD> < <pre-push stdin>

The 0.5.237 tag push (heavy-run job 2-1794110542899233376-466881, 04:03:43Z
to 04:24:52Z) took 1,269 s. Its pre-push hook re-ran clippy, rustdoc, the fuzz
and BPF clippy runs, vale and codespell on b255c4f28, a commit that had passed
every required GitHub check as PR #694 and was merged to main. The tree gates
judge a tree. A tag names a tree that CI has already judged.

THE RULE (`decide`, the one place it is written). The tree gates are skipped
only when all of these hold:

* the push updates tag refs (refs/tags/...) and nothing else;
* it creates or moves at least one tag (a push of deletions proves nothing);
* every tagged commit is on main, as GitHub's compare API reports it
  ("behind" or "identical");
* every check main requires (its rulesets and its branch protection, as
  ~/Development/bin/required-checks reads them) concluded `success` on that
  commit: the latest check run of that name, or the commit status of that
  context. `neutral`, `skipped`, a run still in progress, a pending status
  and a missing check all fail it.
* OR, for a merge commit: the head of the merged pull request it is the merge
  commit of has the SAME TREE (GitHub's git/commits API) and every required
  check concluded `success` on that head. Two of main's required contexts, the
  PR-text check and license/cla, run only on a pull request's head: on
  v0.5.237's b255c4f28, the merge of PR #694, both are missing, while its
  head 8ae7313e2 has all of them and the same tree, 6644a32b9.

Anything this cannot establish -- gh missing or offline, a remote that is not
GitHub, an API error, a ref it cannot resolve -- means the full gates: it
fails closed. SIPNAB_GATE_NO_CACHE=1 means the full gates too.

The tag-specific gates still run either way: the tag signature, the
release-delivery test and the tag's CI-status and code-scanning checks.

Exit 0 and one line naming the proof (each commit, the number of required
checks, and that origin/main contains it) when the tree gates may be skipped;
exit 1 and one line saying why not otherwise.

NOT FOUND YET (RELEASE-TRAIN-TAG-RACE). GitHub lists a merged pull request
for its merge commit some time after the merge. The v0.5.243 tag was pushed
one second after PR #734 merged as 88f46bb83, and the answer was "CI success:
missing, ... license/cla: missing"; five minutes later the same query found
the proof. A commit on main that its own checks do not prove, with no merged
pull request listed, is `pending`: the line says the proof is not found yet,
and the exit status is 3. Every gate still runs.

`--ready <commit>` asks both of the hook's questions about a commit before
any tag exists (this rule and `--tag-ci`), for scripts/release-train.py to
poll: exit 0 when a tag on the commit would take the fast path now.

`--delivery-hint` prints what the hook says when the release-delivery test
refuses a push (`delivery_hint`).
"""

from __future__ import annotations

import dataclasses
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ZERO = "0" * 40
MAIN = "main"
TAG_PREFIX = "refs/tags/"


@dataclasses.dataclass(frozen=True)
class Ref:
    """One line of pre-push's stdin, with the commit its local sha marks."""

    local_ref: str
    local_sha: str
    remote_ref: str
    remote_sha: str
    commit: str | None


@dataclasses.dataclass(frozen=True)
class Checks:
    """A commit's check runs as (name, completed_at or None, conclusion or
    status) and its commit statuses as (context, state)."""

    runs: list
    statuses: list


@dataclasses.dataclass(frozen=True)
class Proof:
    """`pending` marks a refusal that waiting can cure: GitHub does not yet
    list the merged pull request whose head would prove the commit."""

    skip: bool
    line: str
    pending: bool = False


# Exit status of the hook's query for a refusal that is `pending`.
PENDING_EXIT = 3


def exit_status(proof: Proof) -> int:
    """0 the tree gates may be skipped; 3 not yet (`pending`); 1 no."""
    if proof.skip:
        return 0
    return PENDING_EXIT if proof.pending else 1


def _short(sha: str) -> str:
    return sha[:9]


def _verdict(checks: Checks, context: str) -> str:
    """`success`, or what the context shows instead (`missing` when nothing)."""
    runs = [r for r in checks.runs if r[0] == context]
    if runs:
        # The latest run counts; one with no completion time is still going,
        # so it sorts last, as required-checks sorts it.
        latest = sorted(runs, key=lambda r: r[1] or "~")[-1]
        if latest[2] == "success":
            return "success"
        run_result = latest[2]
    else:
        run_result = None
    states = [s[1] for s in checks.statuses if s[0] == context]
    if "success" in states:
        return "success"
    return run_result or (states[0] if states else "missing")


def _not_yet(commit: str) -> str:
    """What `decide` and `tag_ci` say when no merged pull request is listed
    for a commit. On 0.5.243 GitHub listed PR #734 for its merge commit
    88f46bb83 some time after the merge: not one second after it, and by the
    time the query was made again five minutes later."""
    return (f"the proof is not found yet: GitHub lists no merged pull request for {_short(commit)}, "
            "which it can take some seconds after a merge to do (wait, then push again)")


def _unmet(got: Checks | None, required: list[str]) -> list[str] | None:
    """The required contexts `got` does not show as success; None if unreadable."""
    if got is None:
        return None
    return [f"{ctx}: {v}" for ctx in required if (v := _verdict(got, ctx)) != "success"]


def _proving_heads(heads: list, checks: dict, required: list[str]) -> list[tuple[int, str]]:
    """(number, head sha) of each merged pull request head, in order, that has
    the same tree as the commit and on which every required check concluded
    `success`. The one place a head is accepted for a merge commit: `decide`
    and `tag_ci` both read it."""
    return [(n, h) for n, h, same_tree in heads if same_tree and _unmet(checks.get(h), required) == []]


def decide(
    refs: list[Ref], contains: dict, checks: dict, required: list[str] | None, heads: dict | None = None
) -> Proof:
    """The rule. `contains` maps a commit to True, False or None (unknown);
    `checks` maps a commit to its Checks or None (unreadable); `required` is
    main's required contexts, None when they could not be read. `heads` maps a
    tagged commit to the merged pull requests it is the merge commit of, as
    (number, head sha, same tree as the commit): a head on the same tree whose
    required checks all succeeded proves the commit, because two of main's
    required contexts run only on a pull request's head."""
    heads = heads or {}
    full = "  tag-only push: the full gates run --"
    if not refs:
        return Proof(False, f"{full} nothing is being pushed")
    branches = [r.remote_ref for r in refs if not r.remote_ref.startswith(TAG_PREFIX)]
    if branches:
        return Proof(False, f"{full} the push also updates {branches[0]}")
    created = [r for r in refs if r.local_sha != ZERO]
    if not created:
        return Proof(False, f"{full} the push only deletes tags, so no commit is proven")
    if any(r.commit is None for r in created):
        return Proof(False, f"{full} a tag's commit could not be resolved")
    if required is None:
        return Proof(False, f"{full} main's required checks could not be read")
    if not required:
        return Proof(False, f"{full} main requires no checks, so nothing proves the commit")
    commits = list(dict.fromkeys(r.commit for r in created))
    proven: dict[str, str] = {}
    for c in commits:
        answer = contains.get(c)
        if answer is None:
            return Proof(False, f"{full} could not tell whether origin/main contains {_short(c)}")
        if answer is not True:
            return Proof(False, f"{full} {_short(c)} is not on origin/main")
        bad = _unmet(checks.get(c), required)
        if bad == []:
            proven[c] = _short(c)
            continue
        via = next(iter(_proving_heads(heads.get(c, []), checks, required)), None)
        if via:
            proven[c] = f"{_short(c)} (merge of PR #{via[0]}, head {_short(via[1])}, same tree)"
            continue
        if bad is None:
            return Proof(False, f"{full} the checks of {_short(c)} could not be read")
        if not heads.get(c):
            return Proof(False, f"{full} {_not_yet(c)}; on {_short(c)} itself, {', '.join(bad)}", pending=True)
        return Proof(False, f"{full} on {_short(c)}, {', '.join(bad)}")
    named = ", ".join(proven[c] for c in commits)
    return Proof(
        True,
        f"  tag-only push: {named} is on origin/main and passed all {len(required)} required checks "
        f"({', '.join(required)}) on GitHub; the tree gates are skipped",
    )


# ── The tag CI gate: the tagged commit's runs, or its PR head's ────────────
#
# The v0.5.238 tag waited 37 minutes for the workflow runs on its merge commit
# 26bfa26a8, which re-proved the tree PR #701's head f151b38d8 had proved
# (TAG-GATE-WAITS-FOR-MERGE-CI). `tag_ci` is the rule the pre-push tag gate
# applies to each tagged commit.

# A workflow conclusion that is a red verdict on the tree. "cancelled" is not
# one: a concurrency group or a newer push cancels runs without judging them.
RED = {"failure", "timed_out", "action_required", "startup_failure"}

# Exit status of `--tag-ci`, one per verdict, read by .githooks/pre-push.
TAG_CI_EXIT = {"green": 0, "head": 10, "none": 3, "not_green": 4, "unreadable": 5}


@dataclasses.dataclass(frozen=True)
class Run:
    """One workflow run, as `gh run list --json` reports it."""

    id: int
    name: str
    status: str
    conclusion: str | None
    event: str
    head_sha: str


@dataclasses.dataclass(frozen=True)
class TagCi:
    """`state` is a key of TAG_CI_EXIT; `via` is (PR number, head sha) when
    the head proved the commit; `line` says what was found."""

    state: str
    line: str
    via: tuple | None = None


def latest_runs(runs: list, sha: str) -> list:
    """The runs that speak for `sha`: its own (the headSha filter refuses to
    judge one commit by another's runs), scheduled ones set aside (a cron run
    judges whatever main pointed at when its clock fired, not this change;
    TAG-GATE-COUNTS-SCHEDULED-RUNS), and of those the newest of each workflow
    by id (GATE-DUP1: a duplicated event runs a workflow twice and the older
    run is canceled). The filter comes before the newest-per-name pick, so a
    newer scheduled pass cannot hide an older failed push run."""
    newest: dict[str, Run] = {}
    for r in runs:
        if r.head_sha != sha or r.event == "schedule":
            continue
        if r.name not in newest or r.id > newest[r.name].id:
            newest[r.name] = r
    return [newest[n] for n in sorted(newest)]


def _describe(r: Run) -> str:
    return f"{r.status}/{r.conclusion or '-'}/{r.name}"


def runs_verdict(runs: list | None, sha: str) -> tuple[str, list[str]]:
    """("green" | "none" | "not_green" | "unreadable", one line per run)."""
    if runs is None:
        return "unreadable", []
    mine = latest_runs(runs, sha)
    if not mine:
        return "none", []
    lines = [_describe(r) for r in mine]
    if all(r.status == "completed" and r.conclusion == "success" for r in mine):
        return "green", lines
    return "not_green", lines


def tag_ci(
    commit: str,
    own: list | None,
    contains: bool | None,
    required: list[str] | None,
    heads: list,
    checks: dict,
    head_runs: dict,
) -> TagCi:
    """The rule. `own` is the tagged commit's runs (None: unreadable);
    `contains`, `required`, `heads` and `checks` are as `decide` takes them;
    `head_runs` maps a head sha to its runs (None: unreadable).

    The commit passes on its own runs when they are all green. Otherwise a
    merged pull request head proves it when the commit is on main, the head
    has the same tree, every required check concluded `success` on the head,
    every workflow run on the head is green by the same rule as the commit's
    own runs (so the macOS leg, which `CI success` leaves out, still gates),
    and no run on the commit itself has concluded red."""
    own_state, own_lines = runs_verdict(own, commit)
    if own_state == "green":
        return TagCi("green", f"all {len(own_lines)} workflow runs on {_short(commit)} succeeded")
    why = _head_refusal(commit, own, contains, required, heads, checks, head_runs)
    if isinstance(why, tuple):
        (n, h), count = why
        return TagCi(
            "head",
            f"{_short(commit)} is on origin/main and is the merge of PR #{n}, whose head {_short(h)} has the "
            f"same tree and passed all {len(required)} required checks and all {count} workflow runs; "
            f"the runs on {_short(commit)} itself are not awaited",
            (n, h),
        )
    return _fallback(own_state, own_lines, why)


def _fallback(own_state: str, own_lines: list[str], why: str) -> TagCi:
    """The commit's own verdict, with the reason no head proved it."""
    own_text = "\n".join(own_lines)
    return TagCi(own_state, f"PR head proof not used: {why}" + (f"\n{own_text}" if own_text else ""))


def _head_refusal(commit, own, contains, required, heads, checks, head_runs):
    """((number, head), run count) of the head that proves `commit`, or the
    reason, as text, that none does."""
    if own is None:
        return f"the workflow runs on {_short(commit)} could not be read"
    if contains is None:
        return f"could not tell whether origin/main contains {_short(commit)}"
    if contains is not True:
        return f"{_short(commit)} is not on origin/main"
    if required is None:
        return "main's required checks could not be read"
    if not required:
        return "main requires no checks, so nothing proves the head"
    red = [r for r in latest_runs(own or [], commit) if r.status == "completed" and r.conclusion in RED]
    if red:
        return f"red on {_short(commit)} itself: {', '.join(_describe(r) for r in red)}"
    if not heads:
        return _not_yet(commit)
    same = [(n, h) for n, h, same_tree in heads if same_tree]
    if not same:
        return f"no merged pull request head has the tree of {_short(commit)}"
    reasons = []
    proven = set(_proving_heads(heads, checks, required))
    for n, h in same:
        if (n, h) not in proven:
            bad = _unmet(checks.get(h), required)
            reasons.append(f"PR #{n} head {_short(h)}: " + ("checks unreadable" if bad is None else ", ".join(bad)))
            continue
        state, lines = runs_verdict(head_runs.get(h), h)
        if state == "green":
            return (n, h), len(lines)
        reasons.append(f"PR #{n} head {_short(h)} workflow runs {state}: " + (", ".join(lines) or "none"))
    return "; ".join(reasons)


# ── Reading the inputs ─────────────────────────────────────────────────────


def parse_refs(text: str) -> list[tuple[str, str, str, str]] | None:
    """The four fields of each non-blank stdin line; None when a line is malformed."""
    out = []
    for line in text.splitlines():
        if not line.strip():
            continue
        fields = line.split()
        if len(fields) != 4:
            return None
        out.append(tuple(fields))
    return out


_GITHUB = re.compile(r"github\.com[:/]+([^/]+)/([^/]+?)(?:\.git)?/?$")


def github_repo(url: str) -> str | None:
    """owner/name from a GitHub remote URL, None for any other host."""
    m = _GITHUB.search(url.strip())
    return f"{m.group(1)}/{m.group(2)}" if m else None


def gh_api(path: str, jq: str | None = None, paginate: bool = False) -> tuple[int, str]:
    cmd = ["gh", "api", path]
    if paginate:
        cmd.append("--paginate")
    if jq:
        cmd += ["-q", jq]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False)
    except (OSError, subprocess.TimeoutExpired) as e:
        return 1, str(e)
    return out.returncode, out.stdout + (out.stderr if out.returncode else "")


def _lines(text: str) -> list[str]:
    return [line for line in text.splitlines() if line.strip()]


def on_main(repo: str, commit: str, gh) -> bool | None:
    rc, out = gh(f"repos/{repo}/compare/{MAIN}...{commit}", ".status")
    if rc != 0:
        return None
    status = out.strip().strip('"')
    if status in ("behind", "identical"):
        return True
    if status in ("ahead", "diverged"):
        return False
    return None


def read_required(repo: str, gh) -> list[str] | None:
    rc, rules = gh(
        f"repos/{repo}/rules/branches/{MAIN}",
        '.[] | select(.type == "required_status_checks") | .parameters.required_status_checks[].context',
        True,
    )
    if rc != 0:
        return None
    rc, protection = gh(f"repos/{repo}/branches/{MAIN}/protection", ".required_status_checks.contexts[]?")
    if rc != 0:
        if "Branch not protected" not in protection:
            return None
        protection = ""
    return sorted(set(_lines(rules)) | set(_lines(protection)))


def read_checks(repo: str, commit: str, gh) -> Checks | None:
    rc, runs = gh(
        f"repos/{repo}/commits/{commit}/check-runs?per_page=100",
        '.check_runs[] | [.name, (.completed_at // "~"), (.conclusion // .status)] | @tsv',
        True,
    )
    if rc != 0:
        return None
    rc, statuses = gh(f"repos/{repo}/commits/{commit}/status", ".statuses[] | [.context, .state] | @tsv")
    if rc != 0:
        return None
    rows = []
    for line in _lines(runs):
        f = line.split("\t")
        if len(f) != 3:
            return None
        rows.append((f[0], None if f[1] == "~" else f[1], f[2]))
    sts = []
    for line in _lines(statuses):
        f = line.split("\t")
        if len(f) != 2:
            return None
        sts.append((f[0], f[1]))
    return Checks(runs=rows, statuses=sts)


def read_pr_heads(repo: str, commit: str, gh) -> list:
    """(number, head sha, same tree) for each merged pull request whose merge
    commit is `commit`, trees as GitHub reports them; [] when unreadable."""
    rc, out = gh(
        f"repos/{repo}/commits/{commit}/pulls",
        f'.[] | select(.merged_at != null and .merge_commit_sha == "{commit}") | "\\(.number)\\t\\(.head.sha)"',
    )
    if rc != 0:
        return []
    found = []
    for line in _lines(out):
        f = line.split("\t")
        if len(f) != 2 or not f[0].isdigit():
            continue
        trees = []
        for sha in (commit, f[1]):
            trc, tree = gh(f"repos/{repo}/git/commits/{sha}", ".tree.sha")
            trees.append(tree.strip() if trc == 0 and tree.strip() else None)
        found.append((int(f[0]), f[1], trees[0] is not None and trees[0] == trees[1]))
    return found


def parse_runs(text: str) -> list | None:
    """`gh run list --json databaseId,headSha,status,conclusion,name,event`
    output as Runs; None when it is not that."""
    try:
        data = json.loads(text)
    except ValueError:
        return None
    if not isinstance(data, list):
        return None
    out = []
    for d in data:
        # As the jq rule this replaced read them: `.databaseId // 0`, and a
        # missing event is not "schedule". The name, status and commit are
        # what the verdict is about, so a run without them is unreadable.
        try:
            out.append(Run(int(d.get("databaseId") or 0), str(d["name"]), str(d["status"]), d.get("conclusion"),
                           str(d.get("event") or ""), str(d["headSha"])))
        except (AttributeError, KeyError, TypeError, ValueError):
            return None
    return out


def gh_run_list(sha: str) -> tuple[int, str]:
    """The workflow runs of one commit. Scoped by the FULL sha, not by
    recency: `--commit` returns nothing for an abbreviated one, and a window
    over the most recent runs lost older commits."""
    cmd = ["gh", "run", "list", "--commit", sha, "--limit", "50",
           "--json", "databaseId,headSha,status,conclusion,name,event"]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False)
    except (OSError, subprocess.TimeoutExpired) as e:
        return 1, str(e)
    return out.returncode, out.stdout


def _read_runs(run_list, sha: str) -> list | None:
    rc, out = run_list(sha)
    return parse_runs(out) if rc == 0 else None


def gather_tag_ci(repo: str | None, commit: str, gh, run_list) -> TagCi:
    """Gather the answers `tag_ci` needs, asking for a head proof only when
    the commit's own runs are not green, then apply it."""
    rc, out = run_list(commit)
    own = parse_runs(out) if rc == 0 else None
    if rc == 0 and own is None:
        # gh answered, and the answer is not a run list: refuse rather than
        # skip, since "gh unavailable" is the only case the hook lets through.
        return TagCi("not_green", f"gh run list answered for {_short(commit)} with something that is not a run list")
    if runs_verdict(own, commit)[0] == "green":
        return tag_ci(commit, own, None, None, [], {}, {})
    if repo is None:
        return _fallback(*runs_verdict(own, commit), "origin is not a GitHub repository")
    required = read_required(repo, gh)
    contains = on_main(repo, commit, gh)
    heads = read_pr_heads(repo, commit, gh)
    checks, head_runs = {}, {}
    for _n, h, same in heads:
        if same:
            checks[h] = read_checks(repo, h, gh)
            head_runs[h] = _read_runs(run_list, h)
    return tag_ci(commit, own, contains, required, heads, checks, head_runs)


def main_decision(refs: list[Ref], env: dict, repo: str | None, gh) -> Proof:
    """Gather the answers `decide` needs, then apply it."""
    if env.get("SIPNAB_GATE_NO_CACHE", "") not in ("", "0"):
        return Proof(False, "  tag-only push: the full gates run -- SIPNAB_GATE_NO_CACHE=1")
    if not refs or any(not r.remote_ref.startswith(TAG_PREFIX) for r in refs):
        return decide(refs, {}, {}, [])
    if repo is None:
        return Proof(False, "  tag-only push: the full gates run -- origin is not a GitHub repository")
    commits = {r.commit for r in refs if r.commit}
    required = read_required(repo, gh)
    contains = {c: on_main(repo, c, gh) for c in commits}
    checks = {c: read_checks(repo, c, gh) for c in commits}
    heads = {}
    for c in commits:
        if required and _unmet(checks.get(c), required) != []:
            heads[c] = read_pr_heads(repo, c, gh)
            for _n, h, same in heads[c]:
                if same:
                    checks[h] = read_checks(repo, h, gh)
    return decide(refs, contains, checks, required, heads)


def ready(repo: str | None, commit: str, env: dict, gh, run_list) -> tuple[bool, list[str]]:
    """Would the hook's fast path carry a tag on `commit` now? Both of the
    hook's queries, through the functions the hook's own calls end in:
    `main_decision` (the tree gates are skipped) and `gather_tag_ci` (the tag
    CI gate passes, on the commit's runs or its pull request head's).
    scripts/release-train.py polls this before it pushes the tag."""
    ref = Ref("refs/tags/ready", commit, "refs/tags/ready", ZERO, commit)
    proof = main_decision([ref], env, repo, gh)
    ci = gather_tag_ci(repo, commit, gh, run_list)
    return proof.skip and ci.state in ("green", "head"), [proof.line.strip(), f"tag CI gate: {ci.line}"]


# ── What the hook says when the release-delivery test refuses a push ───────

REPRODUCE = ["Reproduce with:", "    cargo test --features full --test release_delivery_test"]


def delivery_hint(tag_commits: list[str], pending: bool, head: str) -> list[str]:
    """The lines .githooks/pre-push prints under FAIL; the first is the
    headline. `tag_commits` is the commits the pushed tags mark (none for a
    push of branches), `pending` whether this push's proof was `pending`,
    `head` the commit the checkout is at ("" when unknown).

    For a tag, CHANGELOG.md is not the answer. On 0.5.243 the test failed
    because the checkout was at 4fae9a255, the main before the release, while
    the tag marked 88f46bb83: the test reads the files and the HEAD of the
    checkout it runs in."""
    elsewhere = [c for c in tag_commits if head and c != head]
    if elsewhere:
        also = [
            "The tag's proof is not found yet as well (the `tag-only push` line above):",
            "after the checkout, wait some seconds before the push.",
        ]
        return [
            f"Push blocked: this checkout is at {_short(head)}, and the pushed tag marks {_short(elsewhere[0])}.",
            "The release-delivery test reads the checkout it runs in, its files and its HEAD,",
            "so it judged a commit that is not the tagged one. Check out the tagged commit,",
            "then push again:",
            f"    git checkout --detach {elsewhere[0]}",
            *(also if pending else []),
        ]
    if tag_commits and pending:
        return [
            "Push blocked: the release-delivery test failed, and the tag's proof is not found yet.",
            "GitHub did not yet list the merged pull request for the tagged commit (the",
            "`tag-only push` line above), so every gate ran. Wait some seconds and push again:",
            "with the proof the tree gates are skipped. If this test fails again:",
            *REPRODUCE[1:],
        ]
    if tag_commits and not head:
        return ["Push blocked: the release-delivery test refused this tag push.", *REPRODUCE]
    if tag_commits:
        return [
            "Push blocked: the release-delivery test refused the tagged commit.",
            "The checkout is at that commit, so the test's own output says what it found.",
            *REPRODUCE,
        ]
    return [
        "Push blocked: work sits past the last tag and the tree does not say so.",
        *REPRODUCE,
        "Usually the fix is an [Unreleased] section in CHANGELOG.md naming what changed.",
    ]


def _git(*args) -> str | None:
    out = subprocess.run(["git", *args], capture_output=True, text=True, check=False)
    return out.stdout.strip() if out.returncode == 0 else None


def main_tag_ci(commit: str) -> int:
    """`--tag-ci <commit>`: print the tag CI gate's verdict on one commit and
    exit with its TAG_CI_EXIT status."""
    url = _git("remote", "get-url", "origin") or ""
    v = gather_tag_ci(github_repo(url), commit, gh_api, gh_run_list)
    print(v.line)
    return TAG_CI_EXIT[v.state]


USAGE = """usage: tag-push-proof.py < <pre-push stdin>
       tag-push-proof.py --tag-ci <40-hex commit>
       tag-push-proof.py --ready <40-hex commit>
       tag-push-proof.py --delivery-hint <0|1: the proof was pending> <HEAD or ""> < <pre-push stdin>"""


def pushed_tag_commits(text: str, resolve) -> list[str]:
    """The commits the pushed tags mark, in order and once each; `resolve`
    maps a pushed sha to its commit, or None. A push that also updates a
    branch, or that cannot be read, has none: the branch text applies."""
    raw = parse_refs(text)
    if not raw or any(not remote.startswith(TAG_PREFIX) for _l, _s, remote, _r in raw):
        return []
    return list(dict.fromkeys(resolve(sha) or sha for _l, sha, _remote, _r in raw if sha != ZERO))


def main_ready(commit: str) -> int:
    """`--ready <commit>`: print both answers; exit 0 when a tag on the
    commit would take the hook's fast path now, 1 when not. The hook runs
    this script from the repository; the release train runs it from whatever
    directory the operator is in, and both git and `gh run list` take the
    repository from the directory, so this moves to the script's checkout."""
    os.chdir(HERE)
    url = _git("remote", "get-url", "origin") or ""
    ok, lines = ready(github_repo(url), commit, dict(os.environ), gh_api, gh_run_list)
    print("\n".join(lines))
    return 0 if ok else 1


def main() -> int:
    args = sys.argv[1:]
    if args:
        full_sha = len(args) == 2 and re.fullmatch(r"[0-9a-f]{40}", args[1])
        if full_sha and args[0] == "--tag-ci":
            return main_tag_ci(args[1])
        if full_sha and args[0] == "--ready":
            return main_ready(args[1])
        if len(args) == 3 and args[0] == "--delivery-hint" and args[1] in ("0", "1"):
            commits = pushed_tag_commits(sys.stdin.read(), lambda sha: _git("rev-list", "-n", "1", sha))
            print("\n".join(delivery_hint(commits, args[1] == "1", args[2])))
            return 0
        print(USAGE, file=sys.stderr)
        return 2
    raw = parse_refs(sys.stdin.read())
    if raw is None:
        print("  tag-only push: the full gates run -- a pushed ref line could not be read")
        return 1
    refs = []
    for local_ref, local_sha, remote_ref, remote_sha in raw:
        commit = None if local_sha == ZERO else _git("rev-list", "-n", "1", local_sha)
        refs.append(Ref(local_ref, local_sha, remote_ref, remote_sha, commit or None))
    url = _git("remote", "get-url", "origin") or ""
    proof = main_decision(refs, dict(os.environ), github_repo(url), gh_api)
    print(proof.line)
    return exit_status(proof)


if __name__ == "__main__":
    sys.exit(main())
