#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""Bump the Homebrew tap's formula with a commit GitHub has signed.

Run by the `tap` job in `.github/workflows/release.yml`, with GH_TOKEN set to
the HOMEBREW_TAP_TOKEN secret:

    python3 scripts/homebrew-tap-push.py --repo NormB/homebrew-tap \\
        --version 0.5.240 --formula sipnab.rb

The rule: every commit pushed is signed and shows Verified on GitHub. The job
used to run `git commit` and `git push` in a clone of the tap, and each of
those commits was unsigned (backlog item HOMEBREW-TAP-UNSIGNED). A commit
made through the contents API without an author or committer is created and
signed by GitHub, so this script makes the bump that way, and moves main only
after checking the result:

1. Read main's sha, then the formula at that sha. If it already equals the
   rendered formula, there is nothing to do.
2. Create the branch `sipnab-bump-<version>` at that sha. A branch of that
   name left by an earlier failed run is deleted and created again.
3. PUT the formula on that branch, with no author and no committer.
4. Read the new commit: `commit.verification.verified` must be the JSON value
   true, and its only parent must be the main sha read in step 1.
5. Fast-forward main to it (`force: false`). If main moved after step 1,
   GitHub refuses the update.
6. Delete the branch.

Every failure exits 1 with gh's message, deletes the branch if this run
created it, and leaves main where it was. All GitHub calls go through one
function, `api(method, path, body)`, so the tests replace it.
"""

import argparse
import base64
import json
import pathlib
import re
import subprocess
import sys
from typing import Callable

VERSION_RE = re.compile(r"\d+\.\d+\.\d+")


class GhError(Exception):
    """A `gh api` call failed; the message is gh's own text."""


Api = Callable[..., dict]


def gh_api(method: str, path: str, body: dict | None = None, run=subprocess.run) -> dict:
    """Call `gh api` once; the JSON body, when given, goes on stdin."""
    argv = ["gh", "api", "--method", method, path]
    stdin = None
    if body is not None:
        argv += ["--input", "-"]
        stdin = json.dumps(body)
    res = run(argv, input=stdin, capture_output=True, text=True, check=False)
    if res.returncode != 0:
        msg = (res.stderr or "").strip() or (res.stdout or "").strip()
        raise GhError(msg or f"gh api {method} {path} exited {res.returncode}")
    out = (res.stdout or "").strip()
    if not out:
        return {}
    try:
        return json.loads(out)
    except json.JSONDecodeError as exc:
        raise GhError(f"gh api {method} {path} printed non-JSON output: {exc}") from exc


def valid_version(version: str) -> bool:
    """True when `version` is X.Y.Z with decimal digits only."""
    return VERSION_RE.fullmatch(version) is not None


def decode_content(text: str) -> bytes:
    """Decode the contents API's base64, which GitHub wraps with newlines."""
    return base64.b64decode("".join(text.split()), validate=True)


def verification(commit: dict) -> tuple[bool, str]:
    """(verified, reason) for a commits API answer.

    Only the JSON value true counts as verified. A missing or malformed
    verification block is not verified, with the reason "unreadable".
    """
    try:
        ver = commit["commit"]["verification"]
        verified = ver["verified"]
        reason = ver.get("reason")
    except (KeyError, TypeError, AttributeError):
        return False, "verification unreadable"
    if not isinstance(verified, bool):
        return False, f"verification unreadable (verified={verified!r})"
    return verified, str(reason)


def parent_problem(commit: dict, main_sha: str) -> str | None:
    """None when the commit's only parent is `main_sha`, else what is wrong."""
    try:
        parents = [p["sha"] for p in commit["parents"]]
    except (KeyError, TypeError):
        return "commit parents unreadable"
    if parents != [main_sha]:
        return f"commit parents are {parents}, expected exactly [{main_sha}] (main when read)"
    return None


def is_stale_branch(exc: GhError) -> bool:
    """True when creating the branch failed because it already exists."""
    return "Reference already exists" in str(exc)


def is_not_fast_forward(exc: GhError) -> bool:
    """True when GitHub refused the main update as not a fast-forward."""
    return "not a fast forward" in str(exc).lower()


def bump(repo: str, version: str, formula: bytes, path: str, api: Api = gh_api) -> tuple[int, str]:
    """Bump `path` in `repo` to `formula`; returns (exit code, message)."""
    if not valid_version(version):
        return 1, f"version {version!r} is not X.Y.Z (digits only, no leading v)"
    branch = f"sipnab-bump-{version}"
    branch_ref = f"repos/{repo}/git/refs/heads/{branch}"

    try:
        main_sha = api("GET", f"repos/{repo}/git/ref/heads/main")["object"]["sha"]
        current = api("GET", f"repos/{repo}/contents/{path}?ref={main_sha}")
        blob_sha = current["sha"]
        if decode_content(current["content"]) == formula:
            return 0, f"homebrew-tap already at {version}; nothing to push."
    except GhError as exc:
        return 1, f"homebrew-tap not bumped: {exc}"
    except (KeyError, TypeError, ValueError) as exc:
        return 1, f"homebrew-tap not bumped: unreadable answer from GitHub ({exc!r})"

    create = {"ref": f"refs/heads/{branch}", "sha": main_sha}
    try:
        try:
            api("POST", f"repos/{repo}/git/refs", create)
        except GhError as exc:
            if not is_stale_branch(exc):
                raise
            api("DELETE", branch_ref)
            api("POST", f"repos/{repo}/git/refs", create)
    except GhError as exc:
        return 1, f"homebrew-tap not bumped: creating {branch}: {exc}"

    def refuse(why: str) -> tuple[int, str]:
        try:
            api("DELETE", branch_ref)
        except GhError as exc:
            return 1, f"homebrew-tap not bumped: {why}; deleting {branch} also failed: {exc}"
        return 1, f"homebrew-tap not bumped: {why}"

    try:
        put = api(
            "PUT",
            f"repos/{repo}/contents/{path}",
            {
                "message": f"sipnab: bump to {version}",
                "content": base64.b64encode(formula).decode("ascii"),
                "sha": blob_sha,
                "branch": branch,
            },
        )
        new_sha = put["commit"]["sha"]
        commit = api("GET", f"repos/{repo}/commits/{new_sha}")
    except GhError as exc:
        return refuse(str(exc))
    except (KeyError, TypeError) as exc:
        return refuse(f"unreadable answer from GitHub ({exc!r})")

    verified, reason = verification(commit)
    if not verified:
        return refuse(f"commit {new_sha} is not verified ({reason}); main left at {main_sha}")
    problem = parent_problem(commit, main_sha)
    if problem is not None:
        return refuse(f"commit {new_sha}: {problem}")

    try:
        api("PATCH", f"repos/{repo}/git/refs/heads/main", {"sha": new_sha, "force": False})
    except GhError as exc:
        if is_not_fast_forward(exc):
            return refuse(f"main moved after it was read at {main_sha}; re-run the job ({exc})")
        return refuse(f"updating main: {exc}")

    try:
        api("DELETE", branch_ref)
    except GhError as exc:
        return 1, (
            f"homebrew-tap bumped to {version} as {new_sha}, verified ({reason}), "
            f"but deleting branch {branch} failed: {exc}"
        )
    return 0, f"homebrew-tap bumped to {version} as {new_sha}, verified ({reason})"


def main(argv: list[str] | None = None, api: Api = gh_api) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--repo", required=True, help="the tap, OWNER/NAME")
    ap.add_argument("--version", required=True, help="the release version, X.Y.Z")
    ap.add_argument("--formula", required=True, help="the rendered formula file")
    ap.add_argument("--path", default="Formula/sipnab.rb", help="the formula's path in the tap")
    args = ap.parse_args(argv)
    try:
        formula = pathlib.Path(args.formula).read_bytes()
    except OSError as exc:
        print(f"homebrew-tap not bumped: cannot read {args.formula}: {exc}", file=sys.stderr)
        return 1
    code, msg = bump(args.repo, args.version, formula, args.path, api=api)
    print(msg, file=sys.stdout if code == 0 else sys.stderr)
    return code


if __name__ == "__main__":
    sys.exit(main())
