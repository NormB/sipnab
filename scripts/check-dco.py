#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors
"""Check that every commit of a pull request carries a DCO sign-off.

The Developer Certificate of Origin (https://developercertificate.org/) is a
statement a contributor makes by adding a line to each commit message:

    Signed-off-by: Your Name <your GitHub noreply address>

`git commit -s` writes it from git's user.name and user.email. `verdict` is
the one rule. A commit passes when:

- its author is a GitHub Bot account (`author.type == "Bot"`) and GitHub
  verified its signature: Dependabot and similar accounts cannot make the
  statement, and GitHub names a commit's author from its email, which anyone
  can set, so the signature is what proves the commit came from the bot;
- or its author AND its committer are the repository owner's GitHub login and
  GitHub verified its signature. The owner holds the rights already, so these
  commits need no statement; the retired ~/Development/bin/cla-owner-exempt
  applied the same rule to `license/cla`;
- or its message has a line `Signed-off-by: Name <email>`, at the start of the
  line, with a name that is not empty and the commit's author email (compared
  without case), AND that email is a GitHub noreply address,
  `<ID>+<login>@users.noreply.github.com` or, for an older account,
  `<login>@users.noreply.github.com` (`is_noreply`). The line is published on
  main with the commit, so it may name only GitHub's alias for the
  contributor, never a personal mailbox (owner decision, 2026-11-18).

The output names an address only when it is a noreply address: a pull
request's CI log is public.

A merge commit follows the same rule: one from anyone but the owner needs its
own sign-off.

Usage: check-dco.py --owner LOGIN FILE

FILE holds JSON arrays of GitHub commit objects written one after another:
the `DCO` job in .github/workflows/pr-text.yml writes one array per commit,
from `gh api repos/OWNER/REPO/commits/SHA` (which needs only `contents:
read`), and the pages of `gh api repos/OWNER/REPO/pulls/N/commits
--paginate` have the same shape.

Exit 0: every commit passes. 1: at least one does not; each is named with the
reason and the fix. 2: the input could not be read, held no commit, or the
owner login is missing; nothing was checked.

Usage: check-dco.py --warn-local MSGFILE AUTHOR_EMAIL SIGNERS

What .githooks/commit-msg runs: prints `WARNING: ...` when the message has no
sign-off the `DCO` job would accept and the author is not a maintainer listed
in SIGNERS (.github/allowed_signers), `OK` otherwise, and always exits 0.
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass

# `Signed-off-by:` at the start of a line, a name, then `<email>` to the end
# of the line. The key ignores case, as git's own trailer parsing does not but
# the DCO apps on GitHub do.
_SIGN_OFF = re.compile(
    r"^signed-off-by:[ \t]*(?P<name>[^<\r\n]*?)[ \t]*<(?P<email>[^<>\s]*)>[ \t]*\r?$",
    re.IGNORECASE | re.MULTILINE,
)

# GitHub's private commit address: `<ID>+<login>@users.noreply.github.com`,
# or `<login>@users.noreply.github.com` for an older account; a bot's login
# ends in `[bot]`. A login is letters, digits and inner hyphens, at most 39
# characters, starting and ending with a letter or digit.
_NOREPLY = re.compile(
    r"(?:[0-9]+\+)?[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?(?:\[bot\])?@users\.noreply\.github\.com",
    re.IGNORECASE,
)

FIX = (
    "fix: set git's user.email to your GitHub noreply address (GitHub, "
    "Settings, Emails), then add the line with `git commit -s` for a new "
    "commit, or `git rebase --signoff <base>` to sign off every commit of the "
    "branch, and push again (CONTRIBUTING.md, \"Signing off commits\")"
)


@dataclass(frozen=True)
class Commit:
    """The fields of one pull request commit that the rule reads."""

    sha: str
    parents: int
    author_login: str | None
    author_type: str | None
    committer_login: str | None
    verified: bool
    author_name: str
    author_email: str
    message: str


def sign_offs(message: str) -> list[tuple[str, str]]:
    """Every (name, email) pair the message signs off with."""
    return [(m.group("name").strip(), m.group("email")) for m in _SIGN_OFF.finditer(message)]


def _same(a: str | None, b: str | None) -> bool:
    return bool(a) and bool(b) and a.lower() == b.lower()


def is_noreply(address: str) -> bool:
    """Whether `address`, whole, is a GitHub noreply address."""
    return _NOREPLY.fullmatch(address) is not None


def _shown(address: str) -> str:
    """`address` for a public log: itself only when it is a noreply address."""
    return f"<{address}>" if is_noreply(address) else "(not shown: not a GitHub noreply address)"


def verdict(commit: Commit, owner: str) -> tuple[bool, str]:
    """Whether `commit` passes, and why, under the rule in the module doc."""
    if commit.author_type == "Bot" and commit.verified:
        return True, f"bot account {commit.author_login}, signature verified"
    if _same(commit.author_login, owner) and _same(commit.committer_login, owner) and commit.verified:
        return True, f"owner {owner}, signature verified"
    found = sign_offs(commit.message)
    if not found:
        return False, "no Signed-off-by line"
    for name, email in found:
        if name and _same(email, commit.author_email):
            if not is_noreply(commit.author_email):
                return False, "the author email is not a GitHub noreply address, so a sign-off cannot name it"
            return True, f"signed off by {name}"
    return False, f"no Signed-off-by line names the author email {_shown(commit.author_email)} with a name"


def check(commits: list[Commit], owner: str) -> tuple[int, list[str]]:
    """The exit status and the lines to print for a whole pull request."""
    if not commits:
        return 2, ["DCO: no commit to check, so nothing was checked"]
    lines = []
    failed = 0
    for c in commits:
        ok, why = verdict(c, owner)
        lines.append(f"{'OK' if ok else 'FAIL'} {c.sha[:9]}: {why}")
        failed += not ok
    if failed:
        lines.append(FIX)
    lines.append(f"DCO: {len(commits)} commit(s), {failed} without a sign-off")
    return (1 if failed else 0), lines


def from_api(raw: dict) -> Commit:
    """A `Commit` from one element of GitHub's pull request commit list."""
    author = raw.get("author") or {}
    committer = raw.get("committer") or {}
    body = raw["commit"]
    return Commit(
        sha=raw["sha"],
        parents=len(raw.get("parents") or []),
        author_login=author.get("login"),
        author_type=author.get("type"),
        committer_login=committer.get("login"),
        verified=bool((body.get("verification") or {}).get("verified", False)),
        author_name=body["author"]["name"],
        author_email=body["author"]["email"],
        message=body["message"],
    )


def read_pages(text: str) -> list[dict]:
    """The elements of one or more JSON arrays written one after another."""
    decoder = json.JSONDecoder()
    out: list[dict] = []
    i = 0
    while True:
        while i < len(text) and text[i].isspace():
            i += 1
        if i == len(text):
            return out
        page, i = decoder.raw_decode(text, i)
        if not isinstance(page, list):
            raise ValueError("a page is not a JSON array")
        out.extend(page)


def local_warning(message: str, author_email: str, signers: str) -> str | None:
    """The commit-msg hook's warning for `message`, or None when it has none.

    The hook cannot see GitHub logins, so a maintainer is an author whose
    email is the first field of a line of .github/allowed_signers, the file
    commit signatures are checked against. A comment line's first field
    starts with `#`, so it never equals an email. Anyone else needs a
    GitHub noreply author email and a sign-off that names it. The hook only
    warns: CI's `DCO` job decides.
    """
    maintainers = {
        line.split()[0].lower()
        for line in signers.splitlines()
        if line.strip()
    }
    if author_email.lower() in maintainers:
        return None
    if not is_noreply(author_email):
        return (
            "your author email is not a GitHub noreply address, so a sign-off "
            "cannot name it and the pull request's DCO check will fail. Set "
            "`git config user.email` to the noreply address GitHub shows under "
            "Settings, Emails (CONTRIBUTING.md, \"Signing off commits\")."
        )
    if any(name and _same(email, author_email) for name, email in sign_offs(message)):
        return None
    return (
        f"no Signed-off-by line names your author email <{author_email}>. "
        "The pull request's DCO check will fail; commit with `git commit -s`."
    )


def ident_email(ident: str) -> str:
    """The email of `git var GIT_AUTHOR_IDENT` output (`Name <email> time tz`).

    A string without `<...>` is taken as the email itself.
    """
    m = re.search(r"<([^<>]*)>", ident)
    return m.group(1) if m else ident.strip()


def warn_local(argv: list[str]) -> int:
    """`--warn-local MSGFILE AUTHOR SIGNERS`: print the warning, exit 0.

    AUTHOR is an email or `git var GIT_AUTHOR_IDENT` output.
    """
    try:
        with open(argv[0], encoding="utf-8") as f:
            message = f.read()
        with open(argv[2], encoding="utf-8") as f:
            signers = f.read()
    except (OSError, IndexError, UnicodeDecodeError) as e:
        print(f"NOT CHECKED ({e})")
        return 0
    warning = local_warning(message, ident_email(argv[1]), signers)
    print(f"WARNING: {warning}" if warning else "OK")
    return 0


def main(argv: list[str]) -> int:
    if argv[:1] == ["--warn-local"]:
        return warn_local(argv[1:])
    if len(argv) != 3 or argv[0] != "--owner" or not argv[1]:
        print("usage: check-dco.py --owner LOGIN FILE", file=sys.stderr)
        print("       check-dco.py --warn-local MSGFILE AUTHOR_EMAIL SIGNERS", file=sys.stderr)
        return 2
    owner, path = argv[1], argv[2]
    try:
        with open(path, encoding="utf-8") as f:
            commits = [from_api(raw) for raw in read_pages(f.read())]
    except (OSError, ValueError, KeyError, TypeError) as e:
        print(f"DCO: cannot read {path}: {e}; nothing was checked", file=sys.stderr)
        return 2
    rc, lines = check(commits, owner)
    for line in lines:
        print(line)
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
