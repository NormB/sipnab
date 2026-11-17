# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""Which copy of scripts/tag-push-proof.py judges a tag push.

TAG-PUSH-GATE-RUNS-FROM-TAG-COMMIT: the release train checks out the merge
commit before it pushes the tag, and .githooks/pre-push ran the proof script of
that checkout. A gate fix merged after the release merge could never reach
that release's tag push (0.5.259, 2026-11-16 04:2xZ). scripts/pick-tag-proof.sh
picks origin/main's copy when the push holds a tag, origin/main resolves to a
commit, every tagged commit is its ancestor and the file is readable there;
otherwise it keeps the checkout's copy and prints the reason. It never picks a
verdict: the copy it names still decides.

Output contract: line 1 is the path the hook runs; any further line is printed
by the hook as it stands. Exit 0, or 2 on a usage error.
"""

import os
import pathlib
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent.parent
SCRIPT = REPO / "scripts/pick-tag-proof.sh"
ZERO = "0" * 40
SRC = "scripts/tag-push-proof.py"
CHECKOUT = "/checkout/scripts/tag-push-proof.py"
MAIN_TEXT = "print('main copy')\n"


def env():
    """A git environment that reads no user or system config (no signing)."""
    e = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    e.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1", LC_ALL="C")
    return e


def git(repo, *args, check=True):
    r = subprocess.run(["git", *args], cwd=repo, env=env(), capture_output=True, text=True, timeout=60)
    if check:
        assert r.returncode == 0, f"git {args} failed: {r.stderr}"
    return r.stdout.strip()


def commit(repo, files, message, parent=None):
    """A commit with `files` ({path: text, or None to delete}) on `parent`
    (default HEAD), made without moving any branch; returns its sha."""
    if parent is not None:
        git(repo, "checkout", "-q", "--detach", parent)
    for path, text in files.items():
        p = repo / path
        if text is None:
            git(repo, "rm", "-q", path)
            continue
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        git(repo, "add", path)
    git(repo, "commit", "-q", "--allow-empty", "-m", message)
    return git(repo, "rev-parse", "HEAD")


class World:
    """A repository: A (base) <- B = origin/main <- N (newer than the fetched
    main); S branches from A and is not on main."""

    def __init__(self, root):
        self.repo = root / "repo"
        self.repo.mkdir()
        git(self.repo, "init", "-q", "-b", "work")
        git(self.repo, "config", "user.name", "Example")
        git(self.repo, "config", "user.email", "dev@example.com")
        self.a = commit(self.repo, {SRC: "print('old copy')\n"}, "A")
        self.b = commit(self.repo, {SRC: MAIN_TEXT}, "B")
        self.n = commit(self.repo, {"later.txt": "n\n"}, "N")
        self.s = commit(self.repo, {"side.txt": "s\n"}, "S", parent=self.a)
        git(self.repo, "checkout", "-q", "work")
        git(self.repo, "update-ref", "refs/remotes/origin/main", self.b)
        self.git_dir = pathlib.Path(git(self.repo, "rev-parse", "--absolute-git-dir"))
        self.copy = self.git_dir / "sipnab-tag-proof-main.test.py"

    def tag(self, name, target, annotated=False):
        if annotated:
            git(self.repo, "tag", "-a", "-m", name, name, target)
        else:
            git(self.repo, "tag", name, target)
        return git(self.repo, "rev-parse", f"refs/tags/{name}")

    def pick(self, stdin, *args, cwd=None):
        argv = ["sh", str(SCRIPT), *(args if args else (CHECKOUT, str(self.copy)))]
        r = subprocess.run(argv, cwd=cwd or self.repo, env=env(), input=stdin, capture_output=True,
                           text=True, timeout=60)
        return r


def tag_line(name, sha, remote_sha=ZERO, remote=None):
    return f"refs/tags/{name} {sha} {remote or 'refs/tags/' + name} {remote_sha}\n"


def branch_line(sha, name="main", remote_sha=ZERO):
    return f"refs/heads/{name} {sha} refs/heads/{name} {remote_sha}\n"


@pytest.fixture
def w(tmp_path):
    return World(tmp_path)


def picked(r):
    assert r.returncode == 0, f"pick-tag-proof.sh exited {r.returncode}: {r.stderr}"
    lines = r.stdout.splitlines()
    assert lines, "pick-tag-proof.sh printed no path"
    return lines[0], lines[1:]


def assert_main(w, r):
    path, rest = picked(r)
    assert path == str(w.copy), f"expected origin/main's copy, got {path}; lines {rest}"
    assert w.copy.read_text() == MAIN_TEXT, "the copy is not origin/main's file"
    assert len(rest) == 1 and "origin/main's scripts/tag-push-proof.py" in rest[0], rest
    return rest[0]


def assert_checkout(w, r, reason):
    path, rest = picked(r)
    assert path == CHECKOUT, f"expected the checkout's copy, got {path}; lines {rest}"
    assert len(rest) == 1, f"expected one reason line, got {rest}"
    assert "this checkout's scripts/tag-push-proof.py" in rest[0], rest
    assert reason in rest[0], f"reason {reason!r} missing from {rest[0]!r}"
    assert not w.copy.exists(), "a fallback must leave no copy behind"
    return rest[0]


# ---------------------------------------------------------------- success


def test_success_lightweight_tag_on_main_tip(w):
    assert_main(w, w.pick(tag_line("v1", w.tag("v1", w.b))))


def test_success_annotated_tag_on_main_tip(w):
    sha = w.tag("v1", w.b, annotated=True)
    assert sha != w.b, "fixture: an annotated tag object has its own sha"
    assert_main(w, w.pick(tag_line("v1", sha)))


def test_success_tag_on_an_older_main_commit(w):
    assert_main(w, w.pick(tag_line("v0", w.tag("v0", w.a))))


def test_success_two_tags_both_on_main(w):
    stdin = tag_line("v0", w.tag("v0", w.a)) + tag_line("v1", w.tag("v1", w.b, annotated=True))
    assert_main(w, w.pick(stdin))


def test_success_a_tag_pushed_with_a_branch(w):
    stdin = branch_line(w.b) + tag_line("v1", w.tag("v1", w.b))
    assert_main(w, w.pick(stdin))


def test_success_the_line_names_origin_main_by_its_short_sha(w):
    line = assert_main(w, w.pick(tag_line("v1", w.tag("v1", w.b))))
    assert w.b[:12] in line, f"origin/main {w.b[:12]} not named in {line!r}"


def test_success_the_copy_is_byte_equal_to_origin_mains_blob(w):
    picked(w.pick(tag_line("v1", w.tag("v1", w.b))))
    assert w.copy.read_bytes() == subprocess.run(
        ["git", "cat-file", "blob", f"{w.b}:{SRC}"], cwd=w.repo, env=env(), capture_output=True,
        check=True).stdout, "the copy differs from origin/main's blob"


def test_success_a_stale_copy_at_the_path_is_replaced(w):
    w.copy.write_text("print('stale')\n")
    assert_main(w, w.pick(tag_line("v1", w.tag("v1", w.b))))


def test_success_a_moved_tag_on_main(w):
    old = w.tag("old", w.a)
    assert_main(w, w.pick(tag_line("v1", w.tag("v1", w.b), remote_sha=old)))


def test_success_a_tag_pushed_under_another_remote_name(w):
    assert_main(w, w.pick(tag_line("local", w.tag("local", w.b), remote="refs/tags/v1")))


def test_success_a_created_tag_beside_a_deleted_tag(w):
    stdin = tag_line("gone", ZERO, remote_sha=w.a) + tag_line("v1", w.tag("v1", w.b))
    assert_main(w, w.pick(stdin))


def test_success_the_same_commit_tagged_twice(w):
    stdin = tag_line("v1", w.tag("v1", w.b)) + tag_line("v1a", w.tag("v1a", w.b, annotated=True))
    assert_main(w, w.pick(stdin))


def test_success_main_copy_even_when_equal_to_the_checkouts(w):
    # The checkout's own file holds the same bytes; origin/main's copy is still named.
    own = w.repo / SRC
    assert own.read_text() == MAIN_TEXT, "fixture: the checkout holds main's bytes"
    path, rest = picked(w.pick(tag_line("v1", w.tag("v1", w.b)), str(own), str(w.copy)))
    assert path == str(w.copy), f"origin/main's copy is named even when equal: {rest}"


def test_success_exit_status_is_zero(w):
    r = w.pick(tag_line("v1", w.tag("v1", w.b)))
    assert r.returncode == 0, r.stderr
    assert r.stderr == "", f"nothing on stderr when main's copy is picked: {r.stderr!r}"


def test_success_a_merge_commit_on_main(w):
    m = commit(w.repo, {"m.txt": "m\n"}, "M", parent=w.b)
    git(w.repo, "checkout", "-q", "--detach", m)
    git(w.repo, "merge", "-q", "--no-ff", "-m", "merge S", w.s)
    merge = git(w.repo, "rev-parse", "HEAD")
    git(w.repo, "checkout", "-q", "work")
    git(w.repo, "update-ref", "refs/remotes/origin/main", merge)
    path, rest = picked(w.pick(tag_line("v2", w.tag("v2", merge))))
    assert path == str(w.copy), rest
    assert w.copy.read_text() == MAIN_TEXT, "the merge's copy is the one from B"


def test_success_from_a_linked_worktree(w, tmp_path):
    wt = tmp_path / "wt"
    git(w.repo, "worktree", "add", "-q", "--detach", str(wt), w.b)
    sha = w.tag("v1", w.b)
    copy = pathlib.Path(git(wt, "rev-parse", "--absolute-git-dir")) / "sipnab-tag-proof-main.test.py"
    r = w.pick(tag_line("v1", sha), CHECKOUT, str(copy), cwd=wt)
    path, rest = picked(r)
    assert path == str(copy), rest
    assert copy.read_text() == MAIN_TEXT, "the linked worktree's copy is main's"


def test_success_with_packed_refs(w):
    sha = w.tag("v1", w.b)
    git(w.repo, "pack-refs", "--all")
    assert_main(w, w.pick(tag_line("v1", sha)))


# ---------------------------------------------------------------- failure


def test_failure_no_origin_main(w):
    git(w.repo, "update-ref", "-d", "refs/remotes/origin/main")
    assert_checkout(w, w.pick(tag_line("v1", w.tag("v1", w.b))), "origin/main does not resolve")


def test_failure_a_tag_not_on_main(w):
    line = assert_checkout(w, w.pick(tag_line("side", w.tag("side", w.s))), "is not on origin/main")
    assert w.s[:12] in line, f"the commit {w.s[:12]} is not named: {line!r}"


def test_failure_one_of_two_tags_not_on_main(w):
    stdin = tag_line("v1", w.tag("v1", w.b)) + tag_line("side", w.tag("side", w.s))
    assert_checkout(w, w.pick(stdin), "is not on origin/main")


def test_failure_a_stale_origin_main_behind_the_tag(w):
    # The tagged commit is newer than the fetched origin/main.
    line = assert_checkout(w, w.pick(tag_line("v2", w.tag("v2", w.n))), "is not on origin/main")
    assert "fetch origin main" in line, f"the fix is not named: {line!r}"


def test_failure_origin_main_lacks_the_file(w):
    gone = commit(w.repo, {SRC: None}, "drop", parent=w.b)
    git(w.repo, "checkout", "-q", "work")
    git(w.repo, "update-ref", "refs/remotes/origin/main", gone)
    assert_checkout(w, w.pick(tag_line("v1", w.tag("v1", w.b))), "origin/main has no scripts/tag-push-proof.py")


def test_failure_an_unresolvable_pushed_sha(w):
    assert_checkout(w, w.pick(tag_line("v1", "1" * 40)), "does not resolve to a commit")


def test_failure_a_tag_of_a_tree(w):
    tree = git(w.repo, "rev-parse", f"{w.b}^{{tree}}")
    assert_checkout(w, w.pick(tag_line("t", tree)), "does not resolve to a commit")


def test_failure_the_copy_cannot_be_written(w):
    copy = w.git_dir / "no-such-dir" / "copy.py"
    r = w.pick(tag_line("v1", w.tag("v1", w.b)), CHECKOUT, str(copy))
    path, rest = picked(r)
    assert path == CHECKOUT, rest
    assert len(rest) == 1 and "could not be written" in rest[0], rest


def test_failure_a_malformed_ref_line(w):
    assert_checkout(w, w.pick(f"refs/tags/v1 {w.b} refs/tags/v1\n"), "could not be read")


def test_failure_origin_main_is_not_a_commit(w):
    blob = git(w.repo, "rev-parse", f"{w.b}:{SRC}")
    git(w.repo, "update-ref", "refs/remotes/origin/main", blob)
    assert_checkout(w, w.pick(tag_line("v1", w.tag("v1", w.b))), "origin/main does not resolve")


def test_failure_a_tag_deletion_only(w):
    assert_checkout(w, w.pick(tag_line("v1", ZERO, remote_sha=w.b)), "creates or moves no tag")


def test_failure_usage_with_no_arguments(w):
    r = subprocess.run(["sh", str(SCRIPT)], cwd=w.repo, env=env(), input="", capture_output=True,
                       text=True, timeout=60)
    assert r.returncode == 2, f"usage error expected, got {r.returncode}"
    assert "usage: pick-tag-proof.sh" in r.stderr, r.stderr
    assert r.stdout == "", "a usage error prints no path"


def test_failure_usage_with_three_arguments(w):
    r = w.pick("", CHECKOUT, str(w.copy), "extra")
    assert r.returncode == 2, f"usage error expected, got {r.returncode}"
    assert "usage: pick-tag-proof.sh" in r.stderr, r.stderr


def test_failure_a_stale_copy_is_removed_on_fallback(w):
    w.copy.write_text("print('stale')\n")
    git(w.repo, "update-ref", "-d", "refs/remotes/origin/main")
    assert_checkout(w, w.pick(tag_line("v1", w.tag("v1", w.b))), "origin/main does not resolve")


def test_failure_the_fallback_line_never_claims_a_verdict(w):
    git(w.repo, "update-ref", "-d", "refs/remotes/origin/main")
    line = assert_checkout(w, w.pick(tag_line("v1", w.tag("v1", w.b))), "origin/main")
    for word in ("pass", "proven", "skip", "OK"):
        assert word not in line, f"the fallback line must not read as a verdict: {line!r}"


def test_failure_origin_main_file_is_empty(w):
    empty = commit(w.repo, {SRC: ""}, "empty", parent=w.b)
    git(w.repo, "checkout", "-q", "work")
    git(w.repo, "update-ref", "refs/remotes/origin/main", empty)
    assert_checkout(w, w.pick(tag_line("v1", w.tag("v1", w.b))), "is empty")


def test_failure_origin_main_file_is_a_symlink(w):
    tree_dir = w.repo / "scripts"
    git(w.repo, "checkout", "-q", "--detach", w.b)
    (tree_dir / "tag-push-proof.py").unlink()
    os.symlink("elsewhere.py", tree_dir / "tag-push-proof.py")
    git(w.repo, "add", SRC)
    git(w.repo, "commit", "-q", "-m", "link")
    link = git(w.repo, "rev-parse", "HEAD")
    git(w.repo, "checkout", "-q", "-f", "work")
    git(w.repo, "update-ref", "refs/remotes/origin/main", link)
    assert_checkout(w, w.pick(tag_line("v1", w.tag("v1", w.b))), "not a regular file")


def test_failure_outside_a_repository(tmp_path):
    outside = tmp_path / "plain"
    outside.mkdir()
    r = subprocess.run(["sh", str(SCRIPT), CHECKOUT, str(outside / "copy.py")], cwd=outside,
                       env={**env(), "GIT_CEILING_DIRECTORIES": str(tmp_path)},
                       input=tag_line("v1", "2" * 40), capture_output=True, text=True, timeout=60)
    path, rest = picked(r)
    assert path == CHECKOUT, rest
    assert len(rest) == 1 and "this checkout's" in rest[0], rest


# ---------------------------------------------------------------- edge


def test_edge_a_branch_only_push_is_silent(w):
    path, rest = picked(w.pick(branch_line(w.b)))
    assert path == CHECKOUT and rest == [], f"a branch push keeps the checkout's copy silently: {rest}"
    assert not w.copy.exists(), "no copy for a branch push"


def test_edge_empty_stdin_is_silent(w):
    path, rest = picked(w.pick(""))
    assert path == CHECKOUT and rest == [], rest


def test_edge_a_tag_pushed_to_a_branch_is_not_a_tag_push(w):
    sha = w.tag("v1", w.b)
    path, rest = picked(w.pick(f"refs/tags/v1 {sha} refs/heads/v1 {ZERO}\n"))
    assert path == CHECKOUT and rest == [], rest


def test_edge_a_branch_named_like_a_tag_path(w):
    path, rest = picked(w.pick(f"refs/heads/refs/tags/x {w.b} refs/heads/refs/tags/x {ZERO}\n"))
    assert path == CHECKOUT and rest == [], rest


def test_edge_blank_lines_are_ignored(w):
    assert_main(w, w.pick("\n" + tag_line("v1", w.tag("v1", w.b)) + "\n\n"))


def test_edge_no_trailing_newline(w):
    assert_main(w, w.pick(tag_line("v1", w.tag("v1", w.b)).rstrip("\n")))


def test_edge_a_copy_path_with_spaces(w):
    copy = w.git_dir / "a dir" / "copy main.py"
    copy.parent.mkdir()
    path, rest = picked(w.pick(tag_line("v1", w.tag("v1", w.b)), CHECKOUT, str(copy)))
    assert path == str(copy), rest
    assert copy.read_text() == MAIN_TEXT, "the spaced path holds main's copy"


def test_edge_a_checkout_path_with_spaces(w):
    git(w.repo, "update-ref", "-d", "refs/remotes/origin/main")
    spaced = "/a checkout/scripts/tag-push-proof.py"
    path, rest = picked(w.pick(tag_line("v1", w.tag("v1", w.b)), spaced, str(w.copy)))
    assert path == spaced, f"the checkout path must come back verbatim: {path!r}"


def test_edge_thirty_tags_on_main(w):
    stdin = "".join(tag_line(f"t{i}", w.tag(f"t{i}", w.a if i % 2 else w.b, annotated=i % 3 == 0))
                    for i in range(30))
    assert_main(w, w.pick(stdin))


def test_edge_glob_characters_in_a_ref_are_not_expanded(w):
    (w.repo / "v1").write_text("not a ref\n")
    sha = w.tag("v1", w.b)
    path, rest = picked(w.pick(f"* {sha} refs/tags/v1 {ZERO}\n"))
    assert path == str(w.copy), f"a `*` local ref must not glob: {rest}"


def test_edge_the_working_tree_and_index_are_untouched(w):
    before = git(w.repo, "status", "--porcelain=v1", "--untracked-files=all")
    index = (w.git_dir / "index").read_bytes()
    picked(w.pick(tag_line("v1", w.tag("v1", w.b))))
    assert git(w.repo, "status", "--porcelain=v1", "--untracked-files=all") == before, "the tree changed"
    assert (w.git_dir / "index").read_bytes() == index, "the index changed"


def test_edge_the_checkout_file_is_never_read(w):
    # The checkout path need not exist: the picker names it, the hook checks it.
    git(w.repo, "update-ref", "-d", "refs/remotes/origin/main")
    path, _ = picked(w.pick(tag_line("v1", w.tag("v1", w.b)), "/does/not/exist.py", str(w.copy)))
    assert path == "/does/not/exist.py", path


def test_edge_a_tag_on_the_root_commit(w):
    root = git(w.repo, "rev-list", "--max-parents=0", w.b)
    assert root == w.a, "fixture: A is the root"
    assert_main(w, w.pick(tag_line("root", w.tag("root", root))))


def test_edge_a_nested_annotated_tag(w):
    inner = w.tag("inner", w.b, annotated=True)
    git(w.repo, "tag", "-a", "-m", "outer", "outer", inner)
    outer = git(w.repo, "rev-parse", "refs/tags/outer")
    assert git(w.repo, "cat-file", "-t", outer) == "tag", "fixture: outer is a tag object"
    assert_main(w, w.pick(tag_line("outer", outer)))


def test_edge_the_copy_runs_as_python(w):
    picked(w.pick(tag_line("v1", w.tag("v1", w.b))))
    r = subprocess.run(["python3", str(w.copy)], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0 and r.stdout == "main copy\n", f"the copy does not run: {r.stdout!r} {r.stderr!r}"


def test_edge_two_unresolvable_tags_name_the_first(w):
    stdin = tag_line("x", "1" * 40) + tag_line("y", "3" * 40)
    line = assert_checkout(w, w.pick(stdin), "does not resolve to a commit")
    assert "1" * 12 in line and "3" * 12 not in line, f"the first unresolved sha is named: {line!r}"


def test_edge_two_tags_off_main_name_the_first(w):
    stdin = tag_line("side", w.tag("side", w.s)) + tag_line("v2", w.tag("v2", w.n))
    line = assert_checkout(w, w.pick(stdin), "is not on origin/main")
    assert w.s[:12] in line and w.n[:12] not in line, f"the first commit off main is named: {line!r}"
