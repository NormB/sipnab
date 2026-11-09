# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""The Homebrew tap bump lands only as a commit GitHub has signed.

Backlog item HOMEBREW-TAP-UNSIGNED: the release workflow's `tap` job ran
`git commit` and `git push origin HEAD:main` against NormB/homebrew-tap, and
every such commit showed `verification.verified: false`. The rule is that
every pushed commit is signed and Verified.

scripts/homebrew-tap-push.py creates the bump commit through the contents API
on a side branch, so GitHub creates and signs it, checks the signature and the
parent, and only then fast-forwards main. GitHub is not reachable from a test,
so every `gh api` call goes through one injectable function and the fake
below records each call. Every failure test asserts main was never patched.
"""

import base64
import json
import subprocess

import pytest
from conftest import load

tp = load("homebrew-tap-push")

REPO = "NormB/homebrew-tap"
FPATH = "Formula/sipnab.rb"
V = "0.5.240"
MAIN = "a" * 40
NEW = "b" * 40
OTHER = "c" * 40
BLOB = "f" * 40
BRANCH = f"sipnab-bump-{V}"
FORMULA = b'class Sipnab < Formula\n  version "0.5.240"\nend\n'
OLD = b'class Sipnab < Formula\n  version "0.5.239"\nend\n'

GET_MAIN = ("GET", f"repos/{REPO}/git/ref/heads/main")
GET_FILE = ("GET", f"repos/{REPO}/contents/{FPATH}?ref={MAIN}")
POST_REF = ("POST", f"repos/{REPO}/git/refs")
DEL_BRANCH = ("DELETE", f"repos/{REPO}/git/refs/heads/{BRANCH}")
PUT_FILE = ("PUT", f"repos/{REPO}/contents/{FPATH}")
GET_COMMIT = ("GET", f"repos/{REPO}/commits/{NEW}")
PATCH_MAIN = ("PATCH", f"repos/{REPO}/git/refs/heads/main")


def b64(data, wrap=False):
    text = base64.b64encode(data).decode()
    if wrap:
        # GitHub's contents API wraps base64 at 60 columns with "\n".
        text = "\n".join(text[i : i + 60] for i in range(0, len(text), 60)) + "\n"
    return text


def commit(verified=True, reason="valid", parents=(MAIN,)):
    return {
        "sha": NEW,
        "commit": {"verification": {"verified": verified, "reason": reason}},
        "parents": [{"sha": p} for p in parents],
    }


def routes(**over):
    """The happy path's answers, keyed by (method, path); `over` replaces some."""
    r = {
        GET_MAIN: {"object": {"sha": MAIN}},
        GET_FILE: {"sha": BLOB, "content": b64(OLD), "encoding": "base64"},
        POST_REF: {"ref": f"refs/heads/{BRANCH}", "object": {"sha": MAIN}},
        DEL_BRANCH: {},
        PUT_FILE: {"commit": {"sha": NEW}},
        GET_COMMIT: commit(),
        PATCH_MAIN: {"object": {"sha": NEW}},
    }
    keys = {
        "get_main": GET_MAIN,
        "get_file": GET_FILE,
        "post_ref": POST_REF,
        "del_branch": DEL_BRANCH,
        "put_file": PUT_FILE,
        "get_commit": GET_COMMIT,
        "patch_main": PATCH_MAIN,
    }
    for name, value in over.items():
        r[keys[name]] = value
    return r


class FakeGh:
    """Answers `api(method, path, body)` from `routes`; records every call.

    A route value that is a list is consumed one answer per call. A value that
    is an exception is raised. A call with no route fails the test.
    """

    def __init__(self, table):
        self.table = {k: (list(v) if isinstance(v, list) else v) for k, v in table.items()}
        self.calls = []

    def __call__(self, method, path, body=None):
        self.calls.append((method, path, body))
        key = (method, path)
        if key not in self.table:
            raise AssertionError(f"unexpected gh call: {method} {path}")
        ans = self.table[key]
        if isinstance(ans, list):
            ans = ans.pop(0)
        if isinstance(ans, Exception):
            raise ans
        return ans

    def keys(self):
        return [(m, p) for m, p, _ in self.calls]

    def body(self, key):
        return [b for m, p, b in self.calls if (m, p) == key][-1]

    def main_patched(self):
        return PATCH_MAIN in self.keys()


def bump(fake, formula=FORMULA, version=V):
    return tp.bump(REPO, version, formula, FPATH, api=fake)


def err(msg):
    return tp.GhError(msg)


# ---------------------------------------------------------------- SUCCESS


def test_success_fast_forwards_main_to_the_verified_bump_commit():
    fake = FakeGh(routes())
    code, msg = bump(fake)
    assert code == 0, msg
    assert fake.body(PATCH_MAIN) == {"sha": NEW, "force": False}
    assert msg == f"homebrew-tap bumped to {V} as {NEW}, verified (valid)"


def test_success_calls_happen_in_the_fail_closed_order():
    """Branch, commit, verify, parent, THEN main, then branch deleted."""
    fake = FakeGh(routes())
    assert bump(fake)[0] == 0
    assert fake.keys() == [GET_MAIN, GET_FILE, POST_REF, PUT_FILE, GET_COMMIT, PATCH_MAIN, DEL_BRANCH]


def test_success_branch_is_created_at_the_main_sha_that_was_read():
    fake = FakeGh(routes())
    bump(fake)
    assert fake.body(POST_REF) == {"ref": f"refs/heads/{BRANCH}", "sha": MAIN}


def test_success_put_names_no_author_or_committer_so_github_signs_it():
    fake = FakeGh(routes())
    bump(fake)
    body = fake.body(PUT_FILE)
    assert "author" not in body and "committer" not in body
    assert body["message"] == f"sipnab: bump to {V}"
    assert body["branch"] == BRANCH
    assert body["sha"] == BLOB


def test_success_put_content_is_the_formula_base64_encoded():
    fake = FakeGh(routes())
    bump(fake)
    assert base64.b64decode(fake.body(PUT_FILE)["content"]) == FORMULA


def test_success_verifies_the_commit_sha_the_put_returned():
    fake = FakeGh(routes())
    bump(fake)
    assert ("GET", f"repos/{REPO}/commits/{NEW}") in fake.keys()


def test_success_main_cli_reads_the_formula_file_and_prints_the_result(tmp_path, capsys):
    f = tmp_path / "sipnab.rb"
    f.write_bytes(FORMULA)
    fake = FakeGh(routes())
    code = tp.main(["--repo", REPO, "--version", V, "--formula", str(f)], api=fake)
    assert code == 0
    assert f"homebrew-tap bumped to {V} as {NEW}" in capsys.readouterr().out
    assert base64.b64decode(fake.body(PUT_FILE)["content"]) == FORMULA


def test_success_path_option_selects_the_file_in_the_tap(tmp_path):
    f = tmp_path / "sipnab.rb"
    f.write_bytes(FORMULA)
    other = "Formula/s/sipnab.rb"
    table = routes()
    table[("GET", f"repos/{REPO}/contents/{other}?ref={MAIN}")] = table.pop(GET_FILE)
    table[("PUT", f"repos/{REPO}/contents/{other}")] = table.pop(PUT_FILE)
    fake = FakeGh(table)
    code = tp.main(["--repo", REPO, "--version", V, "--formula", str(f), "--path", other], api=fake)
    assert code == 0


# ---------------------------------------------------------------- FAILURE


def test_failure_unverified_commit_deletes_branch_and_never_moves_main():
    fake = FakeGh(routes(get_commit=commit(verified=False, reason="unsigned")))
    code, msg = bump(fake)
    assert code == 1
    assert "unsigned" in msg
    assert not fake.main_patched()
    assert fake.keys()[-1] == DEL_BRANCH


def test_failure_verification_block_missing_is_refused():
    fake = FakeGh(routes(get_commit={"sha": NEW, "commit": {}, "parents": [{"sha": MAIN}]}))
    code, msg = bump(fake)
    assert code == 1
    assert "unreadable" in msg
    assert not fake.main_patched()
    assert DEL_BRANCH in fake.keys()


def test_failure_verified_as_string_true_is_not_accepted():
    """Only the JSON boolean true counts; a truthy string is unreadable."""
    fake = FakeGh(routes(get_commit=commit(verified="true")))
    code, _ = bump(fake)
    assert code == 1
    assert not fake.main_patched()


def test_failure_wrong_parent_is_refused():
    fake = FakeGh(routes(get_commit=commit(parents=(OTHER,))))
    code, msg = bump(fake)
    assert code == 1
    assert OTHER in msg and MAIN in msg
    assert not fake.main_patched()
    assert DEL_BRANCH in fake.keys()


def test_failure_two_parents_are_refused():
    fake = FakeGh(routes(get_commit=commit(parents=(MAIN, OTHER))))
    code, _ = bump(fake)
    assert code == 1
    assert not fake.main_patched()


def test_failure_ref_update_refused_exits_1_and_deletes_branch():
    fake = FakeGh(routes(patch_main=err("gh: Resource not accessible by personal access token (HTTP 403)")))
    code, msg = bump(fake)
    assert code == 1
    assert "HTTP 403" in msg
    assert fake.keys()[-1] == DEL_BRANCH


def test_failure_gh_error_reading_main_makes_no_other_call():
    fake = FakeGh(routes(get_main=err("gh: Bad credentials (HTTP 401)")))
    code, msg = bump(fake)
    assert code == 1
    assert "Bad credentials" in msg
    assert fake.keys() == [GET_MAIN]


def test_failure_gh_error_reading_the_tap_file_creates_no_branch():
    fake = FakeGh(routes(get_file=err("gh: Not Found (HTTP 404)")))
    code, msg = bump(fake)
    assert code == 1
    assert "HTTP 404" in msg
    assert fake.keys() == [GET_MAIN, GET_FILE]


def test_failure_gh_error_creating_the_branch_stops_before_any_commit():
    fake = FakeGh(routes(post_ref=err("gh: Server Error (HTTP 502)")))
    code, msg = bump(fake)
    assert code == 1
    assert "HTTP 502" in msg
    assert PUT_FILE not in fake.keys()
    assert not fake.main_patched()


def test_failure_gh_error_on_the_put_deletes_the_branch():
    fake = FakeGh(routes(put_file=err("gh: sha does not match (HTTP 409)")))
    code, msg = bump(fake)
    assert code == 1
    assert "HTTP 409" in msg
    assert not fake.main_patched()
    assert fake.keys()[-1] == DEL_BRANCH


def test_failure_gh_error_reading_the_commit_deletes_the_branch():
    fake = FakeGh(routes(get_commit=err("gh: Server Error (HTTP 500)")))
    code, msg = bump(fake)
    assert code == 1
    assert "HTTP 500" in msg
    assert not fake.main_patched()
    assert fake.keys()[-1] == DEL_BRANCH


def test_failure_put_response_without_a_commit_sha_is_refused():
    fake = FakeGh(routes(put_file={"content": {}}))
    code, _ = bump(fake)
    assert code == 1
    assert not fake.main_patched()
    assert fake.keys()[-1] == DEL_BRANCH


def test_failure_cleanup_error_is_reported_with_the_original_error():
    fake = FakeGh(
        routes(
            get_commit=commit(verified=False, reason="unsigned"),
            del_branch=err("gh: Server Error (HTTP 503)"),
        )
    )
    code, msg = bump(fake)
    assert code == 1
    assert "unsigned" in msg and "HTTP 503" in msg
    assert not fake.main_patched()


def test_failure_deleting_the_branch_after_main_moved_exits_1():
    """main already holds the verified commit; the leftover branch is reported."""
    fake = FakeGh(routes(del_branch=err("gh: Server Error (HTTP 503)")))
    code, msg = bump(fake)
    assert code == 1
    assert BRANCH in msg and "HTTP 503" in msg


def test_failure_missing_formula_file_makes_no_gh_call(tmp_path, capsys):
    fake = FakeGh(routes())
    code = tp.main(["--repo", REPO, "--version", V, "--formula", str(tmp_path / "nope.rb")], api=fake)
    assert code == 1
    assert "nope.rb" in capsys.readouterr().err
    assert fake.calls == []


# ---------------------------------------------------------------- EDGE


def test_edge_already_up_to_date_makes_no_write():
    fake = FakeGh(routes(get_file={"sha": BLOB, "content": b64(FORMULA), "encoding": "base64"}))
    code, msg = bump(fake)
    assert code == 0
    assert msg == f"homebrew-tap already at {V}; nothing to push."
    assert fake.keys() == [GET_MAIN, GET_FILE]


def test_edge_base64_wrapped_with_newlines_still_compares_equal():
    fake = FakeGh(routes(get_file={"sha": BLOB, "content": b64(FORMULA, wrap=True), "encoding": "base64"}))
    code, _ = bump(fake)
    assert code == 0
    assert fake.keys() == [GET_MAIN, GET_FILE]


def test_edge_decode_content_strips_newlines():
    big = FORMULA * 20
    assert "\n" in b64(big, wrap=True)
    assert tp.decode_content(b64(big, wrap=True)) == big


def test_edge_stale_bump_branch_is_deleted_and_recreated():
    exists = err("gh: Reference already exists (HTTP 422)")
    ok = {"ref": f"refs/heads/{BRANCH}", "object": {"sha": MAIN}}
    fake = FakeGh(routes(post_ref=[exists, ok]))
    code, msg = bump(fake)
    assert code == 0, msg
    assert fake.keys()[:5] == [GET_MAIN, GET_FILE, POST_REF, DEL_BRANCH, POST_REF]
    assert fake.body(POST_REF)["sha"] == MAIN


def test_edge_other_post_ref_422_is_not_treated_as_a_stale_branch():
    fake = FakeGh(routes(post_ref=err("gh: Object does not exist (HTTP 422)")))
    code, _ = bump(fake)
    assert code == 1
    assert DEL_BRANCH not in fake.keys()
    assert not fake.main_patched()


def test_edge_verified_true_with_a_reason_other_than_valid_is_accepted():
    """`verified` is the rule; the reason is reported, not judged."""
    fake = FakeGh(routes(get_commit=commit(verified=True, reason="bad_email")))
    code, msg = bump(fake)
    assert code == 0
    assert msg.endswith("verified (bad_email)")


@pytest.mark.parametrize("bad", ["v0.5.1", "0.5", "", "0.5.1.2", "0.5.x", "0.5.1 ", "0.5.1-rc1"])
def test_edge_version_not_x_y_z_is_refused_before_any_gh_call(bad):
    fake = FakeGh(routes())
    code, msg = tp.bump(REPO, bad, FORMULA, FPATH, api=fake)
    assert code == 1
    assert "X.Y.Z" in msg
    assert fake.calls == []


def test_edge_main_moved_between_read_and_update_is_named_and_cleaned_up():
    fake = FakeGh(routes(patch_main=err("gh: Update is not a fast forward (HTTP 422)")))
    code, msg = bump(fake)
    assert code == 1
    assert "main moved" in msg
    assert fake.body(PATCH_MAIN)["force"] is False
    assert fake.keys()[-1] == DEL_BRANCH


# ------------------------------------------------- the one real gh caller


class FakeRun:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.result = subprocess.CompletedProcess([], returncode, stdout, stderr)
        self.argv = None
        self.input = None

    def __call__(self, argv, input=None, capture_output=None, text=None, check=None):
        self.argv = argv
        self.input = input
        return self.result


def test_gh_api_sends_the_body_as_json_on_stdin():
    run = FakeRun(stdout='{"object": {"sha": "x"}}')
    out = tp.gh_api("PATCH", "repos/o/r/git/refs/heads/main", {"sha": "x", "force": False}, run=run)
    assert out == {"object": {"sha": "x"}}
    assert run.argv == ["gh", "api", "--method", "PATCH", "repos/o/r/git/refs/heads/main", "--input", "-"]
    assert json.loads(run.input) == {"sha": "x", "force": False}


def test_gh_api_get_without_body_passes_no_input():
    run = FakeRun(stdout="{}")
    tp.gh_api("GET", "repos/o/r/git/ref/heads/main", run=run)
    assert run.argv == ["gh", "api", "--method", "GET", "repos/o/r/git/ref/heads/main"]
    assert run.input is None


def test_gh_api_empty_output_is_an_empty_dict():
    """DELETE answers 204 with no body."""
    assert tp.gh_api("DELETE", "repos/o/r/git/refs/heads/b", run=FakeRun(stdout="")) == {}


def test_gh_api_nonzero_exit_raises_with_gh_message():
    run = FakeRun(returncode=1, stdout='{"message":"x"}', stderr="gh: Reference already exists (HTTP 422)\n")
    with pytest.raises(tp.GhError, match="Reference already exists"):
        tp.gh_api("POST", "repos/o/r/git/refs", {"ref": "r", "sha": "s"}, run=run)


def test_gh_api_non_json_output_raises():
    with pytest.raises(tp.GhError):
        tp.gh_api("GET", "repos/o/r", run=FakeRun(stdout="<html>"))
