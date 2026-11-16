# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""The DCO check accepts a pull request only when every commit is signed off.

scripts/check-dco.py's `verdict` is the one rule. A commit passes when:

- its author is a GitHub Bot account and GitHub verified its signature
  (Dependabot and similar cannot sign off; GitHub names a commit's author
  from its email, which anyone can set, so the signature is what proves it),
- or its author AND committer are the repository owner's GitHub login and
  GitHub verified its signature (the owner holds the rights already; the same
  rule ~/Development/bin/cla-owner-exempt applies to `license/cla`),
- or its message carries a `Signed-off-by: Name <email>` line whose email is
  the commit's author email and whose name is not empty, AND that email is a
  GitHub noreply address (owner decision (viii), 2026-11-18): the sign-off
  line is published on main with the commit, so it may name only GitHub's
  alias for the contributor, never a personal mailbox.

Merge commits follow the same rule: a merge commit from anyone but the owner
needs its own sign-off. Test data uses reserved names, example.com addresses
and a noreply address for a made-up login, assembled at run time: this file
is scanned as a tracked file too (tests/private_identity_test.rs G1), where a
literal address at github.com is refused.
"""

import json
import pathlib

import pytest
from conftest import load

dco = load("check-dco")

OWNER = "owner-login"
A_SHA = "a" * 40
B_SHA = "b" * 40
AT = "@"
NOREPLY = "users.noreply.github.com"
# The author email of the contributor every fixture commit is from.
EMAIL = f"12345+contrib-login{AT}{NOREPLY}"
# A personal address: a sign-off may not name one.
PERSONAL = "contributor@example.com"


def commit(
    message="Fix a parser bound\n",
    author_login="contrib-login",
    author_type="User",
    committer_login="contrib-login",
    verified=False,
    author_name="A Contributor",
    author_email=EMAIL,
    parents=1,
    sha=A_SHA,
):
    return dco.Commit(
        sha=sha,
        parents=parents,
        author_login=author_login,
        author_type=author_type,
        committer_login=committer_login,
        verified=verified,
        author_name=author_name,
        author_email=author_email,
        message=message,
    )


SIGNED = f"Fix a parser bound\n\nSigned-off-by: A Contributor <{EMAIL}>\n"


def api_commit(
    sha=A_SHA,
    message=SIGNED,
    login="contrib-login",
    user_type="User",
    committer="contrib-login",
    verified=False,
    email=EMAIL,
    name="A Contributor",
    parents=1,
):
    """One element of GET /repos/{owner}/{repo}/pulls/{n}/commits."""
    return {
        "sha": sha,
        "parents": [{"sha": "c" * 40}] * parents,
        "author": None if login is None else {"login": login, "type": user_type},
        "committer": None if committer is None else {"login": committer, "type": "User"},
        "commit": {
            "message": message,
            "author": {"name": name, "email": email},
            "committer": {"name": name, "email": email},
            "verification": {"verified": verified},
        },
    }


# ---------------------------------------------------------------- success


def test_success_a_matching_sign_off_passes():
    ok, why = dco.verdict(commit(message=SIGNED), OWNER)
    assert ok, why


def test_success_the_reason_names_the_sign_off():
    ok, why = dco.verdict(commit(message=SIGNED), OWNER)
    assert ok and "signed off" in why, why


def test_success_a_bot_author_passes_without_a_sign_off():
    ok, why = dco.verdict(commit(author_login="dependabot[bot]", author_type="Bot", verified=True), OWNER)
    assert ok and "bot" in why, why


def test_success_an_owner_commit_that_is_verified_passes_without_a_sign_off():
    c = commit(author_login=OWNER, committer_login=OWNER, verified=True)
    ok, why = dco.verdict(c, OWNER)
    assert ok and "owner" in why, why


def test_success_the_owner_login_compares_without_case():
    c = commit(author_login="Owner-Login", committer_login="OWNER-LOGIN", verified=True)
    assert dco.verdict(c, OWNER)[0]


def test_success_the_email_compares_without_case():
    msg = f"x\n\nSigned-off-by: A Contributor <{EMAIL.upper()}>\n"
    assert dco.verdict(commit(message=msg), OWNER)[0]


def test_success_one_matching_line_among_several_passes():
    msg = (
        "x\n\nSigned-off-by: Someone Else <else@example.com>\n"
        f"Signed-off-by: A Contributor <{EMAIL}>\n"
    )
    assert dco.verdict(commit(message=msg), OWNER)[0]


def test_success_a_merge_commit_signed_off_by_its_author_passes():
    assert dco.verdict(commit(message=SIGNED, parents=2), OWNER)[0]


def test_success_check_passes_a_range_where_every_commit_passes():
    rc, lines = dco.check([commit(message=SIGNED), commit(message=SIGNED, sha=B_SHA)], OWNER)
    assert rc == 0, lines


def test_success_check_prints_one_ok_line_per_commit():
    rc, lines = dco.check([commit(message=SIGNED), commit(message=SIGNED, sha=B_SHA)], OWNER)
    assert [line.split()[0] for line in lines[:2]] == ["OK", "OK"], lines


def test_success_from_api_reads_every_field():
    c = dco.from_api(api_commit(parents=2, verified=True))
    assert (c.sha, c.parents, c.author_login, c.author_type, c.committer_login, c.verified) == (
        A_SHA,
        2,
        "contrib-login",
        "User",
        "contrib-login",
        True,
    )
    assert (c.author_name, c.author_email, c.message) == ("A Contributor", EMAIL, SIGNED)


def test_success_main_exits_0_for_a_signed_range(tmp_path, capsys):
    f = tmp_path / "commits.json"
    f.write_text(json.dumps([api_commit()]))
    assert dco.main(["--owner", OWNER, str(f)]) == 0
    assert "OK" in capsys.readouterr().out


def test_success_main_reads_concatenated_pages(tmp_path):
    f = tmp_path / "commits.json"
    f.write_text(json.dumps([api_commit()]) + "\n" + json.dumps([api_commit(sha=B_SHA)]))
    assert dco.main(["--owner", OWNER, str(f)]) == 0


def test_success_main_exempts_a_bot_from_the_api_shape(tmp_path):
    f = tmp_path / "commits.json"
    f.write_text(
        json.dumps([api_commit(message="Bump x\n", login="dependabot[bot]", user_type="Bot", verified=True)])
    )
    assert dco.main(["--owner", OWNER, str(f)]) == 0


# ---------------------------------------------------------------- failure


def test_failure_no_sign_off_fails():
    ok, why = dco.verdict(commit(message="Fix a parser bound\n"), OWNER)
    assert not ok and "no Signed-off-by" in why, why


def test_failure_a_sign_off_with_another_email_fails():
    msg = "x\n\nSigned-off-by: A Contributor <other@example.com>\n"
    ok, why = dco.verdict(commit(message=msg), OWNER)
    assert not ok and EMAIL in why, why


def test_failure_a_sign_off_without_a_name_fails():
    msg = f"x\n\nSigned-off-by: <{EMAIL}>\n"
    assert not dco.verdict(commit(message=msg), OWNER)[0]


def test_failure_a_sign_off_without_an_email_fails():
    msg = "x\n\nSigned-off-by: A Contributor\n"
    assert not dco.verdict(commit(message=msg), OWNER)[0]


def test_failure_an_owner_commit_without_a_verified_signature_needs_a_sign_off():
    c = commit(author_login=OWNER, committer_login=OWNER, verified=False)
    ok, why = dco.verdict(c, OWNER)
    assert not ok, why


def test_failure_an_owner_authored_commit_with_another_committer_needs_a_sign_off():
    c = commit(author_login=OWNER, committer_login="web-flow", verified=True)
    assert not dco.verdict(c, OWNER)[0]


def test_failure_an_owner_committed_commit_by_another_author_needs_a_sign_off():
    c = commit(author_login="contrib-login", committer_login=OWNER, verified=True)
    assert not dco.verdict(c, OWNER)[0]


def test_failure_a_merge_commit_from_a_contributor_needs_a_sign_off():
    assert not dco.verdict(commit(message="Merge branch 'main'\n", parents=2), OWNER)[0]


def test_failure_a_user_named_like_a_bot_is_not_a_bot():
    c = commit(author_login="lookalike[bot]", author_type="User")
    assert not dco.verdict(c, OWNER)[0]


def test_failure_a_bot_author_without_a_verified_signature_needs_a_sign_off():
    c = commit(author_login="dependabot[bot]", author_type="Bot", verified=False)
    ok, why = dco.verdict(c, OWNER)
    assert not ok, why


def test_success_main_reads_the_single_commit_endpoint_shape(tmp_path):
    # The workflow asks GET /repos/{owner}/{repo}/commits/{sha} once per commit
    # (it needs only `contents: read`) and wraps each answer in an array.
    f = tmp_path / "commits.json"
    f.write_text("\n".join(json.dumps([api_commit(sha=s)]) for s in (A_SHA, B_SHA)))
    assert dco.main(["--owner", OWNER, str(f)]) == 0


def test_failure_check_fails_when_one_commit_fails():
    rc, lines = dco.check([commit(message=SIGNED), commit(message="x\n", sha=B_SHA)], OWNER)
    assert rc == 1, lines


def test_failure_check_names_the_failing_commit():
    rc, lines = dco.check([commit(message=SIGNED), commit(message="x\n", sha=B_SHA)], OWNER)
    assert any(line.startswith("FAIL " + B_SHA[:9]) for line in lines), lines


def test_failure_check_prints_how_to_fix():
    rc, lines = dco.check([commit(message="x\n")], OWNER)
    assert any("git rebase --signoff" in line for line in lines), lines


def test_failure_main_exits_1_for_an_unsigned_commit(tmp_path):
    f = tmp_path / "commits.json"
    f.write_text(json.dumps([api_commit(message="x\n")]))
    assert dco.main(["--owner", OWNER, str(f)]) == 1


def test_failure_a_commit_with_no_github_account_needs_a_sign_off():
    c = dco.from_api(api_commit(message="x\n", login=None, committer=None))
    assert not dco.verdict(c, OWNER)[0]


# ---------------------------------------------------------------- edge


def test_edge_an_empty_range_is_an_error_not_a_pass():
    rc, lines = dco.check([], OWNER)
    assert rc == 2, lines


def test_edge_main_without_owner_is_a_usage_error(tmp_path):
    f = tmp_path / "commits.json"
    f.write_text(json.dumps([api_commit()]))
    assert dco.main([str(f)]) == 2


def test_edge_main_with_an_empty_owner_is_a_usage_error(tmp_path):
    f = tmp_path / "commits.json"
    f.write_text(json.dumps([api_commit()]))
    assert dco.main(["--owner", "", str(f)]) == 2


def test_edge_main_with_a_missing_file_is_an_error(tmp_path):
    assert dco.main(["--owner", OWNER, str(tmp_path / "absent.json")]) == 2


def test_edge_main_with_malformed_json_is_an_error(tmp_path):
    f = tmp_path / "commits.json"
    f.write_text("[{")
    assert dco.main(["--owner", OWNER, str(f)]) == 2


def test_edge_main_with_a_non_list_is_an_error(tmp_path):
    f = tmp_path / "commits.json"
    f.write_text(json.dumps({"message": "Not Found"}))
    assert dco.main(["--owner", OWNER, str(f)]) == 2


def test_edge_main_with_an_element_missing_fields_is_an_error(tmp_path):
    f = tmp_path / "commits.json"
    f.write_text(json.dumps([{"sha": A_SHA}]))
    assert dco.main(["--owner", OWNER, str(f)]) == 2


def test_edge_main_with_an_empty_list_is_an_error(tmp_path):
    f = tmp_path / "commits.json"
    f.write_text("[]")
    assert dco.main(["--owner", OWNER, str(f)]) == 2


def test_edge_crlf_line_endings_are_read():
    msg = f"x\r\n\r\nSigned-off-by: A Contributor <{EMAIL}>\r\n"
    assert dco.verdict(commit(message=msg), OWNER)[0]


def test_edge_the_trailer_key_compares_without_case():
    msg = f"x\n\nsigned-off-by: A Contributor <{EMAIL}>\n"
    assert dco.verdict(commit(message=msg), OWNER)[0]


def test_edge_trailing_spaces_after_the_email_are_accepted():
    msg = f"x\n\nSigned-off-by: A Contributor <{EMAIL}>   \n"
    assert dco.verdict(commit(message=msg), OWNER)[0]


def test_edge_a_quoted_sign_off_inside_a_line_does_not_count():
    msg = f"x\n\nSee the `Signed-off-by: A Contributor <{EMAIL}>` line.\n"
    assert not dco.verdict(commit(message=msg), OWNER)[0]


def test_edge_an_indented_sign_off_does_not_count():
    msg = f"x\n\n    Signed-off-by: A Contributor <{EMAIL}>\n"
    assert not dco.verdict(commit(message=msg), OWNER)[0]


def test_edge_a_sign_off_as_the_last_line_without_a_newline_counts():
    msg = f"x\n\nSigned-off-by: A Contributor <{EMAIL}>"
    assert dco.verdict(commit(message=msg), OWNER)[0]


def test_edge_an_email_that_only_contains_the_author_email_does_not_match():
    msg = f"x\n\nSigned-off-by: A Contributor <x{EMAIL}>\n"
    assert not dco.verdict(commit(message=msg), OWNER)[0]


def test_edge_a_bot_type_compares_exactly():
    c = commit(author_login="dependabot[bot]", author_type="bot")
    assert not dco.verdict(c, OWNER)[0]


def test_edge_an_empty_author_email_never_matches():
    msg = "x\n\nSigned-off-by: A Contributor <>\n"
    assert not dco.verdict(commit(message=msg, author_email=""), OWNER)[0]


def test_edge_an_owner_check_with_no_login_is_not_the_owner():
    c = commit(author_login=None, committer_login=None, verified=True)
    assert not dco.verdict(c, "")[0]


def test_edge_from_api_reads_a_missing_verification_as_unverified():
    raw = api_commit()
    del raw["commit"]["verification"]
    assert dco.from_api(raw).verified is False


def test_edge_from_api_reads_a_null_author_as_no_login():
    c = dco.from_api(api_commit(login=None))
    assert (c.author_login, c.author_type) == (None, None)


def test_edge_check_reports_every_failure_not_just_the_first():
    rc, lines = dco.check([commit(message="x\n"), commit(message="y\n", sha=B_SHA)], OWNER)
    assert sum(line.startswith("FAIL ") for line in lines) == 2, lines


@pytest.mark.parametrize("count", [1, 3])
def test_edge_check_counts_the_commits_it_read(count):
    rc, lines = dco.check([commit(message=SIGNED)] * count, OWNER)
    assert lines[-1].startswith(f"DCO: {count} commit(s)"), lines


# ------------------------------------------------- the commit-msg warning
#
# The commit-msg hook cannot see GitHub logins, so it tells a maintainer
# apart by the email in .github/allowed_signers, the file commit signatures
# are checked against. It warns and never refuses: CI's `DCO` job decides.

SIGNERS = 'maint@example.com namespaces="git" ssh-ed25519 AAAAexamplekey\n'


def test_success_the_local_check_is_quiet_for_a_signed_message():
    assert dco.local_warning(SIGNED, EMAIL, SIGNERS) is None


def test_success_the_local_check_is_quiet_for_a_maintainer():
    assert dco.local_warning("x\n", "maint@example.com", SIGNERS) is None


def test_failure_the_local_check_warns_for_an_unsigned_contributor():
    warning = dco.local_warning("x\n", EMAIL, SIGNERS)
    assert warning and "git commit -s" in warning, warning


def test_failure_the_local_check_warns_for_a_sign_off_with_another_email():
    msg = "x\n\nSigned-off-by: A Contributor <other@example.com>\n"
    assert dco.local_warning(msg, EMAIL, SIGNERS)


def test_edge_the_local_check_reads_only_the_first_field_of_a_signers_line():
    signers = "# comment maint@example.com\nother@example.com ssh-ed25519 AAAAmaint@example.com\n"
    assert dco.local_warning("x\n", "maint@example.com", signers)


def test_edge_the_local_check_compares_the_maintainer_email_without_case():
    assert dco.local_warning("x\n", "Maint@Example.com", SIGNERS) is None


def test_edge_main_warn_local_always_exits_0(tmp_path, capsys):
    msg = tmp_path / "msg"
    msg.write_text("x\n")
    signers = tmp_path / "signers"
    signers.write_text(SIGNERS)
    rc = dco.main(["--warn-local", str(msg), EMAIL, str(signers)])
    assert rc == 0 and "Signed-off-by" in capsys.readouterr().out


def test_success_ident_email_reads_git_var_output():
    assert dco.ident_email("A Contributor <contributor@example.com> 1763300000 +0000") == "contributor@example.com"


def test_edge_ident_email_of_a_bare_address_is_that_address():
    assert dco.ident_email("contributor@example.com") == "contributor@example.com"


def test_edge_main_warn_local_takes_a_git_ident(tmp_path, capsys):
    msg = tmp_path / "msg"
    msg.write_text("x\n")
    signers = tmp_path / "signers"
    signers.write_text(SIGNERS)
    dco.main(["--warn-local", str(msg), "A Maintainer <maint@example.com> 1763300000 +0000", str(signers)])
    assert capsys.readouterr().out.strip() == "OK"


HOOK = pathlib.Path(__file__).resolve().parents[2] / ".githooks" / "commit-msg"


def test_success_the_commit_msg_hook_runs_the_local_check_with_the_real_inputs():
    text = HOOK.read_text()
    assert 'scripts/check-dco.py" --warn-local "$1" "$(git var GIT_AUTHOR_IDENT)"' in text, (
        "the commit-msg hook must pass the message file and git's author identity to check-dco.py"
    )
    assert ".github/allowed_signers" in text


def test_edge_the_commit_msg_hook_never_refuses_on_the_dco_warning():
    text = HOOK.read_text()
    block = text[text.index("DCO sign-off"):]
    assert "exit 1" not in block, "the DCO block of the commit-msg hook only warns"


REPO = pathlib.Path(__file__).resolve().parents[2]


def _section(rel, heading):
    text = (REPO / rel).read_text()
    start = text.index(f"\n## {heading}\n")
    end = text.find("\n## ", start + 1)
    return " ".join(text[start : end if end != -1 else len(text)].split())


def test_success_contributing_tells_a_contributor_how_to_sign_off():
    text = _section("CONTRIBUTING.md", "Signing off commits")
    for needle in ["git commit -s", "git rebase --signoff", "scripts/check-dco.py", "`DCO`", "both apply"]:
        assert needle in text, f"CONTRIBUTING.md's DCO section must mention {needle!r}"


def test_success_maintainers_lists_the_owner_steps_of_the_switch():
    text = _section("MAINTAINERS.md", "The contributor agreement")
    for needle in ["require the `DCO` check", "remove `license/cla`", "Turn CLA Assistant off"]:
        assert needle in text, f"MAINTAINERS.md's agreement section must mention {needle!r}"


def test_success_the_workflow_runs_this_script_on_main_code():
    wf = (REPO / ".github/workflows/pr-text.yml").read_text()
    assert 'python3 scripts/check-dco.py --owner "$OWNER"' in wf
    assert "    name: DCO\n" in wf, "the job's check name is `DCO`, the name branch protection will require"


def test_edge_main_warn_local_with_unreadable_files_exits_0_and_says_so(tmp_path, capsys):
    rc = dco.main(["--warn-local", str(tmp_path / "absent"), "contributor@example.com", str(tmp_path / "absent2")])
    assert rc == 0 and "NOT CHECKED" in capsys.readouterr().out


# ------------------------------------------- the noreply rule, decision (viii)
#
# A sign-off passes only when it names the author email AND that email is a
# GitHub noreply address: `<ID>+<login>@users.noreply.github.com`, or
# `<login>@users.noreply.github.com` for an older account.


def test_success_a_noreply_sign_off_without_an_id_passes():
    email = f"contrib-login{AT}{NOREPLY}"
    msg = f"x\n\nSigned-off-by: A Contributor <{email}>\n"
    ok, why = dco.verdict(commit(message=msg, author_email=email), OWNER)
    assert ok, why


def test_success_the_noreply_domain_compares_without_case():
    email = f"12345+contrib-login{AT}Users.NoReply.GitHub.com"
    msg = f"x\n\nSigned-off-by: A Contributor <{email}>\n"
    assert dco.verdict(commit(message=msg, author_email=email), OWNER)[0]


def test_success_is_noreply_accepts_both_forms_and_a_bot_login():
    for address in (EMAIL, f"contrib-login{AT}{NOREPLY}", f"49699333+dependabot[bot]{AT}{NOREPLY}"):
        assert dco.is_noreply(address), address


def test_success_the_reason_for_a_noreply_sign_off_names_the_signer():
    ok, why = dco.verdict(commit(message=SIGNED), OWNER)
    assert ok and why == "signed off by A Contributor", why


def test_success_the_local_check_is_quiet_for_a_maintainer_without_a_noreply_address():
    # A maintainer's commits are exempt by signature on GitHub; the hook
    # tells them apart by .github/allowed_signers.
    assert dco.local_warning("x\n", "maint@example.com", SIGNERS) is None


def test_failure_a_sign_off_naming_a_personal_author_email_fails():
    msg = f"x\n\nSigned-off-by: A Contributor <{PERSONAL}>\n"
    ok, why = dco.verdict(commit(message=msg, author_email=PERSONAL), OWNER)
    assert not ok and "not a GitHub noreply address" in why, why


def test_failure_a_personal_author_email_is_not_printed_to_the_public_log():
    msg = f"x\n\nSigned-off-by: A Contributor <{PERSONAL}>\n"
    for c in (commit(message=msg, author_email=PERSONAL), commit(message="x\n", author_email=PERSONAL),
              commit(message=SIGNED, author_email=PERSONAL)):
        rc, lines = dco.check([c], OWNER)
        assert rc == 1 and not any(PERSONAL in line for line in lines), lines


def test_failure_a_mismatched_sign_off_from_a_personal_author_says_the_address_is_not_shown():
    ok, why = dco.verdict(commit(message=SIGNED, author_email=PERSONAL), OWNER)
    assert not ok and "not shown" in why, why


def test_failure_another_logins_noreply_address_fails():
    other = f"999+someone-else{AT}{NOREPLY}"
    msg = f"x\n\nSigned-off-by: Someone Else <{other}>\n"
    ok, why = dco.verdict(commit(message=msg), OWNER)
    assert not ok and EMAIL in why, why


def test_failure_a_lookalike_noreply_domain_fails():
    email = f"12345+contrib-login{AT}{NOREPLY}.example.com"
    msg = f"x\n\nSigned-off-by: A Contributor <{email}>\n"
    ok, why = dco.verdict(commit(message=msg, author_email=email), OWNER)
    assert not ok and "not a GitHub noreply address" in why, why


def test_failure_the_fix_says_to_use_the_noreply_address():
    rc, lines = dco.check([commit(message="x\n", author_email=PERSONAL)], OWNER)
    assert any("noreply" in line for line in lines), lines


def test_failure_the_local_check_warns_for_a_personal_author_email():
    msg = f"x\n\nSigned-off-by: A Contributor <{PERSONAL}>\n"
    warning = dco.local_warning(msg, PERSONAL, SIGNERS)
    assert warning and "noreply" in warning, warning


def test_failure_main_exits_1_for_a_personal_sign_off_from_the_api_shape(tmp_path):
    f = tmp_path / "commits.json"
    msg = f"x\n\nSigned-off-by: A Contributor <{PERSONAL}>\n"
    f.write_text(json.dumps([api_commit(message=msg, email=PERSONAL)]))
    assert dco.main(["--owner", OWNER, str(f)]) == 1


@pytest.mark.parametrize(
    "address",
    [
        f"-contrib{AT}{NOREPLY}",
        f"contrib-{AT}{NOREPLY}",
        f"{'a' * 40}{AT}{NOREPLY}",
        f"{AT}{NOREPLY}",
        f"+contrib{AT}{NOREPLY}",
        f"12x+contrib{AT}{NOREPLY}",
        f"contrib{AT}x{NOREPLY}",
        f"contrib{AT}noreply.github.com",
        f"con trib{AT}{NOREPLY}",
        "",
    ],
)
def test_edge_is_noreply_refuses_what_github_never_issues(address):
    assert not dco.is_noreply(address), address


def test_edge_a_39_character_login_is_the_longest_accepted():
    assert dco.is_noreply(f"{'a' * 39}{AT}{NOREPLY}")
    assert dco.is_noreply(f"1+{'a' * 39}{AT}{NOREPLY}")


def test_edge_a_login_with_inner_hyphens_is_accepted():
    assert dco.is_noreply(f"7+a-b-c{AT}{NOREPLY}")


def test_edge_the_noreply_check_reads_the_author_email_not_the_sign_off():
    # The sign-off names a noreply address in different case from the
    # author email; both are the same address, so it passes.
    msg = f"x\n\nSigned-off-by: A Contributor <{EMAIL.upper()}>\n"
    assert dco.verdict(commit(message=msg, author_email=EMAIL), OWNER)[0]


def test_edge_a_bot_and_an_owner_commit_need_no_noreply_address():
    bot = commit(author_login="dependabot[bot]", author_type="Bot", verified=True, author_email=PERSONAL)
    owner = commit(author_login=OWNER, committer_login=OWNER, verified=True, author_email=PERSONAL)
    assert dco.verdict(bot, OWNER)[0] and dco.verdict(owner, OWNER)[0]


def test_edge_text_after_the_address_is_not_a_sign_off():
    msg = f"x\n\nSigned-off-by: A Contributor <{EMAIL}> on behalf of someone\n"
    assert not dco.verdict(commit(message=msg), OWNER)[0]


def test_edge_the_local_check_names_a_noreply_author_email():
    warning = dco.local_warning("x\n", EMAIL, SIGNERS)
    assert warning and EMAIL in warning, warning
