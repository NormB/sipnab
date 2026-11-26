# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""The site's RFC 9116 security.txt, and the check that keeps it current.

https://sipnab.com/.well-known/security.txt answered 404 until this file was
added (world-class audit, 2026-11-24). The file is
website/static/.well-known/security.txt; `zola build` copies static/ to the
site, and pages.yml uploads it with hidden paths included, because the upload
action leaves out every path that starts with a dot unless told otherwise.

RFC 9116 requires an `Expires` field, and a file past it "should not be used"
(section 5.3). So this test fails when the tracked file has 30 days or fewer
left, on every commit, and cert-expiry.yml runs the same check against the
live site every day: the file is renewed before it goes stale.

The rules are tested as pure functions over the file's bytes and a given
clock. The live read (`--url`) reaches the network, which a test must not; its
header and body checks are the functions tested here, and the request itself
is not driven.
"""

import datetime as dt
import pathlib
import re
import subprocess
import sys

import pytest
from conftest import load

sectxt = load("check-security-txt")

REPO = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts/check-security-txt.py"
TRACKED = REPO / "website/static/.well-known/security.txt"
SECURITY_MD = REPO / "SECURITY.md"
PAGES = REPO / ".github/workflows/pages.yml"
CERT_EXPIRY = REPO / ".github/workflows/cert-expiry.yml"
QUALITY = REPO / ".github/workflows/quality.yml"
LYCHEE = REPO / "lychee.toml"
LIVE_URL = "https://sipnab.com/.well-known/security.txt"

NOW = dt.datetime(2026, 11, 24, 12, 0, 0, tzinfo=dt.timezone.utc)
GOOD_EXPIRES = "2027-06-01T00:00:00Z"


def doc(*lines, eol="\n"):
    """A security.txt body: each line followed by `eol`."""
    return "".join(line + eol for line in lines).encode("utf-8")


def minimal(**over):
    fields = {
        "Contact": "mailto:security@example.com",
        "Expires": GOOD_EXPIRES,
    }
    fields.update(over)
    return doc(*(f"{k}: {v}" for k, v in fields.items() if v is not None))


def problems(data, now=NOW, **kw):
    return sectxt.problems(data, now, **kw)


# ---------------------------------------------------------------- success


SUCCESS = {
    "minimal": minimal(),
    "crlf line ends": doc("Contact: mailto:security@example.com",
                          f"Expires: {GOOD_EXPIRES}", eol="\r\n"),
    "comment lines": doc("# Report security issues here.",
                         "Contact: mailto:security@example.com",
                         "# A comment with a tab\tand unicode é",
                         f"Expires: {GOOD_EXPIRES}"),
    "blank lines": doc("", "Contact: mailto:security@example.com", "",
                       f"Expires: {GOOD_EXPIRES}", ""),
    "two contacts": doc("Contact: mailto:security@example.com",
                        "Contact: https://example.com/report",
                        f"Expires: {GOOD_EXPIRES}"),
    "tel contact": doc("Contact: tel:+1-201-555-0123",
                       f"Expires: {GOOD_EXPIRES}"),
    "every RFC field": doc(
        "Acknowledgments: https://example.com/thanks",
        "Canonical: https://example.com/.well-known/security.txt",
        "Contact: mailto:security@example.com",
        "Encryption: https://example.com/pgp-key.txt",
        f"Expires: {GOOD_EXPIRES}",
        "Hiring: https://example.com/jobs",
        "Policy: https://example.com/policy",
        "Preferred-Languages: en",
    ),
    "several languages": minimal(**{"Preferred-Languages": "en, es,fr"}),
    "region subtag": minimal(**{"Preferred-Languages": "en-US"}),
    "lowercase z": minimal(Expires="2027-06-01T00:00:00z"),
    "numeric offset": minimal(Expires="2027-06-01T00:00:00-05:00"),
    "fractional seconds": minimal(Expires="2027-06-01T00:00:00.250Z"),
    "openpgp4fpr encryption": minimal(
        Encryption="openpgp4fpr:5f2de5521c63a801ab59ccb603d49de44b29100f"),
    "dns encryption": minimal(
        Encryption="dns:5d2d37ab76d47d36._openpgpkey.example.com?type=OPENPGPKEY"),
    "unregistered field is ignored": minimal(**{"X-Extra": "anything"}),
    "percent-encoded mailto": minimal(
        Contact="mailto:security%2Buri%2Bencoded@example.com"),
}


@pytest.mark.parametrize("name", sorted(SUCCESS))
def test_valid_file_has_no_problems(name):
    assert problems(SUCCESS[name]) == [], f"{name}: a valid file was refused"


# ---------------------------------------------------------------- failure


FAILURE = {
    "no contact": (minimal(Contact=None), "Contact"),
    "no expires": (minimal(Expires=None), "Expires"),
    "two expires": (doc("Contact: mailto:security@example.com",
                        f"Expires: {GOOD_EXPIRES}",
                        "Expires: 2027-07-01T00:00:00Z"), "Expires"),
    "expires not a date": (minimal(Expires="next year"), "Expires"),
    "expires without time zone": (minimal(Expires="2027-06-01T00:00:00"),
                                  "Expires"),
    "expires date only": (minimal(Expires="2027-06-01"), "Expires"),
    "expired": (minimal(Expires="2026-11-01T00:00:00Z"), "expired"),
    "more than 366 days out": (minimal(Expires="2027-12-01T00:00:00Z"),
                               "366"),
    "http contact": (minimal(Contact="http://example.com/report"), "https"),
    "bare email contact": (minimal(Contact="security@example.com"), "URI"),
    "http policy": (minimal(Policy="http://example.com/policy"), "https"),
    "http canonical": (minimal(
        Canonical="http://example.com/.well-known/security.txt"), "https"),
    "http acknowledgments": (minimal(Acknowledgments="http://example.com/a"),
                             "https"),
    "http encryption": (minimal(Encryption="http://example.com/key.txt"),
                        "https"),
    "http hiring": (minimal(Hiring="http://example.com/jobs"), "https"),
    "two language fields": (doc("Contact: mailto:security@example.com",
                                f"Expires: {GOOD_EXPIRES}",
                                "Preferred-Languages: en",
                                "Preferred-Languages: fr"),
                            "Preferred-Languages"),
    "empty language list": (minimal(**{"Preferred-Languages": ","}),
                            "Preferred-Languages"),
    "bad language tag": (minimal(**{"Preferred-Languages": "english!"}),
                         "Preferred-Languages"),
    "no space after colon": (doc("Contact:mailto:security@example.com",
                                 f"Expires: {GOOD_EXPIRES}"), "line 1"),
    "line without colon": (doc("Contact mailto:security@example.com",
                               f"Expires: {GOOD_EXPIRES}"), "line 1"),
    "last line has no line end": (minimal()[:-1], "line end"),
    "not utf-8": (minimal() + b"# \xff\xfe\n", "UTF-8"),
    "empty file": (b"", "Contact"),
    "pgp signed form": (b"-----BEGIN PGP SIGNED MESSAGE-----\n" + minimal(),
                        "line 1"),
    "contact with spaces": (minimal(Contact="mailto:security @example.com"),
                            "URI"),
}


@pytest.mark.parametrize("name", sorted(FAILURE))
def test_invalid_file_is_refused_with_the_reason(name):
    data, needle = FAILURE[name]
    found = problems(data)
    assert found, f"{name}: an invalid file was accepted"
    assert any(needle in p for p in found), (
        f"{name}: no problem names {needle!r}: {found}")


# ---------------------------------------------------------------- edges


def test_expires_exactly_366_days_out_is_accepted():
    data = minimal(Expires=(NOW + dt.timedelta(days=366)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"))
    assert problems(data) == [], "366 days is the documented upper bound"


def test_expires_one_second_past_366_days_is_refused():
    when = NOW + dt.timedelta(days=366, seconds=1)
    found = problems(minimal(Expires=when.strftime("%Y-%m-%dT%H:%M:%SZ")))
    assert any("366" in p for p in found), f"past the bound accepted: {found}"


def test_expires_31_days_out_is_accepted():
    when = NOW + dt.timedelta(days=31)
    assert problems(minimal(Expires=when.strftime("%Y-%m-%dT%H:%M:%SZ"))) == [], (
        "31 days left is outside the renewal window")


def test_expires_exactly_30_days_out_asks_for_renewal():
    when = NOW + dt.timedelta(days=30)
    found = problems(minimal(Expires=when.strftime("%Y-%m-%dT%H:%M:%SZ")))
    assert any("renew" in p for p in found), (
        f"30 days left did not ask for renewal: {found}")


def test_expires_one_hour_out_asks_for_renewal_not_expired():
    when = NOW + dt.timedelta(hours=1)
    found = problems(minimal(Expires=when.strftime("%Y-%m-%dT%H:%M:%SZ")))
    assert any("renew" in p for p in found), f"no renewal asked: {found}"
    assert not any("expired" in p for p in found), (
        f"a future date was called expired: {found}")


def test_expires_equal_to_now_is_expired():
    found = problems(minimal(Expires=NOW.strftime("%Y-%m-%dT%H:%M:%SZ")))
    assert any("expired" in p for p in found), f"now is not expired: {found}"


def test_offset_is_applied_before_comparing():
    # 2026-11-24T23:00:00+14:00 is 09:00 UTC, before NOW (12:00 UTC).
    found = problems(minimal(Expires="2026-11-24T23:00:00+14:00"))
    assert any("expired" in p for p in found), (
        f"the offset was ignored: {found}")


def test_negative_offset_is_applied_before_comparing():
    # 2026-11-24T08:00:00-05:00 is 13:00 UTC, one hour after NOW.
    found = problems(minimal(Expires="2026-11-24T08:00:00-05:00"))
    assert not any("expired" in p for p in found), (
        f"a negative offset was read as positive: {found}")
    assert any("renew" in p for p in found), f"no renewal asked: {found}"


def test_renewal_window_is_a_parameter():
    when = NOW + dt.timedelta(days=45)
    data = minimal(Expires=when.strftime("%Y-%m-%dT%H:%M:%SZ"))
    assert problems(data) == [], "45 days left is fine at the default window"
    found = problems(data, warn_days=60)
    assert any("renew" in p for p in found), (
        f"a 60-day window did not ask for renewal at 45 days: {found}")


def test_field_names_are_case_insensitive():
    data = doc("contact: mailto:security@example.com",
               f"EXPIRES: {GOOD_EXPIRES}")
    assert problems(data) == [], "RFC 5322 field names are case-insensitive"


def test_trailing_whitespace_before_line_end_is_accepted():
    data = doc("Contact: mailto:security@example.com  ",
               f"Expires: {GOOD_EXPIRES}\t")
    assert problems(data) == [], "eol = *WSP [CR] LF allows trailing blanks"


def test_byte_order_mark_is_refused():
    found = problems(b"\xef\xbb\xbf" + minimal())
    assert found, "a byte order mark is not part of the ABNF"


def test_problems_name_the_line_number():
    data = doc("Contact: mailto:security@example.com",
               f"Expires: {GOOD_EXPIRES}",
               "Broken line")
    found = problems(data)
    assert any("line 3" in p for p in found), f"no line number: {found}"


def test_every_problem_is_reported_not_just_the_first():
    data = doc("Policy: http://example.com/policy", "Broken")
    found = problems(data)
    assert len(found) >= 4, (
        f"expected Contact, Expires, https and line problems: {found}")


def test_naive_clock_is_refused():
    with pytest.raises(ValueError, match="time zone"):
        sectxt.problems(minimal(), dt.datetime(2026, 11, 24, 12, 0, 0))


# ---------------------------------------------------------------- serving


@pytest.mark.parametrize("header", [
    "text/plain; charset=utf-8",
    "text/plain;charset=UTF-8",
    "Text/Plain; Charset=\"utf-8\"",
])
def test_utf8_text_plain_is_accepted(header):
    assert sectxt.content_type_problems(header) == [], (
        f"{header!r} is text/plain in UTF-8")


@pytest.mark.parametrize("header", [
    None,
    "",
    "text/html; charset=utf-8",
    "text/plain",
    "text/plain; charset=iso-8859-1",
    "application/octet-stream",
])
def test_other_content_types_are_refused(header):
    assert sectxt.content_type_problems(header), (
        f"{header!r} is not text/plain with charset utf-8 (RFC 9116 section 3)")


def make_tree(root, paths):
    for rel in paths:
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("x\n", encoding="utf-8")


def test_hidden_paths_allow_well_known_only(tmp_path):
    make_tree(tmp_path, ["index.html", ".well-known/security.txt",
                         "wasm/sipnab.js"])
    assert sectxt.hidden_paths(tmp_path) == [], (
        ".well-known is the one hidden directory the site publishes")


def test_hidden_paths_name_every_other_dot_path(tmp_path):
    make_tree(tmp_path, [".well-known/security.txt", "wasm/.gitignore",
                         ".env", "a/.b/c.txt"])
    assert sectxt.hidden_paths(tmp_path) == [".env", "a/.b", "wasm/.gitignore"], (
        "each hidden path outside .well-known is named, sorted")


def test_hidden_paths_name_a_dot_file_inside_well_known(tmp_path):
    make_tree(tmp_path, [".well-known/security.txt", ".well-known/.secret"])
    assert sectxt.hidden_paths(tmp_path) == [".well-known/.secret"], (
        "only .well-known itself is allowed to start with a dot")


# ---------------------------------------------------------------- the project


def security_md_contact():
    found = re.findall(r"\*\*([^*@\s]+@[^*\s]+)\*\*", SECURITY_MD.read_text(
        encoding="utf-8"))
    assert found, "SECURITY.md names no reporting address"
    return found[0]


def test_tracked_file_exists():
    assert TRACKED.is_file(), f"{TRACKED} is missing; the site serves 404"


def test_tracked_file_passes_at_the_real_clock():
    found = sectxt.problems(TRACKED.read_bytes(),
                            dt.datetime.now(dt.timezone.utc))
    assert found == [], (
        f"{TRACKED.relative_to(REPO)} needs work (renew: set Expires to a "
        f"date at most 366 days out): {found}")


def test_tracked_file_matches_the_project():
    found = sectxt.project_problems(
        TRACKED.read_bytes(), SECURITY_MD.read_text(encoding="utf-8"),
        "https://sipnab.com")
    assert found == [], f"security.txt and the project disagree: {found}"


def test_project_check_wants_the_security_md_address_first():
    data = doc("Contact: mailto:other@example.com",
               f"Contact: mailto:{security_md_contact()}",
               f"Expires: {GOOD_EXPIRES}",
               "Canonical: https://sipnab.com/.well-known/security.txt",
               "Policy: https://github.com/NormB/sipnab/blob/main/SECURITY.md",
               "Preferred-Languages: en")
    found = sectxt.project_problems(
        data, SECURITY_MD.read_text(encoding="utf-8"), "https://sipnab.com")
    assert any("Contact" in p for p in found), (
        f"the first Contact must be SECURITY.md's address: {found}")


@pytest.mark.parametrize("missing", ["Canonical", "Policy",
                                     "Preferred-Languages"])
def test_project_check_wants_each_field(missing):
    lines = {
        "Contact": f"mailto:{security_md_contact()}",
        "Expires": GOOD_EXPIRES,
        "Canonical": "https://sipnab.com/.well-known/security.txt",
        "Policy": "https://github.com/NormB/sipnab/blob/main/SECURITY.md",
        "Preferred-Languages": "en",
    }
    del lines[missing]
    data = doc(*(f"{k}: {v}" for k, v in lines.items()))
    found = sectxt.project_problems(
        data, SECURITY_MD.read_text(encoding="utf-8"), "https://sipnab.com")
    assert any(missing in p for p in found), (
        f"{missing} missing was not reported: {found}")


def test_project_check_wants_canonical_on_the_site():
    data = doc(f"Contact: mailto:{security_md_contact()}",
               f"Expires: {GOOD_EXPIRES}",
               "Canonical: https://example.com/.well-known/security.txt",
               "Policy: https://github.com/NormB/sipnab/blob/main/SECURITY.md",
               "Preferred-Languages: en")
    found = sectxt.project_problems(
        data, SECURITY_MD.read_text(encoding="utf-8"), "https://sipnab.com")
    assert any("Canonical" in p for p in found), (
        f"a Canonical off the site was accepted: {found}")


def test_base_url_is_the_site_config():
    config = (REPO / "website/config.toml").read_text(encoding="utf-8")
    assert 'base_url = "https://sipnab.com"' in config, (
        "the project check is pinned to https://sipnab.com; update both")


# ---------------------------------------------------------------- deploy


def test_pages_upload_includes_hidden_paths():
    text = PAGES.read_text(encoding="utf-8")
    block = text.split("- name: Upload Pages artifact", 1)[1].split("\n\n", 1)[0]
    assert re.search(r"^\s+include-hidden-files: true$", block, re.M), (
        "upload-pages-artifact leaves out every dot path unless "
        "include-hidden-files is true, so /.well-known/security.txt is never "
        f"deployed:\n{block}")


def test_pages_checks_the_built_site_before_upload():
    text = PAGES.read_text(encoding="utf-8")
    check = text.find("scripts/check-security-txt.py --site website/public")
    upload = text.find("- name: Upload Pages artifact")
    build = text.find("run: zola build")
    assert build != -1 and check != -1 and upload != -1, (
        "pages.yml must run the security.txt site check")
    assert build < check < upload, (
        "the check must read the built tree, after zola build, before upload")


def test_pages_removes_the_wasm_pack_gitignore():
    text = PAGES.read_text(encoding="utf-8")
    assert "rm -f website/static/wasm/.gitignore" in text, (
        "wasm-pack writes a .gitignore into its output directory; with hidden "
        "paths uploaded it would be published")


def test_pages_rebuilds_on_changes_to_the_check_and_its_inputs():
    text = PAGES.read_text(encoding="utf-8")
    paths = text.split("paths:", 1)[1].split("workflow_dispatch:", 1)[0]
    for p in ("scripts/check-security-txt.py", "SECURITY.md"):
        assert f"- '{p}'" in paths, (
            f"pages.yml runs the check, which reads {p}; its push paths lack it")


def test_daily_check_reads_the_live_file():
    text = CERT_EXPIRY.read_text(encoding="utf-8")
    assert ("scripts/check-security-txt.py --url "
            "https://sipnab.com/.well-known/security.txt") in text, (
        "cert-expiry.yml must check the live security.txt every day")


def test_daily_check_runs_on_changes_to_the_file_and_script():
    text = CERT_EXPIRY.read_text(encoding="utf-8")
    paths = text.split("paths:", 1)[1].split("permissions:", 1)[0]
    for p in ("scripts/check-security-txt.py",
              "website/static/.well-known/security.txt", "SECURITY.md"):
        assert f"- '{p}'" in paths, f"cert-expiry.yml push paths lack {p}"


# ------------------------------------------------- the docs dead-link pass
# SECURITY.md links the live file, which the site serves only after Pages
# deploys the change that adds or moves it. The docs pass runs before that, so
# it remaps the URL to the committed file the site serves, and lychee then
# fails when that file is missing from the tree.


def docs_link_pass():
    text = QUALITY.read_text(encoding="utf-8")
    step = text.split("- name: Dead links (docs Markdown)", 1)[1]
    return step.split("- name:", 1)[0]


REMAP_RE = re.compile(
    r"--remap \"\^https://sipnab\\\.com/\\\.well-known/security\\\.txt\\\$ "
    r"file://\$GITHUB_WORKSPACE/(?P<target>[^\"\s]+)\"")


def test_docs_link_pass_remaps_the_live_security_txt():
    assert REMAP_RE.search(docs_link_pass()), (
        "the docs dead-link pass must remap the live security.txt URL to the "
        "committed file, because the live file exists only after a deploy")


def test_docs_link_pass_remap_target_is_the_committed_file():
    m = REMAP_RE.search(docs_link_pass())
    assert m, "the docs dead-link pass has no security.txt remap"
    assert REPO / m.group("target") == TRACKED, (
        f"the remap points at {m.group('target')}, not the file the site serves")


def test_docs_link_pass_remap_target_exists():
    m = REMAP_RE.search(docs_link_pass())
    assert m, "the docs dead-link pass has no security.txt remap"
    assert (REPO / m.group("target")).is_file(), (
        f"the remap target {m.group('target')} is missing from the tree")


def test_lychee_does_not_exclude_the_live_security_txt():
    import tomllib
    config = tomllib.loads(LYCHEE.read_text(encoding="utf-8"))
    hits = [p for p in config.get("exclude", []) if re.search(p, LIVE_URL)]
    assert not hits, (
        f"lychee.toml excludes {LIVE_URL} ({hits}); remap it instead, so the "
        "link is still checked")


def test_security_md_links_the_live_security_txt():
    assert f"<{LIVE_URL}>" in SECURITY_MD.read_text(encoding="utf-8"), (
        "SECURITY.md must link the live security.txt that the remap covers")


# ---------------------------------------------------------------- command


def run(*args):
    return subprocess.run([sys.executable, str(SCRIPT), *args],
                          capture_output=True, text=True, timeout=60,
                          check=False)


def test_cli_accepts_the_tracked_file():
    r = run("--file", str(TRACKED))
    assert r.returncode == 0, f"rc {r.returncode}: {r.stdout}{r.stderr}"


def test_cli_refuses_a_bad_file_and_names_it(tmp_path):
    bad = tmp_path / "security.txt"
    bad.write_bytes(minimal(Contact=None))
    r = run("--file", str(bad))
    assert r.returncode == 1, f"rc {r.returncode}: {r.stdout}{r.stderr}"
    assert "Contact" in r.stderr and str(bad) in r.stderr, (
        f"the refusal must name the file and the field: {r.stderr}")


def test_cli_refuses_a_missing_file(tmp_path):
    r = run("--file", str(tmp_path / "absent.txt"))
    assert r.returncode == 1, f"rc {r.returncode}: {r.stdout}{r.stderr}"
    assert "absent.txt" in r.stderr, f"no path in: {r.stderr}"


def test_cli_site_mode_accepts_a_good_tree(tmp_path):
    (tmp_path / ".well-known").mkdir()
    (tmp_path / ".well-known/security.txt").write_bytes(TRACKED.read_bytes())
    (tmp_path / "index.html").write_text("<p></p>\n", encoding="utf-8")
    r = run("--site", str(tmp_path))
    assert r.returncode == 0, f"rc {r.returncode}: {r.stdout}{r.stderr}"


def test_cli_site_mode_refuses_a_tree_without_the_file(tmp_path):
    (tmp_path / "index.html").write_text("<p></p>\n", encoding="utf-8")
    r = run("--site", str(tmp_path))
    assert r.returncode == 1, f"rc {r.returncode}: {r.stdout}{r.stderr}"
    assert "security.txt" in r.stderr, f"no file named in: {r.stderr}"


def test_cli_site_mode_refuses_another_hidden_path(tmp_path):
    (tmp_path / ".well-known").mkdir()
    (tmp_path / ".well-known/security.txt").write_bytes(TRACKED.read_bytes())
    (tmp_path / "wasm").mkdir()
    (tmp_path / "wasm/.gitignore").write_text("*\n", encoding="utf-8")
    r = run("--site", str(tmp_path))
    assert r.returncode == 1, f"rc {r.returncode}: {r.stdout}{r.stderr}"
    assert "wasm/.gitignore" in r.stderr, f"path not named in: {r.stderr}"


def test_cli_without_a_mode_is_a_usage_error():
    r = run()
    assert r.returncode == 2, f"rc {r.returncode}: {r.stdout}{r.stderr}"
