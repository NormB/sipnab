# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""scripts/pages-live.py: the release verdict comes from the run's own artifact.

CDN-REFUSED-RELEASE-CHECK-FROM-RUNNER. On 2026-11-14 the 0.5.254 release run
(43581489173) ended red twice on "Advertise the release on the site": the
live stamp was this run's, and the CDN answered the hosted runner's read of
the download page with a browser challenge (403, `cf-mitigated: challenge`).
The CDN challenges reads of HTML pages from that runner image and answers
static `.txt` files from every runner.

So the verdict no longer depends on a read the edge can refuse:

* the build writes `advertised-release.txt` into the site: the run's stamp,
  the release the built download page names (judged by the verifier's own
  `--classify`) and that page's sha256;
* after the deploy, `verify --artifact` requires live stamp = the artifact's
  stamp = this run's stamp and judges the artifact's download page with the
  same `--classify`; the live read of the page stays as evidence, and a
  refused one is a warning;
* the daily check (`daily`) judges the two static files, and the live page
  when the edge answers it.

No test here reaches the network. The classifier is the real shell script
only in the tests that say so.
"""

import hashlib
import io
import tarfile

import pytest
from conftest import load

pl = load("pages-live")
REAL_RUNNER = pl.subprocess_runner
REAL_SLEEP = pl.time.sleep


@pytest.fixture(autouse=True)
def _no_real_world(monkeypatch):
    """No test reaches the network or sleeps: `main` falls back to these."""

    def refuse(*args, **kwargs):
        raise AssertionError(f"a test reached the real world: {args[:1]}")

    monkeypatch.setattr(pl, "subprocess_runner", refuse)
    monkeypatch.setattr(pl, "urllib_get", refuse)
    monkeypatch.setattr(pl.time, "sleep", refuse)


@pytest.fixture
def real_sleep(monkeypatch):
    """`time.sleep` as the interpreter has it: `subprocess` polls with it."""
    monkeypatch.setattr(pl.time, "sleep", REAL_SLEEP)


SHA = "8" * 40
RUN = "43584381370"
ENV = {"GITHUB_SHA": SHA, "GITHUB_RUN_ID": RUN, "GITHUB_RUN_ATTEMPT": "1", "GITHUB_REPOSITORY": "NormB/sipnab"}
STAMP = f"{SHA} {RUN} 1"
OTHER_STAMP = f"{SHA} 43595667037 1"
REL = "0.5.254"
OLD = "0.5.253"
PAGE = f"<html><h1>Download sipnab {REL}</h1><p>sha256 checksums</p></html>\n".encode()
PAGE_OLD = f"<html><h1>Download sipnab {OLD}</h1><p>sha256 checksums</p></html>\n".encode()
URL = "https://sipnab.example.invalid/deploy-stamp.txt"
ADV_URL = "https://sipnab.example.invalid/advertised-release.txt"
BASE = "https://sipnab.example.invalid/"
EDGE_403 = "edge: status=403 server=cloudflare cf-ray=a5a5d8541bb6b836-DFW cf-mitigated=challenge content-type=text/html"
CHALLENGED = (6, f"{EDGE_403}\nedge: first 200 bytes: Just a moment...\nBLOCKED: the edge refused this client (403).\n  Bot protection.\n")
ANSWERED = (0, f"edge: status=200 server=cloudflare cf-ray=a5a5591d181643b3-EWR cf-mitigated=- content-type=text/html\nOK: the page names {REL}.\n")
STALE_PAGE = (1, f"edge: status=200 server=cloudflare cf-ray=x cf-mitigated=- content-type=text/html\nSTALE: the page is healthy and does not name {REL}.\n")


def adv(stamp=STAMP, release=REL, page=PAGE):
    return pl.format_advertised(stamp, release, page)


def make_tar(path, members, mode="w"):
    """A tar at `path`. A member is (name, bytes) or a ready TarInfo."""
    with tarfile.open(path, mode) as t:
        for m in members:
            if isinstance(m, tarfile.TarInfo):
                t.addfile(m)
            else:
                info = tarfile.TarInfo(m[0])
                info.size = len(m[1])
                t.addfile(info, io.BytesIO(m[1]))
    return str(path)


def site_members(stamp=STAMP, page=PAGE, record=None, prefix="./"):
    record = adv(stamp=stamp, page=page) if record is None else record
    return [(f"{prefix}deploy-stamp.txt", (stamp + "\n").encode()),
            (f"{prefix}index.html", b"<html>home</html>"),
            (f"{prefix}download/index.html", page),
            (f"{prefix}advertised-release.txt", record.encode())]


def link(name, kind, target="deploy-stamp.txt"):
    info = tarfile.TarInfo(name)
    info.type = kind
    info.linkname = target
    return info


# ---------------------------------------------------------------------------
# Reading the artifact: three members, nothing written to disk
# ---------------------------------------------------------------------------


def test_success_the_three_files_are_read_from_the_artifact(tmp_path):
    got = pl.read_artifact(make_tar(tmp_path / "artifact.tar", site_members()))
    assert got == {"deploy-stamp.txt": (STAMP + "\n").encode(), "download/index.html": PAGE,
                   "advertised-release.txt": adv().encode()}


def test_success_names_without_the_dot_slash_are_read_too(tmp_path):
    got = pl.read_artifact(make_tar(tmp_path / "a.tar", site_members(prefix="")))
    assert got["download/index.html"] == PAGE


def test_success_the_other_members_of_a_site_are_passed_over(tmp_path):
    extra = [(f"./docs/page{n}/index.html", b"<html></html>") for n in range(575)]
    got = pl.read_artifact(make_tar(tmp_path / "a.tar", extra + site_members()))
    assert sorted(got) == ["advertised-release.txt", "deploy-stamp.txt", "download/index.html"]


def test_success_a_large_member_nobody_reads_does_not_refuse_the_artifact(tmp_path, monkeypatch):
    # The site carries a wasm bundle of several megabytes.
    monkeypatch.setattr(pl, "MAX_MEMBER", 1024)
    got = pl.read_artifact(make_tar(tmp_path / "a.tar", [("./analyzer.wasm", b"\0" * 5000)] + site_members()))
    assert got["download/index.html"] == PAGE


def test_failure_an_artifact_that_is_not_there_is_refused(tmp_path):
    with pytest.raises(pl.ArtifactError, match="artifact.tar"):
        pl.read_artifact(str(tmp_path / "artifact.tar"))


def test_failure_a_file_that_is_not_a_tar_is_refused(tmp_path):
    p = tmp_path / "artifact.tar"
    p.write_bytes(b"<html>Just a moment...</html>" * 100)
    with pytest.raises(pl.ArtifactError, match="not a tar"):
        pl.read_artifact(str(p))


@pytest.mark.parametrize("name", ["../deploy-stamp.txt", "./../../etc/passwd", "./download/../download/index.html",
                                  "docs/../../x", ".."])
def test_failure_a_member_that_climbs_out_of_the_site_refuses_the_whole_artifact(tmp_path, name):
    with pytest.raises(pl.ArtifactError, match="outside the site"):
        pl.read_artifact(make_tar(tmp_path / "a.tar", site_members() + [(name, b"x")]))


def test_failure_an_absolute_member_name_refuses_the_whole_artifact(tmp_path):
    with pytest.raises(pl.ArtifactError, match="outside the site"):
        pl.read_artifact(make_tar(tmp_path / "a.tar", [("/etc/passwd", b"x")] + site_members()))


@pytest.mark.parametrize("kind", [tarfile.SYMTYPE, tarfile.LNKTYPE])
def test_failure_a_link_in_the_place_of_a_file_that_is_read_is_refused(tmp_path, kind):
    members = [m for m in site_members() if m[0] != "./download/index.html"]
    with pytest.raises(pl.ArtifactError, match="not a regular file"):
        pl.read_artifact(make_tar(tmp_path / "a.tar", members + [link("./download/index.html", kind)]))


def test_failure_an_oversized_member_is_refused_before_it_is_read(tmp_path, monkeypatch):
    monkeypatch.setattr(pl, "MAX_MEMBER", 1024)
    with pytest.raises(pl.ArtifactError, match="1025 bytes"):
        pl.read_artifact(make_tar(tmp_path / "a.tar", site_members(page=b"d" * 1025)))


@pytest.mark.parametrize("missing", ["deploy-stamp.txt", "download/index.html", "advertised-release.txt"])
def test_failure_an_artifact_without_one_of_the_three_files_is_refused(tmp_path, missing):
    members = [m for m in site_members() if m[0] != f"./{missing}"]
    with pytest.raises(pl.ArtifactError, match=missing):
        pl.read_artifact(make_tar(tmp_path / "a.tar", members))


def test_failure_a_file_that_is_there_twice_is_refused(tmp_path):
    with pytest.raises(pl.ArtifactError, match="twice"):
        pl.read_artifact(make_tar(tmp_path / "a.tar", site_members() + [("deploy-stamp.txt", OTHER_STAMP.encode())]))


def test_edge_a_member_of_exactly_the_bound_is_read(tmp_path, monkeypatch):
    monkeypatch.setattr(pl, "MAX_MEMBER", 1024)
    page = b"d" * 1024
    assert pl.read_artifact(make_tar(tmp_path / "a.tar", site_members(page=page)))["download/index.html"] == page


def test_edge_an_empty_tar_has_none_of_the_files(tmp_path):
    with pytest.raises(pl.ArtifactError, match="deploy-stamp.txt"):
        pl.read_artifact(make_tar(tmp_path / "a.tar", []))


def test_edge_an_artifact_of_more_members_than_the_bound_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(pl, "MAX_MEMBERS", 10)
    extra = [(f"./p{n}.html", b"x") for n in range(11)]
    with pytest.raises(pl.ArtifactError, match="more than 10 members"):
        pl.read_artifact(make_tar(tmp_path / "a.tar", extra + site_members()))


def test_edge_a_directory_in_the_place_of_a_file_that_is_read_is_refused(tmp_path):
    members = [m for m in site_members() if m[0] != "./advertised-release.txt"]
    d = tarfile.TarInfo("./advertised-release.txt")
    d.type = tarfile.DIRTYPE
    with pytest.raises(pl.ArtifactError, match="not a regular file"):
        pl.read_artifact(make_tar(tmp_path / "a.tar", members + [d]))


def test_edge_a_tar_cut_short_is_refused(tmp_path):
    whole = tmp_path / "whole.tar"
    make_tar(whole, [("./big.bin", b"b" * 20000)] + site_members())
    cut = tmp_path / "a.tar"
    cut.write_bytes(whole.read_bytes()[:9000])
    with pytest.raises(pl.ArtifactError):
        pl.read_artifact(str(cut))


def test_edge_a_compressed_tar_is_refused_because_nothing_is_decompressed(tmp_path):
    with pytest.raises(pl.ArtifactError, match="not a tar"):
        pl.read_artifact(make_tar(tmp_path / "a.tar", site_members(), mode="w:gz"))


def test_edge_a_link_that_nobody_reads_does_not_refuse_the_artifact(tmp_path):
    got = pl.read_artifact(make_tar(tmp_path / "a.tar", site_members() + [link("./latest", tarfile.SYMTYPE)]))
    assert got["deploy-stamp.txt"] == (STAMP + "\n").encode()


# ---------------------------------------------------------------------------
# advertised-release.txt: what the build says its download page names
# ---------------------------------------------------------------------------


def test_success_the_record_is_three_lines_the_stamp_the_release_and_the_pages_sha256():
    assert adv() == f"stamp {STAMP}\nrelease {REL}\nsha256 {hashlib.sha256(PAGE).hexdigest()}\n"


def test_success_a_record_is_read_back_as_it_was_written():
    assert pl.parse_advertised(adv()) == (STAMP, REL, hashlib.sha256(PAGE).hexdigest())


@pytest.mark.parametrize("text", [
    "", "<html>Just a moment...</html>", STAMP, f"stamp {STAMP}\nrelease {REL}\n",
    f"stamp {STAMP}\nrelease {REL}\nsha256 {'g' * 64}\n", f"stamp {STAMP}\nrelease v{REL}\nsha256 {'a' * 64}\n",
    f"stamp {SHA} {RUN}\nrelease {REL}\nsha256 {'a' * 64}\n", f"release {REL}\nstamp {STAMP}\nsha256 {'a' * 64}\n",
    f"stamp {STAMP}\nrelease {REL}\nsha256 {'a' * 64}\nrelease 9.9.9\n", f"stamp {STAMP}\nrelease {REL}\nsha256 {'a' * 63}\n",
])
def test_failure_text_that_is_not_a_record_is_not_read_as_one(text):
    assert pl.parse_advertised(text) is None


def test_edge_a_record_with_crlf_and_surrounding_whitespace_is_read():
    assert pl.parse_advertised("\n " + adv().replace("\n", "\r\n") + "\n") == pl.parse_advertised(adv())


def test_edge_the_sha256_is_of_the_bytes_not_of_decoded_text():
    page = b"<html>download \xff\xfe 0.5.254</html>"
    assert pl.parse_advertised(adv(page=page)).sha256 == hashlib.sha256(page).hexdigest()


# ---------------------------------------------------------------------------
# One rule for a live page and an artifact page: the verifier's --classify
# ---------------------------------------------------------------------------


class World:
    """The live site, the classifier and the Pages API, on one clock."""

    def __init__(self):
        self.now = 1_800_000_000.0
        self.calls = []
        self.stamp = [(200, STAMP)]
        self.record = [(200, adv().strip())]
        self.page = [ANSWERED]
        self.classifier = None
        self.page_urls = []

    def sleep(self, s):
        self.now += s

    def clock(self):
        return self.now

    @staticmethod
    def _next(answers):
        return answers.pop(0) if len(answers) > 1 else answers[0]

    def count(self, what):
        return sum(what in " ".join(argv) for argv, _ in self.calls)

    def page_reads(self):
        return sum("verify-site-advertises.sh" in " ".join(argv) and "--classify" not in argv for argv, _ in self.calls)

    def __call__(self, argv, timeout, stdin=None):
        self.calls.append((argv, stdin))
        if len(self.calls) > 2000:
            raise RuntimeError("runaway")
        j = " ".join(argv)
        if argv[0] == "curl":
            status, body = self._next(self.record if "advertised-release.txt" in argv[-1] else self.stamp)
            return pl.Result(0, f"{body}\n{status}")
        if "verify-site-advertises.sh" in j and "--classify" in argv:
            if self.classifier is not None:
                return pl.Result(*self.classifier)
            status, _, body = (stdin or "").partition("\n")
            want = argv[-1]
            if status != "200" or not body.strip() or "download" not in body.lower():
                return pl.Result(5, "EMPTY: 200 carrying no download page.\n")
            if want in body:
                return pl.Result(0, f"OK: the page names {want}.\n")
            return pl.Result(1, f"STALE: the page is healthy and does not name {want}.\n")
        if "verify-site-advertises.sh" in j:
            if len(argv) > 3:
                self.page_urls.append(argv[3])
            return pl.Result(*self._next(self.page))
        if "actions/runs/" in j:
            return pl.Result(1, "gh: Not Found (HTTP 404)")
        raise AssertionError(f"no rule for {j}")


def test_success_a_page_is_judged_by_the_verifiers_classify_with_a_200_status_line():
    w = World()
    assert pl.judge_page(w, PAGE, REL).rc == 0
    argv, stdin = w.calls[0]
    assert argv[:1] == ["sh"] and argv[1].endswith("scripts/verify-site-advertises.sh") and argv[2:] == ["--classify", REL]
    assert stdin == "200\n" + PAGE.decode()


def test_success_the_real_classifier_says_the_artifact_page_names_the_release(real_sleep):
    r = pl.judge_page(REAL_RUNNER, PAGE, REL)
    assert (r.rc, r.out.splitlines()[0]) == (0, f"OK: the page names {REL}.")


def test_failure_the_real_classifier_says_a_page_of_the_release_before_is_stale(real_sleep):
    r = pl.judge_page(REAL_RUNNER, PAGE_OLD, REL)
    assert r.rc == 1 and r.out.startswith("STALE: ")


def test_edge_the_real_classifier_calls_a_page_without_download_furniture_empty(real_sleep):
    assert pl.judge_page(REAL_RUNNER, f"<html>{REL}</html>".encode(), REL).rc == 5


def test_edge_bytes_that_are_not_utf8_are_judged_and_not_raised_on():
    assert pl.judge_page(World(), b"download \xff " + REL.encode(), REL).rc == 0


# ---------------------------------------------------------------------------
# The build writes the record, and refuses a page that does not name the release
# ---------------------------------------------------------------------------


def built(tmp_path, page=PAGE, release=REL):
    site = tmp_path / "public"
    (site / "download").mkdir(parents=True)
    if page is not None:
        (site / "download" / "index.html").write_bytes(page)
    config = tmp_path / "config.toml"
    config.write_text(f'title = "sipnab"\n[extra]\nversion = "9.9.9"\npublished_version = "{release}"\nrelease_date = "2026-11-14"\n')
    return site, config


def run_advertised(tmp_path, w=None, env=ENV, **kw):
    site, config = built(tmp_path, **kw)
    rc = pl.main(["advertised", "--site", str(site), "--config", str(config)], dict(env), w or World())
    return rc, site / "advertised-release.txt"


def test_success_the_build_writes_the_record_beside_the_stamp(tmp_path, capsys):
    rc, record = run_advertised(tmp_path)
    assert rc == 0 and record.read_text() == adv()
    assert f"release {REL}" in capsys.readouterr().out


def test_success_the_record_names_the_release_of_the_site_config_not_the_crate_version(tmp_path):
    _, record = run_advertised(tmp_path)
    assert pl.parse_advertised(record.read_text()).release == REL


def test_success_the_build_with_the_real_classifier_writes_the_record(tmp_path, real_sleep):
    rc, record = run_advertised(tmp_path, w=REAL_RUNNER)
    assert rc == 0 and pl.parse_advertised(record.read_text()).sha256 == hashlib.sha256(PAGE).hexdigest()


def test_failure_a_built_page_that_does_not_name_the_release_fails_the_build_and_writes_nothing(tmp_path, capsys):
    rc, record = run_advertised(tmp_path, page=PAGE_OLD)
    assert rc == 1 and not record.exists()
    out = capsys.readouterr().out
    assert "::error::" in out and REL in out and "STALE" in out


def test_failure_a_build_without_a_download_page_fails(tmp_path, capsys):
    rc, record = run_advertised(tmp_path, page=None)
    assert rc == 1 and not record.exists() and "download/index.html" in capsys.readouterr().out


def test_failure_a_config_without_a_published_version_fails_the_build(tmp_path, capsys):
    rc, record = run_advertised(tmp_path, release="soon")
    assert rc == 1 and not record.exists() and "published_version" in capsys.readouterr().out


def test_failure_the_record_is_not_written_without_a_stamp(tmp_path, capsys):
    rc, record = run_advertised(tmp_path, env={**ENV, "GITHUB_RUN_ID": ""})
    assert rc == 2 and not record.exists()


def test_edge_a_classifier_that_could_not_run_fails_the_build(tmp_path, capsys):
    w = World()
    w.classifier = (127, "sh: not found")
    rc, record = run_advertised(tmp_path, w=w)
    assert rc == 1 and not record.exists()


# ---------------------------------------------------------------------------
# The release verdict: live stamp = artifact stamp = this run's stamp, and
# the artifact's page judged; the live read of the page is evidence
# ---------------------------------------------------------------------------


def cfg(artifact, **kw):
    base = dict(stamp=STAMP, url=URL, within=300.0, every=15.0, expect=REL, enforce=True, repo="NormB/sipnab",
                run_id=RUN, attempt="1", sha=SHA, artifact=artifact, advertised_url=ADV_URL)
    base.update(kw)
    return pl.Config(**base)


def verify(tmp_path, w=None, members=None, **kw):
    w = w or World()
    artifact = kw.pop("artifact", None)
    if artifact is None:
        artifact = make_tar(tmp_path / "artifact.tar", site_members() if members is None else members)
    return pl.verify(cfg(artifact, **kw), dict(ENV), w, None, w.sleep, w.clock), w


def test_success_stamp_live_artifact_names_the_release_and_the_live_page_agrees(tmp_path, capsys):
    rc, _ = verify(tmp_path)
    out = capsys.readouterr().out
    assert rc == 0 and "::error::" not in out and "::warning::" not in out


def test_success_stamp_live_artifact_names_the_release_and_a_challenged_live_read_is_a_pass_with_a_warning(tmp_path, capsys):
    # 0.5.254, runs 43584381370 and 43585110268: this is the case that ended red.
    w = World()
    w.page = [CHALLENGED]
    rc, _ = verify(tmp_path, w)
    out = capsys.readouterr().out
    assert rc == 0 and "::error::" not in out
    warning = [line for line in out.splitlines() if line.startswith("::warning::")]
    assert len(warning) == 1 and EDGE_403 in warning[0] and "artifact" in warning[0] and REL in warning[0]


def test_success_the_artifact_line_names_the_stamp_the_release_and_the_pages_sha256(tmp_path, capsys):
    verify(tmp_path)
    line = [x for x in capsys.readouterr().out.splitlines() if x.startswith("artifact: ")]
    assert len(line) == 1 and REL in line[0] and hashlib.sha256(PAGE).hexdigest() in line[0] and STAMP in line[0]


def test_success_after_a_challenge_no_second_request_is_sent_to_the_page(tmp_path):
    w = World()
    w.page = [CHALLENGED]
    t0 = w.now
    _, w = verify(tmp_path, w)
    assert w.page_reads() == 1 and w.now == t0


def test_success_a_push_run_judges_the_artifact_by_the_release_its_record_names(tmp_path, capsys):
    rc, w = verify(tmp_path, expect="")
    assert rc == 0 and f"names {REL}" in capsys.readouterr().out
    assert w.count("--classify") == 1


def test_success_a_push_run_sends_no_request_to_the_live_page(tmp_path):
    _, w = verify(tmp_path, expect="")
    assert w.page_reads() == 0


def test_success_the_live_record_is_compared_with_the_artifacts(tmp_path, capsys):
    rc, w = verify(tmp_path)
    assert rc == 0 and f"live: {ADV_URL} is the record this run's artifact carries" in capsys.readouterr().out
    assert w.count("advertised-release.txt?nonce=") == 1


def test_success_the_artifact_is_judged_only_after_the_stamp_is_live(tmp_path):
    w = World()
    w.stamp = [(200, OTHER_STAMP), (200, OTHER_STAMP), (200, STAMP)]
    rc, w = verify(tmp_path, w)
    order = [" ".join(argv) for argv, _ in w.calls]
    assert rc == 0 and max(i for i, j in enumerate(order) if "deploy-stamp.txt" in j) < min(
        i for i, j in enumerate(order) if "--classify" in j)


def test_failure_an_artifact_that_does_not_name_the_release_fails_although_the_live_page_names_it(tmp_path, capsys):
    rc, _ = verify(tmp_path, members=site_members(page=PAGE_OLD, record=adv(release=OLD, page=PAGE_OLD)))
    out = capsys.readouterr().out
    assert rc == 3 and "::error::" in out and "artifact" in out and f"does not name {REL}" in out


def test_failure_an_artifact_that_does_not_name_the_release_fails_when_the_live_read_is_challenged(tmp_path, capsys):
    w = World()
    w.page = [CHALLENGED]
    rc, _ = verify(tmp_path, w, members=site_members(page=PAGE_OLD, record=adv(release=OLD, page=PAGE_OLD)))
    assert rc == 3 and "::warning::" not in capsys.readouterr().out


def test_failure_an_artifact_that_cannot_be_read_is_exit_4_although_the_live_page_names_the_release(tmp_path, capsys):
    rc, _ = verify(tmp_path, artifact=str(tmp_path / "site-artifact" / "artifact.tar"))
    out = capsys.readouterr().out
    assert rc == 4 and "::error::" in out and "could not be read" in out and "nothing is known" in out


def test_failure_an_artifact_that_cannot_be_read_is_exit_4_when_the_live_read_is_challenged(tmp_path, capsys):
    w = World()
    w.page = [CHALLENGED]
    rc, _ = verify(tmp_path, w, artifact=str(tmp_path / "nothing.tar"))
    assert rc == 4 and EDGE_403 in capsys.readouterr().out


def test_failure_an_artifact_with_the_stamp_of_another_run_is_not_this_deploy(tmp_path, capsys):
    # Its record carries this run's stamp, so the stamp file alone decides.
    rc, _ = verify(tmp_path, members=site_members(stamp=OTHER_STAMP, record=adv()))
    out = capsys.readouterr().out
    assert rc == 4 and "The artifact read is not this deploy" in out and OTHER_STAMP in out and STAMP in out


def test_failure_a_live_stamp_of_another_run_is_not_this_deploy_and_the_artifact_is_not_asked(tmp_path, capsys):
    w = World()
    w.stamp = [(200, OTHER_STAMP)]
    rc, w = verify(tmp_path, w)
    assert rc == 1 and w.count("--classify") == 0 and w.page_reads() == 0
    assert "second deploy failed" in capsys.readouterr().out


def test_failure_a_record_whose_sha256_is_not_the_pages_fails(tmp_path, capsys):
    rc, _ = verify(tmp_path, members=site_members(record=adv(page=PAGE + b"<!-- changed after the record -->")))
    out = capsys.readouterr().out
    assert rc == 3 and "sha256" in out and hashlib.sha256(PAGE).hexdigest() in out


def test_failure_a_record_that_names_another_release_than_the_page_fails(tmp_path, capsys):
    rc, _ = verify(tmp_path, members=site_members(record=adv(release=OLD)))
    out = capsys.readouterr().out
    assert rc == 3 and OLD in out and REL in out and "advertised-release.txt" in out


def test_failure_a_record_with_the_stamp_of_another_run_is_not_this_deploy(tmp_path, capsys):
    rc, _ = verify(tmp_path, members=site_members(record=adv(stamp=OTHER_STAMP)))
    assert rc == 4 and "not this deploy" in capsys.readouterr().out


def test_failure_a_record_that_is_not_a_record_is_exit_4(tmp_path, capsys):
    rc, _ = verify(tmp_path, members=site_members(record="<html>Just a moment...</html>"))
    assert rc == 4 and "advertised-release.txt" in capsys.readouterr().out


def test_failure_a_healthy_live_page_that_does_not_name_the_release_fails_although_the_artifact_does(tmp_path, capsys):
    # The read was answered, so this is known: visitors get another page.
    w = World()
    w.page = [STALE_PAGE]
    rc, _ = verify(tmp_path, w)
    out = capsys.readouterr().out
    assert rc == 3 and "::error::" in out and "live" in out


@pytest.mark.parametrize("answer", [(2, "UNREACHABLE: the host did not answer.\n"), (3, "TLS: 526\n"), (4, "HTTP: the server answered 500.\n"),
                                    (5, "EMPTY: 200 with no body.\n"), (124, "timed out after 120 s")])
def test_failure_a_live_page_that_gave_no_answer_to_judge_is_exit_2_although_the_artifact_names_the_release(tmp_path, answer, capsys):
    w = World()
    w.page = [answer]
    rc, _ = verify(tmp_path, w)
    assert rc == 2 and "::error::" in capsys.readouterr().out


def test_failure_a_live_record_of_another_deploy_after_the_bound_is_stale(tmp_path, capsys):
    w = World()
    w.record = [(200, adv(stamp=OTHER_STAMP).strip())]
    t0 = w.now
    rc, w = verify(tmp_path, w)
    out = capsys.readouterr().out
    assert rc == 1 and "::error::" in out and ADV_URL in out and 285 <= w.now - t0 <= 300


def test_failure_a_live_site_that_has_no_record_after_the_bound_is_stale(tmp_path, capsys):
    # The stamp is this run's and the record is a 404: not this run's site.
    w = World()
    w.record = [(404, "<html>not found</html>")]
    rc, _ = verify(tmp_path, w)
    out = capsys.readouterr().out
    assert rc == 1 and "::error::" in out and "HTTP 404" in out


def test_failure_without_enforce_an_unreadable_artifact_is_an_error_annotation_and_exit_0(tmp_path, capsys):
    rc, _ = verify(tmp_path, artifact=str(tmp_path / "nothing.tar"), enforce=False)
    out = capsys.readouterr().out
    assert rc == 0 and "::error::" in out and "verdict 4 is not enforced" in out


def test_failure_a_classifier_that_could_not_run_is_exit_4(tmp_path, capsys):
    w = World()
    w.classifier = (127, "sh: not found")
    rc, _ = verify(tmp_path, w)
    out = capsys.readouterr().out
    assert rc == 4 and "exit 127" in out and "nothing is known" in out


def test_failure_a_path_traversal_in_the_artifact_is_exit_4(tmp_path, capsys):
    rc, _ = verify(tmp_path, members=site_members() + [("../../etc/cron.d/x", b"x")])
    assert rc == 4 and "outside the site" in capsys.readouterr().out


def test_edge_a_live_record_the_edge_refused_is_a_warning_and_the_artifact_still_decides(tmp_path, capsys):
    w = World()
    w.record = [(403, "<html>Just a moment...</html>")]
    t0 = w.now
    rc, w = verify(tmp_path, w)
    out = capsys.readouterr().out
    assert rc == 0 and "::warning::" in out and ADV_URL in out and "HTTP 403" in out
    # A refused client is not answered by asking again.
    assert w.count("advertised-release.txt?nonce=") == 1 and w.now == t0


def test_edge_a_live_record_that_becomes_this_runs_inside_the_bound_passes(tmp_path):
    w = World()
    w.record = [(404, "not found"), (200, adv(stamp=OTHER_STAMP).strip()), (200, adv().strip())]
    t0 = w.now
    rc, w = verify(tmp_path, w)
    assert rc == 0 and w.now - t0 == 30


def test_edge_a_failed_artifact_costs_one_evidence_read_of_the_live_page_and_no_wait(tmp_path, capsys):
    w = World()
    w.page = [STALE_PAGE]
    t0 = w.now
    rc, w = verify(tmp_path, w, members=site_members(page=PAGE_OLD, record=adv(release=OLD, page=PAGE_OLD)))
    assert rc == 3 and w.page_reads() == 1 and w.now == t0
    assert "release check 1 (+0 s): exit 1" in capsys.readouterr().out


def test_edge_without_an_artifact_argument_a_challenged_read_is_still_exit_4(tmp_path, capsys):
    # The check as #797 left it, for a caller that has no artifact.
    w = World()
    w.page = [CHALLENGED]
    rc = pl.verify(cfg(""), dict(ENV), w, None, w.sleep, w.clock)
    assert rc == 4 and w.page_reads() == 5 and "::warning::" not in capsys.readouterr().out


def test_edge_an_artifact_page_that_is_no_download_page_is_exit_3(tmp_path, capsys):
    page = b"<html>404 not found</html>"
    rc, _ = verify(tmp_path, members=site_members(page=page))
    out = capsys.readouterr().out
    assert rc == 3 and "EMPTY" in out


def test_edge_a_push_run_with_a_record_that_disagrees_prints_an_error_and_exits_0(tmp_path, capsys):
    rc, _ = verify(tmp_path, expect="", enforce=False, members=site_members(record=adv(page=b"download other")))
    out = capsys.readouterr().out
    assert rc == 0 and "::error::" in out and "verdict 3 is not enforced" in out


def test_edge_a_live_page_refused_first_is_not_asked_again_even_with_the_whole_bound_left(tmp_path):
    w = World()
    w.page = [CHALLENGED, ANSWERED]
    rc, w = verify(tmp_path, w)
    assert rc == 0 and w.page_reads() == 1


def test_edge_a_live_page_that_names_the_release_later_is_waited_for(tmp_path):
    # The CDN can serve the page of the deploy before for some minutes.
    w = World()
    w.page = [STALE_PAGE, STALE_PAGE, ANSWERED]
    t0 = w.now
    rc, w = verify(tmp_path, w)
    assert rc == 0 and w.page_reads() == 3 and w.now - t0 == 30


def test_edge_the_warning_of_a_challenged_read_without_an_edge_line_still_says_what_was_read(tmp_path, capsys):
    w = World()
    w.page = [(6, "BLOCKED: the edge refused this client (429).\n")]
    rc, _ = verify(tmp_path, w)
    warning = [x for x in capsys.readouterr().out.splitlines() if x.startswith("::warning::")]
    assert rc == 0 and len(warning) == 1 and "BLOCKED: the edge refused this client (429)." in warning[0]


# ---------------------------------------------------------------------------
# The command line of `verify`
# ---------------------------------------------------------------------------


def test_success_verify_takes_the_artifact_and_derives_the_records_url(monkeypatch):
    seen = {}
    monkeypatch.setattr(pl, "verify", lambda c, *a: seen.update(cfg=c) or 0)
    assert pl.main(["verify", "--artifact", "site-artifact/artifact.tar"], dict(ENV)) == 0
    assert seen["cfg"].artifact == "site-artifact/artifact.tar"
    assert seen["cfg"].advertised_url == "https://sipnab.com/advertised-release.txt"


def test_edge_without_the_flag_no_artifact_is_expected(monkeypatch):
    seen = {}
    monkeypatch.setattr(pl, "verify", lambda c, *a: seen.update(cfg=c) or 0)
    pl.main(["verify"], dict(ENV))
    assert seen["cfg"].artifact == ""


def test_edge_the_records_url_follows_the_stamps_url(monkeypatch):
    seen = {}
    monkeypatch.setattr(pl, "verify", lambda c, *a: seen.update(cfg=c) or 0)
    pl.main(["verify", "--url", "https://staging.example.invalid/site/deploy-stamp.txt?x=1"], dict(ENV))
    assert seen["cfg"].advertised_url == "https://staging.example.invalid/site/advertised-release.txt"


# ---------------------------------------------------------------------------
# The daily check: two static files, and the live page when it answers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("static,page_rc,want", [
    ("ok", 0, (0, "verified")),
    ("ok", 6, (0, "verified")),
    ("unknown", 0, (0, "verified")),
    ("unknown", 6, (0, "not-verified")),
    ("ok", 1, (1, "not-advertised")),
    ("other", 0, (1, "not-advertised")),
    ("other", 6, (1, "not-advertised")),
    ("other", 1, (1, "not-advertised")),
    ("unknown", 1, (1, "not-advertised")),
    ("ok", 2, (2, "unreadable")),
    ("ok", 3, (3, "unreadable")),
    ("ok", 4, (4, "unreadable")),
    ("ok", 5, (5, "unreadable")),
    ("unknown", 4, (4, "unreadable")),
    ("unknown", 124, (124, "unreadable")),
    ("other", 4, (1, "not-advertised")),
])
def test_the_daily_verdict_table(static, page_rc, want):
    assert pl.daily_verdict(static, page_rc) == want


def test_success_two_files_of_one_deploy_that_name_the_release_are_ok():
    assert pl.static_state((200, STAMP), (200, adv().strip()), REL)[0] == "ok"


def test_failure_two_files_of_one_deploy_that_name_another_release_are_other():
    state, detail = pl.static_state((200, STAMP), (200, adv(release=OLD).strip()), REL)
    assert state == "other" and OLD in detail and REL in detail


@pytest.mark.parametrize("stamp,record", [
    ((403, "Just a moment"), (200, adv().strip())),
    ((200, STAMP), (403, "Just a moment")),
    ((200, STAMP), (404, "not found")),
    ((200, STAMP), (200, "<html>home</html>")),
    ((0, ""), (0, "")),
    ((200, "<html>"), (200, adv().strip())),
])
def test_failure_a_file_that_cannot_be_read_as_what_it_is_says_nothing(stamp, record):
    assert pl.static_state(stamp, record, REL)[0] == "unknown"


def test_edge_files_of_two_deploys_are_mixed_and_say_nothing_yet():
    state, detail = pl.static_state((200, OTHER_STAMP), (200, adv().strip()), REL)
    assert state == "mixed" and STAMP in detail and OTHER_STAMP in detail


def daily(tmp_path, w=None, env=None):
    w = w or World()
    summary = tmp_path / "summary.md"
    env = {"GITHUB_RUN_ID": "43600000001", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_STEP_SUMMARY": str(summary)} if env is None else env
    rc = pl.daily(REL, BASE, env, w, w.sleep, w.clock)
    return rc, w, (summary.read_text() if summary.exists() else "")


def test_success_static_files_and_live_page_agree(tmp_path, capsys):
    rc, _, summary = daily(tmp_path)
    out = capsys.readouterr().out
    assert rc == 0 and "::warning::" not in out and "::error::" not in out
    assert summary.startswith("Advertisement VERIFIED: ") and REL in summary


def test_success_a_challenged_page_and_static_files_that_name_the_release_verify_with_a_warning(tmp_path, capsys):
    w = World()
    w.page = [CHALLENGED]
    rc, _, summary = daily(tmp_path, w)
    out = capsys.readouterr().out
    warning = [x for x in out.splitlines() if x.startswith("::warning")]
    assert rc == 0 and len(warning) == 1 and EDGE_403 in warning[0]
    assert summary.startswith("Advertisement VERIFIED: ") and "NOT VERIFIED" not in summary + out
    assert "advertised-release.txt" in summary


def test_success_a_site_from_before_the_record_is_verified_by_a_live_page_that_answers(tmp_path, capsys):
    w = World()
    w.record = [(404, "not found")]
    rc, _, summary = daily(tmp_path, w)
    assert rc == 0 and summary.startswith("Advertisement VERIFIED: ") and "live download page" in summary


def test_success_the_daily_check_reads_the_three_urls_of_one_site(tmp_path):
    _, w, _ = daily(tmp_path)
    urls = [argv[-1] for argv, _ in w.calls if argv[0] == "curl"]
    assert urls == [BASE + "deploy-stamp.txt?nonce=43600000001.1.d1", BASE + "advertised-release.txt?nonce=43600000001.1.d1"]
    assert w.page_urls == [BASE + "download/"]


def test_success_the_live_page_is_asked_once(tmp_path):
    w = World()
    w.page = [CHALLENGED]
    _, w, _ = daily(tmp_path, w)
    assert w.page_reads() == 1


def test_failure_static_files_that_name_another_release_fail_when_the_page_is_challenged(tmp_path, capsys):
    w = World()
    w.record = [(200, adv(release=OLD).strip())]
    w.page = [CHALLENGED]
    rc, _, summary = daily(tmp_path, w)
    out = capsys.readouterr().out
    assert rc == 1 and "::error title=Release not advertised::" in out and OLD in out
    assert summary.startswith("Advertisement FAILED: ")


def test_failure_a_healthy_live_page_that_does_not_name_the_release_fails_whatever_the_files_say(tmp_path, capsys):
    w = World()
    w.page = [STALE_PAGE]
    rc, _, summary = daily(tmp_path, w)
    assert rc == 1 and "::error title=Release not advertised::" in capsys.readouterr().out
    assert summary.startswith("Advertisement FAILED: ")


@pytest.mark.parametrize("answer", [(2, "UNREACHABLE: the host did not answer.\n"), (3, "TLS: 526\n"),
                                    (4, "HTTP: the server answered 500.\n"), (5, "EMPTY: 200 with no body.\n")])
def test_failure_a_live_page_that_is_down_fails_with_the_verifiers_status(tmp_path, answer, capsys):
    w = World()
    w.page = [answer]
    rc, _, summary = daily(tmp_path, w)
    assert rc == answer[0] and "::error title=Download page not readable::" in capsys.readouterr().out
    assert summary.startswith("Advertisement FAILED: ")


def test_failure_nothing_readable_is_not_verified_and_never_says_verified(tmp_path, capsys):
    w = World()
    w.stamp = [(403, "Just a moment")]
    w.record = [(403, "Just a moment")]
    w.page = [CHALLENGED]
    rc, _, summary = daily(tmp_path, w)
    out = capsys.readouterr().out
    assert rc == 0
    assert summary.startswith("NOT VERIFIED: ") and "Advertisement VERIFIED" not in summary + out
    warning = [x for x in out.splitlines() if x.startswith("::warning title=Advertisement not verified::NOT VERIFIED: ")]
    assert len(warning) == 1 and EDGE_403 in warning[0] and "HTTP 403" in warning[0]


def test_edge_a_site_from_before_the_record_and_a_challenged_page_is_not_verified(tmp_path, capsys):
    w = World()
    w.record = [(404, "not found")]
    w.page = [CHALLENGED]
    rc, _, summary = daily(tmp_path, w)
    assert rc == 0 and summary.startswith("NOT VERIFIED: ") and "HTTP 404" in summary
    assert "::warning title=Advertisement not verified::" in capsys.readouterr().out


def test_edge_files_of_two_deploys_are_read_again_and_judged_when_they_agree(tmp_path):
    w = World()
    w.stamp = [(200, OTHER_STAMP), (200, STAMP)]
    w.page = [CHALLENGED]
    t0 = w.now
    rc, w, summary = daily(tmp_path, w)
    assert rc == 0 and summary.startswith("Advertisement VERIFIED: ") and w.now - t0 == 15


def test_edge_files_that_stay_of_two_deploys_are_read_three_times_and_say_nothing(tmp_path):
    w = World()
    w.stamp = [(200, OTHER_STAMP)]
    w.page = [CHALLENGED]
    t0 = w.now
    rc, w, summary = daily(tmp_path, w)
    assert rc == 0 and summary.startswith("NOT VERIFIED: ") and w.count("deploy-stamp.txt") == 3 and w.now - t0 == 30


def test_edge_every_static_read_has_its_own_nonce(tmp_path):
    w = World()
    w.stamp = [(200, OTHER_STAMP)]
    _, w, _ = daily(tmp_path, w)
    urls = [argv[-1] for argv, _ in w.calls if argv[0] == "curl"]
    assert len(urls) == 6 and len(set(urls)) == 6


def test_edge_without_a_summary_file_the_verdict_is_still_printed(tmp_path, capsys):
    w = World()
    w.stamp = [(403, "")]
    w.record = [(403, "")]
    w.page = [CHALLENGED]
    rc, _, summary = daily(tmp_path, w, env={})
    assert rc == 0 and summary == "" and "NOT VERIFIED: " in capsys.readouterr().out


def test_edge_the_summary_is_appended_to_not_replaced(tmp_path):
    (tmp_path / "summary.md").write_text("Certificates: fine\n")
    _, _, summary = daily(tmp_path)
    assert summary.startswith("Certificates: fine\nAdvertisement VERIFIED: ") and summary.endswith("\n")


def test_edge_a_not_verified_run_names_the_release_it_could_not_verify(tmp_path):
    w = World()
    w.record = [(404, "")]
    w.page = [CHALLENGED]
    _, _, summary = daily(tmp_path, w)
    assert REL in summary


def test_success_daily_on_the_command_line_needs_no_stamp_of_its_own(monkeypatch):
    seen = {}
    monkeypatch.setattr(pl, "daily", lambda expect, base, env, *a: seen.update(expect=expect, base=base) or 0)
    assert pl.main(["daily", "--expect", REL], {"GITHUB_REPOSITORY": "NormB/sipnab"}) == 0
    assert seen == {"expect": REL, "base": "https://sipnab.com/"}


@pytest.mark.parametrize("argv", [["daily"], ["daily", "--expect", ""], ["daily", "--expect", "v0.5.254"],
                                  ["daily", "--expect", REL, "--url", "ftp://sipnab.example.invalid/"]])
def test_failure_daily_without_a_release_or_with_a_url_that_is_not_https_is_a_usage_error(argv, capsys):
    assert pl.main(argv, {}) == 2


def test_edge_daily_returns_its_verdict_as_the_exit_status(monkeypatch):
    monkeypatch.setattr(pl, "daily", lambda *a: 1)
    assert pl.main(["daily", "--expect", REL, "--url", "https://sipnab.example.invalid"], {}) == 1
