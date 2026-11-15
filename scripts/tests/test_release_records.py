# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""The release records: the binary-ceiling line and the eBPF load row.

Phase two used to measure the published x86_64-musl binary by hand and type
the line into website/config.toml, and paste the row verify-bpf-load.sh
described into docs/internals/uprobe-capture.md. RELEASE-FAST C moves the
measurement into release.yml, which uploads the line as the `release-records`
artifact of the tag's run, and scripts/release-records.py writes both records
into the advertisement commit of the next release pull request.
"""

import hashlib
import io
import json
import pathlib
import re
import tarfile

import pytest
from conftest import load

rr = load("release-records")

REPO = pathlib.Path(__file__).resolve().parents[2]

CONFIG = """# The record:
#   0.5.237  24,504,384 bytes   (+553,664, leaving 661,440 bytes of headroom under 24 MB)
#   0.5.238  24,651,840 bytes   (+147,456, leaving 513,984 bytes of headroom under 24 MB)
#
# prose naming 0.5.240 is not a measurement
binary_size_ceiling_mb = "24"
"""

LEDGER = """## Testing it

| Version | Artifact | Host | Kernel | Date | Result |
|---|---|---|---|---|---|
| 0.5.238 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.115+deb13.1-amd64 | 2026-11-08 | attached, 2 libraries plus `tcp_sendmsg` |
| 0.5.239 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.115+deb13.1-amd64 | 2026-11-09 | attached, 2 libraries plus `tcp_sendmsg` |

That requirement makes this file part of every advertisement commit.
"""

ROW = ("| 0.5.240 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.115+deb13.1-amd64 "
       "| 2026-11-10 | attached, 2 libraries plus `tcp_sendmsg` |")


def tarball(tmp_path, members):
    path = tmp_path / "sipnab-0.5.240-x86_64-unknown-linux-musl.tar.gz"
    with tarfile.open(path, "w:gz") as tf:
        for name, size in members:
            data = b"\0" * size
            info = tarfile.TarInfo(name)
            info.size = size
            tf.addfile(info, io.BytesIO(data))
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return path, f"{digest}  {path.name}\n"


# ── the ceiling line: SUCCESS ──────────────────────────────────────────────

def test_the_line_has_the_shape_the_record_already_uses():
    assert rr.ceiling_line(CONFIG, "0.5.239", 24_655_936) == (
        "#   0.5.239  24,655,936 bytes   (+4,096, leaving 509,888 bytes of headroom under 24 MB)"
    )


def test_a_smaller_binary_records_a_negative_change():
    assert "(-3,968, leaving" in rr.ceiling_line(CONFIG, "0.5.239", 24_647_872)


def test_the_line_goes_after_the_last_measurement():
    line = rr.ceiling_line(CONFIG, "0.5.239", 24_655_936)
    out = rr.insert_ceiling(CONFIG, line).splitlines()
    assert out[3] == line and out[2].startswith("#   0.5.238")


def test_the_measurement_is_the_sipnab_file_of_a_verified_tarball(tmp_path):
    path, sums = tarball(tmp_path, [("sipnab-0.5.240/sipnab", 4096), ("sipnab-0.5.240/README.md", 10)])
    assert rr.measure(path, sums) == 4096


# ── the ceiling line: FAILURE ──────────────────────────────────────────────

def test_a_version_already_recorded_is_refused():
    with pytest.raises(rr.RecordError, match="already"):
        rr.ceiling_line(CONFIG, "0.5.238", 24_651_840)


def test_a_version_older_than_the_last_measurement_is_refused():
    with pytest.raises(rr.RecordError, match="0.5.238"):
        rr.ceiling_line(CONFIG, "0.5.230", 1_000_000)


def test_a_binary_over_the_ceiling_is_refused():
    with pytest.raises(rr.RecordError, match="over"):
        rr.ceiling_line(CONFIG, "0.5.239", 24 * 1048576 + 1)


def test_a_tarball_whose_checksum_differs_is_refused(tmp_path):
    path, _ = tarball(tmp_path, [("d/sipnab", 10)])
    with pytest.raises(rr.RecordError, match="sha256"):
        rr.measure(path, f"{'0' * 64}  {path.name}\n")


def test_a_tarball_missing_from_the_checksum_list_is_refused(tmp_path):
    path, _ = tarball(tmp_path, [("d/sipnab", 10)])
    with pytest.raises(rr.RecordError, match="SHA256SUMS"):
        rr.measure(path, f"{'0' * 64}  other.tar.gz\n")


def test_a_tarball_with_no_sipnab_binary_is_refused(tmp_path):
    path, sums = tarball(tmp_path, [("d/sipnab-other", 10)])
    with pytest.raises(rr.RecordError, match="no sipnab"):
        rr.measure(path, sums)


def test_a_pending_line_the_new_measurement_includes_is_refused_not_guessed():
    # A pending line can wrap; deleting one line could leave half a sentence.
    config = CONFIG.replace("#\n", "# pending  +100,000 bytes  against 0.5.238: a feature\n#\n")
    line = rr.ceiling_line(config, "0.5.239", 24_655_936)
    with pytest.raises(rr.RecordError, match="pending"):
        rr.insert_ceiling(config, line)


def test_a_config_without_the_ceiling_key_is_refused():
    with pytest.raises(rr.RecordError, match="binary_size_ceiling_mb"):
        rr.ceiling_line(CONFIG.replace("binary_size_ceiling_mb", "x"), "0.5.239", 1)


# ── the ceiling line: EDGE ─────────────────────────────────────────────────

def test_the_same_size_records_unchanged():
    assert "(unchanged, leaving 513,984" in rr.ceiling_line(CONFIG, "0.5.239", 24_651_840)


def test_a_version_named_in_prose_is_not_the_last_measurement():
    # "prose naming 0.5.240" must not make 0.5.240 look recorded.
    assert "0.5.240" in rr.ceiling_line(CONFIG, "0.5.240", 24_655_936)


def test_a_binary_exactly_at_the_ceiling_leaves_zero_headroom():
    assert "leaving 0 bytes" in rr.ceiling_line(CONFIG, "0.5.239", 24 * 1048576)


def test_two_sipnab_files_in_one_tarball_are_refused(tmp_path):
    path, sums = tarball(tmp_path, [("a/sipnab", 10), ("b/sipnab", 10)])
    with pytest.raises(rr.RecordError, match="2"):
        rr.measure(path, sums)


def test_a_binary_mode_checksum_line_is_read(tmp_path):
    path, sums = tarball(tmp_path, [("d/sipnab", 7)])
    digest, name = sums.split()
    assert rr.measure(path, f"{digest} *{name}\n") == 7


def test_the_real_record_accepts_the_next_release():
    config = (REPO / "website/config.toml").read_text()
    last = rr.measurements(config)[-1]
    nxt = ".".join(last[0].split(".")[:2] + [str(int(last[0].split(".")[2]) + 1)])
    assert rr.ceiling_line(config, nxt, last[1]).startswith(f"#   {nxt}  ")


# ── the eBPF load row ──────────────────────────────────────────────────────

def test_the_row_goes_after_the_last_ledger_row():
    out = rr.insert_uprobe_row(LEDGER, ROW, "0.5.240").splitlines()
    assert out[out.index(ROW) - 1].startswith("| 0.5.239 |")


def test_a_row_for_another_version_is_refused():
    with pytest.raises(rr.RecordError, match="0.5.241"):
        rr.insert_uprobe_row(LEDGER, ROW, "0.5.241")


def test_a_row_already_in_the_ledger_is_refused():
    with pytest.raises(rr.RecordError, match="already"):
        rr.insert_uprobe_row(LEDGER, ROW.replace("0.5.240", "0.5.239"), "0.5.239")


def test_a_row_without_six_cells_is_refused():
    with pytest.raises(rr.RecordError, match="six"):
        rr.insert_uprobe_row(LEDGER, "| 0.5.240 | x | attached |", "0.5.240")


def test_a_row_that_did_not_attach_is_refused():
    with pytest.raises(rr.RecordError, match="attached"):
        rr.insert_uprobe_row(LEDGER, ROW.replace("attached, 2", "rejected, 2"), "0.5.240")


def test_the_real_ledger_has_a_place_for_the_next_row():
    md = (REPO / "docs/internals/uprobe-capture.md").read_text()
    out = rr.insert_uprobe_row(md, ROW.replace("0.5.240", "9.9.9"), "9.9.9")
    assert out.count("\n") == md.count("\n") + 1


# ── which run holds a tag's records ────────────────────────────────────────

# The records are the artifact of ONE job of the tag's run. On 2026-11-14 the
# fetch asked for a run whose whole conclusion was success, and release
# 0.5.255 stopped: the 0.5.254 run was red, and then in progress on a re-run,
# for its site-advertisement job, while its records job had succeeded hours
# before and the artifact existed. The rule these tests hold: the newest
# tag-push run of the tag, whatever its status or conclusion, when its records
# job succeeded and its artifact has not expired.

TAG = "v0.5.240"
JOB = "Record the binary size"


def push_run(run_id, conclusion="success", tag=TAG, event="push", status="completed"):
    return {"databaseId": run_id, "headBranch": tag, "event": event, "status": status, "conclusion": conclusion}


def viewed(conclusion="failure", status="completed", attempt=3, job="success", run_id=7, jobs=None):
    """What `gh run view --json databaseId,attempt,status,conclusion,jobs` answers."""
    if jobs is None:
        jobs = [
            {"name": "Create Release", "status": "completed", "conclusion": "success"},
            {"name": JOB, "status": "completed" if job else "in_progress", "conclusion": job},
            {"name": "Advertise the release on the site", "status": status, "conclusion": conclusion},
        ]
    return {"databaseId": run_id, "attempt": attempt, "status": status, "conclusion": conclusion, "jobs": jobs}


def artifact(artifact_id=41, name="release-records", expired=False, expires_at="2027-02-12T09:38:13Z"):
    return {"id": artifact_id, "name": name, "expired": expired, "expires_at": expires_at}


@pytest.mark.parametrize("conclusion", ["success", "failure", "cancelled", "timed_out", "startup_failure", "", None])
def test_the_newest_push_run_of_the_tag_is_chosen_whatever_its_conclusion(conclusion):
    runs = [push_run(9, conclusion), push_run(2, "success")]
    assert rr.tag_run(runs, TAG) == 9, f"a run that concluded {conclusion!r} is still the tag's run"


@pytest.mark.parametrize("runs", [
    [],
    [push_run(1, tag="v0.5.239")],
    [push_run(1, event="workflow_dispatch")],
    [push_run(1, tag="v0.5.24"), push_run(2, tag="v0.5.2400")],
], ids=["no runs", "another tag", "a dispatch only", "tags that share a prefix"])
def test_a_tag_without_a_push_run_is_refused(runs):
    with pytest.raises(rr.RecordError, match=r"no tag-push run for v0\.5\.240"):
        rr.tag_run(runs, TAG)


def test_a_newer_dispatch_run_is_not_the_tags_run():
    runs = [push_run(3, event="workflow_dispatch"), push_run(2, "failure"), push_run(1)]
    assert rr.tag_run(runs, TAG) == 2, "a workflow_dispatch run uploads no records"


def test_a_run_of_another_tag_is_passed_over():
    assert rr.tag_run([push_run(5, tag="v0.5.241"), push_run(4)], TAG) == 4, "v0.5.241's run is not v0.5.240's"


@pytest.mark.parametrize("status, conclusion, said", [
    ("completed", "failure", "conclusion failure"),
    ("completed", "success", "conclusion success"),
    # GitHub's own spelling of the value, kept as the one quoted word.
    ("completed", "cancelled", "conclusion " + "cancelled"),
    ("completed", "timed_out", "conclusion timed_out"),
    ("in_progress", "", "conclusion none yet"),
    ("in_progress", None, "conclusion none yet"),
    ("queued", "", "conclusion none yet"),
])
def test_a_run_whose_records_job_succeeded_is_accepted_and_described(status, conclusion, said):
    line = rr.records_source(viewed(conclusion, status, attempt=3), [artifact()], TAG)
    assert f"status {status}" in line, line
    assert said in line, line
    assert "run 7" in line and "attempt 3" in line and TAG in line, line
    assert "\n" not in line, "the description is one line"


def test_the_description_names_the_job_and_the_artifact():
    line = rr.records_source(viewed(), [artifact(14109154564)], TAG)
    assert JOB in line and "artifact 14109154564" in line and "2027-02-12T09:38:13Z" in line, line


@pytest.mark.parametrize("attempt", [1, 2, 3, 17])
def test_the_attempt_printed_is_the_runs(attempt):
    assert f"attempt {attempt}," in rr.records_source(viewed(attempt=attempt), [artifact()], TAG)


@pytest.mark.parametrize("job", ["failure", "cancelled", "skipped", "timed_out", "neutral", "", None])
def test_a_run_whose_records_job_did_not_succeed_is_refused(job):
    with pytest.raises(rr.RecordError) as e:
        rr.records_source(viewed("success", job=job), [artifact()], TAG)
    said = str(e.value)
    assert JOB in said and "run 7" in said, said
    assert (job or "none yet") in said, f"the refusal names what the job concluded: {said}"


def test_a_green_run_does_not_vouch_for_a_failed_records_job():
    # The run's own conclusion is never the evidence, in either direction.
    with pytest.raises(rr.RecordError, match="did not succeed"):
        rr.records_source(viewed("success", job="failure"), [artifact()], TAG)


@pytest.mark.parametrize("jobs", [
    [],
    [{"name": "Create Release", "status": "completed", "conclusion": "success"}],
    [{"name": "record the binary size", "status": "completed", "conclusion": "success"}],
], ids=["no jobs", "other jobs only", "a name in another case"])
def test_a_run_without_the_records_job_is_refused(jobs):
    with pytest.raises(rr.RecordError, match="has no job"):
        rr.records_source(viewed(jobs=jobs), [artifact()], TAG)


def test_a_run_view_without_a_jobs_list_is_refused():
    run = viewed()
    del run["jobs"]
    with pytest.raises(rr.RecordError, match="has no job"):
        rr.records_source(run, [artifact()], TAG)


def test_two_jobs_with_the_records_name_are_refused_not_guessed():
    twice = [{"name": JOB, "status": "completed", "conclusion": "success"},
             {"name": JOB, "status": "completed", "conclusion": "failure"}]
    with pytest.raises(rr.RecordError, match="2 jobs"):
        rr.records_source(viewed(jobs=twice), [artifact()], TAG)


@pytest.mark.parametrize("artifacts", [
    [],
    [artifact(name="sipnab-x86_64-unknown-linux-musl")],
    [artifact(name="release-records-old"), artifact(name="Release-Records")],
], ids=["none", "another artifact", "names that are near"])
def test_a_run_without_the_artifact_is_refused(artifacts):
    with pytest.raises(rr.RecordError, match="no `release-records` artifact"):
        rr.records_source(viewed(), artifacts, TAG)


def test_an_expired_artifact_is_refused_with_its_date():
    with pytest.raises(rr.RecordError, match=r"expired.*2026-02-12T09:38:13Z"):
        rr.records_source(viewed("success"), [artifact(expired=True, expires_at="2026-02-12T09:38:13Z")], TAG)


def test_a_live_artifact_beside_an_expired_one_is_taken():
    both = [artifact(40, expired=True, expires_at="2026-02-12T09:38:13Z"), artifact(41)]
    assert "artifact 41 " in rr.records_source(viewed(), both, TAG)


def test_the_job_name_is_the_one_release_yml_gives_the_records_job():
    text = (REPO / ".github/workflows/release.yml").read_text(encoding="utf-8")
    block = text[text.index("\n  records:\n"):]
    name = re.search(r"(?m)^    name: (.+)$", block)
    assert name and name.group(1).strip() == rr.RECORDS_JOB, "release.yml and the script name the records job alike"


def test_the_artifact_name_is_the_one_release_yml_uploads():
    text = (REPO / ".github/workflows/release.yml").read_text(encoding="utf-8")
    block = text[text.index("\n  records:\n"):]
    upload = block[block.index("- name: Upload the release records"):]
    name = re.search(r"(?m)^          name: (.+)$", upload)
    assert name and name.group(1).strip() == rr.ARTIFACT, "release.yml and the script name the artifact alike"


# ── the fetch, with `gh` replaced ──────────────────────────────────────────
# The wire is unreachable in a test (a real `gh` needs the network and a
# token), so `_gh`, the one function that starts it, is replaced: each test
# gives the three documents GitHub would answer and reads the calls made.

class Gh:
    def __init__(self, runs, run=None, artifacts=None):
        self.runs, self.run, self.artifacts, self.calls = runs, run, artifacts, []

    def __call__(self, *args):
        self.calls.append(args)
        if args[:2] == ("run", "list"):
            return self.runs if isinstance(self.runs, str) else json.dumps(self.runs)
        if args[:2] == ("run", "view"):
            return json.dumps(self.run)
        if args[0] == "api":
            if self.artifacts is None:
                return "{}"
            return json.dumps({"total_count": len(self.artifacts), "artifacts": self.artifacts})
        if args[:2] == ("run", "download"):
            return ""
        raise AssertionError(f"an unexpected gh call: {args}")

    def downloads(self):
        return [c for c in self.calls if c[:2] == ("run", "download")]


def fetch(monkeypatch, gh, dest="D"):
    monkeypatch.setattr(rr, "_gh", gh)
    return rr.main(["fetch", "--tag", TAG, "--repo", "example/sipnab", "--dest", dest])


def test_the_fetch_takes_the_artifact_of_a_red_run_and_says_so(monkeypatch, capsys):
    gh = Gh([push_run(7, "failure")], viewed("failure", attempt=2), [artifact()])
    assert fetch(monkeypatch, gh) == 0, "the records job succeeded; the red job is another one"
    out = capsys.readouterr()
    assert "conclusion failure" in out.out and "attempt 2" in out.out and "run 7" in out.out, out.out
    assert out.err == "", out.err
    assert gh.downloads() == [("run", "download", "7", "-R", "example/sipnab", "-n", "release-records", "-D", "D")]


def test_the_fetch_takes_the_artifact_of_a_run_still_in_progress(monkeypatch, capsys):
    gh = Gh([push_run(7, "", status="in_progress")], viewed("", "in_progress"), [artifact()])
    assert fetch(monkeypatch, gh) == 0, "a re-run of another job does not hold the records"
    assert "status in_progress" in capsys.readouterr().out
    assert len(gh.downloads()) == 1, gh.calls


def test_the_fetch_takes_the_artifact_of_a_green_run(monkeypatch, capsys):
    gh = Gh([push_run(7)], viewed("success", attempt=1), [artifact()])
    assert fetch(monkeypatch, gh) == 0
    assert "conclusion success" in capsys.readouterr().out
    assert len(gh.downloads()) == 1, gh.calls


def test_the_fetch_asks_about_the_run_it_chose(monkeypatch):
    gh = Gh([push_run(9, "failure"), push_run(7)], viewed("failure", run_id=9), [artifact()])
    assert fetch(monkeypatch, gh) == 0
    assert ("run", "view", "9") == gh.calls[1][:3], gh.calls
    assert gh.calls[2][0] == "api" and "/actions/runs/9/artifacts" in gh.calls[2][1], gh.calls
    assert gh.downloads()[0][2] == "9", gh.calls


def test_the_fetch_writes_where_it_is_told(monkeypatch):
    gh = Gh([push_run(7)], viewed(), [artifact()])
    assert fetch(monkeypatch, gh, dest=".git/release-records") == 0
    assert gh.downloads()[0][-2:] == ("-D", ".git/release-records"), gh.calls


@pytest.mark.parametrize("gh, why", [
    (Gh([]), "no tag-push run"),
    (Gh([push_run(7)], viewed("success", job="failure"), [artifact()]), "did not succeed"),
    (Gh([push_run(7)], viewed("success", job="skipped"), [artifact()]), "did not succeed"),
    (Gh([push_run(7, "", status="in_progress")], viewed("", "in_progress", job=""), [artifact()]), "did not succeed"),
    (Gh([push_run(7)], viewed("success"), []), "no `release-records` artifact"),
    (Gh([push_run(7)], viewed("success"), [artifact(expired=True)]), "expired"),
    (Gh("not json"), ""),
], ids=["no run", "records job failed", "records job skipped", "records job still running", "no artifact",
        "artifact expired", "gh answered no JSON"])
def test_the_fetch_refuses_and_downloads_nothing(monkeypatch, capsys, gh, why):
    assert fetch(monkeypatch, gh) == 1
    out = capsys.readouterr()
    assert out.err.startswith("release-records: refused: ") and why in out.err, out.err
    assert out.out == "", "nothing is described when nothing is taken"
    assert gh.downloads() == [], gh.calls


def test_a_newer_run_whose_records_job_failed_is_not_replaced_by_an_older_green_run(monkeypatch, capsys):
    # A tag pushed twice: the older run's artifact measured another build.
    gh = Gh([push_run(9, "failure"), push_run(7)], viewed("failure", job="failure", run_id=9), [artifact()])
    assert fetch(monkeypatch, gh) == 1
    assert "run 9" in capsys.readouterr().err
    assert gh.downloads() == [], gh.calls


def test_an_artifact_answer_without_a_list_is_a_refusal(monkeypatch, capsys):
    gh = Gh([push_run(7)], viewed("success"), None)
    assert fetch(monkeypatch, gh) == 1
    assert "no `release-records` artifact" in capsys.readouterr().err
    assert gh.downloads() == [], gh.calls


def test_a_gh_that_fails_is_a_refusal(monkeypatch, capsys):
    def gh(*args):
        raise rr.RecordError("`gh run list` exited 1: HTTP 502")
    assert fetch(monkeypatch, gh) == 1
    assert "HTTP 502" in capsys.readouterr().err
