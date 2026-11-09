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
import pathlib
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

def test_the_newest_successful_push_run_of_the_tag_is_chosen():
    runs = [
        {"databaseId": 1, "headBranch": "v0.5.240", "event": "push", "conclusion": "failure"},
        {"databaseId": 2, "headBranch": "v0.5.240", "event": "push", "conclusion": "success"},
        {"databaseId": 3, "headBranch": "v0.5.240", "event": "workflow_dispatch", "conclusion": "success"},
    ]
    assert rr.records_run(runs, "v0.5.240") == 2


def test_no_successful_run_of_the_tag_is_a_refusal():
    with pytest.raises(rr.RecordError, match="v0.5.240"):
        rr.records_run([{"databaseId": 1, "headBranch": "v0.5.240", "event": "push",
                         "conclusion": "failure"}], "v0.5.240")
