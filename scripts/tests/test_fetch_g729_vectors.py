# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""fetch-g729-vectors.py: the ITU-T G.729 test vectors, sha256-pinned.

The ITU package is fetched, never committed (spec decision D4). The fetcher
must hand the conformance tests exactly the bytes the pins name: it refuses a
package whose sha256 differs from the pinned one, extracts only the two
test_vectors directories, and refuses an extracted file whose sha256 differs
from its pin.

The network is not reachable from a test, so each "package" here is a zip
built in a temporary directory and given with --zip.
"""

import hashlib
import pathlib
import subprocess
import sys
import zipfile

from conftest import load

REPO = pathlib.Path(__file__).resolve().parent.parent.parent
SCRIPT = REPO / "scripts/fetch-g729-vectors.py"

fetch = load("fetch-g729-vectors")

A = "Software/G729_Release3/g729AnnexA/test_vectors/"
B = "Software/G729_Release3/g729AnnexB/test_vectors/"


def _zip(path, entries):
    with zipfile.ZipFile(path, "w") as z:
        for name, data in entries.items():
            z.writestr(name, data)
    return path


def _run(*args):
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args], capture_output=True, text=True
    )


def test_refuses_a_package_with_the_wrong_hash(tmp_path):
    pkg = _zip(tmp_path / "pkg.zip", {A + "ALGTHM.BIT": b"not the ITU bytes"})
    dest = tmp_path / "vectors"
    out = _run("--zip", str(pkg), str(dest))
    assert out.returncode == 1, out.stderr
    assert "sha256" in out.stderr
    assert fetch.PACKAGE_SHA256 in out.stderr
    # Nothing was extracted from the refused package.
    assert not any(dest.rglob("*.BIT")) if dest.exists() else True
    # A package given with --zip belongs to the caller and is left in place.
    assert pkg.exists()


def test_extracts_only_test_vector_entries(tmp_path):
    vector = b"\x21\x6b\x50\x00"
    pins = {A + "ALGTHM.BIT": hashlib.sha256(vector).hexdigest()}
    pkg = _zip(
        tmp_path / "pkg.zip",
        {
            A + "ALGTHM.BIT": vector,
            "Software/G729_Release3/g729AnnexA/c_code/OTHER.TXT": b"x",
        },
    )
    dest = tmp_path / "vectors"
    fetch.extract(pkg, dest, pins)
    written = sorted(p.relative_to(dest).as_posix() for p in dest.rglob("*") if p.is_file())
    assert written == ["annex-a/ALGTHM.BIT"]
    assert (dest / "annex-a/ALGTHM.BIT").read_bytes() == vector


def test_extracts_pinned_source_files_and_nothing_else(tmp_path):
    source = b"/* table source */"
    entry = "Software/G729_Release3/g729AnnexA/c_code/TAB_LD8A.C"
    pins = {entry: hashlib.sha256(source).hexdigest()}
    pkg = _zip(
        tmp_path / "pkg.zip",
        {entry: source, "Software/G729_Release3/g729AnnexA/c_code/CODER.C": b"y"},
    )
    dest = tmp_path / "vectors"
    fetch.extract(pkg, dest, pins)
    written = sorted(p.relative_to(dest).as_posix() for p in dest.rglob("*") if p.is_file())
    assert written == ["itu-source/g729AnnexA/c_code/TAB_LD8A.C"]


def test_source_pins_are_the_sixteen_table_sources():
    assert len(fetch.SOURCES) == 16
    for path, digest in fetch.SOURCES.items():
        assert path.startswith("Software/G729_Release3/g729Annex")
        assert path.rsplit(".", 1)[1] in ("C", "c", "H", "h")
        assert len(digest) == 64 and int(digest, 16) >= 0
    # Everything the script extracts is a test vector or one of these sources.
    assert set(fetch.ALL_PINS) == set(fetch.PINS) | set(fetch.SOURCES)


def test_refuses_an_extracted_file_with_the_wrong_hash(tmp_path):
    pins = {B + "tstseq1a.bit": "0" * 64}
    pkg = _zip(tmp_path / "pkg.zip", {B + "tstseq1a.bit": b"tampered"})
    dest = tmp_path / "vectors"
    try:
        fetch.extract(pkg, dest, pins)
    except fetch.FetchError as err:
        assert "tstseq1a.bit" in str(err)
    else:
        raise AssertionError("a file with the wrong sha256 was accepted")
    assert not (dest / "annex-b/tstseq1a.bit").exists()


def test_refuses_a_package_missing_a_pinned_file(tmp_path):
    pins = {A + "TEST.BIT": "0" * 64}
    pkg = _zip(tmp_path / "pkg.zip", {})
    try:
        fetch.extract(pkg, tmp_path / "vectors", pins)
    except fetch.FetchError as err:
        assert "TEST.BIT" in str(err)
    else:
        raise AssertionError("a package without a pinned file was accepted")


def test_pins_cover_the_sixteen_conformance_pairs():
    names = {p.rsplit("/", 1)[1] for p in fetch.PINS}
    for stem in "ALGTHM ERASURE FIXED LSP OVERFLOW PARITY PITCH SPEECH TAME".split():
        assert f"{stem}.BIT" in names and f"{stem}.PST" in names
    assert "TEST.BIT" in names and "TEST.pst" in names
    for bit, out in [
        ("tstseq1a.bit", "tstseq1a.out"),
        ("tstseq2a.bit", "tstseq2a.out"),
        ("tstseq3a.bit", "tstseq3a.out"),
        ("tstseq4a.bit", "tstseq4a.out"),
        ("tstseq5.bit", "tstseq5a.out"),
        ("tstseq6.bit", "tstseq6a.out"),
    ]:
        assert bit in names and out in names
    # Every pin is a full sha256 and every pinned path is a test-vector entry.
    for path, digest in fetch.PINS.items():
        assert path.startswith((A, B))
        assert len(digest) == 64 and int(digest, 16) >= 0


C = "Software/G.729.1_V1.5_Part3_dtxcng_fixed-point_AnnexC/test_vectors_Annex_C_090727/"


def test_g7291_pins_cover_the_core_layer_vectors():
    names = {p.rsplit("/", 1)[1] for p in fetch.G7291_PINS}
    # The G.729.1 bitstreams and the G.729-format bitstreams encoded from the
    # same inputs, which the core-layer conformance tests compare.
    assert names == {
        "test1_16k.b32",
        "test1_16k.b8",
        "test2_8k.b8",
        "test2_8k.b12",
        "test2_8k.b729b",
        "test3_16k.b32",
        "test3_16k.b729b",
    }
    for path, digest in fetch.G7291_PINS.items():
        assert path.startswith(C)
        assert len(digest) == 64 and int(digest, 16) >= 0
    assert len(fetch.G7291_PACKAGE_SHA256) == 64
    assert "T-REC-G.729.1-200908-I!Cor1!SOFT-ZST-E" in fetch.G7291_PACKAGE_URL


def test_extracts_g7291_vectors_into_their_own_directory(tmp_path):
    vector = b"\x21\x6b\xa0\x00"
    pins = {C + "test1_16k.b32": hashlib.sha256(vector).hexdigest()}
    pkg = _zip(
        tmp_path / "pkg.zip",
        {
            C + "test1_16k.b32": vector,
            "Software/G.729.1_V1.5_Part3_dtxcng_fixed-point_AnnexC/src/main/X.c": b"x",
        },
    )
    dest = tmp_path / "vectors"
    fetch.extract(pkg, dest, pins)
    written = sorted(p.relative_to(dest).as_posix() for p in dest.rglob("*") if p.is_file())
    assert written == ["g7291/test1_16k.b32"]


def test_refuses_a_g7291_package_with_the_wrong_hash(tmp_path):
    g729 = _zip(tmp_path / "g729.zip", {A + "ALGTHM.BIT": b"x"})
    g7291 = _zip(tmp_path / "g7291.zip", {C + "test1_16k.b32": b"not the ITU bytes"})
    dest = tmp_path / "vectors"
    out = _run("--g7291-zip", str(g7291), "--g7291-only", str(dest))
    assert out.returncode == 1, out.stderr
    assert fetch.G7291_PACKAGE_SHA256 in out.stderr
    assert not (dest / "g7291").exists()
    assert g729.exists() and g7291.exists()


class _Flaky:
    """An opener that fails with the given HTTP codes, then serves BODY."""

    def __init__(self, codes, body=b"package bytes"):
        self.codes = list(codes)
        self.body = body
        self.calls = 0

    def __call__(self, request, timeout=None):
        import io
        import urllib.error

        self.calls += 1
        if self.codes:
            code = self.codes.pop(0)
            raise urllib.error.HTTPError(request.full_url, code, "fake", {}, None)
        return io.BytesIO(self.body)


def test_download_retries_a_transient_server_error_then_succeeds(tmp_path):
    waits = []
    opener = _Flaky([503, 500])
    path = fetch.download(tmp_path, "https://example.invalid/p.zip", "p.part",
                          opener=opener, sleep=waits.append)
    assert path.read_bytes() == b"package bytes"
    assert opener.calls == 3
    assert waits == list(fetch.RETRY_WAITS[:2])


def test_download_gives_up_after_the_last_attempt(tmp_path):
    import urllib.error

    waits = []
    opener = _Flaky([503] * 50)
    try:
        fetch.download(tmp_path, "https://example.invalid/p.zip", "p.part",
                       opener=opener, sleep=waits.append)
    except urllib.error.HTTPError as err:
        assert err.code == 503
    else:
        raise AssertionError("a server that never answers must fail the fetch")
    assert opener.calls == len(fetch.RETRY_WAITS) + 1
    assert waits == list(fetch.RETRY_WAITS)


def test_download_retries_a_404_the_itu_server_returns_transiently(tmp_path):
    opener = _Flaky([404])
    path = fetch.download(tmp_path, "https://example.invalid/p.zip", "p.part",
                          opener=opener, sleep=lambda _s: None)
    assert path.read_bytes() == b"package bytes"
    assert opener.calls == 2


# -- --check: are the fetched files in place? --------------------------------
#
# The hooks ask this before they run anything, so a fresh worktree is refused
# in seconds with the command that fixes it, instead of 25 minutes into the
# suite. It reads the same pins and destinations a fetch writes, and it never
# touches the network.


def _every_destination(dest):
    pins = {**fetch.ALL_PINS, **fetch.G7291_PINS}
    return sorted(fetch.destination(dest, entry) for entry in pins)


def _provision(dest):
    for path in _every_destination(dest):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"x")


def test_missing_names_every_pinned_file_of_an_empty_destination(tmp_path):
    assert sorted(fetch.missing(tmp_path)) == _every_destination(tmp_path)


def test_missing_is_empty_once_every_pinned_file_is_in_place(tmp_path):
    _provision(tmp_path)
    assert fetch.missing(tmp_path) == []


def test_missing_names_the_one_file_that_was_removed(tmp_path):
    _provision(tmp_path)
    gone = _every_destination(tmp_path)[0]
    gone.unlink()
    assert fetch.missing(tmp_path) == [gone]


def test_check_exits_1_with_the_fetch_command_then_0_once_fetched(tmp_path):
    out = _run("--check", str(tmp_path))
    assert out.returncode == 1, out.stdout + out.stderr
    assert "python3 scripts/fetch-g729-vectors.py" in out.stderr
    assert f"{len(_every_destination(tmp_path))} of" in out.stderr
    _provision(tmp_path)
    out = _run("--check", str(tmp_path))
    assert out.returncode == 0, out.stdout + out.stderr


def test_check_writes_nothing_and_downloads_nothing(tmp_path):
    dest = tmp_path / "vectors"
    out = _run("--check", str(dest))
    assert out.returncode == 1
    assert not dest.exists(), "--check created the destination"
