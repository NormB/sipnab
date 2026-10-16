"""no-itu-values.py: no file sipnab ships holds a run of the G.729 tables.

The scan is the one rule both gates use: crates/g729/tests/no_itu_values.rs
over every committable file, and the release workflow over the built
binaries and packages. These tests use a synthetic table file of the same
layout, never the ITU-T values, which no test fixture may hold.
"""

import io
import pathlib
import struct
import subprocess
import sys
import tarfile
import zipfile

from conftest import load

REPO = pathlib.Path(__file__).resolve().parent.parent.parent
SCRIPT = REPO / "scripts/no-itu-values.py"

scan = load("no-itu-values")

# Two synthetic "tables" and a scalar, values chosen here, not the ITU-T ones.
TABLES = [
    [1001, -1002, 1003, -1004, 1005, -1006, 1007, -1008],
    [31, 32, 33, 34, 35, 36],
    [7],
]


def _table_file(path, tables=TABLES):
    out = bytearray(b"G729TBL\0")
    out += struct.pack("<HH", 1, len(tables))
    for i, values in enumerate(tables):
        out += struct.pack("<HI", i, len(values))
        out += struct.pack(f"<{len(values)}h", *values)
    path.write_bytes(bytes(out))
    return path


def _run(*args):
    return subprocess.run(
        [sys.executable, str(SCRIPT), *map(str, args)], capture_output=True, text=True
    )


def test_a_run_is_found_only_across_separators():
    runs = scan.integer_runs("x = { 1, -2, 3,\n 4, 5, 6 }; y7 8 9 10 11 12 a 13")
    assert len(runs) == 1
    assert [v for v, _ in runs[0]] == [1, -2, 3, 4, 5, 6]
    assert runs[0][3][1] == 2
    assert scan.integer_runs("1 2 3 4 5 v6 7") == []


def test_the_table_file_is_read_per_entry(tmp_path):
    entries = scan.read_table_file(_table_file(tmp_path / "t.bin").read_bytes())
    assert entries == TABLES


def test_a_text_run_is_reported_by_file_line_and_table_never_values(tmp_path):
    tables = _table_file(tmp_path / "t.bin")
    src = tmp_path / "leak.rs"
    src.write_text("// header\nconst T: [i16; 6] = [-1002, 1003,\n -1004, 1005, -1006, 1007];\n")
    r = _run("--tables", tables, "--names", "first,second,third", src)
    assert r.returncode == 1
    assert f"{src}:2: a run of table first" in r.stdout
    assert "1003" not in r.stdout + r.stderr


def test_five_values_are_not_a_run(tmp_path):
    tables = _table_file(tmp_path / "t.bin")
    src = tmp_path / "short.txt"
    src.write_text("31, 32, 33, 34, 35\n")
    assert _run("--tables", tables, src).returncode == 0


def test_a_binary_holding_the_values_as_16_or_32_bit_integers_is_reported(tmp_path):
    tables = _table_file(tmp_path / "t.bin")
    for name, packed in [
        ("le16", struct.pack("<6h", 31, 32, 33, 34, 35, 36)),
        ("be16", struct.pack(">6h", 31, 32, 33, 34, 35, 36)),
        ("le32", struct.pack("<6i", 31, 32, 33, 34, 35, 36)),
    ]:
        binary = tmp_path / f"sipnab-{name}"
        binary.write_bytes(b"\x7fELF" + b"\x00\x01" * 37 + b"\x03" + packed + b"\xff" * 9)
        r = _run("--tables", tables, binary)
        assert r.returncode == 1, name
        assert f"{binary}: the values of table 1 as {name}" in r.stdout, r.stdout


def test_archives_and_directories_are_opened(tmp_path):
    tables = _table_file(tmp_path / "t.bin")
    payload = struct.pack("<6h", 1003, -1004, 1005, -1006, 1007, -1008)
    tgz = tmp_path / "dist" / "sipnab-1.0-x86_64.tar.gz"
    tgz.parent.mkdir()
    with tarfile.open(tgz, "w:gz") as t:
        info = tarfile.TarInfo("sipnab-1.0/sipnab")
        info.size = len(payload) + 3
        t.addfile(info, io.BytesIO(b"abc" + payload))
    z = tmp_path / "dist" / "sipnab.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("sipnab.exe", b"MZ" + payload)
    r = _run("--tables", tables, tmp_path / "dist")
    assert r.returncode == 1
    assert f"{tgz}!sipnab-1.0/sipnab: the values of table 0 as le16" in r.stdout, r.stdout
    assert f"{z}!sipnab.exe: the values of table 0 as le16" in r.stdout, r.stdout


def test_clean_files_pass_and_say_what_was_scanned(tmp_path):
    tables = _table_file(tmp_path / "t.bin")
    (tmp_path / "a.txt").write_text("1 2 3 4 5 6 7\n")
    (tmp_path / "b.bin").write_bytes(bytes(range(256)))
    r = _run("--tables", tables, tmp_path / "a.txt", tmp_path / "b.bin")
    assert r.returncode == 0, r.stdout
    assert "2 file(s)" in r.stdout


def test_a_table_file_of_another_layout_is_refused(tmp_path):
    bad = tmp_path / "bad.bin"
    bad.write_bytes(b"not a table file")
    r = _run("--tables", bad, tmp_path)
    assert r.returncode == 2
    assert "not a G.729 table file" in r.stderr
