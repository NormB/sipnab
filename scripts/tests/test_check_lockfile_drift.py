# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""scripts/check-lockfile-drift.py: the fuzz targets build what ships.

The fuzz workspace has its own Cargo.lock and builds the sipnab crate as a
path dependency, so every crate sipnab uses is resolved twice, once per
lockfile. On 2026-11-08 the two disagreed on 56 of the 214 crates they share
(clap 4.6.3 in Cargo.lock, 4.6.7 in fuzz/Cargo.lock; cc 1.2.59 and 1.4.0),
and nothing compared them: the fuzz targets were fuzzing dependency code the
binary does not ship. The rule: every version of a shared crate in
fuzz/Cargo.lock is one Cargo.lock has, unless an exception names the crate,
the versions and the reason.

The rule is driven through `violations()` with parsed lockfiles built here,
and through `main()` with lockfiles written to a temporary directory.
"""

import hashlib
import pathlib
import re

import pytest

from conftest import SCRIPTS, load

drift = load("check-lockfile-drift")
REPO = SCRIPTS.parent
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"


def pkg(spec: str, source: str = REGISTRY, checksum: str | None = None) -> dict:
    """One `[[package]]` entry from "name version"."""
    name, version = spec.split()
    if checksum is None:
        checksum = hashlib.sha256(f"{name}@{version}".encode()).hexdigest()
    return {"name": name, "version": version, "source": source, "checksum": checksum}


def lock(*entries) -> dict:
    """A parsed Cargo.lock holding the entries ("name version" or a dict)."""
    return {"version": 4, "package": [e if isinstance(e, dict) else pkg(e) for e in entries]}


# Every fixture shares `sipnab 9.9.9`, as the real pair shares the path crate,
# so a test about one crate is never refused for sharing nothing.
SHARED = "sipnab 9.9.9"


def check(root: list, fuzz: list, exceptions=()) -> list[str]:
    return drift.violations(lock(SHARED, *root), lock(SHARED, *fuzz), exceptions)


# ── The rule ────────────────────────────────────────────────────────────────


def test_identical_lockfiles_pass():
    both = ["clap 4.6.3", "cc 1.2.59", "syn 1.0.109", "syn 2.0.117"]
    assert check(both, both) == []


def test_a_fuzz_only_crate_passes():
    assert check(["clap 4.6.3"], ["clap 4.6.3", "libfuzzer-sys 0.4.10", "arbitrary 1.4.2"]) == []


def test_a_root_only_crate_passes():
    assert check(["clap 4.6.3", "tokio 1.54.1"], ["clap 4.6.3"]) == []


def test_a_differing_version_fails_naming_the_crate_and_both_versions():
    found = check(["clap 4.6.3"], ["clap 4.6.7"])
    assert len(found) == 1, found
    assert "clap" in found[0]
    assert "4.6.7" in found[0] and "4.6.3" in found[0]


def test_a_fuzz_version_behind_the_root_fails_too():
    # hybrid-array was 0.4.13 in the fuzz tree and 0.4.15 in the root: older
    # is as much a different dependency as newer.
    found = check(["hybrid-array 0.4.15"], ["hybrid-array 0.4.13"])
    assert len(found) == 1, found
    assert "hybrid-array" in found[0] and "0.4.13" in found[0] and "0.4.15" in found[0]


def test_the_violation_names_the_cargo_update_that_fixes_it():
    (found,) = check(["clap 4.6.3"], ["clap 4.6.7"])
    assert "cargo update --manifest-path fuzz/Cargo.toml -p clap@4.6.7 --precise 4.6.3" in found


def test_a_fuzz_version_missing_from_a_multi_version_root_set_fails():
    # The root holds three semver-incompatible hashbrowns; the fuzz tree's
    # 0.17.1 is none of them. The suggested target is the root's 0.17 line.
    found = check(["hashbrown 0.15.5", "hashbrown 0.16.1", "hashbrown 0.17.0"], ["hashbrown 0.17.1"])
    assert len(found) == 1, found
    assert "hashbrown" in found[0] and "0.17.1" in found[0]
    assert "-p hashbrown@0.17.1 --precise 0.17.0" in found[0]


def test_a_fuzz_version_in_a_multi_version_root_set_passes():
    assert check(["rand 0.8.6", "rand 0.10.1"], ["rand 0.8.6"]) == []


def test_a_root_only_extra_version_passes():
    # The root has more dependents, so it can need a second line of a crate
    # the fuzz tree needs one of. Equality would demand the fuzz tree carry
    # code nothing in it uses.
    assert check(["bitflags 1.3.2", "bitflags 2.13.0"], ["bitflags 2.13.0"]) == []


def test_two_fuzz_versions_with_one_missing_name_only_the_missing_one():
    found = check(["syn 1.0.109", "syn 2.0.117"], ["syn 1.0.109", "syn 2.0.119"])
    assert len(found) == 1, found
    assert "2.0.119" in found[0]
    assert "-p syn@1.0.109" not in found[0]


def test_every_violation_is_returned_not_only_the_first():
    found = check(
        ["arrayvec 0.7.6", "cc 1.2.59", "clap 4.6.3"],
        ["arrayvec 0.7.8", "cc 1.4.0", "clap 4.6.7"],
    )
    assert len(found) == 3, found
    assert [f.split(":")[0] for f in found] == ["arrayvec", "cc", "clap"]


def test_no_root_version_on_the_same_line_names_no_precise_command():
    # shlex 2 (pulled in by cc 1.4) has no counterpart in a root on shlex 1:
    # the fix is to move what pulls it in, and a --precise 1.3.0 would not
    # resolve. The message says so rather than suggesting it.
    (found,) = check(["shlex 1.3.0"], ["shlex 2.0.1"])
    assert "shlex" in found and "2.0.1" in found and "1.3.0" in found
    assert "--precise" not in found
    assert "no 2.x" in found


def test_build_metadata_does_not_split_a_release_line():
    (found,) = check(["wasip2 1.0.2+wasi-0.2.9"], ["wasip2 1.0.4+wasi-0.2.12"])
    assert "-p wasip2@1.0.4+wasi-0.2.12 --precise 1.0.2+wasi-0.2.9" in found


def test_two_root_versions_on_the_line_name_both_and_no_single_target():
    # Cargo can lock two compatible versions when an `=` requirement pins
    # one. Either may be the right target, so the message names both.
    (found,) = check(["clap 4.6.3", "clap 4.6.5"], ["clap 4.6.7"])
    assert "--precise" not in found
    assert "no 4.x line" not in found
    assert "4.6.3 and 4.6.5 on the 4.x line" in found


def test_a_zero_zero_version_is_its_own_line():
    # 0.0.x releases are mutually incompatible in Cargo's semver, so 0.0.3 is
    # not a target for 0.0.4.
    (found,) = check(["tinyc 0.0.3"], ["tinyc 0.0.4"])
    assert "--precise" not in found


def test_the_same_version_from_another_source_fails():
    git = "git+https://example.com/fork/clap?rev=abc#abc"
    found = drift.violations(
        lock(SHARED, "clap 4.6.3"), lock(SHARED, pkg("clap 4.6.3", source=git)), ()
    )
    assert len(found) == 1, found
    assert "clap 4.6.3" in found[0] and "source" in found[0]


def test_the_same_version_with_another_checksum_fails():
    found = drift.violations(
        lock(SHARED, "clap 4.6.3"), lock(SHARED, pkg("clap 4.6.3", checksum="0" * 64)), ()
    )
    assert len(found) == 1, found
    assert "clap 4.6.3" in found[0] and "checksum" in found[0]


def test_path_crates_without_source_or_checksum_compare_equal():
    path = {"name": "sipnab-g729", "version": "0.3.0"}
    assert drift.violations(lock(SHARED, path), lock(SHARED, dict(path)), ()) == []


# ── Exceptions ─────────────────────────────────────────────────────────────

REASON = "libfuzzer-sys 0.4.10 requires cc 1.4 and the root has no 1.4 dependent"


def test_an_exception_passes_its_exact_versions():
    assert check(["cc 1.2.59"], ["cc 1.4.0"], [("cc", ("1.4.0",), REASON)]) == []


def test_an_exception_does_not_cover_another_version_of_its_crate():
    found = check(["cc 1.2.59"], ["cc 1.4.1"], [("cc", ("1.4.0",), REASON)])
    # 1.4.1 is unexcepted drift, and 1.4.0 no longer drifts: both reported.
    assert any("1.4.1" in f and "stale" not in f for f in found), found
    assert any("stale" in f and "1.4.0" in f for f in found), found


def test_an_exception_for_one_crate_does_not_cover_another():
    found = check(["cc 1.2.59", "clap 4.6.3"], ["cc 1.4.0", "clap 4.6.7"], [("cc", ("1.4.0",), REASON)])
    assert len(found) == 1, found
    assert found[0].startswith("clap:")


def test_a_stale_exception_fails():
    found = check(["cc 1.2.59"], ["cc 1.2.59"], [("cc", ("1.4.0",), REASON)])
    assert len(found) == 1, found
    assert "stale" in found[0] and "cc" in found[0] and "1.4.0" in found[0]


def test_an_exception_naming_a_version_that_no_longer_drifts_fails():
    found = check(
        ["syn 1.0.109", "syn 2.0.117"],
        ["syn 1.0.110", "syn 2.0.117"],
        [("syn", ("1.0.110", "2.0.119"), REASON)],
    )
    assert len(found) == 1, found
    assert "stale" in found[0] and "2.0.119" in found[0]
    assert "1.0.110" not in found[0]


def test_an_exception_for_a_crate_not_in_both_lockfiles_fails():
    found = check(["clap 4.6.3"], ["clap 4.6.3", "arbitrary 1.4.2"], [("arbitrary", ("1.4.2",), REASON)])
    assert len(found) == 1, found
    assert "stale" in found[0] and "arbitrary" in found[0]


@pytest.mark.parametrize(
    "bad, said",
    [
        (("cc", ("1.4.0",), ""), "reason"),
        (("cc", ("1.4.0",), "   "), "reason"),
        (("cc", (), REASON), "version"),
        (("", ("1.4.0",), REASON), "crate"),
        (("cc", "1.4.0", REASON), "version"),
        (("cc", ("1.4.0",)), "crate, versions, reason"),
    ],
)
def test_a_malformed_exception_is_refused(bad, said):
    with pytest.raises(drift.InputError, match=said):
        check(["cc 1.2.59"], ["cc 1.4.0"], [bad])


def test_two_exceptions_for_one_crate_are_refused():
    with pytest.raises(drift.InputError, match="cc"):
        check(["cc 1.2.59"], ["cc 1.4.0"], [("cc", ("1.4.0",), REASON), ("cc", ("1.4.0",), REASON)])


# ── Malformed lockfiles ────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "bad",
    [
        {},
        {"package": "clap"},
        {"package": {"name": "clap"}},
        [],
    ],
    ids=["no-package-key", "package-not-a-list", "package-a-table", "not-a-table"],
)
def test_a_lockfile_without_a_package_list_is_refused(bad):
    with pytest.raises(drift.InputError, match="fuzz/Cargo.lock"):
        drift.violations(lock(SHARED), bad, ())


@pytest.mark.parametrize(
    "entry",
    [
        {"name": "clap"},
        {"version": "4.6.3"},
        {"name": "clap", "version": 4},
        {"name": "", "version": "4.6.3"},
        "clap 4.6.3",
    ],
    ids=["no-version", "no-name", "version-not-text", "empty-name", "not-a-table"],
)
def test_a_malformed_package_entry_is_refused(entry):
    with pytest.raises(drift.InputError, match=r"Cargo.lock: package 2"):
        drift.violations({"package": [pkg(SHARED), entry]}, lock(SHARED), ())


def test_the_same_package_twice_is_refused():
    with pytest.raises(drift.InputError, match="clap 4.6.3.*twice"):
        drift.violations(lock(SHARED), lock(SHARED, "clap 4.6.3", "clap 4.6.3"), ())


def test_an_empty_lockfile_is_refused():
    # A lockfile that lists nothing would pass every comparison.
    with pytest.raises(drift.InputError, match="no packages"):
        drift.violations(lock(SHARED), {"version": 4, "package": []}, ())


def test_lockfiles_sharing_nothing_are_refused():
    # The fuzz tree builds sipnab itself, so the pair always shares it. Two
    # lockfiles with nothing in common are the wrong two files.
    with pytest.raises(drift.InputError, match="no crate in common"):
        drift.violations(lock("clap 4.6.3"), lock("libfuzzer-sys 0.4.10"), ())


# ── The command ────────────────────────────────────────────────────────────


def write_pair(tmp_path: pathlib.Path, root: str, fuzz: str) -> list[str]:
    (tmp_path / "Cargo.lock").write_text(root)
    (tmp_path / "fuzz.lock").write_text(fuzz)
    return ["--root", str(tmp_path / "Cargo.lock"), "--fuzz", str(tmp_path / "fuzz.lock")]


def toml(*specs: str) -> str:
    out = ["version = 4", ""]
    for spec in specs:
        name, version = spec.split()
        out += ["[[package]]", f'name = "{name}"', f'version = "{version}"', ""]
    return "\n".join(out)


def test_main_exits_0_on_aligned_lockfiles(tmp_path, capsys):
    args = write_pair(tmp_path, toml(SHARED, "clap 4.6.3"), toml(SHARED, "clap 4.6.3"))
    assert drift.main(args, exceptions=()) == 0
    out = capsys.readouterr().out
    assert "ok:" in out and "2 crates in both" in out


def test_main_exits_1_and_prints_every_violation(tmp_path, capsys):
    args = write_pair(
        tmp_path, toml(SHARED, "clap 4.6.3", "cc 1.2.59"), toml(SHARED, "clap 4.6.7", "cc 1.4.0")
    )
    assert drift.main(args, exceptions=()) == 1
    out = capsys.readouterr().out
    assert "clap:" in out and "cc:" in out
    assert "2 violations" in out


def test_main_exits_2_on_unparsable_toml(tmp_path, capsys):
    args = write_pair(tmp_path, toml(SHARED), "[[package]\nname = ")
    assert drift.main(args, exceptions=()) == 2
    err = capsys.readouterr().err
    assert "NOT CHECKED" in err and "fuzz.lock" in err


def test_main_exits_2_on_a_missing_lockfile(tmp_path, capsys):
    args = ["--root", str(tmp_path / "absent.lock"), "--fuzz", str(tmp_path / "absent.lock")]
    assert drift.main(args, exceptions=()) == 2
    assert "NOT CHECKED" in capsys.readouterr().err


def test_main_exits_2_on_a_malformed_lockfile(tmp_path, capsys):
    args = write_pair(tmp_path, toml(SHARED), "version = 4\n")
    assert drift.main(args, exceptions=()) == 2
    assert "NOT CHECKED" in capsys.readouterr().err


# ── The repository ─────────────────────────────────────────────────────────


def test_the_repository_lockfiles_agree(capsys):
    """Cargo.lock and fuzz/Cargo.lock, with the shipped exception table."""
    rc = drift.main([])
    out = capsys.readouterr()
    assert rc == 0, out.out + out.err


def test_the_pre_commit_hook_runs_the_gate():
    hook = (REPO / ".githooks" / "pre-commit").read_text()
    assert "python3 scripts/check-lockfile-drift.py" in hook


def test_ci_runs_the_gate_in_the_security_audit_job():
    ci = (REPO / ".github" / "workflows" / "ci.yml").read_text()
    audit = re.search(r"(?ms)^  audit:\n(.*?)(?=^  [a-z][a-z0-9-]*:\n)", ci)
    assert audit, "ci.yml has no audit job"
    assert "python3 scripts/check-lockfile-drift.py" in audit.group(1)
