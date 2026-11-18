# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""The release builds' package installs say what failed, and the aarch64
build installs the multiarch packages at one version for both architectures.

Release run 43881101798 (v0.5.260) failed both gnu-aarch64 builds in "Install
build deps (bookworm container)": libpcap-dev:arm64 pulls libc6-dev:arm64,
which needs linux-libc-dev:arm64, and apt took arm64 6.1.192-2 from
bookworm-security while amd64 had only 6.1.192-1. The package is
`Multi-Arch: same`, so both architectures must hold one version, and the
install could not be resolved. The step then printed "did not complete
within 600s ... re-run the job" for an apt run that ended in seconds on
dependency resolution, which a re-run cannot fix.

scripts/release-apt.sh is the rule: `apt_failure_kind` tells a timeout, a
download failure and a resolution failure apart, `apt_failure_message` says
what each means, and `multiarch_pins` names, for each `Multi-Arch: same`
package, the newest version both architectures' indexes carry. The release
step itself runs only on a tag; these tests drive the functions it calls,
with stand-ins for apt-get and apt-cache.
"""

import os
import pathlib
import stat
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent.parent
SCRIPT = REPO / "scripts/release-apt.sh"
RELEASE = REPO / ".github/workflows/release.yml"


def run(*args, env=None, timeout=60):
    return subprocess.run(
        ["bash", str(SCRIPT), *args],
        cwd=REPO,
        capture_output=True,
        text=True,
        env=env,
        timeout=timeout,
    )


def log(tmp_path, text):
    p = tmp_path / "apt.log"
    p.write_text(text)
    return str(p)


def stub(bindir, name, body):
    bindir.mkdir(exist_ok=True)
    p = bindir / name
    p.write_text("#!/bin/sh\n" + body)
    p.chmod(p.stat().st_mode | stat.S_IXUSR)
    return p


def path_env(bindir):
    return dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}")


# --- apt_failure_kind -------------------------------------------------------

UNRESOLVED = """Some packages could not be installed. This may mean that you have
requested an impossible situation.
The following packages have unmet dependencies:
 libc6-dev:arm64 : Depends: linux-libc-dev:arm64 but it is not going to be installed
E: Unable to correct problems, you have held broken packages.
"""
FETCH = "E: Failed to fetch http://deb.debian.org/debian/pool/main/c/cmake/cmake_3.25.1-1_amd64.deb  Connection failed\n"

KIND_CASES = [
    # success: each failure is named for what it was
    ("success", "124", "", "timeout"),
    ("success", "137", "", "timeout"),
    ("success", "100", UNRESOLVED, "resolve"),
    ("success", "100", "E: Unable to locate package libpcap-dev:arm64\n", "resolve"),
    ("success", "100", "E: Version '6.1.192-1' for 'linux-libc-dev:arm64' was not found\n", "resolve"),
    ("success", "100", FETCH, "fetch"),
    ("success", "100", "W: Failed to fetch http://deb.debian.org/debian/dists/bookworm/InRelease  "
                       "Temporary failure resolving 'deb.debian.org'\n", "fetch"),
    ("success", "100", "E: Failed to fetch store:/var/lib/apt/lists/partial/x  Hash Sum mismatch\n", "fetch"),
    ("success", "100", "Err:1 http://deb.debian.org/debian bookworm InRelease\n  Could not connect to "
                       "deb.debian.org:80\n", "fetch"),
    ("success", "100", "E: Sub-process /usr/bin/dpkg returned an error code (1)\n", "other"),
    ("success", "1", "", "other"),
    ("success", "100", "The following packages have unmet dependencies:\n x : Depends: y\n", "resolve"),
    # failure: a wrong reading would send someone to re-run, or not
    ("failure", "100", "Reading package lists... Done\n", "other"),
    ("failure", "2", "a line that says timeout in its text\n", "other"),
    ("failure", "100", "deb.debian.org answered\n", "other"),
    ("failure", "124", UNRESOLVED, "timeout"),
    ("failure", "100", "unable to correct problems (lower case is not apt's line)\n", "other"),
    ("failure", "100", "Failed to fetchless\n", "other"),
    ("failure", "125", "", "other"),
    ("failure", "126", "", "other"),
    ("failure", "127", "", "other"),
    ("failure", "100", "W: Some index files failed to download. They have been ignored\n", "fetch"),
    ("failure", "100", "Temporary failure resolving 'security.debian.org'\n", "fetch"),
    ("failure", "100", " x : Depends: y but it is not going to be installed\n", "resolve"),
    # edge: priority, empty input, odd codes
    ("edge", "100", FETCH + "E: Unable to locate package cmake\n", "fetch"),
    ("edge", "0", "", "none"),
    ("edge", "100", "", "other"),
    ("edge", "100", "\n\n\n", "other"),
    ("edge", "137", FETCH, "timeout"),
    ("edge", "100", UNRESOLVED.replace("\n", "\r\n"), "resolve"),
    ("edge", "255", "", "other"),
    ("edge", "abc", "", "other"),
    ("edge", "100", "E: Unable to locate package\n", "resolve"),
    ("edge", "100", "x" * 100000 + "\n" + UNRESOLVED, "resolve"),
    ("edge", "100", "E: Broken packages\n", "resolve"),
    ("edge", "1", FETCH, "fetch"),
    ("edge", "100", "E: Release file for http://deb.debian.org/x is not valid: Hash Sum mismatch\n", "fetch"),
    ("edge", "100", "E: Unable to correct problems, you have held broken packages.\n", "resolve"),
]


@pytest.mark.parametrize("kind,rc,text,want", KIND_CASES)
def test_apt_failure_kind(tmp_path, kind, rc, text, want):
    r = run("apt_failure_kind", rc, log(tmp_path, text))
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == want, (kind, rc, text[:200], r.stdout)


def test_apt_failure_kind_of_a_missing_log_is_other_or_timeout(tmp_path):
    r = run("apt_failure_kind", "100", str(tmp_path / "absent.log"))
    assert (r.returncode, r.stdout.strip()) == (0, "other"), r.stderr
    r = run("apt_failure_kind", "124", str(tmp_path / "absent.log"))
    assert (r.returncode, r.stdout.strip()) == (0, "timeout"), r.stderr


# --- apt_failure_message ----------------------------------------------------

MESSAGE_CASES = [
    # (kind, must contain, must not contain)
    ("timeout", ["::error::FETCH failure", "did not complete within 600s", "re-run the job", "apt-get install"],
     ["DEPENDENCY"]),
    ("fetch", ["::error::FETCH failure", "could not download", "re-run the job", "exit 100"],
     ["did not complete within"]),
    ("resolve", ["::error::DEPENDENCY failure", "could not resolve", "A re-run fails the same way", "exit 100"],
     ["re-run the job", "did not complete within"]),
    ("other", ["::error::apt-get install failed with exit 100"], ["re-run the job", "did not complete within"]),
]


@pytest.mark.parametrize("kind,want,unwanted", MESSAGE_CASES)
def test_apt_failure_message_says_what_the_failure_was(kind, want, unwanted):
    r = run("apt_failure_message", kind, "install", "600", "100")
    assert r.returncode == 0, r.stderr
    for w in want:
        assert w in r.stdout, (kind, w, r.stdout)
    for u in unwanted:
        assert u not in r.stdout, (kind, u, r.stdout)
    assert r.stdout.count("\n") == 1, r.stdout


def test_apt_failure_message_of_an_unknown_kind_is_refused():
    r = run("apt_failure_message", "weather", "install", "600", "100")
    assert r.returncode != 0
    assert "weather" in r.stderr


# --- madison_versions and common_version ------------------------------------

MADISON_ARM64 = """linux-libc-dev | 6.1.192-2 | http://deb.debian.org/debian-security bookworm-security/main arm64 Packages
linux-libc-dev | 6.1.192-1 | http://deb.debian.org/debian bookworm-updates/main arm64 Packages
linux-libc-dev | 6.1.158-1 | http://deb.debian.org/debian bookworm/main arm64 Packages
"""
MADISON_AMD64 = """linux-libc-dev | 6.1.192-1 | http://deb.debian.org/debian bookworm-updates/main amd64 Packages
linux-libc-dev | 6.1.158-1 | http://deb.debian.org/debian bookworm/main amd64 Packages
"""


def versions(text):
    return subprocess.run(
        ["bash", str(SCRIPT), "madison_versions"], input=text, capture_output=True, text=True, timeout=30
    )


def test_madison_versions_reads_the_version_column():
    r = versions(MADISON_ARM64)
    assert r.stdout.split() == ["6.1.192-2", "6.1.192-1", "6.1.158-1"], r.stdout


def test_madison_versions_drops_blank_lines_and_repeats():
    r = versions("\n" + MADISON_AMD64 + "\n" + MADISON_AMD64)
    assert r.stdout.split() == ["6.1.192-1", "6.1.158-1"], r.stdout


def test_madison_versions_of_nothing_is_nothing():
    r = versions("")
    assert (r.returncode, r.stdout) == (0, ""), r.stderr


def test_madison_versions_skips_a_line_without_columns():
    r = versions("N: Unable to locate package nothing\n" + MADISON_AMD64)
    assert r.stdout.split() == ["6.1.192-1", "6.1.158-1"], r.stdout


def test_madison_versions_skips_a_line_with_two_columns():
    # apt-cache madison prints package | version | source; a line with fewer
    # columns is not one of its answers.
    r = versions("note | 9.9-1\n" + MADISON_AMD64)
    assert r.stdout.split() == ["6.1.192-1", "6.1.158-1"], r.stdout


def lists(tmp_path, a, b):
    pa, pb = tmp_path / "a", tmp_path / "b"
    pa.write_text("".join(v + "\n" for v in a))
    pb.write_text("".join(v + "\n" for v in b))
    return str(pa), str(pb)


COMMON_CASES = [
    # success
    ("success", ["6.1.192-1", "6.1.158-1"], ["6.1.192-2", "6.1.192-1", "6.1.158-1"], "6.1.192-1"),
    ("success", ["6.1.192-2", "6.1.192-1"], ["6.1.192-2", "6.1.192-1"], "6.1.192-2"),
    ("success", ["2.36-9+deb12u10", "2.36-9+deb12u9"], ["2.36-9+deb12u9"], "2.36-9+deb12u9"),
    ("success", ["1:2.0-1", "2.0-1"], ["2.0-1", "1:2.0-1"], "1:2.0-1"),
    ("success", ["6.1~rc1-1", "6.1-1"], ["6.1~rc1-1", "6.1-1"], "6.1-1"),
    ("success", ["6.1.158-1"], ["6.1.192-2", "6.1.158-1"], "6.1.158-1"),
    ("success", ["1.10-1", "1.9-1"], ["1.9-1", "1.10-1"], "1.10-1"),
    # failure: no version both carry
    ("failure", ["6.1.192-1"], ["6.1.192-2"], ""),
    ("failure", [], ["6.1.192-2"], ""),
    ("failure", ["6.1.192-1"], [], ""),
    ("failure", [], [], ""),
    ("failure", ["6.1.192-10"], ["6.1.192-1"], ""),
    # edge
    ("edge", ["6.1.192-1", "6.1.192-1"], ["6.1.192-1"], "6.1.192-1"),
    ("edge", ["2.0-1", "10.0-1"], ["10.0-1", "2.0-1"], "10.0-1"),
    ("edge", ["1.0-1"], ["1.0-1 "], "1.0-1"),
]


@pytest.mark.parametrize("kind,a,b,want", COMMON_CASES)
def test_common_version_is_the_newest_both_carry(tmp_path, kind, a, b, want):
    r = run("common_version", *lists(tmp_path, a, b))
    assert r.stdout.strip() == want, (kind, a, b, r.stdout, r.stderr)
    assert (r.returncode == 0) == bool(want), (kind, r.returncode)


# --- multiarch_pins -----------------------------------------------------------


def fake_madison(tmp_path, per_arch, rc=0):
    """An apt-cache whose `madison <pkg>:<arch>` answers from per_arch."""
    bindir = tmp_path / "bin"
    answers = tmp_path / "madison"
    answers.mkdir()
    for key, text in per_arch.items():
        (answers / key).write_text(text)
    stub(bindir, "apt-cache",
         f'[ "$1" = madison ] || exit 9\n[ -f "{answers}/$2" ] && cat "{answers}/$2"\nexit {rc}\n')
    return path_env(bindir)


def test_multiarch_pins_takes_the_version_both_architectures_carry(tmp_path):
    env = fake_madison(tmp_path, {"linux-libc-dev:amd64": MADISON_AMD64, "linux-libc-dev:arm64": MADISON_ARM64})
    r = run("multiarch_pins", "linux-libc-dev", env=env)
    assert r.returncode == 0, r.stderr
    assert r.stdout.split() == ["linux-libc-dev:amd64=6.1.192-1", "linux-libc-dev:arm64=6.1.192-1"], r.stdout


def test_multiarch_pins_names_every_package_in_order(tmp_path):
    libc = "libc6 | 2.36-9+deb12u10 | x bookworm-security/main {a} Packages\n"
    env = fake_madison(tmp_path, {
        "linux-libc-dev:amd64": MADISON_AMD64, "linux-libc-dev:arm64": MADISON_ARM64,
        "libc6:amd64": libc.format(a="amd64"), "libc6:arm64": libc.format(a="arm64"),
    })
    r = run("multiarch_pins", "linux-libc-dev", "libc6", env=env)
    assert r.returncode == 0, r.stderr
    assert r.stdout.split() == [
        "linux-libc-dev:amd64=6.1.192-1", "linux-libc-dev:arm64=6.1.192-1",
        "libc6:amd64=2.36-9+deb12u10", "libc6:arm64=2.36-9+deb12u10",
    ], r.stdout


def test_multiarch_pins_refuses_when_no_version_is_common(tmp_path):
    env = fake_madison(tmp_path, {
        "linux-libc-dev:amd64": "linux-libc-dev | 6.1.192-1 | x amd64 Packages\n",
        "linux-libc-dev:arm64": "linux-libc-dev | 6.1.192-2 | x arm64 Packages\n",
    })
    r = run("multiarch_pins", "linux-libc-dev", env=env)
    assert r.returncode != 0
    assert r.stdout == "", r.stdout
    assert "::error::" in r.stderr and "linux-libc-dev" in r.stderr, r.stderr
    assert "6.1.192-1" in r.stderr and "6.1.192-2" in r.stderr, r.stderr


def test_multiarch_pins_refuses_a_package_one_architecture_lacks(tmp_path):
    env = fake_madison(tmp_path, {"linux-libc-dev:amd64": MADISON_AMD64})
    r = run("multiarch_pins", "linux-libc-dev", env=env)
    assert r.returncode != 0
    assert "linux-libc-dev" in r.stderr, r.stderr


def test_multiarch_pins_refuses_when_apt_cache_fails(tmp_path):
    env = fake_madison(tmp_path, {"linux-libc-dev:amd64": MADISON_AMD64,
                                  "linux-libc-dev:arm64": MADISON_ARM64}, rc=100)
    r = run("multiarch_pins", "linux-libc-dev", env=env)
    assert r.returncode != 0
    assert "apt-cache" in r.stderr, r.stderr


def test_multiarch_pins_of_no_package_is_refused(tmp_path):
    env = fake_madison(tmp_path, {})
    r = run("multiarch_pins", env=env)
    assert r.returncode != 0
    assert "no package" in r.stderr, r.stderr


def test_multiarch_pins_stops_at_the_first_package_it_cannot_pin(tmp_path):
    env = fake_madison(tmp_path, {
        "libc6:amd64": "libc6 | 2.36-9 | x amd64 Packages\n",
        "linux-libc-dev:amd64": MADISON_AMD64, "linux-libc-dev:arm64": MADISON_ARM64,
    })
    r = run("multiarch_pins", "linux-libc-dev", "libc6", env=env)
    assert r.returncode != 0
    assert r.stdout == "", r.stdout
    assert "libc6" in r.stderr, r.stderr


# --- pins_line ----------------------------------------------------------------
#
# RELEASE-APT-PINS-NOT-PRINTED: the 0.5.262 release computed the pins and
# passed them to apt, but no line of the job log named them, so nobody could
# say which version the aarch64 builds installed. `pins_line` prints them as
# one `::notice` line (a line of the log and an annotation of the job) and
# refuses words that are not one version for both architectures.

PREFIX = "::notice title=multiarch pins::"

PINS_OK = [
    ("one package",
     ["linux-libc-dev:amd64=6.1.192-1", "linux-libc-dev:arm64=6.1.192-1"]),
    ("the three the release pins",
     ["linux-libc-dev:amd64=6.1.192-1", "linux-libc-dev:arm64=6.1.192-1",
      "libc6:amd64=2.36-9+deb12u10", "libc6:arm64=2.36-9+deb12u10",
      "libc6-dev:amd64=2.36-9+deb12u10", "libc6-dev:arm64=2.36-9+deb12u10"]),
    ("an epoch in the version",
     ["libfoo:amd64=1:2.3-4", "libfoo:arm64=1:2.3-4"]),
    ("a tilde in the version",
     ["libfoo:amd64=2.0~rc1-1", "libfoo:arm64=2.0~rc1-1"]),
    ("arm64 named first",
     ["libfoo:arm64=1.0-1", "libfoo:amd64=1.0-1"]),
    ("plus signs and dots in the package name",
     ["libstdc++6:amd64=12.2.0-14", "libstdc++6:arm64=12.2.0-14"]),
    ("two packages at different versions",
     ["liba:amd64=1-1", "liba:arm64=1-1", "libb:amd64=2-2", "libb:arm64=2-2"]),
    ("packages interleaved",
     ["liba:amd64=1-1", "libb:amd64=2-2", "liba:arm64=1-1", "libb:arm64=2-2"]),
    ("a one-character version",
     ["x1:amd64=1", "x1:arm64=1"]),
    ("ten packages",
     [f"lib{n}:{a}={n}.0-1" for n in range(10) for a in ("amd64", "arm64")]),
    ("a version with letters and dots",
     ["libfoo:amd64=1.2.3a.b-1ubuntu2", "libfoo:arm64=1.2.3a.b-1ubuntu2"]),
    ("a two-character package name",
     ["gc:amd64=1:8.2.2-3", "gc:arm64=1:8.2.2-3"]),
]


@pytest.mark.parametrize("kind,words", PINS_OK, ids=[k for k, _ in PINS_OK])
def test_pins_line_prints_the_pins_on_one_notice_line(kind, words):
    r = run("pins_line", *words)
    assert r.returncode == 0, f"{kind}: {r.stderr}"
    assert r.stdout == PREFIX + " ".join(words) + "\n", f"{kind}: {r.stdout!r}"
    assert r.stderr == "", f"{kind}: {r.stderr!r}"


PINS_BAD = [
    ("no equals sign", ["libfoo:amd64", "libfoo:arm64=1-1"], "libfoo:amd64"),
    ("no architecture", ["libfoo=1-1", "libfoo:arm64=1-1"], "libfoo=1-1"),
    ("another architecture", ["libfoo:i386=1-1", "libfoo:arm64=1-1"], "libfoo:i386=1-1"),
    ("an empty version", ["libfoo:amd64=", "libfoo:arm64=1-1"], "libfoo:amd64="),
    ("an empty package", [":amd64=1-1", ":arm64=1-1"], ":amd64=1-1"),
    ("a glob", ["libfoo*:amd64=1-1", "libfoo*:arm64=1-1"], "libfoo*:amd64=1-1"),
    ("an upper-case package", ["LibFoo:amd64=1-1", "LibFoo:arm64=1-1"], "LibFoo:amd64=1-1"),
    ("a space in a word", ["libfoo:amd64=1 -1", "libfoo:arm64=1-1"], "libfoo:amd64=1 -1"),
    ("an empty word", ["", "libfoo:amd64=1-1", "libfoo:arm64=1-1"], "''"),
    ("a version with a slash", ["libfoo:amd64=1/2", "libfoo:arm64=1/2"], "libfoo:amd64=1/2"),
    ("a package starting with a dash", ["-libfoo:amd64=1", "-libfoo:arm64=1"], "-libfoo:amd64=1"),
    ("an equals sign in the version", ["libfoo:amd64=1=2", "libfoo:arm64=1=2"], "libfoo:amd64=1=2"),
]


@pytest.mark.parametrize("kind,words,named", PINS_BAD, ids=[k for k, _, _ in PINS_BAD])
def test_pins_line_refuses_a_word_that_is_not_a_pin(kind, words, named):
    r = run("pins_line", *words)
    assert r.returncode == 1, f"{kind}: rc {r.returncode}"
    assert r.stdout == "", f"{kind}: a refused pin must print no notice: {r.stdout!r}"
    assert "::error::pins_line:" in r.stderr, f"{kind}: {r.stderr!r}"
    assert named in r.stderr, f"{kind}: the message must name {named!r}: {r.stderr!r}"


PINS_UNPAIRED = [
    ("only amd64", ["libfoo:amd64=1-1"], "libfoo"),
    ("only arm64", ["libfoo:arm64=1-1"], "libfoo"),
    ("versions differ", ["libfoo:amd64=1-1", "libfoo:arm64=1-2"], "libfoo"),
    ("one architecture twice", ["libfoo:amd64=1-1", "libfoo:amd64=1-1"], "libfoo"),
    ("a second package unpaired",
     ["liba:amd64=1-1", "liba:arm64=1-1", "libb:amd64=2-2"], "libb"),
    ("a package named twice for one architecture",
     ["libfoo:amd64=1-1", "libfoo:arm64=1-1", "libfoo:amd64=1-1"], "libfoo"),
    ("a package named twice for arm64",
     ["libfoo:amd64=1-1", "libfoo:arm64=1-1", "libfoo:arm64=1-1"], "more than once for arm64"),
    ("a package pinned twice at two versions",
     ["libfoo:amd64=1-1", "libfoo:arm64=1-1", "libfoo:amd64=2-2", "libfoo:arm64=2-2"], "libfoo"),
    ("epochs differ", ["libfoo:amd64=1:2-3", "libfoo:arm64=2-3"], "libfoo"),
    ("arm64 newer, the defect of v0.5.260",
     ["linux-libc-dev:amd64=6.1.192-1", "linux-libc-dev:arm64=6.1.192-2"], "linux-libc-dev"),
    ("a prefix of the other version", ["libfoo:amd64=1-1", "libfoo:arm64=1-10"], "libfoo"),
    ("a package whose name is a prefix of another",
     ["liba:amd64=1", "liba-dev:arm64=1"], "liba"),
    ("the last package unpaired",
     ["liba:amd64=1", "liba:arm64=1", "libb:amd64=1", "libb:arm64=1", "libc:arm64=1"], "libc"),
]


@pytest.mark.parametrize("kind,words,named", PINS_UNPAIRED, ids=[k for k, _, _ in PINS_UNPAIRED])
def test_pins_line_refuses_pins_that_are_not_one_version_for_both(kind, words, named):
    r = run("pins_line", *words)
    assert r.returncode == 1, f"{kind}: rc {r.returncode}"
    assert r.stdout == "", f"{kind}: {r.stdout!r}"
    assert "::error::pins_line:" in r.stderr, f"{kind}: {r.stderr!r}"
    assert named in r.stderr, f"{kind}: the message must name {named!r}: {r.stderr!r}"


PINS_EDGE = [
    ("a trailing newline in a word", ["libfoo:amd64=1\n", "libfoo:arm64=1"], False),
    ("a tab in a word", ["libfoo:amd64=1\t", "libfoo:arm64=1"], False),
    ("a carriage return in a version", ["libfoo:amd64=1\r", "libfoo:arm64=1\r"], False),
    ("a one-character package, which Debian does not allow", ["a:amd64=1", "a:arm64=1"], False),
    ("a non-ASCII letter in the package", ["libfoö:amd64=1", "libfoö:arm64=1"], False),
    ("a lone double dash", ["--", "libfoo:amd64=1", "libfoo:arm64=1"], False),
    ("a version of 200 characters", ["libfoo:amd64=" + "1" * 200, "libfoo:arm64=" + "1" * 200], True),
    ("a version that is only 0", ["libfoo:amd64=0", "libfoo:arm64=0"], True),
    ("an architecture in upper case", ["libfoo:AMD64=1", "libfoo:arm64=1"], False),
    ("an architecture suffix after the name", ["libfoo:amd64x=1", "libfoo:arm64=1"], False),
    ("a version that starts with a letter", ["libfoo:amd64=a1", "libfoo:arm64=a1"], False),
    ("a dollar sign in the version", ["libfoo:amd64=$x", "libfoo:arm64=$x"], False),
]


@pytest.mark.parametrize("kind,words,ok", PINS_EDGE, ids=[k for k, _, _ in PINS_EDGE])
def test_pins_line_at_the_edges_of_a_pin(kind, words, ok):
    r = run("pins_line", *words)
    if ok:
        assert r.returncode == 0, f"{kind}: {r.stderr!r}"
        assert r.stdout == PREFIX + " ".join(words) + "\n", f"{kind}: {r.stdout!r}"
    else:
        assert r.returncode == 1, f"{kind}: rc {r.returncode}, {r.stdout!r}"
        assert r.stdout == "", f"{kind}: {r.stdout!r}"
        assert "::error::pins_line:" in r.stderr, f"{kind}: {r.stderr!r}"


def test_pins_line_of_no_pin_is_refused():
    r = run("pins_line")
    assert r.returncode == 1, r.returncode
    assert r.stdout == "", r.stdout
    assert "::error::pins_line: no pin named" in r.stderr, r.stderr


def test_pins_line_refuses_the_pins_passed_as_one_quoted_word():
    # `pins_line "$pins"` hands it one word with newlines in it; the step
    # passes $pins unquoted so that each pin is its own word.
    r = run("pins_line", "libfoo:amd64=1-1\nlibfoo:arm64=1-1\n")
    assert r.returncode == 1, r.returncode
    assert r.stdout == "", r.stdout
    assert "::error::pins_line:" in r.stderr, r.stderr


def test_pins_line_prints_exactly_one_line():
    words = [f"lib{n}:{a}=1" for n in range(30) for a in ("amd64", "arm64")]
    r = run("pins_line", *words)
    assert r.returncode == 0, r.stderr
    assert r.stdout.count("\n") == 1 and r.stdout.endswith("\n"), r.stdout


def test_pins_line_keeps_the_order_it_was_given():
    words = ["libz:arm64=1", "liba:amd64=2", "libz:amd64=1", "liba:arm64=2"]
    r = run("pins_line", *words)
    assert r.returncode == 0, r.stderr
    assert r.stdout[len(PREFIX):].split() == words, r.stdout


def test_pins_line_prints_what_multiarch_pins_computed(tmp_path):
    env = fake_madison(tmp_path, {"linux-libc-dev:amd64": MADISON_AMD64, "linux-libc-dev:arm64": MADISON_ARM64})
    pins = run("multiarch_pins", "linux-libc-dev", env=env)
    assert pins.returncode == 0, pins.stderr
    r = run("pins_line", *pins.stdout.split())
    assert r.returncode == 0, r.stderr
    assert r.stdout == PREFIX + "linux-libc-dev:amd64=6.1.192-1 linux-libc-dev:arm64=6.1.192-1\n", r.stdout


def test_pins_line_leaves_no_file_behind(tmp_path):
    env = dict(os.environ, RUNNER_TEMP=str(tmp_path), TMPDIR=str(tmp_path))
    run("pins_line", "libfoo:amd64=1", "libfoo:arm64=1", env=env)
    run("pins_line", "libfoo:amd64=1", env=env)
    assert list(tmp_path.iterdir()) == [], list(tmp_path.iterdir())


def test_pins_line_refuses_with_one_error_line():
    r = run("pins_line", "bad", "libfoo:amd64=1", "libfoo:arm64=1")
    assert r.returncode == 1, r.returncode
    assert r.stderr.count("::error::") == 1, f"one refusal line, not one per word: {r.stderr!r}"


def test_pins_line_refuses_before_it_prints_anything_for_a_late_bad_word():
    r = run("pins_line", "liba:amd64=1", "liba:arm64=1", "libb:amd64=1", "libb:arm64=1", "Bad:amd64=1")
    assert r.returncode == 1, r.returncode
    assert r.stdout == "", f"the notice is printed only for pins that all hold: {r.stdout!r}"


# --- apt_bounded --------------------------------------------------------------


def fake_apt_get(tmp_path, body, says=""):
    """An apt-get that runs `body`; `says` is text it prints first, from a file."""
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    (bindir / "says.txt").write_text(says)
    stub(bindir, "apt-get", f'cat "{bindir}/says.txt"\n' + body)
    env = path_env(bindir)
    env["RUNNER_TEMP"] = str(tmp_path)
    return env


def test_apt_bounded_passes_a_good_run_through(tmp_path):
    env = fake_apt_get(tmp_path, 'echo "apt-get $*"\nexit 0\n')
    r = run("apt_bounded", "60", "install", "-y", "cmake", env=env)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "install -y cmake" in r.stdout, r.stdout
    assert "Acquire::Retries=5" in r.stdout, r.stdout
    assert "::error::" not in r.stdout, r.stdout


def test_apt_bounded_names_a_resolution_failure(tmp_path):
    env = fake_apt_get(tmp_path, "exit 100\n", says=UNRESOLVED)
    r = run("apt_bounded", "600", "install", "-y", "libpcap-dev:arm64", env=env)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "::error::DEPENDENCY failure" in r.stdout, r.stdout
    assert "apt-get install could not resolve" in r.stdout, "the message names the apt command"
    assert "did not complete within" not in r.stdout, r.stdout
    assert "held broken packages" in r.stdout, "apt's own lines must stay in the log"


def test_apt_bounded_names_a_download_failure(tmp_path):
    env = fake_apt_get(tmp_path, "exit 100\n", says=FETCH)
    r = run("apt_bounded", "600", "install", "-y", "cmake", env=env)
    assert r.returncode == 1
    assert "::error::FETCH failure" in r.stdout and "could not download" in r.stdout, r.stdout


def test_apt_bounded_names_a_timeout(tmp_path):
    env = fake_apt_get(tmp_path, "exec sleep 30\n")
    r = run("apt_bounded", "1", "update", env=env)
    assert r.returncode == 1
    assert "did not complete within 1s" in r.stdout, r.stdout


def test_apt_bounded_names_another_failure_with_its_exit_status(tmp_path):
    env = fake_apt_get(tmp_path, "echo dpkg was interrupted\nexit 3\n")
    r = run("apt_bounded", "600", "install", "-y", "cmake", env=env)
    assert r.returncode == 1
    assert "failed with exit 3" in r.stdout, r.stdout


def test_apt_bounded_leaves_no_log_behind(tmp_path):
    env = fake_apt_get(tmp_path, "exit 100\n", says=UNRESOLVED)
    run("apt_bounded", "600", "install", "-y", "x", env=env)
    env = fake_apt_get(tmp_path, "echo ok\n")
    run("apt_bounded", "600", "install", "-y", "x", env=env)
    left = [p.name for p in tmp_path.iterdir() if p.name != "bin"]
    assert left == [], left


# --- the release workflow uses the rule ---------------------------------------


def install_step():
    text = RELEASE.read_text()
    start = text.index("      - name: Install build deps (bookworm container)\n")
    end = text.index("\n      - name: ", start + 1)
    return text[start:end]


def test_the_release_step_sources_the_rule_and_defines_no_copy():
    step = install_step()
    assert ". scripts/release-apt.sh" in step, step
    assert "apt_bounded() {" not in step, "a second copy of apt_bounded drifts from the tested one"
    assert "::error::" not in step, "the messages live in scripts/release-apt.sh"


def test_the_aarch64_install_pins_the_multiarch_packages():
    step = install_step()
    at = step.index('if [ "$TARGET" = "aarch64-unknown-linux-gnu" ]; then')
    branch = step[at:step.index("else", at)]
    assert "multiarch_pins linux-libc-dev libc6 libc6-dev" in branch, branch
    pins_at = branch.index("multiarch_pins")
    install_at = branch.index("apt_bounded 600 install")
    assert pins_at < install_at, branch
    assert "update" in branch[:pins_at], "the arm64 indexes must be read before the pins"
    assert "libpcap-dev:arm64" in branch[install_at:], branch


def test_the_other_targets_install_without_pins():
    step = install_step()
    at = step.index('if [ "$TARGET" = "aarch64-unknown-linux-gnu" ]; then')
    other = step[step.index("else", at):]
    assert "apt_bounded 600 install -y libpcap-dev libasound2-dev" in other, other
    assert "multiarch_pins" not in other, other
    assert "pins_line" not in other, other


def aarch64_branch():
    step = install_step()
    at = step.index('if [ "$TARGET" = "aarch64-unknown-linux-gnu" ]; then')
    return step[at:step.index("else", at)]


def test_the_aarch64_install_prints_its_pins_on_the_line_before_the_install():
    lines = [ln.strip() for ln in aarch64_branch().splitlines()]
    code = [ln for ln in lines if ln and not ln.startswith("#")]
    install = next(i for i, ln in enumerate(code) if ln.startswith("apt_bounded 600 install"))
    assert code[install - 1] == "pins_line $pins", (
        f"the command before the install must print the pins it applies: {code[install - 1]!r}")


def test_the_aarch64_install_prints_the_pins_after_computing_them():
    branch = aarch64_branch()
    assert branch.index('pins="$(multiarch_pins') < branch.index("pins_line $pins"), branch


def test_the_aarch64_install_applies_the_pins_it_printed():
    branch = aarch64_branch()
    install = branch[branch.index("apt_bounded 600 install"):]
    assert install.startswith("apt_bounded 600 install -y $pins "), install.splitlines()[0]
    assert branch.count("$pins") == 2, "the pins are printed once and installed once"
