"""fetch-vcon-datasets.py: the public vCon datasets, each at a pinned commit.

The datasets are third-party repositories, so the fetcher's whole job is to
hand the corpus test exactly the bytes a pin names and nothing else: it runs
git and only git, refuses a commit other than the pinned one, and refuses a
cache that has been edited since it was fetched.

The network is not reachable from a test, so each "remote" here is a local
repository built in a temporary directory and named by a `file://` URL.
"""

import os
import pathlib
import re
import subprocess
import sys

import pytest

from conftest import load

REPO = pathlib.Path(__file__).resolve().parent.parent.parent
SCRIPT = REPO / "scripts/fetch-vcon-datasets.py"
PINS = REPO / "tests/fixtures/vcon-datasets/PINS.tsv"

fetch = load("fetch-vcon-datasets")


def _env():
    return {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}


def _git(*args, cwd):
    out = subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid",
         "-c", "commit.gpgsign=false", *args],
        cwd=cwd, env=_env(), check=True, capture_output=True, text=True,
    )
    return out.stdout.strip()


def _remote(tmp_path, commits):
    """A repository with one commit per entry of `commits` ({path: text}).

    Returns (file:// URL, [sha of each commit, oldest first]).
    """
    src = tmp_path / "remote"
    src.mkdir()
    _git("init", "-q", cwd=src)
    shas = []
    for files in commits:
        for rel, text in files.items():
            path = src / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
            _git("add", rel, cwd=src)
        _git("commit", "-q", "-m", "c", cwd=src)
        shas.append(_git("rev-parse", "HEAD", cwd=src))
    return src.as_uri(), shas


def _pins(tmp_path, rows):
    path = tmp_path / "PINS.tsv"
    lines = ["# name\turl\tcommit\tlicense"]
    lines += ["\t".join(r) for r in rows]
    path.write_text("\n".join(lines) + "\n")
    return path


def _run(*args, env_extra=None):
    env = _env()
    env.pop("SIPNAB_VCON_DATASETS", None)
    env.update(env_extra or {})
    return subprocess.run(
        [sys.executable, "-I", str(SCRIPT), *args],
        env=env, capture_output=True, text=True, timeout=120,
    )


def test_the_committed_pins_name_five_datasets_at_full_commits():
    pins = fetch.read_pins(PINS)
    assert [p.name for p in pins] == [
        "vcon-supreme-court-arguments",
        "ietf-meeting-vcons",
        "vcon-dataset-city-of-newport-ri",
        "fake-vcons",
        "tadhack-2025",
    ]
    for pin in pins:
        assert re.fullmatch(r"[0-9a-f]{40}", pin.commit), pin
        assert pin.url == f"https://github.com/vcon-dev/{pin.name}", pin
        assert pin.license in {"MIT", "BSD-3-Clause"}, pin


def test_a_pin_is_checked_out_at_exactly_its_commit(tmp_path):
    url, (first, second) = _remote(tmp_path, [{"a.vcon.json": "{}"},
                                              {"b.vcon.json": "{}"}])
    dest = tmp_path / "cache"
    pin = fetch.Pin("ds", url, first, "MIT")
    fetch.fetch_one(pin, dest)
    tree = dest / "ds"
    assert _git("rev-parse", "HEAD", cwd=tree) == first
    assert (tree / "a.vcon.json").exists()
    # The later commit's file is NOT there: the pin, not the branch tip.
    assert not (tree / "b.vcon.json").exists()


def test_a_cached_checkout_at_another_commit_is_moved_to_the_pin(tmp_path):
    url, (first, second) = _remote(tmp_path, [{"a.vcon.json": "{}"},
                                              {"b.vcon.json": "{}"}])
    dest = tmp_path / "cache"
    fetch.fetch_one(fetch.Pin("ds", url, first, "MIT"), dest)
    fetch.fetch_one(fetch.Pin("ds", url, second, "MIT"), dest)
    assert _git("rev-parse", "HEAD", cwd=dest / "ds") == second


def test_a_commit_the_remote_does_not_hold_is_refused(tmp_path):
    url, _ = _remote(tmp_path, [{"a.vcon.json": "{}"}])
    with pytest.raises(fetch.FetchError):
        fetch.fetch_one(fetch.Pin("ds", url, "0" * 40, "MIT"), tmp_path / "c")


def test_an_edited_cache_is_refused(tmp_path):
    url, (first,) = _remote(tmp_path, [{"a.vcon.json": "{}"}])
    dest = tmp_path / "cache"
    pin = fetch.Pin("ds", url, first, "MIT")
    fetch.fetch_one(pin, dest)
    (dest / "ds" / "a.vcon.json").write_text('{"edited": true}')
    with pytest.raises(fetch.FetchError, match="edited|modified|clean"):
        fetch.verify(pin, dest)


def test_the_hooks_git_environment_does_not_reach_the_fetch(tmp_path):
    # A pre-commit hook exports GIT_DIR; inherited, every git call here would
    # act on the hook's repository instead of the cache.
    url, (first,) = _remote(tmp_path, [{"a.vcon.json": "{}"}])
    decoy = tmp_path / "decoy"
    decoy.mkdir()
    _git("init", "-q", cwd=decoy)
    config_before = (decoy / ".git" / "config").read_text()
    os.environ["GIT_DIR"] = str(decoy / ".git")
    try:
        fetch.fetch_one(fetch.Pin("ds", url, first, "MIT"), tmp_path / "c")
    finally:
        del os.environ["GIT_DIR"]
    assert (decoy / ".git" / "config").read_text() == config_before
    assert _git("rev-parse", "HEAD", cwd=tmp_path / "c" / "ds") == first


def test_a_malformed_pin_line_is_refused(tmp_path):
    path = tmp_path / "PINS.tsv"
    path.write_text("ds\thttps://example.invalid/x\tnot-a-sha\tMIT\n")
    with pytest.raises(fetch.FetchError, match="commit"):
        fetch.read_pins(path)


def test_without_a_destination_the_script_exits_2_naming_the_variable():
    run = _run()
    assert run.returncode == 2, run.stderr
    assert "SIPNAB_VCON_DATASETS" in run.stderr


def test_the_script_fetches_every_pin_and_counts_containers(tmp_path):
    url, (first,) = _remote(tmp_path, [{"x/a.vcon.json": "{}",
                                        "x/b.vcon.json": "{}",
                                        "README.md": "r"}])
    pins = _pins(tmp_path, [("ds", url, first, "MIT")])
    dest = tmp_path / "cache"
    run = _run("--pins", str(pins), env_extra={"SIPNAB_VCON_DATASETS": str(dest)})
    assert run.returncode == 0, run.stderr
    assert re.search(r"ds\s+" + first[:12] + r".*\b2\b", run.stdout), run.stdout


def test_the_script_exits_1_when_a_pin_cannot_be_fetched(tmp_path):
    url, _ = _remote(tmp_path, [{"a.vcon.json": "{}"}])
    pins = _pins(tmp_path, [("ds", url, "1" * 40, "MIT")])
    run = _run("--pins", str(pins), str(tmp_path / "cache"))
    assert run.returncode == 1, run.stdout + run.stderr
    assert "ds" in run.stderr
