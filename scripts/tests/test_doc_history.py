"""scripts/doc-history.py: the release each docs page last changed in."""

import subprocess
import sys
import tomllib

import pytest

from conftest import SCRIPTS, load

history = load("doc-history")
SCRIPT = SCRIPTS / "doc-history.py"


def git(root, *args, date=None):
    env = {"PATH": "/usr/bin:/bin", "HOME": str(root),
           "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}
    if date:
        env["GIT_AUTHOR_DATE"] = env["GIT_COMMITTER_DATE"] = f"{date}T12:00:00+00:00"
    return subprocess.run(["git", "-C", str(root), *args], env=env, check=True,
                          capture_output=True, text=True).stdout.strip()


def commit(root, rel, text, date):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    git(root, "add", rel)
    git(root, "commit", "-q", "-m", f"change {rel}", date=date)


GENERATED = '+++\ntitle = "CLI"\n\n[extra]\nsource = "docs/cli.md"\n+++\n\nbody\n'
HAND = '+++\ntitle = "Build"\n+++\n\nbody\n'


@pytest.fixture
def fixture_repo(tmp_path):
    """A repository with two releases and one unreleased change.

    docs/cli.md changes before v0.1.0 and again before v0.2.0, so its last
    change is in v0.2.0 alone. docs/old.md changes before v0.1.0 only, so both
    tags contain it and the earlier one is where it first shipped. The
    hand-written page changes after v0.2.0 and is in no release.
    """
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-q", "-b", "main")
    commit(root, "docs/old.md", "old\n", "2026-01-01")
    commit(root, "docs/cli.md", "one\n", "2026-01-02")
    git(root, "tag", "v0.1.0")
    commit(root, "docs/cli.md", "two\n", "2026-02-03")
    git(root, "tag", "v0.2.0")
    commit(root, "website/content/docs/cli.md", GENERATED, "2026-02-04")
    commit(root, "website/content/docs/build.md", HAND, "2026-03-05")
    return root


def test_the_earliest_release_containing_the_change_wins(fixture_repo):
    assert history.last_change(fixture_repo, "docs/old.md") == {
        "date": "2026-01-01", "release": "v0.1.0"}


def test_a_later_change_reads_the_release_it_first_shipped_in(fixture_repo):
    assert history.last_change(fixture_repo, "docs/cli.md") == {
        "date": "2026-02-03", "release": "v0.2.0"}


def test_a_change_in_no_release_names_the_latest_release_before_it(fixture_repo):
    assert history.last_change(fixture_repo, "website/content/docs/build.md") == {
        "date": "2026-03-05", "after": "v0.2.0"}


def test_only_release_tags_count(fixture_repo):
    # A pre-release or any other tag is not a release of the page.
    git(fixture_repo, "tag", "v0.3.0-rc1")
    git(fixture_repo, "tag", "docs-snapshot")
    assert history.last_change(fixture_repo, "website/content/docs/build.md") == {
        "date": "2026-03-05", "after": "v0.2.0"}


def test_a_path_with_no_commit_is_refused(fixture_repo):
    with pytest.raises(history.HistoryError):
        history.last_change(fixture_repo, "docs/missing.md")


def test_a_generated_page_reads_its_source_and_a_hand_written_one_itself(fixture_repo):
    content = fixture_repo / "website/content"
    assert history.page_sources(content) == {
        "docs/cli.md", "website/content/docs/build.md"}


def test_writes_the_toml_the_template_reads(fixture_repo, tmp_path):
    out = tmp_path / "data" / "doc-history.toml"
    r = subprocess.run([sys.executable, "-I", str(SCRIPT), "--repo", str(fixture_repo),
                        "--write", str(out)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    doc = tomllib.loads(out.read_text())
    assert doc == {"pages": {
        "docs/cli.md": {"date": "2026-02-03", "release": "v0.2.0"},
        "website/content/docs/build.md": {"date": "2026-03-05", "after": "v0.2.0"},
    }}
