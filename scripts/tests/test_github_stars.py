"""scripts/github-stars.py: the homepage's GitHub star count."""

import json
import subprocess
import sys

import pytest

from conftest import SCRIPTS, load

stars = load("github-stars")
SCRIPT = SCRIPTS / "github-stars.py"


def repo(count, name="NormB/sipnab"):
    return json.dumps({"full_name": name, "stargazers_count": count})


def test_reads_the_star_count_of_the_named_repository():
    assert stars.count(repo(42), "NormB/sipnab") == 42


def test_zero_is_a_count():
    assert stars.count(repo(0), "NormB/sipnab") == 0


@pytest.mark.parametrize("body", [
    repo("42"),                       # a string, not a number
    repo(-1),                         # negative
    repo(4.5),                        # not whole
    repo(True),                       # bool is an int subclass in Python
    json.dumps({"full_name": "NormB/sipnab"}),  # field missing
    "not json",
    json.dumps([]),
])
def test_refuses_anything_but_a_whole_non_negative_count(body):
    with pytest.raises(stars.StarsError):
        stars.count(body, "NormB/sipnab")


def test_refuses_another_repositorys_answer():
    with pytest.raises(stars.StarsError):
        stars.count(repo(42, "someone/else"), "NormB/sipnab")


def test_repository_names_compare_case_insensitively():
    # GitHub's own names are case-insensitive: normb/sipnab is the same repository.
    assert stars.count(repo(7, "normb/sipnab"), "NormB/sipnab") == 7


def run(tmp_path, body, *extra):
    src = tmp_path / "repo.json"
    src.write_text(body)
    out = tmp_path / "data" / "github.toml"
    r = subprocess.run([sys.executable, "-I", str(SCRIPT), str(src), "--repo", "NormB/sipnab",
                        "--write", str(out), *extra], capture_output=True, text=True)
    return r, out


def test_writes_the_toml_the_template_reads(tmp_path):
    r, out = run(tmp_path, repo(123))
    assert r.returncode == 0, r.stderr
    assert "stars = 123\n" in out.read_text()
    assert r.stdout.strip() == "123"


def test_a_refused_answer_writes_nothing_and_exits_1(tmp_path):
    r, out = run(tmp_path, repo("lots"))
    assert r.returncode == 1
    assert not out.exists()
    assert "github-stars:" in r.stderr
