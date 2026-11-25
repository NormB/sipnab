# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""The site, wiki and notices generators parse their command line.

On 2026-11-25 `scripts/build-site-pages.py --help` wrote 88 pages into a new
directory named `--help`: the script read sys.argv[1] as its output
directory, whatever it was. build-site-internals.py, build-wiki.py and
build-third-party-notices.py read sys.argv the same way. Each now parses its
arguments with argparse: --help prints usage and writes nothing, an unknown
option or an extra path is exit 2, and the positional paths every caller on
origin/main passes keep their meaning:

* build-site-pages.py [PAGES_DIR [STATIC_DIR]]: tests/dev_docs_drift_test.rs
  and tests/docs_drift_test.rs pass two, test_client_examples.py one, the
  hooks and scripts none.
* build-site-internals.py [OUTPUT_DIR]: tests/dev_docs_drift_test.rs passes one.
* build-wiki.py [OUTPUT_DIR]: wiki-sync.yml and tests/dev_docs_drift_test.rs
  pass one.
* build-third-party-notices.py [OUT]: tests/docs_drift_test.rs passes one.
"""

import os
import pathlib
import sys

import pytest
from conftest import load

PAGES = load("build-site-pages")
INTERNALS = load("build-site-internals")
WIKI = load("build-wiki")
NOTICES = load("build-third-party-notices")

# (module, script name, how many positional paths it takes)
GENERATORS = [
    pytest.param(PAGES, "build-site-pages.py", 2, id="site-pages"),
    pytest.param(INTERNALS, "build-site-internals.py", 1, id="site-internals"),
    pytest.param(WIKI, "build-wiki.py", 1, id="wiki"),
    pytest.param(NOTICES, "build-third-party-notices.py", 1, id="notices"),
]
# The three that run in about a second and write only under their arguments.
WRITERS = GENERATORS[:3]


@pytest.fixture
def cwd(tmp_path, monkeypatch):
    """An empty current directory, and a notices generator that must not
    reach cargo: a run that got past argument parsing would call it."""
    work = tmp_path / "cwd"
    work.mkdir()
    monkeypatch.chdir(work)

    def no_cargo():
        raise AssertionError("cargo metadata ran: the arguments were not refused first")

    monkeypatch.setattr(NOTICES, "cargo_metadata", no_cargo)
    return work


def run(mod, monkeypatch, *args):
    """mod.main() as the script runs it, with sys.argv set; the exit code."""
    monkeypatch.setattr(sys, "argv", [mod.__name__, *args])
    try:
        return mod.main()
    except SystemExit as stop:
        return stop.code if isinstance(stop.code, int) else 1


# ── SUCCESS ────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("mod, name, count", GENERATORS)
def test_success_help_exits_0_with_usage(mod, name, count, cwd, monkeypatch, capsys):
    assert run(mod, monkeypatch, "--help") == 0
    assert "usage:" in capsys.readouterr().out


@pytest.mark.parametrize("mod, name, count", GENERATORS)
def test_success_short_help_exits_0(mod, name, count, cwd, monkeypatch, capsys):
    assert run(mod, monkeypatch, "-h") == 0
    assert "usage:" in capsys.readouterr().out


@pytest.mark.parametrize("mod, name, count", GENERATORS)
def test_success_the_usage_names_the_script(mod, name, count, cwd, monkeypatch, capsys):
    run(mod, monkeypatch, "--help")
    assert name in capsys.readouterr().out


@pytest.mark.parametrize("mod, name, count", GENERATORS)
def test_success_no_argument_means_every_default(mod, name, count):
    args = mod.parse_args([])
    assert all(value is None for value in vars(args).values()) and len(vars(args)) == count


@pytest.mark.parametrize("mod, name, count", WRITERS)
def test_success_one_path_is_the_output_directory(mod, name, count, cwd, monkeypatch):
    out = cwd / "out"
    static = cwd / "static"
    extra = [str(static)] if count == 2 else []
    assert run(mod, monkeypatch, str(out), *extra) == 0
    assert list(out.glob("*.md")), f"{name} wrote no page into {out}"


def test_success_the_second_path_of_site_pages_takes_the_llms_files(cwd, monkeypatch):
    assert run(PAGES, monkeypatch, str(cwd / "pages"), str(cwd / "static")) == 0
    assert (cwd / "static" / "llms.txt").is_file() and (cwd / "static" / "llms-full.txt").is_file()


def test_success_the_paths_are_read_in_order():
    args = PAGES.parse_args(["p", "s"])
    assert (args.pages_dir, args.static_dir) == (pathlib.Path("p"), pathlib.Path("s"))


# ── FAILURE ────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("mod, name, count", GENERATORS)
def test_failure_help_writes_nothing(mod, name, count, cwd, monkeypatch):
    run(mod, monkeypatch, "--help")
    assert list(cwd.iterdir()) == [], f"{name} --help wrote {list(cwd.iterdir())}"


@pytest.mark.parametrize("mod, name, count", GENERATORS)
def test_failure_an_unknown_option_is_exit_2(mod, name, count, cwd, monkeypatch, capsys):
    assert run(mod, monkeypatch, "--bogus") == 2
    assert "--bogus" in capsys.readouterr().err


@pytest.mark.parametrize("mod, name, count", GENERATORS)
def test_failure_an_unknown_option_writes_nothing(mod, name, count, cwd, monkeypatch):
    run(mod, monkeypatch, "--bogus")
    assert list(cwd.iterdir()) == []


@pytest.mark.parametrize("mod, name, count", GENERATORS)
def test_failure_one_path_too_many_is_exit_2(mod, name, count, cwd, monkeypatch):
    assert run(mod, monkeypatch, *[f"p{i}" for i in range(count + 1)]) == 2
    assert list(cwd.iterdir()) == []


@pytest.mark.parametrize("mod, name, count", GENERATORS)
def test_failure_an_unknown_option_after_a_path_is_exit_2(mod, name, count, cwd, monkeypatch):
    assert run(mod, monkeypatch, "out", "--bogus") == 2
    assert list(cwd.iterdir()) == []


# ── EDGE ───────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("mod, name, count", GENERATORS)
def test_edge_a_path_that_starts_with_a_dash_needs_the_double_dash(mod, name, count):
    first = next(iter(vars(mod.parse_args(["--", "-out"])).values()))
    assert first == pathlib.Path("-out")


@pytest.mark.parametrize("mod, name, count", GENERATORS)
def test_edge_one_path_leaves_the_others_at_their_default(mod, name, count):
    values = list(vars(mod.parse_args(["out"])).values())
    assert values[0] == pathlib.Path("out") and all(v is None for v in values[1:])


@pytest.mark.parametrize("mod, name, count", GENERATORS)
def test_edge_main_takes_its_arguments_as_a_list(mod, name, count, cwd, monkeypatch):
    monkeypatch.setattr(sys, "argv", [mod.__name__, "--bogus"])
    with pytest.raises(SystemExit) as stop:
        mod.main(["--help"])
    assert stop.value.code == 0


@pytest.mark.parametrize("mod, name, count", GENERATORS)
def test_edge_an_empty_list_is_no_argument_not_the_process_arguments(mod, name, count, monkeypatch):
    seen = []

    class Stop(Exception):
        pass

    def capture(argv):
        seen.append(argv)
        raise Stop

    monkeypatch.setattr(sys, "argv", [mod.__name__, "--bogus"])
    monkeypatch.setattr(mod, "parse_args", capture)
    with pytest.raises(Stop):
        mod.main([])
    assert seen == [[]]


def test_edge_every_script_still_ends_in_its_main():
    for path in ("build-site-pages", "build-site-internals", "build-wiki", "build-third-party-notices"):
        text = (pathlib.Path(PAGES.__file__).parent / f"{path}.py").read_text(encoding="utf-8")
        assert "raise SystemExit(main())" in text and "sys.argv[" not in text, path


def test_edge_no_generator_reads_a_positional_argv_slot():
    # The cause, by name: a fixed sys.argv index read as a path.
    for mod in (PAGES, INTERNALS, WIKI, NOTICES):
        source = pathlib.Path(mod.__file__).read_text(encoding="utf-8")
        assert "sys.argv[1]" not in source and "sys.argv[2]" not in source, mod.__file__


def test_edge_the_environment_is_not_an_argument(cwd, monkeypatch):
    monkeypatch.setenv("OUTPUT_DIR", "--help")
    assert PAGES.parse_args([]).pages_dir is None
    assert os.environ["OUTPUT_DIR"] == "--help"
