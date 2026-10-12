"""scripts/flag-since.py: the first release whose command line accepted a flag."""

import subprocess
import sys

import pytest

from conftest import SCRIPTS, load

since = load("flag-since")
SCRIPT = SCRIPTS / "flag-since.py"

CLEAN_ENV = {"PATH": "/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM": "1",
             "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
             "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}


def git(root, *args):
    env = dict(CLEAN_ENV, HOME=str(root))
    return subprocess.run(["git", "-C", str(root), *args], env=env, check=True,
                          capture_output=True, text=True).stdout.strip()


def cli(*fields):
    """A src/cli.rs whose Cli struct declares `fields`."""
    return "#[derive(Parser)]\npub struct Cli {\n" + "\n".join(fields) + "\n}\n"


def field(attr, name, ty="bool"):
    return f"    /// Doc.\n    #[arg({attr})]\n    pub {name}: {ty},\n"


DEVICE = field('short = \'d\', long = "device"', "device", "Option<String>")
DRY_RUN = field("long", "dry_run")
NEW = field('long = "new-name", alias = "old-name"', "new_name")
OLD = field('long = "old-name"', "old_name")
BPF = field('trailing_var_arg = true, value_name = "BPF_FILTER"', "bpf_filter",
            "Vec<String>")


def commit(root, text, message="change"):
    path = root / "src" / "cli.rs"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    git(root, "add", "src/cli.rs")
    git(root, "commit", "-q", "--allow-empty", "-m", message)


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-q", "-b", "main")
    return root


# -- parsing src/cli.rs ------------------------------------------------------

def test_long_with_a_value_names_the_flag():
    assert since.declared_args(cli(DEVICE)) == [("device",)]


def test_a_bare_long_takes_the_kebab_cased_field_name():
    assert since.declared_args(cli(DRY_RUN)) == [("dry-run",)]


def test_a_raw_identifier_field_drops_its_prefix():
    assert since.declared_args(cli(field("long", "r#type"))) == [("type",)]


def test_aliases_belong_to_the_flag_they_alias():
    src = cli(NEW, field('long = "x", visible_alias = "y", aliases = ["z", "w"]', "x"))
    assert since.declared_args(src) == [("new-name", "old-name"), ("x", "y", "z", "w")]


def test_a_positional_argument_is_named_by_its_value_name():
    assert since.declared_args(cli(BPF)) == [("<BPF_FILTER>",)]


def test_a_short_only_argument_is_not_a_flag():
    assert since.declared_args(cli(field("short = 'r', hide = true", "r"))) == []


def test_comments_and_strings_do_not_declare_flags():
    attr = ('\n        // long = "commented", alias = "ghost"\n'
            '        long = "real", help = "long = \\"fake\\", alias = \\"ghost\\" (long)"\n    ')
    src = cli(field(attr, "real"), '    // #[arg(long = "nope")]\n    // pub nope: bool,')
    assert since.declared_args(src) == [("real",)]


def test_attributes_between_arg_and_field_are_skipped():
    src = cli('    #[arg(long)]\n    #[cfg(feature = "plugins")]\n'
              '    #[serde(rename = "x")]\n    pub plugin_dir: bool,')
    assert since.declared_args(src) == [("plugin-dir",)]


# -- dating flags against release tags ---------------------------------------

def test_the_oldest_release_tag_wins(repo):
    commit(repo, cli(DEVICE))
    git(repo, "tag", "v0.1.0")
    commit(repo, cli(DEVICE, DRY_RUN))
    git(repo, "tag", "v0.2.0")
    git(repo, "tag", "v0.10.0")
    assert since.flag_since(repo) == {"device": "0.1.0", "dry-run": "0.2.0"}


def test_tags_are_ordered_by_version_not_by_name(repo):
    commit(repo, cli())
    git(repo, "tag", "v0.10.0")
    commit(repo, cli(DEVICE))
    git(repo, "tag", "v0.9.0")
    # v0.9.0 is the older release although it sorts after v0.10.0 as text,
    # and it was tagged second.
    assert since.flag_since(repo) == {"device": "0.9.0"}


def test_an_alias_counts_as_the_flag(repo):
    commit(repo, cli(OLD))
    git(repo, "tag", "v0.1.0")
    commit(repo, cli(NEW))
    git(repo, "tag", "v0.2.0")
    assert since.flag_since(repo) == {"new-name": "0.1.0", "old-name": "0.1.0"}


def test_a_removed_then_restored_flag_keeps_its_first_release(repo):
    commit(repo, cli(DEVICE, DRY_RUN))
    git(repo, "tag", "v0.1.0")
    commit(repo, cli(DEVICE))
    git(repo, "tag", "v0.2.0")
    commit(repo, cli(DEVICE, DRY_RUN))
    git(repo, "tag", "v0.3.0")
    assert since.flag_since(repo)["dry-run"] == "0.1.0"


def test_pre_release_tags_are_not_releases(repo):
    commit(repo, cli(DEVICE))
    git(repo, "tag", "v0.1.0-alpha")
    git(repo, "tag", "v0.1.0-rc1")
    git(repo, "tag", "snapshot")
    commit(repo, cli(DEVICE, DRY_RUN))
    git(repo, "tag", "v0.2.0")
    assert since.flag_since(repo) == {"device": "0.2.0", "dry-run": "0.2.0"}


def test_a_version_bumped_but_never_tagged_falls_to_the_next_tag(repo):
    commit(repo, cli(DEVICE))
    git(repo, "tag", "v0.1.0")
    commit(repo, cli(DEVICE, DRY_RUN), "Release 0.1.1")  # never tagged
    commit(repo, cli(DEVICE, DRY_RUN), "Release 0.1.2")
    git(repo, "tag", "v0.1.2")
    assert since.flag_since(repo)["dry-run"] == "0.1.2"


def test_a_flag_in_no_release_tag_reads_unreleased(repo):
    commit(repo, cli(DEVICE))
    git(repo, "tag", "v0.1.0")
    commit(repo, cli(DEVICE, DRY_RUN))
    assert since.flag_since(repo)["dry-run"] == "Unreleased"


def test_the_working_tree_source_is_the_current_command_line(repo):
    commit(repo, cli(DEVICE))
    git(repo, "tag", "v0.1.0")
    (repo / "src/cli.rs").write_text(cli(DEVICE, DRY_RUN))  # not committed
    assert since.flag_since(repo) == {"device": "0.1.0", "dry-run": "Unreleased"}


def test_a_release_without_the_source_file_declares_nothing(repo):
    (repo / "README").write_text("x\n")
    git(repo, "add", "README")
    git(repo, "commit", "-q", "-m", "first")
    git(repo, "tag", "v0.1.0")
    commit(repo, cli(DEVICE))
    git(repo, "tag", "v0.2.0")
    assert since.flag_since(repo) == {"device": "0.2.0"}


def test_a_clone_without_tags_is_refused(repo):
    commit(repo, cli(DEVICE))
    with pytest.raises(since.FlagSinceError, match="no v\\* tags in this clone; fetch tags"):
        since.flag_since(repo)


# -- the table in docs/cli-reference.md --------------------------------------

DOC_OLD = """# CLI reference

## Capture

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `-d`, `--device` | `<IFACE\\|ANY>` | -- | Interface. Config: `[capture] device` |
| `--dry-run` | -- | off | Do nothing |
| `<BPF_FILTER>...` | positional | -- | Filter |

| Code | Meaning |
|------|---------|
| `0` | ok |
"""

DOC_NEW = """# CLI reference

## Capture

| Flag | Value | Default | Since | Description |
|------|-------|---------|-------|-------------|
| `-d`, `--device` | `<IFACE\\|ANY>` | -- | 0.1.0 | Interface. Config: `[capture] device` |
| `--dry-run` | -- | off | Unreleased | Do nothing |
| `<BPF_FILTER>...` | positional | -- | 0.1.0 | Filter |

| Code | Meaning |
|------|---------|
| `0` | ok |
"""

SINCE = {"device": "0.1.0", "dry-run": "Unreleased", "<BPF_FILTER>": "0.1.0"}


def test_the_since_column_goes_before_the_description():
    assert since.rewrite(DOC_OLD, SINCE) == (DOC_NEW, [])


def test_a_table_that_has_the_column_is_updated_in_place():
    stale = DOC_NEW.replace("| 0.1.0 | Interface", "| 9.9.9 | Interface")
    assert since.rewrite(stale, SINCE) == (DOC_NEW, [])
    assert since.rewrite(DOC_NEW, SINCE) == (DOC_NEW, [])


def test_a_row_missing_its_cell_in_a_table_with_the_column_keeps_its_description():
    short = DOC_NEW.replace("| off | Unreleased | Do nothing |", "| off | Do nothing |")
    assert since.rewrite(short, SINCE) == (DOC_NEW, [])


def test_a_row_with_the_wrong_number_of_cells_is_an_error():
    doc = DOC_NEW.replace("| -- | off | Unreleased | Do nothing |", "| -- | Do nothing |")
    _, errors = since.rewrite(doc, SINCE)
    assert errors == ["`--dry-run`: the row has 3 cells; a flag row has 4 without Since or 5 with it"]


def test_an_alias_in_the_flag_cell_names_the_same_flag():
    doc = DOC_OLD.replace("`--dry-run` |", "`--dry-run` (`--noop`) |")
    out, errors = since.rewrite(doc, dict(SINCE, noop="Unreleased"))
    assert errors == []
    assert "| `--dry-run` (`--noop`) | -- | off | Unreleased | Do nothing |" in out


def test_a_row_naming_no_declared_flag_is_an_error():
    doc = DOC_OLD.replace("`--dry-run`", "`--gone`")
    _, errors = since.rewrite(doc, SINCE)
    assert errors == ["`--gone`: the row names no flag src/cli.rs declares"]


def test_a_row_naming_a_declared_and_an_undeclared_flag_is_an_error():
    doc = DOC_OLD.replace("`--dry-run`", "`--dry-run`, `--gone`")
    _, errors = since.rewrite(doc, SINCE)
    assert errors == ["`--dry-run`, `--gone`: the row names no flag src/cli.rs declares"]


def test_a_row_naming_two_flags_of_different_releases_is_an_error():
    doc = DOC_OLD.replace("`--dry-run`", "`--dry-run`, `--device`")
    _, errors = since.rewrite(doc, SINCE)
    assert errors == ["`--dry-run`, `--device`: the row names flags of different releases"]


def tagged_repo(repo, doc):
    commit(repo, cli(DEVICE, BPF))
    git(repo, "tag", "v0.1.0")
    commit(repo, cli(DEVICE, BPF, DRY_RUN))
    (repo / "docs").mkdir()
    (repo / "docs/cli-reference.md").write_text(doc)
    git(repo, "add", "docs")
    git(repo, "commit", "-q", "-m", "docs")
    return repo


def run(repo, *args):
    return subprocess.run([sys.executable, "-I", str(SCRIPT), "--repo", str(repo), *args],
                          capture_output=True, text=True, env=dict(CLEAN_ENV, HOME=str(repo)))


def test_check_reports_a_hand_edited_wrong_cell(repo):
    tagged_repo(repo, DOC_NEW.replace("| 0.1.0 | Interface", "| 0.0.9 | Interface"))
    r = run(repo, "--check")
    assert r.returncode == 1
    assert "--device" in r.stdout and "0.0.9" in r.stdout and "0.1.0" in r.stdout
    assert "scripts/flag-since.py --write" in r.stdout


def test_check_passes_on_a_correct_table_and_writes_nothing(repo):
    tagged_repo(repo, DOC_NEW)
    r = run(repo, "--check")
    assert r.returncode == 0, r.stdout + r.stderr
    assert git(repo, "status", "--porcelain") == ""


def test_write_fixes_the_table_and_check_then_agrees(repo):
    tagged_repo(repo, DOC_OLD)
    assert run(repo, "--check").returncode == 1
    r = run(repo, "--write")
    assert r.returncode == 0, r.stdout + r.stderr
    assert (repo / "docs/cli-reference.md").read_text() == DOC_NEW
    assert run(repo, "--check").returncode == 0


def test_the_script_refuses_a_clone_without_tags(repo):
    tagged_repo(repo, DOC_NEW)
    git(repo, "tag", "-d", "v0.1.0")
    r = run(repo, "--check")
    assert r.returncode == 2
    assert "no v* tags in this clone; fetch tags" in r.stderr
