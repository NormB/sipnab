# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""The start-of-run parts records of scripts/gate-cache.py, and the refusal line they feed.

`keys` records, for each step, a digest of every part of the step's key, in
<stamp dir>/parts/. When `pass` finds that a step's key changed while the step
ran, it compares that record with the parts at the end and names the parts that
differ ("its inputs changed while it ran (changed: tags)"). A record holds
digests only, never a value: the environment part admits CARGO_* variables,
and a registry token must never be written to disk.

The cases fall in three groups, in this order: success (the line names what
changed), failure (a record that is absent, damaged or for another key is no
record, and no value leaks), edge (pruning, the older layout, odd values).
"""

import json
import os
import pathlib
import re
import subprocess
import time

import pytest
from conftest import load
from test_gate_cache import snap

gc = load("gate-cache")

KEY_A = "a" * 64
KEY_B = "b" * 64


def record_of(snapshot, step="tests", hook="pre-commit"):
    return gc.parts_record(gc.step_parts(hook, step, snapshot))


def _git(cwd, *args):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    return subprocess.run(["git", *args], cwd=cwd, env=env, check=True, capture_output=True, text=True).stdout


@pytest.fixture
def tree(tmp_path, monkeypatch):
    """A repository with a hook file, entered as the working directory, with
    fixed tool versions so a run does not start rustc or nextest."""
    root = tmp_path / "r"
    root.mkdir()
    _git(root, "init", "-q", ".")
    _git(root, "config", "user.email", "t@example.com")
    _git(root, "config", "user.name", "t")
    (root / ".gitignore").write_text("target/\n*.local.md\n", encoding="utf-8")
    (root / "src").mkdir()
    (root / "src/lib.rs").write_text("pub fn a() {}\n", encoding="utf-8")
    (root / "docs").mkdir()
    (root / "docs/a.md").write_text("A\n", encoding="utf-8")
    (root / ".githooks").mkdir()
    (root / ".githooks/pre-commit").write_text("#!/bin/sh\n", encoding="utf-8")
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "base")
    monkeypatch.chdir(root)
    monkeypatch.setattr(gc, "tool_versions", lambda _root, _env: {"rustc": "rustc 1.90.0", "nextest": "0.9"})
    for name in list(os.environ):
        if name.startswith(("RUST", "CARGO", "NEXTEST_", "SIPNAB_")):
            monkeypatch.delenv(name)
    return root


def hook_file(root):
    return str(root / ".githooks/pre-commit")


def run_keys(root, capsys, hook="pre-commit"):
    assert gc.main(["keys", hook, "--hook-file", hook_file(root)]) == 0, "keys must succeed"
    out = capsys.readouterr().out
    return {m.group(1): m.group(2) for m in re.finditer(r"^(\S+) ([0-9a-f]{64})$", out, re.M)}


def run_pass(root, capsys, step, key, hook="pre-commit"):
    assert gc.main(["pass", hook, step, key, "--hook-file", hook_file(root)]) == 0, "pass must succeed"
    return capsys.readouterr().out


def parts_dir(root):
    return root / ".git" / gc.STAMP_DIR / gc.PARTS_DIR


def stamp_names(root):
    d = root / ".git" / gc.STAMP_DIR
    return sorted(p.name.split(".")[1] for p in d.glob("*.json")) if d.is_dir() else []


# ── Success: the line names what changed ─────────────────────────────────────


def test_a_changed_tag_set_is_named_tags():
    assert gc.changed_parts(record_of(snap()), record_of(snap(tags="e" * 64))) == ["tags"], "only tags differ"


def test_an_edited_file_is_named_files():
    files = {**snap().files, "src/lib.rs": "9" * 40}
    assert gc.changed_parts(record_of(snap()), record_of(snap(files=files))) == ["files"], "only files differ"


def test_several_changed_parts_are_named_in_sorted_order():
    after = record_of(snap(tags="e" * 64, head="f" * 40, index_tree="0" * 40))
    assert gc.changed_parts(record_of(snap()), after) == ["head", "index_tree", "tags"], "sorted names"


def test_a_changed_environment_variable_is_named_with_its_part():
    after = record_of(snap(env={"RUSTFLAGS": "-C debuginfo=0"}))
    assert gc.changed_parts(record_of(snap()), after) == ["env.RUSTFLAGS"], "the variable is named"


def test_a_changed_tool_is_named_with_its_part():
    tools = {**snap().tools, "rustc": "rustc 1.91.0\nhost: aarch64"}
    assert gc.changed_parts(record_of(snap()), record_of(snap(tools=tools))) == ["tools.rustc"], "the tool is named"


def test_an_added_environment_variable_is_named():
    after = record_of(snap(env={"RUSTFLAGS": "", "CARGO_HOME": "/srv/cargo"}))
    assert gc.changed_parts(record_of(snap()), after) == ["env.CARGO_HOME"], "an added variable is named"


def test_a_removed_environment_variable_is_named():
    after = record_of(snap(env={}))
    assert gc.changed_parts(record_of(snap()), after) == ["env.RUSTFLAGS"], "a removed variable is named"


def test_the_record_holds_every_part_of_the_key():
    parts = gc.step_parts("pre-commit", "tests", snap())
    assert sorted(gc.parts_record(parts)) == sorted(parts), "one entry per part"


def test_the_record_holds_each_dict_part_per_name():
    record = record_of(snap())
    assert sorted(record["tools"]) == ["nextest", "rustc"], "tools by name"
    assert sorted(record["env"]) == ["RUSTFLAGS"], "env by name"


def test_a_written_record_is_read_back(tmp_path):
    parts = gc.step_parts("pre-commit", "tests", snap())
    assert gc.write_parts(tmp_path, "pre-commit", "tests", KEY_A, parts, 1000.0) is not None, "written"
    assert gc.read_parts(tmp_path, "pre-commit", "tests", KEY_A, 1001.0) == gc.parts_record(parts), "read back"


def test_the_record_lives_under_the_parts_directory_with_the_stamp_name(tmp_path):
    parts = gc.step_parts("pre-commit", "tests", snap())
    path = gc.write_parts(tmp_path, "pre-commit", "tests", KEY_A, parts, 1000.0)
    assert path == tmp_path / gc.PARTS_DIR / f"pre-commit.tests.{KEY_A}.json", "path"


def test_the_line_names_one_changed_part():
    assert gc.refusal_line("tests", ["tags"]) == (
        "  No pass stamp for tests: its inputs changed while it ran (changed: tags)."
    ), "one name"


def test_the_line_names_several_changed_parts():
    assert gc.refusal_line("hook", ["files", "index_tree"]) == (
        "  No pass stamp for hook: its inputs changed while it ran (changed: files, index_tree)."
    ), "names joined"


def test_keys_records_every_step_it_prints(tree, capsys):
    keys = run_keys(tree, capsys)
    assert set(keys) == set(gc.STEPS["pre-commit"]), keys
    now = time.time()
    for step, key in keys.items():
        assert gc.read_parts(tree / ".git" / gc.STAMP_DIR, "pre-commit", step, key, now) is not None, step


def test_pass_names_a_tag_created_during_the_run(tree, capsys):
    keys = run_keys(tree, capsys)
    _git(tree, "tag", "v9.9.9")
    out = run_pass(tree, capsys, "tests", keys["tests"])
    assert "  No pass stamp for tests: its inputs changed while it ran (changed: tags)." in out, out
    assert "tests" not in stamp_names(tree), "no stamp"


def test_pass_names_an_environment_variable_set_during_the_run(tree, capsys, monkeypatch):
    keys = run_keys(tree, capsys)
    monkeypatch.setenv("RUSTFLAGS", "-C debuginfo=0")
    out = run_pass(tree, capsys, "clippy", keys["clippy"])
    assert "(changed: env.RUSTFLAGS)." in out, out


def test_pass_names_a_file_edited_during_the_run(tree, capsys):
    keys = run_keys(tree, capsys)
    (tree / "src/lib.rs").write_text("pub fn b() {}\n", encoding="utf-8")
    out = run_pass(tree, capsys, "tests", keys["tests"])
    assert "No pass stamp for tests: its inputs changed while it ran (changed: files)." in out, out


def test_pass_with_unchanged_inputs_stamps_and_prints_no_refusal(tree, capsys):
    keys = run_keys(tree, capsys)
    out = run_pass(tree, capsys, "tests", keys["tests"])
    assert "No pass stamp" not in out, out
    assert stamp_names(tree) == ["tests"], stamp_names(tree)


def test_a_build_step_names_files_for_a_build_edit(tree, capsys):
    keys = run_keys(tree, capsys)
    (tree / "src/lib.rs").write_text("pub fn c() {}\n", encoding="utf-8")
    out = run_pass(tree, capsys, "clippy", keys["clippy"])
    assert "No pass stamp for clippy: its inputs changed while it ran (changed: files)." in out, out


def test_a_build_step_is_stamped_after_a_docs_edit(tree, capsys):
    keys = run_keys(tree, capsys)
    (tree / "docs/a.md").write_text("B\n", encoding="utf-8")
    out = run_pass(tree, capsys, "clippy", keys["clippy"])
    assert "No pass stamp" not in out, out
    assert stamp_names(tree) == ["clippy"], stamp_names(tree)


# ── Failure: no record, a damaged record, and no value on disk ───────────────


def _written(tmp_path, key=KEY_A, now=1000.0):
    parts = gc.step_parts("pre-commit", "tests", snap())
    return gc.write_parts(tmp_path, "pre-commit", "tests", key, parts, now)


def _rewrite(path, change):
    record = json.loads(path.read_text(encoding="utf-8"))
    change(record)
    record["check"] = gc._check(record)
    path.write_text(json.dumps(record), encoding="utf-8")


def test_a_missing_record_is_no_record(tmp_path):
    assert gc.read_parts(tmp_path, "pre-commit", "tests", KEY_A, 1000.0) is None, "absent"


def test_a_record_that_does_not_parse_is_no_record(tmp_path):
    _written(tmp_path).write_text("{broken", encoding="utf-8")
    assert gc.read_parts(tmp_path, "pre-commit", "tests", KEY_A, 1000.0) is None, "corrupt"


def test_a_record_that_is_not_an_object_is_no_record(tmp_path):
    _written(tmp_path).write_text("[1, 2]", encoding="utf-8")
    assert gc.read_parts(tmp_path, "pre-commit", "tests", KEY_A, 1000.0) is None, "a list"


def test_a_record_edited_after_writing_is_no_record(tmp_path):
    path = _written(tmp_path)
    record = json.loads(path.read_text(encoding="utf-8"))
    record["parts"]["tags"] = "0" * 64
    path.write_text(json.dumps(record), encoding="utf-8")
    assert gc.read_parts(tmp_path, "pre-commit", "tests", KEY_A, 1000.0) is None, "checksum"


def test_a_record_naming_another_key_is_no_record(tmp_path):
    path = _written(tmp_path)
    _rewrite(path, lambda r: r.update(key=KEY_B))
    assert gc.read_parts(tmp_path, "pre-commit", "tests", KEY_A, 1000.0) is None, "key"


def test_a_record_naming_another_hook_is_no_record(tmp_path):
    path = _written(tmp_path)
    _rewrite(path, lambda r: r.update(hook="pre-push"))
    assert gc.read_parts(tmp_path, "pre-commit", "tests", KEY_A, 1000.0) is None, "hook"


def test_a_record_naming_another_step_is_no_record(tmp_path):
    path = _written(tmp_path)
    _rewrite(path, lambda r: r.update(step="clippy"))
    assert gc.read_parts(tmp_path, "pre-commit", "tests", KEY_A, 1000.0) is None, "step"


def test_a_record_of_another_schema_is_no_record(tmp_path):
    path = _written(tmp_path)
    _rewrite(path, lambda r: r.update(schema=gc.SCHEMA + 1))
    assert gc.read_parts(tmp_path, "pre-commit", "tests", KEY_A, 1000.0) is None, "schema"


def test_an_expired_record_is_no_record(tmp_path):
    _written(tmp_path)
    assert gc.read_parts(tmp_path, "pre-commit", "tests", KEY_A, 1000.0 + gc.MAX_AGE + 1) is None, "expired"


def test_a_record_from_the_future_is_no_record(tmp_path):
    _written(tmp_path, now=1000.0 + gc.FUTURE_SLACK + 1)
    assert gc.read_parts(tmp_path, "pre-commit", "tests", KEY_A, 1000.0) is None, "future"


def test_a_record_without_a_numeric_time_is_no_record(tmp_path):
    path = _written(tmp_path)
    _rewrite(path, lambda r: r.update(written="yesterday"))
    assert gc.read_parts(tmp_path, "pre-commit", "tests", KEY_A, 1000.0) is None, "time"


def test_a_record_whose_parts_are_not_an_object_is_no_record(tmp_path):
    path = _written(tmp_path)
    _rewrite(path, lambda r: r.update(parts=["tags"]))
    assert gc.read_parts(tmp_path, "pre-commit", "tests", KEY_A, 1000.0) is None, "parts"


def test_a_record_for_another_key_is_not_read_under_this_one(tmp_path):
    _written(tmp_path, key=KEY_B)
    assert gc.read_parts(tmp_path, "pre-commit", "tests", KEY_A, 1000.0) is None, "other key"


def test_the_line_without_a_record_says_so():
    assert gc.refusal_line("tests", None) == (
        "  No pass stamp for tests: its inputs changed while it ran (its inputs at the start were not recorded)."
    ), "no record"


def test_the_line_with_no_differing_part_says_the_start_was_not_recorded():
    assert gc.refusal_line("tests", []) == gc.refusal_line("tests", None), "nothing to name"


def test_pass_without_a_record_prints_the_unrecorded_line(tree, capsys):
    keys = run_keys(tree, capsys)
    import shutil

    shutil.rmtree(parts_dir(tree))
    _git(tree, "tag", "v9.9.9")
    out = run_pass(tree, capsys, "tests", keys["tests"])
    assert "while it ran (its inputs at the start were not recorded)." in out, out


def test_pass_with_a_damaged_record_prints_the_unrecorded_line(tree, capsys):
    keys = run_keys(tree, capsys)
    (parts_dir(tree) / f"pre-commit.tests.{keys['tests']}.json").write_text("{", encoding="utf-8")
    _git(tree, "tag", "v9.9.9")
    out = run_pass(tree, capsys, "tests", keys["tests"])
    assert "while it ran (its inputs at the start were not recorded)." in out, out


def test_a_writer_whose_temporary_file_vanished_writes_no_record_and_does_not_fail(tmp_path, monkeypatch):
    def vanished(_src, _dst):
        raise FileNotFoundError("pruned")

    monkeypatch.setattr(gc.os, "replace", vanished)
    assert _written(tmp_path) is None, "no record"
    assert not list((tmp_path / gc.PARTS_DIR).iterdir()), "no temporary file left"


def test_keys_still_prints_every_key_when_no_record_can_be_written(tree, capsys):
    store = tree / ".git" / gc.STAMP_DIR
    store.mkdir()
    (store / gc.PARTS_DIR).write_text("not a directory", encoding="utf-8")
    keys = run_keys(tree, capsys)
    assert set(keys) == set(gc.STEPS["pre-commit"]), keys


def test_an_environment_value_never_reaches_a_file_under_parts(tree, capsys, monkeypatch):
    secret = "never-stored-" + os.urandom(16).hex()
    monkeypatch.setenv("CARGO_REGISTRY_TOKEN", secret)
    keys = run_keys(tree, capsys)
    files = [p for p in parts_dir(tree).rglob("*") if p.is_file()]
    assert len(files) == len(keys), files
    for p in files:
        assert secret.encode() not in p.read_bytes(), p
    record = gc.read_parts(tree / ".git" / gc.STAMP_DIR, "pre-commit", "tests", keys["tests"], time.time())
    assert "CARGO_REGISTRY_TOKEN" in record["env"], "the name is kept, so the line can name it"


def test_a_tool_value_never_reaches_a_file_under_parts(tree, capsys, monkeypatch):
    private = "/home/someone-" + os.urandom(8).hex() + "/bin/vale"
    monkeypatch.setattr(gc, "tool_versions", lambda _root, _env: {"vale": private})
    run_keys(tree, capsys)
    for p in parts_dir(tree).rglob("*"):
        if p.is_file():
            assert private.encode() not in p.read_bytes(), p


# ── Edge: odd records, pruning, the older layout ─────────────────────────────


def test_a_part_only_at_the_end_is_named():
    before = {"files": "1", "head": "2"}
    assert gc.changed_parts(before, {"files": "1", "head": "2", "tags": "3"}) == ["tags"], "added part"


def test_a_part_only_at_the_start_is_named():
    assert gc.changed_parts({"files": "1", "tags": "3"}, {"files": "1"}) == ["tags"], "removed part"


def test_a_dict_part_that_became_a_digest_is_named_whole():
    assert gc.changed_parts({"env": {"A": "1"}}, {"env": "2"}) == ["env"], "type change"


def test_two_empty_dict_parts_name_nothing():
    assert gc.changed_parts({"env": {}}, {"env": {}}) == [], "nothing differs"


def test_two_empty_records_name_nothing():
    assert gc.changed_parts({}, {}) == [], "nothing differs"


def test_pruning_removes_records_older_than_the_maximum_age(tmp_path):
    old = _written(tmp_path)
    fresh = _written(tmp_path, key=KEY_B)
    now = time.time()
    os.utime(old, (now - gc.MAX_AGE - 10, now - gc.MAX_AGE - 10))
    gc.prune(tmp_path, now)
    assert not old.exists() and fresh.exists(), "old record pruned"


def test_pruning_counts_records_apart_from_stamps(tmp_path):
    now = time.time()
    for i in range(3):
        k = f"{i:064x}"
        gc.write_stamp(tmp_path, "pre-commit", "tests", k, now, {})
        path = _written(tmp_path, key=k)
        os.utime(path, (now - 10 + i, now - 10 + i))
    gc.prune(tmp_path, now, max_count=2)
    assert len(list(tmp_path.glob("*.json"))) == 2, "two stamps"
    kept = sorted(p.name for p in (tmp_path / gc.PARTS_DIR).glob("*.json"))
    assert kept == [f"pre-commit.tests.{i:064x}.json" for i in (1, 2)], kept


def test_pruning_removes_stale_record_temporaries_and_leaves_other_files(tmp_path):
    _written(tmp_path)
    parts = tmp_path / gc.PARTS_DIR
    stale = parts / f"pre-commit.tests.{KEY_A}.json.tmp-1-aa"
    fresh = parts / f"pre-commit.tests.{KEY_B}.json.tmp-2-bb"
    other = parts / "notes.txt"
    for p in (stale, fresh, other):
        p.write_text("x", encoding="utf-8")
    now = time.time()
    os.utime(stale, (now - gc.TMP_MAX_AGE - 10, now - gc.TMP_MAX_AGE - 10))
    gc.prune(tmp_path, now)
    assert not stale.exists() and fresh.exists() and other.exists(), "only the stale temporary"


def test_pruning_a_store_without_records_prunes_its_stamps_as_before(tmp_path):
    now = time.time()
    path = gc.write_stamp(tmp_path, "pre-commit", "tests", KEY_A, now, {})
    os.utime(path, (now - gc.MAX_AGE - 10, now - gc.MAX_AGE - 10))
    assert gc.prune(tmp_path, now) == [path], "the old stamp only"


def test_a_stamp_is_found_beside_a_record(tmp_path):
    gc.write_stamp(tmp_path, "pre-commit", "tests", KEY_A, 1000.0, {"head": "h"})
    _written(tmp_path)
    assert gc.valid_stamp(tmp_path, "pre-commit", "tests", KEY_A, 1001.0) is not None, "stamp unaffected"


def test_list_shows_stamps_and_not_records(tree, capsys):
    keys = run_keys(tree, capsys)
    run_pass(tree, capsys, "tests", keys["tests"])
    assert gc.main(["list"]) == 0, "list"
    lines = capsys.readouterr().out.splitlines()
    assert [line.split()[1] for line in lines] == ["tests"], lines


def test_an_older_store_with_stamps_only_still_answers(tree, capsys):
    keys = run_keys(tree, capsys)
    run_pass(tree, capsys, "tests", keys["tests"])
    import shutil

    shutil.rmtree(parts_dir(tree))
    assert gc.main(["hit", "pre-commit", "tests", keys["tests"], "--quiet"]) == 0, "the stamp still counts"


def test_clear_removes_the_records_too(tree, capsys):
    run_keys(tree, capsys)
    assert gc.main(["clear"]) == 0, "clear"
    assert not parts_dir(tree).exists(), "records gone"


def test_writing_one_record_twice_leaves_one_valid_record(tmp_path):
    _written(tmp_path)
    _written(tmp_path)
    files = list((tmp_path / gc.PARTS_DIR).iterdir())
    assert len(files) == 1, files
    assert gc.read_parts(tmp_path, "pre-commit", "tests", KEY_A, 1000.0) is not None, "valid"


def test_equal_inputs_give_equal_records():
    assert record_of(snap()) == record_of(snap()), "deterministic"


def test_a_non_ascii_value_is_recorded_and_read_back(tmp_path):
    parts = gc.step_parts("pre-commit", "tests", snap(env={"RUSTFLAGS": "--cfg=été"}))
    gc.write_parts(tmp_path, "pre-commit", "tests", KEY_A, parts, 1000.0)
    assert gc.read_parts(tmp_path, "pre-commit", "tests", KEY_A, 1000.0) == gc.parts_record(parts), "read back"


def test_a_name_with_dots_and_underscores_is_kept_in_the_line():
    line = gc.refusal_line("tests", ["env.CARGO_HOME", "tools.rustc"])
    assert line.endswith("(changed: env.CARGO_HOME, tools.rustc)."), line


def test_keys_records_parts_when_the_cache_is_switched_off(tree, capsys, monkeypatch):
    monkeypatch.setenv("SIPNAB_GATE_NO_CACHE", "1")
    keys = run_keys(tree, capsys)
    names = sorted(p.name for p in parts_dir(tree).glob("*.json"))
    assert names == sorted(f"pre-commit.{s}.{k}.json" for s, k in keys.items()), names


def test_the_recorded_key_is_the_printed_key(tree, capsys):
    keys = run_keys(tree, capsys)
    record = json.loads((parts_dir(tree) / f"pre-commit.tests.{keys['tests']}.json").read_text(encoding="utf-8"))
    assert record["key"] == keys["tests"], record["key"]


def test_a_hyphenated_step_round_trips(tmp_path):
    parts = gc.step_parts("pre-commit", "script-tests", snap())
    gc.write_parts(tmp_path, "pre-commit", "script-tests", KEY_A, parts, 1000.0)
    assert gc.read_parts(tmp_path, "pre-commit", "script-tests", KEY_A, 1000.0) is not None, "round trip"


def test_a_record_is_digests_only(tmp_path):
    path = _written(tmp_path)
    record = json.loads(path.read_text(encoding="utf-8"))
    values = [v for v in record["parts"].values() if not isinstance(v, dict)]
    values += [v for d in record["parts"].values() if isinstance(d, dict) for v in d.values()]
    assert values and all(re.fullmatch(r"[0-9a-f]{64}", v) for v in values), values
