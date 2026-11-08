# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""The pass stamps of scripts/gate-cache.py: the classifier, the keys and the store.

A hook that passed on a tree records a stamp keyed on everything the check
read. A later run with the same key skips the check; any difference in the key
means the check runs. These tests hold the three parts that decide that:

* the classifier, which says whether a path can change what cargo compiles,
  and so whether a build-only check (clippy, rustdoc) reads it;
* the key, which must differ whenever an input the check reads differs;
* the store, which must never return a stamp that is corrupt, partial,
  expired or written for another key, and which prunes itself.

The hooks themselves are driven in test_gate_cache_hooks.py.
"""

import json
import os
import pathlib
import subprocess

import pytest
from conftest import load

gc = load("gate-cache")

HEX = "0123456789abcdef"


# ── The classifier ────────────────────────────────────────────────────────


def test_a_page_under_docs_that_no_rust_file_includes_is_not_a_build_input():
    assert gc.path_class("docs/fleet.md", frozenset()) == gc.DOCS


def test_a_top_level_markdown_file_that_nothing_includes_is_not_a_build_input():
    assert gc.path_class("ROADMAP.md", frozenset()) == gc.DOCS


def test_a_site_template_is_not_a_build_input():
    assert gc.path_class("website/templates/index.html", frozenset()) == gc.DOCS


def test_rust_source_is_a_build_input():
    assert gc.path_class("src/main.rs", frozenset()) == gc.BUILD


@pytest.mark.parametrize(
    "path",
    [
        "src/lib.rs",
        "tests/x_test.rs",
        "tests/fixtures/data.json",
        "crates/g729/README.md",
        "fuzz/Cargo.toml",
        "bpf/src/main.rs",
        "build.rs",
        "Cargo.toml",
        "Cargo.lock",
        ".config/nextest.toml",
        "scripts/parallel-tests.py",
        ".githooks/pre-commit",
        ".github/workflows/ci.yml",
    ],
)
def test_every_root_the_rule_names_as_code_is_a_build_input(path):
    assert gc.path_class(path, frozenset()) == gc.BUILD


def test_a_manifest_or_toolchain_file_under_a_docs_root_is_still_a_build_input():
    for path in ("docs/example/Cargo.toml", "website/rust-toolchain.toml", "docs/x/build.rs"):
        assert gc.path_class(path, frozenset()) == gc.BUILD, path


def test_a_rust_file_under_a_docs_root_is_a_build_input():
    assert gc.path_class("docs/examples/snippet.rs", frozenset()) == gc.BUILD


def test_a_doc_that_rust_includes_is_a_build_input():
    refs = gc.compiled_references({"src/lib.rs": '#![doc = include_str!("../docs/library.md")]\n'})
    assert gc.path_class("docs/library.md", refs) == gc.BUILD
    assert gc.path_class("docs/other.md", refs) == gc.DOCS


def test_a_path_outside_the_docs_roots_is_a_build_input_when_unsure():
    for path in ("packaging/deb/control", "harness/.env.example", "LICENSE-MIT", "yang/x.yang"):
        assert gc.path_class(path, frozenset()) == gc.BUILD, path


def test_an_include_through_the_manifest_dir_resolves_from_the_crate_root():
    sources = {
        "crates/g729/src/deep/mod.rs": (
            'const T: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/t.md"));\n'
        ),
    }
    refs = gc.compiled_references(sources, manifests={"crates/g729/Cargo.toml"})
    assert refs == frozenset({"crates/g729/docs/t.md"})


def test_include_text_inside_comments_and_strings_is_not_a_reference():
    source = "\n".join(
        [
            '/// include_str!("../docs/commented.md")',
            '/* include_str!("../docs/block.md") */',
            'const A: &str = "include_str!(\\"../docs/in-string.md\\")";',
            'const B: &str = r#"include_str!("../docs/in-raw.md")"#;',
            'const C: &str = include_str!("../docs/real.md");',
        ]
    )
    assert gc.compiled_references({"src/lib.rs": source}) == frozenset({"docs/real.md"})


def test_an_include_whose_argument_cannot_be_read_makes_every_path_a_build_input():
    refs = gc.compiled_references({"src/lib.rs": "const X: &str = include_str!(path_macro!());\n"})
    assert refs is None
    assert gc.path_class("docs/fleet.md", refs) == gc.BUILD


def test_an_include_of_generated_build_output_is_not_a_tree_path():
    source = 'const P: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/sipnab-bpf"));\n'
    assert gc.compiled_references({"src/capture/bpf.rs": source}) == frozenset()


def test_a_relative_include_resolves_against_the_including_file():
    refs = gc.compiled_references({"crates/g729/src/lib.rs": '#![doc = include_str!("../README.md")]\n'})
    assert refs == frozenset({"crates/g729/README.md"})


def test_a_char_literal_quote_does_not_hide_the_include_after_it():
    source = "const Q: char = '\"';\nconst D: &str = include_str!(\"../docs/after.md\");\n"
    assert gc.compiled_references({"src/lib.rs": source}) == frozenset({"docs/after.md"})


def test_a_change_of_docs_pages_only_is_docs():
    assert gc.change_class(["docs/a.md", "README.md"], frozenset()) == gc.DOCS


def test_one_build_input_makes_the_whole_change_build():
    assert gc.change_class(["docs/a.md", "src/lib.rs"], frozenset()) == gc.BUILD


def test_a_change_of_no_paths_is_none():
    assert gc.change_class([], frozenset()) == "none"


# ── The keys ──────────────────────────────────────────────────────────────


def snap(**over):
    """A snapshot with fixed inputs; keyword arguments replace fields."""
    fields = {
        "files": {
            "src/lib.rs": "1" * 40,
            "Cargo.lock": "2" * 40,
            "docs/fleet.md": "3" * 40,
            "README.md": "4" * 40,
        },
        "ignored": {"docs/design/backlog.local.md": "10:1", "crates/g729/test-vectors/a.bin": "5:2"},
        "index_tree": "a" * 40,
        "head": "b" * 40,
        "tags": "c" * 64,
        "tools": {"rustc": "rustc 1.90.0\nhost: aarch64", "nextest": "cargo-nextest 0.9.148"},
        "env": {"RUSTFLAGS": ""},
        "hook_scripts": "d" * 64,
        "compiled": frozenset(),
    }
    fields.update(over)
    return gc.Snapshot(**fields)


def key(snapshot, step="tests", hook="pre-commit"):
    return gc.key_of(gc.step_parts(hook, step, snapshot))


def with_file(path, blob, base=None):
    files = dict((base or snap()).files)
    files[path] = blob
    return files


def test_the_same_inputs_give_the_same_key():
    assert key(snap()) == key(snap())
    assert len(key(snap())) == 64 and set(key(snap())) <= set(HEX)


def test_a_stamp_key_for_tree_a_is_never_the_key_for_tree_b():
    b = snap(files=with_file("src/lib.rs", "9" * 40))
    for step in ("tests", "clippy", "hook"):
        assert key(snap(), step) != key(b, step), step


def test_a_docs_change_keeps_the_build_key_and_changes_the_suite_key():
    b = snap(files=with_file("docs/fleet.md", "9" * 40))
    assert key(snap(), "clippy") == key(b, "clippy")
    assert key(snap(), "tests") != key(b, "tests")


def test_a_change_to_the_hook_or_a_script_it_calls_changes_every_key():
    b = snap(hook_scripts="e" * 64)
    for step in gc.STEPS["pre-commit"]:
        assert key(snap(), step) != key(b, step), step


def test_a_cargo_lock_change_changes_the_build_key():
    b = snap(files=with_file("Cargo.lock", "8" * 40))
    assert key(snap(), "clippy") != key(b, "clippy")


def test_a_toolchain_change_changes_the_key():
    b = snap(tools={**snap().tools, "rustc": "rustc 1.91.0\nhost: aarch64"})
    assert key(snap(), "clippy") != key(b, "clippy")


def test_a_nextest_version_change_changes_the_key():
    b = snap(tools={**snap().tools, "nextest": "cargo-nextest 0.9.149"})
    assert key(snap(), "tests") != key(b, "tests")


def test_a_rustflags_change_changes_the_key():
    b = snap(env={"RUSTFLAGS": "-C opt-level=1"})
    assert key(snap(), "clippy") != key(b, "clippy")


def test_variables_that_cannot_change_a_verdict_stay_out_of_the_key():
    env = {
        "GIT_INDEX_FILE": "/x/index.lock",
        "GIT_DIR": "/x",
        "CARGO_TERM_COLOR": "never",
        "SIPNAB_GATE_NO_CACHE": "1",
        "HOME": "/home/u",
        "RUSTFLAGS": "-D warnings",
        "SIPNAB_TEST_JOBS": "4",
    }
    assert gc.cache_env(env) == {"RUSTFLAGS": "-D warnings", "SIPNAB_TEST_JOBS": "4"}


def test_the_index_and_head_are_in_the_suite_key_and_not_the_build_key():
    for field in ("index_tree", "head", "tags"):
        b = snap(**{field: "f" * 40})
        assert key(snap(), "tests") != key(b, "tests"), field
        assert key(snap(), "clippy") == key(b, "clippy"), field


def test_an_ignored_file_a_test_reads_is_in_the_suite_key():
    b = snap(ignored={**snap().ignored, "docs/design/backlog.local.md": "11:3"})
    assert key(snap(), "tests") != key(b, "tests")


def test_two_steps_never_share_a_key():
    keys = {key(snap(), step) for step in gc.STEPS["pre-commit"]}
    assert len(keys) == len(gc.STEPS["pre-commit"])


def test_every_step_command_is_spelled_in_its_hook():
    root = pathlib.Path(__file__).resolve().parents[2]
    for hook, steps in gc.STEPS.items():
        text = (root / ".githooks" / hook).read_text(encoding="utf-8")
        for step, (_cls, command) in steps.items():
            assert command in text, f"{hook} {step}: {command!r} is not in .githooks/{hook}"
            assert f"gate_hit {step}" in text or f'gate_hit "{step}' in text or (
                step.startswith("check-") and 'gate_hit "check-$combo"' in text
            ), f"{hook} never asks for a {step} stamp"


# ── The store ─────────────────────────────────────────────────────────────

NOW = 1_800_000_000.0
K = "5" * 64


def test_a_written_stamp_is_found_again(tmp_path):
    gc.write_stamp(tmp_path, "pre-commit", "tests", K, NOW, {"tree": "x"})
    stamp = gc.valid_stamp(tmp_path, "pre-commit", "tests", K, NOW + 1)
    assert stamp is not None and stamp["key"] == K


def test_a_corrupt_stamp_is_no_stamp(tmp_path):
    path = gc.write_stamp(tmp_path, "pre-commit", "tests", K, NOW, {})
    path.write_text("{not json", encoding="utf-8")
    assert gc.valid_stamp(tmp_path, "pre-commit", "tests", K, NOW) is None


def test_a_partial_stamp_is_no_stamp(tmp_path):
    path = gc.write_stamp(tmp_path, "pre-commit", "tests", K, NOW, {})
    data = path.read_bytes()
    path.write_bytes(data[: len(data) // 2])
    assert gc.valid_stamp(tmp_path, "pre-commit", "tests", K, NOW) is None


def test_a_stamp_written_for_another_key_is_no_stamp_under_this_one(tmp_path):
    other = "6" * 64
    written = gc.write_stamp(tmp_path, "pre-commit", "tests", other, NOW, {})
    os.replace(written, gc.stamp_path(tmp_path, "pre-commit", "tests", K))
    assert gc.valid_stamp(tmp_path, "pre-commit", "tests", K, NOW) is None


def test_a_stamp_edited_after_writing_is_no_stamp(tmp_path):
    path = gc.write_stamp(tmp_path, "pre-commit", "tests", K, NOW, {"tree": "x"})
    data = json.loads(path.read_text(encoding="utf-8"))
    data["summary"] = {"tree": "y"}
    path.write_text(json.dumps(data), encoding="utf-8")
    assert gc.valid_stamp(tmp_path, "pre-commit", "tests", K, NOW) is None


def test_an_expired_stamp_is_no_stamp(tmp_path):
    gc.write_stamp(tmp_path, "pre-commit", "tests", K, NOW, {})
    assert gc.valid_stamp(tmp_path, "pre-commit", "tests", K, NOW + gc.MAX_AGE + 1) is None


def test_a_stamp_from_the_future_is_no_stamp(tmp_path):
    gc.write_stamp(tmp_path, "pre-commit", "tests", K, NOW + 3600, {})
    assert gc.valid_stamp(tmp_path, "pre-commit", "tests", K, NOW) is None


def test_a_half_written_temporary_file_is_never_read_as_a_stamp(tmp_path):
    final = gc.stamp_path(tmp_path, "pre-commit", "tests", K)
    tmp_path.mkdir(exist_ok=True)
    (tmp_path / (final.name + ".tmp-123-abc")).write_text("{}", encoding="utf-8")
    assert gc.valid_stamp(tmp_path, "pre-commit", "tests", K, NOW) is None


def _age(path, seconds_ago):
    os.utime(path, (NOW - seconds_ago, NOW - seconds_ago))


def test_pruning_removes_stamps_older_than_the_maximum_age(tmp_path):
    old = gc.write_stamp(tmp_path, "pre-commit", "tests", "7" * 64, NOW, {})
    new = gc.write_stamp(tmp_path, "pre-commit", "tests", "8" * 64, NOW, {})
    _age(old, gc.MAX_AGE + 10)
    _age(new, 10)
    removed = gc.prune(tmp_path, NOW)
    assert old in removed and not old.exists()
    assert new.exists()


def test_pruning_keeps_only_the_newest_stamps(tmp_path):
    paths = []
    for i in range(6):
        p = gc.write_stamp(tmp_path, "pre-push", "clippy", f"{i:064x}", NOW, {})
        _age(p, 100 - i)
        paths.append(p)
    gc.prune(tmp_path, NOW, max_count=4)
    assert [p.exists() for p in paths] == [False, False, True, True, True, True]


def test_pruning_removes_stale_temporaries_and_leaves_fresh_ones_and_other_files(tmp_path):
    stale = tmp_path / ("pre-commit.tests." + K + ".json.tmp-1-a")
    fresh = tmp_path / ("pre-commit.tests." + K + ".json.tmp-2-b")
    other = tmp_path / "README"
    for p in (stale, fresh, other):
        p.write_text("x", encoding="utf-8")
    _age(stale, gc.TMP_MAX_AGE + 10)
    _age(fresh, 5)
    _age(other, gc.MAX_AGE * 2)
    gc.prune(tmp_path, NOW)
    assert not stale.exists() and fresh.exists() and other.exists()


def test_stamps_in_a_missing_directory_are_simply_absent(tmp_path):
    missing = tmp_path / "nothing-here"
    assert gc.valid_stamp(missing, "pre-commit", "tests", K, NOW) is None
    assert gc.prune(missing, NOW) == []


# ── The snapshot of a real tree ─────────────────────────────────────────────


def _git(cwd, *args):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    return subprocess.run(["git", *args], cwd=cwd, env=env, check=True, capture_output=True, text=True).stdout


@pytest.fixture
def repo(tmp_path):
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
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "base")
    return root


def files_of(root):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    return gc.tree_files(root, env)


def test_a_clean_tree_reads_as_its_index(repo):
    files = files_of(repo)
    blob = _git(repo, "rev-parse", ":src/lib.rs").strip()
    assert files["src/lib.rs"] == f"100644:{blob}"


def test_an_edit_reverted_before_the_run_reads_as_the_unedited_file(repo):
    before = files_of(repo)
    (repo / "src/lib.rs").write_text("pub fn b() {}\n", encoding="utf-8")
    (repo / "src/lib.rs").write_text("pub fn a() {}\n", encoding="utf-8")
    assert files_of(repo) == before


def test_an_unstaged_edit_changes_the_snapshot(repo):
    before = files_of(repo)
    (repo / "src/lib.rs").write_text("pub fn b() {}\n", encoding="utf-8")
    assert files_of(repo)["src/lib.rs"] != before["src/lib.rs"]


def test_an_untracked_file_is_in_the_snapshot(repo):
    (repo / "tests").mkdir()
    (repo / "tests/new_test.rs").write_text("#[test] fn t() {}\n", encoding="utf-8")
    assert "tests/new_test.rs" in files_of(repo)


def test_a_deleted_tracked_file_is_recorded_as_deleted(repo):
    (repo / "docs/a.md").unlink()
    assert files_of(repo)["docs/a.md"] == "deleted"


def test_an_executable_bit_change_changes_the_snapshot(repo):
    before = files_of(repo)
    (repo / "src/lib.rs").chmod(0o755)
    assert files_of(repo)["src/lib.rs"] != before["src/lib.rs"]


def test_ignored_files_are_read_but_the_build_directory_is_not_walked(repo):
    (repo / "docs/backlog.local.md").write_text("x\n", encoding="utf-8")
    (repo / "target/debug").mkdir(parents=True)
    (repo / "target/debug/huge").write_text("x\n", encoding="utf-8")
    ignored = gc.ignored_files(repo, {})
    assert "docs/backlog.local.md" in ignored
    assert not any(p.startswith("target/") for p in ignored)


def test_a_tools_own_cache_directory_is_not_an_input(repo):
    """pytest rewrites .pytest_cache on every run, and the pre-commit hook runs
    pytest: walked, it changed the snapshot under every run with script tests,
    and the script-tests and whole-hook stamps were never written (2026-11-07)."""
    cache = repo / "scripts/.pytest_cache/v/cache"
    cache.mkdir(parents=True)
    (repo / "scripts/.pytest_cache/.gitignore").write_text("*\n", encoding="utf-8")
    (cache / "nodeids").write_text("[]\n", encoding="utf-8")
    assert not any(".pytest_cache" in p for p in gc.ignored_files(repo, {}))


# ── Shared stamps: the common git dir, content ids for ignored files ────────
#
# Stamps lived in each worktree's own git dir, so every new worktree started
# cold, and the release flow makes one per release. They now live in the
# common git dir. The key already covers the tree, so a stamp from one
# worktree is used in another only for identical inputs. For identical inputs
# to give identical keys across worktrees, an ignored file (the G.729 vectors,
# copied into each new worktree) is identified by its content, not its mtime.


def test_a_linked_worktrees_stamps_live_in_the_common_git_dir(repo):
    wt = repo.parent / "wt"
    _git(repo, "worktree", "add", "-q", str(wt))
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    assert gc.stamp_dir(wt, env) == (repo / ".git" / gc.STAMP_DIR).resolve()


def test_the_main_checkouts_stamps_live_in_its_git_dir(repo):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    assert gc.stamp_dir(repo, env) == (repo / ".git" / gc.STAMP_DIR).resolve()


def test_the_hash_cache_stays_in_the_worktrees_own_git_dir(repo):
    wt = repo.parent / "wt"
    _git(repo, "worktree", "add", "-q", str(wt))
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    own = pathlib.Path(_git(wt, "rev-parse", "--absolute-git-dir").strip())
    assert gc.hash_cache_path(wt, env) == own / gc.HASH_CACHE
    assert own != (repo / ".git").resolve()


def test_an_ignored_file_copied_with_a_new_mtime_keeps_its_id(repo):
    f = repo / "docs/vectors.local.md"
    f.write_text("same bytes\n", encoding="utf-8")
    before = gc.ignored_files(repo, {})["docs/vectors.local.md"]
    os.utime(f, (NOW, NOW))
    assert gc.ignored_files(repo, {})["docs/vectors.local.md"] == before


def test_an_ignored_file_rewritten_with_its_old_size_and_mtime_gets_a_new_id(repo, monkeypatch):
    # The racy rule would rehash this fresh file anyway; switched off here so
    # the test isolates the stat check it names.
    monkeypatch.setattr(gc, "RACY_NS", -10**12)
    f = repo / "docs/vectors.local.md"
    f.write_text("aaaa\n", encoding="utf-8")
    cache = {}
    before = gc.ignored_files(repo, {}, cache)["docs/vectors.local.md"]
    st = f.stat()
    # Past one tick of the kernel's coarse file clock, so ctime moves: within
    # one tick only the racy rule can see the rewrite, and it is off here.
    import time

    time.sleep(0.05)
    f.write_text("bbbb\n", encoding="utf-8")
    os.utime(f, ns=(st.st_atime_ns, st.st_mtime_ns))
    assert gc.ignored_files(repo, {}, cache)["docs/vectors.local.md"] != before


def test_an_unchanged_ignored_file_is_not_read_again(repo, monkeypatch):
    # A file written this instant is racy (see below); this one is trusted.
    monkeypatch.setattr(gc, "RACY_NS", -10**12)
    (repo / "docs/vectors.local.md").write_text("x\n", encoding="utf-8")
    cache = {}
    gc.ignored_files(repo, {}, cache)
    reads = []
    monkeypatch.setattr(gc, "_hash_file", lambda p: reads.append(p) or "never")
    gc.ignored_files(repo, {}, cache)
    assert reads == []


def test_a_cache_entry_for_another_size_is_not_trusted(repo, monkeypatch):
    # The racy rule would rehash this fresh file anyway; switched off here so
    # the test isolates the stat check it names.
    monkeypatch.setattr(gc, "RACY_NS", -10**12)
    f = repo / "docs/vectors.local.md"
    f.write_text("x\n", encoding="utf-8")
    cache = {}
    gc.ignored_files(repo, {}, cache)
    entry = cache["docs/vectors.local.md"]
    cache["docs/vectors.local.md"] = [entry[0] + 1, *entry[1:4], "sha256:" + "0" * 64, entry[5]]
    assert gc.ignored_files(repo, {}, cache)["docs/vectors.local.md"] != "sha256:" + "0" * 64


def test_a_corrupt_hash_cache_is_rebuilt(tmp_path):
    path = tmp_path / gc.HASH_CACHE
    path.write_text("{broken", encoding="utf-8")
    assert gc.load_hash_cache(path) == {}
    gc.save_hash_cache(path, {"a": [1, 2, 3, 4, "sha256:x"]})
    assert gc.load_hash_cache(path) == {"a": [1, 2, 3, 4, "sha256:x"]}


def _write_many(args):
    """Write each stamp and prune after it, on the real clock: prune judges age
    by file times, which a fixed clock would make look days old."""
    import time

    directory, hook, step, keys = args
    for k in keys:
        gc.write_stamp(directory, hook, step, k, time.time(), {"w": os.getpid()})
        gc.prune(directory, time.time(), max_count=10_000)
    return os.getpid()


def test_two_processes_writing_stamps_into_one_directory_leave_every_stamp_valid(tmp_path):
    import multiprocessing

    a = [f"{i:064x}" for i in range(0, 60)]
    b = [f"{i:064x}" for i in range(30, 90)]
    with multiprocessing.get_context("fork").Pool(2) as pool:
        pids = pool.map(_write_many, [(tmp_path, "pre-commit", "tests", a), (tmp_path, "pre-commit", "tests", b)])
    assert len(set(pids)) == 2
    import time

    for k in set(a) | set(b):
        assert gc.valid_stamp(tmp_path, "pre-commit", "tests", k, time.time()) is not None, k
    assert not [p for p in tmp_path.iterdir() if ".tmp-" in p.name]


def test_a_reader_never_sees_a_half_written_stamp_while_another_process_writes(tmp_path):
    import multiprocessing

    import time

    k = "e" * 64
    gc.write_stamp(tmp_path, "pre-push", "clippy", k, time.time(), {})
    ctx = multiprocessing.get_context("fork")
    writer = ctx.Process(target=_write_many, args=((tmp_path, "pre-push", "clippy", [k] * 300),))
    writer.start()
    seen = 0
    while writer.is_alive():
        assert gc.valid_stamp(tmp_path, "pre-push", "clippy", k, time.time()) is not None
        seen += 1
    writer.join()
    assert writer.exitcode == 0 and seen > 0


def test_a_writer_whose_temporary_file_vanished_writes_no_stamp_and_does_not_fail(tmp_path, monkeypatch):
    real = os.replace

    def vanish(src, dst):
        os.unlink(src)
        return real(src, dst)

    monkeypatch.setattr(gc.os, "replace", vanish)
    assert gc.write_stamp(tmp_path, "pre-commit", "tests", K, NOW, {}) is None
    assert gc.valid_stamp(tmp_path, "pre-commit", "tests", K, NOW) is None


def test_a_file_changed_too_close_to_its_hash_is_read_again(repo, monkeypatch):
    """File times come from a coarse kernel clock: a rewrite in the same tick,
    with the same size and the mtime set back, keeps the whole stat. Like git's
    racily-clean rule, a hash is trusted only for a file whose times are older
    than the hash by RACY_NS."""
    f = repo / "docs/vectors.local.md"
    f.write_text("aaaa\n", encoding="utf-8")
    cache = {}
    gc.ignored_files(repo, {}, cache)
    reads = []
    real = gc._hash_file
    monkeypatch.setattr(gc, "_hash_file", lambda p: reads.append(p) or real(p))
    gc.ignored_files(repo, {}, cache)
    assert reads, "a hash taken in the same instant as the write was trusted"
