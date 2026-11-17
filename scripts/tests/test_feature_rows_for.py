# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""Which rows of CI's feature matrix the pre-push hook lints for a push.

PREPUSH-LINTS-3-OF-22-FEATURE-ROWS: pull request #826 passed every local gate
and failed CI's `cargo clippy --no-default-features --features g729 --tests`
("function `read_quoted_body` is never used"; its callers exist only under
vcon/api). The hook linted only the 3 rows marked `hook`.

`rows_for` is the one rule. The changed files of the push are read; each Rust
file's feature gate comes from the `#[cfg(...)]` on the `mod` lines that lead
to it (and a test target's `#![cfg(...)]`):

* no Rust or Cargo file changed: the rows marked `hook`;
* every changed Rust file is behind a feature gate: for each gate, the rows
  with the fewest features that compile it, plus the rows marked `hook`;
* otherwise (a change outside every gated module, or changes that cannot be
  read): every single-feature row the hook can lint, plus the rows marked
  `hook`. The note says how many other combinations stay in CI.
"""

import os
import pathlib
import subprocess
import sys

import pytest
from conftest import load

REPO = pathlib.Path(__file__).resolve().parent.parent.parent
SCRIPT = REPO / "scripts/check-feature-matrix.py"
ZERO = "0" * 40

fm = load("check-feature-matrix")
gc = load("gate-cache")

TABLE = {
    "native": [],
    "tui": ["native", "dep:ratatui"],
    "tls": ["dep:rustls"],
    "api": ["native", "dep:axum"],
    "mcp": ["native"],
    "mcp-http": ["mcp", "api", "rmcp/transport"],
    "vcon": ["native"],
    "opus": ["vcon", "dep:opus"],
    "g729": ["native"],
    "wasm": [],
    "full": ["native", "tui", "tls", "api", "mcp", "mcp-http", "vcon", "opus", "g729"],
}
COMBOS = fm.parse_combos(
    "native,api,mcp,mcp-http suite hook\n"
    "native hook\n"
    "tls\n"
    "api\n"
    "mcp\n"
    "tls,api\n"
    "native,tui lib hook\n"
    "vcon\n"
    "opus needs=cmake\n"
    "g729\n"
    "native,tui,tls,api,mcp,mcp-http,vcon,g729\n"
    "wasm\n"
)
HOOK = ["native,api,mcp,mcp-http", "native", "native,tui"]
SINGLES = ["native", "tls", "api", "mcp", "vcon", "g729"]


def alts(*sets):
    return [frozenset(s) for s in sets]


def names(rows):
    return [r.features for r in rows]


def choose(changed, gates):
    return fm.rows_for(changed, gates, COMBOS, TABLE)


# ---------------------------------------------------------------- success


def test_success_a_feature_predicate_is_one_alternative():
    assert fm.cfg_alternatives('feature = "mcp"') == alts({"mcp"})


def test_success_all_requires_every_feature():
    assert fm.cfg_alternatives('all(feature = "native", feature = "vcon")') == alts({"native", "vcon"})


def test_success_any_gives_one_alternative_per_feature():
    assert fm.cfg_alternatives('any(feature = "api", feature = "mcp")') == alts({"api"}, {"mcp"})


def test_success_a_platform_predicate_adds_no_feature():
    assert fm.cfg_alternatives('all(not(target_arch = "wasm32"), feature = "native")') == alts({"native"})


def test_success_the_closure_follows_enabled_features():
    assert fm.feature_closure(TABLE, ["mcp-http"]) == {"mcp-http", "mcp", "api", "native"}


def test_success_module_gates_follow_mod_lines():
    gates = fm.module_gates({
        "src/lib.rs": '#[cfg(feature = "mcp")]\npub mod mcp;\npub mod error;\n',
        "src/mcp/mod.rs": "pub mod tools;\n",
        "src/mcp/tools.rs": "",
        "src/error.rs": "",
    })
    assert gates["src/mcp/mod.rs"] == alts({"mcp"}) and gates["src/mcp/tools.rs"] == alts({"mcp"}), gates
    assert gates["src/error.rs"] == alts(set()), gates


def test_success_a_test_target_takes_its_inner_cfg():
    gates = fm.module_gates({"tests/vcon_test.rs": '// c\n#![cfg(all(feature = "native", feature = "vcon"))]\n'})
    assert gates["tests/vcon_test.rs"] == alts({"native", "vcon"}), gates


def test_success_no_rust_change_lints_the_hook_rows():
    rows, note = choose(["docs/a.md", "README.md"], {})
    assert names(rows) == HOOK, names(rows)
    assert "no Rust or Cargo file changed" in note, note


def test_success_an_ungated_change_lints_singles_and_hook_rows():
    rows, note = choose(["src/error.rs"], {"src/error.rs": alts(set())})
    assert set(names(rows)) == set(HOOK) | set(SINGLES), names(rows)
    assert "outside every feature-gated module" in note and "src/error.rs" in note, note


def test_success_the_fallback_note_counts_from_the_rows():
    _rows, note = choose(["src/error.rs"], {"src/error.rs": alts(set())})
    assert "the 6 single-feature rows and the 3 rows marked `hook`" in note, note
    # Not linted: tls,api; opus; the long row. wasm has its own step.
    assert "the other 3 combinations stay in CI" in note, note


def test_success_a_gated_change_lints_the_smallest_rows_that_compile_it():
    rows, note = choose(["src/vcon/a.rs"], {"src/vcon/a.rs": alts({"vcon"})})
    assert names(rows) == ["native,api,mcp,mcp-http", "native", "native,tui", "vcon"], names(rows)
    assert "behind a feature gate" in note, note


def test_success_the_826_shape_lints_g729():
    # read_quoted_body sat in a module only g729-gated callers reach.
    rows, _ = choose(["src/g729/x.rs"], {"src/g729/x.rs": alts({"g729"})})
    assert "g729" in names(rows), names(rows)


def test_success_rows_come_in_file_order():
    rows, _ = choose(["src/a.rs", "src/b.rs"], {"src/a.rs": alts({"g729"}), "src/b.rs": alts({"vcon"})})
    order = [c.features for c in COMBOS]
    assert names(rows) == sorted(names(rows), key=order.index), names(rows)


def test_success_a_native_gate_picks_the_single_rows_that_enable_native():
    rows, _ = choose(["src/cli.rs"], {"src/cli.rs": alts({"native"})})
    # `native` is also a row marked `hook`; `tls` does not turn native on.
    assert set(names(rows)) - set(HOOK) == {"api", "mcp", "vcon", "g729"}, names(rows)
    assert "tls" not in names(rows), names(rows)


def test_success_changed_files_from_a_branch_update():
    calls = []

    def git(*args):
        calls.append(args)
        if args[0] == "cat-file":
            return ""
        if args[0] == "diff":
            return "src/a.rs\nsrc/b.rs"
        return None

    out = fm.changed_files(f"refs/heads/x {'a' * 40} refs/heads/x {'b' * 40}\n", git)
    assert out == ["src/a.rs", "src/b.rs"], out
    assert ("diff", "--name-only", "b" * 40, "a" * 40) in calls, calls


def test_success_changed_files_of_a_new_branch_measure_from_origin_main():
    def git(*args):
        if args[0] == "merge-base":
            return "c" * 40
        if args[0] == "diff":
            assert args[2] == "c" * 40, args
            return "src/a.rs"
        return None

    assert fm.changed_files(f"refs/heads/x {'a' * 40} refs/heads/x {ZERO}\n", git) == ["src/a.rs"]


# ---------------------------------------------------------------- failure


def test_failure_an_unparseable_cfg_raises():
    with pytest.raises(ValueError):
        fm.cfg_alternatives('all(feature = "a"')


def test_failure_not_of_a_feature_is_ungated():
    # Code compiled with a feature OFF is linted by the fallback, never skipped.
    assert fm.cfg_alternatives('not(feature = "plain")') == alts(set())


def test_failure_any_with_an_ungated_arm_is_ungated():
    assert frozenset() in fm.cfg_alternatives('any(feature = "api", unix)')


def test_failure_a_file_no_mod_line_reaches_is_ungated():
    rows, note = choose(["src/bin/tool.rs"], {})
    assert set(names(rows)) == set(HOOK) | set(SINGLES), names(rows)
    assert "src/bin/tool.rs" in note, note


def test_failure_unreadable_changes_fall_back():
    rows, note = choose(None, {})
    assert set(names(rows)) == set(HOOK) | set(SINGLES), names(rows)
    assert "could not be read" in note, note


def test_failure_one_ungated_file_among_gated_ones_falls_back():
    gates = {"src/vcon/a.rs": alts({"vcon"}), "src/error.rs": alts(set())}
    rows, _ = choose(["src/vcon/a.rs", "src/error.rs"], gates)
    assert set(names(rows)) == set(HOOK) | set(SINGLES), names(rows)


def test_failure_a_cargo_manifest_change_falls_back():
    rows, note = choose(["Cargo.toml"], {})
    assert set(names(rows)) == set(HOOK) | set(SINGLES), names(rows)
    assert "Cargo.toml" in note, note


def test_failure_a_cargo_lock_change_falls_back():
    rows, _ = choose(["Cargo.lock"], {})
    assert set(names(rows)) == set(HOOK) | set(SINGLES), names(rows)


def test_failure_a_row_that_needs_a_tool_is_never_chosen():
    rows, _ = choose(["src/opus.rs"], {"src/opus.rs": alts({"opus"})})
    assert "opus" not in names(rows), names(rows)


def test_failure_wasm_is_never_chosen():
    rows, _ = choose(["src/error.rs"], {"src/error.rs": alts(set())})
    assert "wasm" not in names(rows), names(rows)


def test_failure_changed_files_of_a_new_branch_without_origin_main_is_none():
    assert fm.changed_files(f"refs/heads/x {'a' * 40} refs/heads/x {ZERO}\n", lambda *a: None) is None


def test_failure_changed_files_of_a_malformed_line_is_none():
    assert fm.changed_files("refs/heads/x only three\n", lambda *a: "") is None


def test_failure_changed_files_when_diff_fails_is_none():
    def git(*args):
        return "" if args[0] == "cat-file" else None

    assert fm.changed_files(f"refs/heads/x {'a' * 40} refs/heads/x {'b' * 40}\n", git) is None


def test_failure_an_unknown_remote_sha_measures_from_origin_main():
    seen = []

    def git(*args):
        seen.append(args[0])
        if args[0] == "cat-file":
            return None
        if args[0] == "merge-base":
            return "c" * 40
        return "src/a.rs"

    assert fm.changed_files(f"refs/heads/x {'a' * 40} refs/heads/x {'b' * 40}\n", git) == ["src/a.rs"]
    assert "merge-base" in seen, seen


def test_failure_lint_row_refuses_a_row_that_needs_a_tool(tmp_path):
    root = repo_with(tmp_path, "native hook\nopus needs=cmake\n")
    r = cli(root, "--lint-row", "opus")
    assert r.returncode == 2, r.stdout + r.stderr


def test_failure_lint_row_refuses_wasm(tmp_path):
    root = repo_with(tmp_path, "native hook\nwasm\n")
    r = cli(root, "--lint-row", "wasm")
    assert r.returncode == 2, r.stdout + r.stderr


def test_failure_push_rows_of_a_malformed_file_fails(tmp_path):
    root = repo_with(tmp_path, "tls\nplain hook hook\n")
    r = cli(root, "--push-rows", stdin="")
    assert r.returncode == 2 and "line 2" in r.stdout, r.stdout + r.stderr


# ---------------------------------------------------------------- edge


def test_edge_a_multi_line_cfg_on_a_mod_line():
    gates = fm.module_gates({
        "src/lib.rs": '#[cfg(any(\n    feature = "tls",\n    feature = "g729"\n))]\npub(crate) mod tls_files;\n',
        "src/tls_files.rs": "",
    })
    assert set(gates["src/tls_files.rs"]) == set(alts({"tls"}, {"g729"})), gates


def test_edge_a_path_attribute_names_the_file():
    gates = fm.module_gates({
        "src/lib.rs": '#[cfg(feature = "vcon")]\n#[path = "elsewhere/v.rs"]\nmod v;\n',
        "src/elsewhere/v.rs": "",
    })
    assert gates["src/elsewhere/v.rs"] == alts({"vcon"}), gates


def test_edge_a_nested_gate_adds_to_its_parents():
    gates = fm.module_gates({
        "src/lib.rs": '#[cfg(feature = "native")]\npub mod app;\n',
        "src/app/mod.rs": '#[cfg(feature = "tui")]\nmod view;\n',
        "src/app/view.rs": "",
    })
    assert gates["src/app/view.rs"] == alts({"native", "tui"}), gates


def test_edge_a_non_mod_rs_file_has_its_children_in_its_stem_dir():
    gates = fm.module_gates({
        "src/lib.rs": '#[cfg(feature = "api")]\npub mod api;\n',
        "src/api.rs": "mod routes;\n",
        "src/api/routes.rs": "",
    })
    assert gates["src/api/routes.rs"] == alts({"api"}), gates


def test_edge_an_inline_module_is_not_a_file():
    gates = fm.module_gates({"src/lib.rs": '#[cfg(feature = "api")]\nmod inline {\n    fn f() {}\n}\n',
                             "src/inline.rs": ""})
    assert set(gates) == {"src/lib.rs"}, gates


def test_edge_a_key_value_platform_predicate_adds_no_feature():
    assert fm.cfg_alternatives('all(unix, target_os = "linux", feature = "native")') == alts({"native"})


def test_failure_two_top_level_predicates_do_not_parse():
    with pytest.raises(ValueError):
        fm.cfg_alternatives('feature = "a", feature = "b"')


def test_edge_the_note_counts_one_row_in_the_singular():
    combos = fm.parse_combos("tls,api hook\napi\napi,wasm\n")
    _rows, note = fm.rows_for(None, {}, combos, {})
    assert ("linting the 1 single-feature row and the 1 row marked `hook`; "
            "the other 1 combination stays in CI") in note, note


def test_edge_a_commented_mod_line_is_ignored():
    gates = fm.module_gates({"src/lib.rs": '// #[cfg(feature = "api")]\n// mod x;\nmod y;\n', "src/y.rs": ""})
    assert gates["src/y.rs"] == alts(set()), gates


def test_edge_a_cfg_on_another_item_does_not_reach_a_later_mod():
    gates = fm.module_gates({"src/lib.rs": '#[cfg(feature = "api")]\nfn f() {}\nmod y;\n', "src/y.rs": ""})
    assert gates["src/y.rs"] == alts(set()), gates


def test_edge_a_doc_attribute_between_cfg_and_mod_keeps_the_gate():
    gates = fm.module_gates({"src/lib.rs": '#[cfg(feature = "api")]\n#[doc(hidden)]\npub mod y;\n', "src/y.rs": ""})
    assert gates["src/y.rs"] == alts({"api"}), gates


def test_edge_a_cfg_test_module_is_ungated():
    gates = fm.module_gates({"src/lib.rs": "#[cfg(test)]\nmod tests;\n", "src/tests.rs": ""})
    assert gates["src/tests.rs"] == alts(set()), gates


def test_edge_an_inner_cfg_in_a_module_file_adds_to_its_gate():
    gates = fm.module_gates({"src/lib.rs": "pub mod x;\n", "src/x.rs": '#![cfg(feature = "g729")]\n'})
    assert gates["src/x.rs"] == alts({"g729"}), gates


def test_edge_a_supporting_test_file_is_ungated():
    gates = fm.module_gates({"tests/support/mod.rs": '#![cfg(feature = "native")]\n'})
    assert "tests/support/mod.rs" not in gates, gates


def test_edge_a_superset_alternative_is_dropped():
    assert fm.cfg_alternatives('any(feature = "a", all(feature = "a", feature = "b"))') == alts({"a"})


def test_edge_a_gate_no_row_compiles_lints_only_the_hook_rows():
    rows, note = choose(["tests/full_test.rs"], {"tests/full_test.rs": alts({"full"})})
    assert names(rows) == HOOK, names(rows)
    assert "full" in note, note


def test_edge_a_gate_only_a_long_row_compiles_picks_that_row():
    table = dict(TABLE, plugins=["native"])
    combos = fm.parse_combos("native hook\nnative,plugins,tui\ntls\n")
    rows, _ = fm.rows_for(["src/p.rs"], {"src/p.rs": alts({"plugins"})}, combos, table)
    assert names(rows) == ["native", "native,plugins,tui"], names(rows)


def test_edge_changed_files_of_no_lines_is_empty():
    assert fm.changed_files("", lambda *a: None) == []


def test_edge_a_deletion_line_adds_no_files():
    assert fm.changed_files(f"refs/heads/x {ZERO} refs/heads/x {'b' * 40}\n", lambda *a: None) == []


def test_edge_changed_files_are_unique_across_refs():
    def git(*args):
        return "" if args[0] == "cat-file" else "src/a.rs"

    text = f"refs/heads/x {'a' * 40} refs/heads/x {'b' * 40}\nrefs/heads/y {'a' * 40} refs/heads/y {'b' * 40}\n"
    assert fm.changed_files(text, git) == ["src/a.rs"]


def test_edge_the_closure_of_an_unknown_feature_is_itself():
    assert fm.feature_closure(TABLE, ["plain"]) == {"plain"}


def test_edge_a_hook_row_is_listed_once_when_also_a_single():
    rows, _ = choose(["src/error.rs"], {"src/error.rs": alts(set())})
    assert names(rows).count("native") == 1, names(rows)


# ---------------------------------------------------------------- the real tree


def real_gates():
    root = REPO
    sources = {}
    for p in list((root / "src").rglob("*.rs")) + list((root / "tests").glob("*.rs")):
        sources[str(p.relative_to(root))] = p.read_text(encoding="utf-8", errors="replace")
    return fm.module_gates(sources)


def real_table():
    import tomllib
    return fm.cargo_features(tomllib.loads((REPO / "Cargo.toml").read_text(encoding="utf-8")))


def test_success_the_real_tree_gates_mcp_and_cli():
    gates = real_gates()
    assert gates["src/mcp/mod.rs"] == alts({"mcp"}), gates.get("src/mcp/mod.rs")
    assert gates["src/cli.rs"] == alts({"native"}), gates.get("src/cli.rs")
    assert gates["src/auth.rs"] == alts({"api"}, {"mcp"}), gates.get("src/auth.rs")
    assert gates["src/error.rs"] == alts(set()), gates.get("src/error.rs")


def test_success_the_real_fallback_lints_12_singles_and_3_hook_rows_and_leaves_7():
    combos = fm.parse_combos((REPO / ".github/feature-combos.txt").read_text(encoding="utf-8"))
    rows, note = fm.rows_for(["src/error.rs"], real_gates(), combos, real_table())
    assert "the 12 single-feature rows and the 3 rows marked `hook`" in note, note
    assert "the other 7 combinations stay in CI" in note, note
    assert len(rows) == 14, names(rows)


def test_edge_the_real_g729_module_change_lints_g729():
    combos = fm.parse_combos((REPO / ".github/feature-combos.txt").read_text(encoding="utf-8"))
    gates = real_gates()
    g729 = [p for p, a in gates.items() if a == alts({"g729"})]
    assert g729, "the tree has a g729-gated module"
    rows, _ = fm.rows_for([g729[0]], gates, combos, real_table())
    assert "g729" in names(rows), names(rows)


# ---------------------------------------------------------------- the command line


def repo_with(tmp_path, combos):
    root = tmp_path / "crate"
    (root / ".github/workflows").mkdir(parents=True)
    if combos is not None:
        (root / ".github/feature-combos.txt").write_text(combos)
    (root / "Cargo.toml").write_text('[package]\nname = "x"\n\n[features]\nnative = []\ntls = []\nplain = []\n')
    (root / "src").mkdir()
    (root / "src/main.rs").write_text('#[cfg(feature = "tls")]\nmod t;\nfn main() {}\n')
    (root / "src/t.rs").write_text("")
    env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
    for args in (["init", "-q", "-b", "work"], ["add", "-A"],
                 ["-c", "user.name=E", "-c", "user.email=e@example.com", "commit", "-q", "-m", "c"]):
        subprocess.run(["git", *args], cwd=root, env=env, check=True, capture_output=True, timeout=60)
    return root


def cli(root, *args, stdin=None):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    return subprocess.run([sys.executable, str(SCRIPT), *args], cwd=root, capture_output=True, text=True,
                          input=stdin, env=env, timeout=120)


def head(root):
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True,
                          check=True).stdout.strip()


def test_success_push_rows_prints_rows_and_a_note(tmp_path):
    root = repo_with(tmp_path, "native hook\ntls\nplain\nnative,tls\n")
    r = cli(root, "--push-rows", stdin=f"refs/heads/x {head(root)} refs/heads/x {ZERO}\n")
    assert r.returncode == 0, r.stdout + r.stderr
    steps = [line.split("\t")[0] for line in r.stdout.splitlines()]
    assert steps == ["lint-native", "lint-tls", "lint-plain"], r.stdout
    assert "feature rows:" in r.stderr and "could not be read" in r.stderr, r.stderr


def test_edge_push_rows_of_an_empty_push_is_the_hook_rows(tmp_path):
    root = repo_with(tmp_path, "native hook\ntls\n")
    r = cli(root, "--push-rows", stdin="")
    assert r.returncode == 0, r.stderr
    assert [line.split("\t")[0] for line in r.stdout.splitlines()] == ["lint-native"], r.stdout


def test_success_lint_row_accepts_an_unmarked_row(tmp_path):
    root = repo_with(tmp_path, "native hook\ntls\n")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "cargo").write_text("#!/bin/sh\nexit 0\n")
    (bin_dir / "cargo").chmod(0o755)
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env["PATH"] = f"{bin_dir}{os.pathsep}{env['PATH']}"
    r = subprocess.run([sys.executable, str(SCRIPT), "--lint-row", "tls"], cwd=root, capture_output=True,
                       text=True, env=env, timeout=120)
    assert r.returncode == 0, r.stdout + r.stderr


def test_success_gate_cache_has_a_step_for_every_lintable_row(tmp_path):
    root = repo_with(tmp_path, "native hook\ntls\nopus needs=cmake\nwasm\n")
    assert set(gc.matrix_rows(root)) == {"lint-native", "lint-tls"}, gc.matrix_rows(root)


def test_edge_the_hook_reads_rows_for_the_push():
    text = (REPO / ".githooks/pre-push").read_text(encoding="utf-8")
    assert 'printf \'%s\\n\' "$PUSH_REFS" | python3 "$FEATURE_MATRIX" --push-rows' in text, \
        "the hook passes its pushed refs to --push-rows"
