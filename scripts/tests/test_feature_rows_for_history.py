# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""The two failures behind the by-hand feature-matrix rule, against `--push-rows`.

FEATURE-MATRIX-BY-HAND-COST. Agents were told to run the whole matrix
(`python3 scripts/check-feature-matrix.py`, every row, 20+ minutes of the main
slot) before pushing a change to `#[cfg(...)]` code or a test seam, because of
two failures:

* #826 (2026-11-16, CI "Features (group 1, aarch64)"):
  `cargo clippy --no-default-features --features g729 --tests -- -D warnings`
  refused "function `read_quoted_body` is never used". The function sat in
  src/app/https_client.rs, a module compiled for g729, vcon and api; only the
  vcon and api modules called it. Fixed by 500a02076. The pre-push hook then
  linted only the three rows marked `hook`; `--push-rows` (#836) came a day
  later.
* 2026-11-23, merge-train tip: the `#[cfg(test)]` seam `sdp_parses_during` in
  src/sip/sdp.rs (an ungated module) was called only by tests of modules gated
  on `native`, so `--no-default-features --features tls --tests` refused it as
  never used. Fixed by b687b9a0d.

A third case came after the rule was retired, as a check of the retirement:

* 2026-11-27, branch fix/reassembly-tally-race (before its fix): test-only
  helpers in src/capture/mod.rs and src/capture/reassembly.rs (ungated
  modules), called only by tests gated on `native`, failed the `tls` and
  `audio` rows with "methods `undecodable_frames` and `captured_packets` are
  never used" and "function `ledger_here` is never used". The fix gates them
  on `all(not(target_arch = "wasm32"), feature = "native")`.

Each failure is rebuilt here as a crate of a few lines with the same module
gates, a base commit and the commit that adds the defect, and the fixed tree.
The rows come from the REAL .github/feature-combos.txt and the REAL Cargo
[features] table (feature-to-feature entries only), so a change to the matrix
or to `rows_for` that drops the failing row turns these tests red. The
end-to-end tests run the real `cargo clippy` row command (`--lint-row`) on the
fixture: the selected row fails with the warning CI printed, the same row
passes on the fixed tree, and the `native` hook row passes on the broken tree
(the gap the hook had before `--push-rows`).
"""

import os
import pathlib
import shutil
import subprocess
import sys
import tomllib

import pytest
from conftest import load

REPO = pathlib.Path(__file__).resolve().parent.parent.parent
SCRIPT = REPO / "scripts/check-feature-matrix.py"

fm = load("check-feature-matrix")

# ---------------------------------------------------------------- the fixtures

# #826: https_client compiled for g729 alone first; the change widens its gate
# to vcon and api and adds read_quoted_body, which only vcon and api call.
F826_BASE = {
    "src/lib.rs": '#[cfg(feature = "native")]\npub mod app;\n',
    "src/app/mod.rs": (
        '#[cfg(feature = "g729")]\n'
        "pub(crate) mod https_client;\n"
        '#[cfg(feature = "g729")]\n'
        "pub mod g729_install;\n"
    ),
    "src/app/https_client.rs": (
        "/// Reads a body of `len` bytes.\n"
        "pub(crate) fn read_body(len: usize) -> usize {\n"
        "    len\n"
        "}\n"
    ),
    "src/app/g729_install.rs": (
        "/// Downloads the codec.\n"
        "pub fn install() -> usize {\n"
        "    super::https_client::read_body(1)\n"
        "}\n"
    ),
}
F826_QUOTED = (
    "/// At most `keep` bytes of a body quoted to a person.\n"
    "{gate}pub(crate) fn read_quoted_body(len: usize, keep: usize) -> usize {{\n"
    "    len.min(keep)\n"
    "}}\n"
)
F826_CALLER = (
    "/// Fetches a document.\n"
    "pub fn fetch() -> usize {\n"
    "    super::https_client::read_body(2) + super::https_client::read_quoted_body(3, 1)\n"
    "}\n"
)


def f826(gate: str) -> dict[str, str]:
    """The #826 tree; `gate` is the attribute line on read_quoted_body."""
    return F826_BASE | {
        "src/app/mod.rs": (
            '#[cfg(any(feature = "g729", feature = "vcon", feature = "api"))]\n'
            "pub(crate) mod https_client;\n"
            '#[cfg(feature = "g729")]\n'
            "pub mod g729_install;\n"
            '#[cfg(feature = "vcon")]\n'
            "pub mod vcon_fetch;\n"
            '#[cfg(feature = "api")]\n'
            "pub mod fleet_member;\n"
        ),
        "src/app/https_client.rs": F826_BASE["src/app/https_client.rs"] + F826_QUOTED.format(gate=gate),
        "src/app/vcon_fetch.rs": F826_CALLER,
        "src/app/fleet_member.rs": F826_CALLER,
    }


F826_BROKEN = f826("")
F826_FIXED = f826('#[cfg(any(feature = "vcon", feature = "api"))]\n')
F826_DEFINITION = "src/app/https_client.rs"

# 2026-11-23: a test seam in an ungated module, read only by tests of a module
# gated on `native`.
F1123_BASE = {
    "src/lib.rs": 'pub mod sip;\n#[cfg(feature = "native")]\npub mod pipeline;\n',
    "src/sip.rs": (
        "/// Parses an SDP body.\n"
        "pub fn parse_sdp(body: &str) -> usize {\n"
        "    body.len()\n"
        "}\n"
    ),
    "src/pipeline.rs": (
        "/// Runs the pipeline over one body.\n"
        "pub fn run(body: &str) -> usize {\n"
        "    crate::sip::parse_sdp(body)\n"
        "}\n"
    ),
}
F1123_SEAM = (
    "\n/// What `f` returns, run as a test seam around the parser.\n"
    "{gate}\n"
    "pub(crate) fn sdp_parses_during(f: impl FnOnce() -> usize) -> usize {{\n"
    "    f()\n"
    "}}\n"
)
F1123_TEST = (
    "\n#[cfg(test)]\n"
    "mod tests {\n"
    "    #[test]\n"
    "    fn the_pipeline_parses_the_body() {\n"
    '        let got = crate::sip::sdp_parses_during(|| super::run("v=0"));\n'
    '        assert_eq!(got, 3, "the pipeline parses the three bytes of the body");\n'
    "    }\n"
    "}\n"
)


def f1123(gate: str) -> dict[str, str]:
    """The 2026-11-23 tree; `gate` is the attribute on the seam."""
    return F1123_BASE | {
        "src/sip.rs": F1123_BASE["src/sip.rs"] + F1123_SEAM.format(gate=gate),
        "src/pipeline.rs": F1123_BASE["src/pipeline.rs"] + F1123_TEST,
    }


F1123_BROKEN = f1123("#[cfg(test)]")
F1123_FIXED = f1123('#[cfg(all(test, feature = "native"))]')
F1123_DEFINITION = "src/sip.rs"

# 2026-11-27: test-only helpers in two ungated capture modules, read only by
# tests of a module gated on `native`.
FRACE_BASE = {
    "src/lib.rs": 'pub mod capture;\n#[cfg(feature = "native")]\npub mod parallel;\n',
    "src/capture/mod.rs": (
        "pub mod reassembly;\n\n"
        "/// What a capture counted.\n"
        "#[derive(Default)]\n"
        "pub struct Tally {\n"
        "    /// Frames that did not decode.\n"
        "    pub undecodable: u64,\n"
        "    /// Packets captured.\n"
        "    pub captured: u64,\n"
        "}\n"
    ),
    "src/capture/reassembly.rs": (
        "/// Reassembles one stream.\n"
        "pub fn reassemble(len: usize) -> usize {\n"
        "    len\n"
        "}\n"
    ),
    "src/parallel.rs": (
        "/// Runs the workers over one capture.\n"
        "pub fn run() -> crate::capture::Tally {\n"
        "    crate::capture::Tally { undecodable: 1, captured: crate::capture::reassembly::reassemble(2) as u64 }\n"
        "}\n"
    ),
}
FRACE_METHODS = (
    "\n{gate}\n"
    "impl Tally {{\n"
    "    pub(crate) fn undecodable_frames(&self) -> u64 {{\n"
    "        self.undecodable\n"
    "    }}\n\n"
    "    pub(crate) fn captured_packets(&self) -> u64 {{\n"
    "        self.captured\n"
    "    }}\n"
    "}}\n"
)
FRACE_LEDGER = (
    "\n/// The reassembly ledger of this thread, read by tests.\n"
    "{gate}\n"
    "pub(crate) fn ledger_here() -> Option<usize> {{\n"
    "    Some(reassemble(0))\n"
    "}}\n"
)
FRACE_TEST = (
    "\n#[cfg(test)]\n"
    "mod tests {\n"
    "    #[test]\n"
    "    fn the_workers_tally_every_packet() {\n"
    "        let t = super::run();\n"
    '        assert_eq!(t.captured_packets(), 2, "both packets are counted");\n'
    '        assert_eq!(t.undecodable_frames(), 1, "one frame did not decode");\n'
    '        assert_eq!(crate::capture::reassembly::ledger_here(), Some(0), "the ledger is empty");\n'
    "    }\n"
    "}\n"
)


def frace(gate: str) -> dict[str, str]:
    """The fix/reassembly-tally-race tree; `gate` is the attribute on the helpers."""
    return FRACE_BASE | {
        "src/capture/mod.rs": FRACE_BASE["src/capture/mod.rs"] + FRACE_METHODS.format(gate=gate),
        "src/capture/reassembly.rs": FRACE_BASE["src/capture/reassembly.rs"] + FRACE_LEDGER.format(gate=gate),
        "src/parallel.rs": FRACE_BASE["src/parallel.rs"] + FRACE_TEST,
    }


FRACE_BROKEN = frace("#[cfg(test)]")
FRACE_FIXED = frace('#[cfg(all(test, not(target_arch = "wasm32"), feature = "native"))]')
FRACE_DEFINITION = "src/capture/reassembly.rs"


def changed(base, tree):
    return sorted(p for p in tree if base.get(p) != tree[p])


def real_combos():
    return fm.parse_combos((REPO / ".github/feature-combos.txt").read_text(encoding="utf-8"))


def real_table():
    return fm.cargo_features(tomllib.loads((REPO / "Cargo.toml").read_text(encoding="utf-8")))


def names(rows):
    return [r.features for r in rows]


def choose(paths, tree):
    return fm.rows_for(paths, fm.module_gates(tree), real_combos(), real_table())


# ---------------------------------------------------------------- the rows rows_for picks


def test_success_the_826_change_lints_g729():
    rows, note = choose(changed(F826_BASE, F826_BROKEN), F826_BROKEN)
    assert "g729" in names(rows), (names(rows), note)


def test_success_the_1123_change_lints_tls():
    rows, note = choose(changed(F1123_BASE, F1123_BROKEN), F1123_BROKEN)
    assert "tls" in names(rows), (names(rows), note)


def test_edge_the_826_definition_file_alone_lints_g729():
    rows, note = choose([F826_DEFINITION], F826_BROKEN)
    assert "g729" in names(rows), (names(rows), note)


def test_edge_the_1123_seam_file_alone_lints_tls():
    rows, note = choose([F1123_DEFINITION], F1123_BROKEN)
    assert "tls" in names(rows), (names(rows), note)


def test_edge_the_826_rows_come_from_the_gates_not_the_fallback():
    # Every changed file is gated, as src/app/https_client.rs was on
    # 2026-11-16 (native and one of g729, vcon, api): g729 is picked as a
    # row that compiles the gate, not by the every-single-row fallback.
    gates = fm.module_gates(F826_BROKEN)
    assert gates[F826_DEFINITION] == [frozenset({"api", "native"}), frozenset({"g729", "native"}),
                                      frozenset({"native", "vcon"})], gates[F826_DEFINITION]
    _rows, note = choose(changed(F826_BASE, F826_BROKEN), F826_BROKEN)
    assert "every changed Rust file is behind a feature gate" in note, note


def test_failure_the_hook_rows_alone_do_not_lint_g729():
    # Before --push-rows the hook linted only these rows: #826 passed them.
    marked = [c.features for c in real_combos() if c.hook]
    assert marked and "g729" not in marked, marked


def test_failure_the_hook_rows_alone_do_not_lint_tls():
    marked = [c.features for c in real_combos() if c.hook]
    assert marked and "tls" not in marked, marked


def test_success_the_race_change_lints_tls_and_audio():
    rows, note = choose(changed(FRACE_BASE, FRACE_BROKEN), FRACE_BROKEN)
    assert {"tls", "audio"} <= set(names(rows)), (names(rows), note)


def test_edge_the_race_reassembly_file_alone_lints_tls_and_audio():
    rows, note = choose([FRACE_DEFINITION], FRACE_BROKEN)
    assert {"tls", "audio"} <= set(names(rows)), (names(rows), note)


def test_failure_the_hook_rows_alone_do_not_lint_audio():
    marked = [c.features for c in real_combos() if c.hook]
    assert marked and "audio" not in marked, marked


# ---------------------------------------------------------------- the real lint on the fixtures


def fixture_crate(root: pathlib.Path, base, tree) -> tuple[str, str]:
    """A git repository holding `base` then `tree`; returns (base, head)."""
    table = real_table()
    features = "\n".join(
        f'{name} = [{", ".join(chr(34) + e + chr(34) for e in entries if ":" not in e and "/" not in e)}]'
        for name, entries in table.items()
    )
    root.mkdir(parents=True)
    (root / "Cargo.toml").write_text(
        '[package]\nname = "fixture"\nversion = "0.0.0"\nedition = "2021"\npublish = false\n\n'
        f"[workspace]\n\n[features]\n{features}\n", encoding="utf-8")
    (root / ".github").mkdir()
    shutil.copy(REPO / ".github/feature-combos.txt", root / ".github/feature-combos.txt")
    env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")

    def git(*args):
        return subprocess.run(["git", *args], cwd=root, env=env, check=True, capture_output=True,
                              text=True, timeout=60).stdout.strip()

    def commit(files, message):
        for path, text in files.items():
            (root / path).parent.mkdir(parents=True, exist_ok=True)
            (root / path).write_text(text, encoding="utf-8")
        git("add", "-A")
        git("-c", "user.name=E", "-c", "user.email=e@example.com", "-c", "commit.gpgsign=false",
            "commit", "-q", "-m", message)
        return git("rev-parse", "HEAD")

    git("init", "-q", "-b", "work")
    first = commit(base, "base")
    for path in set(base) - set(tree):
        (root / path).unlink()
    return first, commit(tree, "change")


def run(root, *args, stdin=None):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env["CARGO_TARGET_DIR"] = str(root / "target")
    env["CARGO_NET_OFFLINE"] = "true"
    env["CARGO_TERM_COLOR"] = "never"
    return subprocess.run([sys.executable, str(SCRIPT), *args], cwd=root, capture_output=True, text=True,
                          input=stdin, env=env, timeout=600)


@pytest.fixture(scope="module")
def crates(tmp_path_factory):
    if shutil.which("cargo") is None:
        pytest.fail("cargo is required: these tests run the real clippy row command")
    top = tmp_path_factory.mktemp("history")
    made = {}
    for name, base, tree in (("826", F826_BASE, F826_BROKEN), ("826-fixed", F826_BASE, F826_FIXED),
                             ("1123", F1123_BASE, F1123_BROKEN), ("1123-fixed", F1123_BASE, F1123_FIXED),
                             ("race", FRACE_BASE, FRACE_BROKEN), ("race-fixed", FRACE_BASE, FRACE_FIXED)):
        made[name] = (top / name, *fixture_crate(top / name, base, tree))
    return made


def push_steps(crate):
    root, base, head = crate
    r = run(root, "--push-rows", stdin=f"refs/heads/work {head} refs/heads/work {base}\n")
    assert r.returncode == 0, r.stdout + r.stderr
    return [line.split("\t")[0] for line in r.stdout.splitlines()], r.stderr


def test_failure_the_826_fixture_fails_the_g729_row_push_rows_picks(crates):
    steps, note = push_steps(crates["826"])
    assert "lint-g729" in steps, (steps, note)
    r = run(crates["826"][0], "--lint-row", "g729")
    assert r.returncode == 1, r.stdout + r.stderr
    assert "function `read_quoted_body` is never used" in r.stderr, r.stderr


def test_success_the_826_fixed_tree_passes_the_g729_row(crates):
    r = run(crates["826-fixed"][0], "--lint-row", "g729")
    assert r.returncode == 0, r.stdout + r.stderr


def test_edge_the_826_fixture_passes_the_native_hook_row(crates):
    r = run(crates["826"][0], "--lint-row", "native")
    assert r.returncode == 0, r.stdout + r.stderr


def test_failure_the_1123_fixture_fails_the_tls_row_push_rows_picks(crates):
    steps, note = push_steps(crates["1123"])
    assert "lint-tls" in steps, (steps, note)
    r = run(crates["1123"][0], "--lint-row", "tls")
    assert r.returncode == 1, r.stdout + r.stderr
    assert "function `sdp_parses_during` is never used" in r.stderr, r.stderr


def test_success_the_1123_fixed_tree_passes_the_tls_row(crates):
    r = run(crates["1123-fixed"][0], "--lint-row", "tls")
    assert r.returncode == 0, r.stdout + r.stderr


def test_edge_the_1123_fixture_passes_the_native_hook_row(crates):
    r = run(crates["1123"][0], "--lint-row", "native")
    assert r.returncode == 0, r.stdout + r.stderr


RACE_WARNINGS = ("methods `undecodable_frames` and `captured_packets` are never used",
                 "function `ledger_here` is never used")


def test_failure_the_race_fixture_fails_the_tls_row_push_rows_picks(crates):
    steps, note = push_steps(crates["race"])
    assert "lint-tls" in steps, (steps, note)
    r = run(crates["race"][0], "--lint-row", "tls")
    assert r.returncode == 1, r.stdout + r.stderr
    for warning in RACE_WARNINGS:
        assert warning in r.stderr, (warning, r.stderr)


def test_failure_the_race_fixture_fails_the_audio_row_push_rows_picks(crates):
    steps, note = push_steps(crates["race"])
    assert "lint-audio" in steps, (steps, note)
    r = run(crates["race"][0], "--lint-row", "audio")
    assert r.returncode == 1, r.stdout + r.stderr
    for warning in RACE_WARNINGS:
        assert warning in r.stderr, (warning, r.stderr)


def test_success_the_race_fixed_tree_passes_the_tls_and_audio_rows(crates):
    for row in ("tls", "audio"):
        r = run(crates["race-fixed"][0], "--lint-row", row)
        assert r.returncode == 0, (row, r.stdout + r.stderr)


def test_edge_the_race_fixture_passes_the_native_hook_row(crates):
    r = run(crates["race"][0], "--lint-row", "native")
    assert r.returncode == 0, r.stdout + r.stderr
