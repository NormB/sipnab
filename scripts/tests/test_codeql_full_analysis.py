# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""The CodeQL CLI version is pinned, and a pull request that changes the
CodeQL setup gets a full analysis.

On 2026-11-20 main's CodeQL push run used CLI 2.27.5 where the run before
it used 2.27.4, under the same pinned `github/codeql-action` SHA: the
action picked a newer bundle on its own, and the new release's query
rust/unsafe-deserialization opened two alerts on main in code no pull
request had changed. So the bundle is now named in `tools:`, and a new CLI
arrives only through a pull request that edits codeql.yml.

That pull request has to see alerts in unchanged code. A pull request's
analysis is diff-informed by default: the same day, every pull request
analysis listed `results_count` 0, because only changed lines are reported.
scripts/codeql-full-analysis.py turns diff-informed analysis off
(CODEQL_ACTION_DIFF_INFORMED_QUERIES=false, which codeql-action reads in
src/feature-flags.ts) when a pull request changes the CodeQL workflow or
its config.
"""

import pathlib
import re
import subprocess
import sys

from conftest import SCRIPTS, load

full = load("codeql-full-analysis")

REPO = SCRIPTS.parent
WORKFLOW = REPO / ".github" / "workflows" / "codeql.yml"
ENV_LINE = "CODEQL_ACTION_DIFF_INFORMED_QUERIES=false\n"


def workflow() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def step(name: str) -> str:
    """The text of the workflow step whose `- name:` is `name`."""
    text = workflow()
    start = text.index(f"- name: {name}\n")
    nxt = text.find("\n    - name:", start + 1)
    return text[start:] if nxt < 0 else text[start:nxt]


# ── Success ───────────────────────────────────────────────────────


def test_a_change_to_the_codeql_workflow_needs_a_full_analysis():
    assert full.full_analysis_needed([".github/workflows/codeql.yml"]), "codeql.yml"


def test_a_change_to_the_codeql_config_needs_a_full_analysis():
    assert full.full_analysis_needed([".github/codeql/codeql-config.yml"]), "config"


def test_the_env_line_turns_diff_informed_analysis_off():
    assert full.env_line(["src/main.rs", ".github/workflows/codeql.yml"]) == ENV_LINE, (
        "one codeql.yml among other paths is enough"
    )


def test_the_program_reads_paths_on_stdin_and_prints_the_env_line():
    out = subprocess.run(
        [sys.executable, str(SCRIPTS / "codeql-full-analysis.py")],
        input="README.md\n.github/workflows/codeql.yml\n",
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert (out.returncode, out.stdout) == (0, ENV_LINE), out.stderr


def test_the_init_step_names_an_explicit_bundle_version():
    fetch = step("Fetch the CodeQL bundle (pinned, cached)")
    assert "uses: ./.github/actions/pinned-download" in fetch, fetch
    version = re.search(r"^\s+version: (\d+\.\d+\.\d+)$", fetch, re.M)
    assert version, f"no pinned bundle version:\n{fetch}"
    assert re.search(r"^\s+sha256: [0-9a-f]{64}$", fetch, re.M), f"no sha256:\n{fetch}"
    url = (
        "https://github.com/github/codeql-action/releases/download/"
        f"codeql-bundle-v{version.group(1)}/codeql-bundle-linux64.tar.zst"
    )
    assert re.search(rf"^\s+url: {re.escape(url)}$", fetch, re.M), (
        f"the URL names another bundle than version {version.group(1)}:\n{fetch}"
    )
    init = step("Initialize CodeQL")
    assert re.search(r"^\s+tools: \$\{\{ steps\.codeql-bundle\.outputs\.path \}\}$", init, re.M), (
        f"Initialize CodeQL does not take the verified bundle:\n{init}"
    )
    text = workflow()
    assert re.search(r"^\s+id: codeql-bundle$", fetch, re.M), fetch
    assert text.index("- name: Fetch the CodeQL bundle") < text.index("- name: Initialize CodeQL"), (
        "the bundle is fetched before init"
    )


# ── Failure ───────────────────────────────────────────────────────


def test_a_source_change_keeps_diff_informed_analysis():
    assert not full.full_analysis_needed(["src/output/api.rs"]), "a source file"


def test_a_change_to_another_workflow_keeps_diff_informed_analysis():
    assert not full.full_analysis_needed([".github/workflows/ci.yml"]), "ci.yml"


def test_no_change_prints_nothing():
    assert full.env_line([]) == "", "no paths"


def test_the_program_prints_nothing_for_other_paths():
    out = subprocess.run(
        [sys.executable, str(SCRIPTS / "codeql-full-analysis.py")],
        input="src/lib.rs\ndocs/rest-api.md\n",
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert (out.returncode, out.stdout) == (0, ""), out.stderr


def test_tools_is_not_a_moving_value():
    init = step("Initialize CodeQL")
    for moving in ("tools: linked", "tools: nightly", "tools: toolcache", "tools: latest"):
        assert moving not in init, f"{moving} lets the CLI change without a pull request"


# ── Edge ──────────────────────────────────────────────────────────


def test_a_path_that_only_starts_like_the_config_dir_is_not_it():
    assert not full.full_analysis_needed([".github/codeql-notes.md"]), "not the dir"


def test_a_path_named_codeql_yml_elsewhere_is_not_the_workflow():
    assert not full.full_analysis_needed(["docs/codeql.yml"]), "not the workflow"


def test_blank_lines_and_surrounding_space_are_ignored():
    assert full.paths_from("\n  .github/workflows/codeql.yml  \n\n") == [
        ".github/workflows/codeql.yml"
    ], "one path from padded input"


def test_the_full_analysis_step_runs_before_init_on_pull_requests_only():
    text = workflow()
    decide = step("Turn off diff-informed analysis when the CodeQL setup changes")
    assert "if: github.event_name == 'pull_request'" in decide, decide
    assert "scripts/codeql-full-analysis.py" in decide, decide
    assert '"$GITHUB_ENV"' in decide, decide
    assert "git diff --name-only HEAD^1 HEAD" in decide, decide
    assert text.index("- name: Turn off diff-informed analysis") < text.index(
        "- name: Initialize CodeQL"
    ), "the env var must be set before init reads its features"


def test_checkout_keeps_the_merge_commits_first_parent():
    checkout = step("Checkout repository")
    assert re.search(r"^\s+fetch-depth: 2$", checkout, re.M), (
        f"HEAD^1 of the pull request merge commit needs fetch-depth 2:\n{checkout}"
    )


def test_the_pinned_bundle_and_the_paths_rule_agree_with_the_script():
    # The script's rule names the workflow file the test reads.
    assert pathlib.Path(".github/workflows/codeql.yml").as_posix() in full.WATCHED_FILES, (
        "the workflow file is watched"
    )
