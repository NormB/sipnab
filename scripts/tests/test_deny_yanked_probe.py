# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""A yanked crate version fails cargo-deny, in CI and in the pre-push hook.

NO-YANKED-VERSION-CHECK. The owner's dependency rule (2026-11-24, "do not
wait at all") takes a new crate version as soon as it is released and still
refuses a yanked one. Before this check nothing refused it: cargo-deny's
`[advisories] yanked` default is "warn", so `cargo deny check` printed
`warning[yanked]` for a yanked version in Cargo.lock and exited 0 (seen
2026-11-27 with cargo-deny 0.20.2 on autocfg 0.1.3), and OSV-Scanner does not
report a yank.

scripts/deny-yanked-probe.py is the one rule:

* `config_problem` reads deny.toml and requires `[advisories] yanked =
  "deny"`;
* `lock_commands` runs the advisories check on Cargo.lock and on
  fuzz/Cargo.lock, which CI's `cargo deny check` does not read;
* `write_crate` writes a crate whose Cargo.lock holds autocfg 0.1.3, a
  version crates.io lists as yanked (cargo resolves a yanked version only
  from a lock file);
* `verdict` passes only when cargo-deny failed with an `error[yanked]` line
  for exactly that crate and version.

These tests drive each part without the network. Running cargo-deny itself
needs crates.io's index and the advisory database, which a test must not
reach, so the script runs as a step of CI's Security audit job and as a gate
of the pre-push hook, and the wiring tests at the end hold both.
"""

import pathlib
import subprocess
import tomllib
import types

import pytest
from conftest import load

probe = load("deny-yanked-probe")

REPO = pathlib.Path(__file__).resolve().parents[2]
NAME, VERSION, CHECKSUM = probe.YANKED

# cargo-deny 0.20.2's report for the probe crate with `yanked = "deny"`;
# the warning form is what the default "warn" printed, with exit status 0.
ERROR_REPORT = f"""error[yanked]: detected yanked crate (try `cargo update -p {NAME}`)
  ┌─ /tmp/yanked-probe-x/Cargo.lock:1:1
  │
1 │ {NAME} {VERSION} registry+https://github.com/rust-lang/crates.io-index
  │ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ yanked version
  │
  ├ {NAME} v{VERSION}
    └── yanked-probe v0.0.0

advisories FAILED
"""
WARNING_REPORT = ERROR_REPORT.replace("error[yanked]", "warning[yanked]").replace(
    "advisories FAILED", "advisories ok"
)


def deny_toml(advisories_body):
    """A deny.toml whose [advisories] table holds `advisories_body`."""
    return f'[advisories]\n{advisories_body}\nignore = []\n\n[licenses]\nallow = ["MIT"]\n'


# ── deny.toml: [advisories] yanked = "deny" ──────────────────────────────


def test_the_repository_deny_toml_denies_yanked_versions():
    problem = probe.config_problem((REPO / "deny.toml").read_text(encoding="utf-8"))
    assert problem is None, f"deny.toml must refuse a yanked version: {problem}"


@pytest.mark.parametrize(
    "body",
    [
        'yanked = "deny"',
        'yanked="deny"',
        'yanked = "deny"  # refuse a yanked version',
        "yanked = 'deny'",
        '# a comment first\nyanked = "deny"',
        'unmaintained = "none"\nyanked = "deny"',
    ],
)
def test_a_config_that_denies_yanked_versions_passes(body):
    assert probe.config_problem(deny_toml(body)) is None, f"{body!r} denies yanked versions"


def test_an_inline_advisories_table_that_denies_passes():
    text = 'advisories = { yanked = "deny" }\n'
    assert probe.config_problem(text) is None, "an inline [advisories] table is the same table"


@pytest.mark.parametrize(
    ("text", "said"),
    [
        (deny_toml('yanked = "warn"'), '"warn"'),
        (deny_toml('yanked = "allow"'), '"allow"'),
        (deny_toml('yanked = "Deny"'), '"Deny"'),
        (deny_toml('yanked = "deny "'), '"deny "'),
        (deny_toml("yanked = true"), "True"),
        (deny_toml('yanked = ["deny"]'), "['deny']"),
        (deny_toml(""), "no `yanked`"),
        (deny_toml('# yanked = "deny"'), "no `yanked`"),
        ('[licenses]\nallow = ["MIT"]\n', "no [advisories] table"),
        ("", "no [advisories] table"),
        ('advisories = "deny"\n', "no [advisories] table"),
        ('[graph]\nyanked = "deny"\n', "no [advisories] table"),
    ],
)
def test_a_config_that_does_not_deny_yanked_versions_is_refused(text, said):
    problem = probe.config_problem(text)
    assert problem is not None, f"{text!r} does not deny yanked versions"
    assert said in problem, f"the refusal names what it read ({said}): {problem}"


@pytest.mark.parametrize("text", ["[advisories\n", 'yanked = "deny', "[advisories]\nyanked = deny\n"])
def test_a_config_that_is_not_toml_is_refused_and_says_so(text):
    problem = probe.config_problem(text)
    assert problem is not None and "not valid TOML" in problem, f"{text!r}: {problem}"


# ── the probe crate ──────────────────────────────────────────────────────


def test_the_probe_crate_pins_the_yanked_version_and_locks_it(tmp_path):
    manifest = probe.write_crate(tmp_path)
    assert manifest == tmp_path / "Cargo.toml", "write_crate returns the manifest path"
    cargo = tomllib.loads(manifest.read_text(encoding="utf-8"))
    assert cargo["dependencies"] == {NAME: f"={VERSION}"}, "the manifest pins the yanked version exactly"
    assert "workspace" in cargo, "the probe is its own workspace, not a member of an enclosing one"
    assert cargo["package"]["publish"] is False, "the probe crate is never published"
    lock = tomllib.loads((tmp_path / "Cargo.lock").read_text(encoding="utf-8"))
    locked = [p for p in lock["package"] if p["name"] == NAME]
    assert locked == [
        {
            "name": NAME,
            "version": VERSION,
            "source": "registry+https://github.com/rust-lang/crates.io-index",
            "checksum": CHECKSUM,
        }
    ], "Cargo.lock holds the yanked version from crates.io with its checksum"
    assert (tmp_path / "src" / "lib.rs").read_text(encoding="utf-8") == "", "the crate has an empty library"


def test_the_probe_crate_takes_another_yanked_version(tmp_path):
    other = ("some-crate", "1.2.3", "ab" * 32)
    probe.write_crate(tmp_path, other)
    cargo = tomllib.loads((tmp_path / "Cargo.toml").read_text(encoding="utf-8"))
    assert cargo["dependencies"] == {"some-crate": "=1.2.3"}, "the manifest pins the version it is given"
    lock = (tmp_path / "Cargo.lock").read_text(encoding="utf-8")
    assert 'checksum = "' + "ab" * 32 + '"' in lock, "the lock carries the checksum it is given"


def test_the_yanked_version_is_one_crate_with_a_sha256_checksum():
    assert NAME == "autocfg" and VERSION == "0.1.3", "crates.io listed autocfg 0.1.3 as yanked on 2026-11-27"
    assert len(CHECKSUM) == 64 and int(CHECKSUM, 16) >= 0, "the checksum is a sha256 in hex"


def test_the_command_reads_the_repository_deny_toml_and_checks_advisories_only():
    argv = probe.command("cargo-deny", pathlib.Path("/x/Cargo.toml"), pathlib.Path("/r/deny.toml"))
    assert argv == [
        "cargo-deny",
        "--manifest-path",
        "/x/Cargo.toml",
        "--config",
        "/r/deny.toml",
        "check",
        "advisories",
    ], "the probe runs only the advisories check, with the repository's deny.toml"


def test_the_default_config_is_the_repository_deny_toml():
    assert probe.DENY_TOML == REPO / "deny.toml", "the probe judges the deny.toml CI and the hook read"


# ── the verdict on cargo-deny's run ──────────────────────────────────────


@pytest.mark.parametrize("returncode", [1, 2, 101])
def test_a_failed_run_that_names_the_yanked_version_passes(returncode):
    assert probe.verdict(returncode, ERROR_REPORT) is None, "cargo-deny refused the yanked version"


def test_the_verdict_reads_stderr_and_stdout_together():
    assert probe.verdict(1, "advisories FAILED\n" + ERROR_REPORT) is None, "the report may follow other lines"


def test_the_verdict_accepts_the_lock_line_without_the_tree_line():
    text = ERROR_REPORT.replace(f"  ├ {NAME} v{VERSION}\n", "")
    assert probe.verdict(1, text) is None, "the Cargo.lock line names the crate and version too"


def test_the_verdict_accepts_the_tree_line_without_the_lock_line():
    text = ERROR_REPORT.replace(f"1 │ {NAME} {VERSION} registry", "1 │ registry")
    assert probe.verdict(1, text) is None, "the inverse-dependency tree line names the crate and version"


def test_a_run_that_passed_is_refused():
    problem = probe.verdict(0, WARNING_REPORT)
    assert problem is not None and "accepted" in problem, f"exit 0 means the yanked version passed: {problem}"


def test_a_run_that_passed_with_no_output_is_refused():
    assert probe.verdict(0, "") is not None, "exit 0 is a pass of the yanked version whatever it printed"


@pytest.mark.parametrize(
    "output",
    [
        "",
        "error: failed to fetch advisory database\n",
        "error[vulnerability]: something else\n  ├ autocfg v0.1.3\n",
        WARNING_REPORT.replace("advisories ok", "advisories FAILED"),
        ERROR_REPORT.replace(NAME, "other-crate"),
        ERROR_REPORT.replace(VERSION, "0.1.4"),
    ],
)
def test_a_failed_run_for_another_reason_is_refused(output):
    problem = probe.verdict(1, output)
    assert problem is not None, f"a failure that does not name {NAME} {VERSION} as yanked: {output!r}"
    assert "without naming" in problem, f"the refusal says why: {problem}"


@pytest.mark.parametrize(
    "version",
    ["0.1.30", "10.1.3", "0.1.3-beta", "0.1.3.1"],
)
def test_a_longer_version_that_contains_the_yanked_one_is_not_it(version):
    text = ERROR_REPORT.replace(f"{NAME} {VERSION}", f"{NAME} {version}").replace(
        f"{NAME} v{VERSION}", f"{NAME} v{version}"
    )
    assert probe.verdict(1, text) is not None, f"{NAME} {version} is not {NAME} {VERSION}"


@pytest.mark.parametrize("name", ["xautocfg", "autocfg-x", "my_autocfg"])
def test_a_longer_crate_name_that_contains_the_yanked_one_is_not_it(name):
    text = ERROR_REPORT.replace(f"{NAME} {VERSION}", f"{name} {VERSION}").replace(
        f"{NAME} v{VERSION}", f"{name} v{VERSION}"
    )
    assert probe.verdict(1, text) is not None, f"{name} is not {NAME}"


# ── main: the config first, then cargo-deny ──────────────────────────────


class FakeDeny:
    """cargo-deny as main runs it: a lock-file check (no `--config`) answers
    `lock`, the probe crate's check (with `--config`) answers `probe`. Each
    answer is (exit status, output) or an exception to raise. Every call is
    kept with its keyword arguments and, for the probe, the crate's manifest."""

    def __init__(self, lock=(0, "advisories ok\n"), probe=(1, ERROR_REPORT), locks=None):
        self.lock, self.probe, self.locks = lock, probe, locks or {}
        self.calls = []

    def __call__(self, argv, **kwargs):
        is_probe = "--config" in argv
        manifest = None
        if is_probe:
            manifest = pathlib.Path(argv[argv.index("--manifest-path") + 1])
            manifest = (manifest, manifest.read_text(encoding="utf-8"))
        self.calls.append((argv, kwargs, manifest))
        answer = self.probe if is_probe else self.locks.get(" ".join(argv[1:]), self.lock)
        if isinstance(answer, BaseException):
            raise answer
        rc, out = answer
        return types.SimpleNamespace(returncode=rc, stdout="", stderr=out)

    def probe_calls(self):
        return [c for c in self.calls if c[2] is not None]

    def lock_calls(self):
        return [c for c in self.calls if c[2] is None]


def good_config(tmp_path):
    path = tmp_path / "deny.toml"
    path.write_text(deny_toml('yanked = "deny"'), encoding="utf-8")
    return path


def repo_root(tmp_path, fuzz=True):
    root = tmp_path / "repo"
    (root / "fuzz").mkdir(parents=True)
    if fuzz:
        (root / "fuzz" / "Cargo.toml").write_text('[package]\nname = "f"\n', encoding="utf-8")
    return root


def run_main(tmp_path, deny, argv=("probe",), fuzz=True, config=None):
    return probe.main(list(argv), run=deny, config=config or good_config(tmp_path), root=repo_root(tmp_path, fuzz))


def test_main_passes_when_both_locks_pass_and_cargo_deny_refuses_the_yanked_version(tmp_path, capsys):
    deny = FakeDeny()
    assert run_main(tmp_path, deny) == 0, "both lock files passed and the probe was refused"
    out = capsys.readouterr().out
    assert "Cargo.lock: advisories ok" in out and "fuzz/Cargo.lock: advisories ok" in out, out
    assert "cargo-deny refused yanked autocfg 0.1.3" in out, out
    argv, kwargs, (manifest, text) = deny.probe_calls()[0]
    assert argv[0] == "cargo-deny" and argv[-2:] == ["check", "advisories"], f"the default binary: {argv}"
    assert f'{NAME} = "={VERSION}"' in text, "cargo-deny ran on the probe crate"
    assert kwargs.get("timeout"), "the probe's cargo-deny run has a deadline"


def test_main_checks_the_locks_before_the_probe_and_in_the_repository_root(tmp_path):
    deny = FakeDeny()
    run_main(tmp_path, deny)
    kinds = ["probe" if c[2] else "lock" for c in deny.calls]
    assert kinds == ["lock", "lock", "probe"], f"the lock files first, then the probe: {kinds}"
    root = tmp_path / "repo"
    for argv, kwargs, _ in deny.lock_calls():
        assert kwargs.get("cwd") == root, f"{argv} runs in the repository root, which holds deny.toml"
        assert kwargs.get("timeout"), f"{argv} has a deadline"


def test_main_checks_only_cargo_lock_without_a_fuzz_workspace(tmp_path):
    deny = FakeDeny()
    assert run_main(tmp_path, deny, fuzz=False) == 0, "a tree with no fuzz workspace has one lock file"
    assert [c[0][1:] for c in deny.lock_calls()] == [["check", "advisories"]], deny.calls


def test_main_runs_the_binary_it_is_given(tmp_path):
    deny = FakeDeny()
    run_main(tmp_path, deny, argv=("probe", "/opt/cargo-deny"))
    assert {c[0][0] for c in deny.calls} == {"/opt/cargo-deny"}, "argv[1] names the cargo-deny binary for every run"


def test_main_removes_the_probe_crate(tmp_path):
    deny = FakeDeny()
    run_main(tmp_path, deny)
    manifest = deny.probe_calls()[0][2][0]
    assert not manifest.exists(), "the temporary crate is gone after the run"


@pytest.mark.parametrize(
    ("lock", "args"),
    [("Cargo.lock", "check advisories"), ("fuzz/Cargo.lock", "--manifest-path fuzz/Cargo.toml check advisories")],
)
def test_main_fails_on_a_yanked_version_in_a_lock_file_and_names_it(tmp_path, capsys, lock, args):
    report = ERROR_REPORT.replace(NAME, "wasmi").replace(VERSION, "2.0.2")
    deny = FakeDeny(locks={args: (1, report)})
    assert run_main(tmp_path, deny) == 1, f"a yanked version in {lock} refuses the push"
    err = capsys.readouterr().err
    assert f"{lock} fails" in err, f"the failure names the lock file: {err}"
    assert "cargo update -p wasmi" in err, f"the failure keeps cargo-deny's fix: {err}"
    assert f"cargo-deny {args}" in err, f"the failure gives the command to reproduce it: {err}"
    assert deny.probe_calls() == [], "the probe does not run after a lock file failed"


def test_main_fails_on_a_lock_file_failure_that_names_no_yanked_crate_and_shows_the_output(tmp_path, capsys):
    deny = FakeDeny(lock=(1, "error[vulnerability]: RUSTSEC-2099-0001\n"))
    assert run_main(tmp_path, deny) == 1, "any advisories failure of a lock file refuses the push"
    assert "RUSTSEC-2099-0001" in capsys.readouterr().err, "the whole output is shown when no yanked line is"


def test_main_fails_when_cargo_deny_accepts_the_yanked_version(tmp_path, capsys):
    deny = FakeDeny(probe=(0, WARNING_REPORT))
    assert run_main(tmp_path, deny) == 1, "a yanked version that passes cargo-deny fails the probe"
    assert "accepted" in capsys.readouterr().err, "the failure is printed on stderr"


def test_main_fails_when_the_probe_fails_for_another_reason(tmp_path, capsys):
    deny = FakeDeny(probe=(1, "error: failed to fetch advisory database\n"))
    assert run_main(tmp_path, deny) == 1, "a probe run that did not name the yanked version fails"
    assert "without naming" in capsys.readouterr().err


def test_main_fails_on_a_config_that_does_not_deny_and_runs_nothing(tmp_path, capsys):
    path = tmp_path / "deny.toml"
    path.write_text(deny_toml('yanked = "warn"'), encoding="utf-8")
    deny = FakeDeny()
    assert run_main(tmp_path, deny, config=path) == 1, "deny.toml must deny yanked versions before cargo-deny is asked"
    assert deny.calls == [], "cargo-deny is not run against a config that cannot pass"
    assert '"warn"' in capsys.readouterr().err, "the failure names the setting it read"


def test_main_fails_when_the_config_is_missing(tmp_path, capsys):
    deny = FakeDeny()
    assert run_main(tmp_path, deny, config=tmp_path / "none.toml") == 1, "a missing deny.toml fails the probe"
    assert "none.toml" in capsys.readouterr().err, "the failure names the file"
    assert deny.calls == [], "nothing runs without a config"


@pytest.mark.parametrize("where", ["lock", "probe"])
def test_main_fails_when_cargo_deny_is_not_installed(tmp_path, capsys, where):
    deny = FakeDeny(**{where: FileNotFoundError("/no/cargo-deny")})
    assert run_main(tmp_path, deny, argv=("probe", "/no/cargo-deny")) == 1, (
        f"a missing cargo-deny at the {where} step fails, it does not pass"
    )
    assert "/no/cargo-deny is not installed" in capsys.readouterr().err, "the failure names the binary"


@pytest.mark.parametrize("where", ["lock", "probe"])
def test_main_fails_when_cargo_deny_runs_past_its_deadline(tmp_path, capsys, where):
    deny = FakeDeny(**{where: subprocess.TimeoutExpired(["cargo-deny"], probe.TIMEOUT_S)})
    assert run_main(tmp_path, deny) == 1, f"a cargo-deny run past its deadline at the {where} step fails"
    assert "deadline" in capsys.readouterr().err, "the failure says why"


# ── the lock-file commands ───────────────────────────────────────────────


def test_the_lock_commands_cover_both_lock_files_with_the_advisories_check(tmp_path):
    root = repo_root(tmp_path)
    assert probe.lock_commands("cargo-deny", root) == [
        ("Cargo.lock", ["cargo-deny", "check", "advisories"]),
        ("fuzz/Cargo.lock", ["cargo-deny", "--manifest-path", "fuzz/Cargo.toml", "check", "advisories"]),
    ], "the root lock file, then the fuzz workspace's, each with only the advisories check"


def test_the_lock_commands_never_narrow_what_cargo_deny_reads(tmp_path):
    for _, argv in probe.lock_commands("cargo-deny", repo_root(tmp_path)):
        for flag in ("--config", "--features", "--no-default-features", "--exclude", "--all-features"):
            assert flag not in argv, f"{argv}: deny.toml decides the config and the features ({flag})"


def test_the_repository_has_the_fuzz_workspace_the_commands_name():
    names = [lock for lock, _ in probe.lock_commands("cargo-deny", REPO)]
    assert names == ["Cargo.lock", "fuzz/Cargo.lock"], f"this repository has both lock files: {names}"
    for lock in names:
        assert (REPO / lock).is_file(), f"{lock} is tracked"


def test_the_yanked_lines_are_cargo_denys_error_lines_only():
    text = ERROR_REPORT + WARNING_REPORT
    assert probe.yanked_lines(text) == [f"error[yanked]: detected yanked crate (try `cargo update -p {NAME}`)"], (
        "only the refusals, not the warnings"
    )
    assert probe.yanked_lines("") == [], "no output, no lines"


# ── the wiring: CI's Security audit job and the pre-push hook ────────────


def audit_job_steps():
    """The one-line `run:` commands of ci.yml's `audit` job, in order.

    Read as text: scripts/tests import nothing outside the standard library
    (test_script_imports.py)."""
    lines = (REPO / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8").splitlines()
    start = lines.index("  audit:")
    runs = []
    for line in lines[start + 1 :]:
        if line.startswith("  ") and not line.startswith("   ") and line.rstrip().endswith(":"):
            break
        stripped = line.strip()
        if stripped.startswith("run: "):
            runs.append(stripped.removeprefix("run: "))
    return runs


def test_ci_runs_the_probe_after_cargo_deny_in_the_audit_job():
    runs = audit_job_steps()
    deny = runs.index("cargo deny check")
    probe_step = runs.index("python3 scripts/deny-yanked-probe.py")
    assert deny < probe_step, "the audit job runs cargo deny, then checks fuzz/Cargo.lock and the probe"


def test_ci_installs_cargo_deny_before_the_probe():
    text = (REPO / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    audit = text[text.index("\n  audit:\n") :]
    assert audit.index("tool: cargo-deny") < audit.index("run: python3 scripts/deny-yanked-probe.py"), (
        "the probe runs the pinned cargo-deny the job installs"
    )


def pre_push():
    return (REPO / ".githooks" / "pre-push").read_text(encoding="utf-8")


def pre_push_yanked_gate():
    text = pre_push()
    start = text.index("# -- Hard gate: yanked crate versions")
    return text[start : text.index("\n# -- ", start + 1)]


def test_the_pre_push_yanked_gate_runs_the_probe_script():
    assert "python3 scripts/deny-yanked-probe.py" in pre_push_yanked_gate(), (
        "the hook runs the one rule CI runs, not a copy of it"
    )


def test_the_pre_push_yanked_gate_fails_the_push():
    assert "exit 1" in pre_push_yanked_gate(), "a yanked version in either lock file refuses the push"


def test_the_pre_push_yanked_gate_is_never_cached():
    block = pre_push_yanked_gate()
    assert "gate_hit" not in block and "gate_pass" not in block, (
        "a version can be yanked after a push that passed, on the same tree, so no pass stamp skips this gate"
    )


def test_the_pre_push_yanked_gate_runs_on_every_push_including_a_tag():
    """A tag publishes the lock file as it is, so a proven tag-only push and a
    release-only push, which skip the tree gates, still check it."""
    text = pre_push()
    gate = text.index("# -- Hard gate: yanked crate versions")
    opened = closed = 0
    for line in text[:gate].splitlines():
        # A tree-gate block opens with exactly this line and closes with
        # `fi # TREE_PROVEN`; other tests of the variable (`if [ ... ] &&
        # ...`) are ordinary conditions with a plain `fi`.
        if line.strip() == 'if [ "$TREE_PROVEN" = 0 ]; then':
            opened += 1
        elif line.strip() == "fi # TREE_PROVEN":
            closed += 1
    assert opened >= 1, "the scan found no tree-gate block before the gate: it stopped matching"
    assert opened == closed, f"the yanked-version gate sits outside every TREE_PROVEN block ({opened} open, {closed} closed)"


def test_the_pre_push_yanked_gate_says_how_to_reproduce_and_fix():
    block = pre_push_yanked_gate()
    assert "cargo update -p" in block, "the refusal says how to move off a yanked version"
    assert "python3 scripts/deny-yanked-probe.py" in block, "the refusal gives the command to run again"
