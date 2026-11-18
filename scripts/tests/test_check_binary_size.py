# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""scripts/check-binary-size.sh and the pull-request job that runs it
(backlog GATE-SIZE1 and MUSL-SIZE-KNOWN-ONLY-AT-TAG).

The published x86_64 musl binary has a size ceiling, binary_size_ceiling_mb
in website/config.toml, which the homepage and the build docs quote. Only
release.yml measured it, in the build job of a tag push. #534 grew the
binary by 16.97% and the first v0.5.228 Release run failed its size step at
22,685,568 bytes against 20 MB, after GHCR had already received the image.
No pull-request or main workflow built a musl target.

The check now lives in one script. release.yml's size step runs it on every
musl artifact, and .github/workflows/binary-size.yml runs it on pull
requests that change what the size depends on beyond the source (the
manifests, the lockfile, the build scripts, the ceiling), weekly for growth
in src/, and on demand. That job builds x86_64-unknown-linux-musl the way
release.yml does: the same feature set, scripts/reproducible-build.sh with
cross, and the same symbol split before measuring.

The script is driven here with files of chosen sizes. The job's build is
not: it needs cross's container and a full LTO release build, tens of
minutes on a GitHub-hosted runner. What is tested of the job is its wiring,
against release.yml's own steps; the build runs on every pull request that
changes one of the job's paths, including the one that added it.
"""

import pathlib
import re
import subprocess

import pytest
import yaml

from conftest import SCRIPTS

ROOT = SCRIPTS.parent
SCRIPT = SCRIPTS / "check-binary-size.sh"
MB = 1024 * 1024


def config(tmp_path, line='binary_size_ceiling_mb = "25"', before="", after=""):
    path = tmp_path / "config.toml"
    path.write_text(f'title = "x"\n{before}{line}\n{after}')
    return path


def binary(tmp_path, size, name="sipnab"):
    path = tmp_path / name
    with open(path, "wb") as f:
        f.truncate(size)
    return path


def run(*args, cwd=None):
    p = subprocess.run(["bash", str(SCRIPT), *map(str, args)], capture_output=True, text=True,
                       timeout=60, cwd=cwd or ROOT)
    return p.returncode, p.stdout, p.stderr


# ---- success ---------------------------------------------------------------


@pytest.mark.parametrize("size", [1, 25 * MB - 1, 25 * MB, 12 * MB + 345])
def test_a_binary_at_or_under_the_ceiling_passes(tmp_path, size):
    rc, out, err = run(binary(tmp_path, size), config(tmp_path))
    assert rc == 0, out + err


def test_the_measurement_names_the_bytes_the_megabytes_and_the_ceiling(tmp_path):
    rc, out, _ = run(binary(tmp_path, 25_184_768), config(tmp_path))
    assert rc == 0
    assert "is 25184768 bytes (24.01 MB), ceiling 25 MB" in out, out


def test_a_pass_reports_the_margin_left_as_a_notice(tmp_path):
    rc, out, _ = run(binary(tmp_path, 24 * MB), config(tmp_path))
    assert rc == 0
    assert "::notice::" in out and f"{MB} bytes under" in out, out


def test_the_default_ceiling_is_the_repositorys_own(tmp_path):
    want = re.search(r'^binary_size_ceiling_mb = "(\d+)"', (ROOT / "website/config.toml").read_text(), re.M)
    rc, out, _ = run(binary(tmp_path, 1))
    assert rc == 0 and f"ceiling {int(want.group(1))} MB" in out, out


def test_the_default_ceiling_is_found_from_another_directory(tmp_path):
    rc, out, err = run(binary(tmp_path, 1), cwd=tmp_path)
    assert rc == 0, out + err


def test_other_keys_before_the_ceiling_are_skipped(tmp_path):
    rc, out, _ = run(binary(tmp_path, 1), config(tmp_path, before='other_mb = "1"\n'))
    assert rc == 0 and "ceiling 25 MB" in out, out


@pytest.mark.parametrize("ceiling", [1, 1000])
def test_any_whole_ceiling_is_read(tmp_path, ceiling):
    rc, out, _ = run(binary(tmp_path, 1), config(tmp_path, f'binary_size_ceiling_mb = "{ceiling}"'))
    assert rc == 0 and f"ceiling {ceiling} MB" in out, out


def test_a_path_with_spaces_is_measured(tmp_path):
    rc, out, err = run(binary(tmp_path, 10, name="my sipnab"), config(tmp_path))
    assert rc == 0 and "is 10 bytes" in out, out + err


# ---- failure ---------------------------------------------------------------


@pytest.mark.parametrize("size", [25 * MB + 1, 22_685_568 + 25 * MB, 26 * MB])
def test_a_binary_over_the_ceiling_fails(tmp_path, size):
    rc, out, err = run(binary(tmp_path, size), config(tmp_path))
    assert rc == 1, out + err
    assert f"::error::" in out and f"is {size} bytes, over the 25 MB" in out, out


def test_the_failure_says_what_to_change(tmp_path):
    _, out, _ = run(binary(tmp_path, 26 * MB), config(tmp_path))
    assert "binary_size_ceiling_mb in website/config.toml" in out, out


def test_a_missing_binary_cannot_be_measured(tmp_path):
    rc, out, err = run(tmp_path / "absent", config(tmp_path))
    assert rc == 2 and "cannot measure" in err, out + err


def test_a_directory_is_not_a_binary(tmp_path):
    rc, _, err = run(tmp_path, config(tmp_path))
    assert rc == 2 and "cannot measure" in err, err


def test_an_empty_file_is_not_a_binary(tmp_path):
    rc, _, err = run(binary(tmp_path, 0), config(tmp_path))
    assert rc == 2 and "empty" in err, err


@pytest.mark.parametrize("args", [(), ("a", "b", "c")])
def test_a_wrong_argument_count_prints_the_usage(args):
    rc, _, err = run(*args)
    assert rc == 2 and "usage:" in err, err


def test_a_missing_config_cannot_give_a_ceiling(tmp_path):
    rc, _, err = run(binary(tmp_path, 1), tmp_path / "none.toml")
    assert rc == 2 and "binary_size_ceiling_mb" in err, err


@pytest.mark.parametrize("line", ['other = "25"', 'binary_size_ceiling_mb = "x25"', 'binary_size_ceiling_mb = ""',
                                  'binary_size_ceiling_mb = "0"', '# binary_size_ceiling_mb = "25"',
                                  'binary_size_ceiling_mb = 25'])
def test_a_ceiling_that_is_missing_or_not_a_positive_whole_number_is_refused(tmp_path, line):
    rc, out, err = run(binary(tmp_path, 1), config(tmp_path, line))
    assert rc == 2, out + err
    assert "binary_size_ceiling_mb" in err, err


# ---- edges -----------------------------------------------------------------


def test_a_leading_zero_is_decimal_not_octal(tmp_path):
    rc, out, _ = run(binary(tmp_path, 22 * MB), config(tmp_path, 'binary_size_ceiling_mb = "025"'))
    assert rc == 0 and "ceiling 25 MB" in out, f"025 is 25, not octal 21: {out}"


def test_the_first_ceiling_line_wins(tmp_path):
    rc, out, _ = run(binary(tmp_path, 1), config(tmp_path, after='binary_size_ceiling_mb = "99"\n'))
    assert rc == 0 and "ceiling 25 MB" in out, out


def test_a_binary_over_four_gigabytes_is_measured_in_64_bits(tmp_path):
    rc, out, _ = run(binary(tmp_path, 5 * 1024 * MB), config(tmp_path, 'binary_size_ceiling_mb = "6000"'))
    assert rc == 0 and f"is {5 * 1024 * MB} bytes" in out, out


def test_a_symlink_is_measured_by_the_file_it_names(tmp_path):
    real = binary(tmp_path, 25 * MB + 1)
    link = tmp_path / "link"
    link.symlink_to(real)
    rc, out, _ = run(link, config(tmp_path))
    assert rc == 1, f"the link's own few bytes are not the binary: {out}"


@pytest.mark.parametrize("size,shown", [(52_429, "(0.05 MB)"), (52_428, "(0.04 MB)")])
def test_the_megabytes_keep_two_decimals_and_truncate(tmp_path, size, shown):
    _, out, _ = run(binary(tmp_path, size), config(tmp_path))
    assert shown in out, f"0.05 MB is 52,428.8 bytes; release.yml truncated, never rounded: {out}"


def test_a_trailing_comment_after_the_ceiling_is_allowed(tmp_path):
    rc, out, _ = run(binary(tmp_path, 1), config(tmp_path, 'binary_size_ceiling_mb = "25"  # MB'))
    assert rc == 0 and "ceiling 25 MB" in out, out


def test_a_crlf_config_line_is_read(tmp_path):
    rc, out, _ = run(binary(tmp_path, 1), config(tmp_path, 'binary_size_ceiling_mb = "25"\r'))
    assert rc == 0 and "ceiling 25 MB" in out, out


def test_one_byte_over_a_one_megabyte_ceiling_fails(tmp_path):
    rc, out, _ = run(binary(tmp_path, MB + 1), config(tmp_path, 'binary_size_ceiling_mb = "1"'))
    assert rc == 1, out


def test_exactly_at_the_ceiling_is_zero_bytes_under(tmp_path):
    _, out, _ = run(binary(tmp_path, 25 * MB), config(tmp_path))
    assert "0 bytes under" in out, out


def test_a_relative_binary_path_is_read_from_the_callers_directory(tmp_path):
    binary(tmp_path, 7)
    rc, out, err = run("sipnab", config(tmp_path), cwd=tmp_path)
    assert rc == 0 and "is 7 bytes" in out, out + err


def test_the_ceiling_key_indented_is_not_the_top_level_key(tmp_path):
    rc, _, err = run(binary(tmp_path, 1), config(tmp_path, '  binary_size_ceiling_mb = "25"'))
    assert rc == 2, "the key is read at the start of a line only, as release.yml read it"


def test_a_commented_out_ceiling_above_the_real_one_is_skipped(tmp_path):
    cfg = config(tmp_path, 'binary_size_ceiling_mb = "30"', before='# binary_size_ceiling_mb = "20" (old)\n')
    rc, out, _ = run(binary(tmp_path, 22 * MB), cfg)
    assert rc == 0 and "ceiling 30 MB" in out, out


# ---- release.yml: the one rule, at the tag ---------------------------------


def release_steps():
    wf = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())
    return wf["jobs"]["build"]["steps"]


def test_the_release_size_step_runs_the_script_on_the_musl_artifact():
    step = next(s for s in release_steps() if s.get("name") == "Enforce published binary size (musl targets)")
    assert step["if"] == "contains(matrix.target, '-linux-musl')"
    assert 'bash scripts/check-binary-size.sh "target/${{ matrix.target }}/release/sipnab"' in step["run"], step


def test_the_release_size_step_holds_no_rule_of_its_own():
    step = next(s for s in release_steps() if s.get("name") == "Enforce published binary size (musl targets)")
    assert "binary_size_ceiling_mb" not in step["run"] and "1024" not in step["run"], step["run"]


# ---- binary-size.yml: the same rule, on pull requests ----------------------


def size_workflow():
    return yaml.safe_load((ROOT / ".github/workflows/binary-size.yml").read_text())


def size_steps():
    return size_workflow()["jobs"]["binary-size"]["steps"]


def triggers():
    wf = size_workflow()
    return wf.get("on", wf.get(True))


@pytest.mark.parametrize("path", ["Cargo.toml", "Cargo.lock", "build.rs", "build_script/**", ".cargo/**",
                                  "Cross.toml", "docker/cross/**", "website/config.toml",
                                  "scripts/check-binary-size.sh", "scripts/reproducible-build.sh",
                                  "scripts/split-debuginfo.sh", ".github/workflows/binary-size.yml",
                                  ".github/workflows/release.yml"])
def test_a_pull_request_that_changes_what_the_size_depends_on_runs_the_job(path):
    assert path in triggers()["pull_request"]["paths"], triggers()["pull_request"]


def test_the_job_also_runs_weekly_and_on_demand_for_growth_in_the_source():
    t = triggers()
    assert "workflow_dispatch" in t and t["schedule"][0]["cron"], t


def test_the_job_builds_the_x86_64_musl_target_with_cross_as_the_release_does():
    runs = "\n".join(s.get("run", "") for s in size_steps())
    assert 'bash scripts/reproducible-build.sh build x86_64-unknown-linux-musl "$FEATURES" cross' in runs, runs


CROSS = re.compile(r"cargo install cross --git https://github\.com/cross-rs/cross --rev ([0-9a-f]{40})$")


def cross_installs(steps):
    return [s["run"].strip() for s in steps if "cargo install cross" in s.get("run", "")]


def test_both_workflows_install_cross_at_the_same_pinned_commit():
    mine, release = cross_installs(size_steps()), cross_installs(release_steps())
    assert len(mine) == 1 and len(release) == 1, (mine, release)
    assert CROSS.match(mine[0]) and CROSS.match(release[0]), \
        f"cross is installed by a full commit, not whatever main holds: {mine} {release}"
    assert mine == release, "the measured build must use the cross that builds the shipped binary"


@pytest.mark.parametrize("unpinned", ["cargo install cross --git https://github.com/cross-rs/cross",
                                      "cargo install cross --git https://github.com/cross-rs/cross --rev a9301e91",
                                      "cargo install cross --git https://github.com/cross-rs/cross --branch main"])
def test_an_unpinned_or_short_cross_install_is_not_a_pin(unpinned):
    assert not CROSS.match(unpinned), unpinned


def test_every_action_the_job_uses_is_pinned_by_a_full_commit():
    uses = [s["uses"] for s in size_steps() if "uses" in s]
    assert uses, "the job uses no action, so this checks nothing"
    for u in uses:
        assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", u), f"not pinned by a full commit: {u}"


def test_the_job_runs_on_a_github_hosted_runner_only():
    runs_on = size_workflow()["jobs"]["binary-size"]["runs-on"]
    assert runs_on == "ubuntu-24.04", f"a GitHub-hosted label, never a self-hosted one: {runs_on!r}"


def test_the_job_builds_the_feature_set_release_yml_ships_for_musl():
    release = next(s for s in release_steps() if s.get("id") == "features")["run"]
    static_set = re.search(r'static_set="([^"]+)"', release).group(1)
    env = next(s for s in size_steps() if "reproducible-build.sh" in s.get("run", ""))["env"]
    assert env["FEATURES"] == static_set, (env, static_set)


def test_the_job_splits_the_symbols_before_it_measures():
    runs = [s.get("run", "") for s in size_steps()]
    split = next(i for i, r in enumerate(runs) if "split-debuginfo.sh target/x86_64-unknown-linux-musl" in r)
    check = next(i for i, r in enumerate(runs)
                 if "check-binary-size.sh target/x86_64-unknown-linux-musl/release/sipnab" in r)
    assert split < check, runs


def test_the_job_uses_the_release_toolchain_pin():
    def pin(steps):
        return next(s["uses"] for s in steps if s.get("uses", "").startswith("dtolnay/rust-toolchain@"))
    assert pin(size_steps()) == pin(release_steps())


def test_the_job_reads_the_repository_and_nothing_more():
    assert size_workflow()["permissions"] == {"contents": "read"}
