"""The composite action that installs Debian packages in CI.

`.github/actions/system-deps` caches the .deb files it downloads and installs
from that cache on the next run. The Check job calls it twice: once for the
build's libraries and once for tshark. On 2026-09-25 the second call found the
first call's .debs in the one shared cache directory, took them for its own
warm cache, reinstalled libpcap-dev and friends, and never fetched tshark; its
Verify step failed the job (CI on 7596678e).

These tests run the action's own Install script, cut from action.yml, twice in
one home directory, with sudo/dpkg/apt-get/timeout replaced by recorders. No
package is installed and nothing outside a temporary directory is touched.
"""

import os
import pathlib
import re
import stat
import subprocess
import textwrap

ACTION = pathlib.Path(__file__).resolve().parents[2] / ".github/actions/system-deps/action.yml"
REAL_ARCHIVES = "/var/cache/apt/archives"


def _step(name: str) -> str:
    """The text of the step called `name`, up to the next step."""
    text = ACTION.read_text()
    parts = re.split(r"(?m)^    - name: ", text)
    for part in parts[1:]:
        if part.splitlines()[0].strip() == name:
            return part
    raise AssertionError(f"action.yml has no step named {name!r}")


def _run_block(step: str) -> str:
    """The `run: |` script of a step, dedented."""
    lines = step.splitlines()
    start = next(i for i, l in enumerate(lines) if l.strip() == "run: |") + 1
    body = []
    for line in lines[start:]:
        if line.strip() and not line.startswith("        "):
            break
        body.append(line)
    return textwrap.dedent("\n".join(body))


def _slug(packages: str) -> str:
    """The probe step's slug, computed the same way (tr ' ' '-' | tr -cd ...)."""
    return re.sub(r"[^a-zA-Z0-9.-]", "", packages.replace(" ", "-"))


def _stubs(root: pathlib.Path) -> pathlib.Path:
    """sudo/timeout pass through; apt-get fakes a download; dpkg logs installs."""
    bin_dir = root / "bin"
    bin_dir.mkdir()
    scripts = {
        # With HOLD set, sudo also records whether another sudo is running:
        # every machine-wide change goes through it, so two at once is the
        # dpkg-lock race the concurrency test looks for.
        "sudo": textwrap.dedent(
            """\
            if [ -z "${HOLD:-}" ]; then exec "$@"; fi
            mkdir "$HOLD" 2>/dev/null || echo overlap >> "$OVERLAP"
            "$@"; rc=$?
            sleep 0.2
            rmdir "$HOLD" 2>/dev/null
            exit "$rc"
            """
        ),
        "debconf-set-selections": 'sed "s/^/debconf: /" >> "$INSTALLED"\n',
        "timeout": 'shift; exec "$@"\n',
        "chown": "exit 0\n",
        "apt-get": textwrap.dedent(
            """\
            case "$1" in
              update) exit 0 ;;
              clean) rm -f "$ARCHIVES"/*.deb; exit 0 ;;
              install)
                shift
                for a in "$@"; do
                  case "$a" in -*) ;; *) : > "$ARCHIVES/$a.deb" ;; esac
                done ;;
            esac
            """
        ),
        "dpkg": textwrap.dedent(
            """\
            [ "$1" = "-i" ] || exit 1
            shift
            for f in "$@"; do basename "$f" .deb >> "$INSTALLED"; done
            """
        ),
    }
    for name, body in scripts.items():
        path = bin_dir / name
        path.write_text("#!/usr/bin/env bash\n" + body)
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return bin_dir


def _install_env(root: pathlib.Path, packages: str, **extra: str) -> dict[str, str]:
    return {
        "PATH": f"{_stubs_dir(root)}:{os.environ['PATH']}",
        "HOME": str(root / "home"),
        "NEED": packages,
        "SLUG": _slug(packages),
        "ARCHIVES": str(root / "archives"),
        "INSTALLED": str(root / f"installed-{_slug(packages)}"),
        **extra,
    }


def _install_script(root: pathlib.Path) -> str:
    return _run_block(_step("Install")).replace(REAL_ARCHIVES, str(root / "archives"))


def _install(root: pathlib.Path, packages: str) -> list[str]:
    """Run the Install step for `packages`; return what dpkg installed."""
    env = _install_env(root, packages)
    subprocess.run(
        ["bash", "-c", _install_script(root)], env=env, check=True, capture_output=True, text=True
    )
    installed = pathlib.Path(env["INSTALLED"])
    return installed.read_text().split() if installed.exists() else []


def _stubs_dir(root: pathlib.Path) -> pathlib.Path:
    bin_dir = root / "bin"
    return bin_dir if bin_dir.exists() else _stubs(root)


def _setup(tmp_path: pathlib.Path) -> pathlib.Path:
    (tmp_path / "home").mkdir()
    (tmp_path / "archives").mkdir()
    return tmp_path


def test_a_second_package_set_in_one_job_installs_its_own_packages(tmp_path):
    root = _setup(tmp_path)
    assert _install(root, "libpcap-dev libyang2-tools") == ["libpcap-dev", "libyang2-tools"]
    second = _install(root, "tshark")
    assert "tshark" in second, (
        f"the tshark call installed {second}: it read the first call's cache as its own"
    )


def test_a_package_sets_cache_holds_only_what_that_set_downloaded(tmp_path):
    root = _setup(tmp_path)
    _install(root, "libpcap-dev")
    second = _install(root, "tshark")
    assert second == ["tshark"], (
        f"the tshark call also installed {sorted(set(second) - {'tshark'})}, left in apt's "
        "download directory by the first call; its cache would carry them too"
    )


def test_the_restore_step_caches_the_directory_install_fills(tmp_path):
    root = _setup(tmp_path)
    _install(root, "tshark")
    restore = _step("Restore the .deb cache")
    path = re.search(r"(?m)^\s+path: (.+?)\s*$", restore).group(1)
    rendered = path.replace("${{ steps.probe.outputs.slug }}", _slug("tshark")).replace(
        "~", str(root / "home")
    )
    debs = sorted(p.name for p in pathlib.Path(rendered).glob("*.deb"))
    assert debs == ["tshark.deb"], (
        f"the cache step saves {path} but the Install step put the .debs elsewhere "
        f"(found {debs} there)"
    )


def _probe(root: pathlib.Path, installed_on_image: str) -> dict[str, str]:
    """Run the probe step on an image whose dpkg-query lists `installed_on_image`."""
    bin_dir = root / f"probe-bin-{abs(hash(installed_on_image))}"
    bin_dir.mkdir()
    for name, body in {
        "dpkg": "exit 1\n",
        "dpkg-query": 'printf "%s" "$IMAGE_PACKAGES"\n',
    }.items():
        path = bin_dir / name
        path.write_text("#!/usr/bin/env bash\n" + body)
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
    out = root / f"out-{abs(hash(installed_on_image))}"
    env = {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "PACKAGES": "libpcap-dev",
        "IMAGE_PACKAGES": installed_on_image,
        "GITHUB_OUTPUT": str(out),
    }
    script = _run_block(_step("Decide what is missing"))
    subprocess.run(["bash", "-c", script], env=env, check=True, capture_output=True, text=True)
    return dict(line.split("=", 1) for line in out.read_text().splitlines())


def test_a_new_runner_image_misses_the_old_images_cache(tmp_path):
    """The cached .debs are a dependency closure computed against the packages
    the image ALREADY had: apt downloads only what is missing. On 2026-09-30
    the arm64 image moved libpcap0.8t64 to a version the cached libpcap0.8-dev
    did not accept, the key (`sipnab-apt-Linux-ARM64--libpcap-dev`: ImageOS is
    empty on that runner) still hit, and dpkg left both dev packages
    unconfigured (CI on b79b261c). The key must change when the image's
    installed set does."""
    root = _setup(tmp_path)
    old = _probe(root, "libpcap0.8t64=1.10.4-4.1ubuntu3.1\n")
    new = _probe(root, "libpcap0.8t64=1.10.4-4.1ubuntu3.2\n")
    assert old.get("base") and new.get("base"), f"the probe emits no `base` output: {old}"
    assert old["base"] != new["base"], "two images with different packages share one cache key"
    key = re.search(r"(?m)^\s+key: (.+?)\s*$", _step("Restore the .deb cache")).group(1)
    assert "steps.probe.outputs.base" in key, f"the cache key ignores the image's packages: {key}"


def test_concurrent_installs_on_one_machine_take_turns(tmp_path):
    """Four runner instances share one machine, and dpkg holds one lock for
    all of them: a second `dpkg -i` or `apt-get install` while the first runs
    fails with "dpkg frontend lock is locked by another process". The probe
    step skips the install when every package is present, which is the
    common path on the self-hosted machine; when one is missing, two jobs
    reach this step together, and it must serialize them."""
    root = _setup(tmp_path)
    overlap = root / "overlap"
    procs = [
        subprocess.Popen(
            ["bash", "-c", _install_script(root)],
            env=_install_env(root, pkgs, HOLD=str(root / "held"), OVERLAP=str(overlap)),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for pkgs in ("libpcap-dev", "tshark", "libyang2-tools")
    ]
    for proc in procs:
        _, err = proc.communicate(timeout=60)
        assert proc.returncode == 0, err
    assert not overlap.exists(), (
        f"{overlap.read_text().count('overlap')} privileged command(s) ran while another "
        "job's install held the machine"
    )


def _install_with_preseed(root: pathlib.Path, packages: str, preseed: str) -> list[str]:
    env = _install_env(root, packages, DEBCONF=preseed)
    subprocess.run(
        ["bash", "-c", _install_script(root)], env=env, check=True, capture_output=True, text=True
    )
    return pathlib.Path(env["INSTALLED"]).read_text().splitlines()


def test_a_debconf_preseed_is_applied_before_the_package_is_configured(tmp_path):
    """wireshark-common asks whether non-root users may capture. The answer
    must be in debconf before dpkg configures the package, on the cold path
    and on the cached one, or the install waits for a terminal the job does
    not have."""
    root = _setup(tmp_path)
    answer = "wireshark-common wireshark-common/install-setuid boolean false"
    for path in ("cold", "cached"):
        log = _install_with_preseed(root, "tshark", answer)
        assert log == [f"debconf: {answer}", "tshark"], f"{path} path: {log}"
        pathlib.Path(_install_env(root, "tshark")["INSTALLED"]).unlink()


def test_no_preseed_means_no_debconf_call(tmp_path):
    root = _setup(tmp_path)
    log = _install_with_preseed(root, "libpcap-dev", "")
    assert log == ["libpcap-dev"], log


def test_the_preseed_reaches_the_install_step_only_through_the_environment():
    """Like `packages`, the input is text substituted before bash runs; it
    reaches the script as an environment value, never inline."""
    install = _step("Install")
    assert "DEBCONF: ${{ inputs.debconf }}" in install, install
    assert "${{ inputs.debconf }}" not in _run_block(install)


def test_every_step_that_changes_the_machine_runs_only_when_something_is_missing():
    for name in ("Restore the .deb cache", "Install", "Verify"):
        assert "if: steps.probe.outputs.need != ''" in _step(name), name


def test_no_workflow_runs_debconf_outside_the_action():
    """A preseed in its own workflow step runs on every job, installed or not,
    and takes debconf's machine-wide lock each time; two jobs on the
    self-hosted machine at once then fail on it. Passed as the action's
    `debconf` input, it runs inside the install lock and only when something
    is installed."""
    workflows = ACTION.parents[2] / "workflows"
    found = []
    for wf in sorted(workflows.glob("*.yml")):
        for n, line in enumerate(wf.read_text().splitlines(), 1):
            if "debconf-set-selections" in line and not line.lstrip().startswith("#"):
                found.append(f"{wf.name}:{n}: {line.strip()}")
    assert not found, "pass the answer as system-deps' `debconf` input:\n" + "\n".join(found)
