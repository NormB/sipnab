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
        "sudo": 'exec "$@"\n',
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


def _install(root: pathlib.Path, packages: str) -> list[str]:
    """Run the Install step for `packages`; return what dpkg installed."""
    script = _run_block(_step("Install")).replace(REAL_ARCHIVES, str(root / "archives"))
    installed = root / f"installed-{_slug(packages)}"
    env = {
        "PATH": f"{_stubs_dir(root)}:{os.environ['PATH']}",
        "HOME": str(root / "home"),
        "NEED": packages,
        "SLUG": _slug(packages),
        "ARCHIVES": str(root / "archives"),
        "INSTALLED": str(installed),
    }
    subprocess.run(["bash", "-c", script], env=env, check=True, capture_output=True, text=True)
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
