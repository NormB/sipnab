"""Runnable examples must publish and run under the project's CI."""

from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]


def test_library_and_example_index_are_generated(tmp_path):
    subprocess.run([sys.executable, str(ROOT / "scripts/build-site-pages.py"), str(tmp_path)],
                   cwd=ROOT, check=True, capture_output=True)
    for page in ("library.md", "examples.md"):
        assert (tmp_path / page).is_file(), f"missing published page: {page}"


def test_client_programs_and_their_tests_are_in_ci():
    workflow = (ROOT / ".github/workflows/ci.yml").read_text()
    for name in ("hep_senders", "leg_correlate", "mcp_probe", "vcon_validate", "vcon_view"):
        assert (ROOT / "clients/python" / f"{name}.py").is_file()
        assert (ROOT / "clients/python/tests" / f"test_{name}.py").is_file()
    assert "python3 -m pytest clients/python/tests" in workflow
    assert "python3 -m compileall -q clients/python" in workflow
    assert "python3 -m pytest scripts/tests" in workflow
