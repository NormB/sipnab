"""An evidence package and repro scripts, checked before an agent hands them on.

`build_evidence_package` and `generate_repro` each report what they wrote.
A report is a claim; the files are the evidence. So the program reads the
package back: every file the answer names is there and nothing else is, the
manifest lists the calls in the order asked for, the README carries the
rebuilt-frames warning a recipient has to see, and each scenario on disk is
the scenario the answer returned, asserting the final response the capture
held.
"""

import hashlib
import importlib.util
import json
import pathlib
import sys

CLIENTS = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(CLIENTS))


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, CLIENTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


eh = _load("evidence_handoff")

CALLS = ["busy@x", "decline@x"]
FILES = ["README.md", "manifest.json", "call-01-ladder.md", "call-02-ladder.md", "signaling.pcapng"]


def package(root: pathlib.Path, name="pkg", calls=CALLS, files=FILES) -> dict:
    d = root / name
    d.mkdir()
    for f in files:
        (d / f).write_text(f"{f}\n")
    (d / "README.md").write_text("## THE FRAMES IN `signaling.pcapng` WERE REBUILT, NOT COPIED\n")
    manifest = {
        "calls": [{"call_id": c, "index": i + 1} for i, c in enumerate(calls)],
        "signaling_frames_rebuilt": True,
    }
    (d / "manifest.json").write_text(json.dumps(manifest))
    return {"calls": len(calls), "files": list(files), "messages": 8, "path": str(d)}


def test_a_whole_package_has_no_problem(tmp_path):
    answer = package(tmp_path)
    assert eh.check_package(tmp_path, "pkg", answer, CALLS) == []


def test_a_file_the_answer_names_and_the_disk_lacks_is_a_problem(tmp_path):
    answer = package(tmp_path)
    (tmp_path / "pkg" / "call-02-ladder.md").unlink()
    assert eh.check_package(tmp_path, "pkg", answer, CALLS) == [
        "pkg/call-02-ladder.md: named in the answer and not on disk"
    ]


def test_a_file_on_disk_the_answer_does_not_name_is_a_problem(tmp_path):
    answer = package(tmp_path)
    (tmp_path / "pkg" / "stray.txt").write_text("x")
    assert eh.check_package(tmp_path, "pkg", answer, CALLS) == [
        "pkg/stray.txt: on disk and not named in the answer"
    ]


def test_calls_out_of_order_or_missing_are_a_problem(tmp_path):
    answer = package(tmp_path, calls=list(reversed(CALLS)))
    assert eh.check_package(tmp_path, "pkg", answer, CALLS) == [
        "pkg/manifest.json lists ['decline@x', 'busy@x'], not ['busy@x', 'decline@x']"
    ]


def test_a_readme_without_the_rebuilt_warning_is_a_problem(tmp_path):
    answer = package(tmp_path)
    (tmp_path / "pkg" / "README.md").write_text("# evidence\n")
    assert eh.check_package(tmp_path, "pkg", answer, CALLS) == [
        "pkg/README.md does not say the frames were rebuilt, not copied"
    ]


def repro_answer(final=486, pinned=("request_uri",), scenario="<scenario/>\n") -> dict:
    return {
        "asserted": {"final": final, "provisional": [100]},
        "hypothesis": {"pinned": list(pinned)},
        "scenario": scenario,
    }


def test_a_scenario_on_disk_that_matches_its_answer_has_no_problem(tmp_path):
    (tmp_path / "r.xml").write_text("<scenario/>\n")
    assert eh.check_repro(tmp_path, "r.xml", repro_answer(), 486, ["request_uri"]) == []


def test_a_scenario_asserting_another_outcome_is_a_problem(tmp_path):
    (tmp_path / "r.xml").write_text("<scenario/>\n")
    assert eh.check_repro(tmp_path, "r.xml", repro_answer(final=200), 486, ["request_uri"]) == [
        "r.xml asserts a final 200, and the capture ended the call with 486"
    ]


def test_a_scenario_file_unlike_the_returned_text_is_a_problem(tmp_path):
    (tmp_path / "r.xml").write_text("<other/>\n")
    assert eh.check_repro(tmp_path, "r.xml", repro_answer(), 486, ["request_uri"]) == [
        "r.xml on disk is not the scenario the answer returned"
    ]


def test_a_pin_the_answer_did_not_honor_is_a_problem(tmp_path):
    (tmp_path / "r.xml").write_text("<scenario/>\n")
    assert eh.check_repro(tmp_path, "r.xml", repro_answer(pinned=()), 486, ["request_uri"]) == [
        "r.xml did not pin ['request_uri']"
    ]


def test_calls_to_package_come_from_the_findings_with_their_final_codes():
    report = {
        "findings": [
            {"evidence": [{"call_id": "d@x", "counts": {"status_code": 603}}]},
            {"evidence": [{"call_id": "b@x", "counts": {"status_code": 486}}, {"endpoints": ["a"]}]},
        ]
    }
    assert eh.problem_calls(report) == [("d@x", 603), ("b@x", 486)]


def test_digests_cover_every_file_under_the_names_given(tmp_path):
    package(tmp_path)
    (tmp_path / "pkg.call-01.xml").write_text("s")
    lines = eh.digest_lines(tmp_path, ["pkg", "pkg.call-01.xml"])
    want = hashlib.sha256(b"s").hexdigest()
    assert f"sha256 {want}  pkg.call-01.xml" in lines
    assert len(lines) == len(FILES) + 1
    assert lines == sorted(lines, key=lambda line: line.split("  ", 1)[1])
