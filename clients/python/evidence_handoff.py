#!/usr/bin/env python3
"""Package the calls a capture's findings name, with a repro script for each.

    evidence_handoff.py capture.pcap --file-root DIR [--name NAME]
                        [--pin ASPECT ...] [--sipnab PATH]

What an agent hands a carrier or a ticket. Over MCP stdio, with sipnab's
file tools confined to --file-root (`--mcp-file-root`), the program:

    get_capture_report      the calls the findings name, with their final codes
    build_evidence_package  one directory, NAME, holding those calls
    generate_repro          one SIPp scenario per call, NAME.call-NN.xml,
                            pinning each --pin aspect (default request_uri)

then reads the files back rather than trusting either answer: every file the
package answer names is on disk and nothing else is, the manifest lists the
calls in the order asked for, the README warns that the frames were rebuilt,
and each scenario on disk is the one returned, asserting the final response
the capture held. It prints one sha256 line per file, relative to
--file-root, so two runs over one capture can be compared line for line.

Exit status: 0 packaged and checked, 1 a check failed or sipnab refused
(a NAME already taken, say), 2 no finding names a call, so there is
nothing to package, 3 sipnab could not be asked.
"""

import argparse
import asyncio
import hashlib
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import mcp_calls  # noqa: E402

REBUILT = "WERE REBUILT, NOT COPIED"


def problem_calls(report: dict) -> list[tuple[str, int | None]]:
    """(Call-ID, final code) for each call a finding names, in its order."""
    out, seen = [], set()
    for f in report["findings"]:
        for e in f.get("evidence", []):
            call_id = e.get("call_id")
            if call_id and call_id not in seen:
                seen.add(call_id)
                out.append((call_id, e.get("counts", {}).get("status_code")))
    return out


def check_package(root: pathlib.Path, name: str, answer: dict, call_ids: list[str]) -> list[str]:
    """What is wrong with the package on disk, against its answer and the ask."""
    # snippet:start package-check
    pkg = root / name
    problems = []
    named = set(answer["files"])
    on_disk = {p.name for p in pkg.iterdir()}
    for f in sorted(named - on_disk):
        problems.append(f"{name}/{f}: named in the answer and not on disk")
    for f in sorted(on_disk - named):
        problems.append(f"{name}/{f}: on disk and not named in the answer")
    if "manifest.json" in on_disk:
        manifest = json.loads((pkg / "manifest.json").read_text())
        listed = [c["call_id"] for c in manifest["calls"]]
        if listed != call_ids:
            problems.append(f"{name}/manifest.json lists {listed}, not {call_ids}")
    if "README.md" in on_disk and REBUILT not in (pkg / "README.md").read_text():
        problems.append(f"{name}/README.md does not say the frames were rebuilt, not copied")
    return problems
    # snippet:end package-check


def check_repro(root: pathlib.Path, filename: str, answer: dict, final: int | None, pins: list[str]) -> list[str]:
    """What is wrong with one scenario, against its answer and the capture."""
    problems = []
    if (root / filename).read_text() != answer["scenario"]:
        problems.append(f"{filename} on disk is not the scenario the answer returned")
    asserted = answer["asserted"]["final"]
    if final is not None and asserted != final:
        problems.append(f"{filename} asserts a final {asserted}, and the capture ended the call with {final}")
    unpinned = [p for p in pins if p not in answer["hypothesis"]["pinned"]]
    if unpinned:
        problems.append(f"{filename} did not pin {unpinned}")
    return problems


def digest_lines(root: pathlib.Path, names: list[str]) -> list[str]:
    """`sha256 <hex>  <path>` for every file under `names`, sorted by path."""
    files = []
    for n in names:
        p = root / n
        files += sorted(q for q in p.rglob("*") if q.is_file()) if p.is_dir() else [p]
    lines = [
        f"sha256 {hashlib.sha256(f.read_bytes()).hexdigest()}  {f.relative_to(root).as_posix()}"
        for f in files
    ]
    return sorted(lines, key=lambda line: line.split("  ", 1)[1])


async def hand_off(call, root: pathlib.Path, name: str, pins: list[str]) -> tuple[int, list[str]]:
    await mcp_calls.wait_drained(call)
    report = await call("get_capture_report", {"format": "json"})
    calls = problem_calls(report)
    if not calls:
        return 2, ["nothing to package: no finding names a call"]
    call_ids = [c for c, _ in calls]
    package = await call("build_evidence_package", {"call_ids": call_ids, "filename": name})
    lines = [f"package {name}: {package['calls']} call(s), {package['messages']} message(s)"]
    problems = check_package(root, name, package, call_ids)
    repros = []
    for i, (call_id, final) in enumerate(calls, start=1):
        filename = f"{name}.call-{i:02d}.xml"
        repro = await call(
            "generate_repro", {"call_id": call_id, "pin": pins, "filename": filename}
        )
        repros.append(filename)
        pinned = " ".join(repro["hypothesis"]["pinned"])
        lines.append(f"repro {filename}  {call_id}  asserts {repro['asserted']['final']}  pinned {pinned}")
        problems += check_repro(root, filename, repro, final, pins)
    lines += digest_lines(root, [name, *repros])
    lines += [f"PROBLEM: {p}" for p in problems]
    return (1 if problems else 0), lines


async def run(args) -> tuple[int, list[str]]:
    root = pathlib.Path(args.file_root).resolve()
    sipnab = mcp_calls.find_sipnab(args.sipnab)
    async with mcp_calls.stdio(sipnab, args.captures, ["--mcp-file-root", str(root)]) as call:
        return await hand_off(call, root, args.name, args.pin or ["request_uri"])


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("captures", nargs="+", help="capture files")
    ap.add_argument("--file-root", required=True, help="sipnab's --mcp-file-root: where the files go")
    ap.add_argument("--name", default="evidence", help="the package directory, which must not exist")
    ap.add_argument("--pin", action="append", help="an aspect each scenario pins (repeatable)")
    ap.add_argument("--sipnab", help="the sipnab binary")
    args = ap.parse_args()
    try:
        status, lines = asyncio.run(run(args))
    except mcp_calls.ToolError as e:
        print(f"evidence_handoff: sipnab refused: {e}", file=sys.stderr)
        return 1
    except (OSError, TimeoutError) as e:
        print(f"evidence_handoff: sipnab could not be asked: {e}", file=sys.stderr)
        return 3
    except BaseExceptionGroup as g:
        cause = mcp_calls.leaf(g)
        if isinstance(cause, mcp_calls.ToolError):
            print(f"evidence_handoff: sipnab refused: {cause}", file=sys.stderr)
            return 1
        print(f"evidence_handoff: sipnab could not be asked: {cause}", file=sys.stderr)
        return 3
    print("\n".join(lines))
    return status


if __name__ == "__main__":
    sys.exit(main())
