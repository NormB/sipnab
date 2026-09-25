"""The two transports behind one `call(name, arguments)`, and the wait.

sipnab drops whatever it has not processed when it stops, and an answer
given before a file is read to its end describes part of it. So every
program here waits for `capture_status` to say the source is exhausted, and
waits on that evidence, never a fixed sleep, with a deadline that names what
it waited for.
"""

import asyncio
import importlib.util
import pathlib
import sys

import pytest

CLIENTS = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(CLIENTS))


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, CLIENTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


mc = _load("mcp_calls")


def status(exhausted: bool, source: str = "file") -> dict:
    return {"source": source, "source_exhausted": exhausted, "source_stopped_early": False}


class Script:
    def __init__(self, *answers):
        self.answers = list(answers)
        self.asked = 0

    async def __call__(self, name, arguments):
        assert name == "capture_status"
        self.asked += 1
        return self.answers.pop(0)


class Clock:
    def __init__(self):
        self.now = 0.0
        self.slept = []

    def __call__(self):
        return self.now

    async def sleep(self, seconds):
        self.slept.append(seconds)
        self.now += seconds


def test_waits_until_the_file_is_read_to_its_end():
    call, clock = Script(status(False), status(False), status(True)), Clock()
    got = asyncio.run(mc.wait_drained(call, deadline=5, sleep=clock.sleep, clock=clock))
    assert got["source_exhausted"] is True
    assert call.asked == 3
    assert clock.slept == [0.1, 0.1]


def test_a_file_never_finished_is_an_error_naming_the_wait():
    call, clock = Script(*[status(False)] * 100), Clock()
    with pytest.raises(TimeoutError, match="not finished reading its capture in 1s"):
        asyncio.run(mc.wait_drained(call, deadline=1, sleep=clock.sleep, clock=clock))


def test_a_live_source_is_not_waited_for():
    # A live capture never exhausts; the report's own `complete` says how
    # much it covers, and waiting would only ever time out.
    call, clock = Script(status(False, source="live")), Clock()
    got = asyncio.run(mc.wait_drained(call, deadline=5, sleep=clock.sleep, clock=clock))
    assert got["source"] == "live"
    assert clock.slept == []


def test_a_tool_answer_is_its_first_text_block_as_json():
    assert mc.tool_json(['{"a": 1}', "Provenance: ..."], False) == {"a": 1}


def test_a_tool_error_is_raised_with_its_text():
    with pytest.raises(mc.ToolError, match="no such call"):
        mc.tool_json(["no such call"], True)


def test_an_answer_with_no_text_is_an_error():
    with pytest.raises(mc.ToolError, match="no text"):
        mc.tool_json([], False)


def test_sipnab_is_found_by_flag_then_environment_then_path(monkeypatch):
    monkeypatch.setenv("SIPNAB_BIN", "/env/sipnab")
    assert mc.find_sipnab("/flag/sipnab") == "/flag/sipnab"
    assert mc.find_sipnab(None) == "/env/sipnab"
    monkeypatch.delenv("SIPNAB_BIN")
    assert mc.find_sipnab(None) == "sipnab"


def test_the_stdio_command_reads_every_capture_quietly():
    assert mc.stdio_args(["a.pcap", "b.pcap"], ["--mcp-file-root", "/r"]) == [
        "--mcp", "-N", "--quiet", "--mcp-file-root", "/r", "-I", "a.pcap", "-I", "b.pcap",
    ]


def test_the_leaf_of_nested_exception_groups_is_the_cause():
    cause = ConnectionError("Connection closed")
    nested = ExceptionGroup("outer", [ExceptionGroup("inner", [cause])])
    assert mc.leaf(nested) is cause
    assert mc.leaf(cause) is cause
