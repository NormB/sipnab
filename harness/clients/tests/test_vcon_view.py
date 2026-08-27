"""The vCon viewer, and the pcap generator the media test depends on."""

import importlib.util
import io
import json
import pathlib
import struct
import subprocess
import sys
import urllib.error

import pytest

HARNESS = pathlib.Path(__file__).resolve().parent.parent.parent
CLIENTS = HARNESS / "clients"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, CLIENTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


vv = _load("vcon_view")


def test_only_recordings_with_a_body_count_as_recordings():
    """A `recording-set` entry carries no audio. Treating it as a recording
    makes the viewer offer to extract bytes that are not there."""
    v = {"dialog": [
        {"type": "recording-set", "recordings": [1]},
        {"type": "recording", "body": "QUJD"},
        {"type": "recording"},
    ]}
    recs = vv.recordings(v)
    assert len(recs) == 1
    assert recs[0]["body"] == "QUJD"


def test_a_missing_vcon_is_distinguished_from_a_failure(monkeypatch):
    """404 with missing_ok returns None so the caller can say "expired", while
    every other status still raises. Collapsing them made an expired entry
    read as a broken store."""
    def not_found(*a, **k):
        raise urllib.error.HTTPError("u", 404, "Not Found", {}, io.BytesIO(b""))

    monkeypatch.setattr(vv.urllib.request, "urlopen", not_found)
    assert vv.get("http://h", "/vcon/x", "t", missing_ok=True) is None
    with pytest.raises(SystemExit):
        vv.get("http://h", "/vcon/x", "t")


def test_a_failing_listing_route_is_reported_as_such(monkeypatch):
    """The conserver's listing parses its own index key as a uuid and answers
    500. That is not the store being down, and the viewer must not say it is."""
    def boom(*a, **k):
        raise urllib.error.HTTPError("u", 500, "Server Error", {}, io.BytesIO(b""))

    monkeypatch.setattr(vv.urllib.request, "urlopen", boom)
    with pytest.raises(vv.ListingBroken):
        vv.get("http://h", "/vcon", "t")


# ── the generated media fixture ──────────────────────────────────────

def generate(tmp_path, **kw) -> pathlib.Path:
    out = tmp_path / "tone.pcap"
    args = [sys.executable, str(HARNESS / "scripts" / "make-pcma-pcap.py"), str(out)]
    for k, v in kw.items():
        args += [f"--{k.replace('_', '-')}", str(v)]
    subprocess.run(args, check=True, capture_output=True, timeout=120)
    return out


def test_the_pcap_is_ethernet_framed_because_sipp_refuses_raw(tmp_path):
    """SIPp answers "Unsupported link-type 12" for DLT_RAW and plays nothing.
    The generator's first version wrote exactly that."""
    data = generate(tmp_path, seconds=0.2).read_bytes()
    magic, _, _, _, _, _, link = struct.unpack("<IHHiIII", data[:24])
    assert magic == 0xA1B2C3D4
    assert link == 1, "LINKTYPE_ETHERNET, or SIPp will not play the file"


def test_the_ssrc_reaches_the_rtp_header(tmp_path):
    """The SSRC is the whole point of a second media file: it is what makes
    the callee's leg distinguishable from the caller's."""
    data = generate(tmp_path, seconds=0.1, ssrc="0x5AFE1234").read_bytes()
    # 24-byte global header, 16-byte record header, 14 Ethernet, 20 IP, 8 UDP.
    rtp = data[24 + 16 + 14 + 20 + 8:]
    assert struct.unpack("!I", rtp[8:12])[0] == 0x5AFE1234
    assert rtp[1] & 0x7F == 8, "payload type 8 is PCMA"


def test_packet_count_follows_the_requested_duration(tmp_path):
    """20 ms per packet. A file shorter than the call leaves the far end silent
    for most of the recording, which is what made the first answer pcap only
    eight seconds of a ninety-second call."""
    data = generate(tmp_path, seconds=1.0).read_bytes()
    count, off = 0, 24
    while off + 16 <= len(data):
        length = struct.unpack("<I", data[off + 8:off + 12])[0]
        off += 16 + length
        count += 1
    assert count == 50, f"1.0s at 20ms per packet is 50 packets, got {count}"


def test_two_tones_produce_different_audio(tmp_path):
    """Distinct SSRCs are not enough on their own: if both ends emit the same
    samples, a stereo export of the two legs is still two identical channels."""
    (tmp_path / "x").mkdir()
    (tmp_path / "y").mkdir()
    p1 = generate(tmp_path / "x", seconds=0.2, hz=440)
    p2 = generate(tmp_path / "y", seconds=0.2, hz=660)
    assert p1.read_bytes() != p2.read_bytes()
