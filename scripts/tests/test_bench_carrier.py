# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""bench/carrier.py, the synthetic carrier corpus generator.

With one stream pair per call (`--stream-pairs 0`) the RTP port of pair N was
10000 + 2N + 1, past 65535 from pair 27768 on, so `--calls 30000 --call-ids 0
--stream-pairs 0` stopped with `struct.error: 'H' format requires 0 <= number
<= 65535` (2026-11-15). Each pair has its own address pair, so the port can
repeat across pairs without two streams sharing a 5-tuple.
"""

import importlib.util
import pathlib
import struct

import pytest

from conftest import SCRIPTS

CARRIER = SCRIPTS.parent / "bench" / "carrier.py"


def _load():
    spec = importlib.util.spec_from_file_location("bench_carrier", CARRIER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


carrier = _load()


def _udp_flows(path):
    """(src ip, dst ip, src port, dst port) of every UDP frame in a pcap."""
    data = pathlib.Path(path).read_bytes()
    flows = []
    at = 24
    while at < len(data):
        _, _, incl, _ = struct.unpack_from("<IIII", data, at)
        frame = data[at + 16 : at + 16 + incl]
        at += 16 + incl
        ihl = (frame[14] & 0x0F) * 4
        if frame[14 + 9] != 17:
            continue
        src, dst = frame[14 + 12 : 14 + 16], frame[14 + 16 : 14 + 20]
        sport, dport = struct.unpack_from("!HH", frame, 14 + ihl)
        flows.append((src, dst, sport, dport))
    return flows


def _generate(tmp_path, calls, pairs, rtp_per_call=2):
    out = tmp_path / "corpus.pcap"
    carrier.generate(str(out), calls, rtp_per_call, 0, pairs, 100, True)
    return out


def test_one_pair_per_call_past_the_port_range_generates(tmp_path):
    out = _generate(tmp_path, 30000, 0)
    rtp = [f for f in _udp_flows(out) if f[2] != carrier.SIP_PORT]
    assert rtp, "the corpus carries RTP"
    assert all(carrier.RTP_PORT_BASE <= f[2] <= 65535 for f in rtp), "every RTP port is in range"


def test_one_pair_per_call_keeps_every_stream_distinct(tmp_path):
    out = _generate(tmp_path, 30000, 0)
    streams = {f for f in _udp_flows(out) if f[2] != carrier.SIP_PORT}
    assert len(streams) == 2 * 30000, "two streams per call, none sharing a 5-tuple"


@pytest.mark.parametrize(
    "pair, ports",
    [
        (0, (10000, 10001)),
        (1, (10002, 10003)),
        (99, (10198, 10199)),
        (27767, (65534, 65535)),
    ],
)
def test_pairs_inside_the_port_range_keep_their_ports(pair, ports):
    assert carrier.rtp_ports(pair) == ports, "the published corpora are unchanged"


@pytest.mark.parametrize(
    "pair, ports",
    [
        (27768, (10000, 10001)),
        (27769, (10002, 10003)),
        (55535, (65534, 65535)),
        (55536, (10000, 10001)),
        (65535, (29998, 29999)),
    ],
)
def test_pairs_past_the_port_range_start_again_at_the_base(pair, ports):
    assert carrier.rtp_ports(pair) == ports, "the port repeats on another address pair"


@pytest.mark.parametrize("pairs", [65537, 70000, 1 << 20])
def test_more_pairs_than_addresses_is_refused(tmp_path, pairs):
    with pytest.raises(SystemExit, match="65536"):
        _generate(tmp_path, 10, pairs)
    assert not (tmp_path / "corpus.pcap").exists(), "nothing is written for a refused run"


def test_the_largest_number_of_pairs_is_accepted(tmp_path):
    out = _generate(tmp_path, 10, 65536)
    assert out.exists(), "65536 address pairs fit 10.1.x.y / 10.2.x.y"
