"""Packet slices cut with the REAL tcpdump, editcap and capinfos (worker image only).

A synthetic capture (Scapy, fixtures only) has three groups of packets: the flow of interest
inside the finding's time range, an unrelated flow, and more packets of the same flow far outside
the range. The slice must contain exactly the first group: right hosts, ports and time range.
"""

import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import rdpcap, wrpcap

from app.ingest.capinfos import run_capinfos
from app.slice.builder import build_bpf, normalise_flows
from app.slice.runner import build_slice

pytestmark = [
    pytest.mark.requires_zeek,
    pytest.mark.skipif(
        any(shutil.which(t) is None for t in ("tcpdump", "editcap", "capinfos")),
        reason="tcpdump/editcap/capinfos not installed (run in the worker image)",
    ),
]

T0 = 1_700_000_000.0
A, B, C, D = "10.0.0.5", "10.0.0.9", "10.0.0.7", "10.0.0.53"


def packet(ts: float, src: str, dst: str, sport: int, dport: int, tcp: bool = True):  # type: ignore[no-untyped-def]
    layer = TCP(sport=sport, dport=dport, flags="PA") if tcp else UDP(sport=sport, dport=dport)
    pkt = Ether() / IP(src=src, dst=dst) / layer
    pkt.time = ts
    return pkt


@pytest.fixture
def capture(tmp_path: Path) -> Path:
    packets = [packet(T0 + i, A, B, 40000, 22) for i in range(6)]  # the flow of interest
    packets += [packet(T0 + 2 + i * 0.1, C, D, 5353, 53, tcp=False) for i in range(4)]  # unrelated
    packets += [packet(T0 + 600 + i, A, B, 40000, 22) for i in range(3)]  # same flow, much later
    path = tmp_path / "all.pcap"
    wrpcap(str(path), sorted(packets, key=lambda p: p.time))
    return path


def test_the_slice_contains_only_the_findings_flow_inside_its_time_range(
    capture: Path, tmp_path: Path
) -> None:
    bpf = build_bpf(normalise_flows([("tcp", A, 40000, B, 22)]))
    start = datetime.fromtimestamp(T0, tz=UTC)
    result = build_slice(
        capture,
        tmp_path / "out" / "1.pcap",
        bpf,
        start,
        start + timedelta(seconds=5),
        timeout_s=30,
    )
    assert result.packets == 6
    info = run_capinfos(result.path, "capinfos", 30)
    assert info.packets == 6 and info.first_ts is not None and info.last_ts is not None
    assert info.first_ts >= T0 - 2 and info.last_ts <= T0 + 5 + 3
    seen = rdpcap(str(result.path))
    assert {(p[IP].src, p[IP].dst, p[TCP].sport, p[TCP].dport) for p in seen} == {(A, B, 40000, 22)}


def test_a_filter_matching_nothing_is_reported_as_an_empty_slice(
    capture: Path, tmp_path: Path
) -> None:
    from app.core.errors import IngestError

    bpf = build_bpf(normalise_flows([("tcp", A, 1, "10.9.9.9", 2)]))
    start = datetime.fromtimestamp(T0, tz=UTC)
    with pytest.raises(IngestError) as err:
        build_slice(
            capture, tmp_path / "e.pcap", bpf, start, start + timedelta(seconds=5), timeout_s=30
        )
    assert err.value.code == "SLICE_EMPTY" and not (tmp_path / "e.pcap").exists()
