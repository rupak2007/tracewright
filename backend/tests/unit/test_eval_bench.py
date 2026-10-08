"""Benchmark tooling: synthetic sizing capture and capture concatenation. No Docker needed."""

import struct
from pathlib import Path

import pytest

pytest.importorskip("eval")
pytest.importorskip("lab")

from eval import bench, synth_capture


def read_frames(path: Path) -> list[tuple[float, bytes]]:
    data = path.read_bytes()
    assert data[:4] == bytes.fromhex("d4c3b2a1")
    frames, offset = [], 24
    while offset < len(data):
        sec, usec, incl, orig = struct.unpack("<IIII", data[offset : offset + 16])
        assert incl == orig
        frames.append((sec + usec / 1e6, data[offset + 16 : offset + 16 + incl]))
        offset += 16 + incl
    assert offset == len(data)  # no trailing bytes
    return frames


def test_the_synthetic_capture_has_valid_checksums_and_complete_handshakes(tmp_path: Path) -> None:
    out = tmp_path / "s.pcap"
    connections = synth_capture.write_sizing_capture(out, 2800, seed=3)
    frames = read_frames(out)
    assert connections == 200 and len(frames) == 200 * synth_capture.PACKETS_PER_CONNECTION
    times = [t for t, _ in frames]
    assert times == sorted(times)  # the file is time-ordered
    syns = 0
    for _, frame in frames:
        ip, tcp = frame[14:34], frame[34:]
        assert synth_capture.checksum(ip) == 0  # a valid IPv4 header sums to zero
        pseudo = ip[12:20] + struct.pack("!BBH", 0, 6, len(tcp))
        assert synth_capture.checksum(pseudo + tcp) == 0  # and so does the TCP segment
        syns += tcp[13] == synth_capture.SYN
    assert syns == connections  # every conversation opens with exactly one SYN


def test_the_synthetic_capture_is_deterministic_and_has_no_failed_connection_pattern(
    tmp_path: Path,
) -> None:
    a, b, c = (tmp_path / n for n in ("a.pcap", "b.pcap", "c.pcap"))
    synth_capture.write_sizing_capture(a, 1400, seed=5)
    synth_capture.write_sizing_capture(b, 1400, seed=5)
    synth_capture.write_sizing_capture(c, 1400, seed=6)
    assert a.read_bytes() == b.read_bytes() != c.read_bytes()
    ports = {int.from_bytes(f[36:38], "big") for _, f in read_frames(a) if f[34 + 13] == 0x02}
    assert ports <= set(synth_capture.SERVICE_PORTS)  # fixed services: nothing scan-like


def test_concatenation_stops_at_a_packet_boundary_at_or_past_the_target(tmp_path: Path) -> None:
    one, two, out = tmp_path / "1.pcap", tmp_path / "2.pcap", tmp_path / "out.pcap"
    synth_capture.write_sizing_capture(one, 1400, seed=1)
    synth_capture.write_sizing_capture(two, 1400, seed=2)
    total = one.stat().st_size + two.stat().st_size - 24
    packets, size = bench.concatenate_to_size([one, two], total // 2 + 1, out)
    assert out.stat().st_size == size and size >= total // 2 + 1
    assert len(read_frames(out)) == packets  # still a well-formed capture
    assert size - total // 2 < 2000  # overshoots by less than one packet
    everything, full = bench.concatenate_to_size([one, two], 10**9, out)
    assert everything == 2800 and full == total  # a target past the end keeps every packet


def test_concatenation_refuses_other_formats_and_mismatched_headers(tmp_path: Path) -> None:
    good, text, other = tmp_path / "g.pcap", tmp_path / "t.pcap", tmp_path / "o.pcap"
    synth_capture.write_sizing_capture(good, 140, seed=1)
    text.write_bytes(b"not a capture at all" * 4)
    data = bytearray(good.read_bytes())
    data[16:20] = struct.pack("<I", 1500)  # a different snaplen
    other.write_bytes(bytes(data))
    with pytest.raises(bench.BenchError, match="not a classic pcap"):
        bench.concatenate_to_size([text], 10**6, tmp_path / "x.pcap")
    with pytest.raises(bench.BenchError, match="different pcap global header"):
        bench.concatenate_to_size([good, other], 10**9, tmp_path / "x.pcap")


def test_prepare_refuses_a_size_the_sources_cannot_reach(tmp_path: Path) -> None:
    source = tmp_path / "s.pcap"
    synth_capture.write_sizing_capture(source, 1400, seed=1)
    with pytest.raises(bench.BenchError, match="requested"):
        bench.prepare([source], [500], tmp_path / "out")
