"""BPF construction and the slice runner's control flow (fake tools). SYNTHETIC inputs."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from app.core.errors import IngestError
from app.slice.builder import MAX_FLOWS, MAX_HOST_PAIRS, SliceTooBroad, build_bpf, normalise_flows
from app.slice.runner import build_slice
from tests.helpers import capinfos_table, fake_executable

START = datetime(2026, 11, 2, 10, 0, 0, tzinfo=UTC)


def flows(n: int, hosts: int = 1) -> list[tuple[str, str, object, str, object]]:
    return [("tcp", "10.0.0.5", 40000 + i, f"10.0.1.{i % hosts + 1}", 80) for i in range(n)]


# ---- builder ----------------------------------------------------------------------------
def test_flows_are_validated_deduplicated_and_sorted() -> None:
    rows: list[tuple[str, str, object, str, object]] = [
        ("tcp", "10.0.0.5", 40000, "10.0.0.9", 22),
        ("tcp", "10.0.0.5", 40000, "10.0.0.9", 22),  # duplicate
        ("tcp", "not-an-ip; rm -rf /", 1, "10.0.0.9", 22),  # dropped, never reaches a filter
        ("udp", "10.0.0.5", True, "10.0.0.9", 99999),  # bool and out-of-range ports -> no port
        ("tcp", "2001:db8::1", 1, "10.0.0.9", 80),
    ]
    out = normalise_flows(rows)
    assert len(out) == 3
    assert [f.src for f in out] == ["10.0.0.5", "10.0.0.5", "2001:db8::1"]
    assert any(f.proto == "udp" and f.src_port is None and f.dst_port is None for f in out)


def test_each_flow_becomes_one_parenthesised_clause_with_both_ports() -> None:
    bpf = build_bpf(normalise_flows([("tcp", "10.0.0.5", 40000, "10.0.0.9", 22)]))
    assert bpf == "(tcp and host 10.0.0.5 and host 10.0.0.9 and port 40000 and port 22)"
    icmp = build_bpf(normalise_flows([("icmp", "10.0.0.5", 8, "10.0.0.9", 0)]))
    assert icmp == "(icmp and host 10.0.0.5 and host 10.0.0.9)"  # no ports for icmp
    unknown = build_bpf(normalise_flows([("gre", "10.0.0.5", None, "10.0.0.9", None)]))
    assert unknown == "(host 10.0.0.5 and host 10.0.0.9)"


def test_the_filter_never_contains_anything_but_addresses_ports_and_keywords() -> None:
    bpf = build_bpf(normalise_flows(flows(10, hosts=3)))
    allowed = set("0123456789abcdef:.() ")
    words = set(bpf.replace("(", " ").replace(")", " ").split())
    assert words <= {"tcp", "and", "or", "host", "port"} | {w for w in words if set(w) <= allowed}
    assert ";" not in bpf and "|" not in bpf and "`" not in bpf and "\n" not in bpf


def test_many_flows_fall_back_to_host_pairs_and_a_huge_spread_is_refused() -> None:
    exactly = build_bpf(normalise_flows(flows(MAX_FLOWS)))
    assert exactly.count("port 80") == MAX_FLOWS
    fallback = build_bpf(normalise_flows(flows(MAX_FLOWS + 1, hosts=3)))
    assert fallback == " or ".join(f"(host 10.0.0.5 and host 10.0.1.{i})" for i in (1, 2, 3))
    spread = [
        ("tcp", "10.0.0.5", 1, f"10.1.{i // 250}.{i % 250 + 1}", 80)
        for i in range(MAX_HOST_PAIRS + 1)
    ]
    with pytest.raises(SliceTooBroad, match="too broad"):
        build_bpf(normalise_flows(spread))
    with pytest.raises(SliceTooBroad, match="no connection evidence"):
        build_bpf([])


# ---- runner -----------------------------------------------------------------------------
def tools(
    tmp: Path, *, tcpdump: str | None = None, packets: int = 4, out_bytes: int = 64
) -> dict[str, str]:
    default_tcpdump = (
        "import sys, pathlib\\n"
        "a = sys.argv[1:]\\n"
        "pathlib.Path(a[a.index('-w') + 1]).write_bytes(b'x' * 10)\\n"
    ).replace("\\n", "\n")
    editcap = f"import sys, pathlib\npathlib.Path(sys.argv[-1]).write_bytes(b'y' * {out_bytes})\n"
    info = f"import sys\nprint({capinfos_table(packets=str(packets))!r}, end='')\n"
    return {
        "tcpdump_bin": fake_executable(tmp, "tcpdump", tcpdump or default_tcpdump),
        "editcap_bin": fake_executable(tmp, "editcap", editcap),
        "capinfos_bin": fake_executable(tmp, "capinfos", info),
    }


def run(tmp: Path, **kw: object) -> object:
    original = tmp / "orig.pcap"
    original.write_bytes(b"orig")
    kwargs = {k: v for k, v in kw.items() if k in ("max_bytes",)}
    return build_slice(
        original,
        tmp / "slices" / "1.pcap",
        "(host 10.0.0.5)",
        START,
        START + timedelta(seconds=30),
        **tools(tmp, **{k: v for k, v in kw.items() if k not in kwargs}),  # type: ignore[arg-type]
        **kwargs,  # type: ignore[arg-type]
    )


def test_a_slice_is_built_counted_and_the_intermediate_file_removed(tmp_path: Path) -> None:
    result = run(tmp_path)
    assert result.path == tmp_path / "slices" / "1.pcap" and result.packets == 4  # type: ignore[attr-defined]
    assert result.size_bytes == 64 and (tmp_path / "slices" / "1.pcap").read_bytes() == b"y" * 64  # type: ignore[attr-defined]
    assert list((tmp_path / "slices").glob("*.filtered.pcap")) == []


def test_an_oversized_slice_is_removed_and_reported(tmp_path: Path) -> None:
    with pytest.raises(IngestError) as err:
        run(tmp_path, out_bytes=500, max_bytes=100)
    assert err.value.code == "SLICE_TOO_LARGE" and not (tmp_path / "slices" / "1.pcap").exists()


def test_an_empty_slice_is_removed_and_reported(tmp_path: Path) -> None:
    with pytest.raises(IngestError) as err:
        run(tmp_path, packets=0)
    assert err.value.code == "SLICE_EMPTY" and not (tmp_path / "slices" / "1.pcap").exists()


def test_tool_failures_and_timeouts_surface_as_slice_errors(tmp_path: Path) -> None:
    with pytest.raises(IngestError) as err:
        run(tmp_path, tcpdump="import sys\nsys.exit(1)\n")
    assert err.value.code == "SLICE_FAILED"
    slow = "import time\ntime.sleep(5)\n"
    original = tmp_path / "orig.pcap"
    original.write_bytes(b"orig")
    with pytest.raises(IngestError) as slow_err:
        build_slice(
            original, tmp_path / "s" / "2.pcap", "(host 10.0.0.5)", START, START,
            tcpdump_bin=fake_executable(tmp_path, "slowdump", slow), timeout_s=1,
        )  # fmt: skip
    assert slow_err.value.code == "SLICE_TIMEOUT"
    with pytest.raises(IngestError) as missing:
        build_slice(original, tmp_path / "s" / "3.pcap", "(host 10.0.0.5)", START, START,
                    tcpdump_bin=str(tmp_path / "nope"))  # fmt: skip
    assert missing.value.code == "SLICE_FAILED"
