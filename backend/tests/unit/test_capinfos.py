from pathlib import Path

import pytest

from app.core.errors import IngestError
from app.ingest.capinfos import parse_capinfos_table, run_capinfos
from tests.helpers import capinfos_table, fake_executable


def test_parses_observed_output() -> None:
    info = parse_capinfos_table(capinfos_table())
    assert info.packets == 29
    assert info.first_ts == pytest.approx(1700000000.01)
    assert info.last_ts == pytest.approx(1700000000.29)
    assert info.duration_s == pytest.approx(0.28)
    assert info.snaplen == 65535
    assert info.link_type == "ether"


def test_empty_capture_has_no_times() -> None:
    info = parse_capinfos_table(capinfos_table(packets="0", duration="n/a", start="n/a", end="n/a"))
    assert (info.packets, info.first_ts, info.last_ts, info.duration_s) == (0, None, None, None)


def test_pcapng_snaplen_not_set() -> None:
    assert parse_capinfos_table(capinfos_table(snaplen="(not set)")).snaplen is None


@pytest.mark.parametrize("output", ["", "garbage", capinfos_table().splitlines()[0] + "\n"])
def test_unexpected_output_rejected(output: str) -> None:
    with pytest.raises(IngestError) as exc:
        parse_capinfos_table(output)
    assert exc.value.code == "CAPINFOS_FAILED"


def test_run_capinfos_with_fake_tool(tmp_path: Path) -> None:
    body = f"import sys\nprint({capinfos_table(packets='7')!r}, end='')\n"
    tool = fake_executable(tmp_path, "capinfos", body)
    assert run_capinfos(tmp_path / "x.pcap", tool, 30).packets == 7


def test_nonzero_exit_is_a_failure_even_with_output(tmp_path: Path) -> None:
    body = f"import sys\nprint({capinfos_table()!r}, end='')\nsys.exit(1)\n"
    tool = fake_executable(tmp_path, "capinfos", body)
    with pytest.raises(IngestError) as exc:
        run_capinfos(tmp_path / "x.pcap", tool, 30)
    assert exc.value.code == "CAPINFOS_FAILED"


def test_missing_binary(tmp_path: Path) -> None:
    with pytest.raises(IngestError) as exc:
        run_capinfos(tmp_path / "x.pcap", str(tmp_path / "nope"), 30)
    assert exc.value.code == "CAPINFOS_FAILED"


def test_timeout(tmp_path: Path) -> None:
    tool = fake_executable(tmp_path, "capinfos", "import time\ntime.sleep(10)\n")
    with pytest.raises(IngestError) as exc:
        run_capinfos(tmp_path / "x.pcap", tool, 1)
    assert exc.value.code == "CAPINFOS_TIMEOUT"
