"""Packet count, time span, snaplen, link type via `capinfos` (architecture §5.3). Worker only."""

import csv
import io
import subprocess
from dataclasses import dataclass
from pathlib import Path

from app.core.errors import IngestError


@dataclass(frozen=True)
class CapInfo:
    packets: int
    first_ts: float | None  # epoch seconds; None for a capture with no packets
    last_ts: float | None
    duration_s: float | None
    snaplen: int | None  # None when the file does not record one
    link_type: str


def _float_or_none(value: str) -> float | None:
    try:
        return float(value)
    except ValueError:
        return None


def parse_capinfos_table(output: str) -> CapInfo:
    """Parse `capinfos -T -m -Q -M -S` output (header row + one record)."""
    rows = list(csv.DictReader(io.StringIO(output)))
    if len(rows) != 1:
        raise IngestError("CAPINFOS_FAILED", "Unexpected capinfos output.")
    row = rows[0]
    try:
        packets = int(row["Number of packets"])
        link_type = row["File encapsulation"]
        snaplen_raw = row["Packet size limit"]
        first = _float_or_none(row["Start time"])
        last = _float_or_none(row["End time"])
        duration = _float_or_none(row["Capture duration (seconds)"])
    except (KeyError, ValueError) as exc:
        raise IngestError("CAPINFOS_FAILED", "Unexpected capinfos output.") from exc
    snaplen = int(snaplen_raw) if snaplen_raw.isdigit() else None
    return CapInfo(packets, first, last, duration, snaplen, link_type)


def run_capinfos(pcap: Path, capinfos_bin: str, timeout_s: int) -> CapInfo:
    argv = [capinfos_bin, "-T", "-m", "-Q", "-M", "-S", str(pcap.resolve())]
    try:
        result = subprocess.run(  # noqa: S603  # fixed argv, shell=False
            argv,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout_s,
            check=False,
            shell=False,
            stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired as exc:
        raise IngestError("CAPINFOS_TIMEOUT", f"capinfos exceeded {timeout_s} s.") from exc
    except OSError as exc:
        raise IngestError("CAPINFOS_FAILED", f"Cannot run capinfos: {type(exc).__name__}.") from exc
    if result.returncode != 0:
        # capinfos prints a table even for a cut-short file but exits 1; do not trust partial data.
        raise IngestError("CAPINFOS_FAILED", f"capinfos exited with status {result.returncode}.")
    return parse_capinfos_table(result.stdout)
