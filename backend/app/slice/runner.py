"""Cut a packet slice from the original capture: `tcpdump -r -w` with the BPF, then `editcap -A/-B`.

Worker only (SEC-02: capture bytes are parsed only there). Both tools get an argv list, shell=False,
a minimal environment (TZ=UTC so editcap reads the time bounds as UTC), a timeout and no stdin. The
result must not exceed `max_bytes` (100 MB by default), otherwise the slice fails with a reason.
"""

import os
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from app.core.errors import IngestError
from app.ingest.capinfos import run_capinfos

MAX_SLICE_BYTES = 100 * 1024 * 1024
PADDING = timedelta(seconds=2)


@dataclass(frozen=True)
class SliceResult:
    path: Path
    size_bytes: int
    packets: int


def _run(argv: list[str], timeout_s: int, tz_utc: bool = False) -> None:
    env = {"PATH": os.environ.get("PATH", ""), "LC_ALL": "C"}
    if tz_utc:
        env["TZ"] = "UTC"
    try:
        result = subprocess.run(  # noqa: S603  # fixed argv, shell=False
            argv,
            capture_output=True,
            timeout=timeout_s,
            check=False,
            shell=False,
            stdin=subprocess.DEVNULL,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        raise IngestError("SLICE_TIMEOUT", f"{Path(argv[0]).name} exceeded {timeout_s} s.") from exc
    except OSError as exc:
        raise IngestError("SLICE_FAILED", f"Cannot run {Path(argv[0]).name}.") from exc
    if result.returncode != 0:
        raise IngestError("SLICE_FAILED", f"{Path(argv[0]).name} exited {result.returncode}.")


def _editcap_time(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S")


def build_slice(
    original: Path,
    out_path: Path,
    bpf: str,
    start: datetime,
    end: datetime,
    *,
    tcpdump_bin: str = "tcpdump",
    editcap_bin: str = "editcap",
    capinfos_bin: str = "capinfos",
    timeout_s: int = 120,
    max_bytes: int = MAX_SLICE_BYTES,
) -> SliceResult:
    """Filter by flows, then trim to [start - 2 s, end + 2 s]; an empty or oversized slice fails."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    filtered = out_path.with_suffix(".filtered.pcap")
    try:
        _run(
            [tcpdump_bin, "-n", "-r", str(original.resolve()), "-w", str(filtered), bpf],
            timeout_s,
        )
        lo = _editcap_time(start - PADDING)
        # editcap's stop bound is exclusive and has whole-second resolution: round the end up
        hi = _editcap_time(end + PADDING + timedelta(seconds=1))
        _run(
            [editcap_bin, "-F", "pcap", "-A", lo, "-B", hi, str(filtered), str(out_path)],
            timeout_s,
            tz_utc=True,
        )
    finally:
        filtered.unlink(missing_ok=True)
    size = out_path.stat().st_size
    if size > max_bytes:
        out_path.unlink(missing_ok=True)
        raise IngestError(
            "SLICE_TOO_LARGE", f"The slice would be {size} bytes (limit {max_bytes})."
        )
    info = run_capinfos(out_path, capinfos_bin, timeout_s)
    if info.packets == 0:
        out_path.unlink(missing_ok=True)
        raise IngestError("SLICE_EMPTY", "No packets matched the finding's flows and time range.")
    return SliceResult(out_path, size, info.packets)
