"""Run Zeek on a validated capture (stage S1). Worker only (SEC-02).

The capture is attacker-controlled: it is passed as a single list element with shell=False, the
child gets a minimal environment (no database credentials) and a timeout, and stderr goes to
a file.
"""

import logging
import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from app.core.errors import IngestError

logger = logging.getLogger(__name__)

_STDERR_TAIL_BYTES = 600


@dataclass(frozen=True)
class ZeekRun:
    log_dir: Path
    stderr_path: Path
    duration_s: float
    log_files: tuple[str, ...]


def _printable_tail(path: Path, limit: int = _STDERR_TAIL_BYTES) -> str:
    """Tail of a diagnostics file, control characters removed (it may echo capture data)."""
    try:
        data = path.read_bytes()[-limit:]
    except OSError:
        return ""
    text = data.decode("utf-8", errors="replace")
    return "".join(ch if ch.isprintable() or ch == "\n" else "?" for ch in text).strip()


def run_zeek(
    pcap: Path,
    log_dir: Path,
    stderr_dir: Path,
    site_script: Path,
    zeek_bin: str,
    timeout_s: int,
) -> ZeekRun:
    """Run `zeek -C -r <pcap> <site policy>` with cwd=log_dir; raise IngestError on any failure."""
    pcap = pcap.resolve()
    log_dir.mkdir(parents=True, exist_ok=True)
    stderr_dir.mkdir(parents=True, exist_ok=True)
    stderr_path = stderr_dir / "zeek.stderr.txt"
    # -C: ignore checksum errors (offloading NICs); -D: zeroed seeds, so UIDs repeat (NFR-02).
    argv = [
        zeek_bin,
        "-C",
        "-D",
        "-r",
        str(pcap),
        str(site_script.resolve()),
        "LogAscii::use_json=T",
    ]
    env = {"PATH": os.environ.get("PATH", ""), "HOME": str(log_dir), "LC_ALL": "C"}
    started = time.monotonic()
    try:
        with stderr_path.open("wb") as err, open(os.devnull, "wb") as out:
            result = subprocess.run(  # noqa: S603  # fixed argv, shell=False
                argv,
                cwd=log_dir,
                env=env,
                stdout=out,
                stderr=err,
                stdin=subprocess.DEVNULL,
                timeout=timeout_s,
                check=False,
                shell=False,
            )
    except subprocess.TimeoutExpired as exc:
        raise IngestError(
            "ZEEK_TIMEOUT", f"Zeek did not finish within {timeout_s} s and was stopped."
        ) from exc
    except OSError as exc:
        raise IngestError("ZEEK_NOT_FOUND", f"Cannot run Zeek: {type(exc).__name__}.") from exc
    duration = time.monotonic() - started
    if result.returncode != 0:
        detail = _printable_tail(stderr_path)
        raise IngestError(
            "ZEEK_FAILED", f"Zeek exited with status {result.returncode}: {detail}".rstrip(": ")
        )
    log_files = tuple(sorted(p.name for p in log_dir.glob("*.log")))
    logger.info("zeek finished", extra={"duration_ms": int(duration * 1000)})
    return ZeekRun(log_dir, stderr_path, duration, log_files)
