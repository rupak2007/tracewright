"""Shared test helpers: fake external tools, synthetic Zeek logs."""

import json
import stat
import sys
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any


def fake_executable(directory: Path, name: str, python_body: str) -> str:
    """An executable running `python_body` with the test interpreter (Windows and POSIX)."""
    directory = directory / "bin"  # keeps tool names from colliding with working directories
    directory.mkdir(exist_ok=True)
    script = directory / f"{name}.py"
    script.write_text(python_body)
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    if sys.platform == "win32":
        wrapper = directory / f"{name}.cmd"
        wrapper.write_text(f'@"{sys.executable}" "{script}" %*\n')
    else:
        wrapper = directory / name
        wrapper.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{script}" "$@"\n')
        wrapper.chmod(0o755)
    return str(wrapper)


def write_zeek_logs(directory: Path, logs: Mapping[str, Iterable[Any]]) -> None:
    """Write Zeek-style JSON-lines logs; str items are written verbatim (for malformed lines)."""
    directory.mkdir(parents=True, exist_ok=True)
    for name, rows in logs.items():
        lines = [row if isinstance(row, str) else json.dumps(row) for row in rows]
        (directory / f"{name}.log").write_text("\n".join(lines) + "\n", encoding="utf-8")


def conn_row(
    ts: float,
    orig: str = "10.0.0.5",
    resp: str = "10.0.0.10",
    resp_p: int = 80,
    **extra: Any,
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "ts": ts,
        "uid": f"C{ts}",
        "id.orig_h": orig,
        "id.orig_p": 50000,
        "id.resp_h": resp,
        "id.resp_p": resp_p,
        "proto": "tcp",
        "service": "http",
        "duration": 1.0,
        "orig_bytes": 100,
        "resp_bytes": 200,
        "conn_state": "SF",
        "history": "ShADadFf",
        "orig_pkts": 5,
        "resp_pkts": 5,
        "orig_ip_bytes": 300,
        "resp_ip_bytes": 400,
        "missed_bytes": 0,
    }
    row.update(extra)
    return row


CAPINFOS_HEADER = (
    '"File name","File type","File encapsulation","File time precision","Packet size limit",'
    '"Packet size limit min (inferred)","Packet size limit max (inferred)","Number of packets",'
    '"File size (bytes)","Data size (bytes)","Capture duration (seconds)","Start time","End time",'
    '"Data byte rate (bytes/sec)","Data bit rate (bits/sec)","Average packet size (bytes)",'
    '"Average packet rate (packets/sec)","SHA256","SHA1","Strict time order","Capture hardware",'
    '"Capture oper-sys","Capture application","Capture comment"'
)


def capinfos_table(
    packets: str = "29",
    snaplen: str = "65535",
    duration: str = "0.280000",
    start: str = "1700000000.010000",
    end: str = "1700000000.290000",
    encap: str = "ether",
) -> str:
    """capinfos `-T -m -Q -M -S` output in the shape observed from Wireshark 4.4.18."""
    row = (
        f'"/x.pcap","pcap","{encap}","microseconds","{snaplen}","n/a","n/a","{packets}","2339",'
        f'"1851","{duration}","{start}","{end}","6610.71","52885.72","63.83","103.57","aa","bb",'
        '"True","","","",""'
    )
    return CAPINFOS_HEADER + "\n" + row + "\n"
