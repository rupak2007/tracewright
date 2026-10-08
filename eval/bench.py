"""End-to-end throughput benchmark of the worker pipeline (NFR-01, plan P9).

    python -m eval.bench prepare --source data/lab/b04/capture.pcap [--source ...]
                                 --sizes 50 200 500
    python -m eval.bench run --run-id bench-v1 [--capture data/bench/bench-50MB.pcap ...]

`prepare` builds benchmark captures of the requested sizes (MB = 10^6 bytes) from REAL benign lab
captures: it appends the sources' packets in order and stops at the first packet boundary at or
past the size.
These files exist only to size the pipeline; they carry no labels and are never used for detector
or anomaly evaluation.

`run` analyses each capture with `python -m app.cli analyze` in a container configured like the
compose worker (non-root, read-only root, no capabilities, no network, memory/CPU limits) and
records wall time, the per-stage timings the pipeline writes to status.json, the largest single
process RSS (RUSAGE_CHILDREN, a lower bound of total memory) and the outcome. Failures (for
example an out-of-memory kill) are recorded as results, never retried silently. Results go to
eval/results/<run_id>/bench.json with the host description; nothing is estimated.
"""

import argparse
import contextlib
import json
import os
import platform
import struct
import subprocess
import sys
import time
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from eval.run_detectors import RESULTS_DIR, git_state

REPO = Path(__file__).resolve().parents[1]
BENCH_DIR = REPO / "data" / "bench"
IMAGE = "tracewright-worker:latest"
MB = 1_000_000  # decimal megabytes, as in NFR-01 (and below the 500 MiB upload cap)
PCAP_GLOBAL_HEADER = 24
PCAP_RECORD_HEADER = 16
_CLASSIC_MAGICS = {
    bytes.fromhex("d4c3b2a1"),
    bytes.fromhex("a1b2c3d4"),
    bytes.fromhex("4d3cb2a1"),
    bytes.fromhex("a1b23c4d"),
}

# runs inside the container: execute the CLI and report the largest child RSS
_WRAPPER = (
    "import json,resource,subprocess,sys,time\n"
    "t=time.monotonic()\n"
    "r=subprocess.run([sys.executable,'-m','app.cli','analyze','/in/capture','--out','/out/run'],"
    "capture_output=True,text=True)\n"
    "print(json.dumps({'rc':r.returncode,'seconds':round(time.monotonic()-t,2),"
    "'max_child_rss_kb':resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,"
    "'stdout_tail':r.stdout[-1500:],'stderr_tail':r.stderr[-800:]}))\n"
)


class BenchError(Exception):
    pass


def docker(*args: str, timeout: float | None = None) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "MSYS_NO_PATHCONV": "1"}
    return subprocess.run(  # noqa: S603
        ["docker", *args],  # noqa: S607
        capture_output=True,
        text=True,
        check=False,
        shell=False,
        timeout=timeout,
        env=env,
    )


def host_path(path: Path) -> str:
    return str(path.resolve()).replace("\\", "/")


def host_info() -> dict[str, Any]:
    info = docker("info", "--format", "{{.NCPU}} {{.MemTotal}} {{.OperatingSystem}}").stdout.split()
    return {
        "platform": platform.platform(),
        "processor": platform.processor(),
        "docker_cpus": int(info[0]) if info else None,
        "docker_memory_bytes": int(info[1]) if len(info) > 1 else None,
        "docker_os": " ".join(info[2:]),
    }


def concatenate_to_size(sources: Sequence[Path], target_bytes: int, out: Path) -> tuple[int, int]:
    """Append classic-pcap sources and stop at the first packet boundary at or past the target.

    Returns (packets, bytes). Sources must share one pcap global header (same byte order, link
    type and snaplen), which holds for captures recorded by the same lab recorder; anything else
    is refused rather than guessed at."""
    header = b""
    packets = written = 0
    with out.open("wb") as dst:
        for src in sources:
            with src.open("rb") as handle:
                head = handle.read(PCAP_GLOBAL_HEADER)
                if len(head) < PCAP_GLOBAL_HEADER or head[:4] not in _CLASSIC_MAGICS:
                    raise BenchError(f"{src.name} is not a classic pcap file")
                if not header:
                    header = head
                    dst.write(head)
                    written += len(head)
                elif head != header:
                    raise BenchError(f"{src.name} has a different pcap global header")
                little = head[:4] in (bytes.fromhex("d4c3b2a1"), bytes.fromhex("4d3cb2a1"))
                byte_order = "<" if little else ">"
                while written < target_bytes:
                    record = handle.read(PCAP_RECORD_HEADER)
                    if len(record) < PCAP_RECORD_HEADER:
                        break
                    (incl_len,) = struct.unpack(byte_order + "I", record[8:12])
                    body = handle.read(incl_len)
                    if len(body) < incl_len:
                        break
                    dst.write(record + body)
                    written += PCAP_RECORD_HEADER + incl_len
                    packets += 1
            if written >= target_bytes:
                break
    return packets, written


def prepare(sources: Sequence[Path], sizes_mb: Sequence[int], out_dir: Path) -> list[Path]:
    """Build one capture per size (MB = 10^6 bytes); a size the sources cannot reach is an error."""
    out_dir.mkdir(parents=True, exist_ok=True)
    available = sum(s.stat().st_size for s in sources)
    written: list[Path] = []
    for size in sizes_mb:
        if size * MB > available:
            raise BenchError(f"{size} MB requested but the sources total {available // MB} MB")
        target = out_dir / f"bench-{size}MB.pcap"
        concatenate_to_size(sources, size * MB, target)
        written.append(target)
    return written


def run_one(capture: Path, memory: str, cpus: str, timeout_s: int) -> dict[str, Any]:
    out = BENCH_DIR / "out" / capture.stem
    if out.exists():
        for child in sorted(out.rglob("*"), reverse=True):
            child.unlink() if child.is_file() else child.rmdir()
    out.mkdir(parents=True, exist_ok=True)
    args = [
        "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true", "--user", "10001:10001",
        "--memory", memory, "--cpus", cpus, "--pids-limit", "256",
        "--tmpfs", "/tmp",  # noqa: S108
        "-v", f"{host_path(capture)}:/in/capture:ro",
        "-v", f"{host_path(out)}:/out",
        "-v", f"{host_path(REPO / 'config')}:/config:ro",
        "-v", f"{host_path(REPO / 'knowledge')}:/knowledge:ro",
        "-e", "POSTGRES_DB=x", "-e", "POSTGRES_USER=x", "-e", "POSTGRES_PASSWORD=x",
        "--entrypoint", "python", IMAGE, "-c", _WRAPPER,
    ]  # fmt: skip
    started = time.monotonic()
    try:
        done = docker(*args, timeout=timeout_s)
    except subprocess.TimeoutExpired:
        return {"capture": capture.name, "outcome": "timeout", "limit_s": timeout_s}
    wall = round(time.monotonic() - started, 2)
    record: dict[str, Any] = {
        "capture": capture.name,
        "bytes": capture.stat().st_size,
        "container_limits": {"memory": memory, "cpus": cpus},
        "wall_seconds_including_container_start": wall,
    }
    try:
        inner = json.loads(done.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        # the container died before reporting: an OOM kill is exit 137
        return {
            **record,
            "outcome": f"container_exit_{done.returncode}",
            "stderr": done.stderr[-600:],
        }
    record["pipeline_seconds"] = inner["seconds"]
    record["max_child_rss_mb"] = round(inner["max_child_rss_kb"] / 1024, 1)
    status_path = out / "run" / "status.json"
    if status_path.exists():
        status = json.loads(status_path.read_text(encoding="utf-8"))
        record["status"] = status.get("status")
        record["error_code"] = status.get("error_code")
        record["stage_ms"] = status.get("stage_ms", {})
    summary: dict[str, Any] = {}
    with contextlib.suppress(ValueError, IndexError):
        summary = json.loads(inner["stdout_tail"].strip().splitlines()[-1])
    record["connections"] = summary.get("connections")
    record["findings"] = summary.get("findings")
    record["incidents"] = len(summary.get("incidents", [])) if summary else None
    record["outcome"] = "completed" if inner["rc"] == 0 else f"analysis_exit_{inner['rc']}"
    if inner["rc"] != 0:
        record["stderr_tail"] = inner["stderr_tail"]
    packets = docker(
        "run", "--rm", "--entrypoint", "capinfos", "-v", f"{host_path(capture)}:/in/c:ro", IMAGE,
        "-c", "-T", "-m", "/in/c",
    )  # fmt: skip
    record["capinfos"] = packets.stdout.strip().splitlines()[-1] if packets.stdout else None
    return record


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    prep = sub.add_parser("prepare")
    prep.add_argument("--source", type=Path, action="append", required=True)
    prep.add_argument("--sizes", type=int, nargs="+", default=[50, 200, 500])
    prep.add_argument("--out-dir", type=Path, default=BENCH_DIR)
    run = sub.add_parser("run")
    run.add_argument("--run-id", required=True)
    run.add_argument("--capture", type=Path, action="append")
    run.add_argument("--memory", default="3g")
    run.add_argument("--cpus", default="4")
    run.add_argument("--timeout-s", type=int, default=1800)
    run.add_argument("--repeat", type=int, default=1, help="runs per capture (variance)")
    run.add_argument("--out", type=Path, default=RESULTS_DIR)
    args = parser.parse_args(argv)
    try:
        if args.command == "prepare":
            for path in prepare(args.source, args.sizes, args.out_dir):
                print(f"wrote {path} ({path.stat().st_size // MB} MB)")
            return 0
        captures = args.capture or sorted(BENCH_DIR.glob("bench-*MB.pcap"))
        if not captures:
            raise BenchError("no capture to benchmark: run `prepare` first")
        target = args.out / args.run_id
        if target.exists():
            raise BenchError(f"{target} already exists; results are never overwritten")
        results = [
            {**run_one(c, args.memory, args.cpus, args.timeout_s), "repeat": n}
            for c in captures
            for n in range(1, args.repeat + 1)
        ]
    except (BenchError, subprocess.SubprocessError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    target.mkdir(parents=True)
    payload = {
        "results": results,
        "host": host_info(),
        "image": IMAGE,
        "git": git_state(),
        "generated_at": datetime.now(UTC).isoformat(),
        "note": "Captures are real benign lab captures cut/concatenated for sizing only.",
    }
    (target / "bench.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    for r in results:
        print(
            json.dumps(
                {
                    k: r.get(k)
                    for k in ("capture", "outcome", "pipeline_seconds", "max_child_rss_mb")
                }
            )
        )
    print(f"wrote {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
