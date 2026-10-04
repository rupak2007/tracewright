"""Record one lab run: services up -> tcpdump -> labelled scenarios -> capture + run.json.

    python -m lab.run_lab --run-id smoke01 --plan client1:ntp:20 --plan client2:cdn_browsing:20
    python -m lab.run_lab --run-id r001 --seed 1 --plan client1:monitoring_heartbeat:300 --promote

A plan item is `client:scenario[:duration_s[:json-params]]` (client1..client3). Output lands in
data/lab/<run_id>/ (capture.pcap, labels.jsonl, run.json; gitignored). `--promote` also copies
labels.jsonl and run.json to lab/runs/<run_id>/ so they can be committed and assigned a split.
Smoke runs must NOT be promoted. Only benign scenarios exist in this milestone.
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess  # fixed argv lists only, shell=False
import sys
import time
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from lab.benign.scenarios import SCENARIOS
from lab.labeler import merge_label_files
from lab.runmeta import RunMeta
from lab.schema import format_time

REPO = Path(__file__).resolve().parents[1]
COMPOSE_FILE = REPO / "lab" / "docker-compose.lab.yml"
CLIENT_IPS = {"client1": "172.20.0.101", "client2": "172.20.0.102", "client3": "172.20.0.103"}
DATA = REPO / "data" / "lab"


class LabError(RuntimeError):
    """A docker compose step of the run failed; the message carries compose's own stderr."""


def compose(*args: str, run_id: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "RUN_ID": run_id}
    result = subprocess.run(  # noqa: S603
        ["docker", "compose", "-f", str(COMPOSE_FILE), *args],  # noqa: S607
        env=env,
        check=False,
        capture_output=True,
        text=True,
        shell=False,
    )
    if check and result.returncode != 0:
        detail = result.stderr.strip()[-2000:]
        raise LabError(f"docker compose {' '.join(args)} failed: {detail}")
    return result


def parse_plan(item: str) -> dict[str, object]:
    parts = item.split(":", 3)
    if len(parts) < 2 or parts[0] not in CLIENT_IPS:
        raise ValueError(
            f"bad plan item {item!r}: expected client1..client3:scenario[:secs[:json]]"
        )
    if parts[1] not in SCENARIOS:
        raise ValueError(f"unknown scenario {parts[1]!r}; known: {sorted(SCENARIOS)}")
    duration = float(parts[2]) if len(parts) > 2 and parts[2] else 60.0
    params = json.loads(parts[3]) if len(parts) > 3 else {}
    if duration <= 0 or not isinstance(params, dict):
        raise ValueError(f"bad duration/params in {item!r}")
    return {"client": parts[0], "scenario": parts[1], "duration_s": duration, "params": params}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--plan", action="append", required=True)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--promote", action="store_true", help="copy labels+run.json to lab/runs/")
    args = parser.parse_args(argv)
    plan = [parse_plan(item) for item in args.plan]
    clients = [str(item["client"]) for item in plan]
    if len(clients) != len(set(clients)):
        print("each client can run one scenario per run (fixed IP address)", file=sys.stderr)
        return 2
    run_dir = DATA / args.run_id
    if run_dir.exists():
        print(f"{run_dir} already exists; refusing to overwrite a recorded run", file=sys.stderr)
        return 2
    run_dir.mkdir(parents=True)
    run_dir.chmod(0o777)  # the lab containers run as an unprivileged uid
    started = datetime.now(UTC)
    failed = False
    try:
        compose("up", "-d", "--build", "--wait", "services", run_id=args.run_id)
        compose("up", "-d", "capture", run_id=args.run_id)
        time.sleep(3)  # let tcpdump open the interface
        procs = []
        for number, item in enumerate(plan):
            client = str(item["client"])
            cmd = [
                "run",
                "--rm",
                "-T",
                "--no-deps",
                client,
                "python",
                "-m",
                "lab.benign.generator",
                "--run-id",
                args.run_id,
                "--scenario",
                str(item["scenario"]),
                "--duration-s",
                str(item["duration_s"]),
                "--seed",
                str(args.seed + number),
                "--actor-ip",
                CLIENT_IPS[client],
                "--labels",
                f"/captures/{args.run_id}/labels.part{number}.jsonl",
                "--id-prefix",
                f"p{number}-",
                "--params",
                json.dumps(item["params"]),
            ]
            procs.append(
                subprocess.Popen(  # noqa: S603
                    ["docker", "compose", "-f", str(COMPOSE_FILE), "--profile", "clients", *cmd],  # noqa: S607
                    env={**os.environ, "RUN_ID": args.run_id},
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    shell=False,
                )
            )
        for proc in procs:
            out, _ = proc.communicate()
            if proc.returncode != 0:
                failed = True
                print(out, file=sys.stderr)
        time.sleep(2)  # let in-flight packets reach the capture
    except LabError as exc:
        compose("down", "-v", "--remove-orphans", run_id=args.run_id, check=False)
        shutil.rmtree(run_dir, ignore_errors=True)  # nothing usable was recorded
        print(exc, file=sys.stderr)
        return 1
    finally:
        compose("stop", "-t", "10", "capture", run_id=args.run_id, check=False)
        compose("down", "-v", "--remove-orphans", run_id=args.run_id, check=False)
    ended = datetime.now(UTC)
    if failed:
        print("a generator failed; run recorded but NOT usable as ground truth", file=sys.stderr)
        return 1
    capture = run_dir / "capture.pcap"
    labels = run_dir / "labels.jsonl"
    parts = sorted(run_dir.glob("labels.part*.jsonl"))
    episodes = merge_label_files(parts, labels)
    for part in parts:
        part.unlink()
    meta = RunMeta(
        run_id=args.run_id,
        capture_sha256=hashlib.sha256(capture.read_bytes()).hexdigest(),
        capture_bytes=capture.stat().st_size,
        start=format_time(started),
        end=format_time(ended),
        seed=args.seed,
        holdout=False,
        benign_only=all(e.kind == "hard_negative" for e in episodes),
        duration_s=round((ended - started).total_seconds(), 1),
        scenarios=tuple(plan),
        network_config="network.lab.yaml",
        tool_versions={"python": sys.version.split()[0]},
    )
    (run_dir / "run.json").write_text(meta.to_json(), encoding="utf-8")
    print(f"recorded {args.run_id}: {capture.stat().st_size} bytes, {len(episodes)} episode(s)")
    if args.promote:
        target = REPO / "lab" / "runs" / args.run_id
        target.mkdir(parents=True)
        shutil.copy2(labels, target / "labels.jsonl")
        shutil.copy2(run_dir / "run.json", target / "run.json")
        print(f"promoted to {target} (commit it, then assign a split with eval/splits.py)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
