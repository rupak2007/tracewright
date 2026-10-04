"""Record, analyse and verify the runs listed in a committed corpus plan (benign lab runs only).

    python -m lab.record_corpus lab/corpus/benign_v1.json [--runs b01,b02] [--discard-partial]

Per run (resumable; a run already verified is skipped):
  1. `lab.run_lab` records the capture + labels and promotes labels/run.json to lab/runs/<id>/;
  2. the capture is analysed by the P1 pipeline in the sandboxed worker (no network, read-only);
  3. `lab.verify_run` checks the labels against that analysis and writes verification.json.
Nothing is assigned to a split here; run `python -m eval.splits assign` afterwards. A failed
step stops the driver and leaves the evidence in place (use --discard-partial to clear an
interrupted recording of a run that was never promoted). Needs Docker and the backend env.
"""

import argparse
import json
import shutil
import subprocess  # fixed argv lists only, shell=False
import sys
from collections.abc import Sequence
from pathlib import Path

from lab import run_lab, verify_run
from lab.runmeta import load_run
from lab.verification import eligibility

REPO = Path(__file__).resolve().parents[1]
DATA = REPO / "data"


def _stage_config(network_config: str) -> Path:
    """Config dir for the worker: the lab's network context presented as network.yaml."""
    target = DATA / "lab_config"
    (target / "zeek").mkdir(parents=True, exist_ok=True)
    shutil.copyfile(REPO / "config" / network_config, target / "network.yaml")
    shutil.copyfile(REPO / "config" / "profile.yaml", target / "profile.yaml")
    shutil.copyfile(REPO / "config" / "zeek" / "site.zeek", target / "zeek" / "site.zeek")
    return target


def analyse(run_id: str, network_config: str) -> Path:
    capture_dir = DATA / "lab" / run_id
    cfg = _stage_config(network_config)
    out_root = DATA / "analysis"
    out_root.mkdir(parents=True, exist_ok=True)
    out_root.chmod(0o777)
    result = subprocess.run(  # noqa: S603
        [  # noqa: S607
            "docker",
            "compose",
            "-f",
            str(REPO / "docker-compose.yml"),
            "run",
            "--rm",
            "--no-deps",
            "-T",
            "-v",
            f"{capture_dir}:/in:ro",
            "-v",
            f"{cfg}:/labcfg:ro",
            "-v",
            f"{out_root}:/out",
            "worker",
            "python",
            "-m",
            "app.cli",
            "analyze",
            "/in/capture.pcap",
            "--out",
            f"/out/{run_id}",
            "--config-dir",
            "/labcfg",
        ],
        capture_output=True,
        text=True,
        check=False,
        shell=False,
        cwd=REPO,
    )
    summary = result.stdout.strip().splitlines()[-1] if result.stdout.strip() else ""
    print(f"  analysis: {summary or result.stderr.strip()[-300:]}")
    if result.returncode != 0:
        raise RuntimeError(f"analysis of {run_id} failed")
    return out_root / run_id


def record_one(entry: dict[str, object], network_config: str, discard_partial: bool) -> bool:
    run_id = str(entry["run_id"])
    promoted = REPO / "lab" / "runs" / run_id
    if promoted.exists():
        eligible, reason = eligibility(promoted, load_run(promoted / "run.json"))
        print(f"{run_id}: already promoted ({reason})")
        if eligible:
            return True
    partial = DATA / "lab" / run_id
    if partial.exists() and not promoted.exists():
        if not discard_partial:
            print(
                f"{run_id}: {partial} exists from an interrupted recording; "
                "re-run with --discard-partial to clear it",
                file=sys.stderr,
            )
            return False
        shutil.rmtree(partial)
    if not promoted.exists():
        args = ["--run-id", run_id, "--seed", str(entry["seed"]), "--promote"]
        for item in entry["plan"]:  # type: ignore[attr-defined]
            args += ["--plan", str(item)]
        print(f"{run_id}: recording ({len(entry['plan'])} scenarios)")  # type: ignore[arg-type]
        if run_lab.main(args) != 0:
            return False
    analysis = analyse(run_id, network_config)
    code = verify_run.main([run_id, str(analysis)])
    return code == 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Record the runs in a corpus plan.")
    parser.add_argument("plan", type=Path)
    parser.add_argument("--runs", help="comma-separated run ids to process (default: all)")
    parser.add_argument("--discard-partial", action="store_true")
    args = parser.parse_args(argv)
    plan = json.loads(args.plan.read_text(encoding="utf-8"))
    wanted = set(args.runs.split(",")) if args.runs else None
    entries = [e for e in plan["runs"] if wanted is None or e["run_id"] in wanted]
    if wanted and len(entries) != len(wanted):
        print("unknown run id in --runs", file=sys.stderr)
        return 2
    for entry in entries:
        if not record_one(entry, plan["network_config"], args.discard_partial):
            print(f"STOPPED at {entry['run_id']}", file=sys.stderr)
            return 1
    print("done; now run `python -m eval.splits assign` and `validate`")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
