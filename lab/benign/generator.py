"""Run one benign scenario against the lab services and label it.

    python -m lab.benign.generator --run-id r001 --scenario ntp --duration-s 300 --seed 1 \
        --actor-ip 172.20.0.101 --labels /captures/r001/labels.jsonl
"""

import argparse
import json
import random
from collections.abc import Sequence
from pathlib import Path

from lab.benign.scenarios import SCENARIOS, Context, run_scenario
from lab.benign.servers import Ports
from lab.labeler import Labeler


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run one labelled benign scenario.")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--scenario", required=True, choices=sorted(SCENARIOS))
    parser.add_argument("--duration-s", type=float, required=True)
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--actor-ip", required=True)
    parser.add_argument("--internal-host", default="172.20.0.20")
    parser.add_argument("--external-host", default="172.21.0.20")
    parser.add_argument("--labels", type=Path, required=True, help="this process's own file")
    parser.add_argument(
        "--id-prefix", help="episode id prefix, unique per process (default c<octet>-)"
    )
    parser.add_argument("--params", default="{}", help="JSON object of scenario parameters")
    args = parser.parse_args(argv)
    params = json.loads(args.params)
    if not isinstance(params, dict):
        parser.error("--params must be a JSON object")
    ctx = Context(
        internal_host=args.internal_host,
        external_host=args.external_host,
        ports=Ports(),
        actor=args.actor_ip,
        rng=random.Random(args.seed),  # noqa: S311  # reproducible traffic, not security
        duration_s=args.duration_s,
        params=params,
    )
    prefix = args.id_prefix or f"c{args.actor_ip.rsplit('.', 1)[-1]}-"
    run_scenario(args.scenario, ctx, Labeler(args.labels, args.run_id, id_prefix=prefix))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
