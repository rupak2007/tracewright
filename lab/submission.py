"""Schema for an externally supplied run (`submission.json`) and its cross-checks.

This describes WHAT a supplier must declare about a capture that was produced outside the lab
runner. It deliberately says nothing about how traffic is produced. Everything here is a claim by
the supplier: it is validated for completeness and internal consistency, then the claims are
checked against the capture itself by `lab/verify_run.py`. Standard library only.

submission.json
{
  "run_id": "x001",
  "holdout": false,                       # true only for LAB-HOLDOUT runs
  "start": "2026-11-02T10:00:00.000Z",    # window the supplier says the capture covers
  "end":   "2026-11-02T10:30:00.000Z",
  "network_config": "network.lab.yaml",   # file under config/ that classifies internal/external
  "clients": [{"id": "c1", "ip": "172.20.0.101"}],
  "scenarios": [{"kind": "attack", "class": "<registered class>", "client": "c1", "tool": ""}],
  "provenance": { ...see lab.runmeta.Provenance... }
}
"""

import ipaddress
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from lab.runmeta import Provenance
from lab.schema import CLASSES_BY_KIND, Episode, parse_time

_REQUIRED = (
    "run_id",
    "holdout",
    "start",
    "end",
    "network_config",
    "clients",
    "scenarios",
    "provenance",
)
TIME_SLACK_S = 5.0
SCENARIO_KEYS = {"kind", "class", "client", "tool"}


def valid_run_id(run_id: object) -> str:
    if (
        not isinstance(run_id, str)
        or not run_id
        or len(run_id) > 64
        or run_id in {".", ".."}
        or not all(c.isalnum() or c in "-_" for c in run_id)
    ):
        raise ValueError(f"invalid run_id {run_id!r}: use letters, digits, '-' and '_' only")
    return run_id


@dataclass(frozen=True)
class DeclaredScenario:
    kind: str
    cls: str
    client: str
    tool: str = ""


@dataclass(frozen=True)
class Submission:
    run_id: str
    holdout: bool
    start: str
    end: str
    network_config: str
    clients: tuple[dict[str, str], ...]
    scenarios: tuple[DeclaredScenario, ...]
    provenance: Provenance

    def client_ips(self) -> frozenset[str]:
        return frozenset(c["ip"] for c in self.clients)

    def declared_pairs(self) -> frozenset[tuple[str, str]]:
        return frozenset((s.kind, s.cls) for s in self.scenarios)


def parse_submission(raw: object) -> Submission:
    """Validate a decoded submission.json. Raises ValueError naming the first problem."""
    if not isinstance(raw, dict):
        raise ValueError("submission must be a JSON object")
    missing = [k for k in _REQUIRED if k not in raw]
    if missing:
        raise ValueError(f"missing fields: {missing}")
    unknown = set(raw) - set(_REQUIRED)
    if unknown:
        raise ValueError(f"unknown fields: {sorted(unknown)}")
    run_id = valid_run_id(raw["run_id"])
    if not isinstance(raw["holdout"], bool):
        raise ValueError("holdout must be true or false")
    start, end = parse_time(raw["start"]), parse_time(raw["end"])
    if end < start:
        raise ValueError("end is before start")
    network_config = raw["network_config"]
    if (
        not isinstance(network_config, str)
        or not network_config.startswith("network")
        or not network_config.endswith(".yaml")
        or "/" in network_config
        or "\\" in network_config
    ):
        raise ValueError("network_config must be a file name like 'network.lab.yaml'")

    clients_raw = raw["clients"]
    if not isinstance(clients_raw, list) or not clients_raw:
        raise ValueError("clients must be a non-empty list")
    clients: list[dict[str, str]] = []
    for client in clients_raw:
        if not isinstance(client, dict) or set(client) != {"id", "ip"}:
            raise ValueError("each client must be an object with exactly 'id' and 'ip'")
        if not isinstance(client["id"], str) or not client["id"].strip():
            raise ValueError("client id must be a non-empty string")
        ipaddress.ip_address(client["ip"])
        clients.append({"id": client["id"], "ip": client["ip"]})
    if len({c["id"] for c in clients}) != len(clients) or len({c["ip"] for c in clients}) != len(
        clients
    ):
        raise ValueError("client ids and ips must be unique")

    scenarios_raw = raw["scenarios"]
    if not isinstance(scenarios_raw, list) or not scenarios_raw:
        raise ValueError("scenarios must be a non-empty list")
    ids = {c["id"] for c in clients}
    scenarios: list[DeclaredScenario] = []
    for item in scenarios_raw:
        if not isinstance(item, dict) or not {"kind", "class", "client"} <= set(item):
            raise ValueError("each scenario needs 'kind', 'class' and 'client'")
        if set(item) - {"kind", "class", "client", "tool"}:
            raise ValueError(f"unknown scenario fields: {sorted(set(item) - SCENARIO_KEYS)}")
        kind, cls = item["kind"], item["class"]
        if kind not in CLASSES_BY_KIND or cls not in CLASSES_BY_KIND[kind]:
            raise ValueError(f"class {cls!r} is not registered for kind {kind!r}")
        if item["client"] not in ids:
            raise ValueError(f"scenario client {item['client']!r} is not a declared client")
        scenarios.append(DeclaredScenario(kind, cls, item["client"], str(item.get("tool", ""))))
    kinds = {s.kind for s in scenarios}
    if raw["holdout"] and kinds != {"holdout"}:
        raise ValueError("a holdout run may declare only kind 'holdout' scenarios")
    if not raw["holdout"] and "holdout" in kinds:
        raise ValueError(
            "holdout scenarios require holdout: true (LAB-HOLDOUT is a separate corpus)"
        )

    return Submission(
        run_id=run_id,
        holdout=raw["holdout"],
        start=raw["start"],
        end=raw["end"],
        network_config=network_config,
        clients=tuple(clients),
        scenarios=tuple(scenarios),
        provenance=Provenance.from_dict(raw["provenance"]),
    )


def check_labels_match_submission(submission: Submission, episodes: list[Episode]) -> list[str]:
    """Problems where the supplied labels contradict the supplier's own declaration."""
    problems: list[str] = []
    if not episodes:
        return ["labels.jsonl has no episodes"]
    ips = submission.client_ips()
    start = parse_time(submission.start) - timedelta(seconds=TIME_SLACK_S)
    end = parse_time(submission.end) + timedelta(seconds=TIME_SLACK_S)
    seen_pairs: set[tuple[str, str]] = set()
    for e in episodes:
        seen_pairs.add((e.kind, e.cls))
        if e.run_id != submission.run_id:
            problems.append(f"{e.episode_id}: label run_id {e.run_id!r} != submission run_id")
        if e.actor not in ips:
            problems.append(f"{e.episode_id}: actor {e.actor} is not a declared client")
        if e.start < start or e.end > end:
            problems.append(f"{e.episode_id}: outside the declared start/end window")
    declared = submission.declared_pairs()
    for kind, cls in sorted(declared - seen_pairs):
        problems.append(f"declared scenario {kind}:{cls} has no labelled episode")
    for kind, cls in sorted(seen_pairs - declared):
        problems.append(f"labelled episode {kind}:{cls} was not declared in the submission")
    return problems


def check_run_flags(holdout: bool, benign_only: bool, episodes: list[Any]) -> list[str]:
    """The run-level flags must agree with the kinds of episodes the run actually labels."""
    kinds = {e.kind for e in episodes}
    problems: list[str] = []
    if holdout and kinds - {"holdout"}:
        problems.append("holdout run labels non-holdout episodes")
    if not holdout and "holdout" in kinds:
        problems.append("holdout episodes in a run not flagged holdout")
    if benign_only and kinds - {"hard_negative"}:
        problems.append("benign_only run labels attack or holdout episodes")
    if not benign_only and not holdout and kinds <= {"hard_negative"}:
        problems.append("run is not flagged benign_only but only labels hard negatives")
    return problems
