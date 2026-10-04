"""Per-run metadata (`run.json`), committed next to `labels.jsonl` under lab/runs/<run_id>/.

Captures themselves are never committed (data/, gitignored); `capture_sha256` ties the committed
metadata to the exact file that was recorded. Standard library only.
"""

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from lab.schema import CLASSES_BY_KIND

RUN_SCHEMA_VERSION = 1
_SHA256_HEX = set("0123456789abcdef")


@dataclass(frozen=True)
class RunMeta:
    run_id: str
    capture_sha256: str
    capture_bytes: int
    start: str
    end: str
    seed: int
    holdout: bool  # run belongs to the LAB-HOLDOUT corpus (anomaly gate G1 only)
    benign_only: bool  # no attack/holdout episodes: counts toward BENIGN hours
    duration_s: float
    scenarios: tuple[dict[str, Any], ...]  # what was run, as recorded by the orchestrator
    network_config: str  # e.g. "network.lab.yaml"
    tool_versions: dict[str, str] = field(default_factory=dict)
    schema_version: int = RUN_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != RUN_SCHEMA_VERSION:
            raise ValueError(f"unsupported run schema_version {self.schema_version}")
        if not self.run_id or "/" in self.run_id or "\\" in self.run_id:
            raise ValueError(f"invalid run_id {self.run_id!r}")
        if len(self.capture_sha256) != 64 or not set(self.capture_sha256) <= _SHA256_HEX:
            raise ValueError("capture_sha256 must be 64 lowercase hex characters")
        if self.duration_s < 0 or self.capture_bytes < 0:
            raise ValueError("negative duration or size")
        if self.holdout and self.benign_only:
            raise ValueError("a run cannot be both holdout and benign_only")

    def to_json(self) -> str:
        data = asdict(self)
        data["scenarios"] = list(self.scenarios)
        return json.dumps(data, indent=2, sort_keys=True) + "\n"


def load_run(path: Path) -> RunMeta:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: run.json must be an object")
    try:
        raw["scenarios"] = tuple(raw.get("scenarios", ()))
        return RunMeta(**raw)
    except TypeError as exc:
        raise ValueError(f"{path}: {exc}") from exc


def episode_classes() -> frozenset[str]:
    return frozenset(c for classes in CLASSES_BY_KIND.values() for c in classes)
