"""Per-run metadata (`run.json`), committed next to `labels.jsonl` under lab/runs/<run_id>/.

Captures themselves are never committed (data/, gitignored); `capture_sha256` ties the committed
metadata to the exact file that was recorded. Standard library only.

A run has an `origin`:
  * `lab_runner`  recorded by `lab/run_lab.py` (seeded benign scenarios), or
  * `external`    a capture produced outside the lab runner and registered through
                  `lab/register_external.py`. External runs must carry full provenance; the
                  provenance is a *claim by the supplier* and is never treated as evidence that the
                  labels are right (that is what `lab/verify_run.py` is for).
"""

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from lab.schema import CLASSES_BY_KIND, parse_time

RUN_SCHEMA_VERSION = 1
ORIGINS = ("lab_runner", "external")
_SHA256_HEX = set("0123456789abcdef")


@dataclass(frozen=True)
class Provenance:
    """Who supplied an external capture, how, and under what conditions (all required)."""

    supplied_by: str
    supplied_at: str
    collection_method: str  # free-text description of how the capture was produced
    tool_versions: dict[str, str]  # versions of whatever produced and captured the traffic
    isolated_environment: bool  # supplier attests: isolated lab network, no real traffic
    contains_real_user_data: bool  # supplier attests: must be False
    scenario_parameters: dict[str, Any] = field(default_factory=dict)  # as recorded, untrusted
    notes: str = ""

    def __post_init__(self) -> None:
        for name in ("supplied_by", "collection_method"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"provenance.{name} is required")
        parse_time(self.supplied_at)
        if not self.tool_versions or not all(
            isinstance(k, str) and isinstance(v, str) and k and v
            for k, v in self.tool_versions.items()
        ):
            raise ValueError("provenance.tool_versions must be a non-empty {name: version} map")
        if self.isolated_environment is not True:
            raise ValueError("provenance.isolated_environment must be true (isolated lab only)")
        if self.contains_real_user_data is not False:
            raise ValueError("provenance.contains_real_user_data must be false")
        if not isinstance(self.scenario_parameters, dict):
            raise ValueError("provenance.scenario_parameters must be an object")

    @classmethod
    def from_dict(cls, raw: object) -> "Provenance":
        if not isinstance(raw, dict):
            raise ValueError("provenance must be an object")
        allowed = set(cls.__dataclass_fields__)
        unknown = set(raw) - allowed
        if unknown:
            raise ValueError(f"unknown provenance fields: {sorted(unknown)}")
        required = allowed - {"scenario_parameters", "notes"}
        missing = sorted(required - set(raw))
        if missing:
            raise ValueError(f"missing provenance fields: {missing}")
        return cls(**raw)


@dataclass(frozen=True)
class RunMeta:
    run_id: str
    capture_sha256: str
    capture_bytes: int
    start: str
    end: str
    seed: int | None  # required for lab_runner runs; external runs may have no seed
    holdout: bool  # run belongs to the LAB-HOLDOUT corpus (anomaly gate G1 only)
    benign_only: bool  # no attack/holdout episodes: counts toward BENIGN hours
    duration_s: float
    scenarios: tuple[dict[str, Any], ...]  # what was run, as declared/recorded
    network_config: str  # e.g. "network.lab.yaml"
    tool_versions: dict[str, str] = field(default_factory=dict)
    schema_version: int = RUN_SCHEMA_VERSION
    origin: str = "lab_runner"
    clients: tuple[dict[str, str], ...] = ()  # [{"id": ..., "ip": ...}] who generated traffic
    provenance: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        if self.schema_version != RUN_SCHEMA_VERSION:
            raise ValueError(f"unsupported run schema_version {self.schema_version}")
        if (
            not self.run_id
            or "/" in self.run_id
            or "\\" in self.run_id
            or self.run_id in {".", ".."}
        ):
            raise ValueError(f"invalid run_id {self.run_id!r}")
        if len(self.capture_sha256) != 64 or not set(self.capture_sha256) <= _SHA256_HEX:
            raise ValueError("capture_sha256 must be 64 lowercase hex characters")
        if self.duration_s < 0 or self.capture_bytes < 0:
            raise ValueError("negative duration or size")
        if self.holdout and self.benign_only:
            raise ValueError("a run cannot be both holdout and benign_only")
        if self.origin not in ORIGINS:
            raise ValueError(f"unknown origin {self.origin!r}")
        if self.origin == "external":
            Provenance.from_dict(self.provenance)  # raises on missing/invalid provenance
            if not self.clients:
                raise ValueError("an external run must identify its clients")
        else:
            if self.provenance is not None:
                raise ValueError("provenance is only valid for external runs")
            if self.seed is None:
                raise ValueError("a lab_runner run must record its seed")
        for client in self.clients:
            if set(client) != {"id", "ip"} or not all(client.values()):
                raise ValueError("each client needs exactly a non-empty 'id' and 'ip'")

    def to_json(self) -> str:
        data = asdict(self)
        data["scenarios"] = list(self.scenarios)
        data["clients"] = list(self.clients)
        return json.dumps(data, indent=2, sort_keys=True) + "\n"


def load_run(path: Path) -> RunMeta:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: run.json must be an object")
    try:
        raw["scenarios"] = tuple(raw.get("scenarios", ()))
        raw["clients"] = tuple(raw.get("clients", ()))
        return RunMeta(**raw)
    except TypeError as exc:
        raise ValueError(f"{path}: {exc}") from exc


def episode_classes() -> frozenset[str]:
    return frozenset(c for classes in CLASSES_BY_KIND.values() for c in classes)
