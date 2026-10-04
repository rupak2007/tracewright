"""Ground-truth label schema for lab runs (eval/PROTOCOL.md §2). Standard library only.

One JSON object per episode in `labels.jsonl`. `kind` separates the three label families so that
hard negatives and held-out families are never mixed into detector classes:

    attack         a behaviour a detector targets (class names below)
    holdout        a family with no detector, used only for the anomaly gate G1
    hard_negative  legitimate look-alike behaviour (a finding on it is a false positive)

This module only names the classes; nothing here generates attack traffic.
"""

import ipaddress
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

SCHEMA_VERSION = 1

ATTACK_CLASSES = ("SCAN", "BRUTE", "DNSTUN", "BEACON", "EXFIL")
HOLDOUT_CLASSES = ("ICMP_TUNNEL", "SLOWLORIS", "SMB_RPC_ENUM", "REVERSE_SHELL")
HARD_NEGATIVE_CLASSES = (
    "RSYNC_BACKUP",
    "PACKAGE_UPDATE",
    "NTP",
    "MONITORING_HEARTBEAT",
    "CLOUD_SYNC_UPLOAD",
    "CDN_BROWSING",
    "VIDEO_STREAMING",
    "AUTOMATION_SSH",
)
CLASSES_BY_KIND: dict[str, tuple[str, ...]] = {
    "attack": ATTACK_CLASSES,
    "holdout": HOLDOUT_CLASSES,
    "hard_negative": HARD_NEGATIVE_CLASSES,
}


def parse_time(value: str) -> datetime:
    """Parse an ISO-8601 UTC timestamp ending in Z (the only form the schema accepts)."""
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError(f"timestamp must be ISO-8601 UTC ending in 'Z': {value!r}")
    return datetime.fromisoformat(value[:-1] + "+00:00").astimezone(UTC)


def format_time(moment: datetime) -> str:
    if moment.tzinfo is None:
        raise ValueError("naive datetime")
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


@dataclass(frozen=True)
class Episode:
    run_id: str
    episode_id: str
    kind: str
    cls: str  # serialised as "class"
    actor: str
    targets: tuple[str, ...]
    start: datetime
    end: datetime
    tool: str = ""
    params: dict[str, Any] = field(default_factory=dict)
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(f"unsupported schema_version {self.schema_version}")
        if self.kind not in CLASSES_BY_KIND:
            raise ValueError(f"unknown kind {self.kind!r}")
        if self.cls not in CLASSES_BY_KIND[self.kind]:
            raise ValueError(f"class {self.cls!r} is not valid for kind {self.kind!r}")
        if not self.run_id or not self.episode_id.startswith(f"{self.run_id}-"):
            raise ValueError("episode_id must start with '<run_id>-'")
        for address in (self.actor, *self.targets):
            ipaddress.ip_address(address)
        if not self.targets:
            raise ValueError("an episode needs at least one target")
        if self.start.tzinfo is None or self.end.tzinfo is None:
            raise ValueError("start/end must be timezone-aware")
        if self.end < self.start:
            raise ValueError("end is before start")

    def to_json_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["class"] = data.pop("cls")
        data["targets"] = list(self.targets)
        data["start"] = format_time(self.start)
        data["end"] = format_time(self.end)
        return data


_REQUIRED = ("run_id", "episode_id", "kind", "class", "actor", "targets", "start", "end")


def parse_episode(raw: dict[str, Any]) -> Episode:
    """Validate one decoded labels.jsonl object; raises ValueError describing the first problem."""
    if not isinstance(raw, dict):
        raise ValueError("label must be a JSON object")
    missing = [key for key in _REQUIRED if key not in raw]
    if missing:
        raise ValueError(f"missing fields: {missing}")
    unknown = set(raw) - set(_REQUIRED) - {"tool", "params", "schema_version"}
    if unknown:
        raise ValueError(f"unknown fields: {sorted(unknown)}")
    if not isinstance(raw["targets"], list) or not all(isinstance(t, str) for t in raw["targets"]):
        raise ValueError("targets must be a list of IP strings")
    params = raw.get("params", {})
    if not isinstance(params, dict):
        raise ValueError("params must be an object")
    return Episode(
        run_id=str(raw["run_id"]),
        episode_id=str(raw["episode_id"]),
        kind=str(raw["kind"]),
        cls=str(raw["class"]),
        actor=str(raw["actor"]),
        targets=tuple(raw["targets"]),
        start=parse_time(raw["start"]),
        end=parse_time(raw["end"]),
        tool=str(raw.get("tool", "")),
        params=params,
        schema_version=int(raw.get("schema_version", SCHEMA_VERSION)),
    )
