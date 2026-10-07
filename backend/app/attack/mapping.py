"""Finding -> ATT&CK technique references (architecture §10): "consistent with", never attribution.

config/attack_mapping.yaml lists, per finding type, techniques with an optional `when` condition:
  BRUTE   single_target | spray            (metric `variant`)
  DNSTUN  high_outbound_name_volume        (metric name_bytes_total >= conditions threshold)
  BEACON  http_or_tls | dns | other        (series/port; port lists in the conditions block)
  EXFIL   shared_peer_with_beacon          (set by correlation, not by the finding itself)
Anomaly findings have no entry and can never receive a mapping.
"""

from collections.abc import Mapping
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.attack.cards import CardIndex
from app.attack.stix import AttackPins
from app.core.errors import ConfigError
from app.detect.base import Finding

KNOWN_WHEN = {
    "single_target",
    "spray",
    "high_outbound_name_volume",
    "http_or_tls",
    "dns",
    "other",
    "shared_peer_with_beacon",
}


class Entry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    phrase: str = ""
    when: str | None = None


class Conditions(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    high_outbound_name_volume_bytes: int = Field(gt=0)
    http_tls_ports: list[int]
    dns_ports: list[int]


class MappingConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    attack_version: str
    conditions: Conditions
    mappings: dict[str, list[Entry]]


class TechniqueRef(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    technique_id: str
    phrase: str


def load_mapping(path: Path) -> MappingConfig:
    try:
        cfg = MappingConfig.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))
    except (OSError, yaml.YAMLError, ValidationError, TypeError) as exc:
        raise ConfigError(f"Invalid ATT&CK mapping {path.name}: {exc}") from exc
    for entries in cfg.mappings.values():
        for e in entries:
            if e.when is not None and e.when not in KNOWN_WHEN:
                raise ConfigError(
                    f"Invalid ATT&CK mapping {path.name}: unknown condition {e.when!r}"
                )
    if cfg.mappings.get("UNEXPLAINED_ANOMALY"):
        raise ConfigError("Invalid ATT&CK mapping: anomalies must never map to a technique")
    return cfg


def mapped_ids(cfg: MappingConfig) -> list[str]:
    return sorted({e.id for entries in cfg.mappings.values() for e in entries})


def validate_mapping(cfg: MappingConfig, index: CardIndex, pins: AttackPins) -> None:
    """Startup/test check: the pinned version and checksum agree, every mapped ID exists in the
    pinned bundle and is neither revoked nor deprecated. Raises ConfigError listing all problems."""
    problems: list[str] = []
    if cfg.attack_version != pins.attack_version:
        problems.append(
            f"mapping targets ATT&CK {cfg.attack_version}, pinned is {pins.attack_version}"
        )
    if index.attack_version != pins.attack_version:
        problems.append(
            f"card index is ATT&CK {index.attack_version}, pinned is {pins.attack_version}"
        )
    if index.bundle_sha256 != pins.bundle_sha256:
        problems.append("card index was not built from the pinned bundle checksum")
    for tid in mapped_ids(cfg):
        entry = index.techniques.get(tid)
        if entry is None:
            problems.append(f"{tid} is not in the pinned bundle")
        elif entry.revoked:
            problems.append(f"{tid} is revoked")
        elif entry.deprecated:
            problems.append(f"{tid} is deprecated")
    if problems:
        raise ConfigError("ATT&CK mapping validation failed: " + "; ".join(problems))


def _beacon_kind(f: Finding, cond: Conditions) -> str:
    port = f.metrics.get("dst_port")
    if f.metrics.get("series") == "name" or (isinstance(port, int) and port in cond.http_tls_ports):
        return "http_or_tls"
    if isinstance(port, int) and port in cond.dns_ports:
        return "dns"
    return "other"


def techniques_for(
    f: Finding,
    cfg: MappingConfig,
    names: Mapping[str, str],
    shared_peer_with_beacon: bool = False,
) -> list[TechniqueRef]:
    """Techniques a finding is consistent with, in the mapping file's order."""
    out: list[TechniqueRef] = []
    beacon_kind = _beacon_kind(f, cfg.conditions) if f.type == "BEACON" else ""
    volume = f.metrics.get("name_bytes_total")
    for e in cfg.mappings.get(f.type, []):
        checks = {
            None: True,
            "single_target": f.metrics.get("variant") == "single_target",
            "spray": f.metrics.get("variant") == "spray",
            "high_outbound_name_volume": isinstance(volume, int | float)
            and volume >= cfg.conditions.high_outbound_name_volume_bytes,
            "http_or_tls": beacon_kind == "http_or_tls",
            "dns": beacon_kind == "dns",
            "other": beacon_kind == "other",
            "shared_peer_with_beacon": shared_peer_with_beacon,
        }
        if checks[e.when]:
            phrase = e.phrase or f"consistent with {names.get(e.id, e.id)}"
            out.append(TechniqueRef(technique_id=e.id, phrase=phrase))
    return out
