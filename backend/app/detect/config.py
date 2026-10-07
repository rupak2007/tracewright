"""Detector thresholds from config/detectors.yaml (FR-12): configuration, never code constants."""

import hashlib
import json
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.core.errors import ConfigError


class _Section(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class CommonConfig(_Section):
    max_evidence_refs: int = Field(gt=0)
    severity_base: dict[str, float]


class ScanConfig(_Section):
    window_short_s: float = Field(gt=0)
    window_long_s: float = Field(gt=0)
    vertical_ports: int = Field(gt=0)
    horizontal_hosts: int = Field(gt=0)
    slow_vertical_ports: int = Field(gt=0)
    failed_states: list[str]
    high_failed_share: float = Field(ge=0, le=1)


class BruteConfig(_Section):
    window_s: float = Field(gt=0)
    ftp_failures: int = Field(gt=0)
    ftp_failure_code: int
    http_failures: int = Field(gt=0)
    http_failure_codes: list[int]
    login_min_connections: int = Field(gt=0)
    login_max_median_duration_s: float = Field(gt=0)
    login_max_bytes_cv: float = Field(ge=0)
    login_services: dict[str, list[int]]
    spray_min_targets: int = Field(gt=0)


class DnsTunnelConfig(_Section):
    min_unique_subdomains: int = Field(gt=0)
    min_mean_entropy: float = Field(ge=0)
    min_mean_subdomain_len: float = Field(ge=0)
    txt_null_share: float = Field(ge=0, le=1)
    txt_null_min_queries: int = Field(gt=0)
    txt_null_qtypes: list[str]


class BeaconWeights(_Section):
    dispersion: float = Field(ge=0)
    skew: float = Field(ge=0)
    size: float = Field(ge=0)
    coverage: float = Field(ge=0)


class BeaconConfig(_Section):
    min_events: int = Field(ge=3)
    min_score: float = Field(ge=0, le=1)
    high_score: float = Field(ge=0, le=1)
    high_min_events: int = Field(gt=0)
    coverage_span_fraction: float = Field(gt=0, le=1)
    weights: BeaconWeights


class ExfilConfig(_Section):
    min_outbound_bytes: int = Field(ge=0)
    min_modified_z: float
    min_out_in_ratio: float = Field(ge=0)
    weak_baseline_min_pairs: int = Field(ge=0)


class DetectorsConfig(_Section):
    version: int
    common: CommonConfig
    scan: ScanConfig
    brute: BruteConfig
    dnstun: DnsTunnelConfig
    beacon: BeaconConfig
    exfil: ExfilConfig

    def config_hash(self) -> str:
        """Stable hash of every threshold in force (stored in each result manifest)."""
        canonical = json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()


def load_detectors_config(path: Path) -> DetectorsConfig:
    try:
        return DetectorsConfig.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))
    except (OSError, yaml.YAMLError, ValidationError, TypeError) as exc:
        raise ConfigError(f"Invalid detector config {path.name}: {exc}") from exc
