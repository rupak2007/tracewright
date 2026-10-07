"""Anomaly-triage settings from config/anomaly.yaml (architecture §8)."""

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.core.errors import ConfigError

ScorerName = Literal["off", "robust_z", "iforest"]


class _Section(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class FeatureConfig(_Section):
    standard_port_max: int = Field(ge=0, le=65535)
    extra_standard_ports: list[int]
    failed_states: list[str]
    established_states: list[str]


class IsolationForestConfig(_Section):
    n_estimators: int = Field(gt=0)
    max_samples: str | int
    seed: int


class PromotionThresholds(_Section):
    robust_z: float | None
    iforest: float | None


class AnomalyConfig(_Section):
    version: int
    window_s: float = Field(gt=0)
    min_population: int = Field(gt=0)
    max_promoted: int = Field(gt=0)
    top_features: int = Field(gt=0)
    max_evidence_refs: int = Field(gt=0)
    features: FeatureConfig
    iforest: IsolationForestConfig
    promotion_threshold: PromotionThresholds

    def threshold_for(self, scorer: str) -> float | None:
        return getattr(self.promotion_threshold, scorer, None)


def load_anomaly_config(path: Path) -> AnomalyConfig:
    try:
        return AnomalyConfig.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))
    except (OSError, yaml.YAMLError, ValidationError, TypeError) as exc:
        raise ConfigError(f"Invalid anomaly config {path.name}: {exc}") from exc
