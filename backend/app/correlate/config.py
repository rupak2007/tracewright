"""Correlation and severity settings from config/correlation.yaml (architecture §9)."""

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.core.errors import ConfigError


class _Section(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Weights(_Section):
    low: float = Field(ge=0)
    medium: float = Field(ge=0)
    high: float = Field(ge=0)


class Buckets(_Section):
    low: float
    medium: float
    high: float


class SeverityConfig(_Section):
    base: dict[str, float]
    weight: Weights
    extra_type_bonus: float = Field(ge=0)
    link_bonus: float = Field(ge=0)
    cap: float = Field(gt=0)
    buckets: Buckets


class CorrelationConfig(_Section):
    version: int
    gap_s: float = Field(gt=0)
    severity: SeverityConfig


def load_correlation_config(path: Path) -> CorrelationConfig:
    try:
        return CorrelationConfig.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))
    except (OSError, yaml.YAMLError, ValidationError, TypeError) as exc:
        raise ConfigError(f"Invalid correlation config {path.name}: {exc}") from exc
