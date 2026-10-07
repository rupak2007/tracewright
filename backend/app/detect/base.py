"""Detector framework: the `Finding` record (FR-11, architecture §7), the `Detector` protocol and
the helpers every detector shares. Detectors are pure functions of the normalised tables, the
network context and the thresholds: no I/O, no clock, no randomness (NFR-02)."""

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal, Protocol

import numpy as np
import pandas as pd
from numpy.typing import NDArray
from pydantic import BaseModel, ConfigDict

from app.detect.config import DetectorsConfig
from app.ingest.normalise import CaptureTables
from app.profile.context import NetworkContext

FindingType = Literal["SCAN", "BRUTE", "DNSTUN", "BEACON", "EXFIL"]
Confidence = Literal["low", "medium", "high"]
MetricValue = int | float | str | bool | None


class Finding(BaseModel):
    """One detector observation. Created once; nothing downstream edits it (instruction §4.8)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str  # "F-<n>", assigned by the runner after deterministic ordering
    investigation_id: str
    detector_id: str
    detector_version: str
    type: FindingType
    primary_entity: str
    secondary_entities: list[str]
    start_ts: datetime
    end_ts: datetime
    metrics: dict[str, MetricValue]  # measured values
    thresholds: dict[str, MetricValue]  # values applied, copied from the configuration
    confidence: Confidence
    severity_base: float
    benign_causes: list[str]
    evidence_refs: list[str]  # Zeek uids, time-ordered, at most common.max_evidence_refs
    evidence_count: int  # total number of evidence records behind the finding
    suppressed_by_allowlist: bool = False  # suppressed findings are counted, never shown


@dataclass(frozen=True)
class DetectorInput:
    tables: CaptureTables
    network: NetworkContext
    config: DetectorsConfig
    capture_span_s: float | None  # first to last connection start, None when unknown


@dataclass
class DetectorOutput:
    findings: list[Finding] = field(default_factory=list)
    # reason -> number of findings that fired but were suppressed (FR-13); never silently dropped
    suppressed: Counter[str] = field(default_factory=Counter)


class Detector(Protocol):
    detector_id: str
    version: str

    def run(self, inp: DetectorInput) -> DetectorOutput: ...


_EPOCH = pd.Timestamp(0, tz="UTC")


def epoch_seconds(ts: "pd.Series[pd.Timestamp]") -> NDArray[np.float64]:
    """Timestamps (UTC) as float seconds since the epoch."""
    return np.asarray((ts - _EPOCH).dt.total_seconds(), dtype=np.float64)


def to_datetime(seconds: float) -> datetime:
    return datetime.fromtimestamp(seconds, tz=UTC)


def cap_evidence(uids: Sequence[str], limit: int) -> tuple[list[str], int]:
    """Keep the first `limit` unique uids in the given (time) order; also return the full count."""
    seen: dict[str, None] = dict.fromkeys(u for u in uids if isinstance(u, str) and u)
    return list(seen)[:limit], len(seen)


def make_finding(
    inp: DetectorInput,
    *,
    detector_id: str,
    version: str,
    type_: FindingType,
    primary: str,
    secondary: Sequence[str],
    start: float,
    end: float,
    metrics: dict[str, MetricValue],
    thresholds: dict[str, MetricValue],
    confidence: Confidence,
    benign_causes: Sequence[str],
    uids: Sequence[str],
) -> Finding:
    refs, count = cap_evidence(uids, inp.config.common.max_evidence_refs)
    return Finding(
        id="",
        investigation_id="",
        detector_id=detector_id,
        detector_version=version,
        type=type_,
        primary_entity=primary,
        secondary_entities=list(secondary),
        start_ts=to_datetime(start),
        end_ts=to_datetime(max(start, end)),
        metrics=metrics,
        thresholds=thresholds,
        confidence=confidence,
        severity_base=float(inp.config.common.severity_base[type_]),
        benign_causes=list(benign_causes),
        evidence_refs=refs,
        evidence_count=count,
    )


def group_indices(
    df: pd.DataFrame, keys: list[str]
) -> list[tuple[tuple[Any, ...], NDArray[np.intp]]]:
    """Row positions of each key group, in sorted key order (typed wrapper over `.indices`)."""
    return [
        (key if isinstance(key, tuple) else (key,), np.asarray(idx, dtype=np.intp))
        for key, idx in df.groupby(keys, sort=True).indices.items()
    ]
