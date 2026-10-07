"""SYNTHETIC test fixtures for the detector tests.

Everything here builds evidence tables (the normalised Zeek schema) directly, with explicit
timestamps and values. None of it is, or imitates, a real capture, and no label or metric derived
from it may be quoted as detector performance (eval/PROTOCOL.md §6)."""

from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

import pandas as pd

from app.detect.base import DetectorInput, Finding, to_datetime
from app.detect.config import DetectorsConfig, load_detectors_config
from app.ingest.normalise import CaptureTables
from app.ingest.schema import ARROW_TYPES, TABLES
from app.profile.context import NetworkContext

SHIPPED_CONFIG = Path(__file__).resolve().parents[2] / "config" / "detectors.yaml"
T0 = 1_700_000_000.0  # arbitrary fixed origin for synthetic timestamps


def empty_table(name: str) -> pd.DataFrame:
    return pd.DataFrame(
        {c.name: pd.Series([], dtype=ARROW_TYPES[c.kind].to_pandas_dtype()) for c in TABLES[name]}
    )


def frame(name: str, rows: Iterable[dict[str, Any]]) -> pd.DataFrame:
    """A normalised table from row dicts (`ts` in epoch seconds); unspecified columns are NULL."""
    items = list(rows)
    if not items:
        return empty_table(name)
    out = pd.DataFrame(items)
    for column in TABLES[name]:
        if column.name not in out.columns:
            out[column.name] = None
    out["ts"] = pd.to_datetime(out["ts"], unit="s", utc=True)
    return out[[c.name for c in TABLES[name]]]


def tables(**given: pd.DataFrame) -> CaptureTables:
    return CaptureTables(**{n: given.get(n, empty_table(n)) for n in TABLES})


def context(**overrides: Any) -> NetworkContext:
    base: dict[str, Any] = {"internal_cidrs": ["10.0.0.0/8"]}
    base.update(overrides)
    return NetworkContext.model_validate(base)


def detector_input(
    captured: CaptureTables | None = None,
    network: NetworkContext | None = None,
    config: DetectorsConfig | None = None,
    span_s: float | None = None,
) -> DetectorInput:
    return DetectorInput(
        tables=captured or tables(),
        network=network or context(),
        config=config or load_detectors_config(SHIPPED_CONFIG),
        capture_span_s=span_s,
    )


def conn_rows(
    src: str,
    dst: str,
    times: Sequence[float],
    ports: Sequence[int] | int = 80,
    *,
    proto: str = "tcp",
    state: str = "SF",
    orig_bytes: Sequence[int] | int = 100,
    resp_bytes: Sequence[int] | int = 100,
    duration: Sequence[float] | float = 1.0,
    uid_prefix: str = "C",
    service: str | None = None,
) -> list[dict[str, Any]]:
    n = len(times)

    def seq(value: Sequence[Any] | Any) -> list[Any]:
        return list(value) if isinstance(value, Sequence) else [value] * n

    return [
        {
            "ts": T0 + t,
            "uid": f"{uid_prefix}-{src}-{dst}-{i}",
            "orig_h": src,
            "orig_p": 40000 + i,
            "resp_h": dst,
            "resp_p": p,
            "proto": proto,
            "service": service,
            "duration": d,
            "orig_bytes": ob,
            "resp_bytes": rb,
            "conn_state": state,
        }
        for i, (t, p, ob, rb, d) in enumerate(
            zip(times, seq(ports), seq(orig_bytes), seq(resp_bytes), seq(duration), strict=True)
        )
    ]


def finding(
    type_: str, primary: str, start: float = 0.0, end: float | None = None, **kw: Any
) -> Finding:
    """A minimal valid Finding for framework tests."""
    return Finding(
        id=kw.get("fid", ""),
        investigation_id="",
        detector_id=f"DET-{type_}",
        detector_version="1.0.0",
        type=type_,
        primary_entity=primary,
        secondary_entities=kw.get("secondary", []),
        start_ts=to_datetime(T0 + start),
        end_ts=to_datetime(T0 + (start if end is None else end)),
        metrics=kw.get("metrics", {}),
        thresholds=kw.get("thresholds", {}),
        confidence=kw.get("confidence", "high"),
        severity_base=1.0,
        benign_causes=[],
        evidence_refs=kw.get("refs", []),
        evidence_count=len(kw.get("refs", [])),
    )
