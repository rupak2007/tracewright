"""Stable per-incident evidence IDs `E-1..E-n` (architecture §14). Pure and deterministic.

Per incident: one *aggregate* item per finding (its measured metrics and applied thresholds), in
the incident's finding order, then *record* items (a connection or DNS row behind the finding)
ordered by time. Templates, reports, the UI and narratives all cite these IDs, so a reader can
trace every sentence to a row. Record fields come from the normalised Zeek tables;
capture-derived strings (query names) are stored as data and escaped wherever rendered.
"""

from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Literal

import numpy as np
import pandas as pd
from pydantic import BaseModel, ConfigDict

from app.correlate.models import Incident
from app.detect.base import Finding, epoch_seconds, to_datetime
from app.ingest.normalise import CaptureTables

Scalar = int | float | str | bool | None
RECORDS_PER_FINDING = 20  # record items kept per finding in the incident view


class EvidenceItem(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    local_id: str  # "E-<n>", unique inside the incident
    kind: Literal["aggregate", "conn", "dns"]
    finding_id: str
    incident_id: str
    zeek_uid: str | None
    ts: datetime | None
    fields: dict[str, Scalar]


def _scalar(value: object) -> Scalar:
    if value is None or (isinstance(value, float) and not np.isfinite(value)):
        return None
    if isinstance(value, bool | int | float | str):
        return value
    if isinstance(value, np.generic):
        return _scalar(value.item())
    if value is pd.NA or value is pd.NaT:
        return None
    return str(value)


def aggregate_fields(f: Finding) -> dict[str, Scalar]:
    fields: dict[str, Scalar] = {
        "finding_type": f.type,
        "confidence": f.confidence,
        "start": f.start_ts.isoformat(),
        "end": f.end_ts.isoformat(),
        "evidence_total": f.evidence_count,
    }
    fields.update({k: _scalar(v) for k, v in f.metrics.items()})
    fields.update({f"threshold_{k}": _scalar(v) for k, v in f.thresholds.items()})
    return fields


def _conn_records(
    conn: pd.DataFrame, uids: Sequence[str]
) -> list[tuple[float, str, dict[str, Scalar]]]:
    rows = conn[conn["uid"].isin(uids)]
    times = epoch_seconds(rows["ts"]) if len(rows) else np.array([])
    out: list[tuple[float, str, dict[str, Scalar]]] = []
    for t, r in zip(times, rows.itertuples(index=False), strict=True):
        out.append(
            (
                float(t),
                str(r.uid),
                {
                    "src": _scalar(r.orig_h),
                    "src_port": _scalar(r.orig_p),
                    "dst": _scalar(r.resp_h),
                    "dst_port": _scalar(r.resp_p),
                    "proto": _scalar(r.proto),
                    "service": _scalar(r.service),
                    "duration_s": _scalar(r.duration),
                    "bytes_out": _scalar(r.orig_bytes),
                    "bytes_in": _scalar(r.resp_bytes),
                    "state": _scalar(r.conn_state),
                },
            )
        )
    return out


def _dns_records(
    dns: pd.DataFrame, uids: Sequence[str]
) -> list[tuple[float, str, dict[str, Scalar]]]:
    rows = dns[dns["uid"].isin(uids)]
    times = epoch_seconds(rows["ts"]) if len(rows) else np.array([])
    return [
        (
            float(t),
            str(r.uid),
            {
                "client": _scalar(r.orig_h),
                "resolver": _scalar(r.resp_h),
                "query": _scalar(r.query),
                "qtype": _scalar(r.qtype_name),
                "rcode": _scalar(r.rcode_name),
            },
        )
        for t, r in zip(times, rows.itertuples(index=False), strict=True)
    ]


def build_incident_evidence(
    incident: Incident,
    findings: Mapping[str, Finding],
    tables: CaptureTables,
    records_per_finding: int = RECORDS_PER_FINDING,
) -> list[EvidenceItem]:
    """Aggregates first (finding order), then records by (time, uid, finding order)."""
    members = [findings[fid] for fid in incident.finding_ids]
    aggregates: list[tuple[Finding, dict[str, Scalar]]] = [
        (f, aggregate_fields(f)) for f in members
    ]
    records: list[tuple[float, str, int, Finding, str, dict[str, Scalar]]] = []
    for order, f in enumerate(members):
        refs = f.evidence_refs[:records_per_finding]
        if f.type == "DNSTUN":
            found = [("dns", *rec) for rec in _dns_records(tables.dns, refs)]
        else:
            found = [("conn", *rec) for rec in _conn_records(tables.conn, refs)]
        found.sort(key=lambda r: (r[1], r[2]))
        records += [
            (t, uid, order, f, kind, fields) for kind, t, uid, fields in found[:records_per_finding]
        ]
    out: list[EvidenceItem] = []
    n = 0
    for f, fields in aggregates:
        n += 1
        out.append(
            EvidenceItem(
                local_id=f"E-{n}",
                kind="aggregate",
                finding_id=f.id,
                incident_id=incident.id,
                zeek_uid=None,
                ts=f.start_ts,
                fields=fields,
            )
        )
    for t, uid, _order, f, kind, fields in sorted(records, key=lambda r: (r[0], r[1], r[2])):
        n += 1
        out.append(
            EvidenceItem(
                local_id=f"E-{n}",
                kind="dns" if kind == "dns" else "conn",
                finding_id=f.id,
                incident_id=incident.id,
                zeek_uid=uid,
                ts=to_datetime(t),
                fields=fields,
            )
        )
    return out
