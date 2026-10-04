"""Capture profile (FR-05, stage S3): a pure function of the normalised tables and capture facts."""

import pandas as pd
from pydantic import BaseModel

from app.ingest.capinfos import CapInfo
from app.ingest.normalise import CaptureTables, NormaliseStats
from app.ingest.validate import CaptureFileInfo
from app.profile.context import NetworkContext
from app.profile.warnings import (
    ProfileConfig,
    QualityWarning,
    WarningInputs,
    compute_warnings,
    max_beacon_interval_s,
)

_TOP_SERVICES = 20
_TOP_WEIRD = 20


class FileFacts(BaseModel):
    sha256: str
    size_bytes: int
    format: str


class CaptureFacts(BaseModel):
    packets: int
    first_ts: float | None
    last_ts: float | None
    duration_s: float | None
    snaplen: int | None
    link_type: str


class TopTalker(BaseModel):
    host: str
    zone: str
    connections: int
    bytes: int


class CaptureProfile(BaseModel):
    file: FileFacts
    capture: CaptureFacts
    zeek_version: str
    table_rows: dict[str, int]
    connections: int
    total_ip_bytes: int
    internal_hosts: int
    external_hosts: int
    internal_external_pairs: int
    services: dict[str, int]
    top_talkers: list[TopTalker]
    dns_queries: int
    weird_by_name: dict[str, int]
    tcp_connections: int
    tcp_no_handshake: int
    max_beacon_interval_s: float | None
    normalise_lines_total: int
    normalise_lines_skipped: int
    normalise_bad_values: int
    warnings: list[QualityWarning]


def _flow_bytes(conn: pd.DataFrame) -> pd.Series:
    return conn["orig_ip_bytes"].fillna(0) + conn["resp_ip_bytes"].fillna(0)


def _top_talkers(conn: pd.DataFrame, ctx: NetworkContext, limit: int) -> list[TopTalker]:
    if conn.empty:
        return []
    volume = _flow_bytes(conn).astype("int64")
    sides = pd.concat(
        [
            pd.DataFrame({"host": conn["orig_h"], "bytes": volume}),
            pd.DataFrame({"host": conn["resp_h"], "bytes": volume}),
        ]
    ).dropna(subset=["host"])
    grouped = sides.groupby("host", sort=False)["bytes"].agg(["size", "sum"]).reset_index()
    grouped = grouped.sort_values(["sum", "host"], ascending=[False, True]).head(limit)
    return [
        TopTalker(
            host=str(host), zone=ctx.classify(str(host)), connections=int(n), bytes=int(total)
        )
        for host, n, total in zip(
            grouped["host"].tolist(), grouped["size"].tolist(), grouped["sum"].tolist(), strict=True
        )
    ]


def build_profile(
    file_info: CaptureFileInfo,
    cap: CapInfo,
    zeek_version: str,
    tables: CaptureTables,
    stats: NormaliseStats,
    ctx: NetworkContext,
    cfg: ProfileConfig,
) -> CaptureProfile:
    conn = tables.conn
    hosts = pd.concat([conn["orig_h"], conn["resp_h"]]).dropna().unique()
    zones = {str(h): ctx.classify(str(h)) for h in hosts}
    internal_hosts = sum(1 for z in zones.values() if z == "internal")

    orig_zone = ctx.classify_series(conn["orig_h"].astype("object"))
    resp_zone = ctx.classify_series(conn["resp_h"].astype("object"))
    crossing = conn[(orig_zone == "internal") & (resp_zone == "external")]
    pairs = int(crossing[["orig_h", "resp_h"]].drop_duplicates().shape[0])

    services = conn["service"].fillna("unknown").value_counts()
    services = services.sort_index().sort_values(ascending=False, kind="stable")
    weird = tables.weird["name"].fillna("unknown").value_counts()
    weird = weird.sort_index().sort_values(ascending=False, kind="stable")

    tcp = conn[conn["proto"] == "tcp"]
    no_handshake = int((~tcp["history"].fillna("").str.contains("[Sh]", regex=True)).sum())

    warning_inputs = WarningInputs(
        connections=len(conn),
        tcp_connections=len(tcp),
        tcp_no_handshake=no_handshake,
        weird_rows=len(tables.weird),
        dns_queries=len(tables.dns),
        internal_hosts=internal_hosts,
        internal_external_pairs=pairs,
        span_s=cap.duration_s,
        snaplen=cap.snaplen,
        normalise_lines_total=stats.lines_total,
        normalise_lines_skipped=stats.lines_skipped,
    )
    return CaptureProfile(
        file=FileFacts(
            sha256=file_info.sha256, size_bytes=file_info.size_bytes, format=file_info.format.value
        ),
        capture=CaptureFacts(
            packets=cap.packets,
            first_ts=cap.first_ts,
            last_ts=cap.last_ts,
            duration_s=cap.duration_s,
            snaplen=cap.snaplen,
            link_type=cap.link_type,
        ),
        zeek_version=zeek_version,
        table_rows=dict(stats.rows),
        connections=len(conn),
        total_ip_bytes=int(_flow_bytes(conn).sum()),
        internal_hosts=internal_hosts,
        external_hosts=len(zones) - internal_hosts,
        internal_external_pairs=pairs,
        services={str(k): int(v) for k, v in services.head(_TOP_SERVICES).items()},
        top_talkers=_top_talkers(conn, ctx, cfg.top_talkers),
        dns_queries=len(tables.dns),
        weird_by_name={str(k): int(v) for k, v in weird.head(_TOP_WEIRD).items()},
        tcp_connections=len(tcp),
        tcp_no_handshake=no_handshake,
        max_beacon_interval_s=max_beacon_interval_s(cap.duration_s, cfg),
        normalise_lines_total=stats.lines_total,
        normalise_lines_skipped=stats.lines_skipped,
        normalise_bad_values=stats.bad_values,
        warnings=compute_warnings(warning_inputs, cfg),
    )
