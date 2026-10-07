"""DET-BEACON: periodic C2-style check-ins (PRD §10, architecture §7.4).

Series (event times t1..tn for n >= min_events), each scored independently:
  ip             (internal src, dst IP, dst port, proto) over conn.log connection starts
  name           (internal src, SNI or HTTP Host) over the connections that carried that name, so a
                 beacon survives CDN IP rotation
  http_requests  (internal src, dst IP, dst port) over http.log request times, which exposes
                 cleartext HTTP beacons that reuse one TCP connection
With d = inter-arrival times (seconds):
  s_disp = max(0, 1 - MAD(d) / median(d))          timing regularity
  s_skew = 1 - |Bowley|, Bowley = (Q3 + Q1 - 2*Q2) / (Q3 - Q1), 0 when Q3 == Q1
  s_size = max(0, 1 - MAD(bytes) / median(bytes))  1 when every size is equal
  s_cov  = min(1, (tn - t1) / (coverage_span_fraction * capture span))
  beacon_score = weighted mean (config weights, default equal)
Fires at score >= min_score; confidence high when score >= high_score and n >= high_min_events,
medium otherwise. MAD is the unscaled median absolute deviation. Ports in
network.yaml allowlist.periodic_ports (default NTP/123) and allowlisted domains are scored but
their findings are suppressed and counted. Only internal sources are considered (architecture §9:
BEACON's primary entity is the possibly affected internal host).

Known limitation (also documented in docs): HTTPS/TLS beacons that keep one TCP connection open are
invisible here; so is any beacon whose interval makes fewer than min_events events fit the capture.
Findings from different series that describe the same connections are reduced to one.
"""

from dataclasses import dataclass

import numpy as np
import pandas as pd
from numpy.typing import NDArray

from app.detect.base import (
    Confidence,
    DetectorInput,
    DetectorOutput,
    Finding,
    MetricValue,
    epoch_seconds,
    group_indices,
    make_finding,
)
from app.detect.config import BeaconConfig
from app.detect.dns_tunnel import is_allowlisted, split_name

BENIGN_CAUSES = (
    "NTP and other time synchronisation",
    "software update checks",
    "telemetry",
    "monitoring agents",
    "keep-alives",
    "mail polling",
)
_KIND_ORDER = {"ip": 0, "http_requests": 1, "name": 2}


@dataclass(frozen=True)
class Scores:
    events: int
    median_interval_s: float
    mad_interval_s: float
    bowley: float
    s_disp: float
    s_skew: float
    s_size: float
    s_cov: float
    score: float


@dataclass(frozen=True)
class _Series:
    kind: str
    src: str
    dst_ip: str | None
    dst_port: int | None
    name: str | None
    times: NDArray[np.float64]
    sizes: NDArray[np.float64]
    uids: list[str]


def _mad(values: NDArray[np.float64]) -> float:
    return float(np.median(np.abs(values - np.median(values))))


def beacon_scores(
    times: NDArray[np.float64],
    sizes: NDArray[np.float64],
    capture_span_s: float | None,
    cfg: BeaconConfig,
) -> Scores:
    """Score one sorted event series (pure; unit-tested on perfect, jittered and random series)."""
    d = np.diff(times)
    median_d = float(np.median(d))
    mad_d = _mad(d)
    s_disp = max(0.0, 1.0 - mad_d / median_d) if median_d > 0 else 0.0
    q1, q2, q3 = (float(q) for q in np.percentile(d, [25, 50, 75]))
    bowley = 0.0 if q3 == q1 else (q3 + q1 - 2 * q2) / (q3 - q1)
    s_skew = max(0.0, 1.0 - abs(bowley))
    median_b = float(np.median(sizes))
    if np.all(sizes == sizes[0]):
        s_size = 1.0
    elif median_b <= 0:
        s_size = 0.0
    else:
        s_size = max(0.0, 1.0 - _mad(sizes) / median_b)
    observed = float(times[-1] - times[0])
    span = capture_span_s if capture_span_s and capture_span_s > 0 else observed
    s_cov = min(1.0, observed / (cfg.coverage_span_fraction * span)) if span > 0 else 0.0
    w = cfg.weights
    total = w.dispersion + w.skew + w.size + w.coverage
    score = (
        (w.dispersion * s_disp + w.skew * s_skew + w.size * s_size + w.coverage * s_cov) / total
        if total > 0
        else 0.0
    )
    return Scores(len(times), median_d, mad_d, bowley, s_disp, s_skew, s_size, s_cov, score)


def thresholds(cfg: BeaconConfig, periodic_ports: list[int]) -> dict[str, MetricValue]:
    return {
        "min_events": cfg.min_events,
        "min_score": cfg.min_score,
        "high_score": cfg.high_score,
        "high_min_events": cfg.high_min_events,
        "coverage_span_fraction": cfg.coverage_span_fraction,
        "weights": (
            f"dispersion={cfg.weights.dispersion},skew={cfg.weights.skew},"
            f"size={cfg.weights.size},coverage={cfg.weights.coverage}"
        ),
        "periodic_ports": ",".join(str(p) for p in periodic_ports),
    }


def _sizes(frame: pd.DataFrame, a: str, b: str) -> NDArray[np.float64]:
    return (frame[a].fillna(0) + frame[b].fillna(0)).to_numpy(dtype=np.float64)


def _build_series(inp: DetectorInput, min_events: int) -> list[_Series]:
    series: list[_Series] = []
    internal = inp.network.classify_series
    conn = inp.tables.conn
    conn = conn[conn["orig_h"].notna() & conn["resp_h"].notna() & conn["resp_p"].notna()]
    conn = conn[internal(conn["orig_h"]) == "internal"]
    if conn.empty:
        return series
    conn = conn.sort_values(["ts", "uid"], kind="stable").reset_index(drop=True)
    conn_sizes = _sizes(conn, "orig_bytes", "resp_bytes")
    conn_times = epoch_seconds(conn["ts"])
    conn_uids = conn["uid"].astype(str).to_numpy(dtype=object)

    for (src, dst, port, _proto), idx in group_indices(
        conn, ["orig_h", "resp_h", "resp_p", "proto"]
    ):
        if len(idx) >= min_events:
            series.append(
                _Series(
                    "ip",
                    str(src),
                    str(dst),
                    int(port),
                    None,
                    conn_times[idx],
                    conn_sizes[idx],
                    [str(u) for u in conn_uids[idx]],
                )
            )

    # name series: connections that carried a TLS server name or an HTTP Host
    named = pd.concat(
        [
            inp.tables.ssl[["uid", "server_name"]].rename(columns={"server_name": "name"}),
            inp.tables.http[["uid", "host"]].rename(columns={"host": "name"}),
        ],
        ignore_index=True,
    )
    named = named[named["name"].notna() & named["uid"].notna()]
    if not named.empty:
        named = named.assign(name=named["name"].astype(str).str.lower().str.rstrip("."))
        named = named[named["name"] != ""].drop_duplicates(["uid", "name"])
        joined = conn.assign(_row=np.arange(len(conn))).merge(named, on="uid", how="inner")
        joined = joined.sort_values("_row", kind="stable")
        for (src, name), idx in group_indices(joined, ["orig_h", "name"]):
            if len(idx) >= min_events:
                rows = joined["_row"].to_numpy(dtype=np.intp)[idx]
                series.append(
                    _Series(
                        "name",
                        str(src),
                        None,
                        None,
                        str(name),
                        conn_times[rows],
                        conn_sizes[rows],
                        [str(u) for u in conn_uids[rows]],
                    )
                )

    # http request series: request timestamps per (src, dst, port)
    http = inp.tables.http
    http = http[http["orig_h"].notna() & http["resp_h"].notna() & http["resp_p"].notna()]
    http = http[internal(http["orig_h"]) == "internal"]
    if not http.empty:
        http = http.sort_values(["ts", "uid", "trans_depth"], kind="stable").reset_index(drop=True)
        http_times = epoch_seconds(http["ts"])
        http_sizes = _sizes(http, "request_body_len", "response_body_len")
        http_uids = http["uid"].astype(str).to_numpy(dtype=object)
        for (src, dst, port), idx in group_indices(http, ["orig_h", "resp_h", "resp_p"]):
            if len(idx) >= min_events:
                series.append(
                    _Series(
                        "http_requests",
                        str(src),
                        str(dst),
                        int(port),
                        None,
                        http_times[idx],
                        http_sizes[idx],
                        [str(u) for u in http_uids[idx]],
                    )
                )
    return series


@dataclass(frozen=True)
class _Hit:
    series: _Series
    scores: Scores
    confidence: Confidence


class BeaconDetector:
    detector_id = "DET-BEACON"
    version = "1.0.0"

    def run(self, inp: DetectorInput) -> DetectorOutput:
        cfg = inp.config.beacon
        out = DetectorOutput()
        periodic = set(inp.network.allowlist.periodic_ports)
        allowed = inp.network.allowlist.domains
        hits: list[_Hit] = []
        for s in _build_series(inp, cfg.min_events):
            scores = beacon_scores(s.times, s.sizes, inp.capture_span_s, cfg)
            if scores.score < cfg.min_score:
                continue
            if s.dst_port is not None and s.dst_port in periodic:
                out.suppressed["periodic_port"] += 1
                continue
            if s.name is not None and is_allowlisted(split_name(s.name)[0], allowed):
                out.suppressed["allowlisted_domain"] += 1
                continue
            high = scores.score >= cfg.high_score and scores.events >= cfg.high_min_events
            hits.append(_Hit(s, scores, "high" if high else "medium"))

        for hit in self._deduplicate(hits):
            out.findings.append(self._finding(inp, hit))
        return out

    @staticmethod
    def _deduplicate(hits: list[_Hit]) -> list[_Hit]:
        """One finding per set of connections: the best-scoring series wins (ties: more events,
        then series kind); a name series whose connections a kept ip/http series already covers
        is dropped."""
        ranked = sorted(
            hits,
            key=lambda h: (
                -h.scores.score,
                -h.scores.events,
                _KIND_ORDER[h.series.kind],
                h.series.src,
                h.series.dst_ip or "",
                h.series.dst_port or 0,
                h.series.name or "",
            ),
        )
        kept: list[_Hit] = []
        for hit in ranked:
            uids = set(hit.series.uids)
            same_flow = any(
                k.series.src == hit.series.src
                and k.series.kind != "name"
                and hit.series.kind != "name"
                and k.series.dst_ip == hit.series.dst_ip
                and k.series.dst_port == hit.series.dst_port
                for k in kept
            )
            covered = hit.series.kind == "name" and any(
                k.series.src == hit.series.src and uids <= set(k.series.uids) for k in kept
            )
            if not (same_flow or covered):
                kept.append(hit)
        return kept

    def _finding(self, inp: DetectorInput, hit: _Hit) -> Finding:
        s, sc = hit.series, hit.scores
        secondary = [s.name] if s.name is not None else [str(s.dst_ip)]
        return make_finding(
            inp,
            detector_id=self.detector_id,
            version=self.version,
            type_="BEACON",
            primary=s.src,
            secondary=secondary,
            start=float(s.times[0]),
            end=float(s.times[-1]),
            metrics={
                "series": s.kind,
                "dst_port": s.dst_port,
                "events": sc.events,
                "median_interval_s": round(sc.median_interval_s, 4),
                "mad_interval_s": round(sc.mad_interval_s, 4),
                "bowley_skew": round(sc.bowley, 4),
                "s_dispersion": round(sc.s_disp, 4),
                "s_skew": round(sc.s_skew, 4),
                "s_size": round(sc.s_size, 4),
                "s_coverage": round(sc.s_cov, 4),
                "beacon_score": round(sc.score, 4),
            },
            thresholds=thresholds(inp.config.beacon, sorted(inp.network.allowlist.periodic_ports)),
            confidence=hit.confidence,
            benign_causes=BENIGN_CAUSES,
            uids=s.uids,
        )


DETECTOR = BeaconDetector()
