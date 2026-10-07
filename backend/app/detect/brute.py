"""DET-BRUTE: repeated login attempts (PRD §10, architecture §7.2).

Unit: (source, destination, service) over closed `window_s` windows (default 5 min).
  ftp      >= ftp_failures replies with code 530 in ftp.log                       -> high
  http     >= http_failures 401/403 responses to the SAME host + URI              -> high
  ssh/rdp/telnet (opaque): >= login_min_connections connections to the service port whose median
           duration is < login_max_median_duration_s and whose orig_bytes have a coefficient of
           variation < login_max_bytes_cv; for SSH, connections Zeek reports as successfully
           authenticated (ssh.log auth_success true) are left out of the set   -> medium
           ("inferred from the connection pattern", not observed failures)
Spraying: when one source fires on the same service against >= spray_min_targets distinct
destinations, every one of those findings carries variant "spray" (else "single_target"). Each
target must itself meet the per-target threshold; the documents do not say whether spraying needs
a lower per-target bar, so none is invented here.
Capture-derived strings (URIs, hosts) are used only as grouping keys, never stored in a finding.
"""

from dataclasses import dataclass

import numpy as np
import pandas as pd
from numpy.typing import NDArray

from app.detect.base import (
    Confidence,
    DetectorInput,
    DetectorOutput,
    MetricValue,
    epoch_seconds,
    group_indices,
    make_finding,
)
from app.detect.config import BruteConfig
from app.detect.windows import max_count_window

BENIGN_CAUSES = (
    "automation tools",
    "health checks",
    "retries after transient errors",
    "shared NAT addresses",
)


@dataclass
class _Hit:
    service: str
    src: str
    dst: str
    start: float
    end: float
    uids: list[str]
    confidence: Confidence
    metrics: dict[str, MetricValue]


def thresholds(cfg: BruteConfig) -> dict[str, MetricValue]:
    return {
        "window_s": cfg.window_s,
        "ftp_failures": cfg.ftp_failures,
        "ftp_failure_code": cfg.ftp_failure_code,
        "http_failures": cfg.http_failures,
        "http_failure_codes": ",".join(str(c) for c in cfg.http_failure_codes),
        "login_min_connections": cfg.login_min_connections,
        "login_max_median_duration_s": cfg.login_max_median_duration_s,
        "login_max_bytes_cv": cfg.login_max_bytes_cv,
        "spray_min_targets": cfg.spray_min_targets,
    }


def _sorted(df: pd.DataFrame) -> pd.DataFrame:
    return df.sort_values(["ts", "uid"], kind="stable").reset_index(drop=True)


def _ftp_hits(inp: DetectorInput) -> list[_Hit]:
    cfg = inp.config.brute
    ftp = inp.tables.ftp
    ftp = ftp[(ftp["reply_code"] == cfg.ftp_failure_code) & ftp["orig_h"].notna()]
    ftp = ftp[ftp["resp_h"].notna()]
    hits: list[_Hit] = []
    if ftp.empty:
        return hits
    ftp = _sorted(ftp)
    for (src, dst), idx in group_indices(ftp, ["orig_h", "resp_h"]):
        rows = ftp.iloc[idx]
        times = epoch_seconds(rows["ts"])
        count, lo, hi = max_count_window(times, cfg.window_s)
        if count < cfg.ftp_failures:
            continue
        window = rows.iloc[lo:hi]
        hits.append(
            _Hit(
                "ftp",
                str(src),
                str(dst),
                float(times[lo]),
                float(times[hi - 1]),
                [str(u) for u in window["uid"]],
                "high",
                {"failures_observed": count, "failure_kind": f"ftp_reply_{cfg.ftp_failure_code}"},
            )
        )
    return hits


def _http_hits(inp: DetectorInput) -> list[_Hit]:
    cfg = inp.config.brute
    http = inp.tables.http
    http = http[http["status_code"].isin(cfg.http_failure_codes) & http["orig_h"].notna()]
    http = http[http["resp_h"].notna()]
    if http.empty:
        return []
    http = _sorted(http).copy()
    http["host"] = http["host"].fillna("")
    http["uri"] = http["uri"].fillna("")
    best: dict[tuple[str, str], tuple[int, _Hit]] = {}
    for (src, dst, _host, _uri), idx in group_indices(http, ["orig_h", "resp_h", "host", "uri"]):
        rows = http.iloc[idx]
        times = epoch_seconds(rows["ts"])
        count, lo, hi = max_count_window(times, cfg.window_s)
        if count < cfg.http_failures:
            continue
        window = rows.iloc[lo:hi]
        hit = _Hit(
            "http",
            str(src),
            str(dst),
            float(times[lo]),
            float(times[hi - 1]),
            [str(u) for u in window["uid"]],
            "high",
            {"failures_observed": count, "failure_kind": "http_401_403_same_uri"},
        )
        key = (str(src), str(dst))
        if key not in best or count > best[key][0]:  # one finding per pair: the strongest URI
            best[key] = (count, hit)
    return [hit for _, hit in best.values()]


def _login_hits(inp: DetectorInput) -> list[_Hit]:
    cfg = inp.config.brute
    conn = inp.tables.conn
    conn = conn[(conn["proto"] == "tcp") & conn["orig_h"].notna() & conn["resp_h"].notna()]
    if conn.empty:
        return []
    ssh_ok: set[str] = set()
    ssh = inp.tables.ssh
    if not ssh.empty:
        ssh_ok = {str(u) for u in ssh.loc[ssh["auth_success"] == True, "uid"]}  # noqa: E712
    hits: list[_Hit] = []
    for service, ports in sorted(cfg.login_services.items()):
        rows = conn[conn["resp_p"].isin(ports)]
        if service == "ssh" and ssh_ok:
            rows = rows[~rows["uid"].isin(ssh_ok)]
        if len(rows) < cfg.login_min_connections:
            continue
        rows = _sorted(rows)
        for (src, dst, _port), idx in group_indices(rows, ["orig_h", "resp_h", "resp_p"]):
            group = rows.iloc[idx]
            hit = _best_login_window(service, str(src), str(dst), group, cfg)
            if hit is not None:
                hits.append(hit)
    return hits


def _best_login_window(
    service: str, src: str, dst: str, group: pd.DataFrame, cfg: BruteConfig
) -> _Hit | None:
    if len(group) < cfg.login_min_connections:
        return None
    times = epoch_seconds(group["ts"])
    durations: NDArray[np.float64] = group["duration"].to_numpy(dtype=np.float64, na_value=np.nan)
    sizes: NDArray[np.float64] = group["orig_bytes"].fillna(0).to_numpy(dtype=np.float64)
    best: tuple[int, int, int, float, float] | None = None
    lo = 0
    for hi in range(len(times)):
        while times[hi] - times[lo] > cfg.window_s:
            lo += 1
        count = hi - lo + 1
        if count < cfg.login_min_connections or (best is not None and count <= best[0]):
            continue
        window_durations = durations[lo : hi + 1]
        if np.isnan(window_durations).any():
            continue  # a connection without a duration cannot be judged "short"
        median = float(np.median(window_durations))
        window_sizes = sizes[lo : hi + 1]
        mean = float(window_sizes.mean())
        cv = 0.0 if mean == 0 else float(window_sizes.std() / mean)
        if median < cfg.login_max_median_duration_s and cv < cfg.login_max_bytes_cv:
            best = (count, lo, hi + 1, median, cv)
    if best is None:
        return None
    count, lo, hi, median, cv = best
    return _Hit(
        service,
        src,
        dst,
        float(times[lo]),
        float(times[hi - 1]),
        [str(u) for u in group["uid"].iloc[lo:hi]],
        "medium",
        {
            "connections": count,
            "median_duration_s": round(median, 4),
            "orig_bytes_cv": round(cv, 4),
            "failure_kind": "inferred_from_connection_pattern",
        },
    )


class BruteDetector:
    detector_id = "DET-BRUTE"
    version = "1.0.0"

    def run(self, inp: DetectorInput) -> DetectorOutput:
        cfg = inp.config.brute
        hits = _ftp_hits(inp) + _http_hits(inp) + _login_hits(inp)
        targets: dict[tuple[str, str], set[str]] = {}
        for h in hits:
            targets.setdefault((h.src, h.service), set()).add(h.dst)
        out = DetectorOutput()
        for h in hits:
            n_targets = len(targets[(h.src, h.service)])
            spray = n_targets >= cfg.spray_min_targets
            out.findings.append(
                make_finding(
                    inp,
                    detector_id=self.detector_id,
                    version=self.version,
                    type_="BRUTE",
                    primary=h.src,
                    secondary=[h.dst],
                    start=h.start,
                    end=h.end,
                    metrics={
                        "service": h.service,
                        "variant": "spray" if spray else "single_target",
                        "distinct_targets": n_targets,
                        "window_s": cfg.window_s,
                        **h.metrics,
                    },
                    thresholds=thresholds(cfg),
                    confidence=h.confidence,
                    benign_causes=BENIGN_CAUSES,
                    uids=h.uids,
                )
            )
        return out


DETECTOR = BruteDetector()
