"""Residual anomaly triage (stage S5, architecture §8).

1. Entity-windows (`features.build_windows`); a window is *rule-explained* when a detector finding
   concerns the same host and overlaps the window in time.
2. The scorer is fitted ONLY on rule-unexplained windows (so a loud attack cannot swamp the
   population) and scores every window.
3. Promotion: a rule-unexplained window above the scorer's calibrated cut-off becomes part of an
   UNEXPLAINED_ANOMALY finding; at most `max_promoted` windows, consecutive windows of one host
   merged. Low severity, low confidence, never an ATT&CK mapping, worded "unusual relative to this
   capture". With no calibrated cut-off nothing is promoted.
4. Fewer than `min_population` unexplained windows: the stage is skipped with a warning.
"""

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Literal

import numpy as np
import pandas as pd

from app.anomaly.config import AnomalyConfig
from app.anomaly.features import FEATURES, build_windows
from app.anomaly.scorers import make_scorer, robust_stats, top_deviations
from app.detect.base import Finding, MetricValue, cap_evidence, epoch_seconds, to_datetime
from app.detect.runner import DetectionReport
from app.ingest.normalise import CaptureTables
from app.profile.context import NetworkContext
from app.profile.warnings import QualityWarning

BENIGN_CAUSES = (
    "a backup or synchronisation job",
    "an operating-system or software update burst",
    "rare but legitimate activity of a busy host",
)
Status = Literal["off", "skipped", "ran"]
REPORTED_WINDOWS = 50  # scored windows kept in anomalies.json (architecture §16: top 50)


@dataclass
class TriageResult:
    status: Status
    scorer: str
    reason: str = ""
    windows: int = 0
    unexplained: int = 0
    scores: pd.DataFrame = field(default_factory=pd.DataFrame)
    promoted: list[Finding] = field(default_factory=list)
    warning_code: str | None = None


def rule_explained_mask(
    windows: pd.DataFrame, findings: Sequence[Finding], window_s: float
) -> np.ndarray:
    """True for windows that overlap, in time and host, any detector finding."""
    explained = np.zeros(len(windows), dtype=bool)
    if windows.empty:
        return explained
    hosts = windows["host"].to_numpy(dtype=object)
    starts = windows["window_start"].to_numpy(dtype=np.float64)
    for f in findings:
        entities = {f.primary_entity, *f.secondary_entities}
        f0, f1 = f.start_ts.timestamp(), f.end_ts.timestamp()
        in_time = (starts < f1) & (starts + window_s > f0)
        explained |= np.isin(hosts, list(entities)) & in_time
    return explained


def _merge_runs(promoted: pd.DataFrame) -> list[pd.DataFrame]:
    """Group promoted windows into runs of consecutive window indices per host."""
    runs: list[pd.DataFrame] = []
    for _, group in promoted.sort_values(["host", "widx"]).groupby("host", sort=True):
        current: list[int] = []
        previous: int | None = None
        for index, widx in zip(group.index, group["widx"], strict=True):
            if previous is not None and widx != previous + 1:
                runs.append(group.loc[current])
                current = []
            current.append(index)
            previous = int(widx)
        if current:
            runs.append(group.loc[current])
    return sorted(runs, key=lambda r: (float(r["window_start"].min()), str(r["host"].iloc[0])))


def _finding(
    run: pd.DataFrame,
    deviations: list[list[tuple[str, float, float, float]]],
    scorer: str,
    cfg: AnomalyConfig,
    tables: CaptureTables,
    severity_base: float,
    threshold: float,
) -> Finding:
    host = str(run["host"].iloc[0])
    start = float(run["window_start"].min())
    end = float(run["window_start"].max()) + cfg.window_s
    best = int(np.argmax(run["score"].to_numpy()))
    metrics: dict[str, MetricValue] = {
        "scorer": scorer,
        "score": round(float(run["score"].max()), 4),
        "windows": len(run),
        "window_s": cfg.window_s,
    }
    for rank, (name, z, value, median) in enumerate(deviations[best], start=1):
        metrics[f"top_feature_{rank}"] = name
        metrics[f"top_feature_{rank}_z"] = z
        metrics[f"top_feature_{rank}_value"] = value
        metrics[f"top_feature_{rank}_median"] = median
    conn = tables.conn
    times = epoch_seconds(conn["ts"]) if len(conn) else np.array([])
    inside = (times >= start) & (times < end)
    involved = (conn["orig_h"] == host) | (conn["resp_h"] == host)
    uids = [str(u) for u in conn.loc[inside & involved.to_numpy(), "uid"]]
    refs, count = cap_evidence(uids, cfg.max_evidence_refs)
    return Finding(
        id="",
        investigation_id="",
        detector_id="ANOMALY-TRIAGE",
        detector_version="1.0.0",
        type="UNEXPLAINED_ANOMALY",
        primary_entity=host,
        secondary_entities=[],
        start_ts=to_datetime(start),
        end_ts=to_datetime(end),
        metrics=metrics,
        thresholds={
            "promotion_threshold": threshold,
            "window_s": cfg.window_s,
            "min_population": cfg.min_population,
            "max_promoted": cfg.max_promoted,
        },
        confidence="low",
        severity_base=severity_base,
        benign_causes=list(BENIGN_CAUSES),
        evidence_refs=refs,
        evidence_count=count,
    )


def triage(
    tables: CaptureTables,
    network: NetworkContext,
    findings: Sequence[Finding],
    cfg: AnomalyConfig,
    scorer_name: str,
    severity_base: float = 1.0,
    skip_population_check: bool = False,
) -> TriageResult:
    if scorer_name == "off":
        return TriageResult(
            "off", "off", reason="anomaly triage is switched off (ANOMALY_SCORER=off)"
        )
    windows = build_windows(tables, network, cfg)
    if windows.empty:
        return TriageResult("skipped", scorer_name, reason="no internal-host windows")
    explained = rule_explained_mask(windows, findings, cfg.window_s)
    unexplained = int((~explained).sum())
    base = TriageResult("ran", scorer_name, windows=len(windows), unexplained=unexplained)
    if unexplained < cfg.min_population and not skip_population_check:
        return TriageResult(
            "skipped",
            scorer_name,
            reason=f"{unexplained} rule-unexplained windows, fewer than {cfg.min_population}",
            windows=len(windows),
            unexplained=unexplained,
            warning_code="ANOMALY_POPULATION_SMALL",
        )
    if unexplained == 0:
        return TriageResult(
            "skipped", scorer_name, reason="every window is rule-explained", windows=len(windows)
        )
    x = windows[list(FEATURES)].to_numpy(dtype=np.float64)
    scorer = make_scorer(scorer_name, cfg)
    scorer.fit(x[~explained])
    scores = scorer.score(x)
    stats = robust_stats(x[~explained])
    table = windows[["host", "widx", "window_start"]].copy()
    table["score"] = scores
    table["rule_explained"] = explained
    table["rank"] = (-table["score"]).rank(method="first").astype(int)
    table["pos"] = np.arange(len(table))
    ordered = table.sort_values("rank").reset_index(drop=True)
    deviations: list[list[dict[str, object]]] = [
        [
            {"feature": d.feature, "z": d.z, "value": d.value, "median": d.median}
            for d in top_deviations(x[int(pos)], stats, cfg.top_features)
        ]
        if rank <= REPORTED_WINDOWS
        else []
        for pos, rank in zip(ordered["pos"].tolist(), ordered["rank"].tolist(), strict=True)
    ]
    ordered["top_features"] = pd.Series(deviations, index=ordered.index, dtype=object)
    base.scores = ordered.drop(columns=["pos"])
    cutoff = cfg.threshold_for(scorer_name)
    if cutoff is None:
        return base
    candidates = table[(~table["rule_explained"]) & (table["score"] >= cutoff)]
    top = candidates.sort_values(["score", "window_start"], ascending=[False, True]).head(
        cfg.max_promoted
    )
    for run in _merge_runs(top):
        devs = [
            [
                (d.feature, d.z, d.value, d.median)
                for d in top_deviations(x[i], stats, cfg.top_features)
            ]
            for i in run.index
        ]
        base.promoted.append(_finding(run, devs, scorer_name, cfg, tables, severity_base, cutoff))
    return base


def describe_windows(result: TriageResult) -> list[dict[str, object]]:
    """The top REPORTED_WINDOWS scored windows as JSON-ready dicts (anomalies.json)."""
    head = result.scores.head(REPORTED_WINDOWS)
    return [
        {
            "host": str(host),
            "window_start": to_datetime(float(start)).isoformat(),
            "score": round(float(score), 4),
            "rank": int(rank),
            "rule_explained": bool(explained),
            "top_features": features,
        }
        for host, start, score, rank, explained, features in zip(
            head["host"].tolist(),
            head["window_start"].tolist(),
            head["score"].tolist(),
            head["rank"].tolist(),
            head["rule_explained"].tolist(),
            head["top_features"].tolist(),
            strict=True,
        )
    ]


def anomaly_warnings(result: TriageResult) -> list[QualityWarning]:
    """Data-quality warning when the stage had to be skipped for lack of population (FR-23)."""
    if result.warning_code is None:
        return []
    return [
        QualityWarning(
            code=result.warning_code,
            severity="info",
            message=f"Anomaly triage skipped: {result.reason}.",
            metric={"unexplained_windows": result.unexplained, "windows": result.windows},
        )
    ]


def anomaly_summary(
    result: TriageResult, report: DetectionReport, cfg: AnomalyConfig
) -> dict[str, object]:
    """anomalies.json: what the stage did, the top scored windows and the promoted findings."""
    return {
        "status": result.status,
        "scorer": result.scorer,
        "reason": result.reason,
        "window_s": cfg.window_s,
        "windows": result.windows,
        "rule_unexplained_windows": result.unexplained,
        "min_population": cfg.min_population,
        "promotion_threshold": cfg.threshold_for(result.scorer),
        "wording": "unusual relative to this capture; not necessarily malicious",
        "scored_windows": describe_windows(result) if result.status == "ran" else [],
        "promoted_findings": [f.id for f in report.findings if f.type == "UNEXPLAINED_ANOMALY"],
    }
