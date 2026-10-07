"""Anomaly triage: features, scorers, rule-explained fitting, promotion. SYNTHETIC tables only."""

from pathlib import Path
from typing import Any

import numpy as np
import pytest

from app.anomaly.config import AnomalyConfig, load_anomaly_config
from app.anomaly.features import FEATURES, build_windows
from app.anomaly.scorers import (
    IForestScorer,
    RobustZScorer,
    make_scorer,
    modified_z,
    robust_stats,
    top_deviations,
)
from app.anomaly.triage import (
    anomaly_summary,
    anomaly_warnings,
    describe_windows,
    rule_explained_mask,
    triage,
)
from app.attack.mapping import load_mapping, techniques_for
from app.core.errors import ConfigError
from app.detect.runner import DetectionReport, extend_report
from tests.detect_helpers import T0, conn_rows, context, finding, frame, tables

REPO = Path(__file__).resolve().parents[3]
CFG: AnomalyConfig = load_anomaly_config(REPO / "config" / "anomaly.yaml")
SMALL = CFG.model_copy(
    update={
        "min_population": 5,
        "promotion_threshold": CFG.promotion_threshold.model_copy(
            update={"robust_z": None, "iforest": None}
        ),
    }
)  # small populations allowed, nothing calibrated
HOST = "10.0.0.5"


def test_config_loads_with_dev_calibrated_thresholds_and_rejects_garbage(tmp_path: Path) -> None:
    assert CFG.window_s == 300 and CFG.min_population == 100 and CFG.max_promoted == 10
    # calibrated on BENIGN dev only (eval/results/anomaly-calibration-dev-v1, REVISIONS #7)
    assert CFG.threshold_for("robust_z") and CFG.threshold_for("iforest")
    assert CFG.threshold_for("off") is None
    assert CFG.iforest.n_estimators == 200
    (tmp_path / "a.yaml").write_text("version: 1\nwindow_s: 0\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_anomaly_config(tmp_path / "a.yaml")


# ---- features ---------------------------------------------------------------------------
def test_sixteen_features_are_computed_per_host_window_with_documented_transforms() -> None:
    rows = (
        conn_rows(
            HOST,
            "198.51.100.1",
            [1.0],
            443,
            orig_bytes=1000,
            resp_bytes=500,
            duration=2.0,
            service="ssl",
            uid_prefix="A",
        )
        + conn_rows(
            HOST,
            "198.51.100.2",
            [2.0],
            4444,
            orig_bytes=10,
            resp_bytes=0,
            state="S0",
            duration=0.0,
            uid_prefix="B",
        )
        + conn_rows(
            HOST,
            "10.0.0.9",
            [3.0],
            80,
            orig_bytes=200,
            resp_bytes=800,
            duration=4.0,
            service="http",
            uid_prefix="C",
        )
        + conn_rows(
            "10.0.0.7",
            HOST,
            [4.0],
            22,
            orig_bytes=100,
            resp_bytes=300,
            duration=6.0,
            service="ssh",
            uid_prefix="D",
        )
        + conn_rows(
            HOST,
            "10.0.0.9",
            [5.0],
            8,
            proto="icmp",
            orig_bytes=0,
            resp_bytes=0,
            duration=0.0,
            uid_prefix="E",
        )
    )
    dns = [
        {"ts": T0 + 1, "uid": "Q1", "orig_h": HOST, "query": "aaaa.example.com"},
        {"ts": T0 + 2, "uid": "Q2", "orig_h": HOST, "query": "abcd.other.org"},
        {"ts": T0 + 3, "uid": "Q3", "orig_h": HOST, "query": "example.com"},
    ]
    w = build_windows(tables(conn=frame("conn", rows), dns=frame("dns", dns)), context(), CFG)
    row = w[w["host"] == HOST].iloc[0]
    assert row["widx"] == 0 and len(w[w["host"] == HOST]) == 1
    assert row["out_conns"] == pytest.approx(np.log1p(4))  # A, B, C, E started by the host
    assert row["in_conns"] == pytest.approx(np.log1p(1))  # D
    assert row["distinct_dst_ips"] == pytest.approx(np.log1p(3))
    assert row["distinct_dst_ports"] == pytest.approx(np.log1p(4))  # 443, 4444, 80, 8
    assert row["failed_share"] == pytest.approx(0.25)  # only B is S0
    assert row["bytes_out"] == pytest.approx(np.log1p(1000 + 10 + 200 + 0 + 300))  # + inbound resp
    assert row["bytes_in"] == pytest.approx(np.log1p(500 + 0 + 800 + 0 + 100))
    assert row["out_in_ratio"] == pytest.approx(np.log((1510 + 1) / (1400 + 1)))
    assert row["mean_duration"] == pytest.approx(np.log1p((2 + 0 + 4 + 0 + 6) / 5))
    assert row["external_dst_share"] == pytest.approx(0.5)  # 2 of 4 outbound go outside 10/8
    assert row["no_service_share"] == pytest.approx(1 / 4)  # E is 1 of the 4 established conns
    assert row["nonstd_port_share"] == pytest.approx(1 / 4)  # only 4444 (icmp port is not tcp/udp)
    assert row["dns_queries"] == pytest.approx(np.log1p(3))
    assert row["distinct_domains"] == pytest.approx(np.log1p(2))
    assert row["dns_label_entropy"] == pytest.approx(
        1.0
    )  # mean of "aaaa" (0) and "abcd" (2); apex skipped
    assert row["icmp_conns"] == pytest.approx(np.log1p(1))
    assert list(w.columns[3:]) == list(FEATURES) and len(FEATURES) == 16


def test_external_hosts_get_no_windows_and_windows_tumble_from_the_first_connection() -> None:
    rows = conn_rows(HOST, "198.51.100.1", [0.0, 299.0, 300.0, 700.0], 443) + conn_rows(
        "203.0.113.5", "198.51.100.1", [10.0], 80, uid_prefix="X"
    )
    w = build_windows(tables(conn=frame("conn", rows)), context(), CFG)
    assert set(w["host"]) == {HOST}
    assert w["widx"].tolist() == [0, 1, 2]
    assert w["window_start"].tolist() == [T0, T0 + 300, T0 + 600]
    assert build_windows(tables(), context(), CFG).empty


# ---- scorers ----------------------------------------------------------------------------
def test_robust_z_uses_median_and_mad_and_scores_the_max_feature() -> None:
    x = np.array([[1.0, 5.0], [2.0, 5.0], [3.0, 5.0], [4.0, 5.0], [100.0, 5.0]])
    scorer = RobustZScorer()
    scorer.fit(x)
    scores = scorer.score(x)
    assert scores[2] == 0.0  # the median row
    assert scores[4] == pytest.approx(97 / (1.0 / 0.6745))  # MAD 1 -> scale 1/0.6745
    assert scores.argmax() == 4


def test_zero_mad_falls_back_to_the_mean_absolute_deviation_and_constants_are_skipped() -> None:
    x = np.array([[5.0, 7.0]] * 6 + [[9.0, 7.0]])
    stats = robust_stats(x)
    assert stats.scale[1] == 0.0  # constant feature: skipped
    assert stats.scale[0] == pytest.approx((4 / 7) * 1.2533)  # MAD 0 -> mean AD fallback
    z = modified_z(x, stats)
    assert z[6, 0] == pytest.approx(4 / ((4 / 7) * 1.2533)) and (z[:, 1] == 0).all()


def test_scoring_before_fitting_is_an_error() -> None:
    with pytest.raises(RuntimeError):
        RobustZScorer().score(np.zeros((1, 2)))
    with pytest.raises(RuntimeError):
        IForestScorer(CFG).score(np.zeros((1, 2)))
    with pytest.raises(ValueError):
        make_scorer("nope", CFG)


def test_iforest_and_random_are_deterministic_under_a_fixed_seed() -> None:
    rng = np.random.default_rng(0)
    x = np.vstack([rng.normal(0, 1, (60, 4)), [[8, 8, 8, 8]]])
    a, b = make_scorer("iforest", CFG), make_scorer("iforest", CFG)
    a.fit(x)
    b.fit(x)
    assert np.array_equal(a.score(x), b.score(x)) and a.score(x).argmax() == 60  # the outlier
    r1, r2 = make_scorer("random", CFG), make_scorer("random", CFG)
    assert np.array_equal(r1.score(x), r2.score(x))


def test_top_deviations_rank_features_by_absolute_z_with_value_and_median() -> None:
    x = np.zeros((9, len(FEATURES)))
    x[:, 0] = np.arange(9.0)
    stats = robust_stats(x)
    row = np.zeros(len(FEATURES))
    row[0], row[5] = 50.0, -20.0
    devs = top_deviations(row, stats, 3)
    assert devs[0].feature == FEATURES[0] and devs[0].value == 50.0
    assert devs[0].median == 4.0 and len(devs) == 3
    assert top_deviations(row, stats, 1)[0].z == devs[0].z


# ---- triage -----------------------------------------------------------------------------
def population(n_windows: int, hosts: int = 3, spike: int | None = None) -> Any:
    """Steady hosts, each making similar connections per window; optionally one huge spike."""
    rows: list[dict[str, Any]] = []
    for h in range(hosts):
        src = f"10.0.0.{h + 10}"
        for w in range(n_windows):
            count = 6 + (w + h) % 3
            if spike is not None and h == 0 and w == spike:
                count = 400
            rows += conn_rows(
                src,
                "198.51.100.1",
                [w * 300.0 + i * 0.5 for i in range(count)],
                443,
                uid_prefix=f"{src}-{w}",
            )
    return tables(conn=frame("conn", rows))


def test_off_means_nothing_runs() -> None:
    result = triage(population(20), context(), [], CFG, "off")
    assert result.status == "off" and result.promoted == [] and result.scores.empty


def test_a_small_unexplained_population_skips_with_a_warning() -> None:
    result = triage(population(20), context(), [], CFG, "robust_z")
    assert result.status == "skipped" and result.warning_code == "ANOMALY_POPULATION_SMALL"
    [warning] = anomaly_warnings(result)
    assert (
        warning.code == "ANOMALY_POPULATION_SMALL" and warning.metric["unexplained_windows"] == 60
    )
    assert anomaly_warnings(triage(population(20), context(), [], CFG, "off")) == []


def test_no_windows_and_all_explained_are_skipped_not_failed() -> None:
    assert triage(tables(), context(), [], CFG, "robust_z").status == "skipped"
    covering = finding("SCAN", "10.0.0.10", 0, 10_000, secondary=["10.0.0.11", "10.0.0.12"])
    result = triage(population(20), context(), [covering], SMALL, "robust_z")
    assert result.status == "skipped" and result.warning_code == "ANOMALY_POPULATION_SMALL"
    forced = triage(
        population(20), context(), [covering], SMALL, "robust_z", skip_population_check=True
    )
    assert forced.status == "skipped" and "rule-explained" in forced.reason


def test_rule_explained_windows_follow_host_and_time_overlap() -> None:
    w = build_windows(population(4), context(), CFG)
    f = finding("BRUTE", "198.51.100.9", 310, 400, secondary=["10.0.0.11"])
    mask = rule_explained_mask(w, [f], CFG.window_s)
    flagged = {(h, int(i)) for h, i, m in zip(w["host"], w["widx"], mask, strict=True) if m}
    assert flagged == {("10.0.0.11", 1)}  # secondary entity, only the window overlapping [310, 400]


def test_the_scorer_is_fitted_only_on_unexplained_windows_and_scores_everything() -> None:
    """Two of three hosts are loud and rule-explained; fitting on them too would normalise loud."""
    rows: list[dict[str, Any]] = []
    for h in range(3):
        src = f"10.0.0.{h + 10}"
        for w in range(20):
            count = 400 if h < 2 else 6 + w % 3
            rows += conn_rows(
                src,
                "198.51.100.1",
                [w * 300.0 + i * 0.5 for i in range(count)],
                443,
                uid_prefix=f"{src}-{w}",
            )
    pop = tables(conn=frame("conn", rows))
    loud = [finding("SCAN", f"10.0.0.{10 + h}", 0, 20 * 300.0) for h in range(2)]
    fitted_on_quiet = triage(pop, context(), loud, SMALL, "robust_z")
    fitted_on_all = triage(pop, context(), [], SMALL, "robust_z")
    assert fitted_on_quiet.status == "ran" and fitted_on_quiet.windows == 60
    assert fitted_on_quiet.unexplained == 20 and fitted_on_all.unexplained == 60

    def best(result: Any, host: str) -> float:
        return float(result.scores[result.scores["host"] == host]["score"].max())

    assert best(fitted_on_quiet, "10.0.0.10") > 10 * best(fitted_on_all, "10.0.0.10")
    top = fitted_on_quiet.scores.iloc[0]
    assert top["rule_explained"] and top["rank"] == 1 and top["host"] in {"10.0.0.10", "10.0.0.11"}
    assert list(fitted_on_quiet.scores["rank"]) == list(range(1, 61))


def test_nothing_is_promoted_without_a_calibrated_threshold() -> None:
    result = triage(population(20, spike=7), context(), [], SMALL, "robust_z")
    assert result.status == "ran" and result.promoted == []


def test_promotion_is_capped_merged_low_severity_and_never_mapped() -> None:
    cfg = SMALL.model_copy(
        update={
            "max_promoted": 2,
            "promotion_threshold": SMALL.promotion_threshold.model_copy(update={"robust_z": 5.0}),
        }
    )
    rows: list[dict[str, Any]] = []
    for h in range(3):
        src = f"10.0.0.{h + 10}"
        for w in range(20):
            count = (
                400
                if (h == 0 and w in (7, 8)) or (h == 1 and w == 15) or (h == 2 and w == 3)
                else 6 + (w + h) % 3
            )
            rows += conn_rows(
                src,
                "198.51.100.1",
                [w * 300.0 + i * 0.5 for i in range(count)],
                443,
                uid_prefix=f"{src}-{w}",
            )
    result = triage(
        tables(conn=frame("conn", rows)), context(), [], cfg, "robust_z", severity_base=1.0
    )
    assert len(result.promoted) <= 2  # the cap counts windows, then runs are merged
    merged = [f for f in result.promoted if f.metrics["windows"] == 2]
    for f in result.promoted:
        assert f.type == "UNEXPLAINED_ANOMALY" and f.confidence == "low" and f.severity_base == 1.0
        assert f.thresholds["promotion_threshold"] == 5.0 and f.metrics["top_feature_1"]
        assert f.evidence_count > 0 and f.benign_causes
    if merged:
        assert merged[0].primary_entity == "10.0.0.10"
        assert merged[0].end_ts.timestamp() - merged[0].start_ts.timestamp() == 600
    mapping = load_mapping(REPO / "config" / "attack_mapping.yaml")
    assert all(techniques_for(f, mapping, {}) == [] for f in result.promoted)


def test_promoted_findings_join_the_report_and_the_summary_names_them() -> None:
    cfg = SMALL.model_copy(
        update={
            "promotion_threshold": SMALL.promotion_threshold.model_copy(update={"robust_z": 5.0})
        }
    )
    pop = population(20, spike=7)
    result = triage(pop, context(), [], cfg, "robust_z")
    assert result.promoted
    base = DetectionReport(
        investigation_id="i", config_hash="h", detector_versions={}, findings=[], suppressed={}
    )
    merged = extend_report(base, result.promoted, {"ANOMALY-TRIAGE": "1.0.0"})
    assert [f.id for f in merged.findings] == [f"F-{i}" for i in range(1, len(merged.findings) + 1)]
    summary = anomaly_summary(result, merged, cfg)
    assert summary["status"] == "ran" and summary["promoted_findings"]
    assert "unusual relative to this capture" in str(summary["wording"])
    windows = describe_windows(result)
    assert len(windows) <= 50 and windows[0]["rank"] == 1 and len(windows[0]["top_features"]) == 3  # type: ignore[arg-type]
    assert extend_report(base, [], {}) is base


def test_iforest_runs_end_to_end_and_is_repeatable() -> None:
    pop = population(20, spike=7)
    a = triage(pop, context(), [], SMALL, "iforest")
    b = triage(pop, context(), [], SMALL, "iforest")
    assert a.status == "ran" and a.scores["score"].tolist() == b.scores["score"].tolist()
    assert (
        a.scores.iloc[0]["host"] == "10.0.0.10" and a.scores.iloc[0]["window_start"] == T0 + 7 * 300
    )
