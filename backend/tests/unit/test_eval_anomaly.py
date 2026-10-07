"""Anomaly gate metrics, the G1 rule and the calibration/evaluation harness. SYNTHETIC data only."""

import json
import random
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("eval")
pytest.importorskip("lab")

from eval import run_anomaly as ra
from eval import splits
from eval.anomaly_metrics import (
    WindowRef,
    bootstrap_difference,
    decide_g1,
    pr_auc,
    precision_at_k,
    promoted_rate,
    recall_at_k,
    window_is_positive,
)
from eval.run_detectors import HarnessError
from lab.schema import Episode

from app.anomaly.config import load_anomaly_config
from app.ingest.normalise import normalise_logs
from tests.helpers import conn_row, write_zeek_logs
from tests.unit.test_eval_splits import manifest, write_run

REPO = Path(__file__).resolve().parents[3]
T0 = datetime(2026, 11, 2, 10, 0, 0, tzinfo=UTC)
START = T0.timestamp()


def episode(
    actor: str = "10.0.0.5", start: int = 600, end: int = 700, kind: str = "holdout"
) -> Episode:
    return Episode(
        "r1", "r1-e1", kind, "SLOWLORIS" if kind == "holdout" else "NTP", actor, ("10.0.0.9",),
        T0 + timedelta(seconds=start), T0 + timedelta(seconds=end),
    )  # fmt: skip


def win(host: str, start: float, score: float, explained: bool = False) -> WindowRef:
    return WindowRef(host, START + start, START + start + 300, score, explained)


# ---- metrics ----------------------------------------------------------------------------
def test_positive_windows_overlap_the_episode_on_a_relevant_host_with_tolerance() -> None:
    e = episode()
    assert window_is_positive(win("10.0.0.5", 600, 1), [e])
    assert window_is_positive(win("10.0.0.9", 600, 1), [e])  # a target host counts
    assert not window_is_positive(win("10.0.0.7", 600, 1), [e])
    assert window_is_positive(win("10.0.0.5", 760, 1), [e])  # starts exactly 60 s after the end
    assert not window_is_positive(win("10.0.0.5", 761, 1), [e])


def test_precision_and_recall_at_k_use_only_rule_unexplained_windows() -> None:
    e = episode()
    windows = [
        win("10.0.0.5", 600, 9.0),  # positive, rank 1
        win("10.0.0.7", 0, 8.0),  # negative, rank 2
        win("10.0.0.5", 300, 7.0, explained=True),  # explained: ignored
        win("10.0.0.7", 300, 1.0),
    ]
    assert precision_at_k(windows, [e], k=2) == 0.5
    assert precision_at_k(windows, [e], k=1) == 1.0
    assert recall_at_k(windows, [e], k=1) == 1.0
    assert recall_at_k(windows, [e, episode("10.0.0.99", 9000, 9100)], k=3) == 0.5
    assert recall_at_k(windows, [], k=3) is None and precision_at_k([], [e]) is None


def test_pr_auc_is_one_for_a_perfect_ranking_and_none_without_positives() -> None:
    e = episode()
    perfect = [win("10.0.0.5", 600, 9.0), win("10.0.0.7", 0, 1.0), win("10.0.0.7", 300, 0.5)]
    assert pr_auc(perfect, [e]) == 1.0
    assert pr_auc([win("10.0.0.7", 0, 1.0)], [e]) is None
    worst = [win("10.0.0.5", 600, 0.1), win("10.0.0.7", 0, 1.0), win("10.0.0.7", 300, 0.5)]
    assert pr_auc(worst, [e]) == pytest.approx(1 / 3)


def test_promoted_rate_needs_a_threshold_and_scores() -> None:
    assert promoted_rate([1.0, 2.0, 3.0, 4.0], 3.0) == 0.5
    assert promoted_rate([1.0], None) is None and promoted_rate([], 1.0) is None


def test_bootstrap_resamples_captures_deterministically() -> None:
    a, b = [0.9, 0.8, 1.0, 0.7], [0.1, 0.2, 0.3, 0.1]
    mean, lo, hi = bootstrap_difference(a, b) or (0, 0, 0)
    assert mean == pytest.approx(0.675) and 0 < lo <= mean <= hi
    assert bootstrap_difference(a, b) == bootstrap_difference(a, b)
    straddling = bootstrap_difference([0.5, 0.1, 0.6, 0.2], [0.1, 0.5, 0.2, 0.6]) or (0, 0, 0)
    assert straddling[1] < 0 < straddling[2]
    assert bootstrap_difference([], []) is None and bootstrap_difference([1.0], [1.0, 2.0]) is None


# ---- the pre-declared G1 rule -----------------------------------------------------------
def test_g1_ships_iforest_only_when_every_condition_holds() -> None:
    ci_ok, ci_zero = (0.2, 0.05, 0.4), (0.2, -0.05, 0.4)
    assert decide_g1(0.8, 0.6, ci_ok, 0.01, 0.9, 0.0)[0] == "iforest"  # margin exactly 0.2 >= 0.10
    assert decide_g1(0.8, 0.7, ci_ok, 0.01, 0.9, 0.0)[0] == "iforest"  # margin 0.10 is enough
    assert decide_g1(0.8, 0.71, ci_ok, 0.01, 0.9, 0.0)[0] == "robust_z"  # margin 0.09 is not
    assert decide_g1(0.8, 0.6, ci_zero, 0.01, 0.9, 0.0)[0] == "robust_z"  # CI includes 0
    assert decide_g1(0.8, 0.6, ci_ok, 0.011, 0.9, 0.0)[0] == "robust_z"  # benign rate > 1%


def test_g1_falls_back_to_robust_z_then_off() -> None:
    assert decide_g1(None, None, None, None, 0.5, 0.01)[0] == "robust_z"  # recall exactly 0.5
    assert decide_g1(None, None, None, None, 0.49, 0.01)[0] == "off"
    assert decide_g1(None, None, None, None, 0.9, 0.02)[0] == "off"  # benign rate too high
    decision, reason = decide_g1(None, None, None, None, None, None)
    assert decision == "off" and "none were measured" in reason


# ---- calibration threshold --------------------------------------------------------------
def test_calibrated_threshold_never_lets_more_than_one_percent_through() -> None:
    scores = [float(i) for i in range(200)]
    cut = ra.calibrated_threshold(scores)
    assert cut is not None and sum(s >= cut for s in scores) <= 2  # floor(1% of 200)
    ties = [1.0] * 150 + [5.0] * 50
    cut_ties = ra.calibrated_threshold(ties)
    assert cut_ties is not None and sum(s >= cut_ties for s in ties) <= 2
    few = [0.1, 0.9, 0.5]  # 1% of 3 is 0 allowed: nothing may reach the cut-off
    cut_few = ra.calibrated_threshold(few)
    assert cut_few is not None and sum(s >= cut_few for s in few) == 0
    assert ra.calibrated_threshold([]) is None


# ---- harness ----------------------------------------------------------------------------
def write_analysis(root: Path, run_id: str, hosts: int = 3, windows: int = 6) -> None:
    """Irregular, low-volume client traffic: no detector fires, every window stays unexplained."""
    rng = random.Random(run_id)  # noqa: S311  # seeded, reproducible fixture
    rows: list[dict[str, Any]] = []
    for h in range(hosts):
        for w in range(windows):
            for i in range(5 + (h + w) % 3):
                when = START + w * 300 + rng.uniform(0, 290)
                row = conn_row(when, f"172.20.0.{h + 101}", "172.20.0.20", 443)
                row["uid"] = f"C-{h}-{w}-{i}"
                row["orig_bytes"] = rng.randint(50, 5000)
                rows.append(row)
    write_zeek_logs(root / run_id / "zeek", {"conn": rows})
    normalise_logs(root / run_id / "zeek", root / run_id / "tables")
    (root / run_id / "status.json").write_text(
        json.dumps({"status": "completed", "sha256": "ab" * 32, "zeek_version": "9.0.0"})
    )
    (root / run_id / "profile.json").write_text(json.dumps({"capture": {"duration_s": 1800.0}}))


@pytest.fixture
def world(tmp_path: Path) -> dict[str, Any]:
    runs_dir = tmp_path / "runs"
    runs_dir.mkdir()
    for run_id in ("d1", "d2", "t1"):
        write_run(runs_dir, run_id, [("hard_negative", "NTP", "")])
    entry = {"stratum": "s", "labels_sha256": "x", "run_json_sha256": "x"}
    analysis = tmp_path / "analysis"
    for run_id in ("d1", "d2", "t1"):
        write_analysis(analysis, run_id)
    return {
        "runs": splits.load_runs(runs_dir),
        "manifest": manifest(
            {
                "d1": {"split": "dev", **entry},
                "d2": {"split": "dev", **entry},
                "t1": {"split": "test", **entry},
            }
        ),
        "analysis": analysis,
        "cfg": load_anomaly_config(REPO / "config" / "anomaly.yaml"),
        "tmp": tmp_path,
    }


def test_calibration_reads_only_dev_benign_runs_and_never_a_test_capture(
    world: dict[str, Any],
) -> None:
    result = ra.calibrate(world["analysis"], world["cfg"], world["manifest"], world["runs"])
    assert result["runs"] == ["d1", "d2"] and set(result["per_run"]) == {"d1", "d2"}
    assert "t1" not in json.dumps(result)  # no test capture id in the tuning log
    # 2 runs x 4 internal hosts (three clients and the server) x 6 windows
    assert all(result["pooled_windows"][s] == 48 for s in ra.SCORERS)
    for scorer in ra.SCORERS:
        rate = result["benign_promoted_rate_at_threshold"][scorer]
        assert rate is not None and rate <= 0.01


def test_calibration_without_dev_benign_runs_is_an_error(world: dict[str, Any]) -> None:
    world["manifest"]["assigned"].pop("d1")
    world["manifest"]["assigned"].pop("d2")
    with pytest.raises(HarnessError, match="no benign run"):
        ra.calibrate(world["analysis"], world["cfg"], world["manifest"], world["runs"])


def test_evaluate_refuses_test_and_reports_holdout_metrics_as_not_measurable_on_dev(
    world: dict[str, Any],
) -> None:
    with pytest.raises(HarnessError, match="refusing to evaluate the test split"):
        ra.evaluate("test", world["analysis"], world["cfg"], world["manifest"], world["runs"])
    out = ra.evaluate("dev", world["analysis"], world["cfg"], world["manifest"], world["runs"])
    assert out["holdout_metrics"].startswith("not measurable")
    assert out["g1_decision"] == "not decided" and out["holdout_runs"] == []
    assert out["scorers"]["robust_z"]["precision_at_10"] is None
    assert (
        out["scorers"]["robust_z"]["benign_promoted_rate"] == 0.0
    )  # at the dev-calibrated cut-off


def test_main_writes_results_once(
    world: dict[str, Any], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(ra, "load_manifest", lambda: world["manifest"])
    monkeypatch.setattr(ra, "load_runs", lambda: world["runs"])
    argv = [
        "calibrate",
        "--analysis-dir",
        str(world["analysis"]),
        "--out",
        str(world["tmp"] / "res"),
        "--run-id",
        "cal",
    ]
    assert ra.main(argv) == 0
    data = json.loads((world["tmp"] / "res" / "cal" / "anomaly_calibration.json").read_text())
    assert data["runs"] == ["d1", "d2"] and "promotion_threshold = " in capsys.readouterr().out
    assert ra.main(argv) == 2 and "never overwritten" in capsys.readouterr().err
    assert ra.main(["evaluate", "--split", "test", "--analysis-dir", str(world["analysis"])]) == 2


def test_committed_calibration_only_used_dev_runs_and_g1_is_recorded_as_not_run() -> None:
    """P5 leakage check: no test capture id appears in any tuning log; G1 is honestly 'not run'."""
    assigned = splits.load_manifest()["assigned"]
    test_ids = {r for r, v in assigned.items() if v["split"] == "test"}
    assert test_ids  # b01, b03, b06
    for log in (REPO / "eval" / "results").glob("anomaly-calibration-*/*.json"):
        text = log.read_text(encoding="utf-8")
        assert not any(run_id in text for run_id in test_ids), log
    cfg = load_anomaly_config(REPO / "config" / "anomaly.yaml")
    assert cfg.promotion_threshold.robust_z is not None  # calibrated from the committed dev result
    decision = (REPO / "eval" / "decisions" / "G1.md").read_text(encoding="utf-8")
    assert "**Not run**" in decision and "`ANOMALY_SCORER=off`" in decision
