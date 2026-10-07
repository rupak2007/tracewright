"""The synthetic beacon sweep. No capture is involved; this checks the model, not detection."""

import json
from pathlib import Path

import pytest

pytest.importorskip("eval")

from eval import beacon_sweep as sweep_mod

from app.detect.config import load_detectors_config
from tests.detect_helpers import SHIPPED_CONFIG

CFG = load_detectors_config(SHIPPED_CONFIG).beacon


def test_series_is_deterministic_and_respects_the_duration() -> None:
    a = sweep_mod.series(60, 0.25, 3600, seed=3)
    assert a == sweep_mod.series(60, 0.25, 3600, seed=3) != sweep_mod.series(60, 0.25, 3600, seed=4)
    assert a[0] == 0.0 and a[-1] <= 3600
    assert sweep_mod.series(60, 0.0, 600, 0) == [i * 60.0 for i in range(11)]


def test_ten_intervals_must_fit_in_the_capture() -> None:
    too_short = sweep_mod.cell(60, 0.0, 300, CFG)  # 6 events < 10
    assert too_short["fire_rate"] == 0.0 and too_short["mean_score_when_enough_events"] is None
    enough = sweep_mod.cell(60, 0.0, 600, CFG)  # 11 events, perfect timing
    assert enough["fire_rate"] == 1.0


def test_jitter_lowers_the_score_but_this_rule_tolerates_a_lot_of_it() -> None:
    scores = [
        sweep_mod.cell(60, jitter, 7200, CFG)["mean_score_when_enough_events"]
        for jitter in (0.0, 0.1, 0.25, 0.5)
    ]
    assert scores == sorted(scores, reverse=True) and scores[0] > scores[-1]
    # with constant sizes and full coverage even +-50% jitter stays above the 0.8 threshold:
    # a property of the documented score, recorded in the sweep rather than hidden
    assert sweep_mod.cell(60, 0.5, 7200, CFG)["fire_rate"] == 1.0


def test_long_intervals_need_long_captures() -> None:
    # PRD §10: detection needs about 10 events, so a 900 s beacon needs a capture of >= 9000 s
    assert sweep_mod.cell(900, 0.0, 7200, CFG)["fire_rate"] == 0.0  # 9 events
    assert sweep_mod.cell(900, 0.0, 14400, CFG)["fire_rate"] == 1.0  # 17 events


def test_sweep_covers_the_whole_grid_and_labels_itself_synthetic() -> None:
    result = sweep_mod.sweep(CFG)
    assert len(result["cells"]) == 5 * 4 * 5
    assert "SYNTHETIC" in result["scope"] and "not detection performance" in result["scope"]


def test_main_writes_once(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert sweep_mod.main(["--out", str(tmp_path), "--run-id", "s"]) == 0
    data = json.loads((tmp_path / "s" / "sweep.json").read_text())
    assert data["min_events"] == 10 and (tmp_path / "s" / "manifest.json").exists()
    assert sweep_mod.main(["--out", str(tmp_path), "--run-id", "s"]) == 2
    assert "never overwritten" in capsys.readouterr().err
