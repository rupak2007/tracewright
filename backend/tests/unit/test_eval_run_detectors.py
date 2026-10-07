"""Evaluation harness guard rails and bookkeeping. SYNTHETIC runs, labels and tables only."""

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("eval")
pytest.importorskip("lab")

from eval import run_detectors as harness
from eval import splits

from app.ingest.normalise import normalise_logs
from tests.helpers import conn_row, write_zeek_logs
from tests.unit.test_eval_splits import manifest, write_run

CAPTURE_SHA = "ab" * 32  # what write_run records as the capture hash
START = datetime(2026, 11, 2, 10, 0, 0, tzinfo=UTC).timestamp()
CLIENT, SERVER = "172.20.0.101", "172.20.0.20"


def write_analysis(root: Path, run_id: str, *, sha: str = CAPTURE_SHA, beacon: bool = True) -> None:
    """A P1-style analysis directory: tables/, status.json, profile.json."""
    rows = []
    if beacon:  # regular check-ins from the labelled client: a beacon finding on a hard negative
        for i in range(30):
            row = conn_row(START + i * 60, CLIENT, SERVER, 8080, orig_bytes=200, resp_bytes=200)
            row["uid"] = f"C{i:03d}"
            rows.append(row)
    write_zeek_logs(root / run_id / "zeek", {"conn": rows})
    normalise_logs(root / run_id / "zeek", root / run_id / "tables")
    (root / run_id / "status.json").write_text(
        json.dumps({"status": "completed", "sha256": sha, "zeek_version": "9.0.0"})
    )
    (root / run_id / "profile.json").write_text(json.dumps({"capture": {"duration_s": 3600.0}}))


@pytest.fixture
def world(tmp_path: Path) -> dict[str, Any]:
    runs_dir = tmp_path / "runs"
    runs_dir.mkdir()
    write_run(runs_dir, "d1", [("hard_negative", "MONITORING_HEARTBEAT", "")])
    write_run(runs_dir, "t1", [("hard_negative", "NTP", "")])
    assigned = {
        "d1": {"split": "dev", "stratum": "s", "labels_sha256": "x", "run_json_sha256": "x"},
        "t1": {"split": "test", "stratum": "s", "labels_sha256": "x", "run_json_sha256": "x"},
    }
    analysis = tmp_path / "analysis"
    write_analysis(analysis, "d1")
    return {
        "runs": splits.load_runs(runs_dir),
        "manifest": manifest(assigned),
        "analysis": analysis,
        "tmp": tmp_path,
    }


def evaluate(world: dict[str, Any], split: str = "dev") -> tuple[dict[str, Any], dict[str, Any]]:
    return harness.evaluate_split(
        split,
        world["analysis"],
        harness.REPO / "config" / "detectors.yaml",
        harness.REPO / "config",
        manifest=world["manifest"],
        runs=world["runs"],
    )


def test_the_test_split_is_refused_while_corpus_requirements_are_unmet(
    world: dict[str, Any],
) -> None:
    with pytest.raises(harness.HarnessError, match="refusing to evaluate the test split"):
        evaluate(world, "test")
    harness.check_split_allowed("dev", world["manifest"], world["runs"])  # dev is always allowed


def test_unknown_split_and_empty_split_are_errors(world: dict[str, Any]) -> None:
    with pytest.raises(harness.HarnessError):
        harness.check_split_allowed("holdout", world["manifest"], world["runs"])
    world["manifest"]["assigned"].pop("d1")
    with pytest.raises(harness.HarnessError, match="no runs are assigned"):
        evaluate(world)


def test_false_positives_on_a_hard_negative_are_attributed_and_attack_metrics_are_null(
    world: dict[str, Any],
) -> None:
    metrics, run_manifest = evaluate(world)
    assert metrics["attack_metrics"].startswith("not measurable")
    assert "NOT detector performance on attacks" in metrics["scope"]
    for mode in harness.MODES:
        s = metrics["modes"][mode]
        assert s["recall"] is None and s["precision"] is None
        assert s["false_positive_by_hard_negative_medium_high"] == {"MONITORING_HEARTBEAT": 1}
        assert s["benign_hours"] == 1.0 and s["false_positives_per_benign_hour_medium_high"] == 1.0
    fp = metrics["false_positive_findings"]["with_allowlists"][0]
    assert fp["type"] == "BEACON" and fp["matches_hard_negative"] == "MONITORING_HEARTBEAT"
    assert run_manifest["split"] == "dev" and run_manifest["runs"]["d1"]["zeek_version"] == "9.0.0"
    assert len(run_manifest["config_hash"]) == 64


def test_metrics_are_reproducible(world: dict[str, Any]) -> None:
    assert evaluate(world)[0] == evaluate(world)[0]


def test_the_analysis_must_exist_and_belong_to_the_runs_capture(world: dict[str, Any]) -> None:
    (world["analysis"] / "d1" / "profile.json").unlink()
    with pytest.raises(harness.HarnessError, match="no P1 analysis"):
        evaluate(world)
    write_analysis(world["analysis"] / "other", "d1", sha="cd" * 32)  # a different capture
    world["analysis"] = world["analysis"] / "other"
    with pytest.raises(harness.HarnessError, match="not a completed analysis"):
        evaluate(world)


def test_allowlists_only_remove_what_the_context_names() -> None:
    from app.profile.context import NetworkContext

    ctx = NetworkContext.model_validate(
        {
            "internal_cidrs": ["10.0.0.0/8"],
            "known_hosts": {"scanners": ["10.0.0.9"]},
            "allowlist": {"domains": ["a.com"], "periodic_ports": [123]},
        }
    )
    bare = harness.without_allowlists(ctx)
    assert bare.internal_cidrs == ctx.internal_cidrs and bare.classify("10.1.1.1") == "internal"
    assert bare.known_hosts.scanners == [] and bare.allowlist.periodic_ports == []


def test_main_writes_results_once_and_never_overwrites(
    world: dict[str, Any], capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(harness, "load_manifest", lambda: world["manifest"])
    monkeypatch.setattr(harness, "load_runs", lambda: world["runs"])
    out = world["tmp"] / "results"
    argv = [
        "--split",
        "dev",
        "--analysis-dir",
        str(world["analysis"]),
        "--out",
        str(out),
        "--run-id",
        "r",
    ]
    assert harness.main(argv) == 0
    written = json.loads((out / "r" / "detectors.json").read_text())
    assert written["split"] == "dev" and (out / "r" / "manifest.json").exists()
    assert "attack metrics: not measurable" in capsys.readouterr().out
    assert harness.main(argv) == 2  # refuses to overwrite a result
    assert "never overwritten" in capsys.readouterr().err
    assert (
        harness.main(
            ["--split", "test", "--analysis-dir", str(world["analysis"]), "--out", str(out)]
        )
        == 2
    )
