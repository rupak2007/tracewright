"""Detector framework: configuration, windows, evidence capping and the deterministic runner.

All inputs are SYNTHETIC test fixtures (tests/detect_helpers.py); no capture is involved."""

from collections import Counter
from pathlib import Path

import numpy as np
import pytest

from app.core.errors import ConfigError
from app.detect.base import DetectorInput, DetectorOutput, Finding, cap_evidence
from app.detect.config import load_detectors_config
from app.detect.runner import run_detectors
from app.detect.windows import max_count_window, max_distinct_window
from tests.detect_helpers import SHIPPED_CONFIG, detector_input, finding


def test_shipped_config_loads_and_matches_the_documented_defaults() -> None:
    cfg = load_detectors_config(SHIPPED_CONFIG)
    assert (cfg.scan.vertical_ports, cfg.scan.horizontal_hosts, cfg.scan.slow_vertical_ports) == (
        50,
        20,
        100,
    )
    assert (cfg.brute.ftp_failures, cfg.brute.http_failures) == (10, 20)
    assert (cfg.dnstun.min_unique_subdomains, cfg.dnstun.min_mean_entropy) == (50, 3.5)
    assert (cfg.beacon.min_events, cfg.beacon.min_score, cfg.beacon.high_score) == (10, 0.8, 0.9)
    assert (cfg.exfil.min_outbound_bytes, cfg.exfil.min_modified_z) == (50_000_000, 3.5)
    assert cfg.common.severity_base == {"SCAN": 2, "BRUTE": 3, "DNSTUN": 4, "BEACON": 4, "EXFIL": 5}


def test_config_hash_is_stable_and_sensitive_to_every_threshold() -> None:
    cfg = load_detectors_config(SHIPPED_CONFIG)
    assert cfg.config_hash() == load_detectors_config(SHIPPED_CONFIG).config_hash()
    changed = cfg.model_copy(update={"scan": cfg.scan.model_copy(update={"vertical_ports": 51})})
    assert changed.config_hash() != cfg.config_hash()


@pytest.mark.parametrize("content", ["", "version: 1", "not: [valid", "version: 1\nextra: 1"])
def test_invalid_config_is_a_config_error(tmp_path: Path, content: str) -> None:
    path = tmp_path / "detectors.yaml"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ConfigError):
        load_detectors_config(path)
    with pytest.raises(ConfigError):
        load_detectors_config(tmp_path / "missing.yaml")


def test_unknown_threshold_names_are_rejected(tmp_path: Path) -> None:
    text = SHIPPED_CONFIG.read_text(encoding="utf-8").replace(
        "vertical_ports:", "vertical_prts:", 1
    )
    (tmp_path / "d.yaml").write_text(text, encoding="utf-8")
    with pytest.raises(ConfigError):
        load_detectors_config(tmp_path / "d.yaml")


def test_max_distinct_window_boundaries_and_ties() -> None:
    times = np.array([0.0, 10.0, 20.0, 60.0, 61.0])
    values = ["a", "b", "c", "d", "e"]
    # closed window: events exactly window_s apart are inside it
    assert max_distinct_window(times, values, 60.0) == (4, 0, 4)
    assert max_distinct_window(times, values, 49.9)[0] == 3
    assert max_distinct_window(np.array([]), [], 60.0) == (0, 0, 0)
    # repeated values count once; the earliest of equal windows wins
    assert max_distinct_window(np.array([0.0, 1.0, 100.0, 101.0]), ["a", "a", "b", "c"], 5) == (
        2,
        2,
        4,
    )


def test_max_count_window() -> None:
    times = np.array([0.0, 1.0, 2.0, 100.0, 101.0, 102.0])
    assert max_count_window(times, 5.0) == (3, 0, 3)  # earliest of two equal windows
    assert max_count_window(times, 200.0) == (6, 0, 6)
    assert max_count_window(np.array([]), 5.0) == (0, 0, 0)


def test_cap_evidence_keeps_order_dedupes_and_counts_everything() -> None:
    refs, count = cap_evidence(["C1", "C2", "C1", "", "C3", "C4"], 3)
    assert refs == ["C1", "C2", "C3"] and count == 4


class _Fake:
    detector_id = "DET-FAKE"
    version = "9.9.9"

    def __init__(self, findings: list[Finding], suppressed: dict[str, int] | None = None) -> None:
        self._findings, self._suppressed = findings, Counter(suppressed or {})

    def run(self, inp: DetectorInput) -> DetectorOutput:
        return DetectorOutput(list(self._findings), self._suppressed)


def test_runner_orders_findings_numbers_them_and_reports_suppression() -> None:
    late = finding("EXFIL", "10.0.0.2", start=500.0)
    early_b = finding("BRUTE", "10.0.0.9", start=100.0)
    early_a = finding("SCAN", "10.0.0.9", start=100.0)
    inp = detector_input()
    report = run_detectors(inp, "inv-1", [_Fake([late, early_b, early_a], {"allowlist": 2})])
    assert [(f.id, f.type) for f in report.findings] == [
        ("F-1", "SCAN"),
        ("F-2", "BRUTE"),
        ("F-3", "EXFIL"),
    ]
    assert {f.investigation_id for f in report.findings} == {"inv-1"}
    assert report.suppressed == {"DET-FAKE": {"allowlist": 2}} and report.suppressed_total == 2
    assert report.detector_versions == {"DET-FAKE": "9.9.9"}
    assert report.counts_by_type() == {"BRUTE": 1, "EXFIL": 1, "SCAN": 1}
    assert report.config_hash == inp.config.config_hash()


def test_runner_output_does_not_depend_on_finding_insertion_order() -> None:
    items = [finding("SCAN", f"10.0.0.{i}", start=float(i % 3)) for i in range(9)]
    inp = detector_input()
    forward = run_detectors(inp, detectors=[_Fake(items)])
    backward = run_detectors(inp, detectors=[_Fake(list(reversed(items)))])
    assert forward.model_dump_json() == backward.model_dump_json()


def test_findings_are_immutable() -> None:
    f = finding("SCAN", "10.0.0.1")
    with pytest.raises(ValueError):
        f.confidence = "low"  # type: ignore[misc]


def test_default_registry_on_an_empty_capture_finds_nothing_and_does_not_fail() -> None:
    assert run_detectors(detector_input()).findings == []
