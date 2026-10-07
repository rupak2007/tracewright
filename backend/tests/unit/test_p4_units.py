"""Templates, evidence IDs, manifest, analysis config and startup checks (P4). SYNTHETIC inputs."""

import shutil
from pathlib import Path

import pytest
from jinja2 import UndefinedError

from app.core.config import PipelineSettings
from app.core.errors import ConfigError, StartupCheckError
from app.correlate.runner import correlate
from app.detect.base import Finding
from app.explain.evidence_ids import aggregate_fields, build_incident_evidence
from app.explain.knowledge import load_playbooks, playbook_id
from app.explain.template_summary import TEMPLATE_DIR, finding_sentence, incident_summary
from app.report.render import md_escape
from app.worker.analysis_config import load_analysis_config
from app.worker.manifest import build_manifest, hash_config_file
from app.worker.startup import check_attack_mapping
from tests.detect_helpers import finding, tables

REPO = Path(__file__).resolve().parents[3]
SETTINGS = PipelineSettings(config_dir=REPO / "config", knowledge_dir=REPO / "knowledge")
ACFG = load_analysis_config(SETTINGS)


def scan_finding() -> Finding:
    return finding(
        "SCAN",
        "10.0.0.5",
        fid="F-1",
        secondary=["10.0.0.9"],
        metrics={
            "scan_type": "vertical",
            "distinct_dst_ports": 60,
            "distinct_dst_hosts": 1,
            "failed_share": 0.9,
            "connections": 60,
            "window_s": 60.0,
        },
        thresholds={"vertical_ports": 50, "horizontal_hosts": 20, "slow_vertical_ports": 100},
        refs=["C1", "C2", "C3"],
    )


def test_every_finding_type_has_a_template() -> None:
    for kind in ("SCAN", "BRUTE", "DNSTUN", "BEACON", "EXFIL"):
        assert (TEMPLATE_DIR / f"{kind}.j2").is_file()


def test_templates_use_strict_variables_so_a_missing_metric_fails_loudly() -> None:
    f = finding("BEACON", "10.0.0.5", fid="F-1", secondary=["x"], metrics={}, thresholds={})
    inc = correlate([f], ACFG.correlation).incidents[0]
    ev = build_incident_evidence(inc, {"F-1": f}, tables())
    with pytest.raises(UndefinedError):
        finding_sentence(f, ev)


def test_a_sentence_cites_the_aggregate_and_at_most_two_records_and_prints_metrics() -> None:
    f = scan_finding()
    inc = correlate([f], ACFG.correlation).incidents[0]
    ev = build_incident_evidence(inc, {"F-1": f}, tables())
    assert [e.kind for e in ev] == ["aggregate"]  # no conn rows in the empty tables: no records
    sentence = finding_sentence(f, ev)
    assert "60 distinct port(s)" in sentence and "90.0%" in sentence
    assert sentence.endswith("[E-1]") and "vertical pattern" in sentence
    summary = incident_summary(inc, [f], ev)
    assert summary.splitlines()[0].startswith("Incident I-1 (") and "not a risk score" in summary


def test_aggregate_fields_hold_metrics_and_prefixed_thresholds() -> None:
    fields = aggregate_fields(scan_finding())
    assert fields["distinct_dst_ports"] == 60 and fields["threshold_vertical_ports"] == 50
    assert fields["finding_type"] == "SCAN" and fields["confidence"] == "high"


def test_md_escape_neutralises_markup_and_flattens_whitespace() -> None:
    assert md_escape("<b>x</b>") == "\\<b\\>x\\</b\\>"
    assert md_escape("a\n\nb\t c") == "a b c"
    assert md_escape("[l](u) `c` |t|") == "\\[l\\](u) \\`c\\` \\|t\\|"  # a link can never form
    assert md_escape(None) == "None" and md_escape(3) == "3"


def test_playbooks_load_for_every_detector_and_a_missing_one_is_an_error(tmp_path: Path) -> None:
    books = load_playbooks(REPO / "knowledge")
    assert set(books) == {playbook_id(k) for k in ("SCAN", "BRUTE", "DNSTUN", "BEACON", "EXFIL")}
    assert all(
        "What would confirm it" in text and "benign" in text.lower() for text in books.values()
    )
    shutil.copytree(REPO / "knowledge" / "playbooks", tmp_path / "playbooks")
    (tmp_path / "playbooks" / "DET-SCAN.md").unlink()
    with pytest.raises(ConfigError, match="missing verification playbook"):
        load_playbooks(tmp_path)


def test_config_hash_ignores_line_endings(tmp_path: Path) -> None:
    (tmp_path / "a").write_bytes(b"x: 1\ny: 2\n")
    (tmp_path / "b").write_bytes(b"x: 1\r\ny: 2\r\n")
    assert hash_config_file(tmp_path / "a") == hash_config_file(tmp_path / "b")


def test_manifest_is_deterministic_and_records_versions_hashes_and_counts() -> None:
    kwargs = {
        "version": "1.2.3",
        "zeek_version": "9.0.0",
        "capture_sha256": "ab" * 32,
        "attack_version": ACFG.pins.attack_version,
        "attack_bundle_sha256": ACFG.pins.bundle_sha256,
        "detector_versions": {"DET-SCAN": "1.0.0"},
        "config_dir": REPO / "config",
        "counts": {"findings": 1},
    }
    a, b = build_manifest(**kwargs), build_manifest(**kwargs)
    assert a.model_dump_json() == b.model_dump_json()
    assert set(a.config_sha256) >= {"detectors.yaml", "correlation.yaml", "attack_mapping.yaml"}
    assert all(len(h) == 64 for h in a.config_sha256.values()) and a.attack_version == "19.2"


def test_analysis_config_loads_everything_and_rejects_a_stale_card_set(tmp_path: Path) -> None:
    assert ACFG.pins.attack_version == "19.2" and set(ACFG.playbooks) and ACFG.cards["T1046"].name
    knowledge = tmp_path / "knowledge"
    shutil.copytree(REPO / "knowledge", knowledge)
    index = knowledge / "cards" / "19.2" / "index.json"
    index.write_text(
        index.read_text(encoding="utf-8").replace('"revoked": false', '"revoked": true', 1)
    )
    with pytest.raises(ConfigError, match="revoked"):
        load_analysis_config(PipelineSettings(config_dir=REPO / "config", knowledge_dir=knowledge))
    with pytest.raises(ConfigError, match="card index"):
        load_analysis_config(
            PipelineSettings(config_dir=REPO / "config", knowledge_dir=tmp_path / "nowhere")
        )


def test_worker_startup_refuses_an_invalid_attack_mapping(tmp_path: Path) -> None:
    assert check_attack_mapping(SETTINGS) == "19.2"
    bad_config = tmp_path / "config"
    shutil.copytree(REPO / "config", bad_config)
    text = (bad_config / "attack_mapping.yaml").read_text(encoding="utf-8")
    (bad_config / "attack_mapping.yaml").write_text(
        text.replace("T1046", "T9999"), encoding="utf-8"
    )
    with pytest.raises(StartupCheckError, match="T9999 is not in the pinned bundle"):
        check_attack_mapping(
            PipelineSettings(config_dir=bad_config, knowledge_dir=REPO / "knowledge")
        )
