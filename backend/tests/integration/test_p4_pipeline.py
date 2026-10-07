"""Zeek-style evidence -> detectors -> incidents -> ATT&CK -> evidence IDs -> report (milestone M2).

SYNTHETIC: Zeek-format JSON log lines written by this test, never a capture. The storyline mirrors
the documented multi-stage case (reconnaissance and brute force, then the targeted host beacons, and
a second host uploads to the same destination) so every link rule and the report are exercised
end to end. It says nothing about detection performance.
"""

import base64
import hashlib
import re
from pathlib import Path
from typing import Any

import pytest

from app.attack.mapping import load_mapping
from app.core.config import PipelineSettings
from app.correlate.runner import correlate
from app.detect.base import DetectorInput
from app.detect.runner import run_detectors
from app.ingest.normalise import normalise_logs
from app.profile.context import NetworkContext
from app.report.assemble import assemble_analysis
from app.report.model import AnalysisOutput
from app.report.render import md_escape, render_markdown
from app.worker.analysis_config import AnalysisConfig, load_analysis_config
from tests.helpers import conn_row, write_zeek_logs

T0 = 1_700_000_000.0
ATTACKER, TARGET, UPLOADER, DEST = "10.0.0.66", "10.0.1.21", "10.0.2.2", "203.0.113.40"
HOSTILE = "<img src=x onerror=alert(1)>.tunnel.example.net"


def _label(i: int, length: int = 40) -> str:
    return (
        base64.b32encode(hashlib.sha256(f"s{i}".encode()).digest())
        .decode()
        .lower()
        .rstrip("=")[:length]
    )


def storyline_logs() -> dict[str, list[dict[str, Any]]]:
    conn: list[dict[str, Any]] = []
    ftp: list[dict[str, Any]] = []
    dns: list[dict[str, Any]] = []
    n = 0

    def add(ts: float, src: str, dst: str, port: int, **extra: Any) -> str:
        nonlocal n
        n += 1
        row = conn_row(ts, src, dst, port, **extra)
        row["uid"] = f"C{n:05d}"
        conn.append(row)
        return str(row["uid"])

    for i in range(60):  # reconnaissance: 60 ports in 30 s, refused
        add(T0 + i * 0.5, ATTACKER, TARGET, 1000 + i, conn_state="REJ", service=None)
    for i in range(12):  # brute force: 12 FTP login failures
        uid = add(T0 + 100 + i, ATTACKER, TARGET, 21, service="ftp")
        ftp.append(
            {
                "ts": T0 + 100 + i,
                "uid": uid,
                "id.orig_h": ATTACKER,
                "id.orig_p": 50000,
                "id.resp_h": TARGET,
                "id.resp_p": 21,
                "command": "PASS",
                "reply_code": 530,
            }
        )
    for i in range(30):  # later the targeted host beacons to DEST every 60 s
        add(T0 + 3000 + i * 60, TARGET, DEST, 8443, orig_bytes=300, resp_bytes=300)
    for i in range(25):  # a population of ordinary external pairs for the exfil baseline
        add(
            T0 + 5000 + i * 5,
            "10.0.3.3",
            f"198.51.100.{i + 1}",
            443,
            orig_bytes=100_000 + i * 9_000,
            resp_bytes=60_000,
        )
    add(T0 + 5200, UPLOADER, DEST, 443, orig_bytes=80_000_000, resp_bytes=40_000, duration=120.0)
    for i in range(55):  # a tunnel with one hostile-looking query name in the data
        uid = add(T0 + 6000 + i, "10.0.4.4", "10.0.0.53", 53, proto="udp", service="dns")
        name = HOSTILE if i == 0 else f"{_label(i)}.tunnel.example.net"
        dns.append(
            {
                "ts": T0 + 6000 + i,
                "uid": uid,
                "id.orig_h": "10.0.4.4",
                "id.orig_p": 50000,
                "id.resp_h": "10.0.0.53",
                "id.resp_p": 53,
                "proto": "udp",
                "trans_id": i,
                "query": name,
                "qtype_name": "A",
                "rcode_name": "NXDOMAIN",
            }
        )
    return {"conn": conn, "ftp": ftp, "dns": dns}


@pytest.fixture(scope="module")
def acfg() -> AnalysisConfig:
    repo = Path(__file__).resolve().parents[3]
    return load_analysis_config(
        PipelineSettings(config_dir=repo / "config", knowledge_dir=repo / "knowledge")
    )


def run_all(tmp_path: Path, acfg: AnalysisConfig, tag: str = "a") -> AnalysisOutput:
    write_zeek_logs(tmp_path / tag / "zeek", storyline_logs())
    tables, _ = normalise_logs(tmp_path / tag / "zeek", tmp_path / tag / "tables")
    ctx = NetworkContext.model_validate({"internal_cidrs": ["10.0.0.0/8"]})
    span = float((tables.conn["ts"].max() - tables.conn["ts"].min()).total_seconds())
    report = run_detectors(DetectorInput(tables, ctx, acfg.detectors, span), "inv-test")
    result = correlate(report.findings, acfg.correlation)
    return assemble_analysis(
        investigation_id="inv-test",
        capture_sha256="ab" * 32,
        report=report,
        correlation=result,
        tables=tables,
        mapping=acfg.mapping,
        cards=acfg.cards,
        playbooks=acfg.playbooks,
    )


def test_the_storyline_yields_the_documented_incidents_links_and_mappings(
    tmp_path: Path, acfg: AnalysisConfig
) -> None:
    out = run_all(tmp_path, acfg)
    by_entity = {d.incident.primary_entity: d for d in out.incidents}
    assert set(by_entity) == {ATTACKER, TARGET, UPLOADER, "10.0.4.4"}
    assert by_entity[ATTACKER].incident.types == ["BRUTE", "SCAN"]
    assert {lk.type for lk in out.links} == {"TARGET_LATER_ACTIVE", "SHARED_EXTERNAL_PEER"}
    peer = next(lk for lk in out.links if lk.type == "SHARED_EXTERNAL_PEER")
    assert {peer.from_incident, peer.to_incident} == {
        by_entity[TARGET].incident.id,
        by_entity[UPLOADER].incident.id,
    }
    tla = next(lk for lk in out.links if lk.type == "TARGET_LATER_ACTIVE")
    assert (tla.from_incident, tla.to_incident) == (
        by_entity[ATTACKER].incident.id,
        by_entity[TARGET].incident.id,
    )
    # severity: the linked incidents get the link bonus and rank above the lone tunnel
    scores = {e: d.incident.severity_score for e, d in by_entity.items()}
    assert scores[UPLOADER] == 6.0  # EXFIL high 5.0 + link bonus 1.0
    assert by_entity[TARGET].incident.severity_breakdown["link_bonus"] == 1.0  # target side + peer
    assert by_entity[ATTACKER].incident.severity_breakdown["link_bonus"] == 0.0
    exfil = by_entity[UPLOADER].findings[0]
    assert [t.technique_id for t in by_entity[UPLOADER].techniques[exfil.id]] == ["T1048", "T1041"]
    brute = next(f for f in by_entity[ATTACKER].findings if f.type == "BRUTE")
    assert [t.technique_id for t in by_entity[ATTACKER].techniques[brute.id]] == ["T1110.001"]
    tunnel = by_entity["10.0.4.4"].findings[0]
    assert [t.technique_id for t in by_entity["10.0.4.4"].techniques[tunnel.id]] == ["T1071.004"]
    ranked = sorted(
        out.incidents,
        key=lambda d: (-d.incident.severity_score, d.incident.start_ts, d.incident.id),
    )
    assert [d.incident.id for d in out.incidents] == [d.incident.id for d in ranked]


def test_evidence_ids_are_sequential_aggregates_first_and_every_citation_resolves(
    tmp_path: Path, acfg: AnalysisConfig
) -> None:
    out = run_all(tmp_path, acfg)
    for d in out.incidents:
        ids = [e.local_id for e in d.evidence]
        assert ids == [f"E-{i}" for i in range(1, len(ids) + 1)]
        kinds = [e.kind for e in d.evidence]
        assert kinds[: len(d.findings)] == ["aggregate"] * len(d.findings)
        records = [e for e in d.evidence if e.kind != "aggregate"]
        assert [e.ts for e in records] == sorted(e.ts for e in records if e.ts)
        cited = set(re.findall(r"E-\d+", d.summary))
        assert cited and cited <= set(ids)
        for sentence in d.summary.splitlines()[1:]:
            assert re.search(r"\[E-\d+(, E-\d+)*\]$", sentence), sentence  # every sentence cites


def test_summaries_are_hedged_and_carry_no_verdict_language(
    tmp_path: Path, acfg: AnalysisConfig
) -> None:
    out = run_all(tmp_path, acfg)
    text = " ".join(d.summary for d in out.incidents).lower()
    for banned in (
        "is compromised",
        "has been compromised",
        "confirmed",
        "definitely",
        "proves",
        "infected",
    ):
        assert banned not in text


def test_summary_numbers_come_from_the_findings_metrics_or_thresholds(
    tmp_path: Path, acfg: AnalysisConfig
) -> None:
    out = run_all(tmp_path, acfg)
    for d in out.incidents:
        allowed: set[str] = set()
        for f in d.findings:
            for v in [*f.metrics.values(), *f.thresholds.values()]:
                if isinstance(v, int | float) and not isinstance(v, bool):
                    allowed.add(str(v))
                    allowed.add(str(round(v * 100, 1)))
        for sentence in d.summary.splitlines()[1:]:
            body = re.sub(r"\[E-[^\]]*\]", "", sentence)
            body = re.sub(r"\b\d+\.\d+\.\d+\.\d+\b", "", body)  # addresses
            for number in re.findall(r"(?<![\w.])\d+(?:\.\d+)?(?![\w.])", body):
                assert number in allowed or number in {"1", "2", "3"}, (number, sentence)


def test_the_report_traces_numbers_to_evidence_and_escapes_hostile_strings(
    tmp_path: Path, acfg: AnalysisConfig
) -> None:
    out = run_all(tmp_path, acfg)
    report = render_markdown(out)
    assert (
        "<img" not in report
        and "onerror=alert" not in report.replace("\\=", "=").replace("\\(", "(")
    ) or "\\<img" in report
    assert "\\<img" in report  # the hostile DNS name is present, escaped, in the evidence table
    for d in out.incidents:
        assert f"## {d.incident.id}:" in report
        for e in d.evidence:
            assert f"| {e.local_id} |" in report
    assert "consistent with" in report and "T1041" in report
    assert "not a risk score" in report
    assert md_escape("a|b\n*c*") == "a\\|b \\*c\\*"


def test_two_runs_produce_identical_json_and_reports(tmp_path: Path, acfg: AnalysisConfig) -> None:
    a = run_all(tmp_path, acfg, "a")
    b = run_all(tmp_path, acfg, "b")
    assert a.model_dump_json() == b.model_dump_json()
    assert render_markdown(a) == render_markdown(b)
    assert (
        AnalysisOutput.model_validate_json(a.model_dump_json()).model_dump_json()
        == a.model_dump_json()
    )


def test_anomaly_findings_would_never_be_mapped() -> None:
    assert (
        load_mapping(
            Path(__file__).resolve().parents[3] / "config" / "attack_mapping.yaml"
        ).mappings["UNEXPLAINED_ANOMALY"]
        == []
    )
