"""Zeek-style evidence -> normalisation -> detector pipeline -> structured findings.

Everything here is SYNTHETIC: Zeek-format JSON log lines written by this test. It exercises the
whole detection path (schema normalisation, the five detectors, the runner, JSON round trip,
suppression accounting). It is not a capture and says nothing about detection performance.
Marked integration only because it touches the filesystem; real Zeek is not needed.
"""

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from app.detect.base import DetectorInput
from app.detect.config import load_detectors_config
from app.detect.runner import DetectionReport, run_detectors
from app.ingest.normalise import normalise_logs
from app.profile.context import NetworkContext
from tests.detect_helpers import SHIPPED_CONFIG
from tests.helpers import conn_row, write_zeek_logs

T0 = 1_700_000_000.0
SCANNER, BRUTER, TUNNEL, BEACONER, UPLOADER = (f"10.0.0.{n}" for n in (66, 77, 88, 99, 55))


def label(i: int, length: int = 40) -> str:
    digest = hashlib.sha256(f"x{i}".encode()).digest()
    return base64.b32encode(digest).decode().lower().rstrip("=")[:length]


def build_logs() -> dict[str, list[dict[str, Any]]]:
    conn: list[dict[str, Any]] = []
    dns: list[dict[str, Any]] = []
    ftp: list[dict[str, Any]] = []
    n = 0

    def add_conn(ts: float, orig: str, resp: str, port: int, **extra: Any) -> str:
        nonlocal n
        n += 1
        row = conn_row(ts, orig, resp, port, **extra)
        row["uid"] = f"C{n:05d}"
        conn.append(row)
        return str(row["uid"])

    # scan: 60 ports on one host within 30 s, all refused
    for i in range(60):
        add_conn(T0 + i * 0.5, SCANNER, "10.0.1.10", 1000 + i, conn_state="REJ", service=None)
    # brute force: 12 FTP 530 replies in 12 s
    for i in range(12):
        uid = add_conn(T0 + 100 + i, BRUTER, "10.0.1.21", 21, service="ftp")
        ftp.append(
            {
                "ts": T0 + 100 + i,
                "uid": uid,
                "id.orig_h": BRUTER,
                "id.orig_p": 50000,
                "id.resp_h": "10.0.1.21",
                "id.resp_p": 21,
                "command": "PASS",
                "reply_code": 530,
                "reply_msg": "Login incorrect.",
            }
        )
    # DNS tunnelling: 60 unique 40-char high-entropy subdomains
    for i in range(60):
        uid = add_conn(T0 + 200 + i, TUNNEL, "10.0.0.53", 53, proto="udp", service="dns")
        dns.append(
            {
                "ts": T0 + 200 + i,
                "uid": uid,
                "id.orig_h": TUNNEL,
                "id.orig_p": 50000,
                "id.resp_h": "10.0.0.53",
                "id.resp_p": 53,
                "proto": "udp",
                "trans_id": i,
                "query": f"{label(i)}.tunnel.example.net",
                "qtype_name": "A",
                "rcode_name": "NXDOMAIN",
            }
        )
    # beacon: 30 check-ins, 60 s apart, constant size
    for i in range(30):
        add_conn(T0 + i * 60, BEACONER, "203.0.113.40", 8443, orig_bytes=300, resp_bytes=300)
    # exfil: 25 ordinary external pairs (spread out: 25 hosts inside a minute would be a scan)
    # plus one 80 MB upload, all from one host
    for i in range(25):
        add_conn(
            T0 + 400 + i * 5,
            UPLOADER,
            f"198.51.100.{i + 1}",
            443,
            orig_bytes=100_000 + i * 9_000,
            resp_bytes=60_000,
        )
    add_conn(
        T0 + 450,
        UPLOADER,
        "192.0.2.77",
        443,
        orig_bytes=80_000_000,
        resp_bytes=40_000,
        duration=120.0,
    )
    # NTP (allowlisted periodic port): perfectly regular, would otherwise be a beacon
    for i in range(30):
        add_conn(
            T0 + i * 64,
            "10.0.0.7",
            "10.0.0.123",
            123,
            proto="udp",
            service="ntp",
            orig_bytes=48,
            resp_bytes=48,
        )
    return {"conn": conn, "dns": dns, "ftp": ftp}


@pytest.fixture
def tables(tmp_path: Path) -> Any:
    write_zeek_logs(tmp_path / "zeek", build_logs())
    captured, _ = normalise_logs(tmp_path / "zeek", tmp_path / "tables")
    return captured


def detect(tables: Any, ctx: NetworkContext) -> DetectionReport:
    cfg = load_detectors_config(SHIPPED_CONFIG)
    return run_detectors(DetectorInput(tables, ctx, cfg, 3600.0), "inv-test")


def ctx(**extra: Any) -> NetworkContext:
    return NetworkContext.model_validate({"internal_cidrs": ["10.0.0.0/8"], **extra})


def test_every_detector_fires_on_its_own_evidence_and_nothing_else_does(tables: Any) -> None:
    report = detect(tables, ctx())
    found = {(f.type, f.primary_entity) for f in report.findings}
    assert found == {
        ("SCAN", SCANNER),
        ("BRUTE", BRUTER),
        ("DNSTUN", TUNNEL),
        ("BEACON", BEACONER),
        ("BEACON", "10.0.0.7"),  # NTP is a beacon unless the context allowlists port 123
        ("EXFIL", UPLOADER),
    }
    assert [f.id for f in report.findings] == [f"F-{i}" for i in range(1, len(found) + 1)]
    assert report.suppressed_total == 0


def test_findings_carry_the_required_fields_and_real_evidence(tables: Any) -> None:
    report = detect(tables, ctx())
    uids = {
        "conn": set(tables.conn["uid"]),
        "dns": set(tables.dns["uid"]),
        "ftp": set(tables.ftp["uid"]),
    }
    all_uids = uids["conn"] | uids["dns"] | uids["ftp"]
    for f in report.findings:
        assert f.detector_id.startswith("DET-") and f.detector_version == "1.0.0"
        assert f.metrics and f.thresholds and f.benign_causes
        assert f.confidence in {"low", "medium", "high"} and f.severity_base > 0
        assert f.start_ts <= f.end_ts and f.investigation_id == "inv-test"
        assert f.evidence_refs and set(f.evidence_refs) <= all_uids
        assert f.evidence_count >= len(f.evidence_refs)
    by_type = {f.type: f for f in report.findings if f.primary_entity != "10.0.0.7"}
    assert by_type["SCAN"].confidence == "high" and by_type["BRUTE"].confidence == "high"
    assert by_type["DNSTUN"].confidence == "high" and by_type["BEACON"].confidence == "high"
    assert by_type["EXFIL"].confidence == "high"
    assert by_type["EXFIL"].metrics["outbound_bytes"] == 80_000_000


def test_the_report_survives_a_json_round_trip_unchanged(tables: Any) -> None:
    report = detect(tables, ctx())
    text = report.model_dump_json()
    assert DetectionReport.model_validate_json(text).model_dump_json() == text
    assert json.loads(text)["findings"][0]["id"] == "F-1"


def test_network_context_suppresses_and_counts_without_hiding_the_rest(tables: Any) -> None:
    # allowlist entries are REGISTERED domains: "tunnel.example.net" would not match anything
    report = detect(
        tables,
        ctx(
            allowlist={"periodic_ports": [123], "domains": ["example.net"]},
            known_hosts={"scanners": [SCANNER], "backup_servers": ["192.0.2.77"]},
        ),
    )
    assert {(f.type, f.primary_entity) for f in report.findings} == {
        ("BRUTE", BRUTER),
        ("BEACON", BEACONER),
    }
    assert report.suppressed == {
        "DET-SCAN": {"known_scanner": 1},
        "DET-BRUTE": {},
        "DET-DNSTUN": {"allowlisted_domain": 1},
        "DET-BEACON": {"periodic_port": 1},
        "DET-EXFIL": {"backup_server": 1},
    }
    assert report.suppressed_total == 4


def test_the_same_evidence_always_yields_byte_identical_output(tables: Any) -> None:
    assert detect(tables, ctx()).model_dump_json() == detect(tables, ctx()).model_dump_json()


def test_an_empty_capture_produces_an_empty_report(tmp_path: Path) -> None:
    write_zeek_logs(tmp_path / "zeek", {})
    empty, _ = normalise_logs(tmp_path / "zeek", tmp_path / "tables")
    report = detect(empty, ctx())
    assert report.findings == [] and report.suppressed_total == 0
