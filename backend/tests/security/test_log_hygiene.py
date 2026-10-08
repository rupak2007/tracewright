"""SEC-12: capture-derived strings never reach the logs, even when analysis succeeds or fails.

A fake Zeek writes logs whose DNS names, URIs, user agents and SNI values carry unique canary
strings. The whole pipeline runs under a capture of every log record (and the JSON the real
formatter would print); none of the canaries may appear.
"""

import io
import json
import logging
from pathlib import Path
from typing import Any

import pytest

from app.core.logging import JsonFormatter
from app.worker.pipeline import analyze_capture
from tests.db_helpers import PCAP_HEADER, pipeline_settings
from tests.integration.test_p4_pipeline import storyline_logs

CANARIES = {
    "dns": "canary-dns-name-7f3a.tunnel.example.net",
    "uri": "/canary-uri-9c1e?token=canary-secret-b2d4",
    "ua": "canary-user-agent-5e8f/1.0",
    "sni": "canary-sni-4a6b.example.org",
    "host": "canary-host-header-3d7c.example.com",
}


def hostile_logs() -> dict[str, list[dict[str, Any]]]:
    logs = storyline_logs()
    t = logs["conn"][0]["ts"]
    logs["dns"].append(
        {
            "ts": t,
            "uid": "Cdns1",
            "id.orig_h": "172.20.0.101",
            "id.orig_p": 5353,
            "id.resp_h": "172.20.0.53",
            "id.resp_p": 53,
            "proto": "udp",
            "query": CANARIES["dns"],
            "qtype_name": "A",
            "rcode_name": "NXDOMAIN",
        }
    )
    logs["http"] = [
        {
            "ts": t,
            "uid": "Chttp1",
            "id.orig_h": "172.20.0.101",
            "id.orig_p": 40000,
            "id.resp_h": "172.20.0.20",
            "id.resp_p": 80,
            "method": "GET",
            "host": CANARIES["host"],
            "uri": CANARIES["uri"],
            "user_agent": CANARIES["ua"],
            "status_code": 200,
        }
    ]
    logs["ssl"] = [
        {
            "ts": t,
            "uid": "Cssl1",
            "id.orig_h": "172.20.0.101",
            "id.orig_p": 40001,
            "id.resp_h": "172.20.0.20",
            "id.resp_p": 443,
            "server_name": CANARIES["sni"],
            "established": True,
        }
    ]
    return logs


def run_and_collect(tmp: Path, logs: dict[str, list[dict[str, Any]]]) -> tuple[str, str]:
    capture = tmp / "c.pcap"
    capture.write_bytes(PCAP_HEADER)
    records: list[logging.LogRecord] = []

    class Collect(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    root = logging.getLogger()
    collector, previous = Collect(level=logging.DEBUG), root.level
    root.addHandler(collector)
    root.setLevel(logging.DEBUG)
    try:
        status = analyze_capture(capture, tmp / "out", pipeline_settings(tmp, logs))
    finally:
        root.removeHandler(collector)
        root.setLevel(previous)
    formatter, printed = JsonFormatter(), io.StringIO()
    for record in records:
        printed.write(formatter.format(record) + "\n")
    return printed.getvalue() + json.dumps(
        [r.__dict__.get("args") for r in records], default=str
    ), (status.status)


def test_no_canary_reaches_a_log_record_on_a_successful_analysis(tmp_path: Path) -> None:
    text, status = run_and_collect(tmp_path, hostile_logs())
    assert status == "completed" and len(text) > 200
    for name, canary in CANARIES.items():
        assert canary not in text, name
    assert "canary-secret" not in text


def test_no_canary_reaches_a_log_record_when_the_analysis_fails(tmp_path: Path) -> None:
    logs = hostile_logs()
    logs["conn"] = [{"ts": "not-a-number", "uid": CANARIES["dns"], "id.orig_h": CANARIES["uri"]}]
    text, status = run_and_collect(tmp_path, logs)
    for name, canary in CANARIES.items():
        assert canary not in text, (name, status)


@pytest.mark.parametrize("stage", ["validate", "zeek_parse"])
def test_failure_messages_name_the_stage_not_the_content(tmp_path: Path, stage: str) -> None:
    capture = tmp_path / "bad.pcap"
    capture.write_bytes(b"MZ" + CANARIES["ua"].encode())
    status = analyze_capture(capture, tmp_path / "out", pipeline_settings(tmp_path))
    assert status.status == "failed" and status.error_message
    assert CANARIES["ua"] not in status.error_message
