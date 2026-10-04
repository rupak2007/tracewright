"""SYNTHETIC fixtures for the external-run tests.

Nothing here is an evaluation capture. The "capture" is a header-only pcap (a structurally valid,
EMPTY file: 24-byte global header, zero packets) used only to exercise file validation and hashing;
the metadata and labels are made up. They never describe real traffic and must never be copied into
lab/runs/.
"""

import json
import struct
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from lab.schema import Episode

T0 = datetime(2026, 11, 2, 10, 0, 0, tzinfo=UTC)
CLIENT_IP = "172.20.0.101"
TARGET_IP = "172.20.0.20"


def empty_pcap_bytes(variant: int = 0) -> bytes:
    """A valid empty pcap; `variant` changes snaplen so different files hash differently."""
    return struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535 - variant, 1)


def valid_submission(run_id: str = "x001", **overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "run_id": run_id,
        "holdout": False,
        "start": "2026-11-02T10:00:00.000Z",
        "end": "2026-11-02T10:10:00.000Z",
        "network_config": "network.lab.yaml",
        "clients": [{"id": "c1", "ip": CLIENT_IP}],
        "scenarios": [{"kind": "attack", "class": "SCAN", "client": "c1", "tool": "synthetic"}],
        "provenance": {
            "supplied_by": "test-author",
            "supplied_at": "2026-11-02T11:00:00.000Z",
            "collection_method": "synthetic metadata for a unit test",
            "tool_versions": {"synthetic": "0"},
            "isolated_environment": True,
            "contains_real_user_data": False,
            "scenario_parameters": {},
            "notes": "",
        },
    }
    base.update(overrides)
    return base


def episode_dict(
    run_id: str = "x001",
    kind: str = "attack",
    cls: str = "SCAN",
    actor: str = CLIENT_IP,
    n: int = 1,
) -> dict[str, Any]:
    e = Episode(
        run_id,
        f"{run_id}-e{n}",
        kind,
        cls,
        actor,
        (TARGET_IP,),
        T0 + timedelta(seconds=60),
        T0 + timedelta(seconds=120),
        "synthetic",
    )
    return e.to_json_dict()


def write_submission_dir(
    base: Path,
    run_id: str = "x001",
    *,
    submission: dict[str, Any] | None = None,
    labels: list[dict[str, Any]] | None = None,
    capture: bytes | None = None,
    capture_name: str = "capture.pcap",
    variant: int = 0,
) -> Path:
    d = base / run_id
    d.mkdir(parents=True)
    (d / "submission.json").write_text(
        json.dumps(submission if submission is not None else valid_submission(run_id)),
        encoding="utf-8",
    )
    rows = labels if labels is not None else [episode_dict(run_id)]
    (d / "labels.jsonl").write_text(
        "".join(json.dumps(r, sort_keys=True) + chr(10) for r in rows), encoding="utf-8"
    )
    (d / capture_name).write_bytes(capture if capture is not None else empty_pcap_bytes(variant))
    return d
