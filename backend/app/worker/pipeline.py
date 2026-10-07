"""Analysis stages for one capture: validate -> Zeek -> normalise -> profile -> detect (S1-S4).

Runs in the worker only. Writes under `out_dir`:
    zeek/*.log         raw Zeek JSON logs
    tables/*.parquet   normalised tables (all eight, empty ones included)
    logs/              Zeek stderr
    profile.json       capture profile + data-quality warnings (+ suppressed finding counts)
    findings.json      detector findings, thresholds applied, suppression counts (stage S4)
    status.json        lifecycle: running -> completed | failed, with stage, error and timings

status.json mirrors the investigations.status/stage/error columns (architecture §15); the DB-backed
job queue arrives with the jobs table (plan P3/P6).
"""

import json
import logging
import os
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Literal

from pydantic import BaseModel

from app.core.config import PipelineSettings
from app.core.errors import IngestError, StartupCheckError, TracewrightError
from app.core.logging import log_context
from app.detect.base import DetectorInput
from app.detect.config import load_detectors_config
from app.detect.runner import run_detectors
from app.ingest.capinfos import run_capinfos
from app.ingest.normalise import normalise_logs
from app.ingest.validate import validate_file
from app.ingest.zeek import run_zeek
from app.profile.context import load_network_context
from app.profile.profile import CaptureProfile, build_profile
from app.profile.warnings import load_profile_config
from app.worker.startup import check_zeek

logger = logging.getLogger(__name__)

STAGES = ("validate", "zeek_parse", "normalise", "profile", "detect")


class AnalysisStatus(BaseModel):
    status: Literal["running", "completed", "failed"]
    stage: str
    error_code: str | None = None
    error_message: str | None = None
    sha256: str | None = None
    zeek_version: str | None = None
    stage_ms: dict[str, int] = {}


def _write_json_atomic(path: Path, payload: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(payload, encoding="utf-8")
    os.replace(tmp, path)


class _Run:
    def __init__(self, out_dir: Path) -> None:
        self.out_dir = out_dir
        self.status = AnalysisStatus(status="running", stage=STAGES[0])

    def save(self) -> None:
        _write_json_atomic(self.out_dir / "status.json", self.status.model_dump_json(indent=2))

    @contextmanager
    def stage(self, name: str) -> Iterator[None]:
        self.status.stage = name
        self.save()
        started = time.monotonic()
        with log_context(stage=name):
            logger.info("stage started")
            try:
                yield
            finally:
                self.status.stage_ms[name] = int((time.monotonic() - started) * 1000)


def analyze_capture(pcap: Path, out_dir: Path, settings: PipelineSettings) -> AnalysisStatus:
    """Run S1-S4. Configuration problems raise; capture/tool problems end in status 'failed'."""
    config_dir = settings.config_dir
    ctx = load_network_context(config_dir / "network.yaml")
    profile_cfg = load_profile_config(config_dir / "profile.yaml")
    detectors_cfg = load_detectors_config(config_dir / "detectors.yaml")
    site_script = config_dir / "zeek" / "site.zeek"

    if out_dir.exists() and any(out_dir.iterdir()):
        raise IngestError("OUTPUT_DIR_NOT_EMPTY", f"Output directory {out_dir} is not empty.")
    for sub in ("zeek", "tables", "logs"):
        (out_dir / sub).mkdir(parents=True, exist_ok=True)

    run = _Run(out_dir)
    try:
        with run.stage("validate"):
            file_info = validate_file(pcap, settings.max_upload_bytes)
            run.status.sha256 = file_info.sha256
        with run.stage("zeek_parse"):
            try:
                run.status.zeek_version = check_zeek(settings)
            except StartupCheckError as exc:
                raise IngestError("ZEEK_UNAVAILABLE", exc.message) from exc
            run_zeek(
                pcap,
                out_dir / "zeek",
                out_dir / "logs",
                site_script,
                settings.zeek_bin,
                settings.zeek_timeout_s,
            )
        with run.stage("normalise"):
            tables, stats = normalise_logs(out_dir / "zeek", out_dir / "tables")
        with run.stage("profile"):
            cap = run_capinfos(pcap, settings.capinfos_bin, settings.tool_timeout_s)
            profile: CaptureProfile = build_profile(
                file_info,
                cap,
                run.status.zeek_version or "unknown",
                tables,
                stats,
                ctx,
                profile_cfg,
            )
            _write_json_atomic(out_dir / "profile.json", profile.model_dump_json(indent=2))
        with run.stage("detect"):
            report = run_detectors(
                DetectorInput(tables, ctx, detectors_cfg, profile.capture.duration_s),
                investigation_id=f"inv-{(run.status.sha256 or 'local')[:12]}",
            )
            _write_json_atomic(out_dir / "findings.json", report.model_dump_json(indent=2))
            # FR-13: suppressed findings are reported in the capture profile, never dropped silently
            profile = profile.model_copy(update={"suppressed_findings": report.suppressed})
            _write_json_atomic(out_dir / "profile.json", profile.model_dump_json(indent=2))
    except TracewrightError as exc:
        run.status.status = "failed"
        run.status.error_code, run.status.error_message = exc.code, exc.message
        logger.warning("analysis failed: %s", exc.code, extra={})
    except Exception as exc:  # NFR-03: any failure must mark the run failed
        run.status.status = "failed"
        run.status.error_code = "INTERNAL_ERROR"
        run.status.error_message = f"Unexpected {type(exc).__name__} during {run.status.stage}."
        logger.exception("analysis crashed")
    else:
        run.status.status = "completed"
    run.save()
    return run.status


def read_profile(out_dir: Path) -> CaptureProfile:
    return CaptureProfile.model_validate(json.loads((out_dir / "profile.json").read_text("utf-8")))
