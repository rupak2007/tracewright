"""Analysis stages for one capture: validate -> Zeek -> normalise -> profile -> detect (S1-S4).

Runs in the worker only. Writes under `out_dir`:
    zeek/*.log         raw Zeek JSON logs
    tables/*.parquet   normalised tables (all eight, empty ones included)
    logs/              Zeek stderr
    profile.json       capture profile + data-quality warnings (+ suppressed finding counts)
    findings.json      detector findings (+ promoted anomalies), thresholds, suppressed counts
    anomalies.json     anomaly-triage outcome: status, scorer, top scored windows, promoted findings
    incidents.json     ranked incidents, links, ATT&CK refs, evidence IDs, summaries (S6-S8)
    report.md          Markdown report with evidence IDs
    manifest.json      versions, config hashes and counts that produced the result
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
from importlib import metadata
from pathlib import Path
from typing import Literal

from pydantic import BaseModel

from app.anomaly.triage import anomaly_summary, anomaly_warnings, triage
from app.core.config import PipelineSettings
from app.core.errors import IngestError, StartupCheckError, TracewrightError
from app.core.logging import log_context
from app.correlate.runner import correlate
from app.detect.base import DetectorInput
from app.detect.runner import extend_report, run_detectors
from app.ingest.capinfos import run_capinfos
from app.ingest.normalise import normalise_logs
from app.ingest.validate import validate_file
from app.ingest.zeek import run_zeek
from app.profile.profile import CaptureProfile, build_profile
from app.report.assemble import assemble_analysis
from app.report.model import AnalysisOutput
from app.report.render import render_markdown
from app.worker.analysis_config import load_analysis_config
from app.worker.manifest import build_manifest
from app.worker.startup import check_zeek

logger = logging.getLogger(__name__)

STAGES = (
    "validate",
    "zeek_parse",
    "normalise",
    "profile",
    "detect",
    "anomaly",
    "correlate",
    "explain",
)


class AnalysisStatus(BaseModel):
    status: Literal["running", "completed", "failed"]
    stage: str
    error_code: str | None = None
    error_message: str | None = None
    sha256: str | None = None
    zeek_version: str | None = None
    stage_ms: dict[str, int] = {}


def _package_version() -> str:
    try:
        return metadata.version("tracewright")
    except metadata.PackageNotFoundError:
        return "0+unknown"


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
    acfg = load_analysis_config(settings)
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
                acfg.network,
                acfg.profile,
            )
            _write_json_atomic(out_dir / "profile.json", profile.model_dump_json(indent=2))
        with run.stage("detect"):
            report = run_detectors(
                DetectorInput(tables, acfg.network, acfg.detectors, profile.capture.duration_s),
                investigation_id=f"inv-{(run.status.sha256 or 'local')[:12]}",
            )
        with run.stage("anomaly"):
            triaged = triage(
                tables,
                acfg.network,
                report.findings,
                acfg.anomaly,
                settings.anomaly_scorer,
                severity_base=acfg.detectors.common.severity_base["UNEXPLAINED_ANOMALY"],
            )
            report = extend_report(
                report, triaged.promoted, {"ANOMALY-TRIAGE": "1.0.0"} if triaged.promoted else {}
            )
            _write_json_atomic(out_dir / "findings.json", report.model_dump_json(indent=2))
            _write_json_atomic(
                out_dir / "anomalies.json",
                json.dumps(anomaly_summary(triaged, report, acfg.anomaly), indent=2),
            )
            # FR-13: suppressed findings are reported in the capture profile, never dropped silently
            profile = profile.model_copy(
                update={
                    "suppressed_findings": report.suppressed,
                    "warnings": [*profile.warnings, *anomaly_warnings(triaged)],
                }
            )
            _write_json_atomic(out_dir / "profile.json", profile.model_dump_json(indent=2))
        with run.stage("correlate"):
            correlation = correlate(report.findings, acfg.correlation)
        with run.stage("explain"):
            analysis = assemble_analysis(
                investigation_id=report.investigation_id,
                capture_sha256=run.status.sha256 or "",
                report=report,
                correlation=correlation,
                tables=tables,
                mapping=acfg.mapping,
                cards=acfg.cards,
                playbooks=acfg.playbooks,
            )
            _write_json_atomic(out_dir / "incidents.json", analysis.model_dump_json(indent=2))
            (out_dir / "report.md").write_text(
                render_markdown(analysis, profile), encoding="utf-8", newline="\n"
            )
            manifest = build_manifest(
                version=_package_version(),
                zeek_version=run.status.zeek_version or "unknown",
                capture_sha256=run.status.sha256 or "",
                attack_version=acfg.pins.attack_version,
                attack_bundle_sha256=acfg.pins.bundle_sha256,
                detector_versions=report.detector_versions,
                config_dir=config_dir,
                counts={
                    "findings": len(report.findings),
                    "incidents": len(analysis.incidents),
                    "links": len(analysis.links),
                    "suppressed_findings": report.suppressed_total,
                },
            )
            _write_json_atomic(out_dir / "manifest.json", manifest.model_dump_json(indent=2))
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


def read_analysis(out_dir: Path) -> AnalysisOutput:
    return AnalysisOutput.model_validate(
        json.loads((out_dir / "incidents.json").read_text("utf-8"))
    )


def read_profile(out_dir: Path) -> CaptureProfile:
    return CaptureProfile.model_validate(json.loads((out_dir / "profile.json").read_text("utf-8")))
