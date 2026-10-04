"""`tracewright` command line. P1 provides `analyze` (stages S1-S3); detectors arrive in P3."""

import argparse
import json
import logging
import sys
from collections.abc import Sequence
from pathlib import Path

from app.core.config import get_pipeline_settings
from app.core.errors import TracewrightError
from app.core.logging import configure_logging
from app.worker.pipeline import analyze_capture, read_profile

EXIT_OK, EXIT_ANALYSIS_FAILED, EXIT_USAGE = 0, 1, 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tracewright", description="Offline PCAP investigation.")
    sub = parser.add_subparsers(dest="command", required=True)
    analyze = sub.add_parser("analyze", help="validate, parse with Zeek, normalise and profile")
    analyze.add_argument("pcap", type=Path, help="capture file (PCAP or PCAPNG)")
    analyze.add_argument("--out", type=Path, required=True, help="empty or new output directory")
    analyze.add_argument("--config-dir", type=Path, help="override CONFIG_DIR")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    settings = get_pipeline_settings()
    if args.config_dir is not None:
        settings = settings.model_copy(update={"config_dir": args.config_dir})
    configure_logging(settings.log_level, stream=sys.stderr)  # stdout carries the result JSON
    try:
        status = analyze_capture(args.pcap, args.out, settings)
    except TracewrightError as exc:
        logging.getLogger("app.cli").error("%s: %s", exc.code, exc.message)
        print(json.dumps({"status": "error", "code": exc.code, "message": exc.message}))
        return EXIT_USAGE
    summary: dict[str, object] = {"status": status.status, "stage": status.stage}
    if status.status == "completed":
        profile = read_profile(args.out)
        summary["connections"] = profile.connections
        summary["warnings"] = [w.code for w in profile.warnings]
    else:
        summary["error"] = {"code": status.error_code, "message": status.error_message}
    print(json.dumps(summary))
    return EXIT_OK if status.status == "completed" else EXIT_ANALYSIS_FAILED


if __name__ == "__main__":
    raise SystemExit(main())
