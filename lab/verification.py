"""Verification record (`verification.json`): proof that a run's labels were checked against its
analysed capture, bound to the exact files that were checked. Standard library only.

A run is eligible for a dev/test split only when its record says `passed`, and the record's hashes
still equal the current `run.json`, `labels.jsonl` and declared capture hash. Editing any of them
after verification makes the run ineligible again, so labels cannot be quietly changed to fit.
"""

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

from lab.runmeta import RunMeta
from lab.schema import format_time

VERIFICATION_VERSION = 1
FILE_NAME = "verification.json"


def sha256_file(path: Path) -> str:
    """SHA-256 of a file, or '' when it does not exist (a run may have no labels file)."""
    if not path.exists():
        return ""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True)
class Verification:
    run_id: str
    passed: bool
    problems: tuple[str, ...]
    capture_sha256: str
    run_json_sha256: str
    labels_sha256: str
    analysis_zeek_version: str
    analysis_connections: int
    verified_at: str
    schema_version: int = VERIFICATION_VERSION

    def to_json(self) -> str:
        data = asdict(self)
        data["problems"] = list(self.problems)
        return json.dumps(data, indent=2, sort_keys=True) + "\n"


def now_stamp() -> str:
    return format_time(datetime.now(UTC))


def load_verification(run_dir: Path) -> Verification | None:
    path = run_dir / FILE_NAME
    if not path.exists():
        return None
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        raw["problems"] = tuple(raw.get("problems", ()))
        return Verification(**raw)
    except (ValueError, TypeError):
        return None


def eligibility(run_dir: Path, meta: RunMeta) -> tuple[bool, str]:
    """(eligible, reason). Reason is 'verified' or says exactly why the run is not eligible."""
    record = load_verification(run_dir)
    if record is None:
        return False, "not verified (no valid verification.json)"
    if record.schema_version != VERIFICATION_VERSION or record.run_id != meta.run_id:
        return False, "verification record does not belong to this run"
    if not record.passed:
        return False, f"verification failed ({len(record.problems)} problem(s))"
    if record.capture_sha256 != meta.capture_sha256:
        return False, "declared capture hash changed after verification"
    if record.run_json_sha256 != sha256_file(run_dir / "run.json"):
        return False, "run.json changed after verification"
    if record.labels_sha256 != sha256_file(run_dir / "labels.jsonl"):
        return False, "labels.jsonl changed after verification"
    return True, "verified"
