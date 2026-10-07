"""Run manifest: what produced a result (versions, config hashes, counts).

No timestamps, so two runs over the same capture write byte-identical manifests (NFR-02);
timings live in status.json."""

import hashlib
import os
from pathlib import Path

from pydantic import BaseModel, ConfigDict

CONFIG_FILES = (
    "detectors.yaml",
    "correlation.yaml",
    "attack.yaml",
    "attack_mapping.yaml",
    "network.yaml",
    "profile.yaml",
)


class RunManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tracewright_version: str
    git_commit: str | None
    zeek_version: str
    capture_sha256: str
    attack_version: str
    attack_bundle_sha256: str
    detector_versions: dict[str, str]
    config_sha256: dict[str, str]
    counts: dict[str, int]


def hash_config_file(path: Path) -> str:
    """SHA-256 of the file with line endings normalised, so Windows and Linux checkouts agree."""
    data = path.read_bytes().replace(b"\r\n", b"\n")
    return hashlib.sha256(data).hexdigest()


def config_hashes(config_dir: Path) -> dict[str, str]:
    return {name: hash_config_file(config_dir / name) for name in CONFIG_FILES}


def build_manifest(
    *,
    version: str,
    zeek_version: str,
    capture_sha256: str,
    attack_version: str,
    attack_bundle_sha256: str,
    detector_versions: dict[str, str],
    config_dir: Path,
    counts: dict[str, int],
) -> RunManifest:
    return RunManifest(
        tracewright_version=version,
        git_commit=os.environ.get("GIT_COMMIT") or None,
        zeek_version=zeek_version,
        capture_sha256=capture_sha256,
        attack_version=attack_version,
        attack_bundle_sha256=attack_bundle_sha256,
        detector_versions=detector_versions,
        config_sha256=config_hashes(config_dir),
        counts=counts,
    )
