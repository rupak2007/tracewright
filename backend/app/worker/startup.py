"""Worker startup preconditions. Fails fast rather than idling in a broken state."""

import re
import subprocess  # fixed argv, shell=False; never fed capture-derived values
from pathlib import Path

from app.core.config import PipelineSettings, Settings
from app.core.errors import StartupCheckError

_ZEEK_VERSION_RE = re.compile(r"^zeek version (\S+)$")
_PROCESS_TIMEOUT_S = 10


def zeek_version(zeek_bin: str) -> str:
    """Return the version string reported by `zeek --version`."""
    try:
        result = subprocess.run(  # noqa: S603
            [zeek_bin, "--version"],
            capture_output=True,
            text=True,
            timeout=_PROCESS_TIMEOUT_S,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise StartupCheckError(f"cannot run '{zeek_bin} --version': {exc}") from exc
    if result.returncode != 0:
        raise StartupCheckError(
            f"'{zeek_bin} --version' exited {result.returncode}: {result.stderr.strip()}"
        )
    match = _ZEEK_VERSION_RE.match(result.stdout.strip())
    if match is None:
        raise StartupCheckError(f"unrecognised zeek version output: {result.stdout.strip()!r}")
    return match.group(1)


def check_zeek(settings: PipelineSettings) -> str:
    version = zeek_version(settings.zeek_bin)
    expected = settings.zeek_expected_version
    if expected is not None and version != expected:
        raise StartupCheckError(f"zeek version {version} does not match pinned {expected}")
    return version


def check_data_dirs(settings: Settings) -> None:
    for name, path in (("uploads", settings.uploads_dir), ("artifacts", settings.artifacts_dir)):
        if not Path(path).is_dir():
            raise StartupCheckError(f"{name} directory {path} does not exist")
