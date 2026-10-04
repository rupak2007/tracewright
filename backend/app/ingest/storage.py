"""Safe storage of an uploaded capture under a server-generated UUID name (SEC-01, FR-03).

The client-supplied filename never touches a path: it is returned only as sanitised metadata.
The API (P6) calls store_upload; the original is never modified afterwards.
"""

import os
import shutil
import unicodedata
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from app.core.errors import IngestError
from app.ingest.validate import CaptureFileInfo, CaptureValidator

_CHUNK = 1024 * 1024
_MAX_NAME_CHARS = 255


@dataclass(frozen=True)
class StoredCapture:
    capture_id: uuid.UUID
    path: Path
    info: CaptureFileInfo
    original_name: str  # metadata only; escape on output


def sanitise_original_name(name: str | None) -> str:
    """Drop control/format characters and directory parts; keep a bounded display string."""
    if not name:
        return ""
    base = name.replace("\\", "/").rsplit("/", 1)[-1]
    cleaned = "".join(ch for ch in base if unicodedata.category(ch)[0] != "C")
    return cleaned[:_MAX_NAME_CHARS]


def store_upload(
    source: BinaryIO,
    uploads_dir: Path,
    max_bytes: int,
    min_free_bytes: int = 0,
    original_name: str | None = None,
) -> StoredCapture:
    """Stream `source` into uploads_dir/<uuid>.pcap|.pcapng, validating while streaming.

    On any failure the partial file is removed and nothing is left behind.
    """
    if shutil.disk_usage(uploads_dir).free < max(min_free_bytes, 0):
        raise IngestError("INSUFFICIENT_DISK", "Not enough free disk space to accept uploads.")
    capture_id = uuid.uuid4()
    partial = uploads_dir / f"{capture_id}.part"
    validator = CaptureValidator(max_bytes)
    try:
        with partial.open("xb") as out:
            while chunk := source.read(_CHUNK):
                validator.feed(chunk)
                out.write(chunk)
        info = validator.finish()
        final = uploads_dir / f"{capture_id}.{info.format.value}"
        os.replace(partial, final)
    except BaseException:
        partial.unlink(missing_ok=True)
        raise
    return StoredCapture(capture_id, final, info, sanitise_original_name(original_name))
