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


class UploadSink:
    """Incremental upload target: validates while bytes arrive and leaves nothing behind on failure.

    `write` raises IngestError as soon as the file is known to be bad (too large, compressed, wrong
    magic); `abort` removes the partial file; `finish` renames it to its UUID name and returns it.
    """

    def __init__(
        self,
        uploads_dir: Path,
        max_bytes: int,
        min_free_bytes: int = 0,
        original_name: str | None = None,
    ) -> None:
        if shutil.disk_usage(uploads_dir).free < max(min_free_bytes, 0):
            raise IngestError("INSUFFICIENT_DISK", "Not enough free disk space to accept uploads.")
        self._dir = uploads_dir
        self._capture_id = uuid.uuid4()
        self._partial = uploads_dir / f"{self._capture_id}.part"
        self._validator = CaptureValidator(max_bytes)
        self._name = sanitise_original_name(original_name)
        self._out: BinaryIO | None = self._partial.open("xb")

    def _open_file(self) -> BinaryIO:
        if self._out is None:
            raise RuntimeError("the upload is already finished or aborted")
        return self._out

    def write(self, chunk: bytes) -> None:
        out = self._open_file()
        try:
            self._validator.feed(chunk)
            out.write(chunk)
        except BaseException:
            self.abort()
            raise

    def abort(self) -> None:
        if self._out is not None:
            self._out.close()
            self._out = None
        self._partial.unlink(missing_ok=True)

    def finish(self) -> StoredCapture:
        out = self._open_file()
        try:
            info = self._validator.finish()
            out.close()
            self._out = None
            final = self._dir / f"{self._capture_id}.{info.format.value}"
            os.replace(self._partial, final)
        except BaseException:
            self.abort()
            raise
        return StoredCapture(self._capture_id, final, info, self._name)


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
    sink = UploadSink(uploads_dir, max_bytes, min_free_bytes, original_name)
    while chunk := source.read(_CHUNK):
        sink.write(chunk)
    return sink.finish()
