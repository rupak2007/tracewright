"""Capture file validation by magic bytes and size, with streaming SHA-256 (FR-01..03, SEC-01).

The extension and any client-supplied MIME type are never consulted. Compressed files are rejected
(capinfos, for one, would happily read a .gz, so this gate matters).
"""

import hashlib
import os
import stat
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from app.core.errors import IngestError

_CHUNK = 1024 * 1024
_PCAP_MAGICS = {
    bytes.fromhex("d4c3b2a1"),  # pcap, microsecond, little-endian
    bytes.fromhex("a1b2c3d4"),  # pcap, microsecond, big-endian
    bytes.fromhex("4d3cb2a1"),  # pcap, nanosecond, little-endian
    bytes.fromhex("a1b23c4d"),  # pcap, nanosecond, big-endian
}
_PCAPNG_MAGIC = bytes.fromhex("0a0d0d0a")
_MIN_PCAP_BYTES = 24  # global header
_MIN_PCAPNG_BYTES = 28  # smallest section header block

_COMPRESSION_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"\x1f\x8b", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"\x28\xb5\x2f\xfd", "zstd"),
    (b"PK\x03\x04", "zip"),
)
_MAX_SIGNATURE = max(len(sig) for sig, _ in _COMPRESSION_SIGNATURES)


class CaptureFormat(StrEnum):
    PCAP = "pcap"
    PCAPNG = "pcapng"


@dataclass(frozen=True)
class CaptureFileInfo:
    format: CaptureFormat
    size_bytes: int
    sha256: str


class CaptureValidator:
    """Feed chunks as they stream in; raises IngestError as soon as the file is known bad."""

    def __init__(self, max_bytes: int) -> None:
        self._max_bytes = max_bytes
        self._hash = hashlib.sha256()
        self._size = 0
        self._head = b""
        self._format: CaptureFormat | None = None

    def feed(self, chunk: bytes) -> None:
        self._size += len(chunk)
        if self._size > self._max_bytes:
            raise IngestError(
                "FILE_TOO_LARGE", f"File exceeds the {self._max_bytes}-byte upload limit."
            )
        self._hash.update(chunk)
        if self._format is None:
            self._head += chunk[: _MAX_SIGNATURE - len(self._head)]
            self._sniff()

    def _sniff(self) -> None:
        for signature, name in _COMPRESSION_SIGNATURES:
            if self._head.startswith(signature):
                raise IngestError(
                    "FILE_COMPRESSED",
                    f"Compressed files ({name}) are not accepted; upload the raw capture.",
                )
        if len(self._head) < 4:
            return
        magic = self._head[:4]
        if magic in _PCAP_MAGICS:
            self._format = CaptureFormat.PCAP
        elif magic == _PCAPNG_MAGIC:
            self._format = CaptureFormat.PCAPNG
        elif not any(sig.startswith(self._head) for sig, _ in _COMPRESSION_SIGNATURES):
            raise IngestError("FILE_TYPE_INVALID", "File is not a PCAP or PCAPNG capture.")

    def finish(self) -> CaptureFileInfo:
        if self._size == 0:
            raise IngestError("FILE_EMPTY", "File is empty.")
        if self._format is None:
            raise IngestError("FILE_TYPE_INVALID", "File is not a PCAP or PCAPNG capture.")
        minimum = _MIN_PCAP_BYTES if self._format is CaptureFormat.PCAP else _MIN_PCAPNG_BYTES
        if self._size < minimum:
            raise IngestError("FILE_TYPE_INVALID", "File is too short to be a valid capture.")
        return CaptureFileInfo(self._format, self._size, self._hash.hexdigest())


def validate_file(path: Path, max_bytes: int) -> CaptureFileInfo:
    """Validate a capture already on disk, streaming it once (hash + size + magic)."""
    try:
        mode = os.stat(path).st_mode
    except OSError as exc:
        raise IngestError("FILE_NOT_FOUND", f"Cannot read file: {type(exc).__name__}.") from exc
    if not stat.S_ISREG(mode):
        raise IngestError("FILE_TYPE_INVALID", "Path is not a regular file.")
    validator = CaptureValidator(max_bytes)
    with path.open("rb") as handle:
        while chunk := handle.read(_CHUNK):
            validator.feed(chunk)
    return validator.finish()
