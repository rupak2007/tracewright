"""Streaming multipart upload (FR-01/02, SEC-01): the file is validated while it arrives.

Starlette's own form parser would spool the whole body to disk before our handler could look at
it. Instead the request body is fed chunk by chunk into a multipart parser whose file part goes
straight into an `UploadSink` (size cap, compression and magic-byte checks, SHA-256). The first
problem aborts the request and removes the partial file. Only a part named `file` is read;
other fields are ignored, and the client filename is kept as sanitised metadata only.
"""

from typing import TYPE_CHECKING, Any, cast

from python_multipart.multipart import MultipartParser, parse_options_header
from starlette.requests import Request

from app.api.errors import ApiError
from app.core.config import Settings
from app.ingest.storage import StoredCapture, UploadSink

if TYPE_CHECKING:  # a typing-only name in python-multipart
    from python_multipart.multipart import MultipartCallbacks

_OVERHEAD = 1024 * 1024  # multipart framing and small form fields allowed on top of the file cap


class _Collector:
    """Callbacks for MultipartParser; fills `stored` from the first `file` part."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.sink: UploadSink | None = None
        self.stored: StoredCapture | None = None
        self._field = b""
        self._value = b""
        self._headers: dict[bytes, bytes] = {}
        self._reading = False

    def callbacks(self) -> dict[str, Any]:
        return {
            "on_part_begin": self._part_begin,
            "on_header_field": self._header_field,
            "on_header_value": self._header_value,
            "on_header_end": self._header_end,
            "on_headers_finished": self._headers_finished,
            "on_part_data": self._part_data,
            "on_part_end": self._part_end,
        }

    def _part_begin(self) -> None:
        self._headers, self._field, self._value, self._reading = {}, b"", b"", False

    def _header_field(self, data: bytes, start: int, end: int) -> None:
        self._field += data[start:end]

    def _header_value(self, data: bytes, start: int, end: int) -> None:
        self._value += data[start:end]

    def _header_end(self) -> None:
        self._headers[self._field.lower()] = self._value
        self._field, self._value = b"", b""

    def _headers_finished(self) -> None:
        _, options = parse_options_header(self._headers.get(b"content-disposition", b""))
        if options.get(b"name") == b"file" and self.stored is None and self.sink is None:
            name = options.get(b"filename", b"").decode("utf-8", errors="replace")
            self.sink = UploadSink(
                self.settings.uploads_dir,
                self.settings.max_upload_bytes,
                self.settings.min_free_disk_bytes,
                name,
            )
            self._reading = True

    def _part_data(self, data: bytes, start: int, end: int) -> None:
        if self._reading and self.sink is not None:
            self.sink.write(data[start:end])

    def _part_end(self) -> None:
        if self._reading and self.sink is not None:
            self.stored = self.sink.finish()
            self.sink, self._reading = None, False

    def abort(self) -> None:
        if self.sink is not None:
            self.sink.abort()
            self.sink = None


async def receive_capture(request: Request, settings: Settings) -> StoredCapture:
    """Read one capture from a multipart/form-data request; raise ApiError/IngestError otherwise."""
    media, options = parse_options_header(request.headers.get("content-type", "").encode())
    boundary = options.get(b"boundary")
    if media != b"multipart/form-data" or not boundary:
        raise ApiError(
            415, "UNSUPPORTED_MEDIA_TYPE", "Upload as multipart/form-data, field 'file'."
        )
    limit = settings.max_upload_bytes + _OVERHEAD
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        raise ApiError(413, "FILE_TOO_LARGE", "The request is larger than the upload limit.")

    collector = _Collector(settings)
    parser = MultipartParser(boundary, cast("MultipartCallbacks", collector.callbacks()))
    received = 0
    try:
        async for chunk in request.stream():
            received += len(chunk)
            if received > limit:
                raise ApiError(413, "FILE_TOO_LARGE", "The request exceeds the upload limit.")
            parser.write(chunk)
        parser.finalize()
    except BaseException:
        collector.abort()
        if collector.stored is not None:  # finished before a later error in the same request
            collector.stored.path.unlink(missing_ok=True)
        raise
    if collector.stored is None:
        raise ApiError(400, "NO_FILE", "The request has no 'file' part.")
    return collector.stored
