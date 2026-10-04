"""Structured JSON logging with investigation_id / job_id / stage context (architecture §22).

Never log payloads, credentials, or evidence dumps: callers pass identifiers and counts only.
"""

import json
import logging
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any

_CONTEXT_KEYS = ("investigation_id", "job_id", "stage")
_EXTRA_KEYS = ("duration_ms",)
_context: ContextVar[dict[str, Any] | None] = ContextVar("log_context", default=None)


@contextmanager
def log_context(**fields: Any) -> Iterator[None]:
    """Bind context fields (e.g. stage="zeek_parse") to every record logged inside the block."""
    unknown = set(fields) - set(_CONTEXT_KEYS)
    if unknown:
        raise ValueError(f"unknown log context keys: {sorted(unknown)}")
    token = _context.set({**(_context.get() or {}), **fields})
    try:
        yield
    finally:
        _context.reset(token)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "event": record.getMessage(),
        }
        payload.update(_context.get() or {})
        for key in _EXTRA_KEYS:
            if key in record.__dict__:
                payload[key] = record.__dict__[key]
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
