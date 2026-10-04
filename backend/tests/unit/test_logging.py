import json
import logging

import pytest

from app.core.logging import JsonFormatter, log_context


def _format(message: str, **extra: object) -> dict[str, object]:
    record = logging.LogRecord("t", logging.INFO, __file__, 1, message, None, None)
    record.__dict__.update(extra)
    parsed: dict[str, object] = json.loads(JsonFormatter().format(record))
    return parsed


def test_basic_fields() -> None:
    out = _format("hello")
    assert out["event"] == "hello"
    assert out["level"] == "INFO"
    assert "ts" in out


def test_context_is_bound_and_released() -> None:
    with log_context(investigation_id="inv-1", stage="zeek_parse"):
        inside = _format("x")
        with log_context(job_id="job-9"):
            nested = _format("y")
    outside = _format("z")
    assert inside["investigation_id"] == "inv-1" and inside["stage"] == "zeek_parse"
    assert nested["job_id"] == "job-9" and nested["investigation_id"] == "inv-1"
    assert "investigation_id" not in outside


def test_duration_extra_is_included_but_arbitrary_extras_are_not() -> None:
    out = _format("x", duration_ms=12, payload="secret bytes")
    assert out["duration_ms"] == 12
    assert "payload" not in out


def test_unknown_context_key_rejected() -> None:
    bad_fields = {"secret": "x"}
    with pytest.raises(ValueError, match="unknown log context keys"), log_context(**bad_fields):
        pass
