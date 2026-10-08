"""The committed OpenAPI file (input of the generated frontend types) matches the live API.

Regression for a release-audit finding: API changes after the last export left
frontend/openapi.json stale, which only CI's export check would have caught.
"""

import json
from pathlib import Path

import pytest

from app.api.main import create_app

OPENAPI = Path(__file__).resolve().parents[3] / "frontend" / "openapi.json"


def test_frontend_openapi_matches_the_live_schema(monkeypatch: pytest.MonkeyPatch) -> None:
    if not OPENAPI.exists():
        pytest.skip("frontend/openapi.json not available")
    for key in ("POSTGRES_DB", "POSTGRES_USER", "POSTGRES_PASSWORD"):
        monkeypatch.setenv(key, "x")
    live = json.dumps(create_app().openapi(), indent=2, sort_keys=True) + "\n"
    assert OPENAPI.read_text(encoding="utf-8").replace("\r\n", "\n") == live, (
        "run: python scripts/export_openapi.py && (cd frontend && npm run gen:api)"
    )
