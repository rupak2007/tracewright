from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from app.api.main import create_app


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("POSTGRES_DB", "tw")
    monkeypatch.setenv("POSTGRES_USER", "u")
    monkeypatch.setenv("POSTGRES_PASSWORD", "p")


@pytest.fixture
def client_ok(env: None) -> Iterator[TestClient]:
    engine = create_engine("sqlite://", poolclass=StaticPool)
    with TestClient(create_app(engine)) as client:
        yield client


@pytest.fixture
def client_db_down(env: None) -> Iterator[TestClient]:
    # Nothing listens on port 1; connection is refused immediately.
    engine = create_engine(
        "postgresql+psycopg://u:p@127.0.0.1:1/tw", connect_args={"connect_timeout": 2}
    )
    with TestClient(create_app(engine)) as client:
        yield client


def test_health_ok(client_ok: TestClient) -> None:
    response = client_ok.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "db": "ok", "worker": "unknown"}


def test_health_503_when_db_unreachable(client_db_down: TestClient) -> None:
    response = client_db_down.get("/api/v1/health")
    assert response.status_code == 503
    assert response.json() == {
        "error": {"code": "DB_UNAVAILABLE", "message": "Database is unavailable."}
    }


def test_health_is_in_openapi(client_ok: TestClient) -> None:
    assert "/api/v1/health" in client_ok.get("/openapi.json").json()["paths"]
