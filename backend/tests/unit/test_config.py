import pytest
from pydantic import ValidationError

from app.core.config import Settings, get_settings

REQUIRED = {
    "POSTGRES_DB": "tw",
    "POSTGRES_USER": "tw_user",
    "POSTGRES_PASSWORD": "s3cret value/with@chars",
}


def _set_env(monkeypatch: pytest.MonkeyPatch, **extra: str) -> None:
    for key, value in {**REQUIRED, **extra}.items():
        monkeypatch.setenv(key, value)


def test_loads_from_env_with_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ZEEK_EXPECTED_VERSION", raising=False)  # set in the worker image
    _set_env(monkeypatch)
    settings = get_settings()
    assert settings.postgres_host == "db"
    assert settings.postgres_port == 5432
    assert settings.environment == "prod"
    assert settings.zeek_expected_version is None


def test_database_url_escapes_password_and_hides_it_in_repr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set_env(monkeypatch)
    settings = get_settings()
    url = settings.database_url
    assert url.drivername == "postgresql+psycopg"
    assert url.password == REQUIRED["POSTGRES_PASSWORD"]
    assert REQUIRED["POSTGRES_PASSWORD"] not in repr(settings)
    assert REQUIRED["POSTGRES_PASSWORD"] not in url.render_as_string(hide_password=True)


def test_missing_required_variable_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in REQUIRED:
        monkeypatch.delenv(key, raising=False)
    with pytest.raises(ValidationError):
        Settings(_env_file=None)  # type: ignore[call-arg]


def test_invalid_port_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_env(monkeypatch, POSTGRES_PORT="70000")
    with pytest.raises(ValidationError):
        Settings(_env_file=None)  # type: ignore[call-arg]
