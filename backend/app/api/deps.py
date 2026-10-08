"""Request dependencies: a database session per request and optional bearer-token auth (SEC-07)."""

import hmac
from collections.abc import Iterator
from typing import Annotated

from fastapi import Depends, Header, Request
from sqlalchemy.orm import Session

from app.api.errors import ApiError
from app.core.config import ApiSettings, Settings, get_api_settings, get_settings


def get_session(request: Request) -> Iterator[Session]:
    with Session(request.app.state.engine) as session:
        yield session


def settings_dep() -> Settings:
    return get_settings()


def api_settings_dep() -> ApiSettings:
    return get_api_settings()


SessionDep = Annotated[Session, Depends(get_session)]
SettingsDep = Annotated[Settings, Depends(settings_dep)]
ApiSettingsDep = Annotated[ApiSettings, Depends(api_settings_dep)]


def require_token(
    settings: ApiSettingsDep, authorization: Annotated[str | None, Header()] = None
) -> None:
    """With API_TOKEN set every route except /health needs `Authorization: Bearer <token>`."""
    if settings.api_token is None:
        return
    expected = settings.api_token.get_secret_value()
    scheme, _, supplied = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(supplied.strip(), expected):
        raise ApiError(401, "UNAUTHORIZED", "A valid bearer token is required.")


AuthDep = Depends(require_token)
