import pytest

from app.core.config import get_settings


@pytest.fixture(autouse=True)
def _clean_settings_cache() -> None:
    get_settings.cache_clear()
