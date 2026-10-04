import os
import sys
from pathlib import Path

import pytest

from app.core.config import get_pipeline_settings, get_settings

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))  # lab/ and eval/ live at the repo root


@pytest.fixture(autouse=True)
def _clean_settings_cache() -> None:
    get_settings.cache_clear()
    get_pipeline_settings.cache_clear()


@pytest.fixture(scope="session")
def config_dir() -> Path:
    """The real config/ directory (CONFIG_DIR inside the worker test image, repo path otherwise)."""
    return Path(os.environ.get("CONFIG_DIR", REPO_ROOT / "config"))


@pytest.fixture(scope="session")
def fixture_captures(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Fixture captures generated once per session with Scapy (see tests/fixtures)."""
    from tests.fixtures import make_fixtures as mk

    out = tmp_path_factory.mktemp("captures")
    basic = mk.make_basic_pcap(out / "basic.pcap")
    mk.make_basic_pcapng(out / "basic.pcapng")
    mk.make_truncated_pcap(out / "truncated.pcap", basic)
    mk.make_non_pcap(out / "not_a_pcap.bin")
    mk.make_gzip_pcap(out / "basic.pcap.gz", basic)
    mk.make_empty_capture(out / "empty.pcap")
    return out
