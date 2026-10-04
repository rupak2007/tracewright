from pathlib import Path

import pandas as pd
import pytest

from app.core.errors import ConfigError
from app.profile.context import NetworkContext, load_network_context


def _ctx(**overrides: object) -> NetworkContext:
    data: dict[str, object] = {"internal_cidrs": ["10.0.0.0/8", "192.168.0.0/16", "fd00::/8"]}
    data.update(overrides)
    return NetworkContext.model_validate(data)


@pytest.mark.parametrize(
    ("address", "zone"),
    [
        ("10.1.2.3", "internal"),
        ("192.168.5.5", "internal"),
        ("fd12::1", "internal"),
        ("8.8.8.8", "external"),
        ("172.16.0.1", "external"),  # not in this context's CIDRs
        ("2001:db8::1", "external"),
        ("not-an-ip", "external"),
        ("", "external"),
    ],
)
def test_classify(address: str, zone: str) -> None:
    assert _ctx().classify(address) == zone


def test_classify_series_handles_nulls_and_repeats() -> None:
    series = pd.Series(["10.0.0.1", "8.8.8.8", None, "10.0.0.1"], dtype="object")
    assert _ctx().classify_series(series).tolist() == [
        "internal",
        "external",
        "external",
        "internal",
    ]


def test_shipped_network_yaml_loads(config_dir: Path) -> None:
    ctx = load_network_context(config_dir / "network.yaml")
    assert ctx.classify("192.168.1.1") == "internal" and ctx.classify("1.1.1.1") == "external"
    assert ctx.allowlist.periodic_ports == [123]


@pytest.mark.parametrize(
    "content",
    [
        "internal_cidrs: [not-a-cidr]",
        "internal_cidrs: [10.0.0.0/8]\nknown_hosts: {scanners: [nope]}",
        "internal_cidrs: [10.0.0.0/8]\nunknown_key: 1",
        "just a string",
        "internal_cidrs: [",
    ],
)
def test_invalid_config_rejected(tmp_path: Path, content: str) -> None:
    path = tmp_path / "network.yaml"
    path.write_text(content)
    with pytest.raises(ConfigError):
        load_network_context(path)


def test_missing_config_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        load_network_context(tmp_path / "absent.yaml")
