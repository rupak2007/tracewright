"""Network context from config/network.yaml: internal/external classification (FR-07)."""

import ipaddress
from functools import cache
from pathlib import Path
from typing import Literal

import pandas as pd
import yaml
from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

from app.core.errors import ConfigError

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
Zone = Literal["internal", "external"]


class KnownHosts(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scanners: list[str] = []
    resolvers: list[str] = []
    backup_servers: list[str] = []

    @field_validator("scanners", "resolvers", "backup_servers")
    @classmethod
    def _valid_ips(cls, values: list[str]) -> list[str]:
        for value in values:
            ipaddress.ip_address(value)
        return values


class Allowlist(BaseModel):
    model_config = ConfigDict(extra="forbid")

    domains: list[str] = []
    periodic_ports: list[int] = []


class NetworkContext(BaseModel):
    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    internal_cidrs: list[IPNetwork]
    known_hosts: KnownHosts = KnownHosts()
    allowlist: Allowlist = Allowlist()

    @field_validator("internal_cidrs", mode="before")
    @classmethod
    def _parse_cidrs(cls, values: list[str]) -> list[IPNetwork]:
        return [ipaddress.ip_network(v, strict=False) for v in values]

    def classify(self, address: str) -> Zone:
        """Zeek addr fields are always valid IPs; anything unparseable is treated as external."""
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return "external"
        return "internal" if any(ip in net for net in self.internal_cidrs) else "external"

    def classify_series(self, addresses: "pd.Series[str]") -> "pd.Series[str]":
        """Classify a column of IP strings (each distinct value is parsed once)."""
        lookup = cache(self.classify)
        return addresses.map(lambda a: lookup(a) if isinstance(a, str) else "external")


def load_network_context(path: Path) -> NetworkContext:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        return NetworkContext.model_validate(raw)
    except (OSError, yaml.YAMLError, ValidationError, ValueError, TypeError) as exc:
        raise ConfigError(f"Invalid network context {path.name}: {exc}") from exc
