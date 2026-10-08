"""Pseudonymisation of hosts and domains before anything reaches an LLM (SEC-04, ADR-005).

IPs become `H<n>` (internal) or `X<n>` (external); domains, TLS names and HTTP Hosts become `D<n>`.
Numbers are assigned in order of first use, so the same incident always yields the same mapping,
which stays on the server and is used only to display a validated narrative. Attacker-controlled
free text never goes through here because it is never collected in the first place.
"""

import ipaddress
from collections.abc import Callable


class Pseudonymiser:
    def __init__(self, is_internal: Callable[[str], bool]) -> None:
        self._is_internal = is_internal
        self._tokens: dict[str, str] = {}
        self._count = {"H": 0, "X": 0, "D": 0}

    def token(self, value: str) -> str:
        """The stable pseudonym of an IP address or a domain-like name."""
        known = self._tokens.get(value)
        if known is not None:
            return known
        try:
            ipaddress.ip_address(value)
            prefix = "H" if self._is_internal(value) else "X"
        except ValueError:
            prefix = "D"
        self._count[prefix] += 1
        pseudonym = f"{prefix}{self._count[prefix]}"
        self._tokens[value] = pseudonym
        return pseudonym

    @property
    def mapping(self) -> dict[str, str]:
        """pseudonym -> real value (server-side only)."""
        return {token: real for real, token in self._tokens.items()}

    @property
    def kinds(self) -> dict[str, str]:
        """pseudonym -> "internal" | "external" | "domain" (safe to send to the model)."""
        names = {"H": "internal", "X": "external", "D": "domain"}
        return {token: names[token[0]] for token in self._tokens.values()}
