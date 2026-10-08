"""Build a BPF filter for a finding's packet slice (architecture §16, plan P6). Pure.

The filter is made only from validated IP addresses and integer ports taken from the Zeek connection
table, never from capture-derived strings, and is handed to tcpdump as ONE argv element
(shell=False). Up to `MAX_FLOWS` distinct flows are listed individually (protocol, both
addresses, both ports); beyond that the filter falls back to the unique host pairs; beyond
`MAX_HOST_PAIRS` the slice is refused as too broad (slice a narrower finding or use the Zeek logs).
"""

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass

MAX_FLOWS = 50
MAX_HOST_PAIRS = 200
PROTOCOLS = {"tcp": "tcp", "udp": "udp", "icmp": "icmp"}


class SliceTooBroad(ValueError):
    """The finding touches too many hosts for a useful slice."""


@dataclass(frozen=True)
class Flow:
    proto: str
    src: str
    src_port: int | None
    dst: str
    dst_port: int | None


def _ip(value: str) -> str:
    return str(ipaddress.ip_address(value))  # ValueError for anything that is not an address


def _port(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if 0 <= value <= 65535 else None


def normalise_flows(rows: Iterable[tuple[str, str, object, str, object]]) -> list[Flow]:
    """(proto, src, src_port, dst, dst_port) rows -> unique, validated, sorted flows."""
    flows: set[Flow] = set()
    for proto, src, sport, dst, dport in rows:
        try:
            flows.add(Flow(str(proto), _ip(src), _port(sport), _ip(dst), _port(dport)))
        except ValueError:
            continue  # an unparseable address cannot be put in a filter; it is simply not sliced
    return sorted(flows, key=lambda f: (f.src, f.dst, f.proto, f.src_port or 0, f.dst_port or 0))


def _flow_expr(f: Flow) -> str:
    parts = []
    proto = PROTOCOLS.get(f.proto)
    if proto:
        parts.append(proto)
    parts.append(f"host {f.src} and host {f.dst}")
    if proto in ("tcp", "udp"):
        if f.src_port is not None:
            parts.append(f"port {f.src_port}")
        if f.dst_port is not None:
            parts.append(f"port {f.dst_port}")
    return "(" + " and ".join(parts) + ")"


def build_bpf(flows: list[Flow]) -> str:
    """Per-flow filter, or host pairs above MAX_FLOWS; SliceTooBroad when even that is large."""
    if not flows:
        raise SliceTooBroad("the finding has no connection evidence to slice")
    if len(flows) <= MAX_FLOWS:
        return " or ".join(_flow_expr(f) for f in flows)
    pairs = sorted({tuple(sorted((f.src, f.dst))) for f in flows})
    if len(pairs) > MAX_HOST_PAIRS:
        raise SliceTooBroad(f"{len(pairs)} host pairs: the finding is too broad for a packet slice")
    return " or ".join(f"(host {a} and host {b})" for a, b in pairs)
