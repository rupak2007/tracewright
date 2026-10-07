"""DET-DNSTUN. All inputs are SYNTHETIC evidence tables (tests/detect_helpers.py), never captures."""

import base64
import hashlib
from typing import Any

import pytest

from app.detect.base import DetectorOutput
from app.detect.dns_tunnel import DETECTOR, is_allowlisted, shannon_entropy, split_name
from tests.detect_helpers import T0, context, detector_input, frame, tables

CLIENT = "10.0.0.5"
DOMAIN = "example.com"


def b32(i: int, length: int) -> str:
    """Deterministic pseudo-random label (high entropy) of the given length."""
    digest = hashlib.sha256(f"label-{i}".encode()).digest()
    return base64.b32encode(digest).decode().lower().rstrip("=")[:length]


def queries(
    names: list[str], *, qtype: str = "A", rcode: str = "NOERROR", spacing: float = 0.5
) -> list[dict[str, Any]]:
    return [
        {
            "ts": T0 + i * spacing,
            "uid": f"D-{i}",
            "orig_h": CLIENT,
            "resp_h": "10.0.0.53",
            "query": name,
            "qtype_name": qtype,
            "rcode_name": rcode,
        }
        for i, name in enumerate(names)
    ]


def run(rows: list[dict[str, Any]], **kw: Any) -> DetectorOutput:
    return DETECTOR.run(detector_input(tables(dns=frame("dns", rows)), **kw))


def tunnel_names(n: int, length: int = 40) -> list[str]:
    return [f"{b32(i, length)}.{DOMAIN}" for i in range(n)]


def test_identity() -> None:
    assert (DETECTOR.detector_id, DETECTOR.version) == ("DET-DNSTUN", "1.0.0")


# ---- helpers on known strings -----------------------------------------------------------
def test_shannon_entropy_on_known_strings() -> None:
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaaaaaa") == 0.0
    assert shannon_entropy("ab") == pytest.approx(1.0)
    assert shannon_entropy("abcd") == pytest.approx(2.0)
    assert shannon_entropy("abcdefghijklmnop") == pytest.approx(4.0)
    assert shannon_entropy("aabb") == pytest.approx(1.0)


def test_registered_domain_uses_the_bundled_suffix_list_and_falls_back_for_unknown_suffixes() -> (
    None
):
    assert split_name("a.b.example.co.uk") == ("example.co.uk", "a.b")
    assert split_name("www.example.com") == ("example.com", "www")
    assert split_name("example.com") == ("example.com", "")
    assert split_name("x.y.corp.test") == ("corp.test", "x.y")  # unknown suffix: last two labels
    assert split_name("localhost") == ("localhost", "")


def test_allowlist_matches_the_domain_or_a_parent_entry_only() -> None:
    assert is_allowlisted("example.com", ["example.com"])
    assert is_allowlisted("cdn.example.com", ["EXAMPLE.com"])
    assert not is_allowlisted("badexample.com", ["example.com"])
    assert not is_allowlisted("example.com", ["cdn.example.com"])


# ---- rule A -----------------------------------------------------------------------------
def test_high_entropy_long_subdomains_fire_with_high_confidence() -> None:
    [f] = run(queries(tunnel_names(50))).findings
    assert (f.type, f.primary_entity, f.secondary_entities) == ("DNSTUN", CLIENT, [DOMAIN])
    assert f.confidence == "high" and f.severity_base == 4.0
    m = f.metrics
    assert m["rule"] == "subdomain_volume" and m["unique_subdomains"] == 50
    assert m["mean_label_entropy"] >= 3.5 and m["mean_subdomain_len"] == 40  # type: ignore[operator]
    assert m["query_count"] == 50 and m["name_bytes_total"] == 50 * (40 + 1 + len(DOMAIN))
    assert f.thresholds["min_unique_subdomains"] == 50 and f.evidence_count == 50


def test_forty_nine_unique_subdomains_is_silent() -> None:
    assert run(queries(tunnel_names(49))).findings == []


def test_repeated_names_are_not_unique_subdomains() -> None:
    assert run(queries(tunnel_names(49) * 4)).findings == []


def test_entropy_alone_is_medium_confidence() -> None:
    names = [f"{b32(i, 20)}.{DOMAIN}" for i in range(50)]  # entropy high, length 20 < 30
    [f] = run(queries(names)).findings
    assert f.confidence == "medium"
    assert f.metrics["mean_subdomain_len"] == 20 and f.metrics["mean_label_entropy"] >= 3.5  # type: ignore[operator]


def test_length_alone_is_medium_confidence() -> None:
    names = [f"{'ab' * 15}{i:03d}.{DOMAIN}" for i in range(50)]  # long, low entropy
    [f] = run(queries(names)).findings
    assert f.confidence == "medium"
    assert f.metrics["mean_subdomain_len"] == 33 and f.metrics["mean_label_entropy"] < 3.5  # type: ignore[operator]


def test_many_short_low_entropy_names_look_like_a_cdn_and_stay_silent() -> None:
    assert run(queries([f"img{i}.cdn.{DOMAIN}" for i in range(200)])).findings == []


def test_boundary_of_the_subdomain_length_criterion() -> None:
    def names(length: int) -> list[str]:
        return [f"{'ab' * 20}"[: length - 3] + f"{i:03d}.{DOMAIN}" for i in range(50)]

    assert len(run(queries(names(30))).findings) == 1  # mean length exactly 30
    assert run(queries(names(29))).findings == []


# ---- rule B -----------------------------------------------------------------------------
def test_txt_heavy_traffic_fires_at_thirty_queries() -> None:
    [f] = run(queries([f"c2.{DOMAIN}"] * 30, qtype="TXT")).findings
    assert f.metrics["rule"] == "txt_null_share" and f.metrics["txt_null_share"] == 1.0
    assert f.confidence == "medium" and f.metrics["unique_subdomains"] == 1


def test_txt_rule_boundaries() -> None:
    assert run(queries([f"c2.{DOMAIN}"] * 29, qtype="TXT")).findings == []
    half = queries([f"c2.{DOMAIN}"] * 30, qtype="TXT") + queries([f"c2.{DOMAIN}"] * 30)
    assert len(run(half).findings) == 1  # share exactly 0.5
    below = queries([f"c2.{DOMAIN}"] * 29, qtype="NULL") + queries([f"c2.{DOMAIN}"] * 31)
    assert run(below).findings == []  # 29/60 < 0.5
    assert len(run(queries([f"c2.{DOMAIN}"] * 30, qtype="null")).findings) == 1


def test_nxdomain_rate_is_reported() -> None:
    rows = queries(tunnel_names(50))
    for i, row in enumerate(rows):
        row["rcode_name"] = "NXDOMAIN" if i < 25 else "NOERROR"
    [f] = run(rows).findings
    assert f.metrics["nxdomain_rate"] == 0.5


# ---- suppression, grouping, robustness --------------------------------------------------
def test_allowlisted_domain_is_suppressed_but_counted() -> None:
    out = run(queries(tunnel_names(50)), network=context(allowlist={"domains": [DOMAIN]}))
    assert out.findings == [] and out.suppressed == {"allowlisted_domain": 1}


def test_units_are_per_client_and_per_registered_domain() -> None:
    a = queries(tunnel_names(30))
    other = [
        {**r, "uid": f"X-{i}", "orig_h": "10.0.0.6"}
        for i, r in enumerate(queries(tunnel_names(30)))
    ]
    assert run(a + other).findings == []  # 30 each: neither client reaches 50 alone
    two_domains = queries([f"{b32(i, 40)}.{'a' if i % 2 else 'b'}-tunnel.com" for i in range(60)])
    assert run(two_domains).findings == []  # 30 per domain


def test_names_are_normalised_for_case_and_trailing_dot() -> None:
    names = [f"{b32(i, 40).upper()}.{DOMAIN.upper()}." for i in range(50)]
    [f] = run(queries(names)).findings
    assert f.secondary_entities == [DOMAIN]


def test_missing_values_empty_tables_and_determinism() -> None:
    assert DETECTOR.run(detector_input()).findings == []
    rows = queries(tunnel_names(50))
    rows[0]["query"] = None
    rows[1]["qtype_name"] = None
    rows[2]["rcode_name"] = None
    assert len(run(rows).findings) == 0  # 49 usable unique names
    full = queries(tunnel_names(55))
    a = [f.model_dump() for f in run(full).findings]
    b = [f.model_dump() for f in run(list(reversed(full))).findings]
    assert a == b
