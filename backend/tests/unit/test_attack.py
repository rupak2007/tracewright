"""ATT&CK loader, cards and mapping. The synthetic bundle below is a tiny hand-made STIX-shaped
fixture; the real pinned bundle is only used by the tests that skip when it is not downloaded."""

import json
from pathlib import Path
from typing import Any

import pytest

from app.attack.cards import CardIndex, CardIndexEntry, load_cards, load_index, write_cards
from app.attack.mapping import (
    load_mapping,
    mapped_ids,
    techniques_for,
    validate_mapping,
)
from app.attack.stix import (
    AttackBundle,
    clean_text,
    load_bundle,
    load_pins,
    parse_bundle,
    sha256_file,
)
from app.core.errors import ConfigError
from tests.detect_helpers import finding

REPO = Path(__file__).resolve().parents[3]
PINS = load_pins(REPO / "config" / "attack.yaml")
MAPPING = load_mapping(REPO / "config" / "attack_mapping.yaml")
CARDS_DIR = REPO / "knowledge" / "cards" / PINS.attack_version


def attack_pattern(tid: str, name: str, **extra: Any) -> dict[str, Any]:
    return {
        "type": "attack-pattern",
        "id": f"attack-pattern--{tid}",
        "name": name,
        "description": f"{name} text (Citation: Foo 2020) with [a link](https://x.test/y).",
        "external_references": [
            {
                "source_name": "mitre-attack",
                "external_id": tid,
                "url": f"https://attack.mitre.org/techniques/{tid}",
            }
        ],
        "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "discovery"}],
        **extra,
    }


def synthetic_raw() -> dict[str, Any]:
    return {
        "objects": [
            {"type": "x-mitre-collection", "x_mitre_version": "9.9"},
            attack_pattern("T0001", "Alpha"),
            attack_pattern("T0002", "Bravo", revoked=True),
            attack_pattern("T0003", "Charlie", x_mitre_deprecated=True),
            {"type": "attack-pattern", "id": "attack-pattern--noext", "name": "No external id"},
            {"type": "course-of-action", "id": "course-of-action--m1", "name": "Mitigation One"},
            {
                "type": "course-of-action",
                "id": "course-of-action--m2",
                "name": "Dead",
                "revoked": True,
            },
            {
                "type": "relationship",
                "relationship_type": "mitigates",
                "source_ref": "course-of-action--m1",
                "target_ref": "attack-pattern--T0001",
            },
            {
                "type": "relationship",
                "relationship_type": "mitigates",
                "source_ref": "course-of-action--m2",
                "target_ref": "attack-pattern--T0001",
            },
            {
                "type": "relationship",
                "relationship_type": "uses",
                "source_ref": "course-of-action--m1",
                "target_ref": "attack-pattern--T0001",
            },
        ]
    }


def test_clean_text_strips_citations_links_and_tags_and_trims_at_a_sentence() -> None:
    assert clean_text("A (Citation: X 1) [link](http://a) <code>b</code>\n  c") == "A link b c"
    long = "One sentence. " * 100
    out = clean_text(long, limit=100)
    assert out.endswith("sentence.") and len(out) <= 100
    assert clean_text("x" * 50, limit=10) == "x" * 10 + "..."


def test_parse_bundle_extracts_techniques_status_and_live_mitigations() -> None:
    bundle = parse_bundle(synthetic_raw(), "abc")
    assert bundle.version == "9.9" and set(bundle.techniques) == {"T0001", "T0002", "T0003"}
    a = bundle.techniques["T0001"]
    assert a.description == "Alpha text with a link." and a.tactics == ["discovery"]
    assert a.mitigations == ["Mitigation One"]  # revoked and non-mitigates relations are ignored
    assert bundle.techniques["T0002"].revoked and bundle.techniques["T0003"].deprecated


def test_load_bundle_verifies_the_pinned_checksum(tmp_path: Path) -> None:
    path = tmp_path / "b.json"
    path.write_text(json.dumps(synthetic_raw()), encoding="utf-8")
    assert load_bundle(path, sha256_file(path)).version == "9.9"
    with pytest.raises(ConfigError, match="checksum mismatch"):
        load_bundle(path, "0" * 64)
    with pytest.raises(ConfigError, match="not found"):
        load_bundle(tmp_path / "missing.json", "0" * 64)
    path.write_text("not json", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_bundle(path, sha256_file(path))


def test_cards_round_trip_and_are_byte_stable(tmp_path: Path) -> None:
    bundle = parse_bundle(synthetic_raw(), "abc")
    write_cards(bundle, ["T0001", "T0002"], tmp_path / "a")
    write_cards(bundle, ["T0002", "T0001"], tmp_path / "b")
    for name in ("T0001.json", "T0002.json", "index.json"):
        assert (tmp_path / "a" / name).read_bytes() == (tmp_path / "b" / name).read_bytes()
    assert b"\r" not in (tmp_path / "a" / "index.json").read_bytes()
    cards = load_cards(tmp_path / "a")
    assert cards["T0001"].knowledge_id == "K-T0001" and cards["T0001"].name == "Alpha"
    index = load_index(tmp_path / "a")
    assert index.attack_version == "9.9" and index.techniques["T0002"].revoked
    with pytest.raises(ConfigError, match="not in the pinned bundle"):
        write_cards(bundle, ["T9999"], tmp_path / "c")
    with pytest.raises(ConfigError):
        load_index(tmp_path / "nowhere")


def test_the_committed_cards_and_mapping_validate_against_the_pins() -> None:
    index = load_index(CARDS_DIR)
    validate_mapping(MAPPING, index, PINS)  # the same check the worker runs at startup
    cards = load_cards(CARDS_DIR)
    assert set(cards) == set(mapped_ids(MAPPING))
    assert all(
        c.description and c.url.startswith("https://attack.mitre.org/") for c in cards.values()
    )


def _index(**flags: dict[str, bool]) -> CardIndex:
    base = load_index(CARDS_DIR)
    techniques = dict(base.techniques)
    for tid, change in flags.items():
        old = techniques[tid]
        techniques[tid] = CardIndexEntry(
            name=old.name,
            revoked=change.get("revoked", False),
            deprecated=change.get("deprecated", False),
        )
    return CardIndex(
        attack_version=base.attack_version, bundle_sha256=base.bundle_sha256, techniques=techniques
    )


def test_validation_rejects_revoked_deprecated_missing_ids_and_version_or_checksum_drift() -> None:
    with pytest.raises(ConfigError, match="T1046 is revoked"):
        validate_mapping(MAPPING, _index(T1046={"revoked": True}), PINS)
    with pytest.raises(ConfigError, match="T1041 is deprecated"):
        validate_mapping(MAPPING, _index(T1041={"deprecated": True}), PINS)
    index = load_index(CARDS_DIR)
    smaller = CardIndex(
        attack_version=index.attack_version,
        bundle_sha256=index.bundle_sha256,
        techniques={k: v for k, v in index.techniques.items() if k != "T1048"},
    )
    with pytest.raises(ConfigError, match="T1048 is not in the pinned bundle"):
        validate_mapping(MAPPING, smaller, PINS)
    drifted = index.model_copy(update={"bundle_sha256": "f" * 64, "attack_version": "0.1"})
    with pytest.raises(ConfigError) as err:
        validate_mapping(MAPPING, drifted, PINS)
    assert "not built from the pinned bundle checksum" in str(
        err.value
    ) and "card index is ATT&CK 0.1" in str(err.value)
    stale = MAPPING.model_copy(update={"attack_version": "1.0"})
    with pytest.raises(ConfigError, match=r"mapping targets ATT&CK 1\.0"):
        validate_mapping(stale, index, PINS)


def test_the_real_pinned_bundle_agrees_with_the_committed_cards() -> None:
    path = REPO / PINS.bundle_path
    if not path.exists():
        pytest.skip("pinned ATT&CK bundle not downloaded (python scripts/fetch_attack.py)")
    bundle: AttackBundle = load_bundle(path, PINS.bundle_sha256)
    assert bundle.version == PINS.attack_version
    for tid in mapped_ids(MAPPING):
        t = bundle.techniques[tid]
        assert not t.revoked and not t.deprecated
    index = load_index(CARDS_DIR)
    assert {k: (v.name, v.revoked, v.deprecated) for k, v in index.techniques.items()} == {
        tid: (bundle.techniques[tid].name, False, False) for tid in mapped_ids(MAPPING)
    }


# ---- the mapping file itself ------------------------------------------------------------
def test_mapping_loader_rejects_unknown_conditions_and_mapped_anomalies(tmp_path: Path) -> None:
    text = (REPO / "config" / "attack_mapping.yaml").read_text(encoding="utf-8")
    (tmp_path / "m.yaml").write_text(
        text.replace("when: spray", "when: sometimes"), encoding="utf-8"
    )
    with pytest.raises(ConfigError, match="unknown condition"):
        load_mapping(tmp_path / "m.yaml")
    (tmp_path / "a.yaml").write_text(
        text.replace("UNEXPLAINED_ANOMALY: []", "UNEXPLAINED_ANOMALY: [{id: T1046}]"),
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="never map"):
        load_mapping(tmp_path / "a.yaml")
    (tmp_path / "b.yaml").write_text("attack_version: 1\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_mapping(tmp_path / "b.yaml")


def ids(f: Any, peer: bool = False) -> list[str]:
    return [t.technique_id for t in techniques_for(f, MAPPING, {}, peer)]


def test_each_finding_type_maps_to_its_documented_techniques() -> None:
    assert ids(finding("SCAN", "h")) == ["T1046"]
    assert ids(finding("BRUTE", "h", metrics={"variant": "single_target"})) == ["T1110.001"]
    assert ids(finding("BRUTE", "h", metrics={"variant": "spray"})) == ["T1110.003"]
    assert ids(finding("DNSTUN", "h", metrics={"name_bytes_total": 10})) == ["T1071.004"]
    assert ids(finding("DNSTUN", "h", metrics={"name_bytes_total": 1_000_000})) == [
        "T1071.004",
        "T1048",
    ]
    assert ids(finding("EXFIL", "h")) == ["T1048"]
    assert ids(finding("EXFIL", "h"), peer=True) == ["T1048", "T1041"]


def test_beacons_map_by_protocol_family() -> None:
    assert ids(finding("BEACON", "h", metrics={"series": "ip", "dst_port": 443})) == ["T1071.001"]
    assert ids(finding("BEACON", "h", metrics={"series": "name", "dst_port": None})) == [
        "T1071.001"
    ]
    assert ids(finding("BEACON", "h", metrics={"series": "ip", "dst_port": 53})) == ["T1071.004"]
    assert ids(finding("BEACON", "h", metrics={"series": "ip", "dst_port": 6667})) == ["T1071"]


def test_anomalies_never_receive_a_technique_and_phrases_are_hedged() -> None:
    anomaly = finding("SCAN", "h").model_copy(update={"type": "UNEXPLAINED_ANOMALY"})
    assert techniques_for(anomaly, MAPPING, {}) == []
    for entries in MAPPING.mappings.values():
        assert all(e.phrase.startswith("consistent with") for e in entries)
    refs = techniques_for(finding("SCAN", "h"), MAPPING, {})
    assert refs[0].phrase == "consistent with network service discovery"
