"""Technique cards (K-T...) derived once from the pinned bundle, committed in knowledge/cards/.

`index.json` records the bundle version and checksum a card set came from plus the status of every
card, so the worker can validate the ATT&CK mapping at startup (every ID present, none revoked or
deprecated, versions and checksum equal to config/attack.yaml) without loading the full bundle.
"""

import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from app.attack.stix import AttackBundle, Technique
from app.core.errors import ConfigError


class Card(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    knowledge_id: str  # "K-T1046"
    technique_id: str
    name: str
    description: str
    tactics: list[str]
    mitigations: list[str]
    detection_notes: str
    url: str


class CardIndexEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    revoked: bool
    deprecated: bool


class CardIndex(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    attack_version: str
    bundle_sha256: str
    techniques: dict[str, CardIndexEntry]


def card_for(t: Technique) -> Card:
    return Card(
        knowledge_id=f"K-{t.id}",
        technique_id=t.id,
        name=t.name,
        description=t.description,
        tactics=t.tactics,
        mitigations=t.mitigations,
        detection_notes=t.detection,
        url=t.url,
    )


def write_cards(bundle: AttackBundle, ids: list[str], out_dir: Path) -> None:
    """Write one JSON card per technique id plus index.json (sorted keys: byte-stable output)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    missing = [i for i in ids if i not in bundle.techniques]
    if missing:
        raise ConfigError(f"technique(s) not in the pinned bundle: {', '.join(sorted(missing))}")
    entries: dict[str, CardIndexEntry] = {}
    for tid in sorted(ids):
        t = bundle.techniques[tid]
        _write_json(out_dir / f"{tid}.json", card_for(t).model_dump())
        entries[tid] = CardIndexEntry(name=t.name, revoked=t.revoked, deprecated=t.deprecated)
    index = CardIndex(
        attack_version=bundle.version, bundle_sha256=bundle.sha256, techniques=entries
    )
    _write_json(out_dir / "index.json", index.model_dump())


def _write_json(path: Path, payload: object) -> None:
    """LF line endings on every platform, so the committed cards are byte-stable."""
    text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    path.write_text(text, encoding="utf-8", newline="\n")


def load_index(cards_dir: Path) -> CardIndex:
    try:
        return CardIndex.model_validate_json((cards_dir / "index.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ConfigError(f"ATT&CK card index missing or invalid in {cards_dir}: {exc}") from exc


def load_cards(cards_dir: Path) -> dict[str, Card]:
    cards: dict[str, Card] = {}
    for path in sorted(cards_dir.glob("T*.json")):
        try:
            card = Card.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ConfigError(f"invalid ATT&CK card {path.name}: {exc}") from exc
        cards[card.technique_id] = card
    return cards
