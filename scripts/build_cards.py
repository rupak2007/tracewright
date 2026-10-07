"""Build knowledge/cards/<attack version>/ from the pinned ATT&CK bundle (architecture §11).

    python scripts/fetch_attack.py && python scripts/build_cards.py

Writes one card per technique used in config/attack_mapping.yaml plus index.json (bundle version,
checksum, revoked/deprecated flags), which the worker validates the mapping against at startup.
"""

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "backend"))

from app.attack.cards import write_cards  # noqa: E402
from app.attack.mapping import load_mapping, mapped_ids  # noqa: E402
from app.attack.stix import load_bundle, load_pins  # noqa: E402


def main() -> int:
    pins = load_pins(REPO / "config" / "attack.yaml")
    mapping = load_mapping(REPO / "config" / "attack_mapping.yaml")
    bundle = load_bundle(REPO / pins.bundle_path, pins.bundle_sha256)
    out = REPO / "knowledge" / "cards" / pins.attack_version
    write_cards(bundle, mapped_ids(mapping), out)
    print(f"wrote {len(mapped_ids(mapping))} cards to {out} (ATT&CK {bundle.version})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
