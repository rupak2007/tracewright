"""Loader for the pinned MITRE ATT&CK Enterprise STIX 2.1 bundle (architecture §10).

Only used at setup time (`scripts/build_cards.py`) and in tests: the worker validates against the
technique index that `build_cards` derived from the pinned bundle (see `cards.py`), so it never
has to parse the 54 MB file. The bundle's SHA-256 is checked against `config/attack.yaml` first.
"""

import hashlib
import json
import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict

from app.core.errors import ConfigError

MAX_DESCRIPTION_CHARS = 700
_CITATION = re.compile(r"\(Citation:[^)]*\)")
_LINK = re.compile(r"\[([^\]]+)\]\([^)]*\)")
_TAG = re.compile(r"</?[a-zA-Z][^>]*>")
_SPACE = re.compile(r"\s+")


class AttackPins(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    attack_version: str
    bundle_url: str
    bundle_path: str
    bundle_sha256: str


def load_pins(path: Path) -> AttackPins:
    try:
        return AttackPins.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))
    except (OSError, yaml.YAMLError, ValueError, TypeError) as exc:
        raise ConfigError(f"Invalid ATT&CK pin file {path.name}: {exc}") from exc


class Technique(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    name: str
    description: str
    tactics: list[str]
    url: str
    revoked: bool
    deprecated: bool
    mitigations: list[str]
    detection: str


class AttackBundle(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: str
    sha256: str
    techniques: dict[str, Technique]


def clean_text(text: str, limit: int = MAX_DESCRIPTION_CHARS) -> str:
    """Strip citations, markdown links and HTML tags; collapse whitespace; trim at a sentence."""
    text = _CITATION.sub("", text)
    text = _LINK.sub(r"\1", text)
    text = _TAG.sub("", text)
    text = _SPACE.sub(" ", text).strip()
    if len(text) <= limit:
        return text
    cut = text[:limit]
    end = cut.rfind(". ")
    return cut[: end + 1].strip() if end > limit // 2 else cut.rstrip() + "..."


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _external_id(obj: dict[str, Any]) -> tuple[str, str] | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return str(ref["external_id"]), str(ref.get("url", ""))
    return None


def _live(obj: dict[str, Any]) -> bool:
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def parse_bundle(raw: dict[str, Any], sha256: str) -> AttackBundle:
    objects: list[dict[str, Any]] = raw.get("objects", [])
    version = ""
    for obj in objects:
        if obj.get("type") == "x-mitre-collection":
            version = str(obj.get("x_mitre_version", ""))
            break
    mitigation_names = {
        o["id"]: str(o.get("name", ""))
        for o in objects
        if o.get("type") == "course-of-action" and _live(o)
    }
    mitigations: dict[str, list[str]] = {}
    for o in objects:
        if o.get("type") == "relationship" and o.get("relationship_type") == "mitigates":
            name = mitigation_names.get(o.get("source_ref", ""))
            if name and _live(o):
                mitigations.setdefault(str(o["target_ref"]), []).append(name)
    techniques: dict[str, Technique] = {}
    for o in objects:
        if o.get("type") != "attack-pattern":
            continue
        ident = _external_id(o)
        if ident is None:
            continue
        tid, url = ident
        techniques[tid] = Technique(
            id=tid,
            name=str(o.get("name", "")),
            description=clean_text(str(o.get("description", ""))),
            tactics=[str(k["phase_name"]) for k in o.get("kill_chain_phases", [])],
            url=url,
            revoked=bool(o.get("revoked", False)),
            deprecated=bool(o.get("x_mitre_deprecated", False)),
            mitigations=sorted(set(mitigations.get(str(o["id"]), [])))[:5],
            detection=clean_text(str(o.get("x_mitre_detection", ""))),
        )
    return AttackBundle(version=version, sha256=sha256, techniques=techniques)


def load_bundle(path: Path, expected_sha256: str) -> AttackBundle:
    """Verify the file against the pinned checksum, then parse it."""
    if not path.is_file():
        raise ConfigError(f"ATT&CK bundle {path} not found; run scripts/fetch_attack.py")
    digest = sha256_file(path)
    if digest != expected_sha256:
        raise ConfigError(
            f"ATT&CK bundle checksum mismatch: pinned {expected_sha256}, got {digest}"
        )
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ConfigError(f"ATT&CK bundle {path.name} is not valid JSON: {exc}") from exc
    return parse_bundle(raw, digest)
