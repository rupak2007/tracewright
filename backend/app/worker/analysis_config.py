"""Everything the analysis pipeline reads from config/ and knowledge/, loaded and checked once.

A configuration problem raises `ConfigError` before any capture work starts. This is also where the
ATT&CK mapping is validated against the cards derived from the pinned bundle (architecture §10): a
revoked, deprecated, missing or version-drifted technique stops the worker instead of shipping
a wrong mapping.
"""

from dataclasses import dataclass
from pathlib import Path

from app.attack.cards import Card, CardIndex, load_cards, load_index
from app.attack.mapping import MappingConfig, load_mapping, validate_mapping
from app.attack.stix import AttackPins, load_pins
from app.core.config import PipelineSettings
from app.correlate.config import CorrelationConfig, load_correlation_config
from app.detect.config import DetectorsConfig, load_detectors_config
from app.explain.knowledge import load_playbooks
from app.profile.context import NetworkContext, load_network_context
from app.profile.warnings import ProfileConfig, load_profile_config


@dataclass(frozen=True)
class AnalysisConfig:
    config_dir: Path
    network: NetworkContext
    profile: ProfileConfig
    detectors: DetectorsConfig
    correlation: CorrelationConfig
    mapping: MappingConfig
    pins: AttackPins
    card_index: CardIndex
    cards: dict[str, Card]
    playbooks: dict[str, str]


def load_analysis_config(settings: PipelineSettings) -> AnalysisConfig:
    cfg = settings.config_dir
    pins = load_pins(cfg / "attack.yaml")
    mapping = load_mapping(cfg / "attack_mapping.yaml")
    cards_dir = settings.knowledge_dir / "cards" / pins.attack_version
    index = load_index(cards_dir)
    validate_mapping(mapping, index, pins)
    return AnalysisConfig(
        config_dir=cfg,
        network=load_network_context(cfg / "network.yaml"),
        profile=load_profile_config(cfg / "profile.yaml"),
        detectors=load_detectors_config(cfg / "detectors.yaml"),
        correlation=load_correlation_config(cfg / "correlation.yaml"),
        mapping=mapping,
        pins=pins,
        card_index=index,
        cards=load_cards(cards_dir),
        playbooks=load_playbooks(settings.knowledge_dir),
    )
