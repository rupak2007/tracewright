"""Deterministic template summaries (architecture §13, stage S8): the always-available explanation.

One Jinja sentence per finding, rendered in a sandbox with strict undefined variables, so a template
can only print values that exist in the finding's metrics, thresholds and entities. Every sentence
ends with citations to the incident's evidence IDs (the finding's aggregate item plus up to two
records), which is what makes the summary traceable. Wording is hedged: findings describe observed
patterns, never a verdict.
"""

from collections.abc import Sequence
from pathlib import Path

from jinja2 import StrictUndefined
from jinja2.sandbox import SandboxedEnvironment

from app.correlate.models import Incident
from app.detect.base import Finding
from app.explain.evidence_ids import EvidenceItem

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
CITED_RECORDS = 2
_ENV = SandboxedEnvironment(
    loader=None, undefined=StrictUndefined, autoescape=False, keep_trailing_newline=False
)


def _template(finding_type: str) -> str:
    return (TEMPLATE_DIR / f"{finding_type}.j2").read_text(encoding="utf-8").strip()


def _percent(value: object) -> float:
    return round(float(value) * 100, 1) if isinstance(value, int | float) else 0.0


def finding_sentence(f: Finding, evidence: Sequence[EvidenceItem]) -> str:
    mine = [e for e in evidence if e.finding_id == f.id]
    aggregate = next(e.local_id for e in mine if e.kind == "aggregate")
    records = [e.local_id for e in mine if e.kind != "aggregate"][:CITED_RECORDS]
    context = {
        "src": f.primary_entity,
        "targets": ", ".join(f.secondary_entities[:3]) or "its peers",
        "m": f.metrics,
        "t": f.thresholds,
        "confidence": f.confidence,
        "failed_pct": _percent(f.metrics.get("failed_share")),
        "txt_pct": _percent(f.metrics.get("txt_null_share")),
        "nx_pct": _percent(f.metrics.get("nxdomain_rate")),
        "cites": "[" + ", ".join([aggregate, *records]) + "]",
    }
    return _ENV.from_string(_template(f.type)).render(**context)


def incident_summary(
    incident: Incident, findings: Sequence[Finding], evidence: Sequence[EvidenceItem]
) -> str:
    """Header line plus one cited sentence per finding, in the incident's finding order."""
    header = (
        f"Incident {incident.id} ({incident.severity_label}, score {incident.severity_score}) "
        f"groups {len(findings)} finding(s) for {incident.primary_entity}; "
        "severity is an ordering aid, not a risk score."
    )
    lines = [finding_sentence(f, evidence) for f in findings]
    return "\n".join([header, *lines])
