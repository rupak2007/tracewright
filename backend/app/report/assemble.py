"""Stage S8: join findings, incidents, ATT&CK references, evidence IDs and template summaries."""

from collections.abc import Mapping

from app.attack.cards import Card
from app.attack.mapping import MappingConfig, TechniqueRef, techniques_for
from app.correlate.runner import CorrelationResult
from app.detect.runner import DetectionReport
from app.explain.evidence_ids import build_incident_evidence
from app.explain.knowledge import playbook_id
from app.explain.template_summary import incident_summary
from app.ingest.normalise import CaptureTables
from app.report.model import AnalysisOutput, IncidentDetail


def assemble_analysis(
    *,
    investigation_id: str,
    capture_sha256: str,
    report: DetectionReport,
    correlation: CorrelationResult,
    tables: CaptureTables,
    mapping: MappingConfig,
    cards: Mapping[str, Card],
    playbooks: Mapping[str, str],
) -> AnalysisOutput:
    findings = {f.id: f for f in report.findings}
    names = {tid: card.name for tid, card in cards.items()}
    details: list[IncidentDetail] = []
    for incident in correlation.incidents:
        members = [findings[fid] for fid in incident.finding_ids]
        techniques: dict[str, list[TechniqueRef]] = {
            f.id: techniques_for(f, mapping, names, f.id in correlation.exfil_with_beacon)
            for f in members
        }
        used = sorted({t.technique_id for refs in techniques.values() for t in refs})
        evidence = build_incident_evidence(incident, findings, tables)
        details.append(
            IncidentDetail(
                incident=incident,
                findings=members,
                techniques=techniques,
                cards=[cards[tid] for tid in used if tid in cards],
                playbooks=sorted(
                    {playbook_id(f.type) for f in members if playbook_id(f.type) in playbooks}
                ),
                evidence=evidence,
                summary=incident_summary(incident, members, evidence),
                links=[
                    lk
                    for lk in correlation.links
                    if incident.id in (lk.from_incident, lk.to_incident)
                ],
            )
        )
    ranked = sorted(
        details, key=lambda d: (-d.incident.severity_score, d.incident.start_ts, d.incident.id)
    )
    return AnalysisOutput(
        investigation_id=investigation_id,
        capture_sha256=capture_sha256,
        attack_version=mapping.attack_version,
        incidents=ranked,
        links=correlation.links,
        suppressed=report.suppressed,
    )
