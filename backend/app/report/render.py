"""Markdown report (P4): ranked incidents with evidence IDs, ATT&CK cards and playbooks.

Everything derived from the capture (entity strings, query names, evidence fields) goes through
`md_escape` so a hostile DNS name cannot inject markup. Every measured number sits in a table row
labelled with the evidence ID of the aggregate item it comes from, and the summary sentences cite
evidence IDs, so a reader can trace each number. The HTML renderer (P6) reuses the same model.
"""

import re
from collections.abc import Mapping

from app.profile.profile import CaptureProfile
from app.report.model import AnalysisOutput, IncidentDetail

_SPECIAL = re.compile(r"([\\`*_\[\]<>|~$&])")
_WHITESPACE = re.compile(r"\s+")


def md_escape(value: object) -> str:
    """Escape markdown/HTML metacharacters and flatten whitespace (one line, no injected markup)."""
    return _WHITESPACE.sub(" ", _SPECIAL.sub(r"\\\1", str(value))).strip()


def _aggregate_id(detail: IncidentDetail, finding_id: str) -> str:
    return next(
        e.local_id for e in detail.evidence if e.finding_id == finding_id and e.kind == "aggregate"
    )


def _fmt(value: object) -> str:
    return "n/a" if value is None else md_escape(value)


def _capture_section(profile: CaptureProfile | None, out: AnalysisOutput) -> list[str]:
    lines = ["## Capture", ""]
    lines.append(f"- SHA-256: `{out.capture_sha256}`")
    if profile is not None:
        cap = profile.capture
        lines += [
            f"- Size: {profile.file.size_bytes} bytes ({md_escape(profile.file.format)})",
            f"- Span: {_fmt(cap.duration_s)} s, {cap.packets} packets, "
            f"{profile.connections} connections",
            f"- Hosts: {profile.internal_hosts} internal, {profile.external_hosts} external",
            f"- Zeek: {md_escape(profile.zeek_version)}",
        ]
        if profile.warnings:
            lines += ["", "Data-quality warnings:", ""]
            lines += [f"- **{w.code}**: {md_escape(w.message)}" for w in profile.warnings]
    if any(n for reasons in out.suppressed.values() for n in reasons.values()):
        lines += ["", "Findings suppressed by the network context (counted, not shown):", ""]
        for det, reasons in sorted(out.suppressed.items()):
            for reason, n in sorted(reasons.items()):
                if n:
                    lines.append(f"- {det}: {n} ({md_escape(reason)})")
    return [*lines, ""]


def _incident_section(detail: IncidentDetail) -> list[str]:
    inc = detail.incident
    lines = [
        f"## {inc.id}: {inc.severity_label} (score {inc.severity_score}), "
        f"{md_escape(inc.primary_entity)}",
        "",
        f"- Span: {inc.start_ts.isoformat()} to {inc.end_ts.isoformat()}",
        f"- Finding types: {', '.join(inc.types)}",
        "- Severity is an ordering aid built from the finding types, their confidence and links; "
        "it is not a risk score.",
        "",
        "### Summary",
        "",
    ]
    lines += [
        md_escape(s) if i == 0 else _escape_summary(s)
        for i, s in enumerate(detail.summary.splitlines())
    ]
    lines += ["", "### Findings", ""]
    for f in detail.findings:
        agg = _aggregate_id(detail, f.id)
        lines += [
            f"#### {f.id} {f.type} ({f.confidence} confidence), evidence {agg}",
            "",
            f"- Detector: {f.detector_id} {f.detector_version}",
            f"- Entities: {md_escape(f.primary_entity)} -> "
            f"{', '.join(md_escape(e) for e in f.secondary_entities) or 'n/a'}",
            f"- Span: {f.start_ts.isoformat()} to {f.end_ts.isoformat()}",
            f"- Evidence records: {f.evidence_count} (sample shown below)",
            "",
            f"| Measured ({agg}) | Value |",
            "|---|---|",
        ]
        lines += [f"| {md_escape(k)} | {_fmt(v)} |" for k, v in sorted(f.metrics.items())]
        lines += ["", "| Threshold applied | Value |", "|---|---|"]
        lines += [f"| {md_escape(k)} | {_fmt(v)} |" for k, v in sorted(f.thresholds.items())]
        lines += [
            "",
            "Known benign causes: " + "; ".join(md_escape(c) for c in f.benign_causes),
            "",
        ]
        refs = detail.techniques.get(f.id, [])
        if refs:
            lines.append("ATT&CK (consistent with, not attribution):")
            lines += [f"- {t.technique_id}: {md_escape(t.phrase)}" for t in refs]
            lines.append("")
    if detail.cards:
        lines += ["### ATT&CK technique cards", ""]
        for c in detail.cards:
            lines += [
                f"- **K-{c.technique_id} {md_escape(c.name)}** "
                f"({md_escape(', '.join(c.tactics))}): "
                f"{md_escape(c.description)} [{c.url}]",
            ]
        lines.append("")
    if detail.playbooks:
        lines += ["### Verification playbooks", ""]
        lines += [f"- {p} (knowledge/playbooks/)" for p in detail.playbooks]
        lines.append("")
    if detail.links:
        lines += ["### Links", ""]
        lines += [
            f"- {lk.type}: {lk.from_incident} -> {lk.to_incident}: {md_escape(lk.reason)}"
            for lk in detail.links
        ]
        lines.append("")
    lines += [
        "### Evidence",
        "",
        "| ID | Kind | Finding | Time | Fields |",
        "|---|---|---|---|---|",
    ]
    for e in detail.evidence:
        when = e.ts.isoformat() if e.ts else ""
        fields = ", ".join(
            f"{md_escape(k)}={_fmt(v)}" for k, v in e.fields.items() if v is not None
        )
        lines.append(f"| {e.local_id} | {e.kind} | {e.finding_id} | {when} | {fields} |")
    return [*lines, ""]


def _escape_summary(sentence: str) -> str:
    """Summary sentences keep their `[E-n]` citations readable; the rest is escaped."""
    parts = re.split(r"(\[E-\d+(?:, E-\d+)*\])", sentence)
    return "".join(p if p.startswith("[E-") else _SPECIAL.sub(r"\\\1", p) for p in parts)


def render_markdown(
    out: AnalysisOutput, profile: CaptureProfile | None = None, title: str = "Tracewright report"
) -> str:
    lines = [
        f"# {md_escape(title)}",
        "",
        f"Investigation {md_escape(out.investigation_id)}. ATT&CK {md_escape(out.attack_version)}. "
        "Findings are rule and statistics observations; the analyst decides what they mean.",
        "",
    ]
    lines += _capture_section(profile, out)
    lines += [f"## Incidents ({len(out.incidents)})", ""]
    if out.incidents:
        lines += [
            "| Rank | ID | Severity | Entity | Types | Findings |",
            "|---|---|---|---|---|---|",
        ]
        for rank, d in enumerate(out.incidents, start=1):
            i = d.incident
            lines.append(
                f"| {rank} | {i.id} | {i.severity_label} ({i.severity_score}) | "
                f"{md_escape(i.primary_entity)} | {', '.join(i.types)} | {len(i.finding_ids)} |"
            )
    else:
        lines.append("No incidents: no detector fired on this capture.")
    lines.append("")
    for detail in out.incidents:
        lines += _incident_section(detail)
    return "\n".join(lines).rstrip("\n") + "\n"


def evidence_by_id(detail: IncidentDetail) -> Mapping[str, object]:
    return {e.local_id: e for e in detail.evidence}
