"""Printable HTML report (FR-44, SEC-06): the same content as the Markdown report, every dynamic
value passed through `html.escape`, no scripts, no external resources, and a CSP meta tag that
forbids both. Capture-derived strings (entities, query names, evidence fields) are inert text."""

import json
from collections.abc import Mapping
from html import escape

from app.profile.profile import CaptureProfile
from app.report import narrative_block
from app.report.model import AnalysisOutput, IncidentDetail
from app.report.narrative_block import NarrativeBlock
from app.report.render import LIMITATIONS, Feedback

_STYLE = (
    "body{font:14px/1.45 system-ui,sans-serif;max-width:60rem;margin:2rem auto;padding:0 1rem;"
    "color:#1b1f23}table{border-collapse:collapse;width:100%;margin:.5rem 0}"
    "th,td{border:1px solid #c8ccd0;padding:.25rem .5rem;text-align:left;vertical-align:top;"
    "word-break:break-word}th{background:#f1f3f5}code{background:#f1f3f5;padding:0 .2rem}"
    ".sev{font-weight:700}@media print{body{margin:0}}"
)
_CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; script-src 'none'"


def _e(value: object) -> str:
    return escape("n/a" if value is None else str(value), quote=True)


def _table(headers: list[str], rows: list[list[object]]) -> str:
    head = "".join(f"<th>{_e(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{_e(c)}</td>" for c in row) + "</tr>" for row in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def _narrative(block: NarrativeBlock) -> list[str]:
    out = ["<h3>Narrative (optional, machine-generated)</h3>"]
    items: list[str] = []
    for kind, text in narrative_block.lines(block, _e):
        if kind.startswith("h_") or kind in ("label", "summary"):
            if items:
                out.append("<ul>" + "".join(items) + "</ul>")
                items = []
            out.append(f"<h4>{text}</h4>" if kind.startswith("h_") else f"<p>{text}</p>")
        else:
            items.append(f"<li>{text}</li>")
    if items:
        out.append("<ul>" + "".join(items) + "</ul>")
    return out


def _incident(detail: IncidentDetail, narrative: NarrativeBlock | None = None) -> list[str]:
    inc = detail.incident
    agg = {e.finding_id: e.local_id for e in detail.evidence if e.kind == "aggregate"}
    out = [
        f'<h2>{_e(inc.id)}: <span class="sev">{_e(inc.severity_label)}</span> '
        f"(score {_e(inc.severity_score)}), {_e(inc.primary_entity)}</h2>",
        f"<p>Span {_e(inc.start_ts.isoformat())} to {_e(inc.end_ts.isoformat())}. Finding types: "
        f"{_e(', '.join(inc.types))}. Severity is an ordering aid, not a risk score.</p>",
        "<h3>Summary</h3>",
        *[f"<p>{_e(line)}</p>" for line in detail.summary.splitlines()],
        *(_narrative(narrative) if narrative is not None else []),
        "<h3>Findings</h3>",
    ]
    for f in detail.findings:
        out += [
            f"<h4>{_e(f.id)} {_e(f.type)} ({_e(f.confidence)} confidence), evidence "
            f"{_e(agg.get(f.id))}</h4>",
            f"<p>Detector {_e(f.detector_id)} {_e(f.detector_version)}. Entities: "
            f"{_e(f.primary_entity)} &rarr; {_e(', '.join(f.secondary_entities) or 'n/a')}. "
            f"Evidence records: {_e(f.evidence_count)}.</p>",
            _table(["Measured", "Value"], [[k, v] for k, v in sorted(f.metrics.items())]),
            _table(
                ["Threshold applied", "Value"], [[k, v] for k, v in sorted(f.thresholds.items())]
            ),
            f"<p>Known benign causes: {_e('; '.join(f.benign_causes))}</p>",
        ]
        refs = detail.techniques.get(f.id, [])
        if refs:
            out.append(
                "<p>ATT&amp;CK (consistent with, not attribution): "
                + "; ".join(f"{_e(t.technique_id)} {_e(t.phrase)}" for t in refs)
                + "</p>"
            )
    if detail.cards:
        out.append("<h3>ATT&amp;CK technique cards</h3>")
        out.append(
            _table(
                ["Technique", "Name", "Tactics", "Description"],
                [
                    [c.technique_id, c.name, ", ".join(c.tactics), c.description]
                    for c in detail.cards
                ],
            )
        )
    if detail.playbooks:
        out.append(f"<p>Verification playbooks: {_e(', '.join(detail.playbooks))}</p>")
    if detail.links:
        out.append(
            _table(
                ["Link", "From", "To", "Meaning"],
                [[lk.type, lk.from_incident, lk.to_incident, lk.reason] for lk in detail.links],
            )
        )
    out.append("<h3>Evidence</h3>")
    out.append(
        _table(
            ["ID", "Kind", "Finding", "Time", "Fields"],
            [
                [
                    e.local_id,
                    e.kind,
                    e.finding_id,
                    e.ts.isoformat() if e.ts else "",
                    ", ".join(f"{k}={v}" for k, v in e.fields.items() if v is not None),
                ]
                for e in detail.evidence
            ],
        )
    )
    return out


def render_html(
    out: AnalysisOutput,
    profile: CaptureProfile | None = None,
    title: str = "Tracewright report",
    manifest: Mapping[str, object] | None = None,
    feedback: Feedback | None = None,
    narratives: Mapping[str, NarrativeBlock] | None = None,
) -> str:
    body = [
        f"<h1>{_e(title)}</h1>",
        f"<p>Investigation {_e(out.investigation_id)}. ATT&amp;CK {_e(out.attack_version)}. "
        "Findings are rule and statistics observations; the analyst decides what they mean.</p>",
        "<h2>Capture</h2>",
        f"<p>SHA-256 <code>{_e(out.capture_sha256)}</code></p>",
    ]
    if profile is not None:
        cap = profile.capture
        body.append(
            f"<p>{_e(profile.file.size_bytes)} bytes ({_e(profile.file.format)}); span "
            f"{_e(cap.duration_s)} s; {_e(cap.packets)} packets; {_e(profile.connections)} "
            f"connections; {_e(profile.internal_hosts)} internal and {_e(profile.external_hosts)} "
            f"external hosts; Zeek {_e(profile.zeek_version)}.</p>"
        )
        if profile.warnings:
            body.append(
                _table(["Warning", "Message"], [[w.code, w.message] for w in profile.warnings])
            )
    body.append(f"<h2>Incidents ({len(out.incidents)})</h2>")
    if out.incidents:
        body.append(
            _table(
                ["Rank", "ID", "Severity", "Entity", "Types", "Findings"],
                [
                    [
                        n,
                        d.incident.id,
                        f"{d.incident.severity_label} ({d.incident.severity_score})",
                        d.incident.primary_entity,
                        ", ".join(d.incident.types),
                        len(d.incident.finding_ids),
                    ]
                    for n, d in enumerate(out.incidents, start=1)
                ],
            )
        )
    else:
        body.append("<p>No incidents: no detector fired on this capture.</p>")
    for detail in out.incidents:
        body += _incident(detail, (narratives or {}).get(detail.incident.id))
    if feedback:
        body.append("<h2>Analyst feedback</h2>")
        body.append(
            _table(
                ["Finding", "Label", "Note"],
                [
                    [fid, label, note]
                    for fid, items in sorted(feedback.items())
                    for label, note in items
                ],
            )
        )
    if manifest:
        body.append("<h2>Run manifest</h2>")
        body.append(
            _table(
                ["Field", "Value"],
                [[k, json.dumps(v, sort_keys=True)] for k, v in sorted(manifest.items())],
            )
        )
    body.append(
        "<h2>Limitations</h2><ul>" + "".join(f"<li>{_e(i)}</li>" for i in LIMITATIONS) + "</ul>"
    )
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        f'<meta http-equiv="Content-Security-Policy" content="{escape(_CSP, quote=True)}">'
        f"<title>{_e(title)}</title><style>{_STYLE}</style></head><body>"
        + "\n".join(body)
        + "</body></html>\n"
    )
