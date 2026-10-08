"""Build the pseudonymised evidence pack the narrative is generated from (architecture §13).

Allowed in the pack: finding types, confidences, measured values and thresholds (numbers and our
own enumerations), pseudonyms `H<n>`/`X<n>`/`D<n>`, ports, byte counts, times relative to capture
start, capture caveats as warning codes, and short excerpts of the ATT&CK cards and hand-written
playbooks of this incident. NOT allowed, and never collected: DNS query names, URIs, user agents,
certificate fields, any other free text from the capture. A string value is passed through only
when it matches a conservative vocabulary pattern (Zeek service/state/qtype/rcode names, our
metric enumerations) and is not an address, so an attacker cannot smuggle text into a prompt
through a field value. At most `MAX_ITEMS` evidence items are included (aggregates first, then up
to 3 sample records per finding) and the serialised pack is size-capped.
"""

import ipaddress
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from app.attack.cards import Card
from app.explain.pseudonymise import Pseudonymiser
from app.report.model import IncidentDetail

MAX_ITEMS = 40
RECORDS_PER_FINDING = 3
MAX_PACK_CHARS = 24_000  # about 6k tokens
EXCERPT_CHARS = 400
_VOCAB = re.compile(r"^[A-Za-z0-9_]{1,24}$")
# metric keys whose string values are our own enumerations (never capture-derived)
_ENUM_METRICS = {
    "scan_type",
    "service",
    "variant",
    "series",
    "failure_kind",
    "rule",
    "grouping",
    "scorer",
    "confidence",
    "finding_type",
}
_RECORD_VOCAB_KEYS = ("proto", "service", "state", "qtype", "rcode")


@dataclass(frozen=True)
class EvidencePack:
    pack: dict[str, Any]
    mapping: dict[str, str]  # pseudonym -> real value; never sent to a model

    def to_json(self) -> str:
        return json.dumps(self.pack, sort_keys=True, separators=(",", ":"))


def relative(moment: datetime | str | None, start: float) -> str | None:
    """`T+HH:MM:SS` since the capture began."""
    if moment is None:
        return None
    stamp = (
        datetime.fromisoformat(moment).timestamp()
        if isinstance(moment, str)
        else moment.timestamp()
    )
    seconds = max(0, round(stamp - start))
    return f"T+{seconds // 3600:02d}:{seconds % 3600 // 60:02d}:{seconds % 60:02d}"


def _safe_string(key: str, value: str) -> str | None:
    if key in _ENUM_METRICS or key in _RECORD_VOCAB_KEYS:
        return value if _VOCAB.match(value) and not _is_address(value) else None
    return None


def _is_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _scalars(source: Mapping[str, Any], *, allow_strings: bool = True) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in source.items():
        if isinstance(value, bool | int | float):
            out[key] = value
        elif isinstance(value, str) and allow_strings:
            safe = _safe_string(key, value)
            if safe is not None:
                out[key] = safe
    return out


def _excerpt(text: str) -> str:
    text = " ".join(text.split())
    return text if len(text) <= EXCERPT_CHARS else text[: EXCERPT_CHARS - 3].rstrip() + "..."


def _playbook_excerpt(text: str) -> str:
    """First paragraph after the heading ("What the detector saw")."""
    for block in text.split("\n\n")[1:]:
        if block.strip() and not block.startswith("#"):
            return _excerpt(block.replace("**", ""))
    return ""


def build_pack(
    detail: IncidentDetail,
    *,
    capture_start: float,
    capture_span_s: float | None,
    warning_codes: list[str],
    max_beacon_interval_s: float | None,
    pseudo: Pseudonymiser,
    cards: Mapping[str, Card],
    playbooks: Mapping[str, str],
) -> EvidencePack:
    inc = detail.incident
    findings_out: list[dict[str, Any]] = []
    evidence_out: dict[str, Any] = {}
    refs_by_finding: dict[str, list[str]] = {f.id: [] for f in detail.findings}

    def entity(value: str) -> str:
        return pseudo.token(value)

    # aggregates first, then up to RECORDS_PER_FINDING records of each finding (in E-n order)
    chosen: list[Any] = [e for e in detail.evidence if e.kind == "aggregate"]
    per_finding: dict[str, int] = {}
    for e in detail.evidence:
        if e.kind == "aggregate":
            continue
        if per_finding.get(e.finding_id, 0) < RECORDS_PER_FINDING:
            per_finding[e.finding_id] = per_finding.get(e.finding_id, 0) + 1
            chosen.append(e)
    for e in chosen[:MAX_ITEMS]:
        if e.kind == "aggregate":
            fields = {
                k: v
                for k, v in _scalars(e.fields).items()
                if k not in ("start", "end")  # absolute times are replaced by relative ones
            }
            fields["start"] = relative(str(e.fields.get("start")), capture_start)
            fields["end"] = relative(str(e.fields.get("end")), capture_start)
        elif e.kind == "conn":
            wanted = (
                "dst_port",
                "bytes_out",
                "bytes_in",
                "duration_s",
                "proto",
                "service",
                "state",
            )
            fields = _scalars({k: v for k, v in e.fields.items() if k in wanted})
            fields["t"] = relative(e.ts, capture_start)
            for key in ("src", "dst"):
                raw = e.fields.get(key)
                if isinstance(raw, str):
                    fields[key] = entity(raw)
        else:  # dns: vocabulary only; the query name is capture-derived and stays out
            fields = _scalars({k: v for k, v in e.fields.items() if k in ("qtype", "rcode")})
            fields["t"] = relative(e.ts, capture_start)
            for key in ("client", "resolver"):
                raw = e.fields.get(key)
                if isinstance(raw, str):
                    fields[key] = entity(raw)
        evidence_out[e.local_id] = {
            "kind": e.kind,
            "fields": {k: v for k, v in fields.items() if v is not None},
        }
    evidence_ids = set(evidence_out)
    aggregate_of = {e.finding_id: e.local_id for e in detail.evidence if e.kind == "aggregate"}
    for e in chosen[:MAX_ITEMS]:
        refs_by_finding[e.finding_id].append(e.local_id)

    for f in detail.findings:
        findings_out.append(
            {
                "fid": f.id,
                "type": f.type,
                "confidence": f.confidence,
                "entity": entity(f.primary_entity),
                "peers": [entity(s) for s in f.secondary_entities],
                "metrics": _scalars(f.metrics),
                "thresholds": _scalars(dict(f.thresholds), allow_strings=False),
                "evidence": [i for i in refs_by_finding[f.id] if i in evidence_ids],
                "summary_item": aggregate_of.get(f.id),
                "techniques": [t.technique_id for t in detail.techniques.get(f.id, [])],
            }
        )
    knowledge: dict[str, str] = {}
    for card in detail.cards:
        tid = str(card.technique_id)
        known = cards.get(tid)
        if known is not None:
            knowledge[f"K-{tid}"] = f"{known.name}: {_excerpt(known.description)}"
    for pid in detail.playbooks:
        if pid in playbooks:
            knowledge[pid] = _playbook_excerpt(playbooks[pid])
    pack: dict[str, Any] = {
        "incident": {
            "id": inc.id,
            "severity": inc.severity_label,
            "span": (
                f"{relative(inc.start_ts, capture_start)} to {relative(inc.end_ts, capture_start)}"
            ),
            "types": list(inc.types),
        },
        "capture": {
            "span_min": None if capture_span_s is None else round(capture_span_s / 60, 1),
            "warnings": warning_codes,
            "max_beacon_interval_s": None
            if max_beacon_interval_s is None
            else round(max_beacon_interval_s, 1),
        },
        "entities": pseudo.kinds,
        "findings": findings_out,
        "evidence": evidence_out,
        "knowledge": knowledge,
        "links": [
            {"type": lk.type, "from": lk.from_incident, "to": lk.to_incident} for lk in detail.links
        ],
    }
    pack["entities"] = pseudo.kinds  # complete: later calls may have added tokens
    text = json.dumps(pack, sort_keys=True, separators=(",", ":"))
    while len(text) > MAX_PACK_CHARS and len(evidence_out) > len(aggregate_of):
        drop = [i for i in evidence_out if i not in aggregate_of.values()][-1]
        del evidence_out[drop]
        for fo in findings_out:
            fo["evidence"] = [i for i in fo["evidence"] if i != drop]
        text = json.dumps(pack, sort_keys=True, separators=(",", ":"))
    return EvidencePack(pack, pseudo.mapping)
