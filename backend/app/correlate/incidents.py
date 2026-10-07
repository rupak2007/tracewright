"""Group findings into incidents per primary entity (architecture §9). Pure and deterministic.

Per primary entity, findings are sorted by start; a finding joins the current incident when
`start <= incident_end + gap`, otherwise it opens a new one. Primary entities are already set by the
detectors (SCAN/BRUTE: the source; DNSTUN/BEACON/EXFIL/anomalies: the internal host).
"""

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta

from app.detect.base import Finding


@dataclass(frozen=True)
class Group:
    primary_entity: str
    start_ts: datetime
    end_ts: datetime
    finding_ids: tuple[str, ...]


def group_findings(findings: Sequence[Finding], gap_s: float) -> list[Group]:
    """Incident groups ordered by (start, primary entity); finding ids keep time order inside."""
    by_entity: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_entity[f.primary_entity].append(f)
    gap = timedelta(seconds=gap_s)
    groups: list[Group] = []
    for entity, items in by_entity.items():
        current: list[Finding] = []
        end: datetime | None = None
        for f in sorted(items, key=lambda x: (x.start_ts, x.end_ts, x.id)):
            if current and end is not None and f.start_ts <= end + gap:
                current.append(f)
                end = max(end, f.end_ts)
            else:
                if current and end is not None:
                    groups.append(_group(entity, current, end))
                current, end = [f], f.end_ts
        if current and end is not None:
            groups.append(_group(entity, current, end))
    return sorted(groups, key=lambda g: (g.start_ts, g.primary_entity))


def _group(entity: str, items: list[Finding], end: datetime) -> Group:
    return Group(entity, items[0].start_ts, end, tuple(f.id for f in items))
