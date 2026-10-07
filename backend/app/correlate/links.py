"""Typed cross-incident links (architecture §9). Deterministic rules, no scoring.

TARGET_LATER_ACTIVE   a BRUTE finding lists host H as a target and a different incident whose
                      primary entity is H starts after that finding began
SHARED_EXTERNAL_PEER  a BEACON and an EXFIL finding share a destination (IP or SNI/Host name);
                      also marks the EXFIL finding for the T1041 mapping and both incidents for
                      the severity bonus, even when both findings sit in the same incident (no
                      link row is produced for a single incident)
SAME_ACTOR_LATER      consecutive incidents of the same primary entity (the gap rule already
                      separated them)
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from itertools import pairwise

from app.correlate.models import Link, LinkType
from app.detect.base import Finding


@dataclass(frozen=True)
class IncidentRef:
    id: str
    primary_entity: str
    start_ts: datetime
    finding_ids: tuple[str, ...]


@dataclass
class LinkResult:
    links: list[Link] = field(default_factory=list)
    target_side: set[str] = field(default_factory=set)  # incident ids that are a link target
    shared_peer_incidents: set[str] = field(default_factory=set)
    exfil_with_beacon: set[str] = field(default_factory=set)  # EXFIL finding ids (for T1041)


def build_links(incidents: Sequence[IncidentRef], findings: Mapping[str, Finding]) -> LinkResult:
    out = LinkResult()
    incident_of = {fid: inc.id for inc in incidents for fid in inc.finding_ids}
    seen: set[tuple[str, str, str]] = set()

    def add(type_: LinkType, a: str, b: str, reason: str, fids: list[str]) -> None:
        if a == b or (type_, a, b) in seen:
            return
        seen.add((type_, a, b))
        out.links.append(
            Link(
                type=type_, from_incident=a, to_incident=b, reason=reason, finding_ids=sorted(fids)
            )
        )

    # TARGET_LATER_ACTIVE
    for inc in incidents:
        for fid in inc.finding_ids:
            f = findings[fid]
            if f.type != "BRUTE":
                continue
            for host in f.secondary_entities:
                for other in incidents:
                    if (
                        other.primary_entity == host
                        and other.id != inc.id
                        and other.start_ts > f.start_ts
                    ):
                        add(
                            "TARGET_LATER_ACTIVE",
                            inc.id,
                            other.id,
                            "Host targeted by login attempts later showed suspicious activity",
                            [fid],
                        )
                        out.target_side.add(other.id)

    # SHARED_EXTERNAL_PEER
    beacons = [f for f in findings.values() if f.type == "BEACON"]
    exfils = [f for f in findings.values() if f.type == "EXFIL"]
    for b in sorted(beacons, key=lambda f: f.id):
        for e in sorted(exfils, key=lambda f: f.id):
            shared = set(b.secondary_entities) & set(e.secondary_entities)
            if not shared:
                continue
            out.exfil_with_beacon.add(e.id)
            ib, ie = incident_of[b.id], incident_of[e.id]
            out.shared_peer_incidents.update((ib, ie))
            add(
                "SHARED_EXTERNAL_PEER",
                ib,
                ie,
                "Beaconing and large outbound transfer to the same destination",
                [b.id, e.id],
            )

    # SAME_ACTOR_LATER
    by_entity: dict[str, list[IncidentRef]] = {}
    for inc in incidents:
        by_entity.setdefault(inc.primary_entity, []).append(inc)
    for items in by_entity.values():
        ordered = sorted(items, key=lambda i: (i.start_ts, i.id))
        for earlier, later in pairwise(ordered):
            add("SAME_ACTOR_LATER", earlier.id, later.id, "Same source active again later", [])
    out.links.sort(key=lambda lk: (lk.type, lk.from_incident, lk.to_incident))
    return out
