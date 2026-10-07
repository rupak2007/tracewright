"""Run every detector over one capture's tables and assemble a deterministic report (stage S4)."""

from collections import Counter
from collections.abc import Sequence

from pydantic import BaseModel

from app.detect import beacon, brute, dns_tunnel, exfil, scan
from app.detect.base import Detector, DetectorInput, Finding

# Appended to as each detector lands; the order here is the order they run in, not the output order.
DETECTORS: tuple[Detector, ...] = (
    scan.DETECTOR,
    brute.DETECTOR,
    dns_tunnel.DETECTOR,
    beacon.DETECTOR,
    exfil.DETECTOR,
)

_TYPE_ORDER = {"SCAN": 0, "BRUTE": 1, "DNSTUN": 2, "BEACON": 3, "EXFIL": 4}


class DetectionReport(BaseModel):
    investigation_id: str
    config_hash: str
    detector_versions: dict[str, str]
    findings: list[Finding]
    # detector id -> reason -> findings that fired but were suppressed (FR-13)
    suppressed: dict[str, dict[str, int]]

    @property
    def suppressed_total(self) -> int:
        return sum(sum(reasons.values()) for reasons in self.suppressed.values())

    def counts_by_type(self) -> dict[str, int]:
        return dict(sorted(Counter(f.type for f in self.findings).items()))


def _sort_key(f: Finding) -> tuple[object, ...]:
    return (
        f.start_ts,
        _TYPE_ORDER[f.type],
        f.primary_entity,
        tuple(f.secondary_entities),
        f.end_ts,
        repr(sorted(f.metrics.items(), key=lambda kv: kv[0])),
    )


def run_detectors(
    inp: DetectorInput,
    investigation_id: str = "local",
    detectors: Sequence[Detector] | None = None,
) -> DetectionReport:
    """Same tables and thresholds in, byte-identical report out: findings are ordered by time, type
    and entity, and only then numbered F-1, F-2, ... (instruction §1.9)."""
    active = DETECTORS if detectors is None else tuple(detectors)
    raw: list[Finding] = []
    suppressed: dict[str, dict[str, int]] = {}
    for detector in active:
        output = detector.run(inp)
        raw.extend(output.findings)
        suppressed[detector.detector_id] = dict(sorted(output.suppressed.items()))
    ordered = sorted(raw, key=_sort_key)
    findings = [
        f.model_copy(update={"id": f"F-{n}", "investigation_id": investigation_id})
        for n, f in enumerate(ordered, start=1)
    ]
    return DetectionReport(
        investigation_id=investigation_id,
        config_hash=inp.config.config_hash(),
        detector_versions={d.detector_id: d.version for d in active},
        findings=findings,
        suppressed=suppressed,
    )
