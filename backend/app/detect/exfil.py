"""DET-EXFIL: unusual outbound volume (PRD §10, architecture §7.5).

Unit: (internal source, external destination IP) over connections the internal host started
(orig internal, resp external; needs the network context). A second grouping by TLS server name /
HTTP Host catches destinations that rotate IPs; it is reported only when the IP grouping does not
already cover its connections.
  outbound = sum(orig_bytes), inbound = sum(resp_bytes), ratio = outbound / max(inbound, 1)
  x = log1p(outbound); modified z = 0.6745 * (x - median) / MAD over ALL pairs of the grouping
Fires when outbound >= min_outbound_bytes AND z >= min_modified_z AND ratio >= min_out_in_ratio
(high confidence). With fewer than weak_baseline_min_pairs pairs z is not computed and only the
byte floor applies: low confidence (the capture profile raises WEAK_BASELINE_EXFIL for this case).
When MAD is 0 (more than half the pairs identical) the Iglewicz-Hoaglin fallback
z = (x - median) / (1.253314 * mean absolute deviation) is used, and 0 if that is 0 too.
Destinations listed as known_hosts.backup_servers are suppressed and counted.

Limitation: only internal-to-external connections initiated by the internal host are counted;
an internal server pushing large responses to an external client is not seen as outbound volume.
"""

from dataclasses import dataclass

import numpy as np
import pandas as pd
from numpy.typing import NDArray

from app.detect.base import (
    Confidence,
    DetectorInput,
    DetectorOutput,
    Finding,
    MetricValue,
    epoch_seconds,
    group_indices,
    make_finding,
)
from app.detect.config import ExfilConfig

BENIGN_CAUSES = (
    "backups",
    "cloud synchronisation",
    "file uploads",
    "video calls",
    "CI artifact pushes",
)
_IQR_FALLBACK = 1.253314


def modified_z(x: NDArray[np.float64]) -> NDArray[np.float64]:
    """Modified z-score of each value against the whole sample (0.0 when there is no spread)."""
    median = float(np.median(x))
    mad = float(np.median(np.abs(x - median)))
    if mad > 0:
        return np.asarray(0.6745 * (x - median) / mad, dtype=np.float64)
    mean_ad = float(np.mean(np.abs(x - median)))
    if mean_ad > 0:
        return np.asarray((x - median) / (_IQR_FALLBACK * mean_ad), dtype=np.float64)
    return np.zeros_like(x)


@dataclass(frozen=True)
class _Pair:
    grouping: str
    src: str
    dst: str  # external IP, or the TLS/HTTP name for the name grouping
    outbound: int
    inbound: int
    connections: int
    first: float
    last: float
    uids: list[str]


def thresholds(cfg: ExfilConfig) -> dict[str, MetricValue]:
    return {
        "min_outbound_bytes": cfg.min_outbound_bytes,
        "min_modified_z": cfg.min_modified_z,
        "min_out_in_ratio": cfg.min_out_in_ratio,
        "weak_baseline_min_pairs": cfg.weak_baseline_min_pairs,
    }


def _pairs(grouping: str, frame: pd.DataFrame, key: str) -> list[_Pair]:
    out: list[_Pair] = []
    if frame.empty:
        return out
    times = epoch_seconds(frame["ts"])
    ends = times + frame["duration"].fillna(0.0).to_numpy(dtype=np.float64)
    sent = frame["orig_bytes"].fillna(0).to_numpy(dtype=np.int64)
    received = frame["resp_bytes"].fillna(0).to_numpy(dtype=np.int64)
    uids = frame["uid"].astype(str).to_numpy(dtype=object)
    for (src, dst), idx in group_indices(frame, ["orig_h", key]):
        out.append(
            _Pair(
                grouping,
                str(src),
                str(dst),
                int(sent[idx].sum()),
                int(received[idx].sum()),
                len(idx),
                float(times[idx].min()),
                float(ends[idx].max()),
                [str(u) for u in uids[idx]],
            )
        )
    return out


class ExfilDetector:
    detector_id = "DET-EXFIL"
    version = "1.0.0"

    def run(self, inp: DetectorInput) -> DetectorOutput:
        out = DetectorOutput()
        conn = inp.tables.conn
        conn = conn[conn["orig_h"].notna() & conn["resp_h"].notna()]
        if conn.empty:
            return out
        zone = inp.network.classify_series
        conn = conn[(zone(conn["orig_h"]) == "internal") & (zone(conn["resp_h"]) == "external")]
        if conn.empty:
            return out
        conn = conn.sort_values(["ts", "uid"], kind="stable").reset_index(drop=True)

        ip_findings = self._grouping(inp, out, _pairs("ip", conn, "resp_h"), None)
        covered: dict[str, set[str]] = {}
        for pair in ip_findings:
            covered.setdefault(pair.src, set()).update(pair.uids)

        named = pd.concat(
            [
                inp.tables.ssl[["uid", "server_name"]].rename(columns={"server_name": "name"}),
                inp.tables.http[["uid", "host"]].rename(columns={"host": "name"}),
            ],
            ignore_index=True,
        )
        named = named[named["name"].notna() & named["uid"].notna()]
        if not named.empty:
            named = named.assign(name=named["name"].astype(str).str.lower().str.rstrip("."))
            named = named[named["name"] != ""].drop_duplicates(["uid", "name"])
            by_name = conn.merge(named, on="uid", how="inner").sort_values(
                ["ts", "uid"], kind="stable"
            )
            self._grouping(inp, out, _pairs("name", by_name, "name"), covered)
        return out

    def _grouping(
        self,
        inp: DetectorInput,
        out: DetectorOutput,
        pairs: list[_Pair],
        covered_by: dict[str, set[str]] | None,
    ) -> list[_Pair]:
        cfg = inp.config.exfil
        if not pairs:
            return []
        x = np.log1p(np.array([p.outbound for p in pairs], dtype=np.float64))
        weak = len(pairs) < cfg.weak_baseline_min_pairs
        z = None if weak else modified_z(x)
        backup = set(inp.network.known_hosts.backup_servers)
        fired: list[_Pair] = []
        for i, pair in enumerate(pairs):
            ratio = pair.outbound / max(pair.inbound, 1)
            if pair.outbound < cfg.min_outbound_bytes:
                continue
            if z is not None and (z[i] < cfg.min_modified_z or ratio < cfg.min_out_in_ratio):
                continue
            if pair.grouping == "ip" and pair.dst in backup:
                out.suppressed["backup_server"] += 1
                continue
            if covered_by is not None and set(pair.uids) <= covered_by.get(pair.src, set()):
                continue  # the IP grouping already reports these connections
            confidence: Confidence = "low" if weak else "high"
            out.findings.append(
                self._finding(
                    inp, pair, ratio, None if z is None else float(z[i]), len(pairs), confidence
                )
            )
            fired.append(pair)
        return fired

    def _finding(
        self,
        inp: DetectorInput,
        pair: _Pair,
        ratio: float,
        z: float | None,
        population: int,
        confidence: Confidence,
    ) -> Finding:
        return make_finding(
            inp,
            detector_id=self.detector_id,
            version=self.version,
            type_="EXFIL",
            primary=pair.src,
            secondary=[pair.dst],
            start=pair.first,
            end=pair.last,
            metrics={
                "grouping": pair.grouping,
                "outbound_bytes": pair.outbound,
                "inbound_bytes": pair.inbound,
                "out_in_ratio": round(ratio, 4),
                "modified_z": None if z is None else round(z, 4),
                "pairs_in_population": population,
                "weak_baseline": z is None,
                "connections": pair.connections,
            },
            thresholds=thresholds(inp.config.exfil),
            confidence=confidence,
            benign_causes=BENIGN_CAUSES,
            uids=pair.uids,
        )


DETECTOR = ExfilDetector()
