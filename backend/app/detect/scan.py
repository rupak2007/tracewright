"""DET-SCAN: port and host scanning (PRD §10, architecture §7.1).

Unit: source host. Sliding closed windows over each source's TCP/UDP connection starts:
  vertical        >= vertical_ports distinct dst ports on ONE host within window_short_s
  horizontal      >= horizontal_hosts distinct dst hosts on ONE port within window_short_s
  slow_vertical   >= slow_vertical_ports distinct dst ports on ONE host within window_long_s
                  (only reported when the same source/host pair did not already fire `vertical`)
Confidence is high when the failed-connection share of the window is >= high_failed_share,
medium otherwise (the documents define only the high condition).
One finding per (source, scan type, target): the earliest window with the most distinct values.
"""

import numpy as np

from app.detect.base import (
    Confidence,
    DetectorInput,
    DetectorOutput,
    Finding,
    MetricValue,
    epoch_seconds,
    make_finding,
)
from app.detect.config import ScanConfig
from app.detect.windows import max_distinct_window

BENIGN_CAUSES = (
    "vulnerability scanners",
    "monitoring systems",
    "NAT gateways",
    "peer-to-peer applications",
)
MAX_SECONDARY = 50  # targets listed on a horizontal finding; the metric carries the true count


def thresholds(cfg: ScanConfig) -> dict[str, MetricValue]:
    return {
        "window_short_s": cfg.window_short_s,
        "window_long_s": cfg.window_long_s,
        "vertical_ports": cfg.vertical_ports,
        "horizontal_hosts": cfg.horizontal_hosts,
        "slow_vertical_ports": cfg.slow_vertical_ports,
        "high_failed_share": cfg.high_failed_share,
        "failed_states": ",".join(cfg.failed_states),
    }


class ScanDetector:
    detector_id = "DET-SCAN"
    version = "1.0.0"

    def run(self, inp: DetectorInput) -> DetectorOutput:
        cfg = inp.config.scan
        out = DetectorOutput()
        conn = inp.tables.conn
        conn = conn[
            conn["proto"].isin(["tcp", "udp"])
            & conn["orig_h"].notna()
            & conn["resp_h"].notna()
            & conn["resp_p"].notna()
        ]
        if conn.empty:
            return out
        conn = conn.sort_values(["ts", "uid"], kind="stable").reset_index(drop=True)
        times = epoch_seconds(conn["ts"])
        ends = times + conn["duration"].fillna(0.0).to_numpy(dtype=np.float64)
        ports = conn["resp_p"].to_numpy(dtype=np.int64)
        dsts = conn["resp_h"].to_numpy(dtype=object)
        failed = conn["conn_state"].isin(cfg.failed_states).to_numpy(dtype=bool)
        uids = conn["uid"].to_numpy(dtype=object)
        scanners = set(inp.network.known_hosts.scanners)

        def emit(
            src: str,
            scan_type: str,
            idx: np.ndarray,
            lo: int,
            hi: int,
            window_s: float,
            secondary: list[str],
            n_ports: int,
            n_hosts: int,
        ) -> None:
            chosen = idx[lo:hi]
            share = float(failed[chosen].mean())
            confidence: Confidence = "high" if share >= cfg.high_failed_share else "medium"
            finding = make_finding(
                inp,
                detector_id=self.detector_id,
                version=self.version,
                type_="SCAN",
                primary=src,
                secondary=secondary,
                start=float(times[chosen[0]]),
                end=float(ends[chosen].max()),
                metrics={
                    "scan_type": scan_type,
                    "distinct_dst_ports": n_ports,
                    "distinct_dst_hosts": n_hosts,
                    "failed_share": round(share, 4),
                    "connections": len(chosen),
                    "window_s": window_s,
                },
                thresholds=thresholds(cfg),
                confidence=confidence,
                benign_causes=BENIGN_CAUSES,
                uids=[str(u) for u in uids[chosen]],
            )
            self._add(out, finding, src, scanners)

        # --- vertical / slow vertical: per (src, dst) ---------------------------------------
        pair_ports = conn.groupby(["orig_h", "resp_h"])["resp_p"].nunique()
        candidates = pair_ports[pair_ports >= cfg.vertical_ports].index
        pair_idx = conn.groupby(["orig_h", "resp_h"], sort=True).indices
        for src, dst in candidates:
            idx = pair_idx[(src, dst)]
            fast, lo, hi = max_distinct_window(times[idx], ports[idx].tolist(), cfg.window_short_s)
            if fast >= cfg.vertical_ports:
                emit(src, "vertical", idx, lo, hi, cfg.window_short_s, [dst], fast, 1)
                continue
            slow, lo, hi = max_distinct_window(times[idx], ports[idx].tolist(), cfg.window_long_s)
            if slow >= cfg.slow_vertical_ports:
                emit(src, "slow_vertical", idx, lo, hi, cfg.window_long_s, [dst], slow, 1)

        # --- horizontal: per (src, port) ----------------------------------------------------
        port_hosts = conn.groupby(["orig_h", "resp_p"])["resp_h"].nunique()
        candidates = port_hosts[port_hosts >= cfg.horizontal_hosts].index
        port_idx = conn.groupby(["orig_h", "resp_p"], sort=True).indices
        for src, port in candidates:
            idx = port_idx[(src, port)]
            hosts, lo, hi = max_distinct_window(times[idx], dsts[idx].tolist(), cfg.window_short_s)
            if hosts >= cfg.horizontal_hosts:
                window = idx[lo:hi]
                targets = sorted({str(d) for d in dsts[window]})[:MAX_SECONDARY]
                emit(src, "horizontal", idx, lo, hi, cfg.window_short_s, targets, 1, hosts)
        return out

    @staticmethod
    def _add(out: DetectorOutput, finding: Finding, src: str, scanners: set[str]) -> None:
        if src in scanners:
            out.suppressed["known_scanner"] += 1
        else:
            out.findings.append(finding)


DETECTOR = ScanDetector()
