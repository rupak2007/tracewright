import type { FindingOut } from "../api/client";

/** One "why this fired" bar: a measured value against the threshold the detector applied. */
export interface MetricBar {
  label: string;
  value: number;
  threshold: number;
  /** true when meeting the threshold is what makes the rule fire (always, for the documented rules) */
  atLeast: boolean;
  metricKey: string;
  thresholdKey: string;
}

const PAIRS: Record<string, [metric: string, threshold: string, label: string][]> = {
  SCAN: [
    ["distinct_dst_ports", "vertical_ports", "Distinct destination ports (vertical)"],
    ["distinct_dst_hosts", "horizontal_hosts", "Distinct destination hosts (horizontal)"],
    ["failed_share", "high_failed_share", "Failed-connection share (high confidence)"],
  ],
  BRUTE: [
    ["failures_observed", "ftp_failures", "Observed failures (FTP rule)"],
    ["connections", "login_min_connections", "Short connections (SSH/RDP/Telnet rule)"],
  ],
  DNSTUN: [
    ["unique_subdomains", "min_unique_subdomains", "Unique subdomains"],
    ["mean_label_entropy", "min_mean_entropy", "Mean label entropy (bits/char)"],
    ["mean_subdomain_len", "min_mean_subdomain_len", "Mean subdomain length"],
    ["txt_null_share", "txt_null_share", "TXT/NULL share"],
  ],
  BEACON: [
    ["beacon_score", "min_score", "Beacon score"],
    ["events", "min_events", "Events"],
  ],
  EXFIL: [
    ["outbound_bytes", "min_outbound_bytes", "Outbound bytes"],
    ["modified_z", "min_modified_z", "Modified z-score"],
    ["out_in_ratio", "min_out_in_ratio", "Outbound/inbound ratio"],
  ],
};

function num(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

/** Pairs a finding's metrics with the thresholds stored beside them; skips anything missing. */
export function metricBars(finding: Pick<FindingOut, "type" | "metrics" | "thresholds">): MetricBar[] {
  const bars: MetricBar[] = [];
  for (const [metricKey, thresholdKey, label] of PAIRS[finding.type] ?? []) {
    const value = num(finding.metrics[metricKey]);
    const threshold = num(finding.thresholds[thresholdKey]);
    if (value === null || threshold === null) continue;
    // the BRUTE and DNSTUN rules compare different thresholds depending on the service
    if (finding.type === "BRUTE" && metricKey === "failures_observed") {
      const http = num(finding.thresholds["http_failures"]);
      const service = finding.metrics["service"];
      bars.push({
        label: service === "http" ? "Observed failures (HTTP rule)" : label,
        value,
        threshold: service === "http" && http !== null ? http : threshold,
        atLeast: true,
        metricKey,
        thresholdKey: service === "http" ? "http_failures" : thresholdKey,
      });
      continue;
    }
    bars.push({ label, value, threshold, atLeast: true, metricKey, thresholdKey });
  }
  return bars;
}

/** Bar fill as a share of the larger of value and threshold (the threshold marks where the rule fires). */
export function barShares(bar: MetricBar): { value: number; threshold: number } {
  const top = Math.max(bar.value, bar.threshold, Number.MIN_VALUE);
  return { value: (bar.value / top) * 100, threshold: (bar.threshold / top) * 100 };
}
