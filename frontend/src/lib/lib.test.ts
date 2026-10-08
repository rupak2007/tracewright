import { describe, expect, it } from "vitest";

import { fieldsText, formatBytes, formatDuration, formatNumber, formatTime } from "./format";
import { barShares, metricBars } from "./thresholds";

const finding = (type: string, metrics: Record<string, unknown>, thresholds: Record<string, unknown>) =>
  ({ type, metrics, thresholds }) as Parameters<typeof metricBars>[0];

const bar = (value: number, threshold: number) => ({
  label: "",
  value,
  threshold,
  atLeast: true,
  metricKey: "",
  thresholdKey: "",
});

describe("metricBars", () => {
  it("pairs each documented metric with the threshold stored beside it", () => {
    const bars = metricBars(
      finding("SCAN", { distinct_dst_ports: 60, failed_share: 0.9 }, { vertical_ports: 50, high_failed_share: 0.6 }),
    );
    expect(bars.map((b) => [b.metricKey, b.value, b.threshold])).toEqual([
      ["distinct_dst_ports", 60, 50],
      ["failed_share", 0.9, 0.6],
    ]);
  });

  it("skips pairs whose metric or threshold is missing, null or not a number", () => {
    expect(metricBars(finding("BEACON", { beacon_score: null, events: "x" }, { min_score: 0.8 }))).toEqual([]);
    expect(metricBars(finding("UNEXPLAINED_ANOMALY", { score: 3 }, {}))).toEqual([]);
  });

  it("uses the HTTP threshold for HTTP brute-force findings", () => {
    const [first] = metricBars(
      finding("BRUTE", { failures_observed: 25, service: "http" }, { ftp_failures: 10, http_failures: 20 }),
    );
    expect(first).toMatchObject({ threshold: 20, thresholdKey: "http_failures" });
    expect(first?.label).toContain("HTTP");
  });

  it("scales bars so the threshold marker and the fill share one axis", () => {
    expect(barShares(bar(100, 50))).toEqual({ value: 100, threshold: 50 });
    expect(barShares(bar(25, 50))).toEqual({ value: 50, threshold: 100 });
    expect(barShares(bar(0, 0)).value).toBe(0);
  });
});

describe("format", () => {
  it("formats numbers, bytes, durations and times without inventing values", () => {
    expect(formatNumber(1234567)).toBe("1,234,567");
    expect(formatNumber(0.123456)).toBe("0.1235");
    expect(formatNumber(null)).toBe("n/a");
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(1536)).toBe("1.5 KiB");
    expect(formatDuration("2026-01-01T00:00:00Z", "2026-01-01T00:00:30Z")).toBe("30 s");
    expect(formatDuration("2026-01-01T00:00:00Z", "2026-01-01T00:10:00Z")).toBe("10.0 min");
    expect(formatTime("2026-01-01T10:00:00Z")).toMatch(/UTC$/);
    expect(formatTime("not a date")).toBe("n/a");
    expect(formatTime(null)).toBe("n/a");
  });

  it("keeps field values as plain text and drops nulls", () => {
    expect(fieldsText({ a: 1, b: null, c: "<b>x</b>", d: { e: 1 } })).toBe('a=1, c=<b>x</b>, d={"e":1}');
  });
});
