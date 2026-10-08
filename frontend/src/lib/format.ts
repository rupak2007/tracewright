const UTC = { timeZone: "UTC", hour12: false } as const;

export function formatTime(iso: string | null | undefined): string {
  if (!iso) return "n/a";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "n/a";
  return `${date.toLocaleString("en-GB", { ...UTC, dateStyle: "medium", timeStyle: "medium" })} UTC`;
}

export function formatDuration(startIso: string, endIso: string): string {
  const seconds = Math.max(0, (new Date(endIso).getTime() - new Date(startIso).getTime()) / 1000);
  if (seconds < 90) return `${Math.round(seconds)} s`;
  if (seconds < 5400) return `${(seconds / 60).toFixed(1)} min`;
  return `${(seconds / 3600).toFixed(1)} h`;
}

export function formatBytes(value: number): string {
  if (value < 1024) return `${value} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let size = value / 1024;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${size.toFixed(1)} ${units[unit]}`;
}

export function formatNumber(value: unknown): string {
  if (typeof value === "number") {
    return Number.isInteger(value) ? value.toLocaleString("en-GB") : String(Number(value.toFixed(4)));
  }
  if (value === null || value === undefined) return "n/a";
  return String(value);
}

/** Evidence fields as `key=value` text (strings stay strings: callers render them as text nodes). */
export function fieldsText(fields: Record<string, unknown>): string {
  return Object.entries(fields)
    .filter(([, value]) => value !== null && value !== undefined)
    .map(([key, value]) => `${key}=${typeof value === "object" ? JSON.stringify(value) : String(value)}`)
    .join(", ");
}

export const SEVERITY_SYMBOL: Record<string, string> = {
  low: "▽",
  medium: "◇",
  high: "△",
  critical: "▲",
};
