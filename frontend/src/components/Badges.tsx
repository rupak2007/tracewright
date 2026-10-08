import { SEVERITY_SYMBOL } from "../lib/format";

/** Severity is shown as text AND a shape, never by colour alone. */
export function SeverityBadge({ label, score }: { label: string; score?: number }) {
  return (
    <span className={`badge sev-${label}`} title={score === undefined ? undefined : `score ${score}`}>
      <span aria-hidden="true">{SEVERITY_SYMBOL[label] ?? "◇"}</span> {label}
      {score === undefined ? null : <span className="muted"> ({score})</span>}
    </span>
  );
}

export function ConfidenceBadge({ level }: { level: string }) {
  return <span className={`badge conf-${level}`}>{level} confidence</span>;
}

const STATUS_TEXT: Record<string, string> = {
  queued: "⏳ queued",
  running: "⚙ running",
  completed: "✔ completed",
  failed: "✖ failed",
};

export function StatusBadge({ status, stage }: { status: string; stage?: string }) {
  return (
    <span className={`badge status-${status}`}>
      {STATUS_TEXT[status] ?? status}
      {status === "running" && stage ? ` (${stage})` : null}
    </span>
  );
}
