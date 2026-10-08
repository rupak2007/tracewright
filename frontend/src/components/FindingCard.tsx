import type { ReactNode } from "react";

import type { FindingOut } from "../api/client";
import { formatNumber, formatTime } from "../lib/format";
import { barShares, metricBars } from "../lib/thresholds";
import { ConfidenceBadge } from "./Badges";

function Bar({ label, value, threshold }: { label: string; value: number; threshold: number }) {
  const shares = barShares({ label, value, threshold, atLeast: true, metricKey: "", thresholdKey: "" });
  const met = value >= threshold;
  return (
    <li className="bar">
      <div className="bar-label">
        <span>{label}</span>
        <span>
          measured <strong>{formatNumber(value)}</strong> · threshold {formatNumber(threshold)}{" "}
          <span aria-label={met ? "threshold met" : "threshold not met"}>{met ? "✔" : "✖"}</span>
        </span>
      </div>
      <div
        className="bar-track"
        role="img"
        aria-label={`${label}: ${formatNumber(value)} against threshold ${formatNumber(threshold)}`}
      >
        <div className={`bar-fill ${met ? "met" : "below"}`} style={{ width: `${shares.value}%` }} />
        <div className="bar-threshold" style={{ left: `${shares.threshold}%` }} />
      </div>
    </li>
  );
}

interface Props {
  finding: FindingOut;
  playbooks: string[];
  actions?: ReactNode;
  evidenceId?: string;
}

/** The "why this fired" panel: metric against threshold, confidence, benign causes, ATT&CK refs. */
export function FindingCard({ finding, playbooks, actions, evidenceId }: Props) {
  const bars = metricBars(finding);
  const playbook = playbooks.find((p) => p.endsWith(`DET-${finding.type}`));
  return (
    <article className="card finding" aria-labelledby={`finding-${finding.id}`}>
      <header>
        <h3 id={`finding-${finding.id}`}>
          {finding.local_id} {finding.type}
        </h3>
        <ConfidenceBadge level={finding.confidence} />
      </header>
      <p className="muted">
        {finding.primary_entity}
        {finding.secondary_entities.length > 0 ? ` → ${finding.secondary_entities.join(", ")}` : ""} ·{" "}
        {formatTime(finding.start_ts)} to {formatTime(finding.end_ts)} · detector {finding.detector_id}{" "}
        {finding.detector_version}
        {evidenceId ? ` · measured values: ${evidenceId}` : ""}
      </p>
      {bars.length > 0 ? (
        <ul className="bars">
          {bars.map((b) => (
            <Bar key={b.metricKey} label={b.label} value={b.value} threshold={b.threshold} />
          ))}
        </ul>
      ) : null}
      {finding.techniques.length > 0 ? (
        <p>
          ATT&amp;CK (consistent with, not attribution):{" "}
          {finding.techniques.map((t) => `${t.technique_id} ${t.phrase}`).join("; ")}
        </p>
      ) : null}
      <details>
        <summary>Known benign causes</summary>
        <ul>
          {finding.benign_causes.map((cause) => (
            <li key={String(cause)}>{String(cause)}</li>
          ))}
        </ul>
        {playbook ? <p className="muted">Verification playbook: {playbook}</p> : null}
      </details>
      <details>
        <summary>All measured values and thresholds</summary>
        <div className="two-col">
          <table>
            <caption>Measured</caption>
            <tbody>
              {Object.entries(finding.metrics).map(([k, v]) => (
                <tr key={k}>
                  <th scope="row">{k}</th>
                  <td>{formatNumber(v)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <table>
            <caption>Thresholds applied</caption>
            <tbody>
              {Object.entries(finding.thresholds).map(([k, v]) => (
                <tr key={k}>
                  <th scope="row">{k}</th>
                  <td>{formatNumber(v)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
      {actions}
    </article>
  );
}
