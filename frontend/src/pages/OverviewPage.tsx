import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "react-router-dom";

import {
  type AnomaliesOut,
  ApiError,
  type IncidentSummary,
  type InvestigationDetail,
  api,
  queryKeys,
} from "../api/client";
import { SeverityBadge, StatusBadge } from "../components/Badges";
import { WarningsList } from "../components/Cards";
import { formatBytes, formatDuration, formatNumber, formatTime } from "../lib/format";

function Profile({ detail }: { detail: InvestigationDetail }) {
  const p = (detail.profile ?? {}) as Record<string, unknown>;
  const capture = (p["capture"] ?? {}) as Record<string, unknown>;
  const rows: [string, string][] = [
    ["SHA-256", detail.sha256],
    ["Size", formatBytes(detail.size_bytes)],
    ["Span", capture["duration_s"] === undefined ? "n/a" : `${formatNumber(capture["duration_s"])} s`],
    ["Packets", formatNumber(capture["packets"])],
    ["Connections", formatNumber(p["connections"])],
    ["Internal / external hosts", `${formatNumber(p["internal_hosts"])} / ${formatNumber(p["external_hosts"])}`],
    ["DNS queries", formatNumber(p["dns_queries"])],
    ["Zeek", String(p["zeek_version"] ?? "n/a")],
  ];
  return (
    <table className="kv">
      <caption>Capture profile</caption>
      <tbody>
        {rows.map(([k, v]) => (
          <tr key={k}>
            <th scope="row">{k}</th>
            <td>{v}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function Anomalies({ id }: { id: string }) {
  const q = useQuery({ queryKey: queryKeys.anomalies(id), queryFn: () => api<AnomaliesOut>(`/investigations/${id}/anomalies`) });
  if (!q.data) return null;
  const status = String(q.data.summary["status"] ?? "off");
  return (
    <section aria-labelledby="anom-h">
      <h2 id="anom-h">Anomalies</h2>
      <p className="muted">Unusual relative to this capture, not necessarily malicious. Never mapped to ATT&amp;CK.</p>
      {status === "off" ? <p>Anomaly triage is switched off in this deployment (gate G1 not run).</p> : null}
      {status === "skipped" ? <p>Anomaly triage was skipped: {String(q.data.summary["reason"] ?? "")}.</p> : null}
      {q.data.promoted_findings.length > 0 ? (
        <ul>
          {q.data.promoted_findings.map((f) => (
            <li key={f.id}>
              {f.local_id} {f.primary_entity}: {formatTime(f.start_ts)} (score {formatNumber(f.metrics["score"])})
            </li>
          ))}
        </ul>
      ) : null}
      {q.data.scored_windows.length > 0 ? (
        <table>
          <caption>Top scored windows</caption>
          <thead>
            <tr>
              <th scope="col">Rank</th>
              <th scope="col">Host</th>
              <th scope="col">Window start</th>
              <th scope="col">Score</th>
              <th scope="col">Rule-explained</th>
            </tr>
          </thead>
          <tbody>
            {q.data.scored_windows.slice(0, 10).map((w) => (
              <tr key={`${String(w["host"])}-${String(w["window_start"])}`}>
                <td>{formatNumber(w["rank"])}</td>
                <td>{String(w["host"])}</td>
                <td>{formatTime(String(w["window_start"]))}</td>
                <td>{formatNumber(w["score"])}</td>
                <td>{w["rule_explained"] ? "yes" : "no"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}
    </section>
  );
}

export function OverviewPage() {
  const { id = "" } = useParams();
  const client = useQueryClient();
  const navigate = useNavigate();
  const detail = useQuery({
    queryKey: queryKeys.investigation(id),
    queryFn: () => api<InvestigationDetail>(`/investigations/${id}`),
    refetchInterval: (q) => (q.state.data && (q.state.data.status === "queued" || q.state.data.status === "running") ? 1500 : false),
  });
  const done = detail.data?.status === "completed";
  const incidents = useQuery({
    queryKey: queryKeys.incidents(id),
    queryFn: () => api<IncidentSummary[]>(`/investigations/${id}/incidents`),
    enabled: done,
  });
  const remove = useMutation({
    mutationFn: () => api(`/investigations/${id}`, { method: "DELETE" }),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: queryKeys.investigations });
      navigate("/");
    },
  });

  if (detail.isPending) return <p>Loading…</p>;
  if (detail.isError)
    return (
      <p className="error">
        {detail.error instanceof ApiError && detail.error.status === 404
          ? "This investigation does not exist (it may have been deleted)."
          : "Could not load the investigation."}
      </p>
    );
  const d = detail.data;
  return (
    <>
      <p>
        <Link to="/">← All investigations</Link>
      </p>
      <h1>{d.original_name || d.id}</h1>
      <p role="status" aria-live="polite">
        <StatusBadge status={d.status} stage={d.stage} />{" "}
        {d.status === "failed" ? <span className="error">{d.error_code}: {d.error_message}</span> : null}
        {d.status === "queued" || d.status === "running" ? " Analysing; this page updates by itself." : null}
      </p>
      {done ? (
        <>
          <section aria-labelledby="inc-h">
            <h2 id="inc-h">Incidents ({incidents.data?.length ?? "…"})</h2>
            {incidents.data && incidents.data.length === 0 ? (
              <p>No incidents: no detector fired on this capture.</p>
            ) : null}
            {incidents.data && incidents.data.length > 0 ? (
              <table>
                <thead>
                  <tr>
                    <th scope="col">Rank</th>
                    <th scope="col">Incident</th>
                    <th scope="col">Severity</th>
                    <th scope="col">Entity</th>
                    <th scope="col">Types</th>
                    <th scope="col">Span</th>
                    <th scope="col">Links</th>
                  </tr>
                </thead>
                <tbody>
                  {incidents.data.map((i) => (
                    <tr key={i.id}>
                      <td>{i.rank}</td>
                      <th scope="row">
                        <Link to={`/incidents/${i.id}`}>{i.local_id}</Link>
                      </th>
                      <td>
                        <SeverityBadge label={i.severity_label} score={i.severity_score} />
                      </td>
                      <td>{i.primary_entity}</td>
                      <td>{i.types.join(", ")}</td>
                      <td>{formatDuration(i.start_ts, i.end_ts)}</td>
                      <td>{i.links.map((l) => l.type.replaceAll("_", " ").toLowerCase()).join("; ") || "–"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : null}
            <p className="muted">Severity is an ordering aid, not a risk score.</p>
          </section>
          <section aria-labelledby="prof-h">
            <h2 id="prof-h">Capture</h2>
            <Profile detail={d} />
            <h3>Data-quality warnings</h3>
            <WarningsList warnings={(d.warnings ?? []) as { code?: unknown; message?: unknown }[]} />
          </section>
          <Anomalies id={id} />
        </>
      ) : null}
      <p>
        <button
          type="button"
          disabled={remove.isPending || d.status === "running"}
          onClick={() => {
            if (window.confirm("Delete this investigation and all its data?")) remove.mutate();
          }}
        >
          Delete investigation
        </button>
      </p>
    </>
  );
}
