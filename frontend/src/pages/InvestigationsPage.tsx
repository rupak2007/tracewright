import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";

import { type InvestigationSummary, api, queryKeys } from "../api/client";
import { StatusBadge } from "../components/Badges";
import { UploadDropzone } from "../components/UploadDropzone";
import { formatBytes, formatTime } from "../lib/format";

export function InvestigationsPage() {
  const list = useQuery({
    queryKey: queryKeys.investigations,
    queryFn: () => api<InvestigationSummary[]>("/investigations"),
    refetchInterval: (q) =>
      q.state.data?.some((i) => i.status === "queued" || i.status === "running") ? 2000 : 15000,
  });
  return (
    <>
      <h1>Investigations</h1>
      <UploadDropzone />
      <section aria-labelledby="inv-list">
        <h2 id="inv-list">Past and running analyses</h2>
        {list.isPending ? <p>Loading…</p> : null}
        {list.isError ? <p className="error">Could not load investigations. Is the API reachable?</p> : null}
        {list.data && list.data.length === 0 ? <p className="muted">Nothing yet: upload a capture above.</p> : null}
        {list.data && list.data.length > 0 ? (
          <table>
            <thead>
              <tr>
                <th scope="col">Capture</th>
                <th scope="col">Status</th>
                <th scope="col">Incidents</th>
                <th scope="col">Size</th>
                <th scope="col">Uploaded</th>
              </tr>
            </thead>
            <tbody>
              {list.data.map((i) => (
                <tr key={i.id}>
                  <th scope="row">
                    <Link to={`/investigations/${i.id}`}>{i.original_name || i.id}</Link>
                  </th>
                  <td>
                    <StatusBadge status={i.status} stage={i.stage} />
                  </td>
                  <td>{i.status === "completed" ? i.incident_count : "…"}</td>
                  <td>{formatBytes(i.size_bytes)}</td>
                  <td>{formatTime(i.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : null}
      </section>
    </>
  );
}
