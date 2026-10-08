import { useInfiniteQuery, useQueries, useQuery } from "@tanstack/react-query";
import { useId, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";

import { type EvidencePage, type IncidentDetail, api, download, queryKeys } from "../api/client";
import { SeverityBadge } from "../components/Badges";
import { TechniqueCards } from "../components/Cards";
import { EvidenceTable } from "../components/EvidenceTable";
import { FeedbackForm, SliceControl } from "../components/FindingActions";
import { FindingCard } from "../components/FindingCard";
import { NarrativePanel } from "../components/Narrative";
import { SummaryPanel } from "../components/SummaryPanel";
import { Timeline, lanesFor } from "../components/Timeline";
import { formatDuration, formatTime } from "../lib/format";

const PAGE = 50;

function Evidence({ incident }: { incident: IncidentDetail }) {
  const [finding, setFinding] = useState<number | undefined>(undefined);
  const selectId = useId();
  const pages = useInfiniteQuery({
    queryKey: queryKeys.evidence(incident.id, finding),
    queryFn: ({ pageParam }) =>
      api<EvidencePage>(
        `/incidents/${incident.id}/evidence?limit=${PAGE}&offset=${pageParam}${finding ? `&finding_id=${finding}` : ""}`,
      ),
    initialPageParam: 0,
    getNextPageParam: (last) => (last.offset + last.items.length < last.total ? last.offset + PAGE : undefined),
  });
  const items = pages.data?.pages.flatMap((p) => p.items) ?? [];
  const total = pages.data?.pages[0]?.total ?? 0;
  return (
    <section aria-labelledby="ev-h">
      <h2 id="ev-h">Evidence</h2>
      <label htmlFor={selectId}>Show evidence of </label>
      <select
        id={selectId}
        value={finding ?? ""}
        onChange={(e) => setFinding(e.target.value ? Number(e.target.value) : undefined)}
      >
        <option value="">all findings</option>
        {incident.findings.map((f) => (
          <option key={f.id} value={f.id}>
            {f.local_id} {f.type}
          </option>
        ))}
      </select>
      {pages.isPending ? <p>Loading evidence…</p> : null}
      {pages.isError ? <p className="error">Could not load evidence.</p> : null}
      {pages.data ? (
        <EvidenceTable
          items={items}
          total={total}
          loading={pages.isFetchingNextPage}
          onLoadMore={pages.hasNextPage ? () => void pages.fetchNextPage() : undefined}
        />
      ) : null}
    </section>
  );
}

export function IncidentPage() {
  const { id = "" } = useParams();
  const numeric = Number(id);
  const incident = useQuery({
    queryKey: queryKeys.incident(numeric),
    queryFn: () => api<IncidentDetail>(`/incidents/${numeric}`),
    enabled: Number.isInteger(numeric),
  });
  const linkedIds = useMemo(() => {
    const own = incident.data?.id;
    const ids = new Set<number>();
    for (const l of incident.data?.links ?? []) {
      for (const other of [l.from_incident, l.to_incident]) if (other !== own) ids.add(other);
    }
    return [...ids].sort((a, b) => a - b);
  }, [incident.data]);
  const linked = useQueries({
    queries: linkedIds.map((other) => ({
      queryKey: queryKeys.incident(other),
      queryFn: () => api<IncidentDetail>(`/incidents/${other}`),
    })),
  });

  if (incident.isPending) return <p>Loading…</p>;
  if (incident.isError) return <p className="error">Could not load this incident.</p>;
  const inc = incident.data;
  const lanes = lanesFor(
    [inc, ...linked.flatMap((q) => (q.data ? [q.data] : []))].map((i) => ({
      local_id: i.local_id,
      findings: i.findings,
    })),
    inc.local_id,
  );
  return (
    <>
      <p>
        <Link to="/">← Investigations</Link>
      </p>
      <h1>
        Incident {inc.local_id} <SeverityBadge label={inc.severity_label} score={inc.severity_score} />
      </h1>
      <p>
        {inc.primary_entity} · {formatTime(inc.start_ts)} · {formatDuration(inc.start_ts, inc.end_ts)} ·{" "}
        {inc.types.join(", ")}
      </p>
      <p className="row">
        <button type="button" onClick={() => void download(`/incidents/${inc.id}/report?format=md`, `tracewright-${inc.local_id}.md`)}>
          Export report (Markdown)
        </button>
        <button type="button" onClick={() => void download(`/incidents/${inc.id}/report?format=html`, `tracewright-${inc.local_id}.html`)}>
          Export report (HTML)
        </button>
      </p>
      <SummaryPanel summary={inc.summary} />
      <NarrativePanel incidentId={inc.id} findings={inc.findings} />
      {inc.links.length > 0 ? (
        <section aria-labelledby="links-h">
          <h2 id="links-h">Linked incidents</h2>
          <ul>
            {inc.links.map((l) => {
              const otherId = l.from_incident === inc.id ? l.to_incident : l.from_incident;
              const otherLocal = l.from_incident === inc.id ? l.to_local : l.from_local;
              return (
                <li key={`${l.type}-${l.from_incident}-${l.to_incident}`}>
                  <strong>{l.type.replaceAll("_", " ").toLowerCase()}</strong>: {l.reason} →{" "}
                  <Link to={`/incidents/${otherId}`}>{otherLocal}</Link>
                </li>
              );
            })}
          </ul>
        </section>
      ) : null}
      <section aria-labelledby="story-h">
        <h2 id="story-h">Storyline</h2>
        <Timeline lanes={lanes} />
      </section>
      <section aria-labelledby="find-h">
        <h2 id="find-h">Findings: why each fired</h2>
        {inc.findings.map((f) => (
          <FindingCard
            key={f.id}
            finding={f}
            playbooks={inc.playbooks}
            actions={
              <>
                <SliceControl finding={f} />
                <FeedbackForm finding={f} incidentId={inc.id} />
              </>
            }
          />
        ))}
      </section>
      <Evidence incident={inc} />
      <TechniqueCards cards={inc.cards} />
    </>
  );
}
