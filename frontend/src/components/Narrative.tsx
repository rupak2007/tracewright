import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Fragment } from "react";

import { type FindingOut, type NarrativeOut, api, post, queryKeys } from "../api/client";
import { focusEvidence } from "./SummaryPanel";

const TOKEN = /\b([HXD]\d+)\b/;

type Entities = Record<string, string>;

/** Show the real host/domain behind a pseudonym (the model only ever saw the pseudonym). */
function WithEntities({ text, entities }: { text: string; entities: Entities }) {
  return (
    <>
      {text.split(TOKEN).map((part, i) => {
        const real = TOKEN.test(part) ? entities[part] : undefined;
        if (real === undefined) return <Fragment key={i}>{part}</Fragment>;
        return (
          <span key={i} className="entity" title={`pseudonym ${part} in the evidence pack`}>
            {real}
          </span>
        );
      })}
    </>
  );
}

function Citations({ ids, onCite }: { ids: string[]; onCite: (id: string) => void }) {
  return (
    <span className="chips">
      {ids.map((id) => (
        <button key={id} type="button" className="chip" onClick={() => onCite(id)} aria-label={`Go to ${id}`}>
          {id}
        </button>
      ))}
    </span>
  );
}

/** A validated, labelled narrative. Every claim is shown with the evidence it cites. */
export function NarrativeView({
  narrative,
  onCite,
}: {
  narrative: NarrativeOut & { output: NonNullable<NarrativeOut["output"]> };
  onCite: (id: string) => void;
}) {
  const { output, entities } = narrative;
  return (
    <div>
      <p>
        <span className="badge" aria-label="validated against the evidence">
          ✓ validated against the evidence
        </span>{" "}
        <span className="muted">
          {narrative.label} ({narrative.provider}
          {narrative.model ? ` / ${narrative.model}` : ""})
        </span>
      </p>
      <p>
        <WithEntities text={output.summary} entities={entities} />
      </p>
      <h3>Observed</h3>
      <ul>
        {output.observed.map((o, i) => (
          <li key={i}>
            <WithEntities text={o.statement} entities={entities} /> <Citations ids={o.evidence_ids} onCite={onCite} />
          </li>
        ))}
      </ul>
      <h3>Inferences (hypotheses, not findings)</h3>
      <ul>
        {output.inferences.map((inf, i) => (
          <li key={i}>
            <WithEntities text={inf.statement} entities={entities} /> <em>({inf.confidence} confidence)</em>{" "}
            <Citations ids={[...inf.supporting_ids, ...(inf.knowledge_ids ?? [])]} onCite={onCite} />
            <div className="muted">
              Could also be:{" "}
              {inf.alternative_explanations.map((a, j) => (
                <Fragment key={j}>
                  {j > 0 ? "; " : ""}
                  <WithEntities text={a} entities={entities} />
                </Fragment>
              ))}
            </div>
          </li>
        ))}
      </ul>
      {output.recommendations.length > 0 ? (
        <>
          <h3>Suggested next checks</h3>
          <ul>
            {output.recommendations.map((r, i) => (
              <li key={i}>
                <WithEntities text={r.action} entities={entities} />{" "}
                <Citations ids={r.rationale_ids} onCite={onCite} />
              </li>
            ))}
          </ul>
        </>
      ) : null}
      {output.open_questions.length > 0 ? (
        <>
          <h3>Open questions</h3>
          <ul>
            {output.open_questions.map((q, i) => (
              <li key={i}>
                <WithEntities text={q} entities={entities} />
              </li>
            ))}
          </ul>
        </>
      ) : null}
    </div>
  );
}

const MESSAGES: Record<string, string> = {
  not_requested: "No narrative was requested. The template summary above is the default.",
  unavailable: "No narrative is available (the provider is off, unreachable or too slow). The template summary above is shown.",
  rejected:
    "The generated text did not pass validation and is not shown. The template summary above is shown.",
};

/** Optional LLM narrative: requested explicitly, validated server-side, never required. */
export function NarrativePanel({ incidentId, findings }: { incidentId: number; findings: FindingOut[] }) {
  const queryClient = useQueryClient();
  const key = queryKeys.narrative(incidentId);
  const query = useQuery({
    queryKey: key,
    queryFn: () => api<NarrativeOut>(`/incidents/${incidentId}/narrative`),
    refetchInterval: (q) => (q.state.data?.status === "pending" ? 2000 : false),
  });
  const generate = useMutation({
    mutationFn: () => post<NarrativeOut>(`/incidents/${incidentId}/narrative`),
    onSuccess: (data) => queryClient.setQueryData(key, data),
  });
  const onCite = (id: string) => {
    if (id.startsWith("E-")) return focusEvidence(id);
    const finding = findings.find((f) => f.local_id === id);
    if (finding) document.getElementById(`finding-${finding.id}`)?.scrollIntoView?.({ block: "center" });
  };
  const data = query.data;
  const busy = generate.isPending || data?.status === "pending";
  return (
    <section className="card" aria-labelledby="narrative-h">
      <h2 id="narrative-h">Narrative (optional, machine-generated)</h2>
      {query.isError ? <p className="error">Could not load the narrative state.</p> : null}
      {data?.status === "validated" && data.output ? (
        <NarrativeView narrative={{ ...data, output: data.output }} onCite={onCite} />
      ) : data ? (
        <>
          {data.status === "pending" ? (
            <p role="status">Generating and validating…</p>
          ) : (
            <p className="muted">{MESSAGES[data.status]}</p>
          )}
          {data.status === "rejected" && data.reasons.length > 0 ? (
            <details>
              <summary>Why it was rejected</summary>
              <ul>
                {data.reasons.map((r, i) => (
                  <li key={i}>{r}</li>
                ))}
              </ul>
            </details>
          ) : null}
        </>
      ) : null}
      {data?.status === "unavailable" && data.reasons.length > 0 ? (
        <p className="muted">{data.reasons[0]}</p>
      ) : null}
      <p>
        <button type="button" disabled={busy} onClick={() => generate.mutate()}>
          {data?.status === "validated" ? "Regenerate narrative" : "Generate narrative"}
        </button>
        {generate.isError ? <span className="error"> Could not start generation.</span> : null}
      </p>
    </section>
  );
}
