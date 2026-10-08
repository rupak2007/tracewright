import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useId, useState } from "react";

import {
  ApiError,
  type FeedbackLabel,
  type FindingOut,
  type SliceOut,
  api,
  download,
  post,
  queryKeys,
} from "../api/client";

const LABELS: { value: FeedbackLabel; text: string }[] = [
  { value: "true_positive", text: "True positive" },
  { value: "false_positive", text: "False positive" },
  { value: "expected_benign", text: "Expected / benign" },
];

function message(error: unknown): string {
  return error instanceof ApiError ? `${error.code}: ${error.message}` : "Unexpected error.";
}

export function FeedbackForm({ finding, incidentId }: { finding: FindingOut; incidentId: number }) {
  const client = useQueryClient();
  const noteId = useId();
  const [note, setNote] = useState("");
  const send = useMutation({
    mutationFn: (label: FeedbackLabel) => post(`/findings/${finding.id}/feedback`, { label, note }),
    onSuccess: () => {
      setNote("");
      void client.invalidateQueries({ queryKey: queryKeys.incident(incidentId) });
    },
  });
  return (
    <fieldset className="feedback">
      <legend>Your assessment of {finding.local_id}</legend>
      <label htmlFor={noteId}>Note (optional)</label>
      <input
        id={noteId}
        value={note}
        maxLength={2000}
        onChange={(e) => setNote(e.target.value)}
        placeholder="why?"
      />
      <div className="row">
        {LABELS.map((l) => (
          <button key={l.value} type="button" disabled={send.isPending} onClick={() => send.mutate(l.value)}>
            {l.text}
          </button>
        ))}
      </div>
      <div role="status" aria-live="polite">
        {send.isError ? <span className="error">{message(send.error)}</span> : null}
        {finding.feedback.length > 0 ? (
          <ul className="muted">
            {finding.feedback.map((fb) => (
              <li key={fb.id}>
                Recorded: {fb.label.replace("_", " ")}
                {fb.note ? ` (${fb.note})` : ""}
              </li>
            ))}
          </ul>
        ) : null}
      </div>
    </fieldset>
  );
}

export function SliceControl({ finding }: { finding: FindingOut }) {
  const [sliceId, setSliceId] = useState<number | null>(null);
  const create = useMutation({
    mutationFn: () => post<{ slice_id: number }>(`/findings/${finding.id}/slice`),
    onSuccess: (r) => setSliceId(r.slice_id),
  });
  const status = useQuery({
    queryKey: queryKeys.slice(sliceId ?? 0),
    queryFn: () => api<SliceOut>(`/slices/${sliceId}`),
    enabled: sliceId !== null,
    refetchInterval: (q) =>
      q.state.data && (q.state.data.status === "done" || q.state.data.status === "failed") ? false : 1500,
  });
  const slice = status.data;
  return (
    <div className="slice" role="status" aria-live="polite">
      <button type="button" onClick={() => create.mutate()} disabled={create.isPending || (!!slice && slice.status !== "failed")}>
        Create packet slice (PCAP for Wireshark)
      </button>{" "}
      {create.isError ? <span className="error">{message(create.error)}</span> : null}
      {slice && slice.status !== "done" && slice.status !== "failed" ? <span>Cutting slice… ({slice.status})</span> : null}
      {slice?.status === "failed" ? <span className="error">Slice failed: {slice.error}</span> : null}
      {slice?.status === "done" ? (
        <button type="button" onClick={() => void download(`/slices/${slice.id}/download`, `tracewright-slice-${slice.id}.pcap`)}>
          Download slice ({slice.packets} packets, {slice.size_bytes} bytes)
        </button>
      ) : null}
    </div>
  );
}
