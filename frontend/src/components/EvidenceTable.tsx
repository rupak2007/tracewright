import type { EvidenceOut } from "../api/client";
import { fieldsText, formatTime } from "../lib/format";

interface Props {
  items: EvidenceOut[];
  total: number;
  onLoadMore?: () => void;
  loading?: boolean;
}

/**
 * Evidence rows with their stable E-n IDs (the anchors citation chips scroll to). Every value comes
 * from the capture and is attacker-controlled, so it is rendered ONLY as a React text node.
 */
export function EvidenceTable({ items, total, onLoadMore, loading }: Props) {
  return (
    <section aria-label="Evidence">
      <table className="evidence">
        <caption>
          Evidence ({items.length} of {total} shown)
        </caption>
        <thead>
          <tr>
            <th scope="col">ID</th>
            <th scope="col">Kind</th>
            <th scope="col">Time</th>
            <th scope="col">Values</th>
          </tr>
        </thead>
        <tbody>
          {items.map((e) => (
            <tr key={e.local_id} id={e.local_id} tabIndex={-1}>
              <th scope="row">{e.local_id}</th>
              <td>{e.kind}</td>
              <td>{formatTime(e.ts)}</td>
              <td className="fields">{fieldsText(e.fields)}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {items.length < total && onLoadMore ? (
        <button type="button" onClick={onLoadMore} disabled={loading}>
          {loading ? "Loading…" : `Show more evidence (${total - items.length} left)`}
        </button>
      ) : null}
    </section>
  );
}
