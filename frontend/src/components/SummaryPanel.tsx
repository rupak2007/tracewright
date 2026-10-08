const CITATION = /(\[E-\d+(?:, E-\d+)*\])/;

/** Scroll to an evidence row and move focus to it (citation chips use this). */
export function focusEvidence(id: string): void {
  const row = document.getElementById(id);
  if (!row) return;
  row.scrollIntoView?.({ block: "center" });
  row.focus();
}

function Sentence({ text }: { text: string }) {
  return (
    <p>
      {text.split(CITATION).map((part, i) => {
        if (!CITATION.test(part)) return part; // plain text node
        const ids = part.slice(1, -1).split(", ");
        return (
          <span key={i} className="chips">
            {ids.map((id) => (
              <button
                key={id}
                type="button"
                className="chip"
                onClick={() => focusEvidence(id)}
                aria-label={`Go to evidence ${id}`}
              >
                {id}
              </button>
            ))}
          </span>
        );
      })}
    </p>
  );
}

/** The deterministic template summary: hedged sentences, each ending in citation chips. */
export function SummaryPanel({ summary }: { summary: string }) {
  const [header, ...sentences] = summary.split("\n");
  return (
    <section className="card" aria-labelledby="summary-h">
      <h2 id="summary-h">Summary (template)</h2>
      <p className="muted">{header}</p>
      {sentences.map((s) => (
        <Sentence key={s} text={s} />
      ))}
    </section>
  );
}
