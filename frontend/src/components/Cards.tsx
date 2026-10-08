export interface TechniqueCard {
  knowledge_id?: unknown;
  technique_id?: unknown;
  name?: unknown;
  description?: unknown;
  tactics?: unknown;
  mitigations?: unknown;
  url?: unknown;
}

const text = (v: unknown): string => (typeof v === "string" ? v : "");
const list = (v: unknown): string[] => (Array.isArray(v) ? v.map(String) : []);

export function TechniqueCards({ cards }: { cards: TechniqueCard[] }) {
  if (cards.length === 0) return null;
  return (
    <section aria-labelledby="attack-h">
      <h2 id="attack-h">ATT&amp;CK technique cards</h2>
      <p className="muted">Mappings are “consistent with”, never attribution.</p>
      {cards.map((c) => (
        <article className="card" key={text(c.technique_id)}>
          <h3>
            {text(c.knowledge_id)} {text(c.name)}
          </h3>
          <p className="muted">Tactics: {list(c.tactics).join(", ") || "n/a"}</p>
          <p>{text(c.description)}</p>
          {list(c.mitigations).length > 0 ? <p>Mitigations: {list(c.mitigations).join("; ")}</p> : null}
          <p className="muted">
            Source: MITRE ATT&amp;CK ({text(c.url).startsWith("https://attack.mitre.org/") ? text(c.url) : "n/a"})
          </p>
        </article>
      ))}
    </section>
  );
}

export function WarningsList({ warnings }: { warnings: { code?: unknown; message?: unknown }[] }) {
  if (warnings.length === 0) return <p className="muted">No data-quality warnings.</p>;
  return (
    <ul className="warnings">
      {warnings.map((w) => (
        <li key={text(w.code)}>
          <strong>{text(w.code)}</strong>: {text(w.message)}
        </li>
      ))}
    </ul>
  );
}
