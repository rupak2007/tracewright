"""A validated narrative as it appears in a report: labelled, cited, pseudonyms resolved.

Only a narrative that passed the validator is ever turned into a block. The real hosts and domains
behind the pseudonyms are substituted here, after validation, for display; the escaping of the
substituted values is done by the markdown/HTML renderers that call `lines`.
"""

import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field

from app.explain.schema import NarrativeOutput

_TOKEN = re.compile(r"\b([HXD]\d+)\b")
LABEL = "Machine-generated narrative, validated against the evidence; the analyst decides."


@dataclass(frozen=True)
class NarrativeBlock:
    output: NarrativeOutput
    entities: Mapping[str, str] = field(default_factory=dict)
    provider: str = ""
    model: str = ""

    def resolve(self, text: str) -> str:
        return _TOKEN.sub(lambda m: self.entities.get(m.group(1), m.group(1)), text)


def _cite(ids: Sequence[str]) -> str:
    return " [" + ", ".join(ids) + "]"


def lines(block: NarrativeBlock, esc: Callable[[object], str]) -> list[tuple[str, str]]:
    """The narrative as (kind, text) rows, text already resolved and escaped with `esc`.

    kinds: label, summary, h_observed, observed, h_inferences, inference, alternative,
    h_recommendations, recommendation, h_questions, question. Citations are appended as `[E-1]`.
    """
    out = block.output
    rows: list[tuple[str, str]] = [
        (
            "label",
            f"{LABEL} ({esc(block.provider)}{' / ' + esc(block.model) if block.model else ''})",
        ),
        ("summary", esc(block.resolve(out.summary))),
        ("h_observed", "Observed"),
    ]
    rows += [
        ("observed", esc(block.resolve(o.statement)) + _cite(o.evidence_ids)) for o in out.observed
    ]
    rows.append(("h_inferences", "Inferences (hypotheses, not findings)"))
    for inf in out.inferences:
        ids = [*inf.supporting_ids, *inf.knowledge_ids]
        rows.append(
            (
                "inference",
                f"{esc(block.resolve(inf.statement))} ({inf.confidence} confidence)" + _cite(ids),
            )
        )
        rows.append(
            (
                "alternative",
                "Could also be: "
                + "; ".join(esc(block.resolve(a)) for a in inf.alternative_explanations),
            )
        )
    if out.recommendations:
        rows.append(("h_recommendations", "Suggested next checks"))
        rows += [
            ("recommendation", esc(block.resolve(r.action)) + _cite(r.rationale_ids))
            for r in out.recommendations
        ]
    if out.open_questions:
        rows.append(("h_questions", "Open questions"))
        rows += [("question", esc(block.resolve(q))) for q in out.open_questions]
    return rows
