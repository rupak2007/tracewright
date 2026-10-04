# ADR-005 — LLM narrative is optional, validated, and gated by G2

| Field | Value |
|---|---|
| Status | Accepted |
| Date | 2026-10-04 |
| Phase | P0 (decision recorded before any LLM code exists) |
| Source | COUNCIL_REVIEW decisions D7, D8; PRD §12–13, SEC-03–05; architecture §13 |

## Context
Template summaries are faithful per finding but do not synthesise. An LLM narrative might save analyst time, but it can invent evidence, over-state certainty, be steered by attacker-controlled capture strings, and leak data to third parties.

## Decision
- Template summaries are always generated (stage S8); they are the baseline and the fallback. The product is fully functional with `LLM_PROVIDER=none` (the default).
- The narrative is generated in the **API** (never the worker) from a **pseudonymised evidence pack** (`H<n>`/`X<n>`/`D<n>`); attacker-controlled strings (DNS names, URIs, user agents, SNI, certificate fields) and raw packets/payloads never enter a prompt. The model has no tools, no network and no database access; temperature 0.
- Output is a Pydantic-validated JSON schema separating `observed`, `inferences` (confidence + ≥ 1 benign alternative) and `recommendations`; a deterministic validator checks IDs, entities/numbers, banned verdict language and pseudonym leaks. Failure → one repair attempt → template fallback with the raw output and reasons stored. Unvalidated text is never shown.
- External providers (`openai_compatible`, `anthropic`) require explicit configuration and API keys from environment variables.
- **Gate G2 is pre-declared** (rule copied verbatim in `eval/PROTOCOL.md`, source PRD §12): the narrative ships enabled-by-configuration only if, on the evaluation set, validator pass rate ≥ 90% (≤ 1 repair attempt); manual audit shows observed-statement support ≥ 95%, unsupported inferences ≤ 5%, citation correctness ≥ 90%; and raters prefer it over the template in ≥ 60% of blind pairwise comparisons. Otherwise templates remain the only summary and the result is documented.

## Alternatives considered
| Option | Why rejected |
|---|---|
| LLM on raw evidence or packet text | Prompt-injection and data-exposure risk (SEC-03/04) |
| Chat interface in the MVP | Non-goal; unbounded surface with no grounding guarantee |
| Narrative on by default | No evidence yet that it is faithful or preferred |

## Consequences
- P8 is the last implementation phase before hardening and can be cut without loss of core function ("If the schedule slips", plan.md).
- `eval/decisions/G2.md` sets the default provider configuration; a failed gate is documented, not worked around.
- Residual risk: plausible-but-weak inferences can pass the validator; narratives are labelled machine-generated with their validation status.
