# ADR-003 — No vector RAG; knowledge is looked up by ID

| Field | Value |
|---|---|
| Status | Accepted |
| Date | 2026-10-04 |
| Phase | P0 |
| Source | COUNCIL_REVIEW decision D6; architecture §11–12; PRD §7, §12 |

## Context
The system needs to show ATT&CK technique context and verification guidance next to findings, and optionally give that context to an LLM. The knowledge set is small (the handful of techniques the five detectors map to, plus five playbooks) and its keys are known at detection time.

## Decision
- Knowledge is addressed by key: finding type → technique IDs (`config/attack_mapping.yaml`) → generated cards (`K-T1046`); detector ID → playbook (`K-PB-DET-SCAN`).
- No embeddings, similarity search, or vector database. LangChain/LlamaIndex-style frameworks are not used.
- Cards are generated from a pinned ATT&CK STIX bundle (version and SHA-256 in `config/attack.yaml`); mapping IDs are validated at worker startup and in tests (no revoked/deprecated techniques).
- ATT&CK wording is "consistent with", never attribution. Anomaly findings get no mapping.
- Free-form chat is out of the MVP; the stretch feature S1 would reuse the same pack and cards, still without retrieval.

## Alternatives considered
| Option | Why rejected |
|---|---|
| Vector store + embeddings over ATT&CK | Adds a way to retrieve the wrong document for a lookup that is exact by construction |
| LLM-generated technique mapping | Not auditable or reproducible; violates "mapping is a versioned, validated table" |

## Consequences
- Retrieval is deterministic and unit-testable: every mapping ID must exist in the pinned bundle.
- Mapping changes are reviewed as config changes with a bundle version bump.
- If a future requirement genuinely needs similarity search, it requires a new ADR with measured evidence.
