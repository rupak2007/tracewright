# ADR-004 — Residual anomaly triage is the only ML component, gated by G1

| Field | Value |
|---|---|
| Status | Accepted |
| Date | 2026-10-04 |
| Phase | P0 (decision recorded before any detection code exists) |
| Source | COUNCIL_REVIEW decisions D4, D5; PRD §11; architecture §8, §20.3 |

## Context
The five primary detectors (DET-SCAN, DET-BRUTE, DET-DNSTUN, DET-BEACON, DET-EXFIL) are deterministic rules over statistics, and are described that way everywhere. They cover named behaviours only. An open question is whether multivariate unsupervised scoring can surface useful *unexplained* host behaviour better than simple univariate robust statistics.

## Decision
- Residual anomaly triage is the **only** ML component. Candidates: `iforest` (scikit-learn Isolation Forest) vs `robust_z` (max absolute modified z-score); random ranking is the floor.
- Input: entity-windows (internal host × 5 min), 16 log-scaled features, fitted **only on rule-unexplained windows**.
- Output: ranked scores, top-3 deviating features, at most 10 promoted low-severity `UNEXPLAINED_ANOMALY` findings. Never mapped to ATT&CK; always worded "unusual relative to this capture".
- **Gate G1 is pre-declared** and evaluated once on the held-out-family test split (rule copied verbatim in `eval/PROTOCOL.md`, source PRD §11):
  - Ship `iforest` if its precision@10 exceeds `robust_z` by ≥ 0.10 absolute, the 95% bootstrap CI (over captures) of the difference excludes 0, and its promoted-window rate on benign captures is ≤ 1%.
  - Otherwise ship `robust_z` if its recall@10 of held-out episodes is ≥ 0.5 and its benign promoted rate is ≤ 1%.
  - Otherwise ship with anomaly triage `off` and document the negative result.
- The gate's outcome ships, whatever it is. No re-tuning on test, no feature additions, no test-set edits to change it (instruction.md §3.8).

## Alternatives considered
| Option | Why rejected |
|---|---|
| Supervised attack classifier | Non-goal (PRD §7); lab data would make it measure the lab, not the world |
| Deep-learning anomaly detector | No justification at this data scale; adds heavy dependencies |
| Ship Isolation Forest unconditionally | Would present ML as valuable without evidence |

## Consequences
- `ANOMALY_SCORER` is set by the G1 decision record (`eval/decisions/G1.md`, P5), not by preference.
- The `robust_z` scorer and `baseline-rules-v1` results are kept permanently as the comparison baseline.
- A negative or `off` outcome is a valid, reportable result.
