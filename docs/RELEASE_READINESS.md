# Release readiness

Assessed 2026-11-01 against `docs/FINAL_AUDIT.md`. One verdict per use, with the evidence behind it and
what is still missing. "Ready" never means "attack detection is proven": it has not been measured.

| Use | Verdict | Evidence for | What is missing or must be said |
|---|---|---|---|
| **Internal demonstration** | **READY** | stack comes up from a fresh clone; full workflow passes (upload, profile, incidents, evidence, packet slice, reports, narrative fallback, delete); `docs/DEMO.md` script | the demo capture is benign, so it shows triage and benign false positives, not an attack storyline. Say so |
| **Academic project submission** | **READY, provided the evaluation gap is presented as a stated limitation** | 736 tests, 98% coverage, CI green, 9/9 sandbox probes, threat model, protocol written before the detectors, gates declared in advance and reported as "not run", every number traceable to a result file, negative results kept (BEACON 2.00 per hour against 1.0) | an examiner who requires measured detector recall or a decided G1/G2 will not find it. Do not describe the detectors as validated |
| **Public GitHub release** | **READY as a pre-release / release candidate (`v1.0-rc4`), NOT as `v1.0`** | public repo, honest README (its first paragraph states that attack detection is unevaluated), no third-party data, no secrets or captures tracked, CI green, SECURITY and EVALUATION documents | there is **no LICENSE file**, so by default nobody may reuse the code: choose one before promoting the repository; keep the "not evaluated" banner |
| **Research evaluation** | **NOT READY** | the protocol, harnesses, matching rule, split tooling, intervals and gates are built and tested | 16 of 27 corpus rows and all 6 reporting prerequisites need authorised captures; G1 needs held-out families; G2 needs a model and three raters; the test split is locked until then |
| **Internship portfolio presentation** | **READY** | a defensible end-to-end system: parsing in a sandboxed worker, deterministic detectors, correlation, ATT&CK mapping, evidence-first UI, an LLM component that cannot show unvalidated text, a leakage-aware evaluation design, CI, scans, and an audit trail of its own mistakes (CI history, hash portability bug, stale docs) | prepare to state the limitation first; `docs/VIVA.md` is the one-page defence |
| **Final `v1.0` release** | **NOT READY** | engineering criteria (PRD section 19 #1, 4, 5, 6 with `none`, 9, 10) are met | PRD section 19 #2 (multi-stage demo capture) and #8 (G1 and G2 decided with numbers) are unmet; #3 and #7 are partial. Acceptance requires the evidence in `docs/FINAL_AUDIT.md` section 9 |

## What would turn `v1.0-rc4` into `v1.0`

In this order, none skippable: authorised captures reaching 27/27 and the 6 prerequisites; tune on `dev`
only; test split once (detector results with intervals); G1 on the held-out test captures; G2 with a
model and three independent raters; replace the "Not run" decision records with the numbers, whatever they
are; build the multi-stage demo from a verified capture; open a slice in Wireshark; green CI on the final
commit; then tag.
