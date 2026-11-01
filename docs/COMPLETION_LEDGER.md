# Project completion ledger

State at 2026-11-01, `master` at the commit that adds this file. Statuses: COMPLETE (verified with
evidence), IN PROGRESS, BLOCKED (external dependency or human decision), NOT STARTED, FAILED.
No percentages: nothing here has a defensible measurable basis for one.

**Release status: NOT releasable as `v1.0`.** The software is complete and CI-green; the scientific
evaluation is blocked on data this repository cannot produce. `v1.0-rc1` and `v1.0-rc2` point at builds that were
red on GitHub; `v1.0-rc3` is the first green release candidate.

| Requirement | Status | Evidence | Remaining blocker |
|---|---|---|---|
| Implementation P0-P10 | COMPLETE | `docs/plan.md` status paragraphs; 730 tests passed, 13 skipped, 98% line coverage (local, 2026-11-01) | none |
| GitHub CI green | COMPLETE | run 41286325329 at `df8b008`: all 3 jobs, no failed step (`gh run view`). Earlier runs failed on `v1.0-rc1`/`v1.0-rc2` (see `docs/EVALUATION.md` §7) | re-confirm on the final commit after each push |
| Fresh-clone reproducibility | COMPLETE | fresh clone `docker compose up` + API end-to-end (2026-10-08, `a991de0`); CI docker job repeats it on every push | none |
| Security checks (sandbox, hardening, audits) | COMPLETE (point in time) | 9/9 sandbox probes, 57-file malformed corpus, `pip-audit`/`npm audit` clean on 2026-10-08, `docs/SECURITY.md` | re-run audits before a final tag; no image CVE scan; no external review |
| Performance NFR-01 | COMPLETE | `eval/results/bench-v1`, `bench-v1-synthetic` (500 MB in 39-74 s; 1M-packet synthetic 97-166 s) | none (host caveats in `docs/EVALUATION.md` §5) |
| Evaluation infrastructure | COMPLETE | per-class and per-sub-population metrics (BRUTE FTP/HTTP vs SSH, SCAN slow), `eval.splits report` sub-population counts, campaign ids, network-role and params checks, `--max-bytes` (`eval/REVISIONS.md` #10; tests in `test_eval_matching.py`, `test_lab_submission.py`, `test_cli.py`) | none |
| Corpus integrity on any checkout | COMPLETE | CRLF-canonical hashing (`REVISIONS.md` #9); CI corpus step green | none |
| Capture handoff package | COMPLETE | `docs/CAPTURE_ACQUISITION_PLAN.md`, `docs/CAPTURE_HANDOFF.md` | none |
| Produce the attack and held-out captures | BLOCKED | `docs/CAPTURE_ACQUISITION_PLAN.md` §G Q1 | **human decision:** who records them (the P2 decision keeps attack tooling out of this repository) |
| Corpus 27/27 | BLOCKED | `python -m eval.splits report`: 10/27 met, 17 unmet (re-run 2026-11-01) | external, verified captures |
| `AUTOMATION_SSH` hard negative | BLOCKED | no generator; plan Q2 | **human decision:** new lab-runner benign scenario or external capture |
| Detector evaluation (precision, recall, per sub-population) and M1 `baseline-rules-v1` | BLOCKED | the harness refuses `--split test` until 27/27 | the captures above |
| Threshold tuning on `dev` | BLOCKED | needs labelled `dev` attack episodes | the captures above |
| BEACON false-positive target (≤ 1.0/h) | FAILED (on benign dev) | 1.78/h with allowlists, `eval/results/dev-benign-baseline-v1/` | tune on `dev` with attack episodes available (so recall is measured at the same time), then re-measure |
| G1 (anomaly scorer) | BLOCKED | `eval/decisions/G1.md` "Not run" | held-out captures (≥ 3 families, ≥ 8 test runs) |
| G2 (LLM narrative) | BLOCKED | `eval/decisions/G2.md` "Not run" | a model, ≥ 30 test incidents, **three independent raters** |
| Multi-stage attack demo capture (PRD §19 #2) | BLOCKED | `docs/DEMO.md` | a verified attack capture |
| Open a slice in Wireshark by hand (PRD §19 #3) | BLOCKED | not done | **human action** (needs a desktop with Wireshark) |
| Recorded hostile capture for the injection criterion (PRD §19 #7) | BLOCKED | synthetic fixture only | a supplied capture |
| Image CVE scan | NOT STARTED | none | scanner not installed here; decide on a tool |
| Licence for third-party DNS-tunnel captures (acquisition plan C5) | BLOCKED | no licence stated by the source | **permission** from the authors |
| `v1.0` tag | BLOCKED | PRD §19 #2, #8 unmet | everything above |
| New release candidate tag after the green run | COMPLETE | `v1.0-rc3` on `45af6db`, CI run 41286595410 green; rc1 and rc2 (red) are not moved | none |

## Separation of work

* **Completed autonomously:** all software, CI, security, performance, evaluation infrastructure and the handoff package.
* **Needs external captures or a supplier:** every BLOCKED row about captures, detector results, tuning, G1, the demo.
* **Needs licensing permission:** acquisition plan C5 only.
* **Needs human authorisation:** who records the attack captures; the `AUTOMATION_SSH` scenario; the Wireshark check.
* **Needs three independent raters:** G2.
* **Needs your decision:** `docs/CAPTURE_ACQUISITION_PLAN.md` §G (questions 1, 2, 3, 6, 7, 9, 10).
