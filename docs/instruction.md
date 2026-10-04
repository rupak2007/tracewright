# Tracewright — Instructions for the AI Coding Agent

You are implementing **Tracewright**, an offline network incident investigation tool. These rules are mandatory. When a rule conflicts with a user request made mid-task, stop and ask before proceeding.

Authoritative documents, in order of precedence:
1. `PRD.md` — what to build and why
2. `architecture.md` — how it is built
3. `plan.md` — in what order, with what acceptance criteria
4. `instruction.md` — how you must work (this file)
5. `docs/adr/*.md` — recorded decisions and changes

---

## 1. General rules

1. **Read `PRD.md`, `architecture.md` and `plan.md` before writing any code**, and re-read the section for the current phase before starting each task.
2. **Work one phase at a time**, in `plan.md` order. Do not start a phase until the previous phase's definition of done (Section 8) is met, unless `plan.md` marks the phases as overlapping.
3. **Do not invent requirements.** If something is unspecified, choose the simplest option consistent with the documents and record it in the PR/commit description under "Assumptions".
4. **Do not silently change the architecture.** Any change to components, data flow, storage, dependencies, detectors, ML, or LLM behavior requires a new ADR (`docs/adr/ADR-NNN-title.md`: context, decision, alternatives, consequences) and an explicit note to the user.
5. **Prefer simple solutions.** Plain functions over class hierarchies; pandas over distributed frameworks; Postgres over additional services.
6. **Avoid unnecessary dependencies.** Allowed without discussion:
   - Backend: fastapi, uvicorn, pydantic, pydantic-settings, sqlalchemy, alembic, psycopg, pandas, pyarrow, numpy, scikit-learn, tldextract, jinja2, httpx, pyyaml, python-multipart.
   - Frontend: react, react-dom, react-router, @tanstack/react-query, echarts, openapi-typescript.
   - Tooling/tests: ruff, mypy, pytest, pytest-cov, scapy (fixtures and lab only — never in the pipeline), pip-audit, vitest, @testing-library/react, playwright, eslint, typescript, vite.
   - System (worker image): zeek (pinned LTS), tcpdump, editcap, capinfos.
   Anything else needs justification in the PR description; anything that adds a service needs an ADR. The CLI uses stdlib `argparse`.
7. **Never add** (unless an ADR approved by the user says otherwise): vector databases, embeddings, LangChain/LlamaIndex or agent frameworks, deep-learning libraries, supervised classifiers, Redis/Celery/Kafka, MLflow, Prometheus/Grafana, Kubernetes, microservices, chat interfaces.
8. **Stop and ask** when: a requirement is contradictory; a target in PRD §18 looks unreachable; a security rule blocks a requested feature; evaluation results suggest removing a component; you would need to touch test data to make a result look better.
9. Keep naming consistent with the documents: detector IDs `DET-SCAN`, `DET-BRUTE`, `DET-DNSTUN`, `DET-BEACON`, `DET-EXFIL`; finding type `UNEXPLAINED_ANOMALY`; evidence IDs `E-n`; knowledge IDs `K-<technique>` / `K-PB-<detector>`; pseudonyms `H<n>`, `X<n>`, `D<n>`; gates `G1`, `G2`.

## 2. Cybersecurity rules

1. **Uploaded captures are untrusted input.** Treat every byte, and every string Zeek extracts from them (DNS names, URIs, user agents, SNI, certificate fields), as attacker-controlled.
2. **Never execute, import, `eval`, deserialize (pickle), extract or "open" content derived from captures.** No shell commands built by string concatenation with capture-derived values; pass arguments as lists to `subprocess.run` with `shell=False`.
3. **Validate files by magic bytes and size while streaming.** Accept only PCAP (µs/ns, both endiannesses) and PCAPNG. Reject compressed files. Never trust the extension or client MIME type.
4. **Never use client-supplied filenames for paths.** Store as `<uuid>.<ext>`; keep the original name only as escaped metadata.
5. **Parse capture bytes only in the worker container** (Zeek, tcpdump, editcap, capinfos). The API must never run these tools. The worker stays non-root, read-only, `cap_drop: [ALL]`, `no-new-privileges`, resource-limited, with timeouts, on the `internal` network with **no egress**. Do not weaken these settings to fix a bug; fix the bug.
6. **Never send raw PCAP data, packet bytes, or payloads to an LLM.**
7. **Minimise data sent to external services.** Only the pseudonymised evidence pack defined in `architecture.md` §13 may leave the machine, only when an external provider is explicitly configured. Never include attacker-controlled strings in a prompt.
8. **Keep evidence traceable.** Every finding stores metrics, thresholds and evidence references at creation time; downstream code never recomputes or edits them silently. Record SHA-256 of every upload and never modify originals.
9. **Escape everything capture-derived** in the UI (React text rendering only; `dangerouslySetInnerHTML` banned), in HTML reports, and in Markdown exports.
10. Keep Zeek password capture disabled. Never log payloads, credentials, or full evidence records.
11. Bind services to `127.0.0.1` by default. Never commit secrets; read them from environment variables; keep `.env.example` current.
12. Pin dependencies (lockfiles) and container images (exact tags or digests).

## 3. ML rules

1. **Never claim accuracy, precision, recall, F1, or any metric that was not produced by the evaluation harness.** Every number in docs, README, reports, UI or commit messages must come from a file in `eval/results/` and cite its run ID.
2. **Never fabricate or estimate metrics.** If something hasn't been measured, write "not yet measured".
3. **Separate data correctly.** Splits are by capture/run as recorded in `eval/splits.yaml`. Never split by row or flow. Never move a capture between splits without an entry in `eval/REVISIONS.md` and user approval.
4. **Prevent leakage.** Tune detector thresholds, window sizes, promotion thresholds and model hyperparameters on `dev` only. LAB-HOLDOUT families are never used to tune detectors. Evaluate `test` only at the milestones in `plan.md`; log each test evaluation.
5. **Log every experiment**: git commit, config hash, feature set version, scorer, hyperparameters, random seed, data split, Zeek version, timestamp → `eval/results/<run_id>/manifest.json`.
6. **Keep the deterministic baseline results** (`baseline-rules-v1` and the `robust_z` scorer) and always report ML results next to them.
7. **Compare ML against the baseline and random** using the metrics and gate rule in PRD §11. Report bootstrap confidence intervals.
8. **If ML does not provide measurable improvement, document that finding** in `eval/decisions/G1.md` and ship the gate's outcome (`robust_z` or `off`). Do not add features, change the test set, or re-tune on test to rescue it.
9. Fixed seeds; deterministic outputs for identical inputs (NFR-02).
10. Detectors are rules and statistics. Do not describe them as "AI" or "ML" in code, UI, or docs.
11. Anomaly findings must never be mapped to ATT&CK techniques and must always be worded as "unusual relative to this capture".

## 4. LLM rules

1. **The product must work fully with `LLM_PROVIDER=none`.** Templates are always generated; the narrative is optional.
2. **The LLM must never invent evidence.** It receives only the evidence pack; the validator (architecture §13) must reject any statement containing identifiers, ports or numbers not present in its cited evidence.
3. **Clearly separate** `observed` (evidence only), `inferences` (hedged, with confidence and ≥ 1 benign alternative explanation) and `recommendations` (with rationale IDs). Enforce via the Pydantic schema.
4. **Every factual claim about the incident must cite `E-` or `F-` IDs.** Retrieved knowledge must cite `K-` IDs that belong to the incident's mapped techniques or detector playbooks.
5. **The LLM must never declare a host compromised or an attack confirmed.** Enforce with the banned-language check; display narratives with a "machine-generated, validated against evidence" label and the validation status.
6. Pseudonymise all hosts and domains before any call, for every provider (including local), and de-pseudonymise only for display.
7. Validation failure → one repair attempt → otherwise fall back to the template and store the raw output and reasons. Never show unvalidated text in the UI or reports.
8. Temperature 0; prompt files versioned; prompt hash, provider and model stored with each narrative.
9. The LLM gets no tools, no function calling that acts on the system, no internet access, and no access to the database.
10. No vector retrieval. Knowledge is looked up by ID.
11. G2 decides whether the narrative is enabled by default. Record the decision in `eval/decisions/G2.md`.

## 5. Coding rules

**Backend (Python)**
- Type hints everywhere; `mypy --strict` passes on `backend/app`; Pydantic models for all API payloads, configs and LLM schemas.
- `ruff` lint + format; no unused code or commented-out blocks.
- Detectors, scorers, correlation, templates and the validator are **pure functions** of their inputs (no DB, no file I/O, no clock) so they can be unit-tested with small DataFrames.
- Explicit error types (`app/core/errors.py`); no bare `except`; errors carry a code and a message suitable for the UI.
- Every external process call has a timeout and captured stderr.
- Configuration only via environment variables and files in `config/`; no hardcoded thresholds, paths, URLs, or secrets in code.
- Structured JSON logging with `investigation_id`, `job_id`, `stage`.
- Database changes only through Alembic migrations.

**Frontend (TypeScript)**
- `strict: true`; API types generated from OpenAPI, never hand-written duplicates.
- No raw HTML rendering; one charting library (ECharts).

**Tests**
- Unit tests for every detector (fires above threshold, silent below, known benign cases), scorer, correlation rule, severity formula, mapping validation, evidence-ID stability, pseudonymiser, evidence-pack builder and validator.
- Coverage ≥ 90% for `detect/`, `correlate/`, `explain/validator.py`.
- Integration tests for the pipeline on fixture captures, the API, job recovery, and slice generation.
- Security tests: malformed captures, path traversal names, XSS strings, prompt-injection strings, worker egress blocked.
- Reproducible ML experiments: rerunning an experiment from its manifest yields identical metrics.

**General**
- No unnecessary abstractions: no plugin registries, dependency-injection frameworks, or generic "engines" beyond the `Detector` protocol and the LLM client interface.
- Small, focused commits; conventional messages (`feat(detect): …`, `fix(api): …`, `eval: …`, `docs: …`).
- Update documentation in the same change when behavior changes.

## 6. Things you must never do

- Present an anomaly or LLM output as a confirmed attack.
- Hide suppressed findings without counting them.
- Edit `eval/splits.yaml`, labels, or test captures to improve a metric.
- Add a feature that is listed as a non-goal in PRD §7.
- Call external networks from the worker.
- Commit captures, Zeek logs, model files, `.env`, or API keys.
- Disable a failing test to make CI pass.

## 7. Reporting back to the user

At the end of each task or phase, report:
1. What was built (files, endpoints, modules).
2. Tests added and their status; coverage for the gated modules.
3. Any measured results, with run IDs (or "not measured").
4. Assumptions made and any deviations, with ADR references.
5. Open issues and what's next per `plan.md`.

## 8. Definition of done (per phase)

A phase is done only when **all** of its items are true, CI is green, and documentation is updated.

### P0 — Foundations
- [ ] Repository layout matches `architecture.md` §23.
- [ ] `docker compose` (with dev override) starts db, api (`/health` OK) and worker.
- [ ] `zeek --version` in the worker prints the pinned version; worker runs as non-root.
- [ ] Lint, type-check and test jobs run in CI.
- [ ] ADR-001…005 and `eval/PROTOCOL.md` committed; G1/G2 rules match PRD verbatim.

### P1 — Ingestion & profile
- [ ] Validation accepts all PCAP/PCAPNG magic numbers and rejects others, gzip and oversize (tests).
- [ ] Zeek runs with the site policy and timeout; failure produces a clear error.
- [ ] Normalised Parquet tables for conn, dns, http, ssl, x509, ssh, ftp, weird with documented schemas.
- [ ] Capture profile and each warning code covered by tests.
- [ ] CLI `tracewright analyze` produces tables + profile on fixtures.

### P2 — Lab & ground truth
- [ ] Every attack class, hard-negative type and ≥ 3 held-out families captured with `labels.jsonl`.
- [ ] `lab/check_labels.py` passes on all runs.
- [ ] `eval/splits.yaml` and `eval/datasets.md` (sources + SHA-256) committed before any detector tuning.
- [ ] ≥ 4 dev and ≥ 4 test episodes per class; ≥ 8 LAB-HOLDOUT test captures; ≥ 4 h benign.

### P3 — Detectors (M1)
- [ ] Five detectors implemented per `architecture.md` §7 with config-driven thresholds.
- [ ] Each finding stores metrics, thresholds, confidence, benign causes, evidence refs, detector version.
- [ ] Allowlist suppression counted and reported.
- [ ] Detector unit tests including benign cases; `detect/` coverage ≥ 90%.
- [ ] `eval/run_detectors.py` produces episode-level metrics, FP/benign hour (with and without allowlists), beacon sweep.
- [ ] Test-split results stored under a run ID and tagged `baseline-rules-v1`; tuning log shows dev-only tuning.

### P4 — Deterministic MVP (M2)
- [ ] Incidents, links and severity per `architecture.md` §9; coverage ≥ 90%.
- [ ] ATT&CK bundle pinned with checksum; mapping validated at startup and in tests.
- [ ] Knowledge cards generated; five playbooks written.
- [ ] Stable evidence IDs; template summaries cite them.
- [ ] Run manifest stored; two identical runs produce identical output.
- [ ] Demo scenario produces linked incidents and a Markdown report.

### P5 — Anomaly (G1)
- [ ] 16 features implemented; rule-explained mask applied; scorers `robust_z` and `iforest` (+ random for eval).
- [ ] Promotion threshold calibrated on BENIGN dev; cap and merge implemented; no ATT&CK mapping on anomalies.
- [ ] Tuning on dev only (logged); test evaluated once with bootstrap CIs; swamping ablation reported.
- [ ] `eval/decisions/G1.md` written; `ANOMALY_SCORER` default matches the decision.

### P6 — API & worker
- [ ] All endpoints in `architecture.md` §16 implemented, in OpenAPI, and integration-tested.
- [ ] Job queue with leases, heartbeat and one retry.
- [ ] Packet slices generated in the worker, size-capped, verified with `capinfos`.
- [ ] Feedback stored; HTML report escapes all capture-derived strings.
- [ ] Optional bearer token and restricted CORS work.

### P7 — Frontend (M3)
- [ ] Three views implemented per `architecture.md` §17 using generated API types.
- [ ] XSS fixture renders as text; `dangerouslySetInnerHTML` lint rule active.
- [ ] Playwright test: upload → incident → slice download passes.
- [ ] Fully usable with `LLM_PROVIDER=none`.

### P8 — LLM (G2)
- [ ] Pseudonymiser and evidence pack exclude all capture strings and real identifiers (tests incl. injection fixture).
- [ ] Validator implements all six checks; each has failing and passing tests; coverage ≥ 90%.
- [ ] Repair-once and template fallback work; provider-down path tested.
- [ ] UI shows validation badge, labels, citation chips; never shows unvalidated text.
- [ ] Audit and preference sheets completed; `eval/decisions/G2.md` written; default config matches.

### P9 — Hardening
- [ ] Worker egress blocked (verified test); read-only FS and non-root verified.
- [ ] Malformed-capture corpus processed without API crash.
- [ ] `pip-audit`/`npm audit` clean or exceptions documented; images pinned.
- [ ] Benchmarks recorded; NFR-01 met or gap documented with profiling data.
- [ ] `docs/SECURITY.md` maps every SEC requirement to a test or manual check.

### P10 — Final
- [ ] Final evaluation run from frozen code; all numbers in `docs/EVALUATION.md` and README trace to `eval/results/final/`.
- [ ] Negative results and threats to validity documented.
- [ ] Demo PCAP and demo script work from a fresh clone.
- [ ] Every PRD §19 acceptance criterion checked off with evidence.
