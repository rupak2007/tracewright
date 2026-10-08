# Tracewright — Implementation Plan

| Field | Value |
|---|---|
| Document | plan.md v1.0 |
| Implements | `PRD.md` v1.0, `architecture.md` v1.0 |
| Duration | ~14 weeks to MVP (solo developer, part-time-friendly), plus optional stretch |

---

## Ordering rationale (council changes to the default sequence)

1. **Evaluation design and the labeled lab come before detector tuning.** Without frozen splits and ground truth, every threshold is tuned on data that later "proves" it works.
2. **The worker container (with Zeek) exists from week 1.** Zeek is the parser; development happens against the same image the product runs in. Only hardening is left for later.
3. **The full deterministic pipeline (detectors → correlation → ATT&CK → templates) is completed before any ML.** It is the baseline the ML must beat, and the anomaly layer needs the "rule-explained" mask.
4. **API and UI are built on a finished, tested pipeline** — not the other way round.
5. **The LLM comes last**, after evidence IDs, templates and the UI exist, so its value can be measured against templates.
6. **Two decision gates** (G1 after ML, G2 after LLM) can remove components. Removing one is a valid outcome.

## Phase overview

| Phase | Weeks | Name | Gate / milestone |
|---|---|---|---|
| P0 | 1 | Foundations & evaluation protocol | Protocol frozen |
| P1 | 1–2 | Ingestion, Zeek, normalisation, profile | `tracewright analyze` produces tables + profile |
| P2 | 2–3 | Lab corpus & ground truth | Dev/test splits committed |
| P3 | 3–5 | Detectors + findings storage | **M1: rules baseline v1 measured** |
| P4 | 6 | Correlation, ATT&CK, knowledge cards, templates, CLI report | **M2: deterministic MVP (CLI)** |
| P5 | 7–8 | Anomaly experiment | **G1 decision** |
| P6 | 8–9 | API, job worker, packet slices, feedback | API contract stable |
| P7 | 9–10 | Frontend | **M3: usable product without LLM** |
| P8 | 10–11 | LLM narrative + validator | **G2 decision** |
| P9 | 12 | Hardening, security tests, performance | Security checklist passed |
| P10 | 13–14 | Final evaluation, demo, documentation | **MVP acceptance (PRD §19)** |
| S1 | after MVP | Grounded incident Q&A (optional) | Only if G2 passed with margin |

---

## P0 — Foundations & evaluation protocol (Week 1)

**Objective:** a repository, a runnable dev environment with Zeek, and an evaluation protocol written *before* any detection code.

**Tasks**
- Create repository structure (architecture §23); Python project with lockfile; ruff, mypy (strict for `app/`), pytest; pre-commit.
- `Dockerfile.worker` from a pinned Zeek LTS image + Python + tcpdump + editcap/capinfos; `Dockerfile.api`; `docker-compose.yml` + dev override with Postgres.
- `core/config.py` (Pydantic settings from env), `.env.example`, JSON logging.
- ADRs: ADR-001 Zeek, ADR-002 modular monolith, ADR-003 no vector RAG, ADR-004 anomaly gate G1, ADR-005 optional LLM + gate G2.
- Write `eval/PROTOCOL.md`: corpora, episode definition, matching rule (entity + time ±60 s), split policy (by run), tuning-on-dev rule, metrics, G1/G2 rules copied verbatim from PRD §11–12.
- Lab topology design document `lab/README.md` (hosts, IP plan, tools, scenario list including hard negatives and held-out families).
- CI workflow: lint, type-check, unit tests.

**Files:** `backend/pyproject.toml`, `backend/app/core/*`, `Dockerfile.*`, `docker-compose*.yml`, `.env.example`, `docs/adr/ADR-00{1..5}.md`, `eval/PROTOCOL.md`, `lab/README.md`, `.github/workflows/ci.yml`.

**Dependencies:** none.

**Expected output:** `docker compose -f docker-compose.yml -f docker-compose.dev.yml up` starts db + worker (idle) + api (health route).

**Testing:** CI green on an empty test suite plus a config-loading test; `docker compose run worker zeek --version` prints the pinned version.

**Acceptance criteria**
- Zeek runs inside the worker container as non-root.
- `eval/PROTOCOL.md` and ADRs committed; G1/G2 rules identical to PRD.

---

## P1 — Ingestion, Zeek parsing, normalisation, capture profile (Weeks 1–2)

**Objective:** a CLI that turns a PCAP into typed Parquet tables, a capture profile and data-quality warnings.

**Tasks**
- `ingest/validate.py`: magic-byte check (PCAP µs/ns both endiannesses, PCAPNG), size check, gzip rejection, SHA-256 streaming hash.
- `ingest/zeek.py`: run Zeek with `config/zeek/site.zeek` (needed analyzers only; password capture off), timeout, stderr capture.
- `ingest/normalise.py`: Zeek JSON → typed DataFrames → Parquet; schema per log type; skipped-line counter.
- `ingest/capinfos.py`: packet count, span, snaplen, link type.
- `profile/context.py`: load `config/network.yaml`, classify internal/external.
- `profile/profile.py` + `profile/warnings.py`: capture profile and warning codes (architecture §6).
- CLI `tracewright analyze <pcap> --out <dir>` (stdlib `argparse`) running stages S1–S3.
- Test fixtures: small PCAPs generated with Scapy scripts in `backend/tests/fixtures/make_*.py` (TCP handshake, failed connections, DNS queries, ICMP), plus a truncated PCAP and a non-PCAP file.

**Files:** `backend/app/ingest/*`, `backend/app/profile/*`, `backend/app/cli.py`, `config/zeek/site.zeek`, `config/network.yaml`, `backend/tests/unit/test_validate.py`, `test_normalise.py`, `test_profile.py`, `backend/tests/integration/test_ingest_pipeline.py`, fixture generators.

**Dependencies:** P0.

**Expected output:** `artifacts/<id>/tables/conn.parquet` etc. and `profile.json` with warnings.

**Testing**
- Unit: each magic number accepted; random bytes, gzip, oversize rejected; normalisation types/nulls; internal/external classification; each warning triggers on a crafted fixture.
- Integration: fixture PCAPs → expected connection counts and `conn_state` values.

**Acceptance criteria**
- All fixtures parse; malformed fixture produces a clean failure, not a crash.
- Profile values match `capinfos`/Zeek for fixtures.
- No network access needed during parsing (verified by running the worker on the `internal` network).

---

## P2 — Lab corpus & ground truth (Weeks 2–3, overlaps P1)

**Objective:** labeled captures to tune on (dev) and to measure on (test), created before detectors exist.

**Tasks**
- `lab/docker-compose.lab.yml`: attacker, ssh/ftp/http servers, authoritative DNS for the tunnel domain, 3–5 clients, benign generators, capture container (`tcpdump -i <bridge>`).
- Scenario scripts (`lab/scenarios/*.sh|py`), each writing episodes to `labels.jsonl` via `lab/labeler.py`:
  - Attacks: nmap SYN/connect/slow (-T1/-T2) scans; hydra/medusa against SSH/FTP/HTTP basic auth; password spraying; iodine and dnscat2 tunnels; custom beacon script with configurable interval (30 s–5 min) and jitter (0–50%); exfil via scp/curl uploads of 50–500 MB; one **multi-stage demo scenario** (scan → brute force → beacon → exfil from the brute-forced host).
  - Hard negatives: rsync backup, package updates, NTP, monitoring heartbeats, cloud-sync-style uploads, CDN-heavy browsing, video streaming, automation SSH.
  - Held-out families (LAB-HOLDOUT): at least three of ICMP tunneling, slowloris, SMB/RPC enumeration, reverse shell on a non-standard port.
- Benign-only runs totalling ≥ 4 hours.
- Download and checksum CICIDS2017 Monday PCAP (BENIGN) and selected attack days (CIC-ATTACK); record source and SHA-256 in `eval/datasets.md`.
- `eval/splits.yaml`: assign runs to `dev`/`test` (≈ 50/50 per scenario type, by run) **before P3 begins**; DNS tool-held-out assignment; LAB-HOLDOUT test captures ≥ 8.

**Files:** `lab/*`, `eval/datasets.md`, `eval/splits.yaml`, `data/` (gitignored captures).

**Dependencies:** P0 (protocol), P1 (to sanity-check captures parse).

**Expected output:** a capture corpus with `labels.jsonl` per run and a committed split manifest.

**Testing:** `lab/check_labels.py` verifies every episode's actor/target IPs appear in the corresponding capture's Zeek `conn.log` within the labeled time range.

**Acceptance criteria**
- Every attack class has ≥ 4 dev and ≥ 4 test episodes; hard negatives present in both splits.
- Split manifest committed; checksums recorded.

---

## P3 — Deterministic detectors + findings storage (Weeks 3–5)

**Objective:** five detectors with tests, persisted findings, and the first measured baseline (M1).

**Status (2026-10-08):** started on explicit user instruction while the P2 attack/holdout corpus is still missing. Implemented: framework, five detectors, `config/detectors.yaml`, allowlist suppression with counts, stage S4 + `findings.json`, `eval/matching.py`, `eval/run_detectors.py` (dev only; refuses `test` until the corpus is complete), `eval/beacon_sweep.py` (synthetic timing model), synthetic-fixture unit tests and an end-to-end integration test. **Not done:** DB models/Alembic/jobs (deferred to P6, see architecture §7.6), threshold tuning (no attack data), the M1 test-split baseline and its `baseline-rules-v1` tag, and every attack-detection metric. FP per benign hour on the three dev benign runs is in `eval/results/dev-benign-baseline-v1/`.

**Tasks**
- `detect/base.py`: `Detector` protocol, `Finding` model, config loading from `config/detectors.yaml`.
- Implement `detect/scan.py`, `brute.py`, `dns_tunnel.py`, `beacon.py`, `exfil.py` per architecture §7 (bundled-PSL `tldextract`; Bowley/MAD beacon score; modified z-score).
- Allowlist suppression with counts.
- DB models + Alembic migration: `investigations`, `findings`, `evidence_items` (sample ≤ 200), `jobs`.
- Pipeline runner (`worker/pipeline.py`) for S1–S4 writing to DB; CLI writes JSON as well.
- Eval harness v1: `eval/run_detectors.py` (episode matching, precision/recall, FP per benign hour with/without allowlists, beacon sweep).
- Tune thresholds on **dev only**; record each change with reason in `config/detectors.yaml` comments and `eval/REVISIONS.md`.
- Run once on test → `eval/results/<run_id>/detectors.json` → tag `baseline-rules-v1`.

**Files:** `backend/app/detect/*`, `backend/app/db/models.py`, `backend/migrations/*`, `backend/app/worker/pipeline.py`, `config/detectors.yaml`, `eval/run_detectors.py`, `eval/matching.py`, tests per detector.

**Dependencies:** P1, P2.

**Expected output:** findings with metrics/thresholds/evidence for every lab capture; baseline results file.

**Testing**
- Unit (per detector, synthetic DataFrames): fires at/above threshold, silent just below; known-benign patterns (NTP, CDN DNS, backup) do not fire with default allowlists; confidence logic; beacon score on perfect, jittered, and random series; modified z with MAD = 0; DNS entropy on known strings.
- Integration: each lab dev capture → expected finding types.
- Coverage ≥ 90% for `detect/`.

**Acceptance criteria (M1)**
- All five detectors produce findings on dev episodes; test metrics recorded (whatever they are) without post-hoc tuning.
- Beacon detectability curve generated.
- FP per benign hour reported with and without network context.

---

## P4 — Correlation, ATT&CK mapping, knowledge cards, templates (Week 6)

**Objective:** the complete deterministic product, usable from the CLI (M2).

**Status (2026-10-08):** implemented and tested on synthetic evidence: correlation, links, severity, pinned ATT&CK 19.2 bundle + cards + startup-validated mapping, five playbooks, evidence IDs, templates, Markdown report, run manifest, CLI output of ranked incidents. The documented storyline (TARGET_LATER_ACTIVE + SHARED_EXTERNAL_PEER) is exercised by `tests/integration/test_p4_pipeline.py` on synthetic Zeek-format logs. **Pending, needs real captures:** the `demo.pcap` multi-stage scenario (requires attack traffic, which this repository does not generate).

**Tasks**
- `correlate/incidents.py` (entity rules, gap grouping), `correlate/links.py` (3 link types), `correlate/severity.py` (documented formula).
- `scripts/fetch_attack.py` (pinned version + checksum), `attack/stix.py` loader, `attack/mapping.py` with startup validation, `scripts/build_cards.py`.
- Write five verification playbooks `knowledge/playbooks/DET-*.md`.
- `explain/evidence_ids.py` (stable `E-n` per incident), `explain/templates/*.j2`, `explain/template_summary.py`.
- Run manifest (`worker/manifest.py`).
- `report/render.py`: Markdown report from DB/JSON (HTML added in P6).
- CLI prints ranked incidents and writes the report.

**Files:** `backend/app/correlate/*`, `backend/app/attack/*`, `backend/app/explain/{evidence_ids,template_summary}.py`, `backend/app/explain/templates/`, `knowledge/playbooks/*`, `config/attack*.yaml`, `scripts/*`, `backend/app/report/*`.

**Dependencies:** P3.

**Expected output:** `tracewright analyze demo.pcap` prints the linked multi-stage incidents and writes a report with evidence IDs and ATT&CK cards.

**Testing**
- Unit: grouping across gap boundaries; each link rule positive/negative; severity examples; every mapping ID exists and is not revoked/deprecated in the pinned bundle; template output contains only values from metrics; evidence IDs stable across re-runs.
- Integration: demo scenario → two linked incidents (`TARGET_LATER_ACTIVE`, `SHARED_EXTERNAL_PEER`).
- Determinism: two runs produce identical JSON.

**Acceptance criteria (M2)**
- Demo capture yields the expected storyline.
- Correlation coverage ≥ 90%.
- Report traces every number to an evidence ID.

---

## P5 — Anomaly experiment (Weeks 7–8) → Gate G1

**Objective:** test whether multivariate anomaly scoring adds value over robust statistics; ship the winner or nothing.

**Status (2026-10-08):** features, scorers, triage, stage S5, promotion, calibration on BENIGN dev and the G1 evaluation/decision tooling are implemented and tested on synthetic windows. **Gate G1 is NOT run** (no LAB-HOLDOUT captures; `eval/decisions/G1.md`): `ANOMALY_SCORER` stays `off`. No held-out metric exists.

**Tasks**
- `anomaly/features.py` (16 features, architecture §8), rule-explained mask.
- `anomaly/scorers.py`: `robust_z`, `iforest`, random (eval only); top-feature explanation.
- Calibrate promotion threshold on BENIGN **dev** (≤ 1% promoted).
- Tune window size (1/5/10 min) and IF `n_estimators`/`max_samples` on LAB-HOLDOUT **dev** only.
- `eval/run_anomaly.py`: metrics + bootstrap CI on LAB-HOLDOUT **test** and BENIGN test.
- Ablation: with vs without fitting on rule-unexplained windows only (documents the swamping effect).
- Write `eval/decisions/G1.md` applying the PRD rule; set `ANOMALY_SCORER` default accordingly.
- Integrate stage S5 and `anomaly_scores` table; promoted findings flow into correlation.

**Files:** `backend/app/anomaly/*`, `eval/run_anomaly.py`, `eval/decisions/G1.md`, migration for `anomaly_scores`, tests.

**Dependencies:** P3 (rule-explained mask), P4 (findings → incidents), P2 (LAB-HOLDOUT, BENIGN).

**Expected output:** results file with three scorers compared; a signed-off G1 decision.

**Testing**
- Unit: features on synthetic windows; scorers deterministic under fixed seed; small-population skip; promotion cap and merging; anomalies never receive ATT&CK mappings.
- Leakage check: assert no test capture ID appears in any tuning log.

**Acceptance criteria (G1)**
- Decision recorded with numbers and CIs; the shipped scorer matches the decision.
- If the result is negative, the report section explains why (e.g. population size, feature set, swamping) — no extra tuning on test to change it.

---

## P6 — API, job worker, packet slices, feedback (Weeks 8–9)

**Objective:** a stable HTTP API over the finished pipeline.

**Status (2026-10-08):** implemented and verified: schema + Alembic migration (checked on PostgreSQL 16), SKIP LOCKED queue with lease/heartbeat and requeue-once, streaming upload, all architecture §16 endpoints except the narrative ones (P8), packet slices (real tcpdump/editcap), feedback, Markdown/HTML reports with escaping, bearer token, CORS, OpenAPI. `scripts/e2e_api.py` drove the real compose stack end to end (upload, analysis, incidents, slice, download, feedback, reports, delete) on lab capture b02. The generated `frontend/src/api/schema.ts` comes with P7. Not verified: opening a slice in Wireshark by hand.

**Tasks**
- Streaming upload endpoint with validation; investigation CRUD; job table with `SKIP LOCKED` lease loop in `worker/main.py`; heartbeat.
- Read endpoints (architecture §16); pagination for evidence.
- `slice/builder.py` (BPF from finding flows; host-pair fallback above 50 flows) and `slice/runner.py` (`tcpdump -r … -w …` then `editcap -A/-B`), executed as worker jobs; 100 MB cap.
- Feedback endpoint and table.
- HTML report rendering with escaping.
- Optional bearer token; CORS; error format.
- Export OpenAPI schema to `frontend/src/api/schema.ts` via `openapi-typescript`.

**Files:** `backend/app/api/*`, `backend/app/worker/main.py`, `backend/app/slice/*`, `backend/app/report/html.py`, migrations, `backend/tests/integration/test_api_*.py`.

**Dependencies:** P4 (P5 integrated or `off`).

**Expected output:** full flow via `curl`/HTTP client: upload → poll → incidents → evidence → slice download → feedback → report.

**Testing**
- API integration tests with a test database and fixture PCAPs.
- Slice output re-parsed with `capinfos`; contains only expected hosts/ports/time range.
- Worker crash simulation → job requeued once.
- Upload of malicious filenames (`../../x`), oversize, wrong magic.

**Acceptance criteria**
- All endpoints documented in OpenAPI and covered by integration tests.
- Slice opens in Wireshark and matches the finding.

---

## P7 — Frontend (Weeks 9–10) → M3

**Objective:** the analyst workflow in a browser, without any LLM.

**Status (2026-10-08):** implemented and verified: all P7 views, generated API types, banned raw-HTML APIs (lint), CSP Nginx image in the compose stack, 15 vitest tests including the XSS fixture, and a Playwright end-to-end test that passed against the real stack on lab capture b02 (upload -> incident -> evidence -> slice download). The narrative tab arrives with P8. NFR-04 met (2 clicks).

**Tasks**
- Vite + React + TS strict; router; TanStack Query; generated API types.
- Views: Investigations (upload, progress), Overview (profile, warnings, incidents, anomalies), Incident (storyline timeline with ECharts, finding cards with metric-vs-threshold, evidence table with `E-` IDs, ATT&CK cards, playbooks, template summary, slice download, feedback, report export).
- Lint rule banning `dangerouslySetInnerHTML`; Nginx config with CSP.
- Accessibility basics: keyboard navigation, labels, colour not the only severity signal.

**Files:** `frontend/src/{pages,components,api,lib}/*`, `frontend/nginx.conf`, `frontend/Dockerfile`.

**Dependencies:** P6.

**Expected output:** demo capture investigated end-to-end in the browser.

**Testing**
- Component tests for finding card and evidence table; an XSS fixture (DNS name `<img src=x onerror=alert(1)>`) renders as text.
- One end-to-end test (Playwright) for upload → incident → slice download.

**Acceptance criteria (M3)**
- NFR-04 met (≤ 3 clicks from completion to top-incident evidence).
- Product fully usable with `LLM_PROVIDER=none`.

---

## P8 — LLM narrative + validator (Weeks 10–11) → Gate G2

**Objective:** an optional narrative that is provably grounded, measured against templates.

**Tasks**
- `explain/pseudonymise.py`, `explain/evidence_pack.py` (rules in architecture §13; attacker strings excluded; size cap).
- `explain/schema.py` (Pydantic output), `explain/validator.py` (6 checks), `explain/llm_client.py` (`none`, `ollama`, `openai_compatible`, `anthropic`), `explain/prompts/narrative_v1.txt`.
- API endpoints + `narratives` table; background generation; repair-once; fallback.
- UI narrative tab with validation badge and citation chips.
- `eval/run_llm.py`, blinded audit and preference sheets, `eval/score_llm.py`; recruit ≥ 3 raters (classmates/mentors) for ≥ 20 incidents.
- Write `eval/decisions/G2.md`; set default provider configuration accordingly.

**Files:** `backend/app/explain/*`, `backend/app/api/narratives.py`, `frontend/src/components/Narrative*`, `eval/run_llm.py`, `eval/score_llm.py`, `eval/audit/*`.

**Dependencies:** P4 (evidence IDs, templates), P6, P7.

**Expected output:** narratives for test incidents with validator outcomes; G2 decision.

**Testing**
- Validator unit tests with hand-written bad outputs: invented IP token, wrong number, missing citation, unknown `K-` ID, verdict language, inference without alternative, real IP leak — each must fail; a correct output must pass. Coverage ≥ 90%.
- Pack tests: no capture strings, no real IPs/domains; injection fixture (DNS name containing "ignore previous instructions…") never appears in the pack.
- Client tests with a fake provider (timeouts, malformed JSON).

**Acceptance criteria (G2)**
- G2 metrics computed from audit sheets; decision recorded; default configuration matches the decision.
- With the provider down, the UI shows the template and status `unavailable`.

---

## P9 — Hardening, security tests, performance (Week 12)

**Objective:** make the security claims true and measured.

**Tasks**
- Apply compose hardening (non-root, read-only, cap_drop, no-new-privileges, limits, `internal` network) and verify: worker cannot resolve/reach the internet (`curl` fails), cannot write outside volumes.
- Malformed-capture corpus: truncated files, corrupted headers, random mutations of fixtures (simple mutation script), huge snaplen, zero-length; ensure clean failures.
- Dependency audit (`pip-audit`, `npm audit`); pin image digests.
- `eval/bench.py` on 50/200/500 MB captures; profile and fix the slowest stage if NFR-01 is missed.
- Retention + delete verification (files and rows gone).
- `docs/SECURITY.md`: threat model, checks performed, residual risks.

**Files:** `docker-compose.yml`, `backend/tests/security/*`, `eval/bench.py`, `docs/SECURITY.md`.

**Dependencies:** P6–P8.

**Expected output:** security test report and benchmark results.

**Testing:** the security tests above run in CI (except the 500 MB benchmark, run manually and recorded).

**Acceptance criteria**
- All SEC requirements have a test or a documented manual check.
- NFR-01 met or the gap documented with profiling evidence.

---

## P10 — Final evaluation, demo, documentation (Weeks 13–14)

**Objective:** frozen results, a repeatable demo, and defensible documentation.

**Tasks**
- Freeze code (`v1.0-rc`); run full evaluation on test splits once: detectors, anomaly (confirm G1 still holds), LLM metrics, performance → `eval/results/final/`.
- `docs/EVALUATION.md`: methodology, results tables generated from result files, CIC-ATTACK results separately, limitations, negative results, threats to validity (lab bias, small rater sample, CICIDS labeling issues).
- `scripts/make_demo.py`: produces `demo/demo.pcap` from the multi-stage lab scenario + a short benign background.
- Demo script (5–7 minutes): upload → profile warnings → storyline → why-this-fired → slice in Wireshark → ATT&CK card → anomaly list → narrative with validation (and a shown rejection example) → report.
- README: quick start, architecture summary, results summary, limitations.
- Viva/interview prep: one-page "why each component exists" (from COUNCIL_REVIEW decision log).

**Files:** `docs/EVALUATION.md`, `README.md`, `demo/*`, `scripts/make_demo.py`, `eval/results/final/*`.

**Dependencies:** all previous phases.

**Expected output:** tagged `v1.0` release.

**Testing:** fresh clone → `docker compose up` → demo runs on a clean machine.

**Acceptance criteria:** every item in PRD §19 passes.

---

## S1 — Grounded incident Q&A (stretch, after MVP)

**Condition:** only if G2 passed with margin (validator pass ≥ 95%, preference ≥ 70%).

**Scope:** a question box on the incident page; context = the same evidence pack + mapped cards; answers in the same schema subset (`observed`, `inferences`, `open_questions`) with the same validator; questions not answerable from the pack return "not supported by the evidence in this incident". No vector store, no tools, no multi-turn memory beyond the current incident.

**Acceptance:** 30-question evaluation set (answerable, partially answerable, unanswerable, injection attempts): ≥ 90% of unanswerable questions correctly declined; validator pass ≥ 90%.

---

## If the schedule slips — cut in this order

1. S1 (grounded Q&A) — drop entirely.
2. CIC-ATTACK secondary evaluation — keep only CICIDS Monday for FP rate.
3. HTML report — keep Markdown only.
4. LLM narrative (P8) — ship templates only and document G2 as "not run". The product loses nothing it depends on.
5. Anomaly triage (P5) — reduce to `robust_z` vs `iforest` on 3 held-out families with fewer captures; never skip the baseline comparison.

Never cut: the labeled lab corpus and splits (P2), detector tests, evidence IDs, packet slices, worker sandboxing, or the honest reporting of results.

## Risk register

| Risk | Likelihood | Impact | Response |
|---|---|---|---|
| Lab setup consumes too much time | Medium | High | Start P2 in week 2; script everything; reuse one topology |
| IF shows no benefit | Medium | Low | Expected possibility; G1 ships robust-z or off and documents it |
| Local LLM too slow on CPU | Medium | Low | Smaller model; narrative is on-demand and optional |
| CICIDS2017 PCAPs too large to handle | Medium | Low | Use selected time slices via `editcap`; document |
| Beacon detector noisy on real benign traffic | High | Medium | Allowlists, periodic-port exclusions, confidence levels, measured FP/hour |
| Scope creep (new detectors, chat, dashboards) | High | High | `instruction.md` rules; changes only via ADR |
| Rater availability for G2 | Medium | Medium | Recruit in week 9; keep sheets short (20 incidents) |
