# CLAUDE.md — Tracewright

Tracewright is an offline network incident investigation tool. One PCAP goes in. Zeek parses it, and five rule/statistics detectors produce findings, which are correlated into incidents. Each incident is mapped to ATT&CK and presented with its evidence, a "why this fired" panel and a packet slice for Wireshark. The human analyst always makes the decision.

## Read first (in this order)

1. `docs/PRD.md` — what to build and why (source of truth)
2. `docs/architecture.md` — how it is built
3. `docs/plan.md` — phase order, tasks, acceptance criteria
4. `docs/instruction.md` — mandatory working rules + definition of done per phase
5. `docs/COUNCIL_REVIEW.md` — why each component exists (decision log D1–D11)

If these conflict, the order above wins. Never change architecture silently: write an ADR in `docs/adr/` and tell the user.

## Current status

- Phase: **P0-P10 are IMPLEMENTED and verified locally (2026-10-08), but the project is NOT fully evaluated: no labelled attack capture exists, so P2 is PARTIAL and every attack-dependent measurement is pending.** Built: P1 ingest/profile; P3 five detectors (`backend/app/detect/`, untuned PRD defaults in `config/detectors.yaml`); P4 correlation, ATT&CK 19.2 cards, evidence IDs, template summaries, reports (`app/correlate`, `app/attack`, `app/explain`, `app/report`); P5 anomaly triage, default `off`; P6 persistence, `SKIP LOCKED` job queue, HTTP API, packet slices, feedback; P7 React UI (Nginx, CSP); P8 optional narrative (pseudonymised pack, six-check validator, repair-once, template fallback, provider clients, UI panel, report embedding, `eval/run_llm.py` / `eval/score_llm.py`), default `LLM_PROVIDER=none`; P9 hardening (`backend/tests/security/`, `scripts/check_worker_sandbox.sh`, `docs/SECURITY.md`, `eval/bench.py`); P10 docs (`docs/EVALUATION.md`, `README.md`, `docs/DEMO.md`, `docs/VIVA.md`, `scripts/make_demo.py`).
- Measured (files under `eval/results/`): benign false positives on the 3 dev runs only (`dev-benign-baseline-v1`: 4 BEACON findings, 1.78 per benign hour with allowlists, PRD target 1.0 NOT met); 500 MB lab capture 61 s mean and a synthetic 1M-packet capture 126 s mean in the worker container (`bench-v1`, `bench-v1-synthetic`; NFR-01 met on that host, with caveats); 702 tests pass / 13 skipped, 98% line coverage of `app/` (detect 99-100%, validator 98%); worker sandbox 9/9 probes; malformed-capture corpus (57 files) clean; `pip-audit` and `npm audit` clean at that date.
- NOT measured / not done: any attack recall or precision, `baseline-rules-v1` on `test` (M1), threshold tuning, G1, G2 (no model was run, no raters), the multi-stage demo capture (no attack traffic is generated here), image CVE scanning, CI on GitHub (never run; new Postgres/frontend/e2e steps unproven there), opening a slice in Wireshark by hand. `python -m eval.splits report`: **10/27 corpus requirements met** (benign part only). `--split test` is refused by every harness until all 27 are met. Missing: >= 4 episodes per split for SCAN/BRUTE/DNSTUN/BEACON/EXFIL, iodine/dnscat2, `AUTOMATION_SSH`, >= 3 LAB-HOLDOUT families, >= 8 LAB-HOLDOUT test captures: externally supplied, verified captures only (`lab/register_external.py`, `lab/verify_run.py`). Frozen benign corpus: b01-b06, test = b01, b03, b06; dev = b02, b04, b05 (`eval/splits.yaml`, do not edit).
- Next work (only with real data): supply attack captures, complete the corpus, tune on `dev`, run `test` once per milestone, replace the G1/G2 "Not run" records. Update this block at the end of every phase.
- Gate G1 (anomaly scorer): not run (`eval/decisions/G1.md`).
- Gate G2 (LLM narrative): not run (`eval/decisions/G2.md`).
- Docs now live in `docs/` (done in P0).

## Architecture in one screen

```
upload (magic bytes, size cap, SHA-256)
 → worker: Zeek → Parquet → capture profile + warnings + network context
 → DET-SCAN · DET-BRUTE · DET-DNSTUN · DET-BEACON · DET-EXFIL → findings
 → anomaly triage (G1: iforest | robust_z | off) on rule-unexplained windows
 → correlation → incidents + links → ATT&CK cards → template summary
 → API: optional LLM narrative (G2) → pseudonymised pack → validator → fallback
 → React UI · packet slice · report · feedback
```

- Modular monolith: `api` (FastAPI) + `worker` (same codebase) + PostgreSQL + `web` (Nginx/React) + optional `ollama`.
- No broker, no Redis, no vector DB, no MLflow, no Prometheus. Job queue = Postgres `SKIP LOCKED`.
- Code layout: `backend/app/{api,core,db,ingest,profile,detect,anomaly,correlate,attack,explain,slice,report,worker}`.

## Commands

Verified in P0/P1 unless marked planned. On Windows, add `C:/Program Files/Docker/Docker/resources/bin` to PATH for the session. The dev stack needs `cp .env.example .env` first.

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build   # dev stack (API on 127.0.0.1:8000)
curl http://127.0.0.1:8000/api/v1/health                                    # health
docker compose run --rm worker zeek --version                               # pinned Zeek check (9.0.0)
./scripts/check_worker_sandbox.sh                                           # worker sandbox + egress checks
cd backend && uv sync --frozen                                              # install from lockfile
cd backend && uv run ruff check . && uv run ruff format --check . && uv run mypy app   # lint + types
cd backend && uv run pytest                                                 # unit tests (real-Zeek tests skip off-container)
# full suite incl. real-Zeek tests, in the worker test image (no network, read-only):
docker build --target test -t tracewright-worker-test -f backend/Dockerfile.worker backend
docker run --rm --network none --read-only --tmpfs /tmp:rw,exec --cap-drop ALL --security-opt no-new-privileges:true -e POSTGRES_DB=x -e POSTGRES_USER=x -e POSTGRES_PASSWORD=x -v "$PWD/config:/config:ro" -v "$PWD/knowledge:/knowledge:ro" tracewright-worker-test pytest -p no:cacheprovider -q
./scripts/e2e_p1.sh <capture.pcap> [<invalid-file>]                         # P1 end-to-end across the real containers
docker compose run --rm -v "$PWD/x.pcap:/in/x.pcap:ro" worker python -m app.cli analyze /in/x.pcap --out /data/artifacts/x
python -m lab.run_lab --run-id smoke01 --plan client1:ntp:20 --plan client2:cdn_browsing:20   # benign lab smoke run (data/lab/, not promoted)
python -m lab.check_labels data/lab/<run> <analysis_dir>                    # labels vs analysed capture
python -m lab.register_external <submission_dir>                           # stage an externally supplied run (UNVERIFIED)
python -m lab.verify_run <run_id> <analysis_dir>                            # verify its labels against the analysed capture
python -m eval.splits assign|validate [--against-git]|report                # eligible runs only; append-only
python -m eval.run_detectors --split dev --run-id <id>                       # detector eval on dev (refuses test until the corpus is complete)
python -m eval.beacon_sweep                                                  # synthetic beacon score sweep (a model, not performance)
python -m eval.bench prepare|run                                           # throughput benchmark (NFR-01), results in eval/results/bench-*
python -m eval.run_llm --split dev|test --run-id ID                          # narrative generation + blinded audit sheets (needs LLM_* env; test refused early)
python -m eval.score_llm --run-id ID [--write-decision]                      # G2 metrics and decision record
```

## Non-negotiables (full list in instruction.md)

**Security**
- PCAPs and every string extracted from them are attacker-controlled. Never exec/eval/pickle them, and never build shell strings from them (`subprocess.run([...], shell=False)` only).
- Only the worker touches capture bytes (Zeek, tcpdump, editcap, capinfos). It runs non-root with a read-only filesystem, `cap_drop: ALL`, and **no egress**. Don't weaken this to fix a bug.
- Never send raw packets, payloads, DNS names, URIs, user agents, SNI or cert fields to an LLM. Hosts and domains are pseudonymised as `H<n>`/`X<n>`/`D<n>`.
- UI and reports escape everything. `dangerouslySetInnerHTML` is banned.

**ML / evaluation**
- Never write a metric that didn't come from `eval/results/<run_id>/`. If it hasn't been measured, write "not yet measured".
- Split by capture/run (`eval/splits.yaml`). Tune on `dev` only. Never edit splits, labels or test captures to improve a number.
- Detectors are rules plus statistics. Don't call them AI/ML.
- G1 and G2 are pre-declared. If Isolation Forest or the LLM loses, ship the gate's outcome and document it. Don't re-tune to rescue it.
- Anomalies are "unusual relative to this capture". They never get an ATT&CK mapping.

**LLM**
- The product must work fully with `LLM_PROVIDER=none` (the default).
- Every observed claim cites `E-`/`F-` IDs, and knowledge cites `K-` IDs. The validator rejects invented hosts or numbers, verdict language, and inferences without a benign alternative.
- On failure: one repair attempt, then fall back to the template. Never show unvalidated text.
- The LLM never says a host is compromised or an attack is confirmed.

**Code**
- Python: type hints, `mypy --strict`, Pydantic for configs/payloads, ruff. Detectors, scorers, correlation and the validator are pure functions (no DB, I/O or clock).
- Thresholds live in `config/*.yaml`, never in code. Secrets come from env vars only.
- Only the dependencies on the allowlist in `docs/instruction.md` §1.6. Anything new needs a reason; a new service needs an ADR.
- Coverage ≥ 90% for `detect/`, `correlate/`, `explain/validator.py`.

## Naming (keep consistent)

- Detectors: `DET-SCAN`, `DET-BRUTE`, `DET-DNSTUN`, `DET-BEACON`, `DET-EXFIL`
- Anomaly finding type: `UNEXPLAINED_ANOMALY`
- Evidence `E-n`; findings `F-n`; incidents `I-n`; knowledge `K-T1046`, `K-PB-DET-SCAN`
- Gates `G1`, `G2`; milestones `M1`–`M3`; phases `P0`–`P10`, stretch `S1`

## Working style

- One phase at a time, in `docs/plan.md` order. A phase is done only when its checklist in `docs/instruction.md` §8 passes and CI is green.
- Small conventional commits (`feat(detect): …`, `eval: …`, `docs: …`).
- Report at the end of each phase: what was built, tests and coverage, measured results with run IDs, assumptions/ADRs, and what's next.
- Stop and ask if a requirement conflicts, a PRD §18 target looks unreachable, or a result would need test data touched.
