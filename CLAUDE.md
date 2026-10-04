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

- Phase: **P1 complete (verified locally); P2 not started.** P0 (Docker 29.8.1, Zeek 9.0.0 pinned, `scripts/check_worker_sandbox.sh` 7/7: non-root, read-only FS, CapEff=0 + no-new-privileges, no DNS/TCP egress, read-only uploads) still passes after P1. P1 verified 2026-10-04: `python -m app.cli analyze` runs validate → Zeek → normalise (8 Parquet tables) → capture profile + warnings. Tested on a real generated PCAP and PCAPNG in the real worker image (read-only FS, no network, cap_drop ALL); truncated, empty, non-PCAP and gzip inputs; and across the real API → worker → API containers (`scripts/e2e_p1.sh`). Tests: 132 pass on Linux/Python 3.13 with real Zeek (on Windows 125 pass and 7 real-Zeek tests skip), ~99% coverage; ruff and `mypy --strict` clean. **Caveats:** the DB-backed job queue (`jobs` table, lease loop) and the upload HTTP endpoint belong to P3/P6, so P1 records lifecycle in `status.json`; `.github/workflows/ci.yml` has never run on GitHub (no remote), though every command in it was run locally; x509/ssh/ftp/weird normalisation is unit-tested on synthetic Zeek-format lines but no fixture capture exercises those logs through real Zeek; only fixture-sized captures have been run (NFR-01 not measured); profile warning thresholds in `config/profile.yaml` are unmeasured initial defaults. Update this line at the end of every phase.
- Gate G1 (anomaly scorer): not run.
- Gate G2 (LLM narrative): not run.
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
docker run --rm --network none --read-only --tmpfs /tmp:rw,exec --cap-drop ALL --security-opt no-new-privileges:true -e POSTGRES_DB=x -e POSTGRES_USER=x -e POSTGRES_PASSWORD=x -v "$PWD/config:/config:ro" tracewright-worker-test pytest -p no:cacheprovider -q
./scripts/e2e_p1.sh <capture.pcap> [<invalid-file>]                         # P1 end-to-end across the real containers
docker compose run --rm -v "$PWD/x.pcap:/in/x.pcap:ro" worker python -m app.cli analyze /in/x.pcap --out /data/artifacts/x
# planned (P3+):
python eval/run_detectors.py --split dev                                    # detector eval (dev only while tuning)
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
