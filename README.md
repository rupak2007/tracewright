# Tracewright

Offline network incident investigation. One PCAP goes in. Zeek parses it, five rule/statistics detectors
produce findings, and the findings are correlated into incidents mapped to MITRE ATT&CK. Each incident comes
with its evidence, a "why this fired" panel (every metric against its threshold, with known benign causes) and
a packet slice you can open in Wireshark. **The analyst always makes the decision**: nothing here says a host
is compromised.

> **Read this first: attack detection has not been evaluated.** The evaluation corpus is 4.53 hours of benign
> lab traffic. No labelled attack capture exists in this repository (it generates none), so there is **no
> recall or precision figure** for any detector, gates G1 (anomaly scorer) and G2 (LLM narrative) were **not
> run**, and the thresholds are untuned defaults. What was measured is in [docs/EVALUATION.md](docs/EVALUATION.md).
> The tooling to finish the job (corpus checks, matching, harnesses that refuse to touch the test split early)
> is built and tested.

## What it does

```
upload (magic bytes, size cap, SHA-256) -> worker: Zeek -> Parquet -> capture profile + warnings
 -> DET-SCAN | DET-BRUTE | DET-DNSTUN | DET-BEACON | DET-EXFIL -> findings
 -> optional anomaly triage (off by default) -> correlation -> incidents + links
 -> ATT&CK cards ("consistent with") -> template summary with E-/F- citations
 -> API: optional validated LLM narrative (off by default) -> React UI, packet slice, report, feedback
```

Modular monolith: FastAPI `api` and a `worker` (same codebase), PostgreSQL (the job queue is `SKIP LOCKED`),
an unprivileged Nginx `web`, and an optional `ollama`. No broker, no vector store. Only the worker touches
capture bytes: non-root, read-only filesystem, no capabilities, **no network**.

## Quick start

Prerequisites: Docker with Compose v2 (Linux, macOS or WSL2).

```bash
cp .env.example .env              # local placeholders only; never commit .env
docker compose up --build -d      # UI at http://127.0.0.1:8080
curl http://127.0.0.1:8080/api/v1/health
```

Open the UI, drop a PCAP, wait for the analysis, open the top incident. `LLM_PROVIDER` defaults to `none`
and everything but the optional narrative works without any model. A walkthrough is in
[docs/DEMO.md](docs/DEMO.md). The demo capture is a benign lab capture; the multi-stage attack storyline is
pending a supplied, verified capture.

Without Docker for the UI, analyse one capture on the command line (inside the worker, the only place capture
bytes are parsed):

```bash
docker compose run --rm -v "$PWD/some.pcap:/in/some.pcap:ro" worker python -m app.cli analyze /in/some.pcap --out /data/artifacts/demo
```

## Development

```bash
cd backend && uv sync --frozen
uv run ruff check . ../lab ../eval && uv run ruff format --check . ../lab ../eval && uv run mypy
uv run pytest                       # real-Zeek tests skip outside the worker image
cd ../frontend && npm ci && npm run lint && npm run typecheck && npm test
./scripts/check_worker_sandbox.sh   # live sandbox probes (needs the stack built)
```

Full suite including real Zeek, inside the worker test image (`MSYS_NO_PATHCONV=1` on Git Bash for Windows):

```bash
docker build --target test -t tracewright-worker-test -f backend/Dockerfile.worker backend
docker run --rm --network none --read-only --tmpfs /tmp:rw,exec --cap-drop ALL --security-opt no-new-privileges:true \
  -e POSTGRES_DB=x -e POSTGRES_USER=x -e POSTGRES_PASSWORD=x \
  -v "$PWD/config:/config:ro" -v "$PWD/knowledge:/knowledge:ro" tracewright-worker-test pytest -p no:cacheprovider -q
```

## Results in one table

| Item | Result | Source |
|---|---|---|
| Detector recall / precision | **Not measured** (no labelled attacks) | `eval/results/dev-benign-baseline-v1/` |
| Benign false positives, dev, medium/high | 4 BEACON findings in 2.25 h = 1.78 per hour with allowlists (PRD target 1.0: **not met**) | same |
| Gate G1 (anomaly) / G2 (narrative) | **Not run**; defaults `off` / `none` | `eval/decisions/` |
| 500 MB lab capture, end to end | 61 s mean (39 to 74 s), 3 runs | `eval/results/bench-v1/` |
| 1M-packet synthetic capture | 126 s mean (97 to 166 s), 3 runs | `eval/results/bench-v1-synthetic/` |
| Tests / coverage | 702 passed, 13 skipped; 98% of `app/` | `docs/EVALUATION.md` section 6 |
| Security | 9/9 live sandbox probes; SEC-01..12 mapped to tests | `docs/SECURITY.md` |

## Limitations

* Rules and statistics, not ML: the detectors are not called AI. Thresholds are untuned; the BEACON detector
  fires on regular harmless traffic (see the benign false positives above) and needs the network context file
  (`config/network.yaml`) to be useful.
* Severity is an ordering aid, not a risk score. ATT&CK mappings say "consistent with", never attribution.
* One PCAP at a time, offline; no streaming, no per-host history, no authentication by default (loopback only;
  set `API_TOKEN` to require a token), no TLS.
* The optional narrative is machine-generated and shown only if a deterministic validator accepts it;
  it remains opt-in because G2 was not run.
* CI has never run on GitHub; everything was verified locally (see `docs/SECURITY.md` section 3).
* Packet slices contain real payload bytes. Pseudonymisation is not anonymisation.

## Documents

[`docs/PRD.md`](docs/PRD.md) -> [`docs/architecture.md`](docs/architecture.md) -> [`docs/plan.md`](docs/plan.md) ->
[`docs/instruction.md`](docs/instruction.md) -> [`docs/COUNCIL_REVIEW.md`](docs/COUNCIL_REVIEW.md);
[`docs/EVALUATION.md`](docs/EVALUATION.md), [`docs/SECURITY.md`](docs/SECURITY.md), [`docs/DEMO.md`](docs/DEMO.md),
[`docs/VIVA.md`](docs/VIVA.md); decisions in [`docs/adr/`](docs/adr/); evaluation rules in
[`eval/PROTOCOL.md`](eval/PROTOCOL.md) and [`eval/REVISIONS.md`](eval/REVISIONS.md); lab design in
[`lab/README.md`](lab/README.md).
