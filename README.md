# Tracewright

Offline network incident investigation: one PCAP in, Zeek parsing, five rule/statistics detectors,
correlated incidents mapped to ATT&CK, with evidence, a "why this fired" panel and a packet slice for
Wireshark. The analyst always makes the decision.

**Status: phase P0 (foundations).** There is no detection pipeline yet. See `CLAUDE.md` for the current
phase and `docs/plan.md` for the roadmap. The full README (results, demo, limitations) is written in P10.

## Quick start (dev)

Prerequisites: Docker with Compose v2.

```bash
cp .env.example .env            # local placeholders only; never commit .env
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build
curl http://127.0.0.1:8000/api/v1/health
docker compose run --rm worker zeek --version
```

Backend checks (needs [uv](https://docs.astral.sh/uv/)):

```bash
cd backend
uv sync --frozen
uv run ruff check . && uv run ruff format --check . && uv run mypy app && uv run pytest
```

Worker sandbox verification (non-root, read-only FS, no capabilities, no egress):

```bash
./scripts/check_worker_sandbox.sh
```

## Documents

`docs/PRD.md` → `docs/architecture.md` → `docs/plan.md` → `docs/instruction.md` → `docs/COUNCIL_REVIEW.md`;
decisions in `docs/adr/`; evaluation rules in `eval/PROTOCOL.md`; lab design in `lab/README.md`.
