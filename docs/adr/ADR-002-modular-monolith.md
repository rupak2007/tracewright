# ADR-002 — Modular monolith: API + worker + PostgreSQL, no broker

| Field | Value |
|---|---|
| Status | Accepted |
| Date | 2026-10-04 |
| Phase | P0 |
| Source | COUNCIL_REVIEW decision D2; architecture §1, §18, §24; instruction.md §1.7 |

## Context
Tracewright is a single-analyst, offline tool processing one capture per investigation. The design needs one security boundary (untrusted capture bytes) and a durable job queue; it does not need horizontal scale.

## Decision
- One Python codebase (`backend/app`) deployed as two processes: **api** (FastAPI) and **worker** (same code, plus Zeek/tcpdump/editcap/capinfos).
- **PostgreSQL** stores domain data and the job queue (`SELECT … FOR UPDATE SKIP LOCKED`, lease timeout, one retry).
- The **worker is the only component that touches capture bytes**; it runs non-root, read-only, `cap_drop: ALL`, `no-new-privileges`, resource-limited, on an `internal: true` network with no egress. The API sits on both networks but never runs capture-parsing tools.
- No Redis, Celery, Kafka, MLflow, vector database, Prometheus, Kubernetes or microservices.

## Alternatives considered
| Option | Why rejected |
|---|---|
| Redis/Celery queue | A second stateful service for a one-job-at-a-time workload; Postgres already provides durable, transactional leases |
| Single process (API parses captures) | Puts parser exploitation risk on the process that holds network access and the DB credentials |
| Microservices per pipeline stage | Operational cost with no scaling requirement |

## Consequences
- Both images must keep the same Python minor version (3.13) and install from the same lockfile.
- Job-queue semantics (leases, heartbeat, retry) are tested against a real Postgres, not mocked.
- Any new service requires a new ADR (instruction.md §1.4, §1.7).
- P0 status: the API `/health` reports database connectivity only. The worker heartbeat (architecture §22) needs the `jobs`/heartbeat table and lands with the job loop (P3 tables, P6 loop).
