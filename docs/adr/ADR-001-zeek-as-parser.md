# ADR-001 — Zeek is the packet parser and flow assembler

| Field | Value |
|---|---|
| Status | Accepted |
| Date | 2026-10-04 |
| Phase | P0 |
| Source | COUNCIL_REVIEW decision D1; architecture §5–6, §24; PRD FR-04, SEC-02 |

## Context
Tracewright must turn an untrusted PCAP into typed connection, DNS, HTTP, TLS, SSH, FTP and anomaly (`weird`) records. Writing a flow assembler and protocol dissectors in Python (Scapy/PyShark) is slow on 500 MB captures, fragile on malformed traffic, and creates a large custom attack surface over attacker-controlled bytes.

## Decision
Use **Zeek** to parse captures. `conn.log` is the flow table; protocol logs are emitted as JSON and normalised to Parquet. Zeek runs only in the worker container (ADR-002), with password capture disabled.

**Pinned version: Zeek 9.0.0** (Docker Hub `zeek/zeek:9.0.0`, the image that the `lts` tag pointed to on 2026-10-04, digest `sha256:70733f4e…16de5`; Debian 13, Python 3.13). The image is pinned by tag and digest in `backend/Dockerfile.worker`, and the worker refuses to start if `zeek --version` differs from the pinned version.

## Alternatives considered
| Option | Why rejected |
|---|---|
| Scapy / PyShark pipeline | Slow, memory-hungry, larger hand-written parsing surface (council D1) |
| Suricata | An IDS emitting alerts; Tracewright needs protocol/flow logs, and alert rules would blur the "deterministic detectors we wrote and can explain" story |
| Custom flow assembler on libpcap | Re-implements Zeek's most-tested component |

## Consequences
- The worker image is built on the Zeek image; development happens in that image from P0.
- Detector logic is written against Zeek field semantics (`conn_state`, `history`, `ssh.auth_success`, …).
- A Zeek version bump is a deliberate change: update the Dockerfile pin and digest, re-run the fixture and evaluation suites, and note it in this ADR. Zeek 8.0.10 (previous LTS line) is the known fallback if 9.0.0 proves problematic; no such problem has been observed or measured.
- Zeek's own parsing bugs are in scope of the worker sandbox threat model (architecture §19).
