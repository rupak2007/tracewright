# Tracewright in one page: why each component exists

For a viva or an interview. Every claim about results points at a file under `eval/results/`; where a
measurement does not exist, this page says so. Decision IDs are from `docs/COUNCIL_REVIEW.md`.

**The problem.** An analyst has a PCAP and must decide what happened. Tracewright turns it into a ranked
list of incidents, each with the evidence behind it, why a rule fired, which ATT&CK techniques the
behaviour is *consistent with*, and a packet slice to open in Wireshark. It never decides.

| Component | Why it exists | What it replaced / what it is not | Status of the evidence |
|---|---|---|---|
| **Zeek** for parsing (D1) | Protocol parsing is a solved, audited problem; hand-written extraction would be the weakest, least trusted part | Not a custom packet parser | Pinned 9.0.0; real-Zeek tests; malformed-capture corpus (57 files): 17 completed, 34 failed cleanly, 6 stopped at the gate |
| **Modular monolith, Postgres queue** (D2) | One analyst, one machine: `SKIP LOCKED` gives a durable job queue without a broker | No Redis/Kafka/Celery | Concurrency test on PostgreSQL 16; lease, heartbeat, requeue-once |
| **Network context config** (D3) | "Exfiltration" and "beaconing" mean nothing without knowing which addresses are internal, which are scanners or backup servers | Not guessed from traffic | Allowlists change the benign false-positive rate from 2.67 to 1.78 per hour on dev (`eval/results/dev-benign-baseline-v1/`) |
| **Rules + robust statistics, not ML** (D4) | Each finding must show a metric against a threshold the analyst can read and argue with | The detectors are not called AI | Thresholds are the untuned PRD defaults; **no attack recall or precision has been measured** (no labelled attack captures exist) |
| **Anomaly triage, gated** (D5) | Surface what the rules do not explain, only if it beats a trivial robust-z baseline | Anomalies never get an ATT&CK mapping | **G1 not run** (`eval/decisions/G1.md`): default `ANOMALY_SCORER=off` |
| **Knowledge cards, no vector RAG** (D6) | The ATT&CK mapping is a lookup by technique ID against a pinned bundle (v19.2, hash recorded), with hand-written playbooks | No embeddings, no chat | Mapping validity enforced at startup and by test |
| **Optional narrative, template by default** (D7) | Templates are faithful but cannot synthesise; a narrative may help only if it stays grounded | Never required; never shown unvalidated | Six-check validator at 98% coverage; **G2 not run** (`eval/decisions/G2.md`): default `LLM_PROVIDER=none` |
| **Pseudonymised evidence pack** (D8) | An LLM must never see raw capture strings: they are attacker-controlled | Capture strings are not "sanitised", they are never collected | Injection fixture; prompt contains no real address (tests) |
| **Episode-level metrics, split by capture, hard negatives, held-out families** (D9) | Per-packet or random-split numbers leak and flatter; detectors must be judged on what an analyst sees | Never tuned on `test` | Protocol and tooling built; corpus 10 of 27 requirements met: benign part only |
| **Packet slice + analyst feedback** (D10) | An analyst trusts what they can verify; the slice opens in Wireshark | Feedback is stored, never auto-applied | Real tcpdump/editcap slice tests; opening in Wireshark by hand was not tested |
| **Name** (D11) | Portfolio clarity | | |

## Questions to be ready for

* **"What is the recall?"** Not measured. The five detectors have run on 4.53 hours of *benign* lab traffic
  only. Dev false positives: 4 BEACON findings (1.78 per hour with allowlists), all matching labelled benign
  behaviour. Nothing was evaluated on `test`.
* **"Why is the attack corpus missing?"** This repository generates no attack traffic. Real labelled captures
  can be supplied through `lab/register_external.py` and verified by `lab/verify_run.py`; the protocol,
  matching rule and refusal to touch `test` early are already in place.
* **"Why not just use an LLM for everything?"** It would be unverifiable. The validator rejects invented hosts and
  numbers, verdict language and inferences without a benign alternative; failure falls back to the template.
* **"What would you do with real attack data?"** Fill the 14 missing episode requirements, tune thresholds on `dev`
  only, run `eval.run_detectors --split test` once, then G1, then G2, and record each outcome, good or bad.
* **"What can go wrong security-wise?"** `docs/SECURITY.md`: a parser exploit inside the sandboxed worker, an
  unauthenticated loopback API, real packets in downloaded slices, and a plausible-but-wrong LLM inference.
* **"Is it fast enough?"** See `eval/results/bench-v1/` and `docs/EVALUATION.md` for the measured numbers and the
  hardware they came from, including where they fall short of NFR-01.
