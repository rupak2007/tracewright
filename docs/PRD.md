# Tracewright — Product Requirements Document

| Field | Value |
|---|---|
| Product | Tracewright (formerly NetInvestigator) |
| Document | PRD v1.0 |
| Status | Approved for implementation |
| Companion docs | `architecture.md`, `plan.md`, `instruction.md`, `COUNCIL_REVIEW.md` |
| Supersedes | NetInvestigator PRD v0 |

---

## 1. Product overview

Tracewright is an **offline network incident investigation tool**. An analyst uploads one packet capture (PCAP/PCAPNG). Tracewright parses it with Zeek, profiles the capture, runs five bounded detectors built from deterministic rules and robust statistics, optionally ranks residual unusual host behavior, correlates findings into incidents, maps them to MITRE ATT&CK, and presents each incident with the exact evidence behind it, a "why this fired" explanation, and a packet slice the analyst can open in Wireshark.

An optional LLM layer can write a hedged incident narrative (observed evidence / inference / recommendation). It receives only pseudonymised, structured evidence; its output is checked by a deterministic validator and falls back to a template summary when it fails. The product is fully functional with the LLM switched off.

**Design principle:**

```
PCAP → Zeek parsing → capture profile → deterministic + statistical detection
→ residual anomaly triage (only if it beats a baseline) → correlation → incidents
→ evidence → ATT&CK mapping → template summary → optional validated narrative
→ human analyst review
```

The human analyst is always the decision maker. Tracewright never declares a host compromised.

## 2. Problem statement

When an incident is suspected, an analyst often has a PCAP and a question: *what happened, involving which hosts, and when?* Answering it means manually pivoting through thousands of connections in Wireshark, which is slow and depends on deep protocol knowledge. Existing tools sit at the extremes: Wireshark shows everything without prioritisation; IDS alerts show signatures without context or linkage.

Tracewright addresses the gap: **"Where should I look first, why, and how do I verify it?"** It produces a short, ranked list of incidents, each grounded in specific connections and records, with clear confidence levels, known false-positive causes, and a direct path back to the raw packets.

## 3. Target users

| User | Context | Need |
|---|---|---|
| **Primary:** security/network analyst | Investigating a specific suspected incident offline from a captured PCAP | Fast triage, linked timeline, verifiable evidence, handoff report |
| **Secondary:** student/learner in network security | Studying attack traffic in lab captures | Understand what each attack looks like on the wire and why it was flagged |
| **Secondary:** technical reviewer (interviewer, examiner) | Assessing engineering and evaluation quality | Reproducible results, honest metrics, explainable design |

## 4. User stories

| ID | Story |
|---|---|
| US-1 | As an analyst, I upload a PCAP and see processing progress, so I know when results are ready. |
| US-2 | As an analyst, I see a capture profile with data-quality warnings, so I know what this capture can and cannot reveal. |
| US-3 | As an analyst, I see incidents ranked by severity, so I know where to look first. |
| US-4 | As an analyst, I open an incident and see a timeline of linked findings across stages (e.g. scan → brute force → beaconing → exfiltration). |
| US-5 | As an analyst, for each finding I see the measured values, the thresholds they crossed, the confidence level, and common benign causes. |
| US-6 | As an analyst, I download the packets behind a finding as a small PCAP to verify in Wireshark. |
| US-7 | As an analyst, I see which ATT&CK techniques the behavior is *consistent with*, with descriptions and mitigations. |
| US-8 | As an analyst, I see a list of unusual host activity that no detector explained, clearly labeled as unusual rather than malicious. |
| US-9 | As an analyst, I optionally generate a narrative that separates observed evidence, inferences (with alternatives), and recommendations, where each statement links to evidence. |
| US-10 | As an analyst, I mark each finding as true positive, false positive, or expected/benign. |
| US-11 | As an analyst, I export an incident report (Markdown/HTML) for handoff. |
| US-12 | As an analyst, I configure internal network ranges and known benign hosts/domains, so results reflect my environment. |
| US-13 | As a reviewer, I see a run manifest (tool versions, config, model parameters) for every investigation, so results are reproducible. |

## 5. Core use cases

1. **Triage a suspicious capture:** upload → profile → ranked incidents → open top incident → verify via evidence and packet slice → record feedback.
2. **Reconstruct a multi-stage intrusion:** scan from an external host, brute force against a server, the server begins beaconing, then sends unusually large outbound volume — shown as linked findings on one timeline.
3. **Explain and hand off:** generate template summary (and optionally a validated narrative), export report.
4. **Learn from lab traffic:** run lab captures; inspect "why this fired" panels and knowledge cards.

## 6. MVP scope

**In scope**
- Offline processing of **one** PCAP or PCAPNG per investigation, up to 500 MB (configurable).
- Parsing with Zeek into normalised tables; no custom packet dissection in the pipeline.
- Capture profile and data-quality warnings.
- Network context configuration (internal CIDRs, known benign hosts, allowlisted domains).
- Five detectors: port scan, brute-force login, DNS tunneling, C2-style beaconing, volume-based exfiltration.
- Residual anomaly triage on rule-unexplained host behavior, **subject to decision gate G1** (Section 11).
- Deterministic correlation of findings into incidents, plus cross-incident links.
- Deterministic ATT&CK mapping and knowledge cards from a pinned ATT&CK STIX bundle plus curated verification playbooks.
- Template-based summaries (always on).
- Optional LLM narrative with pseudonymisation, validation and fallback, **subject to decision gate G2** (Section 12).
- Packet-slice export per finding.
- Analyst feedback per finding.
- Report export (Markdown and printable HTML).
- Web dashboard: investigations, investigation overview, incident detail.
- Local Docker Compose deployment.
- Evaluation harness and labeled lab corpus.

**Stretch (only after MVP acceptance)**
- S1: Grounded incident Q&A reusing the explanation evidence pack and validator (no vector database).

## 7. Explicit non-goals

- Real-time or streaming capture; live interface sniffing.
- Multi-PCAP or cross-investigation correlation; per-host historical profiles.
- Payload decryption or deep inspection of TLS content.
- Supervised attack classification.
- Vector search, embeddings, or a vector database.
- Free-form chat in the MVP.
- Autonomous response (blocking, isolation, remediation).
- Declaring hosts compromised or attacks confirmed.
- Multi-user, multi-tenant, or cloud deployment.
- Replacing Wireshark, Zeek, an IDS, or a SIEM.
- Detection of attack classes beyond the five listed (the anomaly triage surfaces unusual behavior; it does not name attacks).

## 8. Functional requirements

### Ingestion & profiling
| ID | Requirement |
|---|---|
| FR-01 | Accept PCAP (all standard magic numbers, micro- and nanosecond) and PCAPNG uploads via streaming; reject other types by magic bytes, not extension. |
| FR-02 | Enforce a configurable size limit (default 500 MB) during upload; reject compressed files. |
| FR-03 | Compute and store SHA-256 of the uploaded file; never modify the original. |
| FR-04 | Parse the capture with a pinned Zeek version into JSON logs (conn, dns, ssl, x509, http, ssh, ftp, weird) and normalise into Parquet tables. |
| FR-05 | Produce a capture profile: time span, packet/byte/connection counts, host counts (internal/external), protocol/service mix, top talkers. |
| FR-06 | Produce data-quality warnings: short capture vs beacon detectability, one-sided/asymmetric traffic, truncated packets, high Zeek `weird` counts, small host population (weak baseline), no DNS observed. |
| FR-07 | Apply network context from configuration (internal CIDRs default to RFC 1918; known scanners, resolvers, backup servers; allowlisted domains/suffixes). |

### Detection
| ID | Requirement |
|---|---|
| FR-10 | Run detectors DET-SCAN, DET-BRUTE, DET-DNSTUN, DET-BEACON, DET-EXFIL as specified in Section 10. |
| FR-11 | Each finding records: detector ID and version, primary/secondary entities, time range, measured metrics, thresholds applied, confidence (low/medium/high), severity, known benign causes, and references to evidence records (Zeek UIDs). |
| FR-12 | Detector thresholds are configuration, not code constants; the values used are stored with each finding. |
| FR-13 | Allowlisted entities suppress findings but suppressed counts are reported in the capture profile (nothing disappears silently). |

### Anomaly triage
| ID | Requirement |
|---|---|
| FR-20 | Build entity-window features (internal host × window, default 5 min). |
| FR-21 | Score windows with the scorer selected by G1 (`iforest`, `robust_z`, or `off`), fitting only on windows not explained by any detector finding. |
| FR-22 | Promote at most N (default 10) top-scoring rule-unexplained windows per investigation to low-severity `UNEXPLAINED_ANOMALY` findings, each with its top deviating features. Anomalies are never mapped to ATT&CK techniques. |
| FR-23 | Skip anomaly triage, with a warning, when the population is below the configured minimum (default 100 windows). |

### Correlation, mapping, explanation
| ID | Requirement |
|---|---|
| FR-30 | Group findings into incidents by primary entity and time gap (default 30 min). |
| FR-31 | Create typed cross-incident links using deterministic rules (e.g. brute-force target later beacons; beacon destination equals exfil destination). |
| FR-32 | Compute incident severity with a documented deterministic formula; display it as an ordering aid, not a risk score. |
| FR-33 | Map each finding type to ATT&CK technique IDs from a versioned mapping file validated against a pinned ATT&CK STIX bundle (no revoked/deprecated IDs). |
| FR-34 | Render knowledge cards (technique name, description, detection notes, mitigations) and per-detector verification playbooks. |
| FR-35 | Generate a deterministic template summary for every incident. |
| FR-36 | When enabled, generate an LLM narrative from a pseudonymised evidence pack; validate it; retry once on failure; otherwise fall back to the template and record the failure reason. |
| FR-37 | Label LLM output as machine-generated and show its validation status. |

### Analyst workflow
| ID | Requirement |
|---|---|
| FR-40 | Dashboard: investigation list with upload/progress; investigation overview (profile, warnings, incidents, anomaly list); incident detail (timeline, findings, evidence, knowledge cards, summary/narrative, feedback). |
| FR-41 | Evidence tables show up to 200 sample records per finding plus the total count. |
| FR-42 | Export the packet slice for a finding as a PCAP (BPF filter on the finding's flows + time range), generated in the sandboxed worker. |
| FR-43 | Record analyst feedback per finding: `true_positive`, `false_positive`, `expected_benign`, with optional note. |
| FR-44 | Export an incident report (Markdown, printable HTML) including capture hash, run manifest, findings, evidence excerpts, techniques, summary/narrative (labeled), feedback and limitations. |
| FR-45 | Delete an investigation and all derived artifacts. |
| FR-46 | Store a run manifest per investigation: git commit, Zeek version, config hash, detector versions, anomaly scorer and parameters, ATT&CK version, LLM provider/model/prompt version (if used). |

## 9. Non-functional requirements

| ID | Requirement | Target |
|---|---|---|
| NFR-01 | Throughput (excluding LLM) | 500 MB / ~1M-packet PCAP processed end-to-end in ≤ 10 min on a 4-core / 16 GB machine |
| NFR-02 | Determinism | Same input + same config + same seed ⇒ identical findings, incidents and anomaly ranks |
| NFR-03 | Fault isolation | A failed stage marks the investigation failed with a reason; no partial incident set is shown as complete |
| NFR-04 | Usability | An analyst reaches the evidence for the top incident in ≤ 3 clicks from upload completion |
| NFR-05 | Portability | `docker compose up` on Linux/macOS/WSL2 with documented prerequisites |
| NFR-06 | Offline operation | Full functionality with no internet access when `LLM_PROVIDER` is `none` or `ollama` |
| NFR-07 | Maintainability | Detectors are independent modules with a common interface; adding a detector touches no other detector |
| NFR-08 | Test coverage | ≥ 90% line coverage for detectors, correlation and the LLM validator |
| NFR-09 | Observability | Structured logs with investigation ID and stage; per-stage timings in the run manifest |
| NFR-10 | Browser support | Current Chrome/Firefox/Edge; layout usable at ≥ 1280 px |

## 10. Detection capabilities

All detectors read normalised Zeek tables plus network context. Thresholds below are **initial defaults** to be tuned on the development split only (Section 17).

| ID | Behavior | Unit | Core signals | Initial rule (defaults) | Confidence logic | Known benign causes | ATT&CK (consistent with) |
|---|---|---|---|---|---|---|---|
| DET-SCAN | Port/host scanning | source host × time window | distinct dst ports per dst; distinct dst hosts per port; failed-connection share (Zeek `conn_state` S0/REJ/RSTO/RSTR/SH/OTH) | ≥ 50 distinct ports to one host in 60 s, or ≥ 20 hosts on one port in 60 s, or ≥ 100 ports within 10 min (slow scan) | high if failed share ≥ 0.6 | vulnerability scanners, monitoring, NAT gateways, P2P | T1046 |
| DET-BRUTE | Repeated login attempts | (src, dst, service) × 5 min | FTP 530 replies; HTTP 401/403 to same URI; SSH/RDP/Telnet short repeated connections with similar byte counts; Zeek `ssh.log` auth fields | FTP ≥ 10 failures; HTTP ≥ 20 failures; SSH/RDP ≥ 10 short connections with low byte-size variation | high for FTP/HTTP (failures observed); medium for SSH/RDP (inferred from patterns) | automation tools, health checks, retries, shared NAT | T1110.001; T1110.003 when one source targets many hosts on the same service |
| DET-DNSTUN | DNS tunneling | (client, registered domain) | unique subdomains; subdomain length; Shannon entropy of leftmost labels; TXT/NULL share; NXDOMAIN rate; query volume | ≥ 50 unique subdomains AND (mean entropy ≥ 3.5 bits/char OR mean subdomain length ≥ 30); or TXT/NULL share ≥ 0.5 with ≥ 30 queries | high if both entropy and length criteria hold | CDNs, AV/reputation lookups, telemetry, ad-tech | T1071.004; T1048 when outbound name volume is large |
| DET-BEACON | Periodic C2-style check-ins | (src, dst IP, dst port) and (src, SNI/Host) | connection count; inter-arrival time median and MAD; Bowley skewness; size dispersion; coverage of capture | ≥ 10 connections and beacon score ≥ 0.8 (score combines timing regularity, skew symmetry, size regularity, coverage) | high if score ≥ 0.9 and ≥ 20 events | NTP, update checks, telemetry, monitoring agents, keepalives, mail polling | T1071 (.001 for HTTP/S, .004 for DNS) |
| DET-EXFIL | Unusual outbound volume | (internal src, external dst/SNI) | outbound bytes; out/in ratio; modified z-score of log outbound bytes among internal→external pairs | outbound ≥ 50 MB AND modified z ≥ 3.5 AND out/in ≥ 5 | high if population ≥ 20 pairs; low if baseline is weak (absolute floor only) | backups, cloud sync, uploads, video calls, CI artifact pushes | T1048; T1041 when the destination also has a beacon finding |

**Beacon detectability:** a beacon with interval *I* in a capture of duration *D* yields about *D / I* events. With a minimum of 10 events, detection requires *D ≥ 10 × I* (≈ 10 min for 60 s beacons, ≈ 50 min for 5-min beacons). The capture profile reports which beacon intervals the capture can support.

## 11. ML capabilities

Tracewright contains **one** ML component, and it must earn its place.

**Component:** residual anomaly triage.
- **Problem:** the five detectors cover named behaviors by construction. Analysts still benefit from a short list of hosts behaving unlike the rest of the capture in ways no detector explains.
- **Why not only rules:** rules cannot describe unknown behavior; the open question is whether *multivariate* unsupervised scoring finds it better than simple *univariate* robust statistics.
- **Candidates:** `iforest` (scikit-learn Isolation Forest) vs `robust_z` (max absolute modified z-score across features). Random ranking is the floor.
- **Input:** entity-windows (internal host × 5 min) with ~16 log-scaled features; fit only on windows that no detector finding overlaps.
- **Output:** ranked scores, top-3 deviating features per window, at most 10 promoted low-severity findings.
- **Decision gate G1 (pre-declared):** evaluated on the held-out-family test split (Section 17):
  - Ship `iforest` if its precision@10 exceeds `robust_z` by ≥ 0.10 absolute, the 95% bootstrap CI (over captures) of the difference excludes 0, and its promoted-window rate on benign captures is ≤ 1%.
  - Otherwise ship `robust_z` if its recall@10 of held-out episodes is ≥ 0.5 and its benign promoted rate is ≤ 1%.
  - Otherwise ship with anomaly triage `off` and document the negative result.
- **Not ML (by design):** the five detectors and robust baselining are rules over statistics. They are described as such everywhere.

## 12. AI/LLM capabilities

**Component:** optional incident narrative.
- **Problem:** turning several linked findings into a coherent, hedged account with benign alternatives and prioritised next checks.
- **Baseline:** deterministic template summary (always generated; 100% faithful).
- **Provider:** `none` (default), `ollama` (local), or an OpenAI-compatible/Anthropic API (requires explicit configuration).
- **Input:** a pseudonymised evidence pack (structured findings, metrics, evidence records, capture caveats, knowledge-card excerpts). No raw packets, no payloads, no attacker-controlled free text.
- **Output:** JSON with `summary`, `observed[]`, `inferences[]` (with confidence and ≥ 1 alternative explanation), `recommendations[]`, `open_questions[]`; every item references evidence (`E-…`) or knowledge (`K-…`) IDs.
- **Decision gate G2 (pre-declared):** the narrative feature ships enabled-by-configuration only if, on the evaluation set: validator pass rate ≥ 90% (≤ 1 repair attempt); manual audit shows observed-statement support ≥ 95%, unsupported inferences ≤ 5%, citation correctness ≥ 90%; and raters prefer it over the template in ≥ 60% of blind pairwise comparisons. Otherwise templates remain the only summary and the result is documented.
- **Removed:** vector RAG, embeddings, free-form chat (MVP), LLM-generated technique mapping.

## 13. Evidence & grounding requirements

| ID | Requirement |
|---|---|
| GR-01 | Every finding references concrete evidence records (Zeek UIDs or DNS transaction records) and stores the metric values that triggered it. |
| GR-02 | Evidence items have stable IDs (`E-<n>` within an incident) used in UI, reports and LLM packs. |
| GR-03 | ATT&CK references are phrased as "consistent with", never "is". |
| GR-04 | LLM `observed` statements may contain only identifiers, ports, and numbers present in the cited evidence (number tolerance ±1% for rounding). |
| GR-05 | LLM `inferences` must have confidence ≠ certain and ≥ 1 alternative (benign) explanation. |
| GR-06 | LLM output must not contain verdict language (e.g. "is compromised", "confirmed attack", "definitely", "proves"). |
| GR-07 | Knowledge citations must reference cards for techniques mapped to this incident. |
| GR-08 | Validation failures are stored with the raw output for evaluation; the UI shows the template instead. |
| GR-09 | Anomaly findings state "unusual relative to this capture" and list the deviating features; they carry no technique mapping. |

## 14. Security requirements

| ID | Requirement |
|---|---|
| SEC-01 | Uploaded files are untrusted. They are never executed, never extracted, and stored under server-generated UUID names. |
| SEC-02 | All parsing of capture bytes (Zeek, tcpdump/editcap) runs only in the worker container: non-root, read-only root filesystem, all capabilities dropped, `no-new-privileges`, CPU/memory/PID limits, per-stage timeouts, **no internet egress**. |
| SEC-03 | Raw packets and payloads are never sent to an LLM. |
| SEC-04 | Before any LLM call, hosts and domains are pseudonymised (H1 internal, X1 external, D1 domain); the mapping stays server-side. Attacker-controlled strings (DNS names, URIs, user agents, SNI, certificate fields) never appear in prompts. |
| SEC-05 | External LLM providers require explicit configuration and an API key from environment variables; default provider is `none`. |
| SEC-06 | The web UI escapes all capture-derived strings; no raw HTML rendering of capture data; report exports escape Markdown/HTML. |
| SEC-07 | The service binds to `127.0.0.1` by default; optional bearer token via environment variable; CORS restricted to the UI origin. |
| SEC-08 | Zeek password capture stays disabled (FTP/HTTP passwords are not logged). |
| SEC-09 | No secrets in code or images; `.env.example` documents required variables. |
| SEC-10 | Dependencies and container images are pinned (lockfiles, image digests or exact tags). |
| SEC-11 | Investigations can be deleted completely (FR-45); retention is documented. |
| SEC-12 | Logs never contain payloads, credentials, or full evidence dumps. |

## 15. Error handling

| Condition | Behavior |
|---|---|
| Wrong file type / over size / compressed | Reject at upload with a specific message; nothing stored |
| Zeek crash or timeout | Investigation `failed` with stage and reason; logs retained for debugging |
| Capture with no IP traffic or zero connections | Completed with profile and a "nothing to analyse" warning; no incidents |
| No DNS traffic | DET-DNSTUN reports "not applicable"; other detectors run |
| Weak baseline (small population) | Detectors use absolute floors only, with lowered confidence and a warning |
| Anomaly population too small | Anomaly triage skipped with warning (FR-23) |
| LLM unavailable / timeout | Template shown; narrative status `unavailable` |
| LLM output fails validation twice | Template shown; status `rejected` with reasons stored |
| Packet-slice generation fails or exceeds size cap | Error shown on the finding; analysis results unaffected |
| Worker crash mid-job | Job lease expires; job retried once from the start; second failure marks `failed` |
| Disk space below threshold | New uploads rejected with message |
| Database unavailable | API returns 503; worker pauses and retries with backoff |

## 16. Limitations (stated, not discovered)

- **Single capture:** "normal" means normal *within this capture*. Hosts with little traffic have weak baselines.
- **Encrypted traffic:** only metadata is analysed (timing, sizes, SNI, certificate fields). Encrypted brute force is inferred, not observed.
- **Capture position matters:** a capture from one segment cannot show traffic it didn't see; one-sided captures degrade connection-state signals.
- **Beacon detectability** depends on interval vs capture duration (Section 10); heavy jitter (> ~30%) and long sleep intervals evade periodicity scoring.
- **Low-and-slow behavior** (slow scans, small exfil) can stay under thresholds by design.
- **Anomaly ≠ malicious:** anomaly findings are leads, not detections.
- **Lab data bias:** self-generated traffic reflects the tools and topology used; CICIDS2017 is synthetic with documented labeling issues.
- **LLM narratives** are aids; they can be wrong in ways the validator cannot catch (e.g. a plausible but weak inference). They are labeled accordingly.

## 17. Dataset & evaluation strategy

### Corpora
| Corpus | Purpose | Notes |
|---|---|---|
| **LAB** (self-generated) | Primary evaluation | Docker/VM lab: attacker, servers, clients, benign traffic generators. Every attack run writes ground truth (`labels.jsonl`: run ID, tool, params, attacker, target, start/end, detector class). |
| **LAB hard negatives** | False-positive stress | rsync/backup, package updates, NTP, monitoring heartbeats, cloud-sync-like uploads, CDN-heavy browsing, video streaming, automation SSH |
| **LAB-HOLDOUT** | Anomaly gate G1 | Attack families with **no detector**: ICMP tunneling, slowloris, SMB/RPC enumeration, reverse shell on a non-standard port (at least 3 used) |
| **BENIGN** | FP per hour | LAB benign-only runs + CICIDS2017 Monday (benign day) |
| **CIC-ATTACK** | Secondary sanity check | Selected CICIDS2017 PCAP days (FTP/SSH-Patator brute force, PortScan, Bot/Ares beaconing). Reported separately; never the headline. |

### Splits and leakage controls
- Split **by capture/run**, never by row or flow. Captures are assigned to `dev` or `test` before any tuning, recorded in a split manifest committed to the repo.
- All thresholds, window sizes and model hyperparameters are tuned on `dev` only. `test` is evaluated once per milestone; repeated peeking is logged.
- **Tool-held-out:** DNS tunneling tuned on one tool (iodine) and tested on another (dnscat2), and vice versa; both reported.
- **Family-held-out:** LAB-HOLDOUT families are never used for tuning detectors.
- Fixed random seeds; run manifest stored with every result.

### Metrics
- Detectors: **episode-level** precision and recall (an episode is detected if a finding overlaps its entity and time range); FP findings per hour of BENIGN capture (medium/high confidence), reported both with and without network-context allowlists.
- Beaconing: detection rate across a sweep of interval × jitter × capture duration (detectability curve).
- Anomaly: precision@10, recall@10, PR-AUC on LAB-HOLDOUT test; promoted-window rate on BENIGN; 95% bootstrap CIs over captures; vs `robust_z` and random.
- LLM: validator pass rate; manual audit on 30–50 narratives; blind pairwise preference vs template (≥ 3 raters, ≥ 20 incidents) — reported as a small-sample usability signal.
- Performance: end-to-end time and peak memory for 50 MB, 200 MB and 500 MB captures.

## 18. Success metrics

Targets are initial engineering targets on **LAB test**. If a target proves unreachable or meaningless, it is revised with written reasoning in `eval/REVISIONS.md` — never by changing the test set.

| Area | Metric | Target |
|---|---|---|
| DET-SCAN | Episode recall / precision (default-speed scans) | ≥ 0.95 / ≥ 0.90 (slow scans reported separately) |
| DET-BRUTE | Episode recall / precision | ≥ 0.90 / ≥ 0.90 (FTP/HTTP and SSH reported separately) |
| DET-DNSTUN | Episode recall per held-out tool | ≥ 0.90 |
| DET-BEACON | Episode recall at jitter ≤ 20% with ≥ 10 events | ≥ 0.80 |
| DET-EXFIL | Episode recall above floor | ≥ 0.80 |
| All detectors | FP findings per benign hour (medium/high, with network context) | ≤ 1.0 |
| ATT&CK mapping | Mapping-table IDs valid in pinned bundle | 100% (enforced by test) |
| Anomaly | G1 outcome documented with CIs | Required (any outcome) |
| LLM | G2 outcome documented | Required (any outcome) |
| Performance | 500 MB PCAP end-to-end | ≤ 10 min |
| Reproducibility | Re-run of the full evaluation from the manifest | Identical metrics |

## 19. Acceptance criteria (MVP)

1. `docker compose up` starts the system; the UI is reachable on `127.0.0.1`.
2. Uploading the demo PCAP produces the multi-stage incident (scan → brute force → beacon → exfil) with linked findings, evidence, ATT&CK cards and a template summary.
3. Every finding shows metrics, thresholds, confidence, benign causes, and exports a packet slice that opens in Wireshark and contains the finding's flows.
4. Invalid files, oversized files and compressed files are rejected with clear messages.
5. A malformed-PCAP corpus is processed without crashing the API; worker failures are reported per investigation.
6. With `LLM_PROVIDER=none` every feature except the narrative works; with a provider enabled, a narrative either passes validation or the template is shown with a rejection reason.
7. A prompt-injection test capture (DNS names containing instructions) produces no injected text in prompts or outputs.
8. The evaluation harness regenerates all reported metrics from the committed split manifest and labels; G1 and G2 decisions are documented with numbers.
9. Detector, correlation and validator unit tests pass with ≥ 90% coverage; pipeline integration tests pass on the fixture captures.
10. Run manifest and report export are present for every completed investigation.

## 20. Future work

- Supervised DNS-tunnel scorer (conditional on measured DNS false-positive rates).
- Per-host historical baselining across investigations.
- Multi-PCAP correlation; Zeek log ingestion without PCAP.
- Streaming/near-real-time ingestion.
- TLS client fingerprinting (JA4) with a curated fingerprint set.
- Grounded incident Q&A (S1) promoted to MVP if G2 passes with margin.
- Learning from analyst feedback (threshold suggestions, never auto-applied).
- Additional detectors (ICMP tunneling, lateral SMB movement) — each with its own evaluation.
- Multi-user deployment with authentication and audit logging.
