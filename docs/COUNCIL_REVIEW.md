# Council Review — NetInvestigator PRD (v0)

Reviewed document: `prd.md` (NetInvestigator — Product Requirements Document).
Outcome: the project survives, but **narrower in AI, stricter in evaluation, and stronger as a security tool**. Renamed to **Tracewright** (see "Project name").

**One-line verdict:** the investigation pipeline (rules → correlation → evidence → ATT&CK) is the real product; Isolation Forest is kept only as a *gated experiment* with a stricter role; vector RAG and the free-form chat are removed; the LLM is demoted to an *optional, validated narrative layer* that must beat deterministic templates to stay switched on.

---

## Seat-by-seat findings

### 1. Senior Cybersecurity Engineer
- The workflow framing (analyst-assistance, not autonomous verdicts) is correct and rare in student projects. Keep it.
- Writing a custom packet/flow assembler in Python (Scapy/PyShark) is the wrong call. **Zeek** is the standard way to turn a PCAP into connection, DNS, TLS, HTTP, SSH and FTP logs; it handles TCP state, reassembly and malformed traffic far better and much faster. Your value is in what you do *after* parsing.
- "Normal" is undefined without **network context**: which CIDRs are internal, which hosts are known scanners/resolvers/backup servers. Volume-exfil and beacon detection are meaningless without an internal/external notion. Add a small network-context config.
- Several "deterministic" classes are not cleanly deterministic: beaconing and DNS tunneling are *statistical* detectors with well-known false positives (NTP, update checks, telemetry, CDN and AV-reputation DNS). They must be designed with explicit known-FP lists, allowlists and confidence levels.
- The "≥10 minutes" capture rule is too crude. Beacon detectability depends on `capture_duration / beacon_interval`; a 5-minute beacon needs ~50 minutes to show 10 check-ins.
- Encrypted SSH/RDP brute force cannot be "seen" — only inferred from connection patterns. FTP (reply 530) and HTTP (401) can be seen. The tool must label these confidence levels differently.
- JA3 is weakened by modern browsers randomising TLS extension order, and there is no fingerprint database in scope. Record SNI and certificate metadata as evidence; drop fingerprint matching from the MVP.
- Missing analyst essential: **"show me the packets."** Every finding should export the exact packet slice for Wireshark. Analysts verify; they don't trust summaries.

### 2. ML Engineer
- The Isolation Forest (IF) role is **incoherent as written**: it is described as catching "behavior that doesn't match a known rule", yet it is evaluated "per attack class" on the same five classes the rules cover. If it is judged on known classes it is redundant; if it is meant for unknown behavior, it must be evaluated on attack families the rules *don't* cover. Neither is in the PRD.
- Swamping/masking: in a single capture, a port scan can generate thousands of flows. Fit IF on that population and the attack *is* the population — it is not anomalous. Fix: fit on traffic the rules did **not** explain, score everything.
- Unit of analysis matters. Per-host vectors give too few samples in a lab (10 hosts = 10 rows). Use **entity-windows** (internal host × 5-minute window).
- No baseline. IF must beat a trivial **robust z-score** scorer (median/MAD) or it doesn't earn its place. Without that comparison, "IF precision 70%" means nothing.
- Leakage risks are not addressed for rules either: tuning thresholds on the test captures is leakage too. Split by **capture/run**, never by row; tune on dev only; touch test once.
- Flow-level precision/recall inflates results (one scan = thousands of "correct" flows). Evaluate at the **attack-episode level**.
- CICIDS2017 has documented labeling and flow-extraction problems (Engelen et al., 2021). Use its PCAPs as a secondary corpus (benign Monday for false-positive rate; specific attack days as sanity checks), never as the headline result.
- Supervised multi-class classification: correctly excluded. Nothing in the problem needs it, and lab-generated labels would make it an overfitting exercise.

### 3. AI/LLM Engineer
- **Vector RAG is decorative here.** Once a detector fires, you already know which ATT&CK technique and playbook are relevant — retrieval is a key lookup, not a similarity search. The corpus is small and keyed by technique ID. Embeddings + a vector DB add a failure mode and no capability.
- The free-text Q&A conflates two different needs: "what else happened around this time?" is a **structured query over evidence** (a UI filter), not RAG; "what is T1071.004?" is a **knowledge-card lookup**. Neither needs an LLM.
- The incident explanation is the only LLM role with a real argument: synthesising several findings into a coherent, hedged narrative with alternative explanations. But **deterministic templates are a strong baseline** — they are 100% faithful. The LLM must be shown to be *more useful* than templates while staying faithful, or it stays off.
- "Citations" are not grounding unless they are *checked*. Add a deterministic validator: cited IDs must exist; IPs/ports/numbers in "observed" statements must appear in the cited evidence; certainty language is rejected; inferences must name a benign alternative.
- **Prompt injection via the PCAP itself** is unaddressed: DNS names, HTTP user-agents, URIs, SNI and certificate subjects are attacker-controlled strings. They must never reach the prompt verbatim. Pseudonymise identifiers (H1, X1, D1) and send only structured, numeric evidence.
- Network metadata is sensitive. Default to a local model (or no model); pseudonymisation is mandatory before any external API call.

### 4. Software Architect
- Microservices are unnecessary. A **modular monolith** with one API process and one worker process (same codebase) is right.
- No message broker needed: a Postgres job table with `SELECT … FOR UPDATE SKIP LOCKED` is enough for a single-analyst tool.
- Strong security boundary available for free: **the only component that parses untrusted PCAP bytes (worker: Zeek, tcpdump) gets no internet egress**, runs non-root, read-only filesystem, dropped capabilities, resource limits. LLM calls happen in the API process, not the parser.
- Storage: Postgres for incidents/findings/evidence; Parquet files for bulk per-investigation tables. No vector DB, no Redis, no MLflow, no Prometheus/Grafana — each is real infrastructure with no requirement driving it.
- Every run needs a **run manifest** (Zeek version, config hash, detector versions, model params, ATT&CK version, git commit) so results are reproducible and defensible.

### 5. Product Manager
- The real user problem is "where do I look first, and why?" The deliverable is a **ranked set of incidents, each with the evidence behind it and a way to verify it**. That's the MVP.
- Cut the chat. It demos well and delivers little; a filterable timeline and evidence table answer the same questions faster and without hallucination risk.
- Add a tiny feedback loop: analyst marks a finding TP / FP / expected-benign. It costs a day, produces evaluation data, and makes the tool feel real.
- Several success criteria are unmeasurable or arbitrary: "≤2× capture real-time" (a 1M-packet capture can span 10 seconds or 10 hours), "5–10 false alerts per 24h per host" (you will not have 24h of per-host benign traffic). Replace with absolute throughput and false findings **per hour of benign capture**.

### 6. Academic / Project Evaluator
- As written, the ML contribution is thin and indefensible: one off-the-shelf model with targets that don't match its stated purpose. A viva panel will ask "what did IF find that your rules didn't?" — there is currently no way to answer.
- The fix is not *more* models; it's a **real hypothesis**: *"Does multivariate unsupervised scoring of host behavior surface attack families that the rules do not cover, better than univariate robust statistics?"* — tested on held-out attack families, against a baseline, with a pre-declared keep/kill rule. A negative result, honestly reported, is still a strong contribution.
- Second defensible contribution: the **grounding validator** for LLM output, with measured faithfulness against templates.
- Third: the **detection evaluation methodology** itself (episode-level metrics, hard negatives, tool-held-out tests, detectability-vs-duration curves). This is where most student IDS projects are weakest.

### 7. Hackathon / Portfolio Reviewer
- The most impressive demo is **a multi-stage story**: external host scans → brute-forces SSH on host B → host B starts beaconing → host B pushes data out. Tracewright links these into one incident with a timeline, ATT&CK techniques, a "why this fired" panel and a one-click packet export to Wireshark.
- A chat box is what every AI demo has. A **validator that visibly rejects an LLM hallucination and falls back to the template** is what nobody has. Show it.
- Showing *negative* results ("IF did not beat robust-z on X; here's why") reads as senior-level maturity, not weakness.

---

## A. What is already strong

1. **Correct product framing:** analyst-assistance, human remains the decision maker, explicit non-goals (not a SIEM/IDS/Wireshark replacement).
2. **Bounded scope:** five named behavior classes rather than "detect all attacks".
3. **Evidence / inference / recommendation separation** for LLM output — the right instinct for a security tool.
4. **Raw PCAP never goes to the LLM** — correct security instinct.
5. **Deterministic ATT&CK mapping** instead of letting a model "guess" techniques.
6. **Assumptions & limitations stated up front** (encrypted traffic, baseline scope, dataset limits) and a rule that targets are revised with reasoning rather than silently hit.
7. **Supervised classification deferred** until data justifies it.

## B. What is weak (brutally)

| # | Weakness | Why it matters |
|---|---|---|
| 1 | IF role contradicts its evaluation (unknown behavior vs per-known-class metrics) | Indefensible in a viva; may be pure decoration |
| 2 | No baseline for IF | No way to show ML adds anything over simple statistics |
| 3 | IF swamping by high-volume attacks | The model can't flag what dominates its training population |
| 4 | Vector RAG over a small, ID-keyed knowledge base | Retrieval by similarity where retrieval by key is exact |
| 5 | Free-text Q&A mixes evidence queries and knowledge lookup | Uses an LLM where a filter or a lookup is better and safer |
| 6 | Citations without a checker | "Grounded" is a claim, not a property, until validated |
| 7 | Attacker-controlled strings could reach the LLM | Prompt injection via DNS names/URIs/SNI |
| 8 | Custom packet parsing implied | Slower, less robust, and a larger attack surface than Zeek |
| 9 | No internal/external network context | Exfil and beacon logic are ill-defined |
| 10 | "≥10 minutes" duration rule | Beacon detectability depends on interval, not a fixed duration |
| 11 | Flow-level metrics implied | Inflates precision/recall; scans dominate counts |
| 12 | Rule thresholds can leak from test data | Leakage is not only an ML problem |
| 13 | Latency target relative to capture duration | Unmeasurable; capture duration ≠ data volume |
| 14 | FP target per 24h per host | Data won't exist; replace with per hour of benign capture |
| 15 | No hard negatives (backups, NTP, update checks, CDN DNS) | Detectors will look perfect on easy lab data and fail on real traffic |
| 16 | JA3 as a feature | Weakened by TLS extension randomisation; no fingerprint DB in scope |
| 17 | No way to verify a finding against raw packets | Analysts can't trust what they can't check |

## C. What should be removed

| Removed | Replacement |
|---|---|
| Vector RAG (embeddings + vector store) | Deterministic **knowledge cards** keyed by ATT&CK ID + curated per-detector verification playbooks |
| Free-text analyst Q&A chat | Filterable timeline/evidence views; knowledge cards. *Stretch only:* grounded incident Q&A reusing the explanation validator, no vector DB |
| IF per-attack-class precision/recall targets | Held-out-family precision@k vs robust-z baseline, with a keep/kill gate |
| "Combined pipeline F1 ≈ 75–80%" | Per-detector, episode-level precision/recall + FP per benign hour |
| Latency "≤2× capture real-time" | Absolute throughput: ≤10 min for a 500 MB / ~1M-packet PCAP on a 4-core/16 GB machine |
| JA3/JA3S fingerprinting | SNI, TLS version, certificate metadata as evidence attributes only |
| Custom Scapy/PyShark flow assembly in the pipeline | Zeek (Scapy only for test fixtures and lab tooling) |
| Candidate stack items: Qdrant/FAISS, embeddings, XGBoost, MLflow, Prometheus, Grafana | Not needed by any requirement |

## D. What should be added (each materially improves the system)

1. **Zeek-based parsing** in a sandboxed, network-isolated worker.
2. **Network context config** (internal CIDRs, known scanners/resolvers/backup hosts, allowlisted domains).
3. **Capture profile & data-quality warnings** (duration, one-sided traffic, truncated packets, small population → weak baseline, beacon detectability limits).
4. **Findings with "why this fired"**: metrics vs thresholds, confidence level, known false-positive causes.
5. **Packet-slice export** per finding for Wireshark verification.
6. **Evidence IDs + deterministic grounding validator** for LLM output; **template summaries** as baseline and fallback.
7. **Pseudonymisation** of hosts/domains in anything sent to an LLM (prompt-injection and privacy control).
8. **Labeled lab corpus with ground-truth logging**, hard negatives, tool-held-out and family-held-out splits.
9. **Analyst feedback** (TP / FP / expected-benign) per finding.
10. **Run manifest** for reproducibility.
11. **Two pre-declared decision gates**: G1 (anomaly scorer) and G2 (LLM narrative).

## E. ML justification

| Component | Why it exists | Why rules aren't enough | Input | Output | Evaluation | Keep/Remove |
|---|---|---|---|---|---|---|
| Deterministic detectors (scan, brute force) | Known, crisp patterns | Rules *are* enough — that's the point | Zeek conn/ssh/ftp/http logs | Findings + evidence | Episode-level P/R, FP per benign hour | **Keep (not ML)** |
| Statistical detectors (DNS tunneling, beaconing, volume exfil) | Fuzzy behaviors with measurable statistics | They are rules over robust statistics (entropy, MAD, Bowley skew, modified z) — no learning needed | Zeek dns/conn/ssl logs + network context | Findings + confidence | Episode-level P/R on lab test, hard-negative FP, tool-held-out (DNS), jitter/duration sweep (beacon) | **Keep (statistics, explicitly not called ML)** |
| Intra-capture baselining (median/MAD) | "Unusual relative to this network" without history | Absolute thresholds alone ignore network scale | Per-pair / per-window aggregates | Modified z-scores | Used inside detectors; weak-baseline warnings tested | **Keep, renamed "robust baselining"** |
| Isolation Forest anomaly triage | Surface host behavior unlike the rest of the capture that **no rule explains** (unknown families) | Rules only cover five named classes by construction; the open question is whether multivariate scoring finds the rest better than univariate statistics | Entity-windows (internal host × 5 min), ~16 log-scaled features, **fit on rule-unexplained windows only** | Ranked anomaly score + top deviating features; capped low-severity "unexplained anomaly" findings | Held-out attack families (ICMP tunnel, slowloris, SMB enumeration, reverse shell on odd port): precision@10, recall@10, PR-AUC **vs robust-z baseline and random**; promoted-FP rate on benign corpus; bootstrap CI over captures | **Keep only as a gated experiment (G1).** Ship IF if it beats robust-z; else ship robust-z; else switch off and report the negative result |
| Supervised multi-class classifier | — | Rules already cover the named classes; lab labels would cause overfitting; no real labeled data | — | — | — | **Remove (future work only)** |
| Supervised DNS-tunnel classifier | Could reduce DNS rule FPs | Plausible, but adds a second model and dataset before the first is proven | — | — | — | **Defer (future work, conditional on G1 experience and DNS FP measurements)** |

**Isolation Forest, specifically:** in the original design it is not useful — it duplicates the rules and its metrics don't measure its purpose. Re-scoped (rule-unexplained windows, entity-window unit, held-out families, baseline, kill rule), it becomes the project's main *scientific question*. The council expects a real chance that robust-z wins; that outcome is acceptable and must be reported, not tuned away.

## F. LLM justification

| LLM Feature | User Problem Solved | Alternative Without LLM | Why LLM Is Better | Risk | Keep/Remove |
|---|---|---|---|---|---|
| Incident narrative (observed / inference / recommendation) | Turning 3–10 linked findings into a coherent, hedged account with benign alternatives and next checks, for triage and handoff | Deterministic templates per finding + ordered timeline | Cross-finding synthesis, plausible alternative explanations, prioritised next steps — *if* it stays faithful | Hallucinated facts, overconfident verdicts, prompt injection | **Keep as optional layer behind G2.** Templates are default and fallback; validator enforces grounding |
| Vector RAG for knowledge | Find relevant security knowledge | ATT&CK lookup by technique ID + curated playbooks | None — the key is known once a detector fires | Wrong-document retrieval; extra infra | **Remove** |
| Free-text analyst Q&A | Ad-hoc questions about the incident | Timeline/evidence filters; knowledge cards | Marginal for MVP | Answers outside evidence; injection | **Remove from MVP; stretch S1** (same evidence pack + validator, no vector DB) |
| LLM-generated ATT&CK mapping | Technique attribution | Deterministic table | None | Wrong techniques stated as fact | **Remove (never existed as LLM; keep deterministic)** |
| LLM-generated report | Handoff document | Rendered report from stored data; LLM narrative embedded only if validated | None beyond the narrative above | Unvalidated text in a formal artifact | **Remove as separate feature** |

## G. Final recommended architecture

```
PCAP upload (validated, hashed)
 → Zeek (sandboxed worker, no egress) → normalized Parquet tables
 → capture profile + data-quality warnings + network context
 → 5 detectors (rules + robust statistics) → findings with evidence
 → anomaly triage (G1-gated: IF | robust-z | off) on rule-unexplained windows
 → deterministic correlation → incidents (+ cross-incident links)
 → ATT&CK mapping + knowledge cards (pinned STIX bundle)
 → template summary (always)
 → optional LLM narrative (G2-gated, pseudonymized evidence pack, validator, fallback)
 → dashboard + packet-slice export + report + analyst feedback
 → human analyst decides
```

Runtime: FastAPI API + Python worker (same codebase) + PostgreSQL + Nginx-served React UI + optional Ollama, via Docker Compose. Two Python processes, one database, no broker, no vector store.

---

## Project name

### 1. Professional / Enterprise
1. **Tracewright**
2. **Casewire**
3. **Provenet**
4. **Packet Ledger**
5. **Flowbrief**

### 2. Technical / Research
6. **FlowProof**
7. **Corroborator**
8. **NetEpisode**
9. **Capture Casebook**
10. **Residue** (what's left after rules explain the traffic)

### 3. Short / Brandable
11. **Spoor**
12. **Plumb**
13. **Vigil**
14. **Quarry**
15. **Tally**

### 4. Open-source style
16. **pcapcase**
17. **flowdossier**
18. **pktledger**
19. **capsleuth**
20. **netcasefile**

### Top 5 explained

| Name | Meaning | Why it fits | Professional? | Survives AI reduction? |
|---|---|---|---|---|
| **Tracewright** | A *wright* is a builder (shipwright, playwright): one who builds from traces | The product's job is to construct incidents from network traces — evidence first | High; sounds like a real vendor tool | Yes — says nothing about AI |
| **Casewire** | A case file built from what was on the wire | Directly describes PCAP → incident case | High, slightly legal-sounding | Yes |
| **Provenet** | Provenance + network | Every claim traces back to its evidence | Medium-high; could be mistaken for a networking vendor | Yes |
| **Packet Ledger** | An auditable record of what packets prove | Emphasises traceability and chain of custody | High but long | Yes |
| **Spoor** | The trail a tracked animal leaves; trackers reconstruct events from it | Strong investigative metaphor | Medium — memorable but unfamiliar word | Yes |

### Recommended: **Tracewright**

It describes what the system does (builds incidents from traces), carries no AI claim to defend, and stays accurate whether the final system ships with IF, robust-z, an LLM, or none of them.

Availability notes from a quick check: "WireCASE" (3D-model company), "Groundwire Security" (a security consultancy), "WireTrail" (a network scanner) and "Tracebound" (a GitHub project) already exist, so those were dropped. Tracewright was not checked for trademarks or GitHub/org availability — do that before publishing.

---

## Decision log

| ID | Decision | Owner seat(s) |
|---|---|---|
| D1 | Zeek replaces custom packet/flow extraction | Security, Architect |
| D2 | Modular monolith: API + worker, Postgres job table, no broker | Architect |
| D3 | Network context config required for exfil/beacon logic | Security |
| D4 | Detectors are rules + robust statistics, not ML | Security, ML |
| D5 | IF re-scoped to rule-unexplained entity-windows; gated by G1 vs robust-z | ML, Academic |
| D6 | Vector RAG and chat removed; knowledge cards by ATT&CK ID | LLM, PM |
| D7 | LLM narrative optional; templates default; validator + fallback; gated by G2 | LLM, Academic |
| D8 | Pseudonymised evidence pack; attacker strings never reach prompts | LLM, Security |
| D9 | Episode-level metrics, split by capture, hard negatives, held-out families | ML, Academic |
| D10 | Packet-slice export and analyst feedback in MVP | Security, PM |
| D11 | Renamed NetInvestigator → Tracewright | Portfolio, PM |

---

## Final quality check (run after writing all four documents)

| # | Question | Answer | Fix applied |
|---|---|---|---|
| 1 | Is the ML actually necessary? | Not for the core product. It is kept as one bounded, falsifiable experiment (G1) with a robust-z baseline and an `off` outcome. | Gate written into PRD §11, plan P5, instruction §3.8 |
| 2 | Is the LLM actually useful? | Unproven. Its only plausible value is cross-finding synthesis; templates are the baseline and default. | Default `LLM_PROVIDER=none`; G2 decides; validator + fallback |
| 3 | Could any AI component be removed without making the product worse? | Yes — both, by design. The product is complete at M3 (plan P7) with no ML or LLM. | Schedule-slip cut order in plan.md drops the LLM before anything security-critical |
| 4 | ML because the problem needs it, or because it's "an AI project"? | The residual-triage hypothesis is a real question the rules cannot answer by construction; everything that was AI-for-the-title (vector RAG, chat, supervised classifier, JA3 matching) was removed. | COUNCIL_REVIEW §C |
| 5 | Is the evaluation scientifically defensible? | Yes, with stated limits: split by run, dev-only tuning, episode-level metrics, hard negatives, tool- and family-held-out tests, bootstrap CIs, pre-declared gates. Lab bias and small rater samples are documented threats to validity. | PRD §17, architecture §20, plan P10 `EVALUATION.md` |
| 6 | Can every major feature be demonstrated? | Yes: one demo PCAP drives the storyline, why-this-fired, packet slice, ATT&CK cards, anomaly list, and a narrative with a visible validator rejection. | plan P10 demo script |
| 7 | Can every architectural decision be explained in a viva? | Yes — each has a decision-log entry (D1–D11) and an ADR planned in P0. | ADR-001…005 in plan P0 |
| 8 | Is the scope realistic for a student project? | Tight but feasible in ~14 weeks; the lab corpus is the main risk and starts in week 2. | Risk register + cut order in plan.md |
| 9 | Any "AI slop" left? | None found. Detectors are explicitly labelled rules/statistics; anomaly output is worded "unusual relative to this capture"; LLM output can't reach the UI unvalidated. | instruction §3.10–3.11, §4.7 |
| 10 | Does it look like a real investigation product? | Yes: Zeek-based parsing, network context, data-quality warnings, evidence IDs, packet export to Wireshark, analyst feedback, run manifests, sandboxed parser. | — |

Consistency fixes made during the check: severity formula wording clarified for undirected links (architecture §9); explicit dependency allowlist added (instruction §1.6); CLI fixed to stdlib `argparse` (plan P1); schedule-slip cut order added (plan.md).

