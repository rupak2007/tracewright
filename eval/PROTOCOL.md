# Tracewright — Evaluation Protocol

| Field | Value |
|---|---|
| Version | 1.0 (frozen at the end of P0, before any detector code exists) |
| Implements | `docs/PRD.md` §11, §12, §17, §18; `docs/architecture.md` §20; `docs/instruction.md` §3 |
| Changes | Only by an entry in `eval/REVISIONS.md` with written reasoning (and user approval where `instruction.md` requires it). Never by editing a test capture, label or split to improve a number. |

This document is written **before** any detector exists so that no threshold, window size or hyperparameter is chosen with knowledge of the test data. If anything here conflicts with `docs/PRD.md`, the PRD wins.

## 1. Corpora

| Corpus | Purpose | Notes |
|---|---|---|
| **LAB** (self-generated) | Primary evaluation | Docker lab: attacker, servers, clients, benign traffic generators (`lab/README.md`). Every attack run writes ground truth to `labels.jsonl`. |
| **LAB hard negatives** | False-positive stress | rsync/backup, package updates, NTP, monitoring heartbeats, cloud-sync-like uploads, CDN-heavy browsing, video streaming, automation SSH |
| **LAB-HOLDOUT** | Anomaly gate G1 | Attack families with **no detector**: ICMP tunneling, slowloris, SMB/RPC enumeration, reverse shell on a non-standard port (at least 3 used). Never used to tune detectors. |
| **BENIGN** | FP per hour | LAB benign-only runs (≥ 4 h in total) + CICIDS2017 Monday (benign day) |
| **CIC-ATTACK** | Secondary sanity check | Selected CICIDS2017 PCAP days (FTP/SSH-Patator brute force, PortScan, Bot/Ares beaconing). Reported separately; never the headline. |

Sources and SHA-256 of every external capture are recorded in `eval/datasets.md` (P2). Self-generated captures are recorded with their SHA-256 in the split manifest.

## 2. Episodes and ground truth

An **episode** is one labelled attack (or labelled hard-negative) interval inside one capture. Each lab scenario appends one JSON object per episode to the run's `labels.jsonl`:

```json
{"run_id":"r014","episode_id":"r014-e2","class":"BRUTE","tool":"hydra","params":{"service":"ssh","threads":4},
 "actor":"172.20.0.10","targets":["172.20.0.21"],"start":"2026-11-02T10:04:11Z","end":"2026-11-02T10:06:40Z"}
```

(The example is a format illustration, not a data point.) `lab/check_labels.py` (P2) verifies that every episode's actor/target IPs appear in the capture's Zeek `conn.log` within the labelled time range.

## 3. Matching rule

A finding **matches** an episode when all of the following hold:

1. **Entity:** the finding's primary entity equals the episode's actor (SCAN/BRUTE) or the affected internal host (DNSTUN/BEACON/EXFIL), or the finding's secondary entities include an episode target for SCAN/BRUTE;
2. **Time:** the finding's `[start_ts, end_ts]` overlaps the episode's `[start, end]` expanded by **±60 s** on each side;
3. **Class:** the finding type equals the episode class (anomaly findings are matched against LAB-HOLDOUT episodes by entity and time only, since no detector class exists for them).

An episode is **detected** if at least one finding matches it. A finding that matches no episode of any class, in a capture where all attacks are labelled, is a **false positive**. Hard-negative episodes are labelled so that a finding matching one is counted as a false positive for that hard-negative type.

## 4. Splits and leakage controls

- Split **by capture/run**, never by row, flow or time slice within a capture.
- `eval/splits.yaml` assigns every run to `dev` or `test` (≈ 50/50 per scenario type) **before P3 begins**. It is committed; any later change requires an entry in `eval/REVISIONS.md` and user approval. A capture is never moved between splits to improve a metric.
- **Tool-held-out (DNS tunneling):** tuned on one tool (iodine) and tested on another (dnscat2), and vice versa; both directions are reported.
- **Family-held-out:** LAB-HOLDOUT families are never used for tuning detectors. LAB-HOLDOUT `dev` captures may be used only to tune the anomaly window size and Isolation Forest hyperparameters.
- Minimum corpus (plan.md P2 acceptance): every attack class ≥ 4 dev and ≥ 4 test episodes; hard negatives present in both splits; ≥ 8 LAB-HOLDOUT test captures; ≥ 4 h of benign-only capture.
- Fixed random seeds. Every result carries a run manifest (`git commit`, config hash, feature-set version, scorer, hyperparameters, seed, split, Zeek version, timestamp) in `eval/results/<run_id>/manifest.json`.

## 5. Tuning-on-dev rule

- All thresholds, window sizes, promotion thresholds and model hyperparameters are tuned on `dev` **only**.
- Each threshold/default change is recorded with its reason in `config/detectors.yaml` comments and `eval/REVISIONS.md`.
- `test` is evaluated **once per milestone** (plan.md: M1 baseline, G1, final). Every test evaluation is logged with its run ID; repeated peeking is logged, not hidden.
- The assertion "no test capture ID appears in any tuning log" is a test (P5).
- Targets in PRD §18 that prove unreachable or meaningless are revised in `eval/REVISIONS.md` with reasoning, never by changing the test set.

## 6. Metrics

- **Detectors:** episode-level precision and recall; false-positive findings per hour of BENIGN capture (medium/high confidence), reported both with and without network-context allowlists. Slow scans and FTP/HTTP vs SSH brute force are reported separately.
- **Beaconing:** detection rate across a sweep of interval × jitter × capture duration (detectability curve).
- **Anomaly:** precision@10, recall@10, PR-AUC on LAB-HOLDOUT test; promoted-window rate on BENIGN; 95% bootstrap CIs (1,000 samples, resampling captures); compared against `robust_z` and random.
- **LLM:** validator pass rate; manual audit of 30–50 narratives; blind pairwise preference against the template (≥ 3 raters, ≥ 20 incidents), reported as a small-sample usability signal.
- **Performance:** end-to-end time and peak memory for 50 MB, 200 MB and 500 MB captures.
- **Reporting rule:** every number in docs, README, UI or commit messages comes from a file under `eval/results/<run_id>/` and cites the run ID. Anything unmeasured is written "not yet measured". Nothing is estimated.

## 7. Gate G1 — anomaly scorer (verbatim from PRD §11)

> **Decision gate G1 (pre-declared):** evaluated on the held-out-family test split (Section 17):
>   - Ship `iforest` if its precision@10 exceeds `robust_z` by ≥ 0.10 absolute, the 95% bootstrap CI (over captures) of the difference excludes 0, and its promoted-window rate on benign captures is ≤ 1%.
>   - Otherwise ship `robust_z` if its recall@10 of held-out episodes is ≥ 0.5 and its benign promoted rate is ≤ 1%.
>   - Otherwise ship with anomaly triage `off` and document the negative result.

Procedure: `eval/run_anomaly.py` evaluates once on LAB-HOLDOUT test + BENIGN test, writes `anomaly.json`, and `eval/decisions/G1.md` applies the rule above with the numbers and CIs. The shipped `ANOMALY_SCORER` default must match the decision. A negative outcome is documented, not rescued.

## 8. Gate G2 — LLM narrative (verbatim from PRD §12)

> **Decision gate G2 (pre-declared):** the narrative feature ships enabled-by-configuration only if, on the evaluation set: validator pass rate ≥ 90% (≤ 1 repair attempt); manual audit shows observed-statement support ≥ 95%, unsupported inferences ≤ 5%, citation correctness ≥ 90%; and raters prefer it over the template in ≥ 60% of blind pairwise comparisons. Otherwise templates remain the only summary and the result is documented.

Procedure: `eval/run_llm.py` generates narratives for ≥ 30 test incidents; blinded audit and pairwise sheets live in `eval/audit/` (statement-level supported/unsupported/citation-correct; template-vs-narrative with randomised order); `eval/score_llm.py` computes the metrics and `eval/decisions/G2.md` applies the rule above. The default provider configuration must match the decision.

## 9. Reproducibility

Re-running an evaluation from its manifest must give identical metrics (NFR-02). Results are JSON files committed under `eval/results/<run_id>/`; the baseline results (`baseline-rules-v1` tag and the `robust_z` scorer) are kept permanently and always reported next to any ML result.

## 10. Status

| Item | Status |
|---|---|
| Protocol | Frozen (this document) |
| Lab corpus, labels, `eval/splits.yaml`, `eval/datasets.md` | Not yet built (P2) |
| Detector results | Not yet measured |
| G1 | Not run |
| G2 | Not run |
