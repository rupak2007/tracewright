# Evaluation

Every number below is copied from a file under `eval/results/` (named in the table) or from a command
whose output is quoted, and nothing else. Where nothing was measured, the text says **not measured**.
The protocol is `eval/PROTOCOL.md`; changes to it are in `eval/REVISIONS.md` (#1 to #8).

## 1. The headline, stated plainly

**No detector, anomaly or narrative metric on attacks exists.** The evaluation corpus has no labelled
attack episode and no held-out family, because this repository does not generate attack traffic and none
has been supplied. The protocol, matching rule, split tooling and harnesses are built, tested with
synthetic data, and refuse to touch the `test` split until the corpus is complete. What was measured is
(a) false positives on benign traffic, (b) throughput, (c) software correctness (tests, coverage,
sandbox and malformed-input checks).

| Gate / target | Status | Record |
|---|---|---|
| Detector recall and precision (PRD §18) | **Not measured** | `eval/results/dev-benign-baseline-v1/detectors.json` states `attack_metrics: not measurable` |
| `baseline-rules-v1` on `test` (M1) | **Not produced** | the harness refuses `--split test` (10/27 corpus requirements met) |
| G1, anomaly scorer | **Not run**, default `ANOMALY_SCORER=off` | `eval/decisions/G1.md` |
| G2, LLM narrative | **Not run**, default `LLM_PROVIDER=none` | `eval/decisions/G2.md` |
| NFR-01, 500 MB in 10 min | **Met on the benchmark host, with caveats** (section 5) | `eval/results/bench-v1/`, `bench-v1-synthetic/` |

## 2. Corpus

`python -m eval.splits report` (run 2026-10-08): **10 of 27 requirements met**.

* Recorded and frozen: six verified benign lab runs b01 to b06 (45 minutes each, 4.53 hours, 18 hard-negative
  episodes, zero Zeek missed bytes). Split by run: `dev` = b02, b04, b05; `test` = b01, b03, b06
  (`eval/splits.yaml`, append-only).
* Hard negatives present in both splits: RSYNC_BACKUP, PACKAGE_UPDATE, NTP, MONITORING_HEARTBEAT,
  CLOUD_SYNC_UPLOAD, CDN_BROWSING, VIDEO_STREAMING.
* **Missing**: at least 4 episodes per split for each of SCAN, BRUTE, DNSTUN, BEACON, EXFIL (10 requirements),
  the iodine and dnscat2 tool episodes (4), the AUTOMATION_SSH hard negative (1), at least 3 LAB-HOLDOUT
  families (1) and at least 8 LAB-HOLDOUT test captures (1). All need externally supplied, verified captures
  (`lab/register_external.py`, `lab/verify_run.py`). CICIDS2017 was deferred and satisfies none of them.

## 3. Detectors: what was measured

`eval/results/dev-benign-baseline-v1/` (detectors at their untuned PRD defaults, `dev` split, runs b02, b04,
b05, 2.2477 benign hours):

| Network context | Findings | Medium/high false positives | Per benign hour | By hard negative |
|---|---|---|---|---|
| With allowlists | 4 | 4 (all BEACON) | 1.78 | CDN_BROWSING 2, MONITORING_HEARTBEAT 1, PACKAGE_UPDATE 1 |
| Without allowlists | 6 | 6 (all BEACON) | 2.67 | the above plus NTP 2 |

Reading: SCAN, BRUTE, DNSTUN and EXFIL produced nothing on benign traffic. BEACON fires on regular harmless
traffic, and the PRD target (at most 1.0 per hour) is **not met** on this sample (1.78). That is reported as
found; thresholds were not tuned to hide it, and recall cannot be traded against it without attack data.

`eval/results/beacon-sweep-v1/` is a **synthetic timing model** of the beacon score, not performance on real
traffic: with at least 10 events the score fires at rate 1.0 for 10 to 60 s intervals at every jitter up to
50% over a one-hour capture, 0.95 at a 300 s interval with 50% jitter, and 0.0 at a 900 s interval (about
4 to 5 events in an hour, below the 10-event minimum). It shows where the detector cannot see, not how well
it sees.

## 4. Anomaly triage (G1) and narrative (G2)

* G1 needs LAB-HOLDOUT captures: none exist, so precision@10, recall@10, PR-AUC and the bootstrap difference
  are not computed. The only measured thing is a placeholder calibration of the promotion cut-off on benign dev
  windows (`eval/results/anomaly-calibration-dev-v1/`: 37 pooled rule-unexplained windows from b02, b04, b05;
  cut-offs robust_z 1163.98, iforest 0.6877; promoted rate 0.0 at those cut-offs by construction). The stage
  would skip every current lab capture anyway (fewer than 100 unexplained windows).
* G2 needs at least 30 test incidents and 3 raters and a model. No model was run on any incident, so there is
  no validator pass rate, audit or preference number. The tooling (`eval/run_llm.py`, `eval/score_llm.py`,
  `eval/llm_eval.py`) is tested only with scripted providers and synthetic ratings.

## 5. Performance (NFR-01)

`eval/results/bench-v1/bench.json` and `bench-v1-synthetic/bench.json`: three runs per capture of
`python -m app.cli analyze` in a container set up like the compose worker (non-root, read-only root,
no capabilities, no network, 3 GB memory, 4 CPUs, 256 PIDs).
Host: Intel Core i5-9500 (6 CPUs), Docker Desktop VM with 6 CPUs and 4.08 GB of memory, Windows 11.

| Capture | Size | Packets | Connections | Pipeline seconds (3 runs) | Mean ± SD | Largest process RSS |
|---|---|---|---|---|---|---|
| Lab benign, cut | 50 MB | 2,050 | 32 | 12.5, 11.6, 11.7 | 11.9 ± 0.5 | 252 to 254 MB |
| Lab benign, cut | 200 MB | 27,339 | 153 | 40.0, 67.7, 54.9 | 54.2 ± 13.9 | 257 to 259 MB |
| Lab benign, cut | 500 MB | 71,853 | 357 | 74.1, 70.5, 39.0 | 61.2 ± 19.4 | 256 MB |
| **Synthetic sizing capture** | 210 MB | 999,992 | 71,428 | 116.0, 97.5, 165.7 | 126.4 ± 35.3 | 386 to 395 MB |

All twelve runs completed. NFR-01 (500 MB, about 1M packets, within 10 minutes on 4 cores and 16 GB) is met
by a wide margin on both shapes, and no stage was changed for speed. Caveats, none hidden:

* The reference machine has 16 GB; this host's Docker VM has 4 GB. The container limit was 3 GB. Memory
  was never the constraint (the figure is the *largest single process*, a lower bound of the total).
* The spread between runs is large (the same 200 MB file took 40 to 68 s): bind-mount I/O dominates the
  `validate`, `zeek_parse` and `profile` stages and varies with the file cache. Treat means as indicative.
* The lab captures are byte-heavy and packet-poor (500 MB holds 71,853 packets), so they do not exercise
  connection-count scaling. The 1M-packet capture does (`eval/synth_capture.py`), but it is **synthetic**:
  complete, benign-shaped TCP conversations with valid checksums, no labels, no attack behaviour, never used
  for any detector or anomaly result.
* In the synthetic run `zeek_parse` (63 to 122 s) dominates, then `detect` (9 to 12 s) and `normalise`.
* `bench.json` records Git commit `f914ee7` with `dirty: true`: the benchmark tooling was committed afterwards.

## 6. Software correctness

* Tests (2026-10-08, full suite incl. security and integration, local Python 3.12): 702 passed, 13 skipped
  (skips: real-Zeek tests outside the worker image, opt-in PostgreSQL tests, the real ATT&CK bundle test).
  Line coverage of `app/`: 98%; `app/detect/` 99% to 100% per file, `app/correlate/` 100%,
  `app/explain/validator.py` 98% (targets: 90%).
* Frontend: 23 vitest tests (including XSS fixtures), ESLint with raw-HTML APIs banned, TypeScript strict,
  a Playwright test that passed on real Chrome against the real compose stack (P7).
* Inside the worker test image: the real-Zeek malformed-capture test passes (57 generated files: 6 stopped
  at the gate, 17 completed, 34 failed cleanly with a documented code); the worker sandbox script passes 9
  of 9 probes against the live container (`docs/SECURITY.md`).
* Real stack: `scripts/e2e_api.py` drove upload, analysis, incidents, slice (940 packets, real tcpdump and
  editcap), download, feedback, both report formats and delete on lab capture b02 (P6).
* Determinism (NFR-02): artifacts carry no timestamps and the manifest is hashed; tests assert identical
  output for identical input. The detector harness reproduces identical metrics (`test_metrics_are_reproducible`).

## 7. Threats to validity

* **The corpus is benign only.** Every false-positive number comes from 4.53 hours of one synthetic office
  (a Docker lab with scripted clients), which is a small and unusually regular population. Real networks are
  noisier; the BEACON false-positive rate there could be much higher or lower.
* **Lab bias.** Hard negatives were written by the same author as the detectors, so they may be easier or
  harder than what the detectors would meet; no external benign capture was used.
* **Tiny samples.** The anomaly cut-off rests on 37 windows; the dev false-positive rate on four findings.
* **Untuned thresholds.** Defaults come from the PRD, and tuning was deliberately not done without attack
  episodes, so no performance claim can be made for them in either direction.
* **Benchmark host.** One machine, noisy I/O, 3 repeats, a synthetic 1M-packet input.
* **Entity matching.** The protocol reading (actor or target counts as the affected host) was widened
  before any attack label existed (`eval/REVISIONS.md` #6); revisit it when real labels exist.
* **No external review.** Neither the security notes nor the protocol have been reviewed by anyone else, and
  CI has never run on GitHub (the workflow was only exercised locally).

## 8. How to complete the evaluation

1. Supply real, labelled attack captures and verify them (`python -m lab.register_external`,
   `python -m lab.verify_run`); record the AUTOMATION_SSH hard negative; append assignments with
   `python -m eval.splits assign` (never edit existing ones).
2. `python -m eval.splits report` must show 27 of 27 met.
3. Tune thresholds on `dev` only (`python -m eval.run_detectors --split dev`), record each change in
   `eval/REVISIONS.md`.
4. Run `--split test` once per milestone: detectors (`eval.run_detectors`), G1 (`eval.run_anomaly evaluate`),
   G2 (`eval.run_llm`, raters, `eval.score_llm --write-decision`). Replace the "Not run" decision records.
   Publish the numbers whatever they are.
