# Final audit of Tracewright (release candidate 4 and after)

Audit date: 2026-11-01. Auditor: the engineering agent that built the project, auditing its own work, so this
is **not an independent review**; every check below was re-run in this session rather than copied from an
earlier report. Categories are kept apart throughout: *implemented* (the code exists), *tested* (automated
tests pass), *measured* (a result file records a number), *validated against real attack data* (never done),
*not evaluated*.

## 1. Verdict

**Repository-side engineering is complete. Scientific evaluation is not, and cannot be completed from this
repository.** No genuine defect that blocks the engineering claims remains open. What is missing is evidence,
not code: authorised attack and held-out captures, G2 raters and a model, and a few human actions (section 8).
Tracewright is therefore **not** `v1.0`.

## 2. Verified project state (all re-run 2026-11-01)

| Check | Result | Where |
|---|---|---|
| Git | branch `master`, clean tree, `origin/master` equal; tags `v1.0-rc1` to `v1.0-rc4` | `git status`, `git ls-remote` |
| GitHub CI | **green** on `394b699` (run 41302110203) and on the audit's own code commit `f67080f` (run 41306184226): backend lint/mypy/pytest incl. Postgres and corpus integrity, docker job (pinned Zeek, sandbox, real-Zeek suite, API end-to-end), web job. Docs-only commits after `f67080f` were not separately awaited | `gh run view` |
| Ruff / format / mypy | clean (190 files, 113 source files) | local |
| Backend tests | **736 passed, 13 skipped**, 98% line coverage of `app/`; `detect/` + `correlate/` + validator 99% (before the Wilson-interval tests; 4 more tests were added) | local pytest |
| Skips | 13 = real-Zeek tests outside the worker image, opt-in Postgres, the real ATT&CK bundle | |
| Worker image suite | 481 passed, 33 skipped (2026-11-01, earlier in the session on identical code paths) | worker test image |
| Frontend | lint, typecheck clean, **23 tests**, build OK | local |
| Dependency audit | `pip-audit` **0** known vulnerabilities (186 packages); `npm audit --omit=dev` **0**; `npm audit` all: 0 high, **15 moderate**, all in dev tooling (`minimatch` through eslint and friends), accepted | local |
| Image scan (Trivy 0.76.1, pinned) | web 0; API 44 HIGH, **0 fixable**; worker 123 HIGH + 6 CRITICAL, **0 fixable**; upstream `postgres:16.15` 88, of which 26 fixable (compiled Go `gosu`, needs a new upstream image) | `eval/results/image-scan-v2/` |
| Worker sandbox | **9/9** probes PASS on rebuilt images | `scripts/check_worker_sandbox.sh` |
| Compose and API workflow | `docker compose up --wait`, then upload, analysis, incidents, evidence, packet slice, download, feedback, both reports, delete on lab capture b08: all pass | `scripts/e2e_api.py` |
| Fresh clone from GitHub | earlier this session at `d6f1ba0`: `docker compose up --build` and the full API flow pass; CI repeats it on every push | |
| Performance | 500 MB lab capture **25.6 s** mean (24.8, 26.4); synthetic 1M-packet capture **93 s** (89, 98); largest process RSS 393 MB. Earlier set the same day: 24 s and 50 s. The synthetic figure moved by almost 2x between two idle-host sessions, so quote it as roughly 50 to 100 s | `eval/results/bench-v3/`, `bench-v2*` |
| Corpus | `eval.splits validate --against-git`: 8 runs, OK. **11/27** requirements met, **0/6** reporting prerequisites met | `eval.splits report` |
| OpenAPI export | current | `scripts/export_openapi.py --check` |

## 3. Findings, ranked by severity

No critical or high finding is open.

| # | Severity | Finding | Status |
|---|---|---|---|
| 1 | **Medium (evidence)** | No labelled attack capture exists, so every claim about detection effectiveness, G1 and G2 is unsupported. This is a missing-data finding, not a defect | OPEN, external (section 8) |
| 2 | Medium (statistics) | 4 to 8 episodes per class cannot demonstrate the PRD section 18 targets. Even 4 of 4 detected has a 95% Wilson lower bound of 0.51; showing recall of at least 0.90 with 95% confidence needs about 29 perfect detections | Documented; intervals now reported (see 5); the decision rule is a protocol question (section 6) |
| 3 | Low (documentation) | Stale statements found by this audit: `eval/datasets.md` and `lab/README.md` still said `AUTOMATION_SSH` had no scenario and the corpus was 10/27; the corpus report labelled it "not yet written"; README/CLAUDE named an old CI run; one sentence in `docs/EVALUATION.md` explained the missing BRUTE finding on b08 as luck | **FIXED** (`f67080f`) |
| 4 | Low (design limit) | DET-BRUTE leaves out SSH connections Zeek reports as successfully authenticated (`backend/app/detect/brute.py`). That is why the AUTOMATION_SSH run gave no BRUTE finding, and it also means an SSH attack whose sessions all authenticate, or that Zeek cannot classify, is invisible to this rule | Documented; not a bug; effectiveness unmeasured |
| 5 | Low (reporting) | Detector metrics carried point estimates only | **FIXED**: Wilson 95% intervals on overall, per-class and per-sub-population recall and precision (`eval/matching.py`, tests). They assume independent episodes and are optimistic for episodes inside one capture |
| 6 | Low (security, default) | The API has no authentication unless `API_TOKEN` is set; it is loopback-bound; the `api` container shares the `edge` network and so has egress (needed for an external LLM, off by default); the `db` container keeps default capabilities | Documented in `docs/SECURITY.md`; accepted for a single-user local tool |
| 7 | Low (security, supply chain) | 15 moderate dev-tooling npm advisories; unfixable Debian/Zeek-base findings in API and worker images; upstream Postgres fixable only by a new upstream image | Documented exceptions; the shipped web image contains only built static files |
| 8 | Info | CI history: `v1.0-rc1` and `v1.0-rc2` point at builds that were red on GitHub (two defects, since fixed). Tags are not rewritten | Documented |

Not found: any open bug in the detectors, correlation, evidence generation, API or UI beyond the above. That is
a statement about the tests passing and a read-through, not a proof.

## 4. The BEACON rate (2.00 per hour against a target of 1.0)

Evidence: `eval/results/dev-benign-baseline-v2/` (dev runs b02, b04, b05, b08; 3.00 benign hours; with allowlists).
All six findings were inspected:

| Run | Finding | Series, port, events, score | The labelled benign behaviour it matches |
|---|---|---|---|
| b02 | high | ip, 8080, 60 events, 0.94 | monitoring heartbeat every 45 s |
| b02 | medium | ip, 53, 3296 events, 0.89 | CDN browsing client (DNS lookups every 0.2 s in a loop) |
| b02 | medium | http_requests, 80, 3300 events, 0.90 | the same client's HTTP fetches |
| b04 | medium | http_requests, 8082, 350 events, 0.87 | package-update loop |
| b08 | high | ip, 22, 240 events, 0.997 | scheduled SSH automation bursts |
| b08 | high | ip, 8080, 50 events, 0.98 | monitoring heartbeat every 55 s |

**Verdict: these are not mislabelled benign activity and not a code bug.** The traffic really is periodic, which is
what the detector measures, and the generators were written to be periodic on purpose (they are the hard
negatives). It is a **detector limitation**: a timing-regularity score cannot tell a benign scheduler from a
C2 implant, and the PRD lists exactly these as known benign causes. Two further observations:

* The lab hard negatives are designed to look like beacons, so 2.0 per hour is a **stress-test figure, not an
  estimate for real networks**, in either direction. The unallowlisted lab heartbeats would be allowlisted in a
  real deployment (the allowlist exists, but only port 123 is configured for the lab).
* The two sub-second scripted clients (3296 and 3300 events) are not what a human would call beaconing; the
  detector has no minimum interval, because the PRD specifies none. Whether to add one is a tuning decision that
  must be made on `dev` with attack episodes available, so recall is measured in the same step.

**Nothing was tuned**, and the test split was never read. The target stays "not met"; it can only be revisited
with attack data, otherwise any change trades an unmeasured recall for a measured false-positive rate.

## 5. Detection system review (code correctness, not proven effectiveness)

| Detector | What it does (verified in code and tests) | Main risks, stated plainly |
|---|---|---|
| SCAN | distinct ports/hosts in 60 s and 10 min windows, failed-state share for confidence | slow scans slower than the long window; scanners behind NAT; no per-sub-population result until labelled data exists |
| BRUTE | FTP 530 and HTTP 401/403 counts (observed); SSH/RDP/Telnet connection-shape inference (inferred) | blind to authenticated-success SSH (finding 4); the inferred family has the weakest evidence and will probably show the widest intervals |
| DNSTUN | unique subdomains with entropy or length, TXT/NULL share | CDNs and telemetry; DoH tunnels are invisible (plain DNS only) |
| BEACON | MAD-based regularity, skew, size and coverage score over IP, name and HTTP-request series | benign schedulers (section 4); HTTPS beacons that keep one connection open are invisible; needs at least 10 events |
| EXFIL | outbound bytes floor plus modified z and out/in ratio over internal-to-external pairs | needs a correct internal/external network context (a lab topology issue found in P3, now checked at registration); a weak baseline degrades to a floor and low confidence |

Correlation, ATT&CK mapping (pinned v19.2, phrased "consistent with") and evidence IDs are deterministic and tested
(99 to 100% coverage on detect/correlate, byte-identical reruns). Malformed input: a 57-file generated corpus ends in
`completed` or a documented failure with real Zeek; the API never answers 5xx for it. **None of this establishes
that the detectors find attacks.** Zero attack episodes have been scored.

## 6. Evaluation integrity

| Concern | Assessment |
|---|---|
| Capture-level separation | enforced by the tool: splits by run, append-only, hash-bound; the frozen assignments of b01 to b06 are pinned by a regression test; `validate --against-git` and CI check it |
| Campaign independence | external runs need a `campaign_id`; runs sharing one are assigned to one split, and `validate` fails otherwise. **Slices of one recording are not detectable by code** (different hashes); this is a procedural rule in the handoff |
| Leakage into tuning | the test split is refused by every harness until 27/27 and the 6 prerequisites; held-out `dev` runs are for G1 parameters only, held-out `test` never inspected. No code checks the dev-only rule for G1 parameter tuning beyond the calibration command; it rests on discipline and `REVISIONS.md` logging |
| Label completeness | unlabelled in-scope events become false positives, so suppliers must label everything; **verification checks that traffic exists in the window, not that it is of the labelled class** |
| Ground truth reliability | labels come from the supplier's schedule; provenance attestations are recorded, not verified |
| Held-out families | `ICMP_TUNNEL`, `SLOWLORIS`, `REVERSE_SHELL` chosen; about 16 runs for 8 test captures |
| Reproducibility | results carry config hash, git commit and dirty flag, Zeek version; reruns of the dev harness reproduce the numbers (v1 numbers reproduced exactly on 2026-10-08). Benchmarks are noisy (finding in section 2) |
| Reporting accuracy | every number in the docs comes from a result file or a quoted command; stale statements found and fixed (finding 3) |

**Are the 27 requirements and 6 prerequisites enough for the claims Tracewright intends to make?**
Enough to *report* per-class and per-family results with honest intervals, to run G1 with a bootstrap over
captures (G1 itself resamples captures, which handles within-capture correlation), and to keep every gate honest.
**Not enough to *confirm* the PRD section 18 targets** at the minimum counts: with 4 episodes per class and split,
a "target met" claim cannot be statistically supported. **Recommended (a protocol decision for the project
owner, not made here):** adopt before any data arrives the reporting rule "a target is called *met* only if the
95% lower bound reaches it, *not met* if the upper bound falls below it, otherwise *not demonstrated*"; and
prefer the recommended 8 attack runs. No requirement should be weakened.

## 7. Security threat-model review

| Threat | Control and evidence | Residual risk (not claimed away) |
|---|---|---|
| Malicious PCAP / parser exploit | only the worker parses; non-root, read-only filesystem, no capabilities, no network, PID and memory limits; 9/9 probes; malformed corpus | a Zeek/tcpdump/editcap exploit would give code execution inside the worker; escape through the container runtime is not tested here |
| Resource exhaustion | upload cap, Zeek timeout, container limits, streaming validation; 500 MB and 1M packets benchmarked | a user allowed to upload can still occupy the worker; no rate limit |
| API access | optional bearer token (constant-time compare, non-ASCII safe), CORS pin, input ranges, 4xx for malformed input | **no authentication by default**; no TLS; no per-user separation |
| Container privileges | `cap_drop: ALL`, `no-new-privileges`, read-only roots, digest-pinned images; worker gets only its database login, never the LLM key or API token | `db` keeps default capabilities; the `api` container has egress |
| Secrets | tracked-file scan test, `.env` untracked, key and token placeholders empty, the lab SSH key generated at image build (not committed) | none known |
| Network egress | worker on an `internal: true` network (probe-verified); the API's egress exists only for an opt-in external LLM | with an external LLM configured, the pseudonymised pack leaves the machine |
| File handling | server-chosen UUID names, sanitised metadata, traversal tests, slices cut with fixed argv | slices contain real payload bytes |
| Dependencies | audits above | 15 moderate dev-tooling advisories; unfixable upstream OS findings |
| LLM injection and leakage | capture strings never enter the pack, six-check validator, repair-once, template fallback; tested with an injection fixture and scripted providers | **no real model was ever run**; a plausible, wrong, cited inference is possible; pseudonymisation is not anonymisation |

Nothing here is a claim that the system is secure; tests and scans are point-in-time evidence on one machine.

## 8. Outstanding PRD section 19 criteria

| # | Criterion | Status |
|---|---|---|
| 1 | `docker compose up`, UI on 127.0.0.1 | met (verified this session) |
| 2 | Demo PCAP with the multi-stage incident | **not met**: needs a real attack capture |
| 3 | Findings show metrics etc.; slice opens in Wireshark | partly: slice content verified with tcpdump/editcap/capinfos; **opening it in Wireshark by hand was never done** |
| 4 | Invalid/oversized/compressed files rejected clearly | met |
| 5 | Malformed corpus does not crash the API | met |
| 6 | Works with `LLM_PROVIDER=none`; with a provider, validated narrative or template | met for `none`; provider path tested with scripted providers only |
| 7 | Injection capture produces no injected text | partly: synthetic evidence through real pipeline stages; no recorded hostile capture |
| 8 | Harness regenerates all metrics; G1 and G2 decided with numbers | **not met**: G1 and G2 not run |
| 9 | Coverage at least 90% for detectors, correlation, validator; integration tests pass | met |
| 10 | Run manifest and report export | met |

## 9. External blockers (human-dependent, tracked, not simulated)

| Blocker | Who | Handoff prepared |
|---|---|---|
| Authorised attack and held-out captures (recommended 8 attack runs, 16 held-out, spares) | an authorised isolated lab or collaborator | `docs/CAPTURE_HANDOFF.md`, `docs/CAPTURE_ACQUISITION_PLAN.md` |
| Tianjin DNS-tunnel licensing | a human sends the enquiry | `docs/licensing/TIANJIN_DNS_TUNNEL_ENQUIRY.md` (draft, not sent) |
| Three independent G2 raters | people | `eval/run_llm.py` writes blinded sheets, `eval/score_llm.py` scores them |
| A model for G2 | the project owner | `.env.example` and `docker-compose.yml` (`ollama` profile) |
| Wireshark slice check | a person with Wireshark | `docs/DEMO.md` step 6 |
| Secondary dataset downloads (CICIDS2017, CSE-CIC-IDS2018) | the owner's approval per file | licence terms recorded in the plan; nothing downloaded |

## 10. Recommended next actions

1. Commission the captures (the only step that unblocks the evaluation).
2. Decide the reporting rule in section 6 before any result exists.
3. Send the licensing enquiry; open a slice in Wireshark.
4. Then, in order: register and verify, assign, tune on `dev` only, test once, G1, G2, replace the "Not run" decision records, tag `v1.0`.

Nothing else in the repository needs doing, and no further work was invented for this audit.
