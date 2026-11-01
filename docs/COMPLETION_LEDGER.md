# Project completion ledger

State at 2026-11-01 (second session), `master`. Statuses: COMPLETE (verified with evidence), IN PROGRESS,
BLOCKED (external dependency or human decision), NOT STARTED, FAILED. No percentages: nothing here has a
defensible measurable basis for one.

**Release status: NOT releasable as `v1.0`.** The software, security posture and CI are complete and green;
the scientific evaluation is blocked on captures this repository will not and must not generate.
`v1.0-rc4` (on `522ddcc`, green CI) is the latest release candidate; rc1 and rc2 were red on GitHub and rc3 predates this session's work; all are left as published.

| Requirement | Status | Evidence | Remaining blocker |
|---|---|---|---|
| Implementation P0-P10 | COMPLETE | `docs/plan.md`; 736 tests passed, 13 skipped, 98% line coverage (detect 99-100%, validator 98%), local 2026-11-01; 481 passed / 33 skipped in the real-Zeek worker image; frontend 23 tests | none |
| GitHub CI | COMPLETE | green on every push of this session through `d6f1ba0` (run 41300660380: lint, mypy, pytest incl. Postgres and corpus integrity; docker job with real Zeek, sandbox probes, API end-to-end; web job). Earlier red runs: `docs/EVALUATION.md` §7 | re-confirm after the final push (below) |
| Fresh-clone reproducibility | COMPLETE | `git clone` from GitHub, `docker compose up --build`, API end-to-end on lab capture b07 (2026-11-01, `d6f1ba0`); CI repeats it | none |
| Worker sandbox probes | COMPLETE (re-run) | 9/9 PASS on the rebuilt images, 2026-11-01 | none |
| Dependency audit | COMPLETE (re-run) | `pip-audit` 24 advisories found and fixed (certifi, filelock, opentelemetry-api, virtualenv): now 0; `npm audit --omit=dev` 0; 2 high dev advisories fixed (undici, zod); 15 moderate dev-tooling advisories remain as a documented exception (`docs/SECURITY.md` §3a) | none |
| Image vulnerability scan | COMPLETE (point in time) | Trivy 0.76.1 pinned; `eval/results/image-scan-v1/summary.json`: web 0; API 44 HIGH, worker 123 HIGH + 6 CRITICAL, none with a fix available (images rebuilt on newer pinned bases, `apt`/`apk upgrade`); upstream `postgres` has 1 CRITICAL + 25 HIGH in its Go `gosu` (fix needs an upstream image) | the lab and `ollama` images were not scanned; repeat before a release |
| Performance NFR-01 | COMPLETE (re-run) | `eval/results/bench-v2*`: 500 MB 24 s, synthetic 1M-packet 50 s (3 runs each, idle host); earlier noisy `bench-v1*`: 61 s and 126 s | none |
| Evaluation infrastructure | COMPLETE | per-class and per-sub-population metrics; campaign ids; BRUTE/SCAN param checks; network-role checks; `--max-bytes`; reporting prerequisites gating the test split (`eval/REVISIONS.md` #10, #11) | none |
| Corpus integrity on any checkout | COMPLETE | CRLF-canonical hashes (`REVISIONS.md` #9); CI corpus step green; frozen-split regression test pins b01-b06 assignments | none |
| Benign `AUTOMATION_SSH` scenario | COMPLETE | `lab/benign/scenarios.py::automation_ssh`, real OpenSSH in the lab image (key pair generated at build, not committed), 3 unit tests, smoke run showed 12 SSH sessions with `auth_success` in Zeek | none |
| Corpus rows for `AUTOMATION_SSH` | COMPLETE | runs b07 (test) and b08 (dev) recorded, verified (0 missed bytes), appended to `eval/splits.yaml` (append-only); `eval.splits report`: **11/27** | none |
| Capture handoff package | COMPLETE | `docs/CAPTURE_HANDOFF.md`, `docs/CAPTURE_ACQUISITION_PLAN.md` (decisions Q1-Q10 recorded in §I) | none |
| Tianjin DNS-tunnel licensing enquiry | BLOCKED | draft only: `docs/licensing/TIANJIN_DNS_TUNNEL_ENQUIRY.md` (NOT sent; author addresses are in the paper) | **a human sends it** and records the reply; nothing is downloaded until then |
| Public secondary datasets (CICIDS2017, CSE-CIC-IDS2018) | NOT STARTED | licence terms read and recorded (plan §I); nothing downloaded | explicit approval per download (file, source, size); results to be kept separate from the 27 |
| Attack and held-out captures (26-28 runs: 8 attack, 16 held-out, spares) | BLOCKED | `docs/CAPTURE_HANDOFF.md` | **an authorised isolated lab or collaborator** must record them (decision Q1); the repository generates none |
| Corpus 27/27 | BLOCKED | 11/27 met, 16 unmet: SCAN/BRUTE/DNSTUN/BEACON/EXFIL ×2 splits (10), iodine/dnscat2 ×2 splits (4), held-out families (1), held-out test captures (1) | the captures above |
| Reporting prerequisites (BRUTE FTP/HTTP and SSH ≥ 2 per split, slow scan ≥ 1 per split) | BLOCKED | 0/6 met (`eval.splits report`) | the captures above |
| Detector evaluation, M1 `baseline-rules-v1`, threshold tuning | BLOCKED | the harness refuses `--split test` until 27/27 and the 6 prerequisites | the captures above |
| BEACON false-positive target (≤ 1.0 per hour) | FAILED (on benign dev) | 2.00 per hour with allowlists on 4 dev runs (`dev-benign-baseline-v2`; 1.78 on 3 runs in v1) | tune on `dev` once attack episodes exist so recall is measured at the same time |
| G1 (anomaly scorer) | BLOCKED | `eval/decisions/G1.md` "Not run" | held-out captures: ICMP_TUNNEL, SLOWLORIS, REVERSE_SHELL (≥ 8 in test) |
| G2 (LLM narrative) | BLOCKED | `eval/decisions/G2.md` "Not run" | a model, ≥ 30 test incidents, **three independent raters** |
| Multi-stage attack demo (PRD §19 #2) | BLOCKED | `docs/DEMO.md` | a verified attack capture |
| Open a slice in Wireshark by hand (PRD §19 #3) | BLOCKED | not done | **a human with Wireshark** |
| Recorded hostile capture for the injection criterion (PRD §19 #7) | BLOCKED | synthetic fixture only | a supplied capture |
| `v1.0` tag | BLOCKED | PRD §19 #2 and #8 unmet | everything above |

## What only an authorised human can provide

1. **The attack and held-out captures**, recorded in an authorised, isolated lab (decision Q1), delivered per `docs/CAPTURE_HANDOFF.md`.
2. **Sending the licensing enquiry** to the Tianjin authors and acting on the answer.
3. **Three independent raters** (and a model) for G2.
4. **A person with Wireshark** to open a downloaded slice.
5. **Approval for each public-dataset download** (CICIDS2017 / CSE-CIC-IDS2018), if the secondary checks are wanted.

Everything else in the plan is done.
