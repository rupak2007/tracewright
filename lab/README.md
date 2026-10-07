# Tracewright Lab

| Field | Value |
|---|---|
| Status | **P2 partially complete.** The benign skeleton, tooling and the six-run benign corpus (4.53 h, frozen in `eval/splits.yaml`) exist. Attack scenarios, held-out families, `AUTOMATION_SSH` and their captures do **not**; `python -m eval.splits report` shows 10 of 27 requirements met. |
| Implements | `docs/PRD.md` §17, `docs/architecture.md` §20.1, `docs/plan.md` P2, `eval/PROTOCOL.md` |
| Purpose | Produce labelled captures (ground truth known by construction) to tune detectors on `dev` and measure on `test`. |

> **Safety.** Both lab networks are Docker `internal: true`: nothing in the lab can reach the internet
> or the host LAN. Everything that runs here is legitimate traffic generation against lab containers.

## Implemented now

### Topology (`lab/docker-compose.lab.yml`)

| Host | Address | Role |
|---|---|---|
| `services` | 172.20.0.20 (lab-net), 172.21.0.20 (ext-net) | HTTP roles (80, 8080 heartbeat, 8081 upload sink, 8082 packages, 8083 stream), TCP backup sink 873, DNS stub 53, NTP responder 123 |
| `capture` | shares `services`' network namespace | `tcpdump -i any` → `data/lab/<run_id>/capture.pcap` (NET_RAW/NET_ADMIN only) |
| `client1..3` | 172.20.0.101–103 / 172.21.0.101–103 | benign traffic generators |

`172.20.0.0/24` is "internal" and `172.21.0.0/24` stands in for "external" destinations
(`config/network.lab.yaml`; both are RFC 1918, so the lab overrides the default context).
One capture point is used because Docker bridges do not flood unicast traffic to a third container;
the sidecar therefore sees every client↔service conversation, which is all this skeleton produces.
Services and clients run non-root, read-only, `cap_drop: ALL` (only `capture` has NET_RAW/NET_ADMIN).

### Benign scenarios (`lab/benign/`, standard library only, seeded)

Labelled `hard_negative` (a detector finding on one is a false positive):

| Scenario | Class | Resembles |
|---|---|---|
| `ntp` | `NTP` | periodic UDP |
| `monitoring_heartbeat` | `MONITORING_HEARTBEAT` | regular beacon timing |
| `rsync_backup` | `RSYNC_BACKUP` | large outbound transfer (internal target) |
| `cloud_sync_upload` | `CLOUD_SYNC_UPLOAD` | large outbound transfer to an external destination |
| `package_update` | `PACKAGE_UPDATE` | bulk downloads |
| `cdn_browsing` | `CDN_BROWSING` | high-cardinality DNS |
| `video_streaming` | `VIDEO_STREAMING` | long, steady flows |
| `background_browsing` | _unlabelled_ | ordinary DNS + page fetches (background) |

### Ground truth, checking and splits

* `lab/schema.py` — `labels.jsonl` schema (`eval/PROTOCOL.md` §2, `eval/REVISIONS.md` #1); validates
  kind/class pairs, IPs, timestamps. `lab/labeler.py` writes episodes; an episode that raises is not recorded.
* `lab/check_labels.py` / `lab/checks.py` — `python -m lab.check_labels <run_dir> <analysis_dir>`:
  every episode's actor and a target must appear in the capture's Zeek `conn` table inside the labelled range.
* `lab/run_lab.py` — records one run (`data/lab/<run_id>/`), writes `run.json` (`lab/runmeta.py`), `--promote`
  copies labels + `run.json` to `lab/runs/<run_id>/` for committing. Smoke runs are never promoted.
* `eval/splits.py` — deterministic, append-only, stratified split assignment; integrity hashes of each run's
  `run.json`/`labels.jsonl`; `validate --against-git`; `report` compares the committed corpus to the P2
  acceptance numbers and states what is missing.
* `eval/datasets.md` — provenance table (the six frozen benign runs, with capture hashes).
* `lab/record_corpus.py` + `lab/corpus/benign_v1.json` — the committed, resumable recording plan (b01–b06); `python -m lab.record_corpus lab/corpus/benign_v1.json [--runs b03]`.

Verified (2026-10-04): short benign runs recorded through Docker + tcpdump, analysed by the P1 worker, and
passed `lab.check_labels`; a deliberately corrupted label failed it. A plan may use each client once.

```bash
python -m lab.run_lab --run-id smoke01 --plan client1:ntp:20 --plan client2:cdn_browsing:20   # not promoted
python -m eval.splits report
```

## Supplying an externally produced capture (interface only)

The lab runner generates only the benign scenarios above. A capture for any other registered class
(`SCAN`, `BRUTE`, `DNSTUN`, `BEACON`, `EXFIL`; the `LAB-HOLDOUT` families `ICMP_TUNNEL`, `SLOWLORIS`,
`SMB_RPC_ENUM`, `REVERSE_SHELL`; and the `AUTOMATION_SSH` hard negative) must be produced **outside** this
repository's tooling and registered here. This repository provides no way to generate that traffic and
this document says nothing about how to produce it. Everything below is paperwork and verification.

> `LAB-HOLDOUT` is the held-out *corpus* (anomaly gate G1); `AUTOMATION_SSH` is a *hard negative*. They are
> kept as the project documents define them (`docs/PRD.md` §17, `eval/PROTOCOL.md` §1).

### What you provide: one directory per run

```text
<any location>/<run_id>/
    submission.json        the declaration (fields below)
    labels.jsonl           one JSON object per labelled episode (schema: lab/schema.py)
    capture.pcap | capture.pcapng       exactly one capture file
```

`run_id`: letters, digits, `-`, `_`; unique across all runs; never reused. The supplier-stated hash of the
capture is **not** accepted: the SHA-256 is computed by the registration tool.

`submission.json` (all fields required; unknown fields are rejected):

| Field | Meaning |
|---|---|
| `run_id` | the run's identity; must equal every label's `run_id` |
| `holdout` | `true` only for a LAB-HOLDOUT run (then only `kind: "holdout"` scenarios are allowed) |
| `start`, `end` | ISO-8601 UTC (`...Z`): the window the capture covers; every episode must fall inside it |
| `network_config` | file name in `config/` classifying internal/external (e.g. `network.lab.yaml`) |
| `clients` | `[{"id", "ip"}]` — every host that acted; ids and IPs unique; every label's `actor` must be one |
| `scenarios` | `[{"kind", "class", "client", "tool"}]` — what the run claims to contain; must match the labelled `kind:class` set exactly, in both directions |
| `provenance.supplied_by` | who supplied it (non-empty) |
| `provenance.supplied_at` | ISO-8601 UTC time of supply |
| `provenance.collection_method` | free-text description of how the capture was produced (non-empty) |
| `provenance.tool_versions` | non-empty `{name: version}` for whatever produced and captured the traffic |
| `provenance.isolated_environment` | must be `true`: produced in an isolated lab, not on a real network |
| `provenance.contains_real_user_data` | must be `false` |
| `provenance.scenario_parameters`, `provenance.notes` | optional, recorded verbatim, never trusted |

Valid `kind`/`class` pairs are exactly those in `lab/schema.py` (`attack`, `holdout`, `hard_negative`).
A template with placeholder values is in the `lab/submission.py` module docstring.

### Commands (from the repository root, backend environment)

```bash
# 1. Check the paperwork and the file; stage the run as UNVERIFIED. Nothing is written on rejection.
python -m lab.register_external <submission_dir>

# 2. Analyse the staged capture with the P1 pipeline inside the worker container (the only place
#    capture bytes are parsed); use the network config named in the submission.
docker compose run --rm -v "$PWD/data/lab/<run_id>:/in:ro" -v "$PWD/<analysis_out>:/out" \
  worker python -m app.cli analyze /in/capture.pcap --out /out/<run_id> --config-dir <config_dir>

# 3. Verify the labels against that analysis. Writes lab/runs/<run_id>/verification.json.
python -m lab.verify_run <run_id> <analysis_out>/<run_id>

# 4. Only now can the run be given a split (append-only; deterministic; stratified).
python -m eval.splits assign
python -m eval.splits validate --against-git [--captures-dir data/lab]
python -m eval.splits report
```

### What the checks do (and do not) establish

* **Registration** rejects: malformed or incomplete `submission.json`/`labels.jsonl`; labels that contradict the
  declaration; a `run_id` already in use; a capture that fails P1 file validation (magic bytes, size,
  compression) or is already registered under another run id (no capture can appear in two splits).
* **Verification** (`lab.verify_run`) does not trust the supplier: the analysis must come from the same
  capture (SHA-256), and each labelled episode's actor and a target must actually communicate in the capture
  inside the labelled range; run flags must match the labelled kinds. It never edits labels. A failed run
  stays ineligible.
* **Eligibility** requires a passing `verification.json` whose hashes still equal the current `run.json`,
  `labels.jsonl` and declared capture hash. Editing any of them afterwards revokes eligibility, and
  `eval.splits validate` fails if such a run holds an assignment.
* Verification shows that a label is **consistent with the capture's connection records**; it cannot show
  that the traffic is "really" the labelled behaviour. Content-level correctness remains the supplier's
  responsibility and is recorded as their claim (`provenance`).

### From verified run to split

`python -m eval.splits assign` considers only eligible runs. Each is placed in `dev` or `test` by a seeded,
stratified, append-only rule (stratum = the labelled `kind:class` set, plus the tool for `DNSTUN`, so both
tools reach both splits). An existing assignment is never changed; `eval/splits.yaml` stays empty until real
verified runs exist, and must be committed and frozen before P3. Changes to `eval/splits.yaml` after that
need an entry in `eval/REVISIONS.md` and user approval.

## Deferred (not built; requires decisions and data that do not exist yet)

* **Captures for `SCAN`, `BRUTE`, `DNSTUN`, `BEACON`, `EXFIL` and the multi-stage demo**
  (`docs/PRD.md` §17, `docs/plan.md` P2). The registration/verification interface above exists, but no such
  capture has been supplied; the class names exist in `lab/schema.py` only so labels can be validated.
* **LAB-HOLDOUT families** (`docs/PRD.md` §11/§17). Same: names registered, no capture supplied.
* **Automation-SSH hard negative** (class registered; no scenario in the runner and no capture supplied).
* **Attack-target hosts** (separate SSH/FTP/HTTP/file-server hosts) — not part of the benign skeleton.
* **The rest of the corpus**: ≥ 4 dev + ≥ 4 test episodes per attack class, ≥ 8 LAB-HOLDOUT test captures,
  `AUTOMATION_SSH`. The benign part is recorded and frozen (10 of 27 requirements met; 17 unmet).
* **CICIDS2017** (Monday benign + attack days): deferred by decision; nothing downloaded.

P2 is therefore **not complete**, and P3 must not start until the deferred items are done and the split
manifest is committed and frozen.

## Known biases (to be restated in `docs/EVALUATION.md`)

* Lab traffic reflects the specific generators and a single flat topology, far simpler than a real network.
* Benign and (later) attack generators are written by the same author, so benign patterns may be unrealistically easy or hard.
* CICIDS2017 is synthetic with documented labelling issues; it is a secondary check, not the headline.
