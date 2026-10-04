# Tracewright Lab

| Field | Value |
|---|---|
| Status | **P2 partially implemented.** The benign skeleton, label schema and checking/split tooling exist. Attack scenarios, held-out families and the full corpus do **not**. |
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
* `eval/datasets.md` — provenance table (currently: nothing recorded).

Verified (2026-10-04): short benign runs recorded through Docker + tcpdump, analysed by the P1 worker, and
passed `lab.check_labels`; a deliberately corrupted label failed it. A plan may use each client once.

```bash
python -m lab.run_lab --run-id smoke01 --plan client1:ntp:20 --plan client2:cdn_browsing:20   # not promoted
python -m eval.splits report
```

## Deferred (not built; requires decisions and data that do not exist yet)

* **Attack-class scenarios** for `SCAN`, `BRUTE`, `DNSTUN`, `BEACON`, `EXFIL` and the multi-stage demo
  (`docs/PRD.md` §17, `docs/plan.md` P2). The class names exist in `lab/schema.py` so labels can be validated,
  but no scenario code, tooling or episodes exist.
* **LAB-HOLDOUT families** (`docs/PRD.md` §11/§17). Same: names registered, nothing generated.
* **Automation-SSH hard negative** (class registered, scenario not written; needs an SSH server in the lab).
* **Attack-target hosts** (separate SSH/FTP/HTTP/file-server hosts) — not part of the benign skeleton.
* **The corpus itself**: ≥ 4 h benign-only, ≥ 4 dev + ≥ 4 test episodes per class, ≥ 8 LAB-HOLDOUT test captures,
  populated `eval/splits.yaml`. `python -m eval.splits report` shows 0 of the P2 requirements met.
* **CICIDS2017** (Monday benign + attack days): deferred by decision; nothing downloaded.

P2 is therefore **not complete**, and P3 must not start until the deferred items are done and the split
manifest is committed and frozen.

## Known biases (to be restated in `docs/EVALUATION.md`)

* Lab traffic reflects the specific generators and a single flat topology, far simpler than a real network.
* Benign and (later) attack generators are written by the same author, so benign patterns may be unrealistically easy or hard.
* CICIDS2017 is synthetic with documented labelling issues; it is a secondary check, not the headline.
