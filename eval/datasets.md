# Datasets and capture provenance

Source and SHA-256 of every capture used for tuning or evaluation. Rule (`docs/instruction.md` §3):
nothing below may be edited to improve a metric; a changed checksum means a different capture.

## Status (2026-10-04, end of the P2 partial milestone)

| Corpus | Status |
|---|---|
| LAB attack captures | **Not recorded** — attack scenarios are deferred (see `lab/README.md`) |
| LAB hard negatives | Generators implemented; **no committed run yet** |
| LAB-HOLDOUT | **Not recorded** — deferred with the attack scenarios |
| BENIGN (lab benign-only runs, ≥ 4 h) | **Not recorded** — 0.00 h committed |
| BENIGN (CICIDS2017 Monday) | **Deferred by decision** (disk: 39 GB free at decision time; the full file is ~10 GB) |
| CIC-ATTACK (CICIDS2017 attack days) | **Deferred by decision** (first item cut in `docs/plan.md` if time slips) |

## External corpora

### CICIDS2017 (deferred — nothing downloaded)

| Field | Value |
|---|---|
| Purpose | BENIGN (Monday, benign day) and secondary CIC-ATTACK sanity check |
| Source page | https://www.unb.ca/cic/datasets/ids-2017.html (Canadian Institute for Cybersecurity) |
| Files used | none yet |
| SHA-256 | not yet recorded (no file downloaded) |
| Known caveats | synthetic traffic; documented labelling issues; reported separately, never the headline |

When it is fetched (needs explicit user approval for each download: file name, source and size),
add one row per file below, slice with `editcap` if needed, and record the checksum of the exact file
used. Do not delete a row; mark it superseded.

| File | Source URL | Size (bytes) | SHA-256 | Date fetched | Sliced? |
|---|---|---|---|---|---|
| _none_ | | | | | |

## Lab captures (self-generated)

Captures live in `data/lab/<run_id>/capture.pcap` (gitignored). What is committed per run, in
`lab/runs/<run_id>/`, is `run.json` (including `capture_sha256`) and `labels.jsonl`. The split
manifest `eval/splits.yaml` additionally stores the SHA-256 of both committed files and
`python -m eval.splits validate` fails if either changes after assignment.

Externally supplied captures (registered with `python -m lab.register_external`, see `lab/README.md`) are
recorded the same way: `run.json` carries `origin: external`, the supplier's provenance claim and the
SHA-256 computed at registration. They count only after `python -m lab.verify_run` passes.

Current committed runs: **none**. Regenerate this table's contents with:

```bash
python -m eval.splits report
```

| Lab network config | `config/network.lab.yaml` (172.20.0.0/24 internal, 172.21.0.0/24 external) |
|---|---|

## Corpus source assessment (2026-10-04)

Question: which unmet P2 requirements can which source satisfy? `python -m eval.splits report` prints the
same partition (27 unmet: 10 / 1 / 16 by source below). Nothing was downloaded for this assessment; the
CICIDS2017 facts below come from the dataset's own public description page
(https://www.unb.ca/cic/datasets/ids-2017.html), read on this date.

### Requirements by what can satisfy them

| Source | Requirements (all currently unmet) | Count |
|---|---|---|
| Existing benign lab runner (real recordings, no new code) | hard negatives `RSYNC_BACKUP`, `PACKAGE_UPDATE`, `NTP`, `MONITORING_HEARTBEAT`, `CLOUD_SYNC_UPLOAD`, `CDN_BROWSING`, `VIDEO_STREAMING` each present in both `dev` and `test`; benign-only runs in `dev` and in `test`; benign-only capture >= 4 h | 10 |
| A new *benign* scenario (not written) or an external capture | hard negative `AUTOMATION_SSH` in both splits | 1 |
| Externally supplied, verified captures only | `SCAN`, `BRUTE`, `DNSTUN`, `BEACON`, `EXFIL`: >= 4 episodes in `dev` and >= 4 in `test` (10 rows); `DNSTUN` tools `iodine` and `dnscat2` each in both splits (4 rows); LAB-HOLDOUT: >= 3 families captured; >= 8 LAB-HOLDOUT test captures | 16 |

The 10 benign-lab requirements are mechanically satisfiable but need **real wall-clock recording** (>= 4 h in
total) and, to avoid leakage, **distinct seeds and parameter plans for runs that land in different splits**
(enforced: `eval.splits` withholds a run whose seed + scenario plan repeats an assigned run). They have not
been recorded; they are not satisfied by the smoke runs, which were never promoted.

### CICIDS2017 (the only public dataset the project documents name)

The plan lists downloading it in P2 (`docs/plan.md` P2 tasks), but it is **not** part of the P2 definition of
done (`docs/instruction.md` §8), and `docs/PRD.md` §17 makes CIC-ATTACK "secondary... never the headline".
Findings from the dataset page:

| Question | Finding |
|---|---|
| PCAPs available? | Yes, per day (Mon 3 Jul - Fri 7 Jul 2017), plus CICFlowMeter CSVs labelled by time, IPs, ports, protocol |
| Labels map to Tracewright classes? | Partly. Tuesday FTP-Patator and SSH-Patator ~ `BRUTE` (one window each, 9:20-10:20 and 14:00-15:00). Friday PortScan ~ `SCAN` (many short windows inside one day). Friday Ares botnet ~ `BEACON` (one 10:02-11:02 window; not the same behaviour as a periodic-interval sweep). Wednesday slowloris (9:47-10:10) matches a LAB-HOLDOUT family but is one window. **No** DNS tunnelling, **no** exfiltration class, **no** ICMP tunnelling, SMB/RPC enumeration or non-standard-port reverse shell |
| Enough episodes per class and split? | **No.** Each attack type has roughly one documented window per day, so >= 4 `dev` + >= 4 `test` independent episodes per class cannot come from it |
| Can the split protocol hold? | **No for per-class counts.** Splits are by capture and `eval/PROTOCOL.md` §4 forbids slicing one capture across splits; each day is a single capture, so each day goes wholly to one split. Monday (the benign day) therefore cannot provide benign data to both `dev` and `test` |
| Provenance recordable? | Yes (source URL, file, SHA-256, slice commands); the page documents victim/attacker addresses and NAT (flows traverse a firewall), so ground truth by IP needs `lab.verify_run` to confirm it against what Zeek actually sees |
| Timestamps / flow evidence sufficient? | Window times are given as local clock times without a stated zone, and the dataset has known labelling issues (PRD §16). Not established until a capture is analysed; `lab.verify_run` would reject labels that do not match the capture |
| Leakage risk | A given day cannot be both tuned on and tested on. Tuning only on data that is later reported on, within a single capture, is the failure the protocol forbids |

Conclusion: CICIDS2017 can contribute **only** to the secondary evaluations the PRD already assigns it
(BENIGN false-positive rate from Monday; CIC-ATTACK sanity checks, reported separately). It satisfies **none**
of the 27 unmet P2 requirements, and it was deliberately deferred (disk: ~39 GB free; Monday is ~10 GB).
Fetching it should wait until a measured result (P3) actually needs it, and needs explicit approval of each
file (name, source, size). The evaluation targets and protocol are unchanged.

### What the project needs from outside the repository

Real captures, supplied through `lab/README.md` ("Supplying an externally produced capture"):

* for each of `SCAN`, `BRUTE`, `DNSTUN` (both `iodine` and `dnscat2` represented in both splits),
  `BEACON`, `EXFIL`: enough independent runs that, after a 50/50 run-level split, each of `dev` and `test`
  holds >= 4 labelled episodes of that class, with different parameters between runs that will land in
  different splits;
* for LAB-HOLDOUT (`holdout: true`): runs of at least 3 of `ICMP_TUNNEL`, `SLOWLORIS`, `SMB_RPC_ENUM`,
  `REVERSE_SHELL`, totalling >= 8 captures that end up in `test` (so about >= 16 runs after splitting);
* for `AUTOMATION_SSH`: runs in both splits (or a new benign scenario added to the lab runner first);
* each as `capture.pcap|pcapng` + `labels.jsonl` + `submission.json` with full provenance, produced in an
  isolated environment with no real user data.
