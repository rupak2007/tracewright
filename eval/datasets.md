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

Current committed runs: **none**. Regenerate this table's contents with:

```bash
python -m eval.splits report
```

| Lab network config | `config/network.lab.yaml` (172.20.0.0/24 internal, 172.21.0.0/24 external) |
|---|---|
