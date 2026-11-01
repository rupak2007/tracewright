# Capture handoff package

For whoever records or supplies the missing captures. This is a specification of what must be delivered
and how it is checked. It is **not** a recipe for producing traffic; the repository generates no attack
traffic and this document gives no instructions for doing so. The reasoning is in
`docs/CAPTURE_ACQUISITION_PLAN.md`.

## What to deliver

One directory per run:

```text
<run_id>/
    submission.json
    labels.jsonl
    capture.pcap        (or capture.pcapng; exactly one)
```

Deliver at least the **minimum** below; the **recommended** set gives defensible statistics. Every run is
an independent execution: its own seed, parameters, capture file and `campaign_id`. Never slice one
recording into several runs, never register one campaign twice, never repeat a campaign in both splits.

| Set | Runs | Contents |
|---|---|---|
| Attack runs | 4 (minimum) / 8 (recommended), identical label sets | per run: 2 SCAN (≥ 1 slow, `params.speed`), 2 BRUTE (1 FTP/HTTP + 1 SSH, `params.service`), 2 BEACON, 2 EXFIL, 2 DNSTUN (`tool` exactly `iodine` and `dnscat2`) |
| `AUTOMATION_SSH` (benign) | 2, or an episode in every attack run | `kind: hard_negative`, `class: AUTOMATION_SSH` |
| Held-out runs | 16 (`holdout: true`), identical label sets | one episode each of three of `ICMP_TUNNEL`, `SLOWLORIS`, `SMB_RPC_ENUM`, `REVERSE_SHELL` |

Splits are assigned by the tool after verification, never by hand. Identical label sets split 50/50.

## `submission.json` (every field required, unknown fields rejected)

```json
{
  "run_id": "x001",
  "campaign_id": "camp-01",
  "holdout": false,
  "start": "2026-11-02T10:00:00.000Z",
  "end":   "2026-11-02T10:45:00.000Z",
  "network_config": "network.lab.yaml",
  "clients": [{"id": "c1", "ip": "172.20.0.101"}],
  "scenarios": [{"kind": "attack", "class": "SCAN", "client": "c1", "tool": ""}],
  "provenance": {
    "supplied_by": "<who>",
    "supplied_at": "2026-11-03T09:00:00.000Z",
    "collection_method": "<how the capture was produced, in prose>",
    "tool_versions": {"<tool>": "<version>"},
    "isolated_environment": true,
    "contains_real_user_data": false,
    "scenario_parameters": {},
    "notes": ""
  }
}
```

The two provenance attestations must be **true**; they are recorded and not verified, so do not sign
what is not so. `campaign_id` uses letters, digits, `-`, `_`; runs sharing one are one campaign and are
kept in one split.

## `labels.jsonl`

One object per episode; fields `run_id`, `episode_id` (`<run_id>-...`), `kind`, `class`, `actor`,
`targets` (non-empty), `start`, `end` (UTC `...Z`), optional `tool`, `params`.

* **Every in-scope event in the capture is labelled.** An unlabelled event of a detector's class counts
  as a false positive.
* Labels come from the run's own schedule, never from running Tracewright's detectors on the capture.
* `BRUTE` needs `params.service` in `ftp, http, https, ssh, rdp, telnet`; `SCAN` needs `params.speed` in
  `default, slow`. Registration rejects episodes without them.
* DNS tunnelling: `tool` exactly `"iodine"` or `"dnscat2"`.

## Address plan and capture quality (checked)

* Under the `network_config`, the actor of a `DNSTUN`, `BEACON` or `EXFIL` episode must be an **internal**
  address, and `EXFIL` needs an **external** target. A host that reaches the external subnet from its
  external address will be rejected.
* Zeek must report **0 missed bytes** on every labelled connection (use a large capture buffer and check
  before delivery); any dropped packets fail verification.
* `EXFIL`: at least 50 MB outbound to an external address; normal confidence needs at least 20
  internal-to-external pairs in the capture. `BEACON`: at least 10 events and a capture at least 10 times
  longer than the interval. These are the detectors' PRD defaults.
* Captures above 500 MiB: analyse with `python -m app.cli analyze ... --max-bytes <n>` (offline only).

## Safety and authorisation

All traffic must stay inside an isolated environment you own and are authorised to use: nothing may touch
public infrastructure, third-party networks or the host LAN, and no real user data may be captured.

## What happens after delivery

```bash
python -m lab.register_external <run_dir>             # paperwork + file checks; stages UNVERIFIED
# analyse in the worker container (see lab/README.md), then:
python -m lab.verify_run <run_id> <analysis_dir>      # labels vs what Zeek sees
python -m eval.splits assign                          # append-only
python -m eval.splits report                          # target: 27/27
```

After 27/27: tune on `dev` only, run `test` once per milestone, then G1, then G2. Held-out `test`
captures are never inspected before the G1 run.
