# Tracewright Lab — Topology & Scenario Design

| Field | Value |
|---|---|
| Status | **Design only.** Nothing here is built yet; construction and capture are phase P2. |
| Implements | `docs/PRD.md` §17, `docs/architecture.md` §20.1, `docs/plan.md` P2, `eval/PROTOCOL.md` |
| Purpose | Produce labelled PCAPs (ground truth known by construction) to tune detectors on `dev` and measure on `test`. |

> **Safety.** The lab is an isolated Docker bridge with no route to the internet or the host's other networks. Attack tools run only against lab containers. Tools and scenario scripts never run against anything outside `lab-net`.

## 1. Topology

One Docker bridge, `lab-net`, `172.20.0.0/24`, created `internal: true` (no egress). A capture container shares the bridge's namespace view via `tcpdump -i <bridge>` on the host side (or a sidecar with `network_mode` into a mirrored bridge) so that all inter-container traffic is captured, including traffic between clients and servers.

| Role | Count | IP plan (172.20.0.0/24) | Services / tools |
|---|---|---|---|
| Capture | 1 | host-side bridge | `tcpdump -i <bridge> -w data/lab/<run_id>.pcap` (rotating per run) |
| Attacker | 1 | `.10` | nmap, hydra, medusa, iodine client, dnscat2 client, custom beacon script, scp/curl uploader; HOLDOUT tools (see §3) |
| SSH server | 1 | `.21` | OpenSSH with a few test accounts and weak lab-only passwords |
| FTP server | 1 | `.22` | vsftpd or pure-ftpd, lab-only accounts |
| HTTP server | 1 | `.23` | nginx with a basic-auth path; also a slowloris target |
| File server | 1 | `.24` | Samba (SMB/RPC enumeration target) |
| DNS authoritative (tunnel domain) | 1 | `.53` | server side of iodine and dnscat2 for a lab-only domain; also the resolver for clients |
| Backup/monitoring server | 1 | `.30` | rsync target, monitoring heartbeat receiver (hard negatives) |
| Clients | 3–5 | `.101`–`.105` | benign generators (see §4) |
| "External" sink | 1 | separate lab subnet, e.g. `172.21.0.0/24` | stands in for external destinations: C2 listener for the beacon script, upload target for exfil, CDN-like HTTP, NTP |

`config/network.yaml` for lab captures treats `172.20.0.0/24` as internal and `172.21.0.0/24` as external (set explicitly in the lab's network config, since both are RFC 1918). The lab network config used for each evaluation run is recorded in its manifest.

## 2. Attack scenarios (classes with detectors)

Each scenario script writes one episode per attack instance to `labels.jsonl` via `lab/labeler.py` (format in `eval/PROTOCOL.md` §2).

| Class | Scenarios | Parameter variation |
|---|---|---|
| SCAN | nmap SYN scan, nmap connect scan, slow scans (`-T1`/`-T2`) | vertical vs horizontal; default vs slow timing (reported separately) |
| BRUTE | hydra and medusa against SSH, FTP, HTTP basic auth; password spraying (one source, ≥ 5 targets, one service) | threads, wordlist size, service |
| DNSTUN | iodine and dnscat2 tunnels | two tools (tool-held-out evaluation: tune on one, test on the other, and vice versa) |
| BEACON | custom beacon script | interval 30 s – 5 min; jitter 0 – 50 %; HTTP and raw TCP/TLS; capture duration varied for the detectability sweep |
| EXFIL | scp and curl uploads of 50 – 500 MB to the external sink | size, tool, duration |
| Multi-stage demo | scan → brute force → beacon → exfil from the brute-forced host | one fixed, scripted storyline; later used for `demo/demo.pcap` (P10) |

## 3. LAB-HOLDOUT scenarios (families with no detector)

At least three of these four are captured; the corresponding tools and parameters are **never** used to tune any detector:

1. ICMP tunneling
2. Slowloris (against the HTTP server)
3. SMB/RPC enumeration (against the file server)
4. Reverse shell on a non-standard port

## 4. Hard negatives and benign traffic

Hard negatives (each present in both `dev` and `test`, each labelled so that a finding on one counts as a false positive of that type):

- rsync backup to the backup server
- package updates (apt-style bulk HTTP downloads)
- NTP
- monitoring heartbeats (periodic, regular, small)
- cloud-sync-style uploads (large, outbound, legitimate)
- CDN-heavy browsing
- video streaming
- automation SSH (frequent short logins by a scripted client)

Benign-only runs total **≥ 4 hours** of capture, mixing the above with ordinary client browsing, DNS and file access.

## 5. Run structure and labels

- One run = one capture file + one `labels.jsonl` + a small `run.json` (`run_id`, scenario list, lab network config, tool versions, capture SHA-256, start/end). `run_id` is stable (`r001`, `r002`, …).
- Captures live in `data/lab/` (gitignored). Only `labels.jsonl`, `run.json`, scenario scripts, `eval/splits.yaml` and `eval/datasets.md` (sources + SHA-256) are committed.
- Runs mix scenario types realistically (an attack inside background benign traffic) but each episode's actor/targets/time range are logged at the moment the scenario starts and stops.
- `lab/check_labels.py` checks every episode's actor/target IPs appear in the capture's Zeek `conn.log` within the labelled range.

## 6. Split planning (applied in P2, before P3)

- Assign runs to `dev`/`test` by run, ≈ 50/50 per scenario type, in `eval/splits.yaml`.
- DNS tunneling: iodine runs ↔ dnscat2 runs assigned so both held-out directions can be evaluated.
- LAB-HOLDOUT test captures ≥ 8; every attack class ≥ 4 dev and ≥ 4 test episodes.
- External corpora: CICIDS2017 Monday (benign) for BENIGN; selected attack days as CIC-ATTACK, reported separately; use `editcap` time slices if full files are too large. Source and SHA-256 recorded in `eval/datasets.md`.

## 7. Known biases (to be restated in `docs/EVALUATION.md`)

- Traffic reflects the specific tools, versions and topology above; a single flat subnet is far simpler than a real network.
- Attack and benign generators are authored by the same person, so benign patterns may be unrealistically easy or hard.
- CICIDS2017 is synthetic with documented labelling issues; it is a secondary sanity check, not the headline.
