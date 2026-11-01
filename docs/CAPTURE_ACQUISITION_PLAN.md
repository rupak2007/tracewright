# Capture acquisition plan: 10/27 to 27/27

| Field | Value |
|---|---|
| Status | **Plan only.** Nothing has been downloaded, recorded, registered or assigned. Corpus: **10/27** (`python -m eval.splits report`, 2026-11-01, `v1.0-rc2`, commit `0823a2c`) |
| Scope | The 17 unmet rows of `eval/splits.py::corpus_report` |
| Unchanged by this plan | `eval/PROTOCOL.md`, `eval/splits.yaml`, `lab/runs/*`, `config/*`, thresholds, result files |
| Evidence tags | **[code]** verified in this repository; **[source]** verified on the dataset's own page (URL in section C); **[assumption]** not verified; **[decision]** needs a human |

**Headline.**
1. I could verify no public dataset that satisfies any of the 17 unmet rows under Tracewright's
   contract. The main obstacles are:
   - the required provenance attestations (isolated environment, no real user data);
   - the rule that a capture is never sliced across splits;
   - the exact `tool` values required for DNS tunnelling.
2. The practical route is captures produced in an isolated, authorised environment and supplied
   through the existing external-capture interface.
3. Who produces them is an open human decision. In P2 you chose to keep traffic-generation tooling
   for attacks out of this repository (section G, Q1).

---

## A. The dataset contract (as enforced by the code)

### A1. Files, formats, provenance [code: `lab/register_external.py`, `lab/submission.py`, `lab/runmeta.py`]

* One directory per run, holding `submission.json`, `labels.jsonl` and exactly one
  `capture.pcap` or `capture.pcapng`.
* Any PCAP magic or PCAPNG is accepted. Compressed files are rejected.
* The capture's size cap at registration is 8 GiB. **But** `lab.verify_run` needs a worker
  analysis, and that path enforces `MAX_UPLOAD_BYTES` (500 MiB by default,
  `app/worker/pipeline.py:122`). A larger capture must be split before registration, with each
  part its own run, or analysed with a raised limit [decision].
* The SHA-256 is computed by the tool; a supplier-stated hash is never accepted. A hash that is
  already registered is rejected, and run ids are never reused.
* In `submission.json` every field is required and unknown fields are rejected:
  - `run_id`;
  - `holdout`;
  - `start` / `end` in ISO-8601 UTC ending in `Z`;
  - `network_config`, a `network*.yaml` that **must already exist in `config/`**;
  - `clients`, with unique `id`/`ip`;
  - `scenarios`, whose `kind:class` set must equal the labelled set, in both directions.
* Provenance:
  - `supplied_by`, `supplied_at`, `collection_method` and a non-empty `tool_versions` map;
  - `isolated_environment` **must be `true`** and `contains_real_user_data` **must be `false`**.

  These attestations are recorded but not checked, so they must be truthful.

### A2. Labels [code: `lab/schema.py`]

* Each episode has `run_id`, `episode_id` (`<run_id>-…`), `kind`, `class`, `actor` (IP), `targets`
  (a non-empty IP list), and `start`/`end` (UTC `Z`). Optional fields: `tool`, `params`. Nothing
  else is allowed.
* Valid pairs:

  | `kind` | Classes |
  |---|---|
  | `attack` | `SCAN`, `BRUTE`, `DNSTUN`, `BEACON`, `EXFIL` |
  | `holdout` | `ICMP_TUNNEL`, `SLOWLORIS`, `SMB_RPC_ENUM`, `REVERSE_SHELL` |
  | `hard_negative` | the eight benign classes, including `AUTOMATION_SSH` |

* The DNS tunnel tool counts only when `tool` is exactly `"iodine"` or `"dnscat2"`
  (`eval/splits.py:DNS_TUNNEL_TOOLS`).
* The actor must be a declared client, and every episode must lie inside the declared window
  (±5 s).

### A3. Verification [code: `lab/verify_run.py`, `lab/checks.py`]

A run passes only if all of these hold:

* the analysis is of the same capture (hash match) and completed;
* every episode has at least one Zeek `conn` row between the actor and a target, inside
  `[start−5 s, end+5 s]`;
* every episode overlaps the capture span;
* **Zeek reports 0 `missed_bytes` on the episode's connections**, so dropped packets fail the run;
* the run flags agree with the labelled kinds;
* episode ids are unique.

`verification.json` is bound to the hashes of `run.json` and `labels.jsonl`. Any later edit
revokes eligibility.

### A4. Assignment [code: `eval/splits.py`]

* Only verified, unmodified runs are assigned. Assignment is append-only, and
  `validate --against-git` catches edits.
* **Stratum** is the sorted set of `kind:class` in a run, plus `/tool` for DNSTUN. Within a stratum
  runs are balanced, and a seeded hash breaks ties. Runs with identical label sets therefore split
  predictably: 2 runs go 1+1, 4 runs go 2+2.
* Requirements **count episodes, not runs**, except for held-out test captures, which count runs.
* The recipe-duplicate guard applies only to lab-runner runs. **External runs have no campaign
  duplicate check beyond the exact file hash** (see E2).

### A5. Held-out families [code]

Three uses of the corpus are kept apart [`eval/PROTOCOL.md` §4 and §5; code: `eval/run_anomaly.py`]:

| Activity | Allowed data | Forbidden data |
|---|---|---|
| **A. Tuning ordinary detection rules** (thresholds and windows in `config/detectors.yaml`) | `dev` runs of attack, benign and hard-negative kinds | every `test` run, **and every held-out run in either split**, because families are held out of detector tuning (PRD §11, PROTOCOL §4 "Family-held-out") |
| **B. Tuning G1 anomaly parameters** (window size, Isolation Forest hyperparameters, promotion cut-off) | held-out runs assigned to **`dev`**, plus benign `dev` runs (the cut-off was calibrated on benign `dev` only so far) | held-out `test` runs; attack-class runs as fitting data |
| **C. Evaluating** (one `test` run per milestone) | `test` runs, once per milestone, including held-out `test` for G1 | none of these may have influenced A or B |

Consequences for acquisition:

* Held-out runs split 50/50: about half become `dev` (usable only for B) and half `test`. Neither half
  touches A.
* A held-out `test` capture is never analysed to choose anything before the G1 evaluation. Do not look
  at its features or scores informally: it is the only test of G1.
* `eval.run_anomaly evaluate --split test` refuses to run until all 27 rows are met [code]. **Nothing
  in code checks that B used only `dev`**: it rests on the harness defaults (`calibrate` is dev-only)
  and on discipline for any further tuning. This plan recommends logging every B-tuning run in
  `eval/REVISIONS.md`.
* **Supplier-side leakage:** whoever records the held-out captures must not see detector or anomaly
  outputs for the `test` half before delivery, and must not shape the recording to what the detectors
  catch.

* A held-out run has `holdout: true` and contains only held-out episodes.
* "Families captured" counts distinct held-out classes across all runs, in any split.
* "Held-out test captures" counts held-out runs that land in `test`. With 50/50 balancing, reaching
  8 means about **16 held-out runs**.

### A5a. Which requirements the 27-row count enforces and which only reporting does [code + PRD]

The 27-row report counts only `kind:class`, the tool for DNSTUN, and held-out run counts. It does **not**
look at BRUTE service family, slow scans or any `params` field [code: `eval/splits.py:corpus_report`].
But the PRD §18 targets are stated per sub-population, and `eval/PROTOCOL.md` §6 requires them to be
reported separately. `eval/run_detectors.py` does not split by service or scan speed yet [code:
verified by search]; that would have to be added after data exists, with a `REVISIONS.md` entry if it
changes the protocol.

### A5b. Sub-populations that must be reportable separately [PRD §18 row text; PROTOCOL §6]

| Class | Reported separately | Acquisition consequence |
|---|---|---|
| BRUTE | FTP/HTTP vs SSH (PRD §18: "FTP/HTTP and SSH reported separately"). The detector treats them differently: failures are observed for FTP/HTTP but inferred from connection patterns for SSH | **Both are mandatory in acquisition.** A split holding only one family cannot support the separate targets. The 27/27 count would still pass without this, so it is a requirement of the *evaluation*, not of the corpus report. Record the family in `params.service` (`ftp`, `http`, `ssh`). The schema does not enforce it, so a review step must check it |
| SCAN | default-speed vs slow scans (PRD §18) | At least one slow scan (the 10-minute-window rule) per split, labelled in `params` |

The PRD gives no minimum per family. 2 per family per split is the smallest number that allows any
per-family figure at all and is **my assumption**, not a documented requirement (Q10). It will give very
wide intervals; the recommended target (section F) gives 4 per family.

### A6. What causes rejection

| Stage | Cause |
|---|---|
| register | a file is incomplete, has unknown fields, or the files are inconsistent |
| register | a provenance attestation is false or missing |
| register | an actor is not a declared client, or an episode lies outside the window |
| register | the `network_config` is missing, or the run flags are inconsistent |
| register | the capture is invalid, compressed or oversized, or its hash or run id is already registered |
| verify | the analysis is of a different capture or failed |
| verify | there is no actor/target traffic in the window, or the episode lies outside the capture span |
| verify | the episode's connections have missed bytes |
| assign | the run is unverified or edited, or (lab runner only) it repeats an existing recipe |

### A7. Labelling implications for evaluation [`eval/PROTOCOL.md` §3]

* A finding matches an episode on entity, class and time (±60 s).
* **Any detector-class behaviour that is not labelled becomes a false positive**, so every in-scope
  event in a capture must be labelled.
* Detector defaults set minimum episode shapes; these are PRD values, not tuning:
  - BEACON needs at least 10 events, and the capture must span at least 10 × the interval;
  - EXFIL needs at least 50 MB outbound to an address the network config classifies as
    **external**, and normal confidence needs at least 20 internal→external pairs in the capture;
  - SCAN windows are 60 s and 600 s, so separate SCAN episodes in time or by actor.
* **Lab topology limit (found in P3, `eval/datasets.md`).** Under `config/network.lab.yaml`, a
  dual-homed lab client reaches the "external" subnet from its own external address, which makes
  the traffic external→external. EXFIL and BEACON captures need internal-source traffic to external
  destinations, for example through a routing hop [decision on topology, Q4].

---

## B. Requirement-to-capture mapping

Splits are never chosen by hand; the stratum design only makes both splits possible.

| Report rows | Need | Minimum to satisfy | Plausible source | Ground truth | Main leakage risk |
|---|---|---|---|---|---|
| SCAN dev/test (2) | ≥ 4 labelled SCAN episodes per split; **PRD §18 reports slow scans separately, so each split needs at least one slow-scan episode** (A5b) | 8 episodes, at least 2 runs, at least 1 slow scan per split | isolated authorised capture | actor, targets, start/end for **every** scan in the run | the same campaign or parameters in both splits |
| BRUTE dev/test (2) | ≥ 4 per split. **Mandatory for the PRD §18 target: both FTP/HTTP and SSH must be present in each split** (A5b), with `params.service` recorded | 8 episodes, **at least 2 FTP/HTTP and 2 SSH per split** [assumed minimum, Q10] | isolated authorised capture; public data has one window per day (C1, C2) | actor, target, service, start/end | one public day sliced across splits (forbidden) |
| DNSTUN dev/test (2) | ≥ 4 per split | 8 episodes | isolated authorised capture, or a candidate in C5 (unverified licence) | client, resolver/server IPs, tool, start/end | the same tunnel session in both splits |
| DNSTUN iodine dev/test (2) | ≥ 1 `tool:"iodine"` episode per split | 2 | same as above | as above, plus the exact tool string | tool-held-out design: tune on one tool, test on the other (PROTOCOL §4) |
| DNSTUN dnscat2 dev/test (2) | ≥ 1 `tool:"dnscat2"` episode per split | 2 | same as above | same as above | same as above |
| BEACON dev/test (2) | ≥ 4 per split | 8 episodes | isolated authorised capture; the CICIDS2017 bot window is a different behaviour (C1) | source, destination, interval and jitter (params), start/end | the same implant configuration in both splits |
| EXFIL dev/test (2) | ≥ 4 per split | 8 episodes | isolated authorised capture with a correct internal/external layout (A7) | source, external destination, start/end | an identical transfer replayed in both splits |
| AUTOMATION_SSH (1) | present in both splits | ≥ 2 runs (or episodes in 2 runs of the same stratum, one per split) | **benign**: a new lab-runner scenario [decision] or an external benign capture | client, server, start/end | none special (benign); keep distinct from BRUTE actors |
| Held-out families (1) | ≥ 3 of the four held-out classes | 3 families | isolated authorised capture; SLOWLORIS exists in CIC sets but fails provenance (C1, C2) | actor, target, family, start/end | families must never be used to tune detectors (PROTOCOL §4) |
| Held-out test captures (1) | ≥ 8 held-out runs in `test` | ≈ 16 held-out runs | same as above | same as above | duplicated campaigns across splits |

---

## C. Candidate public datasets (verified facts only)

None of these is registered, and none is claimed to satisfy a requirement.

| # | Dataset | Verified facts | Fit for Tracewright's unmet rows |
|---|---|---|---|
| C1 | **CICIDS2017** (UNB CIC). Sharafaldin, Habibi Lashkari, Ghorbani, ICISSP 2018. https://www.unb.ca/cic/datasets/ids-2017.html | [source] Full PCAPs, one per day, Mon 3 to Fri 7 July 2017. Attack windows: FTP-/SSH-Patator (Tue), slowloris and slowhttptest (Wed), PortScan and Ares bot (Fri), and more. **Times have no timezone.** The testbed was **connected to the Internet**. "Publicly available for researchers"; citation requested; no named licence | **Does not satisfy any unmet row.** Each class appears in roughly one window per day; one day is one capture and cannot be split across `dev`/`test`. There is no DNS tunnel, no exfiltration, and only one held-out family. The `isolated_environment: true` attestation would be untrue. Already documented in `eval/datasets.md`; allowed only for the PRD's secondary CIC-ATTACK / BENIGN checks |
| C2 | **CSE-CIC-IDS2018** (CIC + CSE). https://www.unb.ca/cic/datasets/ids-2018.html, AWS bucket `cse-cic-ids2018` | [source] Per-machine PCAPs and logs by day. FTP/SSH brute force (14 Feb), slowloris (15 Feb), slowhttptest (16 Feb), web attacks, infiltration, bot (2 Mar). The testbed was built on AWS with public addresses. **Redistribution permitted with citation and a link** | Same structural problem as C1 (few windows, day-level captures). The isolation attestation is doubtful **[assumption: AWS-hosted with Internet reachability]**. Possible secondary sanity data only |
| C3 | **UNSW-NB15** (UNSW Canberra). Moustafa & Slay, MilCIS 2015. https://research.unsw.edu.au/projects/unsw-nb15-dataset | [source] About 100 GB of raw PCAPs, plus Bro/Argus/CSV and a ground-truth table. IXIA PerfectStorm traffic in a cyber-range lab. Nine coarse categories (Reconnaissance, DoS, Backdoors, …). Free academic use; commercial use by agreement | The categories do not map to Tracewright classes, and no DNS tunnel or exfiltration class exists. Mapping "Reconnaissance" to SCAN would be an **unsupported relabelling** |
| C4 | **CTU-13** (Stratosphere, CTU Prague). García et al., Computers & Security 2014. https://www.stratosphereips.org/datasets-ctu13 | [source] Only **botnet-only** PCAPs are public; full captures are withheld "for privacy". Recorded on a real university network. Labels are in Argus NetFlow. No licence stated | Real network, so it cannot attest no-real-user-data or isolation. Botnet traffic is not a labelled periodic-beacon episode set. **Not suitable** |
| C5 | **DNS-tunnel PCAPs, Tianjin University (Tu, Liu, Sun, Computers & Security 2023)**. https://github.com/Utah1A/DNS-tunnelling-detection-by-fusing-encoding-feature-and-behavioral-feature | [source] Raw PCAPs for eight tunnel tools **including iodine and dnscat2**, captured in a simulated environment with isolated addresses. Mostly heartbeat traffic. Some non-DNS packets. **No licence stated** | The only candidate found with plain-DNS iodine and dnscat2 PCAPs. Open issues: no licence (Q3); per-episode time labels would have to be derived from file-level tool identity (sound only if each file is one tool); provenance must be attested by us as importer, from their description; very little benign context |
| C6 | **CIRA-CIC-DoHBrw-2020**. https://www.unb.ca/cic/datasets/dohbrw-2020.html | [source] iodine, dnscat2 and dns2tcp **over DoH (TLS)**. Flow-level labels. Redistribution with citation | Tunnel content is encrypted inside HTTPS, so Zeek `dns.log` sees no queries and DET-DNSTUN does not apply. **Not suitable** for DNSTUN rows |
| C7 | **CIC-Bell-DNS-EXF-2021**. https://www.unb.ca/cic/datasets/dns-exf-2021.html | [source] DNS exfiltration with DNSExfiltrator. Benign side uses real domains. Packet-level labels. Redistribution with citation. Whether raw PCAPs are downloadable is **not stated** | Not iodine/dnscat2. Could add generic DNSTUN episodes only if PCAPs exist and the isolation attestation holds (doubtful: real Internet domains) |
| C8 | **DNS Threats Dataset** (Palau et al., Zenodo 10.5281/zenodo.6508640). https://mcfp.felk.cvut.cz/publicDatasets/DNS-Threats-Dataset/README.html | [source] CSV of domain names only (iodine/dnscat2/dnsExfiltrator tunnel domains). No PCAPs | **Not usable**: Tracewright needs captures |
| — | **ICMP-tunnel captures** | Searched; no labelled public PCAP dataset found | Held-out `ICMP_TUNNEL` needs authorised controlled capture |
| — | **Stratosphere malware-capture facility**. https://www.stratosphereips.org/datasets-malware | [source] PCAPs of malware runs. Labelling and licence not stated on the page | Real malware with unclear isolation. Not suitable for the attestation |

Result: **controlled, isolated, authorised capture is the primary path for all 17 rows.** C5 is the
only public candidate worth a licence enquiry, and only for the iodine/dnscat2 rows.

---

## D. Controlled capture: governance requirements (not procedures)

Whoever produces the captures (Q1), each run must meet these conditions:

* **Isolation.** The traffic must never touch public infrastructure, third-party networks or the
  host LAN. The existing lab uses Docker `internal: true` networks as the model. Only systems you own
  and are authorised to test may be involved.
* **Authorisation and records.** Record who ran each capture, when, with which tool versions and
  parameters (`provenance.tool_versions`, `scenario_parameters`). Store this in `submission.json`.
* **Capture hygiene.** Use a large capture buffer, because the P2 lesson was that small buffers
  drop packets. Every labelled connection needs Zeek `missed_bytes` of 0. Check this by analysing
  and verifying before submission.
* **Ground truth by construction.** Labels are written from the run's own schedule (actor, targets,
  UTC times, exact tool string). They are never inferred later from the capture.
* **Address plan.** Use internal and external ranges consistent with an existing `config/network*.yaml`,
  or approve a new one (Q4). EXFIL and BEACON need internal-source traffic to external addresses (A7).
* **Complete labelling.** Every in-scope event in a run is labelled. A run carries no unlabelled
  attack activity.
* **Benign background.** Each run should include benign background from several hosts. This is
  realistic, and EXFIL's population baseline needs at least 20 internal→external pairs.

---

## E. Evaluation integrity controls

| Risk | Control | Enforced by |
|---|---|---|
| E1 Train/test leakage | Splits by run only, append-only, decided by the tool. Tune on `dev` only. `test` runs once per milestone | **tool** (`eval.splits`, harness refusals) and protocol |
| E2 Duplicate captures | Exact-hash duplicates are rejected at registration. **Slices of one capture have different hashes and are not caught**: never register two slices of one recording | tool (exact hash); **manual** for slices |
| E3 The same campaign across splits | External runs have no recipe guard. Each run must be an independent execution with **different parameters and seed**, and repeats must be kept within one stratum design. Keep a supplier-side log mapping run id to campaign, reviewed before `assign` | **manual** (Q5: whether to add a campaign-id field via a protocol revision) |
| E4 Wrong timestamps | Labels are UTC `Z` only. Verification rejects episodes with no traffic in the window (±5 s) or outside the capture span. For public data with no stated timezone (C1), do not guess: obtain the zone or reject | tool, partly; **manual** for the timezone source |
| E5 Unsupported labels | Labels come from the run's schedule, never from detector output or post-hoc reading. Verification checks only that traffic exists, not the class. Mapping public categories to Tracewright classes needs a written justification per class | **manual review** |
| E6 Provenance | The attestations must be true. Record the source URL, file, SHA-256 and slicing commands in `eval/datasets.md` for any public file. Get approval before each download (file, source, size) | tool (completeness); **manual** (truth) |
| E7 Tool-held-out DNSTUN | Both tools in both splits, so both directions (tune iodine/test dnscat2 and the reverse) can be reported | tool (report rows); protocol |
| E8 Held-out data influencing tuning | Three separate uses: detector tuning (`dev`, never held-out), G1 parameter tuning (held-out `dev` only), evaluation (`test`, once). See A5. Held-out `test` captures are never inspected before the G1 run | protocol and the `eval.run_anomaly` refusal; the dev-only rule for B is **manual** |

---

## F. Smallest practical plan to 27/27

This is the minimum under the code's counting rules, with the integrity trade-off stated. Run counts
assume assignment balances within each stratum (A4).

| Batch | Runs | Content per run (label structure) | Rows satisfied |
|---|---|---|---|
| 1. Combined attack runs | **4**, all with the same label set (one stratum, so a 2/2 split) | 2 SCAN (one slow in each split), 2 BRUTE (one FTP/HTTP and one SSH, via `params.service`), 2 BEACON, 2 EXFIL, and 2 DNSTUN (one `tool:"iodine"`, one `tool:"dnscat2"`). Optionally also an `AUTOMATION_SSH` hard-negative episode from a separate benign host | 14 attack rows (each split: 4 episodes per class, 2 iodine, 2 dnscat2). With the optional episode, the `AUTOMATION_SSH` row too |
| 2. `AUTOMATION_SSH`, if not in batch 1 | **2** benign-only runs, same label set (1/1) | `hard_negative:AUTOMATION_SSH` (+ other benign) | 1 |
| 3. Held-out runs | **16**, all with the same label set (8/8) | `holdout: true`, with one episode each of three families (for example `ICMP_TUNNEL`, `SLOWLORIS`, `REVERSE_SHELL` [decision Q6]) | 2 held-out rows |

**Minimum total: 20 runs** (22 if `AUTOMATION_SSH` is captured separately), each independent (see the acquisition target below).

**Acquisition target.**

* **20 independent runs is the mathematical minimum** under the counting rules: the smallest set that
  turns the 17 rows green. It is **not** a recommended sample size. Two attack captures per split mean
  episodes within a run are correlated, so 4 episodes per class are far fewer than 4 independent
  observations.
* **Recommended: 26 to 28 independent runs**:
  - 8 combined attack runs (4 per split, so 8 episodes of each class per split, with 4 per BRUTE
    family per split);
  - 2 benign `AUTOMATION_SSH` runs, or that episode inside every attack run;
  - 16 held-out runs;
  - the upper figure leaves a couple of spares for rejections.
* **"Independent" means** a separate execution, with a fresh seed, different parameters, its own
  capture file, and no shared session or campaign with any other run.
* **Do not** reach a count by: (a) slicing one recording into several runs; (b) registering the same
  campaign or recording under two ids; (c) repeating a campaign in both `dev` and `test` with only
  cosmetic changes; (d) adding runs after seeing `test` results. Slices have different hashes and are
  **not** caught by the registration guard (E2, E3), so this is a rule to follow by hand.
* The combined attack runs can also provide the multi-stage demo capture (PRD §19 criterion 2).

### Prioritised acquisition order

1. **Decide Q1–Q4.** Nothing can be recorded before they are answered.
2. **Batch 1** (attack runs). It moves 14 rows at once, and the M1 baseline, threshold tuning and
   the demo all depend on it.
3. **Batch 2, or the optional episode in batch 1** (`AUTOMATION_SSH`). This one is benign and lowest
   risk, so it is the first candidate for a lab-runner scenario if Q2 allows it.
4. **Batch 3** (held-out runs). These are needed only for G1, which comes after M1.
5. **Optional: C5 licence enquiry.** This would give independent second-source iodine/dnscat2
   evidence.
6. **Then** run `lab.register_external` → worker analysis → `lab.verify_run` per run →
   `eval.splits assign` → `eval.splits report` must show 27/27. Only then proceed to `dev` tuning
   and the single `test` run.

---

## G. Unresolved questions (human decisions)

1. **Who produces the attack and held-out captures?** In P2 you declined attack-generation tooling in
   this repository. The options are an authorised external supplier, a separate isolated lab outside
   this repository, or reversing that decision with an ADR.
2. **May the lab runner gain an `AUTOMATION_SSH` benign scenario?** It is benign, but it means new
   lab code and an SSH service container.
3. **Is C5 usable?** It has no licence; contact the authors. It would also need importer-attested
   provenance, which needs a policy decision.
4. **Network configuration for new captures.** Reuse `network.lab.yaml` with a routed topology, or
   approve a new `config/network.<source>.yaml`? A new config file changes `config/` and the
   manifest config hashes.
5. **Campaign duplicates for external runs.** Accept a manual log, or add a campaign identifier to
   `submission.json` through an `eval/REVISIONS.md` entry before any assignment?
6. **Which three held-out families?** Is SMB/RPC enumeration in scope for an isolated lab with no
   Windows hosts?
7. **Target size.** 20 is the mathematical minimum and 26 to 28 the recommendation. Which do you commission? Either way, no slicing and no campaign reuse across splits.
8. **Analysis size limit.** Split captures over 500 MiB, or raise `MAX_UPLOAD_BYTES` for verification
   runs?
9. **CICIDS2017 / CSE-CIC-IDS2018** for the PRD's secondary checks: still deferred? Each download
   needs approval.
10. **Per-family BRUTE minimum.** The PRD requires FTP/HTTP and SSH to be reported separately but sets no minimum per family. Accept 2 per family per split (minimum plan), 4 (recommended plan), or set a different number before anything is recorded?
