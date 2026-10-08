# Demo walkthrough (5 to 7 minutes)

**Honest scope.** The demo capture is a real, verified *benign* lab capture (`scripts/make_demo.py`). It has no
attack in it: this repository generates no attack traffic, so the scan -> brute force -> beacon -> exfil
storyline of plan P10 is **pending a supplied, verified capture** (`python -m lab.register_external`). What the
benign demo shows is what triage looks like when the rules fire on harmless, regular traffic.

## Set up (once)

```bash
cp .env.example .env
docker compose up --build -d          # UI on http://127.0.0.1:8080, API on the internal network
python scripts/make_demo.py           # needs the recorded lab run b02 (data/lab/b02/capture.pcap)
```

Open http://127.0.0.1:8080. `LLM_PROVIDER` stays `none`; the narrative panel is shown in the last step.

## Script

1. **Upload (30 s).** Drop `demo/demo.pcap` on the upload area. Point out: the file type is checked by magic
   bytes, the name is replaced by a UUID, only the worker container parses it (no network, read-only filesystem).
   Try a text file renamed `.pcap`: it is rejected with a clear message.
2. **Profile and data-quality warnings (45 s).** The overview shows the capture span, hosts, connections and any
   warnings (for example one-sided traffic) that would make a detector unreliable. Each stage has a timing.
3. **Incidents and storyline (60 s).** Open the top incident. The severity is an ordering aid, not a risk score. The
   storyline shows each finding on a lane; linked incidents appear when the correlator found a shared entity.
4. **Why this fired (90 s).** Open the BEACON finding. Show every measured value against its threshold with a
   word verdict (not colour alone), the confidence, and the **known benign causes**: a monitoring heartbeat or a
   package-update check looks exactly like this. This is the lesson of the demo: a rule that fires on regular
   traffic is a lead, not a verdict, and the dev run records these as false positives
   (`eval/results/dev-benign-baseline-v1/`).
5. **Evidence (30 s).** Click an `E-` chip in the summary: focus moves to that evidence row. Every number in the
   summary is traceable to a row.
6. **Packet slice (45 s).** Press the slice button on the finding, wait for the worker, download the `.pcap`, and
   open it in Wireshark (not automated; checked by hand only on request).
7. **ATT&CK card (30 s).** The technique is shown as *consistent with*, with the pinned ATT&CK version. No
   attribution, and anomalies never receive a technique.
8. **Feedback and report (30 s).** Mark the finding "expected benign" with a note; export the Markdown or HTML
   report. Both escape everything derived from the capture and list the limitations.
9. **Narrative, optional (45 s).** With `LLM_PROVIDER=none` the panel says no narrative was requested and the
   template summary stays. With a provider configured, a narrative appears only if the validator accepts it
   (badge, citation chips, alternatives for every inference); a rejected one is never shown, only its reasons.
   Gate G2 has not been run, so this stays opt-in.
10. **Close (15 s).** Delete the investigation: rows, upload, artifacts, slices, feedback and narrative are gone.

## When a verified attack capture exists

```bash
python scripts/make_demo.py --attack path/to/verified-attack.pcap
```

Then steps 3 to 7 show a real multi-finding incident. Do not describe it as detector performance: performance
comes only from `eval.run_detectors` on the `test` split once the corpus requirements are met.
