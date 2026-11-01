# Licensing enquiry draft: Tianjin University DNS-tunnel PCAPs

**Status: DRAFT, NOT SENT.** Nothing has been downloaded, registered or used. Sending it is a human action
(it speaks on the project owner's behalf); the author contact addresses are in the paper, not in this
repository, and were not looked up here.

## Why we are asking

Tracewright needs plain-DNS `iodine` and `dnscat2` captures in both its development and test splits
(`docs/CAPTURE_ACQUISITION_PLAN.md` C5). The repository at
https://github.com/Utah1A/DNS-tunnelling-detection-by-fusing-encoding-feature-and-behavioral-feature
accompanies Tu, Liu and Sun, "DNS tunnelling detection by fusing encoding feature and behavioral feature",
*Computers & Security*, 2023 (DOI 10.1016/j.cose.2023.103357). Its README describes raw PCAPs for eight
tunnel tools (including both) produced in a simulated environment with isolated addresses. **The README
states no licence**, so by default we have no right to copy, redistribute or derive from the files.

## What the project will not do until the answer is clear

* download, store, register, analyse or cite results from the files;
* redistribute them or commit them to any repository (captures are never committed in this project);
* treat the files as real-world evidence or mix them into the primary 27-requirement corpus without the
  checks below.

## Draft message

> Subject: Licence and provenance question about the DNS-tunnel PCAPs accompanying your Computers & Security 2023 paper
>
> Dear Professor / Dr. <name>,
>
> I maintain Tracewright, an open, offline network-incident investigation tool that includes a rule-based DNS
> tunnelling detector. We are building an evaluation corpus and would like to use plain-DNS iodine and dnscat2
> traffic from your published dataset
> (github.com/Utah1A/DNS-tunnelling-detection-by-fusing-encoding-feature-and-behavioral-feature).
>
> Before touching the data we would like to ask:
> 1. Under what licence may the PCAPs be used for research evaluation? May derived results be published?
>    May the raw files be redistributed, or only fetched from your repository?
> 2. Were the captures made entirely in an isolated environment, with no real user traffic and no
>    third-party infrastructure involved? Could you confirm that statement in writing?
> 3. For each tool file: tool name and version, which host was the client and which the server, the start
>    and end time (and time zone) of each tunnel session, and whether the capture is one tool per file?
> 4. Do the files contain non-DNS background traffic (the README notes some), and was any of it real?
> 5. How would you like the dataset to be cited?
>
> We will not use the data until you have answered, and we will record your reply as provenance. Thank you.
>
> <name, affiliation, project URL>

## What a "yes" must contain before anything is registered

| Needed | Why (contract reference) |
|---|---|
| a licence statement permitting research evaluation (and publication of results) | `docs/CAPTURE_ACQUISITION_PLAN.md` E6 |
| written confirmation of isolated collection, no real user data | `provenance.isolated_environment: true` and `contains_real_user_data: false` are attestations we would be making ourselves |
| tool versions and exact start/end time of each tunnel session, one tool per file | labels need a UTC `start`/`end`, `tool` exactly `iodine` or `dnscat2` (`lab/schema.py`); labels come from the supplier's schedule, never from our detectors |
| an internal client address for each episode, plus a `network_config` under which it is internal | `lab.submission.check_network_roles` |
| independent sessions for dev and test | one `campaign_id` per independent campaign; a campaign never spans both splits |

If any item is missing the captures are **not** registered. If the answer is "no" or silence, the iodine and
dnscat2 rows come from the authorised isolated-lab path only (`docs/CAPTURE_HANDOFF.md`).
