# Revisions log

Every change to `eval/PROTOCOL.md`, a PRD §18 target, or a split assignment is recorded here with its
reason (`docs/instruction.md` §3.3, `eval/PROTOCOL.md` header). Entries are append-only. A change must
never be motivated by making a metric look better.

| # | Date | Item | Change | Reason | Approved by |
|---|---|---|---|---|---|
| 1 | 2026-10-04 | `eval/PROTOCOL.md` §2 label format | Added optional-in-practice fields `schema_version` and `kind` (`attack` / `holdout` / `hard_negative`) to each `labels.jsonl` record, a `tool` field that defaults to empty, and stable episode-id prefixes per client (e.g. `r001-c101-e1`) | Needed to keep hard negatives and held-out families out of detector classes and to let several clients share one labels file without id collisions. Additive: no metric, threshold, matching rule, split or target changed. Implemented in `lab/schema.py` | User (P2 partial-milestone instruction, "ground-truth label schema") |
| 2 | 2026-10-04 | `lab/README.md` topology | Single `services` host (172.20.0.20, also 172.21.0.20) instead of separate SSH/FTP/HTTP/File/DNS/Backup hosts for the benign skeleton | One tcpdump sidecar sharing that host's network namespace captures every conversation; Docker bridges do not flood unicast to a third container. Separate attack-target hosts remain a deferred design item | User (same instruction) |
