"""Split manifest tooling (eval/PROTOCOL.md §4).

    python -m eval.splits assign                  # give every unassigned run a split (append-only)
    python -m eval.splits validate [--against-git]  # integrity + immutability checks
    python -m eval.splits report [--require-complete]  # corpus requirements vs. what exists

Rules enforced here, not just documented:
  * splits are by run, never by row; a run is in exactly one of dev/test;
  * assignment is deterministic (seeded) and stratified so each scenario stratum is ~50/50;
  * assignment is APPEND-ONLY: an existing run's split is never changed by this tool, and
    `validate --against-git` fails if the committed manifest's assignments were altered;
  * each entry stores SHA-256 of the run's run.json and labels.jsonl, so editing a label or run
    record after assignment is detected.
`report` states plainly which acceptance requirements are unmet; it never fills a gap.
"""

import argparse
import hashlib
import subprocess  # fixed argv, shell=False
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from lab.labeler import read_labels
from lab.runmeta import RunMeta, load_run
from lab.schema import ATTACK_CLASSES, HARD_NEGATIVE_CLASSES, HOLDOUT_CLASSES, Episode

REPO = Path(__file__).resolve().parents[1]
RUNS_DIR = REPO / "lab" / "runs"
SPLITS_PATH = REPO / "eval" / "splits.yaml"
SPLIT_NAMES = ("dev", "test")
MANIFEST_VERSION = 1
DNS_TUNNEL_TOOLS = ("iodine", "dnscat2")  # tool-held-out evaluation (PROTOCOL §4)

# Acceptance numbers from docs/plan.md P2 / instruction.md §8.
MIN_EPISODES_PER_CLASS_PER_SPLIT = 4
MIN_HOLDOUT_FAMILIES = 3
MIN_HOLDOUT_TEST_CAPTURES = 8
MIN_BENIGN_HOURS = 4.0


@dataclass(frozen=True)
class LoadedRun:
    meta: RunMeta
    episodes: tuple[Episode, ...]
    run_json_sha256: str
    labels_sha256: str


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_runs(runs_dir: Path = RUNS_DIR) -> dict[str, LoadedRun]:
    runs: dict[str, LoadedRun] = {}
    for run_dir in sorted(p for p in runs_dir.iterdir() if p.is_dir()):
        meta = load_run(run_dir / "run.json")
        if meta.run_id != run_dir.name:
            raise ValueError(f"{run_dir.name}: run.json run_id is {meta.run_id!r}")
        labels_path = run_dir / "labels.jsonl"
        episodes = tuple(read_labels(labels_path)) if labels_path.exists() else ()
        for episode in episodes:
            if episode.run_id != meta.run_id:
                raise ValueError(
                    f"{run_dir.name}: episode {episode.episode_id} is from another run"
                )
        if not meta.benign_only and not episodes:
            raise ValueError(f"{run_dir.name}: not benign_only but has no labelled episodes")
        runs[meta.run_id] = LoadedRun(
            meta,
            episodes,
            _sha256(run_dir / "run.json"),
            _sha256(labels_path) if labels_path.exists() else "",
        )
    return runs


def stratum(run: LoadedRun) -> str:
    """Runs are balanced within a stratum: the sorted set of kind:class (plus the tool for DNS
    tunnels, so both tools land in both splits). A run with no episodes is plain BENIGN."""
    if not run.episodes:
        return "BENIGN"
    parts = {
        f"{e.kind}:{e.cls}" + (f"/{e.tool}" if e.cls == "DNSTUN" and e.tool else "")
        for e in run.episodes
    }
    return "+".join(sorted(parts))


def _tie_break(seed: int, run_id: str) -> int:
    return hashlib.sha256(f"{seed}:{run_id}".encode()).digest()[0] % 2


def assign_new(
    existing: Mapping[str, Mapping[str, str]], runs: Mapping[str, LoadedRun], seed: int
) -> dict[str, dict[str, str]]:
    """Return entries for runs that have none yet. Existing entries are never touched."""
    counts: dict[str, dict[str, int]] = {}
    for entry in existing.values():
        counts.setdefault(entry["stratum"], dict.fromkeys(SPLIT_NAMES, 0))[entry["split"]] += 1
    created: dict[str, dict[str, str]] = {}
    pending = sorted((stratum(r), run_id) for run_id, r in runs.items() if run_id not in existing)
    for run_stratum, run_id in pending:
        tally = counts.setdefault(run_stratum, dict.fromkeys(SPLIT_NAMES, 0))
        if tally["dev"] == tally["test"]:
            split = SPLIT_NAMES[_tie_break(seed, run_id)]
        else:
            split = "dev" if tally["dev"] < tally["test"] else "test"
        tally[split] += 1
        run = runs[run_id]
        created[run_id] = {
            "split": split,
            "stratum": run_stratum,
            "run_json_sha256": run.run_json_sha256,
            "labels_sha256": run.labels_sha256,
        }
    return created


def load_manifest(path: Path = SPLITS_PATH) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if data.get("version") != MANIFEST_VERSION:
        raise ValueError(f"{path.name}: unsupported manifest version {data.get('version')!r}")
    data["assigned"] = data.get("assigned") or {}
    return data


def dump_manifest(manifest: Mapping[str, Any]) -> str:
    header = (
        "# Split manifest (eval/PROTOCOL.md §4). Generated by `python -m eval.splits assign`.\n"
        "# APPEND-ONLY: never edit an existing assignment. Changes need an entry in\n"
        "# eval/REVISIONS.md and user approval (docs/instruction.md §3.3).\n"
    )
    body = yaml.safe_dump(dict(manifest), sort_keys=True, default_flow_style=False)
    return header + body


def immutability_violations(
    old: Mapping[str, Mapping[str, str]], new: Mapping[str, Mapping[str, str]]
) -> list[str]:
    problems = []
    for run_id, entry in old.items():
        if run_id not in new:
            problems.append(f"{run_id}: assignment removed")
        elif new[run_id]["split"] != entry["split"]:
            problems.append(f"{run_id}: moved from {entry['split']} to {new[run_id]['split']}")
    return problems


def validate(manifest: Mapping[str, Any], runs: Mapping[str, LoadedRun]) -> list[str]:
    problems: list[str] = []
    assigned: Mapping[str, Mapping[str, str]] = manifest["assigned"]
    for run_id in sorted(set(runs) - set(assigned)):
        problems.append(f"{run_id}: has no split assignment")
    for run_id in sorted(set(assigned) - set(runs)):
        problems.append(f"{run_id}: assigned but no run record exists")
    for run_id, entry in assigned.items():
        if entry.get("split") not in SPLIT_NAMES:
            problems.append(f"{run_id}: invalid split {entry.get('split')!r}")
        run = runs.get(run_id)
        if run is None:
            continue
        if entry.get("run_json_sha256") != run.run_json_sha256:
            problems.append(f"{run_id}: run.json changed after assignment")
        if entry.get("labels_sha256") != run.labels_sha256:
            problems.append(f"{run_id}: labels.jsonl changed after assignment")
    return problems


@dataclass(frozen=True)
class Requirement:
    name: str
    required: str
    actual: str
    met: bool


def corpus_report(manifest: Mapping[str, Any], runs: Mapping[str, LoadedRun]) -> list[Requirement]:
    """Compare the committed corpus to the P2 acceptance criteria. Missing data stays missing."""
    split_of = {run_id: e["split"] for run_id, e in manifest["assigned"].items()}
    out: list[Requirement] = []

    def episodes(kind: str, cls: str, split: str, tool: str | None = None) -> int:
        return sum(
            1
            for run_id, r in runs.items()
            if split_of.get(run_id) == split
            for e in r.episodes
            if e.kind == kind and e.cls == cls and (tool is None or e.tool == tool)
        )

    for cls in ATTACK_CLASSES:
        for split in SPLIT_NAMES:
            n = episodes("attack", cls, split)
            need = MIN_EPISODES_PER_CLASS_PER_SPLIT
            out.append(
                Requirement(f"attack {cls} episodes ({split})", f">= {need}", str(n), n >= need)
            )
    for tool in DNS_TUNNEL_TOOLS:
        for split in SPLIT_NAMES:
            n = episodes("attack", "DNSTUN", split, tool)
            out.append(
                Requirement(f"DNSTUN tool {tool} ({split}), tool-held-out", ">= 1", str(n), n >= 1)
            )
    for cls in HARD_NEGATIVE_CLASSES:
        present = [episodes("hard_negative", cls, s) >= 1 for s in SPLIT_NAMES]
        counts = "/".join(str(episodes("hard_negative", cls, s)) for s in SPLIT_NAMES)
        out.append(
            Requirement(
                f"hard negative {cls} in both splits",
                "dev>=1, test>=1",
                f"dev/test {counts}",
                all(present),
            )
        )
    families = {
        e.cls
        for r in runs.values()
        for e in r.episodes
        if e.kind == "holdout" and e.cls in HOLDOUT_CLASSES
    }
    out.append(
        Requirement(
            "LAB-HOLDOUT families captured",
            f">= {MIN_HOLDOUT_FAMILIES}",
            f"{len(families)} ({', '.join(sorted(families)) or 'none'})",
            len(families) >= MIN_HOLDOUT_FAMILIES,
        )
    )
    holdout_test = sum(
        1 for rid, r in runs.items() if r.meta.holdout and split_of.get(rid) == "test"
    )
    out.append(
        Requirement(
            "LAB-HOLDOUT test captures",
            f">= {MIN_HOLDOUT_TEST_CAPTURES}",
            str(holdout_test),
            holdout_test >= MIN_HOLDOUT_TEST_CAPTURES,
        )
    )
    benign_h = sum(r.meta.duration_s for r in runs.values() if r.meta.benign_only) / 3600
    out.append(
        Requirement(
            "benign-only capture hours",
            f">= {MIN_BENIGN_HOURS:g}",
            f"{benign_h:.2f}",
            benign_h >= MIN_BENIGN_HOURS,
        )
    )
    for split in SPLIT_NAMES:
        n = sum(1 for rid, r in runs.items() if r.meta.benign_only and split_of.get(rid) == split)
        out.append(Requirement(f"benign-only runs ({split})", ">= 1", str(n), n >= 1))
    return out


def _git_head_manifest() -> dict[str, Any] | None:
    result = subprocess.run(
        ["git", "show", "HEAD:eval/splits.yaml"],  # noqa: S607
        cwd=REPO,
        capture_output=True,
        text=True,
        check=False,
        shell=False,
    )
    if result.returncode != 0:
        return None
    data = yaml.safe_load(result.stdout) or {}
    data["assigned"] = data.get("assigned") or {}
    return data


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawTextHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", required=True)
    assign = sub.add_parser("assign")
    assign.add_argument("--seed", type=int, default=20261004)
    check = sub.add_parser("validate")
    check.add_argument("--against-git", action="store_true")
    rep = sub.add_parser("report")
    rep.add_argument("--require-complete", action="store_true")
    args = parser.parse_args(argv)

    runs = load_runs()
    manifest = load_manifest()
    if args.command == "assign":
        seed = manifest.get("seed", args.seed)
        manifest["seed"] = seed
        created = assign_new(manifest["assigned"], runs, seed)
        manifest["assigned"].update(created)
        SPLITS_PATH.write_text(dump_manifest(manifest), encoding="utf-8")
        print(f"assigned {len(created)} new run(s); {len(manifest['assigned'])} total")
        return 0
    if args.command == "validate":
        problems = validate(manifest, runs)
        if args.against_git:
            head = _git_head_manifest()
            if head is not None:
                problems += immutability_violations(head["assigned"], manifest["assigned"])
        for problem in problems:
            print(f"PROBLEM  {problem}")
        print(
            f"{len(runs)} run(s), {len(manifest['assigned'])} assignment(s): "
            f"{'OK' if not problems else f'{len(problems)} problem(s)'}"
        )
        return 1 if problems else 0
    requirements = corpus_report(manifest, runs)
    unmet = [r for r in requirements if not r.met]
    for r in requirements:
        status = "MET   " if r.met else "UNMET "
        print(f"{status} {r.name:<55} required {r.required:<16} actual {r.actual}")
    met = len(requirements) - len(unmet)
    print()
    print(f"{met}/{len(requirements)} requirements met; {len(unmet)} unmet")
    return 1 if (args.require_complete and unmet) else 0


if __name__ == "__main__":
    sys.exit(main())
