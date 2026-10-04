import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("eval")
pytest.importorskip("lab")

from eval import splits
from lab.runmeta import RunMeta, load_run
from lab.schema import ATTACK_CLASSES, HARD_NEGATIVE_CLASSES, HOLDOUT_CLASSES, Episode

T0 = datetime(2026, 11, 2, 10, 0, 0, tzinfo=UTC)


def write_run(
    runs_dir: Path,
    run_id: str,
    episodes: list[tuple[str, str, str]] | None = None,  # (kind, class, tool)
    *,
    holdout: bool = False,
    duration_s: float = 600.0,
) -> None:
    episodes = episodes or []
    d = runs_dir / run_id
    d.mkdir(parents=True)
    benign_only = not holdout and all(k == "hard_negative" for k, _, _ in episodes)
    meta = RunMeta(
        run_id=run_id,
        capture_sha256="ab" * 32,
        capture_bytes=1,
        start="2026-11-02T10:00:00.000Z",
        end="2026-11-02T10:10:00.000Z",
        seed=1,
        holdout=holdout,
        benign_only=benign_only,
        duration_s=duration_s,
        scenarios=(),
        network_config="network.lab.yaml",
    )
    (d / "run.json").write_text(meta.to_json())
    if episodes:
        lines = []
        for n, (kind, cls, tool) in enumerate(episodes, start=1):
            e = Episode(
                run_id, f"{run_id}-e{n}", kind, cls, "172.20.0.101", ("172.20.0.20",),
                T0, T0 + timedelta(seconds=5), tool,
            )  # fmt: skip
            lines.append(json.dumps(e.to_json_dict(), sort_keys=True))
        (d / "labels.jsonl").write_text("\n".join(lines) + "\n")


def manifest(assigned: dict[str, Any] | None = None, seed: int = 7) -> dict[str, Any]:
    return {"version": 1, "seed": seed, "assigned": assigned or {}}


@pytest.fixture
def runs_dir(tmp_path: Path) -> Path:
    d = tmp_path / "runs"
    d.mkdir()
    return d


def test_assignment_is_balanced_within_each_stratum(runs_dir: Path) -> None:
    for i in range(10):
        write_run(runs_dir, f"hn{i:02d}", [("hard_negative", "NTP", "")])
    for i in range(7):
        write_run(runs_dir, f"bg{i:02d}")
    runs = splits.load_runs(runs_dir)
    created = splits.assign_new({}, runs, seed=1)
    ntp = [e["split"] for e in created.values() if e["stratum"] == "hard_negative:NTP"]
    benign = [e["split"] for e in created.values() if e["stratum"] == "BENIGN"]
    assert ntp.count("dev") == ntp.count("test") == 5
    assert abs(benign.count("dev") - benign.count("test")) == 1  # odd count: off by exactly one


def test_assignment_is_deterministic_and_independent_of_directory_order(runs_dir: Path) -> None:
    for i in range(6):
        write_run(runs_dir, f"r{i}", [("hard_negative", "NTP", "")])
    runs = splits.load_runs(runs_dir)
    a = splits.assign_new({}, runs, seed=3)
    b = splits.assign_new({}, dict(reversed(list(runs.items()))), seed=3)
    assert a == b
    assert a != splits.assign_new({}, runs, seed=4)


def test_assignment_is_append_only(runs_dir: Path) -> None:
    for i in range(4):
        write_run(runs_dir, f"r{i}", [("hard_negative", "NTP", "")])
    first = splits.assign_new({}, splits.load_runs(runs_dir), seed=1)
    write_run(runs_dir, "r9", [("hard_negative", "NTP", "")])
    later = splits.assign_new(first, splits.load_runs(runs_dir), seed=1)
    assert set(later) == {"r9"}  # existing runs are never reassigned
    assert splits.assign_new({**first, **later}, splits.load_runs(runs_dir), seed=1) == {}


def test_dns_tunnel_tools_are_separate_strata(runs_dir: Path) -> None:
    for i in range(2):
        write_run(runs_dir, f"io{i}", [("attack", "DNSTUN", "iodine")])
        write_run(runs_dir, f"dn{i}", [("attack", "DNSTUN", "dnscat2")])
    runs = splits.load_runs(runs_dir)
    created = splits.assign_new({}, runs, seed=1)
    for tool in ("iodine", "dnscat2"):
        got = {e["split"] for e in created.values() if e["stratum"].endswith(f"/{tool}")}
        assert got == {"dev", "test"}


def test_load_runs_rejects_inconsistent_records(runs_dir: Path) -> None:
    write_run(runs_dir, "r1", [("hard_negative", "NTP", "")])
    (runs_dir / "r1" / "run.json").write_text(
        (runs_dir / "r1" / "run.json").read_text().replace('"r1"', '"other"', 1)
    )
    with pytest.raises(ValueError, match="run_id is 'other'"):
        splits.load_runs(runs_dir)


def test_attack_run_without_labels_is_rejected(runs_dir: Path) -> None:
    write_run(runs_dir, "r1", [("attack", "SCAN", "")])
    (runs_dir / "r1" / "labels.jsonl").unlink()
    with pytest.raises(ValueError, match="no labelled episodes"):
        splits.load_runs(runs_dir)


def test_runmeta_validation(runs_dir: Path) -> None:
    write_run(runs_dir, "r1")
    good = load_run(runs_dir / "r1" / "run.json")
    assert good.benign_only and good.network_config == "network.lab.yaml"
    for bad in (
        {"capture_sha256": "zz"},
        {"holdout": True, "benign_only": True},
        {"run_id": "a/b"},
    ):
        data = json.loads(good.to_json()) | bad
        data["scenarios"] = ()
        with pytest.raises(ValueError):
            RunMeta(**data)


def test_validate_detects_tampering_and_gaps(runs_dir: Path) -> None:
    write_run(runs_dir, "r1", [("hard_negative", "NTP", "")])
    write_run(runs_dir, "r2", [("hard_negative", "NTP", "")])
    runs = splits.load_runs(runs_dir)
    assigned = splits.assign_new({}, runs, seed=1)
    assert splits.validate(manifest(assigned), runs) == []

    # Editing a label after assignment (here: a different actor) must be detected.
    e = Episode("r1", "r1-e1", "hard_negative", "NTP", "172.20.0.102", ("172.20.0.20",), T0, T0)
    changed = json.dumps(e.to_json_dict(), sort_keys=True)
    (runs_dir / "r1" / "labels.jsonl").write_text(changed + chr(10))
    problems = splits.validate(manifest(assigned), splits.load_runs(runs_dir))
    assert problems == ["r1: labels.jsonl changed after assignment"]

    missing = splits.validate(manifest({"r1": assigned["r1"]}), splits.load_runs(runs_dir))
    assert any("r2: has no split assignment" in p for p in missing)
    ghost = splits.validate(
        manifest({**assigned, "gone": assigned["r1"]}), splits.load_runs(runs_dir)
    )
    assert any("gone: assigned but no run record exists" in p for p in ghost)
    bad_split = {**assigned, "r2": {**assigned["r2"], "split": "train"}}
    assert any(
        "invalid split" in p
        for p in splits.validate(manifest(bad_split), splits.load_runs(runs_dir))
    )


def test_immutability_violations() -> None:
    old = {"a": {"split": "dev"}, "b": {"split": "test"}, "c": {"split": "dev"}}
    new = {"a": {"split": "dev"}, "b": {"split": "dev"}, "d": {"split": "test"}}
    assert splits.immutability_violations(old, new) == [
        "b: moved from test to dev",
        "c: assignment removed",
    ]
    assert splits.immutability_violations(old, {**old, "e": {"split": "test"}}) == []


def test_manifest_round_trip_and_version_check(tmp_path: Path) -> None:
    path = tmp_path / "splits.yaml"
    path.write_text(
        splits.dump_manifest(manifest({"r1": {"split": "dev", "stratum": "BENIGN"}})),
        encoding="utf-8",
    )
    assert splits.load_manifest(path)["assigned"]["r1"]["split"] == "dev"
    path.write_text("version: 2\nassigned: {}\n")
    with pytest.raises(ValueError, match="unsupported manifest version"):
        splits.load_manifest(path)


def test_shipped_manifest_is_valid_and_currently_empty() -> None:
    shipped = splits.load_manifest()
    assert shipped["assigned"] == {}  # nothing recorded yet; see eval/datasets.md
    assert splits.validate(shipped, splits.load_runs()) == []


def test_report_on_empty_corpus_marks_everything_unmet_and_requires_completion() -> None:
    requirements = splits.corpus_report(manifest(), {})
    assert requirements and not any(r.met for r in requirements)
    assert len([r for r in requirements if "attack" in r.name]) == len(ATTACK_CLASSES) * 2


def test_report_on_a_synthetic_complete_corpus_is_all_met(runs_dir: Path) -> None:
    n = 8  # >= 4 per split after a 50/50 assignment
    for cls in ATTACK_CLASSES:
        tools = ("iodine", "dnscat2") if cls == "DNSTUN" else ("",)
        for tool in tools:
            for i in range(n):
                write_run(runs_dir, f"a-{cls}-{tool}-{i}", [("attack", cls, tool)])
    for cls in HARD_NEGATIVE_CLASSES:
        for i in range(2):
            write_run(runs_dir, f"h-{cls}-{i}", [("hard_negative", cls, "")])
    for cls in HOLDOUT_CLASSES:
        for i in range(4):
            write_run(runs_dir, f"o-{cls}-{i}", [("holdout", cls, "")], holdout=True)
    for i in range(5):
        write_run(runs_dir, f"b{i}", duration_s=3600.0)
    runs = splits.load_runs(runs_dir)
    assigned = splits.assign_new({}, runs, seed=1)
    result = splits.corpus_report(manifest(assigned), runs)
    unmet = [r.name for r in result if not r.met]
    assert unmet == []


def test_report_flags_each_specific_shortfall(runs_dir: Path) -> None:
    for i in range(3):  # only 3 SCAN runs: cannot reach 4 in both splits
        write_run(runs_dir, f"s{i}", [("attack", "SCAN", "")])
    write_run(runs_dir, "n0", [("hard_negative", "NTP", "")])
    write_run(runs_dir, "b0", duration_s=7200.0)
    runs = splits.load_runs(runs_dir)
    result = {
        r.name: r for r in splits.corpus_report(manifest(splits.assign_new({}, runs, 1)), runs)
    }
    scan = [result["attack SCAN episodes (dev)"], result["attack SCAN episodes (test)"]]
    assert sorted(r.actual for r in scan) == ["1", "2"] and not any(r.met for r in scan)
    assert not result["hard negative NTP in both splits"].met  # one run cannot be in both splits
    assert (
        result["benign-only capture hours"].actual == "2.17"
        and not result["benign-only capture hours"].met
    )


def test_cli_report_exit_codes(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    assert splits.main(["report"]) == 0
    assert "0/27 requirements met; 27 unmet" in capsys.readouterr().out
    assert splits.main(["report", "--require-complete"]) == 1
    assert splits.main(["validate"]) == 0
