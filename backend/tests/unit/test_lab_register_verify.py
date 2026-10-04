"""External-run registration and verification (synthetic metadata; see tests/lab_helpers.py).

The analysis directories below are SYNTHETIC stand-ins for `tracewright analyze` output, built to
test the verification logic; they are not evaluation data.
"""

import gzip
import json
from pathlib import Path
from typing import Any

import pandas as pd
import pytest

pytest.importorskip("lab")

from lab import verify_run
from lab.register_external import RegistrationError, main, register
from lab.runmeta import load_run
from lab.verification import FILE_NAME, eligibility, load_verification

from tests.lab_helpers import (
    CLIENT_IP,
    T0,
    TARGET_IP,
    empty_pcap_bytes,
    episode_dict,
    valid_submission,
    write_submission_dir,
)


@pytest.fixture
def dirs(tmp_path: Path, config_dir: Path) -> dict[str, Path]:
    runs, data = tmp_path / "runs", tmp_path / "data"
    runs.mkdir()
    return {"runs": runs, "data": data, "config": config_dir, "src": tmp_path / "src"}


def reg(d: dict[str, Path], src: Path) -> Any:
    return register(src, d["runs"], d["data"], d["config"])


def assert_nothing_written(d: dict[str, Path]) -> None:
    assert list(d["runs"].iterdir()) == []
    assert not d["data"].exists() or list(d["data"].iterdir()) == []


def test_valid_external_run_is_staged_but_not_yet_eligible(dirs: dict[str, Path]) -> None:
    src = write_submission_dir(dirs["src"])
    meta = reg(dirs, src)
    run_dir = dirs["runs"] / "x001"
    assert meta.origin == "external" and meta.seed is None and meta.benign_only is False
    assert meta.capture_sha256 != "" and meta.capture_bytes == 24
    assert (run_dir / "run.json").exists() and (run_dir / "labels.jsonl").exists()
    assert (dirs["data"] / "x001" / "capture.pcap").exists()
    assert not (run_dir / FILE_NAME).exists()
    loaded = load_run(run_dir / "run.json")
    assert loaded.provenance is not None and loaded.provenance["supplied_by"] == "test-author"
    assert eligibility(run_dir, loaded) == (False, "not verified (no valid verification.json)")


def test_capture_hash_is_computed_here_not_taken_from_the_supplier(dirs: dict[str, Path]) -> None:
    sub = valid_submission() | {"capture_sha256": "00" * 32}
    src = write_submission_dir(dirs["src"], submission=sub)
    with pytest.raises(RegistrationError, match="unknown fields"):
        reg(dirs, src)
    assert_nothing_written(dirs)


def test_missing_provenance_is_rejected(dirs: dict[str, Path]) -> None:
    sub = valid_submission()
    del sub["provenance"]
    with pytest.raises(RegistrationError, match=r"submission.json: missing fields"):
        reg(dirs, write_submission_dir(dirs["src"], submission=sub))
    assert_nothing_written(dirs)


@pytest.mark.parametrize(
    ("capture", "message"),
    [
        (b"this is not a capture file at all......", "FILE_TYPE_INVALID"),
        (gzip.compress(empty_pcap_bytes()), "FILE_COMPRESSED"),
        (b"", "FILE_EMPTY"),
        (empty_pcap_bytes()[:10], "FILE_TYPE_INVALID"),
    ],
)
def test_externally_supplied_capture_failing_validation_is_rejected(
    dirs: dict[str, Path], capture: bytes, message: str
) -> None:
    src = write_submission_dir(dirs["src"], capture=capture)
    with pytest.raises(RegistrationError, match=message):
        reg(dirs, src)
    assert_nothing_written(dirs)


def test_malformed_labels_are_rejected(dirs: dict[str, Path]) -> None:
    bad_class = [episode_dict() | {"class": "NOT_A_CLASS"}]
    with pytest.raises(RegistrationError, match=r"labels.jsonl: .*not valid for kind"):
        reg(dirs, write_submission_dir(dirs["src"], "a1", labels=bad_class))
    broken = dirs["src"] / "a2"
    write_submission_dir(dirs["src"], "a2")
    (broken / "labels.jsonl").write_text("{not json}\n")
    with pytest.raises(RegistrationError, match=r"labels.jsonl"):
        reg(dirs, broken)
    no_labels = write_submission_dir(dirs["src"], "a3", labels=[])
    with pytest.raises(RegistrationError, match="no episodes"):
        reg(dirs, no_labels)
    assert_nothing_written(dirs)


def test_label_run_id_must_match_the_submission(dirs: dict[str, Path]) -> None:
    labels = [episode_dict(run_id="someone-else")]
    with pytest.raises(RegistrationError, match="run_id 'someone-else'"):
        reg(dirs, write_submission_dir(dirs["src"], labels=labels))
    assert_nothing_written(dirs)


def test_labels_and_declaration_must_agree(dirs: dict[str, Path]) -> None:
    labels = [episode_dict(actor="172.20.0.199")]
    with pytest.raises(RegistrationError, match="not a declared client"):
        reg(dirs, write_submission_dir(dirs["src"], "b1", labels=labels))
    undeclared = [episode_dict(), episode_dict(cls="BRUTE", n=2)]
    with pytest.raises(RegistrationError, match="was not declared"):
        reg(dirs, write_submission_dir(dirs["src"], "b2", labels=undeclared))
    assert_nothing_written(dirs)


def test_unknown_network_config_is_rejected(dirs: dict[str, Path]) -> None:
    sub = valid_submission() | {"network_config": "network.nonexistent.yaml"}
    with pytest.raises(RegistrationError, match="not found in config"):
        reg(dirs, write_submission_dir(dirs["src"], submission=sub))
    assert_nothing_written(dirs)


def test_duplicate_run_id_is_rejected_and_first_run_is_untouched(dirs: dict[str, Path]) -> None:
    reg(dirs, write_submission_dir(dirs["src"], "x001", variant=1))
    before = (dirs["runs"] / "x001" / "run.json").read_text()
    with pytest.raises(RegistrationError, match="already registered"):
        reg(dirs, write_submission_dir(dirs["src"] / "again", "x001", variant=2))
    assert (dirs["runs"] / "x001" / "run.json").read_text() == before


def test_the_same_capture_cannot_be_registered_under_a_new_run_id(dirs: dict[str, Path]) -> None:
    reg(dirs, write_submission_dir(dirs["src"], "x001", variant=7))
    again = write_submission_dir(dirs["src"], "x002", variant=7)
    with pytest.raises(RegistrationError, match="already registered as run 'x001'"):
        reg(dirs, again)
    assert not (dirs["runs"] / "x002").exists()


def test_exactly_one_capture_file_is_required(dirs: dict[str, Path]) -> None:
    src = write_submission_dir(dirs["src"])
    (src / "capture.pcapng").write_bytes(empty_pcap_bytes(3))
    with pytest.raises(RegistrationError, match="exactly one of"):
        reg(dirs, src)
    (src / "capture.pcap").unlink()
    (src / "capture.pcapng").unlink()
    with pytest.raises(RegistrationError, match="exactly one of"):
        reg(dirs, src)


def test_cli_exit_codes(dirs: dict[str, Path], capsys: pytest.CaptureFixture[str]) -> None:
    src = write_submission_dir(dirs["src"])
    argv = [
        "--runs-dir", str(dirs["runs"]),
        "--data-dir", str(dirs["data"]),
        "--config-dir", str(dirs["config"]),
    ]  # fmt: skip
    assert main([str(src), *argv]) == 0
    assert "UNVERIFIED" in capsys.readouterr().out
    assert main([str(src), *argv]) == 1  # duplicate
    assert "REJECTED" in capsys.readouterr().err


# ---------------------------------------------------------------- verification


def make_analysis(
    base: Path,
    meta_sha: str,
    *,
    conns: list[tuple[float, str, str]],
    first: float | None = None,
    last: float | None = None,
    status: str = "completed",
    sha: str | None = None,
) -> Path:
    d = base / "analysis"
    (d / "tables").mkdir(parents=True)
    pd.DataFrame(
        {
            "ts": pd.to_datetime([T0.timestamp() + s for s, _, _ in conns], unit="s", utc=True),
            "orig_h": [o for _, o, _ in conns],
            "resp_h": [r for _, _, r in conns],
        }
    ).to_parquet(d / "tables" / "conn.parquet")
    (d / "profile.json").write_text(
        json.dumps(
            {
                "file": {"sha256": sha or meta_sha},
                "capture": {
                    "first_ts": first if first is not None else T0.timestamp(),
                    "last_ts": last if last is not None else T0.timestamp() + 600,
                },
                "zeek_version": "synthetic",
            }
        )
    )
    (d / "status.json").write_text(json.dumps({"status": status}))
    return d


@pytest.fixture
def staged(dirs: dict[str, Path]) -> tuple[Path, str]:
    meta = reg(dirs, write_submission_dir(dirs["src"]))
    return dirs["runs"] / "x001", meta.capture_sha256


GOOD_CONNS = [(90.0, CLIENT_IP, TARGET_IP)]  # inside the labelled 60-120 s window


def test_consistent_analysis_passes_and_makes_the_run_eligible(
    staged: tuple[Path, str], tmp_path: Path
) -> None:
    run_dir, sha = staged
    analysis = make_analysis(tmp_path, sha, conns=GOOD_CONNS)
    labels_before = (run_dir / "labels.jsonl").read_bytes()
    result = verify_run.verify_run(run_dir, analysis)
    assert result.passed and result.problems == ()
    assert (run_dir / "labels.jsonl").read_bytes() == labels_before  # never edits labels
    assert verify_run.main(["x001", str(analysis), "--runs-dir", str(run_dir.parent)]) == 0
    record = load_verification(run_dir)
    assert record is not None and record.passed and record.capture_sha256 == sha
    assert eligibility(run_dir, load_run(run_dir / "run.json")) == (True, "verified")


def test_labels_not_supported_by_the_capture_fail_verification(
    staged: tuple[Path, str], tmp_path: Path
) -> None:
    run_dir, sha = staged
    wrong_time = make_analysis(tmp_path, sha, conns=[(500.0, CLIENT_IP, TARGET_IP)])
    assert not verify_run.verify_run(run_dir, wrong_time).passed
    no_actor = make_analysis(tmp_path / "b", sha, conns=[(90.0, "172.20.0.55", TARGET_IP)])
    problems = verify_run.verify_run(run_dir, no_actor).problems
    assert any("actor does not appear" in p for p in problems)


def test_analysis_of_a_different_capture_fails_verification(
    staged: tuple[Path, str], tmp_path: Path
) -> None:
    run_dir, sha = staged
    other = make_analysis(tmp_path, sha, conns=GOOD_CONNS, sha="cd" * 32)
    result = verify_run.verify_run(run_dir, other)
    assert not result.passed
    assert any("different capture" in p for p in result.problems)


def test_incomplete_analysis_fails_verification(staged: tuple[Path, str], tmp_path: Path) -> None:
    run_dir, sha = staged
    failed = make_analysis(tmp_path, sha, conns=GOOD_CONNS, status="failed")
    assert any("did not complete" in p for p in verify_run.verify_run(run_dir, failed).problems)


def test_failed_verification_leaves_the_run_ineligible(
    staged: tuple[Path, str], tmp_path: Path
) -> None:
    run_dir, sha = staged
    analysis = make_analysis(tmp_path, sha, conns=[(500.0, CLIENT_IP, TARGET_IP)])
    assert verify_run.main(["x001", str(analysis), "--runs-dir", str(run_dir.parent)]) == 1
    eligible, reason = eligibility(run_dir, load_run(run_dir / "run.json"))
    assert not eligible and reason.startswith("verification failed")


@pytest.mark.parametrize("target", ["labels.jsonl", "run.json"])
def test_editing_labels_or_metadata_after_verification_revokes_eligibility(
    staged: tuple[Path, str], tmp_path: Path, target: str
) -> None:
    run_dir, sha = staged
    verify_run.main(
        [
            "x001",
            str(make_analysis(tmp_path, sha, conns=GOOD_CONNS)),
            "--runs-dir",
            str(run_dir.parent),
        ]
    )
    assert eligibility(run_dir, load_run(run_dir / "run.json"))[0]
    path = run_dir / target
    path.write_text(path.read_text() + " ")  # any byte change counts
    eligible, reason = eligibility(run_dir, load_run(run_dir / "run.json"))
    assert not eligible and f"{target} changed after verification" in reason


def test_forged_verification_with_wrong_hashes_is_not_accepted(
    staged: tuple[Path, str], tmp_path: Path
) -> None:
    run_dir, sha = staged
    verify_run.main(
        [
            "x001",
            str(make_analysis(tmp_path, sha, conns=GOOD_CONNS)),
            "--runs-dir",
            str(run_dir.parent),
        ]
    )
    record = json.loads((run_dir / FILE_NAME).read_text())
    record["labels_sha256"] = "00" * 32
    (run_dir / FILE_NAME).write_text(json.dumps(record))
    assert not eligibility(run_dir, load_run(run_dir / "run.json"))[0]
    (run_dir / FILE_NAME).write_text("not json")
    assert load_verification(run_dir) is None
    assert not eligibility(run_dir, load_run(run_dir / "run.json"))[0]


def test_verify_cli_reports_unreadable_input(staged: tuple[Path, str], tmp_path: Path) -> None:
    run_dir, _ = staged
    assert (
        verify_run.main(["x001", str(tmp_path / "missing"), "--runs-dir", str(run_dir.parent)]) == 2
    )
