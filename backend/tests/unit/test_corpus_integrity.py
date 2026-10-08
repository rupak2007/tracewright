"""The recorded corpus must verify on every checkout, whatever the platform's line endings.

Regression for a release-audit finding: the committed split manifest and verification records were
hashed from CRLF working copies while git stores these files with LF, so a fresh Linux checkout
disagreed with every recorded hash (all six runs "changed after assignment") and CI's corpus step
would have failed.
"""

import hashlib
import subprocess
from pathlib import Path

import pytest

pytest.importorskip("eval")
pytest.importorskip("lab")

from eval import splits
from lab.verification import text_sha256

REPO = Path(__file__).resolve().parents[3]


def test_run_record_hashes_do_not_depend_on_line_endings(tmp_path: Path) -> None:
    lf, crlf, mixed, changed = (tmp_path / n for n in ("lf", "crlf", "mixed", "changed"))
    lf.write_bytes(b'{"a": 1}\n{"b": 2}\n')
    crlf.write_bytes(b'{"a": 1}\r\n{"b": 2}\r\n')
    mixed.write_bytes(b'{"a": 1}\r\n{"b": 2}\n')
    changed.write_bytes(b'{"a": 1}\n{"b": 3}\n')
    assert text_sha256(lf) == text_sha256(crlf) == text_sha256(mixed)
    assert text_sha256(changed) != text_sha256(lf)  # a real edit is still detected
    assert text_sha256(tmp_path / "missing") == ""
    # the canonical form is CRLF, which is what the committed manifest recorded
    assert text_sha256(lf) == hashlib.sha256(b'{"a": 1}\r\n{"b": 2}\r\n').hexdigest()


def test_the_committed_corpus_validates_on_this_checkout() -> None:
    manifest_path = REPO / "eval" / "splits.yaml"
    if not manifest_path.exists() or not (REPO / "lab" / "runs").is_dir():
        pytest.skip("repository corpus files not available")
    runs = splits.load_runs(REPO / "lab" / "runs")
    manifest = splits.load_manifest(manifest_path)
    assert runs and set(manifest["assigned"]) <= set(runs)
    assert all(run.eligible for run in runs.values()), {
        r: v.eligibility_reason for r, v in runs.items() if not v.eligible
    }
    for run_id, entry in manifest["assigned"].items():
        assert entry["run_json_sha256"] == runs[run_id].run_json_sha256, run_id
        assert entry["labels_sha256"] == runs[run_id].labels_sha256, run_id


def test_the_recorded_hashes_match_the_blobs_git_stores() -> None:
    """What CI sees: the LF blobs in git, not this machine's working copy."""
    if not (REPO / ".git").exists():
        pytest.skip("not a git checkout")
    manifest = splits.load_manifest(REPO / "eval" / "splits.yaml")
    for run_id, entry in manifest["assigned"].items():
        for name, key in (("run.json", "run_json_sha256"), ("labels.jsonl", "labels_sha256")):
            blob = subprocess.run(  # noqa: S603
                ["git", "show", f"HEAD:lab/runs/{run_id}/{name}"],  # noqa: S607
                capture_output=True,
                cwd=REPO,
                check=False,
                shell=False,
            )
            if blob.returncode != 0:
                pytest.skip("run files are not committed in this checkout")
            canonical = blob.stdout.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
            assert hashlib.sha256(canonical).hexdigest() == entry[key], (run_id, name)
