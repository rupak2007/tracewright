"""SEC-01/02, NFR-03: malformed captures fail cleanly at every layer (plan P9).

Layer 1 (always): the validation gate either accepts a file or raises a documented IngestError.
Layer 2 (always): the upload endpoint answers 202 or a documented 4xx, never 5xx, and leaves
nothing behind for a rejected file. Layer 3 (inside the worker image, real Zeek): every file that
passes validation ends the analysis as `completed` or `failed` with a code, never as an exception
or a hang.
"""

import shutil
from pathlib import Path

import pytest

from app.core.config import PipelineSettings
from app.core.errors import IngestError
from app.ingest.validate import validate_file
from app.worker.pipeline import analyze_capture
from tests.security.mutate import corpus
from tests.unit.test_api import make_world, post_file

DOCUMENTED_CODES = {
    "FILE_EMPTY",
    "FILE_TOO_SHORT",
    "FILE_TYPE_INVALID",
    "FILE_COMPRESSED",
    "FILE_TOO_LARGE",
}


@pytest.fixture(scope="module")
def mutants(tmp_path_factory: pytest.TempPathFactory) -> list[tuple[str, bytes]]:
    from tests.fixtures import make_fixtures as mk

    source = mk.make_basic_pcap(tmp_path_factory.mktemp("seed") / "basic.pcap")
    return corpus(Path(source).read_bytes())


def test_the_corpus_is_large_deterministic_and_varied(mutants: list[tuple[str, bytes]]) -> None:
    assert len(mutants) >= 50
    assert len({name for name, _ in mutants}) == len(mutants)
    assert len({data for _, data in mutants}) > len(mutants) * 0.9  # almost all distinct
    assert any(not data for _, data in mutants)  # a zero-length file is in there


def test_validation_accepts_or_raises_a_documented_ingest_error(
    mutants: list[tuple[str, bytes]], tmp_path: Path
) -> None:
    accepted = rejected = 0
    for name, data in mutants:
        path = tmp_path / "capture.bin"
        path.write_bytes(data)
        try:
            validate_file(path, 10_000_000)
            accepted += 1
        except IngestError as exc:
            rejected += 1
            assert exc.code in DOCUMENTED_CODES, (name, exc.code)
    assert accepted > 0 and rejected > 0  # both outcomes are exercised


def test_the_upload_endpoint_never_answers_5xx_and_cleans_up_rejections(
    mutants: list[tuple[str, bytes]], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for world in make_world(tmp_path, monkeypatch):
        accepted = 0
        for name, data in mutants:
            before = {p.name for p in world.uploads.iterdir()}
            response = post_file(world, data, name=f"{name}.pcap")
            assert response.status_code < 500, (name, response.status_code)
            if response.status_code == 202:
                accepted += 1
                stored = [p for p in world.uploads.iterdir() if p.stem == response.json()["id"]]
                assert len(stored) == 1 and stored[0].read_bytes() == data, name
            else:
                assert response.json()["error"]["code"] in DOCUMENTED_CODES, name
                assert {p.name for p in world.uploads.iterdir()} == before, name
        names = [p.name for p in world.uploads.iterdir()]
        assert len(names) == accepted + 1  # the accepted uploads plus the seeded one
        assert not [n for n in names if n.endswith(".part")]  # no half-written leftovers


@pytest.mark.skipif(shutil.which("zeek") is None, reason="real Zeek only inside the worker image")
@pytest.mark.requires_zeek
def test_real_zeek_ends_every_valid_looking_mutant_as_completed_or_failed(
    mutants: list[tuple[str, bytes]], tmp_path: Path, config_dir: Path
) -> None:
    settings = PipelineSettings(config_dir=config_dir, zeek_timeout_s=60)
    outcomes: dict[str, int] = {"completed": 0, "failed": 0}
    for n, (name, data) in enumerate(mutants):
        path = tmp_path / f"m{n}.pcap"
        path.write_bytes(data)
        try:
            validate_file(path, settings.max_upload_bytes)
        except IngestError:
            continue  # stopped at the gate, covered above
        status = analyze_capture(path, tmp_path / f"out{n}", settings)
        assert status.status in ("completed", "failed"), name
        if status.status == "failed":
            assert status.error_code and status.error_message, name
            assert status.error_code != "INTERNAL_ERROR", (name, status.error_message)
        outcomes[status.status] += 1
    print(
        f"real-zeek malformed corpus outcomes: {outcomes}, stopped at the gate: "
        f"{len(mutants) - sum(outcomes.values())}"
    )
    assert sum(outcomes.values()) > 10, outcomes
