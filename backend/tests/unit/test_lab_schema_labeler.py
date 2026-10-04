import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("lab")  # lab/ is not copied into the worker test image

from lab.labeler import Labeler, merge_label_files, read_labels
from lab.schema import (
    ATTACK_CLASSES,
    CLASSES_BY_KIND,
    format_time,
    parse_episode,
    parse_time,
)

T0 = datetime(2026, 11, 2, 10, 4, 11, tzinfo=UTC)


def raw(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "run_id": "r001",
        "episode_id": "r001-e1",
        "kind": "hard_negative",
        "class": "NTP",
        "actor": "172.20.0.101",
        "targets": ["172.20.0.20"],
        "start": "2026-11-02T10:04:11.000Z",
        "end": "2026-11-02T10:06:40.500Z",
    }
    base.update(overrides)
    return base


def test_round_trip_preserves_every_field() -> None:
    episode = parse_episode(raw(tool="x", params={"a": 1}))
    again = parse_episode(episode.to_json_dict())
    assert again == episode
    assert again.to_json_dict()["class"] == "NTP" and "cls" not in again.to_json_dict()
    assert again.end - again.start == timedelta(seconds=149.5)


def test_every_registered_kind_class_pair_is_accepted_and_cross_kinds_rejected() -> None:
    for kind, classes in CLASSES_BY_KIND.items():
        for cls in classes:
            assert parse_episode(raw(kind=kind, **{"class": cls})).cls == cls
    with pytest.raises(ValueError, match="not valid for kind"):
        parse_episode(raw(kind="hard_negative", **{"class": ATTACK_CLASSES[0]}))
    with pytest.raises(ValueError, match="not valid for kind"):
        parse_episode(raw(kind="attack", **{"class": "NTP"}))


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"kind": "mystery"}, "unknown kind"),
        ({"actor": "not-an-ip"}, "does not appear to be"),
        ({"targets": []}, "at least one target"),
        ({"targets": ["300.1.1.1"]}, "does not appear to be"),
        ({"targets": "172.20.0.20"}, "list of IP"),
        ({"episode_id": "other-e1"}, "episode_id must start"),
        ({"start": "2026-11-02T10:04:11"}, "ending in 'Z'"),
        ({"end": "2026-11-02T10:00:00.000Z"}, "end is before start"),
        ({"params": []}, "params must be an object"),
        ({"schema_version": 99}, "unsupported schema_version"),
        ({"surprise": 1}, "unknown fields"),
    ],
)
def test_invalid_labels_rejected(overrides: dict[str, Any], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        parse_episode(raw(**overrides))


def test_missing_fields_named() -> None:
    bad = raw()
    del bad["actor"]
    with pytest.raises(ValueError, match="missing fields"):
        parse_episode(bad)
    with pytest.raises(ValueError, match="JSON object"):
        parse_episode([])  # type: ignore[arg-type]


def test_time_helpers() -> None:
    assert format_time(T0) == "2026-11-02T10:04:11.000Z"
    assert parse_time("2026-11-02T10:04:11.250Z") == T0 + timedelta(milliseconds=250)
    with pytest.raises(ValueError, match="naive"):
        format_time(datetime(2026, 1, 1))


def _clock(*moments: datetime):  # type: ignore[no-untyped-def]
    values = iter(moments)
    return lambda: next(values)


def test_labeler_records_start_and_end_from_the_clock(tmp_path: Path) -> None:
    labeler = Labeler(
        tmp_path / "r001" / "labels.jsonl", "r001", _clock(T0, T0 + timedelta(seconds=30))
    )
    with labeler.episode("hard_negative", "NTP", "172.20.0.101", ["172.20.0.20"], "gen", {"n": 1}):
        pass
    [episode] = read_labels(labeler.path)
    assert (episode.start, episode.end) == (T0, T0 + timedelta(seconds=30))
    assert episode.episode_id == "r001-e1" and episode.params == {"n": 1} and episode.tool == "gen"


def test_failed_episode_is_not_recorded(tmp_path: Path) -> None:
    labeler = Labeler(tmp_path / "labels.jsonl", "r001", _clock(T0, T0))
    with (
        pytest.raises(RuntimeError),
        labeler.episode("hard_negative", "NTP", "172.20.0.101", ["172.20.0.20"]),
    ):
        raise RuntimeError("scenario crashed")
    assert not labeler.path.exists() or labeler.path.read_text() == ""


def test_invalid_episode_is_rejected_at_write_time(tmp_path: Path) -> None:
    labeler = Labeler(tmp_path / "labels.jsonl", "r001", _clock(T0, T0))
    with (
        pytest.raises(ValueError, match="not valid for kind"),
        labeler.episode("hard_negative", "SCAN", "172.20.0.101", ["172.20.0.20"]),
    ):
        pass
    assert not labeler.path.exists()


def test_per_process_files_merge_into_one_validated_ordered_file(tmp_path: Path) -> None:
    parts = []
    for number, octet in enumerate((101, 102, 103)):
        path = tmp_path / f"labels.part{number}.jsonl"
        labeler = Labeler(path, "r001", id_prefix=f"p{number}-")
        for _ in range(3):
            with labeler.episode("hard_negative", "NTP", f"172.20.0.{octet}", ["172.20.0.20"]):
                pass
        parts.append(path)
    merged = merge_label_files(parts, tmp_path / "labels.jsonl")
    assert len(merged) == 9 and len({e.episode_id for e in merged}) == 9
    assert [e.start for e in merged] == sorted(e.start for e in merged)
    assert read_labels(tmp_path / "labels.jsonl") == merged


def test_merge_refuses_duplicate_ids_and_existing_destination(tmp_path: Path) -> None:
    a, b = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
    for path in (a, b):  # same prefix in both files -> colliding ids
        with Labeler(path, "r001", id_prefix="x-").episode(
            "hard_negative", "NTP", "172.20.0.101", ["172.20.0.20"]
        ):
            pass
    with pytest.raises(ValueError, match="duplicate episode ids"):
        merge_label_files([a, b], tmp_path / "labels.jsonl")
    assert not (tmp_path / "labels.jsonl").exists()
    (tmp_path / "labels.jsonl").write_text("")
    with pytest.raises(FileExistsError):
        merge_label_files([a], tmp_path / "labels.jsonl")


def test_read_labels_reports_the_bad_line(tmp_path: Path) -> None:
    path = tmp_path / "labels.jsonl"
    path.write_text(json.dumps(raw()) + "\n\n" + json.dumps(raw(kind="nope")) + "\n")
    with pytest.raises(ValueError, match=r"labels.jsonl line 3"):
        read_labels(path)
