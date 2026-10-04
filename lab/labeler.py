"""Append-only writer for `labels.jsonl`. Standard library only (runs inside lab containers).

Every scenario wraps its traffic in `with labeler.episode(...)`: the start/end are taken from the
clock when the block is entered and left, so the label cannot disagree with when traffic was sent.
"""

import json
import os
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from lab.schema import Episode, parse_episode


def _utc_now() -> datetime:
    return datetime.now(UTC)


class Labeler:
    def __init__(
        self,
        path: Path,
        run_id: str,
        clock: Callable[[], datetime] = _utc_now,
        id_prefix: str = "",
    ) -> None:
        self.path = path
        self.run_id = run_id
        self._clock = clock
        self._counter = 0
        self._id_prefix = id_prefix  # keeps ids unique when several clients share one labels file
        path.parent.mkdir(parents=True, exist_ok=True)

    def _next_id(self) -> str:
        self._counter += 1
        return f"{self.run_id}-{self._id_prefix}e{self._counter}"

    @contextmanager
    def episode(
        self,
        kind: str,
        cls: str,
        actor: str,
        targets: list[str],
        tool: str = "",
        params: dict[str, Any] | None = None,
    ) -> Iterator[None]:
        """Label the traffic generated inside the block. The record is written on a clean exit
        only: an episode that raised did not complete and must not enter the ground truth."""
        start = self._clock()
        episode_id = self._next_id()
        yield None
        end = self._clock()
        episode = Episode(
            run_id=self.run_id,
            episode_id=episode_id,
            kind=kind,
            cls=cls,
            actor=actor,
            targets=tuple(targets),
            start=start,
            end=end,
            tool=tool,
            params=params or {},
        )
        self.append(episode)

    def append(self, episode: Episode) -> None:
        line = json.dumps(episode.to_json_dict(), sort_keys=True) + "\n"
        # One writer per file (see merge_label_files); O_APPEND keeps one process's writes whole.
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
        try:
            os.write(fd, line.encode("utf-8"))
        finally:
            os.close(fd)


def read_labels(path: Path) -> list[Episode]:
    """Read and validate a labels file; raises ValueError naming the offending line."""
    episodes: list[Episode] = []
    with path.open(encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                episodes.append(parse_episode(json.loads(line)))
            except ValueError as exc:
                raise ValueError(f"{path.name} line {number}: {exc}") from exc
    return episodes


def merge_label_files(parts: list[Path], destination: Path) -> list[Episode]:
    """Combine per-process label files into one `labels.jsonl`, validating every record.

    Each generator process writes its own file (several containers appending to one file on a
    bind mount is not reliably atomic), so merging is the only step that touches the final file.
    Refuses duplicate episode ids and an existing destination; output is ordered by start time.
    """
    if destination.exists():
        raise FileExistsError(f"{destination} already exists; labels are never overwritten")
    episodes = [e for part in parts for e in read_labels(part)]
    ids = [e.episode_id for e in episodes]
    duplicates = sorted({i for i in ids if ids.count(i) > 1})
    if duplicates:
        raise ValueError(f"duplicate episode ids across label files: {duplicates}")
    episodes.sort(key=lambda e: (e.start, e.episode_id))
    lines = [json.dumps(e.to_json_dict(), sort_keys=True) + "\n" for e in episodes]
    destination.write_text("".join(lines), encoding="utf-8")
    return episodes
