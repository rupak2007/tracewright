"""Zeek JSON logs -> typed Parquet tables (stage S2).

Every string in these logs is attacker-controlled data: it is parsed with json only (never eval'd),
stored verbatim, and must be escaped at render time. Malformed lines are skipped and counted, not
fatal (architecture §21).
"""

import json
import logging
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pandas as pd
import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.parquet as pq

from app.ingest.schema import ARROW_TYPES, TABLES, Column, Kind, arrow_schema

logger = logging.getLogger(__name__)

_MAX_LINE_BYTES = 4 * 1024 * 1024
_INT64_MIN, _INT64_MAX = -(2**63), 2**63 - 1
_MAX_EPOCH = 253_402_300_799.0  # 9999-12-31; rejects absurd timestamps


@dataclass
class NormaliseStats:
    lines_total: int = 0
    lines_skipped: int = 0
    bad_values: int = 0
    rows: dict[str, int] = field(default_factory=dict)

    @property
    def skipped_share(self) -> float:
        return self.lines_skipped / self.lines_total if self.lines_total else 0.0


@dataclass(frozen=True)
class CaptureTables:
    """The eight normalised tables, as DataFrames read back from the persisted Parquet."""

    conn: pd.DataFrame
    dns: pd.DataFrame
    http: pd.DataFrame
    ssl: pd.DataFrame
    x509: pd.DataFrame
    ssh: pd.DataFrame
    ftp: pd.DataFrame
    weird: pd.DataFrame


def _convert(value: Any, kind: Kind) -> tuple[Any, bool]:
    """Return (converted value or None, ok). A missing value is not an error."""
    if value is None:
        return None, True
    if kind is Kind.TIME:
        if isinstance(value, bool) or not isinstance(value, int | float):
            return None, False
        if not math.isfinite(value) or not (0 <= value <= _MAX_EPOCH):
            return None, False
        return round(value * 1_000_000), True  # epoch microseconds
    if kind is Kind.STR:
        return (value, True) if isinstance(value, str) else (None, False)
    if kind is Kind.INT:
        if isinstance(value, bool) or not isinstance(value, int):
            return None, False
        return (value, True) if _INT64_MIN <= value <= _INT64_MAX else (None, False)
    if kind is Kind.FLOAT:
        if isinstance(value, bool) or not isinstance(value, int | float):
            return None, False
        return (float(value), True) if math.isfinite(value) else (None, False)
    if kind is Kind.BOOL:
        return (value, True) if isinstance(value, bool) else (None, False)
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        return value, True
    return None, False


def _arrow_array(values: list[Any], column: Column) -> pa.Array:
    if column.kind is Kind.TIME:
        return pa.array(values, type=pa.int64()).cast(ARROW_TYPES[Kind.TIME])
    return pa.array(values, type=ARROW_TYPES[column.kind])


def _normalise_log(name: str, log_path: Path, stats: NormaliseStats) -> pa.Table:
    columns = TABLES[name]
    data: dict[str, list[Any]] = {c.name: [] for c in columns}
    if log_path.is_file():
        with log_path.open("rb") as handle:
            for raw in handle:
                stats.lines_total += 1
                if len(raw) > _MAX_LINE_BYTES or not raw.strip():
                    stats.lines_skipped += 1
                    continue
                try:
                    record = json.loads(raw)
                except (ValueError, RecursionError):
                    stats.lines_skipped += 1
                    continue
                if not isinstance(record, dict):
                    stats.lines_skipped += 1
                    continue
                row: dict[str, Any] = {}
                bad = 0
                for column in columns:
                    converted, ok = _convert(record.get(column.zeek), column.kind)
                    row[column.name] = converted
                    bad += 0 if ok else 1
                if row["ts"] is None:  # ts is required; a row without one is unusable
                    stats.lines_skipped += 1
                    continue
                stats.bad_values += bad
                for column_name, value in row.items():
                    data[column_name].append(value)
    table = pa.table(
        {c.name: _arrow_array(data[c.name], c) for c in columns}, schema=arrow_schema(name)
    )
    stats.rows[name] = table.num_rows
    return table.take(pc.sort_indices(table, sort_keys=[("ts", "ascending")]))


def normalise_logs(zeek_dir: Path, tables_dir: Path) -> tuple[CaptureTables, NormaliseStats]:
    """Write one Parquet file per table (empty ones included) and read them back typed."""
    tables_dir.mkdir(parents=True, exist_ok=True)
    stats = NormaliseStats()
    for name in TABLES:
        table = _normalise_log(name, zeek_dir / f"{name}.log", stats)
        pq.write_table(table, tables_dir / f"{name}.parquet")
    logger.info("normalised zeek logs: %s", stats.rows)
    return read_tables(tables_dir), stats


def read_tables(tables_dir: Path) -> CaptureTables:
    frames = {
        name: pd.read_parquet(tables_dir / f"{name}.parquet", dtype_backend="numpy_nullable")
        for name in TABLES
    }
    return CaptureTables(**frames)
