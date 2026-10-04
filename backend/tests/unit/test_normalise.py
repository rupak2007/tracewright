from pathlib import Path

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from app.ingest.normalise import normalise_logs
from app.ingest.schema import TABLES
from tests.helpers import conn_row, write_zeek_logs


def _run(tmp_path: Path, logs: dict[str, list[object]]):  # type: ignore[no-untyped-def]
    zeek, tables = tmp_path / "zeek", tmp_path / "tables"
    write_zeek_logs(zeek, logs)
    return normalise_logs(zeek, tables), tables


def test_all_eight_tables_written_even_when_logs_are_absent(tmp_path: Path) -> None:
    (tables, stats), out = _run(tmp_path, {})
    assert sorted(p.stem for p in out.glob("*.parquet")) == sorted(TABLES)
    assert all(len(getattr(tables, name)) == 0 for name in TABLES)
    assert stats.lines_total == 0 and stats.skipped_share == 0.0


def test_empty_tables_keep_their_declared_schema(tmp_path: Path) -> None:
    _, out = _run(tmp_path, {})
    schema = pq.read_schema(out / "dns.parquet")
    answers = schema.field("answers").type
    assert pa.types.is_list(answers) and pa.types.is_string(answers.value_type)
    assert str(schema.field("ts").type) == "timestamp[us, tz=UTC]"


def test_conn_row_types_and_values(tmp_path: Path) -> None:
    (tables, stats), _ = _run(tmp_path, {"conn": [conn_row(1700000000.25)]})
    row = tables.conn.iloc[0]
    assert row["orig_h"] == "10.0.0.5" and row["resp_p"] == 80
    assert row["ts"] == pd.Timestamp("2023-11-14T22:13:20.250", tz="UTC")
    assert str(tables.conn["orig_bytes"].dtype) == "Int64"
    assert str(tables.conn["duration"].dtype) == "Float64"
    assert stats.rows["conn"] == 1 and stats.bad_values == 0


def test_missing_fields_are_null_not_zero(tmp_path: Path) -> None:
    sparse = {"ts": 1.0, "uid": "C1", "id.orig_h": "1.1.1.1", "proto": "tcp"}
    (tables, _), _ = _run(tmp_path, {"conn": [sparse]})
    row = tables.conn.iloc[0]
    assert pd.isna(row["orig_bytes"]) and pd.isna(row["duration"]) and pd.isna(row["service"])


def test_rows_sorted_by_timestamp(tmp_path: Path) -> None:
    (tables, _), _ = _run(tmp_path, {"conn": [conn_row(30.0), conn_row(10.0), conn_row(20.0)]})
    assert tables.conn["ts"].is_monotonic_increasing


def test_malformed_lines_are_skipped_and_counted(tmp_path: Path) -> None:
    lines: list[object] = [
        conn_row(1.0),
        "{not json",
        "[1, 2, 3]",
        "",
        '{"uid": "no-ts"}',
        '{"ts": NaN, "uid": "x"}',
        '{"ts": "yesterday", "uid": "x"}',
        conn_row(2.0),
    ]
    (tables, stats), _ = _run(tmp_path, {"conn": lines})
    assert len(tables.conn) == 2
    assert stats.lines_total == 8 and stats.lines_skipped == 6
    assert stats.skipped_share == pytest.approx(0.75)


def test_bad_values_become_null_and_are_counted(tmp_path: Path) -> None:
    row = conn_row(1.0, orig_bytes="lots", duration=float("inf"), orig_pkts=True)
    row["id.resp_p"] = 2**70
    (tables, stats), _ = _run(tmp_path, {"conn": [row]})
    out = tables.conn.iloc[0]
    assert pd.isna(out["orig_bytes"]) and pd.isna(out["duration"])
    assert pd.isna(out["orig_pkts"]) and pd.isna(out["resp_p"])
    assert out["resp_pkts"] == 5
    assert stats.bad_values == 4


def test_invalid_utf8_line_skipped(tmp_path: Path) -> None:
    zeek = tmp_path / "zeek"
    zeek.mkdir()
    (zeek / "conn.log").write_bytes(b'{"ts": 1.0, "uid": "\xff\xfe"}\n')
    tables, stats = normalise_logs(zeek, tmp_path / "tables")
    assert len(tables.conn) == 0 and stats.lines_skipped == 1


def test_list_bool_and_string_fields(tmp_path: Path) -> None:
    dns = {
        "ts": 5.0,
        "uid": "C1",
        "id.orig_h": "10.0.0.5",
        "query": "<script>alert(1)</script>.evil.example",
        "rcode_name": "NXDOMAIN",
        "answers": ["1.2.3.4", "5.6.7.8"],
        "rejected": False,
    }
    (tables, _), _ = _run(tmp_path, {"dns": [dns]})
    row = tables.dns.iloc[0]
    assert list(row["answers"]) == ["1.2.3.4", "5.6.7.8"]
    assert bool(row["rejected"]) is False
    # capture-derived strings are stored verbatim; escaping is a rendering concern
    assert row["query"] == "<script>alert(1)</script>.evil.example"


def test_x509_flattened_names(tmp_path: Path) -> None:
    cert = {
        "ts": 1.0,
        "fingerprint": "ab",
        "certificate.subject": "CN=example",
        "certificate.not_valid_before": 1600000000.0,
        "certificate.key_length": 2048,
        "basic_constraints.ca": False,
    }
    (tables, _), _ = _run(tmp_path, {"x509": [cert]})
    row = tables.x509.iloc[0]
    assert row["certificate_subject"] == "CN=example" and row["certificate_key_length"] == 2048
    assert row["certificate_not_valid_before"] == pd.Timestamp("2020-09-13T12:26:40", tz="UTC")
    assert bool(row["basic_constraints_ca"]) is False


def test_password_fields_are_never_persisted(tmp_path: Path) -> None:
    ftp = {"ts": 1.0, "uid": "C1", "user": "bob", "password": "hunter2", "reply_code": 530}
    http = {"ts": 1.0, "uid": "C2", "username": "bob", "password": "hunter2", "uri": "/"}
    (tables, _), out = _run(tmp_path, {"ftp": [ftp], "http": [http]})
    for name in TABLES:
        columns = set(pq.read_schema(out / f"{name}.parquet").names)
        assert not {"password", "username"} & columns
    assert "hunter2" not in "".join(p.read_bytes().decode("latin1") for p in out.glob("*.parquet"))
    assert tables.ftp.iloc[0]["reply_code"] == 530
