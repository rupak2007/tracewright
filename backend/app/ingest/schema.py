"""Documented schema of each normalised Zeek table (architecture §5.4).

Column names follow Zeek field names with the `id.` prefix dropped (`id.orig_h` -> `orig_h`) and
other dots turned into underscores (`certificate.subject` -> `certificate_subject`). Field names
were checked against the Zeek 9.0.0 scripts. Timestamps are stored as UTC; durations as float
seconds; fields Zeek did not log are NULL (never zero). Password fields (ftp.password,
http.username/password) are deliberately not part of any schema (SEC-08, SEC-12).
"""

from dataclasses import dataclass
from enum import StrEnum

import pyarrow as pa


class Kind(StrEnum):
    TIME = "time"  # epoch seconds -> timestamp[us, UTC]
    STR = "str"
    INT = "int"
    FLOAT = "float"
    BOOL = "bool"
    STR_LIST = "str_list"


ARROW_TYPES: dict[Kind, pa.DataType] = {
    Kind.TIME: pa.timestamp("us", tz="UTC"),
    Kind.STR: pa.string(),
    Kind.INT: pa.int64(),
    Kind.FLOAT: pa.float64(),
    Kind.BOOL: pa.bool_(),
    Kind.STR_LIST: pa.list_(pa.string()),
}


@dataclass(frozen=True)
class Column:
    zeek: str
    name: str
    kind: Kind


def _c(zeek: str, kind: Kind, name: str | None = None) -> Column:
    return Column(zeek, name or zeek.replace(".", "_"), kind)


_CONN_ID = (
    _c("uid", Kind.STR),
    _c("id.orig_h", Kind.STR, "orig_h"),
    _c("id.orig_p", Kind.INT, "orig_p"),
    _c("id.resp_h", Kind.STR, "resp_h"),
    _c("id.resp_p", Kind.INT, "resp_p"),
)
_TS = _c("ts", Kind.TIME)

TABLES: dict[str, tuple[Column, ...]] = {
    "conn": (
        _TS,
        *_CONN_ID,
        _c("proto", Kind.STR),
        _c("service", Kind.STR),
        _c("duration", Kind.FLOAT),
        _c("orig_bytes", Kind.INT),
        _c("resp_bytes", Kind.INT),
        _c("conn_state", Kind.STR),
        _c("history", Kind.STR),
        _c("orig_pkts", Kind.INT),
        _c("resp_pkts", Kind.INT),
        _c("orig_ip_bytes", Kind.INT),
        _c("resp_ip_bytes", Kind.INT),
        _c("missed_bytes", Kind.INT),
    ),
    "dns": (
        _TS,
        *_CONN_ID,
        _c("proto", Kind.STR),
        _c("trans_id", Kind.INT),
        _c("rtt", Kind.FLOAT),
        _c("query", Kind.STR),
        _c("qtype_name", Kind.STR),
        _c("rcode_name", Kind.STR),
        _c("answers", Kind.STR_LIST),
        _c("rejected", Kind.BOOL),
    ),
    "http": (
        _TS,
        *_CONN_ID,
        _c("trans_depth", Kind.INT),
        _c("method", Kind.STR),
        _c("host", Kind.STR),
        _c("uri", Kind.STR),
        _c("user_agent", Kind.STR),
        _c("request_body_len", Kind.INT),
        _c("response_body_len", Kind.INT),
        _c("status_code", Kind.INT),
        _c("status_msg", Kind.STR),
    ),
    "ssl": (
        _TS,
        *_CONN_ID,
        _c("version", Kind.STR),
        _c("cipher", Kind.STR),
        _c("server_name", Kind.STR),
        _c("next_protocol", Kind.STR),
        _c("established", Kind.BOOL),
        _c("resumed", Kind.BOOL),
    ),
    "x509": (
        _TS,
        _c("fingerprint", Kind.STR),
        _c("certificate.version", Kind.INT),
        _c("certificate.serial", Kind.STR),
        _c("certificate.subject", Kind.STR),
        _c("certificate.issuer", Kind.STR),
        _c("certificate.not_valid_before", Kind.TIME),
        _c("certificate.not_valid_after", Kind.TIME),
        _c("certificate.key_alg", Kind.STR),
        _c("certificate.sig_alg", Kind.STR),
        _c("certificate.key_length", Kind.INT),
        _c("basic_constraints.ca", Kind.BOOL),
    ),
    "ssh": (
        _TS,
        *_CONN_ID,
        _c("version", Kind.INT),
        _c("auth_success", Kind.BOOL),
        _c("auth_attempts", Kind.INT),
        _c("direction", Kind.STR),
        _c("client", Kind.STR),
        _c("server", Kind.STR),
    ),
    "ftp": (
        _TS,
        *_CONN_ID,
        _c("user", Kind.STR),
        _c("command", Kind.STR),
        _c("arg", Kind.STR),
        _c("mime_type", Kind.STR),
        _c("file_size", Kind.INT),
        _c("reply_code", Kind.INT),
        _c("reply_msg", Kind.STR),
    ),
    "weird": (
        _TS,
        *_CONN_ID,
        _c("name", Kind.STR),
        _c("addl", Kind.STR),
        _c("notice", Kind.BOOL),
        _c("peer", Kind.STR),
    ),
}


def arrow_schema(table: str) -> pa.Schema:
    return pa.schema([(c.name, ARROW_TYPES[c.kind]) for c in TABLES[table]])
