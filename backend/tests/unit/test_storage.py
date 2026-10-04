import io
import re
from pathlib import Path

import pytest

from app.core.errors import IngestError
from app.ingest.storage import sanitise_original_name, store_upload
from app.ingest.validate import CaptureFormat

PCAP = bytes.fromhex("d4c3b2a1") + b"\x00" * 40
PCAPNG = bytes.fromhex("0a0d0d0a") + b"\x00" * 40
UUID_NAME = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")


def test_stored_under_server_generated_uuid(tmp_path: Path) -> None:
    stored = store_upload(io.BytesIO(PCAP), tmp_path, 1000, original_name="../../etc/passwd.pcap")
    assert stored.path.parent == tmp_path
    assert UUID_NAME.match(stored.path.stem)
    assert stored.path.suffix == ".pcap"
    assert stored.path.read_bytes() == PCAP
    assert stored.original_name == "passwd.pcap"
    assert sorted(p.name for p in tmp_path.iterdir()) == [stored.path.name]


def test_extension_follows_detected_format(tmp_path: Path) -> None:
    stored = store_upload(io.BytesIO(PCAPNG), tmp_path, 1000, original_name="x.pcap")
    assert stored.info.format is CaptureFormat.PCAPNG
    assert stored.path.suffix == ".pcapng"


@pytest.mark.parametrize(
    ("data", "code"),
    [
        (b"not a pcap at all, definitely", "FILE_TYPE_INVALID"),
        (PCAP + b"\x00" * 2000, "FILE_TOO_LARGE"),
    ],
)
def test_rejected_upload_leaves_nothing_behind(tmp_path: Path, data: bytes, code: str) -> None:
    with pytest.raises(IngestError) as exc:
        store_upload(io.BytesIO(data), tmp_path, 1000)
    assert exc.value.code == code
    assert list(tmp_path.iterdir()) == []


def test_insufficient_disk_rejected_before_writing(tmp_path: Path) -> None:
    with pytest.raises(IngestError) as exc:
        store_upload(io.BytesIO(PCAP), tmp_path, 1000, min_free_bytes=2**62)
    assert exc.value.code == "INSUFFICIENT_DISK"
    assert list(tmp_path.iterdir()) == []


def test_two_uploads_never_collide(tmp_path: Path) -> None:
    a = store_upload(io.BytesIO(PCAP), tmp_path, 1000)
    b = store_upload(io.BytesIO(PCAP), tmp_path, 1000)
    assert a.path != b.path and a.capture_id != b.capture_id


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (None, ""),
        ("", ""),
        ("..\\..\\windows\\evil.pcap", "evil.pcap"),
        ("a/b/../../c.pcap", "c.pcap"),
        ("bad\x00name\n\x1b[31m.pcap", "badname[31m.pcap"),
        ("x" * 1000, "x" * 255),
    ],
)
def test_sanitise_original_name(raw: str | None, expected: str) -> None:
    assert sanitise_original_name(raw) == expected
