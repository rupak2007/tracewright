import gzip
import hashlib
from pathlib import Path

import pytest

from app.core.errors import IngestError
from app.ingest.validate import CaptureFormat, CaptureValidator, validate_file

PCAP_BODY = b"\x00" * 40  # pads a magic number up to a plausible minimum size


def _write(tmp_path: Path, data: bytes, name: str = "f.bin") -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


@pytest.mark.parametrize(
    "magic",
    ["d4c3b2a1", "a1b2c3d4", "4d3cb2a1", "a1b23c4d"],
    ids=["us-le", "us-be", "ns-le", "ns-be"],
)
def test_all_pcap_magics_accepted(tmp_path: Path, magic: str) -> None:
    data = bytes.fromhex(magic) + PCAP_BODY
    info = validate_file(_write(tmp_path, data), max_bytes=1000)
    assert info.format is CaptureFormat.PCAP
    assert info.size_bytes == len(data)
    assert info.sha256 == hashlib.sha256(data).hexdigest()


def test_pcapng_accepted(tmp_path: Path) -> None:
    data = bytes.fromhex("0a0d0d0a") + PCAP_BODY
    assert validate_file(_write(tmp_path, data), 1000).format is CaptureFormat.PCAPNG


def test_extension_is_ignored(tmp_path: Path) -> None:
    data = bytes.fromhex("d4c3b2a1") + PCAP_BODY
    assert validate_file(_write(tmp_path, data, "evil.exe"), 1000).format is CaptureFormat.PCAP
    with pytest.raises(IngestError) as exc:
        validate_file(_write(tmp_path, b"MZ" + PCAP_BODY, "good.pcap"), 1000)
    assert exc.value.code == "FILE_TYPE_INVALID"


@pytest.mark.parametrize(
    "prefix",
    [b"\x1f\x8b\x08\x00", b"BZh9", b"\xfd7zXZ\x00", b"\x28\xb5\x2f\xfd", b"PK\x03\x04"],
    ids=["gzip", "bzip2", "xz", "zstd", "zip"],
)
def test_compressed_files_rejected(tmp_path: Path, prefix: bytes) -> None:
    with pytest.raises(IngestError) as exc:
        validate_file(_write(tmp_path, prefix + PCAP_BODY), 1000)
    assert exc.value.code == "FILE_COMPRESSED"


def test_gzipped_real_pcap_rejected(tmp_path: Path) -> None:
    data = gzip.compress(bytes.fromhex("d4c3b2a1") + PCAP_BODY)
    with pytest.raises(IngestError) as exc:
        validate_file(_write(tmp_path, data, "capture.pcap"), 1000)
    assert exc.value.code == "FILE_COMPRESSED"


def test_random_bytes_rejected(tmp_path: Path) -> None:
    with pytest.raises(IngestError) as exc:
        validate_file(_write(tmp_path, bytes(range(256))), 1000)
    assert exc.value.code == "FILE_TYPE_INVALID"


def test_empty_file_rejected(tmp_path: Path) -> None:
    with pytest.raises(IngestError) as exc:
        validate_file(_write(tmp_path, b""), 1000)
    assert exc.value.code == "FILE_EMPTY"


@pytest.mark.parametrize("data", [b"\xd4\xc3\xb2", bytes.fromhex("d4c3b2a1") + b"\x00" * 5])
def test_too_short_rejected(tmp_path: Path, data: bytes) -> None:
    with pytest.raises(IngestError) as exc:
        validate_file(_write(tmp_path, data), 1000)
    assert exc.value.code == "FILE_TYPE_INVALID"


def test_oversize_rejected_while_streaming() -> None:
    validator = CaptureValidator(max_bytes=50)
    validator.feed(bytes.fromhex("d4c3b2a1") + b"\x00" * 40)
    with pytest.raises(IngestError) as exc:
        validator.feed(b"\x00" * 10)
    assert exc.value.code == "FILE_TOO_LARGE"


def test_size_exactly_at_limit_is_accepted(tmp_path: Path) -> None:
    data = bytes.fromhex("d4c3b2a1") + PCAP_BODY
    assert validate_file(_write(tmp_path, data), max_bytes=len(data)).size_bytes == len(data)


def test_magic_split_across_chunks_and_hash_matches() -> None:
    data = bytes.fromhex("0a0d0d0a") + PCAP_BODY
    validator = CaptureValidator(1000)
    for i in range(len(data)):  # one byte at a time
        validator.feed(data[i : i + 1])
    info = validator.finish()
    assert info.format is CaptureFormat.PCAPNG
    assert info.sha256 == hashlib.sha256(data).hexdigest()


def test_bad_magic_detected_as_soon_as_four_bytes_arrive() -> None:
    validator = CaptureValidator(1000)
    validator.feed(b"ab")
    with pytest.raises(IngestError) as exc:
        validator.feed(b"cd")
    assert exc.value.code == "FILE_TYPE_INVALID"


def test_missing_file_and_directory(tmp_path: Path) -> None:
    with pytest.raises(IngestError) as exc:
        validate_file(tmp_path / "nope.pcap", 1000)
    assert exc.value.code == "FILE_NOT_FOUND"
    with pytest.raises(IngestError) as exc2:
        validate_file(tmp_path, 1000)
    assert exc2.value.code == "FILE_TYPE_INVALID"
