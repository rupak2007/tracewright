"""Deterministic malformed-capture corpus: structured and random mutations of a valid capture.

The corpus is generated, never stored. It is a robustness probe for the validation gate, the
upload endpoint and (inside the worker image) the real Zeek run, not a fuzzing campaign: the same
seed always yields the same files so a failure can be reproduced.
"""

import random
import struct
from collections.abc import Iterator

PCAP_HEADER = 24
RECORD_HEADER = 16


def _set(data: bytes, offset: int, value: bytes) -> bytes:
    return data[:offset] + value + data[offset + len(value) :]


def structured(data: bytes) -> Iterator[tuple[str, bytes]]:
    """Named, hand-picked corruptions of a little-endian microsecond pcap."""
    yield "zero_length", b""
    for cut in (1, 3, 4, 10, 23, 24, 25, 39, 40, len(data) // 2, len(data) - 1):
        yield f"truncated_at_{cut}", data[:cut]
    yield "header_only", data[:PCAP_HEADER]
    yield "huge_snaplen", _set(data, 16, struct.pack("<I", 0xFFFFFFFF))
    yield "zero_snaplen", _set(data, 16, struct.pack("<I", 0))
    yield "unknown_linktype", _set(data, 20, struct.pack("<I", 0xFFFF))
    yield "version_99", _set(data, 4, struct.pack("<HH", 99, 99))
    yield "first_record_incl_len_huge", _set(data, PCAP_HEADER + 8, struct.pack("<I", 0xFFFFFFFF))
    yield "first_record_incl_len_gt_orig", _set(data, PCAP_HEADER + 8, struct.pack("<II", 500, 10))
    yield "first_record_zero_len", _set(data, PCAP_HEADER + 8, struct.pack("<II", 0, 0))
    yield "body_all_zero", data[:PCAP_HEADER] + b"\x00" * (len(data) - PCAP_HEADER)
    yield "body_all_ff", data[:PCAP_HEADER] + b"\xff" * (len(data) - PCAP_HEADER)
    yield "trailing_garbage", data + b"\xde\xad\xbe\xef" * 64
    yield "doubled", data + data[PCAP_HEADER:]
    yield "big_endian_magic_little_endian_body", _set(data, 0, bytes.fromhex("a1b2c3d4"))
    yield "nanosecond_magic_microsecond_body", _set(data, 0, bytes.fromhex("4d3cb2a1"))
    yield "pcapng_magic_pcap_body", _set(data, 0, bytes.fromhex("0a0d0d0a"))


def random_mutants(data: bytes, seed: int, count: int) -> Iterator[tuple[str, bytes]]:
    """Bit flips, random byte blocks and random deletions anywhere after the 4-byte magic."""
    rng = random.Random(seed)  # noqa: S311  (reproducible corpus, not cryptography)
    for n in range(count):
        mutant = bytearray(data)
        kind = n % 3
        if kind == 0:  # flip 1-16 bits
            for _ in range(rng.randint(1, 16)):
                pos = rng.randrange(4, len(mutant))
                mutant[pos] ^= 1 << rng.randrange(8)
        elif kind == 1:  # overwrite a random block with random bytes
            start = rng.randrange(4, len(mutant) - 1)
            size = rng.randint(1, min(64, len(mutant) - start))
            mutant[start : start + size] = rng.randbytes(size)
        else:  # delete a random block
            start = rng.randrange(4, len(mutant) - 1)
            del mutant[start : start + rng.randint(1, 64)]
        yield f"random_{seed}_{n:03d}_{('flip', 'block', 'delete')[kind]}", bytes(mutant)


def corpus(data: bytes, seed: int = 20261008, random_count: int = 30) -> list[tuple[str, bytes]]:
    return [*structured(data), *random_mutants(data, seed, random_count)]
