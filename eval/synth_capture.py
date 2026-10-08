"""Synthetic, connection-heavy capture used ONLY to size the pipeline (NFR-01: "~1M packets").

    python -m eval.synth_capture --packets 1000000 --out data/bench/synthetic-1M.pcap [--seed 7]

The real lab captures are byte-heavy and packet-poor (a 500 MB capture holds about 72,000 packets
and 357 connections, because the recorder sees coalesced segments), so they cannot show how the
profile, normalisation and detector stages scale with connection count. This generator writes many
short, complete TCP conversations (handshake, a few data segments each way, orderly close) between
internal clients and a small set of services, with valid IPv4 and TCP checksums so Zeek accepts
them.

It is a SIZING input, not a dataset: there are no labels, no episodes and no attack behaviour (fixed
service ports, no failed connections, random start times, no DNS), it is never registered as a lab
run and never used for detector, anomaly or LLM evaluation. Output is deterministic for a seed.
"""

import argparse
import random
import struct
import sys
from collections.abc import Sequence
from pathlib import Path

PCAP_HEADER = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)  # little-endian pcap
SERVICE_PORTS = (80, 443, 8080, 22, 25, 143, 993, 3306)
CLIENT_MAC, SERVER_MAC = bytes.fromhex("020000000005"), bytes.fromhex("020000000010")
PACKETS_PER_CONNECTION = 14
START_EPOCH = 1_793_613_600  # 2026-11-02T10:00:00Z, the lab's convention


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return int(~total & 0xFFFF)


def frame(src: str, dst: str, sport: int, dport: int, seq: int, ack: int, flags: int,
          payload: bytes, to_server: bool, ident: int) -> bytes:  # fmt: skip
    """One Ethernet/IPv4/TCP frame with valid checksums."""
    src_b, dst_b = bytes(map(int, src.split("."))), bytes(map(int, dst.split(".")))
    total = 20 + 20 + len(payload)
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, total, ident & 0xFFFF, 0x4000, 64, 6, 0, src_b, dst_b
    )
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
                      5 << 4, flags, 65535, 0, 0)  # fmt: skip
    pseudo = src_b + dst_b + struct.pack("!BBH", 0, 6, 20 + len(payload))
    tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp + payload)) + tcp[18:]
    macs = (CLIENT_MAC + SERVER_MAC) if to_server else (SERVER_MAC + CLIENT_MAC)
    return macs + b"\x08\x00" + ip + tcp + payload


SYN, SYNACK, ACK, PSHACK, FINACK = 0x02, 0x12, 0x10, 0x18, 0x11


def connection(
    rng: random.Random, start: float, client: str, server: str, sport: int, dport: int, ident: int
) -> list[tuple[float, bytes]]:
    """14 packets: 3-way handshake, 2 request/response exchanges with ACKs, 4-way-ish close."""
    cseq, sseq = rng.randrange(1 << 31), rng.randrange(1 << 31)
    out: list[tuple[float, bytes]] = []
    t = start

    def send(to_server: bool, flags: int, payload: bytes = b"") -> None:
        nonlocal t, cseq, sseq
        t += rng.uniform(0.0005, 0.02)
        if to_server:
            pkt = frame(client, server, sport, dport, cseq, sseq if flags != SYN else 0, flags,
                        payload, True, ident + len(out))  # fmt: skip
            cseq += len(payload) + (1 if flags & 0x03 else 0)
        else:
            pkt = frame(server, client, dport, sport, sseq, cseq, flags, payload, False,
                        ident + len(out))  # fmt: skip
            sseq += len(payload) + (1 if flags & 0x03 else 0)
        out.append((t, pkt))

    send(True, SYN)
    send(False, SYNACK)
    send(True, ACK)
    for _ in range(2):
        send(True, PSHACK, rng.randbytes(rng.randint(60, 400)))
        send(False, ACK)
        send(False, PSHACK, rng.randbytes(rng.randint(100, 1400)))
        send(True, ACK)
    send(True, FINACK)
    send(False, FINACK)
    send(True, ACK)
    return out


def write_sizing_capture(path: Path, packets: int, seed: int = 7, clients: int = 400) -> int:
    """Write about `packets` packets; returns the number of connections."""
    rng = random.Random(seed)  # noqa: S311  (deterministic sizing data, not cryptography)
    n_conn = max(1, packets // PACKETS_PER_CONNECTION)
    span = 3600.0
    starts = sorted(rng.uniform(0, span) for _ in range(n_conn))
    servers = [f"10.0.0.{n}" for n in range(10, 30)]
    rows: list[tuple[float, bytes]] = []
    for i, offset in enumerate(starts):
        client = f"10.0.{1 + (i % clients) // 250}.{1 + (i % clients) % 250}"
        rows += connection(
            rng,
            START_EPOCH + offset,
            client,
            rng.choice(servers),
            rng.randrange(20_000, 60_000),
            rng.choice(SERVICE_PORTS),
            i * PACKETS_PER_CONNECTION,
        )
    rows.sort(key=lambda r: r[0])
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        handle.write(PCAP_HEADER)
        for ts, data in rows:
            sec = int(ts)
            handle.write(
                struct.pack("<IIII", sec, int((ts - sec) * 1_000_000), len(data), len(data))
            )
            handle.write(data)
    return n_conn


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument("--packets", type=int, default=1_000_000)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args(argv)
    connections = write_sizing_capture(args.out, args.packets, args.seed)
    size = args.out.stat().st_size
    print(f"wrote {args.out}: {connections * PACKETS_PER_CONNECTION} packets, {connections} "
          f"connections, {size} bytes (SYNTHETIC sizing input, not evaluation data)")  # fmt: skip
    return 0


if __name__ == "__main__":
    sys.exit(main())
