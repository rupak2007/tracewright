"""Build `demo/demo.pcap` for the walkthrough in docs/DEMO.md.

    python scripts/make_demo.py [--run-id b02] [--max-mb 20] [--out demo/demo.pcap]

The demo capture is cut from a REAL, verified BENIGN lab run (`data/lab/<run_id>/capture.pcap`).
It contains **no attack traffic**: this repository generates none, so the multi-stage scenario in
plan P10 (scan -> brute force -> beacon -> exfil) cannot be produced here. What the benign demo does
show is the hard part of triage: regular, harmless check-ins that the beacon detector flags, with
the metric against its threshold, the known benign causes and the evidence behind each finding.

When a verified external attack capture exists (python -m lab.register_external, then
lab.verify_run), pass it with `--attack <path>` to append it to a benign background; the result is
a demo of that capture, not new traffic. Captures are never committed (`demo/` is gitignored).
"""

import argparse
import struct
import sys
from collections.abc import Sequence
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
GLOBAL_HEADER = 24
RECORD_HEADER = 16
MAGICS = {bytes.fromhex(h) for h in ("d4c3b2a1", "a1b2c3d4", "4d3cb2a1", "a1b23c4d")}


def append_packets(
    sources: Sequence[Path], limit_bytes: int, out: Path
) -> tuple[int, int]:
    """Concatenate the packets of classic-pcap `sources` (same global header) up to `limit_bytes`."""
    header = b""
    packets = written = 0
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("wb") as dst:
        for src in sources:
            with src.open("rb") as handle:
                head = handle.read(GLOBAL_HEADER)
                if len(head) < GLOBAL_HEADER or head[:4] not in MAGICS:
                    raise SystemExit(f"{src} is not a classic pcap file")
                if not header:
                    header = head
                    dst.write(head)
                    written = GLOBAL_HEADER
                elif head != header:
                    raise SystemExit(
                        f"{src} has a different pcap header from the first source"
                    )
                little = head[:4] in (
                    bytes.fromhex("d4c3b2a1"),
                    bytes.fromhex("4d3cb2a1"),
                )
                order = "<" if little else ">"
                while written < limit_bytes:
                    record = handle.read(RECORD_HEADER)
                    if len(record) < RECORD_HEADER:
                        break
                    (incl_len,) = struct.unpack(order + "I", record[8:12])
                    body = handle.read(incl_len)
                    if len(body) < incl_len:
                        break
                    dst.write(record + body)
                    written += RECORD_HEADER + incl_len
                    packets += 1
    return packets, written


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument("--run-id", default="b02")
    parser.add_argument(
        "--attack", type=Path, help="a verified external capture to append"
    )
    parser.add_argument("--max-mb", type=int, default=20)
    parser.add_argument("--out", type=Path, default=REPO / "demo" / "demo.pcap")
    args = parser.parse_args(argv)
    benign = REPO / "data" / "lab" / args.run_id / "capture.pcap"
    if not benign.exists():
        print(
            f"error: {benign} does not exist. Record the benign lab corpus first "
            "(python -m lab.record_corpus) or point --run-id at an existing run.",
            file=sys.stderr,
        )
        return 2
    sources = [benign, *([args.attack] if args.attack else [])]
    packets, size = append_packets(sources, args.max_mb * 1_000_000, args.out)
    kind = "benign lab run + supplied capture" if args.attack else "benign lab run only"
    print(
        f"wrote {args.out}: {packets} packets, {size} bytes ({kind}; no generated attack traffic)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
