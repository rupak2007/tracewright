"""Generate small deterministic fixture captures with Scapy (fixtures/lab only; never pipeline).

Nothing here is committed as a binary: tests build the files on demand.

basic.pcap contents (client 10.0.0.5, internal server 10.0.0.10, resolver 10.0.0.53, external
93.184.216.34), with known expected Zeek results:
  * 1 complete HTTP session  10.0.0.5 -> 10.0.0.10:80   (conn_state SF, http.log GET /index.html)
  * 1 TLS-port session       10.0.0.5 -> 93.184.216.34:443 (handshake + data + FIN, conn_state SF)
  * 1 rejected connection    10.0.0.5 -> 10.0.0.10:81   (SYN answered by RST, conn_state REJ)
  * 1 unanswered connection  10.0.0.5 -> 10.0.0.10:82   (SYN only, conn_state S0)
  * 2 DNS exchanges          example.com (NOERROR, A record) and nope.example.com (NXDOMAIN)
  * 1 ICMP echo exchange     10.0.0.5 -> 10.0.0.10
"""

import gzip
import sys
from pathlib import Path

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Packet, Raw
from scapy.utils import PcapNgWriter, wrpcap

CLIENT, SERVER, RESOLVER, EXTERNAL = "10.0.0.5", "10.0.0.10", "10.0.0.53", "93.184.216.34"
CLIENT_MAC, SERVER_MAC = "02:00:00:00:00:05", "02:00:00:00:00:10"
T0 = 1_700_000_000.0  # fixed epoch so output is deterministic


class _Clock:
    def __init__(self) -> None:
        self.now = T0

    def tick(self, seconds: float = 0.01) -> float:
        self.now += seconds
        return self.now


def _eth(src_to_dst: bool, pkt: Packet, clock: _Clock) -> Packet:
    src, dst = (CLIENT_MAC, SERVER_MAC) if src_to_dst else (SERVER_MAC, CLIENT_MAC)
    frame = Ether(src=src, dst=dst) / pkt
    frame.time = clock.tick()
    return frame


def _tcp_session(
    clock: _Clock, src: str, dst: str, sport: int, dport: int, request: bytes, response: bytes
) -> list[Packet]:
    def c(flags: str, seq: int, ack: int, payload: bytes = b"") -> Packet:
        p = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack)
        return _eth(True, p / Raw(payload) if payload else p, clock)

    def s(flags: str, seq: int, ack: int, payload: bytes = b"") -> Packet:
        p = IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags=flags, seq=seq, ack=ack)
        return _eth(False, p / Raw(payload) if payload else p, clock)

    cseq, sseq = 1000, 5000
    pkts = [
        c("S", cseq, 0),
        s("SA", sseq, cseq + 1),
        c("A", cseq + 1, sseq + 1),
        c("PA", cseq + 1, sseq + 1, request),
        s("A", sseq + 1, cseq + 1 + len(request)),
        s("PA", sseq + 1, cseq + 1 + len(request), response),
        c("A", cseq + 1 + len(request), sseq + 1 + len(response)),
        c("FA", cseq + 1 + len(request), sseq + 1 + len(response)),
        s("FA", sseq + 1 + len(response), cseq + 2 + len(request)),
        c("A", cseq + 2 + len(request), sseq + 2 + len(response)),
    ]
    return pkts


def _dns(clock: _Clock, sport: int, name: str, nxdomain: bool) -> list[Packet]:
    q = IP(src=CLIENT, dst=RESOLVER) / UDP(sport=sport, dport=53)
    q = q / DNS(id=sport, rd=1, qd=DNSQR(qname=name))
    r = IP(src=RESOLVER, dst=CLIENT) / UDP(sport=53, dport=sport)
    if nxdomain:
        r = r / DNS(id=sport, qr=1, rd=1, ra=1, rcode=3, qd=DNSQR(qname=name))
    else:
        answer = DNSRR(rrname=name, type="A", ttl=300, rdata=EXTERNAL)
        r = r / DNS(id=sport, qr=1, rd=1, ra=1, qd=DNSQR(qname=name), an=answer, ancount=1)
    return [_eth(True, q, clock), _eth(False, r, clock)]


def build_basic_packets() -> list[Packet]:
    clock = _Clock()
    pkts: list[Packet] = []
    http_req = (
        b"GET /index.html HTTP/1.1\r\nHost: intranet.example\r\nUser-Agent: fixture/1.0\r\n\r\n"
    )
    http_resp = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: text/plain\r\n\r\nhello"
    pkts += _dns(clock, 40001, "example.com.", nxdomain=False)
    pkts += _dns(clock, 40002, "nope.example.com.", nxdomain=True)
    pkts += _tcp_session(clock, CLIENT, SERVER, 50001, 80, http_req, http_resp)
    pkts += _tcp_session(
        clock, CLIENT, EXTERNAL, 50002, 443, b"\x16\x03\x01\x00\x05hello", b"x" * 40
    )
    # Rejected: SYN answered by RST/ACK.
    pkts.append(
        _eth(True, IP(src=CLIENT, dst=SERVER) / TCP(sport=50003, dport=81, flags="S", seq=1), clock)
    )
    pkts.append(
        _eth(
            False,
            IP(src=SERVER, dst=CLIENT) / TCP(sport=81, dport=50003, flags="RA", seq=0, ack=2),
            clock,
        )
    )
    # Unanswered SYN.
    pkts.append(
        _eth(True, IP(src=CLIENT, dst=SERVER) / TCP(sport=50004, dport=82, flags="S", seq=1), clock)
    )
    # ICMP echo request/reply.
    pkts.append(
        _eth(True, IP(src=CLIENT, dst=SERVER) / ICMP(type=8, id=7, seq=1) / Raw(b"ping"), clock)
    )
    pkts.append(
        _eth(False, IP(src=SERVER, dst=CLIENT) / ICMP(type=0, id=7, seq=1) / Raw(b"ping"), clock)
    )
    return pkts


def make_basic_pcap(path: Path) -> Path:
    wrpcap(str(path), build_basic_packets())
    return path


def make_basic_pcapng(path: Path) -> Path:
    writer = PcapNgWriter(str(path))
    for pkt in build_basic_packets():
        writer.write(pkt)
    writer.close()
    return path


def make_truncated_pcap(path: Path, source: Path) -> Path:
    """Cut a valid capture mid-packet (keeps the header and part of the records)."""
    data = source.read_bytes()
    path.write_bytes(data[: len(data) * 2 // 3 + 7])
    return path


def make_non_pcap(path: Path) -> Path:
    path.write_bytes(b"This is not a capture file.\n" * 20)
    return path


def make_gzip_pcap(path: Path, source: Path) -> Path:
    path.write_bytes(gzip.compress(source.read_bytes()))
    return path


def make_empty_capture(path: Path) -> Path:
    """A valid pcap with zero packets (header only)."""
    wrpcap(str(path), [])
    return path


if __name__ == "__main__":
    out = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    out.mkdir(parents=True, exist_ok=True)
    basic = make_basic_pcap(out / "basic.pcap")
    make_basic_pcapng(out / "basic.pcapng")
    make_truncated_pcap(out / "truncated.pcap", basic)
    make_non_pcap(out / "not_a_pcap.bin")
    make_gzip_pcap(out / "basic.pcap.gz", basic)
    make_empty_capture(out / "empty.pcap")
    print(f"wrote fixtures to {out.resolve()}")
