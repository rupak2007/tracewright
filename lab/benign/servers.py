"""Benign lab services, standard library only: HTTP (several roles), a raw TCP sink, a DNS stub and
an NTP responder. All answers are deterministic functions of the request (no clock/randomness
except the NTP timestamp), so a scenario with a fixed seed produces a repeatable traffic shape.

`LabServers` is used inside the lab `services` container and, on loopback with ephemeral ports,
by unit tests.
"""

import asyncio
import hashlib
import struct
import time
from dataclasses import dataclass

CHUNK = 64 * 1024
MAX_HEADER_BYTES = 16 * 1024
DNS_ANSWER_NET = "203.0.113."  # TEST-NET-3 (RFC 5737): never a real address


@dataclass(frozen=True)
class Ports:
    http: int = 80
    heartbeat: int = 8080
    upload: int = 8081
    packages: int = 8082
    stream: int = 8083
    backup: int = 873
    dns: int = 53
    ntp: int = 123


def _body(seed: str, size: int) -> bytes:
    block = hashlib.sha256(seed.encode()).digest()
    return (block * (size // len(block) + 1))[:size]


async def _read_request(reader: asyncio.StreamReader) -> tuple[str, str, dict[str, str]] | None:
    try:
        head = await reader.readuntil(b"\r\n\r\n")
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, ConnectionError):
        return None
    if len(head) > MAX_HEADER_BYTES:
        return None
    lines = head.decode("latin-1").split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) != 3:
        return None
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()
    return parts[0], parts[1], headers


async def _respond(writer: asyncio.StreamWriter, status: str, body: bytes = b"") -> None:
    head = f"HTTP/1.1 {status}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    writer.write(head.encode() + body)
    await writer.drain()


async def _drain_body(reader: asyncio.StreamReader, length: int) -> int:
    remaining = length
    while remaining > 0:
        data = await reader.read(min(CHUNK, remaining))
        if not data:
            break
        remaining -= len(data)
    return length - remaining


def _query_int(path: str, key: str, default: int) -> int:
    _, _, query = path.partition("?")
    for pair in query.split("&"):
        name, _, value = pair.partition("=")
        if name == key and value.isdigit():
            return int(value)
    return default


def _http_handler(role: str):  # type: ignore[no-untyped-def]
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            request = await _read_request(reader)
            if request is None:
                return
            _method, path, headers = request
            # Always consume the request body first: closing with unread data makes the kernel
            # send a TCP reset, which the client can see before it reads our response.
            length = int(headers.get("content-length", "0") or 0)
            received = await _drain_body(reader, length)
            if role == "http":
                await _respond(writer, "200 OK", _body(path, 2048 + (len(path) * 97) % 16384))
            elif role == "heartbeat":
                await _respond(writer, "204 No Content")
            elif role == "upload":
                await _respond(writer, "200 OK", f"received {received}\n".encode())
            elif role == "packages":
                await _respond(writer, "200 OK", _body(path, 256 * 1024))
            elif role == "stream":
                kbps = max(_query_int(path, "kbps", 1000), 1)
                seconds = max(_query_int(path, "seconds", 10), 1)
                total = kbps * 1000 // 8 * seconds
                head = f"HTTP/1.1 200 OK\r\nContent-Length: {total}\r\nConnection: close\r\n\r\n"
                writer.write(head.encode())
                step = max(kbps * 1000 // 8 // 10, 1)  # ten writes per second
                block = _body("stream", step)
                sent = 0
                while sent < total:
                    piece = block[: min(step, total - sent)]
                    writer.write(piece)
                    await writer.drain()
                    sent += len(piece)
                    await asyncio.sleep(0.1)
        except (ConnectionError, asyncio.CancelledError):
            pass
        finally:
            writer.close()

    return handle


async def _backup_sink(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while await reader.read(CHUNK):
            pass
        writer.write(b"OK\n")
        await writer.drain()
    except ConnectionError:
        pass
    finally:
        writer.close()


def dns_response(query: bytes) -> bytes | None:
    """Answer an A query: NXDOMAIN for names starting with 'nx-', else a deterministic address."""
    if len(query) < 17:
        return None
    ident, flags, qdcount = struct.unpack("!HHH", query[:6])
    if flags & 0x8000 or qdcount != 1:
        return None
    pos, labels = 12, []
    while pos < len(query) and query[pos] != 0:
        length = query[pos]
        if length > 63 or pos + 1 + length > len(query):
            return None
        labels.append(query[pos + 1 : pos + 1 + length].decode("latin-1"))
        pos += 1 + length
    question_end = pos + 5  # zero byte + QTYPE + QCLASS
    if question_end > len(query):
        return None
    name = ".".join(labels).lower()
    question = query[12:question_end]
    if name.startswith("nx-"):
        return struct.pack("!HHHHHH", ident, 0x8183, 1, 0, 0, 0) + question
    host = hashlib.sha256(name.encode()).digest()[0] % 250 + 1
    answer = (
        b"\xc0\x0c"
        + struct.pack("!HHIH", 1, 1, 300, 4)
        + bytes(int(part) for part in f"{DNS_ANSWER_NET}{host}".split("."))
    )
    return struct.pack("!HHHHHH", ident, 0x8180, 1, 1, 0, 0) + question + answer


def ntp_response(request: bytes) -> bytes | None:
    if len(request) < 48:
        return None
    version = (request[0] >> 3) & 0x7
    seconds = int(time.time()) + 2208988800  # NTP epoch offset
    reply = bytearray(48)
    reply[0] = (version << 3) | 4  # leap 0, same version, mode 4 (server)
    reply[1] = 2  # stratum
    struct.pack_into("!II", reply, 40, seconds, 0)
    return bytes(reply)


class _Datagram(asyncio.DatagramProtocol):
    def __init__(self, responder) -> None:  # type: ignore[no-untyped-def]
        self._responder = responder
        self._transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self._transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        reply = self._responder(data)
        if reply is not None and self._transport is not None:
            self._transport.sendto(reply, addr)


class LabServers:
    def __init__(self, bind: str, ports: Ports) -> None:
        self._bind, self._ports = bind, ports
        self._servers: list[asyncio.AbstractServer] = []
        self._transports: list[asyncio.BaseTransport] = []
        self.bound = Ports()

    async def start(self) -> Ports:
        loop = asyncio.get_running_loop()
        bound: dict[str, int] = {}
        for role, port in (
            ("http", self._ports.http),
            ("heartbeat", self._ports.heartbeat),
            ("upload", self._ports.upload),
            ("packages", self._ports.packages),
            ("stream", self._ports.stream),
        ):
            server = await asyncio.start_server(_http_handler(role), self._bind, port)
            self._servers.append(server)
            bound[role] = server.sockets[0].getsockname()[1]
        sink = await asyncio.start_server(_backup_sink, self._bind, self._ports.backup)
        self._servers.append(sink)
        bound["backup"] = sink.sockets[0].getsockname()[1]
        for role, port, responder in (
            ("dns", self._ports.dns, dns_response),
            ("ntp", self._ports.ntp, ntp_response),
        ):
            transport, _ = await loop.create_datagram_endpoint(
                lambda r=responder: _Datagram(r),  # type: ignore[misc]
                local_addr=(self._bind, port),
            )
            self._transports.append(transport)
            sock = transport.get_extra_info("socket")
            bound[role] = sock.getsockname()[1]
        self.bound = Ports(**bound)
        return self.bound

    async def stop(self) -> None:
        for server in self._servers:
            server.close()
            await server.wait_closed()
        for transport in self._transports:
            transport.close()


async def serve_forever(bind: str, ports: Ports) -> None:
    servers = LabServers(bind, ports)
    await servers.start()
    try:
        await asyncio.Event().wait()
    finally:
        await servers.stop()


if __name__ == "__main__":
    asyncio.run(serve_forever("0.0.0.0", Ports()))  # noqa: S104  # inside the isolated lab network
