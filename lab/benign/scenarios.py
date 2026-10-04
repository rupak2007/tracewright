"""Benign, legitimate-traffic scenarios (hard negatives and background), standard library only.

Each scenario produces traffic that *resembles* something a detector watches (regular timing, bulk
upload, many DNS names, long streams) but is legitimate. They are labelled `hard_negative`: a
detector finding on one counts as a false positive (eval/PROTOCOL.md §3).

All randomness comes from the context's seeded RNG; time comes from the injected clock/sleep so
tests can run scenarios without waiting.
"""

import contextlib
import http.client
import random
import socket
import struct
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from lab.benign.servers import Ports
from lab.labeler import Labeler

Sleep = Callable[[float], None]
ACTOR_TOOL = "lab-benign-generator"


@dataclass
class Context:
    internal_host: str
    external_host: str
    ports: Ports
    actor: str
    rng: random.Random
    duration_s: float
    params: dict[str, Any] = field(default_factory=dict)
    sleep: Sleep = time.sleep
    monotonic: Callable[[], float] = time.monotonic

    def param(self, name: str, default: Any) -> Any:
        return self.params.get(name, default)


def _deadline(ctx: Context) -> float:
    return ctx.monotonic() + ctx.duration_s


def _periodic(ctx: Context, interval_s: float, action: Callable[[], object]) -> int:
    """Run `action` every interval until the duration is used up (at least once)."""
    end = _deadline(ctx)
    count = 0
    while True:
        started = ctx.monotonic()
        action()
        count += 1
        if started + interval_s >= end:
            return count
        ctx.sleep(max(interval_s - (ctx.monotonic() - started), 0.0))


def _http(
    host: str,
    port: int,
    method: str,
    path: str,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
    read_limit: int | None = None,
) -> int:
    conn = http.client.HTTPConnection(host, port, timeout=30)
    try:
        conn.request(method, path, body=body, headers={"Connection": "close", **(headers or {})})
        response = conn.getresponse()
        total = 0
        while chunk := response.read(64 * 1024):
            total += len(chunk)
            if read_limit is not None and total >= read_limit:
                break
        return total
    finally:
        conn.close()


def dns_query(server: str, port: int, name: str, timeout_s: float = 2.0) -> bool:
    """Send one A query over UDP; True if any answer came back."""
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split("."))
    packet = struct.pack("!HHHHHH", random.getrandbits(16), 0x0100, 1, 0, 0, 0)
    packet += labels + b"\x00" + struct.pack("!HH", 1, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout_s)
        sock.sendto(packet, (server, port))
        try:
            sock.recvfrom(512)
        except TimeoutError:
            return False
    return True


def ntp(ctx: Context) -> None:
    interval = float(ctx.param("interval_s", 64))
    packet = bytes([0x23]) + bytes(47)  # LI 0, version 4, mode 3 (client)

    def poll() -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(2.0)
            sock.sendto(packet, (ctx.internal_host, ctx.ports.ntp))
            with contextlib.suppress(TimeoutError):
                sock.recvfrom(128)

    _periodic(ctx, interval, poll)


def monitoring_heartbeat(ctx: Context) -> None:
    interval = float(ctx.param("interval_s", 30))
    payload = b'{"agent":"lab-monitor","status":"ok"}'
    _periodic(
        ctx,
        interval,
        lambda: _http(ctx.internal_host, ctx.ports.heartbeat, "POST", "/heartbeat", payload),
    )


def rsync_backup(ctx: Context) -> None:
    """Bulk upload to an *internal* backup sink: large, outbound-heavy, legitimate."""
    total = int(float(ctx.param("mb", 20)) * 1024 * 1024)
    block = bytes(ctx.rng.getrandbits(8) for _ in range(1024)) * 64  # 64 KiB, seed-determined
    with socket.create_connection((ctx.internal_host, ctx.ports.backup), timeout=30) as sock:
        sent = 0
        while sent < total:
            piece = block[: min(len(block), total - sent)]
            sock.sendall(piece)
            sent += len(piece)
        sock.shutdown(socket.SHUT_WR)
        sock.recv(16)


def cloud_sync_upload(ctx: Context) -> None:
    """Large upload to an *external* destination (above the DET-EXFIL floor): legitimate sync."""
    total = int(float(ctx.param("mb", 60)) * 1024 * 1024)
    block = bytes(ctx.rng.getrandbits(8) for _ in range(1024)) * 64
    conn = http.client.HTTPConnection(ctx.external_host, ctx.ports.upload, timeout=60)
    try:
        conn.putrequest("POST", "/sync")
        conn.putheader("Content-Length", str(total))
        conn.putheader("Host", "sync.example.test")
        conn.endheaders()
        sent = 0
        while sent < total:
            piece = block[: min(len(block), total - sent)]
            conn.send(piece)
            sent += len(piece)
        conn.getresponse().read()
    finally:
        conn.close()


def package_update(ctx: Context) -> None:
    for number in range(int(ctx.param("files", 30))):
        _http(ctx.internal_host, ctx.ports.packages, "GET", f"/pkg/{number}")


def cdn_browsing(ctx: Context) -> None:
    """Many distinct hostnames (DNS) and small fetches: looks like a high-cardinality DNS client."""
    for _ in range(int(ctx.param("hosts", 150))):
        name = f"edge-{ctx.rng.getrandbits(40):010x}.cdn.example.test"
        dns_query(ctx.internal_host, ctx.ports.dns, name)
        _http(ctx.internal_host, ctx.ports.http, "GET", "/asset.js", headers={"Host": name})
        ctx.sleep(float(ctx.param("pause_s", 0.1)))


def video_streaming(ctx: Context) -> None:
    kbps = int(ctx.param("kbps", 2000))
    seconds = max(int(ctx.duration_s), 1)
    _http(ctx.internal_host, ctx.ports.stream, "GET", f"/stream?kbps={kbps}&seconds={seconds}")


def background_browsing(ctx: Context) -> None:
    """Unlabelled ordinary activity: a handful of names, some page fetches, think time."""
    end = _deadline(ctx)
    names = [f"site{n}.example.test" for n in range(12)]
    while ctx.monotonic() < end:
        name = ctx.rng.choice(names)
        dns_query(ctx.internal_host, ctx.ports.dns, name)
        for _ in range(ctx.rng.randint(1, 4)):
            _http(
                ctx.internal_host,
                ctx.ports.http,
                "GET",
                f"/page/{ctx.rng.randint(1, 50)}",
                headers={"Host": name},
            )
        ctx.sleep(ctx.rng.uniform(0.5, 3.0))


@dataclass(frozen=True)
class Scenario:
    name: str
    run: Callable[[Context], None]
    cls: str | None  # hard-negative class label; None = unlabelled background
    external: bool = False  # True when the labelled target is the external sink


SCENARIOS: dict[str, Scenario] = {
    s.name: s
    for s in (
        Scenario("ntp", ntp, "NTP"),
        Scenario("monitoring_heartbeat", monitoring_heartbeat, "MONITORING_HEARTBEAT"),
        Scenario("rsync_backup", rsync_backup, "RSYNC_BACKUP"),
        Scenario("cloud_sync_upload", cloud_sync_upload, "CLOUD_SYNC_UPLOAD", external=True),
        Scenario("package_update", package_update, "PACKAGE_UPDATE"),
        Scenario("cdn_browsing", cdn_browsing, "CDN_BROWSING"),
        Scenario("video_streaming", video_streaming, "VIDEO_STREAMING"),
        Scenario("background_browsing", background_browsing, None),
    )
}


def run_scenario(name: str, ctx: Context, labeler: Labeler | None) -> None:
    """Run one scenario; labelled ones are wrapped in a hard_negative episode."""
    scenario = SCENARIOS[name]
    if scenario.cls is None or labeler is None:
        scenario.run(ctx)
        return
    target = ctx.external_host if scenario.external else ctx.internal_host
    params = {"duration_s": ctx.duration_s, **ctx.params}
    with labeler.episode("hard_negative", scenario.cls, ctx.actor, [target], ACTOR_TOOL, params):
        scenario.run(ctx)
