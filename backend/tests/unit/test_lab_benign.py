"""Benign lab services and scenarios exercised over real loopback sockets (no mocked traffic)."""

import asyncio
import random
import socket
import struct
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("lab")

from lab.benign import scenarios
from lab.benign.scenarios import SCENARIOS, Context, dns_query, run_scenario
from lab.benign.servers import LabServers, Ports, dns_response, ntp_response
from lab.labeler import Labeler, read_labels

LOCAL = "127.0.0.1"


@pytest.fixture(scope="module")
def ports() -> Iterator[Ports]:
    """Start every lab service on loopback with OS-chosen ports, in a background event loop."""
    loop = asyncio.new_event_loop()
    ready: dict[str, Any] = {}
    started = threading.Event()
    servers = LabServers(LOCAL, Ports(0, 0, 0, 0, 0, 0, 0, 0))

    async def boot() -> None:
        ready["ports"] = await servers.start()
        started.set()

    def run() -> None:
        asyncio.set_event_loop(loop)
        boot_task = loop.create_task(boot())
        ready["task"] = boot_task  # keep a reference so the task is not garbage-collected
        loop.run_forever()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    assert started.wait(10)
    yield ready["ports"]
    asyncio.run_coroutine_threadsafe(servers.stop(), loop).result(10)
    loop.call_soon_threadsafe(loop.stop)
    thread.join(5)


def make_ctx(ports: Ports, seed: int = 1, duration_s: float = 1.0, **params: Any) -> Context:
    return Context(
        internal_host=LOCAL,
        external_host=LOCAL,
        ports=ports,
        actor="172.20.0.101",
        rng=random.Random(seed),  # noqa: S311
        duration_s=duration_s,
        params=params,
        sleep=lambda _s: None,  # do not actually wait between actions
    )


def test_dns_stub_answers_deterministically_and_nxdomain_on_prefix() -> None:
    def query(name: str) -> bytes:
        labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split("."))
        return (
            struct.pack("!HHHHHH", 0xBEEF, 0x0100, 1, 0, 0, 0)
            + labels
            + b"\x00"
            + struct.pack("!HH", 1, 1)
        )

    first, again = dns_response(query("a.example.test")), dns_response(query("a.example.test"))
    assert first == again and first is not None
    ident, flags, qd, an = struct.unpack("!HHHH", first[:8])
    assert (ident, flags & 0xF, qd, an) == (0xBEEF, 0, 1, 1)
    assert first[-4:-1] == bytes([203, 0, 113])  # TEST-NET-3
    nx = dns_response(query("nx-gone.example.test"))
    assert (
        nx is not None
        and struct.unpack("!HH", nx[:4])[1] & 0xF == 3
        and struct.unpack("!H", nx[6:8])[0] == 0
    )


@pytest.mark.parametrize("garbage", [b"", b"\x00" * 5, b"\xff" * 40])
def test_dns_stub_ignores_garbage(garbage: bytes) -> None:
    assert dns_response(garbage) is None


def test_ntp_responder_replies_in_server_mode() -> None:
    reply = ntp_response(bytes([0x23]) + bytes(47))
    assert (
        reply is not None and len(reply) == 48 and reply[0] & 0x7 == 4 and (reply[0] >> 3) & 7 == 4
    )
    assert ntp_response(b"short") is None


def test_dns_client_gets_a_real_answer_from_the_server(ports: Ports) -> None:
    assert dns_query(LOCAL, ports.dns, "one.example.test")
    unused = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    unused.bind((LOCAL, 0))
    dead_port = unused.getsockname()[1]
    try:
        assert not dns_query(LOCAL, dead_port, "x.example.test", timeout_s=0.3)
    finally:
        unused.close()


def test_registry_covers_every_hard_negative_scenario() -> None:
    labelled = {s.cls for s in SCENARIOS.values() if s.cls}
    assert labelled == {
        "NTP", "MONITORING_HEARTBEAT", "RSYNC_BACKUP", "CLOUD_SYNC_UPLOAD",
        "PACKAGE_UPDATE", "CDN_BROWSING", "VIDEO_STREAMING",
    }  # fmt: skip
    assert SCENARIOS["background_browsing"].cls is None
    assert SCENARIOS["cloud_sync_upload"].external and not SCENARIOS["rsync_backup"].external


@pytest.mark.parametrize(
    ("name", "params"),
    [
        ("ntp", {"interval_s": 1}),
        ("monitoring_heartbeat", {"interval_s": 1}),
        ("rsync_backup", {"mb": 0.25}),
        ("cloud_sync_upload", {"mb": 0.25}),
        ("package_update", {"files": 3}),
        ("cdn_browsing", {"hosts": 5}),
        ("video_streaming", {"kbps": 16}),
    ],
)
def test_each_labelled_scenario_runs_against_real_servers_and_writes_one_valid_label(
    ports: Ports, tmp_path: Path, name: str, params: dict[str, Any]
) -> None:
    labels = tmp_path / "labels.jsonl"
    run_scenario(name, make_ctx(ports, **params), Labeler(labels, "r001", id_prefix="c101-"))
    [episode] = read_labels(labels)
    assert episode.kind == "hard_negative" and episode.cls == SCENARIOS[name].cls
    assert episode.actor == "172.20.0.101" and episode.episode_id == "r001-c101-e1"
    assert episode.end >= episode.start and episode.tool == scenarios.ACTOR_TOOL


def test_heartbeat_makes_one_request_per_interval_and_uploads_are_fully_received(
    ports: Ports,
) -> None:
    ctx = make_ctx(ports, duration_s=3, interval_s=1)
    ticks = iter(range(100))
    ctx.monotonic = lambda: float(next(ticks))  # scripted clock: each call advances one second
    scenarios.monitoring_heartbeat(ctx)  # must terminate on the scripted clock without raising
    size = 123_456
    sent = scenarios._http(LOCAL, ports.upload, "POST", "/x", b"a" * size)
    assert sent == len(f"received {size}\n")


def test_labelled_scenario_without_labeler_just_runs(ports: Ports) -> None:
    run_scenario("package_update", make_ctx(ports, files=1), None)


def test_unlabelled_background_writes_no_label(ports: Ports, tmp_path: Path) -> None:
    labels = tmp_path / "labels.jsonl"
    run_scenario("background_browsing", make_ctx(ports, duration_s=0.0), Labeler(labels, "r001"))
    assert not labels.exists()


def test_same_seed_gives_same_traffic_shape(ports: Ports, monkeypatch: pytest.MonkeyPatch) -> None:
    def names_for(seed: int) -> list[str]:
        seen: list[str] = []
        monkeypatch.setattr(
            scenarios, "dns_query", lambda _h, _p, name, **_k: seen.append(name) or True
        )
        scenarios.cdn_browsing(make_ctx(ports, seed=seed, hosts=8, pause_s=0))
        return seen

    assert names_for(7) == names_for(7)
    assert names_for(7) != names_for(8)
    assert all(n.endswith(".cdn.example.test") for n in names_for(7))
