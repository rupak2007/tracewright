"""SEC-02, SEC-07, SEC-08, SEC-09, SEC-10: the shipped configuration says what the docs claim.

These read the repository files (docker-compose.yml, Dockerfiles, Zeek site policy, tracked files),
so they are skipped inside the worker test image, which carries none of them. The live worker
sandbox is probed separately by scripts/check_worker_sandbox.sh.
"""

import re
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO = Path(__file__).resolve().parents[3]
COMPOSE = REPO / "docker-compose.yml"
pytestmark = pytest.mark.skipif(not COMPOSE.exists(), reason="repository files not available")


def compose() -> dict[str, Any]:
    return yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))  # type: ignore[no-any-return]


@pytest.mark.parametrize("service", ["worker", "api", "web", "ollama"])
def test_every_application_container_is_locked_down(service: str) -> None:
    spec = compose()["services"][service]
    assert spec["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in spec["security_opt"]
    if service != "ollama":  # the model server needs a writable model volume, not a read-only root
        assert spec["read_only"] is True
    if service in ("worker", "api"):
        assert spec["user"] == "10001:10001"


def test_the_worker_has_resource_limits_and_no_route_to_the_internet() -> None:
    cfg = compose()
    worker = cfg["services"]["worker"]
    assert {"mem_limit", "cpus", "pids_limit"} <= set(worker)
    assert worker["networks"] == ["internal"]  # the only network the worker joins ...
    assert cfg["networks"]["internal"] == {"internal": True}  # ... has no egress


def test_the_database_and_model_server_are_internal_only() -> None:
    services = compose()["services"]
    assert services["db"]["networks"] == ["internal"]
    assert services["ollama"]["networks"] == ["internal"] and services["ollama"]["profiles"] == [
        "llm"
    ]
    assert "ports" not in services["db"] and "ports" not in services["ollama"]


def test_only_the_api_and_web_join_the_edge_network() -> None:
    services = compose()["services"]
    joined = {n for n, s in services.items() if "edge" in s.get("networks", [])}
    assert joined == {"api", "web"}


def test_every_published_port_binds_loopback_only() -> None:
    files = [COMPOSE, REPO / "docker-compose.dev.yml"]
    published = []
    for path in files:
        for name, spec in yaml.safe_load(path.read_text(encoding="utf-8"))["services"].items():
            published += [(name, p) for p in spec.get("ports", [])]
    assert published, "the UI must be reachable"
    for name, port in published:
        assert str(port).startswith("127.0.0.1:"), (name, port)


def test_every_image_is_pinned_by_digest() -> None:
    for name, spec in compose()["services"].items():
        if "image" in spec:
            assert "@sha256:" in spec["image"], (name, spec["image"])
    dockerfiles = [REPO / "backend" / "Dockerfile.api", REPO / "backend" / "Dockerfile.worker"]
    dockerfiles.append(REPO / "frontend" / "Dockerfile")
    for path in dockerfiles:
        froms = re.findall(r"^FROM\s+(\S+)", path.read_text(encoding="utf-8"), re.MULTILINE)
        for ref in froms:
            if ref not in ("base",):  # a later stage of the same file
                assert "@sha256:" in ref, (path.name, ref)


def test_dependency_lockfiles_are_committed() -> None:
    assert (REPO / "backend" / "uv.lock").exists()
    assert (REPO / "frontend" / "package-lock.json").exists()
    assert "--frozen" in (REPO / "backend" / "Dockerfile.api").read_text(encoding="utf-8")


def test_zeek_never_captures_passwords_and_loads_only_stock_analyzers() -> None:
    policy = (REPO / "config" / "zeek" / "site.zeek").read_text(encoding="utf-8")
    assert re.search(r"redef\s+FTP::default_capture_password\s*=\s*F;", policy)
    assert re.search(r"redef\s+HTTP::default_capture_password\s*=\s*F;", policy)
    loads = re.findall(r"^@load\s+(\S+)", policy, re.MULTILINE)
    assert loads and all(item.startswith("base/") for item in loads)  # no packages, no local.zeek


def _tracked_files() -> list[Path]:
    done = subprocess.run(
        ["git", "ls-files", "-z"],  # noqa: S607
        capture_output=True,
        cwd=REPO,
        check=True,
        shell=False,
    )
    return [REPO / n for n in done.stdout.decode().split("\0") if n]


def test_no_secret_is_tracked_and_the_example_env_holds_placeholders_only() -> None:
    tracked = _tracked_files()
    names = {p.name for p in tracked}
    assert ".env" not in names and not any(n.endswith((".pem", ".key")) for n in names)
    patterns = [
        re.compile(r"sk-[A-Za-z0-9]{20,}"),
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        re.compile(r"AKIA[0-9A-Z]{16}"),
        re.compile(r"ghp_[A-Za-z0-9]{30,}"),
    ]
    for path in tracked:
        if path.suffix in {".png", ".ico", ".json", ".lock"} and path.stat().st_size > 400_000:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for pattern in patterns:
            assert not pattern.search(text), (path.relative_to(REPO), pattern.pattern)
    example = (REPO / ".env.example").read_text(encoding="utf-8")
    assert "dev-only" in example
    for line in example.splitlines():
        if line.startswith("LLM_API_KEY=") or line.startswith("API_TOKEN="):
            assert line.split("=", 1)[1].split("#")[0].strip() == "", line  # never a real value


def test_no_generated_data_is_tracked() -> None:
    bad = [
        p.relative_to(REPO)
        for p in _tracked_files()
        if p.suffix in {".pcap", ".pcapng", ".parquet", ".pkl", ".joblib"}
        or "data/" in p.relative_to(REPO).as_posix()[:5]
    ]
    assert not bad, bad
