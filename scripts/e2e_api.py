"""End-to-end check of the running stack over HTTP (plan P6): upload -> poll -> incidents -> evidence
-> slice -> download -> feedback -> report -> delete.

    docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build
    python scripts/e2e_api.py <capture.pcap> [--base http://127.0.0.1:8000] [--token TOKEN]

Standard library only. Exits non-zero (with the failing step) on the first problem. The capture is
whatever file you give it: this script generates no traffic.
"""

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any


class Client:
    def __init__(self, base: str, token: str | None) -> None:
        self.base = base.rstrip("/") + "/api/v1"
        self.headers = {"Authorization": f"Bearer {token}"} if token else {}

    def call(
        self, method: str, path: str, body: bytes | None = None, headers: dict[str, str] | None = None
    ) -> tuple[int, dict[str, str], bytes]:
        request = urllib.request.Request(  # noqa: S310
            self.base + path, data=body, method=method, headers={**self.headers, **(headers or {})}
        )
        try:
            with urllib.request.urlopen(request, timeout=300) as response:  # noqa: S310
                return response.status, dict(response.headers), response.read()
        except urllib.error.HTTPError as err:
            return err.code, dict(err.headers), err.read()

    def json(self, method: str, path: str, payload: object = None) -> Any:
        body = None if payload is None else json.dumps(payload).encode()
        status, _, data = self.call(method, path, body, {"Content-Type": "application/json"})
        if status >= 400:
            raise SystemExit(f"{method} {path} -> {status}: {data[:200]!r}")
        return json.loads(data) if data else None


def upload(client: Client, path: Path) -> str:
    boundary = uuid.uuid4().hex
    head = (
        f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{path.name}"\r\n'
        "Content-Type: application/octet-stream\r\n\r\n"
    ).encode()
    body = head + path.read_bytes() + f"\r\n--{boundary}--\r\n".encode()
    status, _, data = client.call(
        "POST", "/investigations", body, {"Content-Type": f"multipart/form-data; boundary={boundary}"}
    )
    if status != 202:
        raise SystemExit(f"upload -> {status}: {data[:200]!r}")
    return str(json.loads(data)["id"])


def step(message: str) -> None:
    print(f"- {message}", flush=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("--base", default="http://127.0.0.1:8000")
    parser.add_argument("--token")
    parser.add_argument("--timeout", type=int, default=900)
    args = parser.parse_args(argv)
    c = Client(args.base, args.token)

    health = c.json("GET", "/health")
    step(f"health: {health}")
    inv = upload(c, args.capture)
    step(f"uploaded {args.capture.name} -> investigation {inv}")
    deadline = time.monotonic() + args.timeout
    while True:
        detail = c.json("GET", f"/investigations/{inv}")
        if detail["status"] in ("completed", "failed"):
            break
        if time.monotonic() > deadline:
            raise SystemExit(f"timed out in stage {detail['stage']}")
        time.sleep(2)
    step(f"analysis {detail['status']} (stage {detail['stage']}), stage_ms {detail['stage_ms']}")
    if detail["status"] != "completed":
        raise SystemExit(f"analysis failed: {detail['error_code']} {detail['error_message']}")

    incidents = c.json("GET", f"/investigations/{inv}/incidents")
    step(f"{len(incidents)} incident(s): " + ", ".join(f"{i['local_id']} {i['severity_label']}" for i in incidents))
    if incidents:
        top = c.json("GET", f"/incidents/{incidents[0]['id']}")
        evidence = c.json("GET", f"/incidents/{top['id']}/evidence?limit=5")
        step(f"top incident {top['local_id']}: {len(top['findings'])} finding(s), evidence total {evidence['total']}")
        finding = top["findings"][0]["id"]
        slice_id = c.json("POST", f"/findings/{finding}/slice")["slice_id"]
        for _ in range(120):
            sl = c.json("GET", f"/slices/{slice_id}")
            if sl["status"] in ("done", "failed"):
                break
            time.sleep(1)
        step(f"slice {slice_id}: {sl['status']} packets={sl['packets']} size={sl['size_bytes']} {sl['error'] or ''}")
        if sl["status"] == "done":
            status, headers, data = c.call("GET", f"/slices/{slice_id}/download")
            if status != 200 or len(data) != sl["size_bytes"]:
                raise SystemExit("slice download does not match")
            step(f"downloaded {len(data)} bytes ({headers.get('Content-Type')})")
        fb = c.json("POST", f"/findings/{finding}/feedback", {"label": "expected_benign", "note": "e2e"})
        step(f"feedback stored: {fb['label']}")
        for fmt in ("md", "html"):
            status, _, data = c.call("GET", f"/incidents/{top['id']}/report?format={fmt}")
            if status != 200 or b"Limitations" not in data:
                raise SystemExit(f"{fmt} report failed")
            step(f"{fmt} report: {len(data)} bytes")
    status, _, _ = c.call("DELETE", f"/investigations/{inv}")
    if status != 204:
        raise SystemExit(f"delete -> {status}")
    status, _, _ = c.call("GET", f"/investigations/{inv}")
    step(f"deleted; read after delete -> {status}")
    return 0 if status == 404 else 1


if __name__ == "__main__":
    sys.exit(main())
