"""Fetch the pinned MITRE ATT&CK Enterprise STIX bundle (architecture §10). Run during setup, never in the worker.

    python scripts/fetch_attack.py            # download, verify against config/attack.yaml
    python scripts/fetch_attack.py --pin      # first fetch of a new version: record its SHA-256

The version, URL and expected SHA-256 live in config/attack.yaml. A download whose SHA-256 differs
from the pin is deleted and reported as an error: the bundle is the source of truth for mapping
validation and the knowledge cards, so it must be the exact file that was reviewed.
Standard library only; the file is stored outside git (data/attack/, gitignored).
"""

import argparse
import hashlib
import sys
import urllib.request
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
CONFIG = REPO / "config" / "attack.yaml"
CHUNK = 1024 * 1024


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(CHUNK):
            digest.update(block)
    return digest.hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pin", action="store_true", help="record the SHA-256 of the download")
    parser.add_argument("--config", type=Path, default=CONFIG)
    args = parser.parse_args(argv)
    cfg = yaml.safe_load(args.config.read_text(encoding="utf-8"))
    target = REPO / cfg["bundle_path"]
    target.parent.mkdir(parents=True, exist_ok=True)

    if not target.exists():
        print(f"downloading {cfg['bundle_url']}")
        partial = target.with_suffix(".part")
        with urllib.request.urlopen(cfg["bundle_url"], timeout=120) as response:  # noqa: S310
            with partial.open("wb") as out:
                while block := response.read(CHUNK):
                    out.write(block)
        partial.replace(target)
    digest = sha256_of(target)
    pinned = cfg.get("bundle_sha256")
    if args.pin and not pinned:
        text = args.config.read_text(encoding="utf-8")
        args.config.write_text(
            text.replace('bundle_sha256: ""', f'bundle_sha256: "{digest}"'), encoding="utf-8"
        )
        print(f"pinned {cfg['attack_version']} sha256={digest}")
        return 0
    if not pinned:
        print("config/attack.yaml has no bundle_sha256; re-run with --pin after review", file=sys.stderr)
        return 2
    if digest != pinned:
        target.unlink()
        print(f"SHA-256 mismatch: expected {pinned}, got {digest}; file removed", file=sys.stderr)
        return 1
    print(f"ok: {target.name} sha256={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
