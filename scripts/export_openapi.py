"""Write the API's OpenAPI schema to frontend/openapi.json (input of `npm run gen:api`).

    python scripts/export_openapi.py [--check]

--check exits non-zero when the committed file differs from the live schema (used in CI so the
generated frontend types cannot drift from the backend).
"""

import argparse
import json
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "backend"))
for key, value in {"POSTGRES_DB": "x", "POSTGRES_USER": "x", "POSTGRES_PASSWORD": "x"}.items():
    os.environ.setdefault(key, value)

from app.api.main import create_app  # noqa: E402


def schema_text() -> str:
    return json.dumps(create_app().openapi(), indent=2, sort_keys=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    target = REPO / "frontend" / "openapi.json"
    text = schema_text()
    if args.check:
        current = target.read_text(encoding="utf-8") if target.exists() else ""
        if current.replace("\r\n", "\n") != text:
            print("frontend/openapi.json is out of date: run scripts/export_openapi.py", file=sys.stderr)
            return 1
        return 0
    target.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
