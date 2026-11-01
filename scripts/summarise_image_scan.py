"""Summarise Trivy JSON reports of the Tracewright images into a small committed result file.

    # per image (Windows Git Bash: MSYS_NO_PATHCONV=1), Trivy pinned by digest:
    docker save <image> -o data/scan/<name>.tar
    docker run --rm -v "<repo>/data/scan:/scan" -v "<repo>/data/scan/cache:/root/.cache" \
        aquasec/trivy:0.76.1@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c \
        image --input /scan/<name>.tar --scanners vuln --severity HIGH,CRITICAL \
        --format json --output /scan/<name>.json
    python scripts/summarise_image_scan.py --out eval/results/image-scan-v1 <name>...

Records, per image, how many HIGH/CRITICAL findings exist, how many have a fixed version available,
and which packages remain. Nothing is estimated: the numbers are counted from the reports.
"""

import argparse
import json
import sys
from collections import Counter
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def summarise(report: dict[str, object]) -> dict[str, object]:
    severity: Counter[str] = Counter()
    fixable: Counter[str] = Counter()
    packages: dict[str, dict[str, object]] = {}
    for result in report.get("Results", []):  # type: ignore[attr-defined]
        for vuln in result.get("Vulnerabilities") or []:
            severity[vuln["Severity"]] += 1
            entry = packages.setdefault(
                vuln["PkgName"], {"version": vuln["InstalledVersion"], "findings": 0, "fixable": False}
            )
            entry["findings"] = int(entry["findings"]) + 1  # type: ignore[call-overload]
            if vuln.get("FixedVersion"):
                fixable[vuln["Severity"]] += 1
                entry["fixable"] = True
    return {
        "findings_by_severity": dict(sorted(severity.items())),
        "findings_with_a_fix_available": dict(sorted(fixable.items())),
        "packages_with_findings": len(packages),
        "packages_with_a_fix_available": sorted(p for p, e in packages.items() if e["fixable"]),
        "packages_without_a_fix": sorted(p for p, e in packages.items() if not e["fixable"]),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0] if __doc__ else "")
    parser.add_argument("names", nargs="+")
    parser.add_argument("--in-dir", type=Path, default=REPO / "data" / "scan")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--trivy", default="0.76.1")
    args = parser.parse_args(argv)
    images = {}
    for name in args.names:
        path = args.in_dir / f"{name}.json"
        if not path.exists():
            print(f"missing report {path}", file=sys.stderr)
            return 2
        images[name] = summarise(json.loads(path.read_text(encoding="utf-8")))
    args.out.mkdir(parents=True, exist_ok=True)
    payload = {
        "scanner": f"trivy {args.trivy}",
        "scope": "OS and language packages only (--scanners vuln), HIGH and CRITICAL",
        "generated_at": datetime.now(UTC).isoformat(),
        "images": images,
    }
    (args.out / "summary.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    for name, data in images.items():
        print(name, data["findings_by_severity"], "fixable:", data["findings_with_a_fix_available"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
