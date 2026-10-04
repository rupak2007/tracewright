#!/usr/bin/env bash
# P1 end-to-end check across the real compose containers (no mocks):
#   capture file -> API container: validate + SHA-256 + store under a UUID name (only uploads writer)
#   -> worker container (read-only uploads, no network): Zeek -> normalise -> profile + warnings
#   -> API container (read-only artifacts): read the results back.
# Usage: scripts/e2e_p1.sh <capture.pcap> [<invalid-file>]   (run from the repo root)
# Windows/Git Bash: run with MSYS_NO_PATHCONV=1 and Docker on PATH.
set -euo pipefail

PCAP="${1:?usage: e2e_p1.sh <capture.pcap> [<invalid-file>]}"
INVALID="${2:-}"
COMPOSE=(docker compose -f docker-compose.yml)
[ -f docker-compose.dev.yml ] && COMPOSE+=(-f docker-compose.dev.yml)

hostpath() { (cd "$(dirname "$1")" && { pwd -W 2>/dev/null || pwd; }) | sed "s|\$|/$(basename "$1")|"; }

STORE='
from pathlib import Path
from app.core.errors import IngestError
from app.ingest.storage import store_upload
try:
    with open("/in/upload.bin", "rb") as f:
        s = store_upload(f, Path("/data/uploads"), 500 * 1024 * 1024, original_name="capture.pcap")
    print(f"RESULT ok id={s.capture_id} format={s.info.format.value} sha256={s.info.sha256} bytes={s.info.size_bytes}")
except IngestError as e:
    print(f"RESULT rejected code={e.code}")
'

store() { # store <file> -> prints the RESULT line
  "${COMPOSE[@]}" run --rm --no-deps -T -v "$(hostpath "$1"):/in/upload.bin:ro" api python -c "$STORE" | grep '^RESULT'
}
field() { sed -E 's/.* '"$1"'=([^ ]*).*/\1/' <<<"$2"; }

echo "== 1. API container: validate + hash + store ($PCAP)"
RESULT="$(store "$PCAP")"; echo "$RESULT"
case "$RESULT" in "RESULT ok "*) ;; *) echo "upload unexpectedly rejected"; exit 1 ;; esac
ID="$(field id "$RESULT")"; EXT="$(field format "$RESULT")"; SHA="$(field sha256 "$RESULT")"

echo "== 2. Worker container: Zeek -> normalise -> profile (read-only uploads, no network)"
"${COMPOSE[@]}" run --rm --no-deps -T worker \
  python -m app.cli analyze "/data/uploads/$ID.$EXT" --out "/data/artifacts/$ID" 2>/dev/null | tail -1

echo "== 3. API container (read-only artifacts): read the results back"
"${COMPOSE[@]}" run --rm --no-deps -T api python -c "
import json, pathlib, sys
d = pathlib.Path('/data/artifacts/$ID')
status = json.loads((d / 'status.json').read_text())
profile = json.loads((d / 'profile.json').read_text())
print('files   :', sorted(p.name for p in d.iterdir()))
print('tables  :', sorted(p.name for p in (d / 'tables').iterdir()))
print('zeek    :', sorted(p.name for p in (d / 'zeek').iterdir()))
print('status  :', status['status'], '| stages(ms):', status['stage_ms'])
print('zeek ver:', profile['zeek_version'], '| packets:', profile['capture']['packets'],
      '| connections:', profile['connections'], '| rows:', profile['table_rows'])
print('warnings:', [(w['code'], w['severity']) for w in profile['warnings']])
ok = status['status'] == 'completed' and profile['file']['sha256'] == '$SHA'
print('sha256 recorded by API == sha256 in worker profile:', profile['file']['sha256'] == '$SHA')
sys.exit(0 if ok else 1)
"

if [ -n "$INVALID" ]; then
  echo "== 4. Rejected upload ($INVALID) must leave nothing in the uploads volume"
  REJ="$(store "$INVALID")"; echo "$REJ"
  case "$REJ" in "RESULT rejected "*) ;; *) echo "invalid upload was NOT rejected"; exit 1 ;; esac
  "${COMPOSE[@]}" run --rm --no-deps -T api sh -c 'ls /data/uploads | grep -c "\.part$" || true'
fi
echo "E2E OK"
