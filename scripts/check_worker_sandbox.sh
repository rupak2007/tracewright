#!/usr/bin/env bash
# Verifies the worker sandbox claims from architecture §18/§19 by probing a running worker container.
# Each check must observe the *restriction*; any check that does not fails the script.
# Usage: scripts/check_worker_sandbox.sh   (from the repo root; needs `docker compose` and a built image)
set -uo pipefail

COMPOSE=(docker compose -f docker-compose.yml)
[ -f docker-compose.dev.yml ] && COMPOSE+=(-f docker-compose.dev.yml)
fail=0

probe() { # probe <description> <python code that must exit 0 when the restriction holds>
  local desc="$1" code="$2"
  if "${COMPOSE[@]}" run --rm -T --no-deps worker python -c "$code"; then
    echo "PASS  $desc"
  else
    echo "FAIL  $desc"
    fail=1
  fi
}

probe "runs as non-root (uid != 0, uid == 10001)" \
  'import os,sys; sys.exit(0 if os.getuid()==10001 and os.getgid()==10001 else 1)'

probe "root filesystem is read-only" \
  'import sys
try:
    open("/should_not_exist","w")
except OSError:
    sys.exit(0)
sys.exit(1)'

probe "all capabilities dropped (CapEff == 0) and no_new_privs set" \
  'import sys
s=dict(l.split(":\t") for l in open("/proc/self/status").read().splitlines() if ":\t" in l)
sys.exit(0 if int(s["CapEff"],16)==0 and s["NoNewPrivs"].strip()=="1" else 1)'

probe "no DNS resolution of an external name" \
  'import socket,sys
try:
    socket.getaddrinfo("example.com",443)
except OSError:
    sys.exit(0)
sys.exit(1)'

probe "no TCP connection to a public IP (1.1.1.1:443)" \
  'import socket,sys
s=socket.socket(); s.settimeout(5)
try:
    s.connect(("1.1.1.1",443))
except OSError:
    sys.exit(0)
sys.exit(1)'

probe "uploads volume is read-only" \
  'import sys
try:
    open("/data/uploads/x","w")
except OSError:
    sys.exit(0)
sys.exit(1)'

probe "PID and memory limits are applied (cgroup pids.max / memory.max are not unlimited)"   'import sys
def limit(name):
    try:
        return open("/sys/fs/cgroup/" + name).read().strip()
    except OSError:
        return "max"
sys.exit(0 if limit("pids.max") != "max" and limit("memory.max") != "max" else 1)'

probe "the Docker socket is not mounted in the worker"   'import os,sys; sys.exit(1 if os.path.exists("/var/run/docker.sock") else 0)'

# Positive control: the sandbox must not block what the worker legitimately needs.
probe "positive control: can write to the artifacts volume" \
  'import os,sys,tempfile
with tempfile.NamedTemporaryFile(dir="/data/artifacts") as f: f.write(b"ok")
sys.exit(0)'

exit $fail
