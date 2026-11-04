#!/usr/bin/env bash
# Same-host comparison of sopedu-dns, AdGuard Home, Pi-hole and Blocky.
#
# Every server runs in Docker with 1 CPU / ${MEM_LIMIT:-512m}, is published on
# 127.0.0.1:$PORT, loads the same four blocklists from a local HTTP server and
# forwards to the same local upstream (bench/upstream-mock, fixed delay).
# TRANSPORTS picks the upstream transport: "plain" (UDP for everyone) and/or
# "doh" (DoH/h2 for sopedu, AdGuard Home and Blocky; Pi-hole has no DoH client
# and is skipped). Phases are in phases.sh: cold corpus, misses, blocked,
# open-loop hit latency at RATES, then closed-loop saturation.
#
# Usage:
#   ./run.sh                              # all four, plain + doh
#   TRANSPORTS=plain ./run.sh agh blocky
#   SOPEDU_REF=HEAD~1 ./run.sh sopedu     # build sopedu from another commit
#
# Requirements: docker compose, dnsperf >= 2.11 (latency histogram), dig,
# openssl. Corpus: gitignored bench/corpus/queries.txt and bench/corpus/lists/.

set -euo pipefail
cd "$(dirname "$0")"

PORT=${PORT:-15353}
DURATION=${DURATION:-10}
RUNS=${RUNS:-2}
OUTSTANDING=${OUTSTANDING:-200}
TRANSPORTS=${TRANSPORTS:-"plain doh"}
export UPSTREAM_DELAY_MS=${UPSTREAM_DELAY_MS:-10}
export PORT
ROOT=$(cd ../.. && pwd)
HOT=${HOT:-$ROOT/bench/corpus/queries.txt}
LOCAL_RUN=$PWD/.run
LOCAL_INPUTS=$LOCAL_RUN/inputs
TARGET=127.0.0.1
DIG_TARGET=127.0.0.1
INPUTS=$LOCAL_INPUTS
PLAIN=172.29.0.53:5300
DOH=https://172.29.0.53:8443/dns-query
LISTS=http://172.29.0.80:8080
source ./phases.sh

servers=("$@")
[ ${#servers[@]} -gt 0 ] || servers=(sopedu agh pihole blocky)

for cmd in dnsperf dig openssl docker; do
  command -v "$cmd" >/dev/null || { echo "$cmd not found" >&2; exit 1; }
done
[ -f "$HOT" ] || { echo "missing corpus: $HOT" >&2; exit 1; }
[ -d "$LISTS_DIR" ] || { echo "missing lists: $LISTS_DIR" >&2; exit 1; }
if pgrep -x dnsperf >/dev/null || lsof -nP -iUDP:"$PORT" >/dev/null 2>&1; then
  echo "another benchmark is running or port $PORT is busy; not starting" >&2
  exit 1
fi

client_dnsperf() { dnsperf "$@"; }

# cgroup memory.peak through a host-cgroupns helper, VmHWM/VmRSS through a
# helper in the server's PID namespace. Both are what the kernel accounted,
# unlike `docker stats`, which subtracts inactive file cache.
mem_sample() {
  local id peak procs
  id=$(docker inspect -f '{{.Id}}' "bench-$1")
  peak=$(docker run --rm --cgroupns=host -v /sys/fs/cgroup:/cg:ro python:3.14-alpine \
    sh -c "cat /cg/docker/$id/memory.peak 2>/dev/null || echo -" | awk '{ print ($1 == "-") ? "-" : sprintf("%.1f", $1 / 1048576) }')
  procs=$(docker run --rm --pid "container:bench-$1" python:3.14-alpine sh -c '
    for s in /proc/[0-9]*/status; do
      case "$(cat ${s%status}comm 2>/dev/null)" in sh|cat|awk) continue ;; esac
      awk "/^VmHWM:/ {h=\$2} /^VmRSS:/ {r=\$2} END {print h+0, r+0}" "$s" 2>/dev/null
    done' | awk '{ if ($1 > h) h = $1; r += $2 } END { printf "%.1f %.1f", h / 1024, r / 1024 }')
  echo "memory.peak ${peak} MiB; max VmHWM / sum VmRSS $(echo "$procs" | sed 's# # / #') MiB"
}

prepare() {
  local s=$1 up
  rm -rf ".run/$s"; mkdir -p ".run/$s"
  case "$s/$TRANSPORT" in
    sopedu/plain) up='[]' ;;
    sopedu/doh)   up="[\"$DOH\"]" ;;
    */plain)      up=$PLAIN ;;
    */doh)        up=$DOH ;;
  esac
  local sub=(-e "s#@UP@#$up#" -e "s#@PLAIN@#$PLAIN#" -e "s#@LISTS@#$LISTS#g" -e "s#@PORT@#53#")
  case "$s" in
    sopedu) sed "${sub[@]}" configs/sopedu.toml > .run/sopedu/config.toml ;;
    agh)    sed "${sub[@]}" configs/AdGuardHome.yaml > .run/agh/AdGuardHome.yaml ;;
    blocky) sed "${sub[@]}" configs/blocky.yml > .run/blocky/config.yml ;;
    pihole) : ;;
    *) echo "unknown server: $s" >&2; exit 2 ;;
  esac
}

stop_servers() {
  docker compose --profile sopedu --profile agh --profile pihole --profile blocky rm -sfv >/dev/null 2>&1 || true
  docker volume rm -f sopedu-bench_sopedu-state sopedu-bench_agh-work sopedu-bench_pihole-etc >/dev/null 2>&1 || true
}

wait_ready() {
  for _ in $(seq 1 180); do
    dig @127.0.0.1 -p "$PORT" ready.bench +time=1 +tries=1 2>/dev/null | grep -q 'status:' && return 0
    sleep 1
  done
  echo "$1 did not become ready" >&2
  docker compose --profile "$1" logs --tail=40 >&2 || true
  return 1
}

# A clean source tree for the sopedu image: git archive of SOPEDU_REF, never
# the working tree (other work in progress must not leak into the numbers).
export SOPEDU_SRC=$LOCAL_RUN/src
rm -rf "$SOPEDU_SRC"; mkdir -p "$SOPEDU_SRC"
git -C "$ROOT" archive "${SOPEDU_REF:-HEAD}" | tar -x -C "$SOPEDU_SRC"

mkdir -p results
stamp=$(date +%Y%m%d-%H%M%S)
OUT=results/$stamp.tsv
printf 'server\ttransport\tphase\ttarget_qps\tachieved_qps\tsent\tlost\tp50_ms\tp99_ms\tp999_ms\tmax_ms\tmean_ms\trcodes\tnote\n' > "$OUT"

"$ROOT/bench/mkcert.sh" .run/tls IP:172.29.0.53 DNS:upstream
chmod -R a+rX .run/tls
make_inputs
docker compose down -v --remove-orphans >/dev/null 2>&1 || true
docker compose --profile infra up -d --build
# Build sopedu before any timing so "ready" never includes an image build.
case " ${servers[*]} " in *" sopedu "*) docker compose --profile sopedu build sopedu ;; esac
trap 'docker compose --profile "*" down -v --remove-orphans >/dev/null 2>&1 || true' EXIT

for TRANSPORT in $TRANSPORTS; do
  for SERVER in "${servers[@]}"; do
    case "$SERVER" in adguard|adguardhome) SERVER=agh ;; esac
    if [ "$SERVER/$TRANSPORT" = pihole/doh ]; then
      note_row skipped "Pi-hole (FTL/dnsmasq) has no DoH upstream client"
      continue
    fi
    echo "== $SERVER ($TRANSPORT) =="
    stop_servers
    prepare "$SERVER"
    t0=$(python3 -c 'import time; print(time.time())')
    docker compose --profile "$SERVER" up -d "$SERVER"
    wait_ready "$SERVER"
    note_row ready "first answer $(python3 -c "import time; print(round(time.time() - $t0, 1))") s after compose up"
    if [ "$SERVER" = pihole ]; then
      docker exec bench-pihole sh /pihole-lists.sh "$LISTS" || note_row lists "gravity rebuild failed"
    fi
    run_matrix
  done
done
stop_servers

{
  echo "# Competitor benchmark $stamp"
  echo
  echo "Docker, 1 CPU / ${MEM_LIMIT:-512m} per server, 127.0.0.1:$PORT, local upstream +${UPSTREAM_DELAY_MS} ms, shared lists."
  echo "$(provenance)"
  echo
  render_md
} | tee "results/$stamp.md"
echo
echo "results: bench/competitors/results/$stamp.{tsv,md}"
