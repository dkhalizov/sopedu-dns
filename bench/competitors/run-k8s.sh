#!/usr/bin/env bash
# The run.sh matrix on k3s: each server is a hostNetwork Pod pinned to NODE
# with 1 CPU / 512 MiB; dnsperf is an unconstrained Pod on CLIENT_NODE; the
# shared upstream (bench/upstream-mock, +UPSTREAM_DELAY_MS) and list server
# run as one hostNetwork Pod on UPSTREAM_NODE (default: the client node).
# Phases, inputs and the TSV/Markdown format come from phases.sh.
#
# Usage (see README for the one-time image imports):
#   NODE=<server-node> SSH_HOST=<server-ssh-host> NODE_IP=<server-node-ip> \
#   CLIENT_NODE=<client-node> CLIENT_SSH_HOST=<client-ssh-host> UPSTREAM_IP=<client-node-ip> \
#   ./run-k8s.sh [sopedu agh pihole blocky unbound dnsmasq pihole-lean]
#
# Everything runs in its own namespace (NS, default sopedu-bench; created here
# and deleted at the end). Optional: PHASES="hit sat" to run a subset,
# TWO_CLIENTS=1 to add the two-dnsperf-process saturation, OUTSTANDING=n.
# unbound and dnsmasq are neutral reference forwarders (no blocklists);
# pihole-lean is Pi-hole with the query log and database off.
#
# Requirements here: kubectl, ssh/scp to the nodes, dig, openssl.

set -euo pipefail
cd "$(dirname "$0")"

NODE=${NODE:?set NODE (Kubernetes node name for the server Pod)}
SSH_HOST=${SSH_HOST:-$NODE}
NODE_IP=${NODE_IP:?set NODE_IP (LAN address of NODE)}
CLIENT_NODE=${CLIENT_NODE:?set CLIENT_NODE (node for dnsperf and the upstream mock)}
CLIENT_SSH_HOST=${CLIENT_SSH_HOST:-$CLIENT_NODE}
UPSTREAM_NODE=${UPSTREAM_NODE:-$CLIENT_NODE}
UPSTREAM_SSH_HOST=${UPSTREAM_SSH_HOST:-$CLIENT_SSH_HOST}
UPSTREAM_IP=${UPSTREAM_IP:?set UPSTREAM_IP (address of the node running the upstream mock)}
PORT=${PORT:-15353}
NS=${NS:-sopedu-bench}
DURATION=${DURATION:-10}
RUNS=${RUNS:-3}
OUTSTANDING=${OUTSTANDING:-200}
TRANSPORTS=${TRANSPORTS:-"plain doh"}
UPSTREAM_DELAY_MS=${UPSTREAM_DELAY_MS:-10}
ROOT=$(cd ../.. && pwd)
HOT=${HOT:-$ROOT/bench/corpus/queries.txt}
LOCAL_RUN=$PWD/.run/k8s
LOCAL_INPUTS=$LOCAL_RUN/inputs
TARGET=$NODE_IP
DIG_TARGET=$NODE_IP
INPUTS=/data
PLAIN=$UPSTREAM_IP:5300
DOH=https://$UPSTREAM_IP:8443/dns-query
LISTS=http://$UPSTREAM_IP:8080
source ./phases.sh

servers=("$@")
[ ${#servers[@]} -gt 0 ] || servers=(sopedu agh pihole blocky unbound dnsmasq)
for cmd in kubectl ssh scp dig openssl; do
  command -v "$cmd" >/dev/null || { echo "$cmd not found" >&2; exit 1; }
done
[ -f "$HOT" ] || { echo "missing corpus: $HOT" >&2; exit 1; }
[ -d "$LISTS_DIR" ] || { echo "missing lists: $LISTS_DIR" >&2; exit 1; }

# Everything below runs in $NS, never in the kubeconfig's current namespace.
kubectl() { command kubectl -n "$NS" "$@"; }
ns_created=
while command kubectl get ns "$NS" -o jsonpath='{.status.phase}' 2>/dev/null | grep -q Terminating; do sleep 2; done
command kubectl get ns "$NS" >/dev/null 2>&1 || { command kubectl create ns "$NS" >/dev/null; ns_created=1; }

# `times` after dnsperf prints the children's user/system CPU; phases.sh turns
# it into "client cpu N%" so a CPU-bound client shows up in the results.
client_dnsperf() { kubectl exec bench-dnsperf -- bash -c 'dnsperf "$@"; r=$?; times > /tmp/.t; echo "CLIENT_TIMES $(tail -1 /tmp/.t)"; exit $r' _ "$@"; }

push_input() { scp -q "$LOCAL_INPUTS/$1" "$CLIENT_SSH_HOST:/tmp/sopedu-bench/inputs/$1"; }

# Pod-level cgroup v2 memory.peak plus max VmHWM / sum VmRSS of the Pod's
# processes, read on the server node (works for scratch images too).
mem_sample() {
  local uid
  uid=$(kubectl get pod "bench-$1" -o jsonpath='{.metadata.uid}')
  ssh "$SSH_HOST" "sudo sh -s" <<EOF
d=\$(find /sys/fs/cgroup -type d \( -name '*pod${uid}*' -o -name '*pod${uid//-/_}*' \) 2>/dev/null | head -1)
peak=\$(cat "\$d/memory.peak" 2>/dev/null || echo 0)
for p in \$(cat \$(find "\$d" -name cgroup.procs) 2>/dev/null); do
  awk '/^VmHWM:/ {h=\$2} /^VmRSS:/ {r=\$2} END {print h+0, r+0}' /proc/\$p/status 2>/dev/null
done | awk -v peak="\$peak" '{ if (\$1 > h) h = \$1; r += \$2 }
  END { printf "memory.peak %.1f MiB; max VmHWM / sum VmRSS %.1f / %.1f MiB", peak / 1048576, h / 1024, r / 1024 }'
EOF
}

# "usage_usec nr_periods nr_throttled epoch_s" of the server Pod's CPU cgroup, so
# phases.sh can report how busy (and how throttled) the 1-CPU server was.
server_cpu() {
  local uid
  uid=$(kubectl get pod "bench-$SERVER" -o jsonpath='{.metadata.uid}')
  ssh "$SSH_HOST" "sudo sh -s" <<EOF
d=\$(find /sys/fs/cgroup -type d -name '*pod${uid//-/_}*' 2>/dev/null | head -1)
awk '/^usage_usec/ {u=\$2} /^nr_periods/ {p=\$2} /^nr_throttled/ {t=\$2} END {printf "%d %d %d ", u, p, t}' "\$d/cpu.stat"
date +%s.%N
EOF
}

current=
cleanup() {
  [ -n "$current" ] && kubectl delete pod "bench-$current" --ignore-not-found --wait=false >/dev/null 2>&1
  kubectl delete pod bench-dnsperf bench-upstream --ignore-not-found --wait=false >/dev/null 2>&1 || true
  [ -n "$ns_created" ] && command kubectl delete ns "$NS" --wait=false >/dev/null 2>&1
  return 0
}
trap cleanup EXIT

# --- one-time setup: TLS, lists, inputs, upstream and client Pods
mkdir -p "$LOCAL_RUN"
"$ROOT/bench/mkcert.sh" "$LOCAL_RUN/tls" "IP:$UPSTREAM_IP"
make_inputs
for h in "$SSH_HOST" "$UPSTREAM_SSH_HOST" "$CLIENT_SSH_HOST"; do
  ssh "$h" 'sudo mkdir -p /tmp/sopedu-bench && sudo chown -R "$(id -u):$(id -g)" /tmp/sopedu-bench'
done
ssh "$SSH_HOST" 'mkdir -p /tmp/sopedu-bench/sopedu /tmp/sopedu-bench/agh /tmp/sopedu-bench/blocky /tmp/sopedu-bench/unbound /tmp/sopedu-bench/dnsmasq /tmp/sopedu-bench/numa'
for h in "$SSH_HOST" "$UPSTREAM_SSH_HOST"; do
  scp -qr "$LOCAL_RUN/tls" "$h:/tmp/sopedu-bench/"
done
scp -qr "$LISTS_DIR" "$UPSTREAM_SSH_HOST:/tmp/sopedu-bench/"
scp -qr "$LOCAL_INPUTS" "$CLIENT_SSH_HOST:/tmp/sopedu-bench/"

kubectl delete pod bench-upstream bench-dnsperf --ignore-not-found --wait=true >/dev/null
sed -e "s/UPSTREAM_NODE_NAME/$UPSTREAM_NODE/" -e "s/UPSTREAM_DELAY_MS/$UPSTREAM_DELAY_MS/" k8s/upstream.yaml | kubectl apply -f - >/dev/null
sed "s/CLIENT_NODE_NAME/$CLIENT_NODE/" k8s/dnsperf.yaml | kubectl apply -f - >/dev/null
kubectl wait --for=condition=Ready pod/bench-upstream pod/bench-dnsperf --timeout=180s >/dev/null

mkdir -p results
stamp=$(date +%Y%m%d-%H%M%S)
OUT=results/k8s-$stamp.tsv
printf 'server\ttransport\tphase\ttarget_qps\tachieved_qps\tsent\tlost\tp50_ms\tp99_ms\tp999_ms\tmax_ms\tmean_ms\trcodes\tnote\n' > "$OUT"

prepare_node() {
  local s=$1 up
  case "$s/$TRANSPORT" in
    sopedu/plain) up='[]' ;;
    sopedu/doh)   up="[\"$DOH\"]" ;;
    */plain)      up=$PLAIN ;;
    */doh)        up=$DOH ;;
  esac
  local sub=(-e "s#@UP@#$up#" -e "s#@PLAIN@#$PLAIN#" -e "s#@LISTS@#$LISTS#g" -e "s#@PORT@#$PORT#")
  case "$s" in
    sopedu) sed "${sub[@]}" configs/sopedu.toml | ssh "$SSH_HOST" 'cat > /tmp/sopedu-bench/sopedu/config.toml' ;;
    # AGH (root in the Pod) rewrites its config 0600 root:root, so a second transport cannot overwrite it.
    agh)    sed "${sub[@]}" configs/AdGuardHome.yaml | ssh "$SSH_HOST" 'sudo rm -f /tmp/sopedu-bench/agh/AdGuardHome.yaml; cat > /tmp/sopedu-bench/agh/AdGuardHome.yaml' ;;
    blocky) sed "${sub[@]}" configs/blocky.yml | ssh "$SSH_HOST" 'cat > /tmp/sopedu-bench/blocky/config.yml' ;;
    unbound) sed "${sub[@]}" -e "s#@PLAINAT@#${PLAIN/:/@}#" configs/unbound.conf | ssh "$SSH_HOST" 'cat > /tmp/sopedu-bench/unbound/unbound.conf' ;;
    dnsmasq) sed "${sub[@]}" -e "s|@PLAINHASH@|${PLAIN/:/#}|" configs/dnsmasq.conf | ssh "$SSH_HOST" 'cat > /tmp/sopedu-bench/dnsmasq/dnsmasq.conf' ;;
    numa) sed "${sub[@]}" configs/numa.toml | ssh "$SSH_HOST" 'cat > /tmp/sopedu-bench/numa/numa.toml' ;;
    pihole|pihole-lean) : ;;
    *) echo "unknown server: $s" >&2; exit 2 ;;
  esac
}

wait_ready() {
  kubectl wait --for=condition=Ready "pod/bench-$1" --timeout=180s >/dev/null
  for _ in $(seq 1 120); do
    dig @"$NODE_IP" -p "$PORT" ready.bench +time=1 +tries=1 2>/dev/null | grep -q 'status:' && return 0
    sleep 1
  done
  echo "$1 did not answer at $NODE_IP:$PORT" >&2
  kubectl logs "bench-$1" --tail=40 >&2 || true
  return 1
}

for TRANSPORT in $TRANSPORTS; do
  for SERVER in "${servers[@]}"; do
    if [ "$TRANSPORT" = doh ] && [[ "$SERVER" == pihole* || "$SERVER" == unbound || "$SERVER" == dnsmasq || "$SERVER" == numa ]]; then
      note_row skipped "$SERVER has no DoH upstream client in this harness"
      continue
    fi
    echo "== $SERVER ($TRANSPORT) on $NODE =="
    current=$SERVER
    kubectl delete pod "bench-$SERVER" --ignore-not-found --wait=true >/dev/null
    prepare_node "$SERVER"
    sed -e "s/NODE_NAME/$NODE/" -e "s/UPSTREAM_IP/$UPSTREAM_IP/" "k8s/$SERVER.yaml" | kubectl apply -f - >/dev/null
    wait_ready "$SERVER"
    if [[ "$SERVER" == pihole* ]]; then
      kubectl exec -i "bench-$SERVER" -- sh -s "$LISTS" < configs/pihole-lists.sh || note_row lists "gravity rebuild failed"
    fi
    run_matrix
    # A Pod that died during the run (OOM, crash) must be visible in the results.
    note_row pod-state "$(kubectl get pod "bench-$SERVER" -o jsonpath='{.status.phase} {range .status.containerStatuses[*]}{.state}{end}' 2>&1 | cut -c1-300)"
    [ -z "${DIAG:-}" ] || kubectl logs "bench-$SERVER" --tail="${DIAG}" >&2 2>&1 || true
    kubectl delete pod "bench-$SERVER" --wait=true >/dev/null
    current=
  done
done

{
  echo "# Competitor benchmark (k3s, server $NODE, client $CLIENT_NODE, upstream $UPSTREAM_NODE) $stamp"
  echo
  echo "Server Pod 1 CPU / 512 MiB, dnsperf Pod limit 2 CPUs; upstream +${UPSTREAM_DELAY_MS} ms; shared lists."
  echo "sopedu image: whatever sopedu-bench:amd64 the node holds; build it from a clean commit (README)."
  echo "$(provenance)"
  echo
  render_md
} | tee "results/k8s-$stamp.md"
echo "results: bench/competitors/results/k8s-$stamp.{tsv,md}"
echo "clean up: ssh $CLIENT_SSH_HOST 'rm -rf /tmp/sopedu-bench'; ssh $UPSTREAM_SSH_HOST 'rm -rf /tmp/sopedu-bench'; ssh $SSH_HOST 'rm -rf /tmp/sopedu-bench'"
