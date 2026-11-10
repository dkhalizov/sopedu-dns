# Shared measurement phases for run.sh (Docker) and run-k8s.sh (k3s).
# Sourced, not executed. The caller defines:
#   TARGET            server address as seen by the dnsperf client
#   DIG_TARGET        server address as seen from this machine (dig checks)
#   INPUTS            directory holding the generated inputs, as seen by dnsperf
#   client_dnsperf    runs "dnsperf ARGS..." on the client, prints its output
#   mem_sample NAME   prints "peak_mib hwm_mib rss_mib" (cgroup memory.peak,
#                     max VmHWM, sum VmRSS); "-" for anything unreadable
#
# Every phase appends one TSV row:
#   server transport phase target_qps achieved_qps sent lost p50 p99 p99.9 max_ms mean_ms rcodes note
# rcodes is dnsperf's "Response codes" line, e.g. NOERROR=7500,NXDOMAIN=2: a
# fast server that answers SERVFAIL/REFUSED shows up there, not in qps.
#
# Optional caller hooks / env:
#   PHASES            space-separated subset of: cold miss blocked hit sat
#                     (default: all). The primer runs when hit or sat is on.
#   REFERENCE_SERVERS servers without blocklists (unbound dnsmasq): the list
#                     wait and the blocked phase are skipped for them.
#   push_input FILE   copies $LOCAL_INPUTS/FILE to where dnsperf reads $INPUTS
#                     (k3s only; with Docker the directory is already shared).

ROOT=${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}
LISTS_DIR=${LISTS_DIR:-$ROOT/bench/corpus/lists}
RATES=${RATES:-"50 500 5000"}
RATE_SECONDS=${RATE_SECONDS:-15}
COLD_RATE=${COLD_RATE:-500}
MISS_RATE=${MISS_RATE:-200}
PHASES=${PHASES:-"cold miss blocked hit sat"}
REFERENCE_SERVERS=${REFERENCE_SERVERS:-"unbound dnsmasq"}

# Inputs are written once per run into $LOCAL_INPUTS (gitignored .run/).
# hot.txt: every distinct (name, qtype) of the private corpus in first-seen
# order; blocked.txt: 5,000 plain `||name^` rules of the shared lists;
# miss-*.txt: synthetic never-cached names (unique per server and transport).
make_inputs() {
  mkdir -p "$LOCAL_INPUTS"
  awk '!seen[$1" "$2]++' "$HOT" > "$LOCAL_INPUTS/hot.txt"
  cp "$HOT" "$LOCAL_INPUTS/queries.txt"
  awk '/^\|\|[a-z0-9.-]+\.[a-z0-9-]+\^$/ { print substr($0, 3, length($0) - 3) " A"; if (++n == 5000) exit }' \
    "$LISTS_DIR"/*.txt > "$LOCAL_INPUTS/blocked.txt"
  awk 'NR <= 300 { print $1 }' "$LOCAL_INPUTS/blocked.txt" > "$LOCAL_INPUTS/blocked-sample.txt"
  local n=$(( MISS_RATE * RATE_SECONDS * 2 + 1000 ))
  for s in sopedu agh pihole pihole-lean blocky unbound dnsmasq numa; do
    for t in plain doh; do
      awk -v n="$n" -v p="$s$t" 'BEGIN { for (i = 0; i < n; i++) printf "m%d.%s.miss.bench A\n", i, p }' \
        > "$LOCAL_INPUTS/miss-$s-$t.txt"
    done
  done
}

# Fraction of a 300-name sample of list rules the server blocks. The mock
# upstream answers every A with 192.0.2.1, so any other answer is a block.
block_coverage() {
  local allowed
  allowed=$(dig @"$DIG_TARGET" -p "$PORT" +short +time=2 +tries=1 -f "$LOCAL_INPUTS/blocked-sample.txt" 2>/dev/null \
    | grep -c '^192\.0\.2\.1$' || true)
  echo $(( (300 - allowed) * 100 / 300 ))
}

# A name the lists cannot contain must still resolve through the upstream;
# otherwise "blocked" would also count REFUSED/SERVFAIL as blocks.
control_ok() {
  dig @"$DIG_TARGET" -p "$PORT" +short +time=2 +tries=1 control.bench A 2>/dev/null | grep -q '^192\.0\.2\.1$'
}

wait_lists() {
  local t0=$SECONDS
  while [ $(( SECONDS - t0 )) -lt "${LIST_TIMEOUT:-240}" ]; do
    [ "$(block_coverage)" -ge 50 ] && { echo $(( SECONDS - t0 )); return 0; }
    sleep 2
  done
  echo "timeout"
}

# Parses one dnsperf output file into the TSV columns after "phase".
parse_dnsperf() {
  awk -v target="$2" '
    /Queries sent:/        { sent = $3 }
    /Queries lost:/        { lost = $3 }
    /Queries per second:/  { qps = $4 }
    /Average Latency/      { mean = $4 * 1000; v = $NF; gsub(/[()]/, "", v); max = v * 1000 }
    /^[[:space:]]*[0-9.]+ - [0-9.]+:/ { hi = $3; sub(/:$/, "", hi); k++; his[k] = hi; cnt[k] = $4; total += $4 }
    END {
      # Buckets are sorted by bound before taking percentiles.
      for (i = 1; i <= k; i++) for (j = i + 1; j <= k; j++) if (his[j] + 0 < his[i] + 0) {
        t = his[i]; his[i] = his[j]; his[j] = t; t = cnt[i]; cnt[i] = cnt[j]; cnt[j] = t }
      split("0.5 0.99 0.999", ps, " ")
      for (x = 1; x <= 3; x++) {
        cum = 0; p[x] = "-"
        for (i = 1; i <= k; i++) { cum += cnt[i]; if (total && cum >= ps[x] * total) { p[x] = sprintf("%.3f", his[i] * 1000); break } }
      }
      printf "%s\t%.0f\t%d\t%d\t%s\t%s\t%s\t%.3f\t%.3f", target, qps, sent, lost, p[1], p[2], p[3], max, mean
    }' "$1"
}

# "NOERROR 571372 (70.96%), NXDOMAIN 233821 (29.04%)" -> NOERROR=571372,NXDOMAIN=233821
parse_rcodes() {
  awk '/Response codes:/ {
    sub(/^.*Response codes:[[:space:]]*/, ""); n = split($0, a, /, */)
    for (i = 1; i <= n; i++) { split(a[i], f, " "); if (f[1] != "") out = out (out ? "," : "") f[1] "=" f[2] }
  } END { print (out ? out : "none") }' "$1"
}

# Client CPU use as a percentage of one core, from the "CLIENT_TIMES u s" line
# that the k3s client wrapper appends (bash `times`: children user/system).
# dnsperf runs a sender and a receiver thread per -T, so 100 is not a ceiling.
client_cpu() {
  awk '/Run time \(s\):/ { rt = $4 }
    /^CLIENT_TIMES/ { t = 0; for (i = 2; i <= 3; i++) { split($i, m, /[ms]/); t += m[1] * 60 + m[2] } }
    END { if (rt > 0 && t > 0) printf "client cpu %.0f%%", 100 * t / rt }' "$1"
}

# phase NAME TARGET_QPS NOTE dnsperf-args...
phase() {
  local name=$1 target=$2 note=$3; shift 3
  local file="$LOCAL_RUN/$SERVER-$TRANSPORT-$name.out"
  local c0= c1= srv=
  [ "$target" = - ] && type server_cpu >/dev/null 2>&1 && c0=$(server_cpu 2>/dev/null)
  client_dnsperf -s "$TARGET" -p "$PORT" -t 5 -O latency-histogram "$@" > "$file" 2>&1 || true
  if [ -n "$c0" ]; then
    c1=$(server_cpu 2>/dev/null)
    # window includes ~1-2 s of dnsperf start/stop, so cpu% is a slight underestimate
    srv=$(awk -v a="$c0" -v b="$c1" 'BEGIN { split(a, x, " "); split(b, y, " "); dt = y[4] - x[4]; dp = y[2] - x[2]
      if (dt > 0) printf "server cpu %.0f%%, throttled %.0f%% of periods", 100 * (y[1] - x[1]) / 1e6 / dt, (dp > 0 ? 100 * (y[3] - x[3]) / dp : 0) }')
  fi
  local cpu; cpu=$(client_cpu "$file")
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$SERVER" "$TRANSPORT" "$name" "$(parse_dnsperf "$file" "$target")" \
    "$(parse_rcodes "$file")" "${note}${cpu:+; $cpu}${srv:+; $srv}" | tee -a "$OUT"
}

note_row() {
  printf '%s\t%s\t%s\t\t\t\t\t\t\t\t\t\t\t%s\n' "$SERVER" "$TRANSPORT" "$1" "$2" | tee -a "$OUT"
}

is_reference() { case " $REFERENCE_SERVERS " in *" $SERVER "*) return 0 ;; esac; return 1; }
want() { case " $PHASES " in *" $1 "*) return 0 ;; esac; return 1; }

# hot-allowed.txt: the corpus names the blocking server does NOT block. sopedu
# answers blocked names with NXDOMAIN, so one pipelined pass through it (classify.py) splits
# the corpus (about a third of the queries of the corpus are blocked by the shared lists).
# The unfiltered reference servers and the blocking servers can then be loaded
# with a stream that is 100% cache hits. Only derived from sopedu.
make_allowed() {
  if [ "$SERVER" = sopedu ] && [ ! -s "$LOCAL_INPUTS/hot-allowed.txt" ]; then
    python3 "$(dirname "${BASH_SOURCE[0]}")/classify.py" "$DIG_TARGET" "$PORT" < "$LOCAL_INPUTS/hot.txt" \
      > "$LOCAL_INPUTS/hot-allowed.txt"
  fi
  # hot-cacheable.txt: the unblocked A/AAAA names only. dnsmasq (so Pi-hole) does
  # not cache HTTPS records (24% of the corpus's distinct names), so on the
  # whole corpus it forwards a quarter of the stream upstream however big its cache.
  [ -s "$LOCAL_INPUTS/hot-allowed.txt" ] && awk '$2 == "A" || $2 == "AAAA"' "$LOCAL_INPUTS/hot-allowed.txt" > "$LOCAL_INPUTS/hot-cacheable.txt"
  if type push_input >/dev/null 2>&1; then push_input hot-allowed.txt; push_input hot-cacheable.txt; fi
  return 0
}

# The whole matrix for one started server. Order matters: the cold corpus run
# starts from an empty cache, and the hit-rate runs come after a priming pass.
run_matrix() {
  local lists_s coverage
  if is_reference; then
    note_row lists "reference server, no blocklists; control name $(control_ok && echo resolves || echo FAILS)"
  else
    lists_s=$(wait_lists)
    coverage=$(block_coverage)
    note_row lists "ready+lists ${lists_s}s; blocks ${coverage}% of a 300-rule sample; control name $(control_ok && echo resolves || echo FAILS)"
  fi
  note_row mem-idle "$(mem_sample "$SERVER")"

  # Realistic cold start: the time-ordered corpus from its first line at a
  # fixed rate. Misses cost the upstream's fixed delay; repeats hit.
  want cold && phase cold-corpus "$COLD_RATE" "time-ordered corpus from empty cache" \
    -d "$INPUTS/queries.txt" -l "$RATE_SECONDS" -Q "$COLD_RATE" -q 10000 -c 1 -T 1
  # Pure misses: never-cached synthetic names. Subtract UPSTREAM_DELAY_MS.
  want miss && phase miss "$MISS_RATE" "unique names, upstream ${UPSTREAM_DELAY_MS} ms" \
    -d "$INPUTS/miss-$SERVER-$TRANSPORT.txt" -l "$RATE_SECONDS" -Q "$MISS_RATE" -q 10000 -c 1 -T 1
  want blocked && ! is_reference && phase blocked 500 "list rules" \
    -d "$INPUTS/blocked.txt" -l "$RATE_SECONDS" -Q 500 -q 10000 -c 1 -T 1
  if want hit || want sat; then
    make_allowed
    # Prime every distinct corpus name, then open-loop hit latency.
    # Prime under the per-client upstream cap (upstream_inflight_per_client = 64,
    # O7): a single client above it gets TC=1, which dnsperf does not retry.
    client_dnsperf -s "$TARGET" -p "$PORT" -d "$INPUTS/hot.txt" -n 1 -q 50 -t 5 > /dev/null 2>&1 || true
  fi
  local q
  want hit && for q in $RATES; do
    phase "hit-$q" "$q" "warm, fixed rate" -d "$INPUTS/hot.txt" -l "$RATE_SECONDS" -Q "$q" -q 10000 \
      -c "$([ "$q" -le 500 ] && echo 1 || echo 4)" -T 1
  done
  # Saturation (closed loop at OUTSTANDING). sat-udp: the whole corpus (about
  # 29% of it blocked for the blocking servers); sat-allowed: only names that
  # are not blocked, so every answer is a cache hit; sat-cacheable: unblocked A/AAAA names only (what dnsmasq can cache); sat-allowed-x2: the same
  # with two dnsperf processes at once (qps summed), to see whether the client
  # is the limit; sat-tcp: the whole corpus over TCP.
  local i
  if want sat; then
    for i in $(seq 1 "$RUNS"); do
      phase "sat-udp-$i" - "closed loop q$OUTSTANDING, whole corpus" -d "$INPUTS/hot.txt" -l "$DURATION" -q "$OUTSTANDING" -c 4 -T 1
    done
    if [ -s "$LOCAL_INPUTS/hot-allowed.txt" ]; then
      for i in $(seq 1 "$RUNS"); do
        phase "sat-allowed-$i" - "closed loop q$OUTSTANDING, unblocked names only" -d "$INPUTS/hot-allowed.txt" -l "$DURATION" -q "$OUTSTANDING" -c 4 -T 1
      done
      for i in $(seq 1 "$RUNS"); do
        phase "sat-cacheable-$i" - "closed loop q$OUTSTANDING, unblocked A/AAAA only" -d "$INPUTS/hot-cacheable.txt" -l "$DURATION" -q "$OUTSTANDING" -c 4 -T 1
      done
      [ -n "${TWO_CLIENTS:-}" ] && phase_two "sat-allowed-x2" -d "$INPUTS/hot-allowed.txt" -l "$DURATION" -q "$OUTSTANDING" -c 4 -T 1
    fi
    phase sat-tcp - "closed loop q$OUTSTANDING, whole corpus" -d "$INPUTS/hot.txt" -l "$DURATION" -q "$OUTSTANDING" -c 4 -T 1 -m tcp
  fi
  note_row mem-peak "$(mem_sample "$SERVER"); control name $(control_ok && echo resolves || echo FAILS)"
}

# Two dnsperf processes in parallel; one TSV row with the summed rate and the
# worse p99. Each process has its own -c clients, so the server sees 2x the
# source ports and 2x the outstanding queries.
phase_two() {
  local name=$1; shift
  local f1="$LOCAL_RUN/$SERVER-$TRANSPORT-$name-a.out" f2="$LOCAL_RUN/$SERVER-$TRANSPORT-$name-b.out"
  client_dnsperf -s "$TARGET" -p "$PORT" -t 5 -O latency-histogram "$@" > "$f1" 2>&1 &
  local p1=$!
  client_dnsperf -s "$TARGET" -p "$PORT" -t 5 -O latency-histogram "$@" > "$f2" 2>&1 || true
  wait "$p1" || true
  local row c1 c2
  c1=$(client_cpu "$f1"); c2=$(client_cpu "$f2")
  # fields of parse_dnsperf: target qps sent lost p50 p99 p99.9 max mean
  row=$(awk -v a="$(parse_dnsperf "$f1" -)" -v b="$(parse_dnsperf "$f2" -)" 'BEGIN {
    split(a, x, "\t"); split(b, y, "\t"); OFS = "\t"
    print "-", sprintf("%.0f", x[2] + y[2]), x[3] + y[3], x[4] + y[4],
      (x[5] > y[5] ? x[5] : y[5]), (x[6] > y[6] ? x[6] : y[6]), (x[7] > y[7] ? x[7] : y[7]),
      (x[8] > y[8] ? x[8] : y[8]), sprintf("%.3f", (x[9] + y[9]) / 2) }')
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$SERVER" "$TRANSPORT" "$name" "$row" \
    "$(parse_rcodes "$f1") | $(parse_rcodes "$f2")" "two dnsperf processes, qps summed, worst percentiles; $c1 / $c2" | tee -a "$OUT"
}

render_md() {
  echo "| server | transport | phase | target qps | achieved | sent | lost | p50 ms | p99 ms | p99.9 ms | max ms | reply codes | note |"
  echo "|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---|---|"
  awk -F'\t' 'NR > 1 { printf "| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n",
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $13, $14 }' "$OUT"
}

provenance() {
  local ref=${SOPEDU_REF:-HEAD}
  echo "sopedu source: $(git -C "$ROOT" rev-parse "$ref") (git archive of $ref, clean tree);" \
    "repo HEAD $(git -C "$ROOT" rev-parse --short HEAD), $(git -C "$ROOT" status --short src | wc -l | tr -d ' ') dirty src files (not built)"
}
