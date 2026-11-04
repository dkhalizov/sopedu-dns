# Competitor benchmark

sopedu-dns against AdGuard Home, Pi-hole and Blocky with the same resource
limits, blocklists, upstream and client.

## What is held equal

| Factor | How |
|---|---|
| CPU / memory | every server 1 CPU, 512 MiB (`MEM_LIMIT`), no swap (`x-resources` in `compose.yaml`; k8s Pod limits). AdGuard Home with the shared lists is OOM-killed at 256 MiB |
| Blocklists | the same four files (`bench/corpus/lists/filter_{1,24,27,51}.txt`, ~744k lines) served over HTTP by a local `lists` container; Pi-hole loads them through `configs/pihole-lists.sh` (gravity) |
| Upstream | one local `upstream` container (`bench/upstream-mock`): plain UDP/TCP `:5300` and DoH over HTTP/2+TLS `:8443`, fixed added delay `UPSTREAM_DELAY_MS` (default 10 ms), synthetic answers (A = 192.0.2.1, TTL 300). No Internet in the measured path |
| Transport | `TRANSPORTS="plain doh"`: plain UDP for all four, then DoH for sopedu/AGH/Blocky (Pi-hole has no DoH client and is reported as skipped). The throwaway CA is trusted through `SSL_CERT_FILE` |
| sopedu source | built from `git archive $SOPEDU_REF` (default `HEAD`) into `.run/src`, never the working tree; the results print the commit |
| Memory | cgroup v2 `memory.peak` of the container/Pod plus max `VmHWM` / sum `VmRSS` of its processes. Not `docker stats` working set |

Cache sizes are each product's default (sopedu 20k entries / 8 MiB, AGH
8 MiB, Blocky 20k items, Pi-hole 10k). Each one holds the whole hot set.

## Phases (`phases.sh`, same for Docker and k3s)

| Phase | Load | Measures |
|---|---|---|
| `ready`, `lists` | none | time to first answer; seconds until ≥50% of a 300-rule sample is blocked, and the final blocked share (shows the lists are loaded) |
| `cold-corpus` | open loop `-Q 500`, private time-ordered corpus from line 1, empty cache | first-time misses mixed with repeats |
| `miss` | open loop `-Q 200`, never-cached synthetic names | miss path; subtract `UPSTREAM_DELAY_MS` for server overhead |
| `blocked` | open loop `-Q 500`, 5,000 list rules | blocked answer with the four lists loaded (~516k unique rules) |
| `hit-50/500/5000` | open loop `-Q`, every distinct corpus name, primed | hit latency at home, busy and stress rates |
| `sat-udp-N`, `sat-tcp` | closed loop, `OUTSTANDING` in flight, whole corpus | saturation qps. The shared lists block about 29% of the corpus, so this is cache hits plus rule blocks |
| `sat-allowed-N` | same, only corpus names the lists do not block (`hot-allowed.txt`, derived once from sopedu's NXDOMAINs) | pure cache hits; the stream to compare the unfiltered reference servers on |
| `sat-allowed-x2` (`TWO_CLIENTS=1`) | two dnsperf processes at once, qps summed | checks whether the client is the limit |
| `mem-idle`, `mem-peak` | none | memory as above |

Latency phases use `-Q` with `-q 10000`: dnsperf sends on its own schedule
and does not wait for replies, so there is no coordinated omission while
`achieved` equals `target`. Percentiles come from dnsperf's latency
histogram (2.11+). `lost` counts queries with no answer within 5 s,
including those still in flight when a closed-loop phase stops.

Every row has dnsperf's reply-code counts (`rcodes`, e.g. `NOERROR=7500,NXDOMAIN=2`).
Closed-loop rows also have the client's CPU use (`client cpu N%`, percent of
one core; dnsperf runs a sender and a receiver thread, so 100 is not a limit).
SERVFAIL and REFUSED answers count toward qps; check `rcodes`.
`PHASES="hit sat"` runs a subset.

Reference servers (k3s only):

- `unbound`: forwarder, 1 thread, cache on, no blocking.
- `dnsmasq`: cache on, no blocklists, no log.
- `pihole-lean`: Pi-hole with the query log, database and per-query storage off.

`unbound` and `dnsmasq` are neutral baselines. dnsmasq (and so Pi-hole)
caches at most 10,000 names: fewer than the 12.7k-name corpus, more than the
~9k unblocked names of `sat-allowed`. Build the reference image with
`k8s/Dockerfile.ref` (`ref-bench:amd64`, imported on the server node). The
dnsperf Pod is limited to 2 CPUs. Everything runs in its own namespace (`NS`,
default `sopedu-bench`), which the script creates and deletes.

## Docker (any Linux host)

```sh
cd bench/competitors
./run.sh                                  # all four, plain then doh
TRANSPORTS=plain ./run.sh sopedu pihole   # subset
SOPEDU_REF=HEAD RATE_SECONDS=30 ./run.sh
```

Requires Docker Compose v2, dnsperf ≥ 2.11, dig, openssl, and the
gitignored `bench/corpus/queries.txt` and `bench/corpus/lists/` (not
published; supply your own). The script refuses to start if another dnsperf
is running or `PORT` (15353) is busy. Results go to
`results/<stamp>.{tsv,md}` (gitignored).

## k3s

Nothing here touches a cluster until you run it.

One-time image imports (amd64 nodes):

```sh
git archive HEAD | (mkdir -p /tmp/sopedu-src && tar -x -C /tmp/sopedu-src)
docker buildx build --platform linux/amd64 -t sopedu-bench:amd64 --load /tmp/sopedu-src
docker save sopedu-bench:amd64 | ssh <server-ssh-host> 'sudo k3s ctr images import -'
docker buildx build --platform linux/amd64 -t upstream-mock:bench --load bench/upstream-mock
docker save upstream-mock:bench | ssh <client-ssh-host> 'sudo k3s ctr images import -'
docker buildx build --platform linux/amd64 -t dnsperf-bench:amd64 --load \
  -f bench/competitors/k8s/Dockerfile.dnsperf bench/competitors/k8s
docker save dnsperf-bench:amd64 | ssh <client-ssh-host> 'sudo k3s ctr images import -'
```

Run (server Pod on `<server-node>`; dnsperf, upstream and lists Pods on `<client-node>`):

```sh
cd bench/competitors
NODE=<server-node> SSH_HOST=<server-ssh-host> NODE_IP=<server-node-ip> \
CLIENT_NODE=<client-node> CLIENT_SSH_HOST=<client-ssh-host> UPSTREAM_IP=<client-node-ip> \
SOPEDU_REF=HEAD RUNS=3 ./run-k8s.sh sopedu agh pihole blocky
```

The script copies the TLS files, lists and generated inputs (including the
private corpus) to `/tmp/sopedu-bench/` on the nodes and prints the cleanup
command at the end. `mem_sample` reads the Pod's cgroup over SSH with `sudo`.
Ports 15353 (server) and 5300/8443/8080 (upstream node) must be free.

The kubelet garbage-collects imported images that no Pod references, within
minutes on a node whose image filesystem is nearly full. Import
`upstream-mock` and `dnsperf-bench` right before `run-k8s.sh`, with no gap.
