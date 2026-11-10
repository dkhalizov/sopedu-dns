# sopedu-dns configuration and behaviour reference

Every configuration key with its default and bounds, what a reload changes,
and what the server does at its limits. The [README](../README.md) is the
short introduction, [docs/specs/dns-forwarder.md](specs/dns-forwarder.md) is
the protocol contract, and [SECURITY.md](../SECURITY.md) has the threat model.

Contents:

1. [Command line, signals and logs](#1-command-line-signals-and-logs)
2. [Before pointing real clients at it](#2-before-pointing-real-clients-at-it)
3. [Running it as a service](#3-running-it-as-a-service) (systemd, Docker, Kubernetes, updates, troubleshooting)
4. [The configuration file](#4-the-configuration-file) (every key, defaults, bounds)
5. [Reload](#5-reload)
6. [Access control and rate limiting](#6-access-control-and-rate-limiting)
7. [Local answers, special-use names, EDNS and DNSSEC](#7-local-answers-special-use-names-edns-and-dnssec)
8. [Request handling order and refusals](#8-request-handling-order-and-refusals)
9. [Listeners and their limits](#9-listeners-and-their-limits) (UDP, TCP)
10. [Upstreams and the plaintext fallback](#10-upstreams-and-the-plaintext-fallback)
11. [Response cache and query coalescing](#11-response-cache-and-query-coalescing)
12. [Blocklists](#12-blocklists)
13. [Cache pre-warm](#13-cache-pre-warm)
14. [Persistent dashboard stats](#14-persistent-dashboard-stats)
15. [Web UI, health and metrics](#15-web-ui-health-and-metrics)
16. [Memory](#16-memory)
17. [Building and the container image](#17-building-and-the-container-image)

## 1. Command line, signals and logs

```sh
sopedu-dns [CONFIG]          # default CONFIG: ./config.toml
sopedu-dns --check CONFIG    # validate only
sopedu-dns --help
sopedu-dns --version
```

With no argument the server reads `./config.toml`. Start from the commented
`config.example.toml`. The repository's
`config.toml` is a minimal port-53 config, and `config.local.toml` is
git-ignored.

`--check` loads and validates the file, prints `config ok` and exits 0, or
prints the error to stderr and exits 1. It binds no sockets, downloads no
lists and does not create `state_dir`, so you can run it in CI or a
pre-deploy hook.

### First start

The server loads cached lists from `state_dir` before it opens the listener,
so with a large cache the listener opens only after they are parsed. A list
with no cached copy gets at most 0.75 s to download; after that the listener
opens anyway and blocking starts when the download finishes. Nothing is
blocked until you add at least one entry to `blocklists`; the default is none.

### Shutdown

On SIGTERM or SIGINT (Ctrl-C) the server logs readiness false, stops
accepting, gives active requests up to five seconds to drain, then cancels
the rest and exits 0. Five seconds fits inside the ten-second termination
grace period of the Kubernetes manifest. A second SIGTERM/SIGINT ends the
drain at once and still exits 0.

### Logs

The server writes one event per line to stdout:
`ts=<unix> level=<level> msg=<name> key=value ...`. Values are escaped, so a
space, quote, backslash or control character cannot forge an extra field or
line (a space inside a value is written `\x20`). Startup, reload, blocklist
refresh, shutdown and UDP drops are logged this way. Startup errors (bad
config, bind failure) go to stderr and exit 1. Under `systemd`, read the log
with `journalctl -u sopedu-dns`.

Per-query logging is off by default. `log_queries = true` adds one
`msg=query` line per query with client, qname (presentation form, escaped),
qtype, result and latency. The UI's `/log` page does not need it.

### Redaction

Errors and logs that contain a URL keep only its scheme, host and port.
Userinfo, paths, query strings and fragments never reach stdout, stderr or
upstream health. Blocklist status names also keep the last path segment when
it ends in a list extension (`.txt`, `.list`, `.hosts`, `.conf`, `.rules`,
`.dat`; for example `.../filter_1.txt`), so you can tell your lists apart;
other segments are dropped, including dotted ones that may carry a token.
TOML errors keep the line number and expected type but strip the offending
value, in either quote style serde uses, because it can be a URL or key with
credentials in it.

### Trying it locally

```sh
dig @127.0.0.1 -p 15353 example.com
dig @127.0.0.1 -p 15353 example.com +tcp
dig @127.0.0.1 -p 15353 example.com +dnssec +cdflag
dig @127.0.0.1 -p 15353 doubleclick.net     # NXDOMAIN, authority SOA TTL 10, when a list blocks it
dig @127.0.0.1 -p 15353 nas.home.arpa       # 192.168.1.10, with a [rewrites] entry for it
dig @127.0.0.1 -p 15353 nas.home.arpa AAAA  # NOERROR, empty answer
curl -s http://127.0.0.1:9999/healthz       # "ok" once a blocklist has loaded and an upstream is reachable
```

The examples assume `listen = "127.0.0.1:15353"`. They use port 15353 because mDNS already holds UDP 5353 on macOS.

## 2. Before pointing real clients at it

Decide these first. All are config keys, and `config.example.toml` has each
of them.

| Setting | Default | What to do |
|---|---|---|
| `listen` | `0.0.0.0:53` | One address string, or an array of 1 to 16 for a dual-stack LAN: `listen = ["192.168.1.11:53", "[2001:db8::11]:53"]`. Each address gets its own UDP socket set and TCP listener. Every IPv6 socket is `IPV6_V6ONLY`, so `[::]:53` does not take IPv4 too and can sit beside an IPv4 address (a single dual-stack `[::]:53` fails when `systemd-resolved` holds `127.0.0.53:53`). Duplicates and port 0 are rejected, because a server listens on a fixed port. On Linux, port 53 needs root or `CAP_NET_BIND_SERVICE`. Listening on all addresses is safe because `allowed_clients` refuses non-LAN sources, and on a host with several addresses replies leave from the address the client queried (`IP_PKTINFO`, Linux and macOS; a specific address needs nothing). That costs about 10% of cache-hit throughput, so on a busy server bind the one LAN address instead. |
| `upstreams`, `fallback` | Cloudflare and Google DoH; no plain-DNS fallback | Every cache miss goes to these resolvers; change them if you don't want that. `fallback` (for example `["1.1.1.1:53"]`) adds plain DNS servers, tried only when every DoH upstream fails at the transport level (no connection or TLS session). An HTTP error status, a reset request or an invalid reply never triggers it. It is off by default because plain DNS is unauthenticated: anyone who can block port 443 could force the downgrade and forge answers. Each use is counted in `dns_plain_fallback_answers_total` and logged as `plaintext_fallback_used`, at most once a minute. |
| `blocklists` | none | Add list URLs (`http://` or `https://`), or nothing is blocked. Many big lists use more memory; see [Memory](#16-memory). |
| `allowed_clients` | loopback, RFC 1918, link-local, `fc00::/7` | Covers an IPv4 home network. A Tailscale tailnet (`100.64.0.0/10`) is opt-in. Home IPv6 usually uses global addresses, which are refused until you add your LAN /64 (see [Access control](#6-access-control-and-rate-limiting)). Never use `0.0.0.0/0` on an internet-facing host. |
| `state_dir` | `state` (relative to the working directory) | Use an absolute path for a service. It holds cached lists, `prewarm.txt` (your most visited names) while `prewarm` is on, and `stats.v1` (counters, top domains and clients) while `persist_stats` is on. If it is not writable, the server still starts and filters from the downloaded lists, but logs `blocklist_error ... cache directory failed` and keeps no copies, so every restart needs the network. |
| `ui_enabled`, `ui_listen` | on, `127.0.0.1:9999` | No login. Keep it on loopback and use `ssh -L 9999:127.0.0.1:9999 host` from your laptop, or set `ui_enabled = false`. On a LAN address, everyone on the LAN can open it. |

Put plain keys before any `[rewrites]` or `[client_names]` table. A key after
a table header belongs to that table and fails with a wrong-type error.

### Point clients at it

The server is only a resolver; it does not hand out addresses. Give the host
a fixed LAN address (a DHCP reservation on the router is enough), check it
with `dig @<host-ip> example.com` from another machine, then set that address
as the DNS server in the router's DHCP settings or on each device. Clients
pick it up when their lease renews. If you also list a public resolver as a
second DNS server, many clients will use it and skip filtering and local
rewrites. If this host is down, clients that know only this address have no
DNS.

## 3. Running it as a service

### Linux service (untested sketch)

Build on the machine, copy the binary to `/usr/local/bin/sopedu-dns`, the
config to `/etc/sopedu-dns/config.toml` with `state_dir =
"/var/lib/sopedu-dns"`, then a unit such as:

```ini
[Unit]
Description=sopedu-dns
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/sopedu-dns /etc/sopedu-dns/config.toml
ExecReload=/bin/kill -HUP $MAINPID
DynamicUser=yes
StateDirectory=sopedu-dns
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Check it with `systemctl status sopedu-dns` and `dig @127.0.0.1 example.com`.
The repository ships no unit file or installer.

### Docker

Build the image (`docker build -t sopedu-dns .`). On Linux, run it on the
host network so `allowed_clients` sees the clients' real source addresses:

```sh
docker run -d --name sopedu-dns --restart unless-stopped --network host \
  --user 0 --cap-drop ALL --cap-add NET_BIND_SERVICE --read-only \
  -v sopedu-state:/var/lib/sopedu-dns sopedu-dns
```

The image runs as uid 65532 by default. A non-root user cannot use an added
`NET_BIND_SERVICE` because Docker sets no ambient capabilities, so port 53 on
the host network needs `--user 0`. Every other capability is dropped. The
image ships `deploy/docker.toml` as `/etc/sopedu-dns/config.toml` (listen on
`0.0.0.0:53`, UI off, no blocklists) and a volume at `/var/lib/sopedu-dns`,
which is the `state_dir` for cached lists. To change settings, mount your own
file (`-v "$PWD/my.toml:/etc/sopedu-dns/config.toml:ro"`) and keep `state_dir =
"/var/lib/sopedu-dns"`. Check it with `dig @127.0.0.1 example.com`.

Publishing ports instead (`-p 53:53/udp -p 53:53/tcp`, no `--network host`)
works without `--user 0` on Docker 20.10 and later, with one catch. Behind the
bridge, rootless Docker, Docker Desktop or the userland proxy, every client
can show up as the bridge gateway address. That address is private, so the
default `allowed_clients` lets it in, and anyone who can reach the published
port has an open resolver. Set a narrow `allowed_clients` in your config or
bind the publish to one LAN address (`-p 192.168.1.2:53:53/udp`). Never
publish port 53 on a public interface.

#### Docker Compose

Save this as `compose.yaml`, with your `config.toml` next to it (keep
`state_dir = "/var/lib/sopedu-dns"` in it):

```yaml
services:
  sopedu-dns:
    image: ghcr.io/dkhalizov/sopedu-dns:1.1.0
    network_mode: host
    user: "0"
    cap_drop: [ALL]
    cap_add: [NET_BIND_SERVICE]
    read_only: true
    restart: unless-stopped
    volumes:
      - ./config.toml:/etc/sopedu-dns/config.toml:ro
      - sopedu-state:/var/lib/sopedu-dns

volumes:
  sopedu-state:
```

Run `docker compose up -d`. The root filesystem is read-only, so cached lists
can only be written to the volume.

### Kubernetes

Set the image in `deploy/kubernetes.yaml`, then:

```sh
kubectl apply -f deploy/kubernetes.yaml
kubectl rollout status deployment/sopedu-dns
kubectl logs deployment/sopedu-dns
```

The manifest has the example ConfigMap, host networking,
`ClusterFirstWithHostNet`, TCP port 53 startup and liveness probes, an HTTP
`/healthz` readiness probe, a 128Mi limit, and an `emptyDir` at `/state` for
the list cache (it survives container restarts, not pod replacement).

#### Port 53 and privileges

Binding port 53 needs `CAP_NET_BIND_SERVICE`, and Kubernetes does not grant it
to non-root processes: it sets no ambient capabilities, and
`allowPrivilegeEscalation: false` (which sets `no_new_privs`) blocks gaining
it from a file capability. So the container runs as uid 0 with
`capabilities.drop: [ALL]`, `capabilities.add: [NET_BIND_SERVICE]`,
`allowPrivilegeEscalation: false` and a read-only root filesystem. Root is the
only privilege: the image's own user (uid 65532) is overridden to uid 0 for
the bind, and the binary is unchanged.
`/state` is a root-owned emptyDir, so uid 0 can write the list cache through
the owner bits. The manifest also sets `fsGroup: 0`, which is redundant, and
the read-only root filesystem
covers only the container rootfs, not the volume. We don't set
`net.ipv4.ip_unprivileged_port_start=53` instead, because with `hostNetwork`
it changes the whole node. Our checks do not exercise the
bind on a real cluster; verify it on yours.

#### Pod Security Admission

`hostNetwork: true` violates both the Baseline and Restricted profiles, and
uid 0 also violates Restricted. Only a namespace with no
`pod-security.kubernetes.io/enforce` label, the `privileged` profile, or an
exemption admits this manifest.

#### High availability

The manifest runs two replicas on `hostNetwork` with required pod
anti-affinity on `kubernetes.io/hostname`, because two host-network pods on
one node would both try to bind `0.0.0.0:53`. The rollout is `RollingUpdate`
with `maxSurge: 0` and `maxUnavailable: 1`: an update takes one node out and
brings it back while the other keeps answering. A surge pod could not
schedule on a two-node cluster.

The rolling update is verified only on a two-node cluster. On a single node it
cannot finish: the new pod stays `Pending` behind the old one (required
anti-affinity plus the held port), `kubectl rollout status` eventually fails
with `ProgressDeadlineExceeded`, and the old pod keeps serving. There is no
outage, but the update never lands until you scale down and restart by hand.

A `PodDisruptionBudget` with `minAvailable: 1` keeps one replica up during
voluntary disruptions such as node drains. It also stops `kubectl drain` from
evicting the last pod unless you use `--force` or scale down first.

The router's DHCP must hand out both node IPs as DNS servers; with clients
pointed at one node there is no failover. You need at least two schedulable
nodes, each with port 53 free on its LAN address. Add a node selector only if
both chosen nodes carry the label you expect. The startup and liveness probes
are TCP :53. The readiness probe is HTTP `/healthz` on `127.0.0.1:9999`, so a
pod is ready once a blocklist has loaded and an upstream circuit is closed
(readiness gates rollouts, not DNS traffic). Keep cluster DNS independent of
this forwarder, or blocklist downloads can loop on their own bootstrap.
Restrict access to your LAN with host networking or firewall rules.

### Update and uninstall

To update, replace the binary with the new release (or pull the new image, or
rebuild from source) and restart. Unknown config keys are errors, so a config written for a
newer version fails on an older binary; run `--check` first. Changes are in
[CHANGELOG.md](../CHANGELOG.md).

To uninstall, first point the router or clients back at their old DNS server,
then stop the service and delete the binary, the config and `state_dir`. The
server writes nothing anywhere else.

### When it will not start

| Message | Meaning |
|---|---|
| `cannot bind listen (UDP) 127.0.0.1:53: Permission denied ...` | A port below 1024 as a normal user. Use root, `CAP_NET_BIND_SERVICE`, or a higher port to try it. |
| `cannot bind listen ...: Address already in use` | Another resolver (`systemd-resolved`, `dnsmasq`, AdGuard Home, macOS mDNS on 5353) owns the port. Stop it or choose another port. |
| `cannot bind ui_listen ...` | The UI port is taken; change `ui_listen` or set `ui_enabled = false`. |
| `cannot read config.toml: No such file or directory` | No argument was given and there is no `config.toml` in the current directory. |
| `invalid config: ... (line N)` | A TOML syntax error, wrong type or unknown key at that line. The offending value is hidden on purpose, so look at the line. |
| `msg=blocklist_refresh_failed error=no blocklist or user rules available: <list>: <reason>` | Every list failed and none is cached. DNS still works, unfiltered, `/healthz` returns 503, and the refresh retries every 60 seconds. |
| `msg=no_upstreams hint="upstreams and fallback are both empty; ..."` (warning) | Nothing is configured to resolve with; only cached, blocked and local answers work. Add an `upstreams` URL. |
| `msg=plaintext_fallback_used count=N` (warning, at most once a minute) | Every DoH upstream failed at the transport level and N answers since the last warning came over the unauthenticated plain `fallback`. Check why port 443 to the DoH upstreams fails. |
| `msg=ui_exposed reason=ui_has_no_login` (warning) | `ui_listen` is not a loopback address, so anyone who can reach it sees the query log. |

## 4. The configuration file

The file is TOML. Every key is optional and has a default; unknown keys are
rejected. Defaults come from `Config::default` in `src/config.rs`, and
`Config::validate` checks every bound at startup, on `--check` and on reload.
`config.example.toml` is a commented starting point.

"restart" in the Reload column means a reload keeps the old value and logs
`restart_required` (see [Reload](#5-reload)). Every other key applies on
reload.

### Listeners and runtime

| Key | Default | Bounds | Reload |
|---|---|---|---|
| `listen` | `"0.0.0.0:53"` | string or array of 1..=16 addresses, no duplicates | restart |
| `worker_threads` | `0` (available parallelism) | 0..=64 | restart |
| `udp_workers` | `0` (one socket, one receive loop) | 0..=64 | restart |
| `udp_batch` | `32` on Linux, `0` elsewhere | 0..=32 | restart |
| `udp_rcvbuf_bytes` | `1048576` (a 1 MiB request) | 0 (OS default) or 4096..=67108864 | restart |
| `udp_sndbuf_bytes` | `0` (OS default) | 0 or 4096..=67108864 | restart |
| `udp_inflight_max` | `1024` | 1..=65536 | restart |
| `udp_max_payload` | `1232` | at least 512; above 1400 is lowered to 1400 (RFC 9715 section 3.1) | yes |
| `udp_discard_timeout_ms` | `1900` | 0 (off)..=60000; the effective limit is never below `serve_stale_client_timeout_ms` + 100 ms | yes |
| `tcp_max_connections` | `256` | 1..=65536 | restart |
| `tcp_max_connections_per_client` | `32` | 1..=65536 | restart |
| `tcp_queries_per_connection` | `65536` | 1..=65536 | restart |
| `tcp_pipeline_max` | `16` | 1..=256 | restart |
| `tcp_idle_timeout_seconds` | `10` | greater than 0 | restart |

### Upstreams

| Key | Default | Bounds | Reload |
|---|---|---|---|
| `upstreams` | `["https://1.1.1.1/dns-query", "https://1.0.0.1/dns-query", "https://8.8.8.8/dns-query"]` | `https://` URLs | yes |
| `upstream_strategy` | `"fastest"` | `"fastest"` or `"ordered"` | yes |
| `fallback` | `[]` | plain DNS `ip:port`; not the listen address itself | yes |
| `trust_plain_upstreams` | `false` | | yes |
| `home_arpa_server` | unset | `"ip:port"` of the authoritative server for `home.arpa` | yes |
| `upstream_timeout_seconds` | `5` | 1..=60 | yes |
| `upstream_hedge_ms` | `50` | 0 (derived)..=5000 | yes |
| `failure_cache_seconds` | `5` | 1..=300 | yes |
| `upstream_inflight_max` | `256` | 1..=65536 | yes |
| `upstream_inflight_per_client` | `64` | 0 (off)..=65536 | yes |
| `upstream_0x20` | `true` | | yes |
| `upstream_source_ports_exclude` | `[]` | Ports or `"first-last"` ranges (each in 1..=65535) never used as the source port of a plain upstream UDP query, for example `["49152-49200", "5353"]`. Queries choose from 1024..=65535 (RFC 5452 section 9.2 asks for a range as large as practicable), and the list must leave at least one port there. The `listen` and `ui_listen` ports are always excluded. List here any port another local service binds, so a restart of that service never finds it briefly held by a query. | yes |
| `forward_test_names` | `false` | | yes |
| `dnssec` | `"passthrough"` | `"passthrough"` or `"always_upstream"` | yes |
| `private_ptr` | `"nxdomain"` | `"nxdomain"` or `"forward"` | yes |
| `forward_reverse_zones` | `[]` | apexes of the local reverse zones below, such as `"168.192.in-addr.arpa"`; not the shared CGNAT zones | yes |
| `empty_zone_soa_rname` | `"nobody.invalid."` | a valid DNS name | yes |
| `empty_zone_ttl` | `10` | 0..=2147483647 (RFC 2181 section 8) | yes |
| `empty_zone_ns` | the zone apex | a valid DNS name | yes |

An IP literal in a DoH URL needs no bootstrap DNS. Hostnames work too and are
resolved through the host's or container's DNS.

### Clients

| Key | Default | Bounds | Reload |
|---|---|---|---|
| `allowed_clients` | `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `::1/128`, `fc00::/7`, `fe80::/10` | CIDR list, not empty | yes |
| `rate_limit_qps` | `0` (off) | | yes |
| `rate_limit_burst` | `0` (equal to `rate_limit_qps`) | | yes |
| `no_filter_clients` | `[]` | IP addresses | yes |
| `no_filter_macs` | `[]` | six hex octets, one consistent separator (`:` or `-`) | yes |
| `[client_names]` | empty | IP key, display name | yes |

### Filtering and local names

| Key | Default | Bounds | Reload |
|---|---|---|---|
| `blocklists` | `[]` | `http://` or `https://` URLs | yes |
| `refresh_hours` | `24` | at least 1 | yes |
| `user_rules` | `[]` | rules the list parser accepts, blank or comment lines | yes |
| `block_cname_targets` | `true` | | yes (resets the cache) |
| `blocklist_max_bytes` | `268435456` (256 MiB) | greater than 0 | yes |
| `blocklist_max_lines` | `5000000` | greater than 0 | yes |
| `blocklist_max_rules_total` | `5000000` | greater than 0 | yes |
| `[rewrites]` | empty | name or `*.suffix` → IP address | yes |

Rewrite keys are normalized to lowercase without a final dot; two keys that
normalize to the same name are rejected. Exact matches win, then the most
specific wildcard.

### Cache

| Key | Default | Bounds | Reload |
|---|---|---|---|
| `cache_size` | `10000` entries | 0 disables caching | yes (resets the cache) |
| `cache_bytes` | `4194304` (4 MiB) | greater than 0 | yes (resets the cache) |
| `optimistic_max_age` | `43200` (12 h) | integer seconds or `"12h"`, `"30m"`, `"60s"`, `"43200"` | yes |
| `serve_stale_client_timeout_ms` | `1800` | 0..=60000 | yes |
| `prefetch` | `true` | | yes |
| `negative_ttl_min` | `0` s | not above `negative_ttl_max` | yes (resets the cache) |
| `negative_ttl_max` | `3600` s | | yes (resets the cache) |

`optimistic_max_age` is how long an answer may be served after it expires
(RFC 8767 section 4). It counts from expiry, so a long TTL still gets the full
stale window. Negative TTLs are capped at one hour by default, below
RFC 2308's three-hour ceiling.

### State, UI and logging

| Key | Default | Bounds | Reload |
|---|---|---|---|
| `state_dir` | `"state"` | | yes |
| `prewarm` | `true` | | yes |
| `prewarm_count` | `1000` | 0..=10000 | a decrease on reload, an increase on restart |
| `persist_stats` | `true` | | yes |
| `ui_enabled` | `true` | | restart |
| `ui_listen` | `"127.0.0.1:9999"` | | restart |
| `query_log_capacity` | `10000` | 0..=1000000 | restart |
| `log_queries` | `false` | | yes |

Validation also rejects malformed MAC addresses, an empty `allowed_clients`
(`["0.0.0.0/0", "::/0"]` allows everyone) and self-forwarding `fallback`
entries (see [Reload](#5-reload)).

## 5. Reload

`kill -HUP <pid>` reloads the config, and so does saving the file: the
server checks the mtime, length and inode of the file and its symlink target
every two seconds, which catches a Kubernetes ConfigMap symlink swap. The
whole file is parsed and validated first. On error the old config stays
active, `config_reload_failed` is logged and the server stays ready.

On success the server swaps in one immutable generation (config, rules, list
status, upstream pool, cache and single-flight map) atomically, so an
in-flight request sees only one generation.

The response cache survives a reload, so an answer cached from the previous
upstream pool can be served until its TTL runs out, as in any DNS cache. The
cache starts empty only when `cache_size`, `cache_bytes`, the negative TTL
bounds or `block_cname_targets` change, or when the single-flight map is
rebuilt. That reload logs `cache_reset=true`.

The single-flight map, and with it the cache, is rebuilt when any setting
that affects upstreams changes: `upstreams`, `fallback`,
`upstream_timeout_seconds`, `upstream_hedge_ms`, `failure_cache_seconds`, `upstream_strategy`,
`upstream_0x20`, `upstream_source_ports_exclude`, `trust_plain_upstreams`,
`home_arpa_server`,
`forward_test_names`,
`upstream_inflight_max` or `dnssec`. A request under the new generation never
joins a leader or reads an answer from the old pool. A change to `prefetch`
or `serve_stale_client_timeout_ms` applies to new requests and resets neither
the cache nor the map.

A running server cannot rebind a socket, resize a live task pool or rebuild
the Tokio runtime, so these keys need a restart: `listen` (the whole list),
`ui_listen`, `ui_enabled`, `tcp_max_connections`,
`tcp_max_connections_per_client`, `tcp_queries_per_connection`,
`tcp_pipeline_max`, `tcp_idle_timeout_seconds`, `udp_batch`,
`udp_inflight_max`, `udp_workers`, `udp_rcvbuf_bytes`, `udp_sndbuf_bytes`,
`worker_threads`, `query_log_capacity` and an increase of `prewarm_count`
(a decrease applies on reload). A reload that
changes one logs `restart_required` with the field and its old and new
values, and keeps the old behaviour until you restart.

A reload re-downloads lists only when the list URLs or `refresh_hours`
change. Otherwise lists refresh every `refresh_hours`, and a restart
refreshes them at once.

### Self-forwarding

A `fallback` entry is rejected when it equals `listen`, or when it uses the
listen port on a loopback or unspecified address while the listener is also
local. A DoH URL whose host is a listen IP is accepted, because the listener
speaks plain DNS, not DoH, and the address may belong to another service.
Check such a URL by hand.

## 6. Access control and rate limiting

`allowed_clients` lists the client prefixes (CIDR) that may query. The
default is loopback, RFC 1918, link-local and ULA. Any other client gets
REFUSED before the cache, rules or upstreams see the query, so the server is
not an open resolver. A list you set replaces the defaults entirely;
`["0.0.0.0/0", "::/0"]` allows everyone.

Devices on a dual-stack LAN usually have global IPv6 addresses, which the
default refuses, so add your LAN /64 next to the defaults (or use ULA, see
[IPv6 renumbering](#ipv6-renumbering)). The RFC 6598 shared
space `100.64.0.0/10` is not in the default because behind a carrier-grade NAT
it holds other subscribers' addresses. Add it only when it is yours, for
example a Tailscale tailnet:

```toml
allowed_clients = [
  "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
  "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
  "2001:db8:1:2::/64",   # your delegated LAN prefix
  # "100.64.0.0/10",     # only for a Tailscale (or similar) overlay
]
```

The server never adds its own on-link prefix on its own, because on a VPS that
subnet is shared with strangers. When it refuses a source inside one of the
host's global or unique-local IPv6 on-link prefixes, it logs one `client_refused_onlink` warning
per prefix with `hint=add_to_allowed_clients`. The prefixes are re-read at
most once a minute.

#### IPv6 renumbering

Most ISPs can change the IPv6 prefix they delegate to your router, and the
router then renumbers the LAN ([RFC 9096](https://www.rfc-editor.org/rfc/rfc9096.html)
describes how routers should handle it). Anything tied to the old global prefix
breaks: a global `listen` address disappears, and a global /64 in
`allowed_clients` stops matching, so clients get REFUSED. IPv4 keeps working,
and the `client_refused_onlink` warning above tells you when it happened.

To avoid it, if your router can announce a ULA prefix
([RFC 4193](https://www.rfc-editor.org/rfc/rfc4193.html), `fd00::/8`):

- give the DNS host a fixed address in it and listen there (or on `[::]:53`);
- let the router advertise that address as the DNS server (RDNSS,
  [RFC 8106](https://www.rfc-editor.org/rfc/rfc8106.html));
- keep `fc00::/7` in `allowed_clients`, which the default already has, and
  leave the global /64 out.

Clients then reach the server from their ULA addresses
([RFC 6724](https://www.rfc-editor.org/rfc/rfc6724.html) prefers a ULA source
for a ULA destination), and a new global prefix changes nothing. If the router
cannot announce a ULA prefix, use the global /64 and update it after a renumber.

### Rate limit

The token bucket is off by default (`rate_limit_qps = 0`). When on, it keys
each client by its full address (IPv4 /32, IPv6 /128), so one chatty LAN host
cannot silence the others; every device on a home network shares one IPv6
/64. A host with several addresses gets one bucket per address. Sources
outside `allowed_clients` share a single bucket, which limits their REFUSED
replies as a whole and keeps them from filling the table. The table holds at
most 4096 buckets. Excess requests are dropped without a reply and counted.

Queries from an unspecified, multicast or broadcast source address are always
dropped without a reply.

### Filtering bypass

A client in `no_filter_clients` (by IP) or `no_filter_macs` skips only the
blocklists; rewrites, local zones, the cache and the upstreams still apply.
`no_filter_macs` takes six hex octets with one separator style throughout
(colon or dash). On Linux the neighbour table is read from `/proc/net/arp`
every 60 seconds. Other platforms match nothing, and IPv6 neighbours are not
covered.

## 7. Local answers, special-use names, EDNS and DNSSEC

### Private reverse zones

Private reverse names are answered locally by default. A complete four-octet
`.in-addr.arpa` or 32-nibble `.ip6.arpa` name in RFC 1918, loopback,
link-local, CGNAT or unique-local space gets NXDOMAIN with the usual TTL-10
SOA. At their apex the matching reverse zones answer SOA and NS
authoritatively (AA=1, TTL and MINIMUM 10, NS target and MNAME equal to the
apex), NODATA for other types, and NXDOMAIN with the SOA for names below.
`empty_zone_soa_rname`, `empty_zone_ttl` and `empty_zone_ns` change the SOA
RNAME, the TTL and MINIMUM, and the NS target for all of these empty zones,
including `home.arpa`, `service.arpa` and `resolver.arpa`.
Matching is by whole labels. `private_ptr = "forward"` turns this off and
forwards every query for these reverse zones instead, except shared CGNAT
space, which RFC 6598 keeps local. To forward only some of them, list their
apexes in `forward_reverse_zones` (RFC 6303 section 3 asks for the choice
zone by zone); the rest stay local.

### Special-use names

These never leave the host. `.onion`, `.invalid` and `.test` get NXDOMAIN,
`localhost` resolves to loopback, and `home.arpa`, `service.arpa`,
`resolver.arpa` and the RFC 6303 reverse zones are answered as local empty
zones; names below `resolver.arpa` get NODATA rather than NXDOMAIN
(RFC 9462 section 6.4). Set `forward_test_names = true` to send `.test` upstream. Set
`home_arpa_server` to send `home.arpa` to its authoritative server on your
network (RFC 8375). The DS query with DO at the apex still goes upstream.

In all of these local zones, a `DS` query for the zone apex with DO=1 is
forwarded. The DS lives in the signed parent, and a validating client needs
that proof; a local NODATA is something it cannot verify (RFC 4035 3.1.4.1,
RFC 6303 section 7, RFC 8375).

### EDNS

The client's EDNS OPT record is never forwarded (RFC 6891 section 6.1.1). The
upstream query carries our own OPT with our payload size, only the DO and
Compact Answers OK flags, and any unknown client option unchanged (RFC 5625
section 3). ECS, Cookie, keepalive and Padding stay on the client side and do
not prevent caching. Replies carry our own OPT too. An Extended DNS Error from
the upstream is passed on with `upstream` added to its text, so clients don't
mistake it for ours (RFC 8914 section 3).

### DNSSEC

The server does not validate signatures; DNSSEC records pass through.
`dnssec = "passthrough"` (the default) forwards the client's DO bit as is.
`dnssec = "always_upstream"` sets DO on every upstream query. Answers are then
normalized and cached per client EDNS/DO/AD: DNSSEC records are stripped when
the client did not set DO (unless it asked for a DNSSEC qtype), non-EDNS
clients get no OPT, and AD follows the conservative profile, so a cache hit
needs no rebuild. Upstream AD from a DoH upstream is kept only for clients
that set AD or DO (conservative profile, RFC 6840), on the first answer and on
fresh cache hits. Plaintext fallback, truncated, local and stale answers always
clear it. Stale answers can carry expired signatures,
which validating clients may reject.

## 8. Request handling order and refusals

The optional rate limit runs first and drops excess requests without a reply.
Rewrites, blocklists and local reverse answers come next, before the shared
response cache. A bypassed client (by IP or MAC) skips only the blocklists.

ANY is never forwarded. Unless a rewrite, local zone, special-use name, block
or `.local` answers it first, it gets the RFC 8482 minimal answer: one HINFO
record (`"RFC8482" ""`, TTL 10).

`version.bind`, `id.server` and `hostname.bind` get REFUSED in any class, and the refusal
takes precedence.

A malformed request with a readable header, including one with more than one
question, gets FORMERR. A request with no question gets REFUSED (RFC 9619).
The server drops only packets too short for a header and responses sent as
queries. A TCP framing error closes the connection.

TSIG (type 250) and SIG(0) (type 24) signed messages and TKEY are forwarded
byte for byte and their replies relayed unchanged, never cached, because any
change would break the signature (RFC 5625). To a plain `fallback` server they
always go over TCP: the message keeps the client's ID, so over UDP only the
source port would stand between it and a spoofed reply. The server does not check the
signatures. Name policy comes first, so a blocked or local name gets REFUSED.
DNSSEC RRSIG (type 46) is not transaction authentication and follows the
DNSSEC pass-through policy.

Zone transfers go to a plain `fallback` server over TCP, message by message.
AXFR over UDP gets REFUSED, and so does a transfer with no plain server, since
DoH cannot carry one. At most 16 transfers are relayed at once; another one
waits for a slot, and gets REFUSED if none frees within the upstream timeout. The server does not parse the transfer: it ends
when the upstream closes or goes quiet, and after 10 minutes at most. Every client in `allowed_clients` can
ask for a transfer, so a fallback server that trusts the forwarder's address
for transfers trusts all of those clients too.

With `block_cname_targets` (on by default) a query gets NXDOMAIN when a CNAME
or DNAME target in the upstream answer is blocked, unless the query name is
itself allowed or the client is exempt. This stops CNAME cloaking.

## 9. Listeners and their limits

UDP and TCP have separate limits, so neither can starve the other.

### UDP

Fresh UDP cache hits are answered inline in the receive loop and never take a
permit. `udp_inflight_max` (1024) limits only the spawned slow-path requests
in flight, across all receive loops. When it is full, new slow-path requests
are dropped and counted instead of queued, so the socket keeps reading.

`udp_workers = 0` keeps one socket and one receive loop. A value of 1..=64
binds that many UDP sockets to the listen address, each with its own receive
loop, buffers and slow-path task set; values above 1 set `SO_REUSEPORT`. The
kernel spreads client flows across the sockets. The startup `listening` line
reports the effective worker count and buffer sizes.

`udp_rcvbuf_bytes` and `udp_sndbuf_bytes` set `SO_RCVBUF` and `SO_SNDBUF`
before bind. The kernel treats the value as a request. Linux normally
reserves and reports about twice the value, and both platforms clamp it to
their socket-buffer maximum (`net.core.rmem_max` and `net.core.wmem_max` on
Linux; in our measurement macOS returned the request unchanged). Check the
logged effective size or `getsockopt`.

`udp_batch = 0` reads one datagram per readiness wake, which is the only mode
outside Linux. On Linux, 1..=32 reads up to that many datagrams per `recvmmsg`
call. Other platforms log `udp_batch_unsupported` once and use the
single-datagram path. Replies, including inline cache hits, go out through the
asynchronous `send_to`, so each send waits for writability and reports its
own result. `sendmmsg` is not used, because the safe API cannot report a
partial batch, so replies could be lost without a trace. The batched
path reads each datagram into a 64 KiB slot, the same limit as the
single-datagram path. A datagram that does not fit is dropped unparsed and
counted as `udp_truncated`, a server-wide total logged on the first drop and
every 1000th after. The preallocated receive buffer reserves 2 MiB of address
space per receive loop (32 slots of 64 KiB), which becomes resident only as
datagrams arrive.

`worker_threads` sets the worker count of the Tokio multi-thread runtime:
0 uses the platform's available parallelism, 1..=64 is an explicit count. The
runtime is built once at startup, and the `listening` line reports the
effective thread count.

#### Answer size

UDP answers stay within `udp_max_payload` (1232). A value above the 1400
bytes RFC 9715 section 3.1 recommends is lowered to 1400 with a warning. The limit is
`min(max(client EDNS payload, 512), udp_max_payload)`, and non-EDNS clients
get 512. An answer over the limit becomes a well-formed TC=1 reply with the
question, AD cleared, no answers, and an OPT record only if the client sent
EDNS. The full answer stays cached. TCP answers are never capped.

Replies are sent with the don't-fragment flag over IPv6, and over IPv4 on
macOS (Linux offers that for IPv4 only through path MTU discovery, which RFC
9715 advises against). If a reply is still too large for the path, it goes
again as the same TC=1 reply.

#### Late answers

`udp_discard_timeout_ms` (1900; 0 disables it, like Unbound's
`discard-timeout`) keeps a stalled upstream from releasing every waiting
query in one burst. A UDP NOERROR or NXDOMAIN reply to a query older than the
limit is not sent and counts as `dropped` in `/metrics`; the answer is still
cached and TCP clients still get it. SERVFAIL is never discarded, and neither
is a stale answer sent on the `serve_stale_client_timeout_ms` timer, because
the limit is never below that timer plus 100 ms (1900 ms with the defaults).

### TCP

TCP checks `allowed_clients` right after accept and closes a disallowed peer
before it can take a connection permit. It then accepts at most
`tcp_max_connections_per_client` (32) connections from one address and
`tcp_max_connections` (256) in total, and closes a new stream at once when
either limit is full. At startup the server reads the open files limit
(`RLIMIT_NOFILE`). If `tcp_max_connections` would leave less than 128
descriptors plus the UDP sockets free, it lowers the value and logs
`tcp_max_connections_clamped`.

Each connection reads length-prefixed frames continuously and resolves up to
`tcp_pipeline_max` (16) at a time. Each answer is written as soon as it is
ready, so replies can arrive out of order (RFC 7766 §7); each keeps its own
ID and question. Reading pauses while the pipeline is full, so frames are
never buffered without bound. One connection holds at most `tcp_pipeline_max`
frames in flight plus their answers, one 65,535-byte frame per slot. At the
defaults that is 256 connections × 16 slots = 4,096 in-flight TCP queries,
and the worst case is `2 × 4,096 × 65,535` bytes ≈ 0.5 GiB if every slot held
a maximum-size query and answer. Typical frames are about 125 bytes. A
connection also stops reading while more than 128 KiB of its finished answers
are unwritten. Every accepted socket gets `TCP_NODELAY`, and one task per
connection serializes the writes so response frames never interleave. Frames
shorter than the 12-byte DNS header are rejected, and any framing error
closes the connection.

`tcp_idle_timeout_seconds` (10) limits how long a connection waits for the
next frame while no query is in flight (partial bytes do not reset the
deadline), and how long a write may stall. Once a full query is read, the
exchange is bounded by `upstream_timeout_seconds` instead.

A connection serves at most `tcp_queries_per_connection` (65,536) queries.
At that cap it answers the queries it has accepted, then closes with a FIN
(no reset) and drains input for up to a second. Queries pipelined past the
cap get no answer, and the client retries them on a new connection (RFC 7766
§6.2.4). On SIGTERM every connection stops reading new frames, sends its
in-flight answers within the 5 s shutdown drain, and closes.

## 10. Upstreams and the plaintext fallback

### Upstream concurrency

`upstream_inflight_max` (256) limits concurrent upstream work. When the pool
is full, the server answers SERVFAIL at once; there is no queue.

`upstream_inflight_per_client` (64; 0 disables) caps the cache misses one
client address (IPv4 /32, IPv6 /128) has in flight over UDP and TCP together,
so a host flooding random names at a slow upstream cannot starve the others.
Over UDP, queries beyond the cap get a minimal TC=1 reply so that a real
client retries over TCP. SERVFAIL would let a spoofer with a forged UDP
source aim failures at a victim. Over TCP they get SERVFAIL. TC replies are
limited per host to a burst of 16, then 200 a second, and the rest are
dropped. The cap also counts the stale and prefetch refreshes that a host's
hits start, and over UDP its queries waiting on another query's identical
lookup (each holds one of the `udp_inflight_max` request slots). TCP waiters
are not counted. A dual-stack host gets one share per address, and a LAN
host that forges or adds addresses can still fill `upstream_inflight_max`.
Cache hits and local answers are not limited.

### DoH: hedging and strategy

With `upstream_strategy = "fastest"` (the default), DoH requests are hedged.
The pool picks the upstream with the fewest outstanding requests (EWMA
latency breaks ties), starts the next attempt after `upstream_hedge_ms`
(50 ms by default; 0 derives `clamp(2*EWMA, 40, 80)` ms), and cancels the
others when the first terminal answer arrives. A failed attempt moves to the
next upstream at once. At most `upstream_inflight_max` queries run at a time,
and the hard deadline is `upstream_timeout_seconds` (1..=60).

With `upstream_strategy = "ordered"` the pool uses the upstreams in config
order and never hedges. The next upstream sees a query only when the current
one fails, is benched by its circuit, or has not answered by the failover
point. That point is half of `upstream_timeout_seconds`, capped at 1 second
and at half the UDP discard limit (950 ms by default), so the backup's answer
still reaches a UDP client. Use this mode to send every query to one DoH
provider and keep the others as backup.

### DoH: wire details

DoH requests use DNS ID 0 so responses are cacheable, POST
`application/dns-message`, and require a 2xx `application/dns-message` reply.
The HTTP `Age` is subtracted from both the relayed answer and the cache
template. A redirect is not followed: the query only ever reaches the
configured URI, and a 3xx fails the attempt like any other non-success status.
This is the policy choice RFC 8484 section 3 points at: a URI discovered
outside the client's configuration grants no resolution privilege.

A DNS-level failure (SERVFAIL, REFUSED, ...) from a reachable DoH upstream
moves on to the next DoH upstream only. Extended DNS Errors do not change this
(RFC 8914 §6), so a validation SERVFAIL also moves on. If you rely on upstream
DNSSEC validation, list only validating upstreams: a non-validating one can
answer a name a validating one rejected.

If a DoH upstream is given by hostname and that name resolves through this
server, a blocklist entry for it blocks the upstream. DoH then fails to
connect, which counts as unreachable and lets a configured fallback in.
IP-literal upstreams (the defaults) are not affected.

### Circuits, probes and Retry-After

Three consecutive failures open a circuit. Only failures of the endpoint
itself count: no connection (TCP connect or TLS), or a failed probe. A slow or
failing answer for one name never counts. Neither does an HTTP error status,
a non-DNS body or a reset after the request was sent (an HTTP/2 RST_STREAM,
or the connection closed under it) for a client's query, because a DoH front
end can turn one name's slow backend lookup into a 502, 504 or reset. So
clients cannot bench an upstream by asking for broken domains. An
endpoint-wide 5xx or reset is confirmed by the root-NS probes, which ask one
fixed name; a failure RCODE for it also fails the probe. A client can at most
push an upstream to the back in `fastest` mode, or provoke a `Retry-After`
that keeps it out while another upstream serves.

A DoH circuit's cooldown starts at 30 seconds, doubles with each further
failure, and stops at 300 seconds. Root-NS probes run in the background every
30 seconds, with the first pass at startup, and one success closes the
circuit.

A DoH 429 or 503 with `Retry-After` (seconds or HTTP-date) takes that upstream
out of use for the stated time, at most 60 seconds, while the other upstreams
serve. If a health probe drew it, the probes pause too and every query honours
it. With no other upstream left, those queries fail with SERVFAIL and never
fall back to plaintext, since the endpoint did answer. If a client query drew
it, the pause may concern that query alone, so it holds only while another
DoH upstream is usable. On the last upstream, queries still go to it, only
those it refuses fail (never over plaintext), and the probe keeps running to
confirm whether the whole endpoint is paused.

### Plaintext fallback

Plain UDP fallbacks (none by default) are tried only when every DoH attempt
failed at the transport level: no connection (TCP connect or TLS), or an
upstream already benched because its last failures were connection failures,
including a probe that got no response at all. An upstream that answers at
all counts as reachable and never lets the fallback in, even if it answers
only with an HTTP 4xx or 5xx, a `Retry-After` pause or a failure RCODE to the
probe. A client flood can make an upstream rate-limit us or fail, but cannot
make it unreachable. An HTTP 4xx or 5xx, a non-DNS body, a reset request or an
invalid reply to a client query comes from a reachable upstream and may depend
on the name, so the query ends in SERVFAIL with no downgrade. Running out of
`upstream_timeout_seconds` also ends in SERVFAIL.

A resolution that failed is not retried upstream for `failure_cache_seconds`
(default 5, RFC 9520 section 3.2). Repeated failures of the same question
double the window up to 30 seconds, or up to the configured value when that is
larger. It never exceeds 300 seconds. The failure cache holds 4096 entries;
when a flood of distinct failures fills it, entries are kept for at least one
second and new failures go uncached until room frees up.

Every answer from a fallback counts in `dns_plain_fallback_answers_total`, a
`plaintext_fallback_used count=N` warning is logged at most once a minute,
and the dashboard marks the upstreams "degraded". A single query whose DoH
attempts all failed to connect does not change `/healthz`. The fallback
carries traffic for longer only once every DoH circuit is open, and then
`/healthz` returns 503.

A plain fallback that refuses or is unreachable is skipped for 5 seconds,
doubling up to 60, while another fallback is usable.

A UDP query to a fallback that stays silent is sent again after twice the
server's smoothed round-trip time, between 2 and 5 seconds (2 seconds until a
first reply has been measured). If the resend is also unanswered and time
remains in `upstream_timeout_seconds`, the query is tried once over TCP to
the same address while UDP keeps listening. With the default 5-second budget
that means UDP at 0 s, the resend at 2 s and TCP at 4 s.

#### Spoofing defences (RFC 5452)

Each fallback attempt uses a fresh socket, source port and ID. By default
(`upstream_0x20`) it also randomizes the case of the name (0x20) and checks
the question case-sensitively over UDP. Over TCP, which an off-path attacker
cannot inject into, the question is compared without case. A fallback that
has never echoed our case gets one retry without randomization, from a new
source port and ID. A fallback that has echoed it is never retried, so a
reply that differs only in case is discarded as forged. Truncated UDP replies
are retried over TCP.

#### Scrubbing

DoH and fallback replies are scrubbed: an off-chain Answer owner invalidates
the reply, Authority keeps only SOA/NS/NSEC/NSEC3/RRSIG at or above the
question, and Additional keeps only OPT. Fallback answers are cached for at
most 300 s, never served stale and never prefetched. Set
`trust_plain_upstreams = true` to treat plain servers as trusted primaries and
lift these limits for them; the RFC 5452 checks still apply, and DoH replies
are still scrubbed.

### What gets cached, and failure caching

Terminal answers (positive, or NXDOMAIN/NODATA with SOA) are cached. A fresh
NXDOMAIN for a name answers every QTYPE of that name (RFC 2308 §8). One at the
end of a CNAME chain denies the chain's last name, not the alias, and answers
that name directly (RFC 8020 §2). NODATA stays per QTYPE. Incomplete replies
and referrals are returned but never cached. When every
attempt fails, a failure marker keyed by the server, the question and the
EDNS/DO/CD/AD context keeps that server out of repeat lookups for 5 seconds,
doubling up to 30 seconds while the failures continue (RFC 9520, RFC 2308
§7.1). A lookup with no unmarked server left is suppressed, and a server the
failed attempt never reached is still tried. A query that was never sent
(every upstream paused, no fallback) sets no marker.

## 11. Response cache and query coalescing

### Cache

The cache stores the raw response and patches only the ID and record TTLs on
the way out; the EDNS pseudo-TTL is left alone. A positive entry expires with
its lowest record TTL. A negative entry needs a usable SOA and expires after
min(SOA TTL, SOA minimum). Zero-TTL responses are never cached. Eviction is
S3-FIFO with a byte budget (`cache_bytes`) and an entry budget
(`cache_size`).

Nonrecursive queries and queries with client-specific EDNS options (including
ECS and cookies) skip the cache, because the cache key cannot tell those
clients apart. An EDNS/non-EDNS mismatch between query and cached response is
also a miss, so no client gets an unsolicited OPT record.

#### Serve-stale (RFC 8767)

Entries expired for less than `optimistic_max_age` are served with record
TTL 30 and get one background refresh per key. By default a stale hit tries
to refresh first, as RFC 8767 asks. It waits up to
`serve_stale_client_timeout_ms` (1800, the RFC's recommended client response
timer) for the refresh, returns the fresh answer if it arrives and the stale
copy if not, and lets the refresh keep running. Only an upstream outage costs
the full wait, and with prefetch, names asked regularly never go stale.
`serve_stale_client_timeout_ms = 0` answers from expired data at once and
refreshes in the background, like AdGuard Home's optimistic cache. That is
an explicit opt-in and does not conform to RFC 8767. A failed refresh leaves
the stale entry in place.

#### Prefetch

With `prefetch = true` (the default), a fresh positive entry is also
refreshed in the background once less than 10% of its original lifetime
remains (`remaining_ttl * 10 < orig_ttl`). The client still gets the stored
answer. Negative entries are never prefetched. Refreshes go through the
single-flight map, so a key has at most one in flight and a query that cannot
be coalesced is never prefetched. A refresh counts against the
`upstream_inflight_per_client` cap of the client whose hit started it. If
that client is over the cap, it gets the stale copy at once and no refresh
starts.

### Coalescing (single flight)

Concurrent cache misses for the same canonical key are coalesced. The first
caller does the upstream lookup, and up to 128 followers wait for its relayed
answer and patch in their own ID, so no duplicate upstream request goes out.
The map holds at most `upstream_inflight_max` keys (default 256). At either
limit the caller skips coalescing and does its own lookup without queueing,
under its host's `upstream_inflight_per_client` cap. If the pool semaphore is
also full, it answers SERVFAIL at once (bounded, no queue).

Queries that cannot be shared skip coalescing too: signed or TSIG packets,
EDNS options (ECS, cookies) or unknown non-DO EDNS flags, extra sections,
nonrecursive queries, non-IN classes, opcodes other than QUERY, and anything
without exactly one question.

A follower waits at most `upstream_timeout_seconds + 1` and answers SERVFAIL
if the leader fails, is cancelled, panics or times out. A leader puts a
terminal answer into the cache before broadcasting it. The leader's upstream
work runs in its own task, bounded by the upstream deadline, so a leading TCP
client that disconnects does not fail the other clients waiting for the same
name. Fresh cache hits touch the map only when prefetch starts a near-expiry
refresh. The same map keeps stale refreshes and prefetches to one in flight
per key.

## 12. Blocklists

### Formats and parsing

Lists can be hosts files or adblock-style lists. `user_rules` uses the same
syntax: `||ads.example^` blocks a name and its subdomains, and
`@@||ok.example^$important` allows it even if a list blocks it. Priorities
apply across all matching parent domains, so an important exception on a
parent also beats a block on a more specific name.

A hosts line must hold one hostname. Lines with several hosts and inline
hosts comments are skipped. Comments, blank lines and unsupported rules all
count as skipped. Invalid UTF-8 and lines longer than 64 KiB are skipped, and
the rest of the list still loads. `user_rules` is stricter than a downloaded
list: every entry must be a rule the list parser accepts, a blank line or a
comment. `--check` and a reload refuse a config with any other entry and name
its position.

### Storage

Blocklists are streamed and merged into a table of 64-bit fingerprints. Each
slot holds the normalized domain hash, the rule flags and the list id. The
table stores no domain bytes and is exact by hash only; a 64-bit collision is
negligible and could only merge rule flags. The list id is there for the UI
and the rule tester: 0 is the inline `user_rules` set, and downloaded lists
start at 1.

### Limits

When a list exceeds its byte budget (`blocklist_max_bytes`) or line budget
(`blocklist_max_lines`), the server stops reading it, keeps what it parsed
(or its cached copy) and records an error.

`blocklist_max_rules_total` is split equally across the configured lists, in
order: the first `cap % n` lists get one extra rule, so the shares add up to
the cap. A list that exceeds its share is cut at the same line on every
refresh and records an error. Unused share from a small list goes to no one.
A cut list still counts as loaded: its kept lines are cached (without
`ETag`/`Last-Modified`, so the next refresh downloads it again), readiness
holds, and a restart while the list host is down loads that prefix.

### Download rules

Only `http` and `https` list URLs are accepted. Redirects are capped at five.
A redirect may not switch from https to http, and may not target `localhost`
or a loopback, private, shared (`100.64.0.0/10`), benchmarking
(`198.18.0.0/15`), link-local (including cloud metadata), `0.0.0.0/8` or
unspecified IP literal, including those forms embedded in IPv6 (IPv4-mapped,
IPv4-compatible, NAT64 `64:ff9b::/96`; all of `64:ff9b:1::/48`). Hostnames are
not resolved, so this is defence in depth and does not fully prevent SSRF.

### Cached copies and refresh

Each list has a body file and a metadata file under `state_dir/lists/`, named
by a stable hash of the URL and written atomically with owner-only
permissions on Unix. At boot the server loads these copies before the network
is up, then refreshes. Startup removes temp files left in `state_dir/lists/`
by a crash. Startup, and any reload that changes the lists, delete the cached
body and `.meta` of every list that is no longer configured.

A refresh downloads up to eight lists in parallel, sends `If-None-Match` and
`If-Modified-Since` when it has them, and treats `304` as success. A list that
fails falls back to its last good copy, or is skipped if it has none; the
other lists still load. A `200` with no rules in the body is always refused
the same way. To drop a list, remove its URL.

#### Shrink guard

A `200` with fewer than a tenth of the rules in the cached copy is held back,
with no early retry. The cached copy stays in use, `last_error` says
`refused`, and the count and time go into the list's `.meta`. Every download
that small is refused until `refresh_hours` after that first refusal,
including early retries, reloads and restarts in between. The first one after
that which is still that small is accepted. A broken mirror or captive portal
is kept out for at least one refresh interval, and a list that really shrank
is accepted one interval late. A `304` or a normal-sized download in between
clears the note. A hold whose start time is in the future (the clock was
ahead when it was noted) counts as over.

#### Schedule

A refresh fails only when no list, cached copy or inline rule is available.
It then keeps the previous snapshot, logs `blocklist_refresh_failed` at error
level and retries after 60 seconds. Successful refreshes repeat every
`refresh_hours` (default 24). A reload that changes `refresh_hours` triggers
one refresh so the new interval takes effect.

#### Publishing a refresh

A refresh builds a complete replacement snapshot, then publishes it into the
generation current at install time, as long as that generation's list config
still matches the one the download used. If a reload changed the lists
mid-download, the result is discarded and the refresh runs again at once
instead of waiting a full interval. The reverse race is handled too: a reload
that did not change the list config merges in the rules and status current at
the moment it publishes, so it does not overwrite a refresh applied while it
was parsing. Old rules stay active until the new snapshot is ready, so there
is no window without blocking during a refresh.

#### Status

Each list's status has a sanitized name (origin plus a last segment with a
list extension; never userinfo, other path segments or query strings), rule
count, skipped lines, last success, last error and whether the cached copy
was used.

## 13. Cache pre-warm

Keys: `prewarm` (default `true`) and `prewarm_count` (default 1000,
`0..=10000`). The server counts the A and AAAA names it answered from the
cache or an upstream; blocked, local, special-use and failed names never
count. It keeps the `prewarm_count` busiest and writes them to
`state_dir/prewarm.txt`, one name per line, most queried first, on
SIGTERM/SIGINT and every 10 minutes.

On the next start, once the server is ready, it reads the file (at most
1 MiB, malformed lines skipped) and resolves A and AAAA for each name through
the normal path, so rules, rewrites and the cache apply as they would for a
client. At most 8 lookups run at once and at most 50 start per second. They
are not counted in the metrics, the query log or the top lists. They carry
EDNS without DO, so clients that send no EDNS share no cache entry with them.
Turning `prewarm` off in a reload stops a running pre-warm. A run with no
cacheable traffic keeps the previous list, and counting needs
`query_log_capacity > 0`. Changing `prewarm_count` needs a restart (a reload
logs `restart_required`).

The file is browsing history. It is written atomically with mode 0600 in a
0700 directory the server creates, but anyone who can read `state_dir` can
see which sites your clients visit. With `prewarm = false` nothing is written
and an existing file is deleted at startup.

## 14. Persistent dashboard stats

With `persist_stats` (default `true`), the dashboard and `/metrics` numbers
survive restarts. They are kept in `state_dir/stats.v1`, a small versioned
text file written on SIGTERM/SIGINT and every 5 minutes (a crash loses at
most 5 minutes) and read at startup before the listeners open. It holds the
outcome counters, the request and per-upstream latency histograms, the top
domains, top blocked and top clients, and the per-minute snapshots behind the
5-minute and 24-hour windows. The `dns_*` counters on `/metrics` continue from
the saved values instead of starting at zero, and the dashboard footer shows
since when the top lists and all-time counters have been counting. The query
log ring is never written.

On restore, snapshots older than 24 hours are dropped and downtime counts as
idle, so "last 24 hours" means 24 hours of wall time, not of uptime.
Snapshots older than the newest 10 minutes are thinned to one per 5 minutes in
the file, so a window right after a restart can span a few minutes more than
its name says (the card shows the real span). Per-upstream data is keyed by
position in `upstreams`, so reordering the list re-labels the saved latency
history. The "Won" and hedge counters in the upstream table are not saved.

The reader is strict: at most 1 MiB, UTF-8, first line `sopedu-stats v1`,
every count bounded, at most 100 rows per top table. A missing file is
normal. A corrupt, truncated, oversized or other-version file is ignored with
one `stats_ignored` warning and replaced at the next write. Names are stored
as hex of their wire form, so a name cannot inject a line. The writer runs on
the blocking pool, reads atomics and takes the log's drain lock, never a lock
the query path uses.

This file is browsing history too: the top domains and clients show what your
clients visited and which ones are busy. It is written atomically with mode
0600 in a 0700 directory the server creates, but anyone who can read
`state_dir` can read it. With `persist_stats = false` nothing is written and
an existing file is deleted at startup; a reload that turns it off deletes
the file at the next save.

## 15. Web UI, health and metrics

### The listener

With `ui_enabled = true` (the default), a small read-only HTTP listener binds
`ui_listen` (default `127.0.0.1:9999`). If the bind fails, startup fails; set
`ui_enabled = false` to turn the UI off. Changing either key needs a restart.

The UI has no authentication and cannot change the server's state. Keep it on
loopback and reach it with `ssh -L 9999:127.0.0.1:9999 host` on a plain host
or `kubectl port-forward` on Kubernetes. A request whose `Host` header is a
name instead of an IP (for example `http://myhost:9999/`) gets 403
`forbidden host`; use the IP address or `localhost`.

The UI serves `GET` and `HEAD`, and `POST` only on `/rules` (a form that is
checked and answered, never stored). Any other path gets 404 and any other
method 405.

#### Connection limits

The UI accepts 16 concurrent connections, at most 4 from one client address.
The request-head timeout is 2 s and doubles as the keep-alive idle timeout,
heads are limited to 8 KiB, and a connection lives at most 30 s (a live-tail
connection up to 5.5 minutes). When the pool or a host's share is full, up to
16 more connections, at most 4 per client address, are accepted for
`/healthz` and `/metrics` only: one request each, 5 s at most, and 503 for any
other path. Idle browser tabs, live tails or another host therefore cannot
make the readiness probe fail. Past that, connections are closed at accept. A
local process that shares the probe's loopback address can still use up that
address's 4.

### Pages

`GET /` is the dashboard. It shows current qps (last ~10 s), and for the last
5 minutes and the last 24 hours: queries, average qps, cache hit % (fresh and
stale hits), blocked %, and p50/p95/p99 request latency. Latency is the upper
edge of a power-of-two bucket, so it is accurate to within a factor of two.
Windows cover less until enough history exists, and the page shows the span
covered. It also shows upstream health (state, EWMA latency, in flight, wins
and share of wins, last error; URLs redacted to their origin), blocklists
(rule count, last update, status; read-only, refreshed on the
`refresh_hours` schedule), and the top 10 domains, blocked domains and
clients. The page re-fetches itself every 5 s.

`GET /log` is the query log. You can filter by client (substring), domain
(substring), result and qtype, and follow a live tail over Server-Sent Events
with a pause button. Each row has a "Rule" action that shows `||domain^` and
`@@||domain^$important` with copy buttons, for pasting into the config. A
blocked row names the list that blocked it (`user rules` for inline rules).
The matcher keeps hashes and no rule text, so the list is the most precise
origin it can give.

`/rules` holds the rule tester, the rule editor and the rewrites. It is
read-only, and the config stays the source of truth (GitOps).

- "Test a domain" (`POST name`, `qtype`, optional `client`) shows what the
  server would answer for a name, a type and a client IP. You get one verdict
  (`Blocked`, `Rewrite`, `Local zone`, `Special-use name`, `Local` for an
  unconfigured `.local`, `Refused`, `Minimal ANY answer`, or `Forwarded` to
  the cache and upstreams), the reply (`NXDOMAIN`, `NOERROR 192.0.2.7`, ...)
  and whether the client is filtered. The tester does not look in the cache or
  send anything. It runs the server's own decision code without touching counters, the log
  or the cache, so it cannot disagree with a real query. For a
  `no_filter_clients` or `no_filter_macs` client the blocklist is skipped; the
  page says so and still lists the matching rules. The tester cannot see
  upstream CNAMEs, so it notes that a CNAME to a blocked name would also be
  blocked (`block_cname_targets`).
- Below the verdict, every blocklist rule that matches the name or one of its
  parent domains (as the matcher checks them) is listed strongest first:
  important allow, important block, allow, block. Each shows its list and line,
  and the strongest applicable one is tagged "decides". An exact `|name^` rule
  on a parent is listed as not applying. Because the matcher keeps only hashes,
  the table decides what matches and the rule text is looked up on demand: the
  inline `user_rules` and each list's cached copy under `state_dir/lists` are
  re-read for just those parents. The lookup is limited to 128 MiB, 250 ms and
  200 lines, runs one at a time, and runs on the request thread inside
  `block_in_place` so other tasks move off that worker. A rule whose text is
  not found is still shown in normalized form (`||name^`,
  `@@||name^$important`, `|name^`; a plain hostname normalizes to `||name^`,
  a hosts entry to `|name^`) with an unknown list, and the page says when the
  lookup was cut short. Until the next refresh, the cached copy can be newer
  than the loaded table. The page also offers block and allow rules for the
  tested name.
- "User rules" (`POST rules`, at most 5000 lines) checks pasted rules with
  the blocklist parser. It lists errors with 1-based line numbers and a reason
  (unsupported modifier, missing `^`, invalid domain, ...), then the
  normalized rules and a `user_rules = [...]` block, each with a copy button
  for the ConfigMap. The form starts with the current `user_rules`. Nothing is
  saved or applied.
- "Rewrites" shows the `[rewrites]` table with a copy button per row.

`/clients` lists known clients from the query log's client sketch (the
busiest 100, approximate counts since start), `no_filter_clients`,
`client_names` (IP keys), and neighbours whose ARP MAC is in
`no_filter_macs`. Columns are address, name, MAC (kernel ARP table, IPv4,
Linux), whether filtering is on, and queries. The page re-fetches itself
every 5 s.

`GET /api/dashboard`, `GET /api/log?client=&q=&result=&qtype=&limit=` (limit
1..=1000, default 200) and `GET /api/log/stream` (same filters) return the
JSON behind the two pages and the SSE feed. At most 4 live tails run at once,
and a fifth gets 503. A client that stops reading is dropped instead of
buffered. Each tail ends after 5 minutes and the browser reconnects.

### Browser-facing protections

- `/`, `/log`, `/rules`, `/clients`, `/app.css`, `/app.js` and `/api/*` answer
  only when `Host` is present and is an IP literal or `localhost`. Anything
  else gets 403, including an HTTP/1.0 request without `Host`. This stops a
  DNS-rebinding page from reading them. `/healthz` and `/metrics` accept any
  valid `Host`, or none over HTTP/1.0.
- `/api/*`, including the live tail, also returns 403 to a background request
  from another site's page (`Sec-Fetch-Site: cross-site`, or `same-site` that
  is not a top-level navigation), so such a page cannot hold the live-tail
  slots.
- A `POST` must be same-origin: `Sec-Fetch-Site: same-origin`, or an `Origin`
  whose authority equals `Host`. A request with neither, or with a foreign
  one, gets 403 before any handler runs. A `Content-Length` over 64 KiB gets
  413, and a chunked body that grows past 64 KiB gets 400; both close the
  connection. The body must arrive within 5 s.
- An HTTP/1.1 request gets 400 if it has no `Host` (RFC 9112 §3.2), two
  `Host` lines, a `Host` value that is not visible ASCII, or an absolute-form
  target that names another authority.
- Responses carry `Content-Security-Policy: default-src 'self'` (the pages use
  no inline script or style and no CDN) and `X-Content-Type-Options: nosniff`.
  Every DNS name and client-controlled string is escaped, and names show
  RFC 4343 escapes for dots inside labels and for non-printable bytes.
  Blocklist and upstream URLs are sent only in redacted form.

### Query log

The query log is an in-memory ring of `query_log_capacity` entries (default
10000, about 112 bytes each, at most 1000000; changing it needs a restart).
`0` turns off the log, the top lists and the live tail; counters, windows and
`/metrics` keep working.

Each entry holds the time, client, the first 64 wire bytes of the lowercase
qname (longer names are marked and get no rule action), qtype, result
(`cache`, `stale`, `blocked`, `local`, `upstream`, `servfail`, `other`), the
upstream index (`fallback` for the plain servers), total latency and the list
that blocked it.

Packets dropped by the rate limiter or the UDP in-flight limit are counted in
`dns_queries_total{result="dropped"}` but not logged, so with the rate limiter
on, a flood from one host cannot push out the useful history. Without it,
every answered query is logged, and a flood fills the ring and pushes out
older entries. Entries are kept only in memory and are lost on restart. The
counters and top lists are not; see
[Persistent dashboard stats](#14-persistent-dashboard-stats).

Recording a query is one write into a per-thread ring (about 35 ns, no lock,
no allocation). A background task fills the top-N lists (Space-Saving, 100
counters, counts are upper bounds) from the ring every 0.5 s, never on the
DNS path. Under a load that wraps a ring faster than that, the lists are a
sample, and the dashboard shows how many entries were overwritten unseen. The
dashboard windows come from per-minute counter snapshots (1441 kept, about
400 KB). The live tail shows the newest 100 matching rows per 0.5 s.

### `/healthz`

`GET /healthz` returns 200 `ok` when the listeners are up, at least one
configured blocklist has loaded (or none is configured), and at least one DoH
upstream is neither behind an open circuit nor paused by a `Retry-After` its
probe drew (or none is configured). Otherwise it returns 503. The Kubernetes
readiness probe uses it with `httpGet host: 127.0.0.1`, because the listener
is on loopback. Liveness is a TCP check on :53.

### `/metrics`

`GET /metrics` serves Prometheus text:

- `dns_queries_total{result}` with `cache`, `stale`, `blocked`, `local`
  (rewrite, reverse zone, special-use, `.local`), `upstream`, `servfail`,
  `other` (REFUSED, FORMERR, NOTIMP) and `dropped` (no reply sent: the rate
  limit, the UDP in-flight bound, the per-host limit on TC=1 replies to an
  over-cap host, or a UDP answer discarded after `udp_discard_timeout_ms`).
- `dns_upstream_errors_total`
- `dns_plain_fallback_answers_total` (answers obtained over the plaintext
  `fallback` after every DoH attempt failed; nonzero means a downgrade)
- `dns_request_duration_seconds` (histogram, log2 buckets from 1 us to 8.4 s)
- `dns_upstream_duration_seconds{upstream}` (histogram, successful DoH
  exchanges, labelled by configured index, never by URL)
- `dns_cache_entries`, `dns_cache_bytes`
- `dns_upstream_inflight` (upstream exchanges in flight, at most
  `upstream_inflight_max`) and `dns_udp_inflight` (UDP requests on the slow
  path, at most `udp_inflight_max`)
- `dns_blocklist_rejected_oversize_total` (lists stopped while streaming by
  `blocklist_max_bytes` or `blocklist_max_lines`),
  `dns_blocklist_buffer_peak_bytes` (the largest list parse buffer held) and
  `dns_blocklist_buffer_limit_bytes` (the byte bound in force)
- `dns_blocklist_rules{list}`, `dns_blocklist_last_success_timestamp{list}`
  (list is the sanitized display name, for example
  `https://host/filter_1.txt`; the timestamp is absent until a first success)

Counters live in per-thread shards padded to a cache line and are summed on
scrape, so the DNS path takes no lock and shares no atomic between workers.
For an inline UDP cache hit, request time stops when the reply is built,
before `send_to`.

## 16. Memory

Memory grows with the number of unique domains. Domain length and input line
count do not matter: the blocklist table uses 11 bytes per slot at a 0.75
load factor, about 14.7 bytes per domain. Lists are streamed, so downloaded
text is not kept. During a refresh the server briefly holds the old table,
the builder entries and the new table, and the old snapshot stays active.

The sample Kubernetes manifest sets a 128Mi limit. That is not enough to
guarantee room for 1.4 million *distinct* domains plus a full response
cache, so measure with your own lists, including through a refresh, before
you rely on it. For larger unique sets, cut the lists or the cache, or raise
the pod limit.

Measurements:

- The four public HostlistsRegistry lists in `deploy/kubernetes.yaml`
  (`filter_1`, `filter_24`, `filter_27`, `filter_51`) merged on 2026-11-01 to
  516,060 unique domains (885 skipped lines). The fingerprint table was
  7,569,177 bytes (14.7 bytes per domain). A macOS arm64 release build peaked
  at 32.1 MiB RSS loading the real lists in the builder benchmark. The full
  server, with a warm cache and both the old and new snapshots resident during
  a refresh, peaked at 74.1 MiB RSS. Neither number comes from a Linux pod.
- On Linux (k3s pod, 1 CPU, 516k unique list rules from the same four lists), the
  process peak resident set (`VmHWM`) was 18.9 MiB idle and 18.9 MiB after the
  full benchmark matrix ([1.1.0.md](bench/1.1.0.md)).
- On Linux (arm64 container) the worst case was measured directly on a
  release build: a refresh of the same four lists while the 4 MiB cache was
  96% full, the old rule set was still blocking and queries kept arriving.
  The process peaked at 43.4 MiB RSS.

## 17. Building and the container image

```sh
cargo fmt -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --release --locked
cargo deny check
docker build -t sopedu-dns:latest .
# Native multi-architecture builders or QEMU/binfmt must be available:
docker buildx build --platform linux/amd64,linux/arm64 \
  -t YOUR_REGISTRY/sopedu-dns:latest --push .
```

Released images are at `ghcr.io/dkhalizov/sopedu-dns` (`linux/amd64` and
`linux/arm64`, tagged with the version and `latest`). They contain the same
static binaries as the GitHub Release.

CI (`.github/workflows/ci.yml`) runs these checks on every push and pull
request with the toolchain pinned in `rust-toolchain.toml`. `cargo deny check`
enforces the license allowlist and crates.io-only sources set in `deny.toml`;
install it with `cargo install cargo-deny --locked`. Outbound TLS (reqwest
with rustls and ring) verifies against the system root store, `SSL_CERT_FILE`
when set, never bundled CDLA-licensed roots; `deny.toml` checks the targets we
build, which leaves out the wasm32-only `webpki-root-certs` in `Cargo.lock`.

### Allocator

The release binary uses the platform allocator (musl's malloc in the Alpine
image). For experiments, two optional features swap the global allocator:
`mimalloc` (`cargo build --release --features mimalloc`) and `jemalloc`
(`--features jemalloc`, through `tikv-jemallocator`). Enabling both fails
with a `compile_error!`. Neither is on by default, so the shipped binary, the
release profile and the Docker image stay the same unless a build opts in.

### Image

The Alpine build uses musl and rustls with the platform root store and
produces a static binary in a nonroot `scratch` image. The build stage
installs Alpine's `ca-certificates` and copies the bundle to
`/etc/ssl/certs/ca-certificates.crt`, and `SSL_CERT_FILE` points at it. The
image needs no OpenSSL and has no compiled-in roots. The container still needs
working DNS to resolve blocklist hostnames (cluster DNS on Kubernetes).
