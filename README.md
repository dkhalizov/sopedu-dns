<div align="center">

# sopedu-dns

Network-wide ad blocking that follows the DNS RFCs.

A single static binary that blocks ads, forwards the rest over DNS-over-HTTPS and uses about 20 MiB of RAM.

[![CI](https://github.com/dkhalizov/sopedu-dns/actions/workflows/ci.yml/badge.svg)](https://github.com/dkhalizov/sopedu-dns/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/dkhalizov/sopedu-dns)](https://github.com/dkhalizov/sopedu-dns/releases)
[![Container](https://img.shields.io/badge/ghcr.io-sopedu--dns-2496ED?logo=docker&logoColor=white)](https://github.com/dkhalizov/sopedu-dns/pkgs/container/sopedu-dns)
[![crates.io](https://img.shields.io/crates/v/sopedu-dns)](https://crates.io/crates/sopedu-dns)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)
<br>
[![RFC MUSTs](https://img.shields.io/badge/RFC%20MUST%20checks-181%2F181-brightgreen)](docs/conformance.md)
[![Throughput](https://img.shields.io/badge/UDP-94k%20qps%20on%201%20core-orange)](docs/bench/final-2026-11-04.md)
[![Memory](https://img.shields.io/badge/RSS-19%20MiB%20with%20744k%20rules-purple)](docs/bench/final-2026-11-04.md)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/dkhalizov/sopedu-dns/badge)](https://scorecard.dev/viewer/?uri=github.com/dkhalizov/sopedu-dns)

</div>

There are already good DNS blockers out there. Pi-hole and AdGuard Home do a
lot, and they're probably a better fit if you want an all-in-one network
management tool. I wanted to see what a smaller, more focused DNS service
could look like.

sopedu-dns sits between your devices and the internet. Phones, laptops, the
TV and that one smart plug that phones home every 30 seconds ask it for
names. Ads and trackers get NXDOMAIN, popular names come straight from the
cache, and everything else goes upstream over DNS-over-HTTPS, so your ISP
sees less of it.

It runs on a Raspberry Pi, a mini PC, a Docker host or a small Kubernetes
cluster. It's written in Rust, has no database, and needs root only to bind
port 53.

## Features

- Blocks with hosts files and adblock-style lists (`||ads.example^`, `@@`
  exceptions, `$important`), including CNAME chains that end at a blocked
  name, where a lot of trackers hide. Lists are cached on disk and refreshed
  on a schedule. If a list suddenly shrinks, the new copy is held back so it
  can't wipe your blocking.
- Sends queries over DoH to several providers, raced and hedged, with
  circuit breakers and health probes. `ordered` mode keeps every query with
  one provider instead. There is a plain DNS fallback; it's off by default,
  and if you turn it on every use is logged.
- Caches with TTLs, serve-stale (RFC 8767), prefetch for popular names,
  coalesced misses and failure caching (RFC 9520). At startup it resolves
  your most-queried names again, so the cache starts warm.
- Answers local names: rewrites with `*.suffix` wildcards, `home.arpa` and
  private reverse zones. Chosen clients can skip filtering, by IP or MAC.
- Treats every RFC MUST that applies to a forwarder as binding. We write
  down every deliberate deviation in [the spec](docs/specs/dns-forwarder.md).
- Isn't an open resolver out of the box. Every queue and table has a size
  limit, the parsers are fuzzed, and the `scratch` image has no shell.
- Has a web UI with a dashboard, a query log with live tail, a clients page
  and a rule tester that tells you which list and line blocked a name.
- Reloads on SIGHUP or file change and checks the new config before
  applying it. Exposes `/healthz`, Prometheus `/metrics` and structured logs.

## How fast?

On one CPU core with 744k blocklist rules loaded, sopedu-dns answered
94k queries per second. Its slowest run beat Blocky's best by 3.9× and
Pi-hole's best by 15×. Its range overlapped Unbound's, and Unbound had no
blocklists loaded.

| Server | UDP qps, median of 3 (min-max) | Cache-hit p99 at 5k qps | Memory at end of run |
|---|---|---|---|
| **sopedu-dns 1.0.0** | 94.1k (64.2-106.7k) | 1.3 ms | 18.9 MiB |
| Unbound 1.26.2 ¹ | 64.6k (49.9-77.4k) | 1.7 ms | 26.2 MiB |
| dnsmasq 2.91 ¹ | 27.5k (25.3-27.5k) | 13.8 ms | 10.2 MiB |
| Blocky v0.35.0 | 16.4k (16.4-16.4k) | 3.6 ms | 87.2 MiB |
| Pi-hole 2026.10.1 | 4.1k (3.6-4.1k) | 120.8 ms ² | 234.1 MiB |
| AdGuard Home v0.107.79 | stopped answering ³ | 46.1 ms ² | 509.8 MiB |

¹ No blocklists loaded: plain forwarders, here as a reference.
² Dropped queries at this rate: 8,711 (Pi-hole) and 690 (AdGuard Home) of 75,000.
³ 6.7k qps in the first run, then nothing; it reached its 512 MiB limit.

Where it doesn't win: over TCP, Unbound did 57.8k qps to our 54.5k. At
50 qps, AdGuard Home's p99 was one histogram bucket lower (1.15 vs 1.9 ms).
dnsmasq uses less memory. Inside the process a cache hit takes at most 8 µs
at p99; the rest of the cache-hit latency in the table is network time.

Test setup: a two-node k3s cluster. The server Pod got 1 CPU and 512 MiB on an Intel i5-9400T (Linux 6.8), dnsperf 2.14 ran on the other
node, and both nodes kept their usual workloads. Every server got the same
mock upstream (+10 ms) and the blocking ones the same four public lists.
The query stream is 12,692 real names from a home network, so you can't
replay it exactly. dnsmasq and Pi-hole don't cache HTTPS records, which are
24% of that stream, and that explains part of their hit latency. The harness
takes any list of names, so run it on yours and open an issue with the
numbers.
Full results: [docs/bench/final-2026-11-04.md](docs/bench/final-2026-11-04.md).
Method: [bench/competitors/README.md](bench/competitors/README.md).

## RFC conformance

We wrote a conformance harness straight from the RFCs and ran it against
sopedu-dns and four popular servers, all set up as plain forwarders. These
are the MUST and MUST NOT checks every server could be tested on:

| Server | Passed |
|---|---|
| **sopedu-dns 1.0.0** | 181 / 181 |
| Unbound 1.26.2 | 178 / 181 |
| AdGuard Home v0.107.80 | 177 / 181 |
| dnsmasq 2.91 | 173 / 181 |
| Pi-hole (FTL v6.8) | 170 / 181 |

The misses are EDNS corner cases (BADVERS, malformed OPT records) and, for
dnsmasq and Pi-hole, no failure caching. None of it breaks normal browsing.
It's our harness and our reading of the RFCs, so treat it as one data
point. What each server failed, and the RFC list we follow:
[docs/conformance.md](docs/conformance.md).

## Quick start

### Binary

Static Linux binaries (x86_64 and aarch64) with SHA-256 checksums are on the
[releases page](https://github.com/dkhalizov/sopedu-dns/releases). Each one
has signed build provenance: `gh attestation verify <tarball> --repo dkhalizov/sopedu-dns`.

```sh
tar xzf sopedu-dns-v1.0.0-x86_64-unknown-linux-musl.tar.gz
cd sopedu-dns-v1.0.0-x86_64-unknown-linux-musl
cp config.example.toml config.toml   # DNS on 127.0.0.1:15353, UI on 127.0.0.1:9999
./sopedu-dns --check config.toml     # prints "config ok"
./sopedu-dns config.toml
```

Then, in another terminal:

```sh
dig @127.0.0.1 -p 15353 example.com          # forwarded over DoH
dig @127.0.0.1 -p 15353 doubleclick.net      # NXDOMAIN, blocked
curl -s http://127.0.0.1:9999/healthz        # "ok" once a blocklist has loaded and an upstream is reachable
```

### Docker

Use the host network on Linux, so clients keep their real source addresses:

```sh
docker run -d --name sopedu-dns --restart unless-stopped --network host \
  --user 0 --cap-drop ALL --cap-add NET_BIND_SERVICE --read-only \
  -v sopedu-state:/var/lib/sopedu-dns ghcr.io/dkhalizov/sopedu-dns:latest
```

`--user 0` is there to bind port 53; every other capability is dropped. The
built-in config has the UI off and no blocklists, so mount your own with `-v "$PWD/my.toml:/etc/sopedu-dns/config.toml:ro"`. Before
you publish ports instead of using the host network, read
[the warning](docs/configuration.md#docker).

### Kubernetes

```sh
kubectl apply -f deploy/kubernetes.yaml
kubectl rollout status deployment/sopedu-dns
```

Two replicas on `hostNetwork`, one per node, with only `NET_BIND_SERVICE`
and a read-only root filesystem. You need two schedulable nodes with port
53 free. Details: [Kubernetes](docs/configuration.md#kubernetes).

### From source

`cargo install --locked sopedu-dns` (`--locked` builds with the tested
dependency versions), or clone and `cargo build --release`. The pinned
toolchain installs itself through [rustup](https://rustup.rs).

### Point your network at it

Set the host's address as the DNS server in your router's DHCP settings.
Don't add a public resolver as a second DNS server: plenty of devices will
happily use it and skip your blocking.

## Configuration

Every key is optional. A real home network looks like this:

```toml
listen = "0.0.0.0:53"
upstreams = ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"]
blocklists = ["https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt"]
state_dir = "/var/lib/sopedu-dns"
# allowed_clients defaults to loopback and private ranges (IPv6 ULA
# included). For IPv6 clients, see "IPv6 renumbering" in docs/configuration.md.

[rewrites]
"nas.home.arpa" = "192.168.1.10"
```

[config.example.toml](config.example.toml) explains the common keys, and
[docs/configuration.md](docs/configuration.md) has all of them, with
defaults, limits and what a reload changes.

## Web UI

On `127.0.0.1:9999` by default: dashboard (qps, hit rate, latency, upstream
health, top domains), query log with live tail, rule tester, clients. It's
read-only on purpose: the config file is the source of truth, and the rule
pages give you lines to paste into it.

There is no login, so keep it on loopback. Reach it with
`ssh -L 9999:127.0.0.1:9999 <host>` or
`kubectl port-forward deployment/sopedu-dns 9999:9999`. It rejects requests
whose `Host` is a name (DNS rebinding defence), and logs a warning if you
bind it anywhere but loopback.

## What it doesn't do

- No recursion. Every cache miss goes to the DoH upstreams you configure
  (Cloudflare and Google by default).
- No DNSSEC validation. DNSSEC records pass through to clients that
  validate themselves.
- No encrypted listeners. Clients talk plain DNS over UDP and TCP; there's
  no DoH, DoT or DoQ server.
- No DHCP. Your router keeps that job.
- No editing from the UI, no logins, client groups or schedules. The only
  per-client policy is a filtering bypass by IP or MAC.
- No zone transfers, dynamic updates, TSIG or SIG(0). Those requests are
  refused.

## Docs

[Configuration](docs/configuration.md) ·
[Behaviour spec](docs/specs/dns-forwarder.md) ·
[RFC conformance](docs/conformance.md) ·
[Benchmarks](docs/bench/) ·
[Security](SECURITY.md) ·
[Contributing](CONTRIBUTING.md) ·
[Changelog](CHANGELOG.md)

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at
your option.

Blocklists are downloaded at run time and aren't part of this repository;
each has its own license. AdGuard Home, Pi-hole, Blocky, Unbound, dnsmasq
and other product names are trademarks of their owners. sopedu-dns isn't
affiliated with any of them; see [THIRD_PARTY.md](THIRD_PARTY.md).
