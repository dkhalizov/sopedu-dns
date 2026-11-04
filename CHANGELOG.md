# Changelog

Notable changes go here. The format is
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and from the first
release on we follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.0.0] - 2026-11-04

First public release.

### Added

- DNS forwarder over UDP and TCP. `listen` takes one address or up to 16, for
  example an IPv4 and an IPv6 LAN address. Wildcard listeners reply from the
  address the query was sent to.
- Blocking from hosts files and adblock-style lists (`||ads.example^`, `@@`
  exceptions, `$important`), plus `user_rules`. Blocked names get NXDOMAIN.
  Answers whose CNAME chain reaches a blocked name are blocked too
  (`block_cname_targets`). Lists are cached on disk and refreshed every
  `refresh_hours`.
- DNS-over-HTTPS upstreams. The default `fastest` strategy races and hedges
  them; `ordered` keeps each query with the first healthy upstream in config
  order. Circuit breakers, health probes and `Retry-After` handling keep a
  failing upstream out of the way.
- Optional plain-DNS `fallback`, off by default. It kicks in only when no DoH
  upstream is reachable. Every use is counted in `/metrics` and logged, and
  the dashboard shows "degraded".
- Response cache with byte and entry limits, coalescing of concurrent misses,
  prefetch of popular names, serve-stale (RFC 8767, `optimistic_max_age`,
  `serve_stale_client_timeout_ms`) and failure caching (RFC 9520).
- Cache pre-warm: the most queried names are saved to `state_dir` and resolved
  again at the next start (`prewarm`, `prewarm_count`).
- Local names: `[rewrites]` with `*.suffix` wildcards, local answers for
  `home.arpa`, `.local`, `.onion`, private reverse zones (RFC 6303) and other
  special-use names, and the RFC 8482 minimal answer to QTYPE ANY.
- Access control: `allowed_clients` defaults to loopback and private ranges,
  so the server isn't an open resolver. Per-host rate limit
  (`rate_limit_qps`), per-client upstream limits and UDP/TCP connection limits.
  `no_filter_clients` and `no_filter_macs` exempt chosen clients from blocking.
- Read-only web UI on `ui_listen` (`127.0.0.1:9999` by default): dashboard, query
  log with live tail, rule tester and clients page, with JSON under `/api/`.
  Dashboard counters, latency histograms and top lists persist across restarts
  (`persist_stats`).
- Config reload on SIGHUP or file change. The new file is checked before
  it's used. `--check` validates a config offline. `--help` and `--version`.
- `/healthz` and Prometheus `/metrics`. Structured log lines, and startup
  errors that name the address or key at fault.
- Strict DNS RFC handling: EDNS (RFC 6891) including BADVERS and FORMERR,
  Extended DNS Errors (RFC 8914), TCP pipelining (RFC 7766), and DNSSEC
  records passed through to validating clients.
- Fuzz targets, property tests, micro-benchmarks with a CI regression gate,
  `cargo deny` checks, and SECURITY, CONTRIBUTING and CODE_OF_CONDUCT policies.
- Static Linux binaries (x86_64 and aarch64, musl), a `scratch` container
  image with a baked config and state volume, and a two-replica Kubernetes
  manifest in `deploy/kubernetes.yaml`.
