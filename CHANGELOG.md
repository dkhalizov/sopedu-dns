# Changelog

Notable changes go here. The format is
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.1.0] - 2026-11-10

### Added

- `home_arpa_server` sends `home.arpa` to its authoritative server on your
  network (RFC 8375). Unset, the zone stays local.
- `failure_cache_seconds` sets the first window in which a failed resolution
  is not retried (RFC 9520). Repeated failures double it, up to 30 s or the
  configured window.
- `upstream_source_ports_exclude` avoids chosen source ports; plain upstream
  queries now draw a random source port from 1024..=65535 themselves
  instead of taking the OS ephemeral range (RFC 5452).
- `empty_zone_soa_rname`, `empty_zone_ttl` and `empty_zone_ns` configure the
  synthetic SOA and NS of the local empty zones (RFC 6303).
- `forward_reverse_zones` forwards chosen local reverse zones, one by one,
  while the others stay local (RFC 6303).
- `/metrics` reports upstream and UDP work in flight
  (`dns_upstream_inflight`, `dns_udp_inflight`) and the streaming list bounds
  (`dns_blocklist_rejected_oversize_total`, `dns_blocklist_buffer_peak_bytes`,
  `dns_blocklist_buffer_limit_bytes`).

### Changed

- TSIG and SIG(0) signed messages and TKEY are forwarded unchanged (over TCP
  to a plain server), and their replies relayed unchanged, never cached; name
  policy runs first, and they count against `upstream_inflight_per_client`. AXFR and IXFR over TCP stream from a plain `fallback`
  server, message by message, at most 16 at once. AXFR over UDP stays REFUSED
  (RFC 5625).
- Every QTYPE and QCLASS RFC 5625 covers is proxied: CH class, QCLASS ANY and
  NONE, TYPE 0, OPT (41) and the unassigned 129-248 range. NXNAME stays
  FORMERR, and ANY keeps the minimal RFC 8482 answer.
- DoH replies are scrubbed of off-chain records, like plain replies (RFC 5452).
  Additional now keeps only OPT on DoH too.
- A DoH redirect is not followed: the query only reaches the configured URI,
  and a 3xx fails the attempt. This is our policy: RFC 8484 section 3 gives
  no resolution privilege to URIs outside the configuration.
- An unknown EDNS option is forwarded unchanged; ECS, Cookie, keepalive and
  Padding still stop at the forwarder (RFC 5625).
- A SERVFAIL moves on to the next DoH upstream whatever its Extended DNS Error
  says (RFC 8914). If you rely on upstream DNSSEC validation, list only
  validating upstreams: a non-validating one can answer a name a validating one
  rejected.
- `private_ptr = "forward"` now forwards every query for the private reverse
  zones, not only PTR, except shared CGNAT space (RFC 6303).
- A fresh NXDOMAIN answers every QTYPE of its name from the cache (RFC 2308).
  One at the end of a CNAME chain is cached for the chain's last name
  (RFC 8020), when it came over DoH or from a trusted plain server.
- Plain upstreams share one pipelined TCP connection per server, reused until
  idle for 10 s (RFC 7766).
- A silent plain UDP query is sent again once, after an interval derived from
  the measured RTT and kept between 2 and 5 s (RFC 1035, RFC 8085). A path
  that stays silent is then tried once over TCP within the same budget
  (RFC 9715).
- A `udp_max_payload` above 1400 is lowered to 1400 with a warning
  (RFC 9715). Configs from 1.0.0 still load.
- Answers from `trust_plain_upstreams` servers no longer count as a plaintext
  downgrade.
- A DoH answer's AD bit, kept for clients that set AD or DO, now stays on fresh
  cache hits too instead of being cleared after the first answer (RFC 4035).
  Stale answers still clear it.

### Fixed

- The dashboard's top lists and the pre-warm tracker no longer delay cache
  hits. Every half second they took in the queries since the last update in
  one go, on the thread that answers queries, and finding the smallest
  counter scanned every counter (1,000 for the pre-warm tracker by default).
  They now find it in logarithmic time and take 128 queries at a time,
  letting queries through in between. In a local test on one CPU core at
  5,000 cache hits a second, the slowest 0.1% of hits went from about 1.6 ms
  to about 0.6 ms. The pre-warm list is also written off the query threads.
- The benchmark docs now count unique rules: the four lists hold 744k entries
  and 516k unique rules. The measurements themselves did not change.
- Upstream RDATA is validated for DS, RRSIG, NSEC, NSEC3, DNSKEY, TLSA, SVCB,
  HTTPS and CAA (RFC 9267), and names in RRSIG, NSEC and SVCB are sent
  uncompressed.
- A compression pointer to a root octet in a response is refused, and so is a
  first pointer that lands on another pointer (RFC 9267).
- A DoH upstream is deemed dead for at most 300 s, not 600 s (RFC 2308).
- Names below the `::` and `::1` reverse zones are answered locally (RFC 9665).
- With `private_ptr = "forward"`, PTR queries for `home.arpa` stay local.
- A TCP client reset drops the answers in flight (RFC 7766).
- Failure marks are per question and server, so a failed attempt no longer
  suppresses a server it never reached (RFC 2308).
- Additional data that does not fit a UDP reply is omitted with TC clear
  (RFC 2181).
- A record repeated by an upstream is relayed once (RFC 2181).
- A signature that is not the last record, or a second signature of either
  kind (TSIG or SIG(0)), is FORMERR (RFC 8945, RFC 2931).
- Data learned from a name with a `*` label is never cached (RFC 1035).
- MAILB and MAILA answers holding MB, MG, MR, MD and MF are accepted
  (RFC 1035).
- A negative TTL comes from the SOA of the denied name (RFC 1034).
- An alias loop is a failed attempt instead of a NOERROR with no data
  (RFC 1034).
- A forwarded NODATA or NXDOMAIN no longer carries the zone NS set (RFC 2308).
- RDATA of LOC, CERT, SSHFP, DHCID, NSEC3PARAM, SMIMEA, CDS, CDNSKEY,
  OPENPGPKEY, ZONEMD, SPF, URI, X25, GPOS, NID, L32, L64, EUI48 and EUI64
  must fit its format; a malformed one fails the upstream reply (RFC 9267).
- A relayed zone transfer leaves the client TCP connection open for the next
  query (RFC 7766), and other queries on that connection are answered while
  the transfer runs (RFC 5936).
- A signed reply too large for the UDP client comes back with TC set instead
  of oversized (RFC 5625).
- A shared upstream TCP connection that went silent is closed at the next
  idle check, not only when a later query replaces it (RFC 7766).
- With several plain fallbacks, every address gets its first try before any
  is retransmitted to (RFC 1035).
- A response sent to the server over TCP with QTYPE AXFR or IXFR is ignored
  like any other response, instead of being relayed upstream as a transfer.
- A flood of distinct failures no longer evicts a failure mark younger than one
  second; new failures go uncached until one is old enough (RFC 9520).
- At most two queries for one question are in flight to a plain upstream at
  once; further DO, CD or EDNS variants of the name wait for a slot (RFC 5452).
- An upstream TCP connection that answers with junk ends that attempt; it no
  longer opens up to two more connections for the same query.
- A signed query is not sent over plain DNS while a DoH upstream is only paused.
- Replies from `home_arpa_server` are scrubbed of unrelated records like other
  plain replies, unless `trust_plain_upstreams` is set.
- UDP replies are sent with the don't-fragment flag where that is safe (IPv6,
  and IPv4 on macOS). A reply larger than the path MTU then goes again with TC
  set instead of being fragmented (RFC 9715).

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
- Protocol support: EDNS (RFC 6891) including BADVERS and FORMERR,
  Extended DNS Errors (RFC 8914), TCP pipelining (RFC 7766), and DNSSEC
  records passed through to validating clients.
- Fuzz targets, property tests, micro-benchmarks with a CI regression gate,
  `cargo deny` checks, and SECURITY, CONTRIBUTING and CODE_OF_CONDUCT policies.
- Static Linux binaries (x86_64 and aarch64, musl), a `scratch` container
  image with a baked config and state volume, and a two-replica Kubernetes
  manifest in `deploy/kubernetes.yaml`.
