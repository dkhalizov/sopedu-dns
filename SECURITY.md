# Security policy

## Supported versions

Only the latest release gets security fixes.

## Reporting a vulnerability

Report it privately through GitHub's private vulnerability reporting: the
repository's *Security* tab, then *Report a vulnerability*, or
<https://github.com/dkhalizov/sopedu-dns/security/advisories/new>. Don't put
details in a public issue. If private reporting is unavailable, open a
minimal public issue that only asks for a contact.

You should get an acknowledgement within 7 days. We aim to release a fix
within 90 days of the report. The report may go public once a fix is
released or 90 days have passed, whichever comes first. We'll agree the date
with you and credit you unless you ask us not to.

## Threat model

sopedu-dns is a caching DNS forwarder with blocklists. It listens for plain DNS
(UDP and TCP) from local clients and forwards misses to DNS-over-HTTPS
upstreams. Plain-DNS fallbacks are off by default and used only when you list
them in `fallback`.

### Untrusted inputs

- Every client packet, including packets from clients allowed to query.
- Every upstream reply. Plain-DNS fallback replies can be forged off-path; DoH
  replies come from a TLS-authenticated server, and we still validate them.
- Blocklist downloads and their contents.

### Trusted inputs

- The configuration file and the state directory. Anyone who can write them
  controls the server.
- The host's network configuration and clock.

### What the server defends against

#### Being an open resolver

By default only loopback, RFC 1918, link-local and ULA clients may query
(`allowed_clients`). The RFC 6598 shared space (`100.64.0.0/10`) is opt-in,
because behind a carrier-grade NAT it holds other subscribers. Everyone else
gets REFUSED before reaching any cache, policy or upstream. The host's own
on-link prefixes are never admitted automatically, because on a shared (VPS or
cloud) subnet that would serve other tenants. A refused IPv6 source inside one
of them is logged once per prefix (`client_refused_onlink`).

#### Amplification

An error reply is at most the query plus one 11-byte OPT record. UDP answers
are capped at `udp_max_payload` (1232 bytes); larger ones are truncated so the
client retries over TCP. An optional per-host rate limit (`rate_limit_qps`;
IPv4 /32, IPv6 /128) drops excess traffic from allowed clients without
replying. Queries from unspecified, multicast or broadcast source addresses
are dropped without a reply.

#### Resource exhaustion

Every resource has a bound, most of them configurable: TCP connections (checked against
`allowed_clients` at accept, then capped per client by
`tcp_max_connections_per_client`), queries per connection, pipelined queries,
idle time, UDP requests in flight, upstream requests in flight, cache entries
and bytes, failure-cache size, blocklist bytes/lines/rules and line length. A
full limit fails fast; nothing queues without a bound. One client address
can't hold more than `upstream_inflight_per_client` cache misses (default 64)
over UDP and TCP together. That count includes the stale and prefetch
refreshes its hits start and its UDP queries waiting on an identical lookup,
so a random-subdomain flood at a slow upstream doesn't starve everyone else.
The surplus gets TC=1 over UDP (a forged source gets no SERVFAIL to aim at a
victim) and SERVFAIL over TCP; the TC replies are response limited. These
per-address limits don't stop a LAN host that forges source addresses: it can
fill `upstream_inflight_max`, or a victim's share.

#### Query accumulation bursts (DNSBomb, CVE-2024-33655)

A UDP data reply to a query that has waited longer than
`udp_discard_timeout_ms` (default 1900) is dropped and counted; the answer
stays cached and TCP is unaffected.

#### Cache flushing (DNS CacheFlush)

A large answer (above 16 KiB at the default cache size) is cached only the
second time it's seen, so a scan of one-hit 60 KB answers can't evict the hot
set.

#### Hostile upstream replies

Contradictory shapes (NXDOMAIN with data at the name or on its alias chain,
NOERROR with only other types), meta or query-only RR types (128-255, OPT) in
Answer or Authority, unless the record answers a query for that unassigned
type, and answers in a foreign class are invalid and never relayed or cached.
A plain UDP reply larger than the advertised size (512 without EDNS) is
discarded as a fragmentation suspect, and the question is asked again over
TCP. A DoH 429 or 503 with `Retry-After` pauses that upstream for the stated
time (at most 60 s). Every upstream reply is fully validated before use, and a
malformed one counts as a failed attempt. Ambiguous alias chains are relayed
but never cached.

#### Forced downgrade to plaintext

`fallback` is empty by default, so an on-path attacker who blocks port 443
gets SERVFAIL and stale answers; there is no unauthenticated plain DNS for it
to forge. If you configure fallbacks, you see every use: the
`dns_plain_fallback_answers_total` counter in `/metrics`, a
`plaintext_fallback_used` warning at most once a minute with the count, and a
"degraded" note on the dashboard.

#### Cache poisoning on plain-DNS fallbacks

The fallback path follows RFC 5452:

- random query IDs, random source ports and 0x20 case randomisation;
- a reply counts only if it comes from the queried address and its ID and
  question match;
- mismatched datagrams are discarded and don't end the wait;
- at most two queries for one question are in flight to one plain address at
  once (RFC 5452 §5); further DO, CD or EDNS variants of the name wait for a
  slot, never past their own deadline;
- plaintext fallback runs only after DoH transport failures (never after a
  DNS-level or DNSSEC failure from a reachable DoH upstream), and its answers
  live at most 300 s and are never served stale or prefetched;
- a SERVFAIL moves on to the next DoH upstream whatever its Extended DNS
  Error says (RFC 8914 §6), so with mixed upstreams a non-validating one can
  answer a name a validating one rejected: list validating upstreams only;
- DoH and fallback replies are scrubbed of unrelated records (RFC 5452 §6);
  `trust_plain_upstreams = true` lifts the scrub and the 300 s limit for
  plain servers only;
- a case-only mismatch from a fallback that has echoed our 0x20 case is
  treated as forged; the one un-randomised retry for a normalising upstream
  uses a fresh socket and ID.

#### Parser bugs

The code that parses wire queries, upstream responses and rule lines has fuzz
targets (`fuzz/`) and property tests.

### What it does not do

- No DNSSEC validation. Upstream AD is passed on only in an answer relayed
  directly from a DoH upstream, or a fresh cache hit of one, to a client that
  set AD or DO (RFC 6840 §5.8); stale, local, truncated and plaintext-fallback
  answers never assert AD. A client
  that needs validated data should validate it itself; DNSSEC records pass
  through for that.
- No defence against many-source floods from inside the network. Rate limits
  and TCP caps are per source host, so an attacker who can rotate or spoof
  source addresses on the LAN gets one budget per address.
- No client authentication beyond the source address. UDP source addresses
  can be spoofed, so `allowed_clients` is not authentication.
- No TSIG/SIG(0) checking. Signed requests and TKEY are forwarded unchanged
  and never cached; the server neither verifies nor adds signatures. They count
  against `upstream_inflight_per_client` like a cache miss. Name policy applies
  to the question, but the reply is relayed unchanged, so blocked CNAME targets
  inside it are not checked. Zone
  transfers are relayed over TCP from a plain `fallback` server, at most 16
  at once (others wait for a slot within the upstream timeout), or refused
  when there is none. A fallback
  server that allows transfers to the forwarder's address thereby allows them
  to every client in `allowed_clients`: restrict transfers on that server, or
  leave `fallback` unset.
- No encrypted listener (DoH/DoT) for clients yet. Traffic between clients and
  the server is plain DNS on the local network.

## Hardening checklist for operators

- Keep `allowed_clients` as narrow as your network allows. Never expose port
  53 to the internet with `0.0.0.0/0`.
- Prefer DoH upstreams. Plain fallbacks (off by default) are only as
  trustworthy as the path to them; if you add any, alert on
  `dns_plain_fallback_answers_total`.
- Download blocklists over HTTPS.
- Drop every capability except the one needed to bind port 53
  (`CAP_NET_BIND_SERVICE`), and use a read-only root filesystem.
  `deploy/kubernetes.yaml` shows how.
