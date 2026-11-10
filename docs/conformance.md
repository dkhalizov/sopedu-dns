# RFC conformance

We treat every MUST and MUST NOT that applies to a caching forwarder as
binding. Where an RFC leaves a choice, we take the conservative one. The
behaviour spec ([specs/dns-forwarder.md](specs/dns-forwarder.md)) labels every
deliberate deviation. Where other servers are lenient and a MUST says
otherwise, we follow the MUST: sopedu-dns answers BADVERS to unknown EDNS
versions and FORMERR to malformed OPT records, and it caches upstream
failures.

The [RFC evidence site](https://khalizov.com/sopedu/rfc/) shows
every rule sentence of these RFCs with the test behind it and its result.

The main RFCs we follow:

- DNS and TTLs: RFC 1035, 2181, 3597
- Negative and failure caching: RFC 2308, 9520
- EDNS: RFC 6891
- TCP and pipelining: RFC 7766
- Anti-spoofing on the plain fallback: RFC 5452
- DNSSEC pass-through and AD handling: RFC 4035, 6840
- Special-use and local zones: RFC 6303, 6761, 8375
- Minimal ANY answers: RFC 8482
- DoH: RFC 8484
- Serve-stale: RFC 8767
- Extended DNS Errors: RFC 8914
- One question per query: RFC 9619

## Where we don't follow the RFC text

Some RFC sentences have been replaced by later RFCs that formally update them,
and we follow the later text: RFC 8482 for ANY queries (updates RFC 1034 and
1035), RFC 8767 for stale data and TTLs with the top bit set (updates RFC 1035
and 2181), and RFC 6840 §5.7 for AD in queries (updates RFC 4035). We don't
count those as deviations.

The rest, grouped by reason:

- Performance (all SHOULD rules): RFC 8085 asks UDP applications to space
  datagrams out in time and to fall back to 576-byte messages. Spacing would
  queue concurrent lookups behind each other, so we bound the number of
  queries in flight instead (`upstream_inflight_max`). For message size we follow the
  DNS-specific advice of RFC 9715: 1232 bytes by default, capped at 1400.
  Reply rate limiting (`rate_limit_qps`) is available but off by default.
- Security: a UDP answer that doesn't fit goes out as an empty reply with TC
  set (RFC 1035 §6.2), never cut from the end, so a client never takes a
  partial answer for a full one. RFC 2181 §9 tells clients to ignore the contents of a
  TC reply anyway. Datagrams shorter than a DNS header get no reply: RFC 5625
  §6.3 allows dropping malformed packets, and answering junk invites
  reflection.
- Two RFCs disagree: RFC 6762 §22.1 asks for NXDOMAIN at the link-local
  reverse zone apex, and RFC 6303 §3 asks for the SOA and NS there. We follow
  RFC 6303 so the empty zone stays well formed.
- DNSSEC: sopedu-dns does not validate. In the default `passthrough` mode it
  passes the client's DO bit upstream and doesn't strip records itself. RFC
  4035 §3.2.1 and §4.1 ask a security-aware recursive server to always set DO
  and to strip DNSSEC records for clients that didn't ask. The
  `dnssec = "always_upstream"` mode does both.
- Rules for another role: RFC 2308 asks an iterative resolver to chase a
  CNAME itself and to add referrals to negative answers. A forwarder leaves
  that work to its recursive upstream. The ECS response rules of RFC 7871
  bind servers that use ECS; we strip ECS for privacy.

## Comparison with other servers

On 2026-11-10 we ran one revision of our conformance harness against
sopedu-dns 1.1.0 and five widely used servers, each a plain forwarder in front
of local test upstreams.

A comparison is only fair on what both servers set out to do. Each row
therefore counts only the RFC rules for features that server and sopedu-dns
both implement, and that the harness could configure on both. A rule for a
feature the other server lacks is left out of its row, and so is every rule
for a feature sopedu-dns lacks (see below).

| Server | Version | MUST checks | Passed by it | Passed by sopedu-dns | SHOULD checks | Passed by it | Passed by sopedu-dns |
|---|---|---:|---:|---:|---:|---:|---:|
| dnsmasq | 2.91 | 220 | 220 | 220 | 16 | 15 | 16 |
| AdGuard Home | v0.107.80 | 250 | 243 | 250 | 32 | 32 | 32 |
| Pi-hole (FTL) | v6.8 | 220 | 217 | 220 | 16 | 16 | 16 |
| Unbound | 1.26.2 | 195 | 190 | 195 | 29 | 28 | 29 |
| Numa | 0.25.0 | 175 | 172 | 175 | 15 | 15 | 15 |

dnsmasq passed every MUST check it shares with sopedu-dns. AdGuard Home's row
is larger because it has a DoH upstream client too, so the RFC 8484 rules count
for it.

What the others missed, on features they implement:

- AdGuard Home answers FORMERR to malformed OPT option data but leaves the OPT
  record out of that reply (RFC 6891 §7), and its DoH client does not subtract
  the HTTP `Age` header from DNS TTLs (RFC 8484 §5.1).
- Pi-hole sends a 513-octet answer without TC to a client that advertised a
  UDP size below 512 (RFC 6891 §6.2.3).
- Unbound answers NOERROR instead of FORMERR to malformed OPT option data, and
  leaves the OPT record out of its FORMERR to a duplicate OPT or one with a
  non-root owner (RFC 6891 §7).
- Numa lowercases the names inside RRSIG and NSEC records (RFC 3597 §3), and
  leaves the OPT record out of its FORMERR to an OPT with a non-root owner
  (RFC 6891 §7).
- At SHOULD level, dnsmasq and Unbound reuse a negative answer that came
  without an SOA record (RFC 2308 §5).

Most of them only show up with unusual clients or upstreams.

Not compared, because one side doesn't implement the feature:

- Features the other servers lack: dnsmasq and Pi-hole have no cache for
  failed resolutions (RFC 9520), and dnsmasq, Pi-hole and Unbound have no DoH
  upstream client (RFC 8484). Numa has one, but it can't be pointed at a test
  certificate authority, so its DoH rules could not run.
- Features sopedu-dns lacks: recursive resolution and DNSSEC validation
  (Unbound), encrypted listeners for clients (AdGuard Home, Unbound), DNS over
  TLS upstreams, DNS Cookies, DHCP. The harness has no rules for them, so this
  page says nothing about how well the others do them.
- Settings a server can't be given: a controllable clock, one- or two-second
  upstream timeouts, a DNSSEC presentation mode. Some gaps are specific to one
  server: Unbound's built-in reverse zones differ from ours, Pi-hole always
  serves stale answers, and Numa can't turn its cache off or answer blocked
  names with NXDOMAIN.

## Limits of this comparison

- The test upstreams answer EDNS errors as RFC 6891 requires: BADVERS for an
  unknown version and FORMERR for a malformed OPT record. A forwarder that
  passes such a query upstream unchanged, as dnsmasq does, gets the right code
  back to its client and passes the check.
- Numa lowercases the question in its replies. No counted MUST covers that, but
  the harness stops an exchange there, which hid later checks. Its row comes
  from a second run that skipped only that assertion. Both runs failed the
  same three checks.
- Some checks depend on timing or on how a server picks its upstream, and
  Unbound picks partly at random. Across three full runs on 2026-11-10 the
  MUST rows were identical. Unbound passed 27 or 28 of its 29 SHOULD checks,
  and AdGuard Home ran 31 or 32 and passed all of them. The tables show the
  last run.
- We wrote the harness from our own spec, and it is not published. A check
  counts only where the RFC text makes the behaviour a MUST for a forwarder,
  but it's still our reading of the RFCs.
- Product-policy checks don't count: filtering, serve-stale, cache limits,
  Extended DNS Errors, local zones and attack hardening. sopedu-dns ran 259 of
  the 315 generic MUST checks and passed all of them; the other 56 need
  settings the harness can't give any server in this setup.
- Every server ran a minimal forwarder setup. dnsmasq and Unbound came from
  Debian trixie packages. AdGuard Home and Pi-hole came from their official
  images, with rate limiting, DNSSEC validation and filter lists off. Pi-hole's
  local `.test` and `.invalid` zones were disabled. A different configuration
  could change individual results.
- AdGuard Home reaches its DoH test upstream through the test certificate
  authority, given to it with `SSL_CERT_FILE`; the harness first checks that it
  accepts that authority and rejects an unknown one.
