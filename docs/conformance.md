# RFC conformance

We treat every MUST and MUST NOT that applies to a caching forwarder as
binding. Where an RFC leaves a choice, we take the conservative one. The
behaviour spec ([specs/dns-forwarder.md](specs/dns-forwarder.md)) labels every
deliberate deviation. Where other servers are lenient and a MUST says
otherwise, we follow the MUST: sopedu-dns answers BADVERS to unknown EDNS
versions and FORMERR to malformed OPT records, and it caches upstream
failures.

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

## Comparison with other servers

On 2026-11-04 we ran one revision of our conformance harness against
sopedu-dns and four widely used servers. Each server was a plain forwarder in
front of local test upstreams. The table counts the MUST and MUST NOT checks
every server could be tested on:

| Server | Version | Shared MUST checks passed |
|---|---|---|
| sopedu-dns | 1.0.0 | 181 / 181 |
| Unbound | 1.26.2 | 178 / 181 |
| AdGuard Home | v0.107.80 | 177 / 181 |
| dnsmasq | 2.91 | 173 / 181 |
| Pi-hole (FTL) | v6.8 | 170 / 181 |

We added Numa 0.25.0 later the same day, with the same harness checks and spec.
Numa can't turn its cache off or answer blocked names with NXDOMAIN, so those
sessions are blocked for it, and 139 checks are left that all six servers ran:

| Server | Version | MUST checks passed, all six servers |
|---|---|---|
| sopedu-dns | 1.0.0 | 139 / 139 |
| Unbound | 1.26.2 | 136 / 139 |
| AdGuard Home | v0.107.80 | 135 / 139 |
| dnsmasq | 2.91 | 131 / 139 |
| Numa | 0.25.0 | 130 / 139 |
| Pi-hole (FTL) | v6.8 | 128 / 139 |

In the same run sopedu-dns passed all 259 MUST checks and all 35 SHOULD
checks the harness could run against it.

What the others failed:

- Unbound answers NOERROR instead of FORMERR to malformed OPT option data
  (RFC 6891 §7).
- AdGuard Home answers NOERROR instead of BADVERS to EDNS versions 1, 2 and
  255 (§6.1.3), and NOERROR instead of FORMERR to an OPT record with a
  non-root owner (§6.1.2, §7).
- dnsmasq has the same two EDNS failures plus the malformed-option-data one.
  It also has no failure cache: every repeat of a query that just failed
  with SERVFAIL goes upstream again (RFC 9520 §3.2).
- Pi-hole has the dnsmasq failures, and it sends a 513-octet answer without
  TC to a client that advertised a UDP size below 512 (RFC 6891 §6.2.3).
- Numa answers NOERROR instead of BADVERS to EDNS versions 1, 2 and 255
  (RFC 6891 §6.1.3), and NOERROR instead of FORMERR to malformed OPT records
  (§6.1.2, §7). It also lowercases the names inside RRSIG and NSEC records
  (RFC 3597 §3).

None of these break normal browsing. They show up with unusual or broken
clients, and the missing failure cache adds upstream load when a domain is
broken.

## Limits of this comparison

- Numa lowercases the question in its replies. No counted MUST covers that, but
  the harness stops an exchange there, which hid later checks. Its row comes
  from a second run that skipped only that assertion, and a failure in either
  run counts against it.
- We wrote the harness from our own spec, and it isn't public yet. A check
  counts only where the RFC text makes the behaviour a MUST for a forwarder,
  but it's still our reading of the RFCs.
- Product-policy checks don't count: filtering, serve-stale, cache limits,
  Extended DNS Errors, local zones and attack hardening. Neither do checks a
  server couldn't be configured for, such as DoH upstreams and
  product-specific settings. That leaves out about 134 MUST checks.
- Every server ran a minimal forwarder setup. dnsmasq
  and Unbound came from Debian trixie packages. AdGuard Home and Pi-hole
  came from their official images, with rate limiting, DNSSEC validation
  and filter lists off. Pi-hole's local `.test` and `.invalid` zones were
  disabled. A different configuration could change individual results.
- RFC 9520 §3.2 is written for resolvers; this comparison applies it to
  forwarders.
