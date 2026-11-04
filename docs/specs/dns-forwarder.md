# sopedu-dns: DNS protocol and behavior specification

This is the behaviour specification for sopedu-dns v1.0.0. The target is a home
LAN at roughly 50 queries a second, served by one static binary. The spec is
normative and lists the tests for each requirement (section 14).

## 1. Scope and requirement language

The service accepts unicast DNS over UDP and TCP, applies local filtering and
rewrites, and forwards the remaining queries to configured recursive upstreams.
In the terminology of [RFC 9499](https://www.rfc-editor.org/rfc/rfc9499.html)
it is a caching forwarder. It is not an authoritative server, it does not
perform iterative recursion, and it does not validate DNSSEC signatures;
validation is left to the clients.

Inbound DoH/DoT/DoQ, zone transfer, dynamic update, DSO, mDNS, DNS64 and
authenticated client transactions are outside the home profile. A request for
one of them must get a documented response, never an accidental parser failure.
Deployment topology, HA and cutover procedures are outside this spec. IPv6
renumbering (RFC 9096) is a router behaviour; its effect on `listen` and
`allowed_clients` is covered in the configuration reference.

MUST, MUST NOT, SHOULD and MAY are used as in
[BCP 14](https://www.rfc-editor.org/rfc/rfc2119.html) when written in
uppercase, as [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174.html) qualifies.
Each requirement is tagged with its origin:

- RFC: required or recommended by the cited standard for the role this service
  plays. The RFC's own requirement strength still applies.
- PROFILE: a binding choice for this implementation, not a general DNS rule.
  Local safety choices stricter than the RFC carry this tag too.
- DEVIATION: a deliberate departure from the cited standard for compatibility.
  Behaviour tagged this way must not be described as full RFC compliance.

## 2. Request processing model

**P1: PROFILE.** Each accepted request captures one immutable configuration
generation. All list, policy, upstream, cache and presentation decisions for
the request MUST be consistent with that generation. A reload MUST NOT let an
answer still in flight from the old generation populate the new resolution view.

**P2: PROFILE.** Ordinary unsigned requests are processed in this order:

1. Access and admission limits, header and opcode checks, bounded wire parsing.
   A client outside `allowed_clients` (default: loopback, RFC 1918, link-local
   and ULA; the RFC 6598 shared space is opt-in because behind a carrier-grade
   NAT it holds other subscribers) gets REFUSED at this step and reaches no
   cache, local policy or upstream, so a default deployment is not an open
   resolver. A refused source inside one of the host's own global on-link
   prefixes is reported once per prefix (`client_refused_onlink`) and is never
   admitted automatically. A query from an unspecified, multicast or
   limited-broadcast source address, or from UDP source port 0, is dropped
   without a reply even when `allowed_clients` would allow it.
2. Protocol errors and unsupported meta-operations.
3. Diagnostic-name/class policy and ANY policy.
4. Exact/wildcard local rewrites and configured local zones.
5. Client bypass decision, then blocklist evaluation when enabled.
6. Fresh cache, stale/failure state, and safe shared upstream work.
7. Per-client response rendering and transport size enforcement.

Client bypass disables blocklists only. It MUST NOT disable rewrites, local
zone handling, input validation or resource limits. CNAME targets in
upstream answers are checked against the blocklists as described in L7.

**P3: PROFILE.** Ordinary upstream responses MUST be treated as complete
messages. We do not extract arbitrary Additional records to answer other
questions, chase referrals or synthesize subtree negatives, so the cache stays
a packet cache and never acts as an incomplete iterative resolver. Replies
from the plaintext fallback are untrusted: an Answer RR whose owner is off the
question/CNAME/DNAME chain makes the reply invalid (a failed attempt),
Authority keeps only SOA, NS, NSEC, NSEC3 and RRSIG at or above the chain, and
Additional keeps only OPT. DoH replies are not scrubbed. Setting
`trust_plain_upstreams = true` (default false) treats plain servers as trusted
primaries, with no scrubbing and no S1 plaintext limits. RFC 5452 checks always
apply.

## 3. Wire parsing and errors

**W1: RFC / PROFILE.** Check every offset, section count, RDLENGTH and name
traversal before access. A name is at most 255 wire octets including the root;
an ordinary label is at most 63 octets. Bound pointer traversal and reject
loops, invalid targets and reserved encodings. The whole message must be
consumed (a profile choice). Opaque RDATA is never scanned for compression
pointers. See [RFC 1035 §§2.3.4, 4.1](https://www.rfc-editor.org/rfc/rfc1035.html#section-4.1)
and the attack cases in the informational
[RFC 9267 §§2–6](https://www.rfc-editor.org/rfc/rfc9267.html#section-2).

**W2: RFC.** DNS labels are octet strings and need not be hostnames. ASCII
letters compare case-insensitively; other octets and label boundaries are
preserved. Hostname restrictions in blocklists and config MUST NOT become
wire-parser restrictions. A valid name outside the rule grammar is forwarded
without hostname-based matching. Unknown ordinary QTYPE/QCLASS and RDATA MUST
remain representable.
See [RFC 2181 §11](https://www.rfc-editor.org/rfc/rfc2181.html#section-11),
[RFC 4343 §§2, 4](https://www.rfc-editor.org/rfc/rfc4343.html#section-4), and
[RFC 3597 §3](https://www.rfc-editor.org/rfc/rfc3597.html#section-3).

**W3: RFC / PROFILE.** Errors follow the table below. Check for unsupported
opcodes before assuming QUERY section semantics. An error reply to malformed
input includes only fields already parsed safely and never copies an
unvalidated question. Traffic that is rate-limited or unsafe to answer may be
dropped under the admission policy.

| Input | Required behavior | Origin |
|---|---|---|
| Fewer than 12 header bytes | Drop UDP; close the invalid TCP stream | PROFILE: no reliable response |
| Incoming QR=1 on query listener | Ignore, so no response loop can form | PROFILE |
| QUERY with QDCOUNT > 1 | FORMERR, no forwarding | RFC 9619 §4 |
| QUERY with QDCOUNT = 0 | REFUSED, no forwarding in this profile | PROFILE: an unsupported empty operation, not malformed in itself |
| Unsupported opcode | NOTIMP; keep ID and opcode in the safe error header | RFC 8906 §§3–5 |
| Malformed ordinary QUERY with usable header (including a name compression pointer into the header, target < 12) | FORMERR; never forwarded; TCP may close if framing recovery is unsafe | RFC / PROFILE |
| Multiple OPT, invalid OPT structure | FORMERR with a safe OPT where required | RFC 6891 |
| Unsupported EDNS version (checked before QDCOUNT = 0, AXFR/IXFR/TKEY, NXNAME, meta-TYPE and TSIG policy) | BADVERS with supported EDNS version 0 | RFC 6891 §6.1.3 |
| AXFR/IXFR or TKEY query | REFUSED; never start transfer/key negotiation | PROFILE |
| Explicit NXNAME (TYPE128) query | FORMERR, no upstream query | RFC 9824 §3.5 |
| Reserved or meta-TYPE QTYPE: 0, OPT (41), TSIG (250), unassigned 129–248 (MAILB/MAILA forward normally) | FORMERR, no upstream query | RFC 6895 §3.1 |
| TSIG or SIG(0) authenticated request | REFUSED; authentication is unsupported, so a signed request never gets a success | PROFILE |

The zero-question distinction and multiple-question requirement come from
[RFC 9619 §4](https://www.rfc-editor.org/rfc/rfc9619.html#section-4).
Unsupported-feature responses follow
[RFC 8906 §§3–5](https://www.rfc-editor.org/rfc/rfc8906.html#section-3).

**W4: RFC / PROFILE.** Unknown ordinary RRs MUST be relayed with their RDATA
unchanged. A rebuilt message MUST preserve opaque RDATA and re-encode any
supported compressed names correctly; it MUST NOT transplant old compression
offsets. The question may be patched in place for case only after its layout is
proven equal. Otherwise rebuild the message safely or skip the cache/sharing
optimization. See [RFC 3597 §§3–4](https://www.rfc-editor.org/rfc/rfc3597.html#section-4).

**W5: RFC / PROFILE.** An upstream message is invalid when its Answer or
Authority holds an OPT or an RR of a Q-TYPE or meta-TYPE (128 through 255:
TKEY, TSIG, IXFR, AXFR, MAILB, MAILA, ANY and the unassigned range), or when
its Answer holds an RR in a class other than the question's. L2 never forwards
QCLASS ANY, so an answer to it is never usable. An invalid message is a failed
attempt: nothing is relayed or cached, and a plain attempt fails at once
instead of waiting for a better datagram. A TSIG in Additional is dropped (W4).
A foreign-class Authority RR is ignored and cannot make a negative usable (N2).
See [RFC 6895 §3.1](https://www.rfc-editor.org/rfc/rfc6895.html#section-3.1).

## 4. EDNS and response presentation

**E1: RFC.** Parse at most one root-owned OPT and check every option length.
OPT's 32-bit TTL field holds the extended RCODE, version and flags, and MUST
NOT be aged as a TTL. Build a new OPT for each transaction: include it for
supported EDNS requests, omit it for non-EDNS requests, and keep the full
effective RCODE of every reply we send. U5 decides which upstream RCODEs are
usable; an unusable extended RCODE ends that attempt and never reaches the
client. Unknown options are not format errors. Every OPT we build, including on
TC=1 and error replies, advertises our own UDP payload size and never echoes
the client's (RFC 6891 §6.2.3). The only upstream option passed on is Extended
DNS Errors: each becomes a new option with the same INFO-CODE and the
EXTRA-TEXT `upstream` or `upstream: <text>`, so the source is attributed
(RFC 8914 §3). A malformed EDE is dropped. We add no EDE of our own.
See [RFC 6891 §§6.1–6.2, 7](https://www.rfc-editor.org/rfc/rfc6891.html#section-6.1).

**E2: RFC / PROFILE.** Version negotiation happens before policy answers and
cache lookup. An unsupported version gets BADVERS, never an ordinary success.
Only the client's question is forwarded. Its OPT is not (RFC 6891 §§6.1.1, 7:
each side is its own transaction), and neither is anything else: the upstream
request is the header (ID, opcode, RD, AD, CD; other bits zero), the question
and our OPT. Client Answer, Authority and non-OPT Additional records are
dropped (RFC 1035 §4.1 gives a standard query nothing to carry there); such a
query is still answered, uncached and uncoalesced. Every upstream query
carries a fresh OPT built by the forwarder: our payload size, version 0, the
client's DO and Compact Answers OK (RFC 9824) flags when the client set them,
since they ask for data we relay, every other flag zero (RFC 6891 §6.1.4) and no options. A query
without OPT stays without one unless `dnssec = "always_upstream"` adds DO.

No client option is supported end to end (NSID would name the upstream, not
this server). Local responses ignore unsupported options and never reflect
arbitrary request data. Hop-scoped client options (ECS 8, Cookie 10, TCP
keepalive 11, Padding 12) are never echoed and do not affect caching or
coalescing, because they describe the client-to-forwarder hop
(RFC 7873 §5.2.1, RFC 8932 §5.3.1, RFC 7830). A malformed client ECS option (family,
prefix, scope or address bits; RFC 7871 §6) gets FORMERR. A query with any
other option or with unfamiliar flags bypasses the shared cache. We do not
terminate the ECS, Cookie or padding protocols ourselves.

**E3: RFC / PROFILE.** A response MUST use the current client's ID and question.
We echo the client's question case for interoperability. Every client reply,
whether generated, relayed or cached, has QR=1, the request's opcode, RD and
CD, RA=1 (this service offers recursion) and zero reserved bits; RD and RA are
never copied from an upstream or cached reply. AA=0 for filter answers,
rewrites and every relayed or cached upstream answer; actual empty-zone
answers have AA=1. AD follows section 6 and TC follows section 5. A cached
upstream OPT, EDNS buffer size or client option MUST NOT be reused as
transaction state.
See [RFC 1035 §4.1.1](https://www.rfc-editor.org/rfc/rfc1035.html#section-4.1.1)
and [RFC 5625 §§3–4](https://www.rfc-editor.org/rfc/rfc5625.html#section-3).

## 5. UDP and TCP transports

**T1: RFC / PROFILE.** Clients can use UDP and TCP. A UDP reply SHOULD use the
queried destination address as its source, including on multihomed hosts. The
DNS payload limit is 512 for non-EDNS clients and
`min(max(advertised_size, 512), configured_udp_cap)` for EDNS clients. The cap
defaults to 1232 bytes and does not apply to TCP.
See [RFC 2181 §4](https://www.rfc-editor.org/rfc/rfc2181.html#section-4),
[RFC 7766 §5](https://www.rfc-editor.org/rfc/rfc7766.html#section-5), and
[RFC 9210 §4](https://www.rfc-editor.org/rfc/rfc9210.html#section-4).
The cap is a local choice. [RFC 9715 §3](https://www.rfc-editor.org/rfc/rfc9715.html#section-3)
gives fragmentation advice for public paths; it does not mandate anything for a
LAN.

**T2: RFC / PROFILE.** If a complete answer exceeds the client's UDP limit,
return a well-formed TC=1 response. Never cut bytes or split an RRset. This
minimal response has the header, the current question and the appropriate OPT,
no Answer or Authority RRs, and AD=0. If the complete answer is otherwise
cacheable, keep it for a later TCP request. A truncated upstream answer MUST
NOT be inserted as a complete answer. See
[RFC 2181 §9](https://www.rfc-editor.org/rfc/rfc2181.html#section-9).

**T3: RFC / PROFILE.** TCP messages carry a two-byte length prefix in network
byte order. Fragmented and coalesced reads, successive requests and pipelining
all work. Concurrent requests per connection are bounded, and each response
frame is written whole so frames never interleave. Replies may go out of order.
Idle connections MUST NOT consume UDP admission slots. Connection,
partial-frame, resolution and write deadlines are separate. The 10-second idle
default is a PROFILE value; no RFC specifies it. Partial bytes do not renew it
indefinitely. The `allowed_clients` check runs right after accept, before a
connection permit is taken, and a disallowed or impossible peer is closed at
once. One source address may hold at most `tcp_max_connections_per_client`
connections. A connection stops reading new queries while more than 128 KiB of
its finished answers are unwritten.

When a connection stops (query cap, rejected query, rate limit, EOF, idle,
shutdown), it writes the answer to every query it accepted, sends FIN, and
discards input for at most 1 s before closing, so the kernel does not reset the
connection and drop unread answers. Frames read past the query cap get no
answer, and the client retries them (RFC 7766 §6.2.4). See
[RFC 7766 §§6.2–7](https://www.rfc-editor.org/rfc/rfc7766.html#section-6.2).

**T4: RFC / PROFILE.** This refines the T1 source-address SHOULD for a wildcard
`listen` (`0.0.0.0` or `[::]`). Only in that case, request each datagram's
destination address with `IP_PKTINFO` / `IPV6_RECVPKTINFO`, and send every UDP
reply (inline hits and spawned answers alike) with a matching `IP_PKTINFO` /
`IPV6_PKTINFO` control message so its source is the queried address. The
message sets the source only, with interface index 0, so routing still chooses
the interface. A specific `listen` address is already the source and keeps the
plain `recv_from` / `send_to` path. A query sent to a broadcast or multicast
address gets no answer, as for such a source (P2). If the pktinfo send fails or
the kernel supplied no destination, fall back to the plain send. This works on
Linux and macOS; elsewhere a wildcard bind leaves the source to the kernel and
logs `udp_pktinfo_unsupported` once. See
[RFC 8085 §5.1](https://www.rfc-editor.org/rfc/rfc8085.html#section-5.1).

**T5: PROFILE.** `listen` is one address or a list of 1 to 16 distinct
addresses; a duplicate or an empty list fails validation. Each address has its
own UDP socket set (`udp_workers`, batched receive, T4 pktinfo for a wildcard)
and its own TCP listener, and all of them share one server state, cache, limits
and shutdown. A bind failure names the failing address. Every IPv6 socket sets
`IPV6_V6ONLY=1`, so `[::]` serves IPv6 only and can be listed beside an IPv4
address. Changing the list needs a restart (O2).

## 6. DNSSEC boundary

**D1: RFC / PROFILE.** The default mode, `passthrough`, passes DO and CD to the
upstream unchanged. The optional `always_upstream` mode requests DNSSEC material
with DO=1. It changes presentation only and does no local validation. DO does
not prove authenticity. The service MUST NOT claim to validate signatures,
maintain a trust anchor or turn CD=1 into CD=0. A generated EDNS response takes
its DO from the client; the DO bit in an upstream response is not a validation
check. See
[RFC 4035 §3.2](https://www.rfc-editor.org/rfc/rfc4035.html#section-3.2) and
[RFC 6840 §5.6](https://www.rfc-editor.org/rfc/rfc6840.html#section-5.6).

**D2: RFC.** In `always_upstream` mode, strip unsolicited DNSSEC authentication
material for DO=0, but NEVER remove an RRset the QTYPE explicitly asks for. For
example, `DNSKEY +nodnssec` must keep the DNSKEY answer, and an explicit RRSIG
query keeps its RRSIG answer. OPT is handled separately. See
[RFC 4035 §3.2.1](https://www.rfc-editor.org/rfc/rfc4035.html#section-3.2.1).

**D3: RFC / PROFILE.** AD carries the upstream's validation status; we never
infer it locally. AD is kept only from an explicitly trusted, authenticated
upstream, and only when the client set AD or DO. We never set AD=1 ourselves.
This profile clears AD on plaintext fallback answers, synthesized answers,
truncated answers and every stale answer. A cache without trustworthy
validation-lifetime metadata MUST clear cached AD instead of asserting that it
is still valid. This trust policy is stricter than plain wire relay. See
[RFC 6840 §§5.7–5.8](https://www.rfc-editor.org/rfc/rfc6840.html#section-5.7)
and [RFC 4035 §4.9.3](https://www.rfc-editor.org/rfc/rfc4035.html#section-4.9.3).

**D4: PROFILE.** For each DNSSEC mode, tests cover valid, insecure and bogus
upstream outcomes with DO/CD/AD combinations. A CD=0 SERVFAIL and CD=1 data MUST
remain separate. Local filter negatives are unsigned policy answers, and a
validating client may reject them. We never invent DNSSEC denial proofs.

**D5: RFC / PROFILE.** Compact denial proofs are preserved, and their NSEC
bitmaps are never read as ordinary records. TYPE128/NXNAME gets the W3 error.
We do not add Compact Answers OK (CO) on our own or restore RCODEs. Client CO
requests are forwarded separately, with no cache or coalescing reuse. An
unexpected CO response to a CO-clear request is not reused, and the query is
retried elsewhere. See [RFC 9824 §§3.5, 5.1](https://www.rfc-editor.org/rfc/rfc9824.html#section-5.1).

## 7. Upstream transactions and selection

**U1: PROFILE.** Each attempt has its own upstream transaction context, separate
from the downstream ID. Check DNS syntax, QR, opcode, effective RCODE and the
canonical question against the request sent. UDP and TCP replies must carry the
upstream ID. DoH replies are matched mainly by their HTTP exchange. Mismatched
replies and late losers are ignored and MUST NOT populate cache state.

**U2: RFC / PROFILE.** Ordinary upstream UDP queries use unpredictable IDs
across the full 16-bit space and unpredictable ephemeral source ports, with
multiple ports for concurrent queries. The reply must come from the expected
peer and carry the expected question. A small persistent socket pool is not an
acceptable default substitute for port entropy. We use a connected socket per
attempt; pooling would need evidence that it is equally safe. If sockets are
ever shared, active ID collisions must be prevented.
See [RFC 5452 §§9.1–9.2](https://www.rfc-editor.org/rfc/rfc5452.html#section-9).

**U3: RFC / PROFILE.** An upstream UDP reply with TC=1 triggers a TCP query to
the same endpoint within the remaining request budget. The incomplete UDP reply
is never returned as a full successful resolution. One absolute resolution
deadline covers hedges, transport fallback and cleanup; retries MUST NOT reset
it. At most three sends may go to one address/transport/query; this profile
uses one attempt per endpoint and transport. See
[RFC 9520 §3.1](https://www.rfc-editor.org/rfc/rfc9520.html#section-3.1).

**U4: RFC / PROFILE.** DoH uses HTTPS POST, `application/dns-message` for
Content-Type and Accept, certificate and hostname verification, and bodies of
at most 65,535 DNS octets with no TCP length prefix. Ordinary DoH requests use
DNS ID 0, as recommended. A 2xx HTTP response can carry a DNS failure, so the
DNS result is classified separately. The HTTP `Age` is applied before relaying
or caching: it is subtracted, saturating, from RR lifetimes and the negative
lifetime, never from OPT flags or RDATA. A missing Age counts as zero; a
malformed or overflowing Age rejects the upstream result. See
[RFC 8484 §§4–6](https://www.rfc-editor.org/rfc/rfc8484.html#section-5.1).

**U5: PROFILE.** Send to one healthy upstream, hedge after a bounded delay, and
move on at once after an explicit failure. A valid NOERROR, NXDOMAIN or
YXDOMAIN ends the resolution; after a valid negative we never race for an allow
decision. Every other RCODE (SERVFAIL, REFUSED, FORMERR, NOTIMP, update/TSIG
codes, unassigned values) is a failed attempt, and so are invalid messages,
HTTP failures and timeouts. A DoH response with TC set is unusable. Losing
attempts are cancelled.

Plaintext fallback is opt-in (`fallback`, default empty), so blocking port 443
cannot force an unauthenticated path. Every answer it supplies is counted
(`dns_plain_fallback_answers_total`), and a warning with the count
(`plaintext_fallback_used`) is logged at most once a minute. Readiness does not
depend on it. The fallback is tried only after every DoH attempt failed at the
transport level: either no connection could be made (TCP connect or TLS), or
the upstream was already unreachable (circuit open and its last failure a
failure to connect; a probe that gets no response headers within the deadline
counts as one). When every DoH upstream is unreachable and a fallback is
configured, DoH is not tried for the query. The fallback answers within the
deadline, and the probes detect recovery.

An upstream that answers at all is reachable and never lets the fallback in.
That covers an HTTP status, a `Retry-After` pause (drawn by a client query or by
the probe), and a failure RCODE to the probe. A client flood can make an
upstream rate-limit or fail us, but cannot make it unreachable. An HTTP error
status, a non-DNS content type, invalid wire, or a request reset after it was
sent (an HTTP/2 RST_STREAM, or the connection closed under it) from a reachable
DoH upstream never reaches plaintext; otherwise a client could pick names that
downgrade its own queries. A well-formed DNS failure RCODE from a reachable DoH
upstream moves on to the next DoH upstream only. A SERVFAIL carrying a DNSSEC
validation EDE (5 to 12, RFC 8914 §4) is final and is relayed.

Upstream health MUST NOT be steerable by the names clients ask for. It counts
only name-independent transport failures (TCP connect or TLS failures; for a
plain fallback, a refused, reset or unreachable endpoint) and failed root-NS
probes of any kind, including a failure RCODE for `. NS`. An HTTP error status
(5xx included) or a non-DNS content type on a client query depends on the
question, because a DoH front end can map one name's broken backend lookup to
502 or 504. Only the fixed probe confirms an endpoint-wide 5xx. A confirmed 5xx
benches the upstream for selection and readiness but never opens plaintext. A
timeout, a DNS-level RCODE, invalid content and an aborted attempt (a peer won,
the caller left, the deadline passed) never count; an unfinished attempt only
raises the latency estimate. A bind, connect or resource error on our side
never enters the failure cache.

A plain fallback found unreachable is skipped for 5 s, doubling up to 60 s,
while some other fallback is not in backoff; when all are in backoff, all are
tried. The `ordered` strategy asks its next upstream after half of
`upstream_timeout_seconds`, at most 1 s and at most half the UDP discard limit
(O6), so the backup's answer still reaches a UDP client.

A fallback that has echoed our randomised question case treats a case-only
mismatch over UDP as forged. One that never has gets a single retry without
randomisation, from a fresh socket and ID. Over TCP the question is compared
without case, since an off-path attacker cannot inject into the stream.

**U6: PROFILE.** HTTPS connections are reused, but startup and cache or local
service never wait for every upstream to warm. Circuit breakers and latency
estimates are bounded per upstream. Backoff and probes MUST respect failure
suppression. Endpoint identity includes route/view and security policy as well
as the hostname. Self-forwarding loops detectable from the config are rejected.

**U7: PROFILE.** A reply whose header and sections contradict each other is
invalid (a failed attempt, never relayed or cached), over DoH and plain alike.
This covers an NXDOMAIN whose Answer holds data other than aliases (CNAME,
DNAME, or an RRSIG over one) at the query name or anywhere on its alias chain,
including an alias tail that is itself answered. It also covers a NOERROR whose
alias chain ends at a name that holds only RRs of types other than the
question's (ANY asks for every type). NXDOMAIN after a CNAME chain (N1) stays
valid.

**U8: RFC / PROFILE.** A UDP reply from a plain upstream that is longer than the
size the query advertised (512 without EDNS; with EDNS, the forwarder's own
cap, 1232 by default) is never accepted as final. ID, port and question case
all sit in the first fragment, so a forged tail would pass those checks. The
question is asked again over TCP within the same deadline (RFC 5452 §9.3
allows leaving UDP on suspicion). See
[RFC 6891 §6.2.5](https://www.rfc-editor.org/rfc/rfc6891.html#section-6.2.5).

**U9: RFC / PROFILE.** A DoH 429 or 503 with `Retry-After` (delay-seconds or
HTTP-date, [RFC 9110 §10.2.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.3))
marks that upstream unavailable for that long, capped at 60 seconds. A pause
drawn by the root-NS probe stops every request, the probe included. When no
upstream is left, queries fail with SERVFAIL and never reach plaintext (U5: the
endpoint answered). Unlike an open circuit, such a pause is never overridden by
the "try the best anyway" recovery. A pause drawn by a client query may concern
only that query (a client flood or one broken name can provoke it), so it holds
only while another DoH upstream is usable. Otherwise the upstream is still
asked, the queries it refuses fail without reaching plaintext, and the probe
keeps running to confirm an endpoint-wide pause. A config reload keeps the
pause for an unchanged URL. The pause shows in upstream health; readiness fails
only for a probe-drawn pause or an open circuit. Without a usable header, the
ordinary failure counting and backoff apply (U6).

## 8. Cache identity and shared work

**K1: PROFILE.** Sharing eligibility starts conservative. A request is eligible
only if it is one standard IN-class QUERY with RD=1, no signature, empty Answer
and Authority, no non-OPT Additional records, EDNS absent or version 0, no
options other than the hop-scoped ones in E2 (which are stripped), and no EDNS
flags other than DO. Unfamiliar request or header
semantics bypass sharing. A valid ineligible request is still forwarded on its
own unless W3 refuses it locally.

**K2: PROFILE.** The cache uses this semantic identity, and compares exact bytes
after hashing:

```text
K = (resolution_view_generation,
     canonical_length_prefixed_qname, qtype, qclass,
     opcode, RD, CD, query_AD, client_DO, client_EDNS_present,
     dnssec_presentation_mode)
```

Label octets are ASCII-folded; the key is never a lossy dotted string. A view
identifies upstream routing, DNSSEC/trust settings and the rest of the
configuration that affects responses. The client IP can be left out of the key
only when those clients truly share a view and carry no client-specific
options. Client ID, question case and UDP size belong to each waiter's
presentation context, not to K. Key changes invalidate old entries.

**K3: PROFILE.** A cache entry is an immutable, validated response template plus
RR TTL metadata, a classification, and insertion and freshness times. OPT and
client presentation are transaction metadata, even when the raw bytes are kept
internally. Output is rendered fresh for each waiter. The shared template is
never mutated in place; one client's TTL or question patch MUST NOT alter
another answer.

**K4: PROFILE.** At most one upstream resolution or refresh is active for an
eligible K. A successful result may be shared with the current waiters even
when its TTL forbids later reuse. Distinct keys, waiters per key and total
upstream work are bounded. Single-flight state is removed on success, failure,
timeout, panic or task cancellation, and shutdown. One waiter cancelling MUST
NOT cancel work that others need. A stale refresh may outlive the waiter that
started it, and so does a leader's resolution: it runs in its own task (holding
the client's upstream slot, under the pool permits and the upstream deadline),
so a leader whose TCP connection closes or resets still answers its followers.

**K5: PROFILE.** Local policy is evaluated on every request before the cache and
coalescing. Upstream data may be shared after that point; final blocked or
rewritten client replies are never inserted into the public response cache.
Reload generations prevent policy and routing races and stop old tasks from
reinserting stale data. Tests MUST force hash collisions to show that bytes are
compared exactly.

## 9. Fresh, negative and failed cache state

### Fresh response templates

**C1: RFC / PROFILE.** Time is measured with a monotonic clock. An RRset
received with unequal TTLs is normalized to its lowest member TTL before reuse;
all other RR data is preserved. A template's fresh deadline is no later than the
earliest effective lifetime of its retained RRs or negative state. Whole-packet
expiry may be conservative; it MUST NOT serve expired records as fresh.
Referrals and incomplete alias-only responses do not enter the reusable answer
cache. See [RFC 2181 §5.2](https://www.rfc-editor.org/rfc/rfc2181.html#section-5.2).

**C2: RFC / PROFILE.** A TTL is unsigned: one with the most significant bit set
is a large positive value, not zero
([RFC 8767 §4](https://www.rfc-editor.org/rfc/rfc8767.html#section-4), updating
RFC 2181 §8). Every TTL is capped at 604,800 seconds, RFC 8767's recommended
cap, on every path (relay, cache insert, SOA TTL and MINIMUM). A plaintext
answer is further capped at 300 seconds (S1). A zero effective RR lifetime makes
the whole template non-reusable, and such a template never becomes a stale
entry. Authoritative TTLs are never raised by a floor. For reusable entries:

```text
out_rr_ttl = max(0, effective_rr_ttl_at_receipt - elapsed_seconds)
```

Effective lifetimes already include DoH Age and any lowering cap. RDATA fields
such as SOA.MINIMUM and RRSIG times are not generic RR TTL offsets. See
[RFC 8767 §4](https://www.rfc-editor.org/rfc/rfc8767.html#section-4).

**C3: PROFILE.** Entry and byte budgets both apply. Stored responses, keys and
TTL metadata count against them; auxiliary maps and queues have their own
bounds. `cache_size=0` disables reusable response entries; failure suppression
and bounded in-flight sharing stay on. Any eviction policy may be used as long
as correctness and the budgets hold.

**C4: PROFILE.** Accepted new data MUST invalidate contradictory reusable or
stale state in the same resolution/security view. A terminal NXDOMAIN cannot
coexist with older positive state for that terminal name. A new CNAME cannot
leave an older ordinary address answer (any common type or flag variant)
available as fresh or stale at its owner. An entry that itself answers with a
CNAME at that owner is not an ordinary answer and stays (each chain keeps its
own entry, K2/K3), so the A and AAAA answers of a dual-stack alias are cached
side by side. Invalidation follows the terminal owner; it is not applied
blindly to the original alias question. At home scale a reverse index or a
bounded scan is acceptable.

**C5: PROFILE.** An entry whose charged size exceeds
`max(4 KiB, cache_bytes / 256)` (16 KiB at the default 4 MiB) is admitted only
on its second sight, so a scan of one-hit near-64 KB answers cannot evict the
hot set (DNS CacheFlush). A large entry that is already resident is replaced at
once. The check runs on insert only, so cache hits pay nothing. Writing every
large name twice defeats it; a frequency sketch would close that gap.

### Successful negative answers

**N1: RFC.** Distinguish NXDOMAIN, terminal NODATA, referral, positive alias
chain and resolution failure. NODATA is not the same as an empty Answer
section. The CNAME chain is followed only to classify the terminal outcome,
never to start iterative queries. NXDOMAIN after a CNAME describes the terminal
target, not the alias owner. Alias inspection is bounded and detects loops;
ambiguous, incomplete or looping chains are not cacheable. See [RFC 2308 §2](https://www.rfc-editor.org/rfc/rfc2308.html#section-2)
and [RFC 1034 §3.6.2](https://www.rfc-editor.org/rfc/rfc1034.html#section-3.6.2).

**N2: RFC / PROFILE.** Negative templates are cached only with a usable
Authority SOA. The negative lifetime is `min(SOA RR TTL, SOA.MINIMUM)`, reduced
by DoH Age and a lowering cap. A retained alias or proof RR with a shorter
lifetime also limits the whole template. The emitted SOA RR TTL is clamped to
the remaining negative lifetime. This profile has no invented 60-second
negative lifetime and no positive floor. A valid NXDOMAIN or NODATA without a
usable SOA is not cacheable but is a successful answer: it is relayed, and any
stale positive entry for the key is evicted. See
[RFC 2308 §§5–6](https://www.rfc-editor.org/rfc/rfc2308.html#section-5).

**N3: RFC / PROFILE.** For DO-enabled clients, the required denial and
authority records are preserved with their aged TTLs. NODATA applies to
name/type/class; NXDOMAIN applies to the terminal name/class. The packet cache
keeps exact-question variants and never reuses a packet for another QTYPE.
Cross-type reuse would need separate negative metadata and correct rendering.

**N4: PROFILE.** Never infer a descendant NXDOMAIN from a cached packet or from
a filter's synthetic NXDOMAIN. Subtree cuts and aggressive denial are deferred;
they would need a separate design that understands proofs. See
[RFC 8020 §§2–3](https://www.rfc-editor.org/rfc/rfc8020.html#section-2).

### Resolution failures

**F1: RFC / PROFILE.** After all permitted upstream attempts fail, matching
outbound work is suppressed for at least 1 second and at most 300 seconds. This
profile starts at 5 seconds and backs off to 30 seconds on repeated failures.
If no eligible stale answer exists, the client gets SERVFAIL. NXDOMAIN and
NODATA are not failures. A resolution that sent nothing (every upstream paused,
no fallback) is not a failed attempt and sets no marker. Failure state is kept
apart from the successful response cache.
See [RFC 9520 §§2, 3.2](https://www.rfc-editor.org/rfc/rfc9520.html#section-3.2).

**F2: PROFILE.** Failure identity includes the view, the question and the
DNSSEC context, CD in particular. Otherwise ineligible queries use a bounded
client-specific request context, so options and policy never leak across
clients. Upstream cooldown and final-resolution suppression are separate: one
failed endpoint must not prematurely suppress another viable endpoint.

**F3: RFC / PROFILE.** While suppression lasts, no matching outbound query or
refresh starts. A successful resolution or a relevant configuration generation
change clears failure state. Entries, bytes and expiry cleanup are bounded.
Liveness and UI polling MUST NOT bypass suppression by launching equivalent
probes. Resource protection follows [RFC 9520 §3.2](https://www.rfc-editor.org/rfc/rfc9520.html#section-3.2).

## 10. Stale answers and prefetch

**S1: RFC / PROFILE.** Only a previously reusable successful entry can be
served stale; zero-TTL templates and failure packets never are.
`optimistic_max_age` is RFC 8767's maximum stale timer: how long after expiry a
record may still be served. A stale entry is eligible only while
`fresh_deadline <= now < fresh_deadline + optimistic_max_age`. The default is
43,200 seconds. See
[RFC 8767 §4](https://www.rfc-editor.org/rfc/rfc8767.html#section-4). Unless
`trust_plain_upstreams` is set (P3), answers from the plaintext fallback are
cached for at most 300 s and are never served stale or prefetched.

**S2: RFC / PROFILE.** `serve_stale_client_timeout_ms` selects one of two named
behaviors:

| Mode | Behavior | Conformance |
|---|---|---|
| `refresh_first` (timer > 0, default 1800 ms) | Attempt refresh; after the client timer, use stale while the refresh keeps running and populates the cache; a recent cached failure permits immediate stale | RFC 8767 §§4–5: stale only when the data cannot be refreshed |
| `optimistic` (timer = 0) | Return eligible stale immediately and start/join background refresh unless suppressed | DEVIATION, an explicit opt-in like AdGuard Home's optimistic cache |

The default is `refresh_first` with RFC 8767 §5's recommended 1.8 s client
response timer. Prefetch (S4) keeps regularly asked names fresh, so a client
waits on the timer only for a name not asked during the last 10% of its
lifetime, and only for as long as the refresh takes (the full timer only while
the upstreams are failing). The optimistic opt-in MUST NOT be advertised as
RFC 8767 conformant. See [RFC 8767 §§5–7](https://www.rfc-editor.org/rfc/rfc8767.html#section-7).

**S3: RFC / PROFILE.** In a stale answer, expired RR TTLs are positive, normally
30 seconds; unexpired records keep their remaining TTL. AD=0. After the stale
answer is sent, the refresh continues to its absolute deadline. A failed
refresh keeps the old template and enters F1 suppression; a new successful
positive or negative answer replaces the old state. AA=1 is not required from a
recursive upstream: the RFC's authoritative-server wording applies through the
trusted forwarding boundary. See [RFC 8767 §§4–6](https://www.rfc-editor.org/rfc/rfc8767.html#section-4).

**S4: PROFILE.** Prefetch may start on a fresh hit in the last 10% of the
entry's original effective lifetime, measured in milliseconds rather than whole
seconds. It shares K4 with misses and stale refreshes and obeys F3. Zero-TTL,
uncacheable and local-policy answers are never prefetched.

## 11. Local policy and local namespaces

**L1: PROFILE.** Rule precedence across all matching parents is the existing
one: important allow > important block > ordinary allow > ordinary block.
Exact hosts-format entries do not become suffix rules. Exact rewrites take
precedence over the most specific wildcard rewrite. Matching respects label
boundaries. Decisions are exact by default: a probabilistic fingerprint table
may not silently turn an allow or block decision into a false positive. Rule
syntax and priority are our own policy; no IETF adblock specification exists
for them.

**L2: RFC / PROFILE.** Diagnostic names and CHAOS get REFUSED, and the refusal
takes precedence. QTYPE=ANY is never forwarded. Rewrites, local zones,
special-use names, the blocklist and `.local` answer ANY like any other type.
After them, ANY gets the RFC 8482 §4.2 minimal answer: one synthesized HINFO RR
at the question name with CPU "RFC8482", an empty OS and TTL 10, in the
question's class (IN for QCLASS ANY or NONE). The HINFO is unsigned. A forwarder
does not know which zones are signed, so §4.2's RRSIG requirement for DO=1
cannot apply. See [RFC 8482 §§4.1–4.2](https://www.rfc-editor.org/rfc/rfc8482.html#section-4).

Blocks return NXDOMAIN with an unsigned policy SOA and TTL/MINIMUM 10. An IP
rewrite answers its matching address family; other ordinary QTYPEs get
NOERROR/NODATA with a local negative lifetime of 10.

Rewrites, local zones, special-use names, the blocklist and `.local` decide by
name in every class (RFC 7686 §2 asks NXDOMAIN for all `.onion` queries; RFC
8375 §4 and RFC 6303 forbid forwarding the local zones), so no class carries a
blocked or local name upstream. IN address data is never copied into another
class: a rewrite or `localhost` asked in another class gets NODATA, and local
records take the question's class (IN for QCLASS ANY or NONE). A query in QCLASS
ANY (255) or NONE (254), which are query-only classes (RFC 6895 §3.2), that no
name decision answered gets REFUSED and is never forwarded. Other data classes
(except CH) are forwarded.

**L3: RFC / PROFILE.** By default, private reverse names are answered from the
empty local zones below. Matching uses complete label suffixes, never arbitrary
substrings. An explicit override can route a zone to a configured LAN resolver;
that route never uses a public fallback unless explicitly enabled. Nonexistent
descendants are answered locally. Each zone apex serves SOA and NS, and NODATA
for other types, except DS with DO=1. The DS RRset at an apex belongs to the
signed parent, so that query is forwarded to get the real parent proof
(insecure delegation or denial) instead of an unverifiable local NODATA. This
holds for every locally served zone, including those in L4 and L6. See
[RFC 4035 §3.1.4.1](https://www.rfc-editor.org/rfc/rfc4035.html#section-3.1.4.1)
and [RFC 6303 §7](https://www.rfc-editor.org/rfc/rfc6303.html#section-7).

Answers carry correct SOA ownership, AA and negative TTL. This profile uses
TTL/MINIMUM 10, an NS target and SOA MNAME equal to the zone apex, and SOA RNAME
`nobody.invalid.` unless configured otherwise. The apex never gets a blanket
NXDOMAIN. Per-zone overrides are supported. We cover a home subset, not every
zone listed in
[RFC 6303 §§3–4](https://www.rfc-editor.org/rfc/rfc6303.html#section-3).

| Scope | Empty-zone suffixes in the home profile |
|---|---|
| RFC 1918 IPv4 | `10.in-addr.arpa`, `16.172.in-addr.arpa` through `31.172.in-addr.arpa`, `168.192.in-addr.arpa` |
| IPv4 loopback / link-local | `127.in-addr.arpa`, `254.169.in-addr.arpa` |
| IPv6 link-local | `8.e.f.ip6.arpa`, `9.e.f.ip6.arpa`, `a.e.f.ip6.arpa`, `b.e.f.ip6.arpa` |
| ULA | `d.f.ip6.arpa`; also `c.f.ip6.arpa` as an explicit home-profile extension covering the rest of fc00::/7 |
| Shared CGN space | `64.100.in-addr.arpa` through `127.100.in-addr.arpa` |
| RFC 6303 §4 | `0.in-addr.arpa`, `2.0.192.in-addr.arpa`, `100.51.198.in-addr.arpa`, `113.0.203.in-addr.arpa`, `255.255.255.255.in-addr.arpa`, the `::` and `::1` names, `8.b.d.0.1.0.0.2.ip6.arpa` |

The CGN space is separate from RFC 1918. The requirement not to forward its
reverse names to the global DNS is in
[RFC 6598 §4](https://www.rfc-editor.org/rfc/rfc6598.html#section-4).

**L4: RFC / PROFILE.** Prefer `home.arpa` for new unicast home names. Ordinary
queries stay local or use an explicitly configured local authority.
`home.arpa DS` with DO=1 is the delegation exception (the L3 apex DS rule): the real parent
proof is fetched through the configured public resolver instead of a synthetic
local denial. Existing `.local` rewrites stay as explicit compatibility aliases,
with a warning that clients may resolve `.local` over mDNS and never contact
this service. A `.local` name with no explicit rewrite, local zone or route gets
an immediate NXDOMAIN and is never sent upstream. There is no multicast
behavior. See
[RFC 8375 §4](https://www.rfc-editor.org/rfc/rfc8375.html#section-4) and
[RFC 6762 §§3, 22.1](https://www.rfc-editor.org/rfc/rfc6762.html#section-22.1).

**L6: RFC.** Special-use names never reach an upstream. They are checked after
rewrites and local zones and before the blocklist, and their answers are never
cached:

| Name and subdomains | Answer | Origin |
|---|---|---|
| `onion` | NXDOMAIN with SOA | RFC 7686 §2 (MUST) |
| `service.arpa` | Local empty zone like `home.arpa`, same DS+DO exception | RFC 9665 §8.4 (MUST NOT forward) |
| `resolver.arpa` | Local zone answering NODATA for every name and type (no DDR designation is published), except the apex DS with DO=1 (L3) | RFC 9462 §§4, 6.1, 6.4 |
| `localhost` | A 127.0.0.1, AAAA ::1, other types NODATA; TTL 10 | RFC 6761 §6.3 |
| `invalid` | NXDOMAIN with SOA | RFC 6761 §6.4 |
| `test` | NXDOMAIN with SOA unless `forward_test_names = true` (default false) | RFC 6761 §6.2 |

`ipv4only.arpa` and its reverse names are forwarded: a forwarder without DNS64
SHOULD NOT treat them specially (RFC 8880 §7.1).

**L5: PROFILE.** Authenticated TSIG/SIG(0) requests are explicitly unsupported
(W3). DNSSEC RRSIG data is never mistaken for a transaction signature. A future
authenticated pass-through mode would need its own byte-preservation, ID and
transport tests before filtering, TTL patching or cache sharing could touch it.
See [RFC 8945](https://www.rfc-editor.org/rfc/rfc8945.html) and
[RFC 2931 §3](https://www.rfc-editor.org/rfc/rfc2931.html#section-3).

**L7: PROFILE.** CNAME cloaking protection is on by default
(`block_cname_targets = true`). For an IN-class query that reaches the
upstreams, the answer is replaced by the L2 block answer (NXDOMAIN with the
policy SOA, TTL/MINIMUM 10) when both of these hold:

- Some name in the Answer section is blocked by the rules, with L1 precedence
  applied to that name. The names checked are every CNAME/DNAME target and
  every record owner in the question's class, other than the query name
  itself. This is a flat pass over the Answer section with no chain walk, so it
  fails closed: a loop, a conflicting CNAME, an overlong chain or a missing
  link cannot hide a blocked target behind a break in the chain.
- The client is not exempt (`no_filter_clients`, `no_filter_macs`), the same
  test as for a direct block.

If an `@@` rule allows the query name itself (its own rule or one on a parent
domain), the check is skipped: allowing a name allows what it aliases to. A
block on the queried name itself falls under L1 and is applied before this
rule.

The cache keeps the upstream answer byte for byte. The verdict (some target is
blocked and the name is not allowed) does not depend on the client, so it is
stored with the entry together with the rules generation it was computed
against; the client exemption is applied per query. A hit may be answered with
no chain work only when the entry has no chain, or its verdict is clear and for
the current rules generation. Otherwise the parsed path recomputes the verdict,
stores it back on the entry and decides for the client. A blocked verdict is
never served from the inline path. Stale service, the refresh a stale hit waits
for, prefetch refreshes and answers relayed from the plain fallback follow the
same rule: the answer about to be sent is checked, so a refresh that brings a
blocked target blocks non-exempt clients. A reload that changes
`block_cname_targets` starts a fresh cache. The block is counted and logged as
`blocked` with origin "cname target". The UI rule tester cannot know upstream
CNAMEs without asking, so it notes that an upstream CNAME to a blocked name
would also be blocked. AdGuard Home, Pi-hole (deep CNAME inspection) and blocky
behave the same way.

## 12. State lifecycle and home operation

**O1: PROFILE.** TCP connections, partial-frame buffers, UDP requests, upstream
attempts, single-flight keys and waiters, failure state, cache bytes, download
bytes and lines, rule lengths and query-log retention each have an independent
bound. The optional UDP rate limit (off by default) keeps one bucket per client
address: IPv4 /32, IPv6 /128. A source outside `allowed_clients` never takes a
bucket, and a newcomer to a full table costs bounded work. Download limits are
enforced while streaming, not after allocation. A slow dashboard or list parse
MUST NOT hold DNS locks or admission slots.

**O2: PROFILE.** A complete config is validated before it is swapped in. On a
download failure the last good snapshot of that list is kept; a consistent
rules snapshot is built and then swapped atomically. At boot, validated
persisted lists are preferred when available. Degraded inline-only operation is
recorded explicitly. An invalid new config or a partial file MUST NOT replace
the last good generation.

**O3: PROFILE.** Memory figures are whole-process peaks during a refresh, with
queries running and a full cache. They include old snapshots still held by
readers, builders, per-list copies, spare capacity and allocator and runtime
overhead. The 128 MiB deployment limit and the smaller targets are checked by
measurement; choosing a data structure does not guarantee them.

**O4: PROFILE.** A minimal health endpoint works independently of the UI. UI
connections are capped in total (16) and per client host (4, keyed as in O1),
and idle keep-alives close after 2 s. When the pool is full, `/healthz` and
`/metrics` are still served on reserved one-request connections (16, at most 4
per client host, so another host cannot take the probe's share). Liveness
reports process progress, not Internet availability. Local readiness and
upstream degradation are reported separately, so an upstream outage does not
disable local answers or stale service. On shutdown, new work is no longer
admitted, draining is bounded, and remaining tasks are then cancelled.
Shared-work state is released on every exit path.

**O5: PROFILE.** Cache pre-warming (`prewarm`, on by default) resolves the
previous run's most queried forwarded names after readiness. It goes through
the normal resolution path with all policy applied, is bounded in rate and
concurrency, and stays out of client statistics and the query log. The saved
list is browsing data, so it is owner-only on disk and is deleted at startup
when the knob is off.

**O6: PROFILE.** A UDP reply is not sent when its query has waited longer than
`udp_discard_timeout_ms` (default 1900; 0 disables; at least
`serve_stale_client_timeout_ms` + 100 ms, so a reply on the stale timer is
never lost). This stops a stalled upstream from releasing every waiter in one
burst aimed at a spoofed source (DNSBomb, CVE-2024-33655; Unbound's
`discard-timeout`). The answer is still cached, and a TCP client still gets
it. Only NOERROR and NXDOMAIN replies are discarded, since they are the ones
that can amplify; a SERVFAIL is no bigger than the query and is still sent.
Each discard counts as `dropped` in `/metrics`. Cache hits, local answers and
stale or prefetch serving answer at once and are never affected.

**O7: PROFILE.** One client address (the rate-limit key: IPv4 /32, IPv6 /128)
may have at most `upstream_inflight_per_client` (default 64; 0 disables) cache
misses starting upstream work in flight. The count also covers:

- stale and prefetch refreshes started by that address's hits (over the cap it
  gets the stale copy at once and no refresh starts; a near-expiry hit is not
  prefetched);
- a caller over K4's key or waiter bound (it resolves on its own, and never
  gets SERVFAIL for the bound alone);
- a UDP follower of a shared resolution (K4), which holds a UDP request slot
  while it waits.

A TCP follower holds only its own connection's slots and is not counted. Cache
hits and local answers are unaffected, and the global `upstream_inflight_max`
still applies. UDP and TCP share one count. A further miss over TCP gets
SERVFAIL. Over UDP it gets a minimal TC=1 reply (question echoed, no answers),
so a genuine client retries over TCP, which proves its source. A UDP source
address can be forged, and a SERVFAIL there could be aimed at a victim. The TC
replies are themselves limited per host (a burst of 16, then 200 a second); the
rest are dropped and counted, so the cap cannot become a reply burst. See
[RFC 9520 §5](https://www.rfc-editor.org/rfc/rfc9520.html#section-5).

## 13. Defaults

These are the home profile's default values; no RFC mandates them. A new config
key must not change the meaning of existing ones.

| Parameter | Value / rule |
|---|---|
| Client UDP cap | 1232 bytes; non-EDNS remains 512 |
| TCP idle timeout | 10 s; separate full-frame and write deadlines |
| Total resolution budget | 5 s across all attempts, configurable |
| Hedge delay | 50 ms |
| TCP connection limit | 256, independent of UDP; 32 per source address (`tcp_max_connections_per_client`, 1..=65536) |
| UDP in-flight limit | 1024, independent of idle TCP |
| Maximum queries executing per TCP connection | 16; backpressure beyond it |
| Upstream attempts executing globally | 256; no unbounded spawn queue |
| Cache misses in flight per client host | 64 (`upstream_inflight_per_client`, 0..=65536; 0 disables) |
| UDP reply discard | queries older than 1900 ms get no UDP data reply (`udp_discard_timeout_ms`, 0..=60000; 0 disables; never below the stale timer + 100 ms) |
| Retry-After pause | as sent, capped at 60 s |
| Single-flight waiters | 128 per key, 4096 total; excess resolves on its own under O7 and the pool bound |
| Reusable cache | Existing entry bound plus 4 MiB charged-byte budget |
| Failure cache | Separate 1 MiB and 4096-entry limits; 5 s initially, backoff to 30 s |
| Failure TTL validation | 1–300 s; eviction may occur under bounded resource pressure |
| Positive TTL cap | 604,800 s; no upward floor |
| Negative TTL cap | 3600 s; no upward floor; original zero remains zero |
| DNSSEC | `passthrough`; upstream-authenticated AD trust only |
| Stale | `refresh_first`, 43,200 s after expiry |
| `refresh_first` client timer | 1800 ms (RFC 8767 §5); continue upstream work after stale reply; 0 selects `optimistic` |
| Prefetch | On (`prefetch = true`), threshold 10%, obey suppression and single-flight |
| Plain DNS fallback | Off (`fallback = []`); explicit opt-in, counted and warned when used (U5) |

Under overload, excess UDP is dropped or gets a bounded SERVFAIL where capacity
allows; TCP applies backpressure or closes excess connections. Each event is
counted. No unbounded queue is created to avoid dropping.

## 14. Verification

**V1: PROFILE.** Protocol tests use local mock upstreams, synthetic messages, a
controllable monotonic clock and exact expected wire output. They need no
public DNS or cluster access. Each test checks the upstream request count,
cache state and response contents, not only that a parser accepts the output.

| Test | Requirements | Fixture and expected result |
|---|---|---|
| A01 | W1 | Truncated header, missing label bytes, pointer loop/out-of-range target, oversized expanded name, section-count/RDLENGTH overrun: no panic or unbounded work |
| A02 | W2 | Binary/escaped label, mixed ASCII case, root name and unknown ordinary QTYPE: preserve boundaries and forward valid input |
| A03 | W3 | QDCOUNT 2 -> FORMERR; QDCOUNT 0 -> profile REFUSED; unknown opcode -> NOTIMP; none forwarded |
| A04 | E1–E2 | EDNS absent, EDNS0 DO=0/1, unsupported version, duplicate OPT and malformed option length produce their distinct expected responses |
| A05 | E1, K1 | Non-hop option (anything but ECS, Cookie, keepalive, Padding) or non-DO flag: no cross-client cache or shared future; hop options are stripped and share the cache |
| A06 | W4, E3 | Two clients with different question case and IDs; compressed answer owners and unknown RDATA remain correct after presentation |
| A07 | T1–T2 | 512/1232/4096 advertisements against large answer: bounded well-formed TC; later TCP obtains full answer |
| A08 | T1, T4 | Query each configured local address, and on a wildcard bind a second loopback address (`127.0.0.2`, plain and batched receive; IPv6 `::1`): reply source address matches destination queried |
| A09 | T3 | Split prefix/body and multiple frames in one read; slow first query and fast second query; complete noninterleaved frames with correct IDs |
| A10 | T3, O1 | Fill TCP idle slots and trickle partial frames: UDP still works, deadlines and connection limits hold |
| A11 | U1–U2 | Wrong peer, ID, opcode, qname/type/class and late hedge result: rejected and never cached |
| A12 | U2 | Observe independent UDP attempts: valid IDs/ports, no active collision; deterministic randomness injection tests the mapping (it is not a statistical entropy test) |
| A13 | U3 | Upstream TC causes TCP retry within original deadline; failed TCP never inserts partial data |
| A14 | U4 | HTTP 200 + DNS SERVFAIL versus HTTP error; wrong media type; oversized body; Age 250 with TTL 600 yields 350 |
| A15 | U4, C2 | Age >= TTL, invalid/overflowing Age, and SOA minimum smaller than TTL: no accidental fresh/stale reuse |
| A16 | U5 | Fast failure advances immediately; valid NXDOMAIN wins without waiting for an allow; successful hedge cancels losers |
| A17 | D1–D4 | DO/CD/query-AD matrix, explicit DS/DNSKEY/RRSIG with DO=0, trusted DoH versus UDP AD, synthesis and stale AD clearing |
| A18 | D5 | TYPE128 -> FORMERR; CO and non-CO clients never share; compact proof bytes pass through without RCODE restoration |
| A19 | K1–K5 | 100 equivalent misses from different clients (or over TCP, or with `upstream_inflight_per_client = 0`: O7 counts UDP followers per client, 64 by default) create one eligible attempt; each waiter receives its own presentation; forced hash collision is a miss |
| A20 | K4 | Cancel first/all waiters, force timeout/error and shutdown: no leaked key, stuck waiter or duplicate refresh |
| A21 | P1, K5 | Reload upstream/policy view while resolution is pending: old result cannot poison new generation; bypass still observes rewrites |
| A22 | C1–C2 | Age all RR TTLs, keep OPT flags/RDATA intact, normalize unequal RRset TTLs, test unsigned high-bit TTL against cap |
| A23 | C2, S1 | Original TTL zero and Age-exhausted zero: current transaction may complete, later request performs new work, no stale reuse |
| A24 | N1–N3 | Positive, NXDOMAIN, NODATA, referral, CNAME-to-NODATA and CNAME-to-NXDOMAIN; missing SOA stays uncached; emit correct SOA TTL |
| A25 | P3, N4 | Cached `x.example` negative never automatically answers `child.x.example` or another exact-question packet; unrelated Additional RRs never seed answers to new questions |
| A26 | F1–F3, U6 | All upstreams fail: repeated queries and equivalent probes cause no outgoing work during suppression; retry after expiry; CD/view contexts isolated |
| A27 | S1–S3 | Advance virtual time across fresh, stale, suppression and total-age boundaries; test both named stale modes and preserved failed refresh |
| A28 | S4 | Hits near prefetch threshold produce one refresh; failed refresh enters backoff; zero-TTL and policy answers never prefetch |
| A29 | P2, L1–L2 | Priority, parent boundaries, exact hosts, wildcard specificity, ANY/diagnostic precedence and IN-only rewrite behavior |
| A30 | L3–L4, L6 | Reverse-zone descendant/apex SOA/NS/NODATA, private-route failure without public leak, local home.arpa, and the public DS+DO exception at every local zone apex |
| A31 | L5 | TSIG/SIG(0) are refused explicitly; DNSSEC RRSIG data is not mistaken for transaction authentication |
| A32 | C3, O1–O3 | Entry/byte limits, distinct in-flight keys and failure-cache limits; large/malformed lists cannot exceed streaming limits |
| A33 | O2 | One bad list keeps last good copy; malformed config retains prior generation; persisted-list boot works without public network |
| A34 | O4 | Upstream outage preserves local/stale service; minimal health works with UI disabled; shutdown drains or cancels within budget |
| A35 | C4, N1 | Replace A/AAAA with CNAME or terminal NXDOMAIN: old contradictory stale variants disappear without invalidating the alias as nonexistent |
| A36 | L7 | Blocked CNAME/DNAME target on the cold relay, the warm UDP hit, TCP, a stale hit and a refresh; allowed query name, exempt client and knob off are served; a rules reload recomputes a cached verdict; off-chain owners and targets count (fail closed), as do names behind a loop, conflict, gap or overlong chain |
| A37 | W5, U7 | One scripted upstream reply per contradictory shape (NXDOMAIN with an address at the name, NOERROR with only a TXT for an A question, NXDOMAIN whose alias tail is answered) and per meta-TYPE (128, 248, TKEY, TSIG, IXFR, AXFR, ANY, OPT in Answer) or foreign Answer class (ANY, NONE, CH): SERVFAIL, nothing cached, a repeat goes upstream again; NXDOMAIN after a CNAME and ANY/TXT questions stay valid |
| A38 | U8, U9 | A 3000-byte UDP reply to a query advertising 1232 is not the answer and TCP is asked; a DoH 429/503 with `Retry-After: 120` gets one request for 20 names while another upstream serves and is capped at 60 s; on the last usable upstream a client-drawn pause fails no other query, an HTTP-date works, a missing or bad value keeps the ordinary backoff |
| A39 | O6 | A reply held past `udp_discard_timeout_ms` is not sent over UDP but is cached and served over TCP; SERVFAIL, hits and `udp_discard_timeout_ms = 0` are unaffected; `dropped` counts discards |
| A40 | O7 | One host flooding unique names holds at most `upstream_inflight_per_client` misses; its surplus gets TC=1 over UDP (rate limited) and SERVFAIL over TCP, misses held over UDP leave it no extra slots over TCP, another host (including another address in the same IPv6 /64) and cache hits are served, a slot frees when its query ends |
| A41 | C5 | 200 hot names with 3 hits each survive 500 one-hit 60 KB answers; a large answer is admitted on its second sight and a resident one is refreshed |
| A42 | T5 | `listen` array with `127.0.0.1` and `::1`: both answer over UDP and TCP; a duplicate address is rejected at validation |

