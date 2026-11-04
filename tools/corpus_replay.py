#!/usr/bin/env python3
"""Build the private time-faithful replay input from AdGuard Home's querylog.

Writes bench/corpus/replay.tsv (gitignored), one line per log entry:

  epoch_ms  name  qtype  flags  ttl  rcode  agh_cached  agh_elapsed_us  answer_hex

flags: 0 forwarded, 1 blocked (Result.IsFiltered), 2 answered locally by a
rewrite (Result.Reason 9/10/11). ttl is the lifetime the sopedu cache would
assign before negative clamping: min TTL over every non-OPT record for a
positive answer, min(SOA TTL, SOA MINIMUM) for NXDOMAIN/NODATA, -1 when the
answer is absent or unparseable. answer_hex is the wire answer for forwarded,
non-cached entries only (the upstream's real response; empty otherwise).
Elapsed is a Go time.Duration (nanoseconds) and is written in microseconds.

Only aggregate counts are printed. Usage:

  python3 -I tools/corpus_replay.py bench/corpus/querylog.json bench/corpus/replay.tsv
  python3 -I tools/corpus_replay.py --self-test
"""
import base64
import json
import os
import struct
import subprocess
import sys
from collections import Counter
from datetime import datetime

REWRITTEN = {9, 10, 11}


def skip_name(msg, pos):
    while True:
        n = msg[pos]
        if n & 0xC0 == 0xC0:
            return pos + 2
        pos += 1 + n
        if n == 0:
            return pos


def answer_ttl(msg):
    """(rcode, ttl) for a DNS wire response; ttl -1 when not derivable."""
    _, flags, qd, an, ns, ar = struct.unpack_from("!6H", msg, 0)
    rcode = flags & 0xF
    pos = 12
    for _ in range(qd):
        pos = skip_name(msg, pos) + 4
    ttls, soa = [], []
    for section, count in ((0, an), (1, ns), (2, ar)):
        for _ in range(count):
            pos = skip_name(msg, pos)
            rtype, _, ttl, rdlen = struct.unpack_from("!HHIH", msg, pos)
            pos += 10
            if rtype != 41:  # OPT carries no TTL
                ttls.append(ttl)
            if rtype == 6 and section == 1:
                p = skip_name(msg, skip_name(msg, pos))
                minimum = struct.unpack_from("!5I", msg, p)[4]
                soa.append(min(ttl, minimum))
            pos += rdlen
    negative = rcode == 3 or (rcode == 0 and an == 0)
    if negative:
        return rcode, min(soa) if soa else -1
    return rcode, min(ttls) if ttls else -1


def epoch_ms(value):
    try:
        return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp() * 1000)
    except (AttributeError, ValueError):
        return 0


def ignored(path):
    return subprocess.run(["git", "check-ignore", "-q", path], check=False).returncode == 0


def main(src, dst):
    if not ignored(dst):
        print(f"refusing to write {dst}: not gitignored", file=sys.stderr)
        return 1
    os.umask(0o077)
    rows = 0
    flags_seen, ttl_known, cached = Counter(), 0, 0
    with open(src, encoding="utf-8") as f, open(dst + ".tmp", "w", encoding="utf-8") as out:
        for line in f:
            if not line.strip():
                continue
            o = json.loads(line)
            name = o.get("QH", "").rstrip(".").lower()
            if not name:
                continue
            result = o.get("Result") or {}
            flags = 1 if result.get("IsFiltered") else 2 if result.get("Reason") in REWRITTEN else 0
            rcode, ttl, hexed = -1, -1, ""
            raw = base64.b64decode(o.get("Answer") or "")
            if raw:
                try:
                    rcode, ttl = answer_ttl(raw)
                except (IndexError, struct.error):
                    pass
            is_cached = bool(o.get("Cached"))
            if raw and flags == 0 and not is_cached:
                hexed = raw.hex()
            elapsed = o.get("Elapsed") if isinstance(o.get("Elapsed"), int) else 0
            out.write(f"{epoch_ms(o.get('T'))}\t{name}\t{o.get('QT') or 'A'}\t{flags}\t{ttl}\t{rcode}\t"
                      f"{int(is_cached)}\t{elapsed // 1000}\t{hexed}\n")
            rows += 1
            flags_seen[flags] += 1
            ttl_known += ttl >= 0
            cached += is_cached
    os.replace(dst + ".tmp", dst)
    print(json.dumps({"rows": rows, "flags": dict(flags_seen), "ttl_known": ttl_known, "agh_cached": cached}))
    return 0


def self_test():
    # Header: id, flags (NXDOMAIN), 1 question, 0 answer, 1 authority, 1 additional (OPT).
    q = b"\x01a\x00" + struct.pack("!HH", 1, 1)
    soa_rdata = b"\x00\x00" + struct.pack("!5I", 1, 2, 3, 4, 60)
    soa = b"\x00" + struct.pack("!HHIH", 6, 1, 300, len(soa_rdata)) + soa_rdata
    opt = b"\x00" + struct.pack("!HHIH", 41, 1232, 0, 0)
    msg = struct.pack("!6H", 1, 0x8183, 1, 0, 1, 1) + q + soa + opt
    assert answer_ttl(msg) == (3, 60), answer_ttl(msg)
    a = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 120, 4) + b"\x01\x02\x03\x04"
    msg = struct.pack("!6H", 1, 0x8180, 1, 1, 0, 0) + q + a
    assert answer_ttl(msg) == (0, 120), answer_ttl(msg)
    print("self-test: ok")
    return 0


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        sys.exit(self_test())
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1], sys.argv[2]))
