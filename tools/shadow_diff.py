#!/usr/bin/env python3
"""Live differential: ask two DNS servers the same names and compare outcomes.

Usage:
  python3 -I tools/shadow_diff.py NAMES_FILE A_HOST:PORT B_HOST:PORT OUT.tsv [--qps N] [--qtypes A,AAAA]
  python3 -I tools/shadow_diff.py --self-test

NAMES_FILE holds one name per line (bench/corpus/unique.txt, private). Each
answer is classified as blocked (NXDOMAIN, or only 0.0.0.0/::), answered,
nodata, servfail, refused, other, or timeout. Only aggregate counts are
printed; mismatching names go to OUT.tsv, which must stay under the gitignored
bench/corpus/. Answer addresses are not compared (CDNs rotate them).
"""
import asyncio
import os
import random
import struct
import sys
from collections import Counter

TYPES = {"A": 1, "AAAA": 28}


def encode(name, qtype, ident):
    labels = b"".join(bytes([len(p)]) + p.encode("idna") for p in name.strip(".").split(".") if p)
    return struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0) + labels + b"\x00" + struct.pack("!HH", qtype, 1)


def classify(reply):
    if reply is None:
        return "timeout"
    if len(reply) < 12:
        return "other"
    _, flags, qd, an, _, _ = struct.unpack("!HHHHHH", reply[:12])
    rcode = flags & 15
    if rcode == 3:
        return "blocked"
    if rcode == 2:
        return "servfail"
    if rcode == 5:
        return "refused"
    if rcode != 0:
        return "other"
    if an == 0:
        return "nodata"
    pos = 12
    for _ in range(qd):
        pos = skip_name(reply, pos) + 4
    addrs, other = [], False
    for _ in range(an):
        pos = skip_name(reply, pos)
        rtype, _, _, rdlen = struct.unpack("!HHIH", reply[pos:pos + 10])
        data = reply[pos + 10:pos + 10 + rdlen]
        pos += 10 + rdlen
        if rtype in (1, 28):
            addrs.append(data)
        else:
            other = True
    if addrs and not other and all(a in (b"\0" * 4, b"\0" * 16) for a in addrs):
        return "blocked"
    return "answered"


def skip_name(msg, pos):
    while True:
        n = msg[pos]
        if n & 0xC0 == 0xC0:
            return pos + 2
        pos += 1 + n
        if n == 0:
            return pos


async def ask(host, port, packet, timeout=3.0):
    loop = asyncio.get_running_loop()
    fut = loop.create_future()

    class P(asyncio.DatagramProtocol):
        def datagram_received(self, data, addr):
            if not fut.done() and data[:2] == packet[:2]:
                fut.set_result(data)

    transport, _ = await loop.create_datagram_endpoint(P, remote_addr=(host, port))
    try:
        for _ in range(2):
            transport.sendto(packet)
            try:
                return await asyncio.wait_for(asyncio.shield(fut), timeout)
            except asyncio.TimeoutError:
                continue
        return None
    finally:
        transport.close()


async def run(names, a, b, qtypes, qps):
    gate = asyncio.Semaphore(32)
    pairs, rows = Counter(), []

    async def one(name, qtype):
        async with gate:
            await asyncio.sleep(0)
            packet = encode(name, TYPES[qtype], random.randrange(65536))
            ra, rb = await asyncio.gather(ask(*a, packet), ask(*b, packet))
            ca, cb = classify(ra), classify(rb)
            pairs[(qtype, ca, cb)] += 1
            if ca != cb:
                rows.append((name, qtype, ca, cb))

    tasks = []
    for name in names:
        for qtype in qtypes:
            tasks.append(asyncio.create_task(one(name, qtype)))
            await asyncio.sleep(1 / qps)
    await asyncio.gather(*tasks)
    return pairs, rows


def addr(text):
    host, port = text.rsplit(":", 1)
    return host, int(port)


def self_test():
    nx = struct.pack("!HHHHHH", 1, 0x8183, 1, 0, 0, 0) + encode("x.test", 1, 1)[12:]
    assert classify(nx) == "blocked"
    q = encode("x.test", 1, 2)
    zero = struct.pack("!HHHHHH", 2, 0x8180, 1, 1, 0, 0) + q[12:] + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + b"\0\0\0\0"
    real = zero[:-4] + b"\xc0\x00\x02\x01"
    assert classify(zero) == "blocked" and classify(real) == "answered"
    assert classify(None) == "timeout"
    print("self-test ok")


def main():
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
    names_file, a, b, out = sys.argv[1:5]
    qps = float(sys.argv[sys.argv.index("--qps") + 1]) if "--qps" in sys.argv else 100
    qtypes = sys.argv[sys.argv.index("--qtypes") + 1].split(",") if "--qtypes" in sys.argv else ["A"]
    names = [line.strip() for line in open(names_file, encoding="utf-8") if line.strip()]
    pairs, rows = asyncio.run(run(names, addr(a), addr(b), qtypes, qps))
    os.umask(0o077)
    with open(out, "w", encoding="utf-8") as f:
        f.write("name\tqtype\ta\tb\n")
        for row in sorted(rows):
            f.write("\t".join(row) + "\n")
    total = sum(pairs.values())
    same = sum(n for (_, ca, cb), n in pairs.items() if ca == cb)
    print(f"queries={total} same={same} differ={total - same}")
    for (qtype, ca, cb), n in sorted(pairs.items(), key=lambda kv: -kv[1]):
        print(f"  {qtype:5} {ca:9} vs {cb:9} {n}")


if __name__ == "__main__":
    main()
