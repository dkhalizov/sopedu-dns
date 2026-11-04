#!/usr/bin/env python3
"""Reads "name TYPE" lines (dnsperf format) on stdin, queries SERVER:PORT, and
prints the lines whose answer is not NXDOMAIN (sopedu blocks with NXDOMAIN;
the mock upstream never does). Usage: classify.py SERVER PORT < hot.txt
Pipelined, at most 32 in flight (under sopedu's per-client upstream cap)."""
import select, socket, struct, sys

TYPES = {"A": 1, "NS": 2, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28, "SRV": 33, "NAPTR": 35, "HTTPS": 65}

def packet(i, name, qt):
    q = b"".join(bytes([len(l)]) + l.encode() for l in name.rstrip(".").split(".")) + b"\0"
    return struct.pack(">HHHHHH", i, 0x0100, 1, 0, 0, 0) + q + struct.pack(">HH", qt, 1)

server, port = sys.argv[1], int(sys.argv[2])
lines = [l.split() for l in sys.stdin if len(l.split()) >= 2]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect((server, port))
pending, nxt, keep, done = {}, 0, [], 0
while done < len(lines):
    while nxt < len(lines) and len(pending) < 32:
        pending[nxt & 0xFFFF] = (nxt, 0)
        s.send(packet(nxt & 0xFFFF, lines[nxt][0], TYPES[lines[nxt][1]]))
        nxt += 1
    r, _, _ = select.select([s], [], [], 2)
    if not r:  # lost: count as unknown, drop from the allowed set
        done += len(pending); pending.clear(); continue
    d = s.recv(4096)
    i = struct.unpack(">H", d[:2])[0]
    if i in pending:
        idx = pending.pop(i)[0]; done += 1
        if d[3] & 0x0F != 3:
            keep.append(idx)
for idx in sorted(keep):
    print(lines[idx][0], lines[idx][1])
