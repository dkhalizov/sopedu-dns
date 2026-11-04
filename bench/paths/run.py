#!/usr/bin/env python3
"""Request-path benchmark matrix for sopedu-dns.

Starts the real server binary against bench/upstream-mock (plain + DoH with
a throwaway CA) and drives every request path with dnsperf in open-loop,
fixed-rate mode (-Q, a deep -q so the sender never waits on replies, which
keeps it coordinated-omission-safe as long as `achieved` equals the target
rate). Prints one Markdown table and writes raw TSV to bench/paths/.run/.

    cargo build --release --manifest-path bench/upstream-mock/Cargo.toml
    python3 -I bench/paths/run.py --server target/release/sopedu-dns [--seconds 10] [--only a,b]

Needs dnsperf >= 2.16 (latency histogram), dig, openssl. Blocked-hit and
list scenarios need the real lists in bench/corpus/lists/ (gitignored); they
are skipped when absent. Names are synthetic (*.bench) or come from the public
blocklists; nothing from the private query corpus is read or printed.
"""

import argparse
import hashlib
import http.server
import os
import pathlib
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
RUN = ROOT / "bench/paths/.run"
LISTS = ROOT / "bench/corpus/lists"
PORT, MOCK_A, MOCK_B, DOH_A, DOH_B, HTTP = 15360, 15300, 15301, 18443, 18444, 18080
RATES = (50, 500, 5000)
MAXRSS_KIB = 1 if sys.platform.startswith("linux") else 1 / 1024  # ru_maxrss unit

rows = []


def log(msg):
    print(msg, file=sys.stderr, flush=True)


# ---------------------------------------------------------------- processes

class Mock:
    def __init__(self, plain, doh=None, delay=10, mode="ok"):
        args = [str(A.mock), "--listen", f"127.0.0.1:{plain}", "--delay-ms", str(delay), "--mode", mode]
        if doh:
            args += ["--doh", f"127.0.0.1:{doh}", "--cert", str(RUN / "tls/cert.der"), "--key", str(RUN / "tls/key.der")]
        self.err = open(RUN / f"mock-{plain}.log", "w+")
        self.proc = subprocess.Popen(args, stderr=self.err)
        time.sleep(0.3)

    def count(self):
        """Queries received so far (udp+tcp+doh) from the last stats line."""
        time.sleep(1.2)
        self.err.flush()
        lines = [l for l in pathlib.Path(self.err.name).read_text().splitlines() if l.startswith("stats")]
        return sum(int(v) for v in re.findall(r"=(\d+)", lines[-1])) if lines else 0

    def stop(self):
        self.proc.terminate()
        self.proc.wait()


class Server:
    def __init__(self, name, **cfg):
        self.dir = RUN / name
        shutil.rmtree(self.dir, ignore_errors=True) if not cfg.pop("keep_state", False) else None
        self.dir.mkdir(parents=True, exist_ok=True)
        base = {
            "listen": f'"127.0.0.1:{PORT}"',
            "upstreams": f'["https://127.0.0.1:{DOH_A}/dns-query"]',
            "fallback": f'["127.0.0.1:{MOCK_A}"]',
            "state_dir": f'"{self.dir}/state"',
            "ui_enabled": "false",
            "prewarm": "false",
            "blocklists": "[]",
            "upstream_0x20": "false",
        }
        base.update({k: v for k, v in cfg.items() if k != "rewrites"})
        self.text = "".join(f"{k} = {v}\n" for k, v in base.items())
        if "rewrites" in cfg:
            self.text += "[rewrites]\n" + cfg["rewrites"] + "\n"
        self.config = self.dir / "config.toml"
        self.config.write_text(self.text)
        self.out = open(self.dir / "server.log", "w")
        env = dict(os.environ, SSL_CERT_FILE=str(RUN / "tls/ca.pem"))
        self.t0 = time.monotonic()
        self.proc = subprocess.Popen([str(A.server), str(self.config)], stdout=self.out, stderr=subprocess.STDOUT, env=env)
        self.ready_s = wait_answer()
        if self.ready_s is None:
            raise SystemExit(f"{name}: server did not answer; see {self.dir}/server.log")

    def logged(self, msg):
        return [l for l in (self.dir / "server.log").read_text().splitlines() if f"msg={msg} " in l]

    def rss_kib(self):
        out = subprocess.run(["ps", "-o", "rss=", "-p", str(self.proc.pid)], capture_output=True, text=True).stdout
        return int(out.strip() or 0)

    def stop(self):
        """Stops the server and returns its peak RSS (KiB) from wait4."""
        self.proc.send_signal(signal.SIGTERM)
        _, _, usage = os.wait4(self.proc.pid, 0)
        self.proc.returncode = 0
        self.out.close()
        return int(usage.ru_maxrss * MAXRSS_KIB)


def wait_answer(timeout=60):
    """Seconds until the server answers one UDP query (10 ms resend, so the
    resolution is ~10 ms; the query is a 10 ms upstream miss)."""
    query = bytes.fromhex("abcd01000001000000000000") + b"\x05ready\x05bench\x00\x00\x01\x00\x01"
    t0 = time.monotonic()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(0.01)
        while time.monotonic() - t0 < timeout:
            try:
                sock.sendto(query, ("127.0.0.1", PORT))
                if sock.recv(512)[:2] == query[:2]:
                    return time.monotonic() - t0
            except OSError:  # timeout or ICMP port unreachable before bind
                time.sleep(0.005)
    return None


# ------------------------------------------------------------------ dnsperf

def write(name, lines):
    path = RUN / f"{name}.txt"
    path.write_text("".join(f"{l}\n" for l in lines))
    return path


def dnsperf(path, rate=None, seconds=None, outstanding=10000, clients=4, tcp=False, once=False):
    args = ["dnsperf", "-s", "127.0.0.1", "-p", str(PORT), "-d", str(path), "-c", str(clients), "-T", "1",
            "-q", str(outstanding), "-t", "5", "-O", "latency-histogram"]
    args += ["-n", "1"] if once else ["-l", str(seconds or A.seconds)]
    if rate:
        args += ["-Q", str(rate)]
    if tcp:
        args += ["-m", "tcp"]
    out = subprocess.run(args, capture_output=True, text=True).stdout
    num = lambda pat: float(m.group(1)) if (m := re.search(pat, out)) else 0.0
    hist = sorted((float(hi), int(n)) for hi, n in re.findall(r"^\s*[\d.]+ - ([\d.]+):\s+(\d+)", out, re.M))
    total = sum(n for _, n in hist)

    def pct(p):
        cum = 0
        for hi, n in hist:
            cum += n
            if total and cum >= p * total:
                return hi * 1000
        return float("nan")

    return {
        "sent": int(num(r"Queries sent:\s+(\d+)")),
        "lost": int(num(r"Queries lost:\s+(\d+)")),
        "qps": num(r"Queries per second:\s+([\d.]+)"),
        "p50": pct(0.50), "p99": pct(0.99), "p999": pct(0.999),
        "max": num(r"max ([\d.]+)\)") * 1000,
        "codes": (m.group(1).strip() if (m := re.search(r"Response codes:\s+(.*)", out)) else ""),
    }


def record(path_name, load, r, note=""):
    target = load if isinstance(load, (int, float)) else None
    rows.append({"path": path_name, "load": str(load), **r, "note": note,
                 "achieved": f"{r['qps']:.0f}" + ("" if target is None else f"/{target}")})
    log(f"  {path_name:<22} {str(load):>8}  qps={r['qps']:.0f} p50={r['p50']:.3f} p99={r['p99']:.3f} "
        f"p99.9={r['p999']:.3f} lost={r['lost']} {note}")


def rates(path_name, path, tcp=False, rate_list=RATES, note=""):
    for q in rate_list:
        record(path_name, q, dnsperf(path, rate=q, tcp=tcp, clients=1 if q <= 500 else 4), note)


# ---------------------------------------------------------------- scenarios

def names(prefix, zone, n, qtype="A"):
    return [f"{prefix}{i}.{zone} {qtype}" for i in range(n)]


def unique(prefix, zone, rate, qtype="A"):
    return write(prefix, names(prefix, zone, int(rate * A.seconds * 1.3) + 100, qtype))


def s_hits():
    srv = Server("hits")
    hot = write("hot", names("h", "bench", 5000))
    dnsperf(hot, once=True, outstanding=100)
    rates("hit/udp", hot)
    record("hit/udp", "sat q200", dnsperf(hot, outstanding=200))
    rates("hit/tcp", hot, tcp=True)
    record("hit/tcp pipelined", "c1 q200", dnsperf(hot, outstanding=200, clients=1, tcp=True), "1 conn, 200 in flight")
    record("hit/tcp pipelined", "c4 q200", dnsperf(hot, outstanding=200, tcp=True))
    rows.append({"path": "rss after hits", "load": "", "note": f"{srv.rss_kib()} KiB current"})
    srv.stop()
    # Same pipeline without the default 64-queries-per-connection close.
    srv = Server("tcp-unbounded", tcp_queries_per_connection="65536")
    dnsperf(hot, once=True, outstanding=100)
    record("hit/tcp pipelined", "c1 q200", dnsperf(hot, outstanding=200, clients=1, tcp=True),
           "tcp_queries_per_connection = 65536")
    srv.stop()


def s_negative_rewrite_trunc():
    srv = Server("local", rewrites='"*.rw.bench" = "192.0.2.77"')
    nx = write("nx", names("n", "nx.bench", 5000))
    dnsperf(nx, once=True, outstanding=100)
    before = MOCKS["a"].count()
    rates("negative hit (NXDOMAIN)", nx, rate_list=(500, 5000))
    record("negative hit (NXDOMAIN)", "upstream", {"qps": 0, "p50": 0, "p99": 0, "p999": 0, "lost": 0, "max": 0,
           "sent": 0, "codes": ""}, f"{MOCKS['a'].count() - before} upstream queries during the runs")
    rates("rewrite", write("rw", names("r", "rw.bench", 5000)), rate_list=(500, 5000))
    big = write("big", names("b", "big.bench", 2000, "TXT"))
    dnsperf(big, once=True, outstanding=100, tcp=True)  # cache the 1.5 KB answers
    rates("truncation (UDP TC)", big, rate_list=(500,), note="no EDNS: 512-byte limit, answer is TC")
    rates("truncation retry (TCP)", big, tcp=True, rate_list=(500,), note="client retry leg")
    srv.stop()


def s_miss():
    for label, extra in (("miss/DoH", {}), ("miss/plain fallback only", {"upstreams": "[]"})):
        srv = Server("miss", **extra)
        for q in (50, 500):
            path = unique(f"m{q}x{len(rows)}", "bench", q)
            before = MOCKS["a"].count()
            r = dnsperf(path, rate=q, clients=1)
            record(label, q, r, f"upstream delay 10 ms; {MOCKS['a'].count() - before} upstream queries")
        srv.stop()


def s_stale_prefetch():
    srv = Server("stale", upstreams=f'["https://127.0.0.1:{DOH_B}/dns-query"]')  # B: 50 ms
    st = write("stale", names("s", "ttl1.bench", 2000))
    dnsperf(st, once=True, outstanding=200)
    time.sleep(2.5)
    before = MOCKS["b"].count()
    r = dnsperf(st, rate=500, seconds=3.5, clients=1)
    record("stale serve (RFC 8767)", 500, r, f"each name once after expiry; upstream 50 ms; "
           f"{MOCKS['b'].count() - before} background refreshes")
    srv.stop()
    # Prefetch: serve-stale off, so an expiry without prefetch is a 50 ms miss.
    hot = write("pf", names("p", "ttl20.bench", 200))
    for label, pf in (("prefetch on", "true"), ("prefetch off", "false")):
        srv = Server("prefetch", upstreams=f'["https://127.0.0.1:{DOH_B}/dns-query"]',
                     optimistic_max_age="0", prefetch=pf)
        dnsperf(hot, once=True, outstanding=200)
        before = MOCKS["b"].count()
        r = dnsperf(hot, rate=400, seconds=max(45, A.seconds), clients=1)
        record(label, 400, r, f"200 names TTL 20 s, serve-stale off; {MOCKS['b'].count() - before} upstream queries")
        srv.stop()


def s_upstream_faults():
    # Hedging: first upstream 300 ms (C), second 10 ms (A).
    up = f'["https://127.0.0.1:{DOH_C}/dns-query", "https://127.0.0.1:{DOH_A}/dns-query"]'
    srv = Server("hedge", upstreams=up)
    r = dnsperf(unique(f"hg{len(rows)}", "bench", 50), rate=50, clients=1)
    record("miss, slow 1st upstream", 50, r, "300 ms + 10 ms DoH upstreams, hedge 50 ms")
    srv.stop()
    srv = Server("slow-only", upstreams=f'["https://127.0.0.1:{DOH_C}/dns-query"]')
    record("miss, slow only (ref)", 50, dnsperf(unique(f"so{len(rows)}", "bench", 50), rate=50, clients=1),
           "single 300 ms upstream")
    srv.stop()
    # Blackhole first upstream: hedge covers it, then the circuit opens.
    up = f'["https://127.0.0.1:{DOH_H}/dns-query", "https://127.0.0.1:{DOH_A}/dns-query"]'
    srv = Server("hang", upstreams=up)
    for window in ("0-10 s", "10-20 s"):
        before = MOCKS["h"].count()
        r = dnsperf(unique(f"hb{len(rows)}", "bench", 50), rate=50, seconds=10, clients=1)
        record("miss, blackholed 1st", window, r, f"{MOCKS['h'].count() - before} queries reached the dead upstream")
    srv.stop()
    # Every DoH upstream answers 503: plain fallback after DoH failure.
    srv = Server("doh503", upstreams=f'["https://127.0.0.1:{DOH_E}/dns-query"]')
    record("miss, DoH 503 -> plain", 50, dnsperf(unique(f"de{len(rows)}", "bench", 50), rate=50, clients=1),
           "fallback after DoH error")
    srv.stop()


def lists_cfg():
    return "[" + ", ".join(f'"http://127.0.0.1:{HTTP}/{p.name}"' for p in sorted(LISTS.glob("*.txt"))) + "]"


def blocked_names(n=5000):
    out = []
    for p in sorted(LISTS.glob("*.txt")):
        for line in p.read_text(errors="ignore").splitlines():
            m = re.fullmatch(r"\|\|([a-z0-9.-]+)\^", line)
            if m and "." in m.group(1):
                out.append(f"{m.group(1)} A")
                if len(out) >= n:
                    return out
    return out


def s_lists():
    if not LISTS.is_dir():
        log("skip lists: bench/corpus/lists missing")
        return
    http.server.SimpleHTTPRequestHandler.log_message = lambda *a: None
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", HTTP), lambda *a: http.server.SimpleHTTPRequestHandler(
        *a, directory=str(LISTS)))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        # Cold start, empty state: ready before lists, then first download.
        srv = Server("lists", blocklists=lists_cfg())
        t0 = time.monotonic()
        while not srv.logged("blocklists") and time.monotonic() - t0 < 120:
            time.sleep(0.05)
        ev = srv.logged("blocklists")[-1]
        rules = re.search(r"rules=(\d+)", ev).group(1)
        rows.append({"path": "cold start, empty state", "load": "", "note":
                     f"ready {srv.ready_s * 1000:.0f} ms; first list download+build "
                     f"{re.search(r'latency_ms=(\d+)', ev).group(1)} ms, {rules} rules"})
        blocked = write("blocked", blocked_names())
        rates("blocked hit (full lists)", blocked, rate_list=(500, 5000), note=f"{rules} rules")
        peak = srv.stop()
        rows.append({"path": "peak RSS, lists + download", "load": "", "note": f"{peak} KiB (wait4 ru_maxrss)"})
        # Warm start: boot cache load before ready.
        srv = Server("lists", blocklists=lists_cfg(), keep_state=True)
        loaded = srv.logged("blocklists_loaded")[-1]
        rows.append({"path": "cold start, boot cache", "load": "", "note":
                     f"ready {srv.ready_s * 1000:.0f} ms; boot-cache load "
                     f"{re.search(r'latency_ms=(\d+)', loaded).group(1)} ms before listening"})
        while len(srv.logged("blocklists")) < 1:
            time.sleep(0.05)
        hot = write("hot", names("h", "bench", 5000))
        dnsperf(hot, once=True, outstanding=100)
        record("hit during no refresh", 500, dnsperf(hot, rate=500, seconds=20, clients=1), "baseline for next row")
        # Every 4 s change refresh_hours and SIGHUP: each reload refreshes the lists.
        stop = threading.Event()

        def churn():
            n = 0
            while not stop.wait(4):
                n += 1
                srv.config.write_text(srv.text.replace("blocklists", f"refresh_hours = {24 + n}\nblocklists", 1))
                srv.proc.send_signal(signal.SIGHUP)

        before = len(srv.logged("blocklists"))
        t = threading.Thread(target=churn)
        t.start()
        r = dnsperf(hot, rate=500, seconds=20, clients=1)
        stop.set()
        t.join()
        time.sleep(3)
        refreshes = srv.logged("blocklists")[before:]
        lat = [int(re.search(r"latency_ms=(\d+)", l).group(1)) for l in refreshes]
        record("hit during list refresh", 500, r, f"{len(lat)} refreshes, {min(lat or [0])}-{max(lat or [0])} ms each")
        peak = srv.stop()
        rows.append({"path": "peak RSS, boot + refreshes", "load": "", "note": f"{peak} KiB (wait4 ru_maxrss)"})
    finally:
        httpd.shutdown()


def s_cold_start():
    times = []
    for _ in range(5):
        srv = Server("cold")
        times.append(srv.ready_s * 1000)
        idle = srv.rss_kib()
        srv.stop()
    rows.append({"path": "cold start, no lists", "load": "", "note":
                 f"ready median {sorted(times)[2]:.0f} ms (5 runs, {min(times):.0f}-{max(times):.0f}); idle RSS {idle} KiB"})


SCENARIOS = {"hits": s_hits, "local": s_negative_rewrite_trunc, "miss": s_miss, "stale": s_stale_prefetch,
             "faults": s_upstream_faults, "lists": s_lists, "cold": s_cold_start}


def main():
    global A, MOCKS, DOH_C, DOH_H, DOH_E
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", type=pathlib.Path, default=ROOT / "target/release/sopedu-dns")
    ap.add_argument("--mock", type=pathlib.Path, default=ROOT / "bench/upstream-mock/target/release/upstream-mock")
    ap.add_argument("--seconds", type=float, default=10)
    ap.add_argument("--only", default=",".join(SCENARIOS))
    A = ap.parse_args()
    RUN.mkdir(parents=True, exist_ok=True)
    subprocess.run([str(ROOT / "bench/mkcert.sh"), str(RUN / "tls"), "IP:127.0.0.1"], check=True)
    DOH_C, DOH_H, DOH_E = 18445, 18446, 18447
    MOCKS = {
        "a": Mock(MOCK_A, DOH_A, delay=10),
        "b": Mock(MOCK_B, DOH_B, delay=50),
        "c": Mock(15302, DOH_C, delay=300),
        "h": Mock(15303, DOH_H, mode="hang"),
        "e": Mock(15304, DOH_E, mode="error"),
    }
    try:
        for name in A.only.split(","):
            log(f"== {name}")
            SCENARIOS[name]()
    finally:
        for m in MOCKS.values():
            m.stop()
    git = lambda *a: subprocess.run(["git", "-C", str(ROOT), *a], capture_output=True, text=True).stdout.strip()
    sha = hashlib.sha256(A.server.read_bytes()).hexdigest()[:16]
    dirty = len(git("status", "--short", "src").splitlines())
    print(f"server `{A.server}` sha256 {sha}…; repo HEAD {git('rev-parse', '--short', 'HEAD')}, "
          f"{dirty} dirty src files (the binary may come from another tree); "
          f"{A.seconds:.0f} s phases, dnsperf open loop -Q, -q 10000\n")
    print("| path | target qps | achieved | p50 ms | p99 ms | p99.9 ms | max ms | lost | note |")
    print("|---|---:|---:|---:|---:|---:|---:|---:|---|")
    with open(RUN / "results.tsv", "w") as tsv:
        for r in rows:
            if "qps" not in r:
                print(f"| {r['path']} | | | | | | | | {r['note']} |")
                tsv.write(f"{r['path']}\t\t\t\t\t\t\t\t{r['note']}\n")
                continue
            cells = [r["path"], r["load"], r["achieved"], f"{r['p50']:.3f}", f"{r['p99']:.3f}", f"{r['p999']:.3f}",
                     f"{r['max']:.1f}", str(r["lost"]), r["note"]]
            print("| " + " | ".join(cells) + " |")
            tsv.write("\t".join(cells) + "\n")


if __name__ == "__main__":
    main()
