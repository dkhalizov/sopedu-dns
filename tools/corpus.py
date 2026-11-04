#!/usr/bin/env python3
"""Convert an AdGuard Home querylog.json (JSONL) into benchmark corpora.

All outputs contain private browsing data and belong under bench/corpus/
(gitignored). Only aggregate counts are printed.

Usage: python3 -I tools/corpus.py bench/corpus/querylog.json bench/corpus
"""
import json
import os
import sys
from collections import Counter
from datetime import datetime


def qtype(value):
    return value if value else "A"


def epoch_ms(value):
    if not value:
        return 0
    try:
        return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp() * 1000)
    except ValueError:
        return 0


def main(src, outdir):
    # Private browsing data: owner-only directory and files.
    os.makedirs(outdir, mode=0o700, exist_ok=True)
    os.chmod(outdir, 0o700)
    os.umask(0o077)
    unique = {}
    qtypes = Counter()
    reasons = Counter()
    is_filtered = Counter()
    cached = 0
    elapsed = []
    first_ts = last_ts = None
    total = 0
    with open(src, encoding="utf-8") as f, \
            open(os.path.join(outdir, "queries.txt"), "w", encoding="utf-8") as stream, \
            open(os.path.join(outdir, "timeline.tsv"), "w", encoding="utf-8") as timeline, \
            open(os.path.join(outdir, "unique.txt"), "w", encoding="utf-8") as uniq:
        for line in f:
            line = line.strip()
            if not line:
                continue
            o = json.loads(line)
            name = o["QH"].rstrip(".").lower()
            if not name:
                continue
            typ = qtype(o.get("QT"))
            total += 1
            stream.write(f"{name} {typ}\n")
            ts = o.get("T")
            ts_ms = epoch_ms(ts)
            result = o.get("Result") or {}
            blocked = bool(result.get("IsFiltered"))
            timeline.write(f"{ts_ms}\t{name}\t{typ}\t{int(blocked)}\n")
            counts = unique.get(name)
            if counts is None:
                counts = unique[name] = [0, 0]
                uniq.write(name + "\n")
            rules = result.get("Rules") or []
            counts[1 if blocked else 0] += 1
            qtypes[typ] += 1
            if result:
                reasons[result.get("Reason")] += 1
            is_filtered[bool(result.get("IsFiltered"))] += 1
            for rule in rules:
                if rule.get("FilterListID") is not None:
                    reasons[("list", rule["FilterListID"])] += 1
            if o.get("Cached"):
                cached += 1
            if isinstance(o.get("Elapsed"), int):
                elapsed.append(o["Elapsed"])
            if ts:
                if first_ts is None or ts < first_ts:
                    first_ts = ts
                if last_ts is None or ts > last_ts:
                    last_ts = ts
    with open(os.path.join(outdir, "parity.tsv"), "w", encoding="utf-8") as f:
        for name, (allowed, blocked) in unique.items():
            f.write(f"{name}\t{blocked}\t{allowed}\n")

    def pct(values, p):
        if not values:
            return None
        values = sorted(values)
        return values[min(len(values) - 1, int(len(values) * p))]

    stats = {
        "queries": total,
        "unique_names": len(unique),
        "cache_hits": cached,
        "qtypes": dict(qtypes),
        "result_present": sum(is_filtered.values()),
        "is_filtered": {str(k): v for k, v in is_filtered.items()},
        "reasons": {str(k): v for k, v in reasons.items()},
        "elapsed_ms_p50": pct(elapsed, 0.50),
        "elapsed_ms_p95": pct(elapsed, 0.95),
        "elapsed_ms_p99": pct(elapsed, 0.99),
        "first_ts": first_ts,
        "last_ts": last_ts,
    }
    with open(os.path.join(outdir, "stats.json"), "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2, sort_keys=True)
    for name in ("queries.txt", "timeline.tsv", "unique.txt", "parity.tsv", "stats.json"):
        os.chmod(os.path.join(outdir, name), 0o600)
    print(json.dumps({k: v for k, v in stats.items() if k != "reasons"}, sort_keys=True))
    print("reason_counts", dict(reasons))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    main(sys.argv[1], sys.argv[2])
