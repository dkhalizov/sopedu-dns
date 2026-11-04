//! Simulated-time replay of a recorded query log.
//!
//! Input is `bench/corpus/replay.tsv` from `tools/corpus_replay.py`. Each line
//! is replayed at its logged time on a virtual clock, so days of traffic
//! take seconds and TTLs expire exactly as they would have.
//!
//! What is production code and what is a model:
//! - Residency and eviction: the production `cache::Cache` (quick_cache
//!   S3-FIFO, byte weights from the real upstream wire answers). Every query
//!   does the same `get` the server does, every upstream answer is `insert`ed.
//! - Cacheability and lifetime: a second, unbounded production `Cache` decides
//!   whether an answer is stored and its `orig_ttl` (RFC 2308 SOA lifetime,
//!   negative clamps, zero-TTL rejection).
//! - Freshness, stale serving, prefetch, coalescing: modelled here on the
//!   virtual clock, because `Cache` reads `Instant::now()` and has no clock
//!   seam. The rules mirror `Runtime::lookup`/`prefetch_hit` in src/main.rs.
//! - Blocking: AdGuard Home's logged decision (flags column), not sopedu rules.
//! - Miss latency: a deterministic sample of AdGuard Home's own non-cached
//!   forwarded `Elapsed` values; a cache or local answer costs `HIT_US`.
//!
//! Prints aggregates only, never a name.
//!
//! ```sh
//! python3 -I tools/corpus_replay.py bench/corpus/querylog.json bench/corpus/replay.tsv
//! cargo run --release --locked --example replay -- bench/corpus/replay.tsv
//! ```

use std::{
    collections::HashMap,
    env,
    fs::File,
    io::{BufRead, BufReader},
    process::ExitCode,
    str::FromStr,
};

use hickory_proto::{op::Message, rr::RecordType};
use sopedu_dns::{cache::Cache, config::Config, wire};

/// End-to-end UDP hit on loopback, dnsperf `-q 1` p50 (dnsperf on loopback).
const HIT_US: u32 = 75;
const HOUR_MS: u64 = 3_600_000;
const NONE: u32 = u32::MAX;

struct Event {
    t: u64,
    key: u32,
    local: bool,
    /// The upstream answer this query would get: the latest non-cached answer
    /// for its key at or before `t`, else the key's first one.
    ans: u32,
}

struct Variant {
    name: &'static str,
    cache_size: usize,
    max_age_s: u64,
    prefetch: bool,
}

#[derive(Default, Clone)]
struct Slot {
    present: bool,
    stored: u64,
    ttl_ms: u64,
    negative: bool,
    /// Virtual completion time of the in-flight upstream request, 0 if none.
    until: u64,
    miss: bool,
    prefetch: bool,
    /// Lifetime the in-flight refresh will install.
    pending: Option<(u64, bool)>,
    /// Expiry of the entry a completed prefetch replaced, 0 if none.
    old_expiry: u64,
}

#[derive(Default)]
struct Stats {
    forwarded: u64,
    local: u64,
    fresh: u64,
    stale: u64,
    miss: u64,
    coalesced: u64,
    evicted: u64,
    prefetches: u64,
    prefetch_used: u64,
    stale_refreshes: u64,
    upstream: u64,
}

fn key_bytes(name: &str, qtype: u16) -> Option<Vec<u8>> {
    let mut raw = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    for label in name.split('.').filter(|label| !label.is_empty()) {
        raw.push(u8::try_from(label.len()).ok()?);
        raw.extend_from_slice(label.as_bytes());
    }
    raw.push(0);
    raw.extend_from_slice(&qtype.to_be_bytes());
    raw.extend_from_slice(&[0, 1]);
    let view = wire::parse_query(&raw)?;
    let mut buffer = [0u8; wire::MIN_CANONICAL_BUFFER];
    let len = wire::canonical_key(&view, &mut buffer)?;
    Some(buffer[..len].to_vec())
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

struct Corpus {
    keys: Vec<Vec<u8>>,
    events: Vec<Event>,
    answers: Vec<(Vec<u8>, Message)>,
    elapsed_us: Vec<u32>,
    agh_fwd_cached: u64,
}

fn load(path: &str) -> std::io::Result<Corpus> {
    let mut ids: HashMap<(String, u16), u32> = HashMap::new();
    let mut keys = Vec::new();
    let mut events = Vec::new();
    let mut answers = Vec::new();
    let mut elapsed_us = Vec::new();
    let mut agh_fwd_cached = 0;
    let mut latest: Vec<u32> = Vec::new();
    let mut first: Vec<u32> = Vec::new();
    let mut skipped = 0u64;
    for line in BufReader::new(File::open(path)?).lines() {
        let line = line?;
        let f: Vec<&str> = line.split('\t').collect();
        let parsed = (|| {
            let t: u64 = f.first()?.parse().ok()?;
            let qtype = u16::from(RecordType::from_str(f.get(2)?).ok()?);
            let flags: u8 = f.get(3)?.parse().ok()?;
            let cached = *f.get(6)? == "1";
            let elapsed: u32 = f.get(7)?.parse().ok()?;
            Some((t, f.get(1)?.to_string(), qtype, flags, cached, elapsed, *f.get(8)?))
        })();
        let Some((t, name, qtype, flags, cached, elapsed, hex)) = parsed else {
            skipped += 1;
            continue;
        };
        let id = match ids.get(&(name.clone(), qtype)) {
            Some(&id) => id,
            None => {
                let Some(key) = key_bytes(&name, qtype) else {
                    skipped += 1;
                    continue;
                };
                let id = keys.len() as u32;
                keys.push(key);
                latest.push(NONE);
                first.push(NONE);
                ids.insert((name, qtype), id);
                id
            }
        };
        let local = flags != 0;
        if !local && cached {
            agh_fwd_cached += 1;
        }
        if !local && !cached {
            elapsed_us.push(elapsed);
            if let Some(msg) = unhex(hex).and_then(|raw| Some((Message::from_vec(&raw).ok()?, raw))) {
                latest[id as usize] = answers.len() as u32;
                if first[id as usize] == NONE {
                    first[id as usize] = answers.len() as u32;
                }
                answers.push((msg.1, msg.0));
            }
        }
        events.push(Event { t, key: id, local, ans: latest[id as usize] });
    }
    for e in &mut events {
        if e.ans == NONE {
            e.ans = first[e.key as usize];
        }
    }
    events.sort_by_key(|e| e.t);
    eprintln!("replay: skipped {skipped} unparseable lines");
    Ok(Corpus { keys, events, answers, elapsed_us, agh_fwd_cached })
}

struct Rng(u64);

impl Rng {
    /// splitmix64: deterministic, so every variant sees the same latency draws.
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

fn pct(sorted: &[u32], p: f64) -> f64 {
    sorted[((sorted.len() - 1) as f64 * p).round() as usize] as f64 / 1000.0
}

fn run(c: &Corpus, life: &[Option<(u64, bool)>], v: &Variant, defaults: &Config) {
    let cache = Cache::new(v.cache_size, defaults.cache_bytes, defaults.negative_ttl_min, defaults.negative_ttl_max);
    let mut slots = vec![Slot::default(); c.keys.len()];
    let mut s = Stats::default();
    let mut rng = Rng(0x5eed);
    let t0 = c.events.first().map_or(0, |e| e.t);
    let mut hours = vec![0u64; (c.events.last().map_or(0, |e| e.t) - t0) as usize / HOUR_MS as usize + 1];
    let mut lat = Vec::with_capacity(c.events.len());
    let max_age_ms = v.max_age_s * 1000;

    for e in &c.events {
        if e.local {
            s.local += 1;
            lat.push(HIT_US);
            continue;
        }
        s.forwarded += 1;
        let key = &c.keys[e.key as usize];
        let slot = &mut slots[e.key as usize];
        let t = e.t;
        // Apply a completed upstream request.
        if slot.until != 0 && slot.until <= t {
            if let Some((ttl_ms, negative)) = slot.pending.take() {
                if slot.prefetch {
                    slot.old_expiry = slot.stored + slot.ttl_ms;
                }
                (slot.present, slot.stored, slot.ttl_ms, slot.negative) = (true, slot.until, ttl_ms, negative);
            }
            (slot.until, slot.miss, slot.prefetch) = (0, false, false);
        }
        if slot.until > t && slot.miss {
            s.coalesced += 1;
            lat.push(((slot.until - t) * 1000).min(u32::MAX as u64) as u32);
            continue;
        }
        if slot.present && cache.get(key, 0, u64::MAX).is_none() {
            slot.present = false;
            s.evicted += 1;
        }
        let mut upstream = |slot: &mut Slot, s: &mut Stats, hours: &mut Vec<u64>| -> u64 {
            s.upstream += 1;
            hours[((t - t0) / HOUR_MS) as usize] += 1;
            let l = u64::from(c.elapsed_us[(rng.next() % c.elapsed_us.len() as u64) as usize]);
            let until = t + l.div_ceil(1000).max(1);
            slot.until = until;
            slot.pending = None;
            if let (Some(lifetime), Some((raw, msg))) =
                (life.get(e.ans as usize).copied().flatten(), c.answers.get(e.ans as usize))
            {
                if cache.insert(key, raw, msg, 0) {
                    slot.pending = Some(lifetime);
                }
            }
            l
        };
        if slot.present {
            let age = t.saturating_sub(slot.stored);
            if age < slot.ttl_ms {
                s.fresh += 1;
                lat.push(HIT_US);
                if slot.old_expiry != 0 && t >= slot.old_expiry {
                    s.prefetch_used += 1;
                    slot.old_expiry = 0;
                }
                if v.prefetch && !slot.negative && (slot.ttl_ms - age) * 10 < slot.ttl_ms && slot.until == 0 {
                    s.prefetches += 1;
                    upstream(slot, &mut s, &mut hours);
                    slot.prefetch = true;
                }
                continue;
            }
            if age < max_age_ms {
                s.stale += 1;
                lat.push(HIT_US);
                if slot.until == 0 {
                    s.stale_refreshes += 1;
                    upstream(slot, &mut s, &mut hours);
                }
                continue;
            }
            slot.present = false;
        }
        if slot.until > t {
            // A refresh is already in flight for this key: single-flight
            // makes the miss wait for it instead of asking again.
            s.coalesced += 1;
            slot.miss = true;
            lat.push(((slot.until - t) * 1000).min(u32::MAX as u64) as u32);
            continue;
        }
        s.miss += 1;
        slot.old_expiry = 0;
        let l = upstream(slot, &mut s, &mut hours);
        slot.miss = true;
        lat.push(l.min(u32::MAX as u64) as u32);
    }

    lat.sort_unstable();
    let mut per_hour = hours.clone();
    per_hour.sort_unstable();
    let fwd = s.forwarded as f64;
    let hit = (s.fresh + s.stale) as f64 / fwd;
    let slow = lat.iter().filter(|&&l| l > 1000).count() as f64 / lat.len() as f64;
    println!(
        "| {} | {:.2}% | {:.2}% | {:.2}% | {:.2}% | {:.2}% | {} | {:.1} / {} / {} | {} / {} | {} | {} | {:.3} / {:.3} / {:.3} / {:.3} | {:.2}% |",
        v.name,
        hit * 100.0,
        s.fresh as f64 / fwd * 100.0,
        s.stale as f64 / fwd * 100.0,
        s.miss as f64 / fwd * 100.0,
        s.coalesced as f64 / fwd * 100.0,
        s.upstream,
        s.upstream as f64 / hours.len() as f64,
        per_hour[((per_hour.len() - 1) as f64 * 0.95).round() as usize],
        per_hour.last().copied().unwrap_or(0),
        s.prefetches,
        s.prefetch_used,
        s.stale_refreshes,
        s.evicted,
        pct(&lat, 0.50),
        pct(&lat, 0.90),
        pct(&lat, 0.99),
        pct(&lat, 0.999),
        slow * 100.0,
    );
}

fn main() -> ExitCode {
    let path = env::args().nth(1).unwrap_or_else(|| "bench/corpus/replay.tsv".into());
    let corpus = match load(&path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("replay: cannot read {path}: {e} (run tools/corpus_replay.py first)");
            return ExitCode::FAILURE;
        }
    };
    if corpus.elapsed_us.is_empty() || corpus.events.is_empty() {
        eprintln!("replay: no forwarded non-cached entries to sample miss latency from");
        return ExitCode::FAILURE;
    }
    let defaults = Config::default();
    // Production lifetime of each upstream answer, from an unbounded probe cache.
    let probe = Cache::new(1 << 20, 1 << 30, defaults.negative_ttl_min, defaults.negative_ttl_max);
    let mut key_of = vec![0u32; corpus.answers.len()];
    for e in &corpus.events {
        if e.ans != NONE {
            key_of[e.ans as usize] = e.key;
        }
    }
    let life: Vec<Option<(u64, bool)>> = corpus
        .answers
        .iter()
        .zip(&key_of)
        .map(|((raw, msg), &k)| {
            let key = &corpus.keys[k as usize];
            if !probe.insert(key, raw, msg, 0) {
                return None;
            }
            probe.get(key, 0, u64::MAX).map(|hit| (u64::from(hit.orig_ttl) * 1000, hit.negative))
        })
        .collect();

    let fwd = corpus.events.iter().filter(|e| !e.local).count() as u64;
    let span_h = (corpus.events.last().unwrap().t - corpus.events.first().unwrap().t) as f64 / HOUR_MS as f64;
    let agh_upstream = fwd - corpus.agh_fwd_cached;
    let mut elapsed = corpus.elapsed_us.clone();
    elapsed.sort_unstable();
    println!(
        "corpus: {} queries, {} forwarded, {} keys, {} upstream answers ({} cacheable), {:.1} h",
        corpus.events.len(),
        fwd,
        corpus.keys.len(),
        corpus.answers.len(),
        life.iter().flatten().count(),
        span_h
    );
    println!(
        "AdGuard Home as logged: forwarded hit ratio {:.2}%, {} upstream (logged), {:.1}/h; miss latency ms p50/p90/p99/p99.9 {:.3}/{:.3}/{:.3}/{:.3}",
        corpus.agh_fwd_cached as f64 / fwd as f64 * 100.0,
        agh_upstream,
        agh_upstream as f64 / span_h,
        pct(&elapsed, 0.5),
        pct(&elapsed, 0.9),
        pct(&elapsed, 0.99),
        pct(&elapsed, 0.999)
    );
    println!();
    println!("| variant | hit | fresh | stale | miss | coalesced | upstream | upstream/h mean / p95 / max | prefetch / used | stale refresh | evicted | latency ms p50 / p90 / p99 / p99.9 | >1 ms |");
    println!("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|");
    let max_age = defaults.optimistic_max_age.seconds().unwrap_or(43_200);
    for v in [
        Variant { name: "default", cache_size: defaults.cache_size, max_age_s: max_age, prefetch: true },
        Variant { name: "prefetch off", cache_size: defaults.cache_size, max_age_s: max_age, prefetch: false },
        Variant { name: "serve-stale off", cache_size: defaults.cache_size, max_age_s: 0, prefetch: true },
        Variant { name: "stale+prefetch off", cache_size: defaults.cache_size, max_age_s: 0, prefetch: false },
        Variant { name: "cache_size 1000", cache_size: 1000, max_age_s: max_age, prefetch: true },
    ] {
        run(&corpus, &life, &v, &defaults);
    }
    ExitCode::SUCCESS
}
