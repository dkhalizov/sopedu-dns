//! Aggregate-only cache policy probe.
//!
//! Compares a plain `HashMap` cache (count-limited, arbitrary eviction) with
//! three byte/count-limited candidates on the same key stream:
//!
//! - `quick_cache` 0.7 (S3-FIFO, sharded, borrowed `Equivalent` lookups)
//! - `moka` 0.12 sync (TinyLFU)
//! - `tinyufo` 0.9 (TinyLFU admission + S3-FIFO eviction)
//!
//! The real workload is replayed from the private, gitignored
//! `bench/corpus/queries.txt`; only aggregate counters are printed, never a
//! name. Without the corpus the synthetic Zipf workload still runs.
//!
//! ```sh
//! cargo run --release --locked --example cache_bench
//! cargo run --release --locked --example cache_bench -- /path/to/queries.txt
//! ```

use std::{
    cell::RefCell,
    collections::HashMap,
    fs,
    hint::black_box,
    sync::{Arc, Barrier, Mutex},
    thread,
    time::Instant,
};

use sopedu_dns::wire;

/// 200-byte response plus the 48-byte packed entry header.
const VALUE_BYTES: u64 = 248;
/// The live configuration's entry-count cap.
const ENTRY_CAP: usize = 10_000;
/// The live configuration's byte budget.
const BYTE_BUDGET: u64 = 4 * 1024 * 1024;
const ZIPF_NAMES: usize = 1_000_000;
const ZIPF_OPS: usize = 4_000_000;
const THREADS: usize = 4;

/// A weighted cache with a 4 MiB budget would otherwise exceed the 10,000
/// entry cap for small values; every candidate weights an entry at
/// `max(bytes, min_weight)` so both bounds apply to all of them.
fn min_weight() -> u64 {
    BYTE_BUDGET.div_ceil(ENTRY_CAP as u64)
}

type Value = Arc<Vec<u8>>;

fn value() -> Value {
    Arc::new(vec![0u8; VALUE_BYTES as usize])
}

fn wire_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.trim_end_matches('.').split('.').filter(|label| !label.is_empty()) {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

/// Builds the production canonical key through `wire::parse_query` and
/// `wire::canonical_key`, so the probe hashes exactly what the server hashes.
fn key_bytes(name: &str, qtype: u16) -> Option<Vec<u8>> {
    let mut raw = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    raw.extend_from_slice(&wire_name(name));
    raw.extend_from_slice(&qtype.to_be_bytes());
    raw.extend_from_slice(&[0, 1]);
    let view = wire::parse_query(&raw)?;
    let mut buffer = [0u8; wire::MIN_CANONICAL_BUFFER];
    let len = wire::canonical_key(&view, &mut buffer)?;
    Some(buffer[..len].to_vec())
}

fn qtype(name: &str) -> Option<u16> {
    Some(match name {
        "A" => 1,
        "NS" => 2,
        "CNAME" => 5,
        "SOA" => 6,
        "PTR" => 12,
        "MX" => 15,
        "TXT" => 16,
        "AAAA" => 28,
        "SRV" => 33,
        "NAPTR" => 35,
        "DS" => 43,
        "DNSKEY" => 48,
        "SVCB" => 64,
        "HTTPS" => 65,
        "ANY" => 255,
        _ => return None,
    })
}

/// The time-ordered private query stream. Returns `None` when the corpus is
/// absent; the caller reports that and keeps going.
fn real_stream(path: &str) -> Option<Vec<Vec<u8>>> {
    let text = fs::read_to_string(path).ok()?;
    let mut stream = Vec::new();
    let mut skipped = 0u64;
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let (Some(name), Some(record)) = (parts.next(), parts.next()) else {
            skipped += 1;
            continue;
        };
        let Some(qtype) = qtype(record) else {
            skipped += 1;
            continue;
        };
        match key_bytes(&name.to_ascii_lowercase(), qtype) {
            Some(key) => stream.push(key),
            None => skipped += 1,
        }
    }
    eprintln!("real stream: {} keys, {} lines skipped", stream.len(), skipped);
    Some(stream)
}

/// Zipf(1) rank sampling: for s = 1 the inverse CDF is `n^u`, a log-uniform
/// rank. Deterministic xorshift so every policy sees the same stream.
fn zipf_stream() -> (Vec<Vec<u8>>, Vec<u32>) {
    let keys: Vec<Vec<u8>> = (1..=ZIPF_NAMES).filter_map(|rank| key_bytes(&format!("z{rank}.test"), 1)).collect();
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let mut indices = Vec::with_capacity(ZIPF_OPS);
    while indices.len() < ZIPF_OPS {
        let uniform = (next() >> 11) as f64 / (1u64 << 53) as f64;
        let rank = (ZIPF_NAMES as f64).powf(uniform) as usize;
        indices.push(rank.min(ZIPF_NAMES - 1) as u32);
    }
    (keys, indices)
}

trait Policy: Send + Sync {
    fn name(&self) -> &'static str;
    fn get(&self, key: &[u8]) -> bool;
    fn insert(&self, key: &[u8]);
    fn entries(&self) -> u64;
    /// Approximate resident bytes: payload weight plus key and bookkeeping
    /// estimates. Labelled approximate in the report.
    fn approx_bytes(&self) -> u64;
}

struct Quick {
    cache: quick_cache::sync::Cache<Vec<u8>, Value, ByteWeighter>,
}

#[derive(Clone)]
struct ByteWeighter;

impl quick_cache::Weighter<Vec<u8>, Value> for ByteWeighter {
    fn weight(&self, key: &Vec<u8>, value: &Value) -> u64 {
        ((key.len() + value.len()) as u64).max(min_weight())
    }
}

impl Quick {
    fn new() -> Self {
        // Production uses quick_cache's default 97% hot allocation, which
        // keeps the cold probation and ghost queues of S3-FIFO busy.
        let options = quick_cache::OptionsBuilder::new()
            .estimated_items_capacity(ENTRY_CAP)
            .weight_capacity(BYTE_BUDGET)
            .build()
            .unwrap();
        Self {
            cache: quick_cache::sync::Cache::with_options(
                options,
                ByteWeighter,
                Default::default(),
                Default::default(),
            ),
        }
    }
}

impl Policy for Quick {
    fn name(&self) -> &'static str {
        "quick_cache_0.7"
    }
    fn get(&self, key: &[u8]) -> bool {
        self.cache.get(key).is_some()
    }
    fn insert(&self, key: &[u8]) {
        self.cache.insert(key.to_vec(), value());
    }
    fn entries(&self) -> u64 {
        self.cache.len() as u64
    }
    fn approx_bytes(&self) -> u64 {
        // Resident value (48-byte header + 200-byte response), a typical
        // canonical key and quick_cache's documented 21-byte entry overhead
        // (times 1.5 for its table slack).
        self.cache.len() as u64 * (VALUE_BYTES + 16 + 32)
    }
}

struct Moka {
    cache: moka::sync::Cache<Vec<u8>, Value, foldhash::fast::RandomState>,
}

impl Moka {
    fn new() -> Self {
        let cache = moka::sync::CacheBuilder::new(BYTE_BUDGET)
            .weigher(|key: &Vec<u8>, value: &Value| ((key.len() + value.len()) as u64).max(min_weight()) as u32)
            .build_with_hasher(foldhash::fast::RandomState::default());
        Self { cache }
    }
}

impl Policy for Moka {
    fn name(&self) -> &'static str {
        "moka_0.12"
    }
    fn get(&self, key: &[u8]) -> bool {
        self.cache.get(key).is_some()
    }
    fn insert(&self, key: &[u8]) {
        self.cache.insert(key.to_vec(), value());
    }
    fn entries(&self) -> u64 {
        self.cache.run_pending_tasks();
        self.cache.entry_count()
    }
    fn approx_bytes(&self) -> u64 {
        // Count capacity: value + typical key + moka's per-entry bookkeeping.
        self.entries() * (VALUE_BYTES + 16 + 64)
    }
}

thread_local! {
    static UFO_KEY: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

struct Ufo {
    cache: tinyufo::TinyUfo<Vec<u8>, Value>,
    entries: std::sync::atomic::AtomicU64,
}

impl Ufo {
    fn new() -> Self {
        // TinyUFO has no borrow-based lookup: the benchmark reuses a
        // thread-local key buffer, so it pays a copy per get but no allocation.
        Self {
            cache: tinyufo::TinyUfo::new(BYTE_BUDGET as usize, ENTRY_CAP),
            entries: std::sync::atomic::AtomicU64::new(0),
        }
    }
}

impl Policy for Ufo {
    fn name(&self) -> &'static str {
        "tinyufo_0.9"
    }
    fn get(&self, key: &[u8]) -> bool {
        UFO_KEY.with(|buffer| {
            let mut buffer = buffer.borrow_mut();
            buffer.clear();
            buffer.extend_from_slice(key);
            self.cache.get(&buffer).is_some()
        })
    }
    fn insert(&self, key: &[u8]) {
        use std::sync::atomic::Ordering::Relaxed;
        let weight = ((VALUE_BYTES + key.len() as u64).max(min_weight())) as u16;
        let evicted = self.cache.put(key.to_vec(), value(), weight);
        self.entries.fetch_add(1, Relaxed);
        if !evicted.is_empty() {
            self.entries.fetch_sub(evicted.len() as u64, Relaxed);
        }
    }
    fn entries(&self) -> u64 {
        self.entries.load(std::sync::atomic::Ordering::Relaxed)
    }
    fn approx_bytes(&self) -> u64 {
        // TinyUFO exposes no resident count; this is inserts minus returned
        // evictions, so treat the number as approximate.
        self.entries() * (VALUE_BYTES + 16 + 32)
    }
}

/// The naive baseline: one `Mutex<HashMap>`, a 10,000-entry cap,
/// and `keys().next()` as the eviction victim.
struct HashMapRef {
    map: Mutex<HashMap<Vec<u8>, Value>>,
}

impl HashMapRef {
    fn new() -> Self {
        Self { map: Mutex::new(HashMap::new()) }
    }
}

impl Policy for HashMapRef {
    fn name(&self) -> &'static str {
        "hashmap_poc"
    }
    fn get(&self, key: &[u8]) -> bool {
        self.map.lock().unwrap().contains_key(key)
    }
    fn insert(&self, key: &[u8]) {
        let mut map = self.map.lock().unwrap();
        if !map.contains_key(key) && map.len() >= ENTRY_CAP {
            if let Some(victim) = map.keys().next().cloned() {
                map.remove(&victim);
            }
        }
        map.insert(key.to_vec(), value());
    }
    fn entries(&self) -> u64 {
        self.map.lock().unwrap().len() as u64
    }
    fn approx_bytes(&self) -> u64 {
        let map = self.map.lock().unwrap();
        let heap = map.keys().map(|key| key.len() as u64 + 24 + VALUE_BYTES).sum::<u64>();
        heap + map.capacity() as u64 * (24 + 8 + 8)
    }
}

struct Stats {
    hits: u64,
    ops: u64,
    ns_per_op: f64,
    entries: u64,
    bytes: u64,
}

fn replay_stream(policy: &dyn Policy, stream: &[Vec<u8>]) {
    for key in stream {
        if !policy.get(key) {
            policy.insert(key);
        }
    }
}

fn measure_stream(policy: &dyn Policy, stream: &[Vec<u8>]) -> Stats {
    let start = Instant::now();
    let mut hits = 0u64;
    for key in stream {
        if policy.get(black_box(key.as_slice())) {
            hits += 1;
        } else {
            policy.insert(key);
        }
    }
    let elapsed = start.elapsed().as_nanos() as f64;
    Stats {
        hits,
        ops: stream.len() as u64,
        ns_per_op: elapsed / stream.len() as f64,
        entries: policy.entries(),
        bytes: policy.approx_bytes(),
    }
}

fn measure_zipf(policy: &dyn Policy, keys: &[Vec<u8>], indices: &[u32]) -> Stats {
    let start = Instant::now();
    let mut hits = 0u64;
    for &index in indices {
        let key = keys[index as usize].as_slice();
        if policy.get(black_box(key)) {
            hits += 1;
        } else {
            policy.insert(key);
        }
    }
    let elapsed = start.elapsed().as_nanos() as f64;
    Stats {
        hits,
        ops: indices.len() as u64,
        ns_per_op: elapsed / indices.len() as f64,
        entries: policy.entries(),
        bytes: policy.approx_bytes(),
    }
}

fn measure_threads(policy: &dyn Policy, stream: &[Vec<u8>]) -> Stats {
    replay_stream(policy, stream);
    let barrier = Arc::new(Barrier::new(THREADS));
    let start = Instant::now();
    let hits: u64 = thread::scope(|scope| {
        let mut handles = Vec::new();
        for _ in 0..THREADS {
            let barrier = barrier.clone();
            handles.push(scope.spawn(move || {
                barrier.wait();
                let mut hits = 0u64;
                for key in stream {
                    if policy.get(black_box(key.as_slice())) {
                        hits += 1;
                    } else {
                        policy.insert(key);
                    }
                }
                hits
            }));
        }
        handles.into_iter().map(|handle| handle.join().unwrap()).sum()
    });
    let elapsed = start.elapsed().as_nanos() as f64;
    let ops = stream.len() as u64 * THREADS as u64;
    Stats { hits, ops, ns_per_op: elapsed / ops as f64, entries: policy.entries(), bytes: policy.approx_bytes() }
}

fn print_row(workload: &str, stats: &Stats) {
    println!(
        "{workload:<6} hits={:<10} misses={:<10} ops={:<10} hit_rate={:.4} ns_per_op={:.1} entries={:<6} approx_bytes={}",
        stats.hits,
        stats.ops - stats.hits,
        stats.ops,
        stats.hits as f64 / stats.ops as f64,
        stats.ns_per_op,
        stats.entries,
        stats.bytes
    );
}

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| "bench/corpus/queries.txt".into());
    let policies: Vec<Box<dyn Policy>> =
        vec![Box::new(HashMapRef::new()), Box::new(Quick::new()), Box::new(Moka::new()), Box::new(Ufo::new())];

    let real = real_stream(&path).filter(|stream| !stream.is_empty());
    for policy in &policies {
        println!("policy={} entry_cap={ENTRY_CAP} byte_budget={BYTE_BUDGET} value_bytes={VALUE_BYTES}", policy.name());
        match &real {
            Some(stream) => {
                print_row("real", &measure_stream(policy.as_ref(), stream));
                print_row("conc4", &measure_threads(policy.as_ref(), stream));
            }
            None => println!("real   skipped (corpus not found at {path})"),
        }
    }

    let (keys, indices) = zipf_stream();
    for policy in &policies {
        println!("policy={} workload=zipf", policy.name());
        print_row("zipf", &measure_zipf(policy.as_ref(), &keys, &indices));
    }
}
