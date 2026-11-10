//! Query log ring, top-N sketches and per-minute snapshots for the UI.
//!
//! **Hot path.** [`record`] writes one fixed-size entry into a per-thread-shard
//! ring: one thread-local read, one `fetch_add` on a shard head only that
//! thread normally touches, and fourteen relaxed stores. No lock, no
//! allocation, no shared cache line between workers. Slots are arrays of
//! atomics guarded by a sequence word (a seqlock), so readers detect a torn or
//! overwritten slot and skip it; there is no `unsafe`.
//!
//! **Cold path.** A drain task (every [`TICK`]) reads the new entries of every
//! shard, feeds three Space-Saving sketches (domains, blocked domains, clients)
//! and keeps a per-minute ring of counter snapshots for the dashboard windows.
//! Everything the UI shows is read here, never on the DNS path. Under a load
//! where a shard wraps faster than the drain interval the sketches see only
//! the surviving entries (a systematic sample), and `lost` counts the rest.
//!
//! **Entry.** 112 bytes: time (us since start), client, the lowercase wire
//! qname truncated to [`NAME_BYTES`], qtype, result, upstream index, total
//! latency in us and the list id that blocked it. The full name is copied on
//! the inline UDP hit as well: one 64-byte copy, measured in
//! `benches/micro.rs` (`query_log_record`). Longer names keep a prefix and
//! are marked truncated; the UI shows them with an ellipsis and offers no
//! copy-rule action for them. The matcher stores hashes, not rule text, so
//! the origin of a block is the list id (0 = inline user rules).

use crate::{
    clock::Instant,
    rules,
    stats::{self, Outcome, Snapshot, BUCKETS},
    wire,
};
use foldhash::fast::RandomState;
use std::{
    borrow::Cow,
    cell::Cell,
    collections::{BTreeSet, HashMap, VecDeque},
    fmt::Write,
    future::Future,
    net::{IpAddr, Ipv6Addr},
    sync::{
        atomic::{fence, AtomicU64, Ordering::*},
        Mutex, MutexGuard, OnceLock,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// Bytes of wire qname kept per entry.
pub const NAME_BYTES: usize = 64;
const NAME_WORDS: usize = NAME_BYTES / 8;
const WORDS: usize = 5 + NAME_WORDS;
/// List id of a block whose origin is a CNAME/DNAME target in the upstream
/// answer, not a rule that matched the queried name. Never a real list id.
pub const CNAME_TARGET: u16 = u16::MAX;
/// `upstream` of an entry that no upstream answered (cache, local, blocked).
pub const NO_UPSTREAM: u8 = 255;
/// `upstream` of an answer from the plain fallback servers.
pub const PLAIN_UPSTREAM: u8 = 254;
/// Drain interval; also the live-tail cadence.
pub const TICK: Duration = Duration::from_millis(500);
/// Top-N width (Space-Saving k).
pub const TOP_K: usize = 100;
/// Per-minute snapshots kept: 24 hours plus the starting point.
pub const MINUTES: usize = 24 * 60 + 1;
const RECENT: usize = 21;

/// One logged query, decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Completion time, microseconds since the log started.
    pub t_us: u64,
    pub ip: IpAddr,
    pub qtype: u16,
    pub outcome: Outcome,
    pub upstream: u8,
    pub latency_us: u32,
    /// Blocking list id (0 = user rules); `None` unless the query was blocked.
    pub list: Option<u16>,
    pub truncated: bool,
    name_len: u8,
    name: [u8; NAME_BYTES],
}

/// What the hot path knows about a finished query.
pub struct Record<'a> {
    pub ip: IpAddr,
    /// Lowercase wire qname.
    pub qname: &'a [u8],
    pub qtype: u16,
    pub outcome: Outcome,
    pub upstream: u8,
    pub list: Option<u16>,
}

impl Entry {
    pub fn name(&self) -> &[u8] {
        &self.name[..usize::from(self.name_len)]
    }

    /// Presentation-format name, ready for display (still needs HTML/JSON
    /// escaping): dots inside labels and non-printable bytes are escaped.
    pub fn text(&self) -> String {
        name_text(self.name(), self.truncated)
    }

    /// The domain a "copy rule" action may name: whole, without escapes.
    pub fn rule_domain(&self) -> Option<String> {
        let text = self.text();
        (!self.truncated && text != "." && !text.contains('\\')).then_some(text)
    }
}

fn pack(t_us: u64, q: &Record<'_>, latency_us: u32) -> [u64; WORDS] {
    let mut words = [0u64; WORDS];
    let ip = match q.ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    };
    let ip = u128::from(ip);
    let n = q.qname.len().min(NAME_BYTES);
    let mut name = [0u8; NAME_BYTES];
    name[..n].copy_from_slice(&q.qname[..n]);
    words[0] = t_us;
    words[1] = (ip >> 64) as u64;
    words[2] = ip as u64;
    words[3] = u64::from(q.qtype)
        | u64::from(q.outcome as u8) << 16
        | u64::from(q.upstream) << 24
        | u64::from(latency_us) << 32;
    let list = q.list.map_or(0, |list| u64::from(list) + 1);
    words[4] = list | (n as u64) << 32 | u64::from(q.qname.len() > NAME_BYTES) << 40;
    for (word, chunk) in words[5..].iter_mut().zip(name.as_chunks::<8>().0) {
        *word = u64::from_le_bytes(*chunk);
    }
    words
}

fn unpack(words: &[u64; WORDS]) -> Entry {
    let ip = Ipv6Addr::from(u128::from(words[1]) << 64 | u128::from(words[2]));
    let ip = ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4);
    let mut name = [0u8; NAME_BYTES];
    for (chunk, word) in name.as_chunks_mut::<8>().0.iter_mut().zip(&words[5..]) {
        *chunk = word.to_le_bytes();
    }
    let list = (words[4] & 0xffff_ffff) as u32;
    Entry {
        t_us: words[0],
        ip,
        qtype: words[3] as u16,
        outcome: Outcome::ALL.get(usize::from((words[3] >> 16) as u8)).copied().unwrap_or(Outcome::Other),
        upstream: (words[3] >> 24) as u8,
        latency_us: (words[3] >> 32) as u32,
        list: (list != 0).then(|| u16::try_from(list - 1).unwrap_or(u16::MAX)),
        truncated: words[4] >> 40 & 1 == 1,
        name_len: ((words[4] >> 32) as u8).min(NAME_BYTES as u8),
        name,
    }
}

/// One ring slot: the payload words and the sequence word that says which
/// position last finished writing them (`2 * pos + 2`; odd while writing).
struct Slot {
    seq: AtomicU64,
    words: [AtomicU64; WORDS],
}

impl Slot {
    fn new() -> Self {
        Self { seq: AtomicU64::new(0), words: [const { AtomicU64::new(0) }; WORDS] }
    }
}

/// A ring written by (normally) one thread. Aligned so heads of different
/// shards never share a cache line.
#[repr(align(128))]
struct Shard {
    head: AtomicU64,
    slots: Box<[Slot]>,
}

enum Read {
    Entry(Entry),
    /// The writer claimed this position but has not finished; retry later.
    NotReady,
    /// Overwritten, or torn while reading.
    Lost,
}

/// Where a reader stopped in every shard.
pub struct Cursor(Vec<u64>);

/// Query filter from the UI's query string. Empty or unknown values match all.
#[derive(Default, Debug, Clone)]
pub struct Filter {
    client: String,
    name: String,
    result: Option<Outcome>,
    qtype: Option<u16>,
}

impl Filter {
    /// `client`, `q` (domain substring), `result` and `qtype` parameters.
    pub fn from_query(query: &str) -> Self {
        let get = |key| param(query, key).unwrap_or_default();
        Self {
            client: get("client").trim().to_string(),
            name: get("q").trim().to_ascii_lowercase(),
            result: Outcome::ALL.into_iter().find(|o| o.label() == get("result")),
            qtype: qtype_from_name(get("qtype").trim()),
        }
    }

    pub fn matches(&self, e: &Entry) -> bool {
        self.result.is_none_or(|r| r == e.outcome)
            && self.qtype.is_none_or(|t| t == e.qtype)
            && (self.client.is_empty() || e.ip.to_string().contains(&self.client))
            && (self.name.is_empty() || e.text().contains(&self.name))
    }
}

/// The value of `key` in a query string, percent-decoded (`+` is a space).
pub fn param(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        (k == key).then(|| percent_decode(v))
    })
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = |b: u8| char::from(b).to_digit(16);
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() && hex(bytes[i + 1]).is_some() && hex(bytes[i + 2]).is_some() => {
                out.push((hex(bytes[i + 1]).unwrap_or(0) * 16 + hex(bytes[i + 2]).unwrap_or(0)) as u8);
                i += 2;
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

const QTYPES: [(&str, u16); 18] = [
    ("A", 1),
    ("NS", 2),
    ("CNAME", 5),
    ("SOA", 6),
    ("PTR", 12),
    ("MX", 15),
    ("TXT", 16),
    ("AAAA", 28),
    ("SRV", 33),
    ("NAPTR", 35),
    ("DS", 43),
    ("RRSIG", 46),
    ("DNSKEY", 48),
    ("SVCB", 64),
    ("HTTPS", 65),
    ("CAA", 257),
    ("ANY", 255),
    ("AXFR", 252),
];

pub fn qtype_name(qtype: u16) -> Cow<'static, str> {
    match QTYPES.iter().find(|(_, n)| *n == qtype) {
        Some((name, _)) => Cow::Borrowed(name),
        None => Cow::Owned(format!("TYPE{qtype}")),
    }
}

fn qtype_from_name(name: &str) -> Option<u16> {
    let upper = name.to_ascii_uppercase();
    QTYPES
        .iter()
        .find(|(n, _)| *n == upper)
        .map(|(_, n)| *n)
        .or_else(|| upper.strip_prefix("TYPE").unwrap_or(&upper).parse().ok())
}

/// Wire qname to presentation text. A name cut at [`NAME_BYTES`] ends in an
/// ellipsis. Bytes outside `0x21..=0x7e`, dots inside a label and backslashes
/// are escaped (RFC 4343), so the result is one unambiguous line; it can still
/// hold `<`, `&` and quotes, which the HTML and JSON writers escape.
pub fn name_text(name: &[u8], truncated: bool) -> String {
    let mut out = String::new();
    let mut at = 0;
    let mut cut = truncated;
    while let Some(&len) = name.get(at) {
        let len = usize::from(len);
        if len == 0 || len > 63 {
            break;
        }
        at += 1;
        let end = at + len;
        if !out.is_empty() {
            out.push('.');
        }
        for &b in &name[at..end.min(name.len())] {
            match b {
                b'.' | b'\\' => {
                    out.push('\\');
                    out.push(char::from(b));
                }
                0x21..=0x7e => out.push(char::from(b)),
                _ => {
                    let _ = write!(out, "\\{b:03}");
                }
            }
        }
        if end > name.len() {
            cut = true;
            break;
        }
        at = end;
    }
    if out.is_empty() && !cut {
        return ".".to_string();
    }
    if cut {
        out.push('…');
    }
    out
}

// ---------------------------------------------------------------- sketches

/// One Space-Saving counter: the true count is in `count - err ..= count`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Top {
    pub key: Box<[u8]>,
    pub count: u64,
    pub err: u64,
}

/// Space-Saving heavy hitters (Metwally et al.) with a fixed number of
/// counters. A key already tracked is incremented; otherwise it evicts the
/// smallest counter and inherits its count as error.
/// `order` keeps (count, slot) sorted, so finding the smallest counter is
/// O(log k) instead of a scan over all k (`prewarm_count` is up to 10000, and
/// with a large working set nearly every add evicts). The drain runs on the
/// runtime thread, so a scan there delayed cache hits.
/// The index keys are client-chosen names, so the hasher must be seeded
/// per process (foldhash's `RandomState` is), not a fixed one.
pub struct SpaceSaving {
    cap: usize,
    items: Vec<Top>,
    index: HashMap<Box<[u8]>, usize, RandomState>,
    order: BTreeSet<(u64, usize)>,
}

impl SpaceSaving {
    pub fn new(cap: usize) -> Self {
        Self {
            cap,
            items: Vec::with_capacity(cap),
            index: HashMap::with_capacity_and_hasher(cap, RandomState::default()),
            order: BTreeSet::new(),
        }
    }

    pub fn add(&mut self, key: &[u8]) {
        if let Some(&i) = self.index.get(key) {
            let count = &mut self.items[i].count;
            self.order.remove(&(*count, i));
            *count += 1;
            self.order.insert((*count, i));
        } else if self.items.len() < self.cap {
            let i = self.items.len();
            self.index.insert(key.into(), i);
            self.items.push(Top { key: key.into(), count: 1, err: 0 });
            self.order.insert((1, i));
        } else if let Some((min, i)) = self.order.pop_first() {
            self.index.remove(&self.items[i].key);
            self.items[i] = Top { key: key.into(), count: min + 1, err: min };
            self.index.insert(key.into(), i);
            self.order.insert((min + 1, i));
        }
    }

    /// Replaces the counters with saved ones (a restart). Duplicate keys and
    /// anything past the capacity are dropped.
    pub fn restore(&mut self, items: Vec<Top>) {
        self.items.clear();
        self.index.clear();
        self.order.clear();
        for item in items.into_iter().take(self.cap) {
            if !self.index.contains_key(&item.key) {
                self.index.insert(item.key.clone(), self.items.len());
                self.order.insert((item.count, self.items.len()));
                self.items.push(item);
            }
        }
    }

    /// The `n` largest counters, biggest first.
    pub fn top(&self, n: usize) -> Vec<Top> {
        let mut items = self.items.clone();
        items.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.key.cmp(&b.key)));
        items.truncate(n);
        items
    }
}

struct Tops {
    domains: SpaceSaving,
    blocked: SpaceSaving,
    clients: SpaceSaving,
    /// Pre-warm candidates: wire names (no flag byte) of A/AAAA queries that
    /// were cached or forwarded. Sized by [`QueryLog::track_names`].
    names: SpaceSaving,
}

impl Tops {
    fn new() -> Self {
        Self {
            domains: SpaceSaving::new(TOP_K),
            blocked: SpaceSaving::new(TOP_K),
            clients: SpaceSaving::new(TOP_K),
            names: SpaceSaving::new(0),
        }
    }

    fn add(&mut self, e: &Entry) {
        // Key: the stored name plus one byte for "truncated".
        let mut key = [0u8; NAME_BYTES + 1];
        let name = e.name();
        key[..name.len()].copy_from_slice(name);
        key[name.len()] = u8::from(e.truncated);
        let key = &key[..=name.len()];
        if e.outcome == Outcome::Blocked {
            self.blocked.add(key);
        } else {
            self.domains.add(key);
        }
        self.clients.add(&client_key(e.ip));
        // Blocked, local, special-use and failed names are never pre-warmed;
        // a cut name cannot be resolved.
        if matches!(e.outcome, Outcome::Cache | Outcome::Stale | Outcome::Upstream)
            && matches!(e.qtype, 1 | 28)
            && !e.truncated
        {
            self.names.add(e.name());
        }
    }
}

/// The 16-byte key of a client address (IPv4 is v4-mapped).
pub fn client_key(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

/// Text of a sketch key for a domain (last byte is the truncated flag).
pub fn key_domain(key: &[u8]) -> String {
    match key.split_last() {
        Some((&flag, name)) => name_text(name, flag == 1),
        None => ".".to_string(),
    }
}

/// Text of a client sketch key.
pub fn key_client(key: &[u8]) -> String {
    <[u8; 16]>::try_from(key).map_or_else(
        |_| "?".to_string(),
        |octets| {
            let ip = Ipv6Addr::from(octets);
            ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4).to_string()
        },
    )
}

// --------------------------------------------------------------- snapshots

/// The part of a counter snapshot a window needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lite {
    /// Unix time in milliseconds, so a snapshot saved before a restart still
    /// orders correctly against the new ones.
    pub at_ms: u64,
    pub outcomes: [u64; 8],
    pub buckets: [u64; BUCKETS],
    pub sum_us: u64,
}

impl Lite {
    pub fn new(at_ms: u64, snap: &Snapshot) -> Self {
        Self { at_ms, outcomes: snap.outcomes, buckets: snap.request.buckets, sum_us: snap.request.sum_us }
    }

    fn total(&self) -> u64 {
        self.outcomes.iter().sum()
    }
}

/// The difference between two snapshots: one reporting window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Window {
    /// Time actually covered; shorter than asked until enough history exists.
    pub span_ms: u64,
    pub outcomes: [u64; 8],
    pub buckets: [u64; BUCKETS],
}

impl Window {
    pub fn total(&self) -> u64 {
        self.outcomes.iter().sum()
    }

    pub fn count(&self, outcome: Outcome) -> u64 {
        self.outcomes[outcome as usize]
    }

    pub fn qps(&self) -> f64 {
        if self.span_ms == 0 {
            0.0
        } else {
            self.total() as f64 * 1000.0 / self.span_ms as f64
        }
    }

    /// Upper bound of the log2 bucket holding quantile `q` of request
    /// latency, in microseconds (resolution is a factor of two). `None` when
    /// no request was timed.
    pub fn percentile_us(&self, q: f64) -> Option<u64> {
        let count: u64 = self.buckets.iter().sum();
        if count == 0 {
            return None;
        }
        let target = ((count as f64 * q).ceil() as u64).clamp(1, count);
        let mut seen = 0;
        for (i, n) in self.buckets.iter().enumerate() {
            seen += n;
            if seen >= target {
                return Some(1u64 << i.min(BUCKETS - 1));
            }
        }
        None
    }
}

/// Per-minute cumulative snapshots covering the last 24 hours. At 280 bytes
/// each this is about 400 KB, fixed.
pub struct Minutes {
    ring: VecDeque<Lite>,
}

impl Minutes {
    pub fn new() -> Self {
        Self { ring: VecDeque::with_capacity(MINUTES) }
    }

    /// Stores `lite` when a minute passed since the last one (or none yet).
    pub fn push_if_due(&mut self, lite: Lite) {
        if self.ring.back().is_none_or(|last| lite.at_ms >= last.at_ms + 60_000) {
            if self.ring.len() == MINUTES {
                self.ring.pop_front();
            }
            self.ring.push_back(lite);
        }
    }

    /// The change from the newest snapshot at least `span_ms` old (or the
    /// oldest one) to `now`.
    pub fn window(&self, now: &Lite, span_ms: u64) -> Window {
        let base = self.ring.iter().rev().find(|s| s.at_ms + span_ms <= now.at_ms).or(self.ring.front());
        let Some(base) = base else {
            return Window { span_ms: 0, outcomes: [0; 8], buckets: [0; BUCKETS] };
        };
        let mut window =
            Window { span_ms: now.at_ms.saturating_sub(base.at_ms), outcomes: [0; 8], buckets: [0; BUCKETS] };
        for (w, (a, b)) in window.outcomes.iter_mut().zip(now.outcomes.iter().zip(&base.outcomes)) {
            *w = a.saturating_sub(*b);
        }
        for (w, (a, b)) in window.buckets.iter_mut().zip(now.buckets.iter().zip(&base.buckets)) {
            *w = a.saturating_sub(*b);
        }
        window
    }
}

impl Default for Minutes {
    fn default() -> Self {
        Self::new()
    }
}

// ----------------------------------------------------------------- the log

struct Drain {
    cursor: Cursor,
    tops: Tops,
    minutes: Minutes,
    /// `(ms, total queries)` once per tick; the oldest gives the current qps.
    recent: VecDeque<(u64, u64)>,
    lost: u64,
    seen: u64,
    /// Unix ms from which the sketches and all-time counters count. A restore
    /// moves it back to the first start whose data was carried over.
    since_ms: u64,
}

/// What the dashboard reads in one lock.
pub struct Board {
    pub qps: f64,
    pub w5m: Window,
    pub w24h: Window,
    pub domains: Vec<Top>,
    pub blocked: Vec<Top>,
    pub clients: Vec<Top>,
    pub capacity: usize,
    pub seen: u64,
    pub lost: u64,
    /// Unix ms from which the top lists and the all-time counters count.
    pub since_ms: u64,
}

/// The parts of the log that survive a restart (the entry ring does not).
pub struct Kept {
    pub since_ms: u64,
    pub minutes: Vec<Lite>,
    pub domains: Vec<Top>,
    pub blocked: Vec<Top>,
    pub clients: Vec<Top>,
}

pub struct QueryLog {
    base: Instant,
    wall_ms: u64,
    per: u32,
    mask: usize,
    shards: Box<[Shard]>,
    drain: Mutex<Drain>,
}

fn idx(pos: u64, per: u32) -> usize {
    // u32 modulo is cheaper than u64; the reader uses the same mapping.
    (pos as u32 % per) as usize
}

impl QueryLog {
    /// `capacity` 0 disables the log (the sketches and windows still run).
    pub fn new(capacity: usize) -> Self {
        let cores = std::thread::available_parallelism().map_or(1, usize::from).min(16);
        Self::with_shards(capacity, cores.next_power_of_two())
    }

    /// `shards` must be a power of two.
    pub fn with_shards(capacity: usize, mut shards: usize) -> Self {
        while shards > capacity.max(1) {
            shards /= 2;
        }
        let per = if capacity == 0 { 0 } else { capacity.div_ceil(shards) };
        let shards_vec: Box<[Shard]> = if per == 0 {
            Box::new([])
        } else {
            (0..shards)
                .map(|_| Shard { head: AtomicU64::new(0), slots: (0..per).map(|_| Slot::new()).collect() })
                .collect()
        };
        let wall_ms = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64);
        let log = Self {
            base: Instant::now(),
            wall_ms,
            per: u32::try_from(per).unwrap_or(u32::MAX),
            mask: shards.saturating_sub(1),
            drain: Mutex::new(Drain {
                cursor: Cursor(vec![0; shards_vec.len()]),
                tops: Tops::new(),
                minutes: Minutes::new(),
                recent: VecDeque::with_capacity(RECENT),
                lost: 0,
                seen: 0,
                since_ms: wall_ms,
            }),
            shards: shards_vec,
        };
        // History starts at zero so the first window covers everything.
        log.state().minutes.push_if_due(Lite { at_ms: wall_ms, outcomes: [0; 8], buckets: [0; BUCKETS], sum_us: 0 });
        log
    }

    /// Entries the ring holds (a multiple of the shard count).
    pub fn capacity(&self) -> usize {
        self.shards.len() * self.per as usize
    }

    pub fn enabled(&self) -> bool {
        !self.shards.is_empty()
    }

    fn state(&self) -> MutexGuard<'_, Drain> {
        self.drain.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn since_base_us(&self, at: Instant) -> u64 {
        u64::try_from(at.saturating_duration_since(self.base).as_micros()).unwrap_or(u64::MAX)
    }

    /// Unix milliseconds of an entry.
    pub fn unix_ms(&self, e: &Entry) -> u64 {
        self.wall_ms + e.t_us / 1000
    }

    /// Writes one entry. `started` plus `latency` is the completion time, so
    /// no extra clock read is needed.
    pub fn write(&self, started: Instant, latency: Duration, q: &Record<'_>) {
        let Some(shard) = self.shards.get(stats::slot() & self.mask) else { return };
        let latency_us = u32::try_from(latency.as_micros()).unwrap_or(u32::MAX);
        let words = pack(self.since_base_us(started).saturating_add(latency_us.into()), q, latency_us);
        let pos = shard.head.fetch_add(1, Relaxed);
        let slot = &shard.slots[idx(pos, self.per)];
        slot.seq.store(2 * pos + 1, Relaxed);
        fence(Release);
        for (cell, word) in slot.words.iter().zip(words) {
            cell.store(word, Relaxed);
        }
        slot.seq.store(2 * pos + 2, Release);
    }

    fn read(&self, shard: &Shard, pos: u64) -> Read {
        let slot = &shard.slots[idx(pos, self.per)];
        let want = 2 * pos + 2;
        let first = slot.seq.load(Acquire);
        if first != want {
            return if first < want { Read::NotReady } else { Read::Lost };
        }
        let mut words = [0u64; WORDS];
        for (word, cell) in words.iter_mut().zip(&slot.words) {
            *word = cell.load(Relaxed);
        }
        fence(Acquire);
        if slot.seq.load(Relaxed) == first {
            Read::Entry(unpack(&words))
        } else {
            Read::Lost
        }
    }

    /// A cursor at the current heads: only later entries are returned.
    pub fn cursor(&self) -> Cursor {
        Cursor(self.shards.iter().map(|s| s.head.load(Acquire)).collect())
    }

    /// Appends the entries written since `cursor` (shard by shard, not time
    /// ordered) and returns how many were overwritten before being read.
    pub fn read_new(&self, cursor: &mut Cursor, out: &mut Vec<Entry>) -> u64 {
        self.read_new_up_to(cursor, out, usize::MAX)
    }

    /// [`QueryLog::read_new`] that stops once `out` holds `limit` entries;
    /// the cursor keeps the rest for the next call.
    fn read_new_up_to(&self, cursor: &mut Cursor, out: &mut Vec<Entry>, limit: usize) -> u64 {
        let mut lost = 0;
        let per = u64::from(self.per);
        for (shard, at) in self.shards.iter().zip(&mut cursor.0) {
            let head = shard.head.load(Acquire);
            if head - *at > per {
                lost += head - *at - per;
                *at = head - per;
            }
            while *at < head && out.len() < limit {
                match self.read(shard, *at) {
                    Read::Entry(e) => out.push(e),
                    Read::NotReady => break,
                    Read::Lost => lost += 1,
                }
                *at += 1;
            }
        }
        lost
    }

    /// The newest `limit` entries matching `filter`, newest first.
    pub fn recent(&self, filter: &Filter, limit: usize) -> Vec<Entry> {
        let mut out = Vec::new();
        let per = u64::from(self.per);
        for shard in &self.shards {
            let head = shard.head.load(Acquire);
            for pos in (head.saturating_sub(per)..head).rev() {
                if let Read::Entry(e) = self.read(shard, pos) {
                    if filter.matches(&e) {
                        out.push(e);
                    }
                }
            }
        }
        out.sort_unstable_by_key(|e| std::cmp::Reverse(e.t_us));
        out.truncate(limit);
        out
    }

    /// Moves the entries written since the last drain into the sketches.
    fn feed(&self, d: &mut Drain) {
        while self.feed_up_to(d, usize::MAX) {}
    }

    /// Feeds at most `limit` new entries; true when more may be waiting.
    fn feed_up_to(&self, d: &mut Drain, limit: usize) -> bool {
        let mut entries = Vec::new();
        d.lost += self.read_new_up_to(&mut d.cursor, &mut entries, limit);
        d.seen += entries.len() as u64;
        for e in &entries {
            d.tops.add(e);
        }
        entries.len() == limit
    }

    /// Sizes the pre-warm tracker (0 tracks nothing). Call once at startup.
    pub fn track_names(&self, k: usize) {
        self.state().tops.names = SpaceSaving::new(k);
    }

    /// The `n` most queried pre-warm candidates, biggest first, as domain text
    /// that passes [`rules::domain`] (escaped or odd names are left out). It
    /// first drains the ring, so the last half second is not lost at shutdown.
    pub fn prewarm_names(&self, n: usize) -> Vec<String> {
        let mut d = self.state();
        self.feed(&mut d);
        d.tops.names.top(n).iter().filter_map(|t| rules::domain(&name_text(&t.key, false))).collect()
    }

    /// One drain step: feeds the sketches from new entries, samples the
    /// request rate and takes a per-minute snapshot when due.
    pub fn tick(&self, now: Instant, snap: &Snapshot) {
        let mut d = self.state();
        self.feed(&mut d);
        let at_ms = self.at_ms(now);
        let lite = Lite::new(at_ms, snap);
        if d.recent.len() == RECENT {
            d.recent.pop_front();
        }
        d.recent.push_back((at_ms, lite.total()));
        d.minutes.push_if_due(lite);
    }

    /// The busiest clients, at most [`TOP_K`] (Space-Saving counts), for the
    /// clients page.
    pub fn top_clients(&self) -> Vec<Top> {
        self.state().tops.clients.top(TOP_K)
    }

    pub fn board(&self, now: Instant, snap: &Snapshot) -> Board {
        let at_ms = self.at_ms(now);
        let live = Lite::new(at_ms, snap);
        let d = self.state();
        let qps = d.recent.front().map_or(0.0, |&(at, total)| {
            let dt = at_ms.saturating_sub(at);
            if dt == 0 {
                0.0
            } else {
                live.total().saturating_sub(total) as f64 * 1000.0 / dt as f64
            }
        });
        Board {
            qps,
            w5m: d.minutes.window(&live, 5 * 60_000),
            w24h: d.minutes.window(&live, 24 * 3_600_000),
            domains: d.tops.domains.top(10),
            blocked: d.tops.blocked.top(10),
            clients: d.tops.clients.top(10),
            capacity: self.capacity(),
            seen: d.seen,
            lost: d.lost,
            since_ms: d.since_ms,
        }
    }

    /// Unix milliseconds of the monotonic instant `now`.
    fn at_ms(&self, now: Instant) -> u64 {
        let since_start = u64::try_from(now.saturating_duration_since(self.base).as_millis()).unwrap_or(u64::MAX);
        self.wall_ms.saturating_add(since_start)
    }

    /// What a restart keeps, read under the drain lock (the query path never
    /// takes it). It drains the ring first, so the last half second counts.
    pub fn keep(&self) -> Kept {
        let mut d = self.state();
        self.feed(&mut d);
        Kept {
            since_ms: d.since_ms,
            minutes: d.minutes.ring.iter().copied().collect(),
            domains: d.tops.domains.top(TOP_K),
            blocked: d.tops.blocked.top(TOP_K),
            clients: d.tops.clients.top(TOP_K),
        }
    }

    /// Loads what [`QueryLog::keep`] saved. `totals` are the restored counters.
    /// The counters did not move while the server was down, so the gap to now
    /// is filled with one flat snapshot per minute: a window then reports the
    /// real elapsed time instead of attributing the downtime to a short burst.
    /// Call once at startup, before serving.
    pub fn restore(&self, kept: Kept, totals: &Snapshot) {
        let mut d = self.state();
        d.since_ms = kept.since_ms;
        d.tops.domains.restore(kept.domains);
        d.tops.blocked.restore(kept.blocked);
        d.tops.clients.restore(kept.clients);
        let mut ring: VecDeque<Lite> = kept.minutes.into();
        match ring.back().copied() {
            Some(last) => {
                let steps = (self.wall_ms.saturating_sub(last.at_ms) / 60_000).min(MINUTES as u64);
                ring.extend((1..=steps).map(|i| Lite { at_ms: last.at_ms + i * 60_000, ..last }));
            }
            None => ring.push_back(Lite::new(self.wall_ms, totals)),
        }
        while ring.len() > MINUTES {
            ring.pop_front();
        }
        d.minutes.ring = ring;
    }
}

static LOG: OnceLock<QueryLog> = OnceLock::new();

/// Creates the process-wide log. A second call keeps the first.
pub fn init(capacity: usize) -> &'static QueryLog {
    LOG.get_or_init(|| QueryLog::new(capacity))
}

pub fn get() -> Option<&'static QueryLog> {
    LOG.get()
}

/// The log, creating a disabled one if [`init`] never ran (unit tests).
pub fn get_or_disabled() -> &'static QueryLog {
    LOG.get_or_init(|| QueryLog::new(0))
}

/// Hot-path entry point: two loads and a branch when the log is off.
#[inline]
pub fn record(started: Instant, latency: Duration, q: &Record<'_>) {
    if let Some(log) = LOG.get() {
        log.write(started, latency, q);
    }
}

/// Entries fed per drain step before the drain yields to the runtime.
const DRAIN_CHUNK: usize = 128;

/// Runs the drain forever; spawn once after [`init`].
///
/// A tick has every entry of the last half second to feed: about 2,500 at
/// 5k qps. Fed in one go, that kept the single worker of a 1-CPU deployment
/// busy for a millisecond or more, and the cache hits waiting behind it set
/// the p99.9. So it feeds [`DRAIN_CHUNK`] entries at a time (the lock is
/// released in between) and yields, letting the UDP loop run between chunks.
pub fn spawn_drain() -> tokio::task::JoinHandle<()> {
    tokio::spawn(async {
        let mut ticker = tokio::time::interval(TICK);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let Some(log) = LOG.get() else { continue };
            while log.feed_up_to(&mut log.state(), DRAIN_CHUNK) {
                tokio::task::yield_now().await;
            }
            log.tick(Instant::now(), &stats::global().snapshot());
        }
    })
}

// ------------------------------------------------------------------- trace

/// What the parsed path decided about one query. Task-local, so the many
/// `stats::count` call sites feed it without a parameter, and the hot inline
/// path (which never enters a task) is untouched.
#[derive(Default)]
struct Trace {
    /// A pre-warm query: never counted in the client stats.
    quiet: bool,
    outcome: Cell<Option<Outcome>>,
    upstream: Cell<Option<u8>>,
    list: Cell<Option<u16>>,
}

tokio::task_local! {
    static TRACE: Trace;
}

/// The trace of a finished parsed-path query.
pub struct Traced {
    pub outcome: Option<Outcome>,
    pub upstream: u8,
    pub list: Option<u16>,
}

/// Returns whether the caller should count `outcome` in the client stats:
/// false only inside [`quiet`].
pub fn note_outcome(outcome: Outcome) -> bool {
    TRACE
        .try_with(|t| {
            t.outcome.set(Some(outcome));
            !t.quiet
        })
        .unwrap_or(true)
}

/// `None` is the plain fallback (no DoH upstream answered).
pub fn note_upstream(index: Option<usize>) {
    let value = index.map_or(PLAIN_UPSTREAM, |i| u8::try_from(i).unwrap_or(PLAIN_UPSTREAM - 1).min(PLAIN_UPSTREAM - 1));
    let _ = TRACE.try_with(|t| t.upstream.set(Some(value)));
}

pub fn note_list(list: Option<u16>) {
    let _ = TRACE.try_with(|t| t.list.set(list));
}

/// Runs a pre-warm query: its results are kept out of the client stats.
pub async fn quiet<F: Future>(fut: F) -> F::Output {
    TRACE.scope(Trace { quiet: true, ..Trace::default() }, fut).await
}

/// Runs `fut` with a fresh trace and returns it with its output.
pub async fn traced<F: Future>(fut: F) -> (F::Output, Traced) {
    TRACE
        .scope(Trace::default(), async {
            let out = fut.await;
            let traced = TRACE.with(|t| Traced {
                outcome: t.outcome.get(),
                upstream: t.upstream.get().unwrap_or(NO_UPSTREAM),
                list: t.list.get(),
            });
            (out, traced)
        })
        .await
}

/// Logs a parsed-path query. The raw packet is parsed again here (slow path
/// only); an unparsable one has no name to show and is skipped, as is one that
/// never reached a result (a stray response packet).
pub fn record_traced(started: Instant, latency: Duration, ip: IpAddr, raw: &[u8], traced: &Traced) {
    let Some(log) = LOG.get().filter(|log| log.enabled()) else { return };
    let (Some(outcome), Some(view)) = (traced.outcome, wire::parse_query(raw)) else { return };
    let q = Record {
        ip,
        qname: &view.qname_lower[..usize::from(view.qname_len)],
        qtype: view.qtype,
        outcome,
        upstream: traced.upstream,
        list: traced.list,
    };
    log.write(started, latency, &q);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire_name(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in name.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    fn rec<'a>(ip: &str, qname: &'a [u8], outcome: Outcome) -> Record<'a> {
        Record { ip: ip.parse().unwrap(), qname, qtype: 28, outcome, upstream: 1, list: None }
    }

    #[test]
    fn entry_round_trips_every_field() {
        let name = wire_name("Mail.Example.org").to_ascii_lowercase();
        for ip in ["192.0.2.7", "2001:db8::1"] {
            let q = Record { list: Some(0), ..rec(ip, &name, Outcome::Blocked) };
            let e = unpack(&pack(123_456, &q, 789));
            assert_eq!((e.t_us, e.qtype, e.outcome, e.upstream, e.latency_us), (123_456, 28, Outcome::Blocked, 1, 789));
            assert_eq!((e.ip, e.list, e.truncated), (q.ip, Some(0), false));
            assert_eq!(e.name(), &name[..]);
            assert_eq!(e.text(), "mail.example.org");
        }
        let q = Record { list: Some(u16::MAX), ..rec("::1", &name, Outcome::Cache) };
        assert_eq!(unpack(&pack(0, &q, 0)).list, Some(u16::MAX));
        assert_eq!(unpack(&pack(0, &rec("::1", &name, Outcome::Cache), u32::MAX)).latency_us, u32::MAX);
    }

    #[test]
    fn long_names_keep_a_prefix_and_are_marked() {
        let long = wire_name(&format!("{}.{}.example.org", "a".repeat(40), "b".repeat(40)));
        assert!(long.len() > NAME_BYTES);
        let e = unpack(&pack(0, &rec("::1", &long, Outcome::Cache), 0));
        assert!(e.truncated);
        assert_eq!(e.name().len(), NAME_BYTES);
        assert!(e.text().ends_with('…'));
        assert_eq!(e.rule_domain(), None, "a cut name must not become a rule");
        // Exactly NAME_BYTES is not truncated.
        let exact = wire_name(&format!("{}.{}.x", "a".repeat(30), "b".repeat(29)));
        assert_eq!(exact.len(), NAME_BYTES);
        assert!(!unpack(&pack(0, &rec("::1", &exact, Outcome::Cache), 0)).truncated);
    }

    #[test]
    fn name_text_escapes_hostile_bytes() {
        assert_eq!(name_text(&[0], false), ".");
        assert_eq!(name_text(&wire_name("a.b"), false), "a.b");
        // One label holding a dot, a backslash, a space, a high byte and markup.
        let label = b"a.b\\ \xff<s>";
        let mut name = vec![label.len() as u8];
        name.extend_from_slice(label);
        name.push(0);
        assert_eq!(name_text(&name, false), "a\\.b\\\\\\032\\255<s>");
        let entry = unpack(&pack(0, &rec("::1", &name, Outcome::Cache), 0));
        assert_eq!(entry.rule_domain(), None, "escaped names are not rule candidates");
    }

    #[test]
    fn ring_keeps_the_newest_and_reports_losses() {
        let log = QueryLog::with_shards(8, 1);
        let name = wire_name("x.test");
        let t0 = Instant::now();
        let mut cursor = log.cursor();
        for i in 0..20u32 {
            let q = Record { qtype: i as u16, ..rec("10.0.0.1", &name, Outcome::Upstream) };
            log.write(t0, Duration::from_micros(u64::from(i)), &q);
        }
        let recent = log.recent(&Filter::default(), 100);
        assert_eq!(recent.len(), 8);
        assert_eq!(recent.iter().map(|e| e.qtype).collect::<Vec<_>>(), (12..20).rev().collect::<Vec<_>>());
        let mut out = Vec::new();
        assert_eq!(log.read_new(&mut cursor, &mut out), 12, "12 entries were overwritten unread");
        assert_eq!(out.iter().map(|e| e.qtype).collect::<Vec<_>>(), (12..20).collect::<Vec<_>>());
        out.clear();
        assert_eq!(log.read_new(&mut cursor, &mut out), 0);
        assert!(out.is_empty());
    }

    #[test]
    fn drain_feeds_in_chunks_and_keeps_the_rest() {
        let log = QueryLog::with_shards(1024, 2);
        let name = wire_name("x.test");
        let t0 = Instant::now();
        for _ in 0..300 {
            log.write(t0, Duration::ZERO, &rec("10.0.0.1", &name, Outcome::Cache));
        }
        let mut d = log.state();
        assert!(log.feed_up_to(&mut d, 128), "a full chunk says more may wait");
        assert_eq!(d.seen, 128);
        assert!(log.feed_up_to(&mut d, 128));
        assert!(!log.feed_up_to(&mut d, 128), "44 left: the last chunk is short");
        assert_eq!((d.seen, d.lost), (300, 0), "every entry fed once, none skipped");
        assert_eq!(d.tops.domains.top(1)[0].count, 300);
    }

    /// Measurement only: `cargo test --release drain_chunk_cost -- --ignored --nocapture`.
    /// One tick's worth at 5k qps (2,500 entries over 12,700 distinct names,
    /// pre-warm tracker at its default 1,000) fed in DRAIN_CHUNK steps.
    #[test]
    #[ignore]
    fn drain_chunk_cost() {
        let log = QueryLog::new(10_000);
        log.track_names(1000);
        let t0 = Instant::now();
        let names: Vec<Vec<u8>> = (0..12_700).map(|i| wire_name(&format!("host{i}.example{}.com", i % 97))).collect();
        let mut worst = Duration::ZERO;
        let mut total = Duration::ZERO;
        let mut chunks = 0u32;
        let mut tick_worst = Duration::ZERO;
        for tick in 0..40usize {
            for i in 0..2500usize {
                let n = &names[(tick * 2500 + i * 7) % names.len()];
                let outcome = if i % 10 < 3 { Outcome::Blocked } else { Outcome::Cache };
                log.write(t0, Duration::ZERO, &Record { qtype: 1, ..rec("10.0.0.2", n, outcome) });
            }
            loop {
                let started = std::time::Instant::now();
                let more = log.feed_up_to(&mut log.state(), DRAIN_CHUNK);
                let took = started.elapsed();
                worst = worst.max(took);
                total += took;
                chunks += 1;
                if !more {
                    break;
                }
            }
            let started = std::time::Instant::now();
            log.tick(Instant::now(), &stats::global().snapshot());
            tick_worst = tick_worst.max(started.elapsed());
        }
        eprintln!(
            "chunks {chunks}, mean {:?}, worst {:?}, per entry {:?}, tick tail worst {tick_worst:?}",
            total / chunks,
            worst,
            total / (40 * 2500)
        );
    }

    #[test]
    fn disabled_log_writes_nothing() {
        let log = QueryLog::new(0);
        assert!(!log.enabled());
        log.write(Instant::now(), Duration::ZERO, &rec("::1", &[0], Outcome::Cache));
        assert!(log.recent(&Filter::default(), 10).is_empty());
        assert_eq!(log.capacity(), 0);
    }

    /// Writers race on shared shards while a reader scans: every entry the
    /// reader accepts must be internally consistent (the seqlock rejects
    /// torn slots) and nothing may panic.
    #[test]
    fn concurrent_writers_never_yield_a_torn_entry() {
        let log = QueryLog::with_shards(64, 2);
        let stop = std::sync::atomic::AtomicBool::new(false);
        std::thread::scope(|scope| {
            for t in 0..4u16 {
                let (log, stop) = (&log, &stop);
                scope.spawn(move || {
                    let name = wire_name("race.test");
                    // Write before checking `stop`: under load a writer can be
                    // scheduled only after the reader has finished.
                    loop {
                        // qtype, latency and upstream all encode the same value.
                        let q = Record { qtype: t, upstream: t as u8, ..rec("10.0.0.2", &name, Outcome::Cache) };
                        log.write(Instant::now(), Duration::from_micros(u64::from(t)), &q);
                        if stop.load(Relaxed) {
                            break;
                        }
                    }
                });
            }
            let mut seen = 0;
            while seen < 20_000 {
                for e in log.recent(&Filter::default(), 64) {
                    assert_eq!(u64::from(e.qtype), u64::from(e.latency_us));
                    assert_eq!(e.upstream, e.qtype as u8);
                    assert_eq!(e.text(), "race.test");
                    seen += 1;
                }
            }
            stop.store(true, Relaxed);
        });
    }

    #[test]
    fn filter_matches_client_name_result_and_qtype() {
        let name = wire_name("ads.example.org");
        let e = unpack(&pack(0, &rec("192.168.1.20", &name, Outcome::Blocked), 0));
        let f = |q: &str| Filter::from_query(q).matches(&e);
        assert!(f(""));
        assert!(f("client=192.168.1.&q=EXAMPLE&result=blocked&qtype=aaaa"));
        assert!(f("q=ads.ex%61mple"));
        assert!(!f("client=10."));
        assert!(!f("q=nothing"));
        assert!(!f("result=cache"));
        assert!(!f("qtype=A"));
        assert!(f("result=bogus&qtype=bogus"), "unknown values are ignored");
        assert!(Filter::from_query("qtype=28").matches(&e));
        assert_eq!(qtype_name(65), "HTTPS");
        assert_eq!(qtype_name(999), "TYPE999");
        assert_eq!(param("a=1&b=x+y%21", "b").as_deref(), Some("x y!"));
        assert_eq!(param("a=%zz", "a").as_deref(), Some("%zz"));
    }

    #[test]
    fn prewarm_tracks_only_forwarded_or_cached_a_and_aaaa_names() {
        let log = QueryLog::with_shards(64, 1);
        log.track_names(3);
        let t0 = Instant::now();
        let put = |name: &str, qtype: u16, outcome: Outcome, times: u32| {
            let wire = wire_name(name);
            for _ in 0..times {
                log.write(t0, Duration::ZERO, &Record { qtype, ..rec("10.0.0.1", &wire, outcome) });
            }
        };
        put("one.example", 1, Outcome::Upstream, 5);
        put("two.example", 28, Outcome::Cache, 4);
        put("three.example", 1, Outcome::Stale, 3);
        put("blocked.example", 1, Outcome::Blocked, 9);
        put("local.example", 1, Outcome::Local, 9);
        put("failed.example", 1, Outcome::Servfail, 9);
        put("mx.example", 15, Outcome::Upstream, 9);
        assert_eq!(log.prewarm_names(10), ["one.example", "two.example", "three.example"]);
        assert_eq!(log.prewarm_names(2), ["one.example", "two.example"]);
        // Hostile bytes never become a name to resolve.
        let mut odd = vec![3];
        odd.extend_from_slice(b"a.b");
        odd.extend_from_slice(&wire_name("example"));
        let q = Record { qtype: 1, ..rec("10.0.0.1", &odd, Outcome::Upstream) };
        for _ in 0..20 {
            log.write(t0, Duration::ZERO, &q);
        }
        assert!(log.prewarm_names(10).iter().all(|n| !n.contains('\\')));
    }

    #[test]
    fn space_saving_bounds_memory_and_keeps_heavy_hitters() {
        let mut ss = SpaceSaving::new(10);
        let mut truth: HashMap<u32, u64> = HashMap::new();
        // Two heavy keys among a long tail of unique ones.
        for i in 0..5000u32 {
            let key = match i % 5 {
                0 => 1_000_000,
                1 => 2_000_000,
                _ => i,
            };
            *truth.entry(key).or_default() += 1;
            ss.add(&key.to_be_bytes());
        }
        assert_eq!(ss.items.len(), 10);
        assert_eq!(ss.index.len(), 10);
        // The ordered index mirrors the counters exactly, so its first entry is the true minimum.
        let mirrored: BTreeSet<_> = ss.items.iter().enumerate().map(|(i, t)| (t.count, i)).collect();
        assert_eq!(ss.order, mirrored);
        let top = ss.top(2);
        let keys: Vec<_> = top.iter().map(|t| u32::from_be_bytes(t.key[..].try_into().unwrap())).collect();
        assert!(keys.contains(&1_000_000) && keys.contains(&2_000_000), "{keys:?}");
        for t in ss.top(10) {
            let key = u32::from_be_bytes(t.key[..].try_into().unwrap());
            let real = truth[&key];
            assert!(t.count >= real, "never undercounts");
            assert!(t.count - t.err <= real, "count - err is a lower bound");
        }
    }

    fn lite(at_s: u64, cache: u64, bucket10: u64) -> Lite {
        let mut l = Lite { at_ms: at_s * 1000, outcomes: [0; 8], buckets: [0; BUCKETS], sum_us: 0 };
        l.outcomes[Outcome::Cache as usize] = cache;
        l.buckets[10] = bucket10;
        l
    }

    #[test]
    fn minutes_window_diffs_the_right_snapshots() {
        let mut m = Minutes::new();
        assert_eq!(m.window(&lite(10, 5, 5), 300_000).span_ms, 0, "no history is an empty window");
        m.push_if_due(lite(0, 0, 0));
        m.push_if_due(lite(30, 1, 1));
        assert_eq!(m.ring.len(), 1, "less than a minute apart is skipped");
        for minute in 1..=10u64 {
            m.push_if_due(lite(minute * 60, minute * 100, minute * 100));
        }
        let now = lite(10 * 60 + 30, 1_050, 1_050);
        let w5 = m.window(&now, 5 * 60_000);
        // Newest snapshot at least 5 minutes old is minute 5 (500 queries).
        assert_eq!((w5.span_ms, w5.count(Outcome::Cache)), (5 * 60_000 + 30_000, 550));
        assert_eq!(w5.total(), 550);
        let w24 = m.window(&now, 24 * 3_600_000);
        assert_eq!((w24.span_ms, w24.count(Outcome::Cache)), (630_000, 1_050), "short history uses the oldest");
        assert!((w24.qps() - 1050.0 / 630.0).abs() < 1e-9);
        // 1050 timed requests all in bucket 10 (1024 us).
        assert_eq!(w24.percentile_us(0.5), Some(1024));
        assert_eq!(w24.percentile_us(0.99), Some(1024));
    }

    /// A restart keeps the windows honest: the downtime is idle time, so a
    /// short burst after it is not spread over the whole gap.
    #[test]
    fn restore_fills_the_downtime_with_flat_snapshots() {
        let log = QueryLog::new(0);
        let start = log.wall_ms;
        let mut saved = lite(0, 100, 100);
        saved.at_ms = start - 10 * 60_000; // saved ten minutes before this start
        let totals = Snapshot { outcomes: saved.outcomes, ..stats::Stats::new().snapshot() };
        let top = |k: u8, count| Top { key: vec![k].into(), count, err: 0 };
        log.restore(
            Kept {
                since_ms: 5,
                minutes: vec![saved],
                domains: vec![top(1, 9), top(1, 4), top(2, 3)],
                blocked: vec![],
                clients: vec![top(3, 2)],
            },
            &totals,
        );
        // 40 more queries since the restart.
        let mut now = totals.clone();
        now.outcomes[Outcome::Cache as usize] = 140;
        let board = log.board(log.base + Duration::from_secs(30), &now);
        assert_eq!(board.since_ms, 5);
        assert_eq!(board.w5m.count(Outcome::Cache), 40, "downtime adds nothing");
        assert!(board.w5m.span_ms >= 5 * 60_000 && board.w5m.span_ms < 6 * 60_000 + 30_000, "{}", board.w5m.span_ms);
        assert_eq!(board.domains.len(), 2, "a duplicate key is dropped");
        assert_eq!(board.domains[0].count, 9);
        assert_eq!(board.clients.len(), 1);
        // No saved snapshot: the window starts at the restored totals.
        let log = QueryLog::new(0);
        log.restore(Kept { since_ms: 5, minutes: vec![], domains: vec![], blocked: vec![], clients: vec![] }, &now);
        assert_eq!(log.board(log.base + Duration::from_secs(1), &now).w24h.total(), 0);
    }

    #[test]
    fn minutes_ring_is_bounded() {
        let mut m = Minutes::new();
        for minute in 0..(MINUTES as u64 + 50) {
            m.push_if_due(lite(minute * 60, minute, 0));
        }
        assert_eq!(m.ring.len(), MINUTES);
        assert_eq!(m.ring.front().unwrap().at_ms, 50 * 60_000);
    }

    #[test]
    fn percentile_walks_the_buckets() {
        let mut w = Window { span_ms: 1000, outcomes: [0; 8], buckets: [0; BUCKETS] };
        assert_eq!(w.percentile_us(0.5), None);
        w.buckets[3] = 90; // <= 8 us
        w.buckets[10] = 9; // <= 1024 us
        w.buckets[20] = 1; // <= 1.05 s
        assert_eq!(w.percentile_us(0.5), Some(8));
        assert_eq!(w.percentile_us(0.9), Some(8));
        assert_eq!(w.percentile_us(0.95), Some(1024));
        assert_eq!(w.percentile_us(0.99), Some(1024));
        assert_eq!(w.percentile_us(1.0), Some(1 << 20));
    }

    #[test]
    fn tick_feeds_sketches_and_board() {
        let log = QueryLog::with_shards(64, 1);
        let t0 = Instant::now();
        let ads = wire_name("ads.test");
        let ok = wire_name("ok.test");
        for _ in 0..3 {
            log.write(t0, Duration::ZERO, &Record { list: Some(2), ..rec("10.0.0.1", &ads, Outcome::Blocked) });
        }
        log.write(t0, Duration::ZERO, &rec("10.0.0.2", &ok, Outcome::Cache));
        let snap = stats::Stats::new().snapshot();
        log.tick(Instant::now(), &snap);
        let board = log.board(Instant::now(), &snap);
        assert_eq!(board.seen, 4);
        assert_eq!(key_domain(&board.blocked[0].key), "ads.test");
        assert_eq!(board.blocked[0].count, 3);
        assert_eq!(key_domain(&board.domains[0].key), "ok.test");
        assert_eq!(key_client(&board.clients[0].key), "10.0.0.1");
        assert_eq!(board.capacity, 64);
    }

    #[test]
    fn trace_collects_outcome_upstream_and_list() {
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let (out, trace) = rt.block_on(traced(async {
            stats::count(Outcome::Cache);
            stats::count(Outcome::Upstream);
            note_upstream(Some(2));
            note_list(Some(3));
            7
        }));
        assert_eq!((out, trace.outcome, trace.upstream, trace.list), (7, Some(Outcome::Upstream), 2, Some(3)));
        let (_, trace) = rt.block_on(traced(async { note_upstream(None) }));
        assert_eq!((trace.outcome, trace.upstream), (None, PLAIN_UPSTREAM));
        // Outside a trace, noting is a no-op and must not panic.
        note_outcome(Outcome::Cache);
    }
}
