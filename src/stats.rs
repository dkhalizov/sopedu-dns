//! Request counters and latency histograms for `/metrics`.
//!
//! Hot-path cost is one thread-local read and one relaxed `fetch_add` on a
//! cache-line-padded shard that, with at most [`SHARDS`] threads, only this
//! thread writes. No lock, no allocation, no atomic shared between workers.
//! A scrape sums every shard; a reader may see a shard mid-update, so totals
//! are monotonic but not an atomic snapshot (Prometheus tolerates that).
//!
//! The statics are process-wide and keyed by upstream *index*, so a reload
//! that reorders `upstreams` re-labels the history. That is acceptable for
//! counters scraped as rates.

use std::{
    cell::Cell,
    fmt::Write,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed},
    time::Duration,
};

/// Shard count; a power of two so the index is a mask. More threads than
/// shards share a shard, which stays correct (atomics) and only adds contention.
pub const SHARDS: usize = 64;
/// Per-upstream histograms kept. An upstream index at or above this is not
/// recorded (raise it if anyone configures more than 16 DoH upstreams).
pub const MAX_UPSTREAMS: usize = 16;
/// Log2 buckets over microseconds: bucket `i < 24` holds latencies of at most
/// `2^i` us (1 us .. 8.4 s); bucket 24 is the overflow, `+Inf` only.
pub const BUCKETS: usize = 25;

/// How a query ended; the `result` label of `dns_queries_total`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Fresh cache hit (inline UDP or the parsed path).
    Cache,
    /// Stale cache hit served under RFC 8767.
    Stale,
    /// Blocklist or user rule answered NXDOMAIN.
    Blocked,
    /// Rewrite, reverse zone, special-use name or `.local` answered locally.
    Local,
    /// Answered from an upstream (including a coalesced follower).
    Upstream,
    /// Every upstream failed; the client got SERVFAIL.
    Servfail,
    /// REFUSED, FORMERR, NOTIMP and similar protocol-level rejections.
    Other,
    /// Dropped by the rate limiter or the UDP in-flight bound, no reply.
    Dropped,
}

const OUTCOMES: usize = 8;
const LABELS: [&str; OUTCOMES] = ["cache", "stale", "blocked", "local", "upstream", "servfail", "other", "dropped"];

impl Outcome {
    pub const ALL: [Outcome; OUTCOMES] = [
        Outcome::Cache,
        Outcome::Stale,
        Outcome::Blocked,
        Outcome::Local,
        Outcome::Upstream,
        Outcome::Servfail,
        Outcome::Other,
        Outcome::Dropped,
    ];

    /// The `result` label, also used by the UI.
    pub fn label(self) -> &'static str {
        LABELS[self as usize]
    }
}

fn micros(d: Duration) -> u64 {
    d.as_secs().saturating_mul(1_000_000).saturating_add(u64::from(d.subsec_micros()))
}

/// Bucket index for a latency: the smallest `i` with `2^i us >= latency`.
fn bucket(us: u64) -> usize {
    ((u64::BITS - us.saturating_sub(1).leading_zeros()) as usize).min(BUCKETS - 1)
}

struct Hist {
    buckets: [AtomicU64; BUCKETS],
    sum_us: AtomicU64,
}

impl Hist {
    const fn new() -> Self {
        Self { buckets: [const { AtomicU64::new(0) }; BUCKETS], sum_us: AtomicU64::new(0) }
    }

    fn restore(&self, saved: &HistSnap) {
        for (bucket, n) in self.buckets.iter().zip(saved.buckets) {
            bucket.fetch_add(n, Relaxed);
        }
        self.sum_us.fetch_add(saved.sum_us, Relaxed);
    }

    fn record(&self, d: Duration) {
        let us = micros(d);
        self.buckets[bucket(us)].fetch_add(1, Relaxed);
        self.sum_us.fetch_add(us, Relaxed);
    }
}

/// A merged histogram.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HistSnap {
    pub buckets: [u64; BUCKETS],
    pub sum_us: u64,
}

impl HistSnap {
    const ZERO: Self = Self { buckets: [0; BUCKETS], sum_us: 0 };

    pub fn count(&self) -> u64 {
        self.buckets.iter().sum()
    }

    fn add(&mut self, hist: &Hist) {
        for (total, bucket) in self.buckets.iter_mut().zip(&hist.buckets) {
            *total += bucket.load(Relaxed);
        }
        self.sum_us += hist.sum_us.load(Relaxed);
    }

    /// Prometheus histogram series (cumulative buckets, `_sum` in seconds,
    /// `_count`). `labels` is empty or `name="value",` with a trailing comma.
    fn render(&self, out: &mut String, name: &str, labels: &str) {
        let mut cumulative = 0;
        for (i, count) in self.buckets.iter().take(BUCKETS - 1).enumerate() {
            cumulative += count;
            let _ = writeln!(out, "{name}_bucket{{{labels}le=\"{}\"}} {cumulative}", (1u64 << i) as f64 / 1e6);
        }
        let total = self.count();
        let tail = labels.trim_end_matches(',');
        let tail = if tail.is_empty() { String::new() } else { format!("{{{tail}}}") };
        let _ = writeln!(out, "{name}_bucket{{{labels}le=\"+Inf\"}} {total}");
        let _ = writeln!(out, "{name}_sum{tail} {}", self.sum_us as f64 / 1e6);
        let _ = writeln!(out, "{name}_count{tail} {total}");
    }
}

/// One thread's counters, padded so neighbouring shards never share a line.
#[repr(align(128))]
struct Shard {
    outcomes: [AtomicU64; OUTCOMES],
    upstream_errors: AtomicU64,
    request: Hist,
    upstream: [Hist; MAX_UPSTREAMS],
}

impl Shard {
    const fn new() -> Self {
        Self {
            outcomes: [const { AtomicU64::new(0) }; OUTCOMES],
            upstream_errors: AtomicU64::new(0),
            request: Hist::new(),
            upstream: [const { Hist::new() }; MAX_UPSTREAMS],
        }
    }
}

/// All shards merged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub outcomes: [u64; OUTCOMES],
    pub upstream_errors: u64,
    /// Upstream answers obtained over the plaintext fallback.
    pub plain_fallback: u64,
    pub request: HistSnap,
    pub upstream: [HistSnap; MAX_UPSTREAMS],
}

impl Snapshot {
    pub fn outcome(&self, outcome: Outcome) -> u64 {
        self.outcomes[outcome as usize]
    }
}

pub struct Stats {
    shards: [Shard; SHARDS],
    /// Not sharded: it moves only when every DoH upstream has failed, which is
    /// rare and already slow, so contention does not matter.
    plain_fallback: AtomicU64,
}

thread_local! {
    static SLOT: Cell<usize> = const { Cell::new(usize::MAX) };
}
static NEXT_SLOT: AtomicUsize = AtomicUsize::new(0);

/// This thread's shard index, assigned round-robin on first use. The query
/// log reuses it so one thread-local read serves both.
pub(crate) fn slot() -> usize {
    SLOT.with(|cell| {
        let slot = cell.get();
        if slot != usize::MAX {
            return slot;
        }
        let slot = NEXT_SLOT.fetch_add(1, Relaxed) & (SHARDS - 1);
        cell.set(slot);
        slot
    })
}

impl Stats {
    pub const fn new() -> Self {
        Self { shards: [const { Shard::new() }; SHARDS], plain_fallback: AtomicU64::new(0) }
    }

    fn shard(&self) -> &Shard {
        &self.shards[slot() & (SHARDS - 1)]
    }

    pub fn count(&self, outcome: Outcome) {
        self.shard().outcomes[outcome as usize].fetch_add(1, Relaxed);
    }

    /// An inline answer (a cache hit or a block): the outcome and its
    /// duration in one shard lookup.
    pub fn hit(&self, outcome: Outcome, d: Duration) {
        let shard = self.shard();
        shard.outcomes[outcome as usize].fetch_add(1, Relaxed);
        shard.request.record(d);
    }

    pub fn request(&self, d: Duration) {
        self.shard().request.record(d);
    }

    pub fn upstream_error(&self) {
        self.shard().upstream_errors.fetch_add(1, Relaxed);
    }

    pub fn plain_fallback(&self) {
        self.plain_fallback.fetch_add(1, Relaxed);
    }

    pub fn upstream(&self, index: usize, d: Duration) {
        if let Some(hist) = self.shard().upstream.get(index) {
            hist.record(d);
        }
    }

    /// Adds counters saved by an earlier run. Call once at startup, before any
    /// query: it puts them in shard 0, so they merge into every snapshot and
    /// scrape and the counters carry on instead of restarting at zero.
    pub fn restore(&self, saved: &Snapshot) {
        let shard = &self.shards[0];
        for (counter, n) in shard.outcomes.iter().zip(saved.outcomes) {
            counter.fetch_add(n, Relaxed);
        }
        shard.upstream_errors.fetch_add(saved.upstream_errors, Relaxed);
        self.plain_fallback.fetch_add(saved.plain_fallback, Relaxed);
        shard.request.restore(&saved.request);
        for (hist, n) in shard.upstream.iter().zip(&saved.upstream) {
            hist.restore(n);
        }
    }

    /// Sums every shard.
    pub fn snapshot(&self) -> Snapshot {
        let mut merged = Snapshot {
            outcomes: [0; OUTCOMES],
            upstream_errors: 0,
            plain_fallback: self.plain_fallback.load(Relaxed),
            request: HistSnap::ZERO,
            upstream: [HistSnap::ZERO; MAX_UPSTREAMS],
        };
        for shard in &self.shards {
            for (total, counter) in merged.outcomes.iter_mut().zip(&shard.outcomes) {
                *total += counter.load(Relaxed);
            }
            merged.upstream_errors += shard.upstream_errors.load(Relaxed);
            merged.request.add(&shard.request);
            for (total, hist) in merged.upstream.iter_mut().zip(&shard.upstream) {
                total.add(hist);
            }
        }
        merged
    }

    /// Prometheus text for the query counters and latency histograms.
    /// `upstreams` is how many configured upstreams get a series; the label is
    /// the index, never the URL (it can carry a token).
    pub fn render(&self, out: &mut String, upstreams: usize) {
        let snap = self.snapshot();
        out.push_str("# HELP dns_queries_total Queries by result.\n# TYPE dns_queries_total counter\n");
        for (label, count) in LABELS.iter().zip(snap.outcomes) {
            let _ = writeln!(out, "dns_queries_total{{result=\"{label}\"}} {count}");
        }
        out.push_str("# HELP dns_upstream_errors_total Resolutions where every upstream attempt failed.\n");
        out.push_str("# TYPE dns_upstream_errors_total counter\n");
        let _ = writeln!(out, "dns_upstream_errors_total {}", snap.upstream_errors);
        out.push_str(
            "# HELP dns_plain_fallback_answers_total Upstream answers obtained over the plaintext fallback after every DoH attempt failed.\n",
        );
        out.push_str("# TYPE dns_plain_fallback_answers_total counter\n");
        let _ = writeln!(out, "dns_plain_fallback_answers_total {}", snap.plain_fallback);
        out.push_str("# HELP dns_request_duration_seconds Time to answer a query.\n");
        out.push_str("# TYPE dns_request_duration_seconds histogram\n");
        snap.request.render(out, "dns_request_duration_seconds", "");
        out.push_str("# HELP dns_upstream_duration_seconds Successful upstream exchange time by upstream index.\n");
        out.push_str("# TYPE dns_upstream_duration_seconds histogram\n");
        for (index, hist) in snap.upstream.iter().take(upstreams).enumerate() {
            hist.render(out, "dns_upstream_duration_seconds", &format!("upstream=\"{index}\","));
        }
    }
}

impl Default for Stats {
    fn default() -> Self {
        Self::new()
    }
}

static STATS: Stats = Stats::new();

/// The process-wide instance, for `/metrics`.
pub fn global() -> &'static Stats {
    &STATS
}

/// Counts one query result and tells the per-request trace (query log) what
/// the parsed path decided. The inline hit path counts through [`inline_hit`].
pub fn count(outcome: Outcome) {
    if crate::querylog::note_outcome(outcome) {
        STATS.count(outcome);
    }
}

pub fn inline_hit(outcome: Outcome, d: Duration) {
    STATS.hit(outcome, d);
}

pub fn observe_request(d: Duration) {
    STATS.request(d);
}

pub fn upstream_error() {
    STATS.upstream_error();
}

pub fn plain_fallback() {
    STATS.plain_fallback();
}

pub fn observe_upstream(index: usize, d: Duration) {
    STATS.upstream(index, d);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_edges_are_log2_microseconds() {
        assert_eq!(micros(Duration::MAX), u64::MAX);
        assert_eq!(bucket(0), 0);
        assert_eq!(bucket(1), 0);
        assert_eq!(bucket(2), 1);
        assert_eq!(bucket(3), 2);
        assert_eq!(bucket(4), 2);
        assert_eq!(bucket(5), 3);
        assert_eq!(bucket(1 << 23), 23, "8.39 s is the last finite bucket");
        assert_eq!(bucket((1 << 23) + 1), BUCKETS - 1);
        assert_eq!(bucket(u64::MAX), BUCKETS - 1);
    }

    /// Every thread writes its own shard; the snapshot must be their sum.
    #[test]
    fn shards_merge_into_one_total() {
        let stats = Box::new(Stats::new());
        const THREADS: u64 = 8;
        const EACH: u64 = 1000;
        std::thread::scope(|scope| {
            for _ in 0..THREADS {
                scope.spawn(|| {
                    for _ in 0..EACH {
                        stats.count(Outcome::Blocked);
                        stats.hit(Outcome::Cache, Duration::from_micros(3));
                        stats.upstream_error();
                        stats.upstream(1, Duration::from_millis(2));
                    }
                });
            }
        });
        stats.upstream(MAX_UPSTREAMS, Duration::from_secs(1));
        let snap = stats.snapshot();
        assert_eq!(snap.outcome(Outcome::Blocked), THREADS * EACH);
        assert_eq!(snap.outcome(Outcome::Cache), THREADS * EACH);
        assert_eq!(snap.outcome(Outcome::Servfail), 0);
        assert_eq!(snap.upstream_errors, THREADS * EACH);
        assert_eq!(snap.request.count(), THREADS * EACH);
        assert_eq!(snap.request.buckets[2], THREADS * EACH);
        assert_eq!(snap.request.sum_us, THREADS * EACH * 3);
        assert_eq!(snap.upstream[1].count(), THREADS * EACH);
        assert_eq!(snap.upstream[1].sum_us, THREADS * EACH * 2000);
        assert_eq!(snap.upstream[0].count(), 0);
    }

    #[test]
    fn render_is_cumulative_and_labels_by_index() {
        let stats = Box::new(Stats::new());
        stats.count(Outcome::Local);
        stats.request(Duration::from_micros(1));
        stats.request(Duration::from_micros(100));
        stats.request(Duration::from_secs(30));
        stats.upstream(0, Duration::from_micros(500));
        stats.plain_fallback();
        let mut text = String::new();
        stats.render(&mut text, 2);
        assert!(text.contains("dns_queries_total{result=\"local\"} 1\n"));
        assert!(text.contains("dns_plain_fallback_answers_total 1\n"));
        assert!(text.contains("dns_request_duration_seconds_bucket{le=\"0.000001\"} 1\n"));
        assert!(text.contains("dns_request_duration_seconds_bucket{le=\"0.000128\"} 2\n"));
        assert!(text.contains("dns_request_duration_seconds_bucket{le=\"8.388608\"} 2\n"));
        assert!(text.contains("dns_request_duration_seconds_bucket{le=\"+Inf\"} 3\n"));
        assert!(text.contains("dns_request_duration_seconds_count 3\n"));
        assert!(text.contains("dns_upstream_duration_seconds_bucket{upstream=\"0\",le=\"0.000512\"} 1\n"));
        assert!(text.contains("dns_upstream_duration_seconds_count{upstream=\"1\"} 0\n"));
        assert!(!text.contains("upstream=\"2\""));
    }
}
