//! Optional per-client rate limiting.
//!
//! One token bucket per client host: its full address, IPv4 /32 or IPv6 /128.
//! A shorter IPv6 prefix would merge hosts: SLAAC (RFC 4862) gives every
//! device of a home LAN the same /64, and every link-local address shares
//! fe80::/64, so one chatty device would silence every other one. The cost is
//! that a host using several IPv6 addresses (RFC 8981 temporary addresses)
//! gets an allowance per address; a host on the LAN can forge source
//! addresses anyway, so no per-source key stops a determined one.
//! The bucket map is bounded: a new client at the bound evicts the fullest of
//! the oldest few buckets. Disabled by default (`rate_limit_qps = 0`).
//! The clock is a parameter so tests use synthetic instants.

use std::{
    collections::{HashMap, VecDeque},
    net::IpAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
};

use crate::clock::Instant;

/// Upper bound on tracked client hosts.
pub const MAX_BUCKETS: usize = 4096;

/// Buckets compared when a newcomer must evict one from a full table.
const EVICTION_SAMPLE: usize = 8;

/// The per-host key shared by every per-client limit: the full address, with
/// IPv4-mapped IPv6 treated as IPv4.
pub fn host_key(ip: IpAddr) -> IpAddr {
    ip.to_canonical()
}

/// Live connections (or in-flight work) per client host, keyed by
/// [`host_key`]. The table holds only hosts with a live slot, so it is
/// bounded by the caller's global limit. A slot is released when dropped.
#[derive(Default)]
pub struct PerClient(Mutex<HashMap<IpAddr, usize>>);

/// One held slot of a [`PerClient`] table.
pub struct ClientSlot {
    table: Arc<PerClient>,
    ip: IpAddr,
}

impl PerClient {
    /// A slot for `ip`, or `None` when its host already holds `max`.
    pub fn take(table: &Arc<Self>, ip: IpAddr, max: usize) -> Option<ClientSlot> {
        let mut held = table.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        // Same per-host key as the rate limiter.
        let ip = host_key(ip);
        let count = held.entry(ip).or_insert(0);
        if *count >= max {
            return None;
        }
        *count += 1;
        Some(ClientSlot { table: table.clone(), ip })
    }
}

impl Drop for ClientSlot {
    fn drop(&mut self) {
        let mut held = self.table.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(count) = held.get_mut(&self.ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                held.remove(&self.ip);
            }
        }
    }
}

#[derive(Clone, Copy)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

/// A bounded token-bucket limiter. `qps == 0` disables it (and `burst == 0`
/// then means "use `qps` as the burst").
pub struct RateLimit {
    qps: Option<f64>,
    burst: f64,
    /// The buckets, and their hosts oldest first (the eviction queue).
    buckets: Mutex<(HashMap<IpAddr, Bucket>, VecDeque<IpAddr>)>,
    dropped: AtomicU64,
}

impl RateLimit {
    pub fn new(qps: u64, burst: u64) -> Self {
        let burst = if burst == 0 { qps } else { burst };
        Self {
            qps: (qps > 0).then_some(qps as f64),
            burst: burst as f64,
            buckets: Mutex::new((HashMap::new(), VecDeque::new())),
            dropped: AtomicU64::new(0),
        }
    }

    /// Takes one token for this client host. Returns `false` when the bucket
    /// is empty; the caller drops the request without a reply.
    pub fn allow(&self, ip: IpAddr, now: Instant) -> bool {
        let Some(qps) = self.qps else { return true };
        let key = host_key(ip);
        let mut table = self.buckets.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let (buckets, order) = &mut *table;
        let mut start = self.burst;
        if buckets.len() >= MAX_BUCKETS && !buckets.contains_key(&key) {
            // Evict the bucket with the most tokens among the
            // `EVICTION_SAMPLE` oldest: the client furthest from its limit
            // loses (almost) nothing, the others move to the back of the
            // queue, so a client being limited keeps its state while newer
            // buckets are tried, and every newcomer gets its own bucket (no
            // shared bucket an attacker could starve). The work per newcomer
            // is bounded, not a scan of the whole table under the lock.
            let level = |b: &Bucket| b.tokens + now.saturating_duration_since(b.last).as_secs_f64() * qps;
            let sample = order.len().min(EVICTION_SAMPLE);
            order.rotate_left(sample);
            let level_at = |at: usize| buckets.get(&order[at]).map_or(0.0, level);
            let fullest = (order.len() - sample..order.len()).max_by(|&a, &b| level_at(a).total_cmp(&level_at(b)));
            if let Some(left) = fullest.and_then(|at| order.remove(at)).and_then(|ip| buckets.remove(&ip)) {
                let left = level(&left);
                // Under a full table a newcomer inherits the evicted level,
                // not a fresh burst. Rotating sources still get one bucket
                // each: per-source limiting cannot stop spoofing (SECURITY.md).
                // Floor of one token: a first query is never dropped just
                // because the table is full.
                start = left.clamp(1.0, self.burst.max(1.0));
            }
        }
        let bucket = buckets.entry(key).or_insert_with(|| {
            order.push_back(key);
            Bucket { tokens: start, last: now }
        });
        let elapsed = now.saturating_duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * qps).min(self.burst);
        bucket.last = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            false
        }
    }

    /// Requests dropped since this limiter was built.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.buckets.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).0.len()
    }

    #[cfg(test)]
    fn contains(&self, ip: IpAddr) -> bool {
        self.buckets.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).0.contains_key(&host_key(ip))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::Ipv4Addr, time::Duration};

    #[test]
    fn clients_are_capped_per_host_and_slots_are_released() {
        let table = Arc::new(PerClient::default());
        let a: IpAddr = "192.0.2.1".parse().unwrap();
        let b: IpAddr = "192.0.2.2".parse().unwrap();
        let held: Vec<_> = (0..3).map(|_| PerClient::take(&table, a, 3).expect("under the cap")).collect();
        assert!(PerClient::take(&table, a, 3).is_none(), "the fourth connection from one host is refused");
        assert!(PerClient::take(&table, b, 3).is_some(), "another host is unaffected");
        drop(held);
        assert!(PerClient::take(&table, a, 3).is_some(), "slots come back when connections end");
        assert!(table.0.lock().unwrap().len() <= 1, "empty entries are removed");
    }

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    /// SLAAC (RFC 4862) puts every device of a home LAN in one /64, and every
    /// link-local address is in fe80::/64: one device at its limit must not
    /// use up a neighbour's allowance.
    #[test]
    fn ipv6_neighbours_in_one_64_have_separate_allowances() {
        for (a, b) in [("2001:db8:1:2::10", "2001:db8:1:2::20"), ("fe80::1", "fe80::2")] {
            let (a, b) = (ip(a), ip(b));
            let table = Arc::new(PerClient::default());
            let held = PerClient::take(&table, a, 1).expect("under the cap");
            assert!(PerClient::take(&table, a, 1).is_none(), "the host itself is capped");
            assert!(PerClient::take(&table, b, 1).is_some(), "its neighbour {b} keeps its own slots");
            drop(held);
            let limit = RateLimit::new(1, 1);
            let now = Instant::now();
            assert!(limit.allow(a, now));
            assert!(!limit.allow(a, now), "the host itself is limited");
            assert!(limit.allow(b, now), "its neighbour {b} keeps its own bucket");
        }
    }

    #[test]
    fn disabled_by_default() {
        let limit = RateLimit::new(0, 0);
        let now = Instant::now();
        for _ in 0..1000 {
            assert!(limit.allow(ip("192.0.2.1"), now));
        }
        assert_eq!(limit.dropped(), 0);
        assert_eq!(limit.len(), 0);
    }

    #[test]
    fn burst_then_refill() {
        let limit = RateLimit::new(10, 2);
        let start = Instant::now();
        let client = ip("192.0.2.1");
        assert!(limit.allow(client, start));
        assert!(limit.allow(client, start));
        assert!(!limit.allow(client, start));
        // 150 ms at 10 qps is 1.5 tokens: one request fits.
        let later = start + Duration::from_millis(150);
        assert!(limit.allow(client, later));
        assert!(!limit.allow(client, later));
        assert!(limit.allow(client, later + Duration::from_millis(150)));
    }

    #[test]
    fn burst_zero_uses_qps() {
        let limit = RateLimit::new(2, 0);
        let now = Instant::now();
        let client = ip("192.0.2.1");
        assert!(limit.allow(client, now));
        assert!(limit.allow(client, now));
        assert!(!limit.allow(client, now));
    }

    #[test]
    fn clients_key_by_host_address() {
        let limit = RateLimit::new(1, 1);
        let now = Instant::now();
        assert!(limit.allow(ip("192.168.1.1"), now));
        assert!(!limit.allow(ip("192.168.1.1"), now), "one host has one bucket");
        assert!(limit.allow(ip("192.168.1.200"), now), "a neighbour in the same /24 is not silenced");
        assert!(!limit.allow(ip("::ffff:192.168.1.1"), now), "IPv4-mapped is the same host");
    }

    #[test]
    fn a_full_map_evicts_the_fullest_bucket_and_keeps_limited_clients() {
        // burst 2 at 1 qps.
        let limit = RateLimit::new(1, 2);
        let start = Instant::now();
        let host = |i: usize| IpAddr::V4(Ipv4Addr::new(10, (i >> 8) as u8, (i & 0xff) as u8, 1));
        // host(0) is being limited (both tokens spent); everyone else spent one.
        assert!(limit.allow(host(0), start) && limit.allow(host(0), start));
        assert!(!limit.allow(host(0), start));
        for i in 1..MAX_BUCKETS {
            assert!(limit.allow(host(i), start));
        }
        assert_eq!(limit.len(), MAX_BUCKETS);
        // The newcomer gets its own bucket, starting from the evicted level
        // (1 token here), not a fresh burst of 2.
        let newcomer = IpAddr::V4(Ipv4Addr::new(10, 16, 0, 1));
        assert!(limit.allow(newcomer, start));
        assert!(!limit.allow(newcomer, start), "eviction does not hand out a fresh burst");
        assert_eq!(limit.len(), MAX_BUCKETS);
        assert!(limit.contains(host(0)), "a client being limited is never evicted");
        assert!(!limit.allow(host(0), start), "and its limit is not reset");
    }

    /// A newcomer to a full table costs a bounded amount of work, not a scan
    /// of every bucket under the lock: a source-rotating flood must not turn
    /// the limiter into the bottleneck.
    #[test]
    fn a_full_table_admits_newcomers_in_bounded_time() {
        let limit = RateLimit::new(1, 2);
        let now = Instant::now();
        let host = |i: u128| IpAddr::V6(std::net::Ipv6Addr::from_bits(0x2001_0db8 << 96 | i));
        for i in 0..MAX_BUCKETS as u128 {
            assert!(limit.allow(host(i), now));
        }
        let started = std::time::Instant::now();
        for i in 0..50_000 {
            assert!(limit.allow(host(1 << 32 | i), now), "a first query is never dropped for table pressure");
        }
        let elapsed = started.elapsed();
        assert_eq!(limit.len(), MAX_BUCKETS);
        assert!(elapsed < Duration::from_secs(2), "50,000 newcomers took {elapsed:?}");
    }

    #[test]
    fn host_key_is_the_full_address() {
        assert_eq!(host_key(ip("192.0.2.7")), ip("192.0.2.7"));
        assert_eq!(host_key(ip("::ffff:192.0.2.7")), ip("192.0.2.7"));
        assert_eq!(host_key(ip("2001:db8:1:2:aaaa:bbbb:cccc:dddd")), ip("2001:db8:1:2:aaaa:bbbb:cccc:dddd"));
    }
}
