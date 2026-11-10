//! Hedged, health-aware DoH pool with a secure plaintext fallback.
//!
//! One query goes to the best upstream first; the next is launched after the
//! hedge delay, or immediately when the previous attempt fails. The first
//! terminal answer wins and cancels the losers. DoH uses ID 0 over one warm
//! HTTP/2 client; the UDP/TCP fallback uses a fresh socket, a fresh random ID
//! and (by default) 0x20 question-case randomisation.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, Notify, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::{timeout_at, Instant};

use crate::config::{Config, UpstreamStrategy};
use crate::wire::{self, QueryView};

const MAX_DNS_MESSAGE: usize = u16::MAX as usize;
const PROBE_INTERVAL: Duration = Duration::from_secs(30);
/// Suppress matching outbound work for `failure_cache_seconds` (5 s by
/// default) after a failed resolution, backing off to 30 s, or to the
/// configured window when that is larger, on repeated failures (RFC 9520
/// §3.2). The key is capped at 300 s, so the window never exceeds that.
#[cfg(test)]
const FAILURE_WINDOW: Duration = Duration::from_secs(5);
const FAILURE_WINDOW_FLOOR_MAX: Duration = Duration::from_secs(30);
/// When a resolution last failed and how long that suppresses repeats.
type FailureMark = (Instant, Duration);
/// One TCP attempt kept alive while the plain exchange still listens on UDP.
type TcpAttempt<'a> = std::pin::Pin<Box<dyn std::future::Future<Output = Result<PlainReply, Fail>> + Send + 'a>>;
const FAILURE_CAPACITY: usize = 4096;
/// Zone transfers relayed at once across all clients.
pub const TRANSFER_CONCURRENCY: usize = 16;
/// The shortest time a failure mark is kept, even under a flood that fills
/// the map (RFC 9520 §3.2).
const FAILURE_MIN_HOLD: Duration = Duration::from_secs(1);
/// Retained bytes the failure map is bounded by (1 MiB).
const FAILURE_BYTES: usize = 1 << 20;
/// The longest a `Retry-After` can keep one DoH upstream out of use.
const RETRY_AFTER_CAP: Duration = Duration::from_secs(60);

/// The longest `ordered` waits for an upstream before asking the next one. It
/// stays well under the default 1.9 s UDP discard limit, so the failover
/// answer is still sent to a UDP client.
const FAILOVER_MAX: Duration = Duration::from_secs(1);
/// A plain fallback found unreachable is skipped for 5 s, doubling up to 60 s.
const FALLBACK_BACKOFF: Duration = Duration::from_secs(5);
const FALLBACK_BACKOFF_MAX: Duration = Duration::from_secs(60);
/// How long an upstream TCP connection stays open with no query outstanding.
#[cfg(not(test))]
const TCP_IDLE: Duration = Duration::from_secs(10);
/// Short in tests so the idle-close path is exercised without a 10 s wait.
#[cfg(test)]
const TCP_IDLE: Duration = Duration::from_millis(300);
/// How long the rest of a TCP frame may take once its first byte has arrived.
const TCP_FRAME_WAIT: Duration = Duration::from_secs(5);
/// Connections one query may try: a server can close a shared connection
/// with the query unanswered.
const TCP_TRIES: usize = 3;
/// A source port already in use is redrawn at most this many times; then the
/// attempt fails instead of falling back to an ephemeral port.
const SOURCE_PORT_TRIES: usize = 8;
/// When a plain UDP query with no reply is sent again, once: the low end of
/// the 2 to 5 s minimum in RFC 1035 §4.2.1.
const RETRANSMIT_AFTER: Duration = Duration::from_secs(2);
/// The high end of that range: a slow path is not waited on longer.
const RETRANSMIT_MAX: Duration = Duration::from_secs(5);

/// The wait before a plain UDP datagram is sent again: twice the smoothed RTT
/// (`rtt_us`, 0 when unknown), kept within 2 to 5 s (RFC 1035 §4.2.1,
/// RFC 8085 §3.1.1).
fn retransmit_interval(rtt_us: u64) -> Duration {
    Duration::from_micros(rtt_us.saturating_mul(2)).clamp(RETRANSMIT_AFTER, RETRANSMIT_MAX)
}

/// The `plaintext_fallback_used` warning is logged at most this often.
const PLAIN_WARN_INTERVAL_SECS: u64 = 60;

/// Rate limit for the `plaintext_fallback_used` warning: the Unix second of
/// the last warning, and the plaintext answers since then.
struct PlainWarn {
    last: AtomicU64,
    pending: AtomicU64,
}

static PLAIN_WARN: PlainWarn = PlainWarn { last: AtomicU64::new(0), pending: AtomicU64::new(0) };

impl PlainWarn {
    /// Counts one plaintext answer at `now` (Unix seconds). Returns the count to
    /// report when a warning is due: the first answer, then at most once per
    /// interval. A clock step in either direction makes a warning due.
    fn note(&self, now: u64) -> Option<u64> {
        self.pending.fetch_add(1, Ordering::Relaxed);
        let last = self.last.load(Ordering::Relaxed);
        if last != 0 && now.abs_diff(last) < PLAIN_WARN_INTERVAL_SECS {
            return None;
        }
        // One racing caller wins the warning; the others' answers stay pending.
        self.last.compare_exchange(last, now.max(1), Ordering::Relaxed, Ordering::Relaxed).ok()?;
        Some(self.pending.swap(0, Ordering::Relaxed))
    }
}

/// An answer is about to leave over the plaintext fallback: count it for
/// `/metrics` and warn (rate-limited) so a downgrade is never silent.
fn plain_answer_served() {
    crate::stats::plain_fallback();
    if let Some(count) = PLAIN_WARN.note(crate::log::now_unix()) {
        crate::log::log(
            "warn",
            "plaintext_fallback_used",
            &[
                ("count", count.to_string()),
                ("hint", "every DoH upstream failed; answers came over unauthenticated plain DNS".into()),
            ],
        );
    }
}

/// Why one attempt failed. A `Local` error is our own socket or resource
/// trouble (bind/connect/EMFILE/ENOBUFS...), or a resolution that sent
/// nothing: it says nothing about the upstream, so it never enters the
/// failure cache. `Unreachable` is a network error naming the endpoint
/// itself (refused, reset, unreachable): a `Remote` failure that is also
/// evidence against the endpoint's health, whatever the question. Every other `Remote` failure (a timeout, a failure
/// RCODE, invalid content) may be caused by the question alone.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Fail {
    Remote,
    Unreachable,
    Local,
}

impl From<&str> for Fail {
    fn from(_: &str) -> Self {
        Fail::Remote
    }
}

/// ENOMEM, EMFILE, ENFILE, ENOBUFS and EADDRNOTAVAIL (Unix numbers; Linux
/// differs for the last two).
#[cfg(any(target_os = "linux", target_os = "android"))]
const LOCAL_ERRNOS: [i32; 5] = [12, 24, 23, 105, 99];
#[cfg(not(any(target_os = "linux", target_os = "android")))]
const LOCAL_ERRNOS: [i32; 5] = [12, 24, 23, 55, 49];

fn io_fail(error: &std::io::Error) -> Fail {
    let local = matches!(error.kind(), std::io::ErrorKind::OutOfMemory | std::io::ErrorKind::AddrNotAvailable)
        || (cfg!(unix) && error.raw_os_error().is_some_and(|errno| LOCAL_ERRNOS.contains(&errno)));
    use std::io::ErrorKind;
    let unreachable = matches!(
        error.kind(),
        ErrorKind::ConnectionRefused
            | ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::HostUnreachable
            | ErrorKind::NetworkUnreachable
    );
    if local {
        Fail::Local
    } else if unreachable {
        Fail::Unreachable
    } else {
        Fail::Remote
    }
}

/// The failure map and the bytes it retains, kept together so the byte bound
/// costs one addition per change and nothing on a lookup.
#[derive(Default)]
struct FailureMap {
    map: HashMap<Box<[u8]>, FailureMark>,
    bytes: usize,
}

fn charge(key: &[u8]) -> usize {
    key.len() + std::mem::size_of::<Box<[u8]>>() + std::mem::size_of::<FailureMark>()
}

impl FailureMap {
    /// Stores `mark`, evicting the oldest entries until both the entry and
    /// byte bounds hold. A mark younger than [`FAILURE_MIN_HOLD`] is never
    /// evicted (RFC 9520 §3.2: failures are cached for at least 1 s): when the
    /// map is full of those, the new mark is refused instead. `false` means
    /// the mark was not stored.
    /// Known limit: the oldest-first scan is O(n) at the 4096-entry bound; a
    /// queue would matter only at much larger bounds.
    fn insert(&mut self, key: Box<[u8]>, mark: FailureMark, capacity: usize, byte_limit: usize) -> bool {
        let need = charge(&key);
        if need > byte_limit {
            return false;
        }
        self.remove(&key);
        while !self.map.is_empty() && (self.map.len() >= capacity || self.bytes + need > byte_limit) {
            let Some((oldest, at)) =
                self.map.iter().min_by_key(|(_, (at, _))| *at).map(|(key, (at, _))| (key.clone(), *at))
            else {
                break;
            };
            if at.elapsed() < FAILURE_MIN_HOLD {
                return false;
            }
            self.remove(&oldest);
        }
        self.bytes += need;
        self.map.insert(key, mark);
        true
    }

    fn remove(&mut self, key: &[u8]) {
        if self.map.remove(key).is_some() {
            self.bytes = self.bytes.saturating_sub(charge(key));
        }
    }
}

/// One spawned DoH attempt. The guard lives in the task, so a normal return
/// decrements `outstanding`.
///
/// Upstream health must not be steerable by clients: anyone can ask for
/// names whose authoritative servers are slow or broken, so only a
/// name-independent transport failure ([`DohError`]) counts towards the
/// circuit. A timeout, a failure RCODE, an HTTP error status (5xx included:
/// a DoH front end may map one slow or broken backend lookup to 502 or 504)
/// or invalid content may be the question's fault and does not; neither does
/// a task aborted because a peer won, the caller went away or the deadline
/// passed. Such an attempt only contributes a latency lower bound (at most
/// the attempt budget), so an upstream that keeps losing sorts last. A dead
/// upstream is still found by its connection errors and by the root-NS
/// probes, which ask one fixed name: a probe failure of any kind, an
/// endpoint-wide 5xx included, counts.
struct Attempt {
    upstream: Arc<Upstream>,
    completed: bool,
    started: Instant,
}

impl Attempt {
    fn new(upstream: Arc<Upstream>) -> Self {
        upstream.state().outstanding += 1;
        Self { upstream, completed: false, started: Instant::now() }
    }

    /// Records the one outcome this attempt produced. Marking it complete
    /// stops the drop guard from also recording a latency bound.
    fn complete(&mut self, result: &Result<DohReply, DohError>) {
        match result {
            Ok(reply) => {
                crate::stats::observe_upstream(self.upstream.index, reply.latency);
                record_success(&self.upstream, reply.latency);
                self.completed = true;
            }
            Err(error) if error.transport => {
                record_failure(&self.upstream, &error.message, true);
                self.completed = true;
            }
            // Shown in the health view, but left to the drop guard: a
            // latency bound, never a failure.
            Err(error) => self.upstream.state().last_error = Some(error.message.clone()),
        }
    }
}

impl Drop for Attempt {
    fn drop(&mut self) {
        if !self.completed {
            // Known limit: such an attempt lasted at least this long; fold
            // that in only when it exceeds the estimate. A censored sample
            // can bias EWMA high for a slow-but-live upstream; probes pull it
            // back down.
            let lower_bound = self.started.elapsed().as_micros().min(u64::MAX as u128) as u64;
            let mut state = self.upstream.state();
            if lower_bound > state.ewma_us {
                state.ewma_us =
                    if state.ewma_us == 0 { lower_bound } else { (state.ewma_us.saturating_mul(4) + lower_bound) / 5 };
            }
        }
        let mut state = self.upstream.state();
        state.outstanding = state.outstanding.saturating_sub(1);
    }
}

#[derive(Clone, Default)]
struct State {
    ewma_us: u64,
    outstanding: usize,
    wins: u64,
    hedges: u64,
    failures: u32,
    open_until: Option<Instant>,
    /// The upstream asked (`Retry-After` on a 429/503) not to be called
    /// before this instant. A pause the probe drew is never overridden; one
    /// a client query drew yields when no other upstream is usable.
    paused_until: Option<Instant>,
    /// The root-NS probe drew the pause, so it is about the endpoint, not
    /// about one client's question.
    pause_probed: bool,
    /// The last failure was a failure to connect (TCP, TLS or the connect
    /// timeout). Only that lets the plaintext fallback in: any HTTP status,
    /// `Retry-After` or DNS answer proves the endpoint is reachable.
    unreachable: bool,
    last_error: Option<String>,
}

struct Upstream {
    index: usize,
    url: String,
    state: Mutex<State>,
}

impl Upstream {
    fn new(index: usize, url: String) -> Self {
        Self { index, url, state: Mutex::new(State::default()) }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn is_paused(&self, now: Instant) -> bool {
        self.state().paused_until.is_some_and(|until| until > now)
    }

    /// Open circuit or a `Retry-After` pause: not a candidate while others are.
    fn is_blocked(&self, now: Instant) -> bool {
        let state = self.state();
        state.open_until.is_some_and(|until| until > now) || state.paused_until.is_some_and(|until| until > now)
    }

    /// Down at the endpoint level: an open circuit (probes or transport
    /// errors) or a pause the probe drew. A pause a client query drew is not.
    fn is_benched(&self, now: Instant) -> bool {
        let state = self.state();
        state.open_until.is_some_and(|until| until > now)
            || (state.pause_probed && state.paused_until.is_some_and(|until| until > now))
    }

    /// Down because it cannot be connected to: an open circuit whose last
    /// failure was a connect failure. This alone lets the plaintext fallback
    /// in. A client flood can make an upstream rate-limit us (the probe then
    /// sees the 429 too) or answer errors, but it cannot make it unreachable.
    fn is_unreachable(&self, now: Instant) -> bool {
        let state = self.state();
        state.unreachable && state.open_until.is_some_and(|until| until > now)
    }

    fn pause(&self, wait: Duration, probe: bool) {
        if let Some(until) = Instant::now().checked_add(wait.min(RETRY_AFTER_CAP)) {
            let mut state = self.state();
            let still_paused = state.paused_until.is_some_and(|current| current > Instant::now());
            state.pause_probed = probe || (still_paused && state.pause_probed);
            state.paused_until = Some(state.paused_until.map_or(until, |current| current.max(until)));
        }
    }
}

/// Health of one plain fallback: consecutive unreachable results and until
/// when it is skipped. Only [`Fail::Unreachable`] counts, for the reason
/// given on [`Attempt`]; any reply resets it.
#[derive(Default)]
struct FallbackState {
    failures: u32,
    skip_until: Option<Instant>,
    /// Smoothed round-trip time of first-try UDP replies, in microseconds; 0
    /// until one has been seen (RFC 8085 §3.1.1).
    rtt_us: u64,
}

impl FallbackState {
    fn record(state: &Mutex<FallbackState>, result: &Result<PlainReply, Fail>) {
        let mut state = state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        match result {
            Ok(_) => {
                state.failures = 0;
                state.skip_until = None;
            }
            Err(Fail::Unreachable) => {
                state.failures = state.failures.saturating_add(1);
                let backoff = FALLBACK_BACKOFF.saturating_mul(1 << state.failures.saturating_sub(1).min(4));
                state.skip_until = Instant::now().checked_add(backoff.min(FALLBACK_BACKOFF_MAX));
            }
            Err(_) => {}
        }
    }
}

impl FallbackState {
    /// Folds in one round trip with the weighting of [`record_success`].
    fn sample_rtt(&mut self, rtt: Duration) {
        let sample = (rtt.as_micros().min(u64::MAX as u128) as u64).max(1);
        self.rtt_us = if self.rtt_us == 0 { sample } else { (self.rtt_us.saturating_mul(4) + sample) / 5 };
    }
}

/// Health snapshot for the UI and tests.
#[derive(Clone, Debug)]
pub struct UpstreamHealth {
    pub index: usize,
    pub url: String,
    pub healthy: bool,
    pub ewma_us: u64,
    pub outstanding: usize,
    pub wins: u64,
    pub hedges: u64,
    pub last_error: Option<String>,
}

/// The per-upstream counters that survive a restart, keyed by the redacted URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpstreamCount {
    pub url: String,
    pub wins: u64,
    pub hedges: u64,
}

/// A usable upstream answer. `terminal` is false for an incomplete response
/// (empty, CNAME-only, referral) that must not enter the cache.
pub struct UpstreamAnswer {
    pub raw: Vec<u8>,
    pub upstream_index: Option<usize>,
    pub age: u32,
    pub terminal: bool,
    pub message: Message,
}

pub struct UpstreamPool {
    http: reqwest::Client,
    /// The same settings with a connection pool of its own: client queries
    /// filling a shared HTTP/2 connection's stream limit could otherwise
    /// delay a probe, and a probe timeout counts as unreachable.
    probe_http: reqwest::Client,
    upstreams: Vec<Arc<Upstream>>,
    fallback: Vec<SocketAddr>,
    fallback_state: Vec<Arc<Mutex<FallbackState>>>,
    hedge_ms: u64,
    strategy: UpstreamStrategy,
    timeout: Duration,
    /// How long `ordered` waits before asking the next upstream.
    failover: Duration,
    upstream_0x20: bool,
    /// Source ports never used for plain upstream queries
    /// (RFC 5452 §9.2), sorted, merged and validated.
    source_ports_excluded: Arc<[(u16, u16)]>,
    trust_plain: bool,
    inflight: Semaphore,
    /// Zone transfers relayed at once: each holds an upstream TCP connection
    /// for up to TRANSFER_MAX, so a global bound keeps clients from opening
    /// one per connection they can make.
    transfers: Arc<Semaphore>,
    failures: Mutex<FailureMap>,
    /// First failure window and the cap its doubling stops at.
    failure_window: Duration,
    failure_window_max: Duration,
    /// Per fallback address: has it ever echoed our randomised question case?
    /// Once true a case-only mismatch from it is forged, never a retry cue.
    preserves_case: Vec<Arc<AtomicBool>>,
    /// Per fallback address: the one TCP connection queries share.
    tcp_links: Vec<Arc<TcpLink>>,
    /// Per plain address and question: at most [`QUESTION_SLOTS`] in flight.
    question_slots: Arc<QuestionSlots>,
    /// A pool of just `home_arpa_server`, for the queries that go there.
    home: Option<Box<UpstreamPool>>,
    /// Wakes the probe loop when the last pool reference is dropped.
    probe_stop: Arc<Notify>,
    #[cfg(feature = "conformance-adapter")]
    observer: observer::Failures,
}

impl Drop for UpstreamPool {
    fn drop(&mut self) {
        // `spawn_probes` holds a `Weak`, so notifying a stored permit lets a
        // sleeping loop observe the drop and exit instead of leaking a task.
        self.probe_stop.notify_one();
    }
}

impl UpstreamPool {
    /// Stops the background probe loop for this pool even while requests still
    /// hold references to it (config reload). The task exits on its next wakeup.
    pub fn stop_probes(&self) {
        self.probe_stop.notify_one();
    }
}

struct DohReply {
    raw: Vec<u8>,
    message: Message,
    age: u32,
    terminal: bool,
    latency: Duration,
    /// A well-formed reply carrying a failure RCODE (SERVFAIL, REFUSED...):
    /// the upstream is reachable, this question failed there.
    rcode_failure: bool,
}

struct PlainReply {
    raw: Vec<u8>,
    message: Message,
    terminal: bool,
}

impl UpstreamPool {
    /// Builds the warm HTTP/2 client. `spawn_probes` starts the immediate
    /// `. NS` probe pass, so the first real query does not pay for a TLS
    /// handshake. TLS session resumption stays on (rustls' default).
    pub fn new(cfg: &Config) -> Result<Self, reqwest::Error> {
        let client = || {
            crate::tls::client_builder()
                // Keep the pre-pool behaviour: never route DoH through an
                // environment proxy. A redirect is not followed (our policy;
                // RFC 8484 does not require it): the query only reaches the
                // configured URI, and a 3xx fails the attempt like any other
                // non-success status.
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .http2_keep_alive_interval(Duration::from_secs(30))
                .http2_keep_alive_timeout(Duration::from_secs(10))
                .http2_keep_alive_while_idle(true)
                .pool_idle_timeout(Duration::from_secs(90))
                .tcp_keepalive(Duration::from_secs(30))
                .connect_timeout(Duration::from_secs(5))
                .build()
        };
        let upstreams: Vec<Arc<Upstream>> =
            cfg.upstreams.iter().enumerate().map(|(index, url)| Arc::new(Upstream::new(index, url.clone()))).collect();
        let pool = Self {
            http: client()?,
            probe_http: client()?,
            upstreams,
            fallback: cfg.fallback.clone(),
            fallback_state: cfg.fallback.iter().map(|_| Arc::default()).collect(),
            hedge_ms: cfg.upstream_hedge_ms,
            strategy: cfg.upstream_strategy,
            timeout: Duration::from_secs(cfg.upstream_timeout_seconds),
            failover: failover_delay(cfg),
            upstream_0x20: cfg.upstream_0x20,
            source_ports_excluded: cfg.upstream_source_ports_excluded.clone().into(),
            trust_plain: cfg.trust_plain_upstreams,
            inflight: Semaphore::new(cfg.upstream_inflight_max.max(1)),
            transfers: Arc::new(Semaphore::new(TRANSFER_CONCURRENCY)),
            failures: Mutex::new(FailureMap::default()),
            failure_window: Duration::from_secs(cfg.failure_cache_seconds),
            failure_window_max: Duration::from_secs(cfg.failure_cache_seconds).max(FAILURE_WINDOW_FLOOR_MAX),
            preserves_case: cfg.fallback.iter().map(|_| Arc::new(AtomicBool::new(false))).collect(),
            tcp_links: cfg.fallback.iter().map(|addr| Arc::new(TcpLink::new(*addr))).collect(),
            question_slots: Arc::default(),
            home: cfg.home_arpa_server.map(|addr| Self::home_pool(cfg, addr)).transpose()?.map(Box::new),
            probe_stop: Arc::new(Notify::new()),
            #[cfg(feature = "conformance-adapter")]
            observer: observer::Failures::default(),
        };
        Ok(pool)
    }

    /// The operator named this server for the zone, so it is trusted like a
    /// primary: no scrub, and its answers are no downgrade.
    fn home_pool(cfg: &Config, addr: SocketAddr) -> Result<Self, reqwest::Error> {
        Self::new(&Config {
            upstreams: vec![],
            fallback: vec![addr],
            // Plaintext like any fallback: scrubbed unless the operator trusts
            // plain servers.
            trust_plain_upstreams: cfg.trust_plain_upstreams,
            home_arpa_server: None,
            upstream_timeout_seconds: cfg.upstream_timeout_seconds,
            upstream_hedge_ms: cfg.upstream_hedge_ms,
            failure_cache_seconds: cfg.failure_cache_seconds,
            upstream_inflight_max: cfg.upstream_inflight_max,
            upstream_0x20: cfg.upstream_0x20,
            upstream_source_ports_excluded: cfg.upstream_source_ports_excluded.clone(),
            ..Config::default()
        })
    }

    /// Resolves one raw client query. `None` is the SERVFAIL path: every
    /// attempt failed or the in-flight bound was hit.
    pub async fn exchange(&self, raw_query: &[u8], client_id: u16) -> Option<UpstreamAnswer> {
        self.exchange_from(raw_query, client_id, false).await
    }

    /// [`exchange`](Self::exchange) for a client that may have used TCP:
    /// plain upstreams then see the query over TCP first (RFC 5625 §4.2).
    pub async fn exchange_from(&self, raw_query: &[u8], client_id: u16, client_tcp: bool) -> Option<UpstreamAnswer> {
        let asked = wire::parse_query(raw_query)?;
        if let Some(home) = self.home.as_ref().filter(|_| wire::is_home_arpa_query(&asked)) {
            return Box::pin(home.exchange_from(raw_query, client_id, client_tcp)).await;
        }
        // The upstream sees our own request: the client's question under our
        // own OPT (RFC 6891 §§6.1.1, 7), never the client's other records.
        let rebuilt = wire::upstream_query(raw_query)?;
        let raw_query = &rebuilt[..];
        let view = wire::parse_query(raw_query)?;
        if view.id != client_id {
            return None;
        }
        let key = failure_key(&view)?;
        // The failure key is the shared cache key, so only a query that
        // could share it may read or write suppression state. An odd variant
        // (RD=0, options, extra sections) must not blackhole the name for
        // everyone else.
        let shared = crate::inflight::coalescible(&view);
        let _permit = self.inflight.try_acquire().ok()?;
        let deadline = Instant::now().checked_add(self.timeout)?;
        #[cfg(feature = "conformance-adapter")]
        let _armed = self.observer.arm();
        let mut tried = Vec::new();
        let failed = shared.then_some(&key[..]);
        match self.exchange_inner(raw_query, &view, deadline, client_tcp, failed, &mut tried).await {
            Ok(answer) => {
                if answer.terminal {
                    for server in tried {
                        self.clear_failure(&failure_tuple(&key, server));
                    }
                }
                Some(answer)
            }
            // Our own socket trouble, a query that was never sent or one every
            // eligible server has a live mark for is no new evidence.
            Err(Fail::Local) => None,
            Err(Fail::Remote | Fail::Unreachable) => {
                if shared {
                    for server in tried {
                        self.mark_failure(failure_tuple(&key, server));
                    }
                }
                None
            }
        }
    }

    /// Forwards `raw` unchanged and returns the reply unchanged: any change to
    /// a TSIG-signed message breaks it (RFC 5625 §4.5), and TKEY rides in
    /// Additional, which the normal path drops. The reply is only matched to
    /// the query; it is not normalized or cached. `None` means no reply.
    pub async fn exchange_verbatim(&self, raw: &[u8], client_tcp: bool) -> Option<Vec<u8>> {
        let view = wire::parse_query(raw)?;
        if let Some(home) = self.home.as_ref().filter(|_| wire::is_home_arpa_query(&view)) {
            return Box::pin(home.exchange_verbatim(raw, client_tcp)).await;
        }
        let _permit = self.inflight.try_acquire().ok()?;
        let deadline = Instant::now().checked_add(self.timeout)?;
        // As on the normal path, only a failure to connect opens the way to
        // plaintext, and a reachable upstream paused or benched for its
        // answers counts as reached.
        let now = Instant::now();
        let mut reached =
            self.upstreams.iter().any(|upstream| upstream.is_blocked(now) && !upstream.is_unreachable(now));
        for upstream in self.selection() {
            match doh_fetch(&self.http, &upstream, raw.to_vec(), deadline, false).await {
                Ok((body, _)) if verbatim_reply(&body, &view) => return Some(body),
                Ok(_) => reached = true,
                Err(error) => reached |= !error.transport,
            }
        }
        if reached {
            return None;
        }
        for addr in &self.fallback {
            if let Some(reply) = plain_verbatim(*addr, raw, &view, deadline).await {
                return Some(reply);
            }
        }
        None
    }

    /// Sends a zone transfer query to the first plain upstream that takes it
    /// and returns the stream the transfer comes back on. DoH has no way to
    /// carry a transfer, which is many messages.
    /// The upstream stream for a zone transfer, and the permit that counts it
    /// against [`TRANSFER_CONCURRENCY`]; hold the permit for the whole relay.
    /// A transfer waits for a free slot within the upstream timeout. `None`
    /// when no slot frees in time or no server answers.
    pub async fn open_transfer(&self, raw: &[u8]) -> Option<(TcpStream, tokio::sync::OwnedSemaphorePermit)> {
        let view = wire::parse_query(raw)?;
        if let Some(home) = self.home.as_ref().filter(|_| wire::is_home_arpa_query(&view)) {
            return Box::pin(home.open_transfer(raw)).await;
        }
        let deadline = Instant::now().checked_add(self.timeout)?;
        let permit = timeout_at(deadline, self.transfers.clone().acquire_owned()).await.ok()?.ok()?;
        for addr in &self.fallback {
            if let Some(stream) = tcp_send(*addr, raw, deadline).await {
                return Some((stream, permit));
            }
        }
        None
    }

    /// Upstream exchange permits still free (`upstream_inflight_max` minus
    /// the exchanges in flight).
    pub fn inflight_available(&self) -> usize {
        self.inflight.available_permits()
    }

    /// The upstream health snapshot, in configured order.
    pub fn health(&self) -> Vec<UpstreamHealth> {
        let now = Instant::now();
        self.upstreams
            .iter()
            .map(|upstream| {
                let state = upstream.state();
                UpstreamHealth {
                    index: upstream.index,
                    // The configured URL may carry userinfo or a query token;
                    // health snapshots are for display, so redact it.
                    url: crate::log::redact_url(&upstream.url),
                    healthy: state.open_until.is_none_or(|until| until <= now)
                        && state.paused_until.is_none_or(|until| until <= now),
                    ewma_us: state.ewma_us,
                    outstanding: state.outstanding,
                    wins: state.wins,
                    hedges: state.hedges,
                    last_error: state.last_error.clone(),
                }
            })
            .collect()
    }

    /// The win and hedge counters of every upstream, keyed by redacted URL.
    pub fn counters(&self) -> Vec<UpstreamCount> {
        self.upstreams
            .iter()
            .map(|upstream| {
                let state = upstream.state();
                UpstreamCount { url: crate::log::redact_url(&upstream.url), wins: state.wins, hedges: state.hedges }
            })
            .collect()
    }

    /// Adds saved counters to the upstreams still configured under the same
    /// redacted URL. Entries for removed upstreams are dropped. Two upstreams
    /// that redact to the same URL each take one saved entry, in order.
    pub fn restore_counters(&self, saved: &[UpstreamCount]) {
        let mut used = vec![false; saved.len()];
        for upstream in &self.upstreams {
            let url = crate::log::redact_url(&upstream.url);
            if let Some(at) = (0..saved.len()).find(|&i| !used[i] && saved[i].url == url) {
                used[at] = true;
                let mut state = upstream.state();
                state.wins = state.wins.saturating_add(saved[at].wins);
                state.hedges = state.hedges.saturating_add(saved[at].hedges);
            }
        }
    }

    /// Carries state over from the pool a reload replaces: the counters as a
    /// restart restores them, and the health (latency, circuit, `Retry-After`
    /// pause) of every upstream whose URL is unchanged.
    pub fn inherit(&self, old: &UpstreamPool) {
        self.restore_counters(&old.counters());
        for upstream in &self.upstreams {
            if let Some(previous) = old.upstreams.iter().find(|previous| previous.url == upstream.url) {
                let previous = previous.state().clone();
                let mut state = upstream.state();
                *state = State { outstanding: state.outstanding, wins: state.wins, hedges: state.hedges, ..previous };
            }
        }
    }

    /// Ready unless every configured upstream's circuit is open. No
    /// upstreams is a valid test/dev configuration and is ready.
    pub fn ready(&self) -> bool {
        let now = Instant::now();
        self.upstreams.is_empty() || self.upstreams.iter().any(|upstream| !upstream.is_benched(now))
    }

    /// Probes every upstream immediately and then once per 30 seconds,
    /// updating EWMA and circuits. The loop holds only a `Weak` reference, so
    /// dropping the pool (for example on a future config reload) stops it.
    pub fn spawn_probes(self: &Arc<Self>) -> JoinHandle<()> {
        let pool = Arc::downgrade(self);
        let stop = self.probe_stop.clone();
        tokio::spawn(async move {
            loop {
                let Some(pool) = pool.upgrade() else { break };
                pool.probe_all().await;
                drop(pool);
                tokio::select! {
                    _ = tokio::time::sleep(PROBE_INTERVAL) => {}
                    _ = stop.notified() => break,
                }
            }
        })
    }

    async fn probe_all(&self) {
        let mut set = tokio::task::JoinSet::new();
        for upstream in &self.upstreams {
            let http = self.probe_http.clone();
            let upstream = upstream.clone();
            let timeout = self.timeout;
            set.spawn(async move { probe_once(&http, &upstream, timeout).await });
        }
        while set.join_next().await.is_some() {}
    }

    fn selection(&self) -> Vec<Arc<Upstream>> {
        let now = Instant::now();
        let snapshot = |upstream: &Arc<Upstream>| {
            let state = upstream.state();
            (state.outstanding, state.ewma_us, upstream.clone())
        };
        let mut available: Vec<_> = self.upstreams.iter().filter(|u| !u.is_blocked(now)).map(snapshot).collect();
        if available.is_empty() {
            // A pause a client query drew may be about that query alone (a
            // front end can answer 503 with Retry-After for one broken name),
            // so it holds only while another upstream can serve: otherwise
            // one client could fail every other client's queries for a
            // minute. Until the probe confirms the pause, the upstream keeps
            // getting queries, and those it refuses fail.
            available = self.upstreams.iter().filter(|u| !u.is_benched(now)).map(snapshot).collect();
        }
        if available.is_empty() {
            // With a plain fallback configured it takes the query: retrying
            // an endpoint that may hang would spend the whole deadline, and
            // the probes still find its recovery.
            if !self.fallback.is_empty() && self.upstreams.iter().all(|u| u.is_unreachable(now)) {
                return Vec::new();
            }
            // A transient outage must be able to recover: when every circuit
            // is open, try the best one anyway. A `Retry-After` pause the
            // probe drew is the endpoint's own request and never overridden.
            available = self.upstreams.iter().filter(|u| !u.is_paused(now)).map(snapshot).collect();
        }
        match self.strategy {
            UpstreamStrategy::Fastest => {
                available.sort_unstable_by_key(|(outstanding, ewma, upstream)| (*outstanding, *ewma, upstream.index))
            }
            UpstreamStrategy::Ordered => available.sort_unstable_by_key(|(_, _, upstream)| upstream.index),
        }
        available.into_iter().map(|(_, _, upstream)| upstream).collect()
    }

    fn hedge_delay(&self, order: &[Arc<Upstream>]) -> Duration {
        if self.strategy == UpstreamStrategy::Ordered {
            // No hedge: the next provider sees the query only on a failure
            // or at the failover point.
            return self.failover;
        }
        if self.hedge_ms > 0 {
            return Duration::from_millis(self.hedge_ms);
        }
        let ewma_us = order.first().map_or(0, |upstream| upstream.state().ewma_us);
        Duration::from_millis((ewma_us.saturating_mul(2) / 1000).clamp(40, 80))
    }

    async fn exchange_inner(
        &self,
        raw: &[u8],
        view: &QueryView<'_>,
        deadline: Instant,
        client_tcp: bool,
        failed: Option<&[u8]>,
        tried: &mut Vec<usize>,
    ) -> Result<UpstreamAnswer, Fail> {
        // RFC 2308 §7.1: a failure is cached per server, so only servers with
        // a live mark for this question are left out.
        let marked = |server| failed.is_some_and(|key| self.failure_is_recent(&failure_tuple(key, server)));
        let selected = self.selection();
        let order: Vec<_> = selected.iter().filter(|upstream| !marked(upstream.index)).cloned().collect();
        if order.is_empty() && !selected.is_empty() {
            return Err(Fail::Local);
        }
        let hedge = self.hedge_delay(&order);
        let mut tasks = tokio::task::JoinSet::new();
        let mut launched = 0usize;
        let mut next_launch = Instant::now();
        let mut immediate = false;
        let mut postponed: Option<UpstreamAnswer> = None;
        // A reachable DoH upstream answered: a failure RCODE, an HTTP error
        // status or an invalid body. A `Retry-After` pause a client query
        // drew is such an answer too, even when it keeps the upstream out of
        // this query's selection.
        let now = Instant::now();
        // A server left out above failed this question, which must not open
        // the way to plaintext either.
        let mut reached = order.len() < selected.len()
            || self.upstreams.iter().any(|upstream| upstream.is_blocked(now) && !upstream.is_unreachable(now));

        while launched < order.len() || !tasks.is_empty() {
            if launched < order.len() && Instant::now() >= next_launch {
                let upstream = order[launched].clone();
                launched += 1;
                tried.push(upstream.index);
                if !immediate && !tasks.is_empty() {
                    upstream.state().hedges += 1;
                }
                immediate = false;
                let http = self.http.clone();
                let query = raw.to_vec();
                #[cfg(feature = "conformance-adapter")]
                observer::started();
                tasks.spawn(async move {
                    let mut attempt = Attempt::new(upstream.clone());
                    let exchange = doh_exchange(&http, &upstream, &query, deadline, false);
                    #[cfg(feature = "conformance-adapter")]
                    let exchange = observer::fault_after_send(exchange);
                    let result = exchange.await;
                    attempt.complete(&result);
                    (upstream.index, result)
                });
                next_launch = Instant::now().checked_add(hedge).unwrap_or(deadline);
            }
            if tasks.is_empty() && launched >= order.len() {
                break;
            }
            let wait = launched < order.len();
            tokio::select! {
                biased;
                _ = tokio::time::sleep_until(deadline) => break,
                joined = tasks.join_next(), if !tasks.is_empty() => {
                    match joined {
                        Some(Ok((_, Ok(reply)))) if reply.rcode_failure => {
                            reached = true;
                            immediate = true;
                            next_launch = Instant::now();
                        }
                        Some(Ok((index, Ok(reply)))) => {
                            let answer = self.finish(reply.raw, reply.message, Some(index), reply.age, reply.terminal, view.id);
                            if reply.terminal {
                                if let Some(upstream) = self.upstreams.get(index) {
                                    upstream.state().wins += 1;
                                }
                                tasks.abort_all();
                                return Ok(answer);
                            }
                            if postponed.is_none() {
                                postponed = Some(answer);
                            }
                        }
                        Some(Ok((index, Err(error)))) => {
                            // An HTTP-level failure came from a reachable
                            // endpoint and may depend on the question, unless
                            // the endpoint is benched (its circuit opened by
                            // probes or transport errors, or a Retry-After
                            // pause the probe drew): then the endpoint itself
                            // is down.
                            let unreachable = self
                                .upstreams
                                .get(index)
                                .is_some_and(|upstream| upstream.is_unreachable(Instant::now()));
                            reached |= !error.transport && !unreachable;
                            immediate = true;
                            next_launch = Instant::now();
                        }
                        Some(Err(_)) => {
                            // Advance to the next upstream without waiting.
                            immediate = true;
                            next_launch = Instant::now();
                        }
                        None => {}
                    }
                }
                _ = tokio::time::sleep_until(next_launch), if wait => {}
            }
        }
        tasks.abort_all();
        drop(tasks);
        let doh_sent = launched > 0;
        if Instant::now() >= deadline {
            return postponed.ok_or(Fail::Remote);
        }
        // Plaintext only after every DoH attempt failed at the transport
        // level. A DNS-level answer, even a failure or an incomplete one, an
        // HTTP 4xx or 5xx and an invalid body end the resolution here: a
        // plaintext retry would bypass the DoH upstream's validation and
        // filtering, and a client choosing such a name would choose the
        // downgrade.
        if reached || postponed.is_some() {
            // Nothing sent (every upstream paused) is no upstream failure:
            // no RFC 9520 marker for a question no upstream saw.
            return postponed.ok_or(if doh_sent { Fail::Remote } else { Fail::Local });
        }

        // All DoH attempts are exhausted. Race the plain fallbacks like DoH:
        // the next one starts after the hedge delay or at once on failure.
        // They share the one absolute deadline. A fallback found unreachable
        // recently is skipped while another is not.
        let now = Instant::now();
        let usable = |i: &usize| {
            let state = self.fallback_state[*i].lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            state.skip_until.is_none_or(|until| until <= now)
        };
        let mut order: Vec<usize> = (0..self.fallback.len()).filter(usable).collect();
        if order.is_empty() {
            order = (0..self.fallback.len()).collect();
        }
        let first_plain = self.upstreams.len();
        order.retain(|index| !marked(first_plain + index));
        if order.is_empty() && !self.fallback.is_empty() {
            return Err(Fail::Local);
        }
        // The retransmission of an earlier address must not overtake the first
        // try of a later one: RFC 1035 §4.2.1 tries the other server
        // addresses before repeating a query to one. Every attempt learns
        // this instant, so its first resend waits for the whole first cycle.
        let margin = Duration::from_millis(50);
        let launch_span = hedge.saturating_mul(u32::try_from(order.len().saturating_sub(1)).unwrap_or(u32::MAX));
        let retry_after =
            Instant::now().checked_add(launch_span).and_then(|at| at.checked_add(margin)).unwrap_or(deadline);
        let mut tasks = tokio::task::JoinSet::new();
        let invalid = Arc::new(Notify::new());
        let mut launched = 0usize;
        let mut next_launch = Instant::now();
        let (mut saw_local, mut saw_remote) = (false, false);
        while launched < order.len() || !tasks.is_empty() {
            if launched < order.len() && Instant::now() >= next_launch {
                let index = order[launched];
                tried.push(first_plain + index);
                let addr = self.fallback[index];
                let preserves_case = self.preserves_case[index].clone();
                let link = self.tcp_links[index].clone();
                launched += 1;
                let (query, randomize) = (raw.to_vec(), self.upstream_0x20);
                let excluded = self.source_ports_excluded.clone();
                // Scrub plain replies unless the operator opted in to trusting
                // plain servers. DoH replies are always scrubbed.
                let scrub = !self.trust_plain;
                let invalid = invalid.clone();
                let health = self.fallback_state[index].clone();
                let slots = self.question_slots.clone();
                let attempt = async move {
                    // A query that never got a slot was never sent: no
                    // evidence about the server.
                    let Some(_slot) = slots.acquire(addr, &query, deadline).await else {
                        return Err(Fail::Local);
                    };
                    let result = plain_exchange(
                        addr,
                        &excluded,
                        &link,
                        &query,
                        randomize,
                        deadline,
                        retry_after,
                        client_tcp,
                        &invalid,
                        &preserves_case,
                        scrub,
                        &health,
                    )
                    .await;
                    FallbackState::record(&health, &result);
                    result
                };
                // Each request this attempt sends is counted where it is sent.
                #[cfg(feature = "conformance-adapter")]
                let attempt = observer::inherit(attempt);
                tasks.spawn(attempt);
                next_launch = Instant::now().checked_add(hedge).unwrap_or(deadline);
            }
            let wait = launched < order.len();
            tokio::select! {
                biased;
                _ = tokio::time::sleep_until(deadline) => {
                    saw_remote = true;
                    break;
                }
                joined = tasks.join_next(), if !tasks.is_empty() => match joined {
                    Some(Ok(Ok(reply))) if reply.terminal => {
                        tasks.abort_all();
                        if !self.trust_plain {
                            plain_answer_served();
                        }
                        return Ok(self.finish(reply.raw, reply.message, None, 0, true, view.id));
                    }
                    Some(Ok(Ok(reply))) => {
                        if postponed.is_none() {
                            postponed = Some(self.finish(reply.raw, reply.message, None, 0, false, view.id));
                        }
                        next_launch = Instant::now();
                    }
                    Some(Ok(Err(Fail::Local))) => {
                        saw_local = true;
                        next_launch = Instant::now();
                    }
                    _ => {
                        saw_remote = true;
                        next_launch = Instant::now();
                    }
                },
                _ = invalid.notified() => {
                    saw_remote = true;
                    next_launch = Instant::now();
                }
                _ = tokio::time::sleep_until(next_launch), if wait => {}
            }
        }
        tasks.abort_all();
        // Known limit: DoH-side local errors (reqwest) are not classified; only
        // the plaintext sockets we open ourselves are.
        // Only a plain reply can be postponed here: a DoH one returned above.
        if postponed.is_some() && !self.trust_plain {
            plain_answer_served();
        }
        // A query that never left (every upstream paused by the probe, no
        // fallback) failed nowhere: like our own socket trouble it sets no
        // RFC 9520 failure marker.
        let unsent = !doh_sent && launched == 0;
        postponed.ok_or(if (saw_local || unsent) && !saw_remote { Fail::Local } else { Fail::Remote })
    }

    fn finish(
        &self,
        mut raw: Vec<u8>,
        mut message: Message,
        upstream_index: Option<usize>,
        age: u32,
        terminal: bool,
        client_id: u16,
    ) -> UpstreamAnswer {
        if raw.len() >= 2 {
            raw[0..2].copy_from_slice(&client_id.to_be_bytes());
        }
        message.metadata.id = client_id;
        UpstreamAnswer { raw, upstream_index, age, terminal, message }
    }

    fn failure_is_recent(&self, key: &[u8]) -> bool {
        let failures = self.failures.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        match failures.map.get(key) {
            Some((at, window)) => at.elapsed() < *window,
            None => false,
        }
    }

    fn mark_failure(&self, key: Box<[u8]>) {
        let mut failures = self.failures.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let now = Instant::now();
        #[cfg(feature = "conformance-adapter")]
        let (capacity, byte_limit) = self.observer.limits();
        #[cfg(not(feature = "conformance-adapter"))]
        let (capacity, byte_limit) = (FAILURE_CAPACITY, FAILURE_BYTES);
        // An expired marker is kept so the next failure doubles its window;
        // one idle for long enough starts over.
        let window = match failures.map.get(&key) {
            Some((at, window)) if at.elapsed() < *window + self.failure_window_max => {
                (*window * 2).min(self.failure_window_max)
            }
            _ => self.failure_window,
        };
        #[cfg(feature = "conformance-adapter")]
        let replaced_expired = failures.map.get(&key).is_some_and(|(at, window)| at.elapsed() >= *window);
        let stored = failures.insert(key, (now, window), capacity, byte_limit);
        #[cfg(feature = "conformance-adapter")]
        self.observer.inserted(stored, replaced_expired);
        #[cfg(not(feature = "conformance-adapter"))]
        let _ = stored;
    }

    fn clear_failure(&self, key: &[u8]) {
        self.failures.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).remove(key);
    }
}

/// When `ordered` asks the next upstream: half the attempt budget, at most
/// 1 s and at most half the UDP discard limit, so the next upstream's answer
/// still reaches a UDP client.
fn failover_delay(cfg: &Config) -> Duration {
    let delay = (Duration::from_secs(cfg.upstream_timeout_seconds) / 2).min(FAILOVER_MAX);
    cfg.udp_discard_limit().map_or(delay, |limit| delay.min(limit / 2))
}

/// RFC 9520 failure identity: the cache-key context (name, type, class and the
/// EDNS/DO/CD/query-AD flags) so a failure in one DNSSEC context never
/// suppresses an otherwise unrelated query.
fn failure_key(view: &QueryView<'_>) -> Option<Box<[u8]>> {
    let mut key = [0u8; wire::MIN_CANONICAL_BUFFER];
    let len = wire::canonical_key(view, &mut key)?;
    Some(key[..len].into())
}

/// The key of one failure mark: the question and the server, numbered DoH
/// upstreams first, then plain fallbacks (RFC 2308 §7.1).
fn failure_tuple(key: &[u8], server: usize) -> Box<[u8]> {
    [key, &(server as u32).to_be_bytes()].concat().into()
}

fn record_success(upstream: &Upstream, latency: Duration) {
    let sample = latency.as_micros().min(u64::MAX as u128) as u64;
    let sample = sample.max(1);
    let mut state = upstream.state();
    state.ewma_us = if state.ewma_us == 0 { sample } else { (state.ewma_us.saturating_mul(4) + sample) / 5 };
    state.failures = 0;
    state.open_until = None;
    state.unreachable = false;
    state.last_error = None;
}

/// `30s * 2^(failures-3)`, capped at the 300 s of RFC 2308 §7.2.
fn cooldown(failures: u32) -> Duration {
    let exponent = failures.saturating_sub(3).min(5);
    Duration::from_secs(30u64.saturating_mul(1u64 << exponent).min(300))
}

fn record_failure(upstream: &Upstream, error: &str, transport: bool) {
    let mut state = upstream.state();
    state.failures = state.failures.saturating_add(1);
    state.unreachable = transport;
    state.last_error = Some(error.to_string());
    if state.failures >= 3 {
        state.open_until = Instant::now().checked_add(cooldown(state.failures));
    }
}

fn probe_query() -> Vec<u8> {
    let mut message = Message::new(0, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(Name::from_ascii(".").unwrap(), RecordType::NS));
    message.to_vec().unwrap()
}

async fn probe_once(http: &reqwest::Client, upstream: &Upstream, timeout: Duration) {
    // No probe while the upstream asked the probe itself for quiet. A pause
    // a client query drew does not stop it: the probe asks one fixed name, so
    // it is what tells an endpoint-wide pause from a question-dependent one.
    let probe_paused = {
        let state = upstream.state();
        state.pause_probed && state.paused_until.is_some_and(|until| until > Instant::now())
    };
    if probe_paused {
        return;
    }
    let query = probe_query();
    let Some(deadline) = Instant::now().checked_add(timeout) else {
        record_failure(upstream, "timeout out of range", false);
        return;
    };
    // The probe asks one fixed name, so every failure, a timeout included,
    // is evidence about the upstream rather than about a client's question.
    // Every working resolver answers `. NS`, so a failure RCODE fails the probe.
    match doh_exchange(http, upstream, &query, deadline, true).await {
        Ok(reply) if !reply.rcode_failure => record_success(upstream, reply.latency),
        Ok(reply) => {
            record_failure(upstream, &format!("probe answered {}", reply.message.metadata.response_code), false)
        }
        Err(error) => record_failure(upstream, &error.message, error.transport),
    }
}

/// `Retry-After` (RFC 9110 §10.2.3) as a wait: delay-seconds or an
/// HTTP-date, which is measured from now (a date in the past waits not at all).
/// Anything else is ignored and the ordinary backoff applies. The caller caps
/// the wait.
fn retry_after(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    let value = headers.get(reqwest::header::RETRY_AFTER)?.to_str().ok()?.trim();
    if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
        // Saturate: a 40-digit value is "a very long time", which the cap clamps.
        return Some(Duration::from_secs(value.parse().unwrap_or(u64::MAX)));
    }
    let date = httpdate::parse_http_date(value).ok()?;
    Some(date.duration_since(std::time::SystemTime::now()).unwrap_or_default())
}

/// Strict HTTP `Age` (RFC 9111): absent is zero, while a non-numeric,
/// negative, overflowing or repeated value rejects the upstream result.
fn parse_age(headers: &reqwest::header::HeaderMap) -> Result<u32, String> {
    let mut values = headers.get_all(reqwest::header::AGE).iter();
    let Some(value) = values.next() else { return Ok(0) };
    if values.next().is_some() {
        return Err("multiple age headers".into());
    }
    let value = value.to_str().map_err(|_| "invalid age")?.trim();
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("invalid age".into());
    }
    value.parse::<u32>().map_err(|_| "invalid age".into())
}

/// Validates an upstream message and returns the bytes to relay with a
/// hickory view of them (see [`wire::normalize_upstream`] and
/// [`wire::hickory_view`]). `None` is invalid wire: never relayed.
fn parse_upstream(raw: &[u8]) -> Option<(Vec<u8>, Message)> {
    let relayed = wire::normalize_upstream(raw)?.into_owned();
    let message = wire::hickory_view(&relayed)?;
    Some((relayed, message))
}

/// Applies [`wire::scrub_reply`] to a validated reply. `None` means the reply
/// is invalid: an off-chain Answer owner, or a rewrite that no longer parses.
fn scrubbed(relayed: Vec<u8>, message: Message) -> Option<(Vec<u8>, Message)> {
    match wire::scrub_reply(&relayed)? {
        None => Some((relayed, message)),
        Some(rewritten) => parse_upstream(&rewritten),
    }
}

fn with_id(raw: &[u8], id: u16) -> Vec<u8> {
    let mut out = raw.to_vec();
    if out.len() >= 2 {
        out[0..2].copy_from_slice(&id.to_be_bytes());
    }
    out
}

/// A failed DoH exchange. `transport` marks a failure of the endpoint itself,
/// whatever the question: no connection could be made (TCP connect or TLS).
/// Only those count against the upstream's circuit for a client query (see
/// [`Attempt`]). Any HTTP status, a wrong content type, an invalid body and a
/// request reset after it was sent came from a reachable endpoint and may
/// depend on the question asked.
struct DohError {
    message: String,
    transport: bool,
}

impl From<String> for DohError {
    fn from(message: String) -> Self {
        Self { message, transport: false }
    }
}

impl From<&str> for DohError {
    fn from(message: &str) -> Self {
        message.to_string().into()
    }
}

/// One DoH POST: `body` out, the reply's bytes and `Age` back. The caller
/// validates the reply.
async fn doh_fetch(
    http: &reqwest::Client,
    upstream: &Upstream,
    body: Vec<u8>,
    deadline: Instant,
    probe: bool,
) -> Result<(Vec<u8>, u32), DohError> {
    let request = http
        .post(&upstream.url)
        .header(reqwest::header::CONTENT_TYPE, "application/dns-message")
        .header(reqwest::header::ACCEPT, "application/dns-message")
        .body(body);
    let response = match timeout_at(deadline, request.send()).await {
        // No response headers before the deadline. For the probe this means
        // the endpoint cannot be reached (a dropped port 443 hangs in
        // connect): it asks one fixed name, so no client can make it hang.
        // For a client query it may be about the name, so it is not counted.
        Err(_) => return Err(DohError { message: "timeout".into(), transport: probe }),
        // Only a failure to connect (TCP, TLS) is about the endpoint. A
        // reset after the request was sent (an HTTP/2 RST_STREAM, a reused
        // connection closed under it) can be the front end's answer to this
        // one name; the probes confirm an endpoint-wide one.
        Ok(Err(error)) => return Err(DohError { message: request_error(&error), transport: error.is_connect() }),
        Ok(Ok(response)) => response,
    };
    if !response.status().is_success() {
        let status = response.status().as_u16();
        if matches!(status, 429 | 503) {
            if let Some(wait) = retry_after(response.headers()) {
                upstream.pause(wait, probe);
            }
        }
        return Err(format!("http status {status}").into());
    }
    let content_type =
        response.headers().get(reqwest::header::CONTENT_TYPE).and_then(|value| value.to_str().ok()).unwrap_or("");
    if !content_type.split(';').next().unwrap_or("").trim().eq_ignore_ascii_case("application/dns-message") {
        return Err("bad content type".into());
    }
    let age = parse_age(response.headers())?;
    let mut response = response;
    let mut body = Vec::new();
    loop {
        let chunk = match timeout_at(deadline, response.chunk()).await {
            Err(_) => return Err("timeout".into()),
            Ok(Err(error)) => return Err(request_error(&error).into()),
            Ok(Ok(chunk)) => chunk,
        };
        let Some(chunk) = chunk else { break };
        if body.len().saturating_add(chunk.len()) > MAX_DNS_MESSAGE {
            return Err("response too large".into());
        }
        body.extend_from_slice(&chunk);
    }
    Ok((body, age))
}

async fn doh_exchange(
    http: &reqwest::Client,
    upstream: &Upstream,
    raw_query: &[u8],
    deadline: Instant,
    probe: bool,
) -> Result<DohReply, DohError> {
    let sent = with_id(raw_query, 0);
    let view = wire::parse_query(&sent).ok_or("invalid query")?;
    let started = Instant::now();
    let (body, age) = doh_fetch(http, upstream, sent.clone(), deadline, probe).await?;
    let (body, message, terminal, rcode_failure) = validate_response(&body, &view, false)?;
    // The relay and the cache both derive TTLs from the wire walk. An aged
    // answer that cannot be walked cannot be aged, so reject it instead of
    // relaying TTLs the upstream already considers older.
    if age > 0 && wire::ttl_offsets(&body).is_none() {
        return Err("unageable response".into());
    }
    Ok(DohReply { raw: body, message, age, terminal, latency: started.elapsed(), rcode_failure })
}

/// reqwest's `Display` appends the full request URL, including userinfo and the
/// query string. Replace that exact URL with its redacted form so a token
/// never reaches `last_error` or a log line.
fn request_error(error: &reqwest::Error) -> String {
    let message = error.to_string();
    match error.url() {
        Some(url) => message.replace(url.as_str(), &crate::log::redact_url(url.as_str())),
        None => message,
    }
}

/// RCODEs that end one attempt without being a usable answer: everything
/// but NOERROR, NXDOMAIN and YXDOMAIN (RFC 6672 DNAME overflow). FORMERR,
/// SERVFAIL, NOTIMP, REFUSED, hop-scoped BADVERS/BADCOOKIE, update/TSIG codes
/// and unassigned values are not answers to a QUERY (as unbound and Knot).
fn unusable_rcode(rcode: ResponseCode) -> bool {
    !matches!(u16::from(rcode), 0 | 3 | 6)
}

/// The reply, whether it is terminal and whether it carries a failure RCODE.
/// A failure RCODE from a reachable DoH upstream is a DNS-level answer, not a
/// transport failure.
fn validate_response(body: &[u8], sent: &QueryView<'_>, exact: bool) -> Result<(Vec<u8>, Message, bool, bool), String> {
    // DoH: the HTTP exchange correlates the response; the DNS ID is not checked.
    let matched =
        if exact { wire::question_matches_exact(body, sent) } else { wire::question_matches_any_id(body, sent) };
    if !matched {
        return Err("question mismatch".into());
    }
    let (relayed, message) = parse_upstream(body).ok_or("unparseable response")?;
    if unsolicited_co(&relayed, sent) {
        return Err("unsolicited compact answers".into());
    }
    if message.metadata.message_type != MessageType::Response {
        return Err("not a response".into());
    }
    if message.metadata.truncation {
        return Err("truncated response".into());
    }
    if unusable_rcode(message.metadata.response_code) {
        return Ok((relayed, message, false, true));
    }
    let (relayed, message) = scrubbed(relayed, message).ok_or("off-chain answer")?;
    let qname = &sent.qname_lower[..sent.qname_len as usize];
    // A reply whose header and sections contradict each other is invalid.
    let terminal = wire::terminal_answer(&relayed, qname, sent.qtype).ok_or("contradictory response")?;
    Ok((relayed, message, terminal, false))
}

/// RFC 9824 §5.1: a Compact Answers response to a request that did
/// not ask for it is a failed attempt, never relayed or cached.
fn unsolicited_co(relayed: &[u8], sent: &QueryView<'_>) -> bool {
    sent.edns_flags & wire::CO_FLAG == 0
        && wire::response_opt_flags(relayed).is_some_and(|flags| flags & wire::CO_FLAG != 0)
}

/// Toggles the ASCII case of some question letters. Length and letters are
/// preserved, so the upstream sees the same name. `end` is the end offset of
/// the encoded question name.
fn randomize_case(query: &mut [u8], end: usize) {
    let mut pos = 12;
    while pos < end {
        let Some(&len) = query.get(pos) else { return };
        let len = len as usize;
        let Some(label) = query.get_mut(pos + 1..pos + 1 + len) else {
            return;
        };
        for byte in label {
            if byte.is_ascii_alphabetic() && rand::random::<bool>() {
                *byte = if byte.is_ascii_lowercase() { byte.to_ascii_uppercase() } else { byte.to_ascii_lowercase() };
            }
        }
        pos += 1 + len;
    }
}

fn plain_question_matches(reply: &[u8], sent: &QueryView<'_>, exact: bool) -> bool {
    wire::header(reply).is_some_and(|head| head.is_response())
        && if exact { wire::question_matches_exact(reply, sent) } else { wire::question_matches(reply, sent) }
}

/// The largest UDP reply the sent query invited (RFC 6891 §6.2.3).
fn udp_limit(sent: &QueryView<'_>) -> usize {
    if sent.edns_present {
        usize::from(sent.edns_payload.max(512))
    } else {
        512
    }
}

/// A datagram with our ID and QR=1 from the queried endpoint whose body is
/// not a DNS message is an invalid response: the pool advances to the next
/// endpoint at once (`invalid` wakes the hedge scheduler) while this attempt keeps
/// listening until the deadline for a later valid datagram. One with
/// another ID, or any well-formed message for another question, is discarded
/// and the attempt keeps waiting (RFC 5452 §9.1).
fn plain_invalid_message(reply: &[u8], sent: &QueryView<'_>) -> bool {
    wire::header(reply).is_some_and(|head| head.is_response() && head.id == sent.id)
        && wire::hickory_view(reply).is_none()
}

/// The upstream transaction ID. The adapter feature can feed boundary values
/// to this one draw site; production always uses the CSPRNG.
fn draw_id() -> u16 {
    #[cfg(feature = "conformance-adapter")]
    if let Some(id) = observer::injected_id() {
        return id;
    }
    rand::random::<u16>()
}

/// A random source port from [`crate::config::SOURCE_PORTS`] that is not in
/// `excluded`. `excluded` holds sorted, disjoint ranges, clipped to that
/// range, so the draw is uniform over the ports left and never spins on
/// rejected ones. `None` means an unvalidated list covers the whole range.
fn draw_source_port(excluded: &[(u16, u16)]) -> Option<u16> {
    let first = u32::from(*crate::config::SOURCE_PORTS.start());
    let last = u32::from(*crate::config::SOURCE_PORTS.end());
    let mut allowed = last - first + 1;
    for &(range_first, range_last) in excluded {
        let (low, high) = (u32::from(range_first).max(first), u32::from(range_last).min(last));
        if low <= high {
            allowed = allowed.saturating_sub(high - low + 1);
        }
    }
    if allowed == 0 {
        return None;
    }
    let mut pick = rand::random_range(0..allowed);
    let mut cursor = first;
    for &(range_first, range_last) in excluded {
        let (low, high) = (u32::from(range_first).max(first), u32::from(range_last).min(last));
        if low > high || high < cursor {
            continue;
        }
        // Config::validate merges ranges; a direct library caller could pass
        // overlapping ones, and this must still not underflow.
        let low = low.max(cursor);
        let gap = low - cursor;
        if pick < gap {
            return u16::try_from(cursor + pick).ok();
        }
        pick -= gap;
        cursor = high + 1;
    }
    u16::try_from(cursor + pick).ok()
}

/// A fresh UDP socket with a random source port from 1024 and up,
/// connected to `addr`. Both steps happen before any packet leaves, so any
/// error here is ours. A port another socket holds is redrawn a bounded
/// number of times; an attempt that cannot bind fails instead of falling
/// back to an ephemeral port, and every attempt gets a socket of its own.
async fn connected_socket(addr: SocketAddr, excluded: &[(u16, u16)]) -> std::io::Result<UdpSocket> {
    let wildcard = if addr.is_ipv4() { IpAddr::V4(Ipv4Addr::UNSPECIFIED) } else { IpAddr::V6(Ipv6Addr::UNSPECIFIED) };
    let mut last = std::io::Error::from(std::io::ErrorKind::AddrInUse);
    for _ in 0..SOURCE_PORT_TRIES {
        let Some(port) = draw_source_port(excluded) else { return Err(last) };
        match UdpSocket::bind(SocketAddr::new(wildcard, port)).await {
            Ok(socket) => {
                socket.connect(addr).await?;
                return Ok(socket);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => last = error,
            Err(error) => return Err(error),
        }
    }
    Err(last)
}

/// Receives from the un-randomised retry socket, or never when there is none.
async fn recv_retry(
    retry: &Option<(UdpSocket, Vec<u8>)>,
    buffer: &mut [u8],
    deadline: Instant,
) -> Result<std::io::Result<usize>, tokio::time::error::Elapsed> {
    match retry {
        Some((socket, _)) => timeout_at(deadline, socket.recv(buffer)).await,
        None => std::future::pending().await,
    }
}

/// The shared tail of a plain reply (UDP or TCP): the plaintext scrub unless
/// `trust_plain_upstreams` (`scrub`), AD cleared (an unauthenticated transport
/// cannot vouch for validation), terminal classification. A reply the scrub
/// rejects is a failed attempt and wakes the hedge scheduler like any invalid
/// message.
fn finish_plain(
    relayed: Vec<u8>,
    message: Message,
    sent: &QueryView<'_>,
    invalid: &Notify,
    scrub: bool,
) -> Result<PlainReply, Fail> {
    // A contradictory reply is a failed attempt like any invalid message.
    let classify = |raw: &[u8]| {
        let qname = &sent.qname_lower[..sent.qname_len as usize];
        wire::terminal_answer(raw, qname, sent.qtype).ok_or_else(|| {
            invalid.notify_one();
            Fail::Remote
        })
    };
    if !scrub {
        let mut raw = relayed;
        wire::clear_ad(&mut raw);
        let terminal = classify(&raw)?;
        return Ok(PlainReply { raw, message, terminal });
    }
    let Some((mut raw, message)) = scrubbed(relayed, message) else {
        invalid.notify_one();
        return Err(Fail::Remote);
    };
    wire::clear_ad(&mut raw);
    let terminal = classify(&raw)?;
    Ok(PlainReply { raw, message, terminal })
}

/// RFC 5452 §5: several queries for one question outstanding at once make a
/// birthday attack on a plaintext upstream easier. Context variants of a name
/// (DO, CD, EDNS options) are different cache keys, so they do not coalesce;
/// beyond this many in flight to one address they wait for a slot.
const QUESTION_SLOTS: usize = 2;

/// In-flight plaintext queries per (address, name, type, class). An entry
/// lives only while a query for it is in flight or waiting.
#[derive(Default)]
struct QuestionSlots(Mutex<HashMap<QuestionKey, Arc<Semaphore>>>);

/// The plain address, then the lowercase question name, QTYPE and QCLASS.
type QuestionKey = (SocketAddr, Vec<u8>);

struct QuestionSlot<'a> {
    slots: &'a QuestionSlots,
    key: QuestionKey,
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl QuestionSlots {
    /// Waits for a slot until `deadline`; `None` for an unparsable query or no
    /// slot in time.
    async fn acquire(&self, addr: SocketAddr, query: &[u8], deadline: Instant) -> Option<QuestionSlot<'_>> {
        let view = wire::parse_query(query)?;
        let mut question = view.qname_lower[..usize::from(view.qname_len)].to_vec();
        question.extend_from_slice(&view.qtype.to_be_bytes());
        question.extend_from_slice(&view.qclass.to_be_bytes());
        let key = (addr, question);
        let semaphore = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entry(key.clone())
            .or_insert_with(|| Arc::new(Semaphore::new(QUESTION_SLOTS)))
            .clone();
        let mut slot = QuestionSlot { slots: self, key, permit: None };
        slot.permit = Some(timeout_at(deadline, semaphore.acquire_owned()).await.ok()?.ok()?);
        Some(slot)
    }
}

impl Drop for QuestionSlot<'_> {
    fn drop(&mut self) {
        drop(self.permit.take());
        let mut map = self.slots.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        // Unused once only the map holds it: no query in flight or waiting
        // (a waiter holds a clone).
        if map.get(&self.key).is_some_and(|semaphore| Arc::strong_count(semaphore) == 1) {
            map.remove(&self.key);
        }
    }
}

#[allow(clippy::too_many_arguments)] // one call site; a struct would only rename them
async fn plain_exchange(
    addr: SocketAddr,
    excluded: &[(u16, u16)],
    link: &TcpLink,
    raw_query: &[u8],
    randomize: bool,
    deadline: Instant,
    retry_after: Instant,
    tcp_first: bool,
    invalid: &Notify,
    preserves_case: &AtomicBool,
    scrub: bool,
    health: &Mutex<FallbackState>,
) -> Result<PlainReply, Fail> {
    let mut query = with_id(raw_query, draw_id());
    let (compressed, question_end) = {
        let view = wire::parse_query(&query).ok_or("invalid query")?;
        (view.qname_compressed, 12 + view.qname_wire.len())
    };
    if randomize && !compressed {
        randomize_case(&mut query, question_end);
    }
    let sent = wire::parse_query(&query).ok_or("invalid query")?;
    let exact = randomize && !sent.qname_compressed;
    // A reply echoing at least one upper-case letter proves the upstream
    // preserves case; an all-lower-case draw proves nothing.
    let case_probe = exact && sent.qname_wire.iter().any(u8::is_ascii_uppercase);
    if tcp_first {
        // A refused or silent TCP port still leaves UDP: only try TCP first.
        // Known limit: a TCP timeout spends the whole attempt budget; per-hop
        // splitting if slow TCP-less upstreams matter.
        if let Ok(reply) = tcp_exchange(link, &query, &sent, deadline, invalid, scrub).await {
            return Ok(reply);
        }
    }
    let socket = connected_socket(addr, excluded).await.map_err(|_| Fail::Local)?;
    #[cfg(feature = "conformance-adapter")]
    observer::started();
    let sent_at = Instant::now();
    socket.send(&query).await.map_err(|error| io_fail(&error))?;
    let mut buffer = vec![0u8; MAX_DNS_MESSAGE];
    let mut retry_buffer = Vec::new();
    // The un-randomised retry (a case-normalising upstream) leaves
    // from a fresh socket and ID, so a forged case-only mismatch never
    // exposes the first query's source port. It is sent once, and never to an
    // upstream that has already echoed our case.
    let mut retry: Option<(UdpSocket, Vec<u8>)> = None;
    // A silent upstream gets the same datagram once more if the budget allows
    // (RFC 1035 §4.2.1), but not before every configured address has had its
    // first try (`retry_after`). The same ID and socket mean either reply matches.
    let interval = retransmit_interval(health.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).rtt_us);
    let mut resend_at = Instant::now().checked_add(interval).map(|at| at.max(retry_after)).filter(|at| *at < deadline);
    let mut resent = false;
    // RFC 9715 §3.2: a requestor should eventually try an alternative
    // transport. A path that drops UDP never gets a TCP attempt otherwise.
    // It starts one interval after the resend, so UDP, the resend
    // and TCP are spaced evenly: with the default 5 s budget at 0 s, 2 s and
    // 4 s, which leaves TCP the last second (its handshake plus one round
    // trip). A longer interval (a slow path) leaves no room and TCP is
    // skipped. UDP keeps listening meanwhile, so a late reply still wins.
    let mut tcp_at: Option<Instant> = None;
    let mut tcp: Option<TcpAttempt<'_>> = None;
    loop {
        let (received, via_retry) = tokio::select! {
            r = timeout_at(deadline, socket.recv(&mut buffer)) => (r, false),
            r = recv_retry(&retry, &mut retry_buffer, deadline) => (r, true),
            () = tokio::time::sleep_until(resend_at.unwrap_or(deadline)), if resend_at.is_some() && retry.is_none() => {
                resend_at = None;
                resent = true;
                tcp_at = Instant::now().checked_add(interval).filter(|at| *at < deadline);
                #[cfg(feature = "conformance-adapter")]
                observer::started();
                socket.send(&query).await.map_err(|error| io_fail(&error))?;
                continue;
            }
            () = tokio::time::sleep_until(tcp_at.unwrap_or(deadline)), if tcp_at.is_some() && tcp.is_none() && retry.is_none() => {
                tcp_at = None;
                tcp = Some(Box::pin(tcp_exchange(link, &query, &sent, deadline, invalid, scrub)));
                continue;
            }
            r = async {
                match tcp.as_mut() {
                    Some(attempt) => attempt.await,
                    None => std::future::pending().await,
                }
            }, if tcp.is_some() => {
                // A failed TCP attempt leaves UDP waiting for the deadline.
                if let Ok(reply) = r {
                    return Ok(reply);
                }
                tcp = None;
                continue;
            }
        };
        let received = match received {
            Err(_) => return Err(Fail::Remote),
            Ok(Err(error)) => return Err(io_fail(&error)),
            Ok(Ok(received)) => received,
        };
        let reply = if via_retry { &retry_buffer[..received] } else { &buffer[..received] };
        let retry_query = retry.as_ref().map(|(_, query)| query.as_slice());
        let retry_view = if via_retry { retry_query.and_then(wire::parse_query) } else { None };
        let (context, context_query): (&QueryView<'_>, &[u8]) = match (&retry_view, retry_query) {
            (Some(view), Some(query)) => (view, query),
            _ if via_retry => continue,
            _ => (&sent, &query),
        };
        let context_exact = exact && !via_retry;
        if !plain_question_matches(reply, context, context_exact) {
            if !via_retry
                && exact
                && retry.is_none()
                && !preserves_case.load(Ordering::Relaxed)
                && plain_question_matches(reply, &sent, false)
            {
                // A case-normalising upstream never echoes 0x20 case: ask once
                // more without it (as Unbound does).
                let next = with_id(raw_query, draw_id());
                if let Ok(fresh) = connected_socket(addr, excluded).await {
                    #[cfg(feature = "conformance-adapter")]
                    observer::started();
                    fresh.send(&next).await.map_err(|error| io_fail(&error))?;
                    retry_buffer = vec![0u8; MAX_DNS_MESSAGE];
                    retry = Some((fresh, next));
                }
            } else if plain_invalid_message(reply, context) {
                invalid.notify_one();
            }
            continue;
        }
        // Karn's rule (RFC 8085 §3.1.1): once the datagram went out twice, or
        // a case-retry is in flight, a reply could answer either copy.
        if !via_retry && !resent && retry.is_none() {
            health.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).sample_rtt(sent_at.elapsed());
        }
        if case_probe && !via_retry {
            preserves_case.store(true, Ordering::Relaxed);
        }
        // RFC 5452 §9.3: a datagram above the size we advertised
        // (512 without EDNS) is a fragmentation-attack suspect, since the
        // forged tail sits behind the checked ID, port and case. It is never
        // accepted as final: ask again over TCP.
        if received > udp_limit(context) {
            return tcp_exchange(link, context_query, context, deadline, invalid, scrub).await;
        }
        let Some((relayed, message)) = parse_upstream(reply) else {
            // A well-formed reply carrying forbidden records is a failed
            // attempt, like the other invalid-content rejections.
            if wire::forbidden_record(reply) {
                return Err(Fail::Remote);
            }
            invalid.notify_one();
            continue;
        };
        if message.metadata.message_type != MessageType::Response {
            continue;
        }
        if message.metadata.truncation {
            return tcp_exchange(link, context_query, context, deadline, invalid, scrub).await;
        }
        if unusable_rcode(message.metadata.response_code) {
            return Err(Fail::Remote);
        }
        if unsolicited_co(&relayed, context) {
            return Err(Fail::Remote);
        }
        return finish_plain(relayed, message, context, invalid, scrub);
    }
}

type TcpWaiters = HashMap<u16, mpsc::Sender<Vec<u8>>>;

/// One TCP connection to a plain upstream, shared by every query to it
/// (RFC 7766 §6.2.2) and pipelined: replies are routed by message ID, so they
/// may come back in any order. No query waits for another.
struct TcpConn {
    writer: Arc<tokio::sync::Mutex<OwnedWriteHalf>>,
    /// The queries waiting for a reply; `None` once the connection is closed.
    waiters: Arc<Mutex<Option<TcpWaiters>>>,
    /// Frames read so far: shows whether the server is still talking.
    frames: Arc<AtomicU64>,
    reader: JoinHandle<()>,
}

impl TcpConn {
    fn start(stream: TcpStream) -> Self {
        let (read, write) = stream.into_split();
        let waiters = Arc::new(Mutex::new(Some(HashMap::new())));
        let frames = Arc::new(AtomicU64::new(0));
        let writer = Arc::new(tokio::sync::Mutex::new(write));
        let reader = tokio::spawn(read_tcp_replies(read, writer.clone(), waiters.clone(), frames.clone()));
        Self { writer, waiters, frames, reader }
    }

    fn open(&self) -> bool {
        self.waiters.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).is_some()
    }

    /// Ends the connection. Every waiting query sees it closed.
    fn close(&self) {
        self.waiters.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).take();
        self.reader.abort();
        // Dropping the write half sends FIN; do it here because aborting the
        // reader skips its own shutdown. Without this the socket would stay
        // open until a later query replaced the link (RFC 7766 §6.2.3).
        let writer = self.writer.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let _ = writer.lock().await.shutdown().await;
            });
        }
    }

    /// Registers a query. `Ok(None)` means the connection has closed.
    ///
    /// ponytail: an ID already in flight fails this attempt (about 1 in 65536
    /// per outstanding query) rather than opening a second connection.
    fn wait_for(&self, id: u16, deadline: Instant) -> Result<Option<TcpWaiter>, Fail> {
        let mut waiters = self.waiters.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(map) = waiters.as_mut() else { return Ok(None) };
        if map.contains_key(&id) {
            return Err(Fail::Local);
        }
        let (sender, replies) = mpsc::channel(4);
        map.insert(id, sender);
        Ok(Some(TcpWaiter {
            waiters: self.waiters.clone(),
            id,
            replies,
            frames: self.frames.clone(),
            frames_at_start: self.frames.load(Ordering::Relaxed),
            deadline,
        }))
    }
}

impl Drop for TcpConn {
    fn drop(&mut self) {
        self.close();
    }
}

/// A query's place on a [`TcpConn`], given up when the attempt ends.
struct TcpWaiter {
    waiters: Arc<Mutex<Option<TcpWaiters>>>,
    id: u16,
    replies: mpsc::Receiver<Vec<u8>>,
    frames: Arc<AtomicU64>,
    frames_at_start: u64,
    deadline: Instant,
}

impl Drop for TcpWaiter {
    /// Here, because the pool aborts an attempt at the deadline, so no code
    /// after an await in it can be relied on to run.
    fn drop(&mut self) {
        let mut waiters = self.waiters.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        // Out of time with nothing heard since the query went out: the
        // connection is dead, and steady traffic would otherwise keep it open.
        if Instant::now() >= self.deadline && self.frames.load(Ordering::Relaxed) == self.frames_at_start {
            waiters.take();
        } else if let Some(map) = waiters.as_mut() {
            map.remove(&self.id);
        }
    }
}

/// Reads frames until the connection ends or sits idle with nothing
/// outstanding. A frame with no matching ID is dropped. The write half is shut
/// down on every exit, so an idle upstream connection really closes.
async fn read_tcp_replies(
    read: OwnedReadHalf,
    writer: Arc<tokio::sync::Mutex<OwnedWriteHalf>>,
    waiters: Arc<Mutex<Option<TcpWaiters>>>,
    frames: Arc<AtomicU64>,
) {
    let mut read = BufReader::new(read);
    loop {
        // `fill_buf` loses nothing when the timeout cancels it.
        match tokio::time::timeout(TCP_IDLE, read.fill_buf()).await {
            Ok(Ok(buffer)) if !buffer.is_empty() => {}
            Ok(_) => break,
            Err(_) => {
                // Atomic with `wait_for`, so no query joins a closing connection.
                // `None` is a connection a timed-out waiter marked dead.
                let mut waiters = waiters.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                if waiters.as_ref().is_none_or(HashMap::is_empty) {
                    waiters.take();
                    break;
                }
                continue;
            }
        }
        let frame = tokio::time::timeout(TCP_FRAME_WAIT, async {
            let len = read.read_u16().await?;
            let mut body = vec![0u8; usize::from(len)];
            read.read_exact(&mut body).await?;
            Ok::<_, std::io::Error>(body)
        })
        .await;
        let Ok(Ok(body)) = frame else { break };
        let Some(id) = body.get(..2).map(|id| u16::from_be_bytes([id[0], id[1]])) else { break };
        frames.fetch_add(1, Ordering::Relaxed);
        let waiters = waiters.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(map) = waiters.as_ref() else { break };
        if let Some(waiter) = map.get(&id) {
            let _ = waiter.try_send(body);
        }
    }
    waiters.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).take();
    let _ = writer.lock().await.shutdown().await;
}

/// The connection to one plain upstream, opened when first needed.
struct TcpLink {
    addr: SocketAddr,
    conn: tokio::sync::Mutex<Option<Arc<TcpConn>>>,
}

impl TcpLink {
    fn new(addr: SocketAddr) -> Self {
        Self { addr, conn: tokio::sync::Mutex::new(None) }
    }

    /// The open connection, or a new one. The lock is held while connecting,
    /// so concurrent queries wait for that one instead of opening their own.
    async fn conn(&self, deadline: Instant) -> Result<Arc<TcpConn>, Fail> {
        let mut slot = timeout_at(deadline, self.conn.lock()).await.map_err(|_| Fail::Remote)?;
        if let Some(conn) = slot.as_ref().filter(|conn| conn.open()) {
            return Ok(conn.clone());
        }
        let stream = match timeout_at(deadline, TcpStream::connect(self.addr)).await {
            Err(_) => return Err(Fail::Remote),
            Ok(Err(error)) => return Err(io_fail(&error)),
            Ok(Ok(stream)) => stream,
        };
        let conn = Arc::new(TcpConn::start(stream));
        *slot = Some(conn.clone());
        Ok(conn)
    }
}

/// A reply to a query sent unchanged: a response with its ID and question.
fn verbatim_reply(reply: &[u8], view: &QueryView<'_>) -> bool {
    wire::header(reply).is_some_and(|head| head.is_response()) && wire::question_matches(reply, view)
}

/// A new TCP connection with `raw` already sent. It is not the shared
/// connection: the ID is the client's, and a transfer needs the stream to
/// itself.
async fn tcp_send(addr: SocketAddr, raw: &[u8], deadline: Instant) -> Option<TcpStream> {
    let mut stream = timeout_at(deadline, TcpStream::connect(addr)).await.ok()?.ok()?;
    let mut framed = u16::try_from(raw.len()).ok()?.to_be_bytes().to_vec();
    framed.extend_from_slice(raw);
    timeout_at(deadline, stream.write_all(&framed)).await.ok()?.ok()?;
    Some(stream)
}

/// [`UpstreamPool::exchange_verbatim`] for one plain server, over TCP.
async fn plain_verbatim(addr: SocketAddr, raw: &[u8], view: &QueryView<'_>, deadline: Instant) -> Option<Vec<u8>> {
    // Always TCP: a verbatim message keeps the client's ID, so over UDP its
    // only defence against an off-path spoof would be the source port. TCP's
    // handshake removes that window (RFC 5452 §9.3); a reply too large for a
    // UDP client is truncated on the way back.
    let mut stream = tcp_send(addr, raw, deadline).await?;
    let body = timeout_at(deadline, async {
        let mut body = vec![0u8; usize::from(stream.read_u16().await?)];
        stream.read_exact(&mut body).await?;
        Ok::<_, std::io::Error>(body)
    })
    .await
    .ok()?
    .ok()?;
    verbatim_reply(&body, view).then_some(body)
}

/// Closes a connection unless the write it guards finished. A write cut short
/// leaves half a frame on the stream, and it can end without returning: a
/// hedge win aborts the attempt, so this cannot wait for a result.
struct WriteGuard<'a> {
    conn: &'a TcpConn,
    finished: bool,
}

impl Drop for WriteGuard<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.conn.close();
        }
    }
}

/// Writes one frame. `Ok(false)` means the connection has closed.
async fn send_frame(conn: &TcpConn, framed: &[u8], deadline: Instant) -> Result<bool, Fail> {
    let mut writer = timeout_at(deadline, conn.writer.lock()).await.map_err(|_| Fail::Remote)?;
    // The write ahead of this one may have been cut short.
    if !conn.open() {
        return Ok(false);
    }
    let mut guard = WriteGuard { conn, finished: false };
    match timeout_at(deadline, writer.write_all(framed)).await {
        Ok(Ok(())) => {
            guard.finished = true;
            Ok(true)
        }
        Err(_) => Err(Fail::Remote),
        Ok(Err(error)) => Err(io_fail(&error)),
    }
}

/// One reply from the shared pipelined connection, or `None` when the
/// connection closed. Frames for another query are skipped.
async fn shared_tcp_reply(
    link: &TcpLink,
    sent: &QueryView<'_>,
    framed: &[u8],
    deadline: Instant,
    invalid: &Notify,
) -> Result<Option<Vec<u8>>, Fail> {
    let conn = link.conn(deadline).await?;
    let Some(mut waiter) = conn.wait_for(sent.id, deadline)? else { return Ok(None) };
    #[cfg(feature = "conformance-adapter")]
    observer::started();
    match send_frame(&conn, framed, deadline).await {
        Ok(true) => {}
        Ok(false) => return Ok(None),
        Err(error) => return Err(error),
    }
    // A connection that sent anything for this query has answered it, even
    // with junk: when it closes, the last such frame is the reply, so the
    // caller ends the attempt instead of opening a fresh connection (spec U3:
    // one attempt per endpoint). Only a close with nothing for us is retried.
    let mut last_invalid = None;
    loop {
        match timeout_at(deadline, waiter.replies.recv()).await {
            Err(_) => return Err(Fail::Remote),
            Ok(None) => return Ok(last_invalid),
            Ok(Some(body)) => {
                if !plain_question_matches(&body, sent, false) {
                    if plain_invalid_message(&body, sent) {
                        invalid.notify_one();
                    }
                    last_invalid = Some(body);
                    continue;
                }
                return Ok(Some(body));
            }
        }
    }
}

/// One query on a TCP connection of its own. A server that closes after every
/// reply cannot serve a shared connection, so retries use this instead. It
/// costs one connection per retry, still bounded by `upstream_inflight_max`
/// (RFC 7766 §6.2.2 asks clients to keep concurrent connections few).
async fn tcp_once(addr: SocketAddr, framed: &[u8], deadline: Instant) -> Result<Option<Vec<u8>>, Fail> {
    let mut stream = match timeout_at(deadline, TcpStream::connect(addr)).await {
        Err(_) => return Err(Fail::Remote),
        Ok(Err(error)) => return Err(io_fail(&error)),
        Ok(Ok(stream)) => stream,
    };
    match timeout_at(deadline, stream.write_all(framed)).await {
        Err(_) => return Err(Fail::Remote),
        Ok(Err(error)) => return Err(io_fail(&error)),
        Ok(Ok(())) => {}
    }
    let frame = timeout_at(deadline, async {
        let len = stream.read_u16().await?;
        let mut body = vec![0u8; usize::from(len)];
        stream.read_exact(&mut body).await?;
        Ok::<_, std::io::Error>(body)
    })
    .await;
    match frame {
        Err(_) => Err(Fail::Remote),
        Ok(Err(error)) => Err(io_fail(&error)),
        Ok(Ok(body)) => Ok(Some(body)),
    }
}

/// One query over TCP. The question is compared without regard to case: an
/// off-path attacker cannot inject into a TCP stream, so the 0x20 check (a
/// UDP defence, RFC 5452 §9.1) has nothing to add, and a case-normalising
/// upstream would otherwise hold the attempt until its deadline.
async fn tcp_exchange(
    link: &TcpLink,
    query: &[u8],
    sent: &QueryView<'_>,
    deadline: Instant,
    invalid: &Notify,
    scrub: bool,
) -> Result<PlainReply, Fail> {
    let len = u16::try_from(query.len()).map_err(|_| "query too large")?;
    let mut framed = Vec::with_capacity(2 + query.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(query);
    let mut failure = Fail::Remote;
    for attempt in 0..TCP_TRIES {
        // A retry needs time left: on loopback a connect completes before an
        // expired timeout is even checked, so a late retry would still be a
        // real connection (spec U3: one attempt per endpoint).
        if attempt > 0 && Instant::now() >= deadline {
            break;
        }
        // The first try shares one pipelined connection. If it closes, the
        // server may accept only one query per connection, so the remaining
        // tries get a connection of their own rather than racing on a new
        // shared one.
        let body = if attempt == 0 {
            match shared_tcp_reply(link, sent, &framed, deadline, invalid).await {
                Ok(Some(body)) => body,
                Ok(None) => continue,
                // A write racing a close is recoverable on a fresh connection;
                // only exhausting every try is final.
                Err(error) => {
                    failure = error;
                    continue;
                }
            }
        } else {
            match tcp_once(link.addr, &framed, deadline).await {
                Ok(Some(body)) => body,
                Ok(None) => continue,
                Err(error) => {
                    failure = error;
                    continue;
                }
            }
        };
        // A reply came back on this connection: whatever it is, it ends the
        // TCP attempt (one attempt per endpoint and transport, spec U3). Only a
        // connection that closed without a reply gets a fresh one above.
        if !plain_question_matches(&body, sent, false) {
            if plain_invalid_message(&body, sent) {
                invalid.notify_one();
            }
            return Err(Fail::Remote);
        }
        let Some((relayed, message)) = parse_upstream(&body) else {
            if !wire::forbidden_record(&body) {
                invalid.notify_one();
            }
            return Err(Fail::Remote);
        };
        if message.metadata.message_type != MessageType::Response || message.metadata.truncation {
            return Err(Fail::Remote);
        }
        if unusable_rcode(message.metadata.response_code) {
            return Err(Fail::Remote);
        }
        if unsolicited_co(&relayed, sent) {
            return Err(Fail::Remote);
        }
        return finish_plain(relayed, message, sent, invalid, scrub);
    }
    Err(failure)
}

/// Test-only observation and control of the production pool (conformance
/// adapter): failure-cache statistics and limits, armed deadlines, in-flight
/// permits and deterministic ID draws.
#[cfg(feature = "conformance-adapter")]
mod observer {
    use super::*;
    use std::{
        collections::VecDeque,
        sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering},
    };

    pub(super) struct Failures {
        limits: Mutex<(usize, usize)>,
        insertions: AtomicU64,
        expired: AtomicU64,
        armed: AtomicUsize,
    }

    impl Default for Failures {
        fn default() -> Self {
            Self {
                limits: Mutex::new((FAILURE_CAPACITY, FAILURE_BYTES)),
                insertions: AtomicU64::new(0),
                expired: AtomicU64::new(0),
                armed: AtomicUsize::new(0),
            }
        }
    }

    /// One registered upstream deadline, counted while its exchange runs.
    pub(super) struct Armed<'a>(&'a AtomicUsize);

    impl Drop for Armed<'_> {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    impl Failures {
        pub(super) fn arm(&self) -> Armed<'_> {
            self.armed.fetch_add(1, Ordering::SeqCst);
            Armed(&self.armed)
        }

        pub(super) fn limits(&self) -> (usize, usize) {
            *self.limits.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
        }

        /// Counts one stored insertion (and a replaced expired marker).
        pub(super) fn inserted(&self, stored: bool, replaced_expired: bool) {
            if !stored {
                return;
            }
            if replaced_expired {
                self.expired.fetch_add(1, Ordering::SeqCst);
            }
            self.insertions.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// One snapshot of the failure cache for the adapter.
    pub struct FailureStats {
        pub entries: usize,
        pub bytes: usize,
        pub entries_limit: usize,
        pub bytes_limit: usize,
        pub insertions: u64,
        pub expired: u64,
        /// Window of the most recently marked failure, or the first window.
        pub ttl: Duration,
    }

    impl UpstreamPool {
        pub fn failure_stats(&self) -> FailureStats {
            let failures = self.failures.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            let (entries_limit, bytes_limit) = self.observer.limits();
            FailureStats {
                entries: failures.map.len(),
                bytes: failures.bytes,
                entries_limit,
                bytes_limit,
                insertions: self.observer.insertions.load(Ordering::SeqCst),
                expired: self.observer.expired.load(Ordering::SeqCst),
                ttl: failures.map.values().max_by_key(|(at, _)| *at).map_or(self.failure_window, |(_, window)| *window),
            }
        }

        /// True while at least one failure marker is inside its suppression
        /// window: upstream resolution is failing for some name right now.
        pub fn failing(&self) -> bool {
            let failures = self.failures.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            failures.map.values().any(|(at, window)| at.elapsed() < *window)
        }

        /// Applies new bounds to the running failure map and clears it.
        pub fn set_failure_limits(&self, entries: usize, bytes: usize) {
            let mut failures = self.failures.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            *self.observer.limits.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = (entries, bytes);
            *failures = FailureMap::default();
        }

        pub fn deadlines_armed(&self) -> usize {
            self.observer.armed.load(Ordering::SeqCst)
        }
    }

    /// Causal tree of one client request: upstream exchanges it started and
    /// derived tasks (refresh, prefetch) still running. Task-local, so work
    /// started outside any request (probes, startup) is never attributed.
    #[derive(Default)]
    pub struct Lineage {
        starts: AtomicUsize,
        pending: AtomicUsize,
        done: AtomicBool,
    }

    tokio::task_local! {
        static LINEAGE: Arc<Lineage>;
    }

    type Requests = HashMap<Vec<u8>, Vec<Arc<Lineage>>>;

    static REQUESTS: Mutex<Option<Requests>> = Mutex::new(None);

    fn register(raw: &[u8]) -> Arc<Lineage> {
        let lineage = Arc::new(Lineage::default());
        let mut requests = REQUESTS.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let requests = requests.get_or_insert_with(HashMap::new);
        // A flood of distinct queries (a memory measurement) would otherwise
        // grow this test-only map forever; finished requests are dropped once
        // it is large, far beyond what any one conformance case asks about.
        if requests.len() >= 65_536 {
            requests.retain(|_, lineages| {
                lineages.iter().any(|l| !l.done.load(Ordering::SeqCst) || l.pending.load(Ordering::SeqCst) > 0)
            });
        }
        requests.entry(raw.to_vec()).or_default().push(lineage.clone());
        lineage
    }

    /// Runs one request's whole handling inside its own lineage.
    pub async fn track<F: std::future::Future>(raw: &[u8], work: F) -> F::Output {
        let lineage = register(raw);
        let out = LINEAGE.scope(lineage.clone(), work).await;
        lineage.done.store(true, Ordering::SeqCst);
        out
    }

    /// [`track`] for the synchronous inline-hit path.
    pub fn track_sync<R>(raw: &[u8], work: impl FnOnce() -> R) -> R {
        let lineage = register(raw);
        let out = LINEAGE.sync_scope(lineage.clone(), work);
        lineage.done.store(true, Ordering::SeqCst);
        out
    }

    static STARTS: AtomicUsize = AtomicUsize::new(0);

    /// Every upstream exchange launched so far, attributed or not.
    pub fn starts_total() -> usize {
        STARTS.load(Ordering::SeqCst)
    }

    /// One upstream exchange launched by the current request, if any.
    pub(super) fn started() {
        STARTS.fetch_add(1, Ordering::SeqCst);
        let _ = LINEAGE.try_with(|lineage| lineage.starts.fetch_add(1, Ordering::SeqCst));
    }

    struct Descendant(Arc<Lineage>);

    impl Drop for Descendant {
        fn drop(&mut self) {
            self.0.pending.fetch_sub(1, Ordering::SeqCst);
        }
    }

    /// Keeps a spawned task in the spawner's lineage without making it a
    /// pending descendant (its parent request waits for it).
    pub(super) fn inherit<F: std::future::Future>(work: F) -> impl std::future::Future<Output = F::Output> {
        let parent = LINEAGE.try_with(Arc::clone).ok();
        async move {
            match parent {
                Some(parent) => LINEAGE.scope(parent, work).await,
                None => work.await,
            }
        }
    }

    /// Wraps a task about to be spawned so it stays in the spawner's lineage
    /// and counts as pending until it ends (finished or aborted).
    pub fn descend<F: std::future::Future>(work: F) -> impl std::future::Future<Output = F::Output> {
        let parent = LINEAGE.try_with(Arc::clone).ok();
        if let Some(parent) = &parent {
            parent.pending.fetch_add(1, Ordering::SeqCst);
        }
        async move {
            match parent {
                Some(parent) => {
                    let _pending = Descendant(parent.clone());
                    LINEAGE.scope(parent, work).await
                }
                None => work.await,
            }
        }
    }

    /// `(complete, upstream_starts, derived_pending)` over every request seen
    /// with exactly these bytes; `None` when none was observed.
    pub fn request_state(raw: &[u8]) -> Option<(bool, usize, usize)> {
        let requests = REQUESTS.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let all = requests.as_ref()?.get(raw)?;
        Some((
            all.iter().all(|l| l.done.load(Ordering::SeqCst)),
            all.iter().map(|l| l.starts.load(Ordering::SeqCst)).sum(),
            all.iter().map(|l| l.pending.load(Ordering::SeqCst)).sum(),
        ))
    }

    static IDS: Mutex<VecDeque<u16>> = Mutex::new(VecDeque::new());

    /// One-shot fault for the next matching site (0 = none).
    static FAULT: AtomicU8 = AtomicU8::new(0);
    const FAULTS: [&str; 3] = ["upstream_panic", "cancel_all_waiters", "upstream_error"];

    /// Arms one fault by name; false for an unknown name.
    pub fn inject_fault(name: &str) -> bool {
        let Some(at) = FAULTS.iter().position(|known| *known == name) else { return false };
        FAULT.store(at as u8 + 1, Ordering::SeqCst);
        true
    }

    /// Runs one DoH attempt. An armed `upstream_panic` or `upstream_error`
    /// fires 50 ms (virtual) after the attempt began, so the query has reached
    /// the upstream by then.
    pub(super) async fn fault_after_send<T>(
        work: impl std::future::Future<Output = Result<T, DohError>>,
    ) -> Result<T, DohError> {
        let panic = take_fault("upstream_panic");
        if !panic && !take_fault("upstream_error") {
            return work.await;
        }
        tokio::select! {
            biased;
            done = work => done,
            () = tokio::time::sleep(Duration::from_millis(50)) => {
                if panic {
                    panic!("injected upstream panic");
                }
                Err(DohError { message: "injected upstream error".into(), transport: false })
            }
        }
    }

    /// Consumes the armed fault when it is `name`.
    pub fn take_fault(name: &str) -> bool {
        let Some(at) = FAULTS.iter().position(|known| *known == name) else { return false };
        FAULT.compare_exchange(at as u8 + 1, 0, Ordering::SeqCst, Ordering::SeqCst).is_ok()
    }

    pub fn inject_ids(ids: &[u16]) {
        IDS.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).extend(ids);
    }

    pub(super) fn injected_id() -> Option<u16> {
        IDS.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).pop_front()
    }
}

#[cfg(feature = "conformance-adapter")]
pub use observer::{
    descend, inject_fault, inject_ids, request_state, starts_total, take_fault, track, track_sync, FailureStats,
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use hickory_proto::rr::rdata::{A as AData, CNAME, SOA};
    use hickory_proto::rr::{RData, Record};
    use tokio::net::TcpListener;

    #[test]
    fn unsolicited_compact_answers_response_is_a_failed_attempt() {
        let query = raw_query("co.test.", RecordType::A, 7);
        let mut reply = a_reply(&query, [192, 0, 2, 1]);
        // OPT: root, type 41, size 1232, flags DO|CO, no options.
        reply.extend_from_slice(&[0, 0, 41, 4, 0xd0, 0, 0, 0xc0, 0, 0, 0]);
        let n = u16::from_be_bytes([reply[10], reply[11]]) + 1;
        reply[10..12].copy_from_slice(&n.to_be_bytes());
        let sent = wire::parse_query(&query).unwrap();
        assert!(unsolicited_co(&reply, &sent));
        let mut co_query = query.clone();
        co_query.extend_from_slice(&[0, 0, 41, 4, 0xd0, 0, 0, 0xc0, 0, 0, 0]);
        co_query[11] = 1;
        assert!(!unsolicited_co(&reply, &wire::parse_query(&co_query).unwrap()));
    }

    #[test]
    fn failure_rcodes_are_failed_attempts() {
        // FORMERR, SERVFAIL, NOTIMP and REFUSED never reach the client.
        for code in [1u16, 2, 4, 5, 7, 8, 9, 10, 11, 15, 16, 17, 22, 23, 4095] {
            assert!(unusable_rcode(<ResponseCode as From<u16>>::from(code)), "rcode {code}");
        }
        for code in [0u16, 3, 6] {
            assert!(!unusable_rcode(<ResponseCode as From<u16>>::from(code)), "rcode {code}");
        }
    }

    type DohHandler = Arc<dyn Fn(&[u8]) -> Reply + Send + Sync>;
    type UdpHandler = Arc<dyn Fn(&[u8]) -> Option<Vec<u8>> + Send + Sync>;

    struct Reply {
        status: u16,
        content_type: &'static str,
        age: Vec<String>,
        location: Option<String>,
        retry_after: Option<String>,
        delay: Duration,
        body: Vec<u8>,
    }

    impl Reply {
        fn dns(body: Vec<u8>) -> Self {
            Self {
                status: 200,
                content_type: "application/dns-message",
                age: Vec::new(),
                location: None,
                retry_after: None,
                delay: Duration::ZERO,
                body,
            }
        }

        fn error(status: u16) -> Self {
            Self {
                status,
                content_type: "text/plain",
                age: Vec::new(),
                location: None,
                retry_after: None,
                delay: Duration::ZERO,
                body: b"error".to_vec(),
            }
        }

        fn redirect(location: String) -> Self {
            Self {
                status: 302,
                content_type: "text/plain",
                age: Vec::new(),
                location: Some(location),
                retry_after: None,
                delay: Duration::ZERO,
                body: Vec::new(),
            }
        }

        fn delayed(mut self, delay: Duration) -> Self {
            self.delay = delay;
            self
        }

        fn retry_after(mut self, value: &str) -> Self {
            self.retry_after = Some(value.to_string());
            self
        }

        fn aged(mut self, age: u32) -> Self {
            self.age.push(age.to_string());
            self
        }

        fn age_raw(mut self, age: &str) -> Self {
            self.age.push(age.to_string());
            self
        }
    }

    struct DohMock {
        url: String,
        seen: Arc<Mutex<Vec<Vec<u8>>>>,
        task: JoinHandle<()>,
    }

    impl Drop for DohMock {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    impl DohMock {
        async fn start(handler: DohHandler) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let seen = Arc::new(Mutex::new(Vec::new()));
            let recorded = seen.clone();
            let task = tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else { return };
                    let handler = handler.clone();
                    let recorded = recorded.clone();
                    tokio::spawn(async move {
                        let _ = serve(stream, handler, recorded).await;
                    });
                }
            });
            Self { url: format!("http://{addr}/dns-query"), seen, task }
        }
    }

    async fn serve(
        mut stream: TcpStream,
        handler: DohHandler,
        recorded: Arc<Mutex<Vec<Vec<u8>>>>,
    ) -> std::io::Result<()> {
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 4096];
        let head_end = loop {
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                return Ok(());
            }
            buffer.extend_from_slice(&chunk[..n]);
            if let Some(pos) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
                break pos;
            }
            if buffer.len() > 65_536 {
                return Ok(());
            }
        };
        let head = String::from_utf8_lossy(&buffer[..head_end]).to_ascii_lowercase();
        let content_length = head
            .lines()
            .find_map(|line| line.strip_prefix("content-length:"))
            .and_then(|value| value.trim().parse().ok())
            .unwrap_or(0);
        let start = head_end + 4;
        while buffer.len() < start + content_length {
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                break;
            }
            buffer.extend_from_slice(&chunk[..n]);
        }
        let body = buffer.get(start..start + content_length).unwrap_or(&[]).to_vec();
        let reply = handler(&body);
        recorded.lock().unwrap().push(body);
        // Status 0: close the connection after reading the request, unanswered.
        if reply.status == 0 {
            return Ok(());
        }
        if !reply.delay.is_zero() {
            tokio::time::sleep(reply.delay).await;
        }
        let reason = if reply.status == 200 { "OK" } else { "Error" };
        let mut head = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
            reply.status,
            reason,
            reply.content_type,
            reply.body.len()
        );
        for age in &reply.age {
            head.push_str(&format!("Age: {age}\r\n"));
        }
        if let Some(location) = &reply.location {
            head.push_str(&format!("Location: {location}\r\n"));
        }
        if let Some(retry_after) = &reply.retry_after {
            head.push_str(&format!("Retry-After: {retry_after}\r\n"));
        }
        head.push_str("\r\n");
        stream.write_all(head.as_bytes()).await?;
        stream.write_all(&reply.body).await?;
        stream.shutdown().await?;
        Ok(())
    }

    struct UdpMock {
        addr: SocketAddr,
        seen: Arc<Mutex<Vec<Vec<u8>>>>,
        task: JoinHandle<()>,
    }

    impl Drop for UdpMock {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    impl UdpMock {
        async fn start(handler: UdpHandler) -> Self {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr = socket.local_addr().unwrap();
            let seen = Arc::new(Mutex::new(Vec::new()));
            let recorded = seen.clone();
            let task = tokio::spawn(async move {
                let mut buffer = vec![0u8; MAX_DNS_MESSAGE];
                loop {
                    let Ok((n, peer)) = socket.recv_from(&mut buffer).await else { return };
                    let query = buffer[..n].to_vec();
                    recorded.lock().unwrap().push(query.clone());
                    if let Some(reply) = handler(&query) {
                        let _ = socket.send_to(&reply, peer).await;
                    }
                }
            });
            Self { addr, seen, task }
        }
    }

    fn config(upstreams: Vec<String>, fallback: Vec<SocketAddr>) -> Config {
        Config { upstreams, fallback, upstream_hedge_ms: 40, upstream_timeout_seconds: 2, ..Config::default() }
    }

    fn raw_query(name: &str, qtype: RecordType, id: u16) -> Vec<u8> {
        let mut raw = Vec::new();
        raw.extend_from_slice(&id.to_be_bytes());
        raw.extend_from_slice(&0x0100u16.to_be_bytes());
        raw.extend_from_slice(&1u16.to_be_bytes());
        raw.extend_from_slice(&[0, 0, 0, 0]);
        raw.extend_from_slice(&0u16.to_be_bytes());
        for label in name.trim_end_matches('.').split('.').filter(|label| !label.is_empty()) {
            raw.push(label.len() as u8);
            raw.extend_from_slice(label.as_bytes());
        }
        raw.push(0);
        raw.extend_from_slice(&u16::from(qtype).to_be_bytes());
        raw.extend_from_slice(&1u16.to_be_bytes());
        raw
    }

    fn parsed(raw: &[u8]) -> Message {
        Message::from_vec(raw).expect("valid DNS message")
    }

    fn is_probe(raw: &[u8]) -> bool {
        parsed(raw).queries.first().is_some_and(|query| query.query_type() == RecordType::NS && query.name().is_root())
    }

    fn reply_for(raw: &[u8], rcode: ResponseCode, answers: Vec<Record>, authorities: Vec<Record>) -> Vec<u8> {
        let query = parsed(raw);
        let mut response = Message::new(query.metadata.id, MessageType::Response, query.metadata.op_code);
        response.metadata.recursion_desired = query.metadata.recursion_desired;
        response.metadata.recursion_available = true;
        response.metadata.response_code = rcode;
        response.queries = query.queries.clone();
        for answer in answers {
            response.add_answer(answer);
        }
        for authority in authorities {
            response.add_authority(authority);
        }
        let mut bytes = response.to_vec().unwrap();
        wire::copy_question_case(raw, &mut bytes);
        bytes
    }

    fn a_reply(raw: &[u8], octets: [u8; 4]) -> Vec<u8> {
        let query = parsed(raw);
        let record = Record::from_rdata(
            query.queries[0].name().clone(),
            60,
            RData::A(AData::new(octets[0], octets[1], octets[2], octets[3])),
        );
        reply_for(raw, ResponseCode::NoError, vec![record], vec![])
    }

    fn empty_reply(raw: &[u8]) -> Vec<u8> {
        reply_for(raw, ResponseCode::NoError, vec![], vec![])
    }

    fn cname_only_reply(raw: &[u8]) -> Vec<u8> {
        let query = parsed(raw);
        let record = Record::from_rdata(
            query.queries[0].name().clone(),
            60,
            RData::CNAME(CNAME(Name::from_ascii("alias.test.").unwrap())),
        );
        reply_for(raw, ResponseCode::NoError, vec![record], vec![])
    }

    fn nxdomain_with_soa(raw: &[u8]) -> Vec<u8> {
        let query = parsed(raw);
        let soa = Record::from_rdata(
            Name::from_ascii("test.").unwrap(),
            60,
            RData::SOA(SOA::new(
                Name::from_ascii("ns.test.").unwrap(),
                Name::from_ascii("hostmaster.test.").unwrap(),
                1,
                3600,
                600,
                86400,
                60,
            )),
        );
        let _ = query;
        reply_for(raw, ResponseCode::NXDomain, vec![], vec![soa])
    }

    fn answer_address(answer: &UpstreamAnswer) -> Option<[u8; 4]> {
        let message = Message::from_vec(&answer.raw).ok()?;
        message.answers.iter().find_map(|record| match &record.data {
            RData::A(address) => Some(address.0.octets()),
            _ => None,
        })
    }

    fn flip_question_case(raw: &mut [u8]) -> bool {
        let Some(view) = wire::parse_query(raw) else { return false };
        let end = 12 + view.qname_wire.len();
        for byte in &mut raw[12..end] {
            if byte.is_ascii_alphabetic() {
                *byte ^= 0x20;
                return true;
            }
        }
        false
    }

    fn probe_handler(raw: &[u8]) -> Reply {
        Reply::dns(empty_reply(raw))
    }

    /// A DoH mock that answers `address` after `delay` and counts real queries.
    async fn counting_mock(hits: Arc<AtomicUsize>, address: [u8; 4], delay: Duration, status: u16) -> DohMock {
        let handler: DohHandler = Arc::new(move |raw: &[u8]| {
            if is_probe(raw) {
                return probe_handler(raw);
            }
            hits.fetch_add(1, Ordering::SeqCst);
            if status != 200 {
                return Reply::error(status);
            }
            Reply::dns(a_reply(raw, address)).delayed(delay)
        });
        DohMock::start(handler).await
    }

    #[tokio::test]
    async fn ordered_strategy_keeps_queries_on_the_first_upstream() {
        // The first upstream is slower than the hedge delay; `fastest` would
        // hedge to the second and then prefer it. `ordered` never does.
        let (one, two) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
        let first = counting_mock(one.clone(), [192, 0, 2, 1], Duration::from_millis(120), 200).await;
        let second = counting_mock(two.clone(), [192, 0, 2, 2], Duration::ZERO, 200).await;
        let mut cfg = config(vec![first.url.clone(), second.url.clone()], vec![]);
        cfg.upstream_strategy = UpstreamStrategy::Ordered;
        let pool = Arc::new(UpstreamPool::new(&cfg).unwrap());
        for id in 0..5u16 {
            let name = format!("ordered{id}.test.");
            let answer = pool.exchange(&raw_query(&name, RecordType::A, id), id).await.expect("answer");
            assert_eq!(answer_address(&answer), Some([192, 0, 2, 1]));
        }
        assert_eq!(one.load(Ordering::SeqCst), 5);
        assert_eq!(two.load(Ordering::SeqCst), 0, "the second provider never sees a query");
        assert_eq!(pool.health().iter().map(|upstream| upstream.hedges).sum::<u64>(), 0);
    }

    #[tokio::test]
    async fn ordered_strategy_fails_over_on_error_and_after_half_the_timeout() {
        // A failing first upstream: the second answers at once.
        let (one, two) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
        let first = counting_mock(one.clone(), [192, 0, 2, 1], Duration::ZERO, 500).await;
        let second = counting_mock(two.clone(), [192, 0, 2, 2], Duration::ZERO, 200).await;
        let mut cfg = config(vec![first.url.clone(), second.url.clone()], vec![]);
        cfg.upstream_strategy = UpstreamStrategy::Ordered;
        let pool = Arc::new(UpstreamPool::new(&cfg).unwrap());
        let started = Instant::now();
        let answer = pool.exchange(&raw_query("fail.test.", RecordType::A, 1), 1).await.expect("answer");
        assert_eq!(answer_address(&answer), Some([192, 0, 2, 2]));
        assert!(started.elapsed() < Duration::from_millis(500), "{:?}", started.elapsed());

        // A hanging first upstream: the second is asked at the failover point
        // (half of the 2 s timeout, at most 1 s), not after the 40 ms hedge delay.
        let slow = counting_mock(Arc::new(AtomicUsize::new(0)), [192, 0, 2, 1], Duration::from_secs(5), 200).await;
        let mut cfg = config(vec![slow.url.clone(), second.url.clone()], vec![]);
        cfg.upstream_strategy = UpstreamStrategy::Ordered;
        let pool = Arc::new(UpstreamPool::new(&cfg).unwrap());
        let started = Instant::now();
        let answer = pool.exchange(&raw_query("slow.test.", RecordType::A, 2), 2).await.expect("answer");
        let elapsed = started.elapsed();
        assert_eq!(answer_address(&answer), Some([192, 0, 2, 2]));
        assert!(elapsed >= Duration::from_millis(950) && elapsed < Duration::from_millis(1800), "{elapsed:?}");
    }

    #[test]
    fn the_failover_point_stays_under_the_udp_discard_limit() {
        // Default: 5 s timeout, 1.9 s discard limit. Half the timeout (2.5 s)
        // would make every failover answer too late for a UDP client.
        let cfg = Config::default();
        let limit = cfg.udp_discard_limit().unwrap();
        assert_eq!(failover_delay(&cfg), Duration::from_millis(950));
        assert!(failover_delay(&cfg) * 2 <= limit, "the next upstream keeps half the discard window");
        let short = Config { udp_discard_timeout_ms: 400, serve_stale_client_timeout_ms: 0, ..Config::default() };
        assert_eq!(failover_delay(&short), Duration::from_millis(200));
        let off = Config { udp_discard_timeout_ms: 0, upstream_timeout_seconds: 1, ..Config::default() };
        assert_eq!(failover_delay(&off), Duration::from_millis(500));
    }

    #[tokio::test]
    async fn an_unreachable_plain_fallback_is_skipped_while_another_works() {
        // A closed port: the connected UDP socket sees ECONNREFUSED.
        let closed = std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        let good: UdpHandler = Arc::new(|raw: &[u8]| Some(a_reply(raw, [192, 0, 2, 9])));
        let second = UdpMock::start(good).await;
        let pool = Arc::new(UpstreamPool::new(&config(vec![], vec![closed, second.addr])).unwrap());
        let answer = pool.exchange(&raw_query("skip0.test.", RecordType::A, 1), 1).await;
        assert_eq!(answer_address(&answer.expect("the second fallback answers")), Some([192, 0, 2, 9]));
        assert!(pool.fallback_state[0].lock().unwrap().skip_until.is_some(), "the closed port is backed off");
        assert!(pool.fallback_state[1].lock().unwrap().skip_until.is_none());
        // During the backoff only the working fallback is asked.
        assert!(pool.exchange(&raw_query("skip1.test.", RecordType::A, 2), 2).await.is_some());
        assert_eq!(pool.fallback_state[0].lock().unwrap().failures, 1, "the closed port was not asked again");
    }

    /// RFC 6891 §§6.1.1, 6.1.4, 7: the upstream sees a fresh OPT, never the
    /// client's: our payload, DO kept, every other flag zero. RFC 5625 §3: an
    /// unknown option is forwarded unchanged, while hop-scoped ECS is not.
    #[tokio::test]
    async fn the_client_opt_is_rebuilt_and_unknown_options_are_forwarded() {
        let handler: UdpHandler = Arc::new(|raw: &[u8]| Some(a_reply(raw, [192, 0, 2, 5])));
        let udp = UdpMock::start(handler).await;
        let pool = Arc::new(UpstreamPool::new(&config(vec![], vec![udp.addr])).unwrap());
        let mut query = raw_query("opt.test.", RecordType::A, 7);
        query[11] = 1; // ARCOUNT
                       // Root, OPT, payload 1232, ext 0, version 0, flags DO plus the lowest
                       // Z bit, then NSID (3, empty), ECS (8) and an unknown option 65001.
        query.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0x80, 0x01]);
        let options: &[u8] = &[0, 3, 0, 0, 0, 8, 0, 4, 0, 1, 0, 0, 0xfd, 0xe9, 0, 2, 0xab, 0xcd];
        query.extend_from_slice(&(options.len() as u16).to_be_bytes());
        query.extend_from_slice(options);
        assert!(pool.exchange(&query, 7).await.is_some());
        let plain = raw_query("plain.test.", RecordType::A, 8);
        assert!(pool.exchange(&plain, 8).await.is_some());
        let seen = udp.seen.lock().unwrap().clone();
        let sent = wire::parse_query(&seen[0]).unwrap();
        assert!(sent.edns_present && sent.edns_do);
        assert_eq!(sent.edns_flags, 0x8000, "only DO survives; Z is zero");
        assert_eq!(sent.edns_payload, 1232);
        assert!(sent.edns_options, "the unknown option and NSID are forwarded");
        assert!(!sent.edns_hop_options, "ECS is hop-scoped and must not be forwarded");
        assert_eq!(
            &seen[0][seen[0].len() - 10..],
            &[0, 3, 0, 0, 0xfd, 0xe9, 0, 2, 0xab, 0xcd],
            "forwarded options unchanged, ECS removed"
        );
        assert!(!seen[0].windows(8).any(|window| window == [0, 8, 0, 4, 0, 1, 0, 0]), "ECS bytes forwarded");
        assert!(!wire::parse_query(&seen[1]).unwrap().edns_present, "an EDNS-less query stays EDNS-less");
    }

    #[tokio::test]
    async fn hedges_after_delay_and_cancels_the_loser() {
        let real = Arc::new(AtomicUsize::new(0));
        let arrivals: Arc<Mutex<Vec<Instant>>> = Arc::new(Mutex::new(Vec::new()));
        let handler: DohHandler = {
            let real = real.clone();
            let arrivals = arrivals.clone();
            Arc::new(move |raw: &[u8]| {
                if is_probe(raw) {
                    return probe_handler(raw);
                }
                let n = real.fetch_add(1, Ordering::SeqCst);
                arrivals.lock().unwrap().push(Instant::now());
                if n == 0 {
                    Reply::dns(a_reply(raw, [192, 0, 2, 1])).delayed(Duration::from_millis(300))
                } else {
                    Reply::dns(a_reply(raw, [192, 0, 2, 2]))
                }
            })
        };
        let first = DohMock::start(handler.clone()).await;
        let second = DohMock::start(handler).await;
        let cfg = config(vec![first.url.clone(), second.url.clone()], vec![]);
        let pool = Arc::new(UpstreamPool::new(&cfg).unwrap());

        let query = raw_query("hedge.test.", RecordType::A, 0x1234);
        let started = Instant::now();
        let answer = pool.exchange(&query, 0x1234).await.expect("hedged answer");
        let elapsed = started.elapsed();
        assert!(answer.terminal);
        assert_eq!(answer_address(&answer), Some([192, 0, 2, 2]));
        assert!(elapsed >= Duration::from_millis(30), "{elapsed:?}");
        assert!(elapsed < Duration::from_millis(250), "{elapsed:?}");
        assert_eq!(real.load(Ordering::SeqCst), 2);
        let arrivals = arrivals.lock().unwrap();
        assert_eq!(arrivals.len(), 2);
        assert!(arrivals[1] - arrivals[0] >= Duration::from_millis(30));
        let health = pool.health();
        assert_eq!(health.iter().map(|upstream| upstream.hedges).sum::<u64>(), 1);
        assert_eq!(health.iter().map(|upstream| upstream.wins).sum::<u64>(), 1);
        assert_eq!(answer.raw[0..2], 0x1234u16.to_be_bytes());
    }

    #[tokio::test]
    async fn failing_upstream_advances_without_waiting_for_the_hedge() {
        let handler: DohHandler = Arc::new(|raw: &[u8]| Reply::dns(a_reply(raw, [192, 0, 2, 9])));
        let working = DohMock::start(handler).await;
        let mut cfg = config(vec!["http://127.0.0.1:1/dns-query".into(), working.url.clone()], vec![]);
        cfg.upstream_hedge_ms = 1000;
        let pool = Arc::new(UpstreamPool::new(&cfg).unwrap());
        let query = raw_query("failover.test.", RecordType::A, 7);
        let started = Instant::now();
        let answer = pool.exchange(&query, 7).await.expect("second upstream answers");
        assert!(started.elapsed() < Duration::from_millis(700), "{:?}", started.elapsed());
        assert!(answer.terminal);
        assert_eq!(answer_address(&answer), Some([192, 0, 2, 9]));
        assert_eq!(answer.upstream_index, Some(1));
        assert_eq!(pool.health().iter().map(|upstream| upstream.hedges).sum::<u64>(), 0);
    }

    #[tokio::test]
    async fn health_never_exposes_url_credentials_or_tokens() {
        let cfg = config(vec!["http://user:pass@127.0.0.1:1/dns-query?token=supersecret".into()], vec![]);
        let pool = Arc::new(UpstreamPool::new(&cfg).unwrap());
        let query = raw_query("redact.test.", RecordType::A, 1);
        assert!(pool.exchange(&query, 1).await.is_none());
        let health = pool.health();
        assert_eq!(health[0].url, "http://127.0.0.1:1");
        let error = health[0].last_error.as_deref().expect("the failed attempt is recorded");
        assert!(!error.contains("supersecret"), "{error}");
        assert!(!error.contains("user:pass"), "{error}");
    }

    #[tokio::test]
    async fn all_doh_failures_use_the_plain_fallback() {
        let handler: UdpHandler = Arc::new(|raw: &[u8]| Some(a_reply(raw, [192, 0, 2, 44])));
        let udp = UdpMock::start(handler).await;
        let cfg =
            config(vec!["http://127.0.0.1:1/dns-query".into(), "http://127.0.0.1:2/dns-query".into()], vec![udp.addr]);
        let pool = Arc::new(UpstreamPool::new(&cfg).unwrap());
        let query = raw_query("fallback.test.", RecordType::A, 0x4321);
        let before = crate::stats::global().snapshot().plain_fallback;
        let answer = pool.exchange(&query, 0x4321).await.expect("fallback answer");
        assert!(answer.terminal);
        assert_eq!(answer.upstream_index, None);
        assert_eq!(answer.age, 0);
        assert_eq!(answer_address(&answer), Some([192, 0, 2, 44]));
        assert_eq!(answer.raw[0..2], 0x4321u16.to_be_bytes());
        // Other tests share the process-wide counter, so only a lower bound holds.
        assert!(crate::stats::global().snapshot().plain_fallback > before, "a plaintext answer is counted");
    }

    #[test]
    fn plaintext_warning_is_rate_limited_and_counts() {
        let warn = PlainWarn { last: AtomicU64::new(0), pending: AtomicU64::new(0) };
        assert_eq!(warn.note(1000), Some(1), "the first plaintext answer warns at once");
        assert_eq!(warn.note(1001), None);
        assert_eq!(warn.note(1059), None);
        assert_eq!(warn.note(1060), Some(3), "a minute later, with every answer since");
        assert_eq!(warn.note(500), Some(1), "a clock step back does not silence it");
    }

    #[tokio::test]
    async fn plain_fallback_clears_ad() {
        let handler: UdpHandler = Arc::new(|raw: &[u8]| {
            let mut reply = a_reply(raw, [192, 0, 2, 20]);
            reply[3] |= 0x20;
            Some(reply)
        });
        let udp = UdpMock::start(handler).await;
        let cfg = config(vec![], vec![udp.addr]);
        let pool = Arc::new(UpstreamPool::new(&cfg).unwrap());
        let query = raw_query("ad.test.", RecordType::A, 0x7777);
        let answer = pool.exchange(&query, 0x7777).await.expect("fallback answer");
        assert!(answer.terminal);
        assert_eq!(answer.raw[3] & 0x20, 0, "plain fallback clears AD");
        assert_eq!(answer.age, 0);
    }

    #[tokio::test]
    async fn fallback_ignores_wrong_id_question_case_and_source() {
        let listener = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let other = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let task = tokio::spawn(async move {
            let mut buffer = vec![0u8; MAX_DNS_MESSAGE];
            let (n, peer) = listener.recv_from(&mut buffer).await.unwrap();
            let query = buffer[..n].to_vec();

            let mut wrong_id = a_reply(&query, [203, 0, 113, 1]);
            let id = u16::from_be_bytes([wrong_id[0], wrong_id[1]]).wrapping_add(1);
            wrong_id[0..2].copy_from_slice(&id.to_be_bytes());
            listener.send_to(&wrong_id, peer).await.unwrap();

            let mut wrong_question = a_reply(&raw_query("other.test.", RecordType::A, 0x9999), [203, 0, 113, 2]);
            wrong_question[0..2].copy_from_slice(&query[0..2]);
            listener.send_to(&wrong_question, peer).await.unwrap();

            let mut wrong_case = a_reply(&query, [203, 0, 113, 3]);
            assert!(flip_question_case(&mut wrong_case));
            listener.send_to(&wrong_case, peer).await.unwrap();

            let wrong_source = a_reply(&query, [203, 0, 113, 4]);
            other.send_to(&wrong_source, peer).await.unwrap();

            tokio::time::sleep(Duration::from_millis(20)).await;
            let correct = a_reply(&query, [192, 0, 2, 7]);
            listener.send_to(&correct, peer).await.unwrap();
        });
        let cfg = config(vec![], vec![addr]);
        let pool = Arc::new(UpstreamPool::new(&cfg).unwrap());
        let query = raw_query("junk.test.", RecordType::A, 0x2468);
        let answer = pool.exchange(&query, 0x2468).await.expect("valid datagram accepted");
        assert!(answer.terminal);
        assert_eq!(answer_address(&answer), Some([192, 0, 2, 7]));
        task.await.unwrap();
    }

    #[tokio::test]
    async fn plain_invalid_message_advances_and_slow_first_is_hedged() {
        // Matching ID and QR=1 with an unparseable body fails the attempt at once.
        let bad: UdpHandler = Arc::new(|raw: &[u8]| {
            let mut reply = raw[..2].to_vec();
            reply.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 0x3f]);
            reply.extend_from_slice(b"garbage");
            Some(reply)
        });
        let good: UdpHandler = Arc::new(|raw: &[u8]| Some(a_reply(raw, [192, 0, 2, 9])));
        let (first, second) = (UdpMock::start(bad).await, UdpMock::start(good.clone()).await);
        let mut cfg = config(vec![], vec![first.addr, second.addr]);
        cfg.upstream_hedge_ms = 2000;
        let pool = Arc::new(UpstreamPool::new(&cfg).unwrap());
        let query = raw_query("invalid.test.", RecordType::A, 5);
        let started = Instant::now();
        assert!(pool.exchange(&query, 5).await.is_some());
        assert!(started.elapsed() < Duration::from_millis(1000), "invalid message must not wait for the hedge timer");

        // A silent first endpoint is hedged to the second after the hedge delay.
        let silent: UdpHandler = Arc::new(|_| None);
        let (first, second) = (UdpMock::start(silent).await, UdpMock::start(good).await);
        let mut cfg = config(vec![], vec![first.addr, second.addr]);
        cfg.upstream_hedge_ms = 100;
        let pool = Arc::new(UpstreamPool::new(&cfg).unwrap());
        let query = raw_query("hedge.test.", RecordType::A, 6);
        let started = Instant::now();
        assert!(pool.exchange(&query, 6).await.is_some());
        assert!(started.elapsed() < Duration::from_millis(1000));
    }

    #[test]
    fn failure_suppression_starts_at_five_seconds_and_backs_off() {
        let pool = UpstreamPool::new(&config(vec![], vec![])).unwrap();
        pool.mark_failure(Box::from(&b"k"[..]));
        assert_eq!(pool.failures.lock().unwrap().map.get(&b"k"[..]).unwrap().1, Duration::from_secs(5));
        pool.mark_failure(Box::from(&b"k"[..]));
        pool.mark_failure(Box::from(&b"k"[..]));
        pool.mark_failure(Box::from(&b"k"[..]));
        pool.mark_failure(Box::from(&b"k"[..]));
        assert_eq!(pool.failures.lock().unwrap().map.get(&b"k"[..]).unwrap().1, Duration::from_secs(30));
        assert!(pool.failure_is_recent(b"k"));
    }

    /// RFC 9520 section 3.2: the first window is configurable, the cap never
    /// drops below it and never passes 300 s.
    #[test]
    fn failure_cache_seconds_sets_the_first_window_and_the_cap() {
        let mut cfg = config(vec![], vec![]);
        cfg.failure_cache_seconds = 2;
        let pool = UpstreamPool::new(&cfg).unwrap();
        let window = |pool: &UpstreamPool| pool.failures.lock().unwrap().map.get(&b"k"[..]).unwrap().1;
        pool.mark_failure(Box::from(&b"k"[..]));
        assert_eq!(window(&pool), Duration::from_secs(2));
        for _ in 0..8 {
            pool.mark_failure(Box::from(&b"k"[..]));
        }
        assert_eq!(window(&pool), Duration::from_secs(30), "the 30 s cap stays for small keys");

        cfg.failure_cache_seconds = 100;
        let pool = UpstreamPool::new(&cfg).unwrap();
        for _ in 0..8 {
            pool.mark_failure(Box::from(&b"k"[..]));
        }
        assert_eq!(window(&pool), Duration::from_secs(100), "a larger key raises the cap to itself");
    }

    /// RFC 9715 §3.2: a path that drops UDP is tried over TCP once the
    /// datagram and its resend have both gone unanswered.
    #[tokio::test]
    async fn rfc9715_s222_a_silent_udp_path_gets_a_tcp_attempt() {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let udp = UdpSocket::bind(addr).await.unwrap();
        let datagrams = Arc::new(AtomicUsize::new(0));
        let counted = datagrams.clone();
        let udp_task = tokio::spawn(async move {
            let mut buffer = vec![0u8; MAX_DNS_MESSAGE];
            while udp.recv_from(&mut buffer).await.is_ok() {
                counted.fetch_add(1, Ordering::SeqCst);
            }
        });
        let tcp_task = tokio::spawn(async move {
            let (mut stream, _) = tcp.accept().await.unwrap();
            let query = tcp_frame(&mut stream).await.unwrap();
            write_tcp_frame(&mut stream, &a_reply(&query, [192, 0, 2, 8])).await;
            tcp_frame(&mut stream).await;
        });
        let mut cfg = config(vec![], vec![addr]);
        cfg.upstream_timeout_seconds = 5;
        let pool = Arc::new(UpstreamPool::new(&cfg).unwrap());
        let query = raw_query("silent.test.", RecordType::A, 0x2468);
        let started = Instant::now();
        let answer = pool.exchange(&query, 0x2468).await.expect("the TCP attempt answers");
        assert_eq!(answer_address(&answer), Some([192, 0, 2, 8]));
        assert!(started.elapsed() >= 2 * RETRANSMIT_AFTER, "TCP only after the resend went unanswered");
        assert_eq!(datagrams.load(Ordering::SeqCst), 2, "one datagram and one resend");
        udp_task.abort();
        tcp_task.abort();
    }

    #[tokio::test]
    async fn truncated_udp_retries_over_tcp() {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let udp = UdpSocket::bind(addr).await.unwrap();
        let sent: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
        let recorded = sent.clone();
        let udp_task = tokio::spawn(async move {
            let mut buffer = vec![0u8; MAX_DNS_MESSAGE];
            let (n, peer) = udp.recv_from(&mut buffer).await.unwrap();
            let query = buffer[..n].to_vec();
            *recorded.lock().unwrap() = Some(query.clone());
            let mut truncated = a_reply(&query, [198, 51, 100, 1]);
            truncated[2] |= 0x02;
            udp.send_to(&truncated, peer).await.unwrap();
        });
        let tcp_sent = sent.clone();
        let tcp_task = tokio::spawn(async move {
            let (mut stream, _) = tcp.accept().await.unwrap();
            let mut len = [0u8; 2];
            stream.read_exact(&mut len).await.unwrap();
            let mut body = vec![0u8; u16::from_be_bytes(len) as usize];
            stream.read_exact(&mut body).await.unwrap();
            assert_eq!(Some(body.clone()), *tcp_sent.lock().unwrap());
            let reply = a_reply(&body, [192, 0, 2, 8]);
            stream.write_all(&(reply.len() as u16).to_be_bytes()).await.unwrap();
            stream.write_all(&reply).await.unwrap();
        });
        let cfg = config(vec![], vec![addr]);
        let pool = Arc::new(UpstreamPool::new(&cfg).unwrap());
        let query = raw_query("truncated.test.", RecordType::A, 0x1357);
        let answer = pool.exchange(&query, 0x1357).await.expect("tcp answer");
        assert!(answer.terminal);
        assert_eq!(answer_address(&answer), Some([192, 0, 2, 8]));
        udp_task.await.unwrap();
        tcp_task.await.unwrap();
    }

    #[tokio::test]
    async fn tcp_client_query_goes_to_a_plain_upstream_over_tcp_first() {
        // RFC 5625 §4.2: UDP is never tried for a query that arrived over TCP.
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let udp = UdpSocket::bind(addr).await.unwrap();
        let udp_hits = Arc::new(AtomicUsize::new(0));
        let counted = udp_hits.clone();
        tokio::spawn(async move {
            let mut buffer = vec![0u8; MAX_DNS_MESSAGE];
            while udp.recv_from(&mut buffer).await.is_ok() {
                counted.fetch_add(1, Ordering::Relaxed);
            }
        });
        tokio::spawn(async move {
            let (mut stream, _) = tcp.accept().await.unwrap();
            let mut len = [0u8; 2];
            stream.read_exact(&mut len).await.unwrap();
            let mut body = vec![0u8; u16::from_be_bytes(len) as usize];
            stream.read_exact(&mut body).await.unwrap();
            let reply = a_reply(&body, [192, 0, 2, 8]);
            stream.write_all(&(reply.len() as u16).to_be_bytes()).await.unwrap();
            stream.write_all(&reply).await.unwrap();
        });
        let pool = Arc::new(UpstreamPool::new(&config(vec![], vec![addr])).unwrap());
        let query = raw_query("tcp-first.test.", RecordType::A, 0x1357);
        let answer = pool.exchange_from(&query, 0x1357, true).await.expect("tcp answer");
        assert_eq!(answer_address(&answer), Some([192, 0, 2, 8]));
        assert_eq!(udp_hits.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn a_tcp_reply_that_normalises_question_case_is_accepted_at_once() {
        // TCP cannot be forged off-path, so the 0x20 case check (a UDP
        // defence, RFC 5452 §9.1) does not apply: a TCP upstream that
        // lowercases the question answers without waiting out the deadline.
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = tcp.accept().await.unwrap();
            let mut len = [0u8; 2];
            stream.read_exact(&mut len).await.unwrap();
            let mut body = vec![0u8; u16::from_be_bytes(len) as usize];
            stream.read_exact(&mut body).await.unwrap();
            let mut reply = a_reply(&body, [192, 0, 2, 9]);
            let end = 12 + wire::parse_query(&body).unwrap().qname_wire.len();
            reply[12..end].make_ascii_lowercase();
            stream.write_all(&(reply.len() as u16).to_be_bytes()).await.unwrap();
            stream.write_all(&reply).await.unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        let pool = Arc::new(UpstreamPool::new(&config(vec![], vec![addr])).unwrap());
        let query = raw_query("MiXeD.CaSe.TeSt.", RecordType::A, 0x2468);
        let started = Instant::now();
        let answer = pool.exchange_from(&query, 0x2468, true).await.expect("tcp answer");
        assert_eq!(answer_address(&answer), Some([192, 0, 2, 9]));
        assert!(started.elapsed() < Duration::from_secs(1), "{:?}", started.elapsed());
    }

    #[tokio::test]
    async fn plain_randomizes_ids_and_case_and_restores_the_client_id() {
        let seen: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let recorded = seen.clone();
        let handler: UdpHandler = Arc::new(move |raw: &[u8]| {
            recorded.lock().unwrap().push(raw.to_vec());
            Some(a_reply(raw, [192, 0, 2, 10]))
        });
        let udp = UdpMock::start(handler).await;
        let cfg = config(vec![], vec![udp.addr]);
        let pool = Arc::new(UpstreamPool::new(&cfg).unwrap());
        let query = raw_query("MiXeD.CaSe.TeSt.", RecordType::A, 0x1234);
        let client_view = wire::parse_query(&query).unwrap();
        let n = client_view.qname_len as usize;
        for _ in 0..8 {
            let answer = pool.exchange(&query, 0x1234).await.expect("answer");
            assert_eq!(answer.raw[0..2], 0x1234u16.to_be_bytes());
            let view = wire::parse_query(&answer.raw).unwrap();
            assert_eq!(view.qname_lower[..n], client_view.qname_lower[..n]);
        }
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 8);
        assert!(seen.iter().any(|raw| u16::from_be_bytes([raw[0], raw[1]]) != 0x1234));
        assert!(seen.iter().any(|raw| raw[12..12 + n] != query[12..12 + n]));
        for raw in seen.iter() {
            let view = wire::parse_query(raw).unwrap();
            assert_eq!(view.qname_len, client_view.qname_len);
            assert_eq!(view.qname_lower[..n], client_view.qname_lower[..n]);
        }
    }

    #[tokio::test]
    async fn plain_0x20_falls_back_for_a_case_normalising_upstream() {
        let lower: UdpHandler = Arc::new(|raw: &[u8]| {
            let mut reply = a_reply(raw, [192, 0, 2, 13]);
            let end = 12 + wire::parse_query(raw)?.qname_wire.len();
            reply[12..end].make_ascii_lowercase();
            Some(reply)
        });
        let mock = UdpMock::start(lower).await;
        let pool = Arc::new(UpstreamPool::new(&config(vec![], vec![mock.addr])).unwrap());
        let query = raw_query("MiXeD.CaSe.TeSt.", RecordType::A, 0x3333);
        let answer = pool.exchange(&query, 0x3333).await.expect("normalising upstream still answers");
        assert_eq!(answer_address(&answer), Some([192, 0, 2, 13]));
    }

    #[tokio::test]
    async fn plain_0x20_rejects_a_wrong_case_reply_then_accepts_the_right_one() {
        let listener = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut buffer = vec![0u8; MAX_DNS_MESSAGE];
            let (received, peer) = listener.recv_from(&mut buffer).await.unwrap();
            let query = buffer[..received].to_vec();
            let mut wrong_case = a_reply(&query, [203, 0, 113, 5]);
            assert!(flip_question_case(&mut wrong_case));
            listener.send_to(&wrong_case, peer).await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
            let correct = a_reply(&query, [192, 0, 2, 12]);
            listener.send_to(&correct, peer).await.unwrap();
        });
        let cfg = config(vec![], vec![addr]);
        let pool = Arc::new(UpstreamPool::new(&cfg).unwrap());
        let query = raw_query("MiXeD.CaSe.TeSt.", RecordType::A, 0x2222);
        let answer = pool.exchange(&query, 0x2222).await.expect("matching case answer");
        assert!(answer.terminal);
        assert_eq!(answer_address(&answer), Some([192, 0, 2, 12]));
        assert_eq!(answer.raw[0..2], 0x2222u16.to_be_bytes());
        task.await.unwrap();
    }

    #[tokio::test]
    async fn plain_without_0x20_keeps_the_client_case() {
        let udp = UdpMock::start(Arc::new(|raw: &[u8]| Some(a_reply(raw, [192, 0, 2, 13])))).await;
        let mut cfg = config(vec![], vec![udp.addr]);
        cfg.upstream_0x20 = false;
        let pool = Arc::new(UpstreamPool::new(&cfg).unwrap());
        let query = raw_query("MiXeD.CaSe.TeSt.", RecordType::A, 0x3333);
        let answer = pool.exchange(&query, 0x3333).await.expect("answer");
        assert!(answer.terminal);
        let seen = udp.seen.lock().unwrap();
        let n = wire::parse_query(&query).unwrap().qname_wire.len();
        assert_eq!(seen[0][12..12 + n], query[12..12 + n]);
    }

    #[test]
    fn derived_hedge_delay_is_clamped() {
        let cfg = config(vec!["http://127.0.0.1:1/dns-query".into()], vec![]);
        let mut cfg = cfg;
        cfg.upstream_hedge_ms = 0;
        let pool = UpstreamPool::new(&cfg).unwrap();
        let order = pool.selection();
        assert_eq!(pool.hedge_delay(&order), Duration::from_millis(40));
        pool.upstreams[0].state().ewma_us = 10_000;
        assert_eq!(pool.hedge_delay(&order), Duration::from_millis(40));
        pool.upstreams[0].state().ewma_us = 25_000;
        assert_eq!(pool.hedge_delay(&order), Duration::from_millis(50));
        pool.upstreams[0].state().ewma_us = 100_000;
        assert_eq!(pool.hedge_delay(&order), Duration::from_millis(80));
    }

    #[test]
    fn cooldown_backoff_is_capped() {
        assert_eq!(cooldown(3), Duration::from_secs(30));
        assert_eq!(cooldown(4), Duration::from_secs(60));
        assert_eq!(cooldown(5), Duration::from_secs(120));
        assert_eq!(cooldown(6), Duration::from_secs(240));
        // RFC 2308 §7.2: never deemed dead for longer than five minutes.
        assert_eq!(cooldown(7), Duration::from_secs(300));
        assert_eq!(cooldown(8), Duration::from_secs(300));
        assert_eq!(cooldown(100), Duration::from_secs(300));
    }

    #[tokio::test]
    async fn circuit_opens_after_three_failures_and_a_probe_recovers_it() {
        let healthy = Arc::new(AtomicBool::new(false));
        let handler: DohHandler = {
            let healthy = healthy.clone();
            Arc::new(move |raw: &[u8]| {
                if healthy.load(Ordering::SeqCst) {
                    if is_probe(raw) {
                        probe_handler(raw)
                    } else {
                        Reply::dns(a_reply(raw, [192, 0, 2, 14]))
                    }
                } else if is_probe(raw) {
                    Reply::error(500)
                } else {
                    // A DoH front end can answer one client name 502 or with
                    // a non-DNS body when only that name's lookup is broken.
                    let name = parsed(raw).queries[0].name().to_ascii();
                    if name.starts_with("type") {
                        Reply { status: 200, ..Reply::error(0) }
                    } else {
                        Reply::error(502)
                    }
                }
            })
        };
        let mock = DohMock::start(handler).await;
        let cfg = config(vec![mock.url.clone()], vec![]);
        let pool = Arc::new(UpstreamPool::new(&cfg).unwrap());
        assert!(pool.ready());
        // Client queries cannot bench the upstream: the HTTP status and the
        // content type may depend on the question.
        for i in 0..6u16 {
            let name = if i % 2 == 0 { format!("status-{i}.test.") } else { format!("type-{i}.test.") };
            assert!(pool.exchange(&raw_query(&name, RecordType::A, i + 1), i + 1).await.is_none());
        }
        assert!(pool.health()[0].healthy, "client-steered HTTP errors open no circuit");
        assert_eq!(pool.upstreams[0].state().failures, 0);
        assert!(pool.ready());
        // The fixed root-NS probe is what confirms an endpoint-wide 5xx.
        for _ in 0..3 {
            pool.probe_all().await;
        }
        let health = pool.health();
        assert!(!health[0].healthy, "circuit should be open");
        assert!(health[0].last_error.is_some());
        assert!(!pool.ready());

        healthy.store(true, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(30)).await;
        pool.probe_all().await;
        let health = pool.health();
        assert!(health[0].healthy);
        assert!(health[0].last_error.is_none());
        assert!(pool.ready());
        let query = raw_query("after-recovery.test.", RecordType::A, 9);
        let answer = pool.exchange(&query, 9).await.expect("recovered");
        assert!(answer.terminal);
    }

    async fn eventually(timeout: Duration, mut condition: impl FnMut() -> bool) {
        let deadline = Instant::now() + timeout;
        while !condition() {
            assert!(Instant::now() < deadline, "condition was not met within {timeout:?}");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    #[tokio::test]
    async fn a_cancelled_hedge_loser_is_not_a_failure_but_sorts_last() {
        // The loser is aborted when the healthy upstream wins. That is
        // no evidence of failure: the circuit stays closed, and the loser's
        // latency lower bound only moves it behind the winner.
        let blackhole = DohMock::start(Arc::new(|raw: &[u8]| {
            Reply::dns(a_reply(raw, [192, 0, 2, 99])).delayed(Duration::from_millis(1000))
        }))
        .await;
        let healthy = DohMock::start(Arc::new(|raw: &[u8]| Reply::dns(a_reply(raw, [192, 0, 2, 1])))).await;
        let cfg = config(vec![blackhole.url.clone(), healthy.url.clone()], vec![]);
        let pool = Arc::new(UpstreamPool::new(&cfg).unwrap());

        for i in 0..5u16 {
            let query = raw_query(&format!("blackhole-{i}.test."), RecordType::A, i + 1);
            let answer = pool.exchange(&query, i + 1).await.expect("the healthy upstream answers");
            assert_eq!(answer.upstream_index, Some(1), "the healthy upstream wins each hedge");
            eventually(Duration::from_secs(1), || pool.health()[0].outstanding == 0).await;
        }
        let health = pool.health();
        assert!(health[0].healthy, "a hedge loser never opens its circuit");
        assert!(health[0].last_error.is_none());
        assert!(health[0].ewma_us > health[1].ewma_us, "but it sorts behind the winner");
        assert_eq!(pool.selection()[0].index, 1);
        // Once the loser is behind, the winner answers without any hedge.
        let hedges: u64 = pool.health().iter().map(|upstream| upstream.hedges).sum();
        let query = raw_query("after.test.", RecordType::A, 9);
        assert!(pool.exchange(&query, 9).await.is_some());
        assert_eq!(pool.health().iter().map(|upstream| upstream.hedges).sum::<u64>(), hedges);
    }

    #[tokio::test]
    async fn only_a_transport_failure_counts_against_an_upstream() {
        let upstream = Arc::new(Upstream::new(0, "https://example.test/dns-query".into()));
        // Cancelled (a peer won, the caller left or the deadline passed): no failure.
        drop(Attempt::new(upstream.clone()));
        assert_eq!(upstream.state().failures, 0);
        assert!(upstream.state().last_error.is_none());
        assert_eq!(upstream.state().outstanding, 0);
        // A timeout or invalid content may be the question's fault: no failure.
        for error in ["timeout", "invalid response", "http status 502", "bad content type", "http status 400"] {
            let mut attempt = Attempt::new(upstream.clone());
            attempt.complete(&Err(error.into()));
            drop(attempt);
        }
        assert_eq!(upstream.state().failures, 0);
        assert_eq!(upstream.state().last_error.as_deref(), Some("http status 400"), "shown, not counted");
        // A transport failure counts once, never again by the guard.
        let mut attempt = Attempt::new(upstream.clone());
        attempt.complete(&Err(DohError { message: "connection refused".into(), transport: true }));
        drop(attempt);
        assert_eq!(upstream.state().failures, 1);
        assert_eq!(upstream.state().last_error.as_deref(), Some("connection refused"));
    }

    /// Health must not be client-steerable: a client asking for names whose
    /// answers are slow or SERVFAIL must not bench the upstreams or the
    /// fallbacks, while a dead endpoint is still benched.
    #[tokio::test]
    async fn slow_or_failing_names_never_bench_an_upstream_but_a_dead_endpoint_does() {
        let doh = DohMock::start(Arc::new(|raw: &[u8]| {
            if is_probe(raw) {
                probe_handler(raw)
            } else if parsed(raw).queries[0].name().to_ascii().starts_with("slow") {
                Reply::dns(a_reply(raw, [192, 0, 2, 1])).delayed(Duration::from_secs(3))
            } else {
                Reply::dns(reply_for(raw, ResponseCode::ServFail, vec![], vec![]))
            }
        }))
        .await;
        let mut cfg = config(vec![doh.url.clone()], vec![]);
        cfg.upstream_timeout_seconds = 1;
        let pool = Arc::new(UpstreamPool::new(&cfg).unwrap());
        for id in 0..3u16 {
            assert!(pool.exchange(&raw_query(&format!("slow{id}.test."), RecordType::A, id), id).await.is_none());
            let _ = pool.exchange(&raw_query(&format!("fail{id}.test."), RecordType::A, id), id).await;
        }
        assert!(pool.health()[0].healthy, "{:?}", pool.health()[0].last_error);
        assert_eq!(pool.upstreams[0].state().failures, 0);

        // A plain fallback that times out or answers SERVFAIL is not backed off.
        let silent: UdpHandler = Arc::new(|raw: &[u8]| {
            let servfail = parsed(raw).queries[0].name().to_ascii().starts_with("fail");
            servfail.then(|| reply_for(raw, ResponseCode::ServFail, vec![], vec![]))
        });
        let fallback = UdpMock::start(silent).await;
        let mut cfg = config(vec![], vec![fallback.addr]);
        cfg.upstream_timeout_seconds = 1;
        let pool = Arc::new(UpstreamPool::new(&cfg).unwrap());
        for id in 0..2u16 {
            assert!(pool.exchange(&raw_query(&format!("slow{id}.test."), RecordType::A, id), id).await.is_none());
            assert!(pool.exchange(&raw_query(&format!("fail{id}.test."), RecordType::A, id), id).await.is_none());
        }
        assert_eq!(fallback.seen.lock().unwrap().len(), 4, "every query still reached the fallback");
        assert!(pool.fallback_state[0].lock().unwrap().skip_until.is_none());

        // A refused connection is the endpoint, not the question: three open
        // the DoH circuit.
        let pool = Arc::new(UpstreamPool::new(&config(vec!["http://127.0.0.1:1/dns-query".into()], vec![])).unwrap());
        for id in 0..3u16 {
            assert!(pool.exchange(&raw_query(&format!("dead{id}.test."), RecordType::A, id), id).await.is_none());
        }
        assert!(!pool.health()[0].healthy, "a dead endpoint opens its circuit");
    }

    #[tokio::test]
    async fn dns_level_failures_do_not_open_the_circuit_or_reach_the_plain_fallback() {
        // SERVFAIL from a reachable DoH upstream ends the
        // resolution without plaintext and without a health penalty.
        let doh = DohMock::start(Arc::new(|raw: &[u8]| {
            if is_probe(raw) {
                return probe_handler(raw);
            }
            Reply::dns(reply_for(raw, ResponseCode::ServFail, vec![], vec![]))
        }))
        .await;
        let plain = UdpMock::start(Arc::new(|raw: &[u8]| Some(a_reply(raw, [192, 0, 2, 66])))).await;
        let pool = Arc::new(UpstreamPool::new(&config(vec![doh.url.clone()], vec![plain.addr])).unwrap());
        for i in 0..6u16 {
            let query = raw_query(&format!("broken-{i}.test."), RecordType::A, i + 1);
            assert!(pool.exchange(&query, i + 1).await.is_none(), "SERVFAIL, not the fallback's answer");
        }
        assert!(plain.seen.lock().unwrap().is_empty(), "the plaintext fallback was never asked");
        let health = pool.health();
        assert!(health[0].healthy, "DNS-level failures never open the breaker");
        assert!(health[0].last_error.is_none());
        let query = raw_query("good.test.", RecordType::A, 77);
        // The failure cache is per question: other names are still tried.
        assert!(pool.exchange(&query, 77).await.is_none());
    }

    #[tokio::test]
    async fn a_dns_failure_advances_to_the_next_doh_upstream() {
        let failing =
            DohMock::start(Arc::new(|raw: &[u8]| Reply::dns(reply_for(raw, ResponseCode::Refused, vec![], vec![]))))
                .await;
        let good = DohMock::start(Arc::new(|raw: &[u8]| Reply::dns(a_reply(raw, [192, 0, 2, 5])))).await;
        let plain = UdpMock::start(Arc::new(|raw: &[u8]| Some(a_reply(raw, [192, 0, 2, 66])))).await;
        let cfg = config(vec![failing.url.clone(), good.url.clone()], vec![plain.addr]);
        let pool = Arc::new(UpstreamPool::new(&cfg).unwrap());
        let query = raw_query("next.test.", RecordType::A, 3);
        let answer = pool.exchange(&query, 3).await.expect("the second DoH upstream answers");
        assert_eq!(answer_address(&answer), Some([192, 0, 2, 5]));
        assert_eq!(answer.upstream_index, Some(1));
        assert!(plain.seen.lock().unwrap().is_empty());
    }

    /// Appends an OPT with one Extended DNS Error (RFC 8914) to a reply.
    fn with_ede(mut reply: Vec<u8>, info_code: u16) -> Vec<u8> {
        reply.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 6, 0, 15, 0, 2]);
        reply.extend_from_slice(&info_code.to_be_bytes());
        let arcount = u16::from_be_bytes([reply[10], reply[11]]) + 1;
        reply[10..12].copy_from_slice(&arcount.to_be_bytes());
        reply
    }

    /// Reads one DNS-over-TCP frame, or `None` at the end of the stream.
    async fn tcp_frame(stream: &mut TcpStream) -> Option<Vec<u8>> {
        let mut len = [0u8; 2];
        stream.read_exact(&mut len).await.ok()?;
        let mut body = vec![0u8; usize::from(u16::from_be_bytes(len))];
        stream.read_exact(&mut body).await.ok()?;
        Some(body)
    }

    async fn write_tcp_frame(stream: &mut TcpStream, body: &[u8]) {
        let mut framed = (body.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(body);
        let _ = stream.write_all(&framed).await;
    }

    /// RFC 7766 §6.2.2: concurrent queries to a server share one connection,
    /// pipelined, and replies may come back in any order (§6.2.1.1). The
    /// connection is then reused (§6.2.1).
    #[tokio::test]
    async fn rfc7766_s465_concurrent_tcp_queries_share_one_pipelined_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let accepted = connections.clone();
        let server = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                accepted.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    // All three must be outstanding at once to be answered.
                    let mut held = Vec::new();
                    while held.len() < 3 {
                        let Some(query) = tcp_frame(&mut stream).await else { return };
                        held.push(query);
                    }
                    for query in held.iter().rev() {
                        write_tcp_frame(&mut stream, &a_reply(query, [192, 0, 2, 8])).await;
                    }
                    while let Some(query) = tcp_frame(&mut stream).await {
                        write_tcp_frame(&mut stream, &a_reply(&query, [192, 0, 2, 9])).await;
                    }
                });
            }
        });
        let pool = Arc::new(UpstreamPool::new(&config(vec![], vec![addr])).unwrap());
        let ask = |name: &str, id: u16| {
            let (pool, query) = (pool.clone(), raw_query(name, RecordType::A, id));
            tokio::spawn(async move { pool.exchange_from(&query, id, true).await })
        };
        let asked = [ask("one.test.", 1), ask("two.test.", 2), ask("three.test.", 3)];
        for (task, name) in asked.into_iter().zip(["one.test.", "two.test.", "three.test."]) {
            let answer = task.await.unwrap().expect("answered");
            assert_eq!(answer.message.queries[0].name().to_ascii().to_lowercase(), name, "matched by ID");
        }
        assert!(ask("four.test.", 4).await.unwrap().is_some(), "the idle connection is reused");
        assert_eq!(connections.load(Ordering::SeqCst), 1);
        server.abort();
    }

    /// Spec U3: one TCP attempt per endpoint. A reply frame that is invalid
    /// ends it; only a connection closed without a reply gets a fresh one.
    #[tokio::test]
    async fn invalid_tcp_frames_end_the_attempt_without_a_second_connect() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let accepted = connections.clone();
        let server = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                accepted.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    // Junk with the right ID, then the connection closes.
                    if let Some(query) = tcp_frame(&mut stream).await {
                        let mut junk = query[..2].to_vec();
                        junk.extend_from_slice(&[0xff; 30]);
                        for _ in 0..3 {
                            write_tcp_frame(&mut stream, &junk).await;
                        }
                    }
                });
            }
        });
        let link = TcpLink::new(addr);
        let query = raw_query("junk.test.", RecordType::A, 7);
        let view = wire::parse_query(&query).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        let result = tcp_exchange(&link, &query, &view, deadline, &Notify::new(), true).await;
        assert!(result.is_err(), "junk is never an answer");
        // Let the server accept anything still in its backlog before counting.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(connections.load(Ordering::SeqCst), 1, "no second connect for an invalid reply");
        server.abort();
    }

    /// RFC 5452 §5: at most two queries for one question are in flight to one
    /// plain address; another waits. Other types, names or addresses are
    /// separate, and a finished query frees its slot and its map entry.
    #[tokio::test]
    async fn rfc5452_s5_at_most_two_queries_per_question_are_in_flight() {
        let slots = Arc::new(QuestionSlots::default());
        let (here, there): (SocketAddr, SocketAddr) =
            ("127.0.0.1:53".parse().unwrap(), "127.0.0.2:53".parse().unwrap());
        let soon = || Instant::now() + Duration::from_millis(50);
        let a = raw_query("same.test.", RecordType::A, 1);
        let upper = raw_query("SAME.test.", RecordType::A, 2);
        let first = slots.acquire(here, &a, soon()).await.expect("first slot");
        let second = slots.acquire(here, &upper, soon()).await.expect("second slot, case folded");
        assert!(slots.acquire(here, &a, soon()).await.is_none(), "a third query waits and runs out of time");
        assert!(slots.acquire(here, &raw_query("same.test.", RecordType::AAAA, 3), soon()).await.is_some());
        assert!(slots.acquire(there, &a, soon()).await.is_some(), "another address has its own slots");
        drop(first);
        let third = slots.acquire(here, &a, soon()).await.expect("a finished query frees its slot");
        // A waiter cancelled mid-wait (its attempt aborted) leaves nothing behind.
        let waiter = {
            let (slots, a) = (slots.clone(), a.clone());
            tokio::spawn(
                async move { slots.acquire(here, &a, Instant::now() + Duration::from_secs(60)).await.is_some() },
            )
        };
        tokio::task::yield_now().await;
        waiter.abort();
        assert!(waiter.await.is_err(), "the waiter was cancelled");
        drop((second, third));
        assert!(slots.0.lock().unwrap().is_empty(), "no entry outlives its queries");
    }

    /// RFC 7766 §6.2.2: a server may close a connection after one reply.
    /// Every concurrent query must still be answered, so retries use their
    /// own connections instead of racing on a new shared one.
    #[tokio::test]
    async fn a_one_shot_tcp_upstream_answers_concurrent_queries() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let accepted = connections.clone();
        let server = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else { return };
                accepted.fetch_add(1, Ordering::SeqCst);
                let Some(query) = tcp_frame(&mut stream).await else { continue };
                write_tcp_frame(&mut stream, &a_reply(&query, [192, 0, 2, 8])).await;
                // Close after one reply: the next frame is never read.
            }
        });
        let pool = Arc::new(UpstreamPool::new(&config(vec![], vec![addr])).unwrap());
        let asks: Vec<_> = (1..=5u16)
            .map(|id| {
                let pool = pool.clone();
                tokio::spawn(async move {
                    pool.exchange_from(&raw_query(&format!("one-shot-{id}.test."), RecordType::A, id), id, true).await
                })
            })
            .collect();
        for ask in asks {
            assert!(ask.await.unwrap().is_some(), "every concurrent query is answered");
        }
        assert!(connections.load(Ordering::SeqCst) >= 5, "the one-shot server served at least five queries");
        server.abort();
    }

    /// RFC 7766 §6.2.3: a shared upstream connection idle with nothing
    /// outstanding is closed, not left open until a later query replaces it.
    #[tokio::test]
    async fn rfc7766_s623_an_idle_shared_connection_is_closed() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (closed_tx, closed_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let Some(query) = tcp_frame(&mut stream).await else { return };
            write_tcp_frame(&mut stream, &a_reply(&query, [192, 0, 2, 8])).await;
            // Zero bytes only when the peer shut the connection down.
            let mut byte = [0u8; 1];
            let _ = closed_tx.send(stream.read(&mut byte).await.is_ok_and(|n| n == 0));
        });
        let pool = Arc::new(UpstreamPool::new(&config(vec![], vec![addr])).unwrap());
        assert!(pool.exchange_from(&raw_query("idle.test.", RecordType::A, 1), 1, true).await.is_some());
        let closed = tokio::time::timeout(TCP_IDLE + Duration::from_secs(2), closed_rx).await.unwrap();
        assert!(closed.unwrap(), "the idle connection was closed");
        server.abort();
    }

    /// A send cancelled partway, as when a hedge wins, leaves half a frame on
    /// the stream, so the connection must not carry anything else.
    #[tokio::test]
    async fn a_cancelled_tcp_send_closes_the_shared_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
        let (_unread, _) = listener.accept().await.unwrap();
        let conn = Arc::new(TcpConn::start(client));
        let send = {
            let conn = conn.clone();
            tokio::spawn(async move {
                // Larger than the socket buffers, so the write cannot finish.
                let frame = vec![0u8; 64 << 20];
                send_frame(&conn, &frame, Instant::now() + Duration::from_secs(30)).await
            })
        };
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(conn.open(), "the write is still running");
        send.abort();
        let _ = send.await;
        assert!(!conn.open());
    }

    /// RFC 7766 §6.2.3: a connection a timed-out query marked dead is shut
    /// down at the next idle tick even while the link still holds it, so a
    /// blackholed server does not keep a socket open on a quiet host.
    #[tokio::test]
    async fn a_connection_marked_dead_is_shut_down_while_still_held() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        let conn = Arc::new(TcpConn::start(client));
        drop(conn.wait_for(7, Instant::now()).unwrap().expect("open"));
        assert!(!conn.open(), "a waiter out of time with nothing heard marks the connection dead");
        let mut byte = [0u8; 1];
        let read = tokio::time::timeout(TCP_IDLE + Duration::from_secs(2), server.read(&mut byte)).await;
        assert!(matches!(read, Ok(Ok(0))), "the server sees the connection shut down: {read:?}");
        drop(conn);
    }

    /// A connection that went silent is replaced: otherwise steady traffic
    /// keeps it open and every query on it fails.
    #[tokio::test]
    async fn a_silent_tcp_connection_is_replaced_after_a_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut silent, _) = listener.accept().await.unwrap();
            let held = tokio::spawn(async move { while tcp_frame(&mut silent).await.is_some() {} });
            let (mut second, _) = listener.accept().await.unwrap();
            while let Some(query) = tcp_frame(&mut second).await {
                write_tcp_frame(&mut second, &a_reply(&query, [192, 0, 2, 9])).await;
            }
            held.abort();
        });
        let mut cfg = config(vec![], vec![addr]);
        cfg.upstream_timeout_seconds = 1;
        let pool = Arc::new(UpstreamPool::new(&cfg).unwrap());
        assert!(pool.exchange_from(&raw_query("first.test.", RecordType::A, 1), 1, true).await.is_none());
        let next = pool.exchange_from(&raw_query("next.test.", RecordType::A, 2), 2, true).await;
        assert!(next.is_some(), "the next query gets a new connection");
        server.abort();
    }

    /// Frames for no query in flight must not crowd out a real reply.
    #[tokio::test]
    async fn orphan_tcp_frames_do_not_cost_a_query_its_reply() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let query = tcp_frame(&mut stream).await.unwrap();
            let id = u16::from_be_bytes([query[0], query[1]]);
            let mut burst = Vec::new();
            for _ in 0..16 {
                let mut orphan = a_reply(&query, [192, 0, 2, 1]);
                orphan[..2].copy_from_slice(&id.wrapping_add(1).to_be_bytes());
                burst.extend_from_slice(&(orphan.len() as u16).to_be_bytes());
                burst.extend_from_slice(&orphan);
            }
            let real = a_reply(&query, [192, 0, 2, 9]);
            burst.extend_from_slice(&(real.len() as u16).to_be_bytes());
            burst.extend_from_slice(&real);
            stream.write_all(&burst).await.unwrap();
            tcp_frame(&mut stream).await;
        });
        let pool = Arc::new(UpstreamPool::new(&config(vec![], vec![addr])).unwrap());
        let query = raw_query("orphans.test.", RecordType::A, 6);
        assert!(pool.exchange_from(&query, 6, true).await.is_some());
        server.abort();
    }

    /// A server may close a connection at any time, so a query it did not
    /// answer goes out again on a new one (RFC 7766 §6.2.4).
    #[tokio::test]
    async fn rfc7766_a_query_on_a_connection_the_server_closed_is_sent_again() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            // The first connection drops its query unanswered.
            let (mut first, _) = listener.accept().await.unwrap();
            tcp_frame(&mut first).await;
            drop(first);
            let (mut second, _) = listener.accept().await.unwrap();
            while let Some(query) = tcp_frame(&mut second).await {
                write_tcp_frame(&mut second, &a_reply(&query, [192, 0, 2, 9])).await;
            }
        });
        let pool = Arc::new(UpstreamPool::new(&config(vec![], vec![addr])).unwrap());
        let query = raw_query("closed.test.", RecordType::A, 5);
        assert!(pool.exchange_from(&query, 5, true).await.is_some());
        server.abort();
    }

    /// RFC 1035 §4.2.1: a lost datagram is sent again, unchanged, so a reply
    /// to either copy matches.
    #[tokio::test]
    async fn rfc1035_s1792_a_lost_udp_query_is_retransmitted() {
        let asked = AtomicUsize::new(0);
        let handler: UdpHandler = Arc::new(move |raw: &[u8]| {
            (asked.fetch_add(1, Ordering::SeqCst) > 0).then(|| a_reply(raw, [192, 0, 2, 7]))
        });
        let udp = UdpMock::start(handler).await;
        let mut cfg = config(vec![], vec![udp.addr]);
        cfg.upstream_timeout_seconds = 5;
        let pool = Arc::new(UpstreamPool::new(&cfg).unwrap());
        let query = raw_query("lost.test.", RecordType::A, 3);
        let started = Instant::now();
        assert!(pool.exchange(&query, 3).await.is_some(), "the second copy is answered");
        assert!(started.elapsed() >= RETRANSMIT_AFTER, "not sooner than RFC 1035 recommends");
        let seen = udp.seen.lock().unwrap();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0], seen[1], "same ID and same question");
    }

    /// RFC 8085 §3.1.1: a fallback keeps a round-trip estimate, fed only by
    /// replies to a datagram sent once. After a retransmission a reply could
    /// belong to either copy, so it is no sample (Karn's rule).
    #[tokio::test]
    async fn rfc8085_s531_rtt_estimate_skips_retransmitted_datagrams() {
        let answer_at = |skip: usize| {
            let asked = AtomicUsize::new(0);
            let handler: UdpHandler = Arc::new(move |raw: &[u8]| {
                (asked.fetch_add(1, Ordering::SeqCst) >= skip).then(|| a_reply(raw, [192, 0, 2, 7]))
            });
            handler
        };
        let udp = UdpMock::start(answer_at(0)).await;
        let mut cfg = config(vec![], vec![udp.addr]);
        cfg.upstream_timeout_seconds = 5;
        let pool = Arc::new(UpstreamPool::new(&cfg).unwrap());
        assert!(pool.exchange(&raw_query("rtt.test.", RecordType::A, 3), 3).await.is_some());
        assert!(pool.fallback_state[0].lock().unwrap().rtt_us > 0, "a first-try reply is a sample");

        let udp = UdpMock::start(answer_at(1)).await;
        let mut cfg = config(vec![], vec![udp.addr]);
        cfg.upstream_timeout_seconds = 5;
        let pool = Arc::new(UpstreamPool::new(&cfg).unwrap());
        assert!(pool.exchange(&raw_query("rtt.test.", RecordType::A, 3), 3).await.is_some());
        assert_eq!(pool.fallback_state[0].lock().unwrap().rtt_us, 0, "a retransmitted datagram is no sample");
    }

    #[test]
    fn rfc1035_s2541_retransmit_interval_follows_the_rtt_within_2_to_5_s() {
        let ms = |n: u64| Duration::from_millis(n);
        assert_eq!(retransmit_interval(0), ms(2000), "no estimate");
        assert_eq!(retransmit_interval(50_000), ms(2000), "a fast path stays at the floor");
        assert_eq!(retransmit_interval(1_000_000), ms(2000), "2 x 1 s");
        assert_eq!(retransmit_interval(1_500_000), ms(3000));
        assert_eq!(retransmit_interval(2_500_000), ms(5000));
        assert_eq!(retransmit_interval(60_000_000), ms(5000), "capped");
        assert_eq!(retransmit_interval(u64::MAX), ms(5000), "no overflow");
    }

    /// RFC 2308 §7.1: a failure is cached per server. The budget here reaches
    /// only the first upstreams, so the failure says nothing about the last
    /// one, which the next query must still try.
    #[tokio::test]
    async fn rfc2308_s582b_a_failure_does_not_suppress_a_server_that_was_not_asked() {
        let silent = |asked: Arc<AtomicUsize>| {
            Arc::new(move |_: &[u8]| {
                asked.fetch_add(1, Ordering::SeqCst);
                Reply { delay: Duration::from_secs(5), ..Reply::dns(vec![]) }
            })
        };
        let first_asked = Arc::new(AtomicUsize::new(0));
        let first = DohMock::start(silent(first_asked.clone())).await;
        let second = DohMock::start(silent(Arc::default())).await;
        let third = DohMock::start(silent(Arc::default())).await;
        let last = DohMock::start(Arc::new(|raw: &[u8]| Reply::dns(a_reply(raw, [192, 0, 2, 5])))).await;
        let urls = vec![first.url.clone(), second.url.clone(), third.url.clone(), last.url.clone()];
        let mut cfg = config(urls, vec![]);
        cfg.upstream_timeout_seconds = 1;
        cfg.upstream_strategy = UpstreamStrategy::Ordered;
        let pool = Arc::new(UpstreamPool::new(&cfg).unwrap());
        let query = raw_query("partial.test.", RecordType::A, 9);
        assert!(pool.exchange(&query, 9).await.is_none(), "the budget ends before the last upstream");
        let answer = pool.exchange(&query, 9).await.expect("the last upstream was never asked");
        assert_eq!(answer.upstream_index, Some(3));
        assert_eq!(first_asked.load(Ordering::SeqCst), 1, "a server with a live mark is not asked again");
    }

    #[tokio::test]
    async fn rfc8914_s504_a_servfail_advances_whatever_its_ede_says() {
        // EDE 6 (DNSSEC Bogus) is diagnostic: it must not change the failover.
        let bogus = DohMock::start(Arc::new(|raw: &[u8]| {
            Reply::dns(with_ede(reply_for(raw, ResponseCode::ServFail, vec![], vec![]), 6))
        }))
        .await;
        let second = DohMock::start(Arc::new(|raw: &[u8]| Reply::dns(a_reply(raw, [192, 0, 2, 5])))).await;
        let plain = UdpMock::start(Arc::new(|raw: &[u8]| Some(a_reply(raw, [192, 0, 2, 66])))).await;
        let mut cfg = config(vec![bogus.url.clone(), second.url.clone()], vec![plain.addr]);
        cfg.upstream_hedge_ms = 1000;
        cfg.upstream_strategy = UpstreamStrategy::Ordered;
        let pool = Arc::new(UpstreamPool::new(&cfg).unwrap());
        let query = raw_query("bogus.test.", RecordType::A, 4);
        let answer = pool.exchange(&query, 4).await.expect("the next upstream answers");
        assert_eq!(answer.upstream_index, Some(1));
        assert!(plain.seen.lock().unwrap().is_empty(), "a reachable DoH upstream rules out plaintext");

        // With no other DoH upstream the attempt fails and plaintext stays unused.
        let mut cfg = config(vec![bogus.url.clone()], vec![plain.addr]);
        cfg.upstream_hedge_ms = 1000;
        let pool = Arc::new(UpstreamPool::new(&cfg).unwrap());
        assert!(pool.exchange(&query, 4).await.is_none());
        assert!(plain.seen.lock().unwrap().is_empty());
    }

    /// The plaintext fallback is for a DoH upstream that cannot be reached.
    /// An HTTP error status or an invalid body comes from a reachable
    /// endpoint and may depend on the name, so it never downgrades the query;
    /// a refused connection does, and so does an endpoint the root-NS probe
    /// has confirmed down.
    #[tokio::test]
    async fn only_transport_failures_use_the_plain_fallback() {
        let doh = DohMock::start(Arc::new(|raw: &[u8]| {
            if is_probe(raw) {
                return Reply::error(503);
            }
            let name = parsed(raw).queries[0].name().to_ascii();
            let status = name.split('-').next().unwrap_or("").parse::<u16>().unwrap_or(200);
            if status != 200 {
                Reply::error(status)
            } else if name.starts_with("type") {
                Reply { status: 200, ..Reply::error(0) }
            } else {
                Reply::dns(b"not a dns message".to_vec())
            }
        }))
        .await;
        let plain = UdpMock::start(Arc::new(|raw: &[u8]| Some(a_reply(raw, [192, 0, 2, 66])))).await;
        let pool = Arc::new(UpstreamPool::new(&config(vec![doh.url.clone()], vec![plain.addr])).unwrap());
        for (id, name) in ["400-a.test.", "404-b.test.", "502-c.test.", "503-d.test.", "type-e.test.", "body-f.test."]
            .into_iter()
            .enumerate()
        {
            let id = id as u16 + 1;
            assert!(pool.exchange(&raw_query(name, RecordType::A, id), id).await.is_none(), "{name}: no downgrade");
        }
        assert!(plain.seen.lock().unwrap().is_empty(), "the plaintext fallback was never asked");

        // Three failed probes confirm an endpoint-wide 5xx. The endpoint is
        // unhealthy but reachable, so still no downgrade: a client flood can
        // provoke an endpoint-wide error status, never a failure to connect.
        for _ in 0..3 {
            pool.probe_all().await;
        }
        assert!(!pool.health()[0].healthy);
        assert!(pool.exchange(&raw_query("503-g.test.", RecordType::A, 9), 9).await.is_none(), "reachable endpoint");
        assert!(plain.seen.lock().unwrap().is_empty(), "still never plaintext");

        // A refused connection is a transport failure.
        let dead = config(vec!["http://127.0.0.1:1/dns-query".into()], vec![plain.addr]);
        let pool = Arc::new(UpstreamPool::new(&dead).unwrap());
        let answer = pool.exchange(&raw_query("transport.test.", RecordType::A, 5), 5).await.expect("fallback");
        assert_eq!((answer.upstream_index, answer_address(&answer)), (None, Some([192, 0, 2, 66])));
    }

    #[test]
    fn local_socket_errors_are_not_upstream_failures() {
        use std::io::{Error, ErrorKind};
        for code in LOCAL_ERRNOS {
            assert!(io_fail(&Error::from_raw_os_error(code)) == Fail::Local, "errno {code}");
        }
        assert!(io_fail(&Error::from(ErrorKind::OutOfMemory)) == Fail::Local);
        assert!(io_fail(&Error::from(ErrorKind::ConnectionRefused)) == Fail::Unreachable);
        assert!(io_fail(&Error::from(ErrorKind::TimedOut)) == Fail::Remote);
    }

    #[test]
    fn the_failure_map_enforces_entry_and_byte_bounds_and_tracks_its_size() {
        // 4096 entries and 1 MiB in the default build.
        // Marks older than the 1 s hold, so the bounds may evict them.
        let mark = (Instant::now() - FAILURE_MIN_HOLD * 2, FAILURE_WINDOW);
        let mut map = FailureMap::default();
        let key = |n: u32| -> Box<[u8]> { n.to_be_bytes().to_vec().into() };
        for n in 0..10u32 {
            assert!(map.insert(key(n), mark, 4, FAILURE_BYTES));
        }
        assert_eq!(map.map.len(), 4);
        assert_eq!(map.bytes, 4 * charge(&key(0)));
        map.insert(key(9), mark, 4, FAILURE_BYTES);
        assert_eq!(map.map.len(), 4, "re-marking a key does not grow the map");
        map.remove(&key(9));
        assert_eq!(map.map.len(), 3);
        assert_eq!(map.bytes, 3 * charge(&key(0)));
        // Byte bound: room for exactly two 100-byte keys.
        let big = |n: u8| -> Box<[u8]> { vec![n; 100].into() };
        let limit = 2 * charge(&big(0));
        let mut map = FailureMap::default();
        for n in 0..5u8 {
            assert!(map.insert(big(n), mark, 4096, limit));
        }
        assert_eq!(map.map.len(), 2);
        assert!(map.bytes <= limit);
        assert!(!map.insert(vec![0u8; limit].into(), mark, 4096, limit), "a key that cannot fit is rejected");
        assert_eq!(map.map.len(), 2);
        assert_eq!((FAILURE_CAPACITY, FAILURE_BYTES), (4096, 1 << 20));
    }

    #[tokio::test]
    async fn zone_transfers_relayed_at_once_are_bounded() {
        // A server that accepts and holds every connection, like an upstream
        // in the middle of long transfers.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });
        let pool = Arc::new(UpstreamPool::new(&config(vec![], vec![addr])).unwrap());
        let axfr = raw_query("zone.test.", RecordType::AXFR, 7);
        let mut open = Vec::new();
        for n in 0..TRANSFER_CONCURRENCY {
            open.push(pool.open_transfer(&axfr).await.unwrap_or_else(|| panic!("transfer {n} opens")));
        }
        let waiting = {
            let (pool, axfr) = (pool.clone(), axfr.clone());
            tokio::spawn(async move { pool.open_transfer(&axfr).await.is_some() })
        };
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!waiting.is_finished(), "a fifth transfer waits while every slot is taken");
        open.pop();
        assert!(waiting.await.unwrap(), "a finished relay frees its slot for the waiting one");
    }

    #[test]
    fn rfc9520_s454_a_failure_younger_than_one_second_is_never_evicted() {
        let key = |n: u32| -> Box<[u8]> { n.to_be_bytes().to_vec().into() };
        let fresh = (Instant::now(), FAILURE_WINDOW);
        let mut map = FailureMap::default();
        assert!(map.insert(key(1), fresh, 2, FAILURE_BYTES));
        assert!(map.insert(key(2), fresh, 2, FAILURE_BYTES));
        assert!(!map.insert(key(3), fresh, 2, FAILURE_BYTES), "a full map of fresh marks refuses a new one");
        assert!(map.map.contains_key(&key(1)) && map.map.contains_key(&key(2)), "both fresh marks stay");
        assert!(map.insert(key(1), fresh, 2, FAILURE_BYTES), "re-marking a held key needs no eviction");
        // Once the oldest has been held for a second, it makes room.
        let old = (Instant::now() - FAILURE_MIN_HOLD * 2, FAILURE_WINDOW);
        let mut map = FailureMap::default();
        assert!(map.insert(key(1), old, 2, FAILURE_BYTES));
        assert!(map.insert(key(2), fresh, 2, FAILURE_BYTES));
        assert!(map.insert(key(3), fresh, 2, FAILURE_BYTES));
        assert!(!map.map.contains_key(&key(1)) && map.map.contains_key(&key(2)) && map.map.contains_key(&key(3)));
    }

    #[tokio::test]
    async fn the_default_pool_failure_cache_is_byte_bounded() {
        let pool = UpstreamPool::new(&config(vec![], vec![])).unwrap();
        for n in 0..(FAILURE_CAPACITY as u32 + 50) {
            pool.mark_failure(n.to_be_bytes().to_vec().into());
        }
        let failures = pool.failures.lock().unwrap();
        assert_eq!(failures.map.len(), FAILURE_CAPACITY);
        assert_eq!(failures.bytes, failures.map.keys().map(|key| charge(key)).sum::<usize>());
        assert!(failures.bytes <= FAILURE_BYTES);
    }

    fn ns_record(owner: &str) -> Record {
        Record::from_rdata(
            Name::from_ascii(owner).unwrap(),
            60,
            RData::NS(hickory_proto::rr::rdata::NS(Name::from_ascii("ns.evil.test.").unwrap())),
        )
    }

    fn a_record(owner: &str, octets: [u8; 4]) -> Record {
        Record::from_rdata(
            Name::from_ascii(owner).unwrap(),
            60,
            RData::A(AData::new(octets[0], octets[1], octets[2], octets[3])),
        )
    }

    #[tokio::test]
    async fn plain_replies_are_scrubbed_of_unrelated_records() {
        // Additional and off-chain Authority data never reach the client.
        let handler: UdpHandler = Arc::new(|raw: &[u8]| {
            let query = parsed(raw);
            let name = query.queries[0].name().to_ascii();
            let mut message =
                parsed(&reply_for(raw, ResponseCode::NoError, vec![a_record(&name, [192, 0, 2, 7])], vec![]));
            message.add_authority(ns_record("test."));
            message.add_authority(ns_record("victim.test."));
            message.add_authority(a_record("victim.test.", [203, 0, 113, 9]));
            message.add_additional(a_record("victim.test.", [203, 0, 113, 9]));
            message.add_additional(a_record("ns.evil.test.", [203, 0, 113, 10]));
            let mut bytes = message.to_vec().ok()?;
            wire::copy_question_case(raw, &mut bytes);
            Some(bytes)
        });
        let udp = UdpMock::start(handler).await;
        let pool = Arc::new(UpstreamPool::new(&config(vec![], vec![udp.addr])).unwrap());
        let query = raw_query("scrub.test.", RecordType::A, 0x1111);
        let answer = pool.exchange(&query, 0x1111).await.expect("the clean part of the reply is relayed");
        assert!(answer.terminal);
        assert_eq!(answer_address(&answer), Some([192, 0, 2, 7]));
        let message = parsed(&answer.raw);
        assert_eq!(message.answers.len(), 1);
        let authorities: Vec<_> = message.authorities.iter().map(|r| r.name.to_ascii()).collect();
        assert_eq!(authorities, ["test."], "only the NS at or above the question remains");
        assert!(message.additionals.is_empty(), "Additional keeps only OPT");
        assert_eq!(answer.message.authorities.len(), 1, "the parsed view matches the bytes");
    }

    #[tokio::test]
    async fn a_plain_reply_with_an_off_chain_answer_owner_is_a_failed_attempt() {
        let handler: UdpHandler = Arc::new(|raw: &[u8]| {
            Some(reply_for(raw, ResponseCode::NoError, vec![a_record("victim.test.", [203, 0, 113, 9])], vec![]))
        });
        let udp = UdpMock::start(handler).await;
        let pool = Arc::new(UpstreamPool::new(&config(vec![], vec![udp.addr])).unwrap());
        let query = raw_query("a.test.", RecordType::A, 0x2222);
        assert!(pool.exchange(&query, 0x2222).await.is_none());
    }

    #[tokio::test]
    async fn rfc5452_s506_doh_replies_are_scrubbed_of_unrelated_records() {
        let doh = DohMock::start(Arc::new(|raw: &[u8]| {
            let query = parsed(raw);
            let name = query.queries[0].name().to_ascii();
            let mut message =
                parsed(&reply_for(raw, ResponseCode::NoError, vec![a_record(&name, [192, 0, 2, 7])], vec![]));
            message.add_additional(a_record("extra.test.", [203, 0, 113, 9]));
            Reply::dns(message.to_vec().unwrap())
        }))
        .await;
        let pool = Arc::new(UpstreamPool::new(&config(vec![doh.url.clone()], vec![])).unwrap());
        let query = raw_query("scrubbed.test.", RecordType::A, 6);
        let answer = pool.exchange(&query, 6).await.unwrap();
        assert_eq!(parsed(&answer.raw).answers.len(), 1);
        assert!(parsed(&answer.raw).additionals.is_empty(), "Additional keeps only OPT");
        assert!(answer.message.additionals.is_empty(), "the parsed view matches the bytes");
    }

    #[tokio::test]
    async fn rfc5452_s506_a_doh_reply_with_an_off_chain_answer_owner_is_a_failed_attempt() {
        let doh = DohMock::start(Arc::new(|raw: &[u8]| {
            Reply::dns(reply_for(raw, ResponseCode::NoError, vec![a_record("victim.test.", [203, 0, 113, 9])], vec![]))
        }))
        .await;
        let pool = Arc::new(UpstreamPool::new(&config(vec![doh.url.clone()], vec![])).unwrap());
        let query = raw_query("a.test.", RecordType::A, 7);
        assert!(pool.exchange(&query, 7).await.is_none());
    }

    /// A UDP upstream that records `(source port, query)` and answers through
    /// `handler`.
    type PortSeen = Arc<Mutex<Vec<(u16, Vec<u8>)>>>;
    type PortHandler = Arc<dyn Fn(usize, &[u8]) -> Vec<(Duration, Vec<u8>)> + Send + Sync>;

    struct PortMock {
        addr: SocketAddr,
        seen: PortSeen,
        task: JoinHandle<()>,
    }

    impl Drop for PortMock {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    impl PortMock {
        /// `handler(query_index, query)` returns the datagrams to send back,
        /// each after its delay.
        async fn start(handler: PortHandler) -> Self {
            let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let addr = socket.local_addr().unwrap();
            let seen: PortSeen = Arc::new(Mutex::new(Vec::new()));
            let recorded = seen.clone();
            let task = tokio::spawn(async move {
                let mut buffer = vec![0u8; MAX_DNS_MESSAGE];
                loop {
                    let Ok((n, peer)) = socket.recv_from(&mut buffer).await else { return };
                    let query = buffer[..n].to_vec();
                    let index = {
                        let mut seen = recorded.lock().unwrap();
                        seen.push((peer.port(), query.clone()));
                        seen.len() - 1
                    };
                    for (delay, reply) in handler(index, &query) {
                        let socket = socket.clone();
                        tokio::spawn(async move {
                            tokio::time::sleep(delay).await;
                            let _ = socket.send_to(&reply, peer).await;
                        });
                    }
                }
            });
            Self { addr, seen, task }
        }
    }

    const LONG_NAME: &str = "MiXeD.CaSe.QuErY.NaMe.WiTh.LoTs.Of.LeTtErS.TeSt.";

    #[tokio::test]
    async fn the_0x20_retry_leaves_from_a_fresh_source_port_with_a_fresh_id() {
        // A normalising upstream still works, and the un-randomised
        // retry never reuses the first query's socket.
        let lower = Arc::new(|_: usize, raw: &[u8]| {
            let mut reply = a_reply(raw, [192, 0, 2, 13]);
            let end = 12 + wire::parse_query(raw).unwrap().qname_wire.len();
            reply[12..end].make_ascii_lowercase();
            vec![(Duration::ZERO, reply)]
        });
        let mock = PortMock::start(lower).await;
        let pool = Arc::new(UpstreamPool::new(&config(vec![], vec![mock.addr])).unwrap());
        let query = raw_query(LONG_NAME, RecordType::A, 0x3434);
        let answer = pool.exchange(&query, 0x3434).await.expect("normalising upstream answers");
        assert_eq!(answer_address(&answer), Some([192, 0, 2, 13]));
        let seen = mock.seen.lock().unwrap();
        assert_eq!(seen.len(), 2, "the randomised query and one retry");
        assert_ne!(seen[0].0, seen[1].0, "the retry uses a new source port");
        assert_ne!(seen[0].1[0..2], seen[1].1[0..2], "and a new ID");
        let n = wire::parse_query(&query).unwrap().qname_wire.len();
        assert_eq!(seen[1].1[12..12 + n], query[12..12 + n], "the retry carries the client's own case");
    }

    #[tokio::test]
    async fn a_case_preserving_upstream_never_gets_a_retry() {
        // After one exact-case reply, a case-only mismatch is forged.
        let behaviour = Arc::new(|index: usize, raw: &[u8]| {
            if index == 0 {
                return vec![(Duration::ZERO, a_reply(raw, [192, 0, 2, 1]))];
            }
            let mut forged = a_reply(raw, [203, 0, 113, 66]);
            assert!(flip_question_case(&mut forged));
            vec![(Duration::ZERO, forged), (Duration::from_millis(40), a_reply(raw, [192, 0, 2, 2]))]
        });
        let mock = PortMock::start(behaviour).await;
        let pool = Arc::new(UpstreamPool::new(&config(vec![], vec![mock.addr])).unwrap());
        let query = raw_query(LONG_NAME, RecordType::A, 0x4545);
        let first = pool.exchange(&query, 0x4545).await.expect("first answer");
        assert_eq!(answer_address(&first), Some([192, 0, 2, 1]));
        assert!(pool.preserves_case[0].load(Ordering::Relaxed), "the exact-case reply is remembered");
        let second = pool.exchange(&query, 0x4545).await.expect("the correct reply is still accepted");
        assert_eq!(answer_address(&second), Some([192, 0, 2, 2]), "the forged mismatch was discarded");
        assert_eq!(mock.seen.lock().unwrap().len(), 2, "exactly one query per exchange: no retry");
    }

    #[tokio::test]
    async fn failure_markers_suppress_repeats() {
        let requests = Arc::new(AtomicUsize::new(0));
        let handler: DohHandler = {
            let requests = requests.clone();
            Arc::new(move |raw: &[u8]| {
                if is_probe(raw) {
                    probe_handler(raw)
                } else {
                    requests.fetch_add(1, Ordering::SeqCst);
                    Reply::error(500)
                }
            })
        };
        let mock = DohMock::start(handler).await;
        let cfg = config(vec![mock.url.clone()], vec![]);
        let pool = Arc::new(UpstreamPool::new(&cfg).unwrap());
        let query = raw_query("suppress.test.", RecordType::A, 21);
        assert!(pool.exchange(&query, 21).await.is_none());
        let first = requests.load(Ordering::SeqCst);
        let started = Instant::now();
        assert!(pool.exchange(&query, 21).await.is_none());
        assert!(started.elapsed() < Duration::from_millis(100));
        assert_eq!(requests.load(Ordering::SeqCst), first);
    }

    #[tokio::test]
    async fn an_unshareable_query_never_suppresses_the_shared_key() {
        // An RD=0 variant that fails must not put
        // the ordinary RD=1 key of the same name into suppression.
        let requests = Arc::new(AtomicUsize::new(0));
        let handler: DohHandler = {
            let requests = requests.clone();
            Arc::new(move |_raw: &[u8]| {
                requests.fetch_add(1, Ordering::SeqCst);
                Reply::error(500)
            })
        };
        let mock = DohMock::start(handler).await;
        let pool = Arc::new(UpstreamPool::new(&config(vec![mock.url.clone()], vec![])).unwrap());
        let mut odd = raw_query("odd.test.", RecordType::A, 5);
        odd[2] &= !0x01; // RD=0
        assert!(pool.exchange(&odd, 5).await.is_none());
        let after_odd = requests.load(Ordering::SeqCst);
        let plain = raw_query("odd.test.", RecordType::A, 6);
        assert!(pool.exchange(&plain, 6).await.is_none());
        assert!(requests.load(Ordering::SeqCst) > after_odd, "the RD=1 query still went upstream");
    }

    #[tokio::test]
    async fn failure_suppression_is_isolated_by_dnssec_context() {
        let requests = Arc::new(AtomicUsize::new(0));
        let handler: DohHandler = {
            let requests = requests.clone();
            Arc::new(move |_raw: &[u8]| {
                requests.fetch_add(1, Ordering::SeqCst);
                Reply::error(500)
            })
        };
        let mock = DohMock::start(handler).await;
        let cfg = config(vec![mock.url.clone()], vec![]);
        let pool = Arc::new(UpstreamPool::new(&cfg).unwrap());
        let query = |id: u16, cd: bool, do_bit: bool, edns: bool| {
            let mut q = Message::new(id, MessageType::Query, OpCode::Query);
            q.metadata.recursion_desired = true;
            q.metadata.checking_disabled = cd;
            if edns {
                q.edns.get_or_insert_with(Default::default).set_dnssec_ok(do_bit);
            }
            q.add_query(Query::query(Name::from_ascii("ctx.test.").unwrap(), RecordType::A));
            q.to_vec().unwrap()
        };

        let cd = query(1, true, false, false);
        assert!(pool.exchange(&cd, 1).await.is_none());
        assert_eq!(requests.load(Ordering::SeqCst), 1);

        // The CD=1 failure must not suppress the plain context.
        let plain = query(2, false, false, false);
        assert!(pool.exchange(&plain, 2).await.is_none());
        assert_eq!(requests.load(Ordering::SeqCst), 2);

        // DO and bare EDNS presence are distinct contexts too.
        let do_query = query(3, false, true, true);
        assert!(pool.exchange(&do_query, 3).await.is_none());
        assert_eq!(requests.load(Ordering::SeqCst), 3);
        let edns = query(4, false, false, true);
        assert!(pool.exchange(&edns, 4).await.is_none());
        assert_eq!(requests.load(Ordering::SeqCst), 4);

        // The plain query's own failure still suppresses an immediate repeat.
        assert!(pool.exchange(&plain, 2).await.is_none());
        assert_eq!(requests.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn malformed_or_overflowing_age_fails_the_attempt() {
        for value in ["", "-1", "12x", "99999999999"] {
            let header = value.to_string();
            let label = value.to_string();
            let handler: DohHandler =
                Arc::new(move |raw: &[u8]| Reply::dns(a_reply(raw, [192, 0, 2, 21])).age_raw(&header));
            let mock = DohMock::start(handler).await;
            let cfg = config(vec![mock.url.clone()], vec![]);
            let pool = Arc::new(UpstreamPool::new(&cfg).unwrap());
            let query = raw_query("bad-age.test.", RecordType::A, 0x1111);
            assert!(pool.exchange(&query, 0x1111).await.is_none(), "age {label:?}");
            assert!(pool.health()[0].last_error.as_deref().is_some_and(|error| error.contains("age")), "age {label:?}");
        }

        // A repeated Age field is malformed (the value is not a list).
        let handler: DohHandler = Arc::new(|raw: &[u8]| Reply::dns(a_reply(raw, [192, 0, 2, 22])).aged(1).aged(2));
        let mock = DohMock::start(handler).await;
        let cfg = config(vec![mock.url.clone()], vec![]);
        let pool = Arc::new(UpstreamPool::new(&cfg).unwrap());
        let query = raw_query("multi-age.test.", RecordType::A, 0x2222);
        assert!(pool.exchange(&query, 0x2222).await.is_none());
        assert_eq!(pool.health()[0].last_error.as_deref(), Some("multiple age headers"));
    }

    #[tokio::test]
    async fn responses_without_exactly_one_question_are_rejected() {
        for questions in [0usize, 2] {
            let handler: DohHandler = Arc::new(move |raw: &[u8]| {
                let query = parsed(raw);
                let mut response = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
                response.metadata.recursion_desired = true;
                response.metadata.recursion_available = true;
                response.metadata.response_code = ResponseCode::NoError;
                if questions > 0 {
                    response.add_query(query.queries[0].clone());
                }
                if questions > 1 {
                    response.add_query(Query::query(Name::from_ascii("extra.test.").unwrap(), RecordType::A));
                }
                let mut bytes = response.to_vec().unwrap();
                wire::copy_question_case(raw, &mut bytes);
                Reply::dns(bytes)
            });
            let mock = DohMock::start(handler).await;
            let cfg = config(vec![mock.url.clone()], vec![]);
            let pool = Arc::new(UpstreamPool::new(&cfg).unwrap());
            let query = raw_query("qdcount.test.", RecordType::A, 0x3333);
            assert!(pool.exchange(&query, 0x3333).await.is_none(), "qdcount {questions}");
            assert_eq!(pool.health()[0].last_error.as_deref(), Some("question mismatch"));
        }
    }

    #[tokio::test]
    async fn dropping_the_pool_stops_the_probe_loop() {
        let handler: DohHandler = Arc::new(|raw: &[u8]| Reply::dns(empty_reply(raw)));
        let mock = DohMock::start(handler).await;
        let cfg = config(vec![mock.url.clone()], vec![]);
        let pool = Arc::new(UpstreamPool::new(&cfg).unwrap());
        let probes = pool.spawn_probes();
        // Let the immediate pass finish so the loop is sleeping.
        tokio::time::sleep(Duration::from_millis(20)).await;
        drop(pool);
        tokio::time::timeout(Duration::from_millis(500), probes)
            .await
            .expect("probe loop exits after the pool is dropped")
            .unwrap();
    }

    #[tokio::test]
    async fn a_redirect_is_never_followed() {
        // https too: the target never even sees a connection attempt.
        for scheme in ["http", "https"] {
            let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let target_addr = target.local_addr().unwrap();
            let location = format!("{scheme}://{target_addr}/dns-query");
            let mock = DohMock::start(Arc::new(move |_raw: &[u8]| Reply::redirect(location.clone()))).await;
            let cfg = config(vec![mock.url.clone()], vec![]);
            let pool = Arc::new(UpstreamPool::new(&cfg).unwrap());
            let query = raw_query("redirect.test.", RecordType::A, 0x4444);
            assert!(pool.exchange(&query, 0x4444).await.is_none());
            assert!(!mock.seen.lock().unwrap().is_empty(), "initial request was sent");
            assert!(
                tokio::time::timeout(Duration::from_millis(100), target.accept()).await.is_err(),
                "{scheme} redirect target must never receive a connection"
            );
        }
    }

    #[tokio::test]
    async fn terminal_selection_waits_for_a_slow_positive_answer() {
        let real = Arc::new(AtomicUsize::new(0));
        let handler: DohHandler = {
            let real = real.clone();
            Arc::new(move |raw: &[u8]| {
                if is_probe(raw) {
                    return probe_handler(raw);
                }
                let n = real.fetch_add(1, Ordering::SeqCst);
                if n == 0 {
                    Reply::dns(cname_only_reply(raw))
                } else {
                    Reply::dns(a_reply(raw, [192, 0, 2, 15])).delayed(Duration::from_millis(120))
                }
            })
        };
        let first = DohMock::start(handler.clone()).await;
        let second = DohMock::start(handler).await;
        let cfg = config(vec![first.url.clone(), second.url.clone()], vec![]);
        let pool = Arc::new(UpstreamPool::new(&cfg).unwrap());
        let query = raw_query("slow-positive.test.", RecordType::A, 31);
        let started = Instant::now();
        let answer = pool.exchange(&query, 31).await.expect("terminal positive");
        assert!(started.elapsed() >= Duration::from_millis(100), "{:?}", started.elapsed());
        assert!(answer.terminal);
        assert_eq!(answer_address(&answer), Some([192, 0, 2, 15]));
        assert_eq!(real.load(Ordering::SeqCst), 2);
        assert_eq!(pool.health().iter().map(|upstream| upstream.wins).sum::<u64>(), 1);
    }

    #[tokio::test]
    async fn nxdomain_wins_without_hedging() {
        let real = Arc::new(AtomicUsize::new(0));
        let handler: DohHandler = {
            let real = real.clone();
            Arc::new(move |raw: &[u8]| {
                if is_probe(raw) {
                    return probe_handler(raw);
                }
                let n = real.fetch_add(1, Ordering::SeqCst);
                if n == 0 {
                    Reply::dns(nxdomain_with_soa(raw))
                } else {
                    Reply::dns(a_reply(raw, [192, 0, 2, 16])).delayed(Duration::from_millis(200))
                }
            })
        };
        let first = DohMock::start(handler.clone()).await;
        let second = DohMock::start(handler).await;
        let mut cfg = config(vec![first.url.clone(), second.url.clone()], vec![]);
        cfg.upstream_hedge_ms = 200;
        let pool = Arc::new(UpstreamPool::new(&cfg).unwrap());
        let query = raw_query("nx.test.", RecordType::A, 41);
        let started = Instant::now();
        let answer = pool.exchange(&query, 41).await.expect("nxdomain");
        assert!(started.elapsed() < Duration::from_millis(150), "{:?}", started.elapsed());
        assert!(answer.terminal);
        let message = Message::from_vec(&answer.raw).unwrap();
        assert_eq!(message.metadata.response_code, ResponseCode::NXDomain);
        assert_eq!(real.load(Ordering::SeqCst), 1);
        assert_eq!(pool.health().iter().map(|upstream| upstream.hedges).sum::<u64>(), 0);
    }

    #[tokio::test]
    async fn incomplete_answers_are_returned_but_not_terminal() {
        let handler: DohHandler =
            Arc::new(|raw: &[u8]| if is_probe(raw) { probe_handler(raw) } else { Reply::dns(cname_only_reply(raw)) });
        let mock = DohMock::start(handler).await;
        let cfg = config(vec![mock.url.clone()], vec![]);
        let pool = Arc::new(UpstreamPool::new(&cfg).unwrap());
        let query = raw_query("incomplete.test.", RecordType::A, 51);
        let answer = pool.exchange(&query, 51).await.expect("incomplete fallback");
        assert!(!answer.terminal);
        assert!(Message::from_vec(&answer.raw).is_ok());
    }

    #[tokio::test]
    async fn inflight_bound_returns_servfail_instead_of_queueing() {
        let handler: DohHandler = Arc::new(|raw: &[u8]| {
            if is_probe(raw) {
                probe_handler(raw)
            } else {
                Reply::dns(a_reply(raw, [192, 0, 2, 17])).delayed(Duration::from_millis(250))
            }
        });
        let mock = DohMock::start(handler).await;
        let mut cfg = config(vec![mock.url.clone()], vec![]);
        cfg.upstream_inflight_max = 1;
        let pool = Arc::new(UpstreamPool::new(&cfg).unwrap());
        let pool_task = pool.clone();
        let first = tokio::spawn(async move {
            let query = raw_query("bounded-one.test.", RecordType::A, 61);
            pool_task.exchange(&query, 61).await
        });
        let deadline = Instant::now() + Duration::from_secs(1);
        while !mock.seen.lock().unwrap().iter().any(|raw| !is_probe(raw)) {
            assert!(Instant::now() < deadline, "first query was never sent");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let started = Instant::now();
        let query = raw_query("bounded-two.test.", RecordType::A, 62);
        assert!(pool.exchange(&query, 62).await.is_none());
        assert!(started.elapsed() < Duration::from_millis(100));
        assert!(first.await.unwrap().is_some());
        let query = raw_query("bounded-three.test.", RecordType::A, 63);
        assert!(pool.exchange(&query, 63).await.is_some());
    }

    #[tokio::test]
    async fn doh_uses_id_zero_and_returns_the_age_header() {
        // AD policy is applied by the server's relay boundary (main.rs), so
        // the pool keeps the upstream bytes as received.
        let handler: DohHandler = Arc::new(|raw: &[u8]| Reply::dns(a_reply(raw, [192, 0, 2, 18])).aged(30));
        let mock = DohMock::start(handler).await;
        let cfg = config(vec![mock.url.clone()], vec![]);
        let pool = Arc::new(UpstreamPool::new(&cfg).unwrap());
        let query = raw_query("age.test.", RecordType::A, 0x5151);
        let answer = pool.exchange(&query, 0x5151).await.expect("doh answer");
        assert!(answer.terminal);
        assert_eq!(answer.age, 30);
        assert_eq!(answer.upstream_index, Some(0));
        assert_eq!(answer.raw[0..2], 0x5151u16.to_be_bytes());
        let seen = mock.seen.lock().unwrap();
        let sent = seen.iter().find(|raw| !is_probe(raw)).expect("doh request");
        assert_eq!(sent[0..2], [0, 0]);
        let n = wire::parse_query(&query).unwrap().qname_wire.len();
        assert_eq!(sent[12..12 + n], query[12..12 + n], "DoH keeps the client case");
    }

    #[tokio::test]
    async fn startup_probe_warms_every_upstream() {
        let handler: DohHandler = Arc::new(|raw: &[u8]| Reply::dns(empty_reply(raw)));
        let first = DohMock::start(handler.clone()).await;
        let second = DohMock::start(handler).await;
        let cfg = config(vec![first.url.clone(), second.url.clone()], vec![]);
        let pool = Arc::new(UpstreamPool::new(&cfg).unwrap());
        let probes = pool.spawn_probes();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let probes_seen =
                [&first, &second].into_iter().all(|mock| mock.seen.lock().unwrap().iter().any(|raw| is_probe(raw)));
            let warmed = pool.health().iter().all(|upstream| upstream.ewma_us > 0);
            if probes_seen && warmed {
                break;
            }
            assert!(Instant::now() < deadline, "startup probe did not warm every upstream");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        probes.abort();
        let health = pool.health();
        assert_eq!(health.len(), 2);
        assert!(health.iter().all(|upstream| upstream.healthy));
        // One probe path only: the immediate pass in `spawn_probes` is not
        // duplicated by the constructor.
        assert_eq!(first.seen.lock().unwrap().len(), 1);
        assert_eq!(second.seen.lock().unwrap().len(), 1);
    }

    /// Probes have a connection pool of their own: client queries filling a
    /// shared connection (its HTTP/2 stream limit) cannot delay a probe, whose
    /// timeout counts the endpoint as unreachable.
    #[tokio::test]
    async fn probes_do_not_share_the_query_connection() {
        // A keep-alive HTTP/1.1 endpoint that records the connection each
        // request arrived on.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/dns-query", listener.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorded = seen.clone();
        let server = tokio::spawn(async move {
            for connection in 0usize.. {
                let Ok((mut stream, _)) = listener.accept().await else { return };
                let recorded = recorded.clone();
                tokio::spawn(async move {
                    let mut buffer = Vec::new();
                    let mut chunk = [0u8; 4096];
                    loop {
                        let Some(head_end) = buffer.windows(4).position(|w| w == b"\r\n\r\n") else {
                            match stream.read(&mut chunk).await {
                                Ok(0) | Err(_) => return,
                                Ok(n) => buffer.extend_from_slice(&chunk[..n]),
                            }
                            continue;
                        };
                        let head = String::from_utf8_lossy(&buffer[..head_end]).to_ascii_lowercase();
                        let length: usize = head
                            .lines()
                            .find_map(|line| line.strip_prefix("content-length:"))
                            .and_then(|value| value.trim().parse().ok())
                            .unwrap_or(0);
                        while buffer.len() < head_end + 4 + length {
                            match stream.read(&mut chunk).await {
                                Ok(0) | Err(_) => return,
                                Ok(n) => buffer.extend_from_slice(&chunk[..n]),
                            }
                        }
                        let body: Vec<u8> = buffer.drain(..head_end + 4 + length).skip(head_end + 4).collect();
                        let reply = empty_reply(&body);
                        recorded.lock().unwrap().push((connection, is_probe(&body)));
                        let head = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n",
                            reply.len()
                        );
                        if stream.write_all(head.as_bytes()).await.is_err() || stream.write_all(&reply).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        let pool = UpstreamPool::new(&config(vec![url], vec![])).unwrap();
        let query = raw_query("kept.test.", RecordType::A, 9);
        assert!(pool.exchange(&query, 9).await.is_some());
        pool.probe_all().await;
        assert!(pool.exchange(&query, 9).await.is_some());
        server.abort();
        let seen = seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 3, "{seen:?}");
        let query_connections: Vec<usize> = seen.iter().filter(|(_, probe)| !probe).map(|(c, _)| *c).collect();
        assert_eq!(query_connections[0], query_connections[1], "queries reuse their connection: {seen:?}");
        assert!(
            seen.iter().any(|&(connection, probe)| probe && connection != query_connections[0]),
            "the probe opened its own connection: {seen:?}"
        );
    }

    #[tokio::test]
    async fn no_upstreams_is_ready_and_fails_cleanly() {
        let cfg = config(vec![], vec![]);
        let pool = Arc::new(UpstreamPool::new(&cfg).unwrap());
        assert!(pool.ready());
        assert!(pool.health().is_empty());
        let query = raw_query("nothing.test.", RecordType::A, 71);
        assert!(pool.exchange(&query, 71).await.is_none());
    }

    // ---- contradictory replies, oversize UDP, Retry-After ----

    fn txt_record(owner: &str, bytes: usize) -> Record {
        Record::from_rdata(
            Name::from_ascii(owner).unwrap(),
            60,
            RData::TXT(hickory_proto::rr::rdata::TXT::new(vec!["p".repeat(bytes)])),
        )
    }

    fn contradictory(raw: &[u8]) -> Vec<u8> {
        let query = parsed(raw);
        let name = query.queries[0].name().clone();
        let soa = Record::from_rdata(
            Name::from_ascii("test.").unwrap(),
            60,
            RData::SOA(SOA::new(
                Name::from_ascii("ns.test.").unwrap(),
                Name::from_ascii("hostmaster.test.").unwrap(),
                1,
                3600,
                600,
                86400,
                60,
            )),
        );
        let address = Record::from_rdata(name, 60, RData::A(AData::new(192, 0, 2, 66)));
        reply_for(raw, ResponseCode::NXDomain, vec![address], vec![soa])
    }

    #[tokio::test]
    async fn a_contradictory_reply_is_a_failed_attempt_over_doh_and_plain() {
        // NXDOMAIN with an address at the query name is no answer at all.
        let doh = DohMock::start(Arc::new(|raw: &[u8]| Reply::dns(contradictory(raw)))).await;
        let pool = Arc::new(UpstreamPool::new(&config(vec![doh.url.clone()], vec![])).unwrap());
        let query = raw_query("contradiction.test.", RecordType::A, 5);
        assert!(pool.exchange(&query, 5).await.is_none(), "DoH: nothing is relayed");

        // The next upstream's valid answer wins instead.
        let good = DohMock::start(Arc::new(|raw: &[u8]| Reply::dns(a_reply(raw, [192, 0, 2, 7])))).await;
        let pool = Arc::new(UpstreamPool::new(&config(vec![doh.url.clone(), good.url.clone()], vec![])).unwrap());
        let query = raw_query("contradiction2.test.", RecordType::A, 6);
        let answer = pool.exchange(&query, 6).await.expect("the second upstream answers");
        assert_eq!(answer_address(&answer), Some([192, 0, 2, 7]));

        // NOERROR whose Answer holds only another type at the owner, plain.
        let udp = UdpMock::start(Arc::new(|raw: &[u8]| {
            let owner = parsed(raw).queries[0].name().to_ascii();
            Some(reply_for(raw, ResponseCode::NoError, vec![txt_record(&owner, 4)], vec![]))
        }))
        .await;
        let pool = Arc::new(UpstreamPool::new(&config(vec![], vec![udp.addr])).unwrap());
        let query = raw_query("othertype.test.", RecordType::A, 7);
        assert!(pool.exchange(&query, 7).await.is_none(), "plain: nothing is relayed");
        assert!(!udp.seen.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_cname_loop_is_a_failed_attempt() {
        // RFC 1034 s3.6.2: loop-a -> loop-b -> loop-a never reaches an address.
        let cname = |owner: &str, target: &str| {
            Record::from_rdata(
                Name::from_ascii(owner).unwrap(),
                60,
                RData::CNAME(hickory_proto::rr::rdata::CNAME(Name::from_ascii(target).unwrap())),
            )
        };
        let looped = DohMock::start(Arc::new(move |raw: &[u8]| {
            let answers = vec![cname("loop-a.test.", "loop-b.test."), cname("loop-b.test.", "loop-a.test.")];
            Reply::dns(reply_for(raw, ResponseCode::NoError, answers, vec![]))
        }))
        .await;
        let pool = Arc::new(UpstreamPool::new(&config(vec![looped.url.clone()], vec![])).unwrap());
        let query = raw_query("loop-a.test.", RecordType::A, 8);
        assert!(pool.exchange(&query, 8).await.is_none(), "a loop is not relayed");

        let good = DohMock::start(Arc::new(|raw: &[u8]| Reply::dns(a_reply(raw, [192, 0, 2, 7])))).await;
        let pool = Arc::new(UpstreamPool::new(&config(vec![looped.url.clone(), good.url.clone()], vec![])).unwrap());
        let query = raw_query("loop-a.test.", RecordType::A, 9);
        let answer = pool.exchange(&query, 9).await.expect("the second upstream answers");
        assert_eq!(answer_address(&answer), Some([192, 0, 2, 7]));
    }

    #[tokio::test]
    async fn a_meta_type_or_foreign_class_answer_is_a_failed_attempt() {
        // A TSIG in Answer, an ANY-class and a CH-class address.
        for (label, rtype, class) in [("tsig", 250u16, 255u16), ("any-class", 1, 255), ("ch-class", 1, 3)] {
            let doh = DohMock::start(Arc::new(move |raw: &[u8]| {
                // One more Answer record after the genuine one: question-name pointer, type, class.
                let mut body = a_reply(raw, [192, 0, 2, 1]);
                body.extend_from_slice(&[0xc0, 12]);
                body.extend_from_slice(&rtype.to_be_bytes());
                body.extend_from_slice(&class.to_be_bytes());
                body.extend_from_slice(&60u32.to_be_bytes());
                body.extend_from_slice(&4u16.to_be_bytes());
                body.extend_from_slice(&[192, 0, 2, 9]);
                let answers = u16::from_be_bytes([body[6], body[7]]) + 1;
                body[6..8].copy_from_slice(&answers.to_be_bytes());
                Reply::dns(body)
            }))
            .await;
            let pool = Arc::new(UpstreamPool::new(&config(vec![doh.url.clone()], vec![])).unwrap());
            let query = raw_query(&format!("{label}.test."), RecordType::A, 8);
            assert!(pool.exchange(&query, 8).await.is_none(), "{label} makes the reply invalid");
        }
    }

    #[test]
    fn the_udp_limit_is_the_advertised_payload_or_512() {
        let plain = raw_query("limit.test.", RecordType::A, 1);
        assert_eq!(udp_limit(&wire::parse_query(&plain).unwrap()), 512);
        let edns = wire::set_do_bit(&plain).unwrap(); // appends an OPT advertising 1232
        assert_eq!(udp_limit(&wire::parse_query(&edns).unwrap()), 1232);
    }

    #[tokio::test]
    async fn an_oversize_udp_reply_is_not_final_and_the_question_is_retried_over_tcp() {
        // 12 x 255 bytes of TXT padding is far above the 512 a
        // non-EDNS query invited.
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let udp = UdpSocket::bind(addr).await.unwrap();
        let udp_task = tokio::spawn(async move {
            let mut buffer = vec![0u8; MAX_DNS_MESSAGE];
            let (n, peer) = udp.recv_from(&mut buffer).await.unwrap();
            let query = buffer[..n].to_vec();
            let name = parsed(&query).queries[0].name().clone();
            let mut answers = vec![Record::from_rdata(name.clone(), 60, RData::A(AData::new(198, 51, 100, 1)))];
            answers.extend((0..12).map(|_| txt_record(&name.to_ascii(), 255)));
            let big = reply_for(&query, ResponseCode::NoError, answers, vec![]);
            assert!(big.len() > 3000);
            udp.send_to(&big, peer).await.unwrap();
        });
        let tcp_task = tokio::spawn(async move {
            let (mut stream, _) = tcp.accept().await.unwrap();
            let mut len = [0u8; 2];
            stream.read_exact(&mut len).await.unwrap();
            let mut body = vec![0u8; u16::from_be_bytes(len) as usize];
            stream.read_exact(&mut body).await.unwrap();
            let reply = a_reply(&body, [192, 0, 2, 8]);
            stream.write_all(&(reply.len() as u16).to_be_bytes()).await.unwrap();
            stream.write_all(&reply).await.unwrap();
        });
        let pool = Arc::new(UpstreamPool::new(&config(vec![], vec![addr])).unwrap());
        let query = raw_query("oversize.test.", RecordType::A, 0x2468);
        let answer = pool.exchange(&query, 0x2468).await.expect("tcp answer");
        assert!(answer.terminal);
        assert_eq!(answer_address(&answer), Some([192, 0, 2, 8]), "the TCP answer, not the oversize datagram");
        udp_task.await.unwrap();
        tcp_task.await.unwrap();
    }

    #[test]
    fn retry_after_reads_seconds_and_http_dates() {
        let header = |value: &str| {
            let mut map = reqwest::header::HeaderMap::new();
            map.insert(reqwest::header::RETRY_AFTER, value.parse().unwrap());
            map
        };
        assert_eq!(retry_after(&reqwest::header::HeaderMap::new()), None);
        assert_eq!(retry_after(&header("120")), Some(Duration::from_secs(120)));
        assert_eq!(retry_after(&header(" 7 ")), Some(Duration::from_secs(7)));
        assert_eq!(retry_after(&header("0")), Some(Duration::ZERO));
        assert_eq!(retry_after(&header("99999999999999999999999999")), Some(Duration::from_secs(u64::MAX)));
        for bad in ["", "-1", "1.5", "soon", "12 s", "Sun, 99 Foo 2024 00:00:00 GMT"] {
            assert_eq!(retry_after(&header(bad)), None, "{bad:?}");
        }
        let later = httpdate::fmt_http_date(std::time::SystemTime::now() + Duration::from_secs(90));
        let wait = retry_after(&header(&later)).unwrap();
        assert!((85..=90).contains(&wait.as_secs()), "{wait:?}");
        let earlier = httpdate::fmt_http_date(std::time::SystemTime::now() - Duration::from_secs(90));
        assert_eq!(retry_after(&header(&earlier)), Some(Duration::ZERO));
    }

    fn doh_requests(mock: &DohMock) -> usize {
        mock.seen.lock().unwrap().iter().filter(|raw| !is_probe(raw)).count()
    }

    #[tokio::test]
    async fn retry_after_keeps_requests_away_from_an_upstream_and_is_capped() {
        // One 429 with Retry-After: 120 stops all traffic to it while
        // another upstream serves.
        let good = DohMock::start(Arc::new(|raw: &[u8]| Reply::dns(a_reply(raw, [192, 0, 2, 5])))).await;
        for status in [429u16, 503] {
            let doh = DohMock::start(Arc::new(move |_: &[u8]| Reply::error(status).retry_after("120"))).await;
            let mut cfg = config(vec![doh.url.clone(), good.url.clone()], vec![]);
            cfg.upstream_strategy = UpstreamStrategy::Ordered;
            let pool = Arc::new(UpstreamPool::new(&cfg).unwrap());
            for i in 0..20u16 {
                let query = raw_query(&format!("ra{status}-{i}.test."), RecordType::A, i + 1);
                assert!(pool.exchange(&query, i + 1).await.is_some());
            }
            assert_eq!(doh_requests(&doh), 1, "HTTP {status}: one request for 20 names");
            let health = pool.health();
            assert!(!health[0].healthy && pool.ready(), "the pause shows in health");
            let until = pool.upstreams[0].state().paused_until.expect("paused");
            let left = until.saturating_duration_since(Instant::now());
            assert!(left > Duration::from_secs(58) && left <= RETRY_AFTER_CAP, "capped at 60 s, not 120: {left:?}");
            assert!(pool.upstreams[0].state().open_until.is_none(), "one failure opens no circuit");
            // A reload's new pool keeps honouring the pause.
            let reloaded = UpstreamPool::new(&cfg).unwrap();
            reloaded.inherit(&pool);
            assert!(!reloaded.health()[0].healthy, "the pause survives a reload");
        }
    }

    #[tokio::test]
    async fn retry_after_without_a_usable_value_keeps_the_ordinary_backoff() {
        for header in [None, Some("soon")] {
            let doh = DohMock::start(Arc::new(move |_: &[u8]| {
                let reply = Reply::error(503);
                match header {
                    Some(value) => reply.retry_after(value),
                    None => reply,
                }
            }))
            .await;
            let pool = Arc::new(UpstreamPool::new(&config(vec![doh.url.clone()], vec![])).unwrap());
            for i in 0..2u16 {
                let query = raw_query(&format!("plain503-{i}.test."), RecordType::A, i + 1);
                assert!(pool.exchange(&query, i + 1).await.is_none());
            }
            assert_eq!(doh_requests(&doh), 2, "no pause: the next query still goes out");
            assert!(pool.upstreams[0].state().paused_until.is_none());
        }
    }

    #[tokio::test]
    async fn a_paused_upstream_is_skipped_for_the_others_never_for_plaintext() {
        let limited = DohMock::start(Arc::new(|_: &[u8]| Reply::error(429).retry_after("30"))).await;
        let good = DohMock::start(Arc::new(|raw: &[u8]| Reply::dns(a_reply(raw, [192, 0, 2, 5])))).await;
        let pool = Arc::new(UpstreamPool::new(&config(vec![limited.url.clone(), good.url.clone()], vec![])).unwrap());
        for i in 0..10u16 {
            let query = raw_query(&format!("others-{i}.test."), RecordType::A, i + 1);
            let answer = pool.exchange(&query, i + 1).await.expect("the other upstream answers");
            assert_eq!(answer_address(&answer), Some([192, 0, 2, 5]));
        }
        assert!(doh_requests(&limited) <= 1, "at most the first request reached it: {}", doh_requests(&limited));
        assert!(pool.ready(), "one upstream is still usable");

        // A pause a client query drew is an HTTP answer about that query (a
        // client flood can provoke it), so it never downgrades to plaintext:
        // the last usable upstream keeps getting the queries and each fails.
        let only = DohMock::start(Arc::new(|_: &[u8]| Reply::error(503).retry_after("30"))).await;
        let udp = UdpMock::start(Arc::new(|raw: &[u8]| Some(a_reply(raw, [192, 0, 2, 6])))).await;
        let pool = Arc::new(UpstreamPool::new(&config(vec![only.url.clone()], vec![udp.addr])).unwrap());
        for i in 0..4u16 {
            let query = raw_query(&format!("fallback-{i}.test."), RecordType::A, i + 1);
            assert!(pool.exchange(&query, i + 1).await.is_none(), "query {i}: no downgrade");
        }
        assert_eq!(doh_requests(&only), 4);
        assert!(udp.seen.lock().unwrap().is_empty(), "the plaintext fallback was never asked");

        // A pause the fixed root-NS probe drew is the endpoint's own request
        // for quiet: honoured for every query, but the endpoint answered, so
        // still no plaintext (a client flood can make it rate-limit us).
        let only = DohMock::start(Arc::new(|_: &[u8]| Reply::error(503).retry_after("30"))).await;
        let pool = Arc::new(UpstreamPool::new(&config(vec![only.url.clone()], vec![udp.addr])).unwrap());
        pool.probe_all().await;
        let probes = doh_requests(&only);
        for i in 0..4u16 {
            let query = raw_query(&format!("probed-{i}.test."), RecordType::A, i + 1);
            assert!(pool.exchange(&query, i + 1).await.is_none(), "query {i}: paused, no downgrade");
        }
        assert_eq!(doh_requests(&only), probes, "the pause is honoured");
        assert!(udp.seen.lock().unwrap().is_empty(), "the plaintext fallback was never asked");
    }

    /// A front end that resets the request for some names (an HTTP/2
    /// RST_STREAM, a connection closed after the request was sent) answers
    /// about the name, not the endpoint: it never opens the circuit and never
    /// reaches plaintext. Only failing to connect does.
    #[tokio::test]
    async fn a_reset_after_the_request_was_sent_never_benches_or_downgrades() {
        let doh = DohMock::start(Arc::new(|raw: &[u8]| {
            if parsed(raw).queries[0].name().to_ascii().starts_with("rst") {
                Reply::error(0)
            } else {
                Reply::dns(a_reply(raw, [192, 0, 2, 20]))
            }
        }))
        .await;
        let udp = UdpMock::start(Arc::new(|raw: &[u8]| Some(a_reply(raw, [192, 0, 2, 66])))).await;
        let pool = Arc::new(UpstreamPool::new(&config(vec![doh.url.clone()], vec![udp.addr])).unwrap());
        for i in 0..4u16 {
            let query = raw_query(&format!("rst{i}.test."), RecordType::A, i + 1);
            assert!(pool.exchange(&query, i + 1).await.is_none(), "query {i}: no downgrade");
        }
        assert_eq!(pool.upstreams[0].state().failures, 0);
        assert!(pool.health()[0].healthy && pool.ready());
        let answer = pool.exchange(&raw_query("other.test.", RecordType::A, 9), 9).await.expect("DoH answers");
        assert_eq!(answer_address(&answer), Some([192, 0, 2, 20]));
        assert!(udp.seen.lock().unwrap().is_empty(), "the plaintext fallback was never asked");
    }

    /// A `Retry-After` on a client query may be about that query (a front
    /// end can answer 503 for one broken name). It keeps the upstream out
    /// only while another DoH upstream can serve; on the last usable one it
    /// fails only the queries the upstream itself refuses.
    #[tokio::test]
    async fn a_client_drawn_pause_on_the_last_upstream_fails_no_other_query() {
        let doh = DohMock::start(Arc::new(|raw: &[u8]| {
            if is_probe(raw) {
                probe_handler(raw)
            } else if parsed(raw).queries[0].name().to_ascii().starts_with("limited") {
                Reply::error(503).retry_after("30")
            } else {
                Reply::dns(a_reply(raw, [192, 0, 2, 21]))
            }
        }))
        .await;
        let udp = UdpMock::start(Arc::new(|raw: &[u8]| Some(a_reply(raw, [192, 0, 2, 66])))).await;
        let pool = Arc::new(UpstreamPool::new(&config(vec![doh.url.clone()], vec![udp.addr])).unwrap());
        assert!(pool.exchange(&raw_query("limited.test.", RecordType::A, 1), 1).await.is_none());
        assert!(pool.upstreams[0].state().paused_until.is_some(), "the pause is recorded");
        assert!(pool.ready(), "a client-drawn pause does not fail readiness");
        for i in 0..3u16 {
            let query = raw_query(&format!("other{i}.test."), RecordType::A, i + 2);
            let answer = pool.exchange(&query, i + 2).await.expect("other clients are still served");
            assert_eq!(answer_address(&answer), Some([192, 0, 2, 21]));
        }
        assert!(udp.seen.lock().unwrap().is_empty(), "never plaintext");
        // The probe still runs, so it can confirm an endpoint-wide pause.
        let seen = doh.seen.lock().unwrap().len();
        pool.probe_all().await;
        assert_eq!(doh.seen.lock().unwrap().len(), seen + 1);
    }

    /// RFC 9520 §3.2 suppresses repeats of a failed resolution. A query
    /// that never left (every upstream paused by the probe, no fallback) did
    /// not fail at an upstream and must not suppress the name afterwards.
    #[tokio::test]
    async fn a_query_never_sent_leaves_no_failure_marker() {
        let doh = DohMock::start(Arc::new(|_: &[u8]| Reply::error(503).retry_after("30"))).await;
        let pool = Arc::new(UpstreamPool::new(&config(vec![doh.url.clone()], vec![])).unwrap());
        pool.probe_all().await;
        assert!(pool.exchange(&raw_query("unsent.test.", RecordType::A, 1), 1).await.is_none());
        assert_eq!(doh_requests(&doh), 0);
        assert!(pool.failures.lock().unwrap().map.is_empty());
    }

    /// The root-NS probe asks a name every working resolver can answer, so
    /// a failure RCODE for it is a failed probe.
    #[tokio::test]
    async fn a_probe_answered_with_servfail_is_a_failed_probe() {
        let doh =
            DohMock::start(Arc::new(|raw: &[u8]| Reply::dns(reply_for(raw, ResponseCode::ServFail, vec![], vec![]))))
                .await;
        let udp = UdpMock::start(Arc::new(|raw: &[u8]| Some(a_reply(raw, [192, 0, 2, 9])))).await;
        let pool = Arc::new(UpstreamPool::new(&config(vec![doh.url.clone()], vec![udp.addr])).unwrap());
        for _ in 0..3 {
            pool.probe_all().await;
        }
        assert!(!pool.health()[0].healthy, "three failed probes open the circuit");
        assert!(!pool.ready());
        // It answered, so it is reachable: queries still go to it, never to plaintext.
        assert!(pool.exchange(&raw_query("sf.test.", RecordType::A, 1), 1).await.is_none());
        assert!(udp.seen.lock().unwrap().is_empty(), "no downgrade on failure answers");
    }

    /// An endpoint that accepts connections and never answers (a TLS port
    /// that never speaks) uses up every client deadline. Once the probes
    /// have benched it, a configured plain fallback answers at once instead
    /// of the dead endpoint being tried again.
    #[tokio::test]
    async fn a_hung_endpoint_benched_by_probes_leaves_the_query_to_the_plain_fallback() {
        let hung = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/dns-query", hung.local_addr().unwrap());
        let udp = UdpMock::start(Arc::new(|raw: &[u8]| Some(a_reply(raw, [192, 0, 2, 7])))).await;
        let mut cfg = config(vec![url], vec![udp.addr]);
        cfg.upstream_timeout_seconds = 1;
        let pool = Arc::new(UpstreamPool::new(&cfg).unwrap());
        for _ in 0..3 {
            pool.probe_all().await;
        }
        assert!(!pool.ready(), "three failed probes open the circuit");
        let started = Instant::now();
        let answer = pool.exchange(&raw_query("hung.test.", RecordType::A, 1), 1).await.expect("the fallback answers");
        assert_eq!(answer_address(&answer), Some([192, 0, 2, 7]));
        assert!(started.elapsed() < Duration::from_millis(500), "{:?}", started.elapsed());
    }

    #[tokio::test]
    async fn the_probe_loop_leaves_a_paused_upstream_alone_and_a_date_pauses_too() {
        let date = httpdate::fmt_http_date(std::time::SystemTime::now() + Duration::from_secs(45));
        let doh = DohMock::start(Arc::new(move |_: &[u8]| Reply::error(429).retry_after(&date))).await;
        let pool = Arc::new(UpstreamPool::new(&config(vec![doh.url.clone()], vec![])).unwrap());
        pool.probe_all().await;
        let seen = doh.seen.lock().unwrap().len();
        assert_eq!(seen, 1);
        pool.probe_all().await;
        assert_eq!(doh.seen.lock().unwrap().len(), seen, "no probe while paused");
        let left = pool.upstreams[0].state().paused_until.unwrap().saturating_duration_since(Instant::now());
        // The date has whole-second resolution and a loaded host adds delay.
        assert!((38..=45).contains(&left.as_secs()), "{left:?}");
    }

    #[tokio::test]
    async fn a_forbidden_record_in_a_plain_reply_fails_the_attempt_at_once() {
        // The reply matches ID and question but carries a TSIG in Answer;
        // the attempt does not wait out its deadline for a better datagram.
        let udp = UdpMock::start(Arc::new(|raw: &[u8]| {
            let mut body = a_reply(raw, [192, 0, 2, 1]);
            body.extend_from_slice(&[0xc0, 12, 0, 250, 0, 255, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4]);
            let answers = u16::from_be_bytes([body[6], body[7]]) + 1;
            body[6..8].copy_from_slice(&answers.to_be_bytes());
            Some(body)
        }))
        .await;
        let mut cfg = config(vec![], vec![udp.addr]);
        cfg.upstream_timeout_seconds = 5;
        let pool = Arc::new(UpstreamPool::new(&cfg).unwrap());
        let started = Instant::now();
        let query = raw_query("tsig.test.", RecordType::A, 9);
        assert!(pool.exchange(&query, 9).await.is_none());
        assert!(started.elapsed() < Duration::from_secs(1), "{:?}", started.elapsed());
    }
}

#[cfg(test)]
mod rfc_tests_a {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use tokio::net::TcpListener;

    // ---- self-contained helpers (the `tests` module keeps its own private) ----

    type Seen = Arc<Mutex<Vec<(SocketAddr, Vec<u8>)>>>;

    /// A UDP upstream on loopback. `handler` returns the datagrams to send back
    /// for each query, each after its delay.
    struct Mock {
        addr: SocketAddr,
        seen: Seen,
        task: JoinHandle<()>,
    }

    impl Drop for Mock {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    impl Mock {
        async fn start(handler: impl Fn(&[u8]) -> Vec<(Duration, Vec<u8>)> + Send + Sync + 'static) -> Self {
            let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let addr = socket.local_addr().unwrap();
            let seen: Seen = Arc::new(Mutex::new(Vec::new()));
            let recorded = seen.clone();
            let task = tokio::spawn(async move {
                let mut buffer = vec![0u8; 4096];
                loop {
                    let Ok((n, peer)) = socket.recv_from(&mut buffer).await else { return };
                    let query = buffer[..n].to_vec();
                    recorded.lock().unwrap().push((peer, query.clone()));
                    for (delay, reply) in handler(&query) {
                        let socket = socket.clone();
                        tokio::spawn(async move {
                            tokio::time::sleep(delay).await;
                            let _ = socket.send_to(&reply, peer).await;
                        });
                    }
                }
            });
            Self { addr, seen, task }
        }

        fn count(&self) -> usize {
            self.seen.lock().unwrap().len()
        }
    }

    fn config(upstreams: Vec<String>, fallback: Vec<SocketAddr>, timeout_seconds: u64) -> Config {
        Config {
            upstreams,
            fallback,
            upstream_hedge_ms: 40,
            upstream_timeout_seconds: timeout_seconds,
            ..Config::default()
        }
    }

    fn encode_name(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in name.trim_end_matches('.').split('.').filter(|label| !label.is_empty()) {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    fn query_typed(name: &str, qtype: u16, id: u16) -> Vec<u8> {
        let mut raw = Vec::new();
        raw.extend_from_slice(&id.to_be_bytes());
        raw.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
        raw.extend_from_slice(&encode_name(name));
        raw.extend_from_slice(&qtype.to_be_bytes());
        raw.extend_from_slice(&1u16.to_be_bytes());
        raw
    }

    fn query(name: &str, id: u16) -> Vec<u8> {
        query_typed(name, 1, id)
    }

    /// A NOERROR reply to `q` (any `q` built by `query`): the question is echoed
    /// byte for byte, with one A record behind a pointer to the question name.
    fn answer(q: &[u8]) -> Vec<u8> {
        let end = 12 + wire::parse_query(q).unwrap().qname_wire.len() + 4;
        let mut out = q[..end].to_vec();
        out[2] = 0x81;
        out[3] = 0x80;
        out[6..12].fill(0);
        out[7] = 1; // ANCOUNT
        out.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1]);
        out
    }

    fn qname_of(raw: &[u8]) -> String {
        Message::from_vec(raw).unwrap().queries[0].name().to_ascii().to_ascii_lowercase()
    }

    // ---- RFC 1034 s1984, RFC 1035 s2576: malformed and unreasonable replies ----

    /// What the DoH reply path accepts as an answer: question and QR check, the
    /// parse, and no failure RCODE.
    fn accepted(reply: &[u8], sent: &QueryView<'_>) -> bool {
        plain_question_matches(reply, sent, false)
            && validate_response(reply, sent, false).is_ok_and(|(_, _, _, rcode_failure)| !rcode_failure)
    }

    #[test]
    fn rfc1034_s1984_malformed_upstream_replies_are_discarded() {
        let q = query("paranoid.example.", 0x4242);
        let sent = wire::parse_query(&q).unwrap();
        let good = answer(&q);
        assert!(accepted(&good, &sent), "control: the well-formed reply is accepted");
        let name_end = 12 + sent.qname_wire.len() + 4; // first byte after the question
        let rdata = good.len() - 4;

        let mut cases: Vec<(&str, Vec<u8>)> = Vec::new();
        let mut with = |label: &'static str, edit: &dyn Fn(&mut Vec<u8>)| {
            let mut bad = good.clone();
            edit(&mut bad);
            cases.push((label, bad));
        };
        with("ANCOUNT larger than the records present", &|b| b[7] = 2);
        with("RDLENGTH overruns the message", &|b| {
            b[name_end + 10..name_end + 12].copy_from_slice(&5u16.to_be_bytes())
        });
        with("A record with RDLENGTH 3", &|b| {
            b[name_end + 10..name_end + 12].copy_from_slice(&3u16.to_be_bytes());
        });
        with("answer name points into the header", &|b| b[name_end..name_end + 2].copy_from_slice(&[0xc0, 0x00]));
        with("answer name points forward", &|b| {
            let target = (name_end + 2) as u16 | 0xc000;
            b[name_end..name_end + 2].copy_from_slice(&target.to_be_bytes());
        });
        with("answer name points at itself", &|b| {
            let target = name_end as u16 | 0xc000;
            b[name_end..name_end + 2].copy_from_slice(&target.to_be_bytes());
        });
        with("trailing bytes after the last record", &|b| b.extend_from_slice(&[0xde, 0xad, 0xbe]));
        with("question name differs", &|b| b[13] ^= 0x01);
        with("question type differs", &|b| b[name_end - 3] = 28);
        with("question class differs", &|b| b[name_end - 1] = 3);
        with("RDATA cut short of the message", &|b| b.truncate(rdata + 2));
        // A CNAME whose encoded target runs past its RDLENGTH.
        let mut cname = q.clone();
        cname[2] = 0x81;
        cname[3] = 0x80;
        cname[7] = 1;
        cname.extend_from_slice(&[0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 0, 60, 0, 1]);
        cname.extend_from_slice(&[3, b'a', b'b', b'c', 0]);
        cases.push(("CNAME target runs past its RDLENGTH", cname));

        let wrongly_accepted: Vec<&str> =
            cases.iter().filter(|(_, bad)| accepted(bad, &sent)).map(|(label, _)| *label).collect();
        assert!(wrongly_accepted.is_empty(), "must be discarded: {wrongly_accepted:?}");
    }

    #[test]
    fn rfc1035_s2576_reply_headers_are_checked() {
        let q = query("header.example.", 0x1357);
        let sent = wire::parse_query(&q).unwrap();
        let good = answer(&q);
        assert!(accepted(&good, &sent), "control: the well-formed reply is accepted");

        type Edit = Box<dyn Fn(&mut Vec<u8>)>;
        let cases: Vec<(&str, Edit)> = vec![
            ("QR=0 (a query, not a response)", Box::new(|b| b[2] &= 0x7f)),
            ("opcode STATUS", Box::new(|b| b[2] = (b[2] & 0x87) | (2 << 3))),
            ("opcode NOTIFY", Box::new(|b| b[2] = (b[2] & 0x87) | (4 << 3))),
            ("wrong ID", Box::new(|b| b[1] ^= 0x01)),
            ("TC=1", Box::new(|b| b[2] |= 0x02)),
            ("QDCOUNT 0", Box::new(|b| b[5] = 0)),
            ("QDCOUNT 2", Box::new(|b| b[5] = 2)),
            ("RCODE FORMERR", Box::new(|b| b[3] = (b[3] & 0xf0) | 1)),
            ("RCODE SERVFAIL", Box::new(|b| b[3] = (b[3] & 0xf0) | 2)),
            ("RCODE NOTIMP", Box::new(|b| b[3] = (b[3] & 0xf0) | 4)),
            ("RCODE REFUSED", Box::new(|b| b[3] = (b[3] & 0xf0) | 5)),
            ("header shorter than 12 bytes", Box::new(|b| b.truncate(11))),
        ];
        let mut wrongly_accepted = Vec::new();
        for (label, edit) in &cases {
            let mut bad = good.clone();
            edit(&mut bad);
            if accepted(&bad, &sent) {
                wrongly_accepted.push(*label);
            }
        }
        assert!(wrongly_accepted.is_empty(), "must be discarded or failed: {wrongly_accepted:?}");
    }

    // ---- RFC 1035 s2439: bounded work per request ----

    #[tokio::test]
    async fn rfc1035_s2439_work_per_request_is_bounded() {
        // A silent network: each configured address is asked exactly once and
        // the request ends at its deadline with no answer.
        let silent = |_: &[u8]| Vec::new();
        let mocks = [Mock::start(silent).await, Mock::start(silent).await, Mock::start(silent).await];
        let addrs = mocks.iter().map(|mock| mock.addr).collect();
        let pool = Arc::new(UpstreamPool::new(&config(vec![], addrs, 2)).unwrap());
        let started = Instant::now();
        assert!(pool.exchange(&query("silent.example.", 1), 1).await.is_none());
        let elapsed = started.elapsed();
        assert!(elapsed >= Duration::from_millis(1900) && elapsed < Duration::from_millis(3500), "{elapsed:?}");
        tokio::time::sleep(Duration::from_millis(100)).await;
        for mock in &mocks {
            assert_eq!(mock.count(), 1, "one datagram per configured address, no retransmission");
        }

        // A CNAME loop in an answer is not chased: one exchange, then it ends.
        let looping = Mock::start(|q: &[u8]| {
            let mut out = q.to_vec();
            out[2] = 0x81;
            out[3] = 0x80;
            out[7] = 2;
            let (a, b) = (encode_name("loop.example."), encode_name("loop2.example."));
            for (owner, target) in [(&a, &b), (&b, &a)] {
                out.extend_from_slice(owner);
                out.extend_from_slice(&[0, 5, 0, 1, 0, 0, 0, 60]);
                out.extend_from_slice(&(target.len() as u16).to_be_bytes());
                out.extend_from_slice(target);
            }
            vec![(Duration::ZERO, out)]
        })
        .await;
        let pool = Arc::new(UpstreamPool::new(&config(vec![], vec![looping.addr], 2)).unwrap());
        let started = Instant::now();
        let _ = pool.exchange(&query("loop.example.", 2), 2).await;
        assert!(started.elapsed() < Duration::from_millis(3500));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(looping.count(), 1, "a CNAME loop costs one exchange");
    }

    // ---- RFC 5452 s267/s278/s718/s723/s725: matching on the socket 4-tuple ----

    async fn recv_within(socket: &UdpSocket, wait: Duration) -> Option<Vec<u8>> {
        let mut buffer = [0u8; 64];
        match tokio::time::timeout(wait, socket.recv(&mut buffer)).await {
            Ok(Ok(n)) => Some(buffer[..n].to_vec()),
            _ => None,
        }
    }

    const NEGATIVE_WAIT: Duration = Duration::from_millis(250);
    const POSITIVE_WAIT: Duration = Duration::from_secs(3);

    /// A perfect copy of the reply, from a different source IP than the one
    /// the question went to. The peer is on `::1`, the forger on `127.0.0.1`;
    /// the attempt's wildcard IPv6 socket is dual-stack, so the datagram does
    /// reach the port: a wildcard control socket proves it. Both loopback
    /// addresses exist everywhere, so the case always runs.
    async fn a_reply_from_another_source_ip_is_ignored() {
        let control = UdpSocket::bind("[::]:0").await.expect("a dual-stack wildcard socket is needed");
        let forger = UdpSocket::bind("127.0.0.1:0").await.expect("IPv4 loopback is needed");
        forger.send_to(b"c", ("127.0.0.1", control.local_addr().unwrap().port())).await.unwrap();
        assert_eq!(
            recv_within(&control, POSITIVE_WAIT).await.as_deref(),
            Some(&b"c"[..]),
            "control: an IPv4 loopback datagram reaches a wildcard IPv6 port, so the forgery below can arrive"
        );
        let peer = UdpSocket::bind("[::1]:0").await.expect("IPv6 loopback ::1 is needed");
        let addr = peer.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut buffer = vec![0u8; 4096];
            let (n, from) = peer.recv_from(&mut buffer).await.unwrap();
            let mut forged = answer(&buffer[..n]);
            let last = forged.len() - 1;
            forged[last] = 66;
            // Right ID, question and port, wrong source address.
            forger.send_to(&forged, ("127.0.0.1", from.port())).await.unwrap();
            tokio::time::sleep(Duration::from_millis(150)).await;
            forged[last] = 77;
            peer.send_to(&forged, from).await.unwrap();
        });
        let pool = Arc::new(UpstreamPool::new(&config(vec![], vec![addr], 2)).unwrap());
        let reply = pool.exchange(&query("source.example.", 9), 9).await.expect("the genuine reply is used");
        assert_eq!(reply.raw.last(), Some(&77), "the perfect copy from another source IP was not used");
        task.await.unwrap();
    }

    /// A second local IPv4 address of this host that a wildcard socket
    /// receives on when `peer` sends to it: 127.0.0.2 where the loopback
    /// block is bound, otherwise the address the host would use to leave. It
    /// fails the test when there is neither: the case must not pass unrun.
    async fn another_local_address(peer: &UdpSocket) -> std::net::IpAddr {
        let mut candidates = vec![std::net::IpAddr::from([127, 0, 0, 2])];
        let lan = std::net::UdpSocket::bind("0.0.0.0:0").ok().and_then(|probe| {
            probe.connect("192.0.2.1:9").ok()?;
            Some(probe.local_addr().ok()?.ip())
        });
        candidates.extend(lan);
        let control = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let port = control.local_addr().unwrap().port();
        for ip in candidates {
            if peer.send_to(b"c", (ip, port)).await.is_err() {
                continue;
            }
            if recv_within(&control, POSITIVE_WAIT).await.is_some() {
                return ip;
            }
        }
        panic!(
            "no second local IPv4 address (127.0.0.2 or a LAN address) is reachable: the destination case cannot run"
        );
    }

    /// A perfect copy of the reply, from the right peer and port, but sent to
    /// another local address of this host than the one the question left from.
    async fn a_reply_to_another_local_address_is_ignored() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let other = another_local_address(&peer).await;
        let addr = peer.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut buffer = vec![0u8; 4096];
            let (n, from) = peer.recv_from(&mut buffer).await.unwrap();
            let mut forged = answer(&buffer[..n]);
            let last = forged.len() - 1;
            forged[last] = 66;
            peer.send_to(&forged, (other, from.port())).await.unwrap();
            tokio::time::sleep(Duration::from_millis(150)).await;
            forged[last] = 77;
            peer.send_to(&forged, from).await.unwrap();
        });
        let pool = Arc::new(UpstreamPool::new(&config(vec![], vec![addr], 2)).unwrap());
        let reply = pool.exchange(&query("dest.example.", 9), 9).await.expect("the genuine reply is used");
        assert_eq!(reply.raw.last(), Some(&77), "the copy that arrived on another local address was not used");
        task.await.unwrap();
    }

    #[tokio::test]
    async fn rfc5452_s267_replies_are_accepted_only_from_the_peer_on_the_socket_port() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = peer.local_addr().unwrap();
        let a = connected_socket(addr, &[]).await.unwrap();
        let port_a = a.local_addr().unwrap().port();

        // Condition 3, same IP, other port: the kernel's connected-socket filter.
        let stranger = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        stranger.send_to(b"forged", ("127.0.0.1", port_a)).await.unwrap();
        assert_eq!(recv_within(&a, NEGATIVE_WAIT).await, None, "a datagram from another source port is not delivered");
        // Control: the real peer, on the socket's own port, is delivered.
        peer.send_to(b"genuine", ("127.0.0.1", port_a)).await.unwrap();
        assert_eq!(recv_within(&a, POSITIVE_WAIT).await.as_deref(), Some(&b"genuine"[..]));

        // Condition 3, other IP, end to end through the pool.
        a_reply_from_another_source_ip_is_ignored().await;
    }

    #[tokio::test]
    async fn rfc5452_s278_a_reply_to_another_local_address_is_not_delivered() {
        a_reply_to_another_local_address_is_ignored().await;
        // The same kind of datagram sent to the right address is delivered, so
        // the negative above is not blind.
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let socket = connected_socket(peer.local_addr().unwrap(), &[]).await.unwrap();
        let port = socket.local_addr().unwrap().port();
        peer.send_to(b"right-address", ("127.0.0.1", port)).await.unwrap();
        assert_eq!(recv_within(&socket, POSITIVE_WAIT).await.as_deref(), Some(&b"right-address"[..]));
    }

    /// Two exchanges at once to one peer: a perfect reply to the first, sent
    /// to the second's port, must not answer the first.
    #[tokio::test]
    async fn rfc5452_s725_a_reply_sent_to_another_exchanges_port_does_not_answer_this_one() {
        let peer = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = peer.local_addr().unwrap();
        let pool = Arc::new(UpstreamPool::new(&config(vec![], vec![addr], 3)).unwrap());
        let first = {
            let pool = pool.clone();
            tokio::spawn(async move { pool.exchange(&query("first.example.", 1), 1).await })
        };
        let second = {
            let pool = pool.clone();
            tokio::spawn(async move { pool.exchange(&query("second.example.", 2), 2).await })
        };
        let mut buffer = vec![0u8; 4096];
        let mut asked = Vec::new();
        for _ in 0..2 {
            let (n, from) = tokio::time::timeout(POSITIVE_WAIT, peer.recv_from(&mut buffer))
                .await
                .expect("both exchanges send a query")
                .unwrap();
            asked.push((qname_of(&buffer[..n]), from, buffer[..n].to_vec()));
        }
        let of = |name: &str| asked.iter().find(|(asked_name, _, _)| asked_name.starts_with(name)).unwrap().clone();
        let (_, from_first, query_first) = of("first");
        let (_, from_second, query_second) = of("second");
        assert_ne!(from_first.port(), from_second.port(), "each exchange has a source port of its own");
        // The first's valid reply, to the second's port: nobody takes it.
        peer.send_to(&answer(&query_first), from_second).await.unwrap();
        tokio::time::sleep(NEGATIVE_WAIT).await;
        assert!(!first.is_finished(), "a reply to another exchange's port answered the first");
        assert!(!second.is_finished(), "the second is not answered by a reply for another question");
        // Each valid reply to its own port completes its own exchange.
        peer.send_to(&answer(&query_first), from_first).await.unwrap();
        peer.send_to(&answer(&query_second), from_second).await.unwrap();
        for task in [first, second] {
            assert!(tokio::time::timeout(POSITIVE_WAIT, task).await.unwrap().unwrap().is_some());
        }
    }

    #[tokio::test]
    async fn rfc5452_s718_every_query_attribute_must_match_before_a_reply_is_used() {
        // Source address and destination address, end to end: perfect copies
        // from another IP and to another local IP are not used.
        a_reply_from_another_source_ip_is_ignored().await;
        a_reply_to_another_local_address_is_ignored().await;

        // ID, name, type and class: a reply wrong in any one of them is ignored
        // and the attempt goes on to use the later valid datagram. So is a
        // perfect copy sent from a different source port.
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = peer.local_addr().unwrap();
        let stranger = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let task = tokio::spawn(async move {
            let mut buffer = vec![0u8; 4096];
            let (n, from) = peer.recv_from(&mut buffer).await.unwrap();
            let q = buffer[..n].to_vec();
            let good = answer(&q);
            let end = 12 + wire::parse_query(&q).unwrap().qname_wire.len();
            let mut wrong_id = good.clone();
            wrong_id[1] ^= 0x01;
            let mut wrong_name = good.clone();
            wrong_name[13] ^= 0x01;
            let mut wrong_type = good.clone();
            wrong_type[end + 1] = 28;
            let mut wrong_class = good.clone();
            wrong_class[end + 3] = 3;
            for forged in [&wrong_id, &wrong_name, &wrong_type, &wrong_class] {
                peer.send_to(forged, from).await.unwrap();
            }
            let mut elsewhere = good.clone();
            elsewhere[good.len() - 1] = 66;
            stranger.send_to(&elsewhere, from).await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
            let mut genuine = good;
            let last = genuine.len() - 1;
            genuine[last] = 77;
            peer.send_to(&genuine, from).await.unwrap();
        });
        let pool = Arc::new(UpstreamPool::new(&config(vec![], vec![addr], 2)).unwrap());
        let reply = pool.exchange(&query("match.example.", 9), 9).await.expect("the genuine reply is used");
        assert_eq!(reply.raw.last(), Some(&77), "only the datagram matching every attribute was used");
        task.await.unwrap();
    }

    // ---- RFC 5452 s752, s765, s788, s759, s793, RFC 5625 s502, RFC 8085 s1911:
    // ---- unpredictable ports and IDs ----

    #[tokio::test]
    async fn rfc5452_s737_plain_queries_draw_from_ports_1024_and_up() {
        // Excluding 32768 and up removes every OS ephemeral range (Linux
        // 32768-60999, macOS and Windows 49152-65535), so a kernel-chosen
        // port cannot pass.
        let mock = Mock::start(|q: &[u8]| vec![(Duration::ZERO, answer(q))]).await;
        let mut cfg = config(vec![], vec![mock.addr], 2);
        cfg.upstream_source_ports_exclude = vec!["32768-65535".into()];
        cfg.validate().unwrap();
        let pool = UpstreamPool::new(&cfg).unwrap();
        for n in 0..8u16 {
            let name = format!("dynamic{n}.example.");
            assert!(pool.exchange(&query(&name, n), n).await.is_some());
        }
        let seen = mock.seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 8);
        let ports: Vec<u16> = seen.iter().map(|(peer, _)| peer.port()).collect();
        assert!(
            ports.iter().all(|&port| (1024..32768).contains(&port)),
            "our own draw, not the OS ephemeral range: {ports:?}"
        );
    }

    #[tokio::test]
    async fn rfc5452_s765_configured_excluded_source_ports_are_never_used() {
        let mock = Mock::start(|q: &[u8]| vec![(Duration::ZERO, answer(q))]).await;
        let mut cfg = config(vec![], vec![mock.addr], 2);
        cfg.upstream_source_ports_exclude = vec!["49152-57343".into(), "60000".into()];
        cfg.validate().unwrap();
        let pool = UpstreamPool::new(&cfg).unwrap();
        for n in 0..16u16 {
            let name = format!("excluded{n}.example.");
            assert!(pool.exchange(&query(&name, n), n).await.is_some());
        }
        let ports: Vec<u16> = mock.seen.lock().unwrap().iter().map(|(peer, _)| peer.port()).collect();
        assert_eq!(ports.len(), 16);
        assert!(
            ports.iter().all(|&port| port >= 1024 && !(49152..=57343).contains(&port) && port != 60000),
            "an excluded range or port was chosen: {ports:?}"
        );
    }

    #[test]
    fn rfc5452_s765_excluded_source_ports_are_never_drawn() {
        // Every port but 65535 excluded: every draw must be the one left, so
        // this checks the chooser deterministically.
        for _ in 0..1000 {
            assert_eq!(draw_source_port(&[(1, 65534)]).unwrap(), 65535);
        }
        // Excluded ranges and a single excluded port never appear.
        let excluded = [(49152, 60000), (61000, 62000), (64000, 64000)];
        let mut distinct = std::collections::HashSet::new();
        for _ in 0..4096 {
            let port = draw_source_port(&excluded).unwrap();
            assert!(crate::config::SOURCE_PORTS.contains(&port), "{port}");
            assert!(!excluded.iter().any(|&(first, last)| (first..=last).contains(&port)), "{port}");
            distinct.insert(port);
        }
        // The allowed gaps are all reachable, not one fixed port.
        assert!(distinct.len() > 1000, "{} distinct ports", distinct.len());
        // An unvalidated list that covers the whole range leaves no port.
        assert_eq!(draw_source_port(&[(1, 65535)]), None);
    }

    /// Config::validate merges ranges, but the pool is a public library type:
    /// overlapping input must not underflow or land in an excluded range.
    #[test]
    fn draw_source_port_survives_overlapping_ranges() {
        let excluded = [(1024, 55000), (54000, 60000)];
        for _ in 0..1000 {
            let port = draw_source_port(&excluded).unwrap();
            assert!((60001..=65535).contains(&port), "{port}");
        }
    }

    #[tokio::test]
    async fn rfc8085_s1911_a_port_that_cannot_be_bound_fails_local() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap();
        // Hold the only port the chooser may use, so every bounded
        // redraw in the attempt meets EADDRINUSE.
        let (held, port) = loop {
            let port = draw_source_port(&[]).unwrap();
            if let Ok(socket) = UdpSocket::bind(("0.0.0.0", port)).await {
                break (socket, port);
            }
        };
        let mut excluded = Vec::new();
        if port > *crate::config::SOURCE_PORTS.start() {
            excluded.push((*crate::config::SOURCE_PORTS.start(), port - 1));
        }
        if port < *crate::config::SOURCE_PORTS.end() {
            excluded.push((port + 1, *crate::config::SOURCE_PORTS.end()));
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        let held_result = timeout_at(
            deadline,
            plain_exchange(
                peer,
                &excluded,
                &TcpLink::new(peer),
                &query("held.example.", 7),
                true,
                deadline,
                deadline,
                false,
                &Notify::new(),
                &AtomicBool::new(false),
                true,
                &Mutex::new(FallbackState::default()),
            ),
        )
        .await
        .expect("the retries are bounded");
        assert!(matches!(held_result, Err(Fail::Local)), "no port is a local failure, never a port-0 fallback");
        drop(held);
    }

    #[tokio::test]
    async fn rfc5452_s752_each_query_gets_a_fresh_unpredictable_source_port() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut sockets = Vec::new();
        for _ in 0..20 {
            sockets.push(connected_socket(peer.local_addr().unwrap(), &[]).await.unwrap());
        }
        let ports: Vec<u16> = sockets.iter().map(|socket| socket.local_addr().unwrap().port()).collect();
        assert!(ports.iter().all(|&port| port >= 1024), "{ports:?}");
        let mut distinct = ports.clone();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(distinct.len(), ports.len(), "twenty live sockets, twenty different ports: {ports:?}");
        let steps = ports.windows(2).filter(|pair| pair[1] == pair[0].wrapping_add(1)).count();
        assert!(steps < ports.len() - 1, "ports must not simply count up: {ports:?}");
    }

    #[tokio::test]
    async fn rfc5452_s788_concurrent_queries_do_not_share_one_source_port() {
        let mock = Mock::start(|q: &[u8]| vec![(Duration::from_millis(300), answer(q))]).await;
        let pool = Arc::new(UpstreamPool::new(&config(vec![], vec![mock.addr], 5)).unwrap());
        let mut tasks = Vec::new();
        for n in 0..8u16 {
            let pool = pool.clone();
            tasks.push(tokio::spawn(async move {
                let name = format!("concurrent{n}.example.");
                pool.exchange(&query(&name, n), n).await.is_some()
            }));
        }
        for task in tasks {
            assert!(task.await.unwrap());
        }
        let mut ports: Vec<u16> = mock.seen.lock().unwrap().iter().map(|(peer, _)| peer.port()).collect();
        assert_eq!(ports.len(), 8);
        ports.sort_unstable();
        ports.dedup();
        assert_eq!(ports.len(), 8, "eight outstanding queries leave from eight different source ports");
    }

    #[test]
    fn rfc5452_s759_query_ids_cover_the_full_range_and_do_not_count_up() {
        let ids: Vec<u16> = (0..4096).map(|_| draw_id()).collect();
        let mut distinct = ids.clone();
        distinct.sort_unstable();
        distinct.dedup();
        // 4096 uniform draws from 65536 values give about 3970 distinct.
        assert!(distinct.len() >= 3700, "{} distinct", distinct.len());
        assert!(ids.iter().any(|&id| id >= 0xf000) && ids.iter().any(|&id| id <= 0x0fff), "the 16 bit range is used");
        let steps = ids.windows(2).filter(|pair| pair[1] == pair[0].wrapping_add(1)).count();
        assert!(steps < 8, "{steps} +1 steps: IDs are not a counter");
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        assert_ne!(ids, sorted, "IDs are not an ascending sequence");
    }

    #[tokio::test]
    async fn rfc5625_s502_successive_proxy_queries_vary_id_and_source_port() {
        let mock = Mock::start(|q: &[u8]| vec![(Duration::ZERO, answer(q))]).await;
        let pool = Arc::new(UpstreamPool::new(&config(vec![], vec![mock.addr], 2)).unwrap());
        for n in 0..24u16 {
            let name = format!("proxy{n}.example.");
            assert!(pool.exchange(&query(&name, n), n).await.is_some());
        }
        let seen = mock.seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 24);
        let ids: Vec<u16> = seen.iter().map(|(_, q)| u16::from_be_bytes([q[0], q[1]])).collect();
        let ports: Vec<u16> = seen.iter().map(|(peer, _)| peer.port()).collect();
        for (label, values) in [("ID", &ids), ("port", &ports)] {
            let mut distinct = values.clone();
            distinct.sort_unstable();
            distinct.dedup();
            assert!(distinct.len() >= 16, "{label}s repeat too much: {values:?}");
            let steps = values.windows(2).filter(|pair| pair[1] == pair[0].wrapping_add(1)).count();
            assert!(steps < 12, "{label}s run sequentially: {values:?}");
        }
        assert!(ports.iter().all(|&port| port >= 1024));
    }

    // ---- RFC 8484 s198, s888: DoH client keeps to its configured URI, no transport extensions ----

    type DohSeen = Arc<Mutex<Vec<(String, Vec<u8>)>>>;
    type DohAnswer = (u16, Vec<(&'static str, String)>, Vec<u8>);

    struct Doh {
        url: String,
        seen: DohSeen,
        task: JoinHandle<()>,
    }

    impl Drop for Doh {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    impl Doh {
        async fn start(handler: impl Fn(&[u8]) -> DohAnswer + Send + Sync + 'static) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let seen: DohSeen = Arc::new(Mutex::new(Vec::new()));
            let handler = Arc::new(handler);
            let recorded = seen.clone();
            let task = tokio::spawn(async move {
                loop {
                    let Ok((mut stream, _)) = listener.accept().await else { return };
                    let (handler, recorded) = (handler.clone(), recorded.clone());
                    tokio::spawn(async move {
                        let mut buffer = Vec::new();
                        let mut chunk = [0u8; 4096];
                        let head_end = loop {
                            let n = stream.read(&mut chunk).await.unwrap_or(0);
                            if n == 0 {
                                return;
                            }
                            buffer.extend_from_slice(&chunk[..n]);
                            if let Some(at) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                                break at;
                            }
                        };
                        let head = String::from_utf8_lossy(&buffer[..head_end]).to_ascii_lowercase();
                        let length: usize = head
                            .lines()
                            .find_map(|line| line.strip_prefix("content-length:"))
                            .and_then(|value| value.trim().parse().ok())
                            .unwrap_or(0);
                        let path = head.lines().next().unwrap_or("").to_string();
                        let start = head_end + 4;
                        while buffer.len() < start + length {
                            let n = stream.read(&mut chunk).await.unwrap_or(0);
                            if n == 0 {
                                break;
                            }
                            buffer.extend_from_slice(&chunk[..n]);
                        }
                        let body = buffer.get(start..start + length).unwrap_or(&[]).to_vec();
                        let (status, headers, reply) = handler(&body);
                        recorded.lock().unwrap().push((path, body));
                        let mut out = format!(
                            "HTTP/1.1 {status} X\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n",
                            reply.len()
                        );
                        for (name, value) in headers {
                            out.push_str(&format!("{name}: {value}\r\n"));
                        }
                        out.push_str("\r\n");
                        let _ = stream.write_all(out.as_bytes()).await;
                        let _ = stream.write_all(&reply).await;
                        let _ = stream.shutdown().await;
                    });
                }
            });
            Self { url: format!("http://{addr}/dns-query"), seen, task }
        }

        fn paths(&self) -> Vec<String> {
            self.seen.lock().unwrap().iter().map(|(path, _)| path.clone()).collect()
        }
    }

    #[tokio::test]
    async fn rfc8484_s198_an_unconfigured_uri_is_never_used() {
        // Another endpoint that counts connections and never answers.
        let other = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let other_addr = other.local_addr().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let counted = connections.clone();
        let listener_task = tokio::spawn(async move {
            while other.accept().await.is_ok() {
                counted.fetch_add(1, Ordering::SeqCst);
            }
        });
        let other_url = format!("http://{other_addr}/dns-query");
        let configured = {
            let other_url = other_url.clone();
            Doh::start(move |body: &[u8]| {
                if qname_of(body).starts_with("moved") {
                    // The configured server points elsewhere with a plain redirect.
                    (301, vec![("Location", other_url.clone())], Vec::new())
                } else {
                    // Alt-Svc, Link and Refresh all name another authority.
                    let headers = vec![
                        ("Alt-Svc", format!("h2=\"{other_addr}\"; ma=86400")),
                        ("Link", format!("<{other_url}>; rel=\"alternate\"")),
                        ("Refresh", format!("0; url={other_url}")),
                    ];
                    (200, headers, answer(body))
                }
            })
            .await
        };
        let pool = Arc::new(UpstreamPool::new(&config(vec![configured.url.clone()], vec![], 2)).unwrap());
        assert!(pool.exchange(&query("first.example.", 1), 1).await.is_some());
        assert!(
            pool.exchange(&query("moved.example.", 2), 2).await.is_none(),
            "a redirect off the configured URI fails"
        );
        assert!(pool.exchange(&query("third.example.", 3), 3).await.is_some());
        assert!(pool.exchange(&query("fourth.example.", 4), 4).await.is_some());
        tokio::time::sleep(Duration::from_millis(150)).await;
        let paths = configured.paths();
        assert!(paths.len() >= 4 && paths.iter().all(|line| line.starts_with("post /dns-query ")), "{paths:?}");
        assert_eq!(connections.load(Ordering::SeqCst), 0, "the unconfigured authority never sees a connection");
        listener_task.abort();
    }

    #[tokio::test]
    async fn rfc8484_s888_transport_specific_edns_options_are_not_used_over_doh() {
        const KEEPALIVE_REPLY: [u8; 6] = [0, 11, 0, 2, 0, 100];
        let doh = Doh::start(|body: &[u8]| {
            let mut reply = answer(body);
            reply[11] = 1; // ARCOUNT: one OPT that carries a TCP keepalive option
            reply.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 6]);
            reply.extend_from_slice(&KEEPALIVE_REPLY);
            (200, Vec::new(), reply)
        })
        .await;
        let pool = Arc::new(UpstreamPool::new(&config(vec![doh.url.clone()], vec![], 2)).unwrap());
        // Client OPT: TCP keepalive (11), padding (12) and an unknown option.
        let mut client = query("keepalive.example.", 7);
        client[11] = 1;
        client.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0]);
        let options: &[u8] = &[0, 11, 0, 0, 0, 12, 0, 4, 0, 0, 0, 0, 0xfd, 0xe9, 0, 2, 0xab, 0xcd];
        client.extend_from_slice(&(options.len() as u16).to_be_bytes());
        client.extend_from_slice(options);
        let reply = pool.exchange(&client, 7).await.expect("answered");

        let seen = doh.seen.lock().unwrap().clone();
        let (_, sent) =
            seen.iter().find(|(_, body)| qname_of(body) == "keepalive.example.").expect("query reached DoH");
        let message = Message::from_vec(sent).unwrap();
        assert!(
            message.edns.as_ref().is_some_and(|edns| !edns.options().options.is_empty()),
            "the unknown client option reaches the DoH server"
        );
        assert!(
            sent.windows(6).any(|window| window == [0xfd, 0xe9, 0, 2, 0xab, 0xcd]),
            "the unknown option is forwarded unchanged"
        );
        assert!(!sent.windows(4).any(|w| w == [0, 11, 0, 0]) && !sent.windows(4).any(|w| w == [0, 12, 0, 4]));
        assert!(
            reply.raw.windows(KEEPALIVE_REPLY.len()).any(|w| w == KEEPALIVE_REPLY),
            "control: the pool hands over the upstream OPT, so the client shaping below is what drops it"
        );
        let mut relayed = reply.raw.clone();
        assert!(wire::present_for_client(&mut relayed, true, false, false, 1232));
        assert!(
            !relayed.windows(KEEPALIVE_REPLY.len()).any(|w| w == KEEPALIVE_REPLY),
            "the keepalive option in the DoH reply is not relayed to the client"
        );
    }
}

#[cfg(test)]
mod rfc_tests_b {
    use super::*;
    use hickory_proto::rr::rdata::A as AData;
    use hickory_proto::rr::{RData, Record};

    type Seen = Arc<Mutex<Vec<(u16, Vec<u8>)>>>;
    type Handler = Arc<dyn Fn(usize, &[u8]) -> Vec<(Duration, Vec<u8>)> + Send + Sync>;

    /// A UDP upstream that records `(source port, query)` and answers through
    /// `handler(query_index, query)` with datagrams to send after a delay.
    struct Mock {
        addr: SocketAddr,
        seen: Seen,
        task: JoinHandle<()>,
    }

    impl Drop for Mock {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    impl Mock {
        async fn start(handler: Handler) -> Self {
            Self::bind("127.0.0.1:0".parse().unwrap(), handler).await
        }

        async fn bind(at: SocketAddr, handler: Handler) -> Self {
            let socket = Arc::new(UdpSocket::bind(at).await.unwrap());
            let addr = socket.local_addr().unwrap();
            let seen: Seen = Arc::new(Mutex::new(Vec::new()));
            let recorded = seen.clone();
            let task = tokio::spawn(async move {
                let mut buffer = vec![0u8; MAX_DNS_MESSAGE];
                loop {
                    let Ok((n, peer)) = socket.recv_from(&mut buffer).await else { return };
                    let query = buffer[..n].to_vec();
                    let index = {
                        let mut seen = recorded.lock().unwrap();
                        seen.push((peer.port(), query.clone()));
                        seen.len() - 1
                    };
                    for (delay, reply) in handler(index, &query) {
                        let socket = socket.clone();
                        tokio::spawn(async move {
                            tokio::time::sleep(delay).await;
                            let _ = socket.send_to(&reply, peer).await;
                        });
                    }
                }
            });
            Self { addr, seen, task }
        }

        fn count(&self) -> usize {
            self.seen.lock().unwrap().len()
        }
    }

    fn silent() -> Handler {
        Arc::new(|_, _| Vec::new())
    }

    fn answering(octets: [u8; 4], delay: Duration) -> Handler {
        Arc::new(move |_, raw| vec![(delay, a_reply(raw, octets))])
    }

    fn config(fallback: Vec<SocketAddr>, timeout_seconds: u64) -> Config {
        Config {
            upstreams: vec![],
            fallback,
            upstream_hedge_ms: 40,
            upstream_timeout_seconds: timeout_seconds,
            ..Config::default()
        }
    }

    fn raw_query(name: &str, id: u16) -> Vec<u8> {
        let mut raw = Vec::new();
        raw.extend_from_slice(&id.to_be_bytes());
        raw.extend_from_slice(&0x0100u16.to_be_bytes());
        raw.extend_from_slice(&1u16.to_be_bytes());
        raw.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        for label in name.trim_end_matches('.').split('.') {
            raw.push(label.len() as u8);
            raw.extend_from_slice(label.as_bytes());
        }
        raw.push(0);
        raw.extend_from_slice(&u16::from(RecordType::A).to_be_bytes());
        raw.extend_from_slice(&1u16.to_be_bytes());
        raw
    }

    fn a_reply(raw: &[u8], octets: [u8; 4]) -> Vec<u8> {
        let query = Message::from_vec(raw).expect("valid query");
        let mut reply = Message::new(query.metadata.id, MessageType::Response, query.metadata.op_code);
        reply.metadata.recursion_desired = query.metadata.recursion_desired;
        reply.metadata.recursion_available = true;
        reply.queries = query.queries.clone();
        reply.add_answer(Record::from_rdata(
            query.queries[0].name().clone(),
            60,
            RData::A(AData::new(octets[0], octets[1], octets[2], octets[3])),
        ));
        let mut bytes = reply.to_vec().unwrap();
        wire::copy_question_case(raw, &mut bytes);
        bytes
    }

    fn answer_address(answer: &UpstreamAnswer) -> Option<[u8; 4]> {
        let message = Message::from_vec(&answer.raw).ok()?;
        message.answers.iter().find_map(|record| match &record.data {
            RData::A(address) => Some(address.0.octets()),
            _ => None,
        })
    }

    /// A loopback UDP port nothing listens on: a connected socket gets ICMP
    /// port unreachable (ECONNREFUSED).
    fn closed_port() -> SocketAddr {
        std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap()
    }

    fn doh_upstream() -> Arc<Upstream> {
        Arc::new(Upstream::new(0, "https://example.test/dns-query".into()))
    }

    fn doh_reply(latency: Duration) -> DohReply {
        DohReply {
            raw: Vec::new(),
            message: Message::new(0, MessageType::Response, OpCode::Query),
            age: 0,
            terminal: true,
            latency,
            rcode_failure: false,
        }
    }

    /// Part of RFC 8085 s327 (SHOULD, 3.1) too.
    #[tokio::test]
    async fn rfc8085_s268_delay_and_loss_are_met_with_bounded_sending() {
        // Delay: an answer 300 ms late, well inside the deadline, is awaited
        // without sending a second datagram.
        let slow = Mock::start(answering([192, 0, 2, 1], Duration::from_millis(300))).await;
        let pool = UpstreamPool::new(&config(vec![slow.addr], 2)).unwrap();
        let answer = pool.exchange(&raw_query("delay.test.", 1), 1).await.expect("late answer is used");
        assert_eq!(answer_address(&answer), Some([192, 0, 2, 1]));
        assert_eq!(slow.count(), 1, "no retransmission under delay");

        // Loss: a silent destination gets one datagram for the query, none
        // for its immediate repeat, and a burst of distinct names is capped.
        let silent = Mock::start(silent()).await;
        let mut cfg = config(vec![silent.addr], 1);
        cfg.upstream_inflight_max = 2;
        let pool = Arc::new(UpstreamPool::new(&cfg).unwrap());
        assert!(pool.exchange(&raw_query("lost.test.", 2), 2).await.is_none());
        assert_eq!(silent.count(), 1, "one datagram per lost query");
        let started = Instant::now();
        assert!(pool.exchange(&raw_query("lost.test.", 2), 2).await.is_none());
        assert!(started.elapsed() < Duration::from_millis(500), "the repeat is refused at once");
        assert_eq!(silent.count(), 1, "the repeat sends nothing to the silent destination");

        let mut burst = tokio::task::JoinSet::new();
        for i in 0..5u16 {
            let pool = pool.clone();
            burst.spawn(async move { pool.exchange(&raw_query(&format!("burst{i}.test."), 10 + i), 10 + i).await });
        }
        while let Some(done) = burst.join_next().await {
            assert!(done.unwrap().is_none());
        }
        assert_eq!(silent.count(), 1 + 2, "at most upstream_inflight_max datagrams for the burst");
    }

    #[test]
    fn rfc8085_s424_latency_estimate_averages_recent_samples() {
        let upstream = Upstream::new(0, "https://example.test/dns-query".into());
        record_success(&upstream, Duration::from_millis(100));
        assert_eq!(upstream.state().ewma_us, 100_000);
        record_success(&upstream, Duration::from_millis(100));
        assert_eq!(upstream.state().ewma_us, 100_000);
        // A 1 s outlier moves the estimate one fifth of the way, not to 1 s.
        record_success(&upstream, Duration::from_millis(1000));
        assert_eq!(upstream.state().ewma_us, 280_000);
        // And the next ordinary sample pulls it back by the same weighting.
        record_success(&upstream, Duration::from_millis(100));
        assert_eq!(upstream.state().ewma_us, 244_000);
    }

    #[tokio::test]
    async fn rfc8085_s432_only_a_completed_reply_yields_a_latency_sample() {
        // A completed attempt contributes exactly one sample: its reply latency.
        let upstream = doh_upstream();
        upstream.state().ewma_us = 100_000;
        let mut attempt = Attempt::new(upstream.clone());
        attempt.complete(&Ok(doh_reply(Duration::from_millis(50))));
        drop(attempt);
        assert_eq!(upstream.state().ewma_us, (4 * 100_000 + 50_000) / 5, "one sample, taken once");

        // An attempt that never completed (a hedge loser, an aborted request)
        // has no reply to time: a short one cannot lower the estimate.
        let upstream = doh_upstream();
        upstream.state().ewma_us = 1_000_000;
        let attempt = Attempt::new(upstream.clone());
        tokio::time::sleep(Duration::from_millis(20)).await;
        drop(attempt);
        assert_eq!(upstream.state().ewma_us, 1_000_000, "a cancelled attempt is no sample");

        // A long one only raises the estimate as a damped lower bound, never
        // as if it were a measured reply latency.
        let upstream = doh_upstream();
        upstream.state().ewma_us = 1_000;
        let begun = std::time::Instant::now();
        let attempt = Attempt::new(upstream.clone());
        tokio::time::sleep(Duration::from_millis(60)).await;
        drop(attempt);
        let elapsed_us = begun.elapsed().as_micros() as u64;
        let estimate = upstream.state().ewma_us;
        assert!(estimate >= (4 * 1_000 + 60_000) / 5, "{estimate}");
        assert!(
            estimate <= (4 * 1_000 + elapsed_us) / 5,
            "the lower bound is damped, not adopted: {estimate} vs {elapsed_us}"
        );
        assert_eq!(upstream.state().failures, 0, "and it is no failure either");

        // Ambiguous UDP transactions through a pool whose DoH upstream is
        // down (so the plain path answers and every estimate is visible in
        // `health`): a query sent twice to one destination (the case-folding
        // retry, so a reply could belong to either send) and a reply that
        // arrives after the deadline both leave every latency estimate at 0.
        let dead_doh = || Config {
            upstreams: vec!["http://127.0.0.1:1/dns-query".into()],
            upstream_timeout_seconds: 1,
            ..Config::default()
        };
        let folding = Mock::start(Arc::new(|_, raw| {
            let mut reply = a_reply(raw, [192, 0, 2, 13]);
            let end = 12 + wire::parse_query(raw).unwrap().qname_wire.len();
            reply[12..end].make_ascii_lowercase();
            vec![(Duration::ZERO, reply)]
        }))
        .await;
        let mut cfg = dead_doh();
        cfg.fallback = vec![folding.addr];
        let pool = UpstreamPool::new(&cfg).unwrap();
        let answer = pool.exchange(&raw_query("MiXeD.CaSe.QuErY.NaMe.WiTh.LoTs.Of.LeTtErS.TeSt.", 6), 6).await;
        assert!(answer.is_some(), "the retry is answered");
        assert_eq!(folding.count(), 2, "the transaction is ambiguous: the question was sent twice");
        assert_eq!(pool.health().iter().map(|upstream| upstream.ewma_us).sum::<u64>(), 0, "no sample from it");

        let late = Mock::start(Arc::new(|index, raw| {
            let delay = if index == 0 { Duration::from_millis(1300) } else { Duration::from_millis(200) };
            vec![(delay, a_reply(raw, [192, 0, 2, 2]))]
        }))
        .await;
        let mut cfg = dead_doh();
        cfg.fallback = vec![late.addr];
        cfg.upstream_0x20 = false;
        let pool = UpstreamPool::new(&cfg).unwrap();
        let query = raw_query("karn.test.", 7);
        assert!(pool.exchange(&query, 7).await.is_none(), "the first send times out");
        for mark in pool.failures.lock().unwrap().map.values_mut() {
            mark.0 = mark.0.checked_sub(FAILURE_WINDOW).expect("instant can be backdated");
        }
        tokio::time::sleep(Duration::from_millis(400)).await; // the late reply arrives now
        assert!(pool.exchange(&query, 7).await.is_some(), "the repeat is answered by its own reply");
        assert_eq!(late.count(), 2);
        assert_eq!(pool.health().iter().map(|upstream| upstream.ewma_us).sum::<u64>(), 0, "no sample from a repeat");
    }

    /// Also RFC 8085 s463 (SHOULD, 3.1.1) and s546 (RECOMMENDED, 1).
    #[tokio::test]
    async fn rfc8085_s450_nothing_is_resent_before_the_one_second_floor() {
        // Two silent destinations, no latency history. The second is asked
        // after the hedge delay: that is another destination, not a resend.
        // Neither destination receives a second datagram, so no timer ever
        // re-sends to the same one before the 1 s floor (or at all).
        let first_seen: Arc<Mutex<Vec<Instant>>> = Arc::new(Mutex::new(Vec::new()));
        let second_seen: Arc<Mutex<Vec<Instant>>> = Arc::new(Mutex::new(Vec::new()));
        let record = |log: &Arc<Mutex<Vec<Instant>>>| -> Handler {
            let log = log.clone();
            Arc::new(move |_, _| {
                log.lock().unwrap().push(Instant::now());
                Vec::new()
            })
        };
        let (one, two) = (Mock::start(record(&first_seen)).await, Mock::start(record(&second_seen)).await);
        let pool = Arc::new(UpstreamPool::new(&config(vec![one.addr, two.addr], 2)).unwrap());
        let began = Instant::now();
        let task = {
            let pool = pool.clone();
            tokio::spawn(async move { pool.exchange(&raw_query("pair.test.", 8), 8).await })
        };
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert_eq!(one.count(), 1, "the first destination was asked once, not again by 1.5 s");
        assert_eq!(two.count(), 1, "the second destination was asked once (a hedge, not a resend)");
        let hedge_gap = second_seen.lock().unwrap()[0] - first_seen.lock().unwrap()[0];
        assert!(hedge_gap < Duration::from_secs(1), "the other destination is asked early by design: {hedge_gap:?}");
        assert!(task.await.unwrap().is_none());
        assert_eq!((one.count(), two.count()), (1, 1), "nothing was resent up to the deadline {:?}", began.elapsed());

        let silent = Mock::start(silent()).await;
        let pool = Arc::new(UpstreamPool::new(&config(vec![silent.addr], 2)).unwrap());
        let started = Instant::now();
        let task = {
            let pool = pool.clone();
            tokio::spawn(async move { pool.exchange(&raw_query("initial.test.", 3), 3).await })
        };
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert_eq!(silent.count(), 1, "no retransmission at 1.5 s: the first interval is not below 1 s");
        assert!(!task.is_finished(), "the exchange is still waiting inside its deadline");
        assert!(task.await.unwrap().is_none());
        let elapsed = started.elapsed();
        assert!(elapsed >= Duration::from_millis(1900) && elapsed < Duration::from_secs(4), "{elapsed:?}");
        assert_eq!(silent.count(), 1, "the lost query was sent exactly once");
        // The failure interval that follows is not below 1 s either.
        let windows: Vec<Duration> = pool.failures.lock().unwrap().map.values().map(|mark| mark.1).collect();
        assert_eq!(windows.len(), 1);
        assert!(windows[0] >= Duration::from_secs(1), "{:?}", windows[0]);
        // Configuration cannot shrink the first interval below 1 s.
        assert!(Config::default().upstream_timeout_seconds >= 1);
        let mut zero = Config { upstream_timeout_seconds: 0, ..Config::default() };
        assert!(zero.validate().is_err(), "a zero timeout is refused");
    }

    #[tokio::test]
    async fn rfc8085_s596_sending_stops_at_the_failure_signal_and_resumes_after_the_interval() {
        let silent = Mock::start(silent()).await;
        let pool = UpstreamPool::new(&config(vec![silent.addr], 1)).unwrap();
        let query = raw_query("signal.test.", 4);
        assert!(pool.exchange(&query, 4).await.is_none(), "the timeout is the congestion signal");
        assert_eq!(silent.count(), 1);
        let started = Instant::now();
        assert!(pool.exchange(&query, 4).await.is_none());
        assert!(started.elapsed() < Duration::from_millis(500), "refused at once, not after another deadline");
        assert_eq!(silent.count(), 1, "sending stopped");
        // Once the suppression interval has passed the destination is tried again.
        for mark in pool.failures.lock().unwrap().map.values_mut() {
            mark.0 = mark.0.checked_sub(FAILURE_WINDOW).expect("instant can be backdated");
        }
        assert!(pool.exchange(&query, 4).await.is_none());
        assert_eq!(silent.count(), 2, "sending resumed after the interval");
    }

    /// Also RFC 8085 s2094 (SHOULD, 5.2): the destination is not given up on.
    #[tokio::test]
    async fn rfc8085_s866_an_unreachable_destination_is_skipped_then_asked_again_and_cleared() {
        let closed = closed_port();
        let good = Mock::start(answering([192, 0, 2, 9], Duration::ZERO)).await;
        let pool = UpstreamPool::new(&config(vec![closed, good.addr], 2)).unwrap();

        let first = pool.exchange(&raw_query("open0.test.", 1), 1).await.expect("the working fallback answers");
        assert_eq!(answer_address(&first), Some([192, 0, 2, 9]));
        {
            let state = pool.fallback_state[0].lock().unwrap();
            assert_eq!(state.failures, 1);
            assert!(state.skip_until.is_some(), "the breaker is open");
        }
        // Open: the closed destination is not asked again.
        assert!(pool.exchange(&raw_query("open1.test.", 2), 2).await.is_some());
        assert_eq!(pool.fallback_state[0].lock().unwrap().failures, 1);

        // The destination comes back, and the interval has passed.
        let revived = Mock::bind(closed, answering([192, 0, 2, 55], Duration::ZERO)).await;
        pool.fallback_state[0].lock().unwrap().skip_until = Some(Instant::now());
        let third = pool.exchange(&raw_query("open2.test.", 3), 3).await.expect("answer");
        assert_eq!(revived.count(), 1, "the destination is asked again");
        assert_eq!(answer_address(&third), Some([192, 0, 2, 55]));
        let state = pool.fallback_state[0].lock().unwrap();
        assert_eq!(state.failures, 0, "a reply closes the breaker");
        assert!(state.skip_until.is_none());
        drop(state);

        // Repeated unreachable results lengthen the interval.
        let health = Mutex::new(FallbackState::default());
        FallbackState::record(&health, &Err(Fail::Unreachable));
        let first = health.lock().unwrap().skip_until.unwrap();
        FallbackState::record(&health, &Err(Fail::Unreachable));
        let second = health.lock().unwrap().skip_until.unwrap();
        assert!(second > first + Duration::from_secs(4), "the second interval doubles");
        FallbackState::record(&health, &Err(Fail::Remote));
        assert_eq!(health.lock().unwrap().failures, 2, "a timeout is no evidence of unreachability");
    }

    #[tokio::test]
    async fn rfc8085_s1158_a_duplicate_of_an_accepted_reply_is_ignored() {
        // Query 1 is answered twice, the copy 30 ms late; query 2 for the same
        // name is answered 150 ms after it is sent, so the copy lands while
        // query 2 is outstanding.
        let handler: Handler = Arc::new(|index, raw| {
            if index == 0 {
                let reply = a_reply(raw, [203, 0, 113, 1]);
                vec![(Duration::ZERO, reply.clone()), (Duration::from_millis(30), reply)]
            } else {
                vec![(Duration::from_millis(150), a_reply(raw, [192, 0, 2, 2]))]
            }
        });
        let mock = Mock::start(handler).await;
        let mut cfg = config(vec![mock.addr], 2);
        // Isolate the transaction-ID and port checks from the 0x20 check.
        cfg.upstream_0x20 = false;
        let pool = UpstreamPool::new(&cfg).unwrap();
        let first = pool.exchange(&raw_query("dup.test.", 1), 1).await.expect("first answer");
        assert_eq!(answer_address(&first), Some([203, 0, 113, 1]));
        let second = pool.exchange(&raw_query("dup.test.", 2), 2).await.expect("second answer");
        assert_eq!(answer_address(&second), Some([192, 0, 2, 2]), "the stale duplicate was not taken for it");
        assert_eq!(mock.count(), 2);
    }

    #[tokio::test]
    async fn rfc8085_s1184_a_reply_delayed_past_the_deadline_is_not_taken_for_the_next_query() {
        // Query 1 times out (1 s). Its answer then arrives 300 ms after the
        // deadline, addressed to its (closed) socket, while query 2 for the
        // same name is waiting for its own answer at 600 ms.
        let handler: Handler = Arc::new(|index, raw| {
            if index == 0 {
                vec![(Duration::from_millis(1300), a_reply(raw, [203, 0, 113, 1]))]
            } else {
                vec![(Duration::from_millis(600), a_reply(raw, [192, 0, 2, 2]))]
            }
        });
        let mock = Mock::start(handler).await;
        let mut cfg = config(vec![mock.addr], 1);
        cfg.upstream_0x20 = false;
        let pool = UpstreamPool::new(&cfg).unwrap();
        let query = raw_query("stale.test.", 5);
        assert!(pool.exchange(&query, 5).await.is_none(), "query 1 times out");
        // Whatever the lateness (the RFC's window is two minutes), nothing
        // is left listening on query 1's source port: it can be bound again.
        let port_one = mock.seen.lock().unwrap()[0].0;
        // (The cancelled attempt task is dropped by the runtime a moment later.)
        let mut rebound = None;
        for _ in 0..20 {
            rebound = std::net::UdpSocket::bind(("0.0.0.0", port_one)).ok();
            if rebound.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(rebound.is_some(), "the timed-out transaction's socket is closed, so no late reply can be consumed");
        drop(rebound);
        // Let query 2 run despite the failure marker of query 1.
        for mark in pool.failures.lock().unwrap().map.values_mut() {
            mark.0 = mark.0.checked_sub(FAILURE_WINDOW).expect("instant can be backdated");
        }
        let second = pool.exchange(&query, 5).await.expect("query 2 gets its own answer");
        assert_eq!(answer_address(&second), Some([192, 0, 2, 2]), "not the stale 203.0.113.1");
        assert_eq!(mock.count(), 2);
        let seen = mock.seen.lock().unwrap();
        assert_ne!(seen[0].0, seen[1].0, "the repeat uses another source port");
        assert_ne!(seen[0].1[0..2], seen[1].1[0..2], "and another ID");
    }

    #[tokio::test]
    async fn rfc8085_s1909_source_ports_are_random_not_a_sequence() {
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap();
        let mut sockets = Vec::new();
        for _ in 0..64 {
            sockets.push(connected_socket(target, &[]).await.unwrap());
        }
        let ports: Vec<u16> = sockets.iter().map(|socket| socket.local_addr().unwrap().port()).collect();
        assert!(ports.iter().all(|&port| crate::config::SOURCE_PORTS.contains(&port)), "1024 and up only: {ports:?}");
        let distinct: std::collections::HashSet<u16> = ports.iter().copied().collect();
        assert_eq!(distinct.len(), 64, "every query leaves from its own port: {ports:?}");
        let deltas: std::collections::HashSet<i32> =
            ports.windows(2).map(|pair| i32::from(pair[1]) - i32::from(pair[0])).collect();
        assert!(deltas.len() > 32, "a constant stride or short cycle is predictable: {} distinct steps", deltas.len());
        let spread = ports.iter().max().unwrap() - ports.iter().min().unwrap();
        assert!(spread >= 2000, "random ports cover a wide part of the range, not a narrow run: spread {spread}");
    }

    #[test]
    fn rfc8085_s2094_icmp_unreachable_is_a_soft_per_destination_result() {
        use std::io::{Error, ErrorKind};
        for kind in [ErrorKind::HostUnreachable, ErrorKind::NetworkUnreachable, ErrorKind::ConnectionRefused] {
            assert_eq!(io_fail(&Error::from(kind)), Fail::Unreachable, "{kind:?}");
        }
        // Unreachable is evidence about the destination only, never our own fault.
        assert_ne!(io_fail(&Error::from(ErrorKind::HostUnreachable)), Fail::Local);
    }

    #[tokio::test]
    async fn rfc8085_s2094_a_transient_unreachable_does_not_abort_later_communication() {
        let addr = closed_port();
        let pool = UpstreamPool::new(&config(vec![addr], 2)).unwrap();
        assert!(pool.exchange(&raw_query("soft0.test.", 1), 1).await.is_none(), "unreachable fails that query");
        assert_eq!(pool.fallback_state[0].lock().unwrap().failures, 1);
        // The routing failure clears; the lone destination is tried again at once.
        let revived = Mock::bind(addr, answering([192, 0, 2, 7], Duration::ZERO)).await;
        let answer = pool.exchange(&raw_query("soft1.test.", 2), 2).await.expect("communication resumes");
        assert_eq!(answer_address(&answer), Some([192, 0, 2, 7]));
        assert_eq!(revived.count(), 1);
        assert_eq!(pool.fallback_state[0].lock().unwrap().failures, 0);
    }

    #[tokio::test]
    async fn rfc8085_s2123_ports_and_ids_vary_and_off_path_datagrams_are_rejected() {
        // Eight transactions: eight source ports, and IDs that are neither
        // equal nor a counting sequence.
        let fast = Mock::start(answering([192, 0, 2, 1], Duration::ZERO)).await;
        let pool = UpstreamPool::new(&config(vec![fast.addr], 2)).unwrap();
        for i in 0..8u16 {
            let name = format!("rand{i}.test.");
            assert!(pool.exchange(&raw_query(&name, i), i).await.is_some());
        }
        let seen = fast.seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 8);
        let ports: std::collections::HashSet<u16> = seen.iter().map(|(port, _)| *port).collect();
        assert_eq!(ports.len(), 8, "a fresh source port per transaction");
        let ids: Vec<u16> = seen.iter().map(|(_, query)| u16::from_be_bytes([query[0], query[1]])).collect();
        let distinct: std::collections::HashSet<u16> = ids.iter().copied().collect();
        assert!(distinct.len() >= 6, "IDs are drawn at random: {ids:?}");
        assert!(ids.windows(2).any(|pair| pair[1] != pair[0].wrapping_add(1)), "IDs are no counter: {ids:?}");

        // Off-path forgeries aimed at the transaction's port: right ID,
        // question and case but from another source address, and one with
        // another ID as well. Both are discarded.
        let slow = Mock::start(answering([192, 0, 2, 1], Duration::from_millis(300))).await;
        let pool = Arc::new(UpstreamPool::new(&config(vec![slow.addr], 2)).unwrap());
        let task = {
            let pool = pool.clone();
            tokio::spawn(async move { pool.exchange(&raw_query("forged.test.", 9), 9).await })
        };
        let (port, query) = loop {
            if let Some(first) = slow.seen.lock().unwrap().first().cloned() {
                break first;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        };
        let target: SocketAddr = ([127, 0, 0, 1], port).into();
        let outsider = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        outsider.send_to(&a_reply(&query, [203, 0, 113, 9]), target).await.unwrap();
        let mut wrong_id = a_reply(&query, [203, 0, 113, 8]);
        let id = u16::from_be_bytes([wrong_id[0], wrong_id[1]]).wrapping_add(1);
        wrong_id[0..2].copy_from_slice(&id.to_be_bytes());
        outsider.send_to(&wrong_id, target).await.unwrap();
        let answer = task.await.unwrap().expect("the genuine answer arrives");
        assert_eq!(answer_address(&answer), Some([192, 0, 2, 1]), "forged datagrams were not accepted");
    }
}

#[cfg(test)]
mod rfc_tests_c {
    use super::*;
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use hickory_proto::rr::rdata::A as AData;
    use hickory_proto::rr::{RData, Record};
    use tokio::net::TcpListener;

    fn cfg(upstreams: Vec<String>, fallback: Vec<SocketAddr>) -> Config {
        Config { upstreams, fallback, upstream_hedge_ms: 40, upstream_timeout_seconds: 2, ..Config::default() }
    }

    fn query(name: &str, id: u16) -> Vec<u8> {
        let mut raw = vec![(id >> 8) as u8, id as u8, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.trim_end_matches('.').split('.') {
            raw.push(label.len() as u8);
            raw.extend_from_slice(label.as_bytes());
        }
        raw.extend_from_slice(&[0, 0, 1, 0, 1]);
        raw
    }

    fn is_probe(raw: &[u8]) -> bool {
        Message::from_vec(raw)
            .is_ok_and(|m| m.queries.first().is_some_and(|q| q.query_type() == RecordType::NS && q.name().is_root()))
    }

    /// A response to `raw` with one A record per entry of `lasts` (192.0.2.x).
    fn answer(raw: &[u8], rcode: ResponseCode, lasts: &[u8]) -> Vec<u8> {
        let q = Message::from_vec(raw).unwrap();
        let mut r = Message::new(q.metadata.id, MessageType::Response, q.metadata.op_code);
        r.metadata.recursion_desired = q.metadata.recursion_desired;
        r.metadata.recursion_available = true;
        r.metadata.response_code = rcode;
        r.queries = q.queries.clone();
        for last in lasts {
            let name = q.queries[0].name().clone();
            r.add_answer(Record::from_rdata(name, 60, RData::A(AData::new(192, 0, 2, *last))));
        }
        let mut bytes = r.to_vec().unwrap();
        wire::copy_question_case(raw, &mut bytes);
        bytes
    }

    fn ok(raw: &[u8], last: u8) -> Vec<u8> {
        answer(raw, ResponseCode::NoError, &[last])
    }

    fn last_octet(got: &UpstreamAnswer) -> u8 {
        let m = Message::from_vec(&got.raw).unwrap();
        m.answers
            .iter()
            .find_map(|r| match &r.data {
                RData::A(a) => Some(a.0.octets()[3]),
                _ => None,
            })
            .expect("an A record")
    }

    struct Resp {
        status: u16,
        headers: Vec<String>,
        body: Vec<u8>,
        delay: Duration,
    }

    impl Resp {
        fn dns(body: Vec<u8>) -> Self {
            Self {
                status: 200,
                headers: vec!["Content-Type: application/dns-message".into()],
                body,
                delay: Duration::ZERO,
            }
        }
        fn status(status: u16) -> Self {
            Self { status, headers: vec![], body: vec![], delay: Duration::ZERO }
        }
        fn header(mut self, line: String) -> Self {
            self.headers.push(line);
            self
        }
        fn delayed(mut self, delay: Duration) -> Self {
            self.delay = delay;
            self
        }
    }

    struct Doh {
        url: String,
        task: JoinHandle<()>,
    }

    impl Drop for Doh {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    impl Doh {
        async fn start(handler: impl Fn(&[u8]) -> Resp + Send + Sync + 'static) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let handler = Arc::new(handler);
            let task = tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else { return };
                    let handler = handler.clone();
                    tokio::spawn(async move {
                        let _ = Self::serve(stream, &*handler).await;
                    });
                }
            });
            Self { url: format!("http://{addr}/dns-query"), task }
        }

        async fn serve(mut stream: TcpStream, handler: &(dyn Fn(&[u8]) -> Resp + Send + Sync)) -> std::io::Result<()> {
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            let head_end = loop {
                let n = stream.read(&mut chunk).await?;
                if n == 0 {
                    return Ok(());
                }
                buf.extend_from_slice(&chunk[..n]);
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break pos;
                }
            };
            let head = String::from_utf8_lossy(&buf[..head_end]).to_ascii_lowercase();
            let length: usize = head
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(0);
            while buf.len() < head_end + 4 + length {
                let n = stream.read(&mut chunk).await?;
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            let resp = handler(buf.get(head_end + 4..head_end + 4 + length).unwrap_or(&[]));
            if !resp.delay.is_zero() {
                tokio::time::sleep(resp.delay).await;
            }
            let mut out =
                format!("HTTP/1.1 {} X\r\nContent-Length: {}\r\nConnection: close\r\n", resp.status, resp.body.len());
            for line in &resp.headers {
                out.push_str(line);
                out.push_str("\r\n");
            }
            out.push_str("\r\n");
            stream.write_all(out.as_bytes()).await?;
            stream.write_all(&resp.body).await?;
            stream.shutdown().await
        }
    }

    #[derive(Clone, Copy)]
    enum Mode {
        Silent,
        /// Answer after the delay.
        Hold(Duration),
        /// Answer with TC set after the delay.
        Truncate(Duration),
    }

    /// A UDP upstream that records every datagram it receives.
    struct Udp {
        addr: SocketAddr,
        count: Arc<AtomicUsize>,
        ports: Arc<Mutex<HashSet<u16>>>,
        stamps: Arc<Mutex<Vec<Instant>>>,
        max_active: Arc<AtomicUsize>,
        task: JoinHandle<()>,
    }

    impl Drop for Udp {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    impl Udp {
        async fn start(bind: &str, mode: Mode) -> Self {
            let socket = Arc::new(UdpSocket::bind(bind).await.unwrap());
            let addr = socket.local_addr().unwrap();
            let count = Arc::new(AtomicUsize::new(0));
            let ports = Arc::new(Mutex::new(HashSet::new()));
            let stamps = Arc::new(Mutex::new(Vec::new()));
            let active = Arc::new(AtomicUsize::new(0));
            let max_active = Arc::new(AtomicUsize::new(0));
            let (c, p, s, a, m) = (count.clone(), ports.clone(), stamps.clone(), active, max_active.clone());
            let task = tokio::spawn(async move {
                let mut buf = vec![0u8; MAX_DNS_MESSAGE];
                loop {
                    let Ok((n, peer)) = socket.recv_from(&mut buf).await else { return };
                    c.fetch_add(1, Ordering::SeqCst);
                    p.lock().unwrap().insert(peer.port());
                    s.lock().unwrap().push(Instant::now());
                    let delay = match mode {
                        Mode::Silent => continue,
                        Mode::Hold(d) | Mode::Truncate(d) => d,
                    };
                    m.fetch_max(a.fetch_add(1, Ordering::SeqCst) + 1, Ordering::SeqCst);
                    let (socket, a, q) = (socket.clone(), a.clone(), buf[..n].to_vec());
                    tokio::spawn(async move {
                        tokio::time::sleep(delay).await;
                        let mut reply = ok(&q, 1);
                        if matches!(mode, Mode::Truncate(_)) {
                            reply[2] |= 0x02;
                        }
                        let _ = socket.send_to(&reply, peer).await;
                        a.fetch_sub(1, Ordering::SeqCst);
                    });
                }
            });
            Self { addr, count, ports, stamps, max_active, task }
        }

        fn count(&self) -> usize {
            self.count.load(Ordering::SeqCst)
        }
    }

    /// RFC 2308 section 7.2: "A server MAY cache a dead server indication."
    /// Witnessed: once probes open upstream A's circuit, the next client query
    /// is not sent to A (it is the preferred server, and answers if asked).
    #[tokio::test]
    async fn rfc2308_s601_dead_server_indication_is_cached_for_the_next_query() {
        let a_hits = Arc::new(AtomicUsize::new(0));
        let b_hits = Arc::new(AtomicUsize::new(0));
        let a = {
            let hits = a_hits.clone();
            Doh::start(move |raw| {
                if is_probe(raw) {
                    return Resp::status(500);
                }
                hits.fetch_add(1, Ordering::SeqCst);
                Resp::dns(ok(raw, 1))
            })
            .await
        };
        let b = {
            let hits = b_hits.clone();
            Doh::start(move |raw| {
                if is_probe(raw) {
                    return Resp::dns(answer(raw, ResponseCode::NoError, &[]));
                }
                hits.fetch_add(1, Ordering::SeqCst);
                Resp::dns(ok(raw, 2))
            })
            .await
        };
        let mut c = cfg(vec![a.url.clone(), b.url.clone()], vec![]);
        c.upstream_strategy = UpstreamStrategy::Ordered;
        let pool = UpstreamPool::new(&c).unwrap();
        // Control: with no dead indication the preferred server A is asked.
        let first = pool.exchange(&query("before.test.", 1), 1).await.expect("answer");
        assert_eq!(last_octet(&first), 1);
        assert_eq!(a_hits.load(Ordering::SeqCst), 1);
        for _ in 0..3 {
            pool.probe_all().await;
        }
        assert!(!pool.health()[0].healthy, "A is marked dead");
        assert!(pool.health()[1].healthy, "B is not");
        let started = Instant::now();
        let next = pool.exchange(&query("after.test.", 2), 2).await.expect("answer");
        assert_eq!(last_octet(&next), 2, "the next query skips the server marked dead");
        assert_eq!(a_hits.load(Ordering::SeqCst), 1, "the dead server was not sent the next query");
        assert_eq!(b_hits.load(Ordering::SeqCst), 1);
        assert!(started.elapsed() < Duration::from_secs(1), "{:?}", started.elapsed());
    }

    /// RFC 8085 section 3.1: congestion control "over all UDP traffic it sends
    /// to a destination" and "over the aggregate traffic" when "multiple
    /// sockets" generate it. Every attempt uses its own socket; the aggregate
    /// is still held to the in-flight cap and the overflow is refused unsent.
    #[tokio::test]
    async fn rfc8085_s330_s333_udp_aggregate_over_many_sockets_is_capped() {
        const CAP: usize = 4;
        let udp = Udp::start("127.0.0.1:0", Mode::Hold(Duration::from_millis(300))).await;
        let mut c = cfg(vec![], vec![udp.addr]);
        c.upstream_inflight_max = CAP;
        c.upstream_timeout_seconds = 3;
        let pool = Arc::new(UpstreamPool::new(&c).unwrap());
        let mut set = tokio::task::JoinSet::new();
        for i in 0..3 * CAP {
            let pool = pool.clone();
            set.spawn(async move {
                let id = i as u16 + 1;
                pool.exchange(&query(&format!("n{i}.test."), id), id).await.is_some()
            });
        }
        let (mut served, mut refused) = (0, 0);
        while let Some(done) = set.join_next().await {
            if done.unwrap() {
                served += 1;
            } else {
                refused += 1;
            }
        }
        assert_eq!(served, CAP);
        assert_eq!(refused, 2 * CAP, "the overflow gets SERVFAIL");
        assert_eq!(udp.count(), CAP, "only the capped datagrams, with no retransmission, reach the destination");
        assert_eq!(udp.ports.lock().unwrap().len(), CAP, "each of them came from its own socket");
        assert!(udp.max_active.load(Ordering::SeqCst) <= CAP);
    }

    /// RFC 8484 section 4.2.1: a DoH client treats non-successful HTTP status
    /// codes as other HTTP clients do. Redirects off plain http are never
    /// followed (the body would be replayed in the clear) and 401/404/415
    /// move on to the next server.
    #[tokio::test]
    async fn rfc8484_s379_doh_http_status_semantics_fail_over_and_never_replay_over_http() {
        for status in [301u16, 302, 307, 308, 401, 404, 415] {
            let target_hits = Arc::new(AtomicUsize::new(0));
            let a_hits = Arc::new(AtomicUsize::new(0));
            let target = {
                let hits = target_hits.clone();
                Doh::start(move |raw| {
                    hits.fetch_add(1, Ordering::SeqCst);
                    match Message::from_vec(raw) {
                        Ok(_) => Resp::dns(ok(raw, 99)),
                        Err(_) => Resp::status(400),
                    }
                })
                .await
            };
            let location = target.url.clone();
            let a = {
                let hits = a_hits.clone();
                Doh::start(move |_| {
                    hits.fetch_add(1, Ordering::SeqCst);
                    let resp = Resp::status(status);
                    if (300..400).contains(&status) {
                        resp.header(format!("Location: {location}"))
                    } else {
                        resp
                    }
                })
                .await
            };
            let b = Doh::start(|raw| if is_probe(raw) { Resp::status(500) } else { Resp::dns(ok(raw, 2)) }).await;
            let mut c = cfg(vec![a.url.clone(), b.url.clone()], vec![]);
            c.upstream_strategy = UpstreamStrategy::Ordered;
            let pool = UpstreamPool::new(&c).unwrap();
            let got = pool.exchange(&query("status.test.", 5), 5).await.expect("the next server answers");
            assert_eq!(last_octet(&got), 2, "status {status}: nothing from the failing server or its redirect target");
            assert_eq!(a_hits.load(Ordering::SeqCst), 1, "status {status}");
            assert_eq!(target_hits.load(Ordering::SeqCst), 0, "status {status}: the query was replayed over http");
        }
    }

    /// RFC 9520 section 3.2: "Resolvers MUST cache resolution failures for at
    /// least 1 second." A SERVFAIL for a name is not asked again, even after a
    /// full second; another name is unaffected.
    #[tokio::test]
    async fn rfc9520_s454_resolution_failure_is_cached_for_at_least_one_second() {
        let hits = Arc::new(AtomicUsize::new(0));
        let doh = {
            let hits = hits.clone();
            Doh::start(move |raw| {
                hits.fetch_add(1, Ordering::SeqCst);
                Resp::dns(answer(raw, ResponseCode::ServFail, &[]))
            })
            .await
        };
        let pool = UpstreamPool::new(&cfg(vec![doh.url.clone()], vec![])).unwrap();
        assert!(pool.exchange(&query("fails.test.", 1), 1).await.is_none());
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert!(pool.exchange(&query("fails.test.", 2), 2).await.is_none());
        assert_eq!(hits.load(Ordering::SeqCst), 1, "repeat inside the window is not sent");
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert!(pool.exchange(&query("fails.test.", 3), 3).await.is_none());
        assert_eq!(hits.load(Ordering::SeqCst), 1, "still cached after one second");
        assert!(pool.exchange(&query("other.test.", 4), 4).await.is_none());
        assert_eq!(hits.load(Ordering::SeqCst), 2, "the cache is per name");
    }

    /// RFC 1035 section 7.1 and RFC 4035 section 5.4: the work for one request
    /// is bounded and ends in a temporary error. With a silent UDP upstream
    /// one request sends a finite number of datagrams, ends in SERVFAIL at the
    /// deadline and sends nothing afterwards.
    #[tokio::test]
    async fn rfc1035_s2452_s2456_rfc4035_s1835_silent_udp_upstream_work_is_bounded() {
        let udp = Udp::start("127.0.0.1:0", Mode::Silent).await;
        let mut c = cfg(vec![], vec![udp.addr]);
        c.upstream_timeout_seconds = 1;
        let pool = UpstreamPool::new(&c).unwrap();
        let started = Instant::now();
        let got = tokio::time::timeout(Duration::from_secs(4), pool.exchange(&query("silent.test.", 7), 7))
            .await
            .expect("the request is terminated, not retried forever");
        assert!(got.is_none(), "temporary error (SERVFAIL)");
        assert!(started.elapsed() >= Duration::from_millis(900), "{:?}", started.elapsed());
        let sent = udp.count();
        assert!((1..=3).contains(&sent), "datagrams sent: {sent}");
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(udp.count(), sent, "no work after the request ended");
    }

    /// Same bound on the DoH side: two silent upstreams each see the query at
    /// most once, the request ends in SERVFAIL at the deadline, and no further
    /// upstream traffic follows.
    #[tokio::test]
    async fn rfc1035_s2452_rfc4035_s1835_silent_doh_upstreams_work_is_bounded() {
        let hits = [Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0))];
        let mut mocks = Vec::new();
        for hit in &hits {
            let hit = hit.clone();
            mocks.push(
                Doh::start(move |_| {
                    hit.fetch_add(1, Ordering::SeqCst);
                    Resp::status(200).delayed(Duration::from_secs(10))
                })
                .await,
            );
        }
        let mut c = cfg(mocks.iter().map(|m| m.url.clone()).collect(), vec![]);
        c.upstream_timeout_seconds = 1;
        let pool = UpstreamPool::new(&c).unwrap();
        let started = Instant::now();
        let got = tokio::time::timeout(Duration::from_secs(4), pool.exchange(&query("silent.test.", 7), 7))
            .await
            .expect("the request is terminated at its deadline");
        assert!(got.is_none());
        assert!(started.elapsed() >= Duration::from_millis(900), "{:?}", started.elapsed());
        let total = |hits: &[Arc<AtomicUsize>; 2]| hits.iter().map(|h| h.load(Ordering::SeqCst)).sum::<usize>();
        for hit in &hits {
            assert!(hit.load(Ordering::SeqCst) <= 1, "one upstream saw the same request more than once");
        }
        let sent = total(&hits);
        assert!(sent >= 1);
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(total(&hits), sent, "no work after the request ended");
    }

    /// RFC 1035 section 7.3: an RTT sample must come from the transmission
    /// that was answered. A hedged second transmission, launched 400 ms after
    /// the query began, answers at once; its upstream's smoothed RTT is its
    /// own few milliseconds, not the 400 ms since the query began.
    #[tokio::test]
    async fn rfc1035_s2603_rtt_is_sampled_from_the_answered_transmission() {
        let slow = Doh::start(|raw| Resp::dns(ok(raw, 1)).delayed(Duration::from_millis(1500))).await;
        let fast = Doh::start(|raw| Resp::dns(ok(raw, 2))).await;
        let mut c = cfg(vec![slow.url.clone(), fast.url.clone()], vec![]);
        c.upstream_hedge_ms = 400;
        c.upstream_timeout_seconds = 3;
        let pool = UpstreamPool::new(&c).unwrap();
        let got = pool.exchange(&query("rtt.test.", 3), 3).await.expect("answer");
        assert_eq!(last_octet(&got), 2, "the hedged transmission answered");
        assert_eq!(pool.upstreams[1].state().wins, 1);
        let ewma = pool.upstreams[1].state().ewma_us;
        assert!((1..200_000).contains(&ewma), "RTT sampled from the query start, not the transmission: {ewma} us");
    }

    /// RFC 8085 section 3: no assumptions about path characteristics. A path
    /// that takes 700 ms over DoH, and one that needs a truncated UDP reply
    /// plus a large TCP answer at 400 ms per leg, still complete.
    #[tokio::test]
    async fn rfc8085_s266_slow_and_tcp_only_paths_still_complete() {
        let doh = Doh::start(|raw| Resp::dns(ok(raw, 1)).delayed(Duration::from_millis(700))).await;
        // One port for both transports: another test may hold the UDP twin of
        // a free TCP port.
        let tcp = loop {
            let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
            if UdpSocket::bind(tcp.local_addr().unwrap()).await.is_ok() {
                break tcp;
            }
        };
        let addr = tcp.local_addr().unwrap();
        let _udp = Udp::start(&addr.to_string(), Mode::Truncate(Duration::from_millis(400))).await;
        let tcp_task = tokio::spawn(async move {
            let (mut stream, _) = tcp.accept().await.unwrap();
            let mut len = [0u8; 2];
            stream.read_exact(&mut len).await.unwrap();
            let mut body = vec![0u8; u16::from_be_bytes(len) as usize];
            stream.read_exact(&mut body).await.unwrap();
            tokio::time::sleep(Duration::from_millis(400)).await;
            let reply = answer(&body, ResponseCode::NoError, &(1..=150).collect::<Vec<u8>>());
            stream.write_all(&(reply.len() as u16).to_be_bytes()).await.unwrap();
            stream.write_all(&reply).await.unwrap();
        });
        let mut c = cfg(vec![doh.url.clone()], vec![]);
        c.upstream_timeout_seconds = 3;
        let doh_pool = UpstreamPool::new(&c).unwrap();
        let mut c = cfg(vec![], vec![addr]);
        c.upstream_timeout_seconds = 3;
        let plain_pool = UpstreamPool::new(&c).unwrap();
        let (q1, q2) = (query("slow.test.", 1), query("big.test.", 2));
        let (a, b) = tokio::join!(doh_pool.exchange(&q1, 1), plain_pool.exchange(&q2, 2));
        assert!(a.expect("a slow DoH path completes").terminal);
        let big = b.expect("a TCP-only path completes");
        assert!(big.raw.len() > 512 && big.terminal, "{} bytes", big.raw.len());
        tcp_task.await.unwrap();
    }

    /// RFC 8085 section 1: a predetermined interval, exponentially backed off
    /// when packets are deemed lost. The per-name failure window runs 5, 10,
    /// 20 then stays at its 30 s cap; a refused plain fallback is skipped for
    /// 5, 10, 20, 40 then stays at its 60 s cap.
    #[tokio::test]
    async fn rfc8085_s544_loss_backoff_doubles_up_to_a_cap() {
        let pool = UpstreamPool::new(&cfg(vec![], vec![])).unwrap();
        let key: Box<[u8]> = Box::from(&b"name"[..]);
        let mut windows = Vec::new();
        for _ in 0..6 {
            pool.mark_failure(key.clone());
            windows.push(pool.failures.lock().unwrap().map.get(&key[..]).unwrap().1.as_secs());
        }
        assert_eq!(windows, [5, 10, 20, 30, 30, 30]);

        let dead = UdpSocket::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap();
        let pool = UpstreamPool::new(&cfg(vec![], vec![dead])).unwrap();
        let mut skips = Vec::new();
        for i in 0..6u16 {
            assert!(pool.exchange(&query(&format!("lost{i}.test."), i + 1), i + 1).await.is_none());
            let until = pool.fallback_state[0].lock().unwrap().skip_until.expect("fallback is skipped");
            skips.push((until.saturating_duration_since(Instant::now()) + Duration::from_millis(500)).as_secs());
        }
        assert_eq!(skips, [5, 10, 20, 40, 60, 60]);
    }

    /// RFC 8085 section 3.1.6: copies of a packet are paced over more than
    /// one RTT. The query goes to a silent fallback first and the copy to the
    /// next one only after the hedge delay; neither address gets two.
    #[tokio::test]
    async fn rfc8085_s658_extra_copy_is_paced_by_the_hedge_delay() {
        let silent = Udp::start("127.0.0.1:0", Mode::Silent).await;
        let live = Udp::start("127.0.0.1:0", Mode::Hold(Duration::ZERO)).await;
        let mut c = cfg(vec![], vec![silent.addr, live.addr]);
        c.upstream_hedge_ms = 150;
        let pool = UpstreamPool::new(&c).unwrap();
        let got = pool.exchange(&query("paced.test.", 9), 9).await.expect("the second copy is answered");
        assert_eq!(last_octet(&got), 1);
        assert_eq!(silent.count(), 1);
        assert_eq!(live.count(), 1);
        let first = silent.stamps.lock().unwrap()[0];
        let second = live.stamps.lock().unwrap()[0];
        let gap = second.saturating_duration_since(first);
        assert!(gap >= Duration::from_millis(120), "copy sent {gap:?} after the first");
    }

    /// RFC 1035 section 4.2.1: other server addresses are tried before a query
    /// is repeated to one address. Three silent fallbacks must each see a
    /// first datagram before the first one sees a retransmission.
    #[tokio::test]
    async fn rfc1035_s2539_every_address_is_tried_before_the_first_repeat() {
        let a = Udp::start("127.0.0.1:0", Mode::Silent).await;
        let b = Udp::start("127.0.0.1:0", Mode::Silent).await;
        let c = Udp::start("127.0.0.1:0", Mode::Silent).await;
        // The third first try lands at about 2.4 s, after the 2 s retransmit
        // floor, so without the rule the first address is repeated first.
        let mut config = cfg(vec![], vec![a.addr, b.addr, c.addr]);
        config.upstream_hedge_ms = 1200;
        config.upstream_timeout_seconds = 4;
        let pool = UpstreamPool::new(&config).unwrap();
        assert!(pool.exchange(&query("rotation.test.", 10), 10).await.is_none());
        let first = [&a, &b, &c].map(|server| server.stamps.lock().unwrap()[0]);
        let repeats = a.stamps.lock().unwrap().clone();
        assert!(repeats.len() >= 2, "the first address is retransmitted after the floor");
        assert!(first[0] < first[1] && first[1] < first[2], "first tries are paced by the hedge");
        assert!(first[2] < repeats[1], "the third address is tried before the first one is repeated");
    }

    /// RFC 9520 section 3.2: different failure types may be cached for
    /// different times. A SERVFAIL for a name is held 5 s; an upstream whose
    /// probes failed three times is held 30 s.
    #[tokio::test]
    async fn rfc9520_s455_failure_types_are_cached_for_different_times() {
        let doh = Doh::start(|raw| {
            if is_probe(raw) {
                Resp::status(500)
            } else {
                Resp::dns(answer(raw, ResponseCode::ServFail, &[]))
            }
        })
        .await;
        let pool = UpstreamPool::new(&cfg(vec![doh.url.clone()], vec![])).unwrap();
        assert!(pool.exchange(&query("name.test.", 1), 1).await.is_none());
        let name_window = {
            let failures = pool.failures.lock().unwrap();
            assert_eq!(failures.map.len(), 1);
            failures.map.values().next().unwrap().1
        };
        for _ in 0..3 {
            pool.probe_all().await;
        }
        let open_until = pool.upstreams[0].state().open_until.expect("circuit open");
        let upstream_window = open_until.saturating_duration_since(Instant::now());
        assert_eq!(name_window, Duration::from_secs(5));
        assert!(
            upstream_window > Duration::from_secs(25) && upstream_window <= Duration::from_secs(30),
            "{upstream_window:?}"
        );
        assert!(upstream_window > name_window, "the two failure types are cached for different times");
    }

    /// RFC 1035 section 7.2: the timeout for a transmission is "50-100% greater
    /// than the average predicted value". With a smoothed RTT of 30 ms the
    /// next transmission leaves 60 ms after the first (inside the 40-80 ms
    /// clamp), which is 1.5 to 2 times the average.
    #[tokio::test]
    async fn rfc1035_s2541_next_transmission_waits_one_and_a_half_to_two_times_the_average() {
        let stamps: Arc<Mutex<Vec<(u8, Instant)>>> = Arc::new(Mutex::new(Vec::new()));
        let mut mocks = Vec::new();
        for who in [1u8, 2] {
            let stamps = stamps.clone();
            mocks.push(
                Doh::start(move |raw| {
                    stamps.lock().unwrap().push((who, Instant::now()));
                    let resp = Resp::dns(ok(raw, who));
                    if who == 1 {
                        resp.delayed(Duration::from_millis(800))
                    } else {
                        resp
                    }
                })
                .await,
            );
        }
        let mut c = cfg(mocks.iter().map(|m| m.url.clone()).collect(), vec![]);
        c.upstream_hedge_ms = 0;
        c.upstream_timeout_seconds = 3;
        let pool = UpstreamPool::new(&c).unwrap();
        pool.upstreams[0].state().ewma_us = 30_000;
        pool.upstreams[1].state().ewma_us = 500_000;
        let got = pool.exchange(&query("rto.test.", 1), 1).await.expect("answer");
        assert_eq!(last_octet(&got), 2, "the second transmission answered");
        let stamps = stamps.lock().unwrap();
        assert_eq!((stamps[0].0, stamps[1].0), (1, 2), "the lower smoothed RTT is asked first");
        let gap = stamps[1].1.saturating_duration_since(stamps[0].1);
        assert!(
            (Duration::from_millis(45)..=Duration::from_millis(120)).contains(&gap),
            "second transmission {gap:?} after the first, average is 30 ms"
        );
    }
}
