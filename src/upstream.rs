//! Hedged, health-aware DoH pool with a secure plaintext fallback.
//!
//! One query goes to the best upstream first; the next is launched after the
//! hedge delay, or immediately when the previous attempt fails. The first
//! terminal answer wins and cancels the losers. DoH uses ID 0 over one warm
//! HTTP/2 client; the UDP/TCP fallback uses a fresh socket, a fresh random ID
//! and (by default) 0x20 question-case randomisation.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::opt::EdnsOption;
use hickory_proto::rr::{Name, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{Notify, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::{timeout_at, Instant};

use crate::config::{Config, UpstreamStrategy};
use crate::wire::{self, QueryView};

const MAX_DNS_MESSAGE: usize = u16::MAX as usize;
const PROBE_INTERVAL: Duration = Duration::from_secs(30);
/// Suppress matching outbound work for 5 s after a failed resolution, backing
/// off to 30 s on repeated failures (RFC 9520 §3.2).
const FAILURE_WINDOW: Duration = Duration::from_secs(5);
const FAILURE_WINDOW_MAX: Duration = Duration::from_secs(30);
/// When a resolution last failed and how long that suppresses repeats.
type FailureMark = (Instant, Duration);
const FAILURE_CAPACITY: usize = 4096;
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
    /// byte bounds hold. `false` rejects a key that could never fit.
    /// Known limit: the oldest-first scan is O(n) at the 4096-entry bound; a
    /// queue would matter only at much larger bounds.
    fn insert(&mut self, key: Box<[u8]>, mark: FailureMark, capacity: usize, byte_limit: usize) -> bool {
        let need = charge(&key);
        if need > byte_limit {
            return false;
        }
        self.remove(&key);
        while !self.map.is_empty() && (self.map.len() >= capacity || self.bytes + need > byte_limit) {
            let Some(oldest) = self.map.iter().min_by_key(|(_, (at, _))| *at).map(|(key, _)| key.clone()) else {
                break;
            };
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
}

impl FallbackState {
    fn record(state: &Mutex<FallbackState>, result: &Result<PlainReply, Fail>) {
        let mut state = state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        match result {
            Ok(_) => *state = FallbackState::default(),
            Err(Fail::Unreachable) => {
                state.failures = state.failures.saturating_add(1);
                let backoff = FALLBACK_BACKOFF.saturating_mul(1 << state.failures.saturating_sub(1).min(4));
                state.skip_until = Instant::now().checked_add(backoff.min(FALLBACK_BACKOFF_MAX));
            }
            Err(_) => {}
        }
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
    trust_plain: bool,
    inflight: Semaphore,
    failures: Mutex<FailureMap>,
    /// Per fallback address: has it ever echoed our randomised question case?
    /// Once true a case-only mismatch from it is forged, never a retry cue.
    preserves_case: Vec<Arc<AtomicBool>>,
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
                // environment proxy. Redirects are bounded and may not downgrade
                // to plaintext, so a POST body is never replayed over HTTP.
                .no_proxy()
                .redirect(redirect_policy())
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
            trust_plain: cfg.trust_plain_upstreams,
            inflight: Semaphore::new(cfg.upstream_inflight_max.max(1)),
            failures: Mutex::new(FailureMap::default()),
            preserves_case: cfg.fallback.iter().map(|_| Arc::new(AtomicBool::new(false))).collect(),
            probe_stop: Arc::new(Notify::new()),
            #[cfg(feature = "conformance-adapter")]
            observer: observer::Failures::default(),
        };
        Ok(pool)
    }

    /// Resolves one raw client query. `None` is the SERVFAIL path: every
    /// attempt failed or the in-flight bound was hit.
    pub async fn exchange(&self, raw_query: &[u8], client_id: u16) -> Option<UpstreamAnswer> {
        self.exchange_from(raw_query, client_id, false).await
    }

    /// [`exchange`](Self::exchange) for a client that may have used TCP:
    /// plain upstreams then see the query over TCP first (RFC 5625 §4.2).
    pub async fn exchange_from(&self, raw_query: &[u8], client_id: u16, client_tcp: bool) -> Option<UpstreamAnswer> {
        wire::parse_query(raw_query)?;
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
        if shared && self.failure_is_recent(&key) {
            return None;
        }
        let _permit = self.inflight.try_acquire().ok()?;
        let deadline = Instant::now().checked_add(self.timeout)?;
        #[cfg(feature = "conformance-adapter")]
        let _armed = self.observer.arm();
        match self.exchange_inner(raw_query, &view, deadline, client_tcp).await {
            Ok(answer) => {
                if answer.terminal {
                    self.clear_failure(&key);
                } else if shared && answer.message.metadata.response_code == ResponseCode::ServFail {
                    // A relayed DNSSEC SERVFAIL is still a failed resolution for
                    // failure suppression.
                    self.mark_failure(key);
                }
                Some(answer)
            }
            // Our own socket trouble, or a query that was never sent, is no
            // evidence about the question.
            Err(Fail::Local) => None,
            Err(Fail::Remote | Fail::Unreachable) => {
                if shared {
                    self.mark_failure(key);
                }
                None
            }
        }
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
    ) -> Result<UpstreamAnswer, Fail> {
        let order = self.selection();
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
        let mut reached =
            self.upstreams.iter().any(|upstream| upstream.is_blocked(now) && !upstream.is_unreachable(now));

        while launched < order.len() || !tasks.is_empty() {
            if launched < order.len() && Instant::now() >= next_launch {
                let upstream = order[launched].clone();
                launched += 1;
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
                    let result = doh_exchange(&http, &upstream, &query, deadline, false).await;
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
                        Some(Ok((index, Ok(reply)))) if reply.rcode_failure => {
                            reached = true;
                            // A DNSSEC failure from a validating upstream is
                            // final and relayed: asking another resolver (or
                            // plaintext) would bypass its validation.
                            if dnssec_failure(&reply.message) {
                                tasks.abort_all();
                                return Ok(self.finish(reply.raw, reply.message, Some(index), reply.age, false, view.id));
                            }
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
        let mut tasks = tokio::task::JoinSet::new();
        let invalid = Arc::new(Notify::new());
        let mut launched = 0usize;
        let mut next_launch = Instant::now();
        let (mut saw_local, mut saw_remote) = (false, false);
        while launched < order.len() || !tasks.is_empty() {
            if launched < order.len() && Instant::now() >= next_launch {
                let index = order[launched];
                let addr = self.fallback[index];
                let preserves_case = self.preserves_case[index].clone();
                launched += 1;
                let (query, randomize) = (raw.to_vec(), self.upstream_0x20);
                // Scrub plaintext replies unless the operator opted in to
                // trusting plain servers.
                let scrub = !self.trust_plain;
                let invalid = invalid.clone();
                let health = self.fallback_state[index].clone();
                let attempt = async move {
                    let result =
                        plain_exchange(addr, &query, randomize, deadline, client_tcp, &invalid, &preserves_case, scrub)
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
                        plain_answer_served();
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
        if postponed.is_some() {
            // Only a plain reply can be postponed here: a DoH one returned above.
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
            Some((at, window)) if at.elapsed() < *window + FAILURE_WINDOW_MAX => (*window * 2).min(FAILURE_WINDOW_MAX),
            _ => FAILURE_WINDOW,
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

/// `30s * 2^(failures-3)`, capped at 600 s.
fn cooldown(failures: u32) -> Duration {
    let exponent = failures.saturating_sub(3).min(5);
    Duration::from_secs(30u64.saturating_mul(1u64 << exponent).min(600))
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

/// Five redirects at most, and only to HTTPS: a DoH query body must never be
/// replayed over plaintext after a downgrade.
fn redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        if redirect_target_allowed(attempt.previous(), attempt.url()) {
            attempt.follow()
        } else {
            attempt.stop()
        }
    })
}

/// `previous` starts with the original request, so a length above five has
/// already followed five redirects and rejects the sixth.
fn redirect_target_allowed(previous: &[reqwest::Url], target: &reqwest::Url) -> bool {
    previous.len() <= 5 && target.scheme() == "https"
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
    let request = http
        .post(&upstream.url)
        .header(reqwest::header::CONTENT_TYPE, "application/dns-message")
        .header(reqwest::header::ACCEPT, "application/dns-message")
        .body(sent.clone());
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
    let (body, message) = parse_upstream(body).ok_or("unparseable response")?;
    let body = body.as_slice();
    if unsolicited_co(body, sent) {
        return Err("unsolicited compact answers".into());
    }
    if message.metadata.message_type != MessageType::Response {
        return Err("not a response".into());
    }
    if message.metadata.truncation {
        return Err("truncated response".into());
    }
    if unusable_rcode(message.metadata.response_code) {
        return Ok((body.to_vec(), message, false, true));
    }
    let qname = &sent.qname_lower[..sent.qname_len as usize];
    // A reply whose header and sections contradict each other is invalid.
    let terminal = wire::terminal_answer(body, qname, sent.qtype).ok_or("contradictory response")?;
    Ok((body.to_vec(), message, terminal, false))
}

/// SERVFAIL carrying a DNSSEC validation Extended DNS Error (RFC 8914 §4
/// codes 5 to 12: DNSSEC Indeterminate, DNSSEC Bogus, Signature Expired,
/// Signature Not Yet Valid, DNSKEY Missing, RRSIGs Missing, No Zone Key Bit
/// Set, NSEC Missing). Codes 1 and 2 (unsupported algorithm or digest) mean
/// the zone was treated as insecure, not a validation failure.
fn dnssec_failure(message: &Message) -> bool {
    message.metadata.response_code == ResponseCode::ServFail
        && message.edns.as_ref().is_some_and(|edns| {
            edns.options().options.iter().any(|(_, option)| {
                matches!(option, EdnsOption::Unknown(15, data)
                    if data.len() >= 2 && (5..=12).contains(&u16::from_be_bytes([data[0], data[1]])))
            })
        })
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

/// A fresh UDP socket (new random source port) connected to `addr`. Both
/// steps happen before any packet leaves, so any error here is ours.
async fn connected_socket(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    let local: SocketAddr = if addr.is_ipv4() { "0.0.0.0:0".parse().unwrap() } else { "[::]:0".parse().unwrap() };
    let socket = UdpSocket::bind(local).await?;
    socket.connect(addr).await?;
    Ok(socket)
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
    let (mut raw, message) = match wire::scrub_plain_reply(&relayed) {
        Some(None) => (relayed, message),
        Some(Some(scrubbed)) => match parse_upstream(&scrubbed) {
            Some(parsed) => parsed,
            None => {
                invalid.notify_one();
                return Err(Fail::Remote);
            }
        },
        None => {
            invalid.notify_one();
            return Err(Fail::Remote);
        }
    };
    wire::clear_ad(&mut raw);
    let terminal = classify(&raw)?;
    Ok(PlainReply { raw, message, terminal })
}

#[allow(clippy::too_many_arguments)] // one call site; a struct would only rename them
async fn plain_exchange(
    addr: SocketAddr,
    raw_query: &[u8],
    randomize: bool,
    deadline: Instant,
    tcp_first: bool,
    invalid: &Notify,
    preserves_case: &AtomicBool,
    scrub: bool,
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
        if let Ok(reply) = tcp_exchange(addr, &query, &sent, deadline, invalid, scrub).await {
            return Ok(reply);
        }
    }
    let socket = connected_socket(addr).await.map_err(|_| Fail::Local)?;
    #[cfg(feature = "conformance-adapter")]
    observer::started();
    socket.send(&query).await.map_err(|error| io_fail(&error))?;
    let mut buffer = vec![0u8; MAX_DNS_MESSAGE];
    let mut retry_buffer = Vec::new();
    // The un-randomised retry (a case-normalising upstream) leaves
    // from a fresh socket and ID, so a forged case-only mismatch never
    // exposes the first query's source port. It is sent once, and never to an
    // upstream that has already echoed our case.
    let mut retry: Option<(UdpSocket, Vec<u8>)> = None;
    loop {
        let (received, via_retry) = tokio::select! {
            r = timeout_at(deadline, socket.recv(&mut buffer)) => (r, false),
            r = recv_retry(&retry, &mut retry_buffer, deadline) => (r, true),
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
                if let Ok(fresh) = connected_socket(addr).await {
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
        if case_probe && !via_retry {
            preserves_case.store(true, Ordering::Relaxed);
        }
        // RFC 5452 §9.3: a datagram above the size we advertised
        // (512 without EDNS) is a fragmentation-attack suspect, since the
        // forged tail sits behind the checked ID, port and case. It is never
        // accepted as final: ask again over TCP.
        if received > udp_limit(context) {
            return tcp_exchange(addr, context_query, context, deadline, invalid, scrub).await;
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
            return tcp_exchange(addr, context_query, context, deadline, invalid, scrub).await;
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

/// One query over TCP. The question is compared without regard to case: an
/// off-path attacker cannot inject into a TCP stream, so the 0x20 check (a
/// UDP defence, RFC 5452 §9.1) has nothing to add, and a case-normalising
/// upstream would otherwise hold the attempt until its deadline.
async fn tcp_exchange(
    addr: SocketAddr,
    query: &[u8],
    sent: &QueryView<'_>,
    deadline: Instant,
    invalid: &Notify,
    scrub: bool,
) -> Result<PlainReply, Fail> {
    #[cfg(feature = "conformance-adapter")]
    observer::started();
    let mut stream = match timeout_at(deadline, TcpStream::connect(addr)).await {
        Err(_) => return Err(Fail::Remote),
        Ok(Err(error)) => return Err(io_fail(&error)),
        Ok(Ok(stream)) => stream,
    };
    let len = u16::try_from(query.len()).map_err(|_| "query too large")?;
    let mut framed = Vec::with_capacity(2 + query.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(query);
    match timeout_at(deadline, stream.write_all(&framed)).await {
        Err(_) => return Err(Fail::Remote),
        Ok(Err(error)) => return Err(io_fail(&error)),
        Ok(Ok(())) => {}
    }
    loop {
        let mut len_buf = [0u8; 2];
        match timeout_at(deadline, stream.read_exact(&mut len_buf)).await {
            Err(_) => return Err(Fail::Remote),
            Ok(Err(error)) => return Err(io_fail(&error)),
            Ok(Ok(_)) => {}
        }
        let len = u16::from_be_bytes(len_buf) as usize;
        if len == 0 {
            return Err(Fail::Remote);
        }
        let mut body = vec![0u8; len];
        match timeout_at(deadline, stream.read_exact(&mut body)).await {
            Err(_) => return Err(Fail::Remote),
            Ok(Err(error)) => return Err(io_fail(&error)),
            Ok(Ok(_)) => {}
        }
        if !plain_question_matches(&body, sent, false) {
            if plain_invalid_message(&body, sent) {
                invalid.notify_one();
            }
            continue;
        }
        let Some((relayed, message)) = parse_upstream(&body) else {
            if wire::forbidden_record(&body) {
                return Err(Fail::Remote);
            }
            invalid.notify_one();
            continue;
        };
        if message.metadata.message_type != MessageType::Response {
            continue;
        }
        if message.metadata.truncation {
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
}

/// Test-only observation and control of the production pool (conformance
/// adapter): failure-cache statistics and limits, armed deadlines, in-flight
/// permits and deterministic ID draws.
#[cfg(feature = "conformance-adapter")]
mod observer {
    use super::*;
    use std::{
        collections::VecDeque,
        sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
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
                ttl: failures.map.values().max_by_key(|(at, _)| *at).map_or(FAILURE_WINDOW, |(_, window)| *window),
            }
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

        /// Upstream exchanges holding a pool permit.
        pub fn inflight_available(&self) -> usize {
            self.inflight.available_permits()
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
        requests.get_or_insert_with(HashMap::new).entry(raw.to_vec()).or_default().push(lineage.clone());
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

    pub fn inject_ids(ids: &[u16]) {
        IDS.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).extend(ids);
    }

    pub(super) fn injected_id() -> Option<u16> {
        IDS.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).pop_front()
    }
}

#[cfg(feature = "conformance-adapter")]
pub use observer::{descend, inject_ids, request_state, starts_total, track, track_sync, FailureStats};

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
    /// client's: our payload, DO kept, every other flag zero, no options.
    #[tokio::test]
    async fn the_client_opt_is_never_forwarded() {
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
        assert!(!sent.edns_options && !sent.edns_hop_options, "no client option is forwarded");
        assert_eq!(&seen[0][seen[0].len() - 2..], &[0, 0], "empty OPT RDATA");
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
        assert_eq!(cooldown(7), Duration::from_secs(480));
        assert_eq!(cooldown(8), Duration::from_secs(600));
        assert_eq!(cooldown(100), Duration::from_secs(600));
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

    #[tokio::test]
    async fn a_dnssec_servfail_is_final_and_relayed() {
        // EDE 6 (DNSSEC Bogus, RFC 8914 §4.7) is the validating upstream's verdict.
        let bogus = DohMock::start(Arc::new(|raw: &[u8]| {
            Reply::dns(with_ede(reply_for(raw, ResponseCode::ServFail, vec![], vec![]), 6))
        }))
        .await;
        let second_asked = Arc::new(AtomicUsize::new(0));
        let second = {
            let asked = second_asked.clone();
            DohMock::start(Arc::new(move |raw: &[u8]| {
                asked.fetch_add(1, Ordering::SeqCst);
                Reply::dns(a_reply(raw, [192, 0, 2, 5]))
            }))
            .await
        };
        let plain = UdpMock::start(Arc::new(|raw: &[u8]| Some(a_reply(raw, [192, 0, 2, 66])))).await;
        let mut cfg = config(vec![bogus.url.clone(), second.url.clone()], vec![plain.addr]);
        cfg.upstream_hedge_ms = 1000;
        let pool = Arc::new(UpstreamPool::new(&cfg).unwrap());
        let query = raw_query("bogus.test.", RecordType::A, 4);
        let answer = pool.exchange(&query, 4).await.expect("the SERVFAIL is relayed");
        assert!(!answer.terminal);
        assert_eq!(answer.message.metadata.response_code, ResponseCode::ServFail);
        assert!(dnssec_failure(&answer.message));
        assert_eq!(second_asked.load(Ordering::SeqCst), 0, "no other resolver is asked");
        assert!(plain.seen.lock().unwrap().is_empty());
        // Another EDE (Other, 0) is an ordinary failure.
        let ordinary = with_ede(reply_for(&query, ResponseCode::ServFail, vec![], vec![]), 0);
        let (_, message) = parse_upstream(&ordinary).unwrap();
        assert!(!dnssec_failure(&message));
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
        let mark = (Instant::now(), FAILURE_WINDOW);
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
            assert!(map.insert(big(n), (Instant::now(), FAILURE_WINDOW), 4096, limit));
        }
        assert_eq!(map.map.len(), 2);
        assert!(map.bytes <= limit);
        assert!(!map.insert(vec![0u8; limit].into(), mark, 4096, limit), "a key that cannot fit is rejected");
        assert_eq!(map.map.len(), 2);
        assert_eq!((FAILURE_CAPACITY, FAILURE_BYTES), (4096, 1 << 20));
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
    async fn doh_replies_are_relayed_untouched() {
        // Only plaintext replies are scrubbed.
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
        let query = raw_query("untouched.test.", RecordType::A, 6);
        let answer = pool.exchange(&query, 6).await.unwrap();
        assert_eq!(parsed(&answer.raw).additionals.len(), 1);
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
    async fn redirect_to_plain_http_is_not_followed() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        let location = format!("http://{target_addr}/dns-query");
        let mock = DohMock::start(Arc::new(move |_raw: &[u8]| Reply::redirect(location.clone()))).await;
        let cfg = config(vec![mock.url.clone()], vec![]);
        let pool = Arc::new(UpstreamPool::new(&cfg).unwrap());
        let query = raw_query("redirect.test.", RecordType::A, 0x4444);
        assert!(pool.exchange(&query, 0x4444).await.is_none());
        assert!(!mock.seen.lock().unwrap().is_empty(), "initial request was sent");
        assert!(
            tokio::time::timeout(Duration::from_millis(100), target.accept()).await.is_err(),
            "downgraded redirect target must never receive the query"
        );
    }

    #[test]
    fn redirect_targets_must_be_https_and_are_capped_at_five() {
        let url = |text: &str| reqwest::Url::parse(text).unwrap();
        let https = url("https://resolver.example/dns-query");
        let http = url("http://resolver.example/dns-query");
        assert!(redirect_target_allowed(std::slice::from_ref(&https), &https));
        assert!(!redirect_target_allowed(std::slice::from_ref(&https), &http));
        // `previous` holds the original request, so five entries means five
        // redirects already followed; six is the sixth redirect, stopped.
        assert!(redirect_target_allowed(&vec![https.clone(); 5], &https));
        assert!(!redirect_target_allowed(&vec![https.clone(); 6], &https));
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

    #[test]
    fn every_dnssec_validation_ede_is_a_dnssec_failure() {
        // RFC 8914 §4: 5 DNSSEC Indeterminate through 12 NSEC Missing are
        // validation outcomes; 1 and 2 (unsupported algorithm or digest) mean
        // the zone was treated as insecure and come with an answer.
        let query = raw_query("ede.test.", RecordType::A, 1);
        for code in 0..=30u16 {
            let reply = with_ede(reply_for(&query, ResponseCode::ServFail, vec![], vec![]), code);
            let (_, message) = parse_upstream(&reply).unwrap();
            assert_eq!(dnssec_failure(&message), (5..=12).contains(&code), "EDE {code}");
        }
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
