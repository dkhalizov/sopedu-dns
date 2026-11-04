//! Test-only instrumentation adapter for an external black-box conformance
//! test driver (control protocol v1). Compiled only with the
//! `conformance-adapter` cargo feature and started with `--conformance-adapter`.
//!
//! The adapter hosts the real server (`run`) inside this process on a
//! current-thread runtime with tokio's paused clock. Nothing here answers a
//! query, caches, filters or retries: it starts the production server, moves
//! the virtual clock, and reads counters the production code maintains.
//!
//! The clock never advances by itself. A permanently parked blocking task
//! inhibits tokio's auto-advance, so timers fire only when `advance` moves
//! the clock; real socket I/O keeps flowing in real time. Consequently a
//! check that waits for a real upstream timeout without calling `advance`
//! cannot finish in this mode: run those with `--conformance-adapter=wallclock`
//! (the clock follows real time, `clock` is not declared, every other
//! control and observer is unchanged) or with `--binary`.
//!
//! Profile translation: the driver key `stale_mode` becomes the product's
//! `serve_stale_client_timeout_ms` (see `Adapter::profile_config`). Every other
//! key is passed through untouched; an unknown one is reported as `unsupported`,
//! never dropped.

use super::*;
use serde_json::{json, Map, Value};
use std::{io::BufRead, process::Command};
use tokio::sync::{mpsc, Notify};

/// What `run` hands over once the server exists (see the `attach` call there).
pub struct Handles {
    pub server: Arc<Server>,
    pub udp_permits: Arc<Semaphore>,
    pub udp_max: usize,
    pub tcp_permits: Arc<Semaphore>,
    pub tcp_max: usize,
}

static HANDLES: Mutex<Option<Handles>> = Mutex::new(None);
static SHUTDOWN: Notify = Notify::const_new();

/// UDP datagram lifecycle at the production boundaries: ingress, response
/// admission to a send, and completion once a datagram's work is discarded or
/// committed to a response. Plain monotonic counters, nothing inferred.
#[derive(Default)]
pub struct Packets {
    received: AtomicU64,
    attempts: AtomicU64,
    completed: AtomicU64,
}

impl Packets {
    pub fn received(&self) {
        self.received.fetch_add(1, Ordering::SeqCst);
    }

    pub fn attempted(&self) {
        self.attempts.fetch_add(1, Ordering::SeqCst);
    }

    pub fn completed(&self) {
        self.completed.fetch_add(1, Ordering::SeqCst);
    }
}

pub fn attach(handles: Handles) {
    *HANDLES.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(handles);
}

/// Resolves when the adapter asks the production loop to take its graceful
/// shutdown path (the same branch SIGTERM takes).
pub async fn shutdown_requested() {
    SHUTDOWN.notified().await;
}

/// `unsupported` is BLOCKED, `error` an infrastructure ERROR.
enum Failure {
    Unsupported(String),
    Error(String),
}

type Rpc = std::result::Result<Value, Failure>;

fn unsupported<T: Into<String>>(reason: T) -> Failure {
    Failure::Unsupported(reason.into())
}

fn error<T: ToString>(reason: T) -> Failure {
    Failure::Error(reason.to_string())
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Per-process scratch directory (config, fixture roots, persisted state).
static WORKDIR: Mutex<Option<std::path::PathBuf>> = Mutex::new(None);

fn finish() -> ! {
    if let Some(dir) = lock(&WORKDIR).take() {
        let _ = std::fs::remove_dir_all(dir);
    }
    std::process::exit(0)
}

/// False in `--conformance-adapter=wallclock` mode.
static VIRTUAL_CLOCK: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

pub fn main(wallclock: bool) -> Result<()> {
    VIRTUAL_CLOCK.store(!wallclock, Ordering::SeqCst);
    let (lines, mut inbox) = mpsc::unbounded_channel::<String>();
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines() {
            let Ok(line) = line else { break };
            if lines.send(line).is_err() {
                break;
            }
        }
    });
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().start_paused(!wallclock).build()?;
    runtime.block_on(async move {
        if !wallclock {
            // Keeps `auto_advance_inhibit_count` above zero for the whole process.
            tokio::task::spawn_blocking(|| loop {
                std::thread::park();
            });
        }
        // An early SIGHUP must reload, never take the default disposition.
        #[cfg(unix)]
        let _hup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
        // The driver ends a child with SIGTERM. Take the production shutdown
        // path and release the server, so sockets close as they do for the
        // plain binary, but never outlive the driver's short grace period.
        #[cfg(unix)]
        {
            let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
            tokio::spawn(async move {
                term.recv().await;
                SHUTDOWN.notify_one();
                for round in 0..40u32 {
                    real_sleep(Duration::from_millis(5)).await;
                    if round % 8 == 7 {
                        step(Duration::from_secs(1)).await;
                    }
                }
                *lock(&HANDLES) = None;
                real_sleep(Duration::from_millis(20)).await;
                finish();
            });
        }
        let mut adapter = Adapter::new();
        while let Some(line) = inbox.recv().await {
            let request: Value = match serde_json::from_str(&line) {
                Ok(value) => value,
                Err(error) => {
                    eprintln!("adapter: bad request: {error}");
                    continue;
                }
            };
            let id = request["id"].clone();
            let params = request.get("params").cloned().unwrap_or_else(|| json!({}));
            let method = request["method"].as_str().unwrap_or_default().to_string();
            let reply = match adapter.call(&method, &params).await {
                Ok(result) => json!({"id": id, "result": result}),
                Err(Failure::Unsupported(reason)) => json!({"id": id, "unsupported": reason}),
                Err(Failure::Error(reason)) => json!({"id": id, "error": reason}),
            };
            println!("{reply}");
        }
        finish();
    })
}

/// Real-time pause that still lets the runtime poll sockets and tasks.
async fn real_sleep(duration: Duration) {
    let _ = tokio::task::spawn_blocking(move || std::thread::sleep(duration)).await;
}

/// Moves the virtual clock internally (startup and drain only); a no-op when
/// the clock already follows real time.
async fn step(duration: Duration) {
    if VIRTUAL_CLOCK.load(Ordering::SeqCst) {
        tokio::time::advance(duration).await;
    }
}

/// Lets work made ready by the last control action (and the real socket I/O
/// it triggers on loopback) run to a resting point.
async fn settle() {
    for _ in 0..4 {
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
        real_sleep(Duration::from_millis(3)).await;
    }
}

/// Insertion counters survive a generation swap: the cache and pool are rebuilt
/// by a reload that changes their settings, which would otherwise reset them.
#[derive(Default)]
struct Carry {
    cache_ptr: usize,
    cache_last: u64,
    cache_carry: u64,
    pool_ptr: usize,
    failure_last: (u64, u64),
    failure_carry: (u64, u64),
}

struct Adapter {
    dir: Option<std::path::PathBuf>,
    config: Map<String, Value>,
    task: Option<tokio::task::JoinHandle<Result<()>>>,
    base: Option<Instant>,
    carry: Carry,
}

impl Adapter {
    fn new() -> Self {
        Self { dir: None, config: Map::new(), task: None, base: None, carry: Carry::default() }
    }

    async fn call(&mut self, method: &str, params: &Value) -> Rpc {
        match method {
            "hello" => self.hello(),
            "start" => self.start(params).await,
            "alive" => Ok(json!({"alive": self.alive()})),
            "shutdown" => self.shutdown(params).await,
            "advance" => self.advance(params).await,
            "snapshot" => self.snapshot().map(Value::Object),
            "wait_state" => self.wait_state(params).await,
            "evict_cache" => self.evict(params),
            "request_state" => self.request_state(params).await,
            "refresh_cache" => self.refresh_cache(params).await,
            "configure_limits" => self.configure_limits(params),
            "inject" => Self::inject(params),
            "reload" => self.reload(params).await,
            "restart" => self.restart().await,
            "refresh_lists" => self.refresh_lists().await,
            other => Err(unsupported(format!("{other}: not provided by this adapter"))),
        }
    }

    fn hello(&self) -> Rpc {
        let exe = std::env::current_exe().map_err(error)?;
        let digest = ["shasum -a 256", "sha256sum"].iter().find_map(|tool| {
            let mut parts = tool.split(' ');
            let output = Command::new(parts.next()?).args(parts).arg(&exe).output().ok()?;
            let text = String::from_utf8(output.stdout).ok()?;
            let digest = text.split_whitespace().next()?.to_string();
            (digest.len() == 64).then_some(digest)
        });
        let Some(sha256) = digest else { return Err(error("neither shasum nor sha256sum could hash the target")) };
        let mut capabilities = vec![
            "wire",
            "tcp",
            "parallel",
            "snapshot",
            "state-events",
            "reload",
            "restart",
            "refresh-lists",
            "local-tls-trust",
            "cache-insertion-observer",
            "cache-rr-insertion-observer",
            "failure-cache-stats",
            "failure-cache-limits",
            "evict-cache-control",
            "upstream-deadline-observer",
            "rng",
            "packet-lifecycle",
            "request-upstream-observer",
            "refresh-cache-control",
        ];
        if VIRTUAL_CLOCK.load(Ordering::SeqCst) {
            capabilities.push("clock");
        }
        Ok(json!({
            "protocol": 1,
            "capabilities": capabilities,
            "target": {"sha256": sha256, "build": "sopedu-dns --features conformance-adapter"},
        }))
    }

    fn handles<R>(&self, f: impl FnOnce(&Handles) -> R) -> std::result::Result<R, Failure> {
        lock(&HANDLES).as_ref().map(f).ok_or_else(|| error("target is not running"))
    }

    fn alive(&self) -> bool {
        self.task.as_ref().is_some_and(|task| !task.is_finished())
    }

    fn config_path(&self) -> std::result::Result<std::path::PathBuf, Failure> {
        self.dir.as_ref().map(|dir| dir.join("config.toml")).ok_or_else(|| error("target was never started"))
    }

    /// The driver profile names `stale_mode`; the product expresses the same
    /// choice through `serve_stale_client_timeout_ms` (0 answers stale at once
    /// and refreshes in the background; a positive value waits that long for
    /// the refresh first). The mapping is a rename of an existing option, not
    /// emulated behavior. `refresh_first` without an explicit timer uses the
    /// RFC 8767 suggestion of 1800 ms. Other driver-only keys are passed
    /// through, so a missing product knob is reported as unsupported.
    fn profile_config(&self) -> std::result::Result<Map<String, Value>, Failure> {
        let mut config = self.config.clone();
        match config.remove("stale_mode").as_ref().and_then(Value::as_str) {
            None => {}
            Some("optimistic") => {
                config.insert("serve_stale_client_timeout_ms".into(), json!(0));
            }
            Some("refresh_first") => {
                config.entry("serve_stale_client_timeout_ms").or_insert(json!(1800));
            }
            Some(other) => return Err(unsupported(format!("stale_mode {other:?} is not a profile this build maps"))),
        }
        Ok(config)
    }

    fn write_config(&self, raw: Option<&str>) -> std::result::Result<(), Failure> {
        let text = match raw {
            Some(raw) => raw.to_string(),
            None => {
                let value = toml::Value::try_from(self.profile_config()?).map_err(error)?;
                toml::to_string(&value).map_err(error)?
            }
        };
        std::fs::write(self.config_path()?, text).map_err(error)
    }

    async fn start(&mut self, params: &Value) -> Rpc {
        if self.alive() {
            return Err(error("target already started"));
        }
        self.config = params["config"].as_object().cloned().unwrap_or_default();
        if self.dir.is_none() {
            let dir = std::env::temp_dir().join(format!("sopedu-adapter-{}", std::process::id()));
            std::fs::create_dir_all(&dir).map_err(error)?;
            std::env::set_current_dir(&dir).map_err(error)?;
            *lock(&WORKDIR) = Some(dir.clone());
            self.dir = Some(dir);
            let roots: Vec<&str> =
                params["trusted_cas"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
            if !roots.is_empty() {
                // Local fixture roots only; the HTTP client keeps verifying
                // hostnames and chains against them.
                let pem = self.dir.as_ref().map(|dir| dir.join("fixture-roots.pem")).ok_or_else(|| error("no dir"))?;
                std::fs::write(&pem, roots.join("\n")).map_err(error)?;
                std::env::set_var("SSL_CERT_FILE", &pem);
                std::env::set_var("SSL_CERT_DIR", "");
            }
        }
        let listen = self.config.get("listen").and_then(Value::as_str).unwrap_or_default().to_string();
        self.write_config(None)?;
        self.launch(&listen).await?;
        Ok(json!({"listen": listen}))
    }

    /// Starts the production `run` and waits until it reports readiness.
    async fn launch(&mut self, listen: &str) -> std::result::Result<(), Failure> {
        let path = self.config_path()?;
        let cfg = Config::load(&path).map_err(|message| {
            // An unknown key is a profile knob this build lacks: BLOCKED, not a
            // protocol verdict.
            if message.contains("unknown field") || message.contains("unknown variant") {
                unsupported(format!("target configuration lacks profile knob: {message}"))
            } else {
                error(format!("target exited at startup: {message}"))
            }
        })?;
        *lock(&HANDLES) = None;
        // Drop a permit stored by an earlier shutdown so it cannot end this run.
        let _ = timeout(Duration::ZERO, SHUTDOWN.notified()).await;
        let task = tokio::spawn(run(cfg, path));
        let mut waited = 0u32;
        let mut advanced = false;
        loop {
            if task.is_finished() {
                return Err(error(match task.await {
                    Ok(Ok(())) => "target exited at startup".to_string(),
                    Ok(Err(failure)) => format!("target exited at startup: {failure}"),
                    Err(failure) => format!("target panicked at startup: {failure}"),
                }));
            }
            if self.handles(|handles| handles.server.ready.load(Ordering::SeqCst)).unwrap_or(false) {
                break;
            }
            real_sleep(Duration::from_millis(2)).await;
            waited += 1;
            // The first-download wait is a production timer on the virtual
            // clock; step over it once instead of leaving startup pending.
            if waited == 100 && !advanced {
                advanced = true;
                step(STARTUP_LIST_WAIT + Duration::from_millis(1)).await;
            }
            if waited > 3000 {
                task.abort();
                return Err(error(format!("target did not become ready on {listen}")));
            }
        }
        self.task = Some(task);
        self.base = Some(Instant::now());
        settle().await;
        Ok(())
    }

    async fn shutdown(&mut self, params: &Value) -> Rpc {
        let budget = params["timeout"].as_f64().unwrap_or(6.0).clamp(0.1, 7.0);
        let Some(mut task) = self.task.take() else { return Ok(json!({"exit_code": 0})) };
        SHUTDOWN.notify_one();
        let deadline = std::time::Instant::now() + Duration::from_secs_f64(budget);
        let mut rounds = 0u32;
        loop {
            if task.is_finished() {
                *lock(&HANDLES) = None;
                let code = match (&mut task).await {
                    Ok(Ok(())) => 0,
                    _ => 1,
                };
                return Ok(json!({"exit_code": code}));
            }
            if std::time::Instant::now() > deadline {
                task.abort();
                return Err(error("graceful shutdown exceeded its wall budget"));
            }
            real_sleep(Duration::from_millis(5)).await;
            rounds += 1;
            // The drain bound is a virtual timer; let it elapse when the
            // drain is stuck on connections the test left open.
            if rounds.is_multiple_of(40) {
                step(Duration::from_secs(1)).await;
            }
        }
    }

    async fn advance(&mut self, params: &Value) -> Rpc {
        if !VIRTUAL_CLOCK.load(Ordering::SeqCst) {
            return Err(unsupported("advance: the wallclock adapter has no injected clock"));
        }
        let ms = params["milliseconds"].as_u64().ok_or_else(|| error("milliseconds must be a nonnegative integer"))?;
        // Timers due at different instants must fire in order, each with the
        // work it triggers (a hedge before the deadline it races), so the
        // clock moves in steps: fine at first, coarse for long jumps whose
        // only effect is expiry.
        let (mut left, mut moved) = (ms, 0u64);
        while left > 0 {
            let width = match moved {
                0..500 => 25,
                500..5000 => 250,
                _ => (left / 20).max(5000),
            };
            let width = width.min(left);
            let started = sopedu_dns::upstream::starts_total();
            tokio::time::advance(Duration::from_millis(width)).await;
            for _ in 0..16 {
                tokio::task::yield_now().await;
            }
            real_sleep(Duration::from_millis(2)).await;
            if sopedu_dns::upstream::starts_total() != started {
                // New upstream I/O began: let its loopback round trip finish.
                settle().await;
            }
            left -= width;
            moved += width;
        }
        tokio::time::advance(Duration::ZERO).await;
        settle().await;
        Ok(json!({}))
    }

    /// Reads the production counters. A cache or pool replaced by a reload
    /// folds its totals into the carry first, so the totals stay monotonic.
    fn snapshot(&mut self) -> std::result::Result<Map<String, Value>, Failure> {
        let (server, udp_free, udp_max, tcp_free, tcp_max) = self.handles(|handles| {
            (
                handles.server.clone(),
                handles.udp_permits.available_permits(),
                handles.udp_max,
                handles.tcp_permits.available_permits(),
                handles.tcp_max,
            )
        })?;
        let runtime = server.runtime();
        let (entries, bytes, insertions, per_type) = runtime.cache.observe();
        let stats = runtime.upstreams.failure_stats();
        let carry = &mut self.carry;
        let cache_ptr = Arc::as_ptr(&runtime.cache) as usize;
        if carry.cache_ptr != cache_ptr {
            carry.cache_carry += carry.cache_last;
            carry.cache_ptr = cache_ptr;
        }
        carry.cache_last = insertions;
        let pool_ptr = Arc::as_ptr(&runtime.upstreams) as usize;
        if carry.pool_ptr != pool_ptr {
            carry.failure_carry.0 += carry.failure_last.0;
            carry.failure_carry.1 += carry.failure_last.1;
            carry.pool_ptr = pool_ptr;
        }
        carry.failure_last = (stats.insertions, stats.expired);
        let now_ms = self.base.map_or(0, |base| Instant::now().duration_since(base).as_millis() as u64);
        let upstream_free = runtime.upstreams.inflight_available();
        let upstream_max = runtime.cfg.upstream_inflight_max.max(1);
        let mut state = Map::new();
        let mut put = |key: &str, value: u64| {
            state.insert(key.to_string(), json!(value));
        };
        put("now_ms", now_ms);
        put("tcp_connections", tcp_max.saturating_sub(tcp_free) as u64);
        put("udp_inflight", udp_max.saturating_sub(udp_free) as u64);
        put("upstream_inflight", upstream_max.saturating_sub(upstream_free) as u64);
        put("upstream_deadlines_armed", runtime.upstreams.deadlines_armed() as u64);
        put("singleflight_keys", runtime.inflight.len() as u64);
        put("singleflight_waiters", runtime.inflight.waiters() as u64);
        put("cache_entries", entries);
        put("cache_bytes", bytes);
        put("response_cache_insertions_total", carry.cache_carry + insertions);
        put("failure_cache_entries", stats.entries as u64);
        put("failure_cache_bytes", stats.bytes as u64);
        put("failure_cache_entries_limit", stats.entries_limit as u64);
        put("failure_cache_bytes_limit", stats.bytes_limit as u64);
        put("failure_cache_insertions_total", carry.failure_carry.0 + stats.insertions);
        put("failure_cache_expired_total", carry.failure_carry.1 + stats.expired);
        put("failure_ttl_ms", stats.ttl.as_millis() as u64);
        // The forwarder has no request queue: excess UDP work is dropped at
        // `udp_inflight_max`, never parked.
        put("udp_datagrams_received_total", server.packets.received.load(Ordering::SeqCst));
        put("udp_datagrams_completed_total", server.packets.completed.load(Ordering::SeqCst));
        put("udp_response_attempts_total", server.packets.attempts.load(Ordering::SeqCst));
        {
            use sopedu_dns::lists::observed;
            put("blocklist_rejected_oversize", observed::REJECTED_OVERSIZE.load(Ordering::SeqCst));
            put("blocklist_buffer_peak_bytes", observed::PEAK_BYTES.load(Ordering::SeqCst));
            put("blocklist_buffer_limit_bytes", observed::LIMIT_BYTES.load(Ordering::SeqCst));
        }
        put("queued_requests", 0);
        put("queued_requests_limit", 0);
        // "1" (A) and "250" (TSIG) are always present: the observer counts
        // them at the insertion call, so an absent one is a true zero.
        let mut rr: Map<String, Value> = [1u16, 250].iter().map(|t| (t.to_string(), json!(0))).collect();
        for (rtype, total) in per_type {
            rr.insert(rtype.to_string(), json!(total));
        }
        state.insert("response_cache_rr_insertions_total".into(), Value::Object(rr));
        Ok(state)
    }

    async fn wait_state(&mut self, params: &Value) -> Rpc {
        let predicates: Vec<(String, String, i64)> = params["predicates"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|p| Some((p["field"].as_str()?.into(), p["op"].as_str()?.into(), p["value"].as_i64()?)))
            .collect();
        if predicates.is_empty() {
            return Err(error("wait_state needs at least one predicate"));
        }
        let wall = std::time::Instant::now() + Duration::from_secs(7);
        loop {
            let state = self.snapshot()?;
            let mut satisfied = true;
            for (field, op, wanted) in &predicates {
                let Some(actual) = state.get(field).and_then(Value::as_i64) else {
                    return Err(unsupported(format!("wait_state field {field} is not observable")));
                };
                satisfied &= match op.as_str() {
                    "eq" => actual == *wanted,
                    "gte" => actual >= *wanted,
                    other => return Err(error(format!("unknown predicate op {other}"))),
                };
            }
            if satisfied {
                return Ok(Value::Object(state));
            }
            if std::time::Instant::now() > wall {
                return Err(error("wait_state predicate was not reached within the wall budget"));
            }
            real_sleep(Duration::from_millis(2)).await;
            tokio::task::yield_now().await;
        }
    }

    fn unhex(query_hex: &str) -> std::result::Result<Vec<u8>, Failure> {
        (0..query_hex.len() / 2)
            .map(|i| u8::from_str_radix(&query_hex[2 * i..2 * i + 2], 16))
            .collect::<std::result::Result<_, _>>()
            .map_err(error)
    }

    fn canonical(query_hex: &str) -> std::result::Result<Vec<u8>, Failure> {
        let raw = Self::unhex(query_hex)?;
        let view = wire::parse_query(&raw).ok_or_else(|| error("query is not a DNS request"))?;
        let mut key = [0u8; wire::MIN_CANONICAL_BUFFER];
        let len = wire::canonical_key(&view, &mut key).ok_or_else(|| error("query has no canonical cache key"))?;
        Ok(key[..len].to_vec())
    }

    /// Waits for the request's own handling to finish, then reports what its
    /// causal tree started. A request the server never saw is an error, not a
    /// zero.
    async fn request_state(&mut self, params: &Value) -> Rpc {
        let raw = Self::unhex(params["query"].as_str().unwrap_or_default())?;
        let wall = std::time::Instant::now() + Duration::from_secs(7);
        loop {
            let Some((complete, starts, pending)) = sopedu_dns::upstream::request_state(&raw) else {
                return Err(error("the target never observed this request"));
            };
            if complete {
                return Ok(json!({"complete": true, "upstream_starts": starts, "derived_pending": pending}));
            }
            if std::time::Instant::now() > wall {
                return Err(error("request did not complete within the wall budget"));
            }
            real_sleep(Duration::from_millis(2)).await;
            tokio::task::yield_now().await;
        }
    }

    /// One production refresh of an existing key, through the same
    /// single-flight and relay path as a background refresh, awaited. The old
    /// entry is left in place for the production insert to replace or keep.
    async fn refresh_cache(&mut self, params: &Value) -> Rpc {
        let raw = Self::unhex(params["query"].as_str().unwrap_or_default())?;
        let view = wire::parse_query(&raw).ok_or_else(|| error("query is not a DNS request"))?;
        let mut key = [0u8; wire::MIN_CANONICAL_BUFFER];
        let len = wire::canonical_key(&view, &mut key).ok_or_else(|| error("query has no canonical cache key"))?;
        let server = self.handles(|handles| handles.server.clone())?;
        let runtime = server.runtime();
        if !inflight::coalescible(&view) {
            return Err(unsupported("refresh_cache: query is not a coalescible cache key"));
        }
        if let inflight::Role::Leader(guard) = runtime.inflight.join(&key[..len]) {
            let relayed = runtime.upstream_relay(&raw, view.id, DnssecContext::new(&view), Some(&key[..len])).await;
            guard.complete(relayed.as_deref().map(Arc::from));
        }
        settle().await;
        Ok(json!({"completed": true}))
    }

    fn evict(&mut self, params: &Value) -> Rpc {
        let key = Self::canonical(params["query"].as_str().unwrap_or_default())?;
        let only_stale = params["only"].as_str() == Some("stale");
        let server = self.handles(|handles| handles.server.clone())?;
        let evicted = server.runtime().cache.evict(&key, only_stale);
        Ok(json!({"evicted": evicted}))
    }

    fn configure_limits(&mut self, params: &Value) -> Rpc {
        let entries = params["failure_cache_entries_limit"].as_u64().ok_or_else(|| error("entries limit missing"))?;
        let bytes = params["failure_cache_bytes_limit"].as_u64().ok_or_else(|| error("bytes limit missing"))?;
        let server = self.handles(|handles| handles.server.clone())?;
        server.runtime().upstreams.set_failure_limits(entries as usize, bytes as usize);
        Ok(json!({"applied": true}))
    }

    fn inject(params: &Value) -> Rpc {
        let Some(ids) = params["rng_ids"].as_array() else {
            return Err(unsupported("inject: only rng_ids is provided by this adapter"));
        };
        let ids: Vec<u16> = ids.iter().filter_map(|id| id.as_u64().and_then(|id| u16::try_from(id).ok())).collect();
        sopedu_dns::upstream::inject_ids(&ids);
        Ok(json!({"queued": ids.len()}))
    }

    async fn reload(&mut self, params: &Value) -> Rpc {
        use sopedu_dns::log::{RELOADED, RELOAD_FAILED};
        if let Some(config) = params["config"].as_object() {
            self.config.extend(config.clone());
        }
        // Totals are carried across a generation swap by `snapshot`.
        let _ = self.snapshot();
        let before = (RELOADED.load(Ordering::SeqCst), RELOAD_FAILED.load(Ordering::SeqCst));
        self.write_config(params["raw_config"].as_str())?;
        let pid = std::process::id().to_string();
        let mut outcome = "unobserved";
        'attempts: for _ in 0..4 {
            // Production path: SIGHUP into `reload_loop`. Resent in case the
            // loop had not registered its handler yet.
            Command::new("kill").args(["-HUP", &pid]).status().map_err(error)?;
            for _ in 0..150 {
                let now = (RELOADED.load(Ordering::SeqCst), RELOAD_FAILED.load(Ordering::SeqCst));
                if now.0 > before.0 {
                    outcome = "reloaded";
                    break 'attempts;
                }
                if now.1 > before.1 {
                    outcome = "failed";
                    break 'attempts;
                }
                real_sleep(Duration::from_millis(2)).await;
                tokio::task::yield_now().await;
            }
        }
        settle().await;
        let _ = self.snapshot();
        Ok(json!({"alive": self.alive(), "reload": outcome}))
    }

    async fn restart(&mut self) -> Rpc {
        self.shutdown(&json!({"timeout": 6})).await?;
        let listen = self.config.get("listen").and_then(Value::as_str).unwrap_or_default().to_string();
        self.write_config(None)?;
        self.launch(&listen).await?;
        Ok(json!({"alive": self.alive()}))
    }

    async fn refresh_lists(&mut self) -> Rpc {
        let server = self.handles(|handles| handles.server.clone())?;
        let runtime = server.runtime();
        let outcome = server.refresh_lists(&runtime).await;
        settle().await;
        Ok(json!({"completed": true, "error": outcome.err()}))
    }
}
