use cache::Cache;
use hickory_proto::{
    op::{Message, MessageType, OpCode, ResponseCode},
    rr::{
        rdata::{A, AAAA, HINFO, NS, SOA},
        DNSClass, Name, RData, Record, RecordType,
    },
};
use socket2::{Domain, Protocol, SockRef, Socket, Type};
use sopedu_dns::{
    cache,
    clock::Instant,
    config::{self, Config, DnssecMode},
    http, inflight,
    lists::{self, ListManager, SourceStatus},
    log, mac, prewarm, querylog,
    ratelimit::{self, PerClient},
    reverse, rules,
    stats::{self, Outcome},
    stats_store, ui,
    upstream::UpstreamPool,
    wire,
};
use std::{
    error::Error,
    net::{IpAddr, SocketAddr},
    num::NonZeroUsize,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, SystemTime},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{mpsc, watch, Notify, Semaphore},
    task::{JoinHandle, JoinSet},
    time::{sleep, timeout},
};
type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

// Optional global allocator. Neither feature is on by default, so the
// shipped musl binary keeps the platform allocator; the two are exclusive.
#[cfg(all(feature = "mimalloc", feature = "jemalloc"))]
compile_error!("features `mimalloc` and `jemalloc` are mutually exclusive");

// Measurement-only allocator (`dhat-heap`): counts every heap call.
#[cfg(all(feature = "dhat-heap", any(feature = "mimalloc", feature = "jemalloc")))]
compile_error!("feature `dhat-heap` excludes `mimalloc` and `jemalloc`");

#[cfg(feature = "dhat-heap")]
#[global_allocator]
static GLOBAL_ALLOCATOR: dhat::Alloc = dhat::Alloc;

#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL_ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(all(feature = "jemalloc", not(feature = "mimalloc")))]
#[global_allocator]
static GLOBAL_ALLOCATOR: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

/// Linux-only batched UDP receive. The module is not compiled on other
/// targets, so `udp_batch > 0` there only logs a startup warning.
#[cfg(target_os = "linux")]
mod udp_batch;

/// RFC 8085 5.1: on a wildcard bind, reply from the address the client queried
/// (IP_PKTINFO). Linux and macOS; elsewhere a wildcard bind keeps the kernel's
/// choice of source address and logs one startup line.
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod udp_pktinfo;

/// Test-only conformance instrumentation; absent from every default build.
#[cfg(feature = "conformance-adapter")]
mod adapter;

/// Truncated (TC=1) replies for a client over its upstream cap, per host and
/// UDP only: a burst of 16, then 200 a second (about 36 in any 100 ms). The
/// rest are dropped and counted, so a flood from a forged source address is
/// not reflected at its victim.
const CAPPED_REPLY_BURST: u64 = 16;
const CAPPED_REPLY_QPS: u64 = 200;
/// How long in-flight requests may finish after SIGTERM/SIGINT. The manifest's
/// `terminationGracePeriodSeconds` is 10 s, so 5 s leaves a safe margin.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
/// When a configured list has no persisted copy, wait this long for its
/// first download before opening the listener, so the first query already
/// sees the list. Persisted lists never wait.
const STARTUP_LIST_WAIT: Duration = Duration::from_millis(750);
/// First retry after a refresh in which some list failed; each further
/// failure doubles it, up to the regular `refresh_hours` interval.
const LIST_RETRY: Duration = Duration::from_secs(60);

/// What one blocklist refresh did.
#[derive(Debug, PartialEq)]
enum Refreshed {
    /// Published, every list refreshed.
    Applied,
    /// Published, but some list failed and kept its cached copy or has none.
    Degraded,
    /// A reload changed the list configuration while it ran; not published.
    Stale,
}
/// ConfigMap updates appear as a symlink swap; poll metadata to notice them
/// even when no SIGHUP is sent.
const CONFIG_POLL_INTERVAL: Duration = Duration::from_secs(2);
/// Back-off after a transient accept/recv error (resource pressure, aborted
/// connection) before retrying the listener loop.
const LISTENER_RETRY_BACKOFF: Duration = Duration::from_millis(50);

/// One immutable configuration generation. A request loads exactly one of
/// these, so a reload can never mix the old rules with the new upstream pool
/// or cache. Reload publishes a new `Arc<Runtime>`
/// with one `ArcSwap::store`; an old runtime stays alive for its in-flight
/// requests.
#[derive(Clone)]
struct Runtime {
    cfg: Arc<Config>,
    rules: Arc<rules::Rules>,
    list_status: Arc<Vec<SourceStatus>>,
    upstreams: Arc<UpstreamPool>,
    cache: Arc<Cache>,
    /// Single-flight map for misses and stale refreshes, keyed by canonical
    /// cache key. Entry bound is `upstream_inflight_max`, waiter bound
    /// `inflight::MAX_WAITERS`; a bound hit bypasses instead of queueing.
    inflight: Arc<inflight::Inflight>,
    lists: Arc<ListManager>,
    /// Neighbour table shared with the refresh task across generations.
    macs: Arc<mac::ArpTable>,
    rate: Arc<ratelimit::RateLimit>,
    /// Cache misses each client host has in flight (`upstream_inflight_per_client`),
    /// one count across UDP and TCP: separate counts would let one host (or
    /// its TC=1 retries) hold twice its share of `upstream_inflight_max`.
    fair: Arc<PerClient>,
    /// Response limiting for the TC replies the UDP cap produces, so a flood
    /// (or a spoofed source) cannot turn the cap into a reply burst.
    capped_replies: Arc<ratelimit::RateLimit>,
    max_age: u64,
}

impl Runtime {
    /// Test helper: one generation with a fresh ARP table, cache and
    /// single-flight map.
    #[cfg(test)]
    fn build(
        cfg: Config,
        rules: Arc<rules::Rules>,
        list_status: Arc<Vec<SourceStatus>>,
        upstreams: Arc<UpstreamPool>,
        lists: ListManager,
    ) -> Self {
        Self::build_with(cfg, rules, list_status, upstreams, lists, None, None, Arc::new(mac::ArpTable::new()))
    }

    /// Builds a generation, reusing a warm cache and single-flight map when a
    /// reload did not change their settings. The cache is tied to
    /// `cache_size`, `cache_bytes` and the negative TTL bounds; the
    /// single-flight map to every upstream-affecting setting.
    #[allow(clippy::too_many_arguments)]
    fn build_with(
        cfg: Config,
        rules: Arc<rules::Rules>,
        list_status: Arc<Vec<SourceStatus>>,
        upstreams: Arc<UpstreamPool>,
        lists: ListManager,
        cache: Option<Arc<Cache>>,
        inflight: Option<Arc<inflight::Inflight>>,
        macs: Arc<mac::ArpTable>,
    ) -> Self {
        let max_age =
            if cfg.max_age_secs != 0 { cfg.max_age_secs } else { cfg.optimistic_max_age.seconds().unwrap_or(0) };
        let cache = cache.unwrap_or_else(|| {
            Arc::new(Cache::new(cfg.cache_size, cfg.cache_bytes, cfg.negative_ttl_min, cfg.negative_ttl_max))
        });
        let inflight = inflight
            .unwrap_or_else(|| Arc::new(inflight::Inflight::new(cfg.upstream_inflight_max, inflight::MAX_WAITERS)));
        let rate = Arc::new(ratelimit::RateLimit::new(cfg.rate_limit_qps, cfg.rate_limit_burst));
        Self {
            cache,
            inflight,
            cfg: Arc::new(cfg),
            rules,
            list_status,
            upstreams,
            lists: Arc::new(lists),
            macs,
            rate,
            fair: Arc::new(PerClient::default()),
            capped_replies: Arc::new(ratelimit::RateLimit::new(CAPPED_REPLY_QPS, CAPPED_REPLY_BURST)),
            max_age,
        }
    }
}

/// One shared cache lookup outcome. The inline path answers only
/// [`CacheLookup::Hit`]; `resolve` also needs the miss key for single-flight.
enum CacheLookup {
    /// The request must not use the cache; forward without a key.
    Uncacheable,
    /// Cacheable with no matching entry; carries the canonical key length.
    Miss(usize),
    /// A fresh or stale entry matching this client's EDNS class.
    Hit(usize, cache::HitMeta),
}

/// Synchronous result of [`Runtime::hit_inline`]. The UDP receive loop answers
/// `Inline`/`Truncated` without a task spawn; everything else goes through the
/// spawned parsed path.
enum InlineHit {
    /// Complete client answer: `len` bytes in the caller's answer buffer.
    Inline(usize),
    /// Complete truncated client answer: `len` bytes in the caller's scratch
    /// (truncation) buffer.
    Truncated(usize),
    /// The policy block answer: `len` bytes in the caller's answer buffer,
    /// decided by a rule from list `list` (0 = user rules).
    Blocked { len: usize, list: Option<u16> },
    /// A stale entry is in the answer buffer and the canonical key of
    /// `key_len` bytes is in the caller's key buffer. The async path must
    /// serve it; the receive loop must not wait for a refresh.
    NeedAsync { key_len: usize },
    /// The parsed slow path must run: local policy, miss, malformed or a
    /// protocol gate.
    Slow,
}

struct Server {
    runtime: arc_swap::ArcSwap<Runtime>,
    ready: AtomicBool,
    /// Slow-path UDP requests dropped because `udp_inflight_max` was
    /// exhausted. Fresh cache hits are answered inline and never counted.
    udp_dropped: AtomicU64,
    /// Oversized datagrams dropped on the batched receive path. Shared by
    /// every worker so `udp_truncated` reports one server-wide total.
    #[cfg(target_os = "linux")]
    udp_truncated: AtomicU64,
    /// Test probe: full hickory parses that reached `handle_with`.
    #[cfg(test)]
    parse_calls: std::sync::atomic::AtomicUsize,
    /// Test probe: TCP queries handed to a spawned task (not answered inline).
    #[cfg(test)]
    tcp_spawns: std::sync::atomic::AtomicUsize,
    /// Conformance adapter: UDP datagram lifecycle counters.
    #[cfg(feature = "conformance-adapter")]
    packets: adapter::Packets,
    /// Wakes the list refresher after a reload changed list configuration or
    /// `refresh_hours`.
    refresh_now: Notify,
    /// The current upstream probe loop. A reload aborts the previous one.
    probe: Mutex<Option<JoinHandle<()>>>,
}

impl Server {
    fn runtime(&self) -> Arc<Runtime> {
        self.runtime.load_full()
    }

    /// `/healthz`: listeners are up, the configured lists have loaded at least
    /// once (or none are configured), and not every upstream circuit is open.
    fn healthy(&self) -> bool {
        let runtime = self.runtime();
        self.ready.load(Ordering::SeqCst)
            && (runtime.cfg.blocklists.is_empty() || runtime.list_status.iter().any(|s| s.last_success.is_some()))
            && runtime.upstreams.ready()
    }

    /// The UI listener's routes. Everything else is a 404.
    fn route(&self, req: &http::Req<'_>) -> Option<http::Reply> {
        const TEXT: &str = "text/plain; charset=utf-8";
        match req.path {
            "/healthz" => {
                let ok = self.healthy();
                Some(http::Reply::new(if ok { 200 } else { 503 }, TEXT, if ok { "ok\n" } else { "not ready\n" }))
            }
            "/metrics" => Some(http::Reply::new(200, "text/plain; version=0.0.4; charset=utf-8", self.metrics())),
            "/" | "/log" | "/rules" | "/clients" | "/app.css" | "/app.js" | "/api/dashboard" | "/api/log"
            | "/api/log/stream" => {
                // These render query names and client addresses, so refuse a
                // page that a rebinding attack reached under another name.
                // /healthz and /metrics stay reachable by any Host (probes and
                // scrapers use service names).
                if !ui::host_ok(req.host) {
                    return Some(http::Reply::new(403, TEXT, "forbidden host\n"));
                }
                self.ui(req)
            }
            _ => None,
        }
    }

    /// The read-only pages and their JSON.
    fn ui(&self, req: &http::Req<'_>) -> Option<http::Reply> {
        let runtime = self.runtime();
        let log = querylog::get_or_disabled();
        let lists: &[SourceStatus] = &runtime.list_status;
        Some(match req.path {
            "/app.css" => http::Reply::new(200, "text/css; charset=utf-8", ui::CSS),
            "/app.js" => http::Reply::new(200, "text/javascript; charset=utf-8", ui::JS),
            "/log" => http::Reply::new(200, ui::HTML, ui::log_page(log, lists, req.query)),
            "/api/log" => http::Reply::new(200, ui::JSON, ui::log_json(log, lists, req.query)),
            "/api/log/stream" => ui::stream(log, runtime.list_status.clone(), req.query),
            "/clients" => {
                let rows = ui::clients_rows(&log.top_clients(), &runtime.cfg, &runtime.macs);
                http::Reply::new(200, ui::HTML, ui::clients_html(&rows, log.enabled()))
            }
            "/rules" => http::Reply::new(200, ui::HTML, rules_page(&runtime, req)),
            path => {
                let upstreams = runtime.upstreams.health();
                let snapshot = stats::global().snapshot();
                let dash = ui::Dash {
                    board: log.board(Instant::now(), &snapshot),
                    log_enabled: log.enabled(),
                    lists,
                    upstreams: &upstreams,
                    now_unix: log::now_unix(),
                    plain_fallback: snapshot.plain_fallback,
                };
                if path == "/" {
                    http::Reply::new(200, ui::HTML, ui::dashboard_html(&dash))
                } else {
                    http::Reply::new(200, ui::JSON, ui::dashboard_json(&dash))
                }
            }
        })
    }

    /// Prometheus text. List labels are the sanitized display names and
    /// upstreams are labelled by index, so no URL or token is exposed.
    fn metrics(&self) -> String {
        let runtime = self.runtime();
        let mut out = String::with_capacity(8192);
        stats::global().render(&mut out, runtime.cfg.upstreams.len());
        let (entries, bytes) = runtime.cache.usage();
        out.push_str("# HELP dns_cache_entries Entries in the response cache.\n# TYPE dns_cache_entries gauge\n");
        out.push_str(&format!("dns_cache_entries {entries}\n"));
        out.push_str("# HELP dns_cache_bytes Bytes charged to the response cache.\n# TYPE dns_cache_bytes gauge\n");
        out.push_str(&format!("dns_cache_bytes {bytes}\n"));
        out.push_str(
            "# HELP dns_blocklist_rules Rules loaded from each blocklist.\n# TYPE dns_blocklist_rules gauge\n",
        );
        for status in runtime.list_status.iter() {
            out.push_str(&format!("dns_blocklist_rules{{list=\"{}\"}} {}\n", label(&status.name), status.rules));
        }
        out.push_str("# HELP dns_blocklist_last_success_timestamp Unix time of the last successful list load.\n");
        out.push_str("# TYPE dns_blocklist_last_success_timestamp gauge\n");
        for status in runtime.list_status.iter() {
            if let Some(at) = status.last_success {
                out.push_str(&format!(
                    "dns_blocklist_last_success_timestamp{{list=\"{}\"}} {at}\n",
                    label(&status.name)
                ));
            }
        }
        out
    }

    #[cfg(test)]
    fn cache(&self) -> Arc<Cache> {
        self.runtime().cache.clone()
    }

    #[cfg(test)]
    fn inflight(&self) -> Arc<inflight::Inflight> {
        self.runtime().inflight.clone()
    }

    #[cfg(test)]
    fn set_rules(&self, rules: rules::Rules) {
        let current = self.runtime.load_full();
        let mut next = (*current).clone();
        next.rules = Arc::new(rules);
        self.runtime.store(Arc::new(next));
    }
}
/// `/rules`: the page, plus the result of a POSTed form. The tester form posts
/// `name`, `qtype` and `client`; the editor posts `rules`. Neither changes
/// anything.
fn rules_page(runtime: &Runtime, req: &http::Req<'_>) -> String {
    let mut rewrites: Vec<_> = runtime.cfg.rewrites.iter().map(|(name, ip)| (name.as_str(), *ip)).collect();
    rewrites.sort_unstable();
    let mut page = ui::RulesPage {
        lists: &runtime.list_status,
        user_rules: &runtime.cfg.user_rules,
        rewrites,
        form: ui::TestForm { qtype: "A".to_string(), ..ui::TestForm::default() },
        tested: None,
        editor: None,
    };
    if req.post {
        let body = String::from_utf8_lossy(req.body);
        let field = |key| querylog::param(&body, key);
        if let Some(rules) = field("rules") {
            page.editor = Some(rules);
        } else if let Some(name) = field("name") {
            page.form = ui::TestForm {
                name,
                qtype: field("qtype").unwrap_or_else(|| "A".to_string()),
                client: field("client").unwrap_or_default(),
            };
            page.tested = Some(runtime.test_domain(&page.form));
        }
    }
    ui::rules_page(&page)
}
/// Prometheus label value escaping.
fn label(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
}
fn reply(q: &Message, code: ResponseCode) -> Message {
    let mut m = Message::new(q.metadata.id, MessageType::Response, q.metadata.op_code);
    m.metadata.recursion_desired = q.metadata.recursion_desired;
    m.metadata.recursion_available = true;
    m.metadata.checking_disabled = q.metadata.checking_disabled;
    m.metadata.response_code = code;
    m.add_queries(q.queries.iter().cloned());
    if let Some(edns) = &q.edns {
        let mut e = hickory_proto::op::Edns::new();
        e.set_max_payload(1232).set_dnssec_ok(edns.flags().dnssec_ok);
        m.set_edns(e);
    }
    m
}
/// The block answer: NXDOMAIN with the policy SOA, the same for a direct rule
/// and a CNAME target.
fn blocked_reply(q: &Message, name: Name) -> Message {
    let mut m = reply(q, ResponseCode::NXDomain);
    soa(&mut m, name);
    m
}
fn soa(m: &mut Message, name: Name) {
    m.add_authority(Record::from_rdata(
        name,
        10,
        RData::SOA(SOA::new(Name::root(), Name::root(), 1, 3600, 600, 86400, 10)),
    ));
}
/// Authoritative negative SOA for a synthetic local zone: owner and MNAME are
/// the zone apex, RNAME `nobody.invalid.`, TTL/MINIMUM 10.
fn zone_soa(zone: &Name) -> Record {
    let rname = Name::from_ascii("nobody.invalid.").expect("static valid name");
    Record::from_rdata(zone.clone(), 10, RData::SOA(SOA::new(zone.clone(), rname, 1, 3600, 600, 86400, 10)))
}
/// Synthetic apex NS: the target is the zone apex itself.
fn zone_ns(zone: &Name) -> Record {
    Record::from_rdata(zone.clone(), 10, RData::NS(NS(zone.clone())))
}
/// Local answer for a private reverse name or a local empty zone. `None` means
/// "not local, forward it": a public reverse name, a PTR with
/// `private_ptr = "forward"`, or the DS probe at a local zone apex with DO=1.
fn reverse_answer(cfg: &Config, q: &Message, name: &str, do_bit: bool) -> Option<Message> {
    let query = q.queries.first()?;
    let qtype = query.query_type();
    // `forward` opts the whole private PTR path out, including zone-service
    // PTR answers; SOA/NS and negative zone answers stay local.
    if reverse::forwards_ptr(cfg, u16::from(qtype), name) {
        return None;
    }
    let zone = reverse::zone_for(name);
    if qtype == RecordType::PTR {
        if let Some(ip) = reverse::private_ptr_ip(name) {
            // A complete address inside a listed empty zone takes the zone
            // shape below: authoritative NXDOMAIN with the apex SOA. The
            // generic denial covers private addresses outside those zones
            // (for example ::1) and keeps the question-name SOA shape.
            if reverse::is_private(ip) && zone.is_none() {
                let mut local = reply(q, ResponseCode::NXDomain);
                soa(&mut local, query.name().clone());
                return Some(local);
            }
        }
    }
    let zone = zone?;
    // The DS at a locally served zone apex lives in the signed parent zone
    // (RFC 4035 §3.1.4.1); a validating client needs that proof, not a
    // synthetic local NODATA it cannot verify (RFC 6303 §7, RFC 8375 §4). Only
    // with DO=1: a client that does not ask for DNSSEC records cannot use the
    // proof, and the query then stays local like the rest of the zone.
    if zone.is_apex && qtype == RecordType::DS && do_bit {
        return None;
    }
    let apex = Name::from_ascii(format!("{}.", zone.apex)).ok()?;
    let mut local = reply(q, ResponseCode::NoError);
    local.metadata.authoritative = true;
    if zone.is_apex {
        match qtype {
            RecordType::SOA => local.add_answer(zone_soa(&apex)),
            RecordType::NS => local.add_answer(zone_ns(&apex)),
            _ => local.add_authority(zone_soa(&apex)),
        };
        Some(local)
    } else {
        // RFC 9462 §6.4: names under resolver.arpa are NODATA, not NXDOMAIN.
        if zone.kind != reverse::ZoneKind::NoData {
            local.metadata.response_code = ResponseCode::NXDomain;
        }
        local.add_authority(zone_soa(&apex));
        Some(local)
    }
}
/// Special-use names that never leave the host: `localhost` (RFC 6761 §6.3:
/// loopback addresses, NODATA otherwise), `invalid` (§6.4), `test` (§6.2,
/// unless `forward_test_names`) and `onion` (RFC 7686 §2, a MUST): NXDOMAIN.
/// Never cached, so the inline cache path cannot see them. The loopback
/// addresses are IN data: another class gets NODATA for `localhost`.
fn special_use_answer(cfg: &Config, q: &Message, name: &str, is_in: bool) -> Option<Message> {
    let query = q.queries.first()?;
    let mut local = reply(q, ResponseCode::NoError);
    match name.rsplit('.').next()? {
        "localhost" => {
            let data = match query.query_type() {
                RecordType::A if is_in => Some(RData::A(A(std::net::Ipv4Addr::LOCALHOST))),
                RecordType::AAAA if is_in => Some(RData::AAAA(AAAA(std::net::Ipv6Addr::LOCALHOST))),
                _ => None,
            };
            match data {
                Some(data) => local.add_answer(Record::from_rdata(query.name().clone(), 10, data)),
                None => {
                    soa(&mut local, query.name().clone());
                    return Some(local);
                }
            };
        }
        "invalid" | "onion" => {
            local.metadata.response_code = ResponseCode::NXDomain;
            soa(&mut local, query.name().clone());
        }
        "test" if !cfg.forward_test_names => {
            local.metadata.response_code = ResponseCode::NXDomain;
            soa(&mut local, query.name().clone());
        }
        _ => return None,
    }
    Some(local)
}
/// Whether [`special_use_answer`] answers `name` (lowercase, dotted, no
/// final dot) locally, ahead of the blocklist.
fn special_use_name(cfg: &Config, name: &[u8]) -> bool {
    match name.rsplit(|&byte| byte == b'.').next() {
        Some(b"localhost" | b"invalid" | b"onion") => true,
        Some(b"test") => !cfg.forward_test_names,
        _ => false,
    }
}
/// The lowercase text form, without the final dot, that rewrites, local
/// zones, special-use names and rules match on. A dot inside a label
/// (presentation `a\.b`) is written as the decimal escape `\046` (RFC 1035
/// §5.1), so every `.` left separates whole labels: `a\.b.onion` stays under
/// `onion`, and the single label `blocked\.example` never reads as two.
fn policy_name(name: &Name) -> String {
    let text = name.to_ascii();
    if !name.iter().any(|label| label.contains(&b'.')) {
        return text.trim_end_matches('.').to_ascii_lowercase();
    }
    let mut out = String::with_capacity(text.len() + 8);
    let mut escaped = false;
    for c in text.chars() {
        if escaped && c == '.' {
            out.push_str("046");
        } else {
            out.push(c.to_ascii_lowercase());
        }
        escaped = !escaped && c == '\\';
    }
    // Every dot left separates labels: a final one is the root.
    if out.ends_with('.') {
        out.pop();
    }
    out
}
fn parse(raw: &[u8]) -> Option<Message> {
    use hickory_proto::serialize::binary::{BinDecodable, BinDecoder};
    let mut decoder = BinDecoder::new(raw);
    let msg = Message::read(&mut decoder).ok()?;
    (decoder.index() == raw.len()).then_some(msg)
}
/// True when every label is plain DNS text, so hickory's `to_ascii()` name
/// equals [`wire::dotted_name`]'s bytes. Names hickory would escape (special
/// bytes, a leading dash) keep the parsed path, where policy strings are
/// built exactly as before the wire fast path existed.
fn plain_wire_name(view: &wire::QueryView<'_>) -> bool {
    let wire = &view.qname_lower[..view.qname_len as usize];
    let mut pos = 0;
    while let Some(&len) = wire.get(pos) {
        let len = len as usize;
        if len == 0 {
            return true;
        }
        let Some(label) = wire.get(pos + 1..pos + 1 + len) else { return false };
        let plain = |byte: &u8| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-' || *byte == b'_';
        if label.first() == Some(&b'-') || !label.iter().all(plain) {
            return false;
        }
        pos += 1 + len;
    }
    false
}
/// Conservative AD profile (RFC 6840 §5.8): keep the upstream AD only for a
/// client that set AD or DO.
fn ad_ok(view: &wire::QueryView<'_>) -> bool {
    view.authentic_data() || view.edns_do
}
/// The client DNSSEC context a relayed answer is normalized for. Copy so the
/// stale-refresh task can take it into the background.
#[derive(Clone, Copy)]
struct DnssecContext {
    edns: bool,
    do_bit: bool,
    ad_ok: bool,
    cd: bool,
    qtype: u16,
    /// The client asked for Compact Answers OK.
    co: bool,
    /// The client reached us over TCP, so plain upstreams are tried over TCP first.
    tcp: bool,
}

impl DnssecContext {
    fn new(view: &wire::QueryView<'_>) -> Self {
        Self {
            edns: view.edns_present,
            do_bit: view.edns_do,
            ad_ok: ad_ok(view),
            cd: view.cd,
            qtype: view.qtype,
            co: view.edns_flags & wire::CO_FLAG != 0,
            tcp: false,
        }
    }
}
/// Where the local policy answered a query.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    /// CHAOS class, QCLASS ANY or NONE, or a `version.bind`-style name: REFUSED.
    Chaos,
    /// A non-QUERY opcode: NOTIMP.
    NotImp,
    /// QTYPE=ANY that no other local policy answered: a synthesized HINFO.
    Any,
    Rewrite,
    /// A private reverse name or a local empty zone.
    Zone,
    /// `localhost`, `invalid`, `onion` and (by default) `test`.
    SpecialUse,
    /// A blocklist rule decided; carries the list id that did (0 = user rules).
    Blocked(Option<u16>),
    /// An unconfigured `.local` name: NXDOMAIN, it belongs to mDNS.
    Mdns,
}

impl Stage {
    fn outcome(self) -> Outcome {
        match self {
            Stage::Chaos | Stage::NotImp => Outcome::Other,
            Stage::Blocked(_) => Outcome::Blocked,
            _ => Outcome::Local,
        }
    }
}

/// A policy answer: where it came from and the reply to send.
struct Local {
    stage: Stage,
    answer: Message,
}

impl Runtime {
    /// The decision order before the cache and the upstreams: CHAOS and
    /// meta-queries, rewrites, local zones, special-use names, the blocklist
    /// (skipped for a `no_filter_*` client) and `.local`. `None` means
    /// forward. It counts and logs nothing: `resolve` records the outcome, and
    /// the rule tester on the UI calls this same function, so it cannot
    /// disagree with the server.
    ///
    /// The name decisions apply in every class: RFC 7686 §2 asks NXDOMAIN for
    /// all `.onion` queries, RFC 8375 §4 forbids forwarding `home.arpa`
    /// queries, and a blocked name must not leak through an unusual class.
    /// Local records take the question's class (IN for QCLASS ANY or NONE);
    /// IN address data is never copied into another class.
    fn policy(&self, q: &Message, do_bit: bool, ip: IpAddr) -> Option<Local> {
        let mut local = self.policy_by_name(q, do_bit, ip)?;
        let class = data_class(q.queries.first()?.query_class());
        if class != DNSClass::IN {
            for record in local.answer.answers.iter_mut().chain(local.answer.authorities.iter_mut()) {
                record.dns_class = class;
            }
        }
        Some(local)
    }

    fn policy_by_name(&self, q: &Message, do_bit: bool, ip: IpAddr) -> Option<Local> {
        let query = q.queries.first()?;
        let name = policy_name(query.name());
        // Built only by the branches that answer locally: a forwarded miss
        // (the common case) must not pay for a Message and a query clone.
        let local = || reply(q, ResponseCode::NoError);
        if query.query_class() == DNSClass::CH
            || matches!(name.as_str(), "version.bind" | "id.server" | "hostname.bind")
        {
            let mut local = local();
            local.metadata.response_code = ResponseCode::Refused;
            return Some(Local { stage: Stage::Chaos, answer: local });
        }
        if q.metadata.op_code != OpCode::Query {
            let mut local = local();
            local.metadata.response_code = ResponseCode::NotImp;
            return Some(Local { stage: Stage::NotImp, answer: local });
        }
        // ANY is never forwarded. It goes through the local policy below like
        // any type (a blocked or special-use name keeps its answer) and gets
        // the RFC 8482 HINFO where the policy would otherwise forward.
        // QCLASS ANY and NONE (RFC 6895 §3.2: query classes, not data
        // classes) are never forwarded either: an upstream answers them from
        // its IN data, which this server would then serve for another class.
        let forward = || {
            if query.query_type() == RecordType::ANY {
                Some(Local { stage: Stage::Any, answer: any_hinfo(q) })
            } else if matches!(query.query_class(), DNSClass::ANY | DNSClass::NONE) {
                let mut local = local();
                local.metadata.response_code = ResponseCode::Refused;
                Some(Local { stage: Stage::Chaos, answer: local })
            } else {
                None
            }
        };
        let is_in = query.query_class() == DNSClass::IN;
        if let Some(ip) = rules::rewrite(&self.cfg.rewrites, &name) {
            // Another class gets NODATA: the name is local, but the
            // configured address is IN data.
            let data = match (ip, query.query_type()) {
                (IpAddr::V4(ip), RecordType::A) if is_in => Some(RData::A(A(ip))),
                (IpAddr::V6(ip), RecordType::AAAA) if is_in => Some(RData::AAAA(AAAA(ip))),
                _ => None,
            };
            let mut local = local();
            if let Some(data) = data {
                local.add_answer(Record::from_rdata(query.name().clone(), 10, data));
            } else {
                // Wrong family or type is NODATA: carry the local negative
                // lifetime so clients do not cache it unboundedly (RFC 2308).
                soa(&mut local, query.name().clone());
            }
            return Some(Local { stage: Stage::Rewrite, answer: local });
        }
        // Configured local zones precede the bypass decision and the
        // blocklist. The bypass applies to the blocklist only.
        if let Some(answer) = reverse_answer(&self.cfg, q, &name, do_bit) {
            return Some(Local { stage: Stage::Zone, answer });
        }
        if let Some(answer) = special_use_answer(&self.cfg, q, &name, is_in) {
            return Some(Local { stage: Stage::SpecialUse, answer });
        }
        if !self.macs.is_no_filter(ip, &self.cfg.no_filter_clients, &self.cfg.no_filter_mac_addrs) {
            // `decision` scans exactly like `blocked` and also says which
            // list decided; the query log shows it.
            let decision = self.rules.decision(&name);
            if decision.blocked {
                return Some(Local {
                    stage: Stage::Blocked(decision.list_id),
                    answer: blocked_reply(q, query.name().clone()),
                });
            }
        }
        // RFC 6762 §22.1 item 4: an unconfigured .local name belongs to
        // mDNS; answer NXDOMAIN here instead of asking global DNS.
        if name == "local" || name.ends_with(".local") {
            let mut local = local();
            local.metadata.response_code = ResponseCode::NXDomain;
            soa(&mut local, query.name().clone());
            return Some(Local { stage: Stage::Mdns, answer: local });
        }
        forward()
    }
}

/// TTL of the synthesized ANY answer. RFC 8482 §4.2 leaves it to the
/// operator; it is short like every other local answer, so a policy change
/// is seen quickly, and answering a repeat costs nothing upstream.
const ANY_HINFO_TTL: u32 = 10;

/// The class of a locally built record: the question's, or IN for QCLASS ANY
/// or NONE, which are not data classes (RFC 6895 §3.2).
fn data_class(class: DNSClass) -> DNSClass {
    match class {
        DNSClass::ANY | DNSClass::NONE => DNSClass::IN,
        class => class,
    }
}

/// RFC 8482 §4.2: answer QTYPE=ANY with one synthesized HINFO RRset, CPU
/// "RFC8482" and an empty OS. It is deterministic, small (no amplification)
/// and needs no upstream. The record takes the question's class, IN for a
/// QCLASS of ANY or NONE, which are not data classes.
fn any_hinfo(q: &Message) -> Message {
    let mut m = reply(q, ResponseCode::NoError);
    if let Some(query) = q.queries.first() {
        let hinfo = RData::HINFO(HINFO::new("RFC8482".into(), String::new()));
        // `policy` sets the class.
        m.add_answer(Record::from_rdata(query.name().clone(), ANY_HINFO_TTL, hinfo));
    }
    m
}

impl Runtime {
    /// The rules page's "Test a domain": what [`Runtime::policy`] and the
    /// admission gates of `handle_with` would do for this name, type and client,
    /// plus every blocklist rule that matches the name. It calls the same
    /// functions the server does, builds its own query, and touches no counter,
    /// log, cache or upstream.
    fn test_domain(&self, form: &ui::TestForm) -> ui::Tested {
        use std::str::FromStr;
        let fail = |text: &str| ui::Tested { error: Some(text.to_string()), ..ui::Tested::default() };
        let typed = form.name.trim().trim_end_matches('.');
        if typed.is_empty() {
            return fail("Enter a domain name.");
        }
        let Ok(qname) = Name::from_ascii(format!("{typed}.")) else {
            return fail("Not a valid DNS name (labels of 1 to 63 characters, 253 in total).");
        };
        let Ok(qtype) = RecordType::from_str(&form.qtype.trim().to_ascii_uppercase()) else {
            return fail("Unknown query type.");
        };
        let client = match form.client.trim() {
            "" => None,
            text => match text.parse::<IpAddr>() {
                Ok(ip) => Some(ip),
                Err(_) => return fail("The client must be an IP address, or empty."),
            },
        };
        let name = policy_name(&qname);
        let lists = &self.list_status;
        let list_label =
            |id: Option<u16>| id.map_or_else(|| "an unknown list".to_string(), |id| ui::list_name(lists, id));
        let mut t = ui::Tested { rule_domain: rules::domain(&name), ..ui::Tested::default() };

        // The same table the server probes, and the source lines behind it.
        let matches = self.rules.explain(&name);
        if matches.is_empty() {
            t.scan_complete = true;
        } else {
            let wanted = matches.iter().map(|m| m.parent.clone()).collect();
            let scan = self.lists.find_rules(&wanted);
            t.scan_complete = scan.complete;
            t.rows = ui::rule_rows(&name, &matches, &scan.hits);
        }
        let blocking_rule = t.rows.first().is_some_and(|r| r.wins && r.rank % 2 == 1);

        // Admission, as in `handle_with`, before any policy.
        let qtype_code = u16::from(qtype);
        let gate = if client.is_some_and(|ip| !self.cfg.client_allowed(ip)) {
            Some(("REFUSED", "The client is outside allowed_clients, so the server answers REFUSED without a lookup."))
        } else if wire::TRANSFER_TYPES.contains(&qtype_code) {
            Some(("REFUSED", "Zone transfers and TKEY are refused."))
        } else if wire::is_meta_qtype(qtype_code) {
            Some(("FORMERR", "Meta query types are rejected as malformed."))
        } else {
            None
        };
        t.notes.push(match client {
            None => "No client given: filtering applies.".to_string(),
            Some(ip) if self.macs.is_no_filter(ip, &self.cfg.no_filter_clients, &self.cfg.no_filter_mac_addrs) => {
                format!(
                    "{ip} is exempt from filtering (no_filter_clients or no_filter_macs): blocklist rules are skipped."
                )
            }
            Some(ip) => format!("{ip} is filtered."),
        });
        if let Some((answer, detail)) = gate {
            t.verdict = "Refused".to_string();
            t.class = "warn";
            t.answer = answer.to_string();
            t.detail = detail.to_string();
            return t;
        }

        let mut query = Message::new(0, MessageType::Query, OpCode::Query);
        query.add_query(hickory_proto::op::Query::query(qname, qtype));
        // `0.0.0.0` stands for "no client": it is in no no_filter list.
        let ip = client.unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        let Some(local) = self.policy(&query, false, ip) else {
            t.verdict = "Forwarded".to_string();
            t.class = "ok";
            t.answer = "from the cache or an upstream".to_string();
            t.detail =
                "No local policy answers this name, so the query goes to the cache and then the upstreams.".to_string();
            if self.cfg.block_cname_targets {
                t.notes.push("An upstream CNAME to a blocked name would also be blocked.".to_string());
            }
            if blocking_rule {
                t.notes.push("A blocking rule matches, but this client is exempt from filtering.".to_string());
            } else if !t.rows.is_empty() {
                t.notes.push("Rules match the name, but none of them blocks it.".to_string());
            }
            return t;
        };
        let rcode = match local.answer.metadata.response_code {
            ResponseCode::NoError => "NOERROR".to_string(),
            ResponseCode::NXDomain => "NXDOMAIN".to_string(),
            ResponseCode::Refused => "REFUSED".to_string(),
            ResponseCode::NotImp => "NOTIMP".to_string(),
            other => format!("{other:?}").to_ascii_uppercase(),
        };
        let addresses: Vec<String> = local.answer.answers.iter().map(|r| r.data.to_string()).collect();
        t.answer = match (local.answer.metadata.response_code, addresses.is_empty()) {
            (ResponseCode::NoError, true) => "NOERROR, no data".to_string(),
            (_, true) => rcode,
            (_, false) => format!("{rcode} {}", addresses.join(", ")),
        };
        let (verdict, class, detail) = match local.stage {
            Stage::Chaos => ("Refused", "warn", "CHAOS-class and server-identity names are refused.".to_string()),
            Stage::NotImp => ("Not implemented", "warn", "Only the QUERY opcode is implemented.".to_string()),
            Stage::Any => (
                "Minimal ANY answer",
                "warn",
                "ANY queries are answered locally with a synthesized HINFO (RFC 8482) and never forwarded.".to_string(),
            ),
            Stage::Rewrite => ("Rewrite", "ok", "A configured rewrite answers this name.".to_string()),
            Stage::Zone => ("Local zone", "warn", "A local reverse or special zone answers this name.".to_string()),
            Stage::SpecialUse => {
                ("Special-use name", "warn", "A special-use name (RFC 6761, RFC 7686) is answered locally.".to_string())
            }
            Stage::Blocked(list) => ("Blocked", "bad", format!("Blocked by {}.", list_label(list))),
            Stage::Mdns => {
                ("Local", "warn", "An unconfigured .local name belongs to mDNS, so it is not forwarded.".to_string())
            }
        };
        t.verdict = verdict.to_string();
        t.class = class;
        t.detail = detail;
        if !t.rows.is_empty() && !matches!(local.stage, Stage::Blocked(_)) {
            t.notes.push(
                "Blocklist rules also match this name, but the answer above is decided before the blocklist."
                    .to_string(),
            );
        }
        t
    }
}

impl Runtime {
    /// One upstream attempt plus the relay transform shared by leaders and
    /// bypass callers: cache insert first, then Age patching and AD policy.
    /// `key` is the canonical cache key when the query was cacheable.
    async fn upstream_relay(
        &self,
        raw: &[u8],
        client_id: u16,
        client: DnssecContext,
        key: Option<&[u8]>,
    ) -> Option<Vec<u8>> {
        // `always_upstream` asks every upstream for DNSSEC material even when
        // the client did not. `set_do_bit` cannot fail for a packet that the
        // request path already accepted; if it does, SERVFAIL is safer than
        // forwarding without the configured DO bit.
        let mut upstream_query =
            if self.cfg.dnssec == DnssecMode::AlwaysUpstream { wire::set_do_bit(raw)? } else { raw.to_vec() };
        // RFC 6891 §6.2.3: the upstream request advertises this forwarder's
        // own size (never above the RFC 9715 recommended 1400), not the client's.
        wire::set_opt_payload(&mut upstream_query, self.cfg.udp_max_payload.min(1400));
        let Some(answer) = self.upstreams.exchange_from(&upstream_query, client_id, client.tcp).await else {
            stats::upstream_error();
            return None;
        };
        querylog::note_upstream(answer.upstream_index);
        // Normalize for the client class before caching: a client that did not
        // set DO must never receive or share DNSSEC material. The cache key
        // already reflects the client's EDNS/DO/AD bits, so this template is
        // served without a rebuild.
        let strip_dnssec = self.cfg.dnssec == DnssecMode::AlwaysUpstream && !client.do_bit;
        let (mut relayed, mut message) = if strip_dnssec {
            let normalized =
                wire::strip_response_for_client(&answer.raw, client.edns, client.do_bit, strip_dnssec, client.qtype)?;
            let message = Message::from_vec(&normalized).ok()?;
            (normalized, message)
        } else {
            (answer.raw, answer.message)
        };
        // The response CD follows the client, never the upstream reply
        // (RFC 4035 §3.2.2). One RRset leaves with one TTL (RFC 2181 §5.2);
        // the cache normalizes its own copy, the first relay must match it.
        wire::set_cd(&mut relayed, client.cd);
        wire::clear_aa(&mut relayed);
        // RFC 6891 §6.1.1: OPT is hop-by-hop; a non-EDNS client never gets
        // one. Z, OPT presence and DO follow the client; keep the view in step so
        // the cache entry's EDNS flag matches the bytes it stores.
        let payload = self.cfg.udp_max_payload;
        if wire::present_for_client(&mut relayed, client.edns, client.do_bit, client.co, payload) {
            let edns = message.edns.get_or_insert_with(Default::default);
            edns.set_dnssec_ok(client.do_bit).set_max_payload(payload).set_version(0);
        } else {
            message.edns = None;
        }
        // RFC 8767 §4: a TTL with the top bit set is positive and capped,
        // like any TTL above 7 days, whether or not the RRset walk below
        // lines up with the parsed message.
        wire::cap_ttls(&mut relayed);
        wire::normalize_rrset_ttls(&message, &mut relayed);
        // Plaintext answers are short-lived and never served stale unless the
        // operator opted in to trusting plain servers (`trust_plain_upstreams`).
        let downgraded = answer.upstream_index.is_none() && !self.cfg.trust_plain_upstreams;
        if let Some(key) = key {
            if answer.terminal {
                // The cache applies `age` to these unaged bytes. An untrusted
                // plaintext answer is short-lived, never stale, never
                // prefetched.
                // The CNAME-cloaking verdict is stored with the entry, so a
                // hit costs a compare instead of a chain walk.
                let chain = if self.cfg.block_cname_targets {
                    wire::parse_query(raw)
                        .and_then(|v| self.chain_state(&relayed, &v.qname_lower[..usize::from(v.qname_len)]))
                } else {
                    None
                };
                let stored = self.cache.insert_with_chain(key, &relayed, &message, answer.age, downgraded, chain);
                if !stored {
                    // The newer answer supersedes a stale copy it cannot replace.
                    self.cache.remove(key);
                }
            } else {
                // A valid negative without a usable SOA is not
                // cacheable but still ends stale service for the key.
                self.cache.invalidate_negative(key, &message);
            }
        }
        if answer.age > 0 {
            // Age the relayed answer too (the DoH `Age` header, RFC 8484 §5.1),
            // not only the cache template.
            // The pool already verified this walk.
            if let Some(offsets) = wire::ttl_offsets(&relayed) {
                wire::patch(&mut relayed, &offsets, answer.age, false, client_id);
            }
        }
        // The first negative relay emits the same lifetime a cached hit would
        // (RFC 2308 §5), rather than the upstream SOA's unclamped TTL.
        if let Some(lifetime) = self.cache.negative_lifetime(&message, answer.age) {
            wire::set_authority_soa_ttl(&mut relayed, lifetime);
        }
        // A plaintext answer is short-lived for the client too, not only in
        // our cache (after the SOA rewrite above, which must not lift it): a
        // spoof must not sit in a stub cache for days.
        if downgraded {
            if let Some(offsets) = wire::ttl_offsets(&relayed) {
                for &off in offsets.iter() {
                    let at = off as usize;
                    let ttl = u32::from_be_bytes([relayed[at], relayed[at + 1], relayed[at + 2], relayed[at + 3]]);
                    let capped = ttl.min(sopedu_dns::cache::PLAIN_TTL_CAP);
                    relayed[at..at + 4].copy_from_slice(&capped.to_be_bytes());
                }
            }
        }
        if !client.ad_ok {
            wire::clear_ad(&mut relayed);
        }
        Some(relayed)
    }
    /// Runs one upstream relay as its own task, so it outlives a caller that
    /// stops waiting (RFC 8767 §5: the refresh continues after a stale answer)
    /// and a coalescing leader whose client goes away still answers its
    /// followers. The task publishes through `guard` when it has one and holds
    /// the client's upstream `slot` until it ends. It is bounded by the pool's
    /// in-flight permits, the upstream deadline and failure suppression.
    fn spawn_relay(
        self: &Arc<Self>,
        raw: &[u8],
        id: u16,
        context: DnssecContext,
        key: &[u8],
        guard: Option<inflight::LeaderGuard>,
        slot: Option<ratelimit::ClientSlot>,
    ) -> JoinHandle<Option<Vec<u8>>> {
        let (server, raw, key): (_, _, Box<[u8]>) = (self.clone(), raw.to_vec(), key.into());
        let refresh = async move {
            let _slot = slot;
            let relayed = server.upstream_relay(&raw, id, context, Some(&key)).await;
            // Insert happened inside `upstream_relay`; publish after it.
            if let Some(guard) = guard {
                guard.complete(relayed.as_deref().map(Arc::from));
            }
            relayed
        };
        #[cfg(feature = "conformance-adapter")]
        let refresh = sopedu_dns::upstream::descend(refresh);
        tokio::spawn(refresh)
    }

    /// Starts one background refresh through the single-flight map. The caller
    /// has already checked [`inflight::coalescible`]: a follower means a
    /// refresh already runs and a bypass means the map is saturated; both do
    /// nothing, so one key never gets a second refresh. The refresh is
    /// upstream work for the host whose hit started it, so it holds one of
    /// that host's upstream slots; a host over its cap starts none.
    fn spawn_refresh(self: &Arc<Self>, raw: &[u8], id: u16, context: DnssecContext, key: &[u8], ip: IpAddr) {
        // The slot first: a host over its cap must not open a flight that
        // another client could join in the moment before it is dropped.
        let Some(slot) = self.upstream_slot(ip) else { return };
        let inflight::Role::Leader(guard) = self.inflight.join(key) else { return };
        self.spawn_relay(raw, id, context, key, Some(guard), slot);
    }

    /// Stale handling (RFC 8767 §5). A zero client timeout (an opt-in, not RFC
    /// 8767 conformant) keeps the historical
    /// optimistic behavior: answer stale immediately and refresh in the
    /// background. A positive timeout waits at most that long for one upstream
    /// refresh, then answers the RFC 8767 copy while the refresh keeps running
    /// and fills the cache. The stale copy is already transformed by
    /// `Cache::get` (TTL 30, AD clear, SOA remaining TTL).
    ///
    /// A refresh, or waiting on one, takes one of the client host's upstream
    /// slots like a miss does. A host over its cap gets the stale copy at once
    /// and starts no refresh: the data cannot be refreshed for it now, which
    /// is when RFC 8767 §4 allows stale data.
    async fn serve_stale(
        self: &Arc<Self>,
        raw: &[u8],
        id: u16,
        view: &wire::QueryView<'_>,
        key: &[u8],
        stale: Vec<u8>,
        ip: IpAddr,
    ) -> Option<Vec<u8>> {
        let context = DnssecContext::new(view);
        let wait = Duration::from_millis(self.cfg.serve_stale_client_timeout_ms);
        let coalescible = inflight::coalescible(view);
        if wait.is_zero() {
            if coalescible {
                self.spawn_refresh(raw, id, context, key, ip);
            } else if let Some(slot) = self.upstream_slot(ip) {
                // Single-flight never applies to this context: refresh on our
                // own and still answer this client with the stale copy.
                self.spawn_relay(raw, id, context, key, None, slot);
            }
            return Some(stale);
        }
        let Some(slot) = self.upstream_slot(ip) else { return Some(stale) };
        // The refresh is a task of its own: when the client timer fires the
        // stale copy goes out and the refresh carries on (RFC 8767 §5).
        let race = |task: JoinHandle<Option<Vec<u8>>>| async move {
            let mut task = task;
            timeout(wait, &mut task).await.ok().and_then(|joined| joined.ok()).flatten()
        };
        let fresh = if coalescible {
            match self.inflight.join(key) {
                inflight::Role::Leader(guard) => race(self.spawn_relay(raw, id, context, key, Some(guard), slot)).await,
                inflight::Role::Follower(receiver) => {
                    let _slot = slot;
                    inflight::wait(receiver, wait).await.map(|shared| {
                        let mut bytes = shared.to_vec();
                        // The leader patched its own ID; this client needs its own.
                        bytes[..2].copy_from_slice(&id.to_be_bytes());
                        bytes
                    })
                }
                inflight::Role::Bypass => race(self.spawn_relay(raw, id, context, key, None, slot)).await,
            }
        } else {
            race(self.spawn_relay(raw, id, context, key, None, slot)).await
        };
        Some(fresh.unwrap_or(stale))
    }

    /// One cache lookup shared by the inline path, [`Runtime::fast_path`] and
    /// [`Runtime::resolve`]: the cacheability filter, canonical key and
    /// EDNS-class match have one definition. `key` receives the canonical key
    /// on a cacheable request and `answer` the patched response on a hit.
    fn lookup(
        &self,
        view: &wire::QueryView<'_>,
        key: &mut [u8; wire::MIN_CANONICAL_BUFFER],
        answer: &mut Vec<u8>,
    ) -> CacheLookup {
        // Non-hop options (hop-scoped ECS/Cookie/keepalive/Padding are
        // stripped upstream), extra sections, signed messages and any non-DO
        // EDNS flag cannot share this cache key. Only IN is cached or
        // shared; other classes are forwarded separately.
        let cacheable = view.qclass == u16::from(DNSClass::IN)
            && !view.signed
            && !view.has_answer_or_authority
            && !view.has_non_opt_additional
            && !view.edns_options
            && !view.edns_other_flags
            && !view.unfamiliar_header_flags
            && view.rd;
        if !cacheable {
            return CacheLookup::Uncacheable;
        }
        let Some(len) = wire::canonical_key(view, key) else {
            return CacheLookup::Uncacheable;
        };
        match self.cache.get_into(&key[..len], view.id, self.max_age, answer) {
            // Do not send an unsolicited OPT to a non-EDNS client.
            Some(meta) if meta.had_edns == view.edns_present => CacheLookup::Hit(len, meta),
            _ => CacheLookup::Miss(len),
        }
    }

    /// Prefetch (Unbound style): refresh a popular positive entry during the last
    /// 10% of its lifetime, so it never goes stale. The client still gets the
    /// stored answer immediately. Negative entries are skipped (a refresh
    /// would only spend upstream traffic on a name already denied) and
    /// non-coalescible contexts are skipped too, so one hit cannot spawn an
    /// unbounded task. `spawn_refresh` makes follower and bypass a no-op, so a
    /// refresh already running is never duplicated. One definition for the
    /// inline path and `resolve`.
    fn prefetch_hit(
        self: &Arc<Self>,
        raw: &[u8],
        view: &wire::QueryView<'_>,
        key: &[u8],
        meta: &cache::HitMeta,
        ip: IpAddr,
    ) {
        if self.cfg.prefetch
            && !meta.negative
            && !meta.plain
            && meta.remaining_ms * 10 < u64::from(meta.orig_ttl) * 1000
            && inflight::coalescible(view)
        {
            self.spawn_refresh(raw, view.id, DnssecContext::new(view), key, ip);
        }
    }

    /// Synchronous core of the wire-only hit path: protocol and policy gates,
    /// canonical key, cache lookup, prefetch and the in-place question-case
    /// restore and UDP truncation. [`Runtime::fast_path`] is its async
    /// wrapper; the UDP receive loop calls this directly so a fresh hit is
    /// answered without a task spawn. A name the blocklist blocks for this
    /// client gets the block answer here too, built from the wire. `answer`
    /// and `scratch` are reusable caller buffers: the cache lookup and
    /// response build make no allocator call on a warm fresh non-PTR hit that
    /// matches no rewrite rule, nor on a block; PTR/`.arpa` reverse helpers
    /// and a firing prefetch can still allocate.
    ///
    /// The QR gate lives here too: the receive loop calls this before
    /// `handle_with`, so a response-shaped datagram must never be answered
    /// from the cache even though `parse_query` can read one.
    #[allow(clippy::too_many_arguments)]
    fn hit_inline(
        self: &Arc<Self>,
        raw: &[u8],
        view: &wire::QueryView<'_>,
        ip: IpAddr,
        udp: bool,
        key: &mut [u8; wire::MIN_CANONICAL_BUFFER],
        answer: &mut Vec<u8>,
        scratch: &mut Vec<u8>,
    ) -> InlineHit {
        let Some(header) = wire::header(raw) else { return InlineHit::Slow };
        if header.is_response()
            || view.opcode != u8::from(OpCode::Query)
            || view.signed
            || wire::TRANSFER_TYPES.contains(&view.qtype)
            || wire::is_meta_qtype(view.qtype)
            || view.edns_version != 0
            || view.edns_bad_ecs
            || view.qtype == u16::from(RecordType::ANY)
            || view.qname_compressed
            || !plain_wire_name(view)
        {
            return InlineHit::Slow;
        }
        let mut name = [0u8; 255];
        let Some(name_len) = wire::dotted_name(view, &mut name) else { return InlineHit::Slow };
        let name = &name[..name_len];
        if view.qclass == u16::from(DNSClass::CH) || matches!(name, b"version.bind" | b"id.server" | b"hostname.bind") {
            return InlineHit::Slow;
        }
        if view.qclass == u16::from(DNSClass::IN) {
            // `from_utf8` cannot fail for a name `plain_wire_name` accepts; a
            // non-UTF-8 name could not match a configured rewrite String.
            if std::str::from_utf8(name).is_ok_and(|name| rules::rewrite(&self.cfg.rewrites, name).is_some()) {
                return InlineHit::Slow;
            }
            if std::str::from_utf8(name)
                .is_ok_and(|name| reverse::may_answer(&self.cfg, view.qtype, name, view.edns_do))
            {
                return InlineHit::Slow;
            }
            // Check the blocklist before the MAC table so an unblocked name
            // never takes the ARP lock. Local zones (above) and special-use
            // names come before the blocklist, as in `policy`. A query with
            // records in other sections keeps the parsed path, which decides
            // whether hickory can read them at all.
            let decision = self.rules.decision_bytes(name);
            if decision.blocked
                && !self.macs.is_no_filter(ip, &self.cfg.no_filter_clients, &self.cfg.no_filter_mac_addrs)
            {
                if special_use_name(&self.cfg, name) || view.has_answer_or_authority || view.has_non_opt_additional {
                    return InlineHit::Slow;
                }
                wire::blocked_response_into(view, answer);
                return InlineHit::Blocked { len: answer.len(), list: decision.list_id };
            }
        }
        let CacheLookup::Hit(key_len, meta) = self.lookup(view, key, answer) else { return InlineHit::Slow };
        // CNAME cloaking: an answer with a blocked CNAME target, or a verdict computed
        // against older rules, needs the per-client decision of `resolve`.
        // One compare for a chained answer, nothing for any other.
        if meta.chain.as_ref().is_some_and(|c| !c.state.clear(self.rules.generation())) {
            return InlineHit::Slow;
        }
        if meta.stale {
            // The caller must await a background refresh or a serve-stale
            // timeout; never hold the receive loop for that.
            return InlineHit::NeedAsync { key_len };
        }
        self.prefetch_hit(raw, view, &key[..key_len], &meta, ip);
        self.finish_answer_into(raw, view, udp, answer, scratch)
    }

    /// Restores the client's 0x20 question case and applies the UDP payload
    /// cap without parsing the cached answer. The TC reply is built into
    /// `scratch` (or `answer` stays the client answer); neither allocates when
    /// the buffers have capacity.
    fn finish_answer_into(
        &self,
        raw: &[u8],
        view: &wire::QueryView<'_>,
        udp: bool,
        answer: &mut [u8],
        scratch: &mut Vec<u8>,
    ) -> InlineHit {
        wire::copy_question_case(raw, answer);
        // The cached copy keeps the upstream's flags; the client's reply does
        // not (RFC 1035 §4.1.1).
        wire::normalize_rd_ra(answer, view.rd);
        if !udp {
            return InlineHit::Inline(answer.len());
        }
        let limit = if view.edns_present { view.edns_payload.max(512).min(self.cfg.udp_max_payload) } else { 512 };
        if answer.len() <= usize::from(limit) {
            return InlineHit::Inline(answer.len());
        }
        // RFC 8914 §3: drop EDE options before other answer data.
        if wire::drop_ede_to_fit(answer, limit, scratch) {
            return InlineHit::Truncated(scratch.len());
        }
        match wire::truncated_response_into(view, answer, self.cfg.udp_max_payload, scratch) {
            Some(()) => InlineHit::Truncated(scratch.len()),
            None => InlineHit::Slow,
        }
    }

    /// Async wrapper over [`Runtime::hit_inline`] for `handle_with` and the
    /// existing tests. The UDP receive loop calls the synchronous core
    /// directly to answer a fresh hit without a spawn; a stale hit still takes
    /// the async `serve_stale` path here.
    async fn fast_path(
        self: &Arc<Self>,
        raw: &[u8],
        view: &wire::QueryView<'_>,
        ip: IpAddr,
        udp: bool,
    ) -> Option<Vec<u8>> {
        let mut key = [0u8; wire::MIN_CANONICAL_BUFFER];
        let mut answer = Vec::new();
        let mut scratch = Vec::new();
        match self.hit_inline(raw, view, ip, udp, &mut key, &mut answer, &mut scratch) {
            InlineHit::Inline(_) => {
                stats::count(Outcome::Cache);
                Some(answer)
            }
            InlineHit::Truncated(_) => {
                stats::count(Outcome::Cache);
                Some(scratch)
            }
            InlineHit::Blocked { list, .. } => {
                stats::count(Outcome::Blocked);
                querylog::note_list(list);
                Some(answer)
            }
            InlineHit::NeedAsync { key_len } => {
                let answer = self.serve_stale(raw, view.id, view, &key[..key_len], answer, ip).await?;
                // The refresh may have brought a blocked CNAME target.
                let answer = self.gate_answer(raw, None, view, ip, answer, Outcome::Stale);
                self.finish_answer(raw, view, answer, udp)
            }
            InlineHit::Slow => None,
        }
    }

    /// Owned-buffer form of [`Runtime::finish_answer_into`] for the async
    /// wrapper; only the slow path reaches it, so the truncation copy may
    /// allocate.
    fn finish_answer(&self, raw: &[u8], view: &wire::QueryView<'_>, mut answer: Vec<u8>, udp: bool) -> Option<Vec<u8>> {
        let mut scratch = Vec::new();
        match self.finish_answer_into(raw, view, udp, &mut answer, &mut scratch) {
            InlineHit::Inline(_) => Some(answer),
            InlineHit::Truncated(_) => Some(scratch),
            InlineHit::Blocked { .. } | InlineHit::NeedAsync { .. } | InlineHit::Slow => None,
        }
    }

    /// CNAME cloaking: the verdict on the names the Answer section of `answer` (a response
    /// to the question `qname`) leads to: `None` when it holds nothing but the
    /// query name, else whether any record owner or CNAME/DNAME target in the
    /// question's class is blocked by the rules and the queried name is not
    /// itself allowed. A flat pass, not a chain walk, so a loop, a conflict or
    /// a gap cannot hide a blocked target (fail closed). Client independent,
    /// so it can be cached per rules generation.
    fn chain_state(&self, answer: &[u8], qname: &[u8]) -> Option<cache::ChainState> {
        let mut dotted = [0u8; 255];
        let (mut seen, mut blocked) = (false, false);
        // A malformed answer is judged on the names seen before the damage.
        let _ = wire::answer_names(answer, qname, &mut |name| {
            seen = true;
            blocked = wire::dotted_target(name, &mut dotted).is_some_and(|n| self.rules.blocked_bytes(&dotted[..n]));
            blocked
        });
        if blocked {
            // An explicit allow of the queried name wins over its targets.
            blocked = !wire::dotted_target(qname, &mut dotted)
                .is_some_and(|n| self.rules.action_bytes(&dotted[..n]) == rules::Action::Allow);
        }
        seen.then(|| cache::ChainState::new(self.rules.generation(), blocked))
    }

    /// [`Runtime::chain_state`] for the query in `view`, only when the knob is
    /// on and the query is IN class.
    fn chain_blocked(&self, answer: &[u8], view: &wire::QueryView<'_>) -> bool {
        self.cfg.block_cname_targets
            && view.qclass == u16::from(DNSClass::IN)
            && self
                .chain_state(answer, &view.qname_lower[..usize::from(view.qname_len)])
                .is_some_and(cache::ChainState::blocked)
    }

    /// [`Runtime::chain_blocked`] for a cache hit: the entry's stored verdict
    /// when it is for the current rules, else recomputed and stored back on
    /// that entry so the inline path serves it again.
    fn cached_chain_blocked(&self, meta: &mut cache::HitMeta, cached: &[u8], view: &wire::QueryView<'_>) -> bool {
        let generation = self.rules.generation();
        match meta.chain.as_mut() {
            Some(chain) if chain.state.current(generation) => chain.state.blocked(),
            Some(chain) => {
                let blocked = self.chain_blocked(cached, view);
                chain.refresh(cache::ChainState::new(generation, blocked));
                blocked
            }
            None => false,
        }
    }

    /// The block answer for a client that is filtered, counted and logged
    /// as a block whose origin is a CNAME target. `None` for an exempt client.
    /// `q` is the parsed query when the caller has one; the wire-only stale
    /// path parses it here, and only for a block.
    fn cname_reply(&self, raw: &[u8], q: Option<&Message>, ip: IpAddr) -> Option<Vec<u8>> {
        if self.macs.is_no_filter(ip, &self.cfg.no_filter_clients, &self.cfg.no_filter_mac_addrs) {
            return None;
        }
        let parsed;
        let q = match q {
            Some(q) => q,
            None => {
                parsed = parse(raw)?;
                &parsed
            }
        };
        stats::count(Outcome::Blocked);
        querylog::note_list(Some(querylog::CNAME_TARGET));
        blocked_reply(q, q.queries.first()?.name().clone()).to_vec().ok()
    }

    /// Counts `outcome` and returns `answer`, unless a CNAME target blocks it
    /// for this client; then the block answer replaces it.
    fn gate_answer(
        &self,
        raw: &[u8],
        q: Option<&Message>,
        view: &wire::QueryView<'_>,
        ip: IpAddr,
        answer: Vec<u8>,
        outcome: Outcome,
    ) -> Vec<u8> {
        if self.chain_blocked(&answer, view) {
            if let Some(blocked) = self.cname_reply(raw, q, ip) {
                return blocked;
            }
        }
        stats::count(outcome);
        answer
    }

    async fn resolve(
        self: &Arc<Self>,
        raw: &[u8],
        q: &Message,
        view: &wire::QueryView<'_>,
        ip: IpAddr,
        udp: bool,
    ) -> Option<Vec<u8>> {
        q.queries.first()?;
        if let Some(local) = self.policy(q, view.edns_do, ip) {
            stats::count(local.stage.outcome());
            if let Stage::Blocked(list) = local.stage {
                querylog::note_list(list);
            }
            return local.answer.to_vec().ok();
        }
        // Cache conditions, key and hit action are shared with the inline wire
        // path (`Runtime::lookup`/`prefetch_hit`), so the filter and prefetch
        // threshold have one definition.
        let mut key_buffer = [0u8; wire::MIN_CANONICAL_BUFFER];
        let mut cached = Vec::new();
        let key_len = match self.lookup(view, &mut key_buffer, &mut cached) {
            CacheLookup::Uncacheable => None,
            CacheLookup::Miss(len) => Some(len),
            CacheLookup::Hit(len, mut meta) => {
                if meta.stale {
                    let answer = self.serve_stale(raw, view.id, view, &key_buffer[..len], cached, ip).await?;
                    return Some(self.gate_answer(raw, Some(q), view, ip, answer, Outcome::Stale));
                }
                if self.cached_chain_blocked(&mut meta, &cached, view) {
                    if let Some(blocked) = self.cname_reply(raw, Some(q), ip) {
                        return Some(blocked);
                    }
                }
                stats::count(Outcome::Cache);
                self.prefetch_hit(raw, view, &key_buffer[..len], &meta, ip);
                return Some(cached);
            }
        };
        // One leader per canonical key; identical concurrent misses wait
        // on its shared reply instead of sending their own upstream query.
        // `None` from `relay_for` means the client is over its upstream cap
        // (`upstream_inflight_per_client`). A follower starts no upstream work,
        // but over UDP it holds one of the shared UDP request permits while it
        // waits, so there it counts against the cap too; over TCP it holds
        // only its own connection's query slots.
        let context = DnssecContext { tcp: !udp, ..DnssecContext::new(view) };
        let id = q.metadata.id;
        let relayed = match key_len {
            Some(len) if inflight::coalescible(view) => {
                let key = &key_buffer[..len];
                // The slot comes first: a host over its cap only follows a
                // running flight and never opens one, which would fail at
                // once for any client that joined it meanwhile. Over UDP it
                // does not follow either: it answers TC=1 instead of waiting,
                // so it must not take one of the flight's follower places.
                let slot = self.upstream_slot(ip);
                let role = if slot.is_some() {
                    self.inflight.join(key)
                } else if !udp {
                    self.inflight.follow(key)
                } else {
                    inflight::Role::Bypass
                };
                match (role, slot) {
                    // The leader's resolution is a task of its own, so its
                    // followers (other clients, over any transport) still get
                    // the answer when this client goes away: a TCP
                    // connection's tasks end with the connection.
                    (inflight::Role::Leader(guard), Some(slot)) => {
                        Some(self.spawn_relay(raw, id, context, key, Some(guard), slot).await.ok().flatten())
                    }
                    (inflight::Role::Follower(receiver), slot) if slot.is_some() || !udp => {
                        let _slot = slot.flatten().filter(|_| udp);
                        let deadline = Duration::from_secs(self.cfg.upstream_timeout_seconds.saturating_add(1));
                        Some(inflight::wait(receiver, deadline).await.map(|shared| {
                            let mut bytes = shared.to_vec();
                            // The leader patched its own ID; this client
                            // needs its own. `handle` restores the case.
                            bytes[..2].copy_from_slice(&id.to_be_bytes());
                            bytes
                        }))
                    }
                    (inflight::Role::Bypass, Some(_slot)) => {
                        Some(self.upstream_relay(raw, id, context, Some(key)).await)
                    }
                    // Over the cap: nothing was started.
                    _ => None,
                }
            }
            _ => self.relay_for(ip, raw, id, context, key_len.map(|len| &key_buffer[..len])).await,
        };
        match relayed {
            Some(Some(relayed)) => Some(self.gate_answer(raw, Some(q), view, ip, relayed, Outcome::Upstream)),
            Some(None) => self.servfail(q),
            // Over UDP the source may be forged, so SERVFAIL (which a spoofer
            // could aim at a victim) is replaced by a TC=1 reply: a genuine
            // client retries over TCP, which proves its address and is served
            // once one of the host's slots is free.
            None if udp => {
                if !self.capped_replies.allow(ip, Instant::now()) {
                    stats::count(Outcome::Dropped);
                    return None;
                }
                stats::count(Outcome::Other);
                let mut truncated = reply(q, ResponseCode::NoError);
                truncated.metadata.truncation = true;
                truncated.to_vec().ok()
            }
            None => self.servfail(q),
        }
    }

    /// [`Runtime::upstream_relay`] under this client host's cap on
    /// upstream work in flight (`upstream_inflight_per_client`, 0 = off). One
    /// host flooding unique names cannot take every slot. `None` means the
    /// host is over its cap and nothing was started (UDP answers TC=1, TCP
    /// SERVFAIL).
    async fn relay_for(
        &self,
        ip: IpAddr,
        raw: &[u8],
        client_id: u16,
        client: DnssecContext,
        key: Option<&[u8]>,
    ) -> Option<Option<Vec<u8>>> {
        let _slot = self.upstream_slot(ip)?;
        Some(self.upstream_relay(raw, client_id, client, key).await)
    }

    /// One unit of this host's upstream work in flight: `None` when the host
    /// is over `upstream_inflight_per_client`, `Some(None)` when the cap is off.
    fn upstream_slot(&self, ip: IpAddr) -> Option<Option<ratelimit::ClientSlot>> {
        let cap = self.cfg.upstream_inflight_per_client;
        if cap == 0 {
            return Some(None);
        }
        PerClient::take(&self.fair, ip, cap).map(Some)
    }

    fn servfail(&self, q: &Message) -> Option<Vec<u8>> {
        stats::count(Outcome::Servfail);
        let mut local = reply(q, ResponseCode::NoError);
        local.metadata.response_code = ResponseCode::ServFail;
        local.to_vec().ok()
    }
}
impl Server {
    /// Admission plus one runtime generation, then the full path; the tests'
    /// entry point. The UDP receive loop and the TCP connection task load and
    /// admit once themselves, answer a fresh hit inline, and hand the same
    /// generation to [`Server::handle_admitted`] for everything else.
    #[cfg(test)]
    async fn handle(self: &Arc<Self>, raw: &[u8], ip: IpAddr, udp: bool) -> Option<Vec<u8>> {
        let runtime = self.runtime();
        let started = Instant::now();
        // The limit covers every request from this prefix, including ones a
        // local policy could answer: this is admission control, not only
        // upstream protection. Excess requests are dropped without a reply.
        if !runtime.rate.allow(ip, started) {
            log_rate_limited(&runtime, ip);
            return None;
        }
        self.handle_admitted(&runtime, raw, ip, udp, started).await
    }

    /// The parsed path for an already admitted request. `started` is the
    /// instant admission used, so `log_queries` measures the same span the
    /// inline UDP answer reports.
    async fn handle_admitted(
        self: &Arc<Self>,
        runtime: &Arc<Runtime>,
        raw: &[u8],
        ip: IpAddr,
        udp: bool,
        started: Instant,
    ) -> Option<Vec<u8>> {
        #[cfg(feature = "conformance-adapter")]
        let (answer, traced) =
            querylog::traced(sopedu_dns::upstream::track(raw, self.handle_with(runtime, raw, ip, udp))).await;
        #[cfg(not(feature = "conformance-adapter"))]
        let (answer, traced) = querylog::traced(self.handle_with(runtime, raw, ip, udp)).await;
        let elapsed = started.elapsed();
        stats::observe_request(elapsed);
        querylog::record_traced(started, elapsed, ip, raw, &traced);
        if runtime.cfg.log_queries {
            log_query(ip, raw, answer.as_deref(), elapsed);
        }
        answer
    }

    async fn handle_with(
        self: &Arc<Self>,
        runtime: &Arc<Runtime>,
        raw: &[u8],
        ip: IpAddr,
        udp: bool,
    ) -> Option<Vec<u8>> {
        let header = wire::header(raw)?;
        if header.is_response() {
            return None;
        }
        // Protocol-level rejections are answered here and counted as `other`.
        let refuse = |code: ResponseCode| {
            stats::count(Outcome::Other);
            wire::minimal_error_response(raw, u16::from(code))
        };
        // A client outside `allowed_clients` sees no cache, policy
        // or upstream, only REFUSED (never larger than its query).
        if !runtime.cfg.client_allowed(ip) {
            config::note_refused(ip);
            return refuse(ResponseCode::Refused);
        }
        // An unsupported opcode is NOTIMP before any QUERY count rule (RFC 8906 §3.1.4).
        if header.opcode != u8::from(OpCode::Query) {
            return refuse(ResponseCode::NotImp);
        }
        if header.qdcount == 0 {
            // Version negotiation comes before the empty-question rule.
            let rcode = if wire::opt_version(raw).is_some_and(|v| v != 0) {
                ResponseCode::BADVERS
            } else {
                ResponseCode::Refused
            };
            return refuse(rcode);
        }
        let Some(view) = wire::parse_query(raw) else {
            return refuse(ResponseCode::FormErr);
        };
        // RFC 6891 §6.1.3: version negotiation precedes every policy
        // answer, so an unsupported version is BADVERS even for a meta-query.
        if view.edns_version != 0 {
            return refuse(ResponseCode::BADVERS);
        }
        // RFC 7871 §6: a malformed client ECS option, after version negotiation.
        if view.edns_bad_ecs {
            return refuse(ResponseCode::FormErr);
        }
        if view.signed || wire::TRANSFER_TYPES.contains(&view.qtype) {
            // TSIG/SIG(0) needs an authentication boundary we do not implement;
            // zone transfers and TKEY are not part of a forwarder's job.
            return refuse(ResponseCode::Refused);
        }
        if view.opcode != u8::from(OpCode::Query) {
            return refuse(ResponseCode::NotImp);
        }
        if wire::is_meta_qtype(view.qtype) {
            return refuse(ResponseCode::FormErr);
        }
        // A fresh or stale cache hit is answered from the wire view alone;
        // hickory only ever runs on the slow path. Admission and logging are
        // in `handle`, outside this call, so they stay exactly once per packet.
        if let Some(answer) = runtime.fast_path(raw, &view, ip, udp).await {
            return Some(answer);
        }
        #[cfg(test)]
        self.parse_calls.fetch_add(1, Ordering::Relaxed);
        let Some(q) = parse(raw) else {
            // The wire parser accepted what hickory cannot decode (for example
            // an OPT outside the additional section); answer, do not drop.
            return refuse(ResponseCode::FormErr);
        };
        let mut answer = runtime.resolve(raw, &q, &view, ip, udp).await?;
        wire::copy_question_case(raw, &mut answer);
        // Every client reply carries the client's RD and RA=1, whatever the
        // upstream or the cached copy said (RFC 1035 §4.1.1).
        wire::normalize_rd_ra(&mut answer, view.rd);
        if udp {
            // EDNS: max(advertised, 512) capped by policy. Non-EDNS: 512.
            // TCP is never capped.
            let limit = q
                .edns
                .as_ref()
                .map_or(512, |edns| edns.max_payload().max(512).min(runtime.cfg.udp_max_payload) as usize);
            if answer.len() > limit {
                // RFC 8914 §3: drop EDE options before answer data. TC is set
                // because the response no longer carries everything received.
                let mut trimmed = Vec::new();
                if wire::drop_ede_to_fit(&answer, limit as u16, &mut trimmed) {
                    wire::copy_question_case(raw, &mut trimmed);
                    return Some(trimmed);
                }
                let parsed = Message::from_vec(&answer).ok()?;
                let mut m = reply(&q, parsed.metadata.response_code);
                m.metadata.truncation = true;
                // AD stays clear: a truncated relay is not authenticated data.
                // The full answer is already cached by `resolve`.
                // RFC 6891 §6.2.3: advertise our own size, as every reply does.
                if let Some(edns) = m.edns.as_mut() {
                    edns.set_max_payload(runtime.cfg.udp_max_payload);
                }
                let mut truncated = m.to_vec().ok()?;
                wire::copy_question_case(raw, &mut truncated);
                return Some(truncated);
            }
        }
        Some(answer)
    }

    /// Downloads and publishes one blocklist snapshot. Returns `Stale` when a
    /// reload changed the list configuration while the download ran: the
    /// caller must retry against the new generation.
    async fn refresh_lists(&self, runtime: &Arc<Runtime>) -> std::result::Result<Refreshed, String> {
        let started = Instant::now();
        // A failure here means no list, cache or inline rule is usable. Log it
        // before returning so a persistent outage is visible, not just a zero
        // rule count at startup.
        let outcome = match runtime.lists.refresh().await {
            Ok(outcome) => outcome,
            Err(error) => {
                log::log(
                    "error",
                    "blocklist_refresh_failed",
                    &[("error", error.clone()), ("retry_seconds", "60".to_string())],
                );
                return Err(error);
            }
        };
        for status in &outcome.statuses {
            if let Some(error) = &status.last_error {
                log::log("warn", "blocklist_error", &[("source", status.name.clone()), ("error", error.clone())]);
            }
        }
        let cached = outcome.statuses.iter().filter(|status| status.used_cache).count();
        let retry_soon = outcome.retry_soon;
        let rules = Arc::new(outcome.rules);
        let statuses = Arc::new(outcome.statuses);
        // Publish into the current generation when its list configuration still
        // matches the one the download ran with. Comparing and swapping in one
        // `compare_and_swap` closes the load-then-store window: a reload that
        // lands in between fails the swap instead of being overwritten.
        let applied = loop {
            let current = self.runtime.load_full();
            if !same_list_config(&current.cfg, &runtime.cfg) {
                break false;
            }
            let mut next = (*current).clone();
            next.rules = rules.clone();
            next.list_status = statuses.clone();
            let previous = self.runtime.compare_and_swap(&current, Arc::new(next));
            if Arc::ptr_eq(&*previous, &current) {
                // Free the old rule set off the async workers: dropping a
                // large snapshot here would stall the UDP receive loop.
                let old = arc_swap::Guard::into_inner(previous);
                drop(current);
                drop(tokio::task::spawn_blocking(move || drop(old)));
                break true;
            }
            // Contention is bounded by the single reload writer, but yield so
            // an unexpected second writer cannot starve this task.
            std::thread::yield_now();
        };
        log::log(
            "info",
            "blocklists",
            &[
                ("rules", rules.len().to_string()),
                ("lists", statuses.len().to_string()),
                ("cached", cached.to_string()),
                ("latency_ms", started.elapsed().as_millis().to_string()),
                ("applied", applied.to_string()),
            ],
        );
        Ok(match (applied, retry_soon) {
            (false, _) => Refreshed::Stale,
            (true, false) => Refreshed::Applied,
            (true, true) => Refreshed::Degraded,
        })
    }

    /// Publishes one new generation. When the reload did not change the list
    /// configuration, the rules and list status are taken from the generation
    /// that is current at store time: a refresh that completed during the
    /// blocking config parse must survive. The compare-and-swap closes the
    /// load-then-store window; a refresh landing in between makes it retry
    /// against the newer generation.
    fn publish(&self, runtime: Runtime, lists_changed: bool) -> Arc<Runtime> {
        if lists_changed {
            // The rules were rebuilt from disk for the new list config, so any
            // in-flight refresh is stale and is discarded by its own CAS.
            let runtime = Arc::new(runtime);
            self.runtime.store(runtime.clone());
            return runtime;
        }
        loop {
            let current = self.runtime.load_full();
            let mut next = runtime.clone();
            next.rules = current.rules.clone();
            next.list_status = current.list_status.clone();
            let next = Arc::new(next);
            let previous = self.runtime.compare_and_swap(&current, next.clone());
            if Arc::ptr_eq(&*previous, &current) {
                return next;
            }
            std::thread::yield_now();
        }
    }

    /// Loads the config and publishes one new runtime generation on success.
    /// Parse and validation errors leave the old generation untouched, so a
    /// failed reload never makes the server unready.
    async fn reload(&self, path: &Path) {
        let old = self.runtime.load_full();
        // Config parsing and the cached-list scan are blocking file work; keep
        // them off the two-worker runtime.
        let load_path = path.to_path_buf();
        let cfg = match tokio::task::spawn_blocking(move || Config::load(&load_path)).await {
            Ok(Ok(cfg)) => cfg,
            Ok(Err(error)) => {
                log::log("warn", "config_reload_failed", &[("path", path.display().to_string()), ("error", error)]);
                return;
            }
            Err(error) => {
                log::log(
                    "warn",
                    "config_reload_failed",
                    &[("path", path.display().to_string()), ("error", error.to_string())],
                );
                return;
            }
        };
        for (field, changed, old_value, new_value) in [
            ("listen", cfg.listen != old.cfg.listen, join_addrs(&old.cfg.listen), join_addrs(&cfg.listen)),
            ("ui_listen", cfg.ui_listen != old.cfg.ui_listen, old.cfg.ui_listen.to_string(), cfg.ui_listen.to_string()),
            (
                "ui_enabled",
                cfg.ui_enabled != old.cfg.ui_enabled,
                old.cfg.ui_enabled.to_string(),
                cfg.ui_enabled.to_string(),
            ),
            (
                "tcp_max_connections",
                cfg.tcp_max_connections != old.cfg.tcp_max_connections,
                old.cfg.tcp_max_connections.to_string(),
                cfg.tcp_max_connections.to_string(),
            ),
            (
                "tcp_max_connections_per_client",
                cfg.tcp_max_connections_per_client != old.cfg.tcp_max_connections_per_client,
                old.cfg.tcp_max_connections_per_client.to_string(),
                cfg.tcp_max_connections_per_client.to_string(),
            ),
            (
                "tcp_queries_per_connection",
                cfg.tcp_queries_per_connection != old.cfg.tcp_queries_per_connection,
                old.cfg.tcp_queries_per_connection.to_string(),
                cfg.tcp_queries_per_connection.to_string(),
            ),
            (
                "tcp_pipeline_max",
                cfg.tcp_pipeline_max != old.cfg.tcp_pipeline_max,
                old.cfg.tcp_pipeline_max.to_string(),
                cfg.tcp_pipeline_max.to_string(),
            ),
            (
                "tcp_idle_timeout_seconds",
                cfg.tcp_idle_timeout_seconds != old.cfg.tcp_idle_timeout_seconds,
                old.cfg.tcp_idle_timeout_seconds.to_string(),
                cfg.tcp_idle_timeout_seconds.to_string(),
            ),
            (
                "udp_inflight_max",
                cfg.udp_inflight_max != old.cfg.udp_inflight_max,
                old.cfg.udp_inflight_max.to_string(),
                cfg.udp_inflight_max.to_string(),
            ),
            (
                "udp_workers",
                cfg.udp_workers != old.cfg.udp_workers,
                old.cfg.udp_workers.to_string(),
                cfg.udp_workers.to_string(),
            ),
            (
                "udp_rcvbuf_bytes",
                cfg.udp_rcvbuf_bytes != old.cfg.udp_rcvbuf_bytes,
                old.cfg.udp_rcvbuf_bytes.to_string(),
                cfg.udp_rcvbuf_bytes.to_string(),
            ),
            (
                "udp_sndbuf_bytes",
                cfg.udp_sndbuf_bytes != old.cfg.udp_sndbuf_bytes,
                old.cfg.udp_sndbuf_bytes.to_string(),
                cfg.udp_sndbuf_bytes.to_string(),
            ),
            ("udp_batch", cfg.udp_batch != old.cfg.udp_batch, old.cfg.udp_batch.to_string(), cfg.udp_batch.to_string()),
            (
                "query_log_capacity",
                cfg.query_log_capacity != old.cfg.query_log_capacity,
                old.cfg.query_log_capacity.to_string(),
                cfg.query_log_capacity.to_string(),
            ),
            (
                "prewarm_count",
                cfg.prewarm_count > old.cfg.prewarm_count,
                old.cfg.prewarm_count.to_string(),
                cfg.prewarm_count.to_string(),
            ),
            (
                "worker_threads",
                cfg.worker_threads != old.cfg.worker_threads,
                old.cfg.worker_threads.to_string(),
                cfg.worker_threads.to_string(),
            ),
        ] {
            if changed {
                log::log(
                    "warn",
                    "restart_required",
                    &[("field", field.to_string()), ("old", old_value), ("new", new_value)],
                );
            }
        }
        let upstreams = match UpstreamPool::new(&cfg) {
            Ok(pool) => Arc::new(pool),
            Err(error) => {
                log::log(
                    "warn",
                    "config_reload_failed",
                    &[("path", path.display().to_string()), ("error", error.to_string())],
                );
                return;
            }
        };
        upstreams.inherit(&old.upstreams);
        let lists_http = match lists::client_builder().build() {
            Ok(http) => http,
            Err(error) => {
                log::log(
                    "warn",
                    "config_reload_failed",
                    &[("path", path.display().to_string()), ("error", error.to_string())],
                );
                return;
            }
        };
        let lists_changed = !same_list_config(&cfg, &old.cfg);
        let refresh_changed = cfg.refresh_hours != old.cfg.refresh_hours;
        let cache_changed = cfg.cache_size != old.cfg.cache_size
            || cfg.cache_bytes != old.cfg.cache_bytes
            || cfg.negative_ttl_min != old.cfg.negative_ttl_min
            || cfg.negative_ttl_max != old.cfg.negative_ttl_max
            // Entries carry a CNAME verdict only when the knob was on.
            || cfg.block_cname_targets != old.cfg.block_cname_targets;
        // Coalescing joins a leader whose answer is produced by the pool it
        // started with, so a change to anything upstream-affecting starts a
        // fresh map: a new generation must never consume an old pool's answer.
        let inflight_changed = cfg.upstreams != old.cfg.upstreams
            || cfg.fallback != old.cfg.fallback
            || cfg.upstream_timeout_seconds != old.cfg.upstream_timeout_seconds
            || cfg.upstream_hedge_ms != old.cfg.upstream_hedge_ms
            || cfg.upstream_strategy != old.cfg.upstream_strategy
            || cfg.upstream_0x20 != old.cfg.upstream_0x20
            || cfg.trust_plain_upstreams != old.cfg.trust_plain_upstreams
            || cfg.forward_test_names != old.cfg.forward_test_names
            || cfg.upstream_inflight_max != old.cfg.upstream_inflight_max
            || cfg.dnssec != old.cfg.dnssec;
        let lists = ListManager::new(lists_http, &cfg);
        let (rules, list_status) = if lists_changed {
            // Build from the disk cache first so blocking works immediately;
            // the refresh below replaces it with the downloaded snapshot.
            let cached_lists = lists.clone();
            match tokio::task::spawn_blocking(move || cached_lists.load_cached()).await {
                Ok(cached) => (Arc::new(cached.rules), Arc::new(cached.statuses)),
                Err(error) => {
                    log::log(
                        "warn",
                        "config_reload_failed",
                        &[("path", path.display().to_string()), ("error", error.to_string())],
                    );
                    return;
                }
            }
        } else {
            (old.rules.clone(), old.list_status.clone())
        };
        // An unrelated reload keeps the warm cache and coalescing map; only a
        // change to their settings starts a fresh one.
        // A route change also starts a fresh cache, so an old pool's
        // in-flight answer (which inserts into the cache it started with)
        // cannot populate the new generation's view.
        let cache = (!cache_changed && !inflight_changed).then(|| old.cache.clone());
        let inflight = (!inflight_changed).then(|| old.inflight.clone());
        let cache_reset = cache.is_none();
        let rate_changed =
            cfg.rate_limit_qps != old.cfg.rate_limit_qps || cfg.rate_limit_burst != old.cfg.rate_limit_burst;
        let mut next =
            Runtime::build_with(cfg, rules, list_status, upstreams, lists, cache, inflight, old.macs.clone());
        // Per-client limits are about the client, not the generation: a fresh
        // table on each reload would let a host's work still in flight under
        // the old one go uncounted and refill every bucket. The in-flight
        // table takes its cap per call and the TC limiter's rate is fixed, so
        // both always carry over; the query limiter only while its rate and
        // burst are unchanged.
        next.fair = old.fair.clone();
        next.capped_replies = old.capped_replies.clone();
        if !rate_changed {
            next.rate = old.rate.clone();
        }
        let runtime = self.publish(next, lists_changed);
        let probe = runtime.upstreams.spawn_probes();
        let previous_probe = self.probe.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).replace(probe);
        if let Some(previous_probe) = previous_probe {
            previous_probe.abort();
        }
        // The old pool may still back in-flight requests; stop its probe loop
        // now instead of waiting for the last request to release it.
        old.upstreams.stop_probes();
        if lists_changed {
            let lists = runtime.lists.clone();
            tokio::task::spawn_blocking(move || lists.remove_unconfigured_lists());
        }
        if lists_changed || refresh_changed {
            self.refresh_now.notify_one();
        }
        log::log(
            "info",
            "config_reloaded",
            &[
                ("path", path.display().to_string()),
                ("cache_reset", cache_reset.to_string()),
                ("lists_changed", lists_changed.to_string()),
            ],
        );
    }
}

/// The config fields that determine the blocklist snapshot. A refresh may
/// publish into a newer generation only when these still match the generation
/// it downloaded with.
fn same_list_config(a: &Config, b: &Config) -> bool {
    a.blocklists == b.blocklists
        && a.user_rules == b.user_rules
        && a.state_dir == b.state_dir
        && a.blocklist_max_bytes == b.blocklist_max_bytes
        && a.blocklist_max_lines == b.blocklist_max_lines
        && a.blocklist_max_rules_total == b.blocklist_max_rules_total
}

/// Admission refusal line, shared by the TCP path and the UDP receive loop.
/// Sampled at the first drop and then every 1000th.
fn log_rate_limited(runtime: &Runtime, ip: IpAddr) {
    stats::count(Outcome::Dropped);
    let dropped = runtime.rate.dropped();
    if dropped == 1 || dropped.is_multiple_of(1000) {
        log::log(
            "warn",
            "rate_limited",
            &[
                ("client", ip.to_string()),
                ("qps", runtime.cfg.rate_limit_qps.to_string()),
                ("dropped", dropped.to_string()),
            ],
        );
    }
}

/// Structured per-query line, emitted only with `log_queries = true`.
fn log_query(ip: IpAddr, raw: &[u8], answer: Option<&[u8]>, latency: Duration) {
    // Only called when logging is enabled, so the re-parse and its allocations
    // never touch the hot path. Presentation format, not wire label bytes.
    let message = Message::from_vec(raw).ok();
    let question = message.as_ref().and_then(|message| message.queries.first());
    let qname = question.map_or_else(
        || "-".to_string(),
        |query| {
            let name = query.name().to_ascii();
            match name.strip_suffix('.').unwrap_or(&name) {
                "" => ".".to_string(),
                name => name.to_string(),
            }
        },
    );
    let qtype = question.map_or_else(|| "-".to_string(), |query| format!("{:?}", query.query_type()));
    let result = answer
        .and_then(|answer| Message::from_vec(answer).ok())
        .map_or_else(|| "drop".to_string(), |message| format!("{:?}", message.metadata.response_code));
    log::log(
        "info",
        "query",
        &[
            ("client", ip.to_string()),
            ("qname", qname),
            ("qtype", qtype),
            ("result", result),
            ("latency_us", latency.as_micros().to_string()),
        ],
    );
}

#[derive(Clone, PartialEq, Eq)]
struct ConfigStamp {
    mtime: Option<SystemTime>,
    len: u64,
    inode: u64,
    link_mtime: Option<SystemTime>,
    link_len: u64,
    link_inode: u64,
}

/// Metadata identity of the config file and its symlink. A ConfigMap update
/// swaps the symlink to a new directory, which changes the target inode.
fn config_stamp(path: &Path) -> Option<ConfigStamp> {
    let target = std::fs::metadata(path).ok()?;
    let link = std::fs::symlink_metadata(path).ok()?;
    Some(ConfigStamp {
        mtime: target.modified().ok(),
        len: target.len(),
        inode: inode(&target),
        link_mtime: link.modified().ok(),
        link_len: link.len(),
        link_inode: inode(&link),
    })
}

#[cfg(unix)]
fn inode(metadata: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    metadata.ino()
}

#[cfg(not(unix))]
fn inode(_metadata: &std::fs::Metadata) -> u64 {
    0
}

/// SIGHUP plus metadata polling. One task owns every reload, so reloads are
/// serialized; a failed load keeps the old generation and logs the error.
/// Installs the SIGHUP handler. Called before the listeners bind: a SIGHUP
/// that arrives before a handler exists takes the default action and kills
/// the process. Without it, the loop still polls the file.
#[cfg(unix)]
fn sighup() -> Option<tokio::signal::unix::Signal> {
    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        .inspect_err(|error| log::log("error", "sighup_setup_failed", &[("error", error.to_string())]))
        .ok()
}

async fn reload_loop(server: Arc<Server>, path: PathBuf, #[cfg(unix)] mut hup: Option<tokio::signal::unix::Signal>) {
    let mut poll = tokio::time::interval(CONFIG_POLL_INTERVAL);
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    poll.tick().await; // consume the immediate first tick
    #[cfg(unix)]
    {
        let mut stamp = config_stamp(&path);
        loop {
            let hangup = async {
                match hup.as_mut() {
                    Some(signal) => signal.recv().await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                _ = hangup => {
                    stamp = config_stamp(&path);
                    server.reload(&path).await;
                }
                _ = poll.tick() => {
                    let next = config_stamp(&path);
                    if next != stamp {
                        stamp = next;
                        server.reload(&path).await;
                    }
                }
            }
        }
    }
    #[cfg(not(unix))]
    {
        let mut stamp = config_stamp(&path);
        loop {
            poll.tick().await;
            let next = config_stamp(&path);
            if next != stamp {
                stamp = next;
                server.reload(&path).await;
            }
        }
    }
}

/// Refreshes blocklists immediately at startup and then on the configured
/// interval, or sooner when a reload changed the list configuration or
/// `refresh_hours`. A stale or failed refresh is retried promptly; a refresh
/// in which some list failed is retried with a doubling back-off.
async fn refresh_loop(server: Arc<Server>, mut first_sleep: Duration) {
    let mut degraded = 0u32;
    loop {
        if !first_sleep.is_zero() {
            // The startup path already refreshed once before serving.
            tokio::select! {
                _ = sleep(std::mem::take(&mut first_sleep)) => {}
                _ = server.refresh_now.notified() => {}
            }
        }
        let runtime = server.runtime();
        let result = server.refresh_lists(&runtime).await;
        // The snapshot applied to whatever generation is current now; read its
        // interval in case a reload changed `refresh_hours`.
        let interval = Duration::from_secs(server.runtime().cfg.refresh_hours.saturating_mul(3600));
        let wait = match result {
            Ok(Refreshed::Applied) => {
                degraded = 0;
                interval
            }
            // A list failed (an outage at boot, a refused body): try again
            // well before the next interval, backing off while it persists.
            Ok(Refreshed::Degraded) => {
                let wait = LIST_RETRY.saturating_mul(1 << degraded.min(16)).min(interval);
                degraded = degraded.saturating_add(1);
                wait
            }
            // A reload changed the list configuration mid-download: retry now
            // against the new generation instead of sleeping a full interval.
            Ok(Refreshed::Stale) => Duration::ZERO,
            Err(_) => LIST_RETRY,
        };
        if wait.is_zero() {
            continue;
        }
        tokio::select! {
            _ = sleep(wait) => {}
            _ = server.refresh_now.notified() => {}
        }
    }
}
/// At most this many pre-warm queries in flight, started at most
/// `PREWARM_QPS` per second, so a cold start never floods the upstreams.
const PREWARM_INFLIGHT: usize = 8;
const PREWARM_QPS: u64 = 50;
/// A crash or kill keeps the list at most this old.
const PREWARM_SAVE_INTERVAL: Duration = Duration::from_secs(600);

impl Server {
    /// Writes `state_dir/prewarm.txt` from the query log's pre-warm tracker.
    fn save_prewarm(&self) {
        let runtime = self.runtime();
        let cfg = &runtime.cfg;
        let Some(log) = querylog::get().filter(|_| cfg.prewarm) else { return };
        if let Err(error) = prewarm::save(&cfg.state_dir, &log.prewarm_names(cfg.prewarm_count)) {
            log::log("warn", "prewarm_save_failed", &[("error", error.to_string())]);
        }
    }

    /// One pre-warm lookup through the normal resolution path (policy, cache,
    /// single-flight, upstream relay), so the answer is cached exactly as a
    /// client query would cache it. The query carries EDNS without DO, like a
    /// modern stub resolver, because the cache key includes the EDNS flag.
    /// It skips admission and `handle_admitted`, and runs [`querylog::quiet`],
    /// so nothing reaches the client stats, the query log or the top lists.
    async fn prewarm_one(&self, name: &str, qtype: RecordType) {
        let Ok(name) = Name::from_ascii(format!("{name}.")) else { return };
        let mut query = Message::new(0, MessageType::Query, OpCode::Query);
        query.metadata.recursion_desired = true;
        query.add_query(hickory_proto::op::Query::query(name, qtype));
        let mut edns = hickory_proto::op::Edns::new();
        edns.set_max_payload(1232);
        query.set_edns(edns);
        let Ok(raw) = query.to_vec() else { return };
        let (Some(view), Some(parsed)) = (wire::parse_query(&raw), parse(&raw)) else { return };
        let runtime = self.runtime();
        let client = IpAddr::from(std::net::Ipv4Addr::UNSPECIFIED);
        querylog::quiet(runtime.resolve(&raw, &parsed, &view, client, true)).await;
    }
}

/// Reads the saved list and resolves A and AAAA for each name. Ends early when
/// a reload turns `prewarm` off.
async fn prewarm_loop(server: Arc<Server>) {
    let cfg = server.runtime().cfg.clone();
    let names = prewarm::load(&cfg.state_dir, cfg.prewarm_count);
    if names.is_empty() {
        return;
    }
    log::log("info", "prewarm_started", &[("names", names.len().to_string())]);
    let permits = Arc::new(Semaphore::new(PREWARM_INFLIGHT));
    let mut pace = tokio::time::interval(Duration::from_millis(1000 / PREWARM_QPS));
    pace.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut tasks = JoinSet::new();
    'names: for name in names {
        for qtype in [RecordType::A, RecordType::AAAA] {
            pace.tick().await;
            if !server.runtime().cfg.prewarm {
                break 'names;
            }
            let Ok(permit) = permits.clone().acquire_owned().await else { break 'names };
            let (server, name) = (server.clone(), name.clone());
            tasks.spawn(async move {
                let _permit = permit;
                server.prewarm_one(&name, qtype).await;
            });
        }
    }
    while tasks.join_next().await.is_some() {}
    log::log("info", "prewarm_done", &[]);
}

/// Saves the pre-warm list every [`PREWARM_SAVE_INTERVAL`]; shutdown saves it
/// once more.
async fn prewarm_saver(server: Arc<Server>) {
    let start = tokio::time::Instant::now() + PREWARM_SAVE_INTERVAL;
    let mut tick = tokio::time::interval_at(start, PREWARM_SAVE_INTERVAL);
    loop {
        tick.tick().await;
        server.save_prewarm();
    }
}

/// The stats snapshot is rewritten this often; a crash loses at most this much.
const STATS_SAVE_INTERVAL: Duration = Duration::from_secs(300);

/// Writes (or, after a reload set `persist_stats = false`, deletes) the stats
/// snapshot on the blocking pool.
async fn save_stats(server: &Server) {
    let (dir, on) = {
        let runtime = server.runtime();
        (runtime.cfg.state_dir.clone(), runtime.cfg.persist_stats)
    };
    let counts = server.runtime().upstreams.counters();
    let _ = tokio::task::spawn_blocking(move || stats_store::write_current(&dir, on, counts)).await;
}

async fn stats_saver(server: Arc<Server>) {
    let start = tokio::time::Instant::now() + STATS_SAVE_INTERVAL;
    let mut tick = tokio::time::interval_at(start, STATS_SAVE_INTERVAL);
    loop {
        tick.tick().await;
        save_stats(&server).await;
    }
}

/// SIGTERM/SIGINT receivers. `new` registers the handlers synchronously, so it
/// must run before readiness: a signal in the startup window must not hit the
/// default disposition. The same instance is selected again during the drain,
/// where a second signal aborts it.
struct Signals {
    #[cfg(unix)]
    term: tokio::signal::unix::Signal,
    #[cfg(unix)]
    interrupt: tokio::signal::unix::Signal,
}

impl Signals {
    fn new() -> Self {
        #[cfg(unix)]
        {
            Self {
                term: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("SIGTERM handler"),
                interrupt: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                    .expect("SIGINT handler"),
            }
        }
        #[cfg(not(unix))]
        {
            Self {}
        }
    }

    async fn recv(&mut self) {
        #[cfg(feature = "conformance-adapter")]
        tokio::select! {
            _ = self.os_signal() => {}
            _ = adapter::shutdown_requested() => {}
        }
        #[cfg(not(feature = "conformance-adapter"))]
        self.os_signal().await;
    }

    async fn os_signal(&mut self) {
        #[cfg(unix)]
        {
            tokio::select! {
                _ = self.term.recv() => {}
                _ = self.interrupt.recv() => {}
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
}

/// ErrorKind has no stable variant for these resource limits: EMFILE, ENFILE
/// and ENOBUFS. The numbers are the Unix ones (Linux differs for ENOBUFS).
#[cfg(any(target_os = "linux", target_os = "android"))]
const RESOURCE_ERRNOS: [i32; 3] = [24, 23, 105];
#[cfg(not(any(target_os = "linux", target_os = "android")))]
const RESOURCE_ERRNOS: [i32; 3] = [24, 23, 55];

/// Accept/recv errors that must not end the process: resource pressure and
/// aborted connections are transient. Anything else is fatal.
fn transient_socket_error(error: &std::io::Error) -> bool {
    if matches!(
        error.kind(),
        std::io::ErrorKind::Interrupted
            | std::io::ErrorKind::WouldBlock
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::OutOfMemory
    ) {
        return true;
    }
    cfg!(unix) && error.raw_os_error().is_some_and(|errno| RESOURCE_ERRNOS.contains(&errno))
}

/// Bytes of one TCP frame received so far. A `select!` branch can be dropped
/// while another completes, so partial input is kept here: `read` is
/// cancel-safe, and every byte it returned is stored before the next await.
#[derive(Default)]
struct FrameRead {
    length: [u8; 2],
    length_have: usize,
    body: Vec<u8>,
    body_have: usize,
}

/// Reads exactly one length-prefixed DNS frame. The length prefix fixes the
/// body allocation before any body byte is read, so a frame is at most 65535
/// bytes. Bytes past the current frame stay in the caller's read buffer.
async fn read_frame<R: AsyncRead + Unpin>(read: &mut R, state: &mut FrameRead) -> std::io::Result<Vec<u8>> {
    while state.length_have < 2 {
        let n = read.read(&mut state.length[state.length_have..]).await?;
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        state.length_have += n;
    }
    let len = usize::from(u16::from_be_bytes(state.length));
    if len < 12 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "frame shorter than a DNS header"));
    }
    if state.body.is_empty() {
        state.body = vec![0u8; len];
    }
    while state.body_have < len {
        let n = read.read(&mut state.body[state.body_have..]).await?;
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        state.body_have += n;
    }
    let raw = std::mem::take(&mut state.body);
    *state = FrameRead::default();
    Ok(raw)
}

/// Sets `TCP_NODELAY` on an accepted socket. Extracted so a test can assert
/// the option through the same call the accept loop uses.
fn enable_tcp_nodelay(stream: &TcpStream) -> std::io::Result<()> {
    stream.set_nodelay(true)
}

/// A connection stops reading new queries while its finished but unwritten
/// answers exceed this many bytes, so a client that never reads cannot make the
/// server buffer without bound.
const TCP_UNWRITTEN_CAP: usize = 128 * 1024;

/// Whether a TCP connection may read another frame: not stopping, below the
/// query and pipeline bounds, and within the unwritten-output budget.
/// Known limit: queries already admitted when the budget trips still finish, so
/// the ceiling is the budget plus `pipeline_max` answers (16 x 64 KiB), held
/// at most one idle timeout before a blocked write closes the connection;
/// with `tcp_max_connections_per_client` (32) one host pins about 32 MiB.
/// Reserving bytes up front needs the answer size before resolution. The
/// connection's own buffers add at most about 150 KiB: the read buffer, one
/// inline answer and one write batch plus its last answer.
fn tcp_can_read(
    stopping: bool,
    accepted: usize,
    max_queries: usize,
    in_flight: usize,
    pipeline_max: usize,
    unwritten: usize,
) -> bool {
    !stopping && accepted < max_queries && in_flight < pipeline_max && unwritten <= TCP_UNWRITTEN_CAP
}

/// One TCP connection. A fresh cache hit is answered on the connection task
/// itself, as the UDP receive loop does; up to `pipeline_max` other frames
/// are resolved concurrently in their own tasks. Answers are written as they
/// complete, so replies may be out of order (RFC 7766 §7), and every answer
/// ready at once leaves in one write. At most `max_queries` frames are
/// accepted; reading pauses while the pipeline is full (backpressure), which
/// also bounds memory to one frame per slot. The two-byte length prefix
/// selects the body size before it is allocated. A read error, EOF, idle
/// timeout or rejected query stops new reads but still writes the answers
/// already in flight, like the serial loop did; only a panicking task or a
/// write error closes immediately. Frames read past the query cap are not
/// answered. Except after a write error the connection ends with a FIN and
/// a short drain of the input, never a reset (see the end of the function).
///
/// The idle timeout bounds only waiting for the next frame (or the remainder
/// of a partial frame) when no query is in flight, plus a stalled write. Once
/// a query is in flight the connection is active work under the upstream
/// deadline; a slow query is never cut by the idle timeout. `shutdown` stops
/// new reads and drains the in-flight queries within the caller's drain bound.
async fn serve_tcp(
    server: Arc<Server>,
    stream: TcpStream,
    peer: std::net::SocketAddr,
    idle: Duration,
    max_queries: usize,
    pipeline_max: usize,
    mut shutdown: watch::Receiver<bool>,
) {
    if enable_tcp_nodelay(&stream).is_err() {
        return;
    }
    let (reader, mut writer) = stream.into_split();
    // Pipelined frames arrive back to back, so one read usually holds many;
    // the buffer turns two reads per frame into one per burst.
    let mut reader = BufReader::with_capacity(TCP_READ_BUFFER, reader);
    let mut in_flight: JoinSet<Option<Vec<u8>>> = JoinSet::new();
    let mut frame = FrameRead::default();
    let mut accepted = 0usize;
    let mut stopping = false;
    // Bytes of answers finished by a task but not yet written.
    let unwritten = Arc::new(AtomicUsize::new(0));
    // Framed answers waiting for the next write. One task owns the write half,
    // so complete frames are serialized and never interleave.
    let mut out = Vec::new();
    let mut hit = TcpHitBuffers::default();
    'conn: loop {
        let can_read = tcp_can_read(
            stopping,
            accepted,
            max_queries,
            in_flight.len(),
            pipeline_max,
            unwritten.load(Ordering::Relaxed),
        );
        if !can_read && in_flight.is_empty() {
            break;
        }
        // No query in flight means the connection is idle: the wait for the
        // next frame is bounded by the idle timeout. Partial bytes do not
        // renew it because the same `timeout` wraps the whole frame read.
        let idle_wait = in_flight.is_empty();
        tokio::select! {
            _ = shutdown.changed(), if !stopping => {
                stopping = true;
            }
            joined = in_flight.join_next(), if !in_flight.is_empty() => {
                let mut joined = joined;
                // Every answer already finished joins the same write, so a
                // burst leaves in one send instead of one per answer.
                while let Some(result) = joined {
                    match result {
                        Ok(Some(answer)) => {
                            unwritten.fetch_sub(answer.len(), Ordering::Relaxed);
                            if !push_frame(&mut out, &answer) {
                                break 'conn;
                            }
                        }
                        // `handle_admitted` returns None for a malformed or
                        // response-flagged query; the serial loop closed the
                        // connection then, but sibling answers already in
                        // flight are still written.
                        Ok(None) => stopping = true,
                        // A panicking task cannot produce answers.
                        Err(_) => break 'conn,
                    }
                    joined = if out.len() < TCP_WRITE_BATCH { in_flight.try_join_next() } else { None };
                }
            }
            raw = async {
                if idle_wait {
                    timeout(idle, read_frame(&mut reader, &mut frame)).await.ok()
                } else {
                    Some(read_frame(&mut reader, &mut frame).await)
                }
            }, if can_read => {
                match raw {
                    Some(Ok(raw)) => {
                        accepted += 1;
                        let ip = peer.ip();
                        match tcp_query_inline(&server, &raw, ip, &mut hit) {
                            TcpQuery::Answered(answer) => {
                                if !push_frame(&mut out, answer) {
                                    break 'conn;
                                }
                            }
                            // Rate limited: no reply, and no further reads, as
                            // for a malformed query.
                            TcpQuery::Dropped => stopping = true,
                            TcpQuery::Spawn(runtime, started) => {
                                #[cfg(test)]
                                server.tcp_spawns.fetch_add(1, Ordering::Relaxed);
                                let server = server.clone();
                                let unwritten = unwritten.clone();
                                in_flight.spawn(async move {
                                    let answer = server.handle_admitted(&runtime, &raw, ip, false, started).await;
                                    if let Some(answer) = &answer {
                                        unwritten.fetch_add(answer.len(), Ordering::Relaxed);
                                    }
                                    answer
                                });
                            }
                        }
                    }
                    // EOF, a read error, a framing error or the idle timeout
                    // stops new reads; the answers already in flight are still
                    // written before the loop exits.
                    _ => stopping = true,
                }
            }
        }
        // Hold the answers while the next query is already buffered and may
        // be read now: it is handled without waiting, and the write that
        // follows carries both.
        let next_ready = frame.length_have == 0
            && frame_buffered(reader.buffer())
            && tcp_can_read(
                stopping,
                accepted,
                max_queries,
                in_flight.len(),
                pipeline_max,
                unwritten.load(Ordering::Relaxed),
            );
        if !out.is_empty() && (out.len() >= TCP_WRITE_BATCH || !next_ready) {
            if !matches!(timeout(idle, writer.write_all(&out)).await, Ok(Ok(()))) {
                return;
            }
            out.clear();
        }
    }
    // Close without a reset: a close with unread input (frames past the
    // query cap, after a rejected query or still arriving) makes the kernel
    // send RST, and the client may then lose answers it has not read yet.
    // Send FIN after the last answer and discard input until the client
    // closes too, for a short bounded time; the client retries any query
    // left unanswered (RFC 7766 §6.2.4).
    if matches!(timeout(idle, writer.shutdown()).await, Ok(Ok(()))) {
        let _ = timeout(idle.min(TCP_CLOSE_LINGER), tokio::io::copy(&mut reader, &mut tokio::io::sink())).await;
    }
}

/// How long a closing TCP connection keeps reading (and discarding) input
/// after its FIN, so the close is not a reset.
const TCP_CLOSE_LINGER: Duration = Duration::from_secs(1);

/// Reusable per-connection buffers for [`tcp_query_inline`].
struct TcpHitBuffers {
    key: [u8; wire::MIN_CANONICAL_BUFFER],
    answer: Vec<u8>,
    scratch: Vec<u8>,
}

impl Default for TcpHitBuffers {
    fn default() -> Self {
        Self { key: [0u8; wire::MIN_CANONICAL_BUFFER], answer: Vec::new(), scratch: Vec::new() }
    }
}

/// What the connection task did with one TCP query.
enum TcpQuery<'a> {
    /// A fresh cache hit, answered on the connection task.
    Answered(&'a [u8]),
    /// Refused by the rate limiter; nothing is sent.
    Dropped,
    /// Admitted but not a fresh hit: resolve it in its own task.
    Spawn(Arc<Runtime>, Instant),
}

/// Admission and the fresh-hit path for one TCP query, run on the connection
/// task like the UDP receive loop runs them: one runtime load, one rate-limit
/// check, then [`Runtime::hit_inline`]. A hit costs no task spawn and is
/// counted and logged as the UDP inline hit is; a stale hit, a miss, local
/// policy or a malformed query is handed back for the spawned
/// [`Server::handle_admitted`] path with the same admission.
fn tcp_query_inline<'a>(server: &Arc<Server>, raw: &[u8], ip: IpAddr, hit: &'a mut TcpHitBuffers) -> TcpQuery<'a> {
    let started = Instant::now();
    let runtime = server.runtime();
    if !runtime.rate.allow(ip, started) {
        log_rate_limited(&runtime, ip);
        return TcpQuery::Dropped;
    }
    let Some(view) = wire::parse_query(raw).filter(|_| runtime.cfg.client_allowed(ip)) else {
        return TcpQuery::Spawn(runtime, started);
    };
    #[cfg(feature = "conformance-adapter")]
    let result = sopedu_dns::upstream::track_sync(raw, || {
        runtime.hit_inline(raw, &view, ip, false, &mut hit.key, &mut hit.answer, &mut hit.scratch)
    });
    #[cfg(not(feature = "conformance-adapter"))]
    let result = runtime.hit_inline(raw, &view, ip, false, &mut hit.key, &mut hit.answer, &mut hit.scratch);
    let (answer, outcome, list) = match result {
        InlineHit::Inline(len) => (&hit.answer[..len], Outcome::Cache, None),
        InlineHit::Truncated(len) => (&hit.scratch[..len], Outcome::Cache, None),
        InlineHit::Blocked { len, list } => (&hit.answer[..len], Outcome::Blocked, list),
        InlineHit::NeedAsync { .. } | InlineHit::Slow => return TcpQuery::Spawn(runtime, started),
    };
    let latency = started.elapsed();
    stats::inline_hit(outcome, latency);
    querylog::record(
        started,
        latency,
        &querylog::Record {
            ip,
            qname: &view.qname_lower[..usize::from(view.qname_len)],
            qtype: view.qtype,
            outcome,
            upstream: querylog::NO_UPSTREAM,
            list,
        },
    );
    if runtime.cfg.log_queries {
        log_query(ip, raw, Some(answer), latency);
    }
    TcpQuery::Answered(answer)
}

/// Read buffer per TCP connection: room for dozens of pipelined queries, and
/// 1 MiB across the default 256 connections.
const TCP_READ_BUFFER: usize = 4 * 1024;

/// Whether `buffered`, starting at a frame boundary, holds a whole frame.
fn frame_buffered(buffered: &[u8]) -> bool {
    match buffered {
        [hi, lo, body @ ..] => body.len() >= usize::from(u16::from_be_bytes([*hi, *lo])),
        _ => false,
    }
}

/// Answers coalesced into one TCP write stop growing at this size; the rest
/// wait for the next write. Bounds the copy, not the answers already held.
const TCP_WRITE_BATCH: usize = 16 * 1024;

/// Appends one answer with its two-byte length prefix (RFC 7766 §8). False
/// when the answer cannot be framed, which closes the connection.
fn push_frame(out: &mut Vec<u8>, answer: &[u8]) -> bool {
    let Ok(length) = u16::try_from(answer.len()) else { return false };
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(answer);
    true
}

/// Builds one non-blocking UDP socket through `socket2`. `SO_REUSEPORT` and
/// the non-zero kernel buffers are set before bind, so one socket and the
/// worker path are configured identically. The configured buffer size is a
/// request, not a guaranteed read-back: Linux normally reserves and reports
/// about twice it, and every kernel clamps to its socket-buffer maximum.
fn bind_udp_socket(
    addr: SocketAddr,
    reuse_port: bool,
    rcvbuf_bytes: usize,
    sndbuf_bytes: usize,
) -> std::io::Result<std::net::UdpSocket> {
    let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    // Explicit, never the sysctl default: `[::]:53` beside `0.0.0.0:53` must
    // not collide, and a v6 socket must not also answer v4 on its own.
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    #[cfg(unix)]
    if reuse_port {
        socket.set_reuse_port(true)?;
    }
    #[cfg(not(unix))]
    let _ = reuse_port;
    if rcvbuf_bytes != 0 {
        socket.set_recv_buffer_size(rcvbuf_bytes)?;
    }
    if sndbuf_bytes != 0 {
        socket.set_send_buffer_size(sndbuf_bytes)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    Ok(socket.into())
}

/// The TCP twin of [`bind_udp_socket`]: tokio's `bind` leaves IPV6_V6ONLY to
/// the system default, so the socket is built by hand (same address reuse and
/// backlog as tokio's).
fn bind_tcp_listener(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    #[cfg(unix)]
    socket.set_reuse_address(true)?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    TcpListener::from_std(socket.into())
}

fn join_addrs(addrs: &[SocketAddr]) -> String {
    addrs.iter().map(ToString::to_string).collect::<Vec<_>>().join(",")
}

/// One accept loop per TCP listener; accepted connections go to the main loop,
/// which does admission and owns the connection tasks.
async fn tcp_accept_loop(listener: TcpListener, accepted: mpsc::Sender<std::io::Result<(TcpStream, SocketAddr)>>) {
    loop {
        match listener.accept().await {
            Ok(connection) => {
                if accepted.send(Ok(connection)).await.is_err() {
                    return;
                }
            }
            Err(error) if transient_socket_error(&error) => {
                log::log("warn", "tcp_accept_failed", &[("error", error.to_string())]);
                sleep(LISTENER_RETRY_BACKOFF).await;
            }
            Err(error) => {
                let _ = accepted.send(Err(error)).await;
                return;
            }
        }
    }
}

/// One UDP receive loop over one socket. Each worker owns its receive and
/// response buffers and its own slow-path task set, so no two workers share a
/// loop or a drain. Admission, the semaphore, rate limiter, runtime and
/// counters are shared with every other worker and are exactly the unbatched flow.
async fn udp_worker(
    server: Arc<Server>,
    socket: Arc<UdpSocket>,
    permits: Arc<Semaphore>,
    inflight_max: usize,
    udp_batch: usize,
    pktinfo: bool,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    // Only Linux has the batched syscalls. A non-Linux build was already
    // warned at startup and receives 0 here, so this branch never applies.
    #[cfg(target_os = "linux")]
    if udp_batch > 0 {
        return udp_worker_batched(server, socket, permits, inflight_max, udp_batch, pktinfo, shutdown).await;
    }
    #[cfg(not(target_os = "linux"))]
    let _ = udp_batch;
    let mut tasks = JoinSet::new();
    let mut buf = vec![0u8; 65535];
    // One reusable set per receive loop. A warm fresh hit writes into
    // these buffers with no allocator call; they grow once if a cached answer
    // exceeds the UDP payload ceiling.
    let mut buffers = UdpReplyBuffers::new(usize::from(server.runtime().cfg.udp_max_payload));
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
            r = recv_datagram(&socket, &mut buf, pktinfo) => {
                let (n, peer, local) = match r {
                    Ok(value) => value,
                    Err(error) if transient_socket_error(&error) => {
                        log::log("warn", "udp_recv_failed", &[("error", error.to_string())]);
                        sleep(LISTENER_RETRY_BACKOFF).await;
                        continue;
                    }
                    Err(error) => return Err(error.into()),
                };
                if let Some(reply) =
                    buffers.handle(&server, &socket, &permits, inflight_max, &mut tasks, &buf[..n], peer, local)
                {
                    let served = buffers.reply(&reply);
                    #[cfg(feature = "conformance-adapter")]
                    server.packets.attempted();
                    send_reply(&socket, served, peer, local).await;
                    #[cfg(feature = "conformance-adapter")]
                    server.packets.completed();
                    reply.log(peer, &buf[..n], served);
                }
            }
        }
    }
    while tasks.join_next().await.is_some() {}
    Ok(())
}

/// Linux path: one `recvmmsg` wake yields up to `udp_batch` datagrams,
/// each processed by the same per-datagram flow as the unbatched loop. Every
/// reply, including an inline hit, goes out with the async `send_to`, which
/// awaits writability and reports each send; `sendmmsg` was evaluated and
/// rejected because nix's safe API cannot report a partial send. Each datagram
/// is read into a 64 KiB slot, the same limit as the single-datagram path; one
/// that does not fit is dropped and counted in the server-wide `udp_truncated`
/// total.
#[cfg(target_os = "linux")]
async fn udp_worker_batched(
    server: Arc<Server>,
    socket: Arc<UdpSocket>,
    permits: Arc<Semaphore>,
    inflight_max: usize,
    udp_batch: usize,
    pktinfo: bool,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let mut tasks = JoinSet::new();
    let mut buffers = UdpReplyBuffers::new(usize::from(server.runtime().cfg.udp_max_payload));
    let mut recv = udp_batch::RecvBatch::new(udp_batch);
    if pktinfo {
        recv = recv.with_pktinfo();
    }
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
            r = udp_batch::recv_batch(&socket, &mut recv, &server.udp_truncated) => {
                let received = match r {
                    Ok(value) => value,
                    Err(error) if transient_socket_error(&error) => {
                        log::log("warn", "udp_recv_failed", &[("error", error.to_string())]);
                        sleep(LISTENER_RETRY_BACKOFF).await;
                        continue;
                    }
                    Err(error) => return Err(error.into()),
                };
                for slot in 0..received {
                    // `readable()`, `try_io` and the inline reply's `try_send`
                    // never spend Tokio's cooperative budget, so under a
                    // steady flood this loop would never yield: with one
                    // worker thread the spawned slow-path tasks, the IO
                    // driver and the timers would wait until the socket ran
                    // dry, for seconds at saturation. One unit per datagram
                    // yields every 128 datagrams, like the unbatched loop,
                    // whose `recv_from` spends one per call.
                    tokio::task::coop::consume_budget().await;
                    let Some((datagram, peer)) = recv.datagram(slot) else { continue };
                    let local = recv.local(slot);
                    let Some(reply) =
                        buffers.handle(&server, &socket, &permits, inflight_max, &mut tasks, datagram, peer, local)
                    else {
                        continue;
                    };
                    let served = buffers.reply(&reply);
                    #[cfg(feature = "conformance-adapter")]
                    server.packets.attempted();
                    send_reply(&socket, served, peer, local).await;
                    #[cfg(feature = "conformance-adapter")]
                    server.packets.completed();
                    reply.log(peer, datagram, served);
                }
            }
        }
    }
    while tasks.join_next().await.is_some() {}
    Ok(())
}

/// One datagram and, on a pktinfo (wildcard) socket, its destination address.
/// A specific-address socket takes the plain `recv_from`: `local` is `None`.
#[inline]
async fn recv_datagram(
    socket: &UdpSocket,
    buf: &mut [u8],
    pktinfo: bool,
) -> std::io::Result<(usize, SocketAddr, Option<IpAddr>)> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if pktinfo {
        return udp_pktinfo::recv_from(socket, buf).await;
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let _ = pktinfo;
    let (n, peer) = socket.recv_from(buf).await?;
    Ok((n, peer, None))
}

/// Sends one reply. With a known destination `local` (wildcard bind) the reply
/// goes out from that address (RFC 8085 5.1); if that send fails, or there is
/// no `local`, it is the plain `send_to` of a specific-address socket.
#[inline]
async fn send_reply(socket: &UdpSocket, data: &[u8], peer: SocketAddr, local: Option<IpAddr>) {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if let Some(local) = local {
        if udp_pktinfo::send_from(socket, data, peer, local).await.is_ok() {
            return;
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let _ = local;
    // Try the send first: the socket is almost always writable, and skipping
    // the readiness await is +6% hit throughput on Linux.
    if let Err(error) = socket.try_send_to(data, peer) {
        if error.kind() == std::io::ErrorKind::WouldBlock {
            let _ = socket.send_to(data, peer).await;
        }
    }
}

/// Whether this bind needs the destination-address handling: only a wildcard
/// address can leave the reply's source to the kernel's routing choice.
fn effective_pktinfo(listen: SocketAddr) -> bool {
    if !listen.ip().is_unspecified() {
        return false;
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        true
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        log::log(
            "warn",
            "udp_pktinfo_unsupported",
            &[("addr", listen.to_string()), ("platform", std::env::consts::OS.to_string())],
        );
        false
    }
}

/// The per-worker buffers and the synchronous per-datagram flow shared by the
/// unbatched and batched receive loops. Exactly one runtime generation load
/// and one admission happen here, before both the inline hit and the slow
/// path.
struct UdpReplyBuffers {
    answer: Vec<u8>,
    truncate: Vec<u8>,
    key: [u8; wire::MIN_CANONICAL_BUFFER],
}

/// The buffer holding an inline reply and the log decision its sender needs.
struct InlineReply {
    /// `answer` when the cached answer fits, `truncate` for the TC reply.
    from_answer: bool,
    len: usize,
    log_queries: bool,
    started: Instant,
}

impl InlineReply {
    fn log(&self, peer: SocketAddr, raw: &[u8], served: &[u8]) {
        if self.log_queries {
            log_query(peer.ip(), raw, Some(served), self.started.elapsed());
        }
    }
}

impl UdpReplyBuffers {
    fn new(udp_buffer_size: usize) -> Self {
        Self {
            answer: Vec::with_capacity(udp_buffer_size),
            truncate: Vec::with_capacity(udp_buffer_size),
            key: [0u8; wire::MIN_CANONICAL_BUFFER],
        }
    }

    fn reply(&self, reply: &InlineReply) -> &[u8] {
        let buffer = if reply.from_answer { &self.answer } else { &self.truncate };
        &buffer[..reply.len]
    }

    /// One datagram through admission, the inline fresh hit and the bounded
    /// slow-path spawn. Returns the inline reply for the caller to send; a
    /// rate-limited or inflight-limited datagram returns `None` after logging.
    #[allow(clippy::too_many_arguments)]
    fn handle(
        &mut self,
        server: &Arc<Server>,
        socket: &Arc<UdpSocket>,
        permits: &Arc<Semaphore>,
        inflight_max: usize,
        tasks: &mut JoinSet<()>,
        raw: &[u8],
        peer: SocketAddr,
        local: Option<IpAddr>,
    ) -> Option<InlineReply> {
        #[cfg(feature = "conformance-adapter")]
        server.packets.received();
        // Never answer a source that cannot be a client (a reply to a
        // broadcast or multicast address reaches every host on the link). The
        // same goes for a query sent to a broadcast or multicast destination:
        // the reply would need that address as its source.
        if peer.port() == 0
            || config::impossible_source(peer.ip())
            || local.is_some_and(|local| config::impossible_source(local.to_canonical()))
        {
            #[cfg(feature = "conformance-adapter")]
            server.packets.completed();
            return None;
        }
        let started = Instant::now();
        let runtime = server.runtime();
        // A source outside `allowed_clients` only ever gets REFUSED. All such
        // sources share one bucket (keyed by the unspecified address, which is
        // never a real source), so spoofed sources cannot fill the table or
        // spend an allowed client's tokens, and their REFUSED replies are
        // still limited as a whole.
        let allowed = runtime.cfg.client_allowed(peer.ip());
        let bucket = if allowed { peer.ip() } else { IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED) };
        if !runtime.rate.allow(bucket, started) {
            log_rate_limited(&runtime, peer.ip());
            #[cfg(feature = "conformance-adapter")]
            server.packets.completed();
            return None;
        }
        // Answer a fresh hit or a blocked name inline; a stale hit, other
        // local policy, miss, disallowed client or malformed request falls
        // through to the spawned path.
        if let Some(view) = wire::parse_query(raw).filter(|_| allowed) {
            #[cfg(feature = "conformance-adapter")]
            let hit = sopedu_dns::upstream::track_sync(raw, || {
                runtime.hit_inline(raw, &view, peer.ip(), true, &mut self.key, &mut self.answer, &mut self.truncate)
            });
            #[cfg(not(feature = "conformance-adapter"))]
            let hit =
                runtime.hit_inline(raw, &view, peer.ip(), true, &mut self.key, &mut self.answer, &mut self.truncate);
            let reply = match hit {
                InlineHit::Inline(len) => Some((true, len, Outcome::Cache, None)),
                InlineHit::Truncated(len) => Some((false, len, Outcome::Cache, None)),
                InlineHit::Blocked { len, list } => Some((true, len, Outcome::Blocked, list)),
                InlineHit::NeedAsync { .. } | InlineHit::Slow => None,
            };
            if let Some((from_answer, len, outcome, list)) = reply {
                let latency = started.elapsed();
                stats::inline_hit(outcome, latency);
                // One more 64-byte name copy into this thread's ring; see
                // `querylog` for the cost and the truncation of long names.
                querylog::record(
                    started,
                    latency,
                    &querylog::Record {
                        ip: peer.ip(),
                        qname: &view.qname_lower[..usize::from(view.qname_len)],
                        qtype: view.qtype,
                        outcome,
                        upstream: querylog::NO_UPSTREAM,
                        list,
                    },
                );
                return Some(InlineReply { from_answer, len, log_queries: runtime.cfg.log_queries, started });
            }
        }
        // The permit bounds spawned slow-path requests only; inline hits never
        // take one. A full limit drops and counts, as before, and the line
        // keeps the same fields.
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            stats::count(Outcome::Dropped);
            let dropped = server.udp_dropped.fetch_add(1, Ordering::Relaxed) + 1;
            if dropped == 1 || dropped.is_multiple_of(1000) {
                log::log(
                    "warn",
                    "udp_inflight_full",
                    &[("dropped", dropped.to_string()), ("limit", inflight_max.to_string())],
                );
            }
            #[cfg(feature = "conformance-adapter")]
            server.packets.completed();
            return None;
        };
        let raw = raw.to_vec();
        let (server, socket) = (server.clone(), socket.clone());
        tasks.spawn(async move {
            let _permit = permit;
            if let Some(answer) = server.handle_admitted(&runtime, &raw, peer.ip(), true, started).await {
                // DNSBomb defence: a query that waited this long is probably
                // retried or spoofed, and a stalled upstream releasing every
                // waiter at once would be a burst of answers aimed at the
                // source address. The answer is cached already and TCP is
                // unaffected. Only NOERROR and NXDOMAIN replies amplify; a
                // SERVFAIL after a timeout is no bigger than the query and
                // still tells the client to stop waiting.
                let data = answer.get(3).is_some_and(|flags| matches!(flags & 0x0f, 0 | 3));
                if data && runtime.cfg.udp_discard_limit().is_some_and(|limit| started.elapsed() > limit) {
                    stats::count(Outcome::Dropped);
                } else {
                    #[cfg(feature = "conformance-adapter")]
                    server.packets.attempted();
                    send_reply(&socket, &answer, peer, local).await;
                }
            }
            #[cfg(feature = "conformance-adapter")]
            server.packets.completed();
        });
        None
    }
}

/// Resolves the configured `worker_threads`: `0` asks for the platform
/// default, `1..=64` is explicit and already validated by `Config::validate`.
/// The error fallback is Tokio's own: a platform that cannot report a
/// parallelism gets one worker thread.
fn effective_worker_threads(configured: usize) -> usize {
    match configured {
        0 => std::thread::available_parallelism().map_or(1, NonZeroUsize::get),
        explicit => explicit,
    }
}

/// Batched receive is Linux-only. Elsewhere the key is accepted and ignored, with one
/// startup warning, so a config written for a Linux node still starts.
fn effective_udp_batch(configured: usize) -> usize {
    #[cfg(target_os = "linux")]
    {
        configured
    }
    #[cfg(not(target_os = "linux"))]
    {
        if configured > 0 {
            log::log(
                "warn",
                "udp_batch_unsupported",
                &[
                    ("field", "udp_batch".to_string()),
                    ("configured", configured.to_string()),
                    ("platform", std::env::consts::OS.to_string()),
                ],
            );
        }
        0
    }
}

fn main() -> Result<()> {
    #[cfg(feature = "dhat-heap")]
    let _profiler = dhat::Profiler::new_heap();
    let mut args = std::env::args().skip(1);
    let first = args.next();
    #[cfg(feature = "conformance-adapter")]
    if matches!(first.as_deref(), Some("--conformance-adapter" | "--conformance-adapter=wallclock")) {
        return adapter::main(first.as_deref() == Some("--conformance-adapter=wallclock"));
    }
    let (check, path) = match first.as_deref() {
        Some("--help" | "-h") => {
            println!("{USAGE}");
            return Ok(());
        }
        Some("--version" | "-V") => {
            println!("sopedu-dns {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        Some(flag) if flag.starts_with('-') && flag != "--check" => {
            eprintln!("unknown option {flag}\n{USAGE}");
            std::process::exit(2);
        }
        Some("--check") => (true, PathBuf::from(args.next().unwrap_or_else(|| "config.toml".into()))),
        Some(path) => (false, PathBuf::from(path)),
        None => (false, PathBuf::from("config.toml")),
    };
    let cfg = match Config::load(&path) {
        Ok(cfg) => cfg,
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    };
    if check {
        println!("config ok");
        return Ok(());
    }
    // The runtime exists once, before the async body runs, so the worker
    // count cannot change on reload. `enable_all` keeps the signal, timer and
    // I/O drivers that `#[tokio::main]` would enable.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(effective_worker_threads(cfg.worker_threads))
        .enable_all()
        .build()?;
    if let Err(error) = runtime.block_on(run(cfg, path)) {
        eprintln!("{error}");
        std::process::exit(1);
    }
    Ok(())
}

const USAGE: &str = "usage: sopedu-dns [CONFIG]           run with CONFIG (default ./config.toml)
       sopedu-dns --check [CONFIG]   validate CONFIG and exit
       sopedu-dns --version
       sopedu-dns --help";

/// Names the config key and a likely fix for the two common bind failures;
/// a bare `Os { code: 13 }` says neither which address nor what to change.
fn bind_error(key: &str, addr: SocketAddr, error: std::io::Error) -> String {
    let hint = match error.kind() {
        std::io::ErrorKind::PermissionDenied => {
            " (ports below 1024 need root or CAP_NET_BIND_SERVICE; use a higher port to try it)"
        }
        std::io::ErrorKind::AddrInUse => {
            " (another DNS server or a second sopedu-dns already uses it; macOS uses UDP/TCP 5353 for mDNS)"
        }
        _ => "",
    };
    format!("cannot bind {key} {addr}: {error}{hint}")
}

async fn run(cfg: Config, path: PathBuf) -> Result<()> {
    let worker_threads = effective_worker_threads(cfg.worker_threads);
    let listen_addrs = cfg.listen.clone();
    // Before any listener exists, so no query goes unrecorded; the capacity
    // is fixed for the process (a reload logs `restart_required`).
    querylog::init(cfg.query_log_capacity).track_names(cfg.prewarm_count);
    // The list is browsing data; with the feature off keep none on disk.
    if !cfg.prewarm {
        prewarm::remove(&cfg.state_dir);
    }
    // Restores the dashboard counters before any query, or deletes the file.
    let saved_counts = stats_store::start(&cfg.state_dir, cfg.persist_stats);
    let udp_inflight_max = cfg.udp_inflight_max;
    let udp_workers = cfg.udp_workers;
    let udp_rcvbuf_bytes = cfg.udp_rcvbuf_bytes;
    let udp_sndbuf_bytes = cfg.udp_sndbuf_bytes;
    let udp_batch = effective_udp_batch(cfg.udp_batch);
    let tcp_max_connections = cfg.tcp_max_connections;
    let tcp_max_per_client = cfg.tcp_max_connections_per_client;
    let tcp_queries_per_connection = cfg.tcp_queries_per_connection;
    let tcp_pipeline_max = cfg.tcp_pipeline_max;
    let tcp_idle_timeout = Duration::from_secs(cfg.tcp_idle_timeout_seconds);
    // Register the signal handlers before readiness so a SIGTERM/SIGINT in the
    // startup window takes the graceful path instead of the default one.
    let mut signals = Signals::new();

    let started = Instant::now();
    let lists = ListManager::new(lists::client_builder().build()?, &cfg);
    lists.sweep_temp_files();
    lists.remove_unconfigured_lists();
    let cached = lists.load_cached();
    log::log(
        "info",
        "blocklists_loaded",
        &[
            ("rules", cached.rules.len().to_string()),
            ("lists", cached.statuses.len().to_string()),
            ("latency_ms", started.elapsed().as_millis().to_string()),
        ],
    );
    let first_download_pending = !cfg.blocklists.is_empty()
        && (cached.statuses.len() < cfg.blocklists.len() || cached.statuses.iter().any(|s| !s.used_cache));
    let upstreams = Arc::new(UpstreamPool::new(&cfg)?);
    upstreams.restore_counters(&saved_counts);
    // A missing or unreadable ARP table is not a startup failure; MAC bypass
    // simply matches nothing on non-Linux hosts.
    let macs = Arc::new(mac::ArpTable::new());
    macs.refresh_from_proc();
    let _ = macs.spawn_refresh();
    let runtime = Arc::new(Runtime::build_with(
        cfg,
        Arc::new(cached.rules),
        Arc::new(cached.statuses),
        upstreams,
        lists,
        None,
        None,
        macs,
    ));
    let server = Arc::new(Server {
        runtime: arc_swap::ArcSwap::from(runtime.clone()),
        ready: AtomicBool::new(false),
        udp_dropped: AtomicU64::new(0),
        #[cfg(target_os = "linux")]
        udp_truncated: AtomicU64::new(0),
        #[cfg(test)]
        parse_calls: std::sync::atomic::AtomicUsize::new(0),
        #[cfg(test)]
        tcp_spawns: std::sync::atomic::AtomicUsize::new(0),
        #[cfg(feature = "conformance-adapter")]
        packets: adapter::Packets::default(),
        refresh_now: Notify::new(),
        probe: Mutex::new(None),
    });
    let probe = runtime.upstreams.spawn_probes();
    *server.probe.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(probe);

    let mut first_sleep = Duration::ZERO;
    if first_download_pending {
        first_sleep = match timeout(STARTUP_LIST_WAIT, server.refresh_lists(&runtime)).await {
            Ok(Ok(Refreshed::Applied)) => Duration::from_secs(runtime.cfg.refresh_hours.saturating_mul(3600)),
            Ok(Ok(Refreshed::Degraded)) => LIST_RETRY,
            _ => Duration::ZERO,
        };
    }
    let refresh = tokio::spawn(refresh_loop(server.clone(), first_sleep));
    #[cfg(unix)]
    let reloader = tokio::spawn(reload_loop(server.clone(), path.clone(), sighup()));
    #[cfg(not(unix))]
    let reloader = tokio::spawn(reload_loop(server.clone(), path.clone()));
    if runtime.cfg.upstreams.is_empty() && runtime.cfg.fallback.is_empty() {
        log::log(
            "warn",
            "no_upstreams",
            &[(
                "hint",
                "upstreams and fallback are both empty; only cached, blocked and local answers will work".into(),
            )],
        );
    }

    // 0 keeps today's single socket. More than one worker needs SO_REUSEPORT
    // so every socket can bind the same address; the kernel spreads flows.
    let socket_count = udp_workers.max(1);
    // Each listen address gets its own socket set and TCP listener; the
    // loops share the server state, limits and shutdown.
    let mut udp_sockets = Vec::with_capacity(socket_count * listen_addrs.len());
    let mut tcp_listeners = Vec::with_capacity(listen_addrs.len());
    // (address, pktinfo, effective rcvbuf, effective sndbuf) for the log lines.
    let mut bound = Vec::with_capacity(listen_addrs.len());
    for &listen in &listen_addrs {
        let udp_pktinfo = effective_pktinfo(listen);
        let first = udp_sockets.len();
        for _ in 0..socket_count {
            let socket = bind_udp_socket(listen, socket_count > 1, udp_rcvbuf_bytes, udp_sndbuf_bytes)
                .map_err(|error| bind_error("listen (UDP)", listen, error))?;
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            if udp_pktinfo {
                udp_pktinfo::enable(&socket, listen.is_ipv6())
                    .map_err(|error| bind_error("listen (UDP, IP_PKTINFO)", listen, error))?;
            }
            udp_sockets.push((UdpSocket::from_std(socket)?, udp_pktinfo));
        }
        tcp_listeners.push(bind_tcp_listener(listen).map_err(|error| bind_error("listen (TCP)", listen, error))?);
        // Log the effective values, not the requests: 0 means the OS default
        // and a non-zero size may have been doubled or clamped by the kernel.
        let effective_buffers = SockRef::from(&udp_sockets[first].0);
        bound.push((listen, udp_pktinfo, effective_buffers.recv_buffer_size()?, effective_buffers.send_buffer_size()?));
    }
    // A bind failure is a startup error like the DNS sockets; the message
    // names the key so the fix is obvious.
    let ui = if runtime.cfg.ui_enabled {
        let addr = runtime.cfg.ui_listen;
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|error| format!("cannot bind ui_listen {addr}: {error} (set ui_enabled = false to disable it)"))?;
        log::log("info", "ui_listening", &[("addr", addr.to_string())]);
        if !addr.ip().is_loopback() {
            // The UI has no login: anyone who can reach it sees the query log.
            log::log("warn", "ui_exposed", &[("addr", addr.to_string()), ("reason", "ui_has_no_login".into())]);
        }
        Some(listener)
    } else {
        None
    };
    for (listen, udp_pktinfo, rcvbuf_bytes, sndbuf_bytes) in bound {
        log::log(
            "info",
            "listening",
            &[
                ("addr", listen.to_string()),
                ("worker_threads", worker_threads.to_string()),
                ("udp_workers", socket_count.to_string()),
                ("udp_rcvbuf_bytes", rcvbuf_bytes.to_string()),
                ("udp_sndbuf_bytes", sndbuf_bytes.to_string()),
                ("udp_batch", udp_batch.to_string()),
                ("udp_pktinfo", udp_pktinfo.to_string()),
                ("udp_inflight_max", udp_inflight_max.to_string()),
                ("tcp_max_connections", tcp_max_connections.to_string()),
                ("tcp_max_connections_per_client", tcp_max_per_client.to_string()),
                ("upstream_inflight_max", runtime.cfg.upstream_inflight_max.to_string()),
            ],
        );
    }

    let udp_permits = Arc::new(Semaphore::new(udp_inflight_max));
    let tcp_permits = Arc::new(Semaphore::new(tcp_max_connections));
    let per_client = Arc::new(PerClient::default());
    // Existing connections stop reading new frames on shutdown and drain the
    // queries already in flight; each UDP worker stops receiving and drains
    // its own slow-path set.
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    #[cfg(feature = "conformance-adapter")]
    adapter::attach(adapter::Handles {
        server: server.clone(),
        udp_permits: udp_permits.clone(),
        udp_max: udp_inflight_max,
        tcp_permits: tcp_permits.clone(),
        tcp_max: tcp_max_connections,
    });
    let mut udp_worker_tasks = JoinSet::new();
    for (socket, udp_pktinfo) in udp_sockets {
        udp_worker_tasks.spawn(udp_worker(
            server.clone(),
            Arc::new(socket),
            udp_permits.clone(),
            udp_inflight_max,
            udp_batch,
            udp_pktinfo,
            shutdown_rx.clone(),
        ));
    }
    let mut tcp_tasks = JoinSet::new();
    // `accepted_tx` stays alive in this scope so `recv` never reports closed.
    let (accepted_tx, mut accepted_rx) = mpsc::channel(64);
    let mut accept_tasks = JoinSet::new();
    for listener in tcp_listeners {
        accept_tasks.spawn(tcp_accept_loop(listener, accepted_tx.clone()));
    }
    let ui_task = ui.map(|listener| {
        let server = server.clone();
        tokio::spawn(http::serve(listener, move |req| server.route(req)))
    });
    // Feeds the top-N sketches and the dashboard windows; the DNS path never
    // waits for it.
    let query_log_drain = querylog::spawn_drain();
    server.ready.store(true, Ordering::SeqCst);
    log::log("info", "readiness", &[("ready", "true".to_string())]);
    let prewarm_task = server.runtime().cfg.prewarm.then(|| tokio::spawn(prewarm_loop(server.clone())));
    let prewarm_saver = tokio::spawn(prewarm_saver(server.clone()));
    let stats_saver = tokio::spawn(stats_saver(server.clone()));
    loop {
        tokio::select! {
            _ = signals.recv() => break,
            Some(joined) = udp_worker_tasks.join_next(), if !udp_worker_tasks.is_empty() => {
                // A worker returns early only on a fatal receive error; end
                // the process as the single-loop path did instead of leaving
                // the remaining workers half-serving.
                match joined {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => return Err(error),
                    Err(error) => return Err(error.into()),
                }
            },
            Some(_) = tcp_tasks.join_next(), if !tcp_tasks.is_empty() => {},
            Some(r) = accepted_rx.recv() => {
                let (stream, peer) = r?;
                // Admission before resources. A peer that is not
                // allowed (or cannot exist) is closed at once, before it can
                // take a shared permit; one allowed host is capped so it cannot
                // take them all. Bounded: close instead of queueing.
                let ip = peer.ip().to_canonical();
                if config::impossible_source(ip) || !server.runtime().cfg.client_allowed(ip) {
                    drop(stream);
                    continue;
                }
                let Some(slot) = PerClient::take(&per_client, ip, tcp_max_per_client) else {
                    drop(stream);
                    continue;
                };
                let Ok(permit) = tcp_permits.clone().try_acquire_owned() else {
                    drop(stream);
                    continue;
                };
                let server = server.clone();
                let shutdown = shutdown_rx.clone();
                tcp_tasks.spawn(async move {
                    let _permit = permit;
                    let _slot = slot;
                    serve_tcp(
                        server,
                        stream,
                        peer,
                        tcp_idle_timeout,
                        tcp_queries_per_connection,
                        tcp_pipeline_max,
                        shutdown,
                    )
                    .await;
                });
            }
        }
    }

    // Shutdown: readiness false first, then stop accepting, then drain.
    server.ready.store(false, Ordering::SeqCst);
    // Wake every connection: it stops reading new frames and finishes the
    // queries already in flight instead of waiting out its idle timeout.
    let _ = shutdown_tx.send(true);
    log::log(
        "warn",
        "shutdown",
        &[("ready", "false".to_string()), ("drain_seconds", DRAIN_TIMEOUT.as_secs().to_string())],
    );
    accept_tasks.abort_all();
    if let Some(task) = &ui_task {
        task.abort();
    }
    query_log_drain.abort();
    prewarm_saver.abort();
    stats_saver.abort();
    if let Some(task) = &prewarm_task {
        task.abort();
    }
    server.save_prewarm();
    save_stats(&server).await;
    reloader.abort();
    refresh.abort();
    if let Some(probe) = server.probe.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).take() {
        probe.abort();
    }
    // Scope the drain so its borrow of the task sets ends before `abort_all`.
    {
        let drain = timeout(DRAIN_TIMEOUT, async {
            tokio::join!(async { while udp_worker_tasks.join_next().await.is_some() {} }, async {
                while tcp_tasks.join_next().await.is_some() {}
            },);
        });
        tokio::pin!(drain);
        tokio::select! {
            _ = &mut drain => {}
            // A second SIGTERM/SIGINT is an operator asking to stop now; abort
            // the rest of the drain immediately instead of waiting it out.
            _ = signals.recv() => {
                log::log("warn", "shutdown_forced", &[("reason", "second signal".to_string())]);
            }
        }
    }
    udp_worker_tasks.abort_all();
    tcp_tasks.abort_all();
    log::log("info", "shutdown_complete", &[]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::Query;
    use sopedu_dns::config::PrivatePtr;
    use std::collections::HashMap;
    /// Test fixtures use `*.test` as stand-ins for real names, so they forward
    /// `.test` (RFC 6761 §6.2 option); [`server_exact`] keeps the default.
    fn server(mut cfg: Config) -> Arc<Server> {
        cfg.forward_test_names = true;
        server_exact(cfg)
    }

    fn server_exact(cfg: Config) -> Arc<Server> {
        let r = rules::Rules::from_lines(&cfg.user_rules, 0);
        let upstreams = Arc::new(UpstreamPool::new(&cfg).unwrap());
        let lists = ListManager::new(lists::client_builder().build().unwrap(), &cfg);
        let runtime = Arc::new(Runtime::build(cfg, Arc::new(r), Arc::new(Vec::new()), upstreams, lists));
        Arc::new(Server {
            runtime: arc_swap::ArcSwap::from(runtime),
            ready: AtomicBool::new(true),
            udp_dropped: AtomicU64::new(0),
            #[cfg(target_os = "linux")]
            udp_truncated: AtomicU64::new(0),
            parse_calls: std::sync::atomic::AtomicUsize::new(0),
            tcp_spawns: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(feature = "conformance-adapter")]
            packets: adapter::Packets::default(),
            refresh_now: Notify::new(),
            probe: Mutex::new(None),
        })
    }
    fn query(name: &str, typ: RecordType) -> Message {
        let mut q = Message::new(42, MessageType::Query, OpCode::Query);
        q.metadata.recursion_desired = true;
        q.add_query(Query::query(Name::from_ascii(format!("{}.", name.trim_end_matches('.'))).unwrap(), typ));
        q
    }
    /// The canonical cache key of a query, built exactly as `resolve` builds it.
    fn key_for(q: &Message) -> Vec<u8> {
        let raw = q.to_vec().unwrap();
        let view = wire::parse_query(&raw).unwrap();
        let mut buffer = [0u8; wire::MIN_CANONICAL_BUFFER];
        let len = wire::canonical_key(&view, &mut buffer).unwrap();
        buffer[..len].to_vec()
    }
    fn v6_reverse(address: &str) -> String {
        let mut labels = Vec::new();
        for byte in address.parse::<std::net::Ipv6Addr>().unwrap().octets().iter().rev() {
            labels.push(format!("{:x}", byte & 0x0f));
            labels.push(format!("{:x}", byte >> 4));
        }
        format!("{}.ip6.arpa", labels.join("."))
    }
    #[test]
    fn socket_helper_applies_reuse_port_and_receive_buffer() {
        let socket = bind_udp_socket("127.0.0.1:0".parse().unwrap(), true, 65_536, 0).unwrap();
        assert!(socket.local_addr().unwrap().port() != 0, "the helper binds the requested address");
        let raw = SockRef::from(&socket);
        let readback = raw.recv_buffer_size().unwrap();
        assert!(readback >= 65_536, "the kernel reports at least the requested receive buffer: {readback}");
        #[cfg(unix)]
        assert!(raw.reuse_port().unwrap(), "SO_REUSEPORT is set before bind");
    }
    /// Two workers must be able to bind the same concrete
    /// address through the helper. The ops test alone would still pass with one
    /// socket serving, so this checks the rebind directly.
    #[test]
    fn two_sockets_share_one_concrete_port_with_reuse_port() {
        let first = bind_udp_socket("127.0.0.1:0".parse().unwrap(), true, 0, 0).unwrap();
        let addr = first.local_addr().unwrap();
        let second = bind_udp_socket(addr, true, 0, 0).unwrap();
        assert_eq!(second.local_addr().unwrap(), addr, "the second bind uses the same concrete address");
        drop(first);
    }
    #[test]
    fn effective_worker_threads_defaults_and_explicit_counts() {
        assert!(effective_worker_threads(0) >= 1, "0 asks for the platform default, never zero threads");
        for explicit in [1, 2, 64] {
            assert_eq!(effective_worker_threads(explicit), explicit);
        }
    }
    #[tokio::test]
    async fn accepted_tcp_sockets_enable_nodelay() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
        let (server_side, _) = listener.accept().await.unwrap();
        let _client = client.await.unwrap();
        enable_tcp_nodelay(&server_side).unwrap();
        assert!(server_side.nodelay().unwrap(), "the accept path sets TCP_NODELAY");
    }
    /// A pipelined burst of cache hits behind a slow miss on one connection:
    /// every hit is answered inline on the connection task (no spawn), each
    /// under its own ID and question, and none waits for the miss, whose
    /// answer comes last (RFC 7766 §7: replies may be out of order).
    #[tokio::test]
    async fn tcp_pipelined_hits_are_answered_inline_ahead_of_a_slow_miss() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // A plain upstream that accepts over both transports and never
        // answers, so the miss lasts the whole upstream deadline.
        let silent_tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream = silent_tcp.local_addr().unwrap();
        let _silent_udp = std::net::UdpSocket::bind(upstream).unwrap();
        let s = server(Config {
            upstreams: vec![],
            fallback: vec![upstream],
            upstream_timeout_seconds: 1,
            ..Config::default()
        });
        let names: Vec<String> = (0..8).map(|i| format!("hit{i}.test")).collect();
        for name in &names {
            cache_answer(&s, &query(name, RecordType::A), 1, 300);
        }

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).await.unwrap();
        let (accepted, peer) = listener.accept().await.unwrap();
        let (_stop, shutdown) = watch::channel(false);
        let conn = tokio::spawn(serve_tcp(s.clone(), accepted, peer, Duration::from_secs(10), 1000, 16, shutdown));

        let mut sent = Vec::new();
        let mut burst = Vec::new();
        let mut frame = |name: &str, id: u16| {
            let mut q = query(name, RecordType::A);
            q.metadata.id = id;
            let raw = q.to_vec().unwrap();
            burst.extend_from_slice(&u16::try_from(raw.len()).unwrap().to_be_bytes());
            burst.extend_from_slice(&raw);
            sent.push((id, name.to_string()));
        };
        frame("slow.test", 1);
        for id in 100..140u16 {
            frame(&names[usize::from(id) % names.len()], id);
        }
        // One write: the frames reach the server back to back.
        client.write_all(&burst).await.unwrap();

        let mut seen = Vec::new();
        for _ in 0..sent.len() {
            let length = client.read_u16().await.unwrap();
            let mut raw = vec![0u8; usize::from(length)];
            client.read_exact(&mut raw).await.unwrap();
            let answer = Message::from_vec(&raw).unwrap();
            let name = answer.queries[0].name().to_ascii().trim_end_matches('.').to_string();
            seen.push((answer.metadata.id, name, answer.metadata.response_code));
        }
        let (last_id, _, last_code) = seen.last().unwrap();
        assert_eq!(*last_id, 1, "the slow miss is answered after every hit: {seen:?}");
        assert_eq!(*last_code, ResponseCode::ServFail);
        assert!(seen[..seen.len() - 1].iter().all(|(_, _, code)| *code == ResponseCode::NoError));
        let mut got: Vec<(u16, String)> = seen.into_iter().map(|(id, name, _)| (id, name)).collect();
        got.sort_unstable();
        sent.sort_unstable();
        assert_eq!(got, sent, "every reply carries its own query's ID and question");
        assert_eq!(s.tcp_spawns.load(Ordering::Relaxed), 1, "only the miss leaves the connection task");
        drop(client);
        conn.await.unwrap();
    }
    /// A TCP client that leads a coalesced miss and then resets its
    /// connection must not cost a UDP client following the same name its
    /// answer. The connection's tasks end with it (here the connection task
    /// is aborted, as a write error after the reset ends it), so the
    /// leader's upstream work has to run on its own.
    #[tokio::test]
    async fn a_reset_tcp_leader_still_answers_its_udp_follower() {
        use std::sync::atomic::Ordering::SeqCst;
        use tokio::io::AsyncWriteExt;
        let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (upstream, _peer) = serve_udp(true, Duration::from_millis(400), requests.clone()).await;
        let s = server(Config {
            upstreams: vec![],
            fallback: vec![upstream],
            upstream_inflight_per_client: 1,
            upstream_timeout_seconds: 3,
            ..Config::default()
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
        let (accepted, peer) = listener.accept().await.unwrap();
        let (_stop, shutdown) = watch::channel(false);
        let conn = tokio::spawn(serve_tcp(s.clone(), accepted, peer, Duration::from_secs(10), 1000, 16, shutdown));

        let raw = query("shared.test", RecordType::A).to_vec().unwrap();
        let mut frame = u16::try_from(raw.len()).unwrap().to_be_bytes().to_vec();
        frame.extend_from_slice(&raw);
        client.write_all(&frame).await.unwrap();
        wait_until(|| s.inflight().len() == 1).await;
        let follower = {
            let (s, raw) = (s.clone(), raw.clone());
            tokio::spawn(async move { s.handle(&raw, "10.0.0.2".parse().unwrap(), true).await })
        };
        sleep(Duration::from_millis(50)).await;

        SockRef::from(&client).set_linger(Some(Duration::ZERO)).unwrap();
        drop(client);
        conn.abort();
        let _ = conn.await;

        let answer = follower.await.unwrap().expect("the follower is answered");
        assert_eq!(code(&answer), ResponseCode::NoError, "the leader's reset must not SERVFAIL its follower");
        assert_eq!(answer_a(&answer), Some(std::net::Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(requests.load(SeqCst), 1, "one upstream request for both clients");
        // The answer was cached, and the leader's upstream slot was released.
        let cached = s.handle(&raw, "10.0.0.3".parse().unwrap(), true).await.unwrap();
        assert_eq!(answer_a(&cached), Some(std::net::Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(requests.load(SeqCst), 1);
        let leader_ip = "127.0.0.1".parse().unwrap();
        assert!(PerClient::take(&s.runtime().fair, leader_ip, 1).is_some(), "no slot outlives the work");
    }
    /// At the per-connection query cap the server answers the queries it
    /// accepted and then closes cleanly: FIN after the last answer, never a
    /// reset that would discard answers still in flight to the client. The
    /// client retries the rest on a new connection (RFC 7766 §6.2.4). The
    /// unread tail (over 1 MB) is still arriving when the server is done: a
    /// plain close then resets (Linux at once for unread data, every kernel
    /// for data that arrives after it), so the server must drain it.
    #[tokio::test]
    async fn the_query_cap_answers_the_accepted_queries_and_closes_without_a_reset() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let s = server(Config { upstreams: vec![], fallback: vec![], ..Config::default() });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
        let (accepted, peer) = listener.accept().await.unwrap();
        let (_stop, shutdown) = watch::channel(false);
        let conn = tokio::spawn(serve_tcp(s.clone(), accepted, peer, Duration::from_secs(10), 5, 16, shutdown));

        let mut burst = Vec::new();
        for id in 1..=24u16 {
            let name = format!("cap{id}.test");
            cache_answer(&s, &query(&name, RecordType::A), 1, 300);
            let mut q = query(&name, RecordType::A);
            q.metadata.id = id;
            let mut raw = q.to_vec().unwrap();
            if id > 5 {
                // Never read: the server stops at the cap.
                raw.resize(60_000, 0);
            }
            burst.extend_from_slice(&u16::try_from(raw.len()).unwrap().to_be_bytes());
            burst.extend_from_slice(&raw);
        }
        let (mut read, mut write) = client.into_split();
        let sender = tokio::spawn(async move {
            write.write_all(&burst).await?;
            write.shutdown().await
        });

        let mut ids = Vec::new();
        let mut rest = Vec::new();
        let outcome = timeout(Duration::from_secs(5), async {
            while ids.len() < 5 {
                let length = read.read_u16().await?;
                let mut raw = vec![0u8; usize::from(length)];
                read.read_exact(&mut raw).await?;
                ids.push(Message::from_vec(&raw).unwrap().metadata.id);
            }
            read.read_to_end(&mut rest).await
        })
        .await
        .expect("the server closes within the bound");
        assert_eq!(ids, [1, 2, 3, 4, 5], "every accepted query is answered");
        assert!(matches!(outcome, Ok(0)), "a clean FIN with nothing after it, not a reset: {outcome:?} {rest:?}");
        conn.await.unwrap();
        let sent = sender.await.unwrap();
        assert!(sent.is_ok(), "the unanswered tail is drained, not reset: {sent:?}");
    }
    #[tokio::test]
    async fn local_policy() {
        let s = server(Config {
            user_rules: vec!["||blocked.test^".into()],
            rewrites: HashMap::from([("blocked.test".into(), "::1".parse().unwrap())]),
            upstreams: vec![],
            fallback: vec![],
            ..Config::default()
        });
        for (name, typ, code, count) in [
            ("blocked.test", RecordType::AAAA, ResponseCode::NoError, 1),
            ("blocked.test", RecordType::A, ResponseCode::NoError, 0),
            ("a.blocked.test", RecordType::A, ResponseCode::NXDomain, 0),
            ("version.bind", RecordType::A, ResponseCode::Refused, 0),
            // RFC 8482 §4.2: a synthesized HINFO, local (no upstream here, so
            // a forwarded query would be SERVFAIL).
            ("x", RecordType::ANY, ResponseCode::NoError, 1),
            // Local policy still decides first: a blocked name stays blocked.
            ("a.blocked.test", RecordType::ANY, ResponseCode::NXDomain, 0),
        ] {
            let q = query(name, typ);
            let a = s.handle(&q.to_vec().unwrap(), "127.0.0.1".parse().unwrap(), true).await.unwrap();
            let a = Message::from_vec(&a).unwrap();
            assert_eq!(a.metadata.response_code, code);
            assert_eq!(a.answers.len(), count);
            if code == ResponseCode::NXDomain {
                assert_eq!(a.authorities[0].ttl, 10);
            }
        }
        for class in [DNSClass::IN, DNSClass::HS] {
            let mut q = query("any.example", RecordType::ANY);
            q.queries[0].set_query_class(class);
            let a = s.handle(&q.to_vec().unwrap(), "127.0.0.1".parse().unwrap(), true).await.unwrap();
            let a = Message::from_vec(&a).unwrap();
            assert_eq!(a.metadata.response_code, ResponseCode::NoError, "{class:?} ANY is never forwarded");
            let RData::HINFO(hinfo) = &a.answers[0].data else { panic!("{class:?} ANY: HINFO") };
            assert_eq!((&hinfo.cpu[..], &hinfo.os[..]), (&b"RFC8482"[..], &b""[..]));
            assert_eq!(a.answers[0].ttl, 10);
            assert_eq!(a.answers[0].name, q.queries[0].name().clone());
        }
        assert!(s.handle(&[0, 1], "127.0.0.1".parse().unwrap(), true).await.is_none());
        let mut q = query("x", RecordType::A);
        q.queries[0].set_query_class(DNSClass::CH);
        let a = s.handle(&q.to_vec().unwrap(), "127.0.0.1".parse().unwrap(), true).await.unwrap();
        assert_eq!(Message::from_vec(&a).unwrap().metadata.response_code, ResponseCode::Refused);
    }
    #[tokio::test]
    async fn private_ptr_is_answered_locally_and_public_reverse_is_forwarded() {
        let s = server(Config { upstreams: vec![], fallback: vec![], ..Config::default() });
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        for name in [
            "1.0.0.10.in-addr.arpa",
            "1.0.16.172.in-addr.arpa",
            "1.0.31.172.in-addr.arpa",
            "1.0.168.192.in-addr.arpa",
            "1.0.0.127.in-addr.arpa",
            "1.0.254.169.in-addr.arpa",
            "1.0.64.100.in-addr.arpa",
            "1.0.127.100.in-addr.arpa",
        ] {
            let q = query(name, RecordType::PTR);
            let answer = Message::from_vec(&s.handle(&q.to_vec().unwrap(), ip, false).await.unwrap()).unwrap();
            assert_eq!(answer.metadata.response_code, ResponseCode::NXDomain, "{name}");
            assert!(answer.answers.is_empty(), "{name}");
            assert!(answer.metadata.authoritative, "{name} is a local empty zone");
            let RData::SOA(soa) = &answer.authorities[0].data else { panic!("{name} has no SOA") };
            let apex = reverse::zone_for(name).unwrap().apex;
            assert_eq!(
                answer.authorities[0].name.to_ascii().trim_end_matches('.'),
                apex,
                "{name} is denied by its zone apex"
            );
            assert_eq!(answer.authorities[0].ttl, 10);
            assert_eq!(soa.minimum, 10);
        }
        for address in ["fe80::1", "fd00::1"] {
            let name = v6_reverse(address);
            let q = query(&name, RecordType::PTR);
            let answer = Message::from_vec(&s.handle(&q.to_vec().unwrap(), ip, false).await.unwrap()).unwrap();
            assert_eq!(answer.metadata.response_code, ResponseCode::NXDomain, "{name}");
        }
        // RFC 6303 §4.3: the ::1 name is itself an empty zone apex, so PTR is NODATA.
        let q = query(&v6_reverse("::1"), RecordType::PTR);
        let answer = Message::from_vec(&s.handle(&q.to_vec().unwrap(), ip, false).await.unwrap()).unwrap();
        assert_eq!((answer.metadata.response_code, answer.answers.len()), (ResponseCode::NoError, 0));
        // Public and incomplete reverse names are forwarded; with no upstream
        // configured that shows up as SERVFAIL, not a local denial.
        for name in ["8.8.8.8.in-addr.arpa", "1.2.3.in-addr.arpa", &v6_reverse("2001:4860:4860::8888")] {
            let q = query(name, RecordType::PTR);
            let answer = Message::from_vec(&s.handle(&q.to_vec().unwrap(), ip, false).await.unwrap()).unwrap();
            assert_eq!(answer.metadata.response_code, ResponseCode::ServFail, "{name}");
        }
    }

    #[tokio::test]
    async fn private_ptr_forward_mode_forwards_the_ptr_path_only() {
        let s = server(Config {
            private_ptr: PrivatePtr::Forward,
            upstreams: vec![],
            fallback: vec![],
            ..Config::default()
        });
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        for name in ["1.0.0.10.in-addr.arpa", &v6_reverse("fd00::1")] {
            let q = query(name, RecordType::PTR);
            let answer = Message::from_vec(&s.handle(&q.to_vec().unwrap(), ip, false).await.unwrap()).unwrap();
            assert_eq!(answer.metadata.response_code, ResponseCode::ServFail, "{name} must be forwarded");
        }
        // Zone apex service is not the PTR path and stays local.
        let q = query("10.in-addr.arpa", RecordType::SOA);
        let answer = Message::from_vec(&s.handle(&q.to_vec().unwrap(), ip, false).await.unwrap()).unwrap();
        assert_eq!(answer.metadata.response_code, ResponseCode::NoError);
        assert_eq!(answer.answers.len(), 1);
    }

    #[tokio::test]
    async fn blocklist_precedes_private_ptr_forwarding() {
        let mut cfg = Config {
            private_ptr: PrivatePtr::Forward,
            user_rules: vec!["||10.in-addr.arpa^".into()],
            upstreams: vec![],
            fallback: vec![],
            ..Config::default()
        };
        cfg.validate().unwrap();
        let s = server(cfg);
        let q = query("1.0.0.10.in-addr.arpa", RecordType::PTR);
        let answer =
            Message::from_vec(&s.handle(&q.to_vec().unwrap(), "127.0.0.1".parse().unwrap(), false).await.unwrap())
                .unwrap();
        assert_eq!(answer.metadata.response_code, ResponseCode::NXDomain);
        assert!(matches!(answer.authorities[0].data, RData::SOA(_)));
    }

    #[tokio::test]
    async fn local_reverse_zone_precedes_the_blocklist_and_dotted_labels_never_match_rules() {
        let cfg = Config {
            user_rules: vec!["||10.in-addr.arpa^".into(), "||a.test^".into()],
            upstreams: vec![],
            fallback: vec![],
            ..Config::default()
        };
        let s = server(cfg);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let q = query("1.10.in-addr.arpa", RecordType::PTR);
        let answer = Message::from_vec(&s.handle(&q.to_vec().unwrap(), ip, false).await.unwrap()).unwrap();
        assert_eq!(answer.metadata.response_code, ResponseCode::NXDomain);
        assert!(answer.metadata.authoritative, "the local zone answers before the blocklist");

        // One label `x.a` under `test` is not under `a.test`.
        let mut q = query("placeholder.test", RecordType::A);
        let labels: [&[u8]; 2] = [b"x.a", b"test"];
        q.queries[0].set_name(Name::from_labels(labels.iter().copied()).unwrap());
        let answer = Message::from_vec(&s.handle(&q.to_vec().unwrap(), ip, false).await.unwrap()).unwrap();
        assert_ne!(answer.metadata.response_code, ResponseCode::NXDomain, "forwarded, not blocked");
        let q = query("x.a.test", RecordType::A);
        let answer = Message::from_vec(&s.handle(&q.to_vec().unwrap(), ip, false).await.unwrap()).unwrap();
        assert_eq!(answer.metadata.response_code, ResponseCode::NXDomain, "the real subtree is still blocked");
    }

    #[tokio::test]
    async fn a_label_holding_a_dot_is_one_whole_label_for_every_local_policy() {
        let mut cfg = Config {
            user_rules: vec!["||blocked.example^".into()],
            rewrites: HashMap::from([("*.lan.example".into(), "192.0.2.7".parse().unwrap())]),
            upstreams: vec![],
            fallback: vec![],
            ..Config::default()
        };
        cfg.validate().unwrap();
        let s = server_exact(cfg);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let ask = |labels: &[&[u8]], typ| {
            let mut q = query("placeholder.example", typ);
            q.queries[0].set_name(Name::from_labels(labels.iter().copied()).unwrap());
            let s = s.clone();
            async move { Message::from_vec(&s.handle(&q.to_vec().unwrap(), ip, false).await.unwrap()).unwrap() }
        };

        // RFC 7686 §2: every name under .onion is NXDOMAIN, whatever its labels hold.
        let answer = ask(&[b"a.b", b"onion"], RecordType::A).await;
        assert_eq!(answer.metadata.response_code, ResponseCode::NXDomain);
        // RFC 8375 / RFC 6303: local zones answer authoritatively.
        for labels in [&[&b"x.y"[..], b"home", b"arpa"][..], &[b"1.0", b"168", b"192", b"in-addr", b"arpa"]] {
            let answer = ask(labels, RecordType::PTR).await;
            assert_eq!(answer.metadata.response_code, ResponseCode::NXDomain, "{labels:?}");
            assert!(answer.metadata.authoritative, "{labels:?}");
        }
        // RFC 6761 §6.3: localhost names resolve to loopback.
        let answer = ask(&[b"p.q", b"localhost"], RecordType::A).await;
        assert_eq!(answer.answers[0].data, RData::A(A(std::net::Ipv4Addr::LOCALHOST)));
        // A `||name^` rule covers its whole subtree; a rewrite wildcard likewise.
        let answer = ask(&[b"z.w", b"blocked", b"example"], RecordType::A).await;
        assert_eq!(answer.metadata.response_code, ResponseCode::NXDomain);
        assert!(matches!(answer.authorities[0].data, RData::SOA(_)));
        let answer = ask(&[b"a.b", b"lan", b"example"], RecordType::A).await;
        assert_eq!(answer.answers[0].data, RData::A(A("192.0.2.7".parse().unwrap())));

        // One label never matches as two: `blocked.example` as a single
        // label, or `x.blocked` under `example`, is not under the rule, and
        // the single label `a.onion` is not under .onion.
        for labels in
            [&[&b"blocked.example"[..]][..], &[b"x.blocked", b"example"], &[b"a.onion"], &[b"x.lan", b"example"]]
        {
            let answer = ask(labels, RecordType::A).await;
            assert_eq!(answer.metadata.response_code, ResponseCode::ServFail, "{labels:?} is forwarded");
        }
    }

    #[tokio::test]
    async fn reverse_zone_apex_and_descendants_are_authoritative() {
        let s = server(Config { upstreams: vec![], fallback: vec![], ..Config::default() });
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        for apex in ["10.in-addr.arpa", "16.172.in-addr.arpa", "64.100.in-addr.arpa", "d.f.ip6.arpa"] {
            let apex_name = Name::from_ascii(format!("{apex}.")).unwrap();

            let q = query(apex, RecordType::SOA);
            let answer = Message::from_vec(&s.handle(&q.to_vec().unwrap(), ip, false).await.unwrap()).unwrap();
            assert_eq!(answer.metadata.response_code, ResponseCode::NoError, "{apex}");
            assert!(answer.metadata.authoritative, "{apex} SOA must be authoritative");
            assert_eq!(answer.answers.len(), 1, "{apex}");
            assert_eq!(answer.answers[0].name, apex_name);
            assert_eq!(answer.answers[0].ttl, 10);
            let RData::SOA(soa) = &answer.answers[0].data else { panic!("{apex} SOA") };
            assert_eq!(soa.mname, apex_name);
            assert_eq!(soa.rname.to_ascii(), "nobody.invalid.");
            assert_eq!(soa.minimum, 10);

            let q = query(apex, RecordType::NS);
            let answer = Message::from_vec(&s.handle(&q.to_vec().unwrap(), ip, false).await.unwrap()).unwrap();
            assert_eq!(answer.metadata.response_code, ResponseCode::NoError, "{apex}");
            assert!(answer.metadata.authoritative);
            assert_eq!(answer.answers.len(), 1, "{apex}");
            let RData::NS(ns) = &answer.answers[0].data else { panic!("{apex} NS") };
            assert_eq!(ns.0, apex_name, "the NS target is the apex itself");
            assert_eq!(answer.answers[0].name, apex_name);

            let q = query(apex, RecordType::A);
            let answer = Message::from_vec(&s.handle(&q.to_vec().unwrap(), ip, false).await.unwrap()).unwrap();
            assert_eq!(answer.metadata.response_code, ResponseCode::NoError, "{apex} NODATA");
            assert!(answer.metadata.authoritative);
            assert!(answer.answers.is_empty(), "the apex is not blanket-NXDOMAINed");
            assert!(matches!(answer.authorities[0].data, RData::SOA(_)));
            assert_eq!(answer.authorities[0].name, apex_name);

            let descendant = format!("1.0.{apex}");
            let q = query(&descendant, RecordType::A);
            let answer = Message::from_vec(&s.handle(&q.to_vec().unwrap(), ip, false).await.unwrap()).unwrap();
            assert_eq!(answer.metadata.response_code, ResponseCode::NXDomain, "{descendant}");
            assert!(answer.metadata.authoritative);
            assert!(matches!(answer.authorities[0].data, RData::SOA(_)));
            assert_eq!(answer.authorities[0].name, apex_name);
        }
        // A text suffix that is not a whole-label suffix is forwarded.
        let q = query("x10.in-addr.arpa", RecordType::A);
        let answer = Message::from_vec(&s.handle(&q.to_vec().unwrap(), ip, false).await.unwrap()).unwrap();
        assert_eq!(answer.metadata.response_code, ResponseCode::ServFail);
    }

    #[tokio::test]
    async fn home_arpa_is_local_except_the_ds_probe() {
        let s = server(Config { upstreams: vec![], fallback: vec![], ..Config::default() });
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let home = Name::from_ascii("home.arpa.").unwrap();

        let q = query("home.arpa", RecordType::SOA);
        let answer = Message::from_vec(&s.handle(&q.to_vec().unwrap(), ip, false).await.unwrap()).unwrap();
        assert_eq!(answer.metadata.response_code, ResponseCode::NoError);
        assert!(answer.metadata.authoritative);
        let RData::SOA(soa) = &answer.answers[0].data else { panic!("home.arpa SOA") };
        assert_eq!(soa.mname, home);
        assert_eq!(soa.rname.to_ascii(), "nobody.invalid.");

        let q = query("home.arpa", RecordType::A);
        let answer = Message::from_vec(&s.handle(&q.to_vec().unwrap(), ip, false).await.unwrap()).unwrap();
        assert_eq!(answer.metadata.response_code, ResponseCode::NoError);
        assert!(answer.answers.is_empty());
        assert!(matches!(answer.authorities[0].data, RData::SOA(_)));

        let q = query("printer.home.arpa", RecordType::A);
        let answer = Message::from_vec(&s.handle(&q.to_vec().unwrap(), ip, false).await.unwrap()).unwrap();
        assert_eq!(answer.metadata.response_code, ResponseCode::NXDomain);
        assert!(answer.metadata.authoritative);
        assert_eq!(answer.authorities[0].name, home);

        // DS without DO stays a local NODATA.
        let q = query("home.arpa", RecordType::DS);
        let answer = Message::from_vec(&s.handle(&q.to_vec().unwrap(), ip, false).await.unwrap()).unwrap();
        assert_eq!(answer.metadata.response_code, ResponseCode::NoError);
        assert!(answer.answers.is_empty());

        // DS with DO=1 asks the public tree, and with no upstream that is SERVFAIL.
        let mut q = query("home.arpa", RecordType::DS);
        q.edns.get_or_insert_with(Default::default).set_dnssec_ok(true);
        let answer = Message::from_vec(&s.handle(&q.to_vec().unwrap(), ip, false).await.unwrap()).unwrap();
        assert_eq!(answer.metadata.response_code, ResponseCode::ServFail);

        // The exception is only the apex DS probe.
        let mut q = query("printer.home.arpa", RecordType::DS);
        q.edns.get_or_insert_with(Default::default).set_dnssec_ok(true);
        let answer = Message::from_vec(&s.handle(&q.to_vec().unwrap(), ip, false).await.unwrap()).unwrap();
        assert_eq!(answer.metadata.response_code, ResponseCode::NXDomain);

        let q = query("xhome.arpa", RecordType::A);
        let answer = Message::from_vec(&s.handle(&q.to_vec().unwrap(), ip, false).await.unwrap()).unwrap();
        assert_eq!(answer.metadata.response_code, ResponseCode::ServFail);
    }

    /// RFC 4035 §3.1.4.1 and RFC 6303 §7: a validator below us needs the
    /// signed parent's proof for the DS at every locally served zone apex, not
    /// a local NODATA it cannot verify. With no upstream, "forwarded" shows up
    /// as SERVFAIL; a local answer would be NOERROR.
    #[tokio::test]
    async fn every_local_zone_apex_forwards_its_ds_probe() {
        let s = server(Config { upstreams: vec![], fallback: vec![], ..Config::default() });
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        for apex in ["10.in-addr.arpa", "168.192.in-addr.arpa", "d.f.ip6.arpa", "resolver.arpa", "service.arpa"] {
            let mut q = query(apex, RecordType::DS);
            q.edns.get_or_insert_with(Default::default).set_dnssec_ok(true);
            let answer = Message::from_vec(&s.handle(&q.to_vec().unwrap(), ip, false).await.unwrap()).unwrap();
            assert_eq!(answer.metadata.response_code, ResponseCode::ServFail, "{apex} DS with DO=1 is forwarded");

            let q = query(apex, RecordType::DS);
            let answer = Message::from_vec(&s.handle(&q.to_vec().unwrap(), ip, false).await.unwrap()).unwrap();
            assert_eq!(answer.metadata.response_code, ResponseCode::NoError, "{apex} DS without DO stays local");
            assert!(answer.metadata.authoritative && answer.answers.is_empty());
        }
        // Below the apex the local zone still answers.
        let mut q = query("1.10.in-addr.arpa", RecordType::DS);
        q.edns.get_or_insert_with(Default::default).set_dnssec_ok(true);
        let answer = Message::from_vec(&s.handle(&q.to_vec().unwrap(), ip, false).await.unwrap()).unwrap();
        assert_eq!(answer.metadata.response_code, ResponseCode::NXDomain);
    }

    #[tokio::test]
    async fn local_policy_applies_in_every_class_and_query_classes_are_refused() {
        let mut cfg = Config {
            user_rules: vec!["||blocked.test^".into()],
            rewrites: HashMap::from([("rewrite.test".into(), "::1".parse().unwrap())]),
            forward_test_names: true,
            upstreams: vec![],
            fallback: vec![],
            ..Config::default()
        };
        cfg.validate().unwrap();
        let s = server(cfg);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let (any, none, hs) = (DNSClass::ANY, DNSClass::NONE, DNSClass::HS);
        // No upstream is configured: a forwarded query would be SERVFAIL.
        let queries = [
            ("rewrite.test", RecordType::AAAA, DNSClass::IN, ResponseCode::NoError, 1),
            // A rewritten name is local in every class, but its address is IN data.
            ("rewrite.test", RecordType::AAAA, hs, ResponseCode::NoError, 0),
            ("rewrite.test", RecordType::AAAA, any, ResponseCode::NoError, 0),
            ("blocked.test", RecordType::A, DNSClass::IN, ResponseCode::NXDomain, 0),
            ("blocked.test", RecordType::A, hs, ResponseCode::NXDomain, 0),
            ("blocked.test", RecordType::A, any, ResponseCode::NXDomain, 0),
            ("blocked.test", RecordType::A, none, ResponseCode::NXDomain, 0),
            // RFC 7686 §2, RFC 8375 §4, RFC 6303, RFC 6761 §6, RFC 6762 §22.1.
            ("x.onion", RecordType::A, any, ResponseCode::NXDomain, 0),
            ("x.onion", RecordType::A, DNSClass::Unknown(4000), ResponseCode::NXDomain, 0),
            ("nas.home.arpa", RecordType::A, any, ResponseCode::NXDomain, 0),
            ("nas.home.arpa", RecordType::A, none, ResponseCode::NXDomain, 0),
            ("1.0.0.10.in-addr.arpa", RecordType::PTR, hs, ResponseCode::NXDomain, 0),
            ("1.0.0.10.in-addr.arpa", RecordType::PTR, any, ResponseCode::NXDomain, 0),
            ("printer.local", RecordType::A, any, ResponseCode::NXDomain, 0),
            ("x.invalid", RecordType::A, hs, ResponseCode::NXDomain, 0),
            ("localhost", RecordType::A, any, ResponseCode::NoError, 0),
            ("localhost", RecordType::A, hs, ResponseCode::NoError, 0),
            // QCLASS ANY and NONE are never forwarded.
            ("example.com", RecordType::A, any, ResponseCode::Refused, 0),
            ("example.com", RecordType::A, none, ResponseCode::Refused, 0),
            ("a.test", RecordType::A, any, ResponseCode::Refused, 0),
            // Another data class is forwarded.
            ("example.com", RecordType::A, hs, ResponseCode::ServFail, 0),
        ];
        for (name, record_type, class, expected, count) in queries {
            let mut q = query(name, record_type);
            q.queries[0].set_query_class(class);
            let answer = Message::from_vec(&s.handle(&q.to_vec().unwrap(), ip, false).await.unwrap()).unwrap();
            assert_eq!(answer.metadata.response_code, expected, "{name} {class:?}");
            assert_eq!(answer.answers.len(), count, "{name} {class:?}: no IN data is copied into another class");
            let data_class = if matches!(class, DNSClass::ANY | DNSClass::NONE) { DNSClass::IN } else { class };
            for record in answer.answers.iter().chain(&answer.authorities) {
                assert_eq!(record.dns_class, data_class, "{name} {class:?}: local records take the question's class");
            }
        }
    }

    #[tokio::test]
    async fn mac_bypass_skips_only_the_blocklist() {
        let mut cfg = Config {
            user_rules: vec!["||blocked.test^".into()],
            rewrites: HashMap::from([("rewrite.test".into(), "::1".parse().unwrap())]),
            no_filter_macs: vec!["AA:BB:CC:DD:EE:FF".into()],
            no_filter_clients: vec!["192.168.1.99".parse().unwrap()],
            upstreams: vec![],
            fallback: vec![],
            ..Config::default()
        };
        cfg.validate().unwrap();
        let s = server(cfg);
        let ip: IpAddr = "192.168.1.10".parse().unwrap();
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

        let q = query("blocked.test", RecordType::A);
        let answer = Message::from_vec(&s.handle(&q.to_vec().unwrap(), ip, false).await.unwrap()).unwrap();
        assert_eq!(answer.metadata.response_code, ResponseCode::NXDomain, "no ARP entry yet");

        s.runtime().macs.replace(HashMap::from([(ip, mac)]));
        let answer = Message::from_vec(&s.handle(&q.to_vec().unwrap(), ip, false).await.unwrap()).unwrap();
        assert_eq!(answer.metadata.response_code, ResponseCode::ServFail, "the blocklist was bypassed");
        let q = query("rewrite.test", RecordType::AAAA);
        let answer = Message::from_vec(&s.handle(&q.to_vec().unwrap(), ip, false).await.unwrap()).unwrap();
        assert_eq!(answer.answers.len(), 1, "rewrites still apply to a bypassed client");

        let q = query("blocked.test", RecordType::A);
        let listed: IpAddr = "192.168.1.99".parse().unwrap();
        let answer = Message::from_vec(&s.handle(&q.to_vec().unwrap(), listed, false).await.unwrap()).unwrap();
        assert_eq!(answer.metadata.response_code, ResponseCode::ServFail, "an IP bypass needs no ARP entry");

        s.runtime().macs.replace(HashMap::from([(ip, [0; 6])]));
        let answer = Message::from_vec(&s.handle(&q.to_vec().unwrap(), ip, false).await.unwrap()).unwrap();
        assert_eq!(answer.metadata.response_code, ResponseCode::NXDomain, "a different MAC does not bypass");
    }

    #[tokio::test]
    async fn rate_limit_drops_excess_without_a_reply() {
        let mut cfg = Config {
            rate_limit_qps: 1,
            rate_limit_burst: 1,
            rewrites: HashMap::from([("limited.test".into(), "::1".parse().unwrap())]),
            upstreams: vec![],
            fallback: vec![],
            ..Config::default()
        };
        cfg.validate().unwrap();
        let s = server(cfg);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let q = query("limited.test", RecordType::AAAA);
        let raw = q.to_vec().unwrap();
        assert!(s.handle(&raw, ip, true).await.is_some(), "the first request fits the burst");
        assert!(s.handle(&raw, ip, true).await.is_none(), "the second request is dropped without a reply");
        assert_eq!(s.runtime().rate.dropped(), 1);
    }

    #[tokio::test]
    async fn clients_outside_allowed_clients_get_refused_before_cache_or_policy() {
        let mut cfg = Config {
            rewrites: HashMap::from([("acl.test".into(), "192.0.2.1".parse().unwrap())]),
            upstreams: vec![],
            fallback: vec![],
            ..Config::default()
        };
        cfg.validate().unwrap();
        let s = server(cfg);
        let raw = query("acl.test", RecordType::A).to_vec().unwrap();
        for (ip, code) in [("192.168.1.20", ResponseCode::NoError), ("203.0.113.9", ResponseCode::Refused)] {
            let answer = Message::from_vec(&s.handle(&raw, ip.parse().unwrap(), true).await.unwrap()).unwrap();
            assert_eq!(answer.metadata.response_code, code, "{ip}");
        }
    }

    fn rrsig(name: &Name) -> Record {
        Record::from_rdata(
            name.clone(),
            60,
            RData::Unknown { code: RecordType::RRSIG, rdata: hickory_proto::rr::rdata::NULL::with(vec![0, 1, 2]) },
        )
    }
    /// A DoH upstream that records each non-probe query's (EDNS, DO) and always
    /// answers with an A record, an RRSIG and AD set.
    async fn dnssec_upstream(seen: Arc<Mutex<Vec<(bool, bool)>>>) -> (String, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else { return };
                let mut head = Vec::new();
                while let Ok(byte) = stream.read_u8().await {
                    head.push(byte);
                    if head.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                let head = String::from_utf8_lossy(&head).to_ascii_lowercase();
                let Some(len) = head.lines().find_map(|line| line.strip_prefix("content-length:")) else {
                    continue;
                };
                let Ok(len) = len.trim().parse::<usize>() else { continue };
                let mut body = vec![0u8; len];
                if stream.read_exact(&mut body).await.is_err() {
                    continue;
                }
                let Some(view) = wire::parse_query(&body) else { continue };
                let Ok(q) = Message::from_vec(&body) else { continue };
                let probe = q.queries[0].query_type() == RecordType::NS && q.queries[0].name().is_root();
                if !probe {
                    seen.lock().unwrap().push((view.edns_present, view.edns_do));
                }
                let name = q.queries[0].name().clone();
                let mut a = reply(&q, ResponseCode::NoError);
                a.metadata.authentic_data = true;
                a.edns.get_or_insert_with(Default::default); // answers always carry an OPT
                a.add_answer(Record::from_rdata(name.clone(), 60, RData::A(A::new(192, 0, 2, 7))));
                a.add_answer(rrsig(&name));
                let a = a.to_vec().unwrap();
                let response_head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    a.len()
                );
                if stream.write_all(response_head.as_bytes()).await.is_err() {
                    continue;
                }
                let _ = stream.write_all(&a).await;
            }
        });
        (format!("http://{addr}/dns-query"), task)
    }

    #[tokio::test]
    async fn upstream_opt_never_reaches_a_non_edns_client() {
        let (url, peer) = dnssec_upstream(Default::default()).await;
        let s = server(Config { upstreams: vec![url], fallback: vec![], ..Config::default() });
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let raw = query("opt.test", RecordType::A).to_vec().unwrap();
        // First call is forwarded, second is a cache hit (RFC 6891 §6.1.1).
        for _ in 0..2 {
            let a = Message::from_vec(&s.handle(&raw, ip, true).await.unwrap()).unwrap();
            assert_eq!(a.answers.len(), 2);
            assert!(a.edns.is_none(), "a non-EDNS client gets no OPT");
        }
        peer.abort();
    }

    #[tokio::test]
    async fn reserved_and_meta_qtypes_are_formerr_and_never_forwarded() {
        // RFC 6895 §3.1: TYPE 0 is reserved, like the meta-TYPEs.
        let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (addr, _peer) = serve_udp_replies(requests.clone(), |q| reply(q, ResponseCode::NoError)).await;
        let s = server(Config { upstreams: vec![], fallback: vec![addr], ..Config::default() });
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        for qtype in [0u16, 41, 128, 248, 250] {
            let raw = query("x.test", RecordType::from(qtype)).to_vec().unwrap();
            let a = Message::from_vec(&s.handle(&raw, ip, true).await.unwrap()).unwrap();
            assert_eq!(a.metadata.response_code, ResponseCode::FormErr, "QTYPE {qtype}");
        }
        assert_eq!(requests.load(std::sync::atomic::Ordering::SeqCst), 0, "nothing reached the upstream");
    }

    #[tokio::test]
    async fn malformed_edns_formerr_carries_an_opt() {
        let s = server(Config { upstreams: vec![], fallback: vec![], ..Config::default() });
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let base = query("x.test", RecordType::A).to_vec().unwrap();
        let mut duplicate = append_record(&base, 41, 1232, 0, &[]);
        duplicate = append_record(&duplicate, 41, 1232, 0, &[]);
        let bad_option = append_record(&base, 41, 1232, 0, &[0, 10, 0]);
        for raw in [duplicate, bad_option] {
            let a = Message::from_vec(&s.handle(&raw, ip, true).await.unwrap()).unwrap();
            assert_eq!(a.metadata.response_code, ResponseCode::FormErr);
            assert!(a.edns.is_some_and(|e| e.max_payload() == 1232), "RFC 6891 §7: FORMERR carries an OPT");
        }
    }

    #[tokio::test]
    async fn always_upstream_sets_do_and_normalizes_per_client_class() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (url, peer) = dnssec_upstream(seen.clone()).await;
        let s = server(Config {
            dnssec: DnssecMode::AlwaysUpstream,
            upstreams: vec![url],
            fallback: vec![],
            ..Config::default()
        });
        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        let plain = query("dnssec.test", RecordType::A);
        let plain_raw = plain.to_vec().unwrap();
        let a = Message::from_vec(&s.handle(&plain_raw, ip, true).await.unwrap()).unwrap();
        assert_eq!(a.metadata.response_code, ResponseCode::NoError);
        assert!(a.edns.is_none(), "a non-EDNS client gets no OPT");
        assert!(!a.metadata.authentic_data, "AD needs the client AD or DO bit");
        assert_eq!(a.answers.len(), 1);
        assert_eq!(a.answers[0].record_type(), RecordType::A, "DNSSEC records are stripped");

        let mut edns_ad = query("dnssec.test", RecordType::A);
        edns_ad.metadata.authentic_data = true;
        edns_ad.edns.get_or_insert_with(Default::default);
        let a = Message::from_vec(&s.handle(&edns_ad.to_vec().unwrap(), ip, true).await.unwrap()).unwrap();
        assert!(a.edns.as_ref().is_some_and(|e| !e.flags().dnssec_ok), "OPT stays, DO is clear");
        assert!(a.metadata.authentic_data, "AD is kept because the client set AD");
        assert!(!a.answers.iter().any(|r| r.record_type() == RecordType::RRSIG), "DNSSEC is stripped");

        let mut edns = query("dnssec.test", RecordType::A);
        edns.edns.get_or_insert_with(Default::default);
        let a = Message::from_vec(&s.handle(&edns.to_vec().unwrap(), ip, true).await.unwrap()).unwrap();
        assert!(a.edns.as_ref().is_some_and(|e| !e.flags().dnssec_ok));
        assert!(!a.metadata.authentic_data, "AD is cleared without client AD or DO");

        let mut do_query = query("dnssec.test", RecordType::A);
        do_query.edns.get_or_insert_with(Default::default).set_dnssec_ok(true);
        let a = Message::from_vec(&s.handle(&do_query.to_vec().unwrap(), ip, true).await.unwrap()).unwrap();
        assert!(a.edns.as_ref().is_some_and(|e| e.flags().dnssec_ok), "DO is returned to a DO client");
        assert!(a.metadata.authentic_data);
        assert!(a.answers.iter().any(|r| r.record_type() == RecordType::RRSIG), "a DO client gets the full response");

        // An explicit DNSSEC qtype is answered even with DO=0 (RFC 4035 3.2.1).
        let mut explicit = query("dnssec.test", RecordType::RRSIG);
        explicit.edns.get_or_insert_with(Default::default);
        let a = Message::from_vec(&s.handle(&explicit.to_vec().unwrap(), ip, true).await.unwrap()).unwrap();
        assert!(a.answers.iter().any(|r| r.record_type() == RecordType::RRSIG), "the explicit query type survives");

        let calls = seen.lock().unwrap().len();
        let a = Message::from_vec(&s.handle(&plain_raw, ip, true).await.unwrap()).unwrap();
        assert!(a.edns.is_none());
        assert_eq!(seen.lock().unwrap().len(), calls, "the normalized cache hit needs no new upstream query");

        let seen = seen.lock().unwrap();
        assert!(seen.iter().all(|(edns, do_bit)| *edns && *do_bit), "DO is set upstream: {seen:?}");
        peer.abort();
    }

    #[tokio::test]
    async fn passthrough_forwards_the_client_do_bit_unchanged() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (url, peer) = dnssec_upstream(seen.clone()).await;
        let s = server(Config { upstreams: vec![url], fallback: vec![], ..Config::default() });
        assert_eq!(s.runtime().cfg.dnssec, DnssecMode::Passthrough);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        let a = Message::from_vec(
            &s.handle(&query("plain.test", RecordType::A).to_vec().unwrap(), ip, true).await.unwrap(),
        )
        .unwrap();
        assert!(a.edns.is_none());
        let mut do_query = query("plain.test", RecordType::A);
        do_query.edns.get_or_insert_with(Default::default).set_dnssec_ok(true);
        let a = Message::from_vec(&s.handle(&do_query.to_vec().unwrap(), ip, true).await.unwrap()).unwrap();
        assert!(a.edns.as_ref().is_some_and(|e| e.flags().dnssec_ok));

        let seen = seen.lock().unwrap();
        assert_eq!(&*seen, &[(false, false), (true, true)], "the client bits reach the upstream unchanged");
        peer.abort();
    }

    #[tokio::test]
    async fn fallback_preserves_wire_truncation_and_cache() {
        // RFC 5452 §9.3: the upstream answers 40 records (above 512) with TC over UDP and
        // in full over TCP; the client still gets TC over UDP, then the cache.
        let mut q = query("large.test", RecordType::A);
        q.metadata.checking_disabled = true;
        let raw = q.to_vec().unwrap();
        let original = wire::parse_query(&raw).unwrap();
        let expected = (original.qname_lower, original.qname_len, original.qtype, original.qclass, original.cd);
        let sent_ok = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let checked = sent_ok.clone();
        let (addr, peer) = serve_udp_replies(Arc::new(std::sync::atomic::AtomicUsize::new(0)), move |q| {
            let sent = wire::parse_query(&q.to_vec().unwrap())
                .map(|sent| (sent.qname_lower, sent.qname_len, sent.qtype, sent.qclass, sent.cd) == expected);
            checked.fetch_or(sent == Some(true), Ordering::SeqCst);
            let mut a = reply(q, ResponseCode::NoError);
            for i in 0..40 {
                a.add_answer(Record::from_rdata(q.queries[0].name().clone(), 120, RData::A(A::new(192, 0, 2, i))));
            }
            a
        })
        .await;
        let s = server(Config { upstreams: vec![], fallback: vec![addr], ..Config::default() });
        let ip = "127.0.0.1".parse().unwrap();
        let a = s.handle(&raw, ip, true).await.unwrap();
        let a = Message::from_vec(&a).unwrap();
        assert!(a.metadata.truncation);
        assert!(a.answers.is_empty());
        assert!(sent_ok.load(Ordering::SeqCst), "the upstream saw the client's name, type, class and CD");
        peer.abort();
        q.metadata.id = 99;
        let a = s.handle(&q.to_vec().unwrap(), ip, false).await.unwrap();
        let a = Message::from_vec(&a).unwrap();
        assert_eq!(a.metadata.id, 99);
        assert_eq!(a.answers.len(), 40);
        assert!(a.metadata.checking_disabled);
    }
    #[tokio::test]
    async fn stale_refresh_is_single_and_bypass_still_rewrites() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let s = server(Config {
            upstreams: vec![],
            fallback: vec![addr],
            user_rules: vec!["||x.test^".into()],
            no_filter_clients: vec!["127.0.0.1".parse().unwrap()],
            rewrites: HashMap::from([("r.test".into(), "::1".parse().unwrap())]),
            ..Config::default()
        });
        let q = query("x.test", RecordType::A);
        let mut a = reply(&q, ResponseCode::NoError);
        a.add_answer(Record::from_rdata(q.queries[0].name().clone(), 120, RData::A(A::new(192, 0, 2, 1))));
        let key = key_for(&q);
        assert!(s.cache().insert(&key, &a.to_vec().unwrap(), &a, 0));
        s.cache().backdate(&key, 121);
        let ip = "127.0.0.1".parse().unwrap();
        for _ in 0..10 {
            let a = s.handle(&q.to_vec().unwrap(), ip, false).await.unwrap();
            assert_eq!(Message::from_vec(&a).unwrap().answers[0].ttl, 30);
        }
        let mut buf = vec![0; 65535];
        let (n, peer) = timeout(Duration::from_secs(1), socket.recv_from(&mut buf)).await.unwrap().unwrap();
        assert!(timeout(Duration::from_millis(20), socket.recv_from(&mut vec![0; 65535])).await.is_err());
        let mut a = reply(&Message::from_vec(&buf[..n]).unwrap(), ResponseCode::NoError);
        a.add_answer(Record::from_rdata(q.queries[0].name().clone(), 120, RData::A(A::new(192, 0, 2, 2))));
        socket.send_to(&wire_reply(&buf[..n], a), peer).await.unwrap();
        timeout(Duration::from_secs(1), async {
            while !s.inflight().is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let q = query("r.test", RecordType::AAAA);
        let a = s.handle(&q.to_vec().unwrap(), ip, false).await.unwrap();
        assert_eq!(Message::from_vec(&a).unwrap().answers.len(), 1);
        let mut raw = q.to_vec().unwrap();
        raw.push(0);
        // Trailing bytes are unparseable, so they get FORMERR rather than an answer.
        let a = s.handle(&raw, ip, false).await.unwrap();
        assert_eq!(Message::from_vec(&a).unwrap().metadata.response_code, ResponseCode::FormErr);
    }
    #[tokio::test]
    async fn doh_race_and_udp_fallback() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut q = query("doh.test", RecordType::A);
        q.metadata.checking_disabled = true;
        q.edns.get_or_insert_with(Default::default).set_dnssec_ok(true);
        let raw = q.to_vec().unwrap();
        let mut expected = raw.clone();
        expected[0..2].copy_from_slice(&0u16.to_be_bytes());
        let peer = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut b = Vec::new();
                loop {
                    b.push(stream.read_u8().await.unwrap());
                    if b.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                let head = String::from_utf8(b).unwrap().to_ascii_lowercase();
                assert!(head.contains("content-type: application/dns-message"));
                assert!(head.contains("accept: application/dns-message"));
                let len: usize =
                    head.lines().find_map(|line| line.strip_prefix("content-length:")).unwrap().trim().parse().unwrap();
                let mut body = vec![0; len];
                stream.read_exact(&mut body).await.unwrap();
                assert_eq!(&body[..2], &[0, 0]);
                let parsed = Message::from_vec(&body).unwrap();
                let probe = parsed.queries[0].query_type() == RecordType::NS && parsed.queries[0].name().is_root();
                let mut a = reply(&parsed, ResponseCode::NoError);
                if probe {
                    assert!(parsed.edns.is_none());
                } else {
                    assert_eq!(&body[12..], &expected[12..]);
                    assert!(parsed.metadata.checking_disabled);
                    assert!(parsed.edns.as_ref().unwrap().flags().dnssec_ok);
                    a.add_answer(Record::from_rdata(
                        parsed.queries[0].name().clone(),
                        60,
                        RData::A(A::new(192, 0, 2, 1)),
                    ));
                }
                let a = a.to_vec().unwrap();
                stream
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            a.len()
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
                stream.write_all(&a).await.unwrap();
                if !probe {
                    return;
                }
            }
        });
        let s = server(Config {
            upstreams: vec!["http://127.0.0.1:1/dns-query".into(), format!("http://{addr}/dns-query")],
            fallback: vec![],
            ..Config::default()
        });
        assert!(s.runtime().upstreams.exchange(&raw, q.metadata.id).await.is_some());
        peer.await.unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let mut b = vec![0; 65535];
            let (n, p) = socket.recv_from(&mut b).await.unwrap();
            let q = Message::from_vec(&b[..n]).unwrap();
            let mut a = reply(&q, ResponseCode::NoError);
            a.add_answer(Record::from_rdata(q.queries[0].name().clone(), 60, RData::A(A::new(192, 0, 2, 1))));
            let mut bytes = a.to_vec().unwrap();
            wire::copy_question_case(&b[..n], &mut bytes);
            socket.send_to(&bytes, p).await.unwrap();
        });
        let s = server(Config {
            upstreams: vec!["http://127.0.0.1:1/dns-query".into()],
            fallback: vec![addr],
            ..Config::default()
        });
        assert!(s.runtime().upstreams.exchange(&raw, q.metadata.id).await.is_some());
        peer.await.unwrap();
    }
    #[tokio::test]
    async fn non_terminal_answer_is_not_cached() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let peer = tokio::spawn({
            let calls = calls.clone();
            async move {
                loop {
                    let mut buf = vec![0; 65535];
                    let Ok((n, peer)) = socket.recv_from(&mut buf).await else { break };
                    calls.fetch_add(1, SeqCst);
                    let q = Message::from_vec(&buf[..n]).unwrap();
                    let a = reply(&q, ResponseCode::NoError);
                    socket.send_to(&wire_reply(&buf[..n], a), peer).await.unwrap();
                }
            }
        });
        let s = server(Config { upstreams: vec![], fallback: vec![addr], ..Config::default() });
        let raw = query("incomplete.test", RecordType::A).to_vec().unwrap();
        let ip = "127.0.0.1".parse().unwrap();
        for _ in 0..2 {
            let a = s.handle(&raw, ip, false).await.unwrap();
            assert_eq!(code(&a), ResponseCode::NoError);
            assert!(Message::from_vec(&a).unwrap().answers.is_empty());
        }
        assert_eq!(calls.load(SeqCst), 2);
        peer.abort();
    }
    #[tokio::test]
    async fn doh_age_reduces_relayed_and_cached_ttl() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut b = Vec::new();
                loop {
                    b.push(stream.read_u8().await.unwrap());
                    if b.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                let head = String::from_utf8(b).unwrap().to_ascii_lowercase();
                let len: usize =
                    head.lines().find_map(|line| line.strip_prefix("content-length:")).unwrap().trim().parse().unwrap();
                let mut body = vec![0; len];
                stream.read_exact(&mut body).await.unwrap();
                let parsed = Message::from_vec(&body).unwrap();
                let probe = parsed.queries[0].query_type() == RecordType::NS && parsed.queries[0].name().is_root();
                let mut a = reply(&parsed, ResponseCode::NoError);
                if !probe {
                    a.add_answer(Record::from_rdata(
                        parsed.queries[0].name().clone(),
                        300,
                        RData::A(A::new(192, 0, 2, 7)),
                    ));
                }
                let a = a.to_vec().unwrap();
                stream
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nAge: 120\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            a.len()
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
                stream.write_all(&a).await.unwrap();
                if !probe {
                    return;
                }
            }
        });
        let s = server(Config {
            upstreams: vec![format!("http://{addr}/dns-query")],
            fallback: vec![],
            ..Config::default()
        });
        let raw = query("age.test", RecordType::A).to_vec().unwrap();
        let ip = "127.0.0.1".parse().unwrap();
        let first = Message::from_vec(&s.handle(&raw, ip, false).await.unwrap()).unwrap();
        assert_eq!(first.answers[0].ttl, 180);
        let second = Message::from_vec(&s.handle(&raw, ip, false).await.unwrap()).unwrap();
        assert_eq!(second.answers[0].ttl, 180);
        peer.await.unwrap();
    }
    /// One long-lived plain-HTTP/1.1 DoH mock answering every request with an
    /// A record and an `Age` header, used by the relaying tests below.
    async fn serve_doh(
        ttl: u32,
        age: u32,
        ad: bool,
        requests: Arc<std::sync::atomic::AtomicUsize>,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else { return };
                let mut head = Vec::new();
                while let Ok(byte) = stream.read_u8().await {
                    head.push(byte);
                    if head.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                let head = String::from_utf8_lossy(&head).to_ascii_lowercase();
                let Some(len) = head.lines().find_map(|line| line.strip_prefix("content-length:")) else {
                    continue;
                };
                let Ok(len) = len.trim().parse::<usize>() else { continue };
                let mut body = vec![0u8; len];
                if stream.read_exact(&mut body).await.is_err() {
                    continue;
                }
                let Ok(parsed) = Message::from_vec(&body) else { continue };
                requests.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let mut answer = reply(&parsed, ResponseCode::NoError);
                answer.add_answer(Record::from_rdata(
                    parsed.queries[0].name().clone(),
                    ttl,
                    RData::A(A::new(192, 0, 2, 7)),
                ));
                answer.metadata.authentic_data = ad;
                let answer = answer.to_vec().unwrap();
                let response_head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nAge: {age}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    answer.len()
                );
                if stream.write_all(response_head.as_bytes()).await.is_err() {
                    continue;
                }
                let _ = stream.write_all(&answer).await;
            }
        });
        (format!("http://{addr}/dns-query"), task)
    }
    #[tokio::test]
    async fn zero_ttl_after_age_is_relayed_but_not_cached() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        let requests = Arc::new(AtomicUsize::new(0));
        let (url, peer) = serve_doh(60, 60, false, requests.clone()).await;
        let s = server(Config { upstreams: vec![url], fallback: vec![], ..Config::default() });
        let raw = query("zero-age.test", RecordType::A).to_vec().unwrap();
        let ip = "127.0.0.1".parse().unwrap();
        for _ in 0..2 {
            let answer = Message::from_vec(&s.handle(&raw, ip, false).await.unwrap()).unwrap();
            assert_eq!(answer.answers[0].ttl, 0);
        }
        assert_eq!(requests.load(SeqCst), 2, "zero-TTL answer must not be cached");
        peer.abort();
    }
    #[tokio::test]
    async fn an_unstorable_refresh_ends_stale_service() {
        // A TTL-0 refresh supersedes the stale copy.
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        let requests = Arc::new(AtomicUsize::new(0));
        let counter = requests.clone();
        let (addr, _peer) = serve_udp_replies(requests.clone(), move |q| {
            let ttl = if counter.load(SeqCst) <= 1 { 1 } else { 0 };
            let mut answer = reply(q, ResponseCode::NoError);
            answer.add_answer(Record::from_rdata(q.queries[0].name().clone(), ttl, RData::A(A::new(192, 0, 2, 3))));
            answer
        })
        .await;
        let s = server(Config {
            upstreams: vec![],
            fallback: vec![addr],
            cache_size: 100,
            prefetch: false,
            trust_plain_upstreams: true,
            ..Config::default()
        });
        let raw = query("refresh-zero.test", RecordType::A).to_vec().unwrap();
        send(&s, &raw).await.unwrap();
        tokio::time::sleep(Duration::from_millis(1200)).await;
        send(&s, &raw).await.unwrap(); // stale hit; the refresh answers TTL 0
        tokio::time::sleep(Duration::from_millis(300)).await;
        let before = requests.load(SeqCst);
        assert_eq!(before, 2, "one fill, one refresh");
        let third = Message::from_vec(&send(&s, &raw).await.unwrap()).unwrap();
        assert_eq!(third.answers[0].ttl, 0, "a relayed TTL-0 answer, not the stale copy (TTL 30)");
        assert_eq!(requests.load(SeqCst), 3, "the stale copy is gone; the next query goes upstream");
    }

    #[tokio::test]
    async fn uncached_doh_ad_follows_the_conservative_client_profile() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        let requests = Arc::new(AtomicUsize::new(0));
        let (url, peer) = serve_doh(60, 0, true, requests.clone()).await;
        let s = server(Config { upstreams: vec![url], fallback: vec![], ..Config::default() });
        let ip = "127.0.0.1".parse().unwrap();

        let plain = query("ad-profile.test", RecordType::A).to_vec().unwrap();
        for _ in 0..2 {
            let answer = Message::from_vec(&s.handle(&plain, ip, false).await.unwrap()).unwrap();
            assert!(!answer.metadata.authentic_data, "AD cleared for a non-AD/DO client");
        }

        let mut ad_query = query("ad-profile.test", RecordType::A);
        ad_query.metadata.authentic_data = true;
        let ad_query = ad_query.to_vec().unwrap();
        // Only the directly relayed answer keeps AD (RFC 6840 §5.8); a cache hit has no
        // validation-lifetime metadata and clears it.
        for first in [true, false] {
            let answer = Message::from_vec(&s.handle(&ad_query, ip, false).await.unwrap()).unwrap();
            assert_eq!(answer.metadata.authentic_data, first, "AD kept on the relay, cleared on a hit");
        }

        let mut do_query = query("ad-profile.test", RecordType::A);
        do_query.edns.get_or_insert_with(Default::default).set_dnssec_ok(true);
        let do_query = do_query.to_vec().unwrap();
        for first in [true, false] {
            let answer = Message::from_vec(&s.handle(&do_query, ip, false).await.unwrap()).unwrap();
            assert_eq!(answer.metadata.authentic_data, first, "AD kept on the relay when DO is set, cleared on a hit");
        }

        assert_eq!(requests.load(SeqCst), 3, "one upstream call per cache key");
        peer.abort();
    }
    /// UDP fallback mock that counts queries, optionally delays and optionally
    /// answers with one A record. Each query gets its own 60 s TTL answer.
    async fn serve_udp(
        replies: bool,
        delay: Duration,
        requests: Arc<std::sync::atomic::AtomicUsize>,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        use std::sync::atomic::Ordering::SeqCst;
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = socket.local_addr().unwrap();
        let task = tokio::spawn(async move {
            loop {
                let mut buf = vec![0; 65535];
                let Ok((n, peer)) = socket.recv_from(&mut buf).await else { return };
                // Count on arrival, not after the reply delay: a leaked second
                // query must be visible even while the first reply is sleeping.
                requests.fetch_add(1, SeqCst);
                if !replies {
                    continue;
                }
                buf.truncate(n);
                let socket = socket.clone();
                tokio::spawn(async move {
                    if !delay.is_zero() {
                        sleep(delay).await;
                    }
                    let q = Message::from_vec(&buf).unwrap();
                    let mut a = reply(&q, ResponseCode::NoError);
                    a.add_answer(Record::from_rdata(q.queries[0].name().clone(), 60, RData::A(A::new(192, 0, 2, 1))));
                    let _ = socket.send_to(&wire_reply(&buf, a), peer).await;
                });
            }
        });
        (addr, task)
    }
    #[tokio::test]
    async fn concurrent_identical_misses_coalesce_to_one_upstream_request() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        let requests = Arc::new(AtomicUsize::new(0));
        let (addr, peer) = serve_udp(true, Duration::from_millis(300), requests.clone()).await;
        let s = server(Config {
            upstreams: vec![],
            fallback: vec![addr],
            upstream_timeout_seconds: 2,
            ..Config::default()
        });
        let ip = "127.0.0.1".parse().unwrap();
        let mut clients = JoinSet::new();
        for i in 0..50u16 {
            let s = s.clone();
            clients.spawn(async move {
                let name = if i % 2 == 0 { "burst.test" } else { "BuRsT.TeSt" };
                let mut q = query(name, RecordType::A);
                q.metadata.id = 0x4000 + i;
                let answer = s.handle(&q.to_vec().unwrap(), ip, false).await.unwrap();
                (q.metadata.id, wire_name(name), answer)
            });
        }
        let mut ids = std::collections::HashSet::new();
        while let Some(result) = clients.join_next().await {
            let (id, name, answer) = result.unwrap();
            let parsed = Message::from_vec(&answer).unwrap();
            assert_eq!(parsed.metadata.id, id, "each waiter patches its own ID");
            assert_eq!(parsed.answers.len(), 1);
            let view = wire::parse_query(&answer).unwrap();
            assert_eq!(view.qname_wire, name.as_slice(), "each waiter echoes its own question case");
            assert!(ids.insert(id));
        }
        assert_eq!(ids.len(), 50);
        assert_eq!(requests.load(SeqCst), 1, "50 identical misses must make one upstream request");
        assert!(s.inflight().is_empty());
        peer.abort();
    }
    #[tokio::test]
    async fn different_do_and_cd_contexts_do_not_coalesce() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        let requests = Arc::new(AtomicUsize::new(0));
        let (addr, peer) = serve_udp(true, Duration::from_millis(100), requests.clone()).await;
        let s = server(Config {
            upstreams: vec![],
            fallback: vec![addr],
            upstream_timeout_seconds: 2,
            ..Config::default()
        });
        let ip = "127.0.0.1".parse().unwrap();
        let mut clients = JoinSet::new();
        for context in 0..3u16 {
            let s = s.clone();
            clients.spawn(async move {
                let mut q = query("contexts.test", RecordType::A);
                q.metadata.id = 0x5000 + context;
                match context {
                    1 => q.metadata.checking_disabled = true,
                    2 => {
                        q.edns.get_or_insert_with(Default::default).set_dnssec_ok(true);
                    }
                    _ => {}
                }
                Message::from_vec(&s.handle(&q.to_vec().unwrap(), ip, false).await.unwrap()).unwrap().metadata.id
            });
        }
        let mut ids = std::collections::HashSet::new();
        while let Some(result) = clients.join_next().await {
            assert!(ids.insert(result.unwrap()));
        }
        assert_eq!(ids.len(), 3);
        assert_eq!(requests.load(SeqCst), 3, "DO and CD contexts must have their own leaders");
        peer.abort();
    }
    #[tokio::test]
    async fn edns_option_queries_bypass_the_flight_map() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        let requests = Arc::new(AtomicUsize::new(0));
        let (addr, peer) = serve_udp(true, Duration::from_millis(100), requests.clone()).await;
        let s = server(Config {
            upstreams: vec![],
            fallback: vec![addr],
            upstream_timeout_seconds: 2,
            ..Config::default()
        });
        let ip = "127.0.0.1".parse().unwrap();
        let mut clients = JoinSet::new();
        for payload in 0..2u8 {
            let s = s.clone();
            clients.spawn(async move {
                let mut q = query("ecs.test", RecordType::A);
                q.metadata.id = 0x6000 + u16::from(payload);
                q.edns
                    .get_or_insert_with(Default::default)
                    .options_mut()
                    .insert(hickory_proto::rr::rdata::opt::EdnsOption::Unknown(65001, vec![payload]));
                let answer = s.handle(&q.to_vec().unwrap(), ip, false).await.unwrap();
                Message::from_vec(&answer).unwrap().metadata.id
            });
        }
        while clients.join_next().await.is_some() {}
        assert_eq!(requests.load(SeqCst), 2, "EDNS options bypass coalescing and caching");
        assert!(s.inflight().is_empty());
        peer.abort();
    }
    #[tokio::test]
    async fn a_failed_leader_answers_every_follower_with_servfail() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        let requests = Arc::new(AtomicUsize::new(0));
        let (addr, peer) = serve_udp(false, Duration::ZERO, requests.clone()).await;
        let s = server(Config {
            upstreams: vec![],
            fallback: vec![addr],
            upstream_timeout_seconds: 1,
            ..Config::default()
        });
        let ip = "127.0.0.1".parse().unwrap();
        let mut clients = JoinSet::new();
        for i in 0..10u16 {
            let s = s.clone();
            clients.spawn(async move {
                let mut q = query("fail.test", RecordType::A);
                q.metadata.id = 0x7000 + i;
                (q.metadata.id, s.handle(&q.to_vec().unwrap(), ip, false).await.unwrap())
            });
        }
        while let Some(result) = clients.join_next().await {
            let (id, answer) = result.unwrap();
            assert_eq!(Message::from_vec(&answer).unwrap().metadata.id, id);
            assert_eq!(code(&answer), ResponseCode::ServFail, "a failed leader must SERVFAIL its followers");
        }
        assert_eq!(requests.load(SeqCst), 1, "followers must not retry after a leader failure");
        assert!(s.inflight().is_empty());
        peer.abort();
    }
    #[tokio::test]
    async fn fresh_cache_hits_do_not_touch_the_flight_map() {
        let s = server(Config { upstreams: vec![], fallback: vec![], ..Config::default() });
        let q = query("hit.test", RecordType::A);
        let mut a = reply(&q, ResponseCode::NoError);
        a.add_answer(Record::from_rdata(q.queries[0].name().clone(), 60, RData::A(A::new(192, 0, 2, 9))));
        let key = key_for(&q);
        assert!(s.cache().insert(&key, &a.to_vec().unwrap(), &a, 0));
        // Hold a live leader for the same key: a hit that joined the map would
        // wait on this guard instead of answering from the cache.
        let inflight::Role::Leader(guard) = s.inflight().join(&key) else { panic!("leader") };
        let answer = timeout(Duration::from_millis(200), send(&s, &q.to_vec().unwrap()))
            .await
            .expect("a cache hit must not join the flight map")
            .unwrap();
        let answer = Message::from_vec(&answer).unwrap();
        assert_eq!(answer.answers.len(), 1);
        assert_eq!(answer.answers[0].ttl, 60);
        assert_eq!(s.inflight().len(), 1, "the hit left the test leader's entry alone");
        guard.complete(None);
        assert!(s.inflight().is_empty());
    }
    #[tokio::test]
    async fn a_non_in_class_query_is_never_served_from_cache_or_shared() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let (seen_tx, seen_rx) = tokio::sync::oneshot::channel();
        let peer = tokio::spawn(async move {
            let mut buf = vec![0; 65535];
            let (n, peer) = socket.recv_from(&mut buf).await.unwrap();
            let _ = seen_tx.send(());
            let q = Message::from_vec(&buf[..n]).unwrap();
            let mut a = reply(&q, ResponseCode::NoError);
            // The answer is in the question's class.
            let mut record = Record::from_rdata(q.queries[0].name().clone(), 60, RData::A(A::new(192, 0, 2, 3)));
            record.dns_class = q.queries[0].query_class();
            a.add_answer(record);
            socket.send_to(&wire_reply(&buf[..n], a), peer).await.unwrap();
        });
        let s = server(Config { upstreams: vec![], fallback: vec![addr], ..Config::default() });
        let mut q = query("hesiod.test", RecordType::A);
        q.queries[0].set_query_class(DNSClass::HS);
        let mut a = reply(&q, ResponseCode::NoError);
        a.add_answer(Record::from_rdata(q.queries[0].name().clone(), 120, RData::A(A::new(192, 0, 2, 1))));
        let key = key_for(&q);
        assert!(s.cache().insert(&key, &a.to_vec().unwrap(), &a, 0));
        s.cache().backdate(&key, 121);
        let answer = s.handle(&q.to_vec().unwrap(), "127.0.0.1".parse().unwrap(), false).await.unwrap();
        // Non-IN classes are IN-only for sharing, so even an entry that
        // somehow exists is ignored and the query goes upstream.
        assert_eq!(Message::from_vec(&answer).unwrap().answers[0].ttl, 60, "forwarded, not served from cache");
        timeout(Duration::from_secs(1), seen_rx).await.expect("a non-IN query is forwarded").unwrap();
        assert!(s.inflight().is_empty(), "a non-IN-class query must not join the single-flight map");
        peer.await.unwrap();
    }

    /// Polls `condition` until it holds. Generous 2 s bound for a noisy host.
    async fn wait_until(mut condition: impl FnMut() -> bool) {
        timeout(Duration::from_secs(2), async {
            while !condition() {
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("condition was not reached in time");
    }

    /// Inserts a positive TTL-100 entry under `key` and ages it past expiry.
    fn seed_stale(s: &Arc<Server>, q: &Message, key: &[u8]) {
        let mut a = reply(q, ResponseCode::NoError);
        a.add_answer(Record::from_rdata(q.queries[0].name().clone(), 100, RData::A(A::new(192, 0, 2, 1))));
        assert!(s.cache().insert(key, &a.to_vec().unwrap(), &a, 0));
        s.cache().backdate(key, 101);
    }

    /// Only a fresh positive hit in its last 10% of lifetime prefetches.
    /// The client still gets the stored answer and the next hit gets the
    /// refreshed one.
    #[tokio::test]
    async fn prefetch_refreshes_positive_hits_only_in_the_last_tenth() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        let requests = Arc::new(AtomicUsize::new(0));
        let (addr, peer) = serve_udp(true, Duration::ZERO, requests.clone()).await;
        let s = server(Config { upstreams: vec![], fallback: vec![addr], ..Config::default() });
        let ip = "127.0.0.1".parse().unwrap();
        let q = query("prefetch.test", RecordType::A);
        let raw = q.to_vec().unwrap();
        let key = key_for(&q);
        let mut stored = reply(&q, ResponseCode::NoError);
        stored.add_answer(Record::from_rdata(q.queries[0].name().clone(), 100, RData::A(A::new(192, 0, 2, 1))));
        assert!(s.cache().insert(&key, &stored.to_vec().unwrap(), &stored, 0));

        let answer = Message::from_vec(&s.handle(&raw, ip, false).await.unwrap()).unwrap();
        assert_eq!(answer.answers[0].ttl, 100);
        assert_eq!(requests.load(SeqCst), 0, "a hit with more than 10% left must not prefetch");

        // 11 s of 100 s left: outside the window.
        s.cache().backdate(&key, 89);
        let answer = Message::from_vec(&s.handle(&raw, ip, false).await.unwrap()).unwrap();
        assert_eq!(answer.answers[0].ttl, 11);
        assert!(s.inflight().is_empty(), "more than 10% left must not prefetch");

        // The window opens at 90.000 s, decided in milliseconds. At
        // 90.001 s whole seconds still say "10 s left"; that must prefetch.
        s.cache().backdate_ms(&key, 1_001);
        let answer = Message::from_vec(&s.handle(&raw, ip, false).await.unwrap()).unwrap();
        assert_eq!(answer.answers[0].ttl, 10, "the client still gets the stored answer");
        wait_until(|| s.cache().get(&key, 0, 43_200).is_some_and(|hit| hit.orig_ttl == 60)).await;
        assert_eq!(requests.load(SeqCst), 1, "exactly one background refresh");

        let answer = Message::from_vec(&s.handle(&raw, ip, false).await.unwrap()).unwrap();
        assert_eq!(answer.answers[0].ttl, 60, "the next hit serves the refreshed answer");
        assert_eq!(requests.load(SeqCst), 1, "the refreshed entry is not prefetched");
        peer.abort();
    }

    /// `prefetch = false` leaves a near-expiry hit alone.
    #[tokio::test]
    async fn prefetch_disabled_does_not_refresh_near_expiry_hits() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        let requests = Arc::new(AtomicUsize::new(0));
        let (addr, peer) = serve_udp(true, Duration::ZERO, requests.clone()).await;
        let s = server(Config { upstreams: vec![], fallback: vec![addr], prefetch: false, ..Config::default() });
        let ip = "127.0.0.1".parse().unwrap();
        let q = query("no-prefetch.test", RecordType::A);
        let key = key_for(&q);
        let mut stored = reply(&q, ResponseCode::NoError);
        stored.add_answer(Record::from_rdata(q.queries[0].name().clone(), 100, RData::A(A::new(192, 0, 2, 1))));
        assert!(s.cache().insert(&key, &stored.to_vec().unwrap(), &stored, 0));
        s.cache().backdate(&key, 96);

        let answer = Message::from_vec(&s.handle(&q.to_vec().unwrap(), ip, false).await.unwrap()).unwrap();
        assert_eq!(answer.answers[0].ttl, 4, "the near-expiry hit is still answered");
        sleep(Duration::from_millis(100)).await;
        assert_eq!(requests.load(SeqCst), 0, "prefetch is off");
        assert!(s.inflight().is_empty());
        peer.abort();
    }

    /// Two concurrent hits inside the threshold share one refresh.
    #[tokio::test]
    async fn concurrent_near_expiry_hits_refresh_once() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        let requests = Arc::new(AtomicUsize::new(0));
        let (addr, peer) = serve_udp(true, Duration::from_millis(200), requests.clone()).await;
        let s = server(Config { upstreams: vec![], fallback: vec![addr], ..Config::default() });
        let ip = "127.0.0.1".parse().unwrap();
        let q = query("burst-prefetch.test", RecordType::A);
        let key = key_for(&q);
        let mut stored = reply(&q, ResponseCode::NoError);
        stored.add_answer(Record::from_rdata(q.queries[0].name().clone(), 100, RData::A(A::new(192, 0, 2, 1))));
        assert!(s.cache().insert(&key, &stored.to_vec().unwrap(), &stored, 0));
        s.cache().backdate(&key, 96);

        let mut clients = JoinSet::new();
        for id in 0..2u16 {
            let s = s.clone();
            let mut q = q.clone();
            q.metadata.id = 0x9000 + id;
            clients.spawn(async move {
                Message::from_vec(&s.handle(&q.to_vec().unwrap(), ip, false).await.unwrap()).unwrap()
            });
        }
        while let Some(result) = clients.join_next().await {
            assert_eq!(result.unwrap().answers[0].ttl, 4, "each client gets the stored answer");
        }
        wait_until(|| requests.load(SeqCst) == 1).await;
        sleep(Duration::from_millis(300)).await;
        assert_eq!(requests.load(SeqCst), 1, "the second hit joined the running refresh");
        peer.abort();
    }

    /// A stale hit goes through the stale refresh path only; prefetch must
    /// not add a second upstream query.
    #[tokio::test]
    async fn stale_hits_are_not_prefetched_twice() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        let requests = Arc::new(AtomicUsize::new(0));
        let (addr, peer) = serve_udp(true, Duration::from_millis(100), requests.clone()).await;
        let s = server(Config {
            upstreams: vec![],
            fallback: vec![addr],
            serve_stale_client_timeout_ms: 0,
            ..Config::default()
        });
        let ip = "127.0.0.1".parse().unwrap();
        let q = query("stale-prefetch.test", RecordType::A);
        let key = key_for(&q);
        seed_stale(&s, &q, &key);

        let answer = Message::from_vec(&s.handle(&q.to_vec().unwrap(), ip, false).await.unwrap()).unwrap();
        assert_eq!(answer.answers[0].ttl, 30, "the stale copy answers the client");
        wait_until(|| requests.load(SeqCst) == 1).await;
        sleep(Duration::from_millis(300)).await;
        assert_eq!(requests.load(SeqCst), 1, "only the stale refresh went upstream");
        peer.abort();
    }

    /// Near-expiry negatives are never prefetched.
    #[tokio::test]
    async fn near_expiry_negative_entries_are_not_prefetched() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        let requests = Arc::new(AtomicUsize::new(0));
        let (addr, peer) = serve_udp(true, Duration::ZERO, requests.clone()).await;
        let s = server(Config { upstreams: vec![], fallback: vec![addr], ..Config::default() });
        let ip = "127.0.0.1".parse().unwrap();
        let q = query("negative-prefetch.test", RecordType::A);
        let key = key_for(&q);
        let mut negative = reply(&q, ResponseCode::NXDomain);
        negative.add_authority(Record::from_rdata(
            Name::root(),
            100,
            RData::SOA(SOA::new(Name::root(), Name::root(), 0, 0, 0, 0, 100)),
        ));
        assert!(s.cache().insert(&key, &negative.to_vec().unwrap(), &negative, 0));
        s.cache().backdate(&key, 96);

        let answer = Message::from_vec(&s.handle(&q.to_vec().unwrap(), ip, false).await.unwrap()).unwrap();
        assert_eq!(answer.metadata.response_code, ResponseCode::NXDomain, "the negative is still answered");
        sleep(Duration::from_millis(100)).await;
        assert_eq!(requests.load(SeqCst), 0, "negatives are never prefetched");
        peer.abort();
    }

    /// Timeout 0 (an opt-in, not RFC 8767): stale now, refresh in background.
    #[tokio::test]
    async fn stale_timeout_zero_answers_immediately_and_refreshes() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        let requests = Arc::new(AtomicUsize::new(0));
        let (addr, peer) = serve_udp(true, Duration::from_secs(1), requests.clone()).await;
        let s = server(Config {
            upstreams: vec![],
            fallback: vec![addr],
            serve_stale_client_timeout_ms: 0,
            ..Config::default()
        });
        let ip = "127.0.0.1".parse().unwrap();
        let q = query("stale-zero.test", RecordType::A);
        let key = key_for(&q);
        seed_stale(&s, &q, &key);

        let started = Instant::now();
        let answer = Message::from_vec(&s.handle(&q.to_vec().unwrap(), ip, false).await.unwrap()).unwrap();
        assert!(started.elapsed() < Duration::from_millis(500), "stale is served without waiting");
        assert_eq!(answer.answers[0].ttl, 30);
        wait_until(|| requests.load(SeqCst) == 1).await;
        peer.abort();
    }

    /// A positive timeout turns a stale hit into one refresh attempt; a
    /// fast upstream answer is returned instead of the TTL-30 copy.
    #[tokio::test]
    async fn stale_timeout_returns_a_fast_fresh_answer() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        let requests = Arc::new(AtomicUsize::new(0));
        let (addr, peer) = serve_udp(true, Duration::from_millis(50), requests.clone()).await;
        let s = server(Config {
            upstreams: vec![],
            fallback: vec![addr],
            serve_stale_client_timeout_ms: 1000,
            ..Config::default()
        });
        let ip = "127.0.0.1".parse().unwrap();
        let q = query("stale-wait.test", RecordType::A);
        let key = key_for(&q);
        seed_stale(&s, &q, &key);

        let answer = Message::from_vec(&s.handle(&q.to_vec().unwrap(), ip, false).await.unwrap()).unwrap();
        assert_eq!(answer.metadata.response_code, ResponseCode::NoError);
        assert_eq!(answer.answers[0].ttl, 60, "the fresh answer, not the stale TTL-30 copy");
        assert_eq!(requests.load(SeqCst), 1);
        peer.abort();
    }

    /// RFC 8767 §5: with a slow upstream both the leader and its follower
    /// answer stale at the client timer, the refresh keeps running (one query,
    /// no retry) and populates the cache when it lands.
    #[tokio::test]
    async fn stale_timeout_falls_back_and_does_not_leak_a_second_query() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        let requests = Arc::new(AtomicUsize::new(0));
        let (addr, peer) = serve_udp(true, Duration::from_millis(1500), requests.clone()).await;
        let s = server(Config {
            upstreams: vec![],
            fallback: vec![addr],
            serve_stale_client_timeout_ms: 200,
            ..Config::default()
        });
        let ip = "127.0.0.1".parse().unwrap();
        let q = query("stale-slow.test", RecordType::A);
        let key = key_for(&q);
        seed_stale(&s, &q, &key);

        let mut clients = JoinSet::new();
        for id in 0..2u16 {
            let s = s.clone();
            let mut q = q.clone();
            q.metadata.id = 0x9100 + id;
            clients.spawn(async move {
                let started = Instant::now();
                let answer = Message::from_vec(&s.handle(&q.to_vec().unwrap(), ip, false).await.unwrap()).unwrap();
                (started.elapsed(), answer)
            });
        }
        while let Some(result) = clients.join_next().await {
            let (elapsed, answer) = result.unwrap();
            assert!(elapsed >= Duration::from_millis(150), "waited for the client timer: {elapsed:?}");
            assert!(elapsed < Duration::from_secs(2), "did not wait for the slow upstream: {elapsed:?}");
            assert_eq!(answer.answers[0].ttl, 30, "both callers fall back to stale");
        }
        assert_eq!(requests.load(SeqCst), 1, "one refresh query, no retry after the timeout");
        sleep(Duration::from_millis(300)).await;
        assert_eq!(requests.load(SeqCst), 1, "the refresh still running sent no second query");
        assert!(!s.inflight().is_empty(), "the refresh outlives the client timer");
        wait_until(|| s.inflight().is_empty()).await;
        let fresh = s.cache().get(&key, 1, 43_200).expect("the refresh populated the cache");
        assert!(!fresh.stale, "the refreshed entry is fresh");
        assert_eq!(Message::from_vec(&fresh.raw).unwrap().answers[0].ttl, 60);
        assert_eq!(requests.load(SeqCst), 1);
        peer.abort();
    }

    /// Two concurrent stale requests share one refresh and both get the
    /// fresh answer.
    #[tokio::test]
    async fn concurrent_stale_waiters_share_one_fresh_answer() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        let requests = Arc::new(AtomicUsize::new(0));
        let (addr, peer) = serve_udp(true, Duration::from_millis(200), requests.clone()).await;
        let s = server(Config {
            upstreams: vec![],
            fallback: vec![addr],
            serve_stale_client_timeout_ms: 1000,
            ..Config::default()
        });
        let ip = "127.0.0.1".parse().unwrap();
        let q = query("stale-share.test", RecordType::A);
        let key = key_for(&q);
        seed_stale(&s, &q, &key);

        let mut clients = JoinSet::new();
        for id in 0..2u16 {
            let s = s.clone();
            let mut q = q.clone();
            q.metadata.id = 0x9200 + id;
            clients.spawn(async move {
                Message::from_vec(&s.handle(&q.to_vec().unwrap(), ip, false).await.unwrap()).unwrap()
            });
        }
        let mut ids = std::collections::HashSet::new();
        while let Some(result) = clients.join_next().await {
            let answer = result.unwrap();
            assert!(ids.insert(answer.metadata.id), "each waiter gets its own ID");
            assert_eq!(answer.answers[0].ttl, 60, "a follower shares the leader's fresh answer");
        }
        assert_eq!(requests.load(SeqCst), 1);
        peer.abort();
    }
    #[tokio::test]
    async fn a_follower_woken_by_a_failed_leader_answers_servfail() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        let requests = Arc::new(AtomicUsize::new(0));
        let (addr, peer) = serve_udp(true, Duration::ZERO, requests.clone()).await;
        let s = server(Config { upstreams: vec![], fallback: vec![addr], ..Config::default() });
        let q = query("woken.test", RecordType::A);
        let key = key_for(&q);
        let inflight::Role::Leader(guard) = s.inflight().join(&key) else { panic!("leader") };
        let handle = tokio::spawn({
            let s = s.clone();
            let raw = q.to_vec().unwrap();
            async move { s.handle(&raw, "127.0.0.1".parse().unwrap(), false).await }
        });
        // Let the spawned handle register as a follower before publishing failure.
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
        guard.complete(None);
        let answer = handle.await.unwrap().unwrap();
        assert_eq!(code(&answer), ResponseCode::ServFail, "a failed leader SERVFAILs its followers");
        assert_eq!(requests.load(SeqCst), 0, "the follower must not retry upstream");
        assert!(s.inflight().is_empty());
        peer.abort();
    }
    #[tokio::test]
    async fn a_follower_deadline_answers_servfail_without_hanging() {
        // `upstream_timeout_seconds = 0` is rejected by `Config::validate`, but
        // a struct literal bypasses validation to get the shortest follower
        // deadline: timeout + 1 = 1 s.
        let s =
            server(Config { upstreams: vec![], fallback: vec![], upstream_timeout_seconds: 0, ..Config::default() });
        let q = query("deadline.test", RecordType::A);
        let key = key_for(&q);
        let inflight::Role::Leader(guard) = s.inflight().join(&key) else { panic!("leader") };
        let started = Instant::now();
        let answer = timeout(Duration::from_secs(3), send(&s, &q.to_vec().unwrap()))
            .await
            .expect("a timed-out follower must not hang")
            .unwrap();
        assert_eq!(code(&answer), ResponseCode::ServFail);
        assert!(started.elapsed() >= Duration::from_millis(900), "returned before the follower deadline");
        assert_eq!(s.inflight().len(), 1, "a timed-out follower must not remove the leader entry");
        drop(guard);
        assert!(s.inflight().is_empty());
    }
    #[tokio::test]
    async fn a_reload_keeps_per_client_limits_unless_their_rate_changed() {
        let s = server(Config {
            rate_limit_qps: 1,
            rate_limit_burst: 1,
            upstream_inflight_per_client: 1,
            ..Config::default()
        });
        let ip: IpAddr = "192.0.2.7".parse().unwrap();
        let now = Instant::now();
        let old = s.runtime();
        let slot = old.upstream_slot(ip).unwrap();
        assert!(old.rate.allow(ip, now) && !old.rate.allow(ip, now));
        while old.capped_replies.allow(ip, now) {}
        let dir = std::env::temp_dir().join(format!("sopedu-dns-reload-limits-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        let base =
            "listen = \"0.0.0.0:53\"\nui_enabled = false\nupstream_inflight_per_client = 1\nrate_limit_burst = 1\n";
        std::fs::write(&path, format!("{base}rate_limit_qps = 1\nlog_queries = true\n")).unwrap();
        s.reload(&path).await;
        let next = s.runtime();
        assert!(next.cfg.log_queries, "the reload applied");
        assert!(next.upstream_slot(ip).is_none(), "work in flight under the old generation still counts");
        assert!(!next.rate.allow(ip, now), "the bucket is not refilled");
        assert!(!next.capped_replies.allow(ip, now), "the TC limiter is not refilled");
        drop(slot);
        assert!(next.upstream_slot(ip).is_some_and(|slot| slot.is_some()));

        std::fs::write(&path, format!("{base}rate_limit_qps = 2\n")).unwrap();
        s.reload(&path).await;
        assert!(s.runtime().rate.allow(ip, now), "a new rate starts new buckets");
        let _ = std::fs::remove_dir_all(&dir);
    }
    #[tokio::test]
    async fn a_reload_keeps_the_upstream_counters() {
        let url = "https://127.0.0.1:1/dns-query";
        let s = server(Config { upstreams: vec![url.into()], ..Config::default() });
        let saved = sopedu_dns::upstream::UpstreamCount { url: "https://127.0.0.1:1".into(), wins: 41, hedges: 3 };
        s.runtime().upstreams.restore_counters(std::slice::from_ref(&saved));
        let dir = std::env::temp_dir().join(format!("sopedu-dns-reload-counters-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(
            &path,
            format!("listen = \"0.0.0.0:53\"\nupstreams = [\"{url}\"]\nui_enabled = false\nlog_queries = true\n"),
        )
        .unwrap();
        s.reload(&path).await;
        assert!(s.runtime().cfg.log_queries, "the reload applied");
        assert_eq!(s.runtime().upstreams.counters(), vec![saved], "an unrelated edit keeps the counters");
        let _ = std::fs::remove_dir_all(&dir);
    }
    #[tokio::test]
    async fn a_new_generation_does_not_join_an_old_generations_inflight_leader() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        // The old fallback holds its answer until released, so the reload and
        // the second query happen deterministically while the leader is live.
        let old_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let old_addr = old_socket.local_addr().unwrap();
        let (seen_tx, seen_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let old_peer = tokio::spawn(async move {
            let mut buf = vec![0; 65535];
            let (n, peer) = old_socket.recv_from(&mut buf).await.unwrap();
            let _ = seen_tx.send(());
            let _ = release_rx.await;
            let q = Message::from_vec(&buf[..n]).unwrap();
            let mut answer = reply(&q, ResponseCode::NoError);
            answer.add_answer(Record::from_rdata(q.queries[0].name().clone(), 60, RData::A(A::new(192, 0, 2, 1))));
            old_socket.send_to(&wire_reply(&buf[..n], answer), peer).await.unwrap();
        });
        let new_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let new_addr = new_socket.local_addr().unwrap();
        let new_queries = Arc::new(AtomicUsize::new(0));
        let new_do = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let new_peer = tokio::spawn({
            let new_queries = new_queries.clone();
            let new_do = new_do.clone();
            async move {
                loop {
                    let mut buf = vec![0; 65535];
                    let Ok((n, peer)) = new_socket.recv_from(&mut buf).await else { return };
                    new_queries.fetch_add(1, SeqCst);
                    new_do.store(wire::parse_query(&buf[..n]).unwrap().edns_do, SeqCst);
                    let q = Message::from_vec(&buf[..n]).unwrap();
                    let mut answer = reply(&q, ResponseCode::NoError);
                    answer.add_answer(Record::from_rdata(
                        q.queries[0].name().clone(),
                        60,
                        RData::A(A::new(192, 0, 2, 2)),
                    ));
                    let _ = new_socket.send_to(&wire_reply(&buf[..n], answer), peer).await;
                }
            }
        });
        let s = server(Config {
            upstreams: vec![],
            fallback: vec![old_addr],
            upstream_timeout_seconds: 5,
            ..Config::default()
        });
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let raw = query("generation.test", RecordType::A).to_vec().unwrap();
        let leader = tokio::spawn({
            let s = s.clone();
            let raw = raw.clone();
            async move { s.handle(&raw, ip, true).await }
        });
        seen_rx.await.unwrap();

        // Reload to the new fallback while the old leader is still blocked.
        // `upstream_inflight_max` is unchanged, so the in-flight map must still
        // be rebuilt, or the new generation would get the old pool's answer.
        let dir = std::env::temp_dir().join(format!("sopedu-dns-inflight-generation-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(
            &path,
            format!(
                "listen = \"0.0.0.0:53\"\nupstreams = []\nfallback = [\"{new_addr}\"]\nui_enabled = false\nforward_test_names = true\n\
                 upstream_timeout_seconds = 5\ndnssec = \"always_upstream\"\n"
            ),
        )
        .unwrap();
        s.reload(&path).await;

        let mut follow = query("generation.test", RecordType::A);
        follow.metadata.id = 2;
        let follow_raw = follow.to_vec().unwrap();
        let answer = timeout(Duration::from_secs(1), s.handle(&follow_raw, ip, true))
            .await
            .expect("a new-generation request must not wait on an old-generation leader")
            .unwrap();
        assert_eq!(answer_a(&answer), Some(std::net::Ipv4Addr::new(192, 0, 2, 2)));
        assert_eq!(new_queries.load(SeqCst), 1, "the new generation's pool answered the query");
        assert!(new_do.load(SeqCst), "the new generation's DNSSEC mode reaches upstream");

        let _ = release_tx.send(());
        let old_answer = leader.await.unwrap().unwrap();
        assert_eq!(answer_a(&old_answer), Some(std::net::Ipv4Addr::new(192, 0, 2, 1)));
        old_peer.await.unwrap();
        new_peer.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }
    #[tokio::test]
    async fn unknown_edns_flags_and_extra_sections_bypass_coalescing() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        let requests = Arc::new(AtomicUsize::new(0));
        let (addr, peer) = serve_udp(true, Duration::from_millis(100), requests.clone()).await;
        let s = server(Config {
            upstreams: vec![],
            fallback: vec![addr],
            upstream_timeout_seconds: 2,
            ..Config::default()
        });
        let ip = "127.0.0.1".parse().unwrap();
        let mut clients = JoinSet::new();
        for context in 0..2u16 {
            for id in 0..2u16 {
                let s = s.clone();
                clients.spawn(async move {
                    let mut q = query("bypass.test", RecordType::A);
                    q.metadata.id = 0x8000 + context * 2 + id;
                    if context == 0 {
                        // RFC 9824 Compact Answers OK is one such unknown flag.
                        q.edns.get_or_insert_with(Default::default).flags_mut().z = 1;
                    } else {
                        q.add_additional(Record::from_rdata(
                            Name::from_ascii("bypass.test.").unwrap(),
                            60,
                            RData::A(A::new(192, 0, 2, 2)),
                        ));
                    }
                    let answer = s.handle(&q.to_vec().unwrap(), ip, false).await.unwrap();
                    (q.metadata.id, Message::from_vec(&answer).unwrap().metadata.id)
                });
            }
        }
        while let Some(result) = clients.join_next().await {
            let (sent, got) = result.unwrap();
            assert_eq!(sent, got, "each bypass caller gets its own reply");
        }
        assert_eq!(requests.load(SeqCst), 4, "unknown EDNS flags and extra sections never coalesce");
        assert!(s.inflight().is_empty());
        peer.abort();
    }
    fn wire_name(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in name.trim_end_matches('.').split('.').filter(|l| !l.is_empty()) {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }
    fn append_record(raw: &[u8], rtype: u16, class: u16, ttl: u32, rdata: &[u8]) -> Vec<u8> {
        let mut out = raw.to_vec();
        out.push(0);
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&class.to_be_bytes());
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(rdata);
        let count = u16::from_be_bytes([out[10], out[11]]) + 1;
        out[10..12].copy_from_slice(&count.to_be_bytes());
        out
    }
    async fn send(s: &Arc<Server>, raw: &[u8]) -> Option<Vec<u8>> {
        s.handle(raw, "127.0.0.1".parse().unwrap(), false).await
    }
    fn code(answer: &[u8]) -> ResponseCode {
        Message::from_vec(answer).unwrap().metadata.response_code
    }
    fn answer_a(answer: &[u8]) -> Option<std::net::Ipv4Addr> {
        Message::from_vec(answer).ok()?.answers.iter().find_map(|record| match &record.data {
            RData::A(address) => Some(address.0),
            _ => None,
        })
    }
    /// Serializes an answer and echoes the upstream query's randomized case.
    fn wire_reply(sent: &[u8], answer: Message) -> Vec<u8> {
        let mut bytes = answer.to_vec().unwrap();
        wire::copy_question_case(sent, &mut bytes);
        bytes
    }
    #[tokio::test]
    async fn unsupported_opcode_is_notimp_whatever_the_question_count() {
        // The opcode is inspected before QUERY section rules (RFC 8906 §3.1.4).
        let s = server(Config { upstreams: vec![], fallback: vec![], ..Config::default() });
        for opcode in [1u8, 2, 5, 15] {
            for count in [0u16, 1, 2] {
                let mut raw = vec![0x43, 0x21, 0x01 | (opcode << 3), 0, 0, 0, 0, 0, 0, 0, 0, 0];
                raw[4..6].copy_from_slice(&count.to_be_bytes());
                for _ in 0..count {
                    raw.extend_from_slice(&[1, b'a', 0, 0, 1, 0, 1]);
                }
                let a = send(&s, &raw).await.unwrap();
                assert_eq!(code(&a), ResponseCode::NotImp, "opcode {opcode} count {count}");
                assert_eq!((a[2] >> 3) & 0x0f, opcode);
            }
        }
    }
    #[tokio::test]
    async fn unconfigured_local_names_are_nxdomain_and_never_forwarded() {
        // RFC 6762 §22.1 item 4: no upstream query for an unconfigured .local;
        // an explicit rewrite still wins.
        let mut rewrites = std::collections::HashMap::new();
        rewrites.insert("known.local".to_string(), "192.0.2.60".parse().unwrap());
        let s = server(Config { upstreams: vec![], fallback: vec![], rewrites, ..Config::default() });
        for name in ["printer.local", "a.b.local", "local"] {
            let a = send(&s, &query(name, RecordType::A).to_vec().unwrap()).await.unwrap();
            let message = Message::from_vec(&a).unwrap();
            assert_eq!(message.metadata.response_code, ResponseCode::NXDomain, "{name}");
            assert!(matches!(message.authorities.first().map(|r| &r.data), Some(RData::SOA(_))), "{name}");
        }
        let a = send(&s, &query("known.local", RecordType::A).to_vec().unwrap()).await.unwrap();
        assert_eq!(answer_a(&a), Some("192.0.2.60".parse().unwrap()));
    }
    #[tokio::test]
    async fn rewrite_nodata_carries_the_local_negative_soa() {
        let mut rewrites = std::collections::HashMap::new();
        rewrites.insert("v4.test".to_string(), "192.0.2.1".parse().unwrap());
        let s = server(Config { upstreams: vec![], fallback: vec![], rewrites, ..Config::default() });
        let a = send(&s, &query("v4.test", RecordType::AAAA).to_vec().unwrap()).await.unwrap();
        let message = Message::from_vec(&a).unwrap();
        assert_eq!(message.metadata.response_code, ResponseCode::NoError);
        assert!(message.answers.is_empty());
        assert!(matches!(message.authorities.first().map(|r| &r.data), Some(RData::SOA(_))));
    }
    #[tokio::test]
    async fn rejects_unsupported_and_malformed_queries() {
        let s = server(Config { upstreams: vec![], fallback: vec![], ..Config::default() });
        let mut empty = Message::new(1, MessageType::Query, OpCode::Query);
        empty.metadata.recursion_desired = true;
        let a = send(&s, &empty.to_vec().unwrap()).await.unwrap();
        assert_eq!(code(&a), ResponseCode::Refused);
        assert_eq!(u16::from_be_bytes([a[4], a[5]]), 0);

        let mut two = query("a.test", RecordType::A);
        two.add_query(Query::query(Name::from_ascii("b.test.").unwrap(), RecordType::A));
        assert_eq!(code(&send(&s, &two.to_vec().unwrap()).await.unwrap()), ResponseCode::FormErr);

        let mut status = query("x.test", RecordType::A);
        status.metadata.op_code = OpCode::Status;
        assert_eq!(code(&send(&s, &status.to_vec().unwrap()).await.unwrap()), ResponseCode::NotImp);

        let mut v1 = query("x.test", RecordType::A);
        v1.edns.get_or_insert_with(Default::default).set_version(1);
        let a = send(&s, &v1.to_vec().unwrap()).await.unwrap();
        // BADVERS is extended RCODE 16; hickory's From<u16> names it BADSIG.
        assert_eq!(u16::from(code(&a)), 16);
        assert_eq!(u16::from_be_bytes([a[4], a[5]]), 1);

        for typ in [RecordType::AXFR, RecordType::IXFR, RecordType::Unknown(249)] {
            let q = query("x.test", typ);
            assert_eq!(code(&send(&s, &q.to_vec().unwrap()).await.unwrap()), ResponseCode::Refused);
        }
        let nxname = query("x.test", RecordType::Unknown(128));
        assert_eq!(code(&send(&s, &nxname.to_vec().unwrap()).await.unwrap()), ResponseCode::FormErr);

        let signed = append_record(&query("x.test", RecordType::A).to_vec().unwrap(), 250, 255, 0, &[]);
        assert_eq!(code(&send(&s, &signed).await.unwrap()), ResponseCode::Refused);
        // SIG(0) is type 24 covering type 0; like TSIG it needs an authentication boundary.
        let sig0 = append_record(&query("x.test", RecordType::A).to_vec().unwrap(), 24, 255, 0, &[0, 0]);
        assert_eq!(code(&send(&s, &sig0).await.unwrap()), ResponseCode::Refused);

        let mut duplicate = query("x.test", RecordType::A).to_vec().unwrap();
        duplicate = append_record(&duplicate, 41, 1232, 0, &[]);
        duplicate = append_record(&duplicate, 41, 1232, 0, &[]);
        assert_eq!(code(&send(&s, &duplicate).await.unwrap()), ResponseCode::FormErr);
        let bad_option = append_record(&query("x.test", RecordType::A).to_vec().unwrap(), 41, 1232, 0, &[0, 10, 0]);
        assert_eq!(code(&send(&s, &bad_option).await.unwrap()), ResponseCode::FormErr);

        let mut malformed = query("x.test", RecordType::A).to_vec().unwrap();
        malformed[12] = 0x3f;
        assert_eq!(code(&send(&s, &malformed).await.unwrap()), ResponseCode::FormErr);

        let mut response = query("x.test", RecordType::A);
        response.metadata.message_type = MessageType::Response;
        assert!(send(&s, &response.to_vec().unwrap()).await.is_none());
        assert!(send(&s, &[0; 11]).await.is_none());
    }
    #[tokio::test]
    async fn mixed_case_local_answer_echoes_client_case() {
        let s = server(Config {
            user_rules: vec!["||mixed.test^".into()],
            upstreams: vec![],
            fallback: vec![],
            ..Config::default()
        });
        let raw = query("MiXeD.TeSt", RecordType::A).to_vec().unwrap();
        let answer = send(&s, &raw).await.unwrap();
        assert_eq!(code(&answer), ResponseCode::NXDomain);
        let view = wire::parse_query(&answer).unwrap();
        assert_eq!(view.qname_wire, wire_name("MiXeD.TeSt").as_slice());
    }
    #[tokio::test]
    async fn mixed_case_cache_hit_echoes_client_case() {
        let s = server(Config { upstreams: vec![], fallback: vec![], ..Config::default() });
        let lower = query("mixed.test", RecordType::A);
        let mut stored = reply(&lower, ResponseCode::NoError);
        stored.add_answer(Record::from_rdata(lower.queries[0].name().clone(), 300, RData::A(A::new(192, 0, 2, 1))));
        let key = key_for(&lower);
        assert!(s.cache().insert(&key, &stored.to_vec().unwrap(), &stored, 0));
        let raw = query("MiXeD.TeSt", RecordType::A).to_vec().unwrap();
        let answer = send(&s, &raw).await.unwrap();
        let parsed = Message::from_vec(&answer).unwrap();
        assert_eq!(parsed.answers.len(), 1);
        assert_eq!(wire::parse_query(&answer).unwrap().qname_wire, wire_name("MiXeD.TeSt").as_slice());
    }
    #[tokio::test]
    async fn mixed_case_upstream_answer_echoes_client_case() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let mut buf = vec![0; 65535];
            let (n, peer) = socket.recv_from(&mut buf).await.unwrap();
            let request = Message::from_vec(&buf[..n]).unwrap();
            let mut answer = reply(&request, ResponseCode::NoError);
            answer.add_answer(Record::from_rdata(
                request.queries[0].name().clone(),
                60,
                RData::A(A::new(192, 0, 2, 9)),
            ));
            socket.send_to(&wire_reply(&buf[..n], answer), peer).await.unwrap();
        });
        let s = server(Config { upstreams: vec![], fallback: vec![addr], ..Config::default() });
        let raw = query("MiXeD.TeSt", RecordType::A).to_vec().unwrap();
        let answer = send(&s, &raw).await.unwrap();
        let view = wire::parse_query(&answer).unwrap();
        assert_eq!(view.qname_wire, wire_name("MiXeD.TeSt").as_slice());
        peer.await.unwrap();
    }
    #[tokio::test]
    async fn truncated_doh_answer_clears_ad() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut b = Vec::new();
                loop {
                    b.push(stream.read_u8().await.unwrap());
                    if b.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                let head = String::from_utf8(b).unwrap().to_ascii_lowercase();
                let len: usize =
                    head.lines().find_map(|line| line.strip_prefix("content-length:")).unwrap().trim().parse().unwrap();
                let mut body = vec![0; len];
                stream.read_exact(&mut body).await.unwrap();
                let parsed = Message::from_vec(&body).unwrap();
                let probe = parsed.queries[0].query_type() == RecordType::NS && parsed.queries[0].name().is_root();
                let mut a = reply(&parsed, ResponseCode::NoError);
                if !probe {
                    a.metadata.authentic_data = true;
                    for i in 0..40 {
                        a.add_answer(Record::from_rdata(
                            parsed.queries[0].name().clone(),
                            60,
                            RData::A(A::new(192, 0, 2, i)),
                        ));
                    }
                }
                let a = a.to_vec().unwrap();
                stream
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            a.len()
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
                stream.write_all(&a).await.unwrap();
                if !probe {
                    return;
                }
            }
        });
        let s = server(Config { upstreams: vec![format!("http://{addr}/dns-query")], ..Config::default() });
        let raw = query("truncated-ad.test", RecordType::A).to_vec().unwrap();
        let answer = s.handle(&raw, "127.0.0.1".parse().unwrap(), true).await.unwrap();
        let parsed = Message::from_vec(&answer).unwrap();
        assert!(parsed.metadata.truncation);
        assert!(!parsed.metadata.authentic_data);
        assert!(parsed.answers.is_empty());
        peer.await.unwrap();
    }
    #[tokio::test]
    async fn hickory_rejected_query_gets_formerr_without_upstream() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let s = server(Config { upstreams: vec![], fallback: vec![addr], ..Config::default() });
        // The wire parser accepts an OPT in the answer section; hickory
        // rejects it as misplaced.
        let mut raw = query("misplaced.test", RecordType::A).to_vec().unwrap();
        raw[6..8].copy_from_slice(&1u16.to_be_bytes()); // ANCOUNT = 1
        raw.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0]);
        assert!(wire::parse_query(&raw).is_some());
        let answer = s.handle(&raw, "127.0.0.1".parse().unwrap(), false).await.unwrap();
        assert_eq!(code(&answer), ResponseCode::FormErr);
        assert!(Message::from_vec(&answer).unwrap().edns.is_none());
        // An overlapping-label compressed question: the name is a pointer to
        // offset 0 whose 14-byte label spans the pointer itself. The pointer
        // targets the header, so the wire parser refuses it and the error reply
        // must not echo the decompressed name.
        let overlapping = [
            0x0e, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, // header
            0xc0, 0x00, // question name: pointer to offset 0
            0x01, 0x00, // QTYPE: high byte is label data, low byte is the root
            0x00, 0x01, // QCLASS IN
        ];
        assert!(wire::parse_query(&overlapping).is_none());
        assert!(parse(&overlapping).is_none());
        let answer = s.handle(&overlapping, "127.0.0.1".parse().unwrap(), false).await.unwrap();
        assert_eq!(code(&answer), ResponseCode::FormErr);
        assert_eq!(u16::from_be_bytes([answer[4], answer[5]]), 0);
        assert!(answer.len() <= overlapping.len() + 11);
        let mut buf = [0u8; 64];
        assert!(timeout(Duration::from_millis(50), socket.recv_from(&mut buf)).await.is_err());
    }
    #[tokio::test]
    async fn truncated_reply_echoes_client_case() {
        let (addr, peer) = serve_udp_replies(Arc::new(std::sync::atomic::AtomicUsize::new(0)), |q| {
            assert_eq!(q.queries[0].name().to_ascii().to_ascii_lowercase(), "mixed.test.");
            let mut a = reply(q, ResponseCode::NoError);
            for i in 0..40 {
                a.add_answer(Record::from_rdata(q.queries[0].name().clone(), 60, RData::A(A::new(192, 0, 2, i))));
            }
            a
        })
        .await;
        let s = server(Config { upstreams: vec![], fallback: vec![addr], ..Config::default() });
        let raw = query("MiXeD.TeSt", RecordType::A).to_vec().unwrap();
        let answer = s.handle(&raw, "127.0.0.1".parse().unwrap(), true).await.unwrap();
        assert!(Message::from_vec(&answer).unwrap().metadata.truncation);
        assert_eq!(wire::parse_query(&answer).unwrap().qname_wire, wire_name("MiXeD.TeSt").as_slice());
        peer.abort();
    }
    #[tokio::test]
    async fn edns_options_and_extra_sections_bypass_cache() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let peer = tokio::spawn({
            let calls = calls.clone();
            async move {
                loop {
                    let mut buf = vec![0; 65535];
                    let Ok((n, peer)) = socket.recv_from(&mut buf).await else { break };
                    calls.fetch_add(1, SeqCst);
                    let q = Message::from_vec(&buf[..n]).unwrap();
                    let mut a = reply(&q, ResponseCode::NoError);
                    a.add_answer(Record::from_rdata(q.queries[0].name().clone(), 300, RData::A(A::new(192, 0, 2, 1))));
                    socket.send_to(&wire_reply(&buf[..n], a), peer).await.unwrap();
                }
            }
        });
        let s = server(Config { upstreams: vec![], fallback: vec![addr], ..Config::default() });
        let ip = "127.0.0.1".parse().unwrap();

        // An EDNS option bypasses the cache: two queries, two upstream calls.
        let mut option = query("option.test", RecordType::A);
        option
            .edns
            .get_or_insert_with(Default::default)
            .options_mut()
            .insert(hickory_proto::rr::rdata::opt::EdnsOption::Unknown(65001, vec![1, 2, 3]));
        let raw = option.to_vec().unwrap();
        for _ in 0..2 {
            assert_eq!(code(&s.handle(&raw, ip, false).await.unwrap()), ResponseCode::NoError);
        }
        assert_eq!(calls.load(SeqCst), 2);

        // Any EDNS flag other than DO (here an unknown reserved bit) bypasses
        // caching and coalescing too (RFC 9824 Compact Answers OK is one).
        let mut flagged = query("flag.test", RecordType::A);
        flagged.edns.get_or_insert_with(Default::default).flags_mut().z = 1;
        let raw = flagged.to_vec().unwrap();
        for _ in 0..2 {
            assert_eq!(code(&s.handle(&raw, ip, false).await.unwrap()), ResponseCode::NoError);
        }
        assert_eq!(calls.load(SeqCst), 4);

        // An extra non-OPT additional record bypasses the cache too.
        let mut extra = query("extra.test", RecordType::A);
        extra.add_additional(Record::from_rdata(
            Name::from_ascii("extra.test.").unwrap(),
            60,
            RData::A(A::new(192, 0, 2, 2)),
        ));
        let raw = extra.to_vec().unwrap();
        for _ in 0..2 {
            assert_eq!(code(&s.handle(&raw, ip, false).await.unwrap()), ResponseCode::NoError);
        }
        assert_eq!(calls.load(SeqCst), 6);

        // The same query without options or extra sections is cached.
        let raw = query("plain.test", RecordType::A).to_vec().unwrap();
        for _ in 0..2 {
            assert_eq!(code(&s.handle(&raw, ip, false).await.unwrap()), ResponseCode::NoError);
        }
        assert_eq!(calls.load(SeqCst), 7);
        peer.abort();
    }
    #[tokio::test]
    async fn failed_refresh_keeps_previous_snapshot() {
        let state = std::env::temp_dir().join(format!("sopedu-dns-refresh-test-{}", std::process::id()));
        let cfg = Config {
            blocklists: vec!["http://127.0.0.1:1/list.txt".into()],
            user_rules: vec![],
            state_dir: state,
            upstreams: vec![],
            fallback: vec![],
            ..Config::default()
        };
        let s = server(cfg);
        s.set_rules(rules::Rules::from_lines(["||old.test^"], 1));
        assert!(s.refresh_lists(&s.runtime()).await.is_err());
        assert!(s.runtime().rules.blocked("old.test"));
        assert_eq!(s.runtime().list_status.len(), 0);
    }

    #[test]
    fn a_reload_does_not_revert_a_refresh_that_landed_during_its_parse() {
        let s = server(Config { upstreams: vec![], fallback: vec![], ..Config::default() });
        // The reload snapshots this generation before its blocking config
        // parse and builds its candidate from it.
        let old = s.runtime();
        // A refresh CAS lands while the parse is still running.
        let refreshed = SourceStatus {
            id: 1,
            name: "https://example.com/filter_1.txt".into(),
            rules: 1,
            skipped: 0,
            last_success: Some(1),
            last_error: None,
            used_cache: false,
        };
        let mut landed = (*old).clone();
        landed.rules = Arc::new(rules::Rules::from_lines(["||listed.test^"], 1));
        landed.list_status = Arc::new(vec![refreshed.clone()]);
        s.runtime.store(Arc::new(landed));
        // Publishing the stale candidate must merge the applied refresh.
        let published = s.publish((*old).clone(), false);
        assert!(published.rules.blocked("listed.test"), "the reload must not revert the applied refresh");
        assert_eq!(*published.list_status, vec![refreshed]);
        assert!(s.runtime().rules.blocked("listed.test"), "the published generation carries the refresh");
    }

    #[tokio::test]
    async fn udp_payload_cap_truncates_with_tc_and_keeps_the_full_answer_cached() {
        fn big_answer(q: &Message, records: usize) -> Message {
            let mut m = reply(q, ResponseCode::NoError);
            m.metadata.authentic_data = true;
            for i in 0..records {
                m.add_answer(Record::from_rdata(
                    Name::from_ascii("big.test.").unwrap(),
                    60,
                    RData::A(A(std::net::Ipv4Addr::new(192, 0, 2, (i % 250) as u8))),
                ));
            }
            m
        }
        let s = server(Config { cache_size: 64, udp_max_payload: 600, ..Config::default() });
        let ip = "127.0.0.1".parse().unwrap();
        for (advertised, limit, records) in [(Some(4096u16), 600u16, 80usize), (Some(300), 512, 80), (None, 512, 80)] {
            let mut q = query("big.test", RecordType::A);
            if let Some(advertised) = advertised {
                q.edns.get_or_insert_with(Default::default).set_max_payload(advertised);
            }
            let raw = q.to_vec().unwrap();
            let key = key_for(&q);
            let full = big_answer(&q, records);
            let full_raw = full.to_vec().unwrap();
            assert!(full_raw.len() > 600, "test answer must exceed every cap");
            assert!(s.cache().insert(&key, &full_raw, &full, 0));

            let answer = s.handle(&raw, ip, true).await.unwrap();
            let parsed = Message::from_vec(&answer).unwrap();
            assert!(parsed.metadata.truncation, "advertised {advertised:?}");
            assert!(!parsed.metadata.authentic_data);
            assert_eq!(parsed.metadata.response_code, ResponseCode::NoError);
            assert!(parsed.answers.is_empty(), "a TC reply carries no answers");
            assert_eq!(parsed.queries.len(), 1, "the question is echoed");
            // RFC 6891 §6.2.3: the OPT advertises our configured size (600).
            assert_eq!(parsed.edns.as_ref().map(hickory_proto::op::Edns::max_payload), advertised.map(|_| 600));
            assert!(answer.len() <= usize::from(limit));

            // TCP has no payload cap; the full answer was cached before truncation.
            let tcp = s.handle(&raw, ip, false).await.unwrap();
            let tcp = Message::from_vec(&tcp).unwrap();
            assert!(!tcp.metadata.truncation);
            assert_eq!(tcp.answers.len(), records);
        }
    }

    // --- wire-only cache-hit fast path -------------------------------------

    /// Inserts a `records`-record A answer for `q` and returns its wire bytes.
    fn cache_answer(s: &Arc<Server>, q: &Message, records: usize, ttl: u32) -> Vec<u8> {
        let mut answer = reply(q, ResponseCode::NoError);
        for i in 0..records {
            answer.add_answer(Record::from_rdata(
                q.queries[0].name().clone(),
                ttl,
                RData::A(A::new(192, 0, 2, (i % 250) as u8)),
            ));
        }
        let raw = answer.to_vec().unwrap();
        assert!(s.cache().insert(&key_for(q), &raw, &answer, 0), "test cache entry");
        raw
    }

    /// The fully parsed path, kept as the byte-identical reference: full
    /// hickory parse, `resolve`, question-case restore and hickory truncation.
    async fn slow_path_answer(s: &Arc<Server>, raw: &[u8], ip: IpAddr, udp: bool) -> Option<Vec<u8>> {
        let runtime = s.runtime();
        let q = parse(raw)?;
        let view = wire::parse_query(raw)?;
        let mut answer = runtime.resolve(raw, &q, &view, ip, udp).await?;
        wire::copy_question_case(raw, &mut answer);
        if !udp {
            return Some(answer);
        }
        let limit =
            q.edns.as_ref().map_or(512, |edns| edns.max_payload().max(512).min(runtime.cfg.udp_max_payload) as usize);
        if answer.len() <= limit {
            return Some(answer);
        }
        let parsed = Message::from_vec(&answer).ok()?;
        let mut m = reply(&q, parsed.metadata.response_code);
        m.metadata.truncation = true;
        if let Some(edns) = m.edns.as_mut() {
            edns.set_max_payload(limit as u16);
        }
        let mut truncated = m.to_vec().ok()?;
        wire::copy_question_case(raw, &mut truncated);
        Some(truncated)
    }

    #[tokio::test]
    async fn cache_hit_does_not_parse_a_full_message() {
        let s = server(Config { upstreams: vec![], fallback: vec![], ..Config::default() });
        let ip = "127.0.0.1".parse().unwrap();
        let hit = query("probe-hit.test", RecordType::A);
        cache_answer(&s, &hit, 1, 300);
        let hit_raw = hit.to_vec().unwrap();

        let answer = Message::from_vec(&s.handle(&hit_raw, ip, true).await.unwrap()).unwrap();
        assert_eq!(answer.answers.len(), 1);
        assert_eq!(s.parse_calls.load(Ordering::Relaxed), 0, "a fresh hit must not reach hickory");

        // A miss proves the probe counts: with no upstream, `resolve` parses
        // the request and then answers SERVFAIL.
        let miss = query("probe-miss.test", RecordType::A).to_vec().unwrap();
        assert_eq!(code(&s.handle(&miss, ip, true).await.unwrap()), ResponseCode::ServFail);
        assert_eq!(s.parse_calls.load(Ordering::Relaxed), 1, "a miss parses once");

        s.handle(&hit_raw, ip, true).await.unwrap();
        assert_eq!(s.parse_calls.load(Ordering::Relaxed), 1, "the hit stays parse-free");
    }

    #[tokio::test]
    async fn fast_path_matches_the_parsed_path_for_fresh_hits() {
        let s = server(Config { upstreams: vec![], fallback: vec![], ..Config::default() });
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        for edns in [false, true] {
            let mut q = query(&format!("byte-identical-{edns}.test"), RecordType::A);
            if edns {
                q.edns.get_or_insert_with(Default::default).set_max_payload(4096);
            }
            let raw = q.to_vec().unwrap();
            cache_answer(&s, &q, 2, 300);
            let runtime = s.runtime();
            let view = wire::parse_query(&raw).unwrap();
            let fast = runtime.fast_path(&raw, &view, ip, true).await.unwrap();
            let slow = slow_path_answer(&s, &raw, ip, true).await.unwrap();
            assert_eq!(fast, slow, "EDNS={edns}: the wire hit must be byte-identical");
            assert_eq!(s.handle(&raw, ip, true).await.unwrap(), slow);
            assert_eq!(s.parse_calls.load(Ordering::Relaxed), 0);
        }
    }

    /// The synchronous core answers a fresh hit with no hickory parse and
    /// no task spawn. Stale, local policy, miss and response-shaped inputs
    /// return the slow-path marker instead.
    #[tokio::test]
    async fn inline_hit_path_answers_only_fresh_hits() {
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let s = server(Config { upstreams: vec![], fallback: vec![], ..Config::default() });
        let q = query("inline-hit.test", RecordType::A);
        let stored = cache_answer(&s, &q, 2, 300);
        let raw = q.to_vec().unwrap();
        let view = wire::parse_query(&raw).unwrap();
        let mut key = [0u8; wire::MIN_CANONICAL_BUFFER];
        let mut answer = Vec::new();
        let mut truncate = Vec::new();

        let InlineHit::Inline(len) =
            s.runtime().hit_inline(&raw, &view, ip, true, &mut key, &mut answer, &mut truncate)
        else {
            panic!("a fresh warm hit must answer inline");
        };
        let wrapped = s.runtime().fast_path(&raw, &view, ip, true).await.unwrap();
        assert_eq!(&answer[..len], wrapped.as_slice(), "the inline answer matches the async wrapper");
        assert_eq!(&answer[..len], stored.as_slice(), "the inline answer is the cached response");
        assert_eq!(s.parse_calls.load(Ordering::Relaxed), 0, "the inline hit never parses");

        // A large cached answer is rebuilt into the truncation buffer.
        let big = query("inline-trunc.test", RecordType::A);
        cache_answer(&s, &big, 100, 300);
        let big_raw = big.to_vec().unwrap();
        let big_view = wire::parse_query(&big_raw).unwrap();
        let InlineHit::Truncated(len) =
            s.runtime().hit_inline(&big_raw, &big_view, ip, true, &mut key, &mut answer, &mut truncate)
        else {
            panic!("an over-limit fresh hit must build a TC reply");
        };
        assert_eq!(&truncate[..len], s.runtime().fast_path(&big_raw, &big_view, ip, true).await.unwrap().as_slice());

        // A stale hit asks the async path to serve it; the receive loop must
        // not wait for a refresh.
        let stale = query("inline-stale.test", RecordType::A);
        let stale_raw = stale.to_vec().unwrap();
        let stale_view = wire::parse_query(&stale_raw).unwrap();
        seed_stale(&s, &stale, &key_for(&stale));
        assert!(matches!(
            s.runtime().hit_inline(&stale_raw, &stale_view, ip, true, &mut key, &mut answer, &mut truncate),
            InlineHit::NeedAsync { .. }
        ));

        // A miss and a response-shaped packet take the parsed slow path.
        let miss = query("inline-miss.test", RecordType::A);
        let miss_raw = miss.to_vec().unwrap();
        let miss_view = wire::parse_query(&miss_raw).unwrap();
        assert!(matches!(
            s.runtime().hit_inline(&miss_raw, &miss_view, ip, true, &mut key, &mut answer, &mut truncate),
            InlineHit::Slow
        ));
        let response_view = wire::parse_query(&stored).unwrap();
        assert!(matches!(
            s.runtime().hit_inline(&stored, &response_view, ip, true, &mut key, &mut answer, &mut truncate),
            InlineHit::Slow
        ));

        // A block wins over a warm entry: the block answer, not the cache.
        let blocked = server(Config {
            user_rules: vec!["||inline-block.test^".into()],
            upstreams: vec![],
            fallback: vec![],
            ..Config::default()
        });
        let block_q = query("inline-block.test", RecordType::A);
        cache_answer(&blocked, &block_q, 1, 300);
        let block_raw = block_q.to_vec().unwrap();
        let block_view = wire::parse_query(&block_raw).unwrap();
        let mut block_answer = Vec::new();
        assert!(matches!(
            blocked.runtime().hit_inline(&block_raw, &block_view, ip, true, &mut key, &mut block_answer, &mut truncate),
            InlineHit::Blocked { list: Some(0), .. }
        ));
        assert_eq!(code(&block_answer), ResponseCode::NXDomain);
    }

    /// A blocked name is answered on the inline path with exactly the bytes
    /// the parsed policy path builds, across EDNS, DO, CD, RD, qtypes, 0x20
    /// case and both transports, and counted and logged as a block. An
    /// exempt client, a special-use name and a local reverse zone keep the
    /// parsed path.
    #[tokio::test]
    async fn inline_block_answer_is_byte_identical_to_the_parsed_path() {
        let exempt: IpAddr = "127.0.0.2".parse().unwrap();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let s = server(Config {
            user_rules: vec!["||blocked.example^".into(), "||onion^".into(), "||10.in-addr.arpa^".into()],
            no_filter_clients: vec![exempt],
            upstreams: vec![],
            fallback: vec![],
            ..Config::default()
        });
        let (mut key, mut answer, mut scratch) = ([0u8; wire::MIN_CANONICAL_BUFFER], Vec::new(), Vec::new());
        let names = ["blocked.example", "Ads.BlOcKeD.example", "a-b.c_d.blocked.example"];
        let qtypes = [RecordType::A, RecordType::AAAA, RecordType::HTTPS, RecordType::TXT];
        for (name, qtype) in names.iter().flat_map(|name| qtypes.map(|qtype| (name, qtype))) {
            for variant in 0..6 {
                let mut q = query(name, qtype);
                match variant {
                    1 => q.edns = Some(Default::default()),
                    2 => drop(q.edns.get_or_insert_with(Default::default).set_dnssec_ok(true).set_max_payload(4096)),
                    3 => q.metadata.checking_disabled = true,
                    4 => q.metadata.recursion_desired = false,
                    5 => drop(q.edns.get_or_insert_with(Default::default).set_max_payload(512)),
                    _ => {}
                }
                let raw = q.to_vec().unwrap();
                let view = wire::parse_query(&raw).unwrap();
                for udp in [true, false] {
                    let label = format!("{name} {qtype} variant {variant} udp {udp}");
                    let InlineHit::Blocked { len, list } =
                        s.runtime().hit_inline(&raw, &view, ip, udp, &mut key, &mut answer, &mut scratch)
                    else {
                        panic!("{label}: a blocked name must answer inline");
                    };
                    assert_eq!(list, Some(0), "{label}");
                    let slow = slow_path_answer(&s, &raw, ip, udp).await.unwrap();
                    assert_eq!(&answer[..len], slow.as_slice(), "{label}");
                    let (served, traced) = querylog::traced(s.handle_with(&s.runtime(), &raw, ip, udp)).await;
                    assert_eq!(served.unwrap(), slow, "{label}");
                    assert_eq!((traced.outcome, traced.list), (Some(Outcome::Blocked), Some(0)), "{label}");
                }
                // The exempt client is not blocked: no upstream, so SERVFAIL.
                assert!(matches!(
                    s.runtime().hit_inline(&raw, &view, exempt, true, &mut key, &mut answer, &mut scratch),
                    InlineHit::Slow
                ));
                assert_eq!(code(&s.handle(&raw, exempt, true).await.unwrap()), ResponseCode::ServFail);
            }
        }
        // Special-use and local-zone answers precede the blocklist.
        for (name, qtype) in [("x.onion", RecordType::A), ("4.3.2.10.in-addr.arpa", RecordType::PTR)] {
            let raw = query(name, qtype).to_vec().unwrap();
            let view = wire::parse_query(&raw).unwrap();
            assert!(matches!(
                s.runtime().hit_inline(&raw, &view, ip, true, &mut key, &mut answer, &mut scratch),
                InlineHit::Slow
            ));
            let (_, traced) = querylog::traced(s.handle_with(&s.runtime(), &raw, ip, true)).await;
            assert_eq!(traced.outcome, Some(Outcome::Local), "{name}");
        }
        let exempt_queries = names.len() * qtypes.len() * 6;
        assert_eq!(s.parse_calls.load(Ordering::Relaxed), exempt_queries + 2, "only exempt and local queries parse");
    }

    /// The receive loop must yield to other tasks while datagrams keep
    /// arriving: with one thread, spawned slow-path queries, the IO driver
    /// and timers only run when it does. One query that needs a spawned task
    /// (a `.local` name) is queued ahead of 159 cache hits. A loop that spends
    /// Tokio's budget yields after 128 datagrams and the spawned answer goes
    /// out among the hits; one that does not answers every hit first. On
    /// Linux this is the batched (`recvmmsg`) loop.
    #[tokio::test]
    async fn the_receive_loop_yields_while_datagrams_keep_arriving() {
        const QUEUED: usize = 160;
        let s = server(Config { upstreams: vec![], fallback: vec![], ..Config::default() });
        let hit = query("yield-hit.test", RecordType::A);
        cache_answer(&s, &hit, 1, 300);
        let mut probe = query("probe.local", RecordType::A);
        probe.metadata.id = 7;
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        client.connect(socket.local_addr().unwrap()).unwrap();
        client.set_nonblocking(true).unwrap();
        client.send(&probe.to_vec().unwrap()).unwrap();
        let raw = hit.to_vec().unwrap();
        for _ in 1..QUEUED {
            client.send(&raw).unwrap();
        }
        let (stop, stop_rx) = watch::channel(false);
        let worker = tokio::spawn(udp_worker(s, socket, Arc::new(Semaphore::new(1024)), 1024, 32, false, stop_rx));
        // Replies in arrival order; the probe's position says when its task ran.
        let (mut buf, mut answered, mut probe_at) = ([0u8; 512], 0, None);
        let deadline = Instant::now() + Duration::from_secs(5);
        while answered < QUEUED && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(1)).await;
            while let Ok(n) = client.recv(&mut buf) {
                answered += 1;
                if n >= 2 && buf[..2] == [0, 7] {
                    probe_at = Some(answered);
                }
            }
        }
        stop.send(true).unwrap();
        worker.await.unwrap().unwrap();
        assert_eq!(answered, QUEUED, "every query is answered");
        let probe_at = probe_at.expect("the probe is answered");
        assert!(probe_at <= 130, "the spawned answer waited for {} cache hits", probe_at - 1);
    }

    #[tokio::test]
    async fn fast_path_truncates_a_large_cached_answer_without_parsing() {
        let s = server(Config { upstreams: vec![], fallback: vec![], ..Config::default() });
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        // 100 A records is about 1.5 KB on the wire; 40 records (~700 B) would
        // not reach the default 1232-byte EDNS cap.
        for (advertised, expected) in [(None, None), (Some(4096u16), Some(1232u16))] {
            let mut q = query(&format!("TruncatEd-{}.test", advertised.unwrap_or(512)), RecordType::A);
            if let Some(advertised) = advertised {
                q.edns.get_or_insert_with(Default::default).set_max_payload(advertised);
            }
            let raw = q.to_vec().unwrap();
            cache_answer(&s, &q, 100, 300);
            let runtime = s.runtime();
            let view = wire::parse_query(&raw).unwrap();
            let answer = runtime.fast_path(&raw, &view, ip, true).await.unwrap();
            let parsed = Message::from_vec(&answer).unwrap();
            assert!(parsed.metadata.truncation);
            assert!(!parsed.metadata.authentic_data, "a truncated relay is not authenticated data");
            assert!(parsed.answers.is_empty(), "a TC reply carries no answers");
            assert!(parsed.authorities.is_empty());
            assert_eq!(parsed.metadata.id, 42, "the client ID is preserved");
            assert_eq!(
                wire::parse_query(&answer).unwrap().qname_wire,
                view.qname_wire,
                "the client's question is echoed"
            );
            assert_eq!(parsed.edns.as_ref().map(hickory_proto::op::Edns::max_payload), expected);
            assert!(answer.len() <= usize::from(expected.unwrap_or(512)));
            assert_eq!(answer, slow_path_answer(&s, &raw, ip, true).await.unwrap(), "same bytes as the parsed path");
            // `s.handle` is the path whose probe detects a hickory parse;
            // `slow_path_answer` calls the free `parse` and cannot. Both must
            // produce the fast path's bytes, and the probe must not move.
            assert_eq!(s.handle(&raw, ip, true).await.unwrap(), answer);
            assert_eq!(s.parse_calls.load(Ordering::Relaxed), 0, "no hickory parse on a truncated hit");
        }
    }

    #[tokio::test]
    async fn fast_path_never_bypasses_local_policy_on_a_warm_cache() {
        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        // A block applied after the positive entry was cached.
        let blocked = server(Config { upstreams: vec![], fallback: vec![], ..Config::default() });
        let q = query("late-block.test", RecordType::A);
        cache_answer(&blocked, &q, 1, 300);
        blocked.set_rules(rules::Rules::from_lines(["||late-block.test^"], 1));
        assert_eq!(code(&blocked.handle(&q.to_vec().unwrap(), ip, true).await.unwrap()), ResponseCode::NXDomain);

        // A rewrite that applies to a name with a cached entry.
        let rewritten = server(Config {
            rewrites: HashMap::from([("late-rewrite.test".to_string(), "192.0.2.7".parse().unwrap())]),
            upstreams: vec![],
            fallback: vec![],
            ..Config::default()
        });
        let q = query("late-rewrite.test", RecordType::A);
        cache_answer(&rewritten, &q, 1, 300);
        let answer = rewritten.handle(&q.to_vec().unwrap(), ip, true).await.unwrap();
        assert_eq!(answer_a(&answer), Some("192.0.2.7".parse().unwrap()), "the rewrite wins over the cache");
        assert_eq!(Message::from_vec(&answer).unwrap().answers.len(), 1);

        // A local reverse zone still answers for a name with a cached entry.
        let reverse = server(Config { upstreams: vec![], fallback: vec![], ..Config::default() });
        let q = query("10.in-addr.arpa", RecordType::A);
        cache_answer(&reverse, &q, 1, 300);
        let answer = reverse.handle(&q.to_vec().unwrap(), ip, true).await.unwrap();
        let parsed = Message::from_vec(&answer).unwrap();
        assert!(parsed.metadata.authoritative, "the local zone answer is authoritative");
        assert!(parsed.answers.is_empty(), "the zone apex is NODATA for A");
        assert!(matches!(parsed.authorities[0].data, RData::SOA(_)));
    }

    #[tokio::test]
    async fn fast_path_handles_stale_hits() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        // Timeout 0: answer the stale copy now and refresh in the background.
        let requests = Arc::new(AtomicUsize::new(0));
        let (addr, peer) = serve_udp(true, Duration::ZERO, requests.clone()).await;
        let optimistic = Config { serve_stale_client_timeout_ms: 0, ..Config::default() };
        let s = server(Config { upstreams: vec![], fallback: vec![addr], ..optimistic });
        let q = query("fast-stale.test", RecordType::A);
        seed_stale(&s, &q, &key_for(&q));
        let raw = q.to_vec().unwrap();
        let runtime = s.runtime();
        let view = wire::parse_query(&raw).unwrap();
        let answer = runtime.fast_path(&raw, &view, ip, true).await.unwrap();
        assert_eq!(Message::from_vec(&answer).unwrap().answers[0].ttl, 30, "the stale copy answers immediately");
        wait_until(|| requests.load(SeqCst) == 1).await;

        // A positive timeout waits for the refresh and returns the fresh copy.
        let requests = Arc::new(AtomicUsize::new(0));
        let (addr, peer2) = serve_udp(true, Duration::from_millis(50), requests.clone()).await;
        let s = server(Config {
            upstreams: vec![],
            fallback: vec![addr],
            serve_stale_client_timeout_ms: 1000,
            ..Config::default()
        });
        let q = query("fast-stale-wait.test", RecordType::A);
        seed_stale(&s, &q, &key_for(&q));
        let raw = q.to_vec().unwrap();
        let runtime = s.runtime();
        let view = wire::parse_query(&raw).unwrap();
        let answer = runtime.fast_path(&raw, &view, ip, true).await.unwrap();
        assert_eq!(Message::from_vec(&answer).unwrap().answers[0].ttl, 60, "the fresh answer, not the stale copy");
        assert_eq!(requests.load(SeqCst), 1);
        peer.abort();
        peer2.abort();
    }

    #[tokio::test]
    async fn fast_path_prefetches_positives_but_not_negatives() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        let requests = Arc::new(AtomicUsize::new(0));
        let (addr, peer) = serve_udp(true, Duration::ZERO, requests.clone()).await;
        let s = server(Config { upstreams: vec![], fallback: vec![addr], ..Config::default() });
        let q = query("fast-prefetch.test", RecordType::A);
        let key = key_for(&q);
        let mut stored = reply(&q, ResponseCode::NoError);
        stored.add_answer(Record::from_rdata(q.queries[0].name().clone(), 100, RData::A(A::new(192, 0, 2, 1))));
        assert!(s.cache().insert(&key, &stored.to_vec().unwrap(), &stored, 0));
        s.cache().backdate(&key, 96);
        let raw = q.to_vec().unwrap();
        let runtime = s.runtime();
        let view = wire::parse_query(&raw).unwrap();
        let answer = runtime.fast_path(&raw, &view, ip, true).await.unwrap();
        assert_eq!(Message::from_vec(&answer).unwrap().answers[0].ttl, 4, "the client still gets the stored answer");
        wait_until(|| requests.load(SeqCst) == 1).await;

        let requests = Arc::new(AtomicUsize::new(0));
        let (addr, peer2) = serve_udp(true, Duration::ZERO, requests.clone()).await;
        let s = server(Config { upstreams: vec![], fallback: vec![addr], ..Config::default() });
        let q = query("fast-negative.test", RecordType::A);
        let key = key_for(&q);
        let mut negative = reply(&q, ResponseCode::NXDomain);
        negative.add_authority(Record::from_rdata(
            Name::root(),
            100,
            RData::SOA(SOA::new(Name::root(), Name::root(), 0, 0, 0, 0, 100)),
        ));
        assert!(s.cache().insert(&key, &negative.to_vec().unwrap(), &negative, 0));
        s.cache().backdate(&key, 96);
        assert!(s.cache().get(&key, 0, 43_200).is_some_and(|hit| hit.negative));
        let raw = q.to_vec().unwrap();
        let runtime = s.runtime();
        let view = wire::parse_query(&raw).unwrap();
        let answer = runtime.fast_path(&raw, &view, ip, true).await.unwrap();
        assert_eq!(code(&answer), ResponseCode::NXDomain, "the negative is still answered");
        sleep(Duration::from_millis(100)).await;
        assert_eq!(requests.load(SeqCst), 0, "negatives are never prefetched");
        peer.abort();
        peer2.abort();
    }

    #[test]
    fn reverse_may_answer_agrees_with_the_builder() {
        let cases = [
            ("1.0.0.10.in-addr.arpa", RecordType::PTR, false),
            ("1.0.0.10.in-addr.arpa", RecordType::A, false),
            ("8.8.8.8.in-addr.arpa", RecordType::PTR, false),
            ("1.2.3.in-addr.arpa", RecordType::PTR, false),
            ("10.in-addr.arpa", RecordType::SOA, false),
            ("10.in-addr.arpa", RecordType::NS, false),
            ("10.in-addr.arpa", RecordType::A, false),
            ("10.in-addr.arpa", RecordType::DS, true),
            ("1.2.10.in-addr.arpa", RecordType::A, false),
            ("home.arpa", RecordType::DS, true),
            ("home.arpa", RecordType::DS, false),
            ("home.arpa", RecordType::SOA, false),
            ("printer.home.arpa", RecordType::DS, true),
            ("example.com", RecordType::A, false),
        ];
        for private_ptr in [PrivatePtr::Nxdomain, PrivatePtr::Forward] {
            let cfg = Config { private_ptr, ..Config::default() };
            for class in [DNSClass::IN, DNSClass::CH, DNSClass::HS] {
                for &(name, qtype, do_bit) in &cases {
                    let mut q = query(name, qtype);
                    q.queries[0].set_query_class(class);
                    let built = reverse_answer(&cfg, &q, name, do_bit).is_some();
                    let predicate = reverse::may_answer(&cfg, u16::from(qtype), name, do_bit);
                    assert_eq!(predicate, built, "{private_ptr:?} {class:?} {name} {qtype:?} do={do_bit}");
                }
            }
        }
        // A complete private IPv6 PTR is local too.
        let name = v6_reverse("fd00::1");
        let cfg = Config::default();
        let q = query(&name, RecordType::PTR);
        assert_eq!(
            reverse::may_answer(&cfg, u16::from(RecordType::PTR), &name, false),
            reverse_answer(&cfg, &q, &name, false).is_some()
        );
    }

    /// A conformant plain upstream that counts every query and answers it with
    /// `make`. An answer above the size the query advertised (512 without EDNS)
    /// is sent as an empty TC reply and served whole over TCP on the same port,
    /// as a real server does; that TCP retry is not counted, it is the same
    /// resolution. `wire_reply` restores the randomized question case.
    async fn serve_udp_replies<F>(
        requests: Arc<std::sync::atomic::AtomicUsize>,
        make: F,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>)
    where
        F: Fn(&Message) -> Message + Send + Sync + 'static,
    {
        use std::sync::atomic::Ordering::SeqCst;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // One port for both transports: take a free TCP port, then its UDP twin.
        let (tcp, socket) = loop {
            let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            if let Ok(socket) = UdpSocket::bind(tcp.local_addr().unwrap()).await {
                break (tcp, Arc::new(socket));
            }
        };
        let addr = socket.local_addr().unwrap();
        let make = Arc::new(make);
        let tcp_make = make.clone();
        let truncated_ids = Arc::new(Mutex::new(std::collections::HashSet::new()));
        let (tcp_ids, tcp_requests) = (truncated_ids.clone(), requests.clone());
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = tcp.accept().await else { return };
                let (make, ids, requests) = (tcp_make.clone(), tcp_ids.clone(), tcp_requests.clone());
                tokio::spawn(async move {
                    let mut len = [0u8; 2];
                    while stream.read_exact(&mut len).await.is_ok() {
                        let mut body = vec![0u8; usize::from(u16::from_be_bytes(len))];
                        if stream.read_exact(&mut body).await.is_err() {
                            return;
                        }
                        let Ok(q) = Message::from_vec(&body) else { return };
                        if !ids.lock().unwrap().remove(&q.metadata.id) {
                            requests.fetch_add(1, SeqCst);
                        }
                        let reply = wire_reply(&body, make(&q));
                        let framed = [&(reply.len() as u16).to_be_bytes()[..], &reply].concat();
                        if stream.write_all(&framed).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        let task = tokio::spawn(async move {
            loop {
                let mut buf = vec![0u8; 65535];
                let Ok((n, peer)) = socket.recv_from(&mut buf).await else { return };
                requests.fetch_add(1, SeqCst);
                let Ok(q) = Message::from_vec(&buf[..n]) else { continue };
                let mut bytes = wire_reply(&buf[..n], make(&q));
                let limit = q.edns.as_ref().map_or(512, |edns| usize::from(edns.max_payload().max(512)));
                if bytes.len() > limit {
                    let mut truncated = reply(&q, ResponseCode::NoError);
                    truncated.metadata.truncation = true;
                    truncated_ids.lock().unwrap().insert(q.metadata.id);
                    bytes = wire_reply(&buf[..n], truncated);
                }
                let _ = socket.send_to(&bytes, peer).await;
            }
        });
        (addr, task)
    }

    fn upstream_server(addr: std::net::SocketAddr) -> Arc<Server> {
        server(Config { upstreams: vec![], fallback: vec![addr], cache_size: 100, ..Config::default() })
    }

    #[tokio::test]
    async fn a_complete_answer_truncated_for_udp_is_reused_for_a_smaller_edns_client() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        let requests = Arc::new(AtomicUsize::new(0));
        let (addr, _peer) = serve_udp_replies(requests.clone(), |q| {
            let mut answer = reply(q, ResponseCode::NoError);
            for octet in 0..120u8 {
                answer.add_answer(Record::from_rdata(
                    q.queries[0].name().clone(),
                    60,
                    RData::A(A::new(192, 0, 2, octet)),
                ));
            }
            let mut edns = hickory_proto::op::Edns::new();
            edns.set_max_payload(4096);
            answer.set_edns(edns);
            answer
        })
        .await;
        let s = upstream_server(addr);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        let mut first = query("hop-opt.test", RecordType::A);
        first.edns.get_or_insert_with(Default::default).set_max_payload(1400);
        let answer = s.handle(&first.to_vec().unwrap(), ip, true).await.unwrap();
        assert!(Message::from_vec(&answer).unwrap().metadata.truncation, "the large answer is truncated for UDP");

        let mut second = query("hop-opt.test", RecordType::A);
        second.metadata.id = 43;
        second.edns.get_or_insert_with(Default::default).set_max_payload(1232);
        let answer = s.handle(&second.to_vec().unwrap(), ip, true).await.unwrap();
        assert!(Message::from_vec(&answer).unwrap().metadata.truncation);
        assert_eq!(requests.load(SeqCst), 1, "the retained complete answer serves the later request");
    }

    #[tokio::test]
    async fn complete_private_ptr_in_a_local_zone_is_authoritative_with_zone_soa() {
        let s = server(Config { upstreams: vec![], fallback: vec![], ..Config::default() });
        let q = query("4.3.2.10.in-addr.arpa", RecordType::PTR);
        let raw = s.handle(&q.to_vec().unwrap(), "127.0.0.1".parse().unwrap(), false).await.unwrap();
        let answer = Message::from_vec(&raw).unwrap();
        assert_eq!(answer.metadata.response_code, ResponseCode::NXDomain);
        assert!(answer.metadata.authoritative, "a nonexistent descendant is authoritative");
        assert_eq!(answer.authorities.len(), 1);
        assert_eq!(
            answer.authorities[0].name.to_ascii().trim_end_matches('.'),
            "10.in-addr.arpa",
            "the negative SOA is owned by the zone apex"
        );
    }

    #[tokio::test]
    async fn response_cd_copies_the_client_cd() {
        use std::sync::atomic::AtomicUsize;
        let (addr, _peer) = serve_udp_replies(Arc::new(AtomicUsize::new(0)), |q| {
            let mut answer = reply(q, ResponseCode::NoError);
            // The upstream reply differs from the client on CD.
            answer.metadata.checking_disabled = false;
            answer.add_answer(Record::from_rdata(q.queries[0].name().clone(), 60, RData::A(A::new(192, 0, 2, 1))));
            answer
        })
        .await;
        let s = upstream_server(addr);
        let mut q = query("cd-copy.test", RecordType::A);
        q.metadata.checking_disabled = true;
        let raw = s.handle(&q.to_vec().unwrap(), "127.0.0.1".parse().unwrap(), false).await.unwrap();
        assert!(
            Message::from_vec(&raw).unwrap().metadata.checking_disabled,
            "response CD copies the client CD, not the upstream reply"
        );
    }

    #[tokio::test]
    async fn ede_option_is_dropped_before_answer_data_on_udp_overflow() {
        use hickory_proto::rr::rdata::opt::EdnsOption;
        use std::sync::atomic::AtomicUsize;
        let (addr, _peer) = serve_udp_replies(Arc::new(AtomicUsize::new(0)), |q| {
            let mut answer = reply(q, ResponseCode::NoError);
            answer.add_answer(Record::from_rdata(
                q.queries[0].name().clone(),
                60,
                RData::Unknown {
                    code: RecordType::Unknown(65400),
                    rdata: hickory_proto::rr::rdata::NULL::with(vec![b'x'; 1147]),
                },
            ));
            let mut edns = hickory_proto::op::Edns::new();
            edns.set_max_payload(1232);
            let mut ede = vec![0u8, 23];
            ede.extend([b'e'; 80]);
            edns.options_mut().insert(EdnsOption::Unknown(15, ede));
            answer.set_edns(edns);
            answer
        })
        .await;
        let s = upstream_server(addr);
        let mut q = query("ede-fit.test", RecordType::Unknown(65400));
        q.edns.get_or_insert_with(Default::default).set_max_payload(1232);
        let raw = s.handle(&q.to_vec().unwrap(), "127.0.0.1".parse().unwrap(), true).await.unwrap();
        let answer = Message::from_vec(&raw).unwrap();
        assert!(raw.len() <= 1232, "the response fits the requestor payload size");
        assert_eq!(answer.answers.len(), 1, "answer data survives the EDE drop");
        assert!(answer.metadata.truncation, "TC is set when the EDE option is dropped");
    }

    #[tokio::test]
    async fn first_negative_relay_clamps_the_soa_ttl_to_the_negative_lifetime() {
        use std::sync::atomic::AtomicUsize;
        let (addr, _peer) = serve_udp_replies(Arc::new(AtomicUsize::new(0)), |q| {
            let mut answer = reply(q, ResponseCode::NXDomain);
            answer.add_authority(Record::from_rdata(
                q.queries[0].name().clone(),
                80,
                RData::SOA(SOA::new(
                    Name::from_ascii("ns.test.").unwrap(),
                    Name::from_ascii("hostmaster.test.").unwrap(),
                    1,
                    3600,
                    600,
                    86400,
                    25,
                )),
            ));
            answer
        })
        .await;
        let s = upstream_server(addr);
        let q = query("denied.test", RecordType::A);
        let raw = s.handle(&q.to_vec().unwrap(), "127.0.0.1".parse().unwrap(), false).await.unwrap();
        let answer = Message::from_vec(&raw).unwrap();
        assert_eq!(answer.metadata.response_code, ResponseCode::NXDomain);
        assert_eq!(answer.authorities[0].ttl, 25, "the emitted SOA TTL is min(SOA TTL, SOA.MINIMUM)");
    }

    #[tokio::test]
    async fn first_relay_normalizes_unequal_rrset_ttls() {
        use std::sync::atomic::AtomicUsize;
        let (addr, _peer) = serve_udp_replies(Arc::new(AtomicUsize::new(0)), |q| {
            let mut answer = reply(q, ResponseCode::NoError);
            let name = q.queries[0].name().clone();
            answer.add_answer(Record::from_rdata(name.clone(), 90, RData::A(A::new(192, 0, 2, 1))));
            answer.add_answer(Record::from_rdata(name, 30, RData::A(A::new(192, 0, 2, 2))));
            answer
        })
        .await;
        let s = upstream_server(addr);
        let q = query("rrset.test", RecordType::A);
        let raw = s.handle(&q.to_vec().unwrap(), "127.0.0.1".parse().unwrap(), false).await.unwrap();
        let answer = Message::from_vec(&raw).unwrap();
        assert_eq!(answer.answers.len(), 2);
        assert!(answer.answers.iter().all(|record| record.ttl == 30), "one RRset carries its lowest TTL");
    }

    #[tokio::test]
    async fn upstream_badvers_and_badcookie_are_failed_attempts() {
        use std::sync::atomic::AtomicUsize;
        for rcode in [ResponseCode::BADVERS, ResponseCode::BADCOOKIE] {
            let (addr, _peer) = serve_udp_replies(Arc::new(AtomicUsize::new(0)), move |q| {
                let mut answer = reply(q, rcode);
                answer.set_edns(hickory_proto::op::Edns::new());
                answer
            })
            .await;
            let s = upstream_server(addr);
            let mut q = query("hop-error.test", RecordType::A);
            q.edns.get_or_insert_with(Default::default);
            let raw = s.handle(&q.to_vec().unwrap(), "127.0.0.1".parse().unwrap(), false).await.unwrap();
            assert_eq!(
                code(&raw),
                ResponseCode::ServFail,
                "{rcode:?} from an upstream is a failed attempt, not a client answer"
            );
        }
    }
    fn hex(text: &str) -> Vec<u8> {
        (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
    }

    #[tokio::test]
    async fn a_compression_pointer_into_the_header_is_formerr_and_never_forwarded() {
        // Pointer targets 0..=11 would decode header bytes as a name.
        let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (addr, peer) = serve_udp(true, Duration::ZERO, requests.clone()).await;
        let s = upstream_server(addr);
        for target in 0u8..12 {
            let mut raw = hex("000701000001000000000000c00200010001");
            raw[12 + 1] = target;
            let answer = send(&s, &raw).await.expect("a reply, not silence");
            assert_eq!(code(&answer), ResponseCode::FormErr, "pointer to {target}");
        }
        assert_eq!(requests.load(std::sync::atomic::Ordering::SeqCst), 0, "nothing reached the upstream");
        peer.abort();
    }

    #[tokio::test]
    async fn bad_edns_version_is_badvers_even_for_meta_queries() {
        // Version negotiation precedes every policy answer (RFC 6891 §6.1.3).
        let s = server(Config { upstreams: vec![], fallback: vec![], ..Config::default() });
        for raw in [
            // AXFR with OPT version 1, and NXNAME (type 128) with OPT version 1.
            "0d0d0100000100000000000104746573740000fc000100002904d0000100000000",
            "0d0d010000010000000000010474657374000080000100002904d0000100000000",
        ] {
            let answer = send(&s, &hex(raw)).await.unwrap();
            // hickory names wire RCODE 16 BADSIG; compare the number.
            assert_eq!(u16::from(code(&answer)), 16, "{raw}");
        }
        // Version 0 keeps the opcode/QTYPE table: AXFR is REFUSED, NXNAME is FORMERR.
        let axfr = send(&s, &hex("0d0d0100000100000000000104746573740000fc000100002904d0000000000000")).await.unwrap();
        assert_eq!(code(&axfr), ResponseCode::Refused);
        let nxname =
            send(&s, &hex("0d0d010000010000000000010474657374000080000100002904d0000000000000")).await.unwrap();
        assert_eq!(code(&nxname), ResponseCode::FormErr);
    }

    #[tokio::test]
    async fn hop_options_are_stripped_upstream_and_do_not_block_caching() {
        // ECS, Cookie and Padding describe the client hop only.
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
        let requests = Arc::new(AtomicUsize::new(0));
        let leaked = Arc::new(AtomicBool::new(false));
        let seen = leaked.clone();
        let (addr, _peer) = serve_udp_replies(requests.clone(), move |q| {
            let raw = q.to_vec().unwrap();
            let view = wire::parse_query(&raw).unwrap();
            seen.fetch_or(view.edns_options || view.edns_hop_options, SeqCst);
            let mut answer = reply(q, ResponseCode::NoError);
            answer.add_answer(Record::from_rdata(q.queries[0].name().clone(), 300, RData::A(A::new(192, 0, 2, 9))));
            answer
        })
        .await;
        let s = upstream_server(addr);
        let mut options = Vec::new();
        options.extend_from_slice(&[0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8]); // Cookie
        options.extend_from_slice(&[0, 8, 0, 7, 0, 1, 24, 0, 192, 0, 2]); // ECS 192.0.2/24
        options.extend_from_slice(&[0, 12, 0, 4, 0, 0, 0, 0]); // Padding
        let raw = append_record(&query("opts.test", RecordType::A).to_vec().unwrap(), 41, 1232, 0, &options);
        for _ in 0..3 {
            let answer = Message::from_vec(&send(&s, &raw).await.unwrap()).unwrap();
            assert_eq!(answer.answers.len(), 1);
        }
        assert!(!leaked.load(SeqCst), "no client option reached the upstream");
        assert_eq!(requests.load(SeqCst), 1, "the option-carrying query was answered from cache");
    }

    #[tokio::test]
    async fn special_use_names_never_leave_the_host() {
        // RFC 6761 §6.2-6.4, RFC 7686 §2, RFC 9665 §8.4, RFC 9462 §6.1.
        let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (addr, peer) = serve_udp(true, Duration::ZERO, requests.clone()).await;
        let s = server_exact(Config { upstreams: vec![], fallback: vec![addr], ..Config::default() });
        let ask = |name: &'static str, rtype| {
            let s = s.clone();
            async move { Message::from_vec(&send(&s, &query(name, rtype).to_vec().unwrap()).await.unwrap()).unwrap() }
        };
        let a = ask("app.localhost", RecordType::A).await;
        assert_eq!(a.answers[0].data, RData::A(A(std::net::Ipv4Addr::LOCALHOST)));
        let aaaa = ask("localhost", RecordType::AAAA).await;
        assert_eq!(aaaa.answers[0].data, RData::AAAA(AAAA(std::net::Ipv6Addr::LOCALHOST)));
        let mx = ask("localhost", RecordType::MX).await;
        assert_eq!((mx.metadata.response_code, mx.answers.len()), (ResponseCode::NoError, 0));
        for name in ["x.invalid", "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion", "a.test"] {
            assert_eq!(ask(name, RecordType::A).await.metadata.response_code, ResponseCode::NXDomain, "{name}");
        }
        assert_eq!(ask("printer.service.arpa", RecordType::SVCB).await.metadata.response_code, ResponseCode::NXDomain);
        // RFC 9462 §§4, 6.4: no designated resolver, so NODATA under resolver.arpa.
        let ddr = ask("_dns.resolver.arpa", RecordType::SVCB).await;
        assert_eq!((ddr.metadata.response_code, ddr.answers.len()), (ResponseCode::NoError, 0));
        assert_eq!(ask("1.2.0.192.in-addr.arpa", RecordType::PTR).await.metadata.response_code, ResponseCode::NXDomain);
        assert_eq!(requests.load(std::sync::atomic::Ordering::SeqCst), 0, "nothing was forwarded");
        // The RFC 6761 §6.2 option forwards .test again.
        let s = server(Config { upstreams: vec![], fallback: vec![addr], ..Config::default() });
        send(&s, &query("a.test", RecordType::A).to_vec().unwrap()).await.unwrap();
        assert_eq!(requests.load(std::sync::atomic::Ordering::SeqCst), 1);
        peer.abort();
    }

    #[tokio::test]
    async fn version_negotiation_precedes_the_malformed_ecs_formerr() {
        // Version negotiation before RFC 7871 §6 (found by wire fuzzing): OPT version 2
        // with an ECS of unknown family is BADVERS; with version 0, FORMERR.
        let s = server(Config { upstreams: vec![], fallback: vec![], ..Config::default() });
        let v2 = "6dc2010000010000000000010368313104746573740001010001000029020000020000000c0008000440010000000b0000";
        assert_eq!(u16::from(code(&send(&s, &hex(v2)).await.unwrap())), 16);
        let mut v0 = hex(v2);
        v0[36] = 0; // OPT TTL byte 2: the version
        assert_eq!(code(&send(&s, &v0).await.unwrap()), ResponseCode::FormErr);
    }

    #[tokio::test]
    async fn an_empty_question_with_a_bad_edns_version_is_badvers() {
        // Version negotiation precedes the QDCOUNT=0 rule (found by differential fuzzing).
        let s = server(Config { upstreams: vec![], fallback: vec![], ..Config::default() });
        let answer = send(&s, &hex("00070100000000000000000100002904d0000100000000")).await.unwrap();
        assert_eq!(u16::from(code(&answer)), 16);
        let answer = send(&s, &hex("00070100000000000000000100002904d0000000000000")).await.unwrap();
        assert_eq!(code(&answer), ResponseCode::Refused);
    }

    #[tokio::test]
    async fn meta_qtypes_are_formerr_and_never_forwarded() {
        // RFC 6895 §3.1 (found by differential fuzzing): OPT, TSIG and
        // the 128-248 meta range never reach an upstream; MAILA/MAILB do.
        let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (addr, peer) = serve_udp(true, Duration::ZERO, requests.clone()).await;
        let s = upstream_server(addr);
        for qtype in [41u16, 129, 200, 248, 250] {
            let mut raw = hex("0d0d01000001000000000000016404746573740000c80001");
            raw[20..22].copy_from_slice(&qtype.to_be_bytes());
            let answer = send(&s, &raw).await.expect("a reply");
            assert_eq!(code(&answer), ResponseCode::FormErr, "qtype {qtype}");
        }
        assert_eq!(requests.load(std::sync::atomic::Ordering::SeqCst), 0);
        peer.abort();
    }

    #[tokio::test]
    async fn error_replies_advertise_our_payload_not_the_clients() {
        // RFC 6891 §6.2.3 (found by differential fuzzing): OPT CLASS is our own size.
        let s = server(Config { upstreams: vec![], fallback: vec![], ..Config::default() });
        // REFUSED (QDCOUNT=0) and BADVERS from clients advertising 0 and 4096.
        for raw in [
            "0007010000000000000000010000290000000000000000",
            "0007010000000000000000010000291000000000000000",
            "0007010000000000000000010000290000000100000000",
        ] {
            let answer = send(&s, &hex(raw)).await.unwrap();
            let opt = answer.len() - 11;
            assert_eq!(&answer[opt..opt + 5], &[0, 0, 41, 0x04, 0xd0], "{raw}");
        }
    }

    #[tokio::test]
    async fn replies_carry_the_clients_rd_and_ra_one_whatever_the_upstream_said() {
        // RFC 1035 §4.1.1: RD is copied from the query; RA=1 because this is a
        // recursive resolver. Checked on the relayed path and on a cache hit.
        for (rd, ra) in [(false, false), (true, false)] {
            let (addr, _peer) = serve_udp_replies(Arc::new(std::sync::atomic::AtomicUsize::new(0)), move |q| {
                let mut answer = reply(q, ResponseCode::NoError);
                answer.metadata.recursion_desired = rd;
                answer.metadata.recursion_available = ra;
                answer.add_answer(Record::from_rdata(q.queries[0].name().clone(), 60, RData::A(A::new(192, 0, 2, 1))));
                answer
            })
            .await;
            let s = upstream_server(addr);
            let raw = query("flags.test", RecordType::A).to_vec().unwrap();
            for round in ["relayed", "cached"] {
                let answer = send(&s, &raw).await.unwrap();
                assert_eq!(answer[2] & 0x01, 1, "RD follows the client ({round}, upstream rd={rd})");
                assert_eq!(answer[3] & 0x80, 0x80, "RA=1 ({round}, upstream ra={ra})");
                assert_eq!(answer[3] & 0x40, 0, "Z stays 0");
            }
        }
        // A client that cleared RD gets RD=0 back (non-cacheable, forwarded).
        let (addr, _peer) = serve_udp_replies(Arc::new(std::sync::atomic::AtomicUsize::new(0)), |q| {
            let mut answer = reply(q, ResponseCode::NoError);
            answer.metadata.recursion_desired = true;
            answer.metadata.recursion_available = false;
            answer.add_answer(Record::from_rdata(q.queries[0].name().clone(), 60, RData::A(A::new(192, 0, 2, 1))));
            answer
        })
        .await;
        let s = upstream_server(addr);
        let mut q = query("flags-nord.test", RecordType::A);
        q.metadata.recursion_desired = false;
        let answer = send(&s, &q.to_vec().unwrap()).await.unwrap();
        assert_eq!((answer[2] & 0x01, answer[3] & 0x80), (0, 0x80));
    }

    #[tokio::test]
    async fn plaintext_answers_are_neither_prefetched_nor_served_stale() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        let requests = Arc::new(AtomicUsize::new(0));
        let (addr, _peer) = serve_udp_replies(requests.clone(), |q| {
            let mut answer = reply(q, ResponseCode::NoError);
            answer.add_answer(Record::from_rdata(q.queries[0].name().clone(), 86_400, RData::A(A::new(192, 0, 2, 1))));
            answer
        })
        .await;
        let s = upstream_server(addr);
        let q = query("plain-origin.test", RecordType::A);
        let raw = q.to_vec().unwrap();
        let key = key_for(&q);
        let first = Message::from_vec(&send(&s, &raw).await.unwrap()).unwrap();
        assert_eq!(first.answers[0].ttl, 300, "the client copy of a plaintext answer is capped too");
        assert_eq!(requests.load(SeqCst), 1);
        let hit = s.cache().get(&key, 1, 43_200).expect("cached");
        assert!(hit.plain);
        assert_eq!(hit.orig_ttl, 300, "plaintext lifetime is capped");
        // Inside the last 10% of its 300 s: a DoH-learned entry would prefetch.
        s.cache().backdate(&key, 280);
        let answer = send(&s, &raw).await.unwrap();
        assert_eq!(answer_a(&answer), Some(std::net::Ipv4Addr::new(192, 0, 2, 1)));
        sleep(Duration::from_millis(100)).await;
        assert_eq!(requests.load(SeqCst), 1, "no prefetch of a plaintext answer");
        assert!(s.inflight().is_empty());
        // Expired: never served stale, the query is resolved again.
        s.cache().backdate(&key, 30);
        assert!(s.cache().get(&key, 1, 43_200).is_none());
        send(&s, &raw).await.unwrap();
        assert_eq!(requests.load(SeqCst), 2);
    }

    #[tokio::test]
    async fn a_ttl_with_the_top_bit_set_is_relayed_and_cached_capped() {
        // RFC 8767 §4, on the plain (300 s cap) and the trusted-plain (7 day
        // cap) paths.
        for (trust, ttl, cap) in [(false, 0x8000_0000, 300), (false, u32::MAX, 300), (true, u32::MAX, 604_800)] {
            let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let (addr, _peer) = serve_udp_replies(requests, move |q| {
                let mut answer = reply(q, ResponseCode::NoError);
                answer.add_answer(Record::from_rdata(q.queries[0].name().clone(), ttl, RData::A(A::new(192, 0, 2, 1))));
                answer
            })
            .await;
            let s = server(Config {
                upstreams: vec![],
                fallback: vec![addr],
                cache_size: 100,
                trust_plain_upstreams: trust,
                ..Config::default()
            });
            let q = query("msb-ttl.test", RecordType::A);
            let answer = Message::from_vec(&send(&s, &q.to_vec().unwrap()).await.unwrap()).unwrap();
            assert_eq!(answer.answers[0].ttl, cap, "trust={trust} ttl={ttl:#x}");
            let cached = s.cache().get(&key_for(&q), 0, 0).expect("cached");
            assert_eq!(cached.orig_ttl, cap, "trust={trust} ttl={ttl:#x}");
        }
    }

    #[tokio::test]
    async fn trusted_plain_upstreams_keep_their_ttls() {
        // `trust_plain_upstreams` opts out of the 300 s plaintext cap.
        let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (addr, _peer) = serve_udp_replies(requests, |q| {
            let mut answer = reply(q, ResponseCode::NoError);
            answer.add_answer(Record::from_rdata(q.queries[0].name().clone(), 86_400, RData::A(A::new(192, 0, 2, 1))));
            answer
        })
        .await;
        let s = server(Config {
            upstreams: vec![],
            fallback: vec![addr],
            cache_size: 100,
            trust_plain_upstreams: true,
            ..Config::default()
        });
        let q = query("trusted-plain.test", RecordType::A);
        let first = Message::from_vec(&send(&s, &q.to_vec().unwrap()).await.unwrap()).unwrap();
        assert_eq!(first.answers[0].ttl, 86_400);
        assert!(!s.cache().get(&key_for(&q), 0, 0).unwrap().plain);
    }

    #[tokio::test]
    async fn plaintext_negative_lifetimes_are_capped_after_the_soa_rewrite() {
        // The negative-TTL SOA rewrite must not lift a plaintext negative past 300 s.
        use std::sync::atomic::AtomicUsize;
        let requests = Arc::new(AtomicUsize::new(0));
        let (addr, _peer) = serve_udp_replies(requests, |q| {
            let mut answer = reply(q, ResponseCode::NXDomain);
            answer.add_authority(Record::from_rdata(
                Name::from_ascii("test.").unwrap(),
                86_400,
                RData::SOA(SOA::new(Name::root(), Name::root(), 1, 3600, 600, 86400, 86_400)),
            ));
            answer
        })
        .await;
        let s =
            server(Config { upstreams: vec![], fallback: vec![addr], negative_ttl_max: 86_400, ..Config::default() });
        let raw = query("nx-plain.test", RecordType::A).to_vec().unwrap();
        let answer = Message::from_vec(&send(&s, &raw).await.unwrap()).unwrap();
        assert_eq!(answer.metadata.response_code, ResponseCode::NXDomain);
        assert!(answer.authorities.iter().all(|r| r.ttl <= 300), "{:?}", answer.authorities);
    }

    #[tokio::test]
    async fn a_negative_without_soa_ends_stale_service() {
        // Valid NXDOMAIN without an SOA is relayed and evicts the stale A.
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        let requests = Arc::new(AtomicUsize::new(0));
        let (addr, _peer) = serve_udp_replies(requests.clone(), |q| reply(q, ResponseCode::NXDomain)).await;
        let s = server(Config {
            upstreams: vec![],
            fallback: vec![addr],
            serve_stale_client_timeout_ms: 1000,
            ..Config::default()
        });
        let q = query("gone.test", RecordType::A);
        let raw = q.to_vec().unwrap();
        let key = key_for(&q);
        seed_stale(&s, &q, &key);
        for round in 0..2 {
            let answer = send(&s, &raw).await.unwrap();
            assert_eq!(code(&answer), ResponseCode::NXDomain, "round {round}: never the old A");
        }
        assert!(s.cache().get(&key, 1, 43_200).is_none());
        assert_eq!(requests.load(SeqCst), 2, "the uncacheable negative is asked again, not served stale");
    }

    #[test]
    fn tcp_stops_reading_while_unwritten_output_exceeds_the_budget() {
        assert!(tcp_can_read(false, 0, 10, 0, 16, 0));
        assert!(tcp_can_read(false, 0, 10, 0, 16, TCP_UNWRITTEN_CAP));
        assert!(!tcp_can_read(false, 0, 10, 0, 16, TCP_UNWRITTEN_CAP + 1));
        assert!(!tcp_can_read(true, 0, 10, 0, 16, 0));
        assert!(!tcp_can_read(false, 10, 10, 0, 16, 0));
        assert!(!tcp_can_read(false, 0, 10, 16, 16, 0));
    }

    /// The rules page's tester against the real server: for each name, type
    /// and client, the tester's answer must equal what `handle` really returns
    /// (a name the tester says is forwarded gets SERVFAIL here, as no upstream
    /// is configured), and the matching rules must be listed strongest first.
    #[tokio::test]
    async fn rule_tester_agrees_with_the_server() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let s = server_exact(Config {
            user_rules: [
                "||blocked.example^",
                "@@||ok.blocked.example^",
                "||imp.example^$important",
                "@@||imp.example^",
                "|exact.example^",
                "||rw.example^",
                "||nas.local^",
                "||a.test^",
            ]
            .map(String::from)
            .into(),
            rewrites: HashMap::from([
                ("rw.example".into(), ip("192.0.2.7")),
                ("*.wild.example".into(), ip("192.0.2.8")),
            ]),
            no_filter_clients: vec![ip("10.0.0.5")],
            upstreams: vec![],
            fallback: vec![],
            ..Config::default()
        });
        let runtime = s.runtime();
        // (name, type, client, expected verdict)
        let cases = [
            ("blocked.example", "A", "10.0.0.9", "Blocked"),
            ("a.b.blocked.example", "AAAA", "10.0.0.9", "Blocked"),
            ("blocked.example", "A", "", "Blocked"),
            ("BLOCKED.example.", "A", "10.0.0.9", "Blocked"),
            ("ok.blocked.example", "A", "10.0.0.9", "Forwarded"),
            ("deep.ok.blocked.example", "A", "10.0.0.9", "Forwarded"),
            ("imp.example", "A", "10.0.0.9", "Blocked"),
            ("exact.example", "A", "10.0.0.9", "Blocked"),
            ("sub.exact.example", "A", "10.0.0.9", "Forwarded"),
            ("blocked.example", "A", "10.0.0.5", "Forwarded"),
            ("rw.example", "A", "10.0.0.9", "Rewrite"),
            ("rw.example", "AAAA", "10.0.0.9", "Rewrite"),
            ("x.wild.example", "A", "10.0.0.9", "Rewrite"),
            ("a.test", "A", "10.0.0.9", "Special-use name"),
            ("localhost", "A", "10.0.0.9", "Special-use name"),
            ("localhost", "AAAA", "10.0.0.9", "Special-use name"),
            ("localhost", "TXT", "10.0.0.9", "Special-use name"),
            ("1.0.0.10.in-addr.arpa", "PTR", "10.0.0.9", "Local zone"),
            ("nas.local", "A", "10.0.0.9", "Blocked"),
            ("other.local", "A", "10.0.0.9", "Local"),
            ("nas.local", "A", "10.0.0.5", "Local"),
            ("version.bind", "TXT", "10.0.0.9", "Refused"),
            ("anything.example", "ANY", "10.0.0.9", "Minimal ANY answer"),
            ("imp.example", "ANY", "10.0.0.9", "Blocked"),
            ("axfr.example", "AXFR", "10.0.0.9", "Refused"),
            ("blocked.example", "A", "8.8.8.8", "Refused"),
            ("public.example", "A", "10.0.0.9", "Forwarded"),
        ];
        for (name, qtype, client, verdict) in cases {
            let form = ui::TestForm { name: name.into(), qtype: qtype.into(), client: client.into() };
            let tested = runtime.test_domain(&form);
            assert_eq!(tested.error, None, "{name}");
            assert_eq!(tested.verdict, verdict, "{name} {qtype} from {client:?}: {}", tested.detail);
            let peer = if client.is_empty() { ip("10.0.0.9") } else { ip(client) };
            let q = query(name, qtype.parse::<RecordType>().unwrap());
            let real = Message::from_vec(&s.handle(&q.to_vec().unwrap(), peer, true).await.unwrap()).unwrap();
            let rcode = real.metadata.response_code;
            if verdict == "Forwarded" {
                assert_eq!(rcode, ResponseCode::ServFail, "{name}: the server did not answer locally");
                continue;
            }
            let addresses: Vec<String> = real.answers.iter().map(|r| r.data.to_string()).collect();
            let expected = match (rcode, addresses.is_empty()) {
                (ResponseCode::NoError, true) => "NOERROR, no data".to_string(),
                (ResponseCode::NoError, false) => format!("NOERROR {}", addresses.join(", ")),
                (ResponseCode::NXDomain, _) => "NXDOMAIN".to_string(),
                (ResponseCode::Refused, _) => "REFUSED".to_string(),
                (ResponseCode::NotImp, _) => "NOTIMP".to_string(),
                (other, _) => panic!("{name}: unexpected {other:?}"),
            };
            assert_eq!(tested.answer, expected, "{name} {qtype} from {client:?}");
        }

        // Rules: strongest first, from the right list and line.
        let t = |name: &str, client: &str| {
            runtime.test_domain(&ui::TestForm { name: name.into(), qtype: "A".into(), client: client.into() })
        };
        let rows = t("x.imp.example", "").rows;
        let view: Vec<_> = rows.iter().map(|r| (r.rule.as_str(), r.list, r.line, r.wins)).collect();
        assert_eq!(
            view,
            [("||imp.example^$important", Some(0), Some(3), true), ("@@||imp.example^", Some(0), Some(4), false)]
        );
        assert!(t("ok.blocked.example", "").rows[0].rule.starts_with("@@||ok.blocked.example^"));
        let rows = t("x.sub.exact.example", "").rows;
        assert!(
            rows.len() == 1 && !rows[0].applies && !rows[0].wins,
            "an exact rule on a parent is listed, not applied"
        );
        assert!(t("unlisted.example", "").rows.is_empty());
        assert!(t("blocked.example", "10.0.0.5").notes.iter().any(|n| n.contains("exempt")));
        assert!(t("rw.example", "").notes.iter().any(|n| n.contains("decided before the blocklist")));
        assert!(t("exact.example", "").scan_complete);

        // Bad input is refused with a message, never a decision.
        for (name, qtype, client) in [
            ("", "A", ""),
            ("a..b", "A", ""),
            (&"a".repeat(64), "A", ""),
            ("ok.example", "NOPE", ""),
            ("ok.example", "A", "not-an-ip"),
        ] {
            let tested =
                runtime.test_domain(&ui::TestForm { name: name.into(), qtype: qtype.into(), client: client.into() });
            assert!(tested.error.is_some(), "{name:?} {qtype} {client:?}");
        }
        // The tester counted nothing: only the real queries above did.
    }

    // ---- CNAME-target blocking (CNAME cloaking) -------------------------------------

    /// Answers every query with `<owner> CNAME tracker.cloak.test` and an A
    /// record at the target.
    fn cloaked(q: &Message) -> Message {
        let mut answer = reply(q, ResponseCode::NoError);
        let target = Name::from_ascii("tracker.cloak.test.").unwrap();
        answer.add_answer(Record::from_rdata(
            q.queries[0].name().clone(),
            60,
            RData::CNAME(hickory_proto::rr::rdata::CNAME(target.clone())),
        ));
        answer.add_answer(Record::from_rdata(target, 60, RData::A(A::new(192, 0, 2, 1))));
        answer
    }

    fn cname_server(addr: std::net::SocketAddr, rules: &[&str], tweak: impl FnOnce(&mut Config)) -> Arc<Server> {
        let mut cfg = Config {
            user_rules: rules.iter().map(|r| r.to_string()).collect(),
            upstreams: vec![],
            fallback: vec![addr],
            cache_size: 100,
            ..Config::default()
        };
        tweak(&mut cfg);
        server(cfg)
    }

    const FILTERED: &str = "192.168.1.20";

    /// The parsed path for one client, with its query-log trace.
    async fn traced_answer(s: &Arc<Server>, name: &str, client: &str, udp: bool) -> (Message, querylog::Traced) {
        let raw = query(name, RecordType::A).to_vec().unwrap();
        let (answer, traced) = querylog::traced(s.handle_with(&s.runtime(), &raw, client.parse().unwrap(), udp)).await;
        (Message::from_vec(&answer.unwrap()).unwrap(), traced)
    }

    fn is_cname_block(answer: &Message) -> bool {
        answer.metadata.response_code == ResponseCode::NXDomain
            && answer.answers.is_empty()
            && matches!(answer.authorities.first().map(|r| &r.data), Some(RData::SOA(_)))
    }

    /// Whether the synchronous UDP hit path answers `name` for `client`.
    fn answers_inline(s: &Arc<Server>, name: &str, client: &str) -> bool {
        let raw = query(name, RecordType::A).to_vec().unwrap();
        let view = wire::parse_query(&raw).unwrap();
        let (mut key, mut answer, mut scratch) = ([0u8; wire::MIN_CANONICAL_BUFFER], Vec::new(), Vec::new());
        match s.runtime().hit_inline(&raw, &view, client.parse().unwrap(), true, &mut key, &mut answer, &mut scratch) {
            InlineHit::Inline(_) | InlineHit::Truncated(_) | InlineHit::Blocked { .. } => true,
            InlineHit::NeedAsync { .. } | InlineHit::Slow => false,
        }
    }

    #[tokio::test]
    async fn a_blocked_cname_target_blocks_the_relayed_and_the_cached_answer() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        let requests = Arc::new(AtomicUsize::new(0));
        let (addr, _peer) = serve_udp_replies(requests.clone(), cloaked).await;
        let s = cname_server(addr, &["||cloak.test^"], |_| {});

        // Relayed: the direct-block shape, logged as a block by "cname target".
        let (answer, traced) = traced_answer(&s, "a.pem.test", FILTERED, true).await;
        assert!(is_cname_block(&answer), "{answer:?}");
        assert_eq!(traced.outcome, Some(Outcome::Blocked));
        assert_eq!(traced.list, Some(querylog::CNAME_TARGET));
        assert_eq!(ui::list_name(&[], querylog::CNAME_TARGET), "cname target");
        assert_eq!(requests.load(SeqCst), 1);

        // Cached: the inline path hands over, the parsed path blocks, no upstream.
        assert!(!answers_inline(&s, "a.pem.test", FILTERED), "a blocked target never answers inline");
        for udp in [true, false] {
            let (answer, traced) = traced_answer(&s, "a.pem.test", FILTERED, udp).await;
            assert!(is_cname_block(&answer));
            assert_eq!((traced.outcome, traced.list), (Some(Outcome::Blocked), Some(querylog::CNAME_TARGET)));
        }
        assert_eq!(requests.load(SeqCst), 1, "the answer is cached unchanged");
        // The same shape as a direct block.
        let direct = cname_server(addr, &["||a.pem.test^"], |_| {});
        let (direct, _) = traced_answer(&direct, "a.pem.test", FILTERED, false).await;
        let (cname, _) = traced_answer(&s, "a.pem.test", FILTERED, false).await;
        assert_eq!(direct.to_vec().unwrap(), cname.to_vec().unwrap());
    }

    #[tokio::test]
    async fn an_allowed_query_name_is_not_blocked_by_its_target() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        let requests = Arc::new(AtomicUsize::new(0));
        let (addr, _peer) = serve_udp_replies(requests.clone(), cloaked).await;
        let s = cname_server(addr, &["||cloak.test^", "@@||pem.test^"], |_| {});
        let (answer, traced) = traced_answer(&s, "a.pem.test", FILTERED, true).await;
        assert_eq!(answer.metadata.response_code, ResponseCode::NoError);
        assert_eq!(answer.answers.len(), 2, "the CNAME chain is relayed untouched");
        assert_eq!(traced.outcome, Some(Outcome::Upstream));
        assert!(answers_inline(&s, "a.pem.test", FILTERED), "an allowed name keeps the cheap hit path");
        // Another name with the same target is still blocked.
        let (answer, _) = traced_answer(&s, "a.other.test", FILTERED, true).await;
        assert!(is_cname_block(&answer));
        assert_eq!(requests.load(SeqCst), 2);
    }

    #[tokio::test]
    async fn a_client_exempt_from_filtering_gets_the_answer() {
        use std::sync::atomic::AtomicUsize;
        let (addr, _peer) = serve_udp_replies(Arc::new(AtomicUsize::new(0)), cloaked).await;
        let s =
            cname_server(addr, &["||cloak.test^"], |cfg| cfg.no_filter_clients = vec!["127.0.0.1".parse().unwrap()]);
        // The exempt client fills the cache; the filtered one is then blocked
        // from that very entry, and the exempt one still gets it.
        for (client, blocked) in [("127.0.0.1", false), (FILTERED, true), ("127.0.0.1", false), (FILTERED, true)] {
            let (answer, _) = traced_answer(&s, "a.pem.test", client, false).await;
            assert_eq!(is_cname_block(&answer), blocked, "{client}");
            assert_eq!(answer.answers.len(), if blocked { 0 } else { 2 }, "{client}");
        }
        assert!(!answers_inline(&s, "a.pem.test", "127.0.0.1"), "a blocked entry always takes the parsed path");
    }

    #[tokio::test]
    async fn a_rules_reload_recomputes_a_cached_verdict() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        let requests = Arc::new(AtomicUsize::new(0));
        let (addr, _peer) = serve_udp_replies(requests.clone(), cloaked).await;
        let s = cname_server(addr, &[], |_| {});
        let (answer, _) = traced_answer(&s, "a.pem.test", FILTERED, true).await;
        assert_eq!(answer.metadata.response_code, ResponseCode::NoError);
        assert!(answers_inline(&s, "a.pem.test", FILTERED));

        // New rules: the stored verdict is for an older table, so the inline
        // path hands over and the parsed path decides with the new rules.
        s.set_rules(rules::Rules::from_lines(["||cloak.test^"], 0));
        assert!(!answers_inline(&s, "a.pem.test", FILTERED));
        let (answer, _) = traced_answer(&s, "a.pem.test", FILTERED, true).await;
        assert!(is_cname_block(&answer));
        assert!(!answers_inline(&s, "a.pem.test", FILTERED), "still blocked, so still the parsed path");

        // The list is gone again: unblocked from the same entry, cheap again.
        s.set_rules(rules::Rules::default());
        assert!(!answers_inline(&s, "a.pem.test", FILTERED), "stale verdict");
        let (answer, _) = traced_answer(&s, "a.pem.test", FILTERED, true).await;
        assert_eq!(answer.metadata.response_code, ResponseCode::NoError);
        assert!(answers_inline(&s, "a.pem.test", FILTERED), "the refreshed verdict is current");
        assert_eq!(requests.load(SeqCst), 1, "the cache was never refetched");
    }

    #[tokio::test]
    async fn block_cname_targets_off_serves_the_answer() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        let requests = Arc::new(AtomicUsize::new(0));
        let (addr, _peer) = serve_udp_replies(requests.clone(), cloaked).await;
        let s = cname_server(addr, &["||cloak.test^"], |cfg| cfg.block_cname_targets = false);
        for udp in [true, false] {
            let (answer, _) = traced_answer(&s, "a.pem.test", FILTERED, udp).await;
            assert_eq!(answer.metadata.response_code, ResponseCode::NoError);
            assert_eq!(answer.answers.len(), 2);
        }
        assert!(answers_inline(&s, "a.pem.test", FILTERED));
        assert_eq!(requests.load(SeqCst), 1);
    }

    #[tokio::test]
    async fn every_owner_and_target_in_the_answer_is_judged() {
        let s = cname_server("127.0.0.1:9".parse().unwrap(), &["||cloak.test^"], |_| {});
        let runtime = s.runtime();
        let q = query("www.test", RecordType::A);
        let qname = wire_name("www.test");
        let a = |owner: &str| Record::from_rdata(Name::from_ascii(owner).unwrap(), 60, RData::A(A::new(192, 0, 2, 1)));
        let cname = |owner: &str, target: &str| {
            Record::from_rdata(
                Name::from_ascii(owner).unwrap(),
                60,
                RData::CNAME(hickory_proto::rr::rdata::CNAME(Name::from_ascii(target).unwrap())),
            )
        };
        let build = |records: Vec<Record>| {
            let mut answer = reply(&q, ResponseCode::NoError);
            for record in records {
                answer.add_answer(record);
            }
            answer.to_vec().unwrap()
        };
        // Nothing but the query name: no verdict to store.
        assert!(runtime.chain_state(&build(vec![a("www.test.")]), &qname).is_none());
        // A clean chain is not blocked; a blocked target or owner is.
        let verdict = |records: Vec<Record>| runtime.chain_state(&build(records), &qname).map(|c| c.blocked());
        assert_eq!(verdict(vec![cname("www.test.", "ok.test."), a("ok.test.")]), Some(false));
        assert_eq!(verdict(vec![cname("www.test.", "x.cloak.test."), a("x.cloak.test.")]), Some(true));
        assert_eq!(verdict(vec![a("www.test."), a("off.cloak.test.")]), Some(true), "an off-chain owner counts");
        assert_eq!(verdict(vec![cname("elsewhere.test.", "x.cloak.test.")]), Some(true), "an off-chain target counts");
        // A broken chain hides nothing: a loop, a conflict, a gap and an overlong chain.
        let looped =
            vec![cname("www.test.", "a.test."), cname("a.test.", "www.test."), cname("a.test.", "x.cloak.test.")];
        assert_eq!(verdict(looped), Some(true), "loop");
        let conflict = vec![cname("www.test.", "a.test."), cname("www.test.", "x.cloak.test.")];
        assert_eq!(verdict(conflict), Some(true), "conflict");
        let gap = vec![cname("www.test.", "a.test."), a("x.cloak.test.")];
        assert_eq!(verdict(gap), Some(true), "missing link");
        let long: Vec<Record> = (0..40)
            .map(|i| cname(&format!("h{i}.test."), &format!("h{}.test.", i + 1)))
            .chain([cname("www.test.", "h0.test."), cname("h40.test.", "x.cloak.test.")])
            .collect();
        assert_eq!(verdict(long), Some(true), "overlong chain");
        // An allowed target is not a hit, even under a blocked parent.
        let chained = build(vec![cname("www.test.", "tracker.cloak.test."), a("tracker.cloak.test.")]);
        s.set_rules(rules::Rules::from_lines(["||cloak.test^", "@@||tracker.cloak.test^"], 0));
        assert!(!s.runtime().chain_state(&chained, &qname).unwrap().blocked());
        // The query name's own allow rule wins over a blocked target.
        s.set_rules(rules::Rules::from_lines(["||cloak.test^", "@@||test^"], 0));
        assert!(!s.runtime().chain_state(&chained, &qname).unwrap().blocked());
    }

    #[tokio::test]
    async fn a_broken_chain_with_a_blocked_target_is_blocked_end_to_end() {
        use std::sync::atomic::AtomicUsize;
        let (addr, _peer) = serve_udp_replies(Arc::new(AtomicUsize::new(0)), |q| {
            // owner -> a -> owner (loop), and a -> blocked target past the break.
            let owner = q.queries[0].name().clone();
            let a = Name::from_ascii("a.loop.test.").unwrap();
            let cname = |from: &Name, to: &Name| {
                Record::from_rdata(from.clone(), 60, RData::CNAME(hickory_proto::rr::rdata::CNAME(to.clone())))
            };
            let mut answer = reply(q, ResponseCode::NoError);
            answer.add_answer(cname(&owner, &a));
            answer.add_answer(cname(&a, &owner));
            answer.add_answer(cname(&a, &Name::from_ascii("tracker.cloak.test.").unwrap()));
            answer
        })
        .await;
        let s = cname_server(addr, &["||cloak.test^"], |_| {});
        let (answer, traced) = traced_answer(&s, "www.loop.test", FILTERED, false).await;
        assert!(is_cname_block(&answer), "{answer:?}");
        assert_eq!(traced.list, Some(querylog::CNAME_TARGET));
    }

    #[tokio::test]
    async fn a_dname_target_counts_as_a_chain_target() {
        use hickory_proto::rr::rdata::NULL;
        // Extra rule next to `||cloak.test^`, and whether the answer is blocked.
        let rule_sets = [("||other.test^", true), ("@@||src.test^", false)];
        let q = query("www.src.test", RecordType::A);
        // www.src.test is rewritten to www.cloak.test by `src.test DNAME cloak.test`.
        let mut answer = reply(&q, ResponseCode::NoError);
        answer.add_answer(Record::from_rdata(
            Name::from_ascii("src.test.").unwrap(),
            60,
            RData::Unknown { code: RecordType::DNAME, rdata: NULL::with(wire_name("cloak.test.")) },
        ));
        answer.add_answer(Record::from_rdata(
            Name::from_ascii("www.cloak.test.").unwrap(),
            60,
            RData::A(A::new(192, 0, 2, 1)),
        ));
        let raw = answer.to_vec().unwrap();
        for (rule_text, blocked) in rule_sets {
            let s = cname_server("127.0.0.1:9".parse().unwrap(), &["||cloak.test^", rule_text], |_| {});
            let state = s.runtime().chain_state(&raw, &wire_name("www.src.test")).unwrap();
            assert_eq!(state.blocked(), blocked, "{rule_text}");
        }
    }

    #[tokio::test]
    async fn a_stale_answer_with_a_blocked_target_is_blocked_and_so_is_its_refresh() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        let requests = Arc::new(AtomicUsize::new(0));
        let (addr, _peer) = serve_udp_replies(requests.clone(), cloaked).await;
        let s = cname_server(addr, &[], |cfg| cfg.no_filter_clients = vec!["127.0.0.1".parse().unwrap()]);
        let q = query("a.pem.test", RecordType::A);
        let key = key_for(&q);
        let stored = cloaked(&q);
        assert!(s.cache().insert(&key, &stored.to_vec().unwrap(), &stored, 0));
        s.cache().backdate(&key, 61);

        // Stale and blocked: the filtered client is blocked, the exempt one
        // would be served the stale copy.
        s.set_rules(rules::Rules::from_lines(["||cloak.test^"], 0));
        let (answer, _) = traced_answer(&s, "a.pem.test", FILTERED, false).await;
        assert!(is_cname_block(&answer), "{answer:?}");
        // The refresh carries the same target; it is cached with a blocked verdict.
        wait_until(|| requests.load(SeqCst) >= 1 && s.cache().get(&key, 0, 43_200).is_some_and(|hit| !hit.stale)).await;
        let (answer, traced) = traced_answer(&s, "a.pem.test", FILTERED, true).await;
        assert!(is_cname_block(&answer));
        assert_eq!(traced.list, Some(querylog::CNAME_TARGET));
        assert!(!answers_inline(&s, "a.pem.test", FILTERED));
        let (answer, _) = traced_answer(&s, "a.pem.test", "127.0.0.1", true).await;
        assert_eq!(answer.answers.len(), 2, "an exempt client is not affected");
    }

    #[tokio::test]
    async fn the_rule_tester_mentions_cname_targets_only_when_they_are_blocked() {
        let note = "An upstream CNAME to a blocked name would also be blocked.";
        for on in [true, false] {
            let s = server_exact(Config {
                block_cname_targets: on,
                upstreams: vec![],
                fallback: vec![],
                ..Config::default()
            });
            let form = ui::TestForm { name: "public.example".into(), qtype: "A".into(), client: String::new() };
            let tested = s.runtime().test_domain(&form);
            assert_eq!(tested.verdict, "Forwarded");
            assert_eq!(tested.notes.iter().any(|n| n == note), on, "knob {on}");
        }
    }

    /// A client over `upstream_inflight_per_client` gets SERVFAIL for
    /// new misses at once; another host, cache hits and later queries are not
    /// affected, and a slot frees when its query ends.
    #[tokio::test]
    async fn a_client_over_its_upstream_cap_gets_tc_and_others_are_served() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        let requests = Arc::new(AtomicUsize::new(0));
        let (addr, _peer) = serve_udp(true, Duration::from_millis(400), requests.clone()).await;
        let s = server(Config {
            upstreams: vec![],
            fallback: vec![addr],
            upstream_inflight_per_client: 2,
            upstream_timeout_seconds: 3,
            ..Config::default()
        });
        let (a, b): (IpAddr, IpAddr) = ("10.0.0.10".parse().unwrap(), "10.0.0.11".parse().unwrap());
        // A cached name for the flooder: hits never take a slot.
        let warm = query("warm.test", RecordType::A);
        let key = key_for(&warm);
        let reply_for_warm = {
            let mut m = reply(&warm, ResponseCode::NoError);
            m.add_answer(Record::from_rdata(warm.queries[0].name().clone(), 600, RData::A(A::new(192, 0, 2, 9))));
            m
        };
        assert!(s.cache().insert(&key, &reply_for_warm.to_vec().unwrap(), &reply_for_warm, 0));

        let mut flood = JoinSet::new();
        for i in 0..5u16 {
            let s = s.clone();
            flood.spawn(async move {
                let mut q = query(&format!("flood{i}.test"), RecordType::A);
                q.metadata.id = 0x100 + i;
                s.handle(&q.to_vec().unwrap(), a, true).await
            });
        }
        // Let the five arrive; two hold slots behind the 400 ms upstream.
        tokio::time::sleep(Duration::from_millis(150)).await;
        let started = Instant::now();
        let mut victim = query("victim.test", RecordType::A);
        victim.metadata.id = 0x200;
        let answer = s.handle(&victim.to_vec().unwrap(), b, true).await.unwrap();
        assert_eq!(code(&answer), ResponseCode::NoError, "another host is served");
        let hit = s.handle(&warm.to_vec().unwrap(), a, true).await.unwrap();
        assert_eq!(answer_a(&hit), Some("192.0.2.9".parse().unwrap()), "a cache hit needs no slot");
        assert!(started.elapsed() < Duration::from_millis(700));

        let mut codes = Vec::new();
        while let Some(done) = flood.join_next().await {
            codes.push(truncated(&done.unwrap().unwrap()));
        }
        let failed = codes.iter().filter(|tc| **tc).count();
        assert_eq!((failed, codes.len() - failed), (3, 2), "two slots, three TC replies: {codes:?}");
        assert!(requests.load(SeqCst) <= 3, "the refused ones never reached the upstream");

        // Slots are free again.
        let mut again = query("flood9.test", RecordType::A);
        again.metadata.id = 0x300;
        assert_eq!(code(&s.handle(&again.to_vec().unwrap(), a, true).await.unwrap()), ResponseCode::NoError);
    }

    /// A UDP reply that is a TC=1 with no answers: what the cap answers over UDP.
    fn truncated(answer: &[u8]) -> bool {
        let m = Message::from_vec(answer).unwrap();
        m.metadata.truncation && m.answers.is_empty() && m.metadata.response_code == ResponseCode::NoError
    }

    #[tokio::test]
    async fn the_per_client_upstream_cap_keys_on_the_host_and_zero_disables_it() {
        let (addr, _peer) = serve_udp(true, Duration::from_millis(300), Arc::new(Default::default())).await;
        for (cap, expect_failed) in [(1usize, 3usize), (0, 0)] {
            let s = server(Config {
                upstreams: vec![],
                fallback: vec![addr],
                upstream_inflight_per_client: cap,
                upstream_timeout_seconds: 3,
                ..Config::default()
            });
            // Four misses from one IPv6 host.
            let mut tasks = JoinSet::new();
            for i in 0..4u16 {
                let s = s.clone();
                tasks.spawn(async move {
                    let ip: IpAddr = "fd00:0:0:1::1".parse().unwrap();
                    let mut q = query(&format!("host{i}.test"), RecordType::A);
                    q.metadata.id = i + 1;
                    truncated(&s.handle(&q.to_vec().unwrap(), ip, true).await.unwrap())
                });
            }
            let mut failed = 0;
            while let Some(tc) = tasks.join_next().await {
                failed += usize::from(tc.unwrap());
            }
            assert_eq!(failed, expect_failed, "cap {cap}");
        }
    }

    /// A follower waiting over UDP holds one of the shared UDP request
    /// permits, so it counts against its host's cap: one host cannot park
    /// followers behind slow names until no permit is left for anyone else.
    /// Over TCP a follower holds only its own connection's slots and is not
    /// counted, so the TC=1 retry of a capped follower is served.
    #[tokio::test]
    async fn udp_followers_count_against_the_cap_and_tcp_followers_do_not() {
        let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (addr, _peer) = serve_udp(true, Duration::from_millis(300), requests.clone()).await;
        let s = server(Config {
            upstreams: vec![],
            fallback: vec![addr],
            upstream_inflight_per_client: 2,
            upstream_timeout_seconds: 3,
            ..Config::default()
        });
        let ip: IpAddr = "10.0.0.20".parse().unwrap();
        for (udp, name, expect) in [(true, "same.test", (2, 2)), (false, "same-tcp.test", (4, 0))] {
            let mut tasks = JoinSet::new();
            for i in 0..4u16 {
                let s = s.clone();
                tasks.spawn(async move {
                    let mut q = query(name, RecordType::A);
                    q.metadata.id = i + 1;
                    s.handle(&q.to_vec().unwrap(), ip, udp).await.unwrap()
                });
            }
            let (mut ok, mut tc) = (0, 0);
            while let Some(answer) = tasks.join_next().await {
                let answer = answer.unwrap();
                ok += usize::from(answer_a(&answer).is_some());
                tc += usize::from(truncated(&answer));
            }
            assert_eq!((ok, tc), expect, "udp {udp}: one leader and one follower fit a cap of 2");
        }
        assert_eq!(requests.load(std::sync::atomic::Ordering::SeqCst), 2, "one upstream query per name");
    }

    /// Stale and prefetch refreshes are upstream work for the host whose hit
    /// started them. Over its cap the host gets the cached copy at once and no
    /// refresh starts, so its expired entries cannot fill the upstream pool;
    /// another host's stale hit still refreshes.
    #[tokio::test]
    async fn stale_and_prefetch_refreshes_count_against_the_clients_upstream_cap() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        for wait_ms in [0u64, 1000] {
            let requests = Arc::new(AtomicUsize::new(0));
            let (addr, peer) = serve_udp(true, Duration::from_millis(400), requests.clone()).await;
            let s = server(Config {
                upstreams: vec![],
                fallback: vec![addr],
                upstream_inflight_per_client: 1,
                serve_stale_client_timeout_ms: wait_ms,
                upstream_timeout_seconds: 3,
                ..Config::default()
            });
            let (a, b): (IpAddr, IpAddr) = ("10.0.0.50".parse().unwrap(), "10.0.0.51".parse().unwrap());
            let held = query("held-stale.test", RecordType::A);
            seed_stale(&s, &held, &key_for(&held));
            let holder = {
                let (s, raw) = (s.clone(), held.to_vec().unwrap());
                tokio::spawn(async move { s.handle(&raw, a, true).await })
            };
            wait_until(|| requests.load(SeqCst) == 1).await;

            let over = query("over-stale.test", RecordType::A);
            seed_stale(&s, &over, &key_for(&over));
            let started = Instant::now();
            let answer = Message::from_vec(&s.handle(&over.to_vec().unwrap(), a, true).await.unwrap()).unwrap();
            assert_eq!(answer.answers[0].ttl, 30, "wait {wait_ms}: over the cap the stale copy answers");
            assert!(started.elapsed() < Duration::from_millis(300), "wait {wait_ms}: without waiting");

            let near = query("over-prefetch.test", RecordType::A);
            let key = key_for(&near);
            let mut stored = reply(&near, ResponseCode::NoError);
            stored.add_answer(Record::from_rdata(near.queries[0].name().clone(), 100, RData::A(A::new(192, 0, 2, 1))));
            assert!(s.cache().insert(&key, &stored.to_vec().unwrap(), &stored, 0));
            s.cache().backdate(&key, 96);
            let answer = Message::from_vec(&s.handle(&near.to_vec().unwrap(), a, true).await.unwrap()).unwrap();
            assert_eq!(answer.answers[0].ttl, 4, "the near-expiry hit is answered");
            sleep(Duration::from_millis(100)).await;
            assert_eq!(requests.load(SeqCst), 1, "wait {wait_ms}: no refresh or prefetch over the cap");

            s.handle(&over.to_vec().unwrap(), b, true).await.unwrap();
            wait_until(|| requests.load(SeqCst) == 2).await;
            holder.await.unwrap();
            peer.abort();
        }
    }

    /// A key whose waiter list is full does not fail the next caller: it
    /// resolves on its own, under its host's cap and the pool's bound.
    #[tokio::test]
    async fn a_full_waiter_list_resolves_on_its_own_instead_of_servfail() {
        let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (addr, peer) = serve_udp(true, Duration::ZERO, requests.clone()).await;
        let s = server(Config { upstreams: vec![], fallback: vec![addr], ..Config::default() });
        let q = query("crowded.test", RecordType::A);
        let key = key_for(&q);
        let inflight::Role::Leader(guard) = s.inflight().join(&key) else { panic!("leader") };
        let followers: Vec<_> = (0..inflight::MAX_WAITERS).map(|_| s.inflight().join(&key)).collect();
        let answer = s.handle(&q.to_vec().unwrap(), "10.0.0.70".parse().unwrap(), false).await.unwrap();
        assert_eq!(answer_a(&answer), Some("192.0.2.1".parse().unwrap()), "answered, not SERVFAIL");
        assert_eq!(requests.load(std::sync::atomic::Ordering::SeqCst), 1);
        drop((guard, followers));
        peer.abort();
    }

    /// Sources outside `allowed_clients` share one rate-limit bucket: they
    /// cannot fill the table or spend an allowed client's tokens, and their
    /// REFUSED replies are limited as a whole. An allowed client keeps its own.
    #[tokio::test]
    async fn disallowed_sources_share_one_rate_limit_bucket() {
        let s = server(Config { rate_limit_qps: 1, rate_limit_burst: 1, ..Config::default() });
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let permits = Arc::new(Semaphore::new(8));
        let mut tasks = JoinSet::new();
        let mut buffers = UdpReplyBuffers::new(1232);
        let raw = query("localhost", RecordType::A).to_vec().unwrap();
        for peer in ["203.0.113.5:5353", "203.0.113.6:5353", "203.0.113.7:5353", "10.0.0.80:5353"] {
            buffers.handle(&s, &socket, &permits, 8, &mut tasks, &raw, peer.parse().unwrap(), None);
        }
        assert_eq!(s.runtime().rate.dropped(), 2, "three disallowed sources share one bucket of 1");
        buffers.handle(&s, &socket, &permits, 8, &mut tasks, &raw, "10.0.0.80:5353".parse().unwrap(), None);
        assert_eq!(s.runtime().rate.dropped(), 3, "the allowed client has its own bucket of 1");
        tasks.shutdown().await;
    }

    /// The TC replies for a client over its cap are response
    /// limited over UDP (a burst, then a trickle); TCP, whose source address is
    /// proven, gets its SERVFAIL.
    #[tokio::test]
    async fn tc_replies_for_a_capped_client_are_response_limited_over_udp() {
        let (addr, _peer) = serve_udp(true, Duration::from_millis(500), Arc::new(Default::default())).await;
        let s = server(Config {
            upstreams: vec![],
            fallback: vec![addr],
            upstream_inflight_per_client: 1,
            upstream_timeout_seconds: 3,
            ..Config::default()
        });
        let ip: IpAddr = "10.0.0.30".parse().unwrap();
        let mut tasks = JoinSet::new();
        for i in 0..100u16 {
            let s = s.clone();
            tasks.spawn(async move {
                let mut q = query(&format!("burst{i}.test"), RecordType::A);
                q.metadata.id = i + 1;
                // The first holds the one slot; the others are over the cap.
                let tcp = i % 2 == 1 && i > 90;
                (tcp, s.handle(&q.to_vec().unwrap(), ip, !tcp).await)
            });
        }
        let (mut tc, mut servfail, mut silent) = (0, 0, 0);
        while let Some(done) = tasks.join_next().await {
            match done.unwrap() {
                (false, Some(answer)) if truncated(&answer) => tc += 1,
                (true, Some(answer)) if code(&answer) == ResponseCode::ServFail => servfail += 1,
                (_, Some(_)) => {}
                (_, None) => silent += 1,
            }
        }
        // 16 immediate TC replies over UDP at most (plus the few the clock
        // refills) and the surplus is dropped. The TCP callers (5) share the
        // host's one slot, which a UDP query holds: five SERVFAILs.
        assert!(silent >= 50, "most of the surplus UDP replies are dropped: {silent}");
        assert!((16..=40).contains(&tc), "the burst got TC: {tc}");
        assert_eq!(servfail, 5, "TCP over its cap gets SERVFAIL");
    }

    /// One host has one upstream cap across UDP and TCP: misses held over UDP
    /// leave it no extra slots over TCP, so its TC=1 retries cannot double its
    /// share of `upstream_inflight_max`. Another host is still served.
    #[tokio::test]
    async fn one_host_has_one_upstream_cap_across_udp_and_tcp() {
        let (addr, _peer) = serve_udp(true, Duration::from_millis(400), Arc::new(Default::default())).await;
        let s = server(Config {
            upstreams: vec![],
            fallback: vec![addr],
            upstream_inflight_per_client: 1,
            upstream_timeout_seconds: 3,
            ..Config::default()
        });
        let host: IpAddr = "10.0.0.40".parse().unwrap();
        let holder = {
            let s = s.clone();
            tokio::spawn(async move {
                let q = query("held.test", RecordType::A);
                s.handle(&q.to_vec().unwrap(), host, true).await
            })
        };
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut q = query("more.test", RecordType::A);
        q.metadata.id = 77;
        let raw = q.to_vec().unwrap();
        assert!(truncated(&s.handle(&raw, host, true).await.unwrap()), "over the cap, UDP answers TC=1");
        let tcp = s.handle(&raw, host, false).await.unwrap();
        assert_eq!(code(&tcp), ResponseCode::ServFail, "the TCP retry counts against the same cap");
        let other = s.handle(&raw, "10.0.0.41".parse().unwrap(), false).await.unwrap();
        assert_eq!(answer_a(&other), Some("192.0.2.1".parse().unwrap()), "another host is served");
        holder.await.unwrap();
    }

    /// A UDP query from a host over its cap answers TC=1 without joining a
    /// running flight: it would not wait, so it must not use up one of the
    /// flight's follower places. Over TCP the same host still follows.
    #[tokio::test]
    async fn an_over_cap_udp_query_does_not_take_a_follower_place() {
        let (addr, _peer) = serve_udp(true, Duration::from_millis(400), Arc::new(Default::default())).await;
        let s = server(Config {
            upstreams: vec![],
            fallback: vec![addr],
            upstream_inflight_per_client: 1,
            upstream_timeout_seconds: 3,
            ..Config::default()
        });
        let host: IpAddr = "10.0.0.42".parse().unwrap();
        let holder = {
            let s = s.clone();
            tokio::spawn(
                async move { s.handle(&query("held.test", RecordType::A).to_vec().unwrap(), host, true).await },
            )
        };
        tokio::time::sleep(Duration::from_millis(100)).await;
        let q = query("popular.test", RecordType::A);
        let inflight::Role::Leader(guard) = s.inflight().join(&key_for(&q)) else { panic!("leader") };
        let raw = q.to_vec().unwrap();
        assert!(truncated(&s.handle(&raw, host, true).await.unwrap()), "over the cap, UDP answers TC=1");
        assert_eq!(s.inflight().waiters(), 0, "the UDP query took no follower place");
        let tcp = tokio::spawn({
            let s = s.clone();
            async move { s.handle(&raw, host, false).await }
        });
        wait_until(|| s.inflight().waiters() == 1).await;
        guard.complete(None);
        assert_eq!(code(&tcp.await.unwrap().unwrap()), ResponseCode::ServFail, "the TCP query followed");
        holder.await.unwrap();
    }
}
