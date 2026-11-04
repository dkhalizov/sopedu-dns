//! Configuration model. Every key is optional, and `validate` is the single
//! place that checks bounds and normalizes values before the server uses them.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use serde::Deserialize;

use crate::rules;

/// Upper bound for `udp_batch`. The batched receive path sizes its per-worker
/// slot arrays and payload buffer from it (32 x 4096 = 128 KiB).
pub const MAX_UDP_BATCH: usize = 32;

/// Upper bound for `listen` entries (each costs `udp_workers` sockets).
pub const MAX_LISTEN: usize = 16;

/// `listen` as a single address string (the original form) or an array.
fn deserialize_listen<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Vec<SocketAddr>, D::Error> {
    struct Listen;
    impl<'de> serde::de::Visitor<'de> for Listen {
        type Value = Vec<SocketAddr>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a socket address string or an array of them")
        }
        fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
            v.parse().map(|addr| vec![addr]).map_err(|_| E::custom("invalid listen address: expected ip:port"))
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut addrs = Vec::new();
            while let Some(text) = seq.next_element::<String>()? {
                addrs.push(
                    text.parse().map_err(|_| serde::de::Error::custom("invalid listen address: expected ip:port"))?,
                );
            }
            Ok(addrs)
        }
    }
    deserializer.deserialize_any(Listen)
}

/// A duration in seconds or a string with an `s`, `m` or `h` suffix.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(untagged)]
pub enum Age {
    Seconds(u64),
    Text(String),
}

impl Age {
    pub fn seconds(&self) -> Result<u64, String> {
        match self {
            Self::Seconds(n) => Ok(*n),
            Self::Text(s) => {
                let (n, factor) = match s.chars().last() {
                    Some('h') => (&s[..s.len() - 1], 3600u64),
                    Some('m') => (&s[..s.len() - 1], 60),
                    Some('s') => (&s[..s.len() - 1], 1),
                    _ => (s.as_str(), 1),
                };
                n.parse::<u64>()
                    .map_err(|e| format!("invalid duration: {e}"))?
                    .checked_mul(factor)
                    .ok_or_else(|| "duration overflow".to_string())
            }
        }
    }
}

/// How PTR questions for private reverse zones are answered.
#[derive(Deserialize, Debug, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PrivatePtr {
    #[default]
    Nxdomain,
    Forward,
}

/// How a cache miss picks among the DoH upstreams.
#[derive(Deserialize, Debug, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamStrategy {
    /// Least outstanding queries, then lowest smoothed latency; a slow answer
    /// is hedged to the next upstream after `upstream_hedge_ms`.
    #[default]
    Fastest,
    /// Config order: the next upstream is asked only when the current one
    /// fails, is benched, or has not answered at the failover point: half of
    /// `upstream_timeout_seconds`, at most 1 s and at most half the UDP
    /// discard limit. Keeps queries with one provider.
    Ordered,
}

/// Whether upstream queries always set the DNSSEC OK bit.
#[derive(Deserialize, Debug, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DnssecMode {
    #[default]
    Passthrough,
    AlwaysUpstream,
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// One address, or an array of up to [`MAX_LISTEN`]; each gets its own UDP
    /// socket set and TCP listener. A bare string in the file is a one-element
    /// list.
    #[serde(deserialize_with = "deserialize_listen")]
    pub listen: Vec<SocketAddr>,
    pub upstreams: Vec<String>,
    /// Plain DNS servers tried only after every DoH attempt failed at the
    /// transport level. Empty by default: an on-path attacker who blocks
    /// port 443 must not be able to force unauthenticated plaintext, so
    /// plaintext is an explicit opt-in.
    pub fallback: Vec<SocketAddr>,
    pub cache_size: usize,
    pub optimistic_max_age: Age,
    /// `optimistic_max_age` in seconds, computed by [`Config::validate`] so
    /// the request path never re-parses the age string.
    #[serde(skip)]
    pub max_age_secs: u64,
    pub blocklists: Vec<String>,
    pub refresh_hours: u64,
    pub user_rules: Vec<String>,
    pub no_filter_clients: Vec<IpAddr>,
    /// Block a query when a CNAME/DNAME target in the upstream answer chain is
    /// blocked (CNAME cloaking), unless the queried name is itself allowed or
    /// the client is exempt from filtering.
    pub block_cname_targets: bool,
    pub rewrites: HashMap<String, IpAddr>,
    pub cache_bytes: usize,
    pub ui_enabled: bool,
    pub ui_listen: SocketAddr,
    /// RFC 8767 §5 client response timer: how long a stale hit waits for its
    /// refresh before the stale copy answers (default 1800 ms, the RFC's
    /// recommendation). 0 answers from expired data at once, like AdGuard
    /// Home's optimistic cache; that is not RFC 8767 conformant.
    pub serve_stale_client_timeout_ms: u64,
    pub prefetch: bool,
    pub negative_ttl_min: u64,
    pub negative_ttl_max: u64,
    pub prewarm: bool,
    pub prewarm_count: usize,
    /// Keep the dashboard counters and top lists across restarts in
    /// `state_dir/stats.v1`. They are browsing data; off deletes the file.
    pub persist_stats: bool,
    pub state_dir: PathBuf,
    pub blocklist_max_bytes: u64,
    pub blocklist_max_lines: u64,
    pub blocklist_max_rules_total: u64,
    pub no_filter_macs: Vec<String>,
    /// Parsed and lowercased `no_filter_macs`, filled by [`Config::validate`].
    /// A hand-built or old config without this key stays valid.
    #[serde(skip)]
    pub no_filter_mac_addrs: Vec<[u8; 6]>,
    pub rate_limit_qps: u64,
    pub rate_limit_burst: u64,
    /// Client prefixes (CIDR) that may query. Everyone else gets REFUSED, so
    /// the default is not an open resolver. `0.0.0.0/0` and `::/0` allow all.
    pub allowed_clients: Vec<String>,
    /// Parsed `allowed_clients`, filled by [`Config::validate`].
    #[serde(skip)]
    pub allowed_client_nets: Vec<(IpAddr, u8)>,
    pub tcp_max_connections: usize,
    /// Concurrent TCP connections one client address may hold, so one host cannot exhaust the connection limit.
    pub tcp_max_connections_per_client: usize,
    pub tcp_queries_per_connection: usize,
    /// How many queries one TCP connection may resolve concurrently. Reading
    /// stops while the pipeline is full, so this is also the per-connection
    /// frame bound (RFC 7766 §6.2.1.1/§7).
    pub tcp_pipeline_max: usize,
    pub tcp_idle_timeout_seconds: u64,
    /// Spawned slow-path UDP requests allowed in flight. Fresh cache hits are
    /// answered inline in the receive loop and never take a permit.
    pub udp_inflight_max: usize,
    pub udp_max_payload: u16,
    pub udp_workers: usize,
    pub udp_rcvbuf_bytes: usize,
    pub udp_sndbuf_bytes: usize,
    /// Datagrams per `recvmmsg` on Linux; 0 keeps one `recv_from` per wake.
    pub udp_batch: usize,
    pub worker_threads: usize,
    pub query_log_capacity: usize,
    pub upstream_inflight_max: usize,
    /// Upstream work one client host may have in flight at once, so one
    /// busy or spoofing host cannot starve the others (keyed like the rate
    /// limiter, UDP and TCP counted apart); a miss over it
    /// gets TC=1 over UDP (a forged source cannot lock a victim out: the client
    /// retries over TCP) and SERVFAIL over TCP. 0 disables.
    pub upstream_inflight_per_client: usize,
    /// A UDP reply to a query older than this is not sent (a defence
    /// against DNSBomb-style amplification; Unbound's `discard-timeout`). The answer is still cached. 0 disables.
    /// A stale answer sent on the `serve_stale_client_timeout_ms` timer is
    /// never discarded: the limit is at least that timer plus 100 ms.
    pub udp_discard_timeout_ms: u64,
    pub upstream_hedge_ms: u64,
    pub upstream_strategy: UpstreamStrategy,
    pub upstream_timeout_seconds: u64,
    pub upstream_0x20: bool,
    /// Opt-in: treat plain `fallback` servers as trusted primaries, lifting the
    /// scrub of plaintext replies and the 300 s cap / no-stale rule for them.
    /// Off by default; RFC 5452 checks apply either way.
    pub trust_plain_upstreams: bool,
    /// RFC 6761 §6.2: forward `.test` names upstream instead of answering
    /// NXDOMAIN locally. Off by default.
    pub forward_test_names: bool,
    pub private_ptr: PrivatePtr,
    pub dnssec: DnssecMode,
    pub log_queries: bool,
    pub client_names: HashMap<String, String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: vec!["0.0.0.0:53".parse().unwrap()],
            upstreams: vec![
                "https://1.1.1.1/dns-query".into(),
                "https://1.0.0.1/dns-query".into(),
                "https://8.8.8.8/dns-query".into(),
            ],
            fallback: Vec::new(),
            cache_size: 10000,
            optimistic_max_age: Age::Seconds(43200),
            max_age_secs: 0,
            blocklists: Vec::new(),
            refresh_hours: 24,
            user_rules: Vec::new(),
            no_filter_clients: Vec::new(),
            block_cname_targets: true,
            rewrites: HashMap::new(),
            cache_bytes: 4_194_304,
            ui_enabled: true,
            ui_listen: "127.0.0.1:9999".parse().unwrap(),
            serve_stale_client_timeout_ms: 1800,
            prefetch: true,
            negative_ttl_min: 0,
            negative_ttl_max: 3600,
            prewarm: true,
            prewarm_count: 1000,
            persist_stats: true,
            state_dir: PathBuf::from("state"),
            blocklist_max_bytes: 268_435_456,
            blocklist_max_lines: 5_000_000,
            blocklist_max_rules_total: 5_000_000,
            no_filter_macs: Vec::new(),
            no_filter_mac_addrs: Vec::new(),
            rate_limit_qps: 0,
            rate_limit_burst: 0,
            allowed_clients: DEFAULT_ALLOWED_CLIENTS.iter().map(|net| (*net).into()).collect(),
            allowed_client_nets: DEFAULT_ALLOWED_CLIENTS.iter().filter_map(|net| parse_cidr(net)).collect(),
            tcp_max_connections: 256,
            tcp_max_connections_per_client: 32,
            tcp_queries_per_connection: 65_536,
            tcp_pipeline_max: 16,
            tcp_idle_timeout_seconds: 10,
            udp_inflight_max: 1024,
            udp_max_payload: 1232,
            udp_workers: 0,
            // A request; the kernel clamps it to its maximum (rmem_max).
            udp_rcvbuf_bytes: 1 << 20,
            udp_sndbuf_bytes: 0,
            // recvmmsg batching is Linux-only; elsewhere 0 avoids a startup warning.
            udp_batch: if cfg!(target_os = "linux") { 32 } else { 0 },
            worker_threads: 0,
            query_log_capacity: 10000,
            upstream_inflight_max: 256,
            upstream_inflight_per_client: 64,
            udp_discard_timeout_ms: 1900,
            upstream_hedge_ms: 50,
            upstream_strategy: UpstreamStrategy::Fastest,
            upstream_timeout_seconds: 5,
            upstream_0x20: true,
            trust_plain_upstreams: false,
            forward_test_names: false,
            private_ptr: PrivatePtr::Nxdomain,
            dnssec: DnssecMode::Passthrough,
            log_queries: false,
            client_names: HashMap::new(),
        }
    }
}

impl Config {
    /// Reads, parses and validates a configuration file.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let mut config: Self = toml::from_str(&text).map_err(|e| describe_toml_error(&text, &e))?;
        config.validate()?;
        Ok(config)
    }

    /// How old a query may be when its UDP reply is sent, or `None`
    /// when discarding is off. The stale timer (RFC 8767 §5) sends its answer
    /// that late on purpose, so the limit never falls below it plus 100 ms.
    pub fn udp_discard_limit(&self) -> Option<Duration> {
        (self.udp_discard_timeout_ms != 0).then(|| {
            Duration::from_millis(
                self.udp_discard_timeout_ms.max(self.serve_stale_client_timeout_ms.saturating_add(100)),
            )
        })
    }

    /// Checks bounds and normalizes rewrite keys. Every error keeps the
    /// previous configuration valid because callers only swap after success.
    pub fn validate(&mut self) -> Result<(), String> {
        if self.listen.is_empty() || self.listen.len() > MAX_LISTEN {
            return Err(format!("listen must have 1..={MAX_LISTEN} addresses"));
        }
        for (i, addr) in self.listen.iter().enumerate() {
            if self.listen[..i].contains(addr) {
                return Err(format!("duplicate listen address {addr}"));
            }
        }
        if self.refresh_hours == 0 || self.refresh_hours.checked_mul(3600).is_none() {
            return Err("refresh_hours must be at least 1 (hours between blocklist refreshes)".into());
        }
        self.max_age_secs =
            self.optimistic_max_age.seconds().map_err(|e| format!("invalid optimistic_max_age: {e}"))?;
        for url in &self.upstreams {
            let parsed = reqwest::Url::parse(url).map_err(|e| {
                format!(
                    "invalid upstream URL {}: {e} (expected a DoH URL such as https://1.1.1.1/dns-query)",
                    crate::log::redact_url(url)
                )
            })?;
            if parsed.scheme() != "https" {
                return Err(format!("DoH upstreams require https: {}", crate::log::redact_url(url)));
            }
        }
        for url in &self.blocklists {
            let ok = reqwest::Url::parse(url)
                .is_ok_and(|parsed| matches!(parsed.scheme(), "http" | "https") && parsed.host_str().is_some());
            if !ok {
                return Err(format!(
                    "invalid blocklists entry {}: expected an http:// or https:// URL",
                    crate::log::redact_url(url)
                ));
            }
        }
        if self.allowed_clients.is_empty() {
            return Err("allowed_clients is empty; use [\"0.0.0.0/0\", \"::/0\"] to allow every client".into());
        }
        self.allowed_client_nets = self
            .allowed_clients
            .iter()
            .map(|net| parse_cidr(net).ok_or_else(|| format!("invalid allowed_clients entry {net:?}: expected a CIDR")))
            .collect::<Result<_, _>>()?;
        let mut rewrites = HashMap::with_capacity(self.rewrites.len());
        for (name, ip) in &self.rewrites {
            let (prefix, name) = name.strip_prefix("*.").map_or(("", name.as_str()), |s| ("*.", s));
            let name = rules::domain(name).ok_or("invalid rewrite name: expected a domain name")?;
            if rewrites.insert(format!("{prefix}{name}"), *ip).is_some() {
                return Err("duplicate normalized rewrite".into());
            }
        }
        if self.cache_bytes == 0 {
            return Err("cache_bytes must be greater than zero".into());
        }
        // The pre-warm tracker scans k counters per untracked name; 10000
        // keeps that and the ~170 B per name (1.7 MB) small.
        if self.prewarm_count > 10_000 {
            return Err("prewarm_count must be in 0..=10000".into());
        }
        if self.negative_ttl_min > self.negative_ttl_max {
            return Err("negative_ttl_min must not exceed negative_ttl_max".into());
        }
        if self.tcp_idle_timeout_seconds == 0 {
            return Err("tcp_idle_timeout_seconds must be greater than zero".into());
        }
        for (name, value) in [
            ("tcp_max_connections", self.tcp_max_connections),
            ("tcp_max_connections_per_client", self.tcp_max_connections_per_client),
            ("tcp_queries_per_connection", self.tcp_queries_per_connection),
            ("udp_inflight_max", self.udp_inflight_max),
        ] {
            if value == 0 || value > 65_536 {
                return Err(format!("{name} must be between 1 and 65536"));
            }
        }
        // 256 is also the default connection bound. A pipeline slot can hold
        // one maximum-size query and one answer (2 x 65535 bytes), so this
        // keeps the configurable worst case per connection at 32 MiB and the
        // default total at 256 x 32 slots.
        if self.tcp_pipeline_max == 0 || self.tcp_pipeline_max > 256 {
            return Err("tcp_pipeline_max must be between 1 and 256".into());
        }
        if self.udp_max_payload < 512 {
            return Err("udp_max_payload must be at least 512".into());
        }
        // 0 disables the query log; 112 bytes per entry bounds this at 112 MB.
        if self.query_log_capacity > 1_000_000 {
            return Err("query_log_capacity must be in 0..=1000000".into());
        }
        // 0 keeps one socket; each worker binds its own SO_REUSEPORT socket.
        if self.udp_workers > 64 {
            return Err("udp_workers must be in 0..=64".into());
        }
        // 0 keeps one datagram per wake. The upper bound also bounds the
        // per-worker receive buffer set (32 x 4096 = 128 KiB).
        if self.udp_batch > MAX_UDP_BATCH {
            return Err(format!("udp_batch must be in 0..={MAX_UDP_BATCH}"));
        }
        // 0 asks the runtime builder for the platform default. The runtime is
        // built once at startup, so a reload cannot change the thread count.
        if self.worker_threads > 64 {
            return Err("worker_threads must be in 0..=64".into());
        }
        // 0 leaves the OS default. A non-zero request is applied before bind;
        // kernels may double or clamp it, so it is not a guaranteed read-back.
        for (name, value) in [("udp_rcvbuf_bytes", self.udp_rcvbuf_bytes), ("udp_sndbuf_bytes", self.udp_sndbuf_bytes)]
        {
            if value != 0 && !(4096..=67_108_864).contains(&value) {
                return Err(format!("{name} must be 0 or in 4096..=67108864"));
            }
        }
        self.validate_self_forwarding()?;
        if self.upstream_timeout_seconds == 0 || self.upstream_timeout_seconds > 60 {
            return Err("upstream_timeout_seconds must be between 1 and 60".into());
        }
        if self.upstream_inflight_max == 0 || self.upstream_inflight_max > 65_536 {
            return Err("upstream_inflight_max must be between 1 and 65536".into());
        }
        if self.upstream_inflight_per_client > 65_536 {
            return Err("upstream_inflight_per_client must be between 0 and 65536".into());
        }
        if self.udp_discard_timeout_ms > 60_000 {
            return Err("udp_discard_timeout_ms must be between 0 and 60000".into());
        }
        if self.upstream_hedge_ms > 5000 {
            return Err("upstream_hedge_ms must be at most 5000".into());
        }
        // A stale client wait is per request and holds a client slot. This is
        // the configured ceiling; the effective wait at request time is also
        // capped by the upstream deadline (`upstream_timeout_seconds`).
        if self.serve_stale_client_timeout_ms > 60_000 {
            return Err("serve_stale_client_timeout_ms must be between 0 and 60000".into());
        }
        if self.blocklist_max_bytes == 0 || self.blocklist_max_lines == 0 || self.blocklist_max_rules_total == 0 {
            return Err("blocklist maxima must be greater than zero".into());
        }
        // The same parser as the blocklists: a rule the filter would skip is a
        // typo, and loading the config anyway would silently not block it.
        // Like the other errors here, the message names the entry, not its text.
        for (index, line) in self.user_rules.iter().enumerate() {
            if let Err(reason) = rules::parse_rule(line) {
                return Err(format!("user_rules entry {}: {reason}", index + 1));
            }
        }
        let mut macs = Vec::with_capacity(self.no_filter_macs.len());
        for mac in &self.no_filter_macs {
            macs.push(crate::mac::parse_mac(mac).ok_or_else(|| {
                "invalid MAC address in no_filter_macs: expected six hex octets such as aa:bb:cc:dd:ee:ff".to_string()
            })?);
        }
        self.rewrites = rewrites;
        self.no_filter_mac_addrs = macs;
        Ok(())
    }

    /// Rejects plaintext fallbacks that are the listener itself or would be
    /// with the same local port, which would loop every query back into this
    /// process. A DoH URL whose host is a literal listen IP is suspicious but
    /// not rejected: the listener is plain DNS, so it cannot answer DoH, and
    /// the address may legitimately be another service on that host. That
    /// case is documented in docs/configuration.md.
    fn validate_self_forwarding(&self) -> Result<(), String> {
        for fallback in &self.fallback {
            for &listen in &self.listen {
                if *fallback == listen {
                    return Err(format!("fallback {fallback} is the listen address; this forwards to itself"));
                }
                let local_pair = is_local_address(listen.ip()) && is_local_address(fallback.ip());
                if local_pair && fallback.port() == listen.port() {
                    return Err(format!(
                        "fallback {fallback} uses the listen port while listening on {listen}; this forwards to itself"
                    ));
                }
            }
        }
        Ok(())
    }
}

/// TOML's own `Display` quotes the offending source line, which for an upstream
/// URL is exactly where a token lives. Keep the message and the line number.
/// Serde errors also quote the offending value inside the message, either with
/// double quotes (`invalid type: string "https://user:pass@..."`) or with
/// backticks (for `unknown variant` and `unknown field`), so those values are
/// stripped before the message is shown.
fn describe_toml_error(text: &str, error: &toml::de::Error) -> String {
    let message = redact_toml_values(error.message());
    let Some(span) = error.span() else {
        return format!("invalid config: {message}");
    };
    let line = text.as_bytes()[..span.start.min(text.len())].iter().filter(|&&byte| byte == b'\n').count() + 1;
    format!("invalid config: {message} (line {line})")
}

/// Replaces every quoted offending value with `<redacted>`, in both quote
/// styles serde uses: double quotes for values and backticks for values, keys
/// and TOML tokens. Everything after an unquoted `expected` is kept, because
/// serde writes the expected type and variant list there in backticks too; a
/// value cannot fake that keyword because its content is never scanned.
/// Backslash escapes inside a double-quoted value are skipped so an embedded
/// quote cannot end the segment early and leak the rest. The one exception is
/// the key in `unknown field`: it is a name the user typed, not a value, so a
/// plain identifier-like name is kept to make the typo findable; any other
/// name is redacted like a value.
fn redact_toml_values(message: &str) -> String {
    if let Some((name, tail)) = message.strip_prefix("unknown field `").and_then(|rest| rest.split_once('`')) {
        let plain = !name.is_empty()
            && name.len() <= 64
            && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'));
        if plain && tail.starts_with(", ") {
            return format!("unknown field `{name}`{}", redact_toml_values(tail));
        }
    }
    let mut out = String::with_capacity(message.len());
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut keep_expected = false;
    for character in message.chars() {
        match quote {
            None => {
                if character == '"' || (character == '`' && !keep_expected) {
                    quote = Some(character);
                    out.push(character);
                    out.push_str("<redacted>");
                } else {
                    out.push(character);
                    if !keep_expected && ends_with_the_word_expected(&out) {
                        keep_expected = true;
                    }
                }
            }
            Some(open) => {
                if escaped {
                    escaped = false;
                } else if character == '\\' && open == '"' {
                    escaped = true;
                } else if character == open {
                    quote = None;
                    out.push(open);
                }
            }
        }
    }
    out
}

/// `out` ends with the whole word `expected`, not just the tail of one such as
/// `unexpected`.
fn ends_with_the_word_expected(out: &str) -> bool {
    out.strip_suffix("expected").is_some_and(|prefix| {
        !prefix.as_bytes().last().is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
    })
}

/// Loopback, RFC 1918, link-local, and ULA (RFC 4193). The RFC 6598 shared
/// space `100.64.0.0/10` is left out: behind a carrier-grade NAT it holds
/// other subscribers' addresses, so admitting it is opt-in (for example for a
/// Tailscale tailnet, which numbers its devices from it).
pub const DEFAULT_ALLOWED_CLIENTS: &[&str] = &[
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
];

/// The global and ULA IPv6 on-link prefixes of this host's up interfaces. They
/// are never admitted automatically (on a VPS the subnet is shared with other
/// customers); they only drive the [`note_refused`] hint.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn host_client_prefixes() -> Vec<(IpAddr, u8)> {
    use nix::{ifaddrs::getifaddrs, net::if_::InterfaceFlags};
    let Ok(interfaces) = getifaddrs() else { return Vec::new() };
    let mut out = Vec::new();
    for interface in interfaces.filter(|i| i.flags.contains(InterfaceFlags::IFF_UP)) {
        let (Some(addr), Some(mask)) = (interface.address, interface.netmask) else { continue };
        let (Some(addr), Some(mask)) = (addr.as_sockaddr_in6(), mask.as_sockaddr_in6()) else { continue };
        if let Some(net) = onlink_prefix(addr.ip(), mask.ip()) {
            if !out.contains(&net) {
                out.push(net);
            }
        }
    }
    out
}

/// No interface listing on other platforms: only the default prefixes apply.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn host_client_prefixes() -> Vec<(IpAddr, u8)> {
    Vec::new()
}

/// The network of a global-unicast (2000::/3) or ULA (fc00::/7) interface
/// address, or `None` for anything else, a non-contiguous mask, or a prefix
/// shorter than /64 (a misconfigured wide mask must not open the resolver).
fn onlink_prefix(addr: Ipv6Addr, mask: Ipv6Addr) -> Option<(IpAddr, u8)> {
    let mask = mask.to_bits();
    let len = mask.leading_ones();
    if mask.count_ones() != len || len < 64 {
        return None;
    }
    let bits = addr.to_bits();
    if bits >> 125 != 0b001 && bits >> 121 != 0b111_1110 {
        return None;
    }
    Some((IpAddr::V6(Ipv6Addr::from_bits(bits & mask)), len as u8))
}

/// How long the host's on-link prefixes are reused before they are listed again.
const ONLINK_REFRESH: Duration = Duration::from_secs(60);

/// The host's on-link prefixes (listed lazily, at most once per
/// [`ONLINK_REFRESH`]) and the prefixes already reported.
#[derive(Default)]
struct OnlinkHints {
    listed_at: Option<Instant>,
    prefixes: Vec<(IpAddr, u8)>,
    warned: Vec<(IpAddr, u8)>,
}

impl OnlinkHints {
    /// The on-link prefix of a refused `ip` that has not been reported yet.
    /// `list` runs only when the cached prefixes are older than a minute, and
    /// only for sources in 2000::/3 or fc00::/7, so a flood of ordinary
    /// refusals neither lists interfaces nor grows anything.
    fn refused(&mut self, ip: IpAddr, now: Instant, list: impl FnOnce() -> Vec<(IpAddr, u8)>) -> Option<(IpAddr, u8)> {
        let IpAddr::V6(v6) = ip.to_canonical() else { return None };
        let bits = v6.to_bits();
        if bits >> 125 != 0b001 && bits >> 121 != 0b111_1110 {
            return None;
        }
        if self.listed_at.is_none_or(|at| now.duration_since(at) >= ONLINK_REFRESH) {
            self.prefixes = list();
            self.listed_at = Some(now);
            let current = self.prefixes.clone();
            self.warned.retain(|net| current.contains(net));
        }
        let net = *self
            .prefixes
            .iter()
            .find(|&&(net, len)| matches!(net, IpAddr::V6(net) if prefix_eq(net.to_bits(), bits, len)))?;
        if self.warned.contains(&net) {
            return None;
        }
        self.warned.push(net);
        Some(net)
    }
}

/// Called when `allowed_clients` refused `ip`. When the source sits inside one
/// of this host's own global or ULA on-link prefixes, logs one warning per
/// prefix: that is almost always a LAN whose IPv6 prefix the operator has not
/// added to `allowed_clients`.
pub fn note_refused(ip: IpAddr) {
    static HINTS: std::sync::Mutex<Option<OnlinkHints>> = std::sync::Mutex::new(None);
    let Ok(mut hints) = HINTS.lock() else { return };
    let hints = hints.get_or_insert_with(OnlinkHints::default);
    if let Some((net, len)) = hints.refused(ip, Instant::now(), host_client_prefixes) {
        crate::log::log(
            "warn",
            "client_refused_onlink",
            &[("prefix", format!("{net}/{len}")), ("hint", "add_to_allowed_clients".into())],
        );
    }
}

fn parse_cidr(text: &str) -> Option<(IpAddr, u8)> {
    let (ip, len) = text.split_once('/')?;
    let ip: IpAddr = ip.parse().ok()?;
    let len: u8 = len.parse().ok()?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    (len <= max).then_some((ip, len))
}

impl Config {
    /// Whether `ip` falls in `allowed_clients`. An IPv4-mapped IPv6 peer is
    /// matched as IPv4.
    pub fn client_allowed(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.allowed_client_nets.iter().any(|&(net, len)| match (ip, net) {
            (IpAddr::V4(a), IpAddr::V4(n)) => {
                prefix_eq(u128::from(a.to_bits()) << 96, u128::from(n.to_bits()) << 96, len)
            }
            (IpAddr::V6(a), IpAddr::V6(n)) => prefix_eq(a.to_bits(), n.to_bits(), len),
            _ => false,
        })
    }
}

/// A source address no real client has. Queries from it are dropped
/// without a reply even when `allowed_clients` would allow it: unspecified,
/// multicast, or the limited broadcast address. A reply to a broadcast source
/// would reach every host on the link.
pub fn impossible_source(ip: IpAddr) -> bool {
    let ip = ip.to_canonical();
    ip.is_unspecified() || ip.is_multicast() || ip == IpAddr::V4(std::net::Ipv4Addr::BROADCAST)
}

fn prefix_eq(a: u128, b: u128, len: u8) -> bool {
    len == 0 || (a ^ b) >> (128 - u32::from(len)) == 0
}

/// Loopback or unspecified. Either can reach the same process when it is
/// listening on the same local port.
fn is_local_address(ip: IpAddr) -> bool {
    ip.is_loopback() || ip.is_unspecified()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowed_clients_default_is_private_only() {
        let mut c = Config::default();
        c.validate().unwrap();
        for ip in
            ["127.0.0.1", "10.1.2.3", "172.31.0.1", "192.168.1.10", "::1", "fd00::1", "fe80::1", "::ffff:192.168.1.1"]
        {
            assert!(c.client_allowed(ip.parse().unwrap()), "{ip}");
        }
        // RFC 6598 shared space holds other CGN subscribers unless opted in.
        for ip in ["8.8.8.8", "172.32.0.1", "100.64.0.1", "100.127.255.254", "2001:db8::1", "::ffff:8.8.8.8"] {
            assert!(!c.client_allowed(ip.parse().unwrap()), "{ip}");
        }
        c.allowed_clients = vec!["0.0.0.0/0".into(), "::/0".into()];
        c.validate().unwrap();
        assert!(c.client_allowed("8.8.8.8".parse().unwrap()) && c.client_allowed("2001:db8::1".parse().unwrap()));
        for bad in [vec![], vec!["10.0.0.0/33".to_string()], vec!["nope".to_string()]] {
            c.allowed_clients = bad;
            assert!(c.validate().is_err());
        }
    }

    #[test]
    fn onlink_prefix_keeps_only_global_and_ula_networks() {
        let v6 = |text: &str| text.parse::<Ipv6Addr>().unwrap();
        let mask64 = v6("ffff:ffff:ffff:ffff::");
        let net = |text: &str, len| Some((IpAddr::V6(v6(text)), len));
        assert_eq!(onlink_prefix(v6("2001:db8:1:2:abcd::5"), mask64), net("2001:db8:1:2::", 64));
        assert_eq!(onlink_prefix(v6("fd12:3456:789a:1::9"), mask64), net("fd12:3456:789a:1::", 64));
        assert_eq!(onlink_prefix(v6("2001:db8::1"), Ipv6Addr::from_bits(u128::MAX)), net("2001:db8::1", 128));
        for (addr, mask) in [
            ("fe80::1", mask64),
            ("::1", Ipv6Addr::from_bits(u128::MAX)),
            ("ff02::1", mask64),
            ("2001:db8::1", v6("ffff:ffff::")),
            ("2001:db8::1", v6("ffff:ffff:ffff:ffff:0:ffff::")),
            ("2001:db8::1", v6("::")),
        ] {
            assert_eq!(onlink_prefix(v6(addr), mask), None, "{addr}");
        }
    }

    #[test]
    fn a_global_source_is_refused_by_default_and_admitted_by_an_explicit_entry() {
        let global: IpAddr = "2001:db8:1:2:aaaa::7".parse().unwrap();
        let mut c = Config::default();
        c.validate().unwrap();
        assert!(!c.client_allowed(global), "the default never admits a global address, on-link or not");
        c.allowed_clients.push("2001:db8:1:2::/64".into());
        c.validate().unwrap();
        assert!(c.client_allowed(global));
        assert!(!c.client_allowed("2001:db8:1:3::7".parse().unwrap()), "only the listed /64");
    }

    #[test]
    fn a_refused_on_link_source_is_reported_once_per_prefix_and_the_list_is_cached() {
        let mut hints = OnlinkHints::default();
        let net: (IpAddr, u8) = ("2001:db8:1:2::".parse().unwrap(), 64);
        let mut listings = 0;
        let mut now = Instant::now();
        let mut refuse = |hints: &mut OnlinkHints, ip: &str, now: Instant| {
            hints.refused(ip.parse().unwrap(), now, || {
                listings += 1;
                vec![net]
            })
        };
        assert_eq!(refuse(&mut hints, "2001:db8:1:2::9", now), Some(net));
        assert_eq!(refuse(&mut hints, "2001:db8:1:2::a", now), None, "one warning per prefix");
        assert_eq!(refuse(&mut hints, "2001:db8:9::1", now), None, "off-link sources are not hinted");
        assert_eq!(refuse(&mut hints, "203.0.113.5", now), None, "IPv4 and non-global sources never list interfaces");
        assert_eq!(refuse(&mut hints, "fe80::1", now), None);
        now += Duration::from_secs(61);
        assert_eq!(refuse(&mut hints, "2001:db8:1:2::b", now), None, "still reported once after a refresh");
        drop(refuse);
        assert_eq!(listings, 2, "listed on first use and again only after a minute");
    }

    #[test]
    fn defaults_match_the_documented_values() {
        let c = Config::default();
        assert_eq!(c.listen, vec!["0.0.0.0:53".parse().unwrap()]);
        assert!(c.fallback.is_empty(), "plaintext fallback is an explicit opt-in");
        assert_eq!(c.cache_size, 10000);
        assert_eq!(c.optimistic_max_age.seconds().unwrap(), 43200);
        assert_eq!(c.refresh_hours, 24);
        assert_eq!(c.cache_bytes, 4_194_304);
        assert!(c.ui_enabled);
        assert_eq!(c.ui_listen.to_string(), "127.0.0.1:9999");
        assert_eq!(c.serve_stale_client_timeout_ms, 1800, "RFC 8767 §5 client response timer");
        assert!(c.prefetch);
        assert!(c.block_cname_targets);
        assert_eq!(c.negative_ttl_min, 0);
        assert_eq!(c.negative_ttl_max, 3600);
        assert!(c.prewarm);
        assert_eq!(c.prewarm_count, 1000);
        assert!(c.persist_stats);
        assert_eq!(c.state_dir, PathBuf::from("state"));
        assert_eq!(c.blocklist_max_bytes, 268_435_456);
        assert_eq!(c.blocklist_max_lines, 5_000_000);
        assert_eq!(c.blocklist_max_rules_total, 5_000_000);
        assert!(c.no_filter_macs.is_empty());
        assert_eq!(c.rate_limit_qps, 0);
        assert_eq!(c.rate_limit_burst, 0);
        assert_eq!(c.tcp_max_connections, 256);
        assert_eq!(c.tcp_max_connections_per_client, 32);
        assert_eq!(c.tcp_queries_per_connection, 65_536);
        assert_eq!(c.tcp_pipeline_max, 16);
        assert_eq!(c.tcp_idle_timeout_seconds, 10);
        assert_eq!(c.udp_inflight_max, 1024);
        assert_eq!(c.udp_max_payload, 1232);
        assert_eq!(c.udp_workers, 0);
        assert_eq!(c.udp_rcvbuf_bytes, 1 << 20);
        assert_eq!(c.udp_sndbuf_bytes, 0);
        assert_eq!(c.udp_batch, if cfg!(target_os = "linux") { 32 } else { 0 });
        assert_eq!(c.worker_threads, 0);
        assert_eq!(c.query_log_capacity, 10000);
        assert_eq!(c.upstream_inflight_max, 256);
        assert_eq!(c.upstream_hedge_ms, 50);
        assert_eq!(c.upstream_strategy, UpstreamStrategy::Fastest);
        assert_eq!(c.upstream_timeout_seconds, 5);
        assert!(c.upstream_0x20);
        assert!(!c.trust_plain_upstreams);
        assert!(!c.forward_test_names);
        assert_eq!(c.private_ptr, PrivatePtr::Nxdomain);
        assert_eq!(c.dnssec, DnssecMode::Passthrough);
        assert!(!c.log_queries);
        assert!(c.client_names.is_empty());
    }

    #[test]
    fn duration_parsing() {
        assert_eq!(Age::Seconds(5).seconds().unwrap(), 5);
        assert_eq!(Age::Text("12h".into()).seconds().unwrap(), 43200);
        assert_eq!(Age::Text("30m".into()).seconds().unwrap(), 1800);
        assert_eq!(Age::Text("60s".into()).seconds().unwrap(), 60);
        assert_eq!(Age::Text("43200".into()).seconds().unwrap(), 43200);
        assert!(Age::Text("12x".into()).seconds().is_err());
        assert!(Age::Text(String::new()).seconds().is_err());
        assert!(Age::Text(format!("{}h", u64::MAX)).seconds().is_err());
    }

    #[test]
    fn unknown_fields_are_rejected() {
        assert!(toml::from_str::<Config>("bogus = 1").is_err());
    }

    #[test]
    fn old_and_current_samples_parse() {
        let old = r#"
listen = "0.0.0.0:53"
upstreams = ["https://1.1.1.1/dns-query"]
fallback = ["1.1.1.1:53"]
cache_size = 10000
optimistic_max_age = "12h"
blocklists = []
refresh_hours = 24
user_rules = ["@@||example.com^$important"]
no_filter_clients = ["192.0.2.226"]

[rewrites]
"*.home.arpa" = "192.0.2.60"
"#;
        let mut old: Config = toml::from_str(old).unwrap();
        old.validate().unwrap();
        assert_eq!(old.cache_bytes, 4_194_304);
        assert!(old.block_cname_targets, "an old config gets CNAME-target blocking");
        let off: Config = toml::from_str("block_cname_targets = false").unwrap();
        assert!(!off.block_cname_targets);

        // The documented example must parse and validate, including its
        // commented-out [rewrites] and [client_names] tables.
        let text = include_str!("../config.example.toml").replace("\n# [", "\n[").replace("\n# \"", "\n\"");
        let mut example: Config = toml::from_str(&text).unwrap();
        example.validate().unwrap();
        assert_eq!(example.cache_size, Config::default().cache_size);
        assert!(example.fallback.is_empty(), "the example keeps plaintext off");
        assert_eq!(example.rewrites.len(), 1);
        assert_eq!(example.state_dir, PathBuf::from("state"));
    }

    #[test]
    fn user_rules_the_list_parser_cannot_read_are_rejected_with_their_position() {
        let mut c = Config {
            user_rules: vec![
                "".into(),
                "! comment".into(),
                "# comment".into(),
                "||ads.test^".into(),
                "||ads.test^|".into(),
                "|exact.test^".into(),
                "@@||ok.test^".into(),
                "@@||ok.test^$important".into(),
                "||bad.test^$important".into(),
                "0.0.0.0 hosts.test".into(),
                "127.0.0.1 hosts2.test".into(),
                "plain.test".into(),
            ],
            ..Config::default()
        };
        c.validate().unwrap();
        for (bad, reason) in [
            ("||typo.example", "must end with ^"),
            ("||evil.example^$dnstype=A", "unsupported modifier"),
            ("@@plain.test", "unsupported rule syntax"),
        ] {
            c.user_rules = vec!["||fine.test^".into(), bad.into()];
            let err = c.validate().unwrap_err();
            assert!(err.contains("user_rules entry 2") && err.contains(reason), "{bad}: {err}");
        }
    }

    #[test]
    fn enum_values_are_enforced() {
        let cfg: Config = toml::from_str("private_ptr = \"forward\"\ndnssec = \"always_upstream\"").unwrap();
        assert_eq!(cfg.private_ptr, PrivatePtr::Forward);
        assert_eq!(cfg.dnssec, DnssecMode::AlwaysUpstream);
        assert!(toml::from_str::<Config>("private_ptr = \"sinkhole\"").is_err());
        assert!(toml::from_str::<Config>("dnssec = \"validate\"").is_err());
    }

    #[test]
    fn blocklist_urls_must_be_http_or_https() {
        for bad in ["ftp://example.com/x", "/etc/hosts", "example.com/list.txt"] {
            let mut c = Config { blocklists: vec![bad.into()], ..Config::default() };
            assert!(c.validate().unwrap_err().contains("blocklists"), "{bad}");
        }
        let mut c = Config { blocklists: vec!["https://example.com/list.txt".into()], ..Config::default() };
        c.validate().unwrap();
    }

    #[test]
    fn bad_https_refresh_and_mac_are_rejected() {
        let mut c = Config { upstreams: vec!["http://1.1.1.1/dns-query".into()], ..Config::default() };
        assert!(c.validate().is_err());
        let mut c = Config { upstreams: vec!["not a url".into()], ..Config::default() };
        assert!(c.validate().is_err());

        for hours in [0, u64::MAX] {
            let mut c = Config { refresh_hours: hours, ..Config::default() };
            assert!(c.validate().is_err());
        }

        let mut c = Config { no_filter_macs: vec!["aa:bb:cc:dd:ee".into()], ..Config::default() };
        assert!(c.validate().is_err());
        let mut c = Config { no_filter_macs: vec!["zz:bb:cc:dd:ee:ff".into()], ..Config::default() };
        assert!(c.validate().is_err());
        let mut c = Config { no_filter_macs: vec!["aa:bb-cc-dd-ee-ff".into()], ..Config::default() };
        assert!(c.validate().is_err(), "mixed separators are rejected");
        let mut c = Config {
            no_filter_macs: vec!["AA-bb-cc-dd-ee-ff".into(), "01:23:45:67:89:ab".into()],
            ..Config::default()
        };
        c.validate().unwrap();
        assert_eq!(
            c.no_filter_mac_addrs,
            vec![[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], [0x01, 0x23, 0x45, 0x67, 0x89, 0xab]]
        );
    }

    #[test]
    fn configuration_errors_never_echo_url_secrets() {
        for url in ["http://user:pass@example.com/dns-query?token=supersecret", "not a url?token=supersecret"] {
            let mut c = Config { upstreams: vec![url.into()], ..Config::default() };
            let error = c.validate().unwrap_err();
            assert!(!error.contains("supersecret"), "{error}");
            assert!(!error.contains("user:pass"), "{error}");
            assert!(!error.contains("token="), "{error}");
        }
        let mut c = Config {
            upstreams: vec!["http://user:pass@example.com/dns-query?token=supersecret".into()],
            ..Config::default()
        };
        assert_eq!(c.validate().unwrap_err(), "DoH upstreams require https: http://example.com");
    }

    fn assert_validation_error_is_clean(error: &str, kept: &str) {
        for secret in ["supersecret", "user:pass", "example.com", "dns-query"] {
            assert!(!error.contains(secret), "{secret} leaked: {error}");
        }
        assert!(error.contains(kept), "{kept} is named: {error}");
    }

    #[test]
    fn an_invalid_optimistic_max_age_never_echoes_a_url() {
        let url = "https://user:pass@example.com/dns-query?token=supersecret";
        let mut c = Config { optimistic_max_age: Age::Text(url.into()), ..Config::default() };
        assert_validation_error_is_clean(&c.validate().unwrap_err(), "optimistic_max_age");
    }

    #[test]
    fn an_invalid_no_filter_macs_entry_never_echoes_a_url() {
        let url = "https://user:pass@example.com/dns-query?token=supersecret";
        let mut c = Config { no_filter_macs: vec![url.into()], ..Config::default() };
        assert_validation_error_is_clean(&c.validate().unwrap_err(), "no_filter_macs");
    }

    #[test]
    fn an_invalid_rewrite_name_never_echoes_a_url() {
        let url = "https://user:pass@example.com/dns-query?token=supersecret";
        let mut c = Config { rewrites: [(url.to_string(), "192.0.2.1".parse().unwrap())].into(), ..Config::default() };
        assert_validation_error_is_clean(&c.validate().unwrap_err(), "rewrite name");
    }

    #[test]
    fn toml_errors_keep_the_line_but_not_the_source_text() {
        let text = "upstreams = [\"https://user:pass@example.com/dns-query?token=supersecret\"";
        let error = toml::from_str::<Config>(text).err().unwrap();
        let described = describe_toml_error(text, &error);
        assert!(!described.contains("supersecret"), "{described}");
        assert!(!described.contains("user:pass"), "{described}");
        assert!(described.contains("(line 1)"), "{described}");
    }

    #[test]
    fn toml_type_errors_strip_the_offending_value() {
        // A plausible operator mistake: a string instead of an array. Serde's
        // message quotes the value verbatim, leaking userinfo and the token.
        let text =
            "listen = \"127.0.0.1:5353\"\nupstreams = \"https://user:pass@example.com/dns-query?token=supersecret\"\n";
        let error = toml::from_str::<Config>(text).err().unwrap();
        let described = describe_toml_error(text, &error);
        assert!(!described.contains("supersecret"), "{described}");
        assert!(!described.contains("user:pass"), "{described}");
        assert!(!described.contains("example.com"), "{described}");
        assert!(described.contains("expected a sequence"), "the expectation is kept: {described}");
        assert!(described.contains("(line 2)"), "the line number is kept: {described}");
    }

    #[test]
    fn toml_enum_and_field_errors_strip_the_offending_value() {
        // Serde quotes these with backticks instead of double quotes.
        let secret = "https://user:pass@example.com/dns-query?token=supersecret";
        for (text, kept) in [
            (format!("dnssec = \"{secret}\"\n"), vec!["unknown variant", "`passthrough`", "`always_upstream`"]),
            (format!("private_ptr = \"{secret}\"\n"), vec!["unknown variant", "`nxdomain`", "`forward`"]),
            (format!("\"{secret}\" = true\n"), vec!["unknown field", "expected one of", "`listen`"]),
        ] {
            let error = toml::from_str::<Config>(&text).err().unwrap();
            let described = describe_toml_error(&text, &error);
            for leaked in ["supersecret", "user:pass", "example.com", "dns-query"] {
                assert!(!described.contains(leaked), "{leaked} leaked: {described}");
            }
            for kept in kept {
                assert!(described.contains(kept), "{kept} is kept: {described}");
            }
            assert!(described.contains("(line 1)"), "the line number is kept: {described}");
        }
    }

    #[test]
    fn unknown_key_name_is_shown_but_not_its_value() {
        let text = "upstream = \"https://user:pass@example.com/dns-query?token=supersecret\"\n";
        let error = toml::from_str::<Config>(text).err().unwrap();
        let described = describe_toml_error(text, &error);
        assert!(described.contains("unknown field `upstream`"), "{described}");
        assert!(!described.contains("supersecret") && !described.contains("user:pass"), "{described}");
    }

    #[test]
    fn toml_value_redaction_covers_both_quote_styles() {
        assert_eq!(
            redact_toml_values(
                "unknown variant `https://user:pass@example.com/x`, expected `passthrough` or `always_upstream`"
            ),
            "unknown variant `<redacted>`, expected `passthrough` or `always_upstream`"
        );
        assert_eq!(
            redact_toml_values(
                "unknown field `https://x/expected?token=secret`, expected one of `listen`, `upstreams`"
            ),
            "unknown field `<redacted>`, expected one of `listen`, `upstreams`"
        );
        // A plain key name is kept; a value-like one (above) is not.
        assert_eq!(
            redact_toml_values("unknown field `listenn`, expected one of `listen`, `upstreams`"),
            "unknown field `listenn`, expected one of `listen`, `upstreams`"
        );
        // A backslash-escaped quote inside the value cannot end it early.
        assert_eq!(
            redact_toml_values(r#"invalid type: string "a\"b", expected a sequence"#),
            r#"invalid type: string "<redacted>", expected a sequence"#
        );
    }

    #[test]
    fn duplicate_normalized_rewrite_is_rejected() {
        let mut c: Config = toml::from_str(
            r#"
[rewrites]
"X.local" = "192.0.2.1"
"x.local." = "192.0.2.2"
"#,
        )
        .unwrap();
        assert!(c.validate().is_err());
    }

    #[test]
    fn rewrites_are_normalized() {
        let mut c: Config = toml::from_str(
            r#"
[rewrites]
"*.Example.COM." = "192.0.2.1"
"Host.Local" = "192.0.2.2"
"#,
        )
        .unwrap();
        c.validate().unwrap();
        assert_eq!(c.rewrites["*.example.com"], "192.0.2.1".parse::<IpAddr>().unwrap());
        assert_eq!(c.rewrites["host.local"], "192.0.2.2".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn failed_validation_leaves_rewrites_untouched() {
        let mut c: Config = toml::from_str(
            r#"
cache_bytes = 0
[rewrites]
"Host.Local" = "192.0.2.1"
"#,
        )
        .unwrap();
        assert!(c.validate().is_err());
        assert_eq!(c.rewrites.len(), 1);
        assert_eq!(c.rewrites["Host.Local"], "192.0.2.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn bounds_are_enforced() {
        let mut c = Config { cache_bytes: 0, ..Config::default() };
        assert!(c.validate().is_err());
        let mut c = Config { negative_ttl_min: 10, negative_ttl_max: 5, ..Config::default() };
        assert!(c.validate().is_err());
        let mut c = Config { tcp_idle_timeout_seconds: 0, ..Config::default() };
        assert!(c.validate().is_err());
        let mut c = Config { upstream_timeout_seconds: 0, ..Config::default() };
        assert!(c.validate().is_err());
        let mut c = Config { upstream_timeout_seconds: 61, ..Config::default() };
        assert!(c.validate().is_err());
        let mut c = Config { upstream_timeout_seconds: 60, ..Config::default() };
        assert!(c.validate().is_ok());
        let mut c = Config { upstream_hedge_ms: 5001, ..Config::default() };
        assert!(c.validate().is_err());
        for max in [0, 65_537] {
            let mut c = Config { upstream_inflight_max: max, ..Config::default() };
            assert!(c.validate().is_err(), "upstream_inflight_max = {max} must be rejected");
        }
        for max in [1, 65_536] {
            let mut c = Config { upstream_inflight_max: max, ..Config::default() };
            assert!(c.validate().is_ok(), "upstream_inflight_max = {max} must be accepted");
        }
        for zero in [
            Config { blocklist_max_bytes: 0, ..Config::default() },
            Config { blocklist_max_lines: 0, ..Config::default() },
            Config { blocklist_max_rules_total: 0, ..Config::default() },
        ] {
            let mut zero = zero;
            assert!(zero.validate().is_err());
        }
        let mut c = Config { serve_stale_client_timeout_ms: 0, ..Config::default() };
        assert!(c.validate().is_ok());
        for value in [1, 60_000] {
            let mut c = Config { serve_stale_client_timeout_ms: value, ..Config::default() };
            assert!(c.validate().is_ok(), "serve_stale_client_timeout_ms = {value} must be accepted");
        }
        let mut c = Config { serve_stale_client_timeout_ms: 60_001, ..Config::default() };
        let error = c.validate().unwrap_err();
        assert_eq!(error, "serve_stale_client_timeout_ms must be between 0 and 60000");
        assert!(!error.contains("60001"), "the rejected value is never echoed: {error}");
        for config in [
            Config { tcp_max_connections: 0, ..Config::default() },
            Config { tcp_max_connections: 65_537, ..Config::default() },
            Config { tcp_max_connections_per_client: 0, ..Config::default() },
            Config { tcp_max_connections_per_client: 65_537, ..Config::default() },
            Config { tcp_queries_per_connection: 0, ..Config::default() },
            Config { tcp_pipeline_max: 0, ..Config::default() },
            Config { tcp_pipeline_max: 257, ..Config::default() },
            Config { udp_inflight_max: 0, ..Config::default() },
            Config { udp_inflight_max: 65_537, ..Config::default() },
            Config { udp_max_payload: 511, ..Config::default() },
            Config { query_log_capacity: 1_000_001, ..Config::default() },
        ] {
            let mut config = config;
            assert!(config.validate().is_err());
        }
    }

    #[test]
    fn listen_accepts_a_string_or_an_array_and_validates_the_list() {
        let one: Config = toml::from_str("listen = \"127.0.0.1:5353\"").unwrap();
        assert_eq!(one.listen, vec!["127.0.0.1:5353".parse().unwrap()]);
        let mut both: Config = toml::from_str("listen = [\"192.0.2.11:53\", \"[2001:db8::11]:53\"]").unwrap();
        assert_eq!(both.listen.len(), 2);
        assert!(both.listen[1].is_ipv6());
        both.validate().unwrap();

        let mut dup: Config = toml::from_str("listen = [\"192.0.2.11:53\", \"192.0.2.11:53\"]").unwrap();
        assert_eq!(dup.validate().unwrap_err(), "duplicate listen address 192.0.2.11:53");
        let mut empty: Config = toml::from_str("listen = []").unwrap();
        assert!(empty.validate().is_err());
        let many = (0..=MAX_LISTEN).map(|i| format!("\"127.0.0.1:{}\"", 5000 + i)).collect::<Vec<_>>().join(", ");
        let mut over: Config = toml::from_str(&format!("listen = [{many}]")).unwrap();
        assert!(over.validate().is_err());
        assert!(toml::from_str::<Config>("listen = [\"nonsense\"]").is_err());
        assert!(toml::from_str::<Config>("listen = 53").is_err());
    }

    #[test]
    fn udp_worker_and_socket_buffer_bounds_are_enforced() {
        for workers in [0, 1, 64] {
            let mut c = Config { udp_workers: workers, ..Config::default() };
            assert!(c.validate().is_ok(), "udp_workers = {workers} must be accepted");
        }
        let mut c = Config { udp_workers: 65, ..Config::default() };
        let error = c.validate().unwrap_err();
        assert_eq!(error, "udp_workers must be in 0..=64");
        assert!(!error.contains("65"), "the rejected value is never echoed: {error}");

        for buffer in ["udp_rcvbuf_bytes", "udp_sndbuf_bytes"] {
            for value in [0, 4096, 67_108_864] {
                let mut c = match buffer {
                    "udp_rcvbuf_bytes" => Config { udp_rcvbuf_bytes: value, ..Config::default() },
                    _ => Config { udp_sndbuf_bytes: value, ..Config::default() },
                };
                assert!(c.validate().is_ok(), "{buffer} = {value} must be accepted");
            }
            for value in [4095, 67_108_865] {
                let mut c = match buffer {
                    "udp_rcvbuf_bytes" => Config { udp_rcvbuf_bytes: value, ..Config::default() },
                    _ => Config { udp_sndbuf_bytes: value, ..Config::default() },
                };
                let error = c.validate().unwrap_err();
                assert_eq!(error, format!("{buffer} must be 0 or in 4096..=67108864"));
                assert!(!error.contains(&value.to_string()), "the rejected value is never echoed: {error}");
            }
        }
    }

    #[test]
    fn udp_batch_bounds_are_enforced() {
        for batch in [0, 1, MAX_UDP_BATCH] {
            let mut c = Config { udp_batch: batch, ..Config::default() };
            assert!(c.validate().is_ok(), "udp_batch = {batch} must be accepted");
        }
        let mut c = Config { udp_batch: MAX_UDP_BATCH + 1, ..Config::default() };
        let error = c.validate().unwrap_err();
        assert_eq!(error, format!("udp_batch must be in 0..={MAX_UDP_BATCH}"));
        assert!(!error.contains(&(MAX_UDP_BATCH + 1).to_string()), "the rejected value is never echoed: {error}");
    }

    #[test]
    fn worker_thread_bounds_are_enforced() {
        for workers in [0, 1, 64] {
            let mut c = Config { worker_threads: workers, ..Config::default() };
            assert!(c.validate().is_ok(), "worker_threads = {workers} must be accepted");
        }
        let mut c = Config { worker_threads: 65, ..Config::default() };
        let error = c.validate().unwrap_err();
        assert_eq!(error, "worker_threads must be in 0..=64");
        assert!(!error.contains("65"), "the rejected value is never echoed: {error}");
    }

    #[test]
    fn max_age_secs_is_computed_by_validate() {
        let mut c: Config = toml::from_str("optimistic_max_age = \"90m\"").unwrap();
        assert_eq!(c.max_age_secs, 0, "computed only during validation");
        c.validate().unwrap();
        assert_eq!(c.max_age_secs, 5400);
    }

    #[test]
    fn self_forwarding_fallbacks_are_rejected() {
        let mut exact = Config {
            listen: vec!["192.0.2.10:53".parse().unwrap()],
            fallback: vec!["192.0.2.10:53".parse().unwrap()],
            ..Config::default()
        };
        assert!(exact.validate().is_err());

        let mut local_port = Config {
            listen: vec!["0.0.0.0:53".parse().unwrap()],
            fallback: vec!["127.0.0.1:53".parse().unwrap()],
            ..Config::default()
        };
        assert!(local_port.validate().is_err());

        let mut loopback_listener = Config {
            listen: vec!["127.0.0.1:5353".parse().unwrap()],
            fallback: vec!["0.0.0.0:5353".parse().unwrap()],
            ..Config::default()
        };
        assert!(loopback_listener.validate().is_err());

        // A public fallback on the same port is not a loop.
        let mut public = Config {
            listen: vec!["0.0.0.0:53".parse().unwrap()],
            fallback: vec!["1.1.1.1:53".parse().unwrap()],
            ..Config::default()
        };
        public.validate().unwrap();

        // A loopback listener may still forward to a public resolver on port 53.
        let mut public_from_loopback = Config {
            listen: vec!["127.0.0.1:5353".parse().unwrap()],
            fallback: vec!["1.1.1.1:53".parse().unwrap()],
            ..Config::default()
        };
        public_from_loopback.validate().unwrap();

        // A DoH URL equal to the literal listen IP is suspicious, not rejected.
        let mut doh = Config {
            listen: vec!["192.0.2.10:53".parse().unwrap()],
            upstreams: vec!["https://192.0.2.10/dns-query".into()],
            fallback: vec![],
            ..Config::default()
        };
        doh.validate().unwrap();
    }

    #[test]
    fn impossible_sources_are_unspecified_multicast_and_broadcast() {
        for ip in
            ["0.0.0.0", "::", "224.0.0.1", "239.255.255.250", "ff02::1", "255.255.255.255", "::ffff:255.255.255.255"]
        {
            assert!(impossible_source(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["127.0.0.1", "192.168.1.255", "10.1.2.3", "::1", "fe80::1", "fd00::1", "::ffff:192.168.1.5"] {
            assert!(!impossible_source(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn attack_hardening_knobs_default_and_are_bounded() {
        // The two attack-hardening limits default to on.
        let c = Config::default();
        assert_eq!((c.udp_discard_timeout_ms, c.upstream_inflight_per_client), (1900, 64));
        assert_eq!(c.udp_discard_limit(), Some(Duration::from_millis(1900)));
        for ok in [0, 1, 60_000] {
            let mut c = Config { udp_discard_timeout_ms: ok, ..Config::default() };
            assert!(c.validate().is_ok(), "udp_discard_timeout_ms = {ok}");
        }
        for ok in [0, 1, 65_536] {
            let mut c = Config { upstream_inflight_per_client: ok, ..Config::default() };
            assert!(c.validate().is_ok(), "upstream_inflight_per_client = {ok}");
        }
        let mut c = Config { udp_discard_timeout_ms: 60_001, ..Config::default() };
        assert_eq!(c.validate().unwrap_err(), "udp_discard_timeout_ms must be between 0 and 60000");
        let mut c = Config { upstream_inflight_per_client: 65_537, ..Config::default() };
        assert_eq!(c.validate().unwrap_err(), "upstream_inflight_per_client must be between 0 and 65536");
        // Zero turns discarding off; a long stale timer keeps its own answers.
        let off = Config { udp_discard_timeout_ms: 0, serve_stale_client_timeout_ms: 5000, ..Config::default() };
        assert_eq!(off.udp_discard_limit(), None);
        let stale = Config { serve_stale_client_timeout_ms: 5000, ..Config::default() };
        assert_eq!(stale.udp_discard_limit(), Some(Duration::from_millis(5100)));
    }
}
