//! Closed-loop DNS load generator for the performance baselines.
//!
//! The corpus is one `name [qtype]` per line; a missing qtype means A. Each
//! worker keeps one query in flight, validates the response ID, and the tool
//! prints one JSON line with throughput, RTT percentiles and error counts.
//! RTTs are held in a fixed 32-bucket log2 histogram (each percentile is the
//! bucket's upper bound, within 2x), so memory stays O(1). `--server` accepts
//! `HOST:PORT` and resolves the name once at startup.

use std::{
    env,
    fs::File,
    io::{self, BufRead, BufReader},
    net::SocketAddr,
    process::ExitCode,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    task::JoinSet,
    time::timeout,
};

const RESPONSE_TIMEOUT: Duration = Duration::from_secs(2);
const LATENCY_BUCKETS: usize = 32;

/// Fixed-size log2 histogram: bucket k (k >= 1) holds RTTs in
/// `[2^(k-1), 2^k)` microseconds; bucket 0 holds 0 us. Percentiles report the
/// bucket's upper bound, so a value can overstate by less than 2x.
#[derive(Default)]
struct LatencyHistogram {
    buckets: [u64; LATENCY_BUCKETS],
}

impl LatencyHistogram {
    fn record(&mut self, micros: u64) {
        let bucket = (u64::BITS - micros.leading_zeros()) as usize;
        self.buckets[bucket.min(LATENCY_BUCKETS - 1)] += 1;
    }

    fn merge(&mut self, other: &Self) {
        for (total, count) in self.buckets.iter_mut().zip(&other.buckets) {
            *total += *count;
        }
    }

    fn len(&self) -> u64 {
        self.buckets.iter().sum()
    }

    fn percentile_ms(&self, p: f64) -> f64 {
        let count = self.len();
        if count == 0 {
            return 0.0;
        }
        let rank = ((count - 1) as f64 * p).round() as u64;
        let mut seen = 0u64;
        for (bucket, &in_bucket) in self.buckets.iter().enumerate() {
            seen += in_bucket;
            if seen > rank {
                let upper_us = if bucket == 0 { 0 } else { 1u64 << bucket };
                return upper_us as f64 / 1000.0;
            }
        }
        0.0
    }
}

struct Args {
    server: String,
    file: String,
    concurrency: usize,
    seconds: u64,
    tcp: bool,
    recycle: bool,
    limit: Option<usize>,
}

fn usage() -> &'static str {
    "usage: loadgen --server HOST:PORT --file PATH [--concurrency N] [--seconds N] [--tcp] [--recycle] [--limit N]"
}

fn next_value(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    args.next().ok_or_else(|| format!("{flag} requires a value"))
}

impl Args {
    fn parse() -> Result<Self, String> {
        let mut server = None;
        let mut file = None;
        let mut concurrency = 1usize;
        let mut seconds = 10u64;
        let mut tcp = false;
        let mut recycle = false;
        let mut limit = None;
        let mut args = env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--server" => {
                    server = Some(next_value(&mut args, "--server")?);
                }
                "--file" => file = Some(next_value(&mut args, "--file")?),
                "--concurrency" => {
                    let value = next_value(&mut args, "--concurrency")?;
                    concurrency = value.parse().map_err(|_| "invalid --concurrency".to_string())?;
                }
                "--seconds" => {
                    let value = next_value(&mut args, "--seconds")?;
                    seconds = value.parse().map_err(|_| "invalid --seconds".to_string())?;
                }
                "--limit" => {
                    let value = next_value(&mut args, "--limit")?;
                    limit = Some(value.parse().map_err(|_| "invalid --limit".to_string())?);
                }
                "--tcp" => tcp = true,
                "--recycle" => recycle = true,
                "-h" | "--help" => {
                    println!("{}", usage());
                    std::process::exit(0);
                }
                other => return Err(format!("unknown argument {other}")),
            }
        }
        if concurrency == 0 || seconds == 0 {
            return Err("--concurrency and --seconds must be at least 1".into());
        }
        Ok(Self {
            server: server.ok_or("--server is required")?,
            file: file.ok_or("--file is required")?,
            concurrency,
            seconds,
            tcp,
            recycle,
            limit,
        })
    }
}

#[derive(Clone)]
struct Query {
    name: String,
    qtype: u16,
}

fn parse_qtype(value: &str) -> Result<u16, String> {
    let qtype = match value.to_ascii_uppercase().as_str() {
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
        "RRSIG" => 46,
        "NSEC" => 47,
        "DNSKEY" => 48,
        "SVCB" => 64,
        "HTTPS" => 65,
        "ANY" => 255,
        other => other.parse().map_err(|_| "unknown qtype".to_string())?,
    };
    Ok(qtype)
}

fn load_corpus(path: &str, limit: Option<usize>) -> Result<Vec<Query>, String> {
    let file = File::open(path).map_err(|e| format!("cannot open {path}: {e}"))?;
    let mut queries = Vec::new();
    for (line_number, line) in BufReader::new(file).lines().enumerate() {
        if limit.is_some_and(|limit| queries.len() >= limit) {
            break;
        }
        let line = line.map_err(|e| format!("cannot read {path}: {e}"))?;
        let mut fields = line.split_whitespace();
        let Some(qname) = fields.next() else { continue };
        let qtype = match fields.next() {
            Some(value) => parse_qtype(value).map_err(|e| format!("line {}: {e}", line_number + 1))?,
            None => 1,
        };
        queries.push(Query { name: qname.to_string(), qtype });
    }
    if queries.is_empty() {
        return Err("corpus is empty".into());
    }
    Ok(queries)
}

fn build_query(query: &Query, id: u16) -> Option<Vec<u8>> {
    let name = query.name.trim_end_matches('.');
    if name.is_empty() {
        return None;
    }
    let mut packet = Vec::with_capacity(12 + name.len() + 6);
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&0x0100u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&[0; 6]);
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 || !label.is_ascii() {
            return None;
        }
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&query.qtype.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    Some(packet)
}

fn corpus_index(index: &AtomicUsize, len: usize, recycle: bool) -> Option<usize> {
    let position = index.fetch_add(1, Ordering::Relaxed);
    if position < len {
        Some(position)
    } else if recycle {
        Some(position % len)
    } else {
        None
    }
}

fn remaining(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now()).min(RESPONSE_TIMEOUT)
}

#[derive(Default)]
struct WorkerStats {
    latencies: LatencyHistogram,
    sent: u64,
    errors: u64,
    timeouts: u64,
}

impl WorkerStats {
    fn merge(&mut self, other: Self) {
        self.latencies.merge(&other.latencies);
        self.sent += other.sent;
        self.errors += other.errors;
        self.timeouts += other.timeouts;
    }
}

#[allow(clippy::too_many_arguments)]
async fn udp_worker(
    server: SocketAddr,
    corpus: Arc<Vec<Query>>,
    index: Arc<AtomicUsize>,
    recycle: bool,
    deadline: Instant,
    id_base: u16,
) -> WorkerStats {
    let mut stats = WorkerStats::default();
    let bind = if server.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let socket = match UdpSocket::bind(bind).await {
        Ok(socket) => socket,
        Err(_) => {
            stats.errors += 1;
            return stats;
        }
    };
    if socket.connect(server).await.is_err() {
        stats.errors += 1;
        return stats;
    }
    let mut buf = vec![0u8; 65535];
    let mut id = id_base;
    while Instant::now() < deadline {
        let Some(position) = corpus_index(&index, corpus.len(), recycle) else { break };
        let Some(raw) = build_query(&corpus[position], id) else {
            stats.errors += 1;
            id = id.wrapping_add(1);
            continue;
        };
        let started = Instant::now();
        if socket.send(&raw).await.is_err() {
            stats.errors += 1;
            id = id.wrapping_add(1);
            continue;
        }
        stats.sent += 1;
        let recv_deadline = started + remaining(deadline);
        loop {
            let wait = recv_deadline.saturating_duration_since(Instant::now());
            if wait.is_zero() {
                stats.timeouts += 1;
                break;
            }
            match timeout(wait, socket.recv(&mut buf)).await {
                Ok(Ok(n)) if n >= 2 && buf[..2] == raw[..2] => {
                    stats.latencies.record(started.elapsed().as_micros() as u64);
                    break;
                }
                Ok(Ok(_)) => stats.errors += 1,
                Ok(Err(_)) => {
                    stats.errors += 1;
                    break;
                }
                Err(_) => {
                    stats.timeouts += 1;
                    break;
                }
            }
        }
        id = id.wrapping_add(1);
    }
    stats
}

#[derive(PartialEq, Eq)]
enum Exchange {
    Matched,
    Mismatched,
}

async fn tcp_exchange(stream: &mut TcpStream, raw: &[u8], buf: &mut [u8]) -> io::Result<Exchange> {
    stream.write_u16(raw.len() as u16).await?;
    stream.write_all(raw).await?;
    let len = stream.read_u16().await? as usize;
    if len < 2 || len > buf.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad response length"));
    }
    stream.read_exact(&mut buf[..len]).await?;
    Ok(if buf[..2] == raw[..2] { Exchange::Matched } else { Exchange::Mismatched })
}

#[allow(clippy::too_many_arguments)]
async fn tcp_worker(
    server: SocketAddr,
    corpus: Arc<Vec<Query>>,
    index: Arc<AtomicUsize>,
    recycle: bool,
    deadline: Instant,
    id_base: u16,
) -> WorkerStats {
    let mut stats = WorkerStats::default();
    let mut stream = TcpStream::connect(server).await.ok();
    if stream.is_none() {
        stats.errors += 1;
        return stats;
    }
    let mut buf = vec![0u8; 65535];
    let mut id = id_base;
    while Instant::now() < deadline {
        let Some(position) = corpus_index(&index, corpus.len(), recycle) else { break };
        let Some(raw) = build_query(&corpus[position], id) else {
            stats.errors += 1;
            id = id.wrapping_add(1);
            continue;
        };
        let Some(connection) = stream.as_mut() else { break };
        let started = Instant::now();
        stats.sent += 1;
        match timeout(remaining(deadline), tcp_exchange(connection, &raw, &mut buf)).await {
            Ok(Ok(Exchange::Matched)) => {
                stats.latencies.record(started.elapsed().as_micros() as u64);
            }
            Ok(Ok(Exchange::Mismatched)) => stats.errors += 1,
            Ok(Err(_)) => {
                stats.errors += 1;
                stream = TcpStream::connect(server).await.ok();
            }
            Err(_) => {
                stats.timeouts += 1;
                stream = TcpStream::connect(server).await.ok();
            }
        }
        id = id.wrapping_add(1);
    }
    stats
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = match Args::parse() {
        Ok(args) => args,
        Err(e) => {
            eprintln!("loadgen: {e}\n{}", usage());
            return ExitCode::from(2);
        }
    };
    let corpus = match load_corpus(&args.file, args.limit) {
        Ok(corpus) => Arc::new(corpus),
        Err(e) => {
            eprintln!("loadgen: {e}");
            return ExitCode::from(2);
        }
    };
    let mut addresses = match tokio::net::lookup_host(args.server.as_str()).await {
        Ok(addresses) => addresses.collect::<Vec<_>>(),
        Err(e) => {
            eprintln!("loadgen: cannot resolve --server {}: {e}", args.server);
            return ExitCode::from(2);
        }
    };
    // Prefer IPv4 when a name has both families; the common DNS listener is
    // IPv4 and this keeps `localhost` working against an IPv4-only server.
    let server = match addresses.iter().copied().find(SocketAddr::is_ipv4).or_else(|| addresses.pop()) {
        Some(server) => server,
        None => {
            eprintln!("loadgen: --server {} resolved to no addresses", args.server);
            return ExitCode::from(2);
        }
    };
    let (concurrency, seconds, tcp, recycle) = (args.concurrency, args.seconds, args.tcp, args.recycle);
    let index = Arc::new(AtomicUsize::new(0));
    let started = Instant::now();
    let deadline = started + Duration::from_secs(seconds);
    let mut tasks = JoinSet::new();
    for worker in 0..concurrency {
        let corpus = Arc::clone(&corpus);
        let index = Arc::clone(&index);
        let id_base = (worker as u16).wrapping_mul(997).wrapping_add(1);
        tasks.spawn(async move {
            if tcp {
                tcp_worker(server, corpus, index, recycle, deadline, id_base).await
            } else {
                udp_worker(server, corpus, index, recycle, deadline, id_base).await
            }
        });
    }
    let mut stats = WorkerStats::default();
    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok(worker) => stats.merge(worker),
            Err(_) => stats.errors += 1,
        }
    }
    let elapsed = started.elapsed().as_secs_f64();
    let ok = stats.latencies.len();
    let qps = if elapsed > 0.0 { ok as f64 / elapsed } else { 0.0 };
    println!(
        "{{\"protocol\":\"{}\",\"concurrency\":{},\"duration_s\":{elapsed:.3},\"sent\":{},\"ok\":{ok},\"errors\":{},\"timeouts\":{},\"qps\":{qps:.1},\"p50_ms\":{:.3},\"p95_ms\":{:.3},\"p99_ms\":{:.3}}}",
        if tcp { "tcp" } else { "udp" },
        concurrency,
        stats.sent,
        stats.errors,
        stats.timeouts,
        stats.latencies.percentile_ms(0.50),
        stats.latencies.percentile_ms(0.95),
        stats.latencies.percentile_ms(0.99),
    );
    ExitCode::SUCCESS
}
