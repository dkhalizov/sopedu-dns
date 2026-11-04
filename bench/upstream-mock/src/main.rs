//! Deterministic upstream for the request-path and competitor benchmarks.
//!
//! Serves plain DNS over UDP and TCP (pipelined, out of order) and, with a
//! certificate, DNS-over-HTTPS over HTTP/2 + TLS (POST and GET `?dns=`). Every
//! reply waits `--delay-ms` first, so a miss costs a known amount and the
//! server's own overhead is `client latency - delay`.
//!
//! Answers are synthetic and depend only on the question:
//! - a label `ttlN` anywhere in the name sets the TTL to N (default `--ttl`);
//! - `*.nx.bench` is NXDOMAIN with an SOA (negative caching);
//! - `*.big.bench` returns ~1.5 KB of TXT (truncation over UDP);
//! - A gets 192.0.2.1, AAAA 2001:db8::1, every other type NODATA + SOA.
//!
//! `--mode hang` accepts and never answers (blackhole), `--mode error`
//! answers SERVFAIL / HTTP 503. Counters are printed to stderr once a second
//! when they change: `stats udp=N tcp=N doh=N`.
//!
//! ```sh
//! cargo run --release --manifest-path bench/upstream-mock/Cargo.toml -- \
//!   --listen 127.0.0.1:5300 --doh 127.0.0.1:8443 --cert cert.der --key key.der --delay-ms 10
//! ```

use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use hickory_proto::{
    op::{Message, MessageType, OpCode, ResponseCode},
    rr::{
        rdata::{A, AAAA, SOA, TXT},
        Name, RData, Record, RecordType,
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::mpsc,
};
use tokio_rustls::rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    ServerConfig,
};

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Ok,
    Hang,
    Error,
}

struct State {
    delay: Duration,
    ttl: u32,
    mode: Mode,
    udp: AtomicU64,
    tcp: AtomicU64,
    doh: AtomicU64,
}

fn usage() -> ! {
    eprintln!(
        "usage: upstream_mock [--listen ADDR] [--doh ADDR --cert DER --key PKCS8_DER] \
         [--delay-ms N] [--ttl N] [--mode ok|hang|error]"
    );
    std::process::exit(2)
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let mut listen: Option<SocketAddr> = None;
    let mut doh: Option<SocketAddr> = None;
    let (mut cert, mut key) = (None, None);
    let (mut delay_ms, mut ttl, mut mode) = (0u64, 300u32, Mode::Ok);
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let value = args.next().unwrap_or_else(|| usage());
        match flag.as_str() {
            "--listen" => listen = Some(value.parse().unwrap_or_else(|_| usage())),
            "--doh" => doh = Some(value.parse().unwrap_or_else(|_| usage())),
            "--cert" => cert = Some(std::fs::read(value)?),
            "--key" => key = Some(std::fs::read(value)?),
            "--delay-ms" => delay_ms = value.parse().unwrap_or_else(|_| usage()),
            "--ttl" => ttl = value.parse().unwrap_or_else(|_| usage()),
            "--mode" => {
                mode = match value.as_str() {
                    "ok" => Mode::Ok,
                    "hang" => Mode::Hang,
                    "error" => Mode::Error,
                    _ => usage(),
                }
            }
            _ => usage(),
        }
    }
    if listen.is_none() && doh.is_none() {
        listen = Some("127.0.0.1:5300".parse().unwrap());
    }
    let state = Arc::new(State {
        delay: Duration::from_millis(delay_ms),
        ttl,
        mode,
        udp: AtomicU64::new(0),
        tcp: AtomicU64::new(0),
        doh: AtomicU64::new(0),
    });

    if let Some(addr) = listen {
        let udp = Arc::new(UdpSocket::bind(addr).await?);
        let tcp = TcpListener::bind(addr).await?;
        tokio::spawn(serve_udp(udp, state.clone()));
        tokio::spawn(serve_tcp(tcp, state.clone()));
        eprintln!("upstream_mock plain udp+tcp on {addr}");
    }
    if let Some(addr) = doh {
        let (Some(cert), Some(key)) = (cert, key) else { usage() };
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![CertificateDer::from(cert)], PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)))
            .map_err(std::io::Error::other)?;
        config.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind(addr).await?;
        tokio::spawn(serve_doh(listener, acceptor, state.clone()));
        eprintln!("upstream_mock doh (h2) on {addr}");
    }

    let mut last = (0, 0, 0);
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let now =
            (state.udp.load(Ordering::Relaxed), state.tcp.load(Ordering::Relaxed), state.doh.load(Ordering::Relaxed));
        if now != last {
            eprintln!("stats udp={} tcp={} doh={}", now.0, now.1, now.2);
            last = now;
        }
    }
}

/// The reply for one wire query, or `None` to stay silent.
fn answer(raw: &[u8], state: &State) -> Option<Vec<u8>> {
    if state.mode == Mode::Hang {
        return None;
    }
    let query = Message::from_vec(raw).ok()?;
    let question = query.queries.first()?.clone();
    let mut reply = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
    reply.metadata.recursion_desired = query.metadata.recursion_desired;
    reply.metadata.recursion_available = true;
    reply.add_queries(query.queries.iter().cloned());
    if let Some(edns) = query.edns.clone() {
        reply.set_edns(edns);
    }
    if state.mode == Mode::Error {
        reply.metadata.response_code = ResponseCode::ServFail;
        return reply.to_vec().ok();
    }
    let name = question.name().clone();
    let lower = name.to_lowercase().to_ascii();
    let ttl = name
        .to_lowercase()
        .iter()
        .find_map(|label| std::str::from_utf8(label).ok()?.strip_prefix("ttl")?.parse::<u32>().ok())
        .unwrap_or(state.ttl);
    let soa = || {
        // SOA owner at the qname: in bailiwick, so sopedu (RFC 2308 section 5) caches the negative answer
        let zone = name.clone();
        Record::from_rdata(
            zone.clone(),
            ttl,
            RData::SOA(SOA::new(Name::from_ascii("ns.bench.").unwrap(), zone, 1, 3600, 600, 86400, ttl)),
        )
    };
    if lower.ends_with(".nx.bench.") {
        reply.metadata.response_code = ResponseCode::NXDomain;
        reply.add_authority(soa());
    } else if lower.ends_with(".big.bench.") && question.query_type() == RecordType::TXT {
        for i in 0..6 {
            let text = format!("{i}{}", "x".repeat(249));
            reply.add_answer(Record::from_rdata(name.clone(), ttl, RData::TXT(TXT::new(vec![text]))));
        }
    } else {
        match question.query_type() {
            RecordType::A => {
                reply.add_answer(Record::from_rdata(name, ttl, RData::A(A(Ipv4Addr::new(192, 0, 2, 1)))));
            }
            RecordType::AAAA => {
                reply.add_answer(Record::from_rdata(
                    name,
                    ttl,
                    RData::AAAA(AAAA(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))),
                ));
            }
            _ => {
                reply.add_authority(soa());
            }
        }
    }
    reply.to_vec().ok()
}

/// `sleep(0)` still waits for the next 1 ms timer tick; skip it entirely.
async fn delay(state: &State) {
    if !state.delay.is_zero() {
        tokio::time::sleep(state.delay).await;
    }
}

async fn serve_udp(socket: Arc<UdpSocket>, state: Arc<State>) {
    let mut buf = vec![0u8; 65_535];
    loop {
        let Ok((n, peer)) = socket.recv_from(&mut buf).await else { continue };
        state.udp.fetch_add(1, Ordering::Relaxed);
        let raw = buf[..n].to_vec();
        let (socket, state) = (socket.clone(), state.clone());
        tokio::spawn(async move {
            delay(&state).await;
            if let Some(reply) = answer(&raw, &state) {
                let _ = socket.send_to(&reply, peer).await;
            }
        });
    }
}

async fn serve_tcp(listener: TcpListener, state: Arc<State>) {
    loop {
        let Ok((stream, _)) = listener.accept().await else { continue };
        let _ = stream.set_nodelay(true);
        tokio::spawn(tcp_connection(stream, state.clone()));
    }
}

async fn tcp_connection(stream: TcpStream, state: Arc<State>) {
    let (mut reader, mut writer) = stream.into_split();
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
    tokio::spawn(async move {
        while let Some(reply) = rx.recv().await {
            let mut framed = (reply.len() as u16).to_be_bytes().to_vec();
            framed.extend_from_slice(&reply);
            if writer.write_all(&framed).await.is_err() {
                return;
            }
        }
    });
    loop {
        let mut len = [0u8; 2];
        if reader.read_exact(&mut len).await.is_err() {
            return;
        }
        let mut raw = vec![0u8; u16::from_be_bytes(len) as usize];
        if reader.read_exact(&mut raw).await.is_err() {
            return;
        }
        state.tcp.fetch_add(1, Ordering::Relaxed);
        let (tx, state) = (tx.clone(), state.clone());
        tokio::spawn(async move {
            delay(&state).await;
            if let Some(reply) = answer(&raw, &state) {
                let _ = tx.send(reply);
            }
        });
    }
}

async fn serve_doh(listener: TcpListener, acceptor: tokio_rustls::TlsAcceptor, state: Arc<State>) {
    loop {
        let Ok((stream, _)) = listener.accept().await else { continue };
        let _ = stream.set_nodelay(true);
        let (acceptor, state) = (acceptor.clone(), state.clone());
        tokio::spawn(async move {
            let Ok(tls) = acceptor.accept(stream).await else { return };
            let Ok(mut conn) = h2::server::handshake(tls).await else { return };
            while let Some(Ok((request, respond))) = conn.accept().await {
                tokio::spawn(doh_request(request, respond, state.clone()));
            }
        });
    }
}

async fn doh_request(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<bytes::Bytes>,
    state: Arc<State>,
) {
    state.doh.fetch_add(1, Ordering::Relaxed);
    let query = request.uri().query().and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("dns=")));
    let raw = match query {
        Some(encoded) => base64url(encoded),
        None => {
            let mut body = request.into_body();
            let mut raw = Vec::new();
            while let Some(Ok(chunk)) = body.data().await {
                let _ = body.flow_control().release_capacity(chunk.len());
                raw.extend_from_slice(&chunk);
            }
            Some(raw)
        }
    };
    delay(&state).await;
    let Some(raw) = raw else { return };
    let (status, body) = match answer(&raw, &state) {
        None => return std::future::pending().await, // hang: hold the stream open
        Some(_) if state.mode == Mode::Error => (503, Vec::new()),
        Some(reply) => (200, reply),
    };
    let response = http::Response::builder()
        .status(status)
        .header("content-type", "application/dns-message")
        .header("cache-control", "max-age=0")
        .body(())
        .unwrap();
    if let Ok(mut stream) = respond.send_response(response, false) {
        let _ = stream.send_data(body.into(), true);
    }
}

/// RFC 4648 base64url without padding (the DoH GET encoding).
fn base64url(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in text.bytes().filter(|&c| c != b'=') {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' | b'+' => 62,
            b'_' | b'/' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

#[test]
fn base64url_decodes_rfc8484_example() {
    // RFC 8484 §4.1.1: "www.example.com" A query with ID 0.
    let raw = base64url("AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB").unwrap();
    assert_eq!(&raw[..4], &[0, 0, 1, 0]);
    assert_eq!(raw.len(), 33);
}
