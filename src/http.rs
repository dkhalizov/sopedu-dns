//! Read-only HTTP/1 listener for the UI, `/healthz` and `/metrics`.
//!
//! It shares the DNS runtime but cannot slow it: connections are capped in
//! total and per client host, each one has a header-read (and idle) timeout
//! and a hard lifetime, a few reserved connections keep `/healthz` and
//! `/metrics` answerable when the pool is full, request headers are
//! bounded, and a handler is a short synchronous function. GET and HEAD are
//! served; POST only on [`POST_PATHS`], where it carries a form to validate and
//! changes nothing: its body is bounded by [`MAX_BODY`] and read under the
//! header timeout, and a POST that is not same-origin (`Sec-Fetch-Site` /
//! `Origin`) is refused before any handler runs. No other body is read. A handler may return a
//! bounded channel instead of a body (Server-Sent Events): the connection then
//! gets a longer, still hard, lifetime, and the producer drops a stream whose
//! client stops reading.

use crate::ratelimit::PerClient;
use http_body_util::{BodyExt, Either, Full, Limited};
use hyper::{
    body::{Body, Bytes, Frame, Incoming},
    header::{
        HeaderMap, ALLOW, CACHE_CONTROL, CONNECTION, CONTENT_LENGTH, CONTENT_SECURITY_POLICY, CONTENT_TYPE, HOST,
        ORIGIN, REFERRER_POLICY, X_CONTENT_TYPE_OPTIONS,
    },
    server::conn::http1,
    service::service_fn,
    Method, Request, Response, StatusCode,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use std::{
    borrow::Cow,
    convert::Infallible,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering::Relaxed},
        Arc,
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    net::TcpListener,
    sync::{mpsc, Semaphore},
    task::JoinSet,
    time::{sleep, timeout},
};

/// Concurrent connections that may use every route.
pub const MAX_CONNECTIONS: usize = 16;
/// Of those, what one client host may hold (keyed like the DNS per-client
/// limits: the full address), so one host cannot take the whole pool.
pub const MAX_CONNECTIONS_PER_CLIENT: usize = 4;
/// Extra connections, beyond a full pool or a client's full share, that serve
/// only [`PROBE_PATHS`]: one request each, no keep-alive, a short lifetime.
/// Idle keep-alives or live tails therefore cannot take the readiness probe
/// and the scraper offline.
pub const PROBE_CONNECTIONS: usize = 16;
/// Of those, what one client host may hold, so another host cannot lock the
/// probe's address out. The probe usually shares its address (loopback) with
/// the browser that filled the pool, so this is the whole old lane.
pub const PROBE_CONNECTIONS_PER_CLIENT: usize = 4;
/// The only paths a probe connection answers; anything else gets 503.
pub const PROBE_PATHS: &[&str] = &["/healthz", "/metrics"];
/// Hard cap on a probe connection.
const PROBE_LIFETIME: Duration = Duration::from_secs(5);
/// Time to receive a full request head. hyper starts this timer whenever the
/// connection waits for a request, so it is also the idle keep-alive timeout;
/// kept short so idle browser connections give their slot back quickly.
const HEADER_TIMEOUT: Duration = Duration::from_secs(2);
/// Time to receive a POST body.
const BODY_TIMEOUT: Duration = Duration::from_secs(5);
/// Hard cap on one connection, however busy or slow.
const CONNECTION_LIFETIME: Duration = Duration::from_secs(30);
/// Request head limit in bytes (hyper's minimum).
const MAX_HEAD_BYTES: usize = 8192;
/// Producers end their stream after this long; the browser's `EventSource`
/// reconnects. A connection that carries a stream may live 30 s longer.
pub const STREAM_LIFETIME: Duration = Duration::from_secs(300);
const STREAM_CONNECTION_LIFETIME: Duration = Duration::from_secs(330);

/// Largest accepted POST body in bytes.
pub const MAX_BODY: usize = 64 * 1024;
/// The only paths that take POST; every other path answers POST with 405.
pub const POST_PATHS: &[&str] = &["/rules"];

/// What a handler sees of a request.
pub struct Req<'a> {
    /// The path without the query.
    pub path: &'a str,
    /// The raw query string (empty when absent).
    pub query: &'a str,
    /// The `Host` header, if any.
    pub host: Option<&'a str>,
    /// True for a POST (already checked same-origin and size-bounded).
    pub post: bool,
    /// The POST body (empty otherwise).
    pub body: &'a [u8],
}

/// A routed response: a text body, or a stream of chunks that ends when the
/// sender is dropped.
pub struct Reply {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Cow<'static, str>,
    pub stream: Option<mpsc::Receiver<Bytes>>,
}

impl Reply {
    pub fn new(status: u16, content_type: &'static str, body: impl Into<Cow<'static, str>>) -> Self {
        Self { status, content_type, body: body.into(), stream: None }
    }
}

/// A response body fed by a bounded channel.
pub struct Chunks(mpsc::Receiver<Bytes>);

impl Body for Chunks {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        self.0.poll_recv(cx).map(|chunk| chunk.map(|bytes| Ok(Frame::data(bytes))))
    }
}

type ReplyBody = Either<Full<Bytes>, Chunks>;

/// Accepts connections until the task is aborted. `route` returns `None` for
/// 404.
pub async fn serve<F>(listener: TcpListener, route: F)
where
    F: Fn(&Req<'_>) -> Option<Reply> + Send + Sync + 'static,
{
    serve_limited(listener, route, MAX_CONNECTIONS, MAX_CONNECTIONS_PER_CLIENT).await
}

/// [`serve`] with explicit pool limits, so tests can fill the pool cheaply.
async fn serve_limited<F>(listener: TcpListener, route: F, total: usize, per_client: usize)
where
    F: Fn(&Req<'_>) -> Option<Reply> + Send + Sync + 'static,
{
    let route = Arc::new(route);
    let permits = Arc::new(Semaphore::new(total));
    let probe_permits = Arc::new(Semaphore::new(PROBE_CONNECTIONS));
    let clients = Arc::new(PerClient::default());
    let probe_clients = Arc::new(PerClient::default());
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        crate::log::log("warn", "ui_accept_failed", &[("error", error.to_string())]);
                        sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                };
                // A full pool or a host over its share still gets the probe
                // paths, on the reserved lane; past that the connection closes.
                let full = permits.clone().try_acquire_owned().ok().and_then(|permit| {
                    Some((permit, PerClient::take(&clients, peer.ip(), per_client)?))
                });
                let (permit, slot, probe_slot) = match full {
                    Some((permit, slot)) => (permit, Some(slot), None),
                    None => {
                        let probe = probe_permits.clone().try_acquire_owned().ok().and_then(|permit| {
                            Some((permit, PerClient::take(&probe_clients, peer.ip(), PROBE_CONNECTIONS_PER_CLIENT)?))
                        });
                        match probe {
                            Some((permit, probe_slot)) => (permit, None, Some(probe_slot)),
                            None => continue,
                        }
                    }
                };
                let probe_only = slot.is_none();
                let route = route.clone();
                connections.spawn(async move {
                    let _held = (permit, slot, probe_slot);
                    let streaming = Arc::new(AtomicBool::new(false));
                    let flag = streaming.clone();
                    let service = service_fn(move |request: Request<Incoming>| {
                        let (route, flag) = (route.clone(), flag.clone());
                        async move { Ok::<_, Infallible>(respond(&*route, request, &flag, probe_only).await) }
                    });
                    let connection = http1::Builder::new()
                        .timer(TokioTimer::new())
                        .header_read_timeout(HEADER_TIMEOUT)
                        .max_buf_size(MAX_HEAD_BYTES)
                        .keep_alive(!probe_only)
                        .serve_connection(TokioIo::new(stream), service);
                    let mut connection = std::pin::pin!(connection);
                    let lifetime = if probe_only { PROBE_LIFETIME } else { CONNECTION_LIFETIME };
                    tokio::select! {
                        _ = connection.as_mut() => return,
                        _ = sleep(lifetime) => {}
                    }
                    // Past the normal lifetime only a stream may continue.
                    if streaming.load(Relaxed) {
                        let _ = timeout(STREAM_CONNECTION_LIFETIME - CONNECTION_LIFETIME, connection).await;
                    }
                });
            }
        }
    }
}

/// A request another site's page made in the background (`fetch`, an
/// `EventSource`, an `<img>`): `Sec-Fetch-Site` is `cross-site` or
/// `same-site` and it is not a top-level navigation. Such a page cannot read
/// the answer, but it can still hold a connection or a live-tail slot.
fn foreign_fetch(headers: &HeaderMap) -> bool {
    let text = |name: &str| headers.get(name).and_then(|value| value.to_str().ok());
    let navigation = text("sec-fetch-mode") == Some("navigate") && text("sec-fetch-dest") == Some("document");
    matches!(text("sec-fetch-site"), Some("cross-site" | "same-site")) && !navigation
}

/// A POST is a same-origin form submission or it is refused. Browsers send
/// `Sec-Fetch-Site` and/or `Origin` on every form POST; a request with
/// neither (a script, `curl`) or with a foreign one is not accepted. The
/// `Origin` authority must equal `Host`.
fn same_origin(headers: &HeaderMap) -> bool {
    let text = |name: &str| headers.get(name).and_then(|value| value.to_str().ok());
    let site = text("sec-fetch-site");
    if site.is_some_and(|site| site != "same-origin") {
        return false;
    }
    match (text(ORIGIN.as_str()), text(HOST.as_str())) {
        (Some(origin), Some(host)) => origin.split_once("://").is_some_and(|(scheme, authority)| {
            matches!(scheme, "http" | "https") && authority.eq_ignore_ascii_case(host)
        }),
        (None, _) => site.is_some(),
        (Some(_), None) => false,
    }
}

async fn respond<F: Fn(&Req<'_>) -> Option<Reply>>(
    route: &F,
    request: Request<Incoming>,
    streaming: &AtomicBool,
    probe_only: bool,
) -> Response<ReplyBody> {
    let mut response = Response::new(Either::Left(Full::default()));
    let headers = response.headers_mut();
    headers.insert(CACHE_CONTROL, "no-store".parse().expect("static header"));
    // The pages load nothing from anywhere else and run no inline script.
    headers.insert(
        CONTENT_SECURITY_POLICY,
        "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
            .parse()
            .expect("static header"),
    );
    headers.insert(X_CONTENT_TYPE_OPTIONS, "nosniff".parse().expect("static header"));
    // `same-origin`, not `no-referrer`: under `no-referrer` browsers must send
    // `Origin: null` on every POST (Fetch, "serializing a request origin"),
    // which the same-origin check rightly refuses, so no form would work.
    // Referrers still never leave the UI.
    headers.insert(REFERRER_POLICY, "same-origin".parse().expect("static header"));
    let (parts, body) = request.into_parts();
    if probe_only && !PROBE_PATHS.contains(&parts.uri.path()) {
        error(&mut response, StatusCode::SERVICE_UNAVAILABLE, "busy: too many UI connections, retry shortly\n");
        return response;
    }
    // RFC 9112 §3.2: an HTTP/1.1 request without Host, or with more than one
    // Host line or an invalid Host value (a host name is ASCII, RFC 3986
    // §3.2.2), is a 400. §3.2.2: an absolute-form target's authority
    // replaces Host; refuse one that disagrees so the rebinding guard never
    // checks a different name than the one in use.
    let host = parts.headers.get(HOST).map(|host| host.as_bytes());
    if (host.is_none() && parts.version == hyper::Version::HTTP_11)
        || parts.headers.get(HOST).is_some_and(|host| host.to_str().is_err())
        || parts.headers.get_all(HOST).iter().nth(1).is_some()
        || parts
            .uri
            .authority()
            .is_some_and(|authority| !host.is_some_and(|host| host.eq_ignore_ascii_case(authority.as_str().as_bytes())))
    {
        error(&mut response, StatusCode::BAD_REQUEST, "bad request: missing or ambiguous Host\n");
        return response;
    }
    if parts.uri.path().starts_with("/api/") && foreign_fetch(&parts.headers) {
        error(&mut response, StatusCode::FORBIDDEN, "forbidden: cross-site request refused\n");
        return response;
    }
    let post = parts.method == Method::POST && POST_PATHS.contains(&parts.uri.path());
    if !post && !matches!(parts.method, Method::GET | Method::HEAD) {
        error(&mut response, StatusCode::METHOD_NOT_ALLOWED, "method not allowed\n");
        response.headers_mut().insert(ALLOW, "GET, HEAD".parse().expect("static header"));
        return response;
    }
    let mut bytes = Bytes::new();
    if post {
        // A refused body is not read, so the connection must not be reused.
        let refuse = |response: &mut Response<ReplyBody>, status: StatusCode, text: &'static str| {
            error(response, status, text);
            response.headers_mut().insert(CONNECTION, "close".parse().expect("static header"));
        };
        let length =
            parts.headers.get(CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<usize>().ok());
        if !same_origin(&parts.headers) {
            refuse(&mut response, StatusCode::FORBIDDEN, "forbidden: cross-site request refused\n");
            return response;
        }
        if length.is_some_and(|length| length > MAX_BODY) {
            refuse(&mut response, StatusCode::PAYLOAD_TOO_LARGE, "request body too large\n");
            return response;
        }
        match timeout(BODY_TIMEOUT, Limited::new(body, MAX_BODY).collect()).await {
            Ok(Ok(collected)) => bytes = collected.to_bytes(),
            _ => {
                refuse(&mut response, StatusCode::BAD_REQUEST, "bad request body\n");
                return response;
            }
        }
    }
    let req = Req {
        path: parts.uri.path(),
        query: parts.uri.query().unwrap_or(""),
        host: parts.headers.get(HOST).and_then(|host| host.to_str().ok()),
        post,
        body: &bytes,
    };
    match route(&req) {
        // hyper drops the body of a HEAD response and keeps its length. A
        // dropped stream receiver ends its producer at once.
        Some(reply) => {
            *response.status_mut() = StatusCode::from_u16(reply.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            response.headers_mut().insert(CONTENT_TYPE, reply.content_type.parse().expect("static header"));
            *response.body_mut() = match reply.stream {
                Some(chunks) => {
                    streaming.store(true, Relaxed);
                    Either::Right(Chunks(chunks))
                }
                None => Either::Left(Full::new(match reply.body {
                    Cow::Borrowed(text) => Bytes::from_static(text.as_bytes()),
                    Cow::Owned(text) => Bytes::from(text),
                })),
            };
        }
        None => error(&mut response, StatusCode::NOT_FOUND, "not found\n"),
    }
    response
}

/// An error status with a short text body. Without a body and a content
/// type, browsers show a blank page or save an empty download.
fn error(response: &mut Response<ReplyBody>, status: StatusCode, text: &'static str) {
    *response.status_mut() = status;
    response.headers_mut().insert(CONTENT_TYPE, "text/plain; charset=utf-8".parse().expect("static header"));
    *response.body_mut() = Either::Left(Full::new(Bytes::from_static(text.as_bytes())));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::SocketAddr, sync::Mutex};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpStream,
    };

    /// A listener whose `/stream` holds its connection open (a live tail).
    async fn start(total: usize, per_client: usize) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let senders = Mutex::new(Vec::new());
        let route = move |req: &Req<'_>| match req.path {
            "/healthz" | "/metrics" | "/page" | "/api/x" => Some(Reply::new(200, "text/plain", "ok\n")),
            "/stream" => {
                let (tx, rx) = mpsc::channel(1);
                senders.lock().unwrap().push(tx);
                Some(Reply { stream: Some(rx), ..Reply::new(200, "text/event-stream", "") })
            }
            _ => None,
        };
        (addr, tokio::spawn(serve_limited(listener, route, total, per_client)))
    }

    /// Sends a GET on `stream` and returns the status code, or `None` when
    /// the server closed the connection instead.
    async fn get_on(stream: &mut TcpStream, path: &str) -> Option<u16> {
        send_on(stream, &format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")).await
    }

    async fn send_on(stream: &mut TcpStream, request: &str) -> Option<u16> {
        stream.write_all(request.as_bytes()).await.ok()?;
        let mut head = Vec::new();
        let mut chunk = [0u8; 1024];
        while !head.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = timeout(Duration::from_secs(3), stream.read(&mut chunk)).await.ok()?.ok()?;
            if n == 0 {
                return None;
            }
            head.extend_from_slice(&chunk[..n]);
        }
        std::str::from_utf8(head.get(9..12)?).ok()?.parse().ok()
    }

    async fn get(addr: SocketAddr, path: &str) -> Option<u16> {
        get_on(&mut TcpStream::connect(addr).await.ok()?, path).await
    }

    /// Opens a live tail and keeps its connection.
    async fn hold_stream(addr: SocketAddr) -> TcpStream {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        assert_eq!(get_on(&mut stream, "/stream").await, Some(200));
        stream
    }

    #[tokio::test]
    async fn a_full_pool_still_answers_health_and_metrics() {
        let (addr, server) = start(2, 8).await;
        let _held = [hold_stream(addr).await, hold_stream(addr).await];
        assert_eq!(get(addr, "/healthz").await, Some(200), "the readiness probe is not locked out");
        assert_eq!(get(addr, "/metrics").await, Some(200));
        assert_eq!(get(addr, "/page").await, Some(503), "other pages wait for a slot");
        server.abort();
    }

    #[tokio::test]
    async fn one_host_cannot_take_the_whole_pool() {
        let (addr, server) = start(16, 2).await;
        let _held = [hold_stream(addr).await, hold_stream(addr).await];
        assert_eq!(get(addr, "/page").await, Some(503), "a third connection from the same host gets no full slot");
        assert_eq!(get(addr, "/healthz").await, Some(200));
        server.abort();
    }

    /// The probe lane is counted per host: one address (a remote client of
    /// an exposed UI) filling it leaves the probe's own address its share.
    #[tokio::test]
    async fn one_host_cannot_take_the_whole_probe_lane() {
        // Dual-stack, so 127.0.0.1 and ::1 are two client hosts.
        let Ok(listener) = TcpListener::bind("[::]:0").await else { return };
        let port = listener.local_addr().unwrap().port();
        let route = |_: &Req<'_>| Some(Reply::new(200, "text/plain", "ok\n"));
        // No full slots at all: every connection takes the probe lane.
        let server = tokio::spawn(serve_limited(listener, route, 0, 0));
        let v4 = SocketAddr::from(([127, 0, 0, 1], port));
        let v6 = SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, port));
        if TcpStream::connect(v6).await.is_err() {
            server.abort();
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        // Idle connections hold their lane slot until the head timeout.
        let mut idle = Vec::new();
        for _ in 0..PROBE_CONNECTIONS_PER_CLIENT {
            idle.push(TcpStream::connect(v4).await.unwrap());
        }
        assert_eq!(get(v4, "/healthz").await, None, "the host is at its share of the lane");
        assert_eq!(get(v6, "/healthz").await, Some(200), "another host still gets a probe slot");
        server.abort();
    }

    /// Another site's page can make a browser call the API in the background
    /// (it cannot read the answer, but a live tail would hold a slot); only a
    /// top-level navigation from another site is served.
    #[tokio::test]
    async fn cross_site_api_requests_are_refused() {
        let (addr, server) = start(8, 8).await;
        let navigate = "Sec-Fetch-Mode: navigate\r\nSec-Fetch-Dest: document\r\n";
        for (path, headers, status) in [
            ("/api/x", "Sec-Fetch-Site: cross-site\r\nSec-Fetch-Mode: cors\r\n".to_string(), 403),
            ("/api/x", "Sec-Fetch-Site: same-site\r\nSec-Fetch-Mode: no-cors\r\n".to_string(), 403),
            (
                "/api/x",
                "Sec-Fetch-Site: cross-site\r\nSec-Fetch-Mode: navigate\r\nSec-Fetch-Dest: iframe\r\n".to_string(),
                403,
            ),
            ("/api/x", format!("Sec-Fetch-Site: cross-site\r\n{navigate}"), 200),
            ("/api/x", "Sec-Fetch-Site: same-origin\r\nSec-Fetch-Mode: cors\r\n".to_string(), 200),
            ("/api/x", "Sec-Fetch-Site: none\r\n".to_string(), 200),
            ("/api/x", String::new(), 200),
            ("/page", "Sec-Fetch-Site: cross-site\r\nSec-Fetch-Mode: no-cors\r\n".to_string(), 200),
        ] {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            let request = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n{headers}\r\n");
            assert_eq!(send_on(&mut stream, &request).await, Some(status), "{request}");
        }
        server.abort();
    }

    /// RFC 9112 §3.2: a Host value that is not a valid host (here not even
    /// ASCII) is a 400 on every path, never read as "no Host".
    #[tokio::test]
    async fn an_invalid_host_value_is_a_bad_request() {
        let (addr, server) = start(8, 8).await;
        for path in ["/page", "/healthz"] {
            for version in ["1.1", "1.0"] {
                let mut stream = TcpStream::connect(addr).await.unwrap();
                let mut request = format!("GET {path} HTTP/{version}\r\nHost: ").into_bytes();
                request.extend_from_slice(b"\xff\xfe.example\r\n\r\n");
                stream.write_all(&request).await.unwrap();
                assert_eq!(send_on(&mut stream, "").await, Some(400), "{path} HTTP/{version}");
            }
        }
        server.abort();
    }

    #[tokio::test]
    async fn an_idle_keep_alive_connection_is_closed_quickly() {
        let (addr, server) = start(MAX_CONNECTIONS, MAX_CONNECTIONS_PER_CLIENT).await;
        let mut stream = TcpStream::connect(addr).await.unwrap();
        assert_eq!(get_on(&mut stream, "/healthz").await, Some(200));
        let started = std::time::Instant::now();
        let mut chunk = [0u8; 64];
        let closed =
            timeout(Duration::from_secs(4), async { while stream.read(&mut chunk).await.is_ok_and(|n| n > 0) {} })
                .await;
        assert!(closed.is_ok(), "an idle connection must not hold its slot for long");
        assert!(started.elapsed() >= Duration::from_secs(1), "but keep-alive itself still works");
        server.abort();
    }

    /// The UI's rebinding guard reads one Host, so a second Host line or an
    /// absolute-form target naming another authority is refused outright.
    #[tokio::test]
    async fn ambiguous_host_is_a_bad_request() {
        let (addr, server) = start(8, 8).await;
        for (request, status) in [
            ("GET /page HTTP/1.1\r\nHost: 127.0.0.1\r\nHost: evil.example\r\n\r\n", 400),
            ("GET http://evil.example/page HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", 400),
            ("GET http://127.0.0.1/page HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", 200),
            ("GET http://LOCALHOST:80/page HTTP/1.1\r\nHost: localhost:80\r\n\r\n", 200),
            ("GET /page HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", 200),
        ] {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            assert_eq!(send_on(&mut stream, request).await, Some(status), "{request}");
        }
        server.abort();
    }

    /// RFC 9112 §3.2: an HTTP/1.1 request without Host is a 400; HTTP/1.0
    /// predates Host and may omit it.
    #[tokio::test]
    async fn http11_without_host_is_a_bad_request() {
        let (addr, server) = start(8, 8).await;
        for (request, status) in [
            ("GET /page HTTP/1.1\r\n\r\n", 400),
            ("GET /healthz HTTP/1.1\r\n\r\n", 400),
            ("GET /page HTTP/1.0\r\n\r\n", 200),
        ] {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            assert_eq!(send_on(&mut stream, request).await, Some(status), "{request}");
        }
        server.abort();
    }

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(*name, value.parse().unwrap());
        }
        map
    }

    #[test]
    fn a_post_must_be_same_origin() {
        let host = ("host", "127.0.0.1:9999");
        for ok in [
            vec![host, ("origin", "http://127.0.0.1:9999")],
            vec![host, ("origin", "https://127.0.0.1:9999")],
            vec![host, ("sec-fetch-site", "same-origin")],
            vec![host, ("sec-fetch-site", "same-origin"), ("origin", "http://127.0.0.1:9999")],
        ] {
            assert!(same_origin(&headers(&ok)), "{ok:?}");
        }
        for bad in [
            vec![host],
            vec![host, ("origin", "http://evil.example")],
            vec![host, ("origin", "http://127.0.0.1:1")],
            vec![host, ("origin", "null")],
            vec![host, ("origin", "127.0.0.1:9999")],
            vec![host, ("origin", "ftp://127.0.0.1:9999")],
            vec![host, ("sec-fetch-site", "cross-site")],
            vec![host, ("sec-fetch-site", "same-site")],
            vec![host, ("sec-fetch-site", "none")],
            vec![host, ("sec-fetch-site", "same-origin"), ("origin", "http://evil.example")],
            vec![("origin", "http://127.0.0.1:9999")],
        ] {
            assert!(!same_origin(&headers(&bad)), "{bad:?}");
        }
    }
}
