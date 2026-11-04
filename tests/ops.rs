//! Server-ops integration tests. Each test spawns
//! the real binary against a temp config, so listener limits, reload, `--check`,
//! SIGTERM and structured logs are exercised end to end.

use std::{
    fs,
    io::{Read, Write},
    net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

use hickory_proto::{
    op::{Message, MessageType, OpCode, Query, ResponseCode},
    rr::{
        rdata::{A, CNAME, TXT},
        Name, RData, Record, RecordType,
    },
};

static UNIQUE: AtomicU64 = AtomicU64::new(0);

fn temp_dir(tag: &str) -> PathBuf {
    let unique = UNIQUE.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let dir = std::env::temp_dir().join(format!("sopedu-ops-{tag}-{}-{nanos}-{unique}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// A loopback port free for both UDP and TCP, for a server under test to bind.
/// Port 0 would hand out an ephemeral port that, once released, the kernel can
/// give to a parallel test's outgoing connection before the server binds it.
/// 20000-31999 sits below the ephemeral ranges of Linux (32768+) and macOS
/// (49152+), and the counter keeps tests in this process apart; the start is
/// spread by PID so concurrent test binaries rarely overlap.
fn free_addr() -> SocketAddr {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let base = 20_000 + (std::process::id() as usize * 97) % 12_000;
    for _ in 0..12_000 {
        let port = (20_000 + (base - 20_000 + NEXT.fetch_add(1, Ordering::Relaxed)) % 12_000) as u16;
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        if UdpSocket::bind(addr).is_ok() && TcpListener::bind(addr).is_ok() {
            return addr;
        }
    }
    panic!("no free loopback port in 20000-31999");
}

fn config(addr: SocketAddr, dir: &Path, fallback: &[SocketAddr], extra: &str) -> String {
    let fallback = fallback.iter().map(|addr| format!("\"{addr}\"")).collect::<Vec<_>>().join(", ");
    format!(
        "listen = \"{addr}\"\nstate_dir = \"{}\"\nupstreams = []\nfallback = [{fallback}]\n\
         ui_enabled = false\nupstream_0x20 = false\nforward_test_names = true\n{extra}\n",
        dir.join("state").display()
    )
}

struct Running {
    child: Child,
    dir: PathBuf,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
}

impl Running {
    /// Writes `text` to `<dir>/config.toml` and spawns the server on it. Tests
    /// that reload rewrite the same path, as a ConfigMap update would.
    fn start(dir: &Path, text: &str) -> Self {
        Self::spawn(dir, text, Command::new(env!("CARGO_BIN_EXE_sopedu-dns")))
    }

    /// [`start`](Self::start) with `ca` as the only trust anchor, set through
    /// `SSL_CERT_FILE` as the scratch image does.
    fn start_trusting(dir: &Path, text: &str, ca: &Path) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_sopedu-dns"));
        command.env("SSL_CERT_FILE", ca).env_remove("SSL_CERT_DIR");
        Self::spawn(dir, text, command)
    }

    fn spawn(dir: &Path, text: &str, mut command: Command) -> Self {
        let path = dir.join("config.toml");
        fs::write(&path, text).unwrap();
        let stdout_path = dir.join("stdout.log");
        let stderr_path = dir.join("stderr.log");
        let stdout = fs::File::create(&stdout_path).unwrap();
        let stderr = fs::File::create(&stderr_path).unwrap();
        let child = command.arg(&path).stdout(Stdio::from(stdout)).stderr(Stdio::from(stderr)).spawn().unwrap();
        Self { child, dir: dir.to_path_buf(), stdout_path, stderr_path }
    }

    fn stdout(&self) -> String {
        fs::read_to_string(&self.stdout_path).unwrap_or_default()
    }

    fn stderr(&self) -> String {
        fs::read_to_string(&self.stderr_path).unwrap_or_default()
    }

    fn wait_ready(&mut self) {
        if !eventually(Duration::from_secs(30), || self.stdout().contains("msg=readiness ready=true")) {
            panic!("server never became ready\nstdout:\n{}\nstderr:\n{}", self.stdout(), self.stderr());
        }
    }

    fn signal(&self, signal: &str) {
        let status =
            Command::new("/bin/kill").arg(format!("-{signal}")).arg(self.child.id().to_string()).status().unwrap();
        assert!(status.success(), "kill -{signal} failed");
    }

    fn wait_exit(&mut self, limit: Duration) -> ExitStatus {
        let deadline = Instant::now() + limit;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            if Instant::now() >= deadline {
                panic!("server still running after {limit:?}\nstdout:\n{}", self.stdout());
            }
            thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn eventually(limit: Duration, mut condition: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if condition() {
            return true;
        }
        thread::sleep(Duration::from_millis(50));
    }
    condition()
}

fn query(name: &str, id: u16) -> Vec<u8> {
    let mut message = Message::new(id, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(Name::from_ascii(format!("{name}.")).unwrap(), RecordType::A));
    message.to_vec().unwrap()
}

fn udp_exchange(fallback: SocketAddr, raw: &[u8], limit: Duration) -> Option<Message> {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.set_read_timeout(Some(limit)).unwrap();
    socket.send_to(raw, fallback).unwrap();
    let mut buf = [0u8; 4096];
    let (n, _) = socket.recv_from(&mut buf).ok()?;
    Message::from_vec(&buf[..n]).ok()
}

fn response_code(fallback: SocketAddr, name: &str, id: u16) -> Option<ResponseCode> {
    udp_exchange(fallback, &query(name, id), Duration::from_secs(3)).map(|m| m.metadata.response_code)
}

fn tcp_connect(addr: SocketAddr) -> TcpStream {
    let stream = TcpStream::connect(addr).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    stream.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
    stream
}

fn tcp_send(stream: &mut TcpStream, raw: &[u8]) -> std::io::Result<()> {
    stream.write_all(&u16::try_from(raw.len()).unwrap().to_be_bytes())?;
    stream.write_all(raw)
}

fn tcp_receive(stream: &mut TcpStream) -> std::io::Result<Message> {
    let mut length = [0u8; 2];
    stream.read_exact(&mut length)?;
    let mut raw = vec![0u8; usize::from(u16::from_be_bytes(length))];
    stream.read_exact(&mut raw)?;
    Ok(Message::from_vec(&raw).unwrap())
}

fn is_closed(read: &std::io::Result<usize>) -> bool {
    match read {
        Ok(0) => true,
        Err(error) => matches!(
            error.kind(),
            std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::BrokenPipe
        ),
        Ok(_) => false,
    }
}

struct UdpMock {
    addr: SocketAddr,
    queries: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl UdpMock {
    /// Replies to every query with `192.0.2.<octet> A`, or stays silent when
    /// `respond` is false (a slow/blackholed upstream).
    fn start(octet: u8, respond: bool) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
        let addr = socket.local_addr().unwrap();
        let queries = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let queries = queries.clone();
            let stop = stop.clone();
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while !stop.load(Ordering::Relaxed) {
                    let Ok((n, peer)) = socket.recv_from(&mut buf) else { continue };
                    let Ok(question) = Message::from_vec(&buf[..n]) else { continue };
                    queries.fetch_add(1, Ordering::Relaxed);
                    if !respond {
                        continue;
                    }
                    let mut answer = Message::new(question.metadata.id, MessageType::Response, OpCode::Query);
                    answer.metadata.recursion_available = true;
                    answer.add_queries(question.queries.iter().cloned());
                    if let Some(question) = question.queries.first() {
                        answer.add_answer(Record::from_rdata(
                            question.name().clone(),
                            60,
                            RData::A(A(Ipv4Addr::new(192, 0, 2, octet))),
                        ));
                    }
                    let _ = socket.send_to(&answer.to_vec().unwrap(), peer);
                }
            })
        };
        Self { addr, queries, stop, thread: Some(thread) }
    }
}

impl Drop for UdpMock {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// The UDP bytes a conformant server sends for `answer`: the answer itself, or
/// an empty TC reply when it exceeds what the query advertised (512 without
/// EDNS), so the client retries over TCP (RFC 1035 s4.2.1, RFC 6891 s6.2.5).
/// The binary drops a larger datagram as a fragmentation suspect (RFC 5452 §9.3).
fn udp_reply(question: &Message, answer: Message) -> Vec<u8> {
    let bytes = answer.to_vec().unwrap();
    let limit = question.edns.as_ref().map_or(512, |edns| usize::from(edns.max_payload().max(512)));
    if bytes.len() <= limit {
        return bytes;
    }
    let mut truncated = Message::new(question.metadata.id, MessageType::Response, OpCode::Query);
    truncated.metadata.recursion_available = true;
    truncated.metadata.truncation = true;
    truncated.add_queries(question.queries.iter().cloned());
    truncated.to_vec().unwrap()
}

/// Serves the full `build` answer over TCP on `addr`, the twin of a UDP mock.
fn tcp_twin(
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    build: impl Fn(&Message) -> Message + Send + 'static,
) -> thread::JoinHandle<()> {
    let listener = TcpListener::bind(addr).unwrap();
    listener.set_nonblocking(true).unwrap();
    thread::spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            let Ok((mut stream, _)) = listener.accept() else {
                thread::sleep(Duration::from_millis(10));
                continue;
            };
            stream.set_nonblocking(false).unwrap();
            stream.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
            let mut length = [0u8; 2];
            if stream.read_exact(&mut length).is_err() {
                continue;
            }
            let mut raw = vec![0u8; usize::from(u16::from_be_bytes(length))];
            if stream.read_exact(&mut raw).is_err() {
                continue;
            }
            let Ok(question) = Message::from_vec(&raw) else { continue };
            let bytes = build(&question).to_vec().unwrap();
            let _ = stream.write_all(&u16::try_from(bytes.len()).unwrap().to_be_bytes());
            let _ = stream.write_all(&bytes);
        }
    })
}

/// Answers every query with enough distinct A records to exceed every UDP
/// payload cap; the binary must truncate the UDP reply and keep the full
/// answer for TCP. Conformant upstream: TC over UDP, the full answer over TCP.
struct LargeUdpMock {
    addr: SocketAddr,
    /// UDP queries; the TCP retry of a truncated answer is the same resolution.
    queries: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
    twin: Option<thread::JoinHandle<()>>,
}

impl LargeUdpMock {
    const RECORDS: usize = 100;

    fn answer(question: &Message) -> Message {
        let mut answer = Message::new(question.metadata.id, MessageType::Response, OpCode::Query);
        answer.metadata.recursion_available = true;
        answer.add_queries(question.queries.iter().cloned());
        if let Some(question) = question.queries.first() {
            for index in 1..=Self::RECORDS as u8 {
                answer.add_answer(Record::from_rdata(
                    question.name().clone(),
                    60,
                    RData::A(A(Ipv4Addr::new(192, 0, 2, index))),
                ));
            }
        }
        answer
    }

    fn start() -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
        let addr = socket.local_addr().unwrap();
        let queries = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let twin = tcp_twin(addr, stop.clone(), Self::answer);
        let thread = {
            let queries = queries.clone();
            let stop = stop.clone();
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while !stop.load(Ordering::Relaxed) {
                    let Ok((n, peer)) = socket.recv_from(&mut buf) else { continue };
                    let Ok(question) = Message::from_vec(&buf[..n]) else { continue };
                    queries.fetch_add(1, Ordering::Relaxed);
                    let _ = socket.send_to(&udp_reply(&question, Self::answer(&question)), peer);
                }
            })
        };
        Self { addr, queries, stop, thread: Some(thread), twin: Some(twin) }
    }
}

impl Drop for LargeUdpMock {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for thread in [self.thread.take(), self.twin.take()].into_iter().flatten() {
            let _ = thread.join();
        }
    }
}

/// Answers every query with one cacheable TXT record whose RDATA is larger
/// than 2048 bytes. A warm UDP hit therefore carries
/// a large inline answer through the ordinary asynchronous send.
struct LargeTxtUdpMock {
    addr: SocketAddr,
    /// UDP queries (see [`LargeUdpMock::queries`]).
    queries: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
    twin: Option<thread::JoinHandle<()>>,
}

impl LargeTxtUdpMock {
    /// 12 character-strings of 200 bytes: 2400 bytes of RDATA, above
    /// 2048 bytes and below the 4096-byte UDP cap.
    const STRINGS: usize = 12;
    const STRING_LEN: usize = 200;

    fn answer(question: &Message) -> Message {
        let mut answer = Message::new(question.metadata.id, MessageType::Response, OpCode::Query);
        answer.metadata.recursion_available = true;
        answer.add_queries(question.queries.iter().cloned());
        // Echo EDNS so the cached template matches an EDNS client
        // (the server never adds an unsolicited OPT).
        answer.edns.get_or_insert_with(Default::default).set_max_payload(4096);
        if let Some(question) = question.queries.first() {
            let strings = (0..Self::STRINGS).map(|_| "a".repeat(Self::STRING_LEN)).collect();
            answer.add_answer(Record::from_rdata(question.name().clone(), 60, RData::TXT(TXT::new(strings))));
        }
        answer
    }

    fn start() -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
        let addr = socket.local_addr().unwrap();
        let queries = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let twin = tcp_twin(addr, stop.clone(), Self::answer);
        let thread = {
            let queries = queries.clone();
            let stop = stop.clone();
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while !stop.load(Ordering::Relaxed) {
                    let Ok((n, peer)) = socket.recv_from(&mut buf) else { continue };
                    let Ok(question) = Message::from_vec(&buf[..n]) else { continue };
                    queries.fetch_add(1, Ordering::Relaxed);
                    let _ = socket.send_to(&udp_reply(&question, Self::answer(&question)), peer);
                }
            })
        };
        Self { addr, queries, stop, thread: Some(thread), twin: Some(twin) }
    }
}

impl Drop for LargeTxtUdpMock {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for thread in [self.thread.take(), self.twin.take()].into_iter().flatten() {
            let _ = thread.join();
        }
    }
}

/// Answers every query after `delay` from its own thread, so two requests that
/// arrive together can be answered one delay after arrival rather than one
/// after the other. Used to prove that pipelined queries overlap.
struct DelayedUdpMock {
    addr: SocketAddr,
    queries: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl DelayedUdpMock {
    fn start(octet: u8, delay: Duration) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
        let addr = socket.local_addr().unwrap();
        let replies = socket.try_clone().unwrap();
        let queries = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let queries = queries.clone();
            let stop = stop.clone();
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while !stop.load(Ordering::Relaxed) {
                    let Ok((n, peer)) = socket.recv_from(&mut buf) else { continue };
                    let Ok(question) = Message::from_vec(&buf[..n]) else { continue };
                    queries.fetch_add(1, Ordering::Relaxed);
                    let replies = replies.try_clone().unwrap();
                    thread::spawn(move || {
                        thread::sleep(delay);
                        let mut answer = Message::new(question.metadata.id, MessageType::Response, OpCode::Query);
                        answer.metadata.recursion_available = true;
                        answer.add_queries(question.queries.iter().cloned());
                        if let Some(question) = question.queries.first() {
                            answer.add_answer(Record::from_rdata(
                                question.name().clone(),
                                60,
                                RData::A(A(Ipv4Addr::new(192, 0, 2, octet))),
                            ));
                        }
                        let _ = replies.send_to(&answer.to_vec().unwrap(), peer);
                    });
                }
            })
        };
        Self { addr, queries, stop, thread: Some(thread) }
    }
}

impl Drop for DelayedUdpMock {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

struct HttpMock {
    addr: SocketAddr,
    requests: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl HttpMock {
    fn start(body: &'static str) -> Self {
        Self::start_delayed(body, Duration::ZERO)
    }

    /// Responds after `delay`, so a reload can land while the download is in
    /// flight.
    fn start_delayed(body: &'static str, delay: Duration) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let requests = requests.clone();
            let stop = stop.clone();
            thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let Ok((mut stream, _)) = listener.accept() else {
                        thread::sleep(Duration::from_millis(20));
                        continue;
                    };
                    requests.fetch_add(1, Ordering::Relaxed);
                    stream.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
                    let mut request = Vec::new();
                    let mut buf = [0u8; 1024];
                    while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                        match stream.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => request.extend_from_slice(&buf[..n]),
                        }
                    }
                    thread::sleep(delay);
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes());
                }
            })
        };
        Self { addr, requests, stop, thread: Some(thread) }
    }
}

impl Drop for HttpMock {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// A DoH upstream over TLS (HTTP/1.1, one request per connection) serving
/// the `tests/tls` certificate `leaf`, answering every query with
/// `192.0.2.7 A`. It records the requests it answered and the handshake
/// errors it saw, so a test can tell a rejected certificate from a network
/// failure.
struct DohTlsMock {
    addr: SocketAddr,
    served: Arc<AtomicUsize>,
    handshake_errors: Arc<std::sync::Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl DohTlsMock {
    fn start(leaf: &str) -> Self {
        use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/tls");
        let chain = CertificateDer::pem_file_iter(dir.join(leaf)).unwrap().collect::<Result<Vec<_>, _>>().unwrap();
        let key = PrivateKeyDer::from_pem_file(dir.join("leaf.key")).unwrap();
        let mut config =
            rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(chain, key)
                .unwrap();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let config = Arc::new(config);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let served = Arc::new(AtomicUsize::new(0));
        let handshake_errors = Arc::new(std::sync::Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let (served, handshake_errors, stop) = (served.clone(), handshake_errors.clone(), stop.clone());
            thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let Ok((tcp, _)) = listener.accept() else {
                        thread::sleep(Duration::from_millis(20));
                        continue;
                    };
                    let (config, served, handshake_errors) = (config.clone(), served.clone(), handshake_errors.clone());
                    thread::spawn(move || {
                        tcp.set_nonblocking(false).unwrap();
                        tcp.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                        let mut tls = rustls::StreamOwned::new(rustls::ServerConnection::new(config).unwrap(), tcp);
                        while tls.conn.is_handshaking() {
                            if let Err(error) = tls.conn.complete_io(&mut tls.sock) {
                                handshake_errors.lock().unwrap().push(error.to_string());
                                return;
                            }
                        }
                        if Self::serve(&mut tls).is_some() {
                            served.fetch_add(1, Ordering::Relaxed);
                        }
                    });
                }
            })
        };
        Self { addr, served, handshake_errors, stop, thread: Some(thread) }
    }

    fn serve(tls: &mut (impl Read + Write)) -> Option<()> {
        let mut request = Vec::new();
        let mut buf = [0u8; 1024];
        let header_end = loop {
            if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                break end + 4;
            }
            let n = tls.read(&mut buf).ok().filter(|&n| n > 0)?;
            request.extend_from_slice(&buf[..n]);
        };
        let headers = String::from_utf8_lossy(&request[..header_end]).to_ascii_lowercase();
        let length: usize =
            headers.lines().find_map(|line| line.strip_prefix("content-length:"))?.trim().parse().ok()?;
        while request.len() < header_end + length {
            let n = tls.read(&mut buf).ok().filter(|&n| n > 0)?;
            request.extend_from_slice(&buf[..n]);
        }
        let question = Message::from_vec(&request[header_end..header_end + length]).ok()?;
        let mut answer = Message::new(question.metadata.id, MessageType::Response, OpCode::Query);
        answer.metadata.recursion_desired = question.metadata.recursion_desired;
        answer.metadata.recursion_available = true;
        answer.add_queries(question.queries.iter().cloned());
        let name = question.queries.first()?.name().clone();
        answer.add_answer(Record::from_rdata(name, 60, RData::A(A(Ipv4Addr::new(192, 0, 2, 7)))));
        let body = answer.to_vec().ok()?;
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        tls.write_all(head.as_bytes()).ok()?;
        tls.write_all(&body).ok()?;
        tls.flush().ok()
    }

    fn url(&self) -> String {
        format!("https://{}/dns-query", self.addr)
    }
}

impl Drop for DohTlsMock {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn first_a(message: &Message) -> Option<Ipv4Addr> {
    message.answers.iter().find_map(|record| match &record.data {
        RData::A(address) => Some(address.0),
        _ => None,
    })
}

#[test]
fn udp_keeps_serving_when_tcp_connections_are_exhausted() {
    let addr = free_addr();
    let dir = temp_dir("tcp-saturation");
    let text = config(
        addr,
        &dir,
        &[],
        "tcp_max_connections = 1\ntcp_idle_timeout_seconds = 5\nuser_rules = [\"||blocked.test^\"]",
    );
    let mut server = Running::start(&dir, &text);
    server.wait_ready();

    let idle = tcp_connect(addr);
    thread::sleep(Duration::from_millis(200));
    assert_eq!(response_code(addr, "blocked.test", 1), Some(ResponseCode::NXDomain), "UDP must not queue behind TCP");

    let mut second = tcp_connect(addr);
    let mut byte = [0u8; 1];
    assert!(is_closed(&second.read(&mut byte)), "a connection over tcp_max_connections is closed, not queued");

    assert_eq!(response_code(addr, "blocked.test", 2), Some(ResponseCode::NXDomain));
    drop(idle);
}

#[test]
fn tcp_per_client_cap_closes_the_surplus_connection() {
    // One host cannot take every shared connection permit.
    let addr = free_addr();
    let dir = temp_dir("tcp-per-client");
    let text = config(
        addr,
        &dir,
        &[],
        "tcp_max_connections = 8\ntcp_max_connections_per_client = 2\ntcp_idle_timeout_seconds = 5\n\
         user_rules = [\"||blocked.test^\"]",
    );
    let mut server = Running::start(&dir, &text);
    server.wait_ready();

    let first = tcp_connect(addr);
    let mut second = tcp_connect(addr);
    thread::sleep(Duration::from_millis(200));
    let mut third = tcp_connect(addr);
    let mut byte = [0u8; 1];
    assert!(is_closed(&third.read(&mut byte)), "the third connection from one address is closed, not queued");
    // The two admitted connections still work.
    tcp_send(&mut second, &query("blocked.test", 7)).unwrap();
    assert_eq!(tcp_receive(&mut second).unwrap().metadata.response_code, ResponseCode::NXDomain);
    // A freed slot is reusable.
    drop(first);
    thread::sleep(Duration::from_millis(300));
    let mut again = tcp_connect(addr);
    tcp_send(&mut again, &query("blocked.test", 8)).unwrap();
    assert_eq!(tcp_receive(&mut again).unwrap().metadata.response_code, ResponseCode::NXDomain);
}

#[test]
fn tcp_connections_from_disallowed_clients_are_closed_at_accept() {
    // The ACL runs right after accept, before any permit is taken.
    let addr = free_addr();
    let dir = temp_dir("tcp-acl");
    let text = config(
        addr,
        &dir,
        &[],
        "allowed_clients = [\"192.0.2.0/24\"]\ntcp_max_connections = 1\ntcp_idle_timeout_seconds = 5",
    );
    let mut server = Running::start(&dir, &text);
    server.wait_ready();

    let mut outsider = tcp_connect(addr);
    let mut byte = [0u8; 1];
    assert!(is_closed(&outsider.read(&mut byte)), "a disallowed client is closed immediately");
    let _ = tcp_send(&mut outsider, &query("blocked.test", 1));
}

#[test]
fn tcp_idle_timeout_closes_the_connection() {
    let addr = free_addr();
    let dir = temp_dir("tcp-idle");
    let text = config(addr, &dir, &[], "tcp_idle_timeout_seconds = 1\nuser_rules = [\"||blocked.test^\"]");
    let mut server = Running::start(&dir, &text);
    server.wait_ready();

    let mut stream = tcp_connect(addr);
    let started = Instant::now();
    let mut byte = [0u8; 1];
    assert!(is_closed(&stream.read(&mut byte)), "an idle connection is closed by the server");
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn tcp_idle_timeout_does_not_cut_an_active_query() {
    let addr = free_addr();
    let dir = temp_dir("tcp-slow-query");
    let blackhole = UdpMock::start(1, false);
    let text = config(addr, &dir, &[blackhole.addr], "tcp_idle_timeout_seconds = 2\nupstream_timeout_seconds = 5");
    let mut server = Running::start(&dir, &text);
    server.wait_ready();

    let mut stream = tcp_connect(addr);
    // Longer than the upstream deadline; the client must see the bounded
    // SERVFAIL, not an idle-timeout close at two seconds.
    stream.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
    let started = Instant::now();
    tcp_send(&mut stream, &query("slow.test", 1)).unwrap();
    let answer = match tcp_receive(&mut stream) {
        Ok(answer) => answer,
        Err(error) => panic!("the slow query must get an answer, not an idle close: {error}\n{}", server.stdout()),
    };
    assert_eq!(answer.metadata.response_code, ResponseCode::ServFail);
    assert!(
        started.elapsed() >= Duration::from_secs(4),
        "the query waited for the upstream deadline, not the idle timeout: {:?}",
        started.elapsed()
    );
    assert!(started.elapsed() < Duration::from_secs(7), "the answer is bounded by upstream_timeout_seconds");
}

#[test]
fn a_read_timeout_is_not_a_closed_connection() {
    let addr = free_addr();
    let dir = temp_dir("tcp-idle-open");
    let text = config(addr, &dir, &[], "tcp_idle_timeout_seconds = 30\nuser_rules = [\"||blocked.test^\"]");
    let mut server = Running::start(&dir, &text);
    server.wait_ready();

    let mut stream = tcp_connect(addr);
    stream.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
    let mut byte = [0u8; 1];
    let read = stream.read(&mut byte);
    assert!(!is_closed(&read), "a read timeout is not EOF or a reset: {read:?}");
    assert!(
        matches!(&read, Err(error) if matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut)),
        "the short read times out client-side: {read:?}"
    );

    // The same connection still carries a query.
    stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    tcp_send(&mut stream, &query("blocked.test", 1)).unwrap();
    let answer = tcp_receive(&mut stream).expect("an idle connection stays open");
    assert_eq!(answer.metadata.response_code, ResponseCode::NXDomain);
}

#[test]
fn tcp_query_cap_closes_the_connection() {
    let addr = free_addr();
    let dir = temp_dir("tcp-cap");
    let text = config(addr, &dir, &[], "tcp_queries_per_connection = 2\nuser_rules = [\"||blocked.test^\"]");
    let mut server = Running::start(&dir, &text);
    server.wait_ready();

    let mut stream = tcp_connect(addr);
    // Both are pipelined before either answer is read; the cap still counts
    // frames, not completed responses.
    tcp_send(&mut stream, &query("blocked.test", 1)).unwrap();
    tcp_send(&mut stream, &query("blocked.test", 2)).unwrap();
    let mut ids = Vec::new();
    for _ in 0..2 {
        let answer = tcp_receive(&mut stream).unwrap();
        assert_eq!(answer.metadata.response_code, ResponseCode::NXDomain);
        ids.push(answer.metadata.id);
    }
    ids.sort_unstable();
    assert_eq!(ids, vec![1, 2]);
    // The third query is not answered: the handler returns and drops the socket.
    let _ = tcp_send(&mut stream, &query("blocked.test", 3));
    let mut length = [0u8; 2];
    assert!(is_closed(&stream.read(&mut length)), "the query cap must close the connection");
}

#[test]
fn tcp_connection_serves_more_than_the_old_default_cap() {
    let addr = free_addr();
    let dir = temp_dir("tcp-default-cap");
    let text = config(addr, &dir, &[], "user_rules = [\"||blocked.test^\"]");
    let mut server = Running::start(&dir, &text);
    server.wait_ready();

    // The default cap is the 65536 validation maximum. A pipelined client
    // sends 100 frames before reading; the former 64 default would close the
    // connection after 64 of them.
    let mut stream = tcp_connect(addr);
    stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let ids: Vec<u16> = (1..=100).collect();
    for id in &ids {
        tcp_send(&mut stream, &query("blocked.test", *id)).unwrap();
    }
    let mut seen = Vec::new();
    for _ in &ids {
        let answer = tcp_receive(&mut stream).expect("every query on one connection is answered");
        assert_eq!(answer.metadata.response_code, ResponseCode::NXDomain);
        seen.push(answer.metadata.id);
    }
    seen.sort_unstable();
    assert_eq!(seen, ids);

    // The connection is still open after 100 answers.
    tcp_send(&mut stream, &query("blocked.test", 101)).unwrap();
    let answer = tcp_receive(&mut stream).expect("the default cap does not close after 100 queries");
    assert_eq!(answer.metadata.id, 101);
}

#[test]
fn tcp_pipelined_queries_get_their_own_answers() {
    let addr = free_addr();
    let dir = temp_dir("tcp-pipeline");
    let text = config(addr, &dir, &[], "tcp_pipeline_max = 16\nuser_rules = [\"||blocked.test^\"]");
    let mut server = Running::start(&dir, &text);
    server.wait_ready();

    let mut stream = tcp_connect(addr);
    stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let ids: Vec<u16> = (100..108).collect();
    // Send the whole pipeline before reading any answer.
    for (index, id) in ids.iter().enumerate() {
        tcp_send(&mut stream, &query(&format!("q{index}.blocked.test"), *id)).unwrap();
    }
    let mut seen = Vec::new();
    for _ in &ids {
        let answer = tcp_receive(&mut stream).expect("every pipelined query is answered");
        assert_eq!(answer.metadata.response_code, ResponseCode::NXDomain);
        let name = answer.queries[0].name().to_ascii().trim_end_matches('.').to_string();
        seen.push((answer.metadata.id, name));
    }
    // Replies may arrive out of order (RFC 7766 §7); the ID/question pairing
    // must not cross over.
    seen.sort_unstable();
    let expected: Vec<(u16, String)> =
        ids.iter().enumerate().map(|(index, id)| (*id, format!("q{index}.blocked.test"))).collect();
    assert_eq!(seen, expected);
}

#[test]
fn tcp_pipelined_queries_run_concurrently() {
    let addr = free_addr();
    let dir = temp_dir("tcp-overlap");
    let upstream = DelayedUdpMock::start(7, Duration::from_millis(700));
    let text =
        config(addr, &dir, &[upstream.addr], "tcp_pipeline_max = 4\ncache_size = 0\nupstream_timeout_seconds = 5");
    let mut server = Running::start(&dir, &text);
    server.wait_ready();

    let mut stream = tcp_connect(addr);
    stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let started = Instant::now();
    tcp_send(&mut stream, &query("first.test", 41)).unwrap();
    tcp_send(&mut stream, &query("second.test", 42)).unwrap();
    let mut ids = Vec::new();
    for _ in 0..2 {
        let answer = tcp_receive(&mut stream).expect("both pipelined queries are answered");
        assert_eq!(first_a(&answer), Some(Ipv4Addr::new(192, 0, 2, 7)));
        ids.push(answer.metadata.id);
    }
    ids.sort_unstable();
    assert_eq!(ids, vec![41, 42]);
    let elapsed = started.elapsed();
    // Two 700 ms upstream delays answered in one delay means both were in
    // flight together; a serialized exchange would need at least 1400 ms.
    assert!(elapsed < Duration::from_millis(1300), "the two queries overlapped in flight: {elapsed:?}");
}

#[test]
fn tcp_pipeline_cap_stops_reading_and_answers_everything() {
    let addr = free_addr();
    let dir = temp_dir("tcp-backpressure");
    let upstream = DelayedUdpMock::start(8, Duration::from_millis(700));
    let text =
        config(addr, &dir, &[upstream.addr], "tcp_pipeline_max = 1\ncache_size = 0\nupstream_timeout_seconds = 5");
    let mut server = Running::start(&dir, &text);
    server.wait_ready();

    let mut stream = tcp_connect(addr);
    stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let started = Instant::now();
    tcp_send(&mut stream, &query("one.test", 51)).unwrap();
    tcp_send(&mut stream, &query("two.test", 52)).unwrap();
    let mut ids = Vec::new();
    for _ in 0..2 {
        let answer = tcp_receive(&mut stream).expect("backpressure must not drop a query");
        assert_eq!(first_a(&answer), Some(Ipv4Addr::new(192, 0, 2, 8)));
        ids.push(answer.metadata.id);
    }
    ids.sort_unstable();
    assert_eq!(ids, vec![51, 52]);
    let elapsed = started.elapsed();
    // The cap is one, so the second frame is not even read until the first
    // exchange finishes: two delays, not one.
    assert!(elapsed >= Duration::from_millis(1300), "a full pipeline stops reading: {elapsed:?}");
}

#[test]
fn tcp_half_close_still_receives_an_in_flight_answer() {
    let addr = free_addr();
    let dir = temp_dir("tcp-half-close");
    let upstream = DelayedUdpMock::start(6, Duration::from_millis(700));
    let text =
        config(addr, &dir, &[upstream.addr], "tcp_pipeline_max = 4\ncache_size = 0\nupstream_timeout_seconds = 5");
    let mut server = Running::start(&dir, &text);
    server.wait_ready();

    let mut stream = tcp_connect(addr);
    stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    tcp_send(&mut stream, &query("half-close.test", 77)).unwrap();
    // One-shot clients half-close after writing; the FIN must not abort a
    // query that is still waiting on a slow upstream.
    stream.shutdown(Shutdown::Write).unwrap();
    let answer = tcp_receive(&mut stream)
        .unwrap_or_else(|error| panic!("a half-closed client still gets its in-flight answer: {error}"));
    assert_eq!(answer.metadata.id, 77);
    assert_eq!(answer.queries.len(), 1);
    assert_eq!(answer.queries[0].name().to_ascii(), "half-close.test.");
    assert_eq!(first_a(&answer), Some(Ipv4Addr::new(192, 0, 2, 6)));
}

#[test]
fn sigterm_drains_in_flight_pipelined_queries() {
    let addr = free_addr();
    let dir = temp_dir("tcp-shutdown-pipeline");
    let upstream = DelayedUdpMock::start(9, Duration::from_millis(600));
    let text =
        config(addr, &dir, &[upstream.addr], "tcp_pipeline_max = 8\ncache_size = 0\nupstream_timeout_seconds = 5");
    let mut server = Running::start(&dir, &text);
    server.wait_ready();

    let mut stream = tcp_connect(addr);
    stream.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
    for id in 1..=4 {
        tcp_send(&mut stream, &query(&format!("slow{id}.test"), id)).unwrap();
    }
    assert!(
        eventually(Duration::from_secs(3), || upstream.queries.load(Ordering::Relaxed) == 4),
        "all four queries are in flight before shutdown:\n{}",
        server.stdout()
    );

    let started = Instant::now();
    server.signal("TERM");
    let mut ids = Vec::new();
    for _ in 0..4 {
        let answer = tcp_receive(&mut stream).expect("in-flight answers are drained after SIGTERM");
        assert_eq!(first_a(&answer), Some(Ipv4Addr::new(192, 0, 2, 9)));
        ids.push(answer.metadata.id);
    }
    ids.sort_unstable();
    assert_eq!(ids, vec![1, 2, 3, 4]);
    let status = server.wait_exit(Duration::from_secs(5));
    assert!(status.success(), "the drained shutdown exits 0, got {status:?}");
    assert!(started.elapsed() < Duration::from_secs(5), "the drain stays within the bound");
}

#[test]
fn tcp_framing_errors_close_the_connection() {
    let addr = free_addr();
    let dir = temp_dir("tcp-framing");
    let text = config(addr, &dir, &[], "user_rules = [\"||blocked.test^\"]");
    let mut server = Running::start(&dir, &text);
    server.wait_ready();

    let mut zero = tcp_connect(addr);
    zero.write_all(&[0, 0]).unwrap();
    let mut byte = [0u8; 1];
    assert!(is_closed(&zero.read(&mut byte)), "a zero-length frame closes the connection");

    let mut short = tcp_connect(addr);
    short.write_all(&[0, 5]).unwrap();
    short.write_all(&[0u8; 5]).unwrap();
    assert!(is_closed(&short.read(&mut byte)), "a frame shorter than 12 bytes closes the connection");
}

#[test]
fn udp_truncates_a_large_answer_and_tcp_gets_the_full_answer() {
    let addr = free_addr();
    let dir = temp_dir("udp-truncation");
    let upstream = LargeUdpMock::start();
    let text = config(addr, &dir, &[upstream.addr], "");
    let mut server = Running::start(&dir, &text);
    server.wait_ready();

    // EDNS advertises 4096 but the configured 1232 cap wins.
    let mut edns = Message::new(1, MessageType::Query, OpCode::Query);
    edns.metadata.recursion_desired = true;
    edns.add_query(Query::query(Name::from_ascii("big.test.").unwrap(), RecordType::A));
    edns.edns.get_or_insert_with(Default::default).set_max_payload(4096);
    let truncated = udp_exchange(addr, &edns.to_vec().unwrap(), Duration::from_secs(5)).expect("EDNS UDP reply");
    assert!(truncated.metadata.truncation, "an over-cap UDP answer sets TC");
    assert_eq!(truncated.metadata.id, 1, "the client ID is preserved");
    assert_eq!(truncated.metadata.response_code, ResponseCode::NoError);
    assert!(truncated.answers.is_empty(), "a TC reply carries no answers");
    assert!(!truncated.metadata.authentic_data, "a truncated relay is not authenticated data");
    assert_eq!(truncated.queries.len(), 1, "the question is echoed");
    assert_eq!(truncated.queries[0].name().to_ascii(), "big.test.");
    assert_eq!(
        truncated.edns.as_ref().map(hickory_proto::op::Edns::max_payload),
        Some(1232),
        "an EDNS client gets an OPT advertising the applied cap"
    );

    // No EDNS: the 512-byte cap applies and the reply carries no OPT.
    let plain = udp_exchange(addr, &query("big.test", 2), Duration::from_secs(5)).expect("plain UDP reply");
    assert!(plain.metadata.truncation, "a non-EDNS answer over 512 bytes sets TC");
    assert_eq!(plain.metadata.id, 2);
    assert!(plain.answers.is_empty());
    assert_eq!(plain.queries[0].name().to_ascii(), "big.test.");
    assert!(plain.edns.is_none(), "a non-EDNS client gets no OPT");

    // Both UDP probes fetched because the over-cap-chain answer is never
    // cached, not because the keys differ. EDNS presence is part of the
    // canonical key as well, but that is not the cause here.
    let forwarded = upstream.queries.load(Ordering::Relaxed);
    assert_eq!(forwarded, 2, "both UDP probes fetched: the answer is never cached");

    // The full answer is relayed uncapped over TCP. It is not served from the
    // cache here: a 100-record RRset exceeds the 64-record chain cap in
    // `wire::terminal_answer`, which classifies such an answer as
    // non-terminal, and only terminal answers are cached. The TCP retry is
    // therefore a third upstream query today; if the chain-cap follow-up
    // makes the answer cacheable, it becomes a hit instead. Smaller
    // (cacheable) answers are covered by the crate-level truncation test in
    // `src/main.rs`.
    let mut stream = tcp_connect(addr);
    stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    tcp_send(&mut stream, &query("big.test", 3)).unwrap();
    let full = tcp_receive(&mut stream).expect("the full answer over TCP");
    assert!(!full.metadata.truncation, "TCP is never capped");
    assert_eq!(full.metadata.id, 3, "the TCP client ID is preserved");
    assert_eq!(full.queries[0].name().to_ascii(), "big.test.");
    let addresses: Vec<Ipv4Addr> = full
        .answers
        .iter()
        .filter_map(|record| match record.data {
            RData::A(address) => Some(address.0),
            _ => None,
        })
        .collect();
    let expected: Vec<Ipv4Addr> =
        (1..=LargeUdpMock::RECORDS as u8).map(|index| Ipv4Addr::new(192, 0, 2, index)).collect();
    assert_eq!(addresses, expected, "the full answer survived the UDP truncation");
    let after_tcp = upstream.queries.load(Ordering::Relaxed);
    assert!(
        after_tcp <= forwarded + 1,
        "TCP fetched at most once (a cache hit stays green): {after_tcp} > {forwarded} + 1"
    );
}

#[test]
fn udp_inflight_max_drops_excess_without_stopping_the_listener() {
    let addr = free_addr();
    let dir = temp_dir("udp-inflight");
    let blackhole = UdpMock::start(1, false);
    let text = config(
        addr,
        &dir,
        &[blackhole.addr],
        "udp_inflight_max = 1\nupstream_timeout_seconds = 1\nuser_rules = [\"||blocked.test^\"]",
    );
    let mut server = Running::start(&dir, &text);
    server.wait_ready();

    let first = UdpSocket::bind("127.0.0.1:0").unwrap();
    first.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    first.send_to(&query("a.test", 1), addr).unwrap();
    assert!(
        eventually(Duration::from_secs(3), || blackhole.queries.load(Ordering::Relaxed) >= 1),
        "the first query must occupy the single UDP permit"
    );

    assert!(
        udp_exchange(addr, &query("b.test", 2), Duration::from_millis(500)).is_none(),
        "a second in-flight packet is dropped, not queued"
    );

    let mut buf = [0u8; 4096];
    let (n, _) = first.recv_from(&mut buf).expect("the first query still gets a bounded SERVFAIL");
    assert_eq!(Message::from_vec(&buf[..n]).unwrap().metadata.response_code, ResponseCode::ServFail);
    assert_eq!(response_code(addr, "blocked.test", 3), Some(ResponseCode::NXDomain), "the listener is still alive");
    assert!(eventually(Duration::from_secs(2), || server.stdout().contains("msg=udp_inflight_full")));
}

/// Two SO_REUSEPORT sockets share the listen address, so two client
/// source ports both get answers and TCP still serves the same port.
#[test]
fn udp_workers_share_the_port_and_tcp_still_answers() {
    let addr = free_addr();
    let dir = temp_dir("udp-workers");
    let text = config(addr, &dir, &[], "udp_workers = 2\nworker_threads = 2\nuser_rules = [\"||blocked.test^\"]");
    let mut server = Running::start(&dir, &text);
    server.wait_ready();
    let stdout = server.stdout();
    assert!(stdout.contains("udp_workers=2"), "the startup log reports the worker count:\n{stdout}");
    assert!(stdout.contains("worker_threads=2"), "the startup log reports the runtime thread count:\n{stdout}");
    assert!(stdout.contains("udp_rcvbuf_bytes="), "the startup log reports the effective receive buffer:\n{stdout}");
    assert!(stdout.contains("udp_sndbuf_bytes="), "the startup log reports the effective send buffer:\n{stdout}");

    let clients = [UdpSocket::bind("127.0.0.1:0").unwrap(), UdpSocket::bind("127.0.0.1:0").unwrap()];
    assert_ne!(
        clients[0].local_addr().unwrap().port(),
        clients[1].local_addr().unwrap().port(),
        "the two clients use different source ports"
    );
    for client in &clients {
        client.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        client.send_to(&query("blocked.test", 7), addr).unwrap();
    }
    for client in &clients {
        let mut buf = [0u8; 4096];
        let (n, _) = client.recv_from(&mut buf).expect("each source port gets its answer");
        let answer = Message::from_vec(&buf[..n]).unwrap();
        assert_eq!(answer.metadata.id, 7);
        assert_eq!(answer.queries[0].name().to_ascii(), "blocked.test.");
        assert_eq!(answer.metadata.response_code, ResponseCode::NXDomain);
    }

    let mut stream = tcp_connect(addr);
    tcp_send(&mut stream, &query("blocked.test", 9)).unwrap();
    let answer = tcp_receive(&mut stream).expect("TCP shares the listen port with the UDP workers");
    assert_eq!(answer.metadata.id, 9);
    assert_eq!(answer.metadata.response_code, ResponseCode::NXDomain);
}

/// `listen` as an array: one IPv4 and one IPv6 loopback address, each with its
/// own UDP and TCP listener, both answered by the same server.
#[test]
fn listen_array_serves_ipv4_and_ipv6_over_udp_and_tcp() {
    let Ok(probe) = UdpSocket::bind("[::1]:0") else {
        eprintln!("skipped: no IPv6 loopback on this host");
        return;
    };
    let v6 = probe.local_addr().unwrap();
    drop(probe);
    let v4 = free_addr();
    let dir = temp_dir("listen-array");
    let text = config(v4, &dir, &[], "user_rules = [\"||blocked.test^\"]").replacen(
        &format!("listen = \"{v4}\""),
        &format!("listen = [\"{v4}\", \"{v6}\"]"),
        1,
    );
    let mut server = Running::start(&dir, &text);
    server.wait_ready();
    let stdout = server.stdout();
    for addr in [v4, v6] {
        assert!(stdout.contains(&format!("msg=listening addr={addr} ")), "one listening line per address:\n{stdout}");
    }
    for (id, addr) in [(1, v4), (2, v6)] {
        let socket = UdpSocket::bind(if addr.is_ipv6() { "[::1]:0" } else { "127.0.0.1:0" }).unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        socket.send_to(&query("blocked.test", id), addr).unwrap();
        let mut buf = [0u8; 4096];
        let (n, _) = socket.recv_from(&mut buf).unwrap_or_else(|e| panic!("no UDP answer on {addr}: {e}"));
        let answer = Message::from_vec(&buf[..n]).unwrap();
        assert_eq!((answer.metadata.id, answer.metadata.response_code), (id, ResponseCode::NXDomain));

        let mut stream = tcp_connect(addr);
        tcp_send(&mut stream, &query("blocked.test", id + 10)).unwrap();
        let answer = tcp_receive(&mut stream).unwrap_or_else(|e| panic!("no TCP answer on {addr}: {e}"));
        assert_eq!((answer.metadata.id, answer.metadata.response_code), (id + 10, ResponseCode::NXDomain));
    }
}

/// A repeated `listen` address is rejected at validation, naming the address.
#[test]
fn check_rejects_a_duplicate_listen_address() {
    let addr = free_addr();
    let dir = temp_dir("listen-dup");
    let path = dir.join("config.toml");
    let text = config(addr, &dir, &[], "").replacen(
        &format!("listen = \"{addr}\""),
        &format!("listen = [\"{addr}\", \"{addr}\"]"),
        1,
    );
    fs::write(&path, text).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_sopedu-dns")).arg("--check").arg(&path).output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(&format!("duplicate listen address {addr}")), "{stderr}");
    let _ = fs::remove_dir_all(&dir);
}

/// `udp_batch = 4` drives the batched receive path on Linux and is
/// accepted with one warning elsewhere; either way several warm UDP cache
/// hits are answered correctly from two client sockets.
#[test]
fn udp_batch_answers_warm_hits_over_udp() {
    let addr = free_addr();
    let dir = temp_dir("udp-batch");
    let upstream = UdpMock::start(9, true);
    let text = config(addr, &dir, &[upstream.addr], "udp_batch = 4\ncache_size = 1000\nworker_threads = 2");
    let mut server = Running::start(&dir, &text);
    server.wait_ready();
    let stdout = server.stdout();
    if cfg!(target_os = "linux") {
        assert!(stdout.contains("udp_batch=4"), "the batched path is active:\n{stdout}");
    } else {
        assert!(stdout.contains("msg=udp_batch_unsupported"), "the ignored key is reported:\n{stdout}");
        assert!(stdout.contains("udp_batch=0"), "the listening line reports the effective value:\n{stdout}");
    }

    // An 8 KB query (2000 empty OPT options) is answered, not truncated away
    // by a small batch slot. `localhost` is answered locally, so only
    // the receive path is under test.
    let mut big = query("localhost", 7);
    big[11] = 1; // ARCOUNT
    big.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0]);
    big.extend_from_slice(&8000u16.to_be_bytes());
    for _ in 0..2000 {
        big.extend_from_slice(&[0xfd, 0xe9, 0, 0]);
    }
    assert!(udp_exchange(addr, &big, Duration::from_secs(3)).is_some(), "a large UDP query gets a reply");

    let cold = udp_exchange(addr, &query("batched.test", 1), Duration::from_secs(3)).expect("cold answer");
    assert_eq!(first_a(&cold), Some(Ipv4Addr::new(192, 0, 2, 9)));
    assert_eq!(upstream.queries.load(Ordering::Relaxed), 1);

    // Ten warm hits from two sockets: on Linux the receive loop drains them in
    // batches and each inline reply goes out with the async send.
    let clients = [UdpSocket::bind("127.0.0.1:0").unwrap(), UdpSocket::bind("127.0.0.1:0").unwrap()];
    for client in &clients {
        client.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    }
    for (i, client) in clients.iter().cycle().take(10).enumerate() {
        client.send_to(&query("batched.test", 100 + i as u16), addr).unwrap();
    }
    for (index, client) in clients.iter().enumerate() {
        let mut ids = Vec::new();
        for _ in 0..5 {
            let mut buf = [0u8; 4096];
            let (n, _) = client.recv_from(&mut buf).expect("every warm hit is answered");
            let answer = Message::from_vec(&buf[..n]).unwrap();
            assert_eq!(first_a(&answer), Some(Ipv4Addr::new(192, 0, 2, 9)));
            ids.push(answer.metadata.id);
        }
        ids.sort_unstable();
        let expected: Vec<u16> = (100..110).filter(|id| (id - 100) % 2 == index as u16).collect();
        assert_eq!(ids, expected, "each socket gets the answers for its own queries");
    }
    assert_eq!(upstream.queries.load(Ordering::Relaxed), 1, "warm hits never reach the upstream");
}

/// Large inline replies are not lost on the send path. A warm hit whose
/// answer exceeds 2048 bytes is still delivered over UDP,
/// with the client ID restored and no upstream query.
#[test]
fn udp_batch_delivers_a_large_inline_hit() {
    let addr = free_addr();
    let dir = temp_dir("udp-batch-large");
    let upstream = LargeTxtUdpMock::start();
    let text = config(addr, &dir, &[upstream.addr], "udp_batch = 4\nudp_max_payload = 4096\ncache_size = 1000");
    let mut server = Running::start(&dir, &text);
    server.wait_ready();

    let request = |id: u16| {
        let mut query = Message::new(id, MessageType::Query, OpCode::Query);
        query.metadata.recursion_desired = true;
        query.add_query(Query::query(Name::from_ascii("large-hit.test.").unwrap(), RecordType::TXT));
        query.edns.get_or_insert_with(Default::default).set_max_payload(4096);
        query.to_vec().unwrap()
    };
    let txt_len = |answer: &Message| -> usize {
        answer
            .answers
            .iter()
            .filter_map(|record| match &record.data {
                RData::TXT(txt) => Some(txt.txt_data.iter().map(|part| part.len()).sum::<usize>()),
                _ => None,
            })
            .sum()
    };
    let expected = LargeTxtUdpMock::STRINGS * LargeTxtUdpMock::STRING_LEN;

    let cold = udp_exchange(addr, &request(1), Duration::from_secs(5)).expect("cold answer");
    assert_eq!(cold.metadata.id, 1);
    assert!(!cold.metadata.truncation, "the answer fits the configured 4096-byte cap");
    assert_eq!(txt_len(&cold), expected);
    assert_eq!(upstream.queries.load(Ordering::Relaxed), 1);

    let warm = udp_exchange(addr, &request(2), Duration::from_secs(5)).expect("warm answer");
    assert_eq!(warm.metadata.id, 2, "the client ID is restored");
    assert_eq!(warm.metadata.response_code, ResponseCode::NoError);
    assert!(!warm.metadata.truncation, "a warm inline answer is not truncated");
    assert_eq!(txt_len(&warm), expected, "the full large answer arrives");
    assert!(warm.to_vec().unwrap().len() > 2048, "the reply is larger than the removed send batch");
    assert_eq!(upstream.queries.load(Ordering::Relaxed), 1, "the warm hit is answered inline");
}

/// A warm UDP cache hit is answered inline with the cached bytes and
/// never reaches the upstream again.
/// Answers `cloaked.*` names with `<name> CNAME tracker.cloak.test` plus an A
/// record at the target, and every other name with a plain A record.
struct CnameMock {
    addr: SocketAddr,
    queries: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl CnameMock {
    fn start() -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
        let addr = socket.local_addr().unwrap();
        let queries = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let queries = queries.clone();
            let stop = stop.clone();
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while !stop.load(Ordering::Relaxed) {
                    let Ok((n, peer)) = socket.recv_from(&mut buf) else { continue };
                    let Ok(question) = Message::from_vec(&buf[..n]) else { continue };
                    queries.fetch_add(1, Ordering::Relaxed);
                    let mut answer = Message::new(question.metadata.id, MessageType::Response, OpCode::Query);
                    answer.metadata.recursion_available = true;
                    answer.add_queries(question.queries.iter().cloned());
                    let name = question.queries[0].name().clone();
                    let address = RData::A(A(Ipv4Addr::new(192, 0, 2, 1)));
                    if name.to_ascii().to_ascii_lowercase().starts_with("cloaked.") {
                        let target = Name::from_ascii("tracker.cloak.test.").unwrap();
                        answer.add_answer(Record::from_rdata(name, 60, RData::CNAME(CNAME(target.clone()))));
                        answer.add_answer(Record::from_rdata(target, 60, address));
                    } else {
                        answer.add_answer(Record::from_rdata(name, 60, address));
                    }
                    let _ = socket.send_to(&answer.to_vec().unwrap(), peer);
                }
            })
        };
        Self { addr, queries, stop, thread: Some(thread) }
    }
}

impl Drop for CnameMock {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// CNAME cloaking: a CNAME to a blocked name is blocked on the cold relay, on the warm UDP
/// hit and over TCP; an unrelated name keeps the cheap hit; and a reload that
/// drops the rule unblocks the same cached entry without a new upstream query.
#[test]
fn a_blocked_cname_target_blocks_udp_warm_hits_and_tcp_until_the_rule_is_gone() {
    let addr = free_addr();
    let dir = temp_dir("cname-target");
    let path = dir.join("config.toml");
    let upstream = CnameMock::start();
    let text = config(addr, &dir, &[upstream.addr], "cache_size = 1000\nuser_rules = [\"||cloak.test^\"]");
    fs::write(&path, &text).unwrap();
    let mut server = Running::start(&dir, &text);
    server.wait_ready();
    let asked = || upstream.queries.load(Ordering::Relaxed);
    let ask = |name: &str, id: u16| udp_exchange(addr, &query(name, id), Duration::from_secs(3)).expect("an answer");
    let blocked = |m: &Message| {
        m.metadata.response_code == ResponseCode::NXDomain
            && m.answers.is_empty()
            && matches!(m.authorities.first().map(|r| &r.data), Some(RData::SOA(_)))
    };

    assert!(blocked(&ask("cloaked.test", 1)), "cold relay");
    assert_eq!(asked(), 1);
    let warm = ask("cloaked.test", 2);
    assert!(blocked(&warm), "warm UDP hit");
    assert_eq!(warm.metadata.id, 2);
    assert_eq!(asked(), 1, "answered from the cache");
    let mut tcp = tcp_connect(addr);
    tcp_send(&mut tcp, &query("cloaked.test", 3)).unwrap();
    let over_tcp = tcp_receive(&mut tcp).unwrap();
    assert!(blocked(&over_tcp), "TCP hit");
    assert_eq!(over_tcp.metadata.id, 3);

    // A name without a cloaked target is answered, warm included.
    assert_eq!(first_a(&ask("plain.test", 4)), Some(Ipv4Addr::new(192, 0, 2, 1)));
    assert_eq!(first_a(&ask("plain.test", 5)), Some(Ipv4Addr::new(192, 0, 2, 1)));
    assert_eq!(asked(), 2, "the plain name was fetched once");

    // The rule goes away: the cached CNAME answer is served, not refetched.
    fs::write(&path, config(addr, &dir, &[upstream.addr], "cache_size = 1000")).unwrap();
    server.signal("HUP");
    assert!(
        eventually(Duration::from_secs(5), || !blocked(&ask("cloaked.test", 6))),
        "a reload applies to the cached answer:\n{}",
        server.stdout()
    );
    let served = ask("cloaked.test", 7);
    assert_eq!(served.answers.len(), 2, "the CNAME chain is served");
    assert_eq!(asked(), 2, "no new upstream query");
    assert!(server.stdout().contains("cache_reset=false"), "{}", server.stdout());
}

#[test]
fn warm_udp_cache_hit_answers_with_cached_bytes() {
    let addr = free_addr();
    let dir = temp_dir("warm-cache-udp");
    let upstream = UdpMock::start(9, true);
    let text = config(addr, &dir, &[upstream.addr], "cache_size = 1000");
    let mut server = Running::start(&dir, &text);
    server.wait_ready();

    let cold = udp_exchange(addr, &query("warm-udp.test", 0x1234), Duration::from_secs(3)).expect("cold answer");
    assert_eq!(cold.metadata.id, 0x1234);
    assert_eq!(first_a(&cold), Some(Ipv4Addr::new(192, 0, 2, 9)));
    assert_eq!(upstream.queries.load(Ordering::Relaxed), 1);

    // Same question, different ID: the cache answers and the ID is patched.
    let hit = udp_exchange(addr, &query("warm-udp.test", 0x5678), Duration::from_secs(3)).expect("warm answer");
    assert_eq!(hit.metadata.id, 0x5678, "the client ID is restored");
    assert_eq!(first_a(&hit), Some(Ipv4Addr::new(192, 0, 2, 9)));
    assert!(hit.metadata.response_code == ResponseCode::NoError);
    assert_eq!(upstream.queries.load(Ordering::Relaxed), 1, "the warm hit does not reach the upstream");
}

/// Admission runs before the inline cache hit, so a warm cache cannot
/// bypass `rate_limit_qps`; the excess is dropped without a reply exactly as
/// before the inline path existed.
#[test]
fn rate_limiter_drops_a_warm_cache_hit_before_the_inline_path() {
    let addr = free_addr();
    let dir = temp_dir("rate-limit-inline");
    let upstream = UdpMock::start(7, true);
    let text = config(addr, &dir, &[upstream.addr], "rate_limit_qps = 1\nrate_limit_burst = 1\ncache_size = 1000");
    let mut server = Running::start(&dir, &text);
    server.wait_ready();

    let cold = udp_exchange(addr, &query("limited-hit.test", 1), Duration::from_secs(3)).expect("cold answer");
    assert_eq!(cold.metadata.response_code, ResponseCode::NoError);
    assert_eq!(upstream.queries.load(Ordering::Relaxed), 1);

    // Refill exactly one token, then spend it on a cache hit.
    thread::sleep(Duration::from_millis(1100));
    let hit = udp_exchange(addr, &query("limited-hit.test", 2), Duration::from_secs(3)).expect("the hit answers");
    assert_eq!(hit.metadata.id, 2);
    assert_eq!(upstream.queries.load(Ordering::Relaxed), 1, "the second answer came from the cache");

    // The bucket is empty again: the next datagram is dropped before the
    // inline path can answer it.
    assert!(
        udp_exchange(addr, &query("limited-hit.test", 3), Duration::from_millis(300)).is_none(),
        "a warm hit must still be admitted"
    );
    assert!(eventually(Duration::from_secs(2), || server.stdout().contains("msg=rate_limited")));
}

/// A log reader that goes away (`| head`, a dead log shipper) must not stop the
/// server: `println!` panics on a closed pipe, which kills the task that
/// logs. Here the UDP receive loop logs `rate_limited` after the reader is
/// gone, and must keep answering afterwards.
#[test]
fn a_closed_stdout_does_not_stop_the_server() {
    use std::io::BufRead;
    let addr = free_addr();
    let dir = temp_dir("stdout-closed");
    let upstream = UdpMock::start(7, true);
    let path = dir.join("config.toml");
    fs::write(&path, config(addr, &dir, &[upstream.addr], "rate_limit_qps = 1\nrate_limit_burst = 1")).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_sopedu-dns"))
        .arg(&path)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdout = std::io::BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    while !line.contains("msg=readiness ready=true") {
        line.clear();
        assert!(stdout.read_line(&mut line).unwrap() > 0, "the server exited before it was ready");
    }
    drop(stdout);

    let answered = |id| udp_exchange(addr, &query("closed-stdout.test", id), Duration::from_secs(2)).is_some();
    assert!(answered(1));
    // The bucket is empty: these are dropped and the first drop is logged.
    assert!(!answered(2));
    thread::sleep(Duration::from_millis(1200));
    assert!(answered(3), "the receive loop survived its log line");
    assert!(child.try_wait().unwrap().is_none(), "the server is still running");
    let _ = child.kill();
    let _ = child.wait();
    let _ = fs::remove_dir_all(&dir);
}

/// An inline hit does not take the slow-path permit. With
/// `udp_inflight_max = 1`, hold the only permit behind a delayed upstream
/// answer, then prove a warm hit from another client still answers.
#[test]
fn warm_udp_cache_hit_bypasses_a_full_inflight_permit() {
    let addr = free_addr();
    let dir = temp_dir("warm-cache-inflight");
    let upstream = DelayedUdpMock::start(11, Duration::from_millis(1500));
    let text = config(addr, &dir, &[upstream.addr], "cache_size = 1000\nudp_inflight_max = 1");
    let mut server = Running::start(&dir, &text);
    server.wait_ready();

    // Warm the cache; this request holds the permit until its delayed answer.
    let cold = udp_exchange(addr, &query("permit-warm.test", 0x1111), Duration::from_secs(3)).expect("cold answer");
    assert_eq!(first_a(&cold), Some(Ipv4Addr::new(192, 0, 2, 11)));

    // A different uncached name now takes the only permit and waits upstream.
    let slow = UdpSocket::bind("127.0.0.1:0").unwrap();
    slow.send_to(&query("permit-slow.test", 0x2222), addr).unwrap();
    assert!(
        eventually(Duration::from_secs(2), || upstream.queries.load(Ordering::Relaxed) == 2),
        "the slow query did not reach the upstream and hold the permit"
    );

    // Another client's warm hit must answer inline, without the permit.
    let hit = udp_exchange(addr, &query("permit-warm.test", 0x3333), Duration::from_millis(500))
        .expect("the warm hit must bypass the full permit");
    assert_eq!(hit.metadata.id, 0x3333);
    assert_eq!(first_a(&hit), Some(Ipv4Addr::new(192, 0, 2, 11)));
    let _ = slow;
}

#[test]
fn sigterm_exits_zero_within_the_drain_window() {
    let addr = free_addr();
    let dir = temp_dir("sigterm");
    let text = config(addr, &dir, &[], "user_rules = [\"||blocked.test^\"]");
    let mut server = Running::start(&dir, &text);
    server.wait_ready();

    server.signal("TERM");
    let status = server.wait_exit(Duration::from_secs(10));
    assert!(status.success(), "SIGTERM is a graceful exit 0, got {status:?}\nstderr:\n{}", server.stderr());
    let stdout = server.stdout();
    assert!(stdout.contains("ready=false"), "readiness turns false during shutdown:\n{stdout}");
    assert!(stdout.contains("msg=shutdown_complete"));
}

#[test]
fn a_second_signal_aborts_the_drain() {
    let addr = free_addr();
    let dir = temp_dir("sigterm-twice");
    let blackhole = UdpMock::start(1, false);
    let text = config(addr, &dir, &[blackhole.addr], "upstream_timeout_seconds = 5");
    let mut server = Running::start(&dir, &text);
    server.wait_ready();

    let mut stream = tcp_connect(addr);
    tcp_send(&mut stream, &query("slow.test", 1)).unwrap();
    assert!(
        eventually(Duration::from_secs(3), || blackhole.queries.load(Ordering::Relaxed) >= 1),
        "the slow query is in flight before shutdown"
    );

    server.signal("TERM");
    thread::sleep(Duration::from_millis(300));
    let started = Instant::now();
    server.signal("TERM");
    let status = server.wait_exit(Duration::from_secs(3));
    assert!(status.success(), "a forced shutdown still exits 0, got {status:?}\n{}", server.stderr());
    assert!(started.elapsed() < Duration::from_secs(2), "the second signal ends the drain immediately");
    assert!(server.stdout().contains("msg=shutdown_forced"), "the forced drain is logged:\n{}", server.stdout());
}

#[test]
fn check_validates_without_binding_downloading_or_creating_state() {
    let http = HttpMock::start("||listed.test^\n");
    let dir = temp_dir("check");
    // Occupy the listen address: a check that bound sockets would fail.
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = udp.local_addr().unwrap();
    let tcp = TcpListener::bind(addr).unwrap();
    let path = dir.join("config.toml");
    let blocklist = format!("http://user:pass@{}/list.txt?token=secret", http.addr);
    fs::write(&path, config(addr, &dir, &[], &format!("blocklists = [\"{blocklist}\"]\nlog_queries = true"))).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_sopedu-dns")).arg("--check").arg(&path).output().unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(String::from_utf8_lossy(&output.stdout), "config ok\n");
    assert!(!dir.join("state").exists(), "--check must not create the state directory");
    thread::sleep(Duration::from_millis(300));
    assert_eq!(http.requests.load(Ordering::Relaxed), 0, "--check must not download lists");
    drop(tcp);
    drop(udp);

    let bad = dir.join("bad.toml");
    fs::write(&bad, config(addr, &dir, &[], "cache_bytes = 0")).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_sopedu-dns")).arg("--check").arg(&bad).output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("cache_bytes must be greater than zero"));

    // Validation errors name the sanitized upstream, never its credentials.
    let secret = dir.join("secret.toml");
    fs::write(
        &secret,
        format!(
            "listen = \"{addr}\"\nstate_dir = \"{}\"\nupstreams = [\"http://user:pass@example.com/dns-query?token=supersecret\"]\nfallback = []\nui_enabled = false\n",
            dir.join("state").display()
        ),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_sopedu-dns")).arg("--check").arg(&secret).output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("DoH upstreams require https: http://example.com"), "stderr: {stderr}");
    assert!(!stderr.contains("supersecret"), "the token is redacted: {stderr}");
    assert!(!stderr.contains("user:pass"), "the userinfo is redacted: {stderr}");
    assert!(!stderr.contains("dns-query"), "a path can carry a token and is redacted: {stderr}");

    // TOML's own error display quotes the source line; keep only the line number.
    let broken = dir.join("broken.toml");
    fs::write(&broken, "upstreams = [\"http://user:pass@example.com/dns-query?token=supersecret\"\n").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_sopedu-dns")).arg("--check").arg(&broken).output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("(line "), "the line number is kept: {stderr}");
    assert!(!stderr.contains("supersecret"), "a TOML error must not quote the source line: {stderr}");
    assert!(!stderr.contains("user:pass"), "a TOML error must not quote the source line: {stderr}");

    // A serde type error quotes the offending value inside the message, so the
    // value is stripped too; the expected type and line number stay.
    let typed = dir.join("typed.toml");
    fs::write(&typed, "upstreams = \"http://user:pass@example.com/dns-query?token=supersecret\"\n").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_sopedu-dns")).arg("--check").arg(&typed).output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("expected a sequence"), "the expected type is kept: {stderr}");
    assert!(stderr.contains("(line 1)"), "the line number is kept: {stderr}");
    assert!(!stderr.contains("supersecret"), "a type error must not echo the value: {stderr}");
    assert!(!stderr.contains("user:pass"), "a type error must not echo the value: {stderr}");
    assert!(!stderr.contains("example.com"), "a type error must not echo the value: {stderr}");

    // Serde quotes unknown variants and unknown fields with backticks. The
    // offending value is stripped in this shape too; the expected values and
    // the line number stay.
    let secret_url = "https://user:pass@example.com/dns-query?token=supersecret";
    for (name, body, kept) in [
        (
            "enum-dnssec",
            format!("dnssec = \"{secret_url}\"\n"),
            vec!["unknown variant", "`passthrough`", "`always_upstream`"],
        ),
        (
            "enum-private-ptr",
            format!("private_ptr = \"{secret_url}\"\n"),
            vec!["unknown variant", "`nxdomain`", "`forward`"],
        ),
        ("unknown-field", format!("\"{secret_url}\" = true\n"), vec!["unknown field", "expected one of", "`listen`"]),
    ] {
        let path = dir.join(format!("{name}.toml"));
        fs::write(&path, body).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_sopedu-dns")).arg("--check").arg(&path).output().unwrap();
        assert_eq!(output.status.code(), Some(1), "{name} must be rejected");
        let stderr = String::from_utf8_lossy(&output.stderr);
        for leaked in ["supersecret", "user:pass", "example.com", "dns-query"] {
            assert!(!stderr.contains(leaked), "{leaked} leaked from {name}: {stderr}");
        }
        for kept in kept {
            assert!(stderr.contains(kept), "{kept} is kept for {name}: {stderr}");
        }
        assert!(stderr.contains("(line 1)"), "the line number is kept for {name}: {stderr}");
    }
}

#[test]
fn global_blocklist_refresh_failure_is_logged_with_a_retry() {
    let addr = free_addr();
    let dir = temp_dir("refresh-failure");
    let failing = "http://user:pass@127.0.0.1:1/missing?token=supersecret";
    let text = config(addr, &dir, &[], &format!("blocklists = [\"{failing}\"]"));
    let mut server = Running::start(&dir, &text);
    server.wait_ready();

    // The log is a file the server appends to; wait for the whole line (its last
    // field is `retry_seconds`), not just the first bytes of it.
    let complete = |out: &str| {
        out.lines().any(|line| line.contains("msg=blocklist_refresh_failed") && line.contains("retry_seconds=60"))
    };
    assert!(
        eventually(Duration::from_secs(20), || complete(&server.stdout())),
        "a whole-refresh failure is an error-level event:\n{}\nstderr:\n{}",
        server.stdout(),
        server.stderr()
    );
    let stdout = server.stdout();
    assert!(stdout.contains("level=error"), "the failure is not silent:\n{stdout}");
    assert!(stdout.contains("retry_seconds=60"), "the failure has a bounded retry:\n{stdout}");
    assert!(!stdout.contains("supersecret"), "the URL token never reaches the logs:\n{stdout}");
    assert!(!stdout.contains("user:pass"), "URL credentials never reach the logs:\n{stdout}");
}

#[test]
fn refresh_after_a_reload_still_applies_the_new_list() {
    let addr = free_addr();
    let dir = temp_dir("refresh-reload-race");
    let path = dir.join("config.toml");
    let http = HttpMock::start_delayed("||listed.test^\n", Duration::from_millis(1500));

    let first = config(addr, &dir, &[], "");
    fs::write(&path, &first).unwrap();
    let mut server = Running::start(&dir, &first);
    server.wait_ready();

    let listed = format!("http://user:pass@{}/list.txt?token=secret", http.addr);
    let second = config(addr, &dir, &[], &format!("blocklists = [\"{listed}\"]"));
    fs::write(&path, &second).unwrap();
    server.signal("HUP");
    assert!(
        eventually(Duration::from_secs(5), || http.requests.load(Ordering::Relaxed) >= 1),
        "the reloaded list download started:\n{}",
        server.stdout()
    );

    // An unrelated reload lands while the download is still in flight. The
    // old refresh result must apply to this newer generation, not be dropped.
    let third = config(addr, &dir, &[], &format!("blocklists = [\"{listed}\"]\nlog_queries = true"));
    fs::write(&path, &third).unwrap();
    server.signal("HUP");
    assert!(
        eventually(Duration::from_secs(5), || server.stdout().matches("msg=config_reloaded").count() >= 2),
        "the unrelated reload completed during the download:\n{}",
        server.stdout()
    );

    assert!(
        eventually(Duration::from_secs(5), || response_code(addr, "listed.test", 3) == Some(ResponseCode::NXDomain)),
        "the downloaded snapshot applies to the current generation instead of waiting for the next interval:\n{}",
        server.stdout()
    );
    let stdout = server.stdout();
    assert!(stdout.contains("msg=blocklists"), "the refresh publishes one snapshot:\n{stdout}");
    assert!(stdout.contains("applied=true"), "the snapshot was not discarded as stale:\n{stdout}");
}

#[test]
fn first_query_sees_a_list_that_had_no_persisted_copy() {
    // With nothing persisted, the listener opens only after the first
    // download attempt, so the very first query is already filtered. The
    // delay stays well under the server's 750 ms startup wait: busy CI
    // runners need the headroom, and any delay still races the query
    // against the download if the wait is missing.
    let addr = free_addr();
    let dir = temp_dir("first-list");
    let http = HttpMock::start_delayed("||listed.test^\n", Duration::from_millis(150));
    let text = config(addr, &dir, &[], &format!("blocklists = [\"http://{}/list.txt\"]", http.addr));
    let mut server = Running::start(&dir, &text);
    assert!(eventually(Duration::from_secs(10), || TcpStream::connect(addr).is_ok()), "{}", server.stderr());
    assert_eq!(response_code(addr, "listed.test", 1), Some(ResponseCode::NXDomain), "{}", server.stdout());
    server.wait_ready();
    assert_eq!(http.requests.load(Ordering::Relaxed), 1, "the startup refresh is not repeated at once");
}

#[test]
fn reload_swaps_rules_and_keeps_the_old_config_on_error() {
    let addr = free_addr();
    let dir = temp_dir("reload-rules");
    let path = dir.join("config.toml");
    let old = config(addr, &dir, &[], "user_rules = [\"||old.test^\"]\nlog_queries = true");
    fs::write(&path, &old).unwrap();
    let mut server = Running::start(&dir, &old);
    server.wait_ready();
    assert_eq!(response_code(addr, "old.test", 1), Some(ResponseCode::NXDomain));
    assert!(
        eventually(Duration::from_secs(2), || server.stdout().contains("qname=old.test")),
        "query logging uses the presentation name, not wire label bytes:\n{}",
        server.stdout()
    );

    let new = config(addr, &dir, &[], "user_rules = [\"||new.test^\"]");
    fs::write(&path, &new).unwrap();
    server.signal("HUP");
    assert!(
        eventually(Duration::from_secs(5), || response_code(addr, "new.test", 2) == Some(ResponseCode::NXDomain)),
        "a valid reload applies the new rules:\n{}",
        server.stdout()
    );
    assert_eq!(response_code(addr, "old.test", 3), Some(ResponseCode::ServFail), "the old block rule is gone");

    let invalid = config(addr, &dir, &[], "user_rules = [\"||new.test^\"]\ncache_bytes = 0");
    let lines_before = server.stdout().lines().count();
    fs::write(&path, &invalid).unwrap();
    server.signal("HUP");
    assert!(
        eventually(Duration::from_secs(5), || {
            server.stdout().contains("msg=config_reload_failed") && server.stdout().lines().count() > lines_before
        }),
        "a failed reload is logged:\n{}",
        server.stdout()
    );
    assert_eq!(response_code(addr, "new.test", 4), Some(ResponseCode::NXDomain), "the old generation stays active");
}

#[test]
fn reload_applies_upstream_and_cache_changes() {
    let addr = free_addr();
    let dir = temp_dir("reload-upstreams");
    let path = dir.join("config.toml");
    let first_mock = UdpMock::start(1, true);
    let second_mock = UdpMock::start(2, true);

    let first = config(addr, &dir, &[first_mock.addr], "cache_size = 0");
    fs::write(&path, &first).unwrap();
    let mut server = Running::start(&dir, &first);
    server.wait_ready();
    for id in 1..=2 {
        let answer = udp_exchange(addr, &query("flip.test", id), Duration::from_secs(3)).unwrap();
        assert_eq!(first_a(&answer), Some(Ipv4Addr::new(192, 0, 2, 1)));
    }
    assert!(first_mock.queries.load(Ordering::Relaxed) >= 2, "cache_size = 0 forwards every query");

    let second = config(addr, &dir, &[second_mock.addr], "cache_size = 1000");
    fs::write(&path, &second).unwrap();
    server.signal("HUP");
    assert!(
        eventually(Duration::from_secs(5), || {
            udp_exchange(addr, &query("flip.test", 3), Duration::from_secs(2)).and_then(|answer| first_a(&answer))
                == Some(Ipv4Addr::new(192, 0, 2, 2))
        }),
        "a reload swaps the upstream pool:\n{}",
        server.stdout()
    );
    let before = second_mock.queries.load(Ordering::Relaxed);
    let cached = udp_exchange(addr, &query("flip.test", 4), Duration::from_secs(3)).unwrap();
    assert_eq!(first_a(&cached), Some(Ipv4Addr::new(192, 0, 2, 2)));
    assert_eq!(second_mock.queries.load(Ordering::Relaxed), before, "the new cache answers without upstream");
    assert!(
        server.stdout().contains("cache_reset=true"),
        "changing cache_size starts a fresh cache:\n{}",
        server.stdout()
    );

    // An unrelated reload reuses the cache Arc: warm entries survive.
    let third = config(addr, &dir, &[second_mock.addr], "cache_size = 1000\nlog_queries = true");
    fs::write(&path, &third).unwrap();
    server.signal("HUP");
    assert!(
        eventually(Duration::from_secs(5), || server.stdout().matches("msg=config_reloaded").count() >= 2),
        "the unrelated reload applied:\n{}",
        server.stdout()
    );
    assert!(
        server.stdout().contains("cache_reset=false"),
        "an unchanged cache configuration reuses the cache:\n{}",
        server.stdout()
    );
    let before = second_mock.queries.load(Ordering::Relaxed);
    let cached = udp_exchange(addr, &query("flip.test", 5), Duration::from_secs(3)).unwrap();
    assert_eq!(first_a(&cached), Some(Ipv4Addr::new(192, 0, 2, 2)));
    assert_eq!(second_mock.queries.load(Ordering::Relaxed), before, "a warm entry survives an unrelated reload");
}

#[test]
fn reload_route_change_starts_a_fresh_cache() {
    // Answers cached from the old route must not survive into the new view.
    let addr = free_addr();
    let dir = temp_dir("reload-route-cache");
    let path = dir.join("config.toml");
    let first_mock = UdpMock::start(1, true);
    let second_mock = UdpMock::start(2, true);
    let first = config(addr, &dir, &[first_mock.addr], "cache_size = 1000");
    fs::write(&path, &first).unwrap();
    let mut server = Running::start(&dir, &first);
    server.wait_ready();
    let answer = udp_exchange(addr, &query("route.test", 1), Duration::from_secs(3)).unwrap();
    assert_eq!(first_a(&answer), Some(Ipv4Addr::new(192, 0, 2, 1)));

    let second = config(addr, &dir, &[second_mock.addr], "cache_size = 1000");
    fs::write(&path, &second).unwrap();
    server.signal("HUP");
    assert!(
        eventually(Duration::from_secs(5), || {
            udp_exchange(addr, &query("route.test", 2), Duration::from_secs(2)).and_then(|answer| first_a(&answer))
                == Some(Ipv4Addr::new(192, 0, 2, 2))
        }),
        "the old route's cached answer is not served after the swap:\n{}",
        server.stdout()
    );
    assert!(server.stdout().contains("cache_reset=true"), "{}", server.stdout());
}

#[test]
fn reload_adds_a_blocklist_and_logs_sanitized_sources() {
    let addr = free_addr();
    let dir = temp_dir("reload-lists");
    let path = dir.join("config.toml");
    let http = HttpMock::start("||listed.test^\n");

    let first = config(addr, &dir, &[], "");
    fs::write(&path, &first).unwrap();
    let mut server = Running::start(&dir, &first);
    server.wait_ready();
    assert_eq!(response_code(addr, "listed.test", 1), Some(ResponseCode::ServFail));

    let listed = format!("http://user:pass@{}/list.txt?token=secret", http.addr);
    let failing = "http://127.0.0.1:1/missing?token=secret2".to_string();
    let second = config(addr, &dir, &[], &format!("blocklists = [\"{listed}\", \"{failing}\"]"));
    fs::write(&path, &second).unwrap();
    server.signal("HUP");
    assert!(
        eventually(Duration::from_secs(5), || response_code(addr, "listed.test", 2) == Some(ResponseCode::NXDomain)),
        "the reloaded list starts blocking:\n{}",
        server.stdout()
    );
    assert!(
        eventually(Duration::from_secs(5), || server.stdout().contains("source=http://127.0.0.1:1 ")),
        "a per-list error carries the sanitized origin:\n{}",
        server.stdout()
    );
    let stdout = server.stdout();
    assert!(!stdout.contains("secret"), "userinfo and query strings never reach the logs:\n{stdout}");
    assert!(!stdout.contains("user:pass"), "userinfo never reaches the logs:\n{stdout}");
    assert!(!stdout.contains("/missing"), "a path that is not a file name is redacted:\n{stdout}");
    assert!(stdout.contains("source=http://127.0.0.1:1"), "the sanitized origin is kept");
}

#[test]
fn reload_errors_never_echo_url_secrets() {
    let addr = free_addr();
    let dir = temp_dir("reload-secrets");
    let path = dir.join("config.toml");
    let valid = config(addr, &dir, &[], "");
    fs::write(&path, &valid).unwrap();
    let mut server = Running::start(&dir, &valid);
    server.wait_ready();

    let bad = format!(
        "listen = \"{addr}\"\nstate_dir = \"{}\"\nupstreams = [\"http://user:pass@example.com/dns-query?token=supersecret\"]\nfallback = []\nui_enabled = false\n",
        dir.join("state").display()
    );
    fs::write(&path, &bad).unwrap();
    server.signal("HUP");
    assert!(
        eventually(Duration::from_secs(5), || server.stdout().contains("msg=config_reload_failed")),
        "the invalid reload is reported:\n{}",
        server.stdout()
    );
    let stdout = server.stdout();
    assert!(stdout.contains("http://example.com"), "the sanitized upstream is kept:\n{stdout}");
    assert!(!stdout.contains("dns-query"), "the path can carry a token and is redacted:\n{stdout}");
    assert!(!stdout.contains("supersecret"), "the reload log redacts the token:\n{stdout}");
    assert!(!stdout.contains("user:pass"), "the reload log redacts the userinfo:\n{stdout}");
}

#[test]
fn reload_requests_restart_for_listener_changes() {
    let addr = free_addr();
    let next = free_addr();
    let dir = temp_dir("reload-listen");
    let path = dir.join("config.toml");
    let first = config(addr, &dir, &[], "user_rules = [\"||blocked.test^\"]");
    fs::write(&path, &first).unwrap();
    let mut server = Running::start(&dir, &first);
    server.wait_ready();

    let second = config(
        next,
        &dir,
        &[],
        "user_rules = [\"||blocked.test^\"]\ntcp_max_connections = 3\ntcp_queries_per_connection = 3\n\
         tcp_pipeline_max = 3\ntcp_idle_timeout_seconds = 3\nudp_inflight_max = 3\n\
         udp_workers = 2\nudp_rcvbuf_bytes = 65536\nudp_sndbuf_bytes = 65536\nudp_batch = 2\nworker_threads = 3",
    );
    fs::write(&path, &second).unwrap();
    server.signal("HUP");
    // One line per field: wait for the last one, not just the first.
    assert!(
        eventually(Duration::from_secs(5), || server.stdout().contains("field=worker_threads ")),
        "a listener change asks for a restart:\n{}",
        server.stdout()
    );
    let stdout = server.stdout();
    for field in [
        "listen",
        "tcp_max_connections",
        "tcp_queries_per_connection",
        "tcp_pipeline_max",
        "tcp_idle_timeout_seconds",
        "udp_inflight_max",
        "udp_workers",
        "udp_rcvbuf_bytes",
        "udp_sndbuf_bytes",
        "udp_batch",
        "worker_threads",
    ] {
        assert!(stdout.contains(&format!("field={field} ")), "the log names {field} as needing a restart:\n{stdout}");
    }
    assert!(
        stdout.contains("field=tcp_idle_timeout_seconds old=10 new=3"),
        "the log carries the old and new value:\n{stdout}"
    );
    assert!(
        stdout.contains("field=udp_inflight_max old=1024 new=3"),
        "the log carries the old and new value:\n{stdout}"
    );
    assert!(stdout.contains("field=worker_threads old=0 new=3"), "the log carries the old and new value:\n{stdout}");
    let batch_default = if cfg!(target_os = "linux") { 32 } else { 0 };
    assert!(
        stdout.contains(&format!("field=udp_batch old={batch_default} new=2")),
        "the log carries the old and new value:\n{stdout}"
    );
    assert_eq!(response_code(addr, "blocked.test", 1), Some(ResponseCode::NXDomain), "the old listener keeps serving");
    assert!(
        TcpStream::connect_timeout(&next, Duration::from_millis(500)).is_err(),
        "the new listen address is not bound until restart"
    );
}

/// Drops whole-line `#` comments so a guard cannot pass on a commented-out
/// declaration or example.
fn uncommented(text: &str) -> String {
    text.lines().filter(|line| !line.trim_start().starts_with('#')).collect::<Vec<_>>().join("\n")
}

/// Regression: the Deployment must keep the root plus
/// `NET_BIND_SERVICE` context that makes the port-53 bind work. The actual
/// on-cluster bind is still a manual check.
#[test]
fn deploy_manifest_keeps_the_port_53_bind_security_context() {
    let manifest = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/deploy/kubernetes.yaml"));
    let manifest = uncommented(manifest);
    for expected in [
        "runAsUser: 0",
        "allowPrivilegeEscalation: false",
        "readOnlyRootFilesystem: true",
        "drop: [ALL]",
        "add: [NET_BIND_SERVICE]",
        "automountServiceAccountToken: false",
        "fsGroup: 0",
    ] {
        assert!(manifest.contains(expected), "deploy/kubernetes.yaml lost `{expected}`");
    }
}

/// A free loopback TCP address (the UI listener).
fn free_tcp_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap()
}

/// One HTTP/1.1 exchange on a fresh connection: (status, headers, body).
fn http(addr: SocketAddr, method: &str, path: &str) -> (u16, String, String) {
    http_host(addr, method, path, "127.0.0.1")
}

fn http_host(addr: SocketAddr, method: &str, path: &str, host: &str) -> (u16, String, String) {
    let mut stream = tcp_connect(addr);
    write!(stream, "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").unwrap();
    let mut raw = String::new();
    let _ = stream.read_to_string(&mut raw);
    let (head, body) = raw.split_once("\r\n\r\n").unwrap_or_else(|| panic!("no HTTP response: {raw:?}"));
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    (status, head.to_string(), body.to_string())
}

fn metric(text: &str, series: &str) -> f64 {
    let prefix = format!("{series} ");
    text.lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .unwrap_or_else(|| panic!("metric {series} missing in:\n{text}"))
        .parse()
        .unwrap()
}

/// `/healthz` and `/metrics` against the real binary,
/// including the hot-path counters, method and path handling.
#[test]
fn ui_serves_healthz_and_metrics() {
    let mock = UdpMock::start(1, true);
    let addr = free_addr();
    let ui = free_tcp_addr();
    let dir = temp_dir("ui-metrics");
    let text = format!(
        "listen = \"{addr}\"\nstate_dir = \"{}\"\nupstreams = []\nfallback = [\"{}\"]\nui_listen = \"{ui}\"\n\
         upstream_0x20 = false\nforward_test_names = true\nuser_rules = [\"||blocked.test^\"]\n",
        dir.join("state").display(),
        mock.addr
    );
    let mut server = Running::start(&dir, &text);
    server.wait_ready();

    let (status, _, body) = http(ui, "GET", "/healthz");
    assert_eq!((status, body.as_str()), (200, "ok\n"));

    assert_eq!(response_code(addr, "blocked.test", 1), Some(ResponseCode::NXDomain));
    for id in 2..6 {
        assert_eq!(response_code(addr, "fresh.test", id), Some(ResponseCode::NoError));
    }
    let (status, head, metrics) = http(ui, "GET", "/metrics?x=1");
    assert_eq!(status, 200);
    assert!(head.to_ascii_lowercase().contains("content-type: text/plain; version=0.0.4"), "{head}");
    assert_eq!(metric(&metrics, "dns_queries_total{result=\"blocked\"}"), 1.0);
    assert_eq!(metric(&metrics, "dns_queries_total{result=\"upstream\"}"), 1.0);
    assert_eq!(metric(&metrics, "dns_queries_total{result=\"cache\"}"), 3.0, "inline UDP hits are counted");
    assert_eq!(metric(&metrics, "dns_request_duration_seconds_count"), 5.0);
    assert_eq!(metric(&metrics, "dns_request_duration_seconds_bucket{le=\"+Inf\"}"), 5.0);
    assert_eq!(metric(&metrics, "dns_cache_entries"), 1.0);
    assert!(metric(&metrics, "dns_cache_bytes") > 0.0);
    assert_eq!(metric(&metrics, "dns_upstream_errors_total"), 0.0);
    assert_eq!(mock.queries.load(Ordering::Relaxed), 1, "only the first query reached the upstream");

    let (status, _, body) = http(ui, "HEAD", "/metrics");
    assert_eq!((status, body.as_str()), (200, ""));
    let (status, head, _) = http(ui, "POST", "/metrics");
    assert_eq!(status, 405);
    assert!(head.to_ascii_lowercase().contains("allow: get, head"), "{head}");
    assert_eq!(http(ui, "DELETE", "/healthz").0, 405);
    assert_eq!(http(ui, "GET", "/metrics/").0, 404);
    assert_eq!(http(ui, "GET", "/api/nope").0, 404);
    assert_eq!(http(ui, "GET", "/rules/").0, 404);
}

/// Sends one A query for a name made of raw label bytes.
fn send_raw_name(server: SocketAddr, labels: &[&[u8]], id: u16) {
    let mut packet = Vec::from(id.to_be_bytes());
    packet.extend_from_slice(&[1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in labels {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label);
    }
    packet.extend_from_slice(&[0, 0, 1, 0, 1]);
    let _ = udp_exchange(server, &packet, Duration::from_secs(3));
}

/// The dashboard, the query log and their JSON against the
/// real binary: results, block origin, the inline-hit entries, escaping, the
/// secrets rule and the security headers.
#[test]
fn ui_dashboard_and_query_log() {
    let mock = UdpMock::start(1, true);
    let addr = free_addr();
    let ui = free_tcp_addr();
    let dir = temp_dir("ui-pages");
    // List 1 is served here; list 2's download fails (nothing listens on port
    // 1), so its token must not appear anywhere in what the browser gets.
    let list_server = TcpListener::bind("127.0.0.1:0").unwrap();
    let list_url = format!("http://{}/list.txt", list_server.local_addr().unwrap());
    thread::spawn(move || {
        for stream in list_server.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut request = [0u8; 2048];
            let _ = stream.read(&mut request);
            let body = "||listed.test^\n";
            let _ =
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
        }
    });
    let text = format!(
        "listen = \"{addr}\"\nstate_dir = \"{}\"\nupstreams = []\nfallback = [\"{}\"]\nui_listen = \"{ui}\"\n\
         upstream_0x20 = false\nforward_test_names = true\nuser_rules = [\"||blocked.test^\", \"||evil.test^\"]\n\
         blocklists = [\"{list_url}\", \"http://127.0.0.1:1/list.txt?token=SECRETTOKEN\"]\n",
        dir.join("state").display(),
        mock.addr
    );
    let mut server = Running::start(&dir, &text);
    server.wait_ready();

    assert_eq!(response_code(addr, "listed.test", 8), Some(ResponseCode::NXDomain));
    assert_eq!(response_code(addr, "blocked.test", 1), Some(ResponseCode::NXDomain));
    for id in 2..6 {
        assert_eq!(response_code(addr, "fresh.test", id), Some(ResponseCode::NoError));
    }
    send_raw_name(addr, &[b"<img/src=x/onerror=alert(1)>", b"evil", b"test"], 7);

    // The drain task feeds the top lists every 500 ms.
    assert!(
        eventually(Duration::from_secs(10), || http(ui, "GET", "/api/dashboard")
            .2
            .contains("\"name\":\"blocked.test\"")),
        "blocked.test never reached the top lists"
    );
    let (status, head, dash) = http(ui, "GET", "/api/dashboard");
    assert_eq!(status, 200);
    assert!(head.to_ascii_lowercase().contains("content-type: application/json"), "{head}");
    // blocked.test, the hostile name (also blocked) and 4 fresh.test answers.
    assert!(dash.contains("\"5m\":{") && dash.contains("\"24h\":{"), "{dash}");
    assert!(dash.contains("\"top\":{\"domains\":[{\"name\":\"fresh.test\",\"count\":4"), "{dash}");
    assert!(dash.contains("\"blocked\":[{"), "{dash}");
    assert!(dash.contains("\"clients\":[{\"name\":\"127.0.0.1\""), "{dash}");
    assert!(dash.contains("\"status\":\"error\"") && dash.contains("http://127.0.0.1:1/list.txt"), "{dash}");
    assert!(dash.contains(&format!("\"id\":1,\"name\":\"{list_url}\",\"rules\":1,")), "{dash}");
    assert!(dash.contains("\"status\":\"ok\""), "{dash}");
    assert!(dash.contains("\"upstreams\":[]"), "{dash}");
    assert!(!dash.contains("SECRETTOKEN"), "a list token reached the browser: {dash}");

    // The log: one upstream answer, three inline cache hits, the blocks.
    let (_, _, log) = http(ui, "GET", "/api/log");
    for needle in [
        "\"name\":\"blocked.test\"",
        "\"result\":\"blocked\"",
        "\"list\":{\"id\":0,\"name\":\"user rules\"}",
        "\"name\":\"listed.test\",\"truncated\":false,\"qtype\":\"A\",\"result\":\"blocked\",\"upstream\":null,\"latency_us\":",
        &format!("\"list\":{{\"id\":1,\"name\":\"{list_url}\"}}"),
        "\"allow_rule\":\"@@||blocked.test^$important\"",
        "\"block_rule\":\"||fresh.test^\"",
        "\"result\":\"upstream\"",
        "\"result\":\"cache\"",
        "\"client\":\"127.0.0.1\"",
        "\"qtype\":\"A\"",
    ] {
        assert!(log.contains(needle), "missing {needle} in {log}");
    }
    assert_eq!(log.matches("\"name\":\"fresh.test\"").count(), 4, "{log}");
    assert_eq!(log.matches("\"result\":\"cache\"").count(), 3, "inline UDP hits are logged: {log}");
    let (_, _, only) = http(ui, "GET", "/api/log?result=blocked&q=BLOCKED.te&client=127.0.0.&qtype=a");
    assert_eq!(only.matches("\"time_ms\"").count(), 1, "{only}");
    let (_, _, none) = http(ui, "GET", "/api/log?client=10.");
    assert!(none.contains("\"entries\":[]"), "{none}");
    let (_, _, two) = http(ui, "GET", "/api/log?limit=2");
    assert_eq!(two.matches("\"time_ms\"").count(), 2, "{two}");

    // Hostile bytes in a qname stay inert in the page and in the JSON.
    let (_, _, page) = http(ui, "GET", "/log");
    assert!(page.contains("&lt;img/src=x/onerror=alert(1)&gt;"), "{page}");
    assert!(!page.contains("<img") && !page.contains("onerror=alert(1)>"), "{page}");
    let (_, _, hostile) = http(ui, "GET", "/api/log?q=img");
    assert!(hostile.contains("\\u003cimg/src=x/onerror=alert(1)\\u003e"), "{hostile}");
    assert!(!hostile.contains('<'), "{hostile}");
    let (_, _, echoed) = http(ui, "GET", "/log?client=%22%3E%3Cscript%3Ealert(1)%3C/script%3E");
    assert!(!echoed.contains("<script>alert"), "{echoed}");

    // Pages, assets, headers.
    let (status, head, page) = http(ui, "GET", "/");
    let head = head.to_ascii_lowercase();
    assert_eq!(status, 200);
    assert!(head.contains("content-type: text/html"), "{head}");
    assert!(head.contains("content-security-policy: default-src 'self'"), "{head}");
    assert!(head.contains("x-content-type-options: nosniff"), "{head}");
    assert!(!page.contains("<style") && !page.contains("style=\"") && !page.contains("<script>"), "no inline code");
    assert!(page.contains("Top blocked") && page.contains("blocked.test") && page.contains("Blocklists"), "{page}");
    assert!(!page.contains("SECRETTOKEN") && !page.contains("{{"), "{page}");
    let (status, head, css) = http(ui, "GET", "/app.css");
    assert!(status == 200 && head.to_ascii_lowercase().contains("text/css") && css.contains("--accent"));
    let (status, head, js) = http(ui, "GET", "/app.js");
    assert!(status == 200 && head.to_ascii_lowercase().contains("javascript") && js.contains("EventSource"));
    assert!(js.lines().count() <= 200, "plain JS stays within 200 lines");

    // A page reached under a foreign Host (DNS rebinding) is refused; probes
    // and scrapers by service name are not.
    for path in ["/", "/log", "/api/log", "/api/dashboard", "/api/log/stream", "/app.js"] {
        assert_eq!(http_host(ui, "GET", path, "attacker.example").0, 403, "{path}");
    }
    assert_eq!(http_host(ui, "GET", "/metrics", "dns.kube.svc:9999").0, 200);
    assert_eq!(http_host(ui, "GET", "/", "localhost:9999").0, 200);
    assert_eq!(http_host(ui, "GET", "/", "[::1]:9999").0, 200);
    assert_eq!(http(ui, "POST", "/api/log").0, 405);
}

/// A form body: every byte outside `[A-Za-z0-9]` is percent-encoded.
fn form(fields: &[(&str, &str)]) -> String {
    let encode = |text: &str| {
        text.bytes()
            .map(|b| if b.is_ascii_alphanumeric() { char::from(b).to_string() } else { format!("%{b:02X}") })
            .collect::<String>()
    };
    fields.iter().map(|(k, v)| format!("{k}={}", encode(v))).collect::<Vec<_>>().join("&")
}

/// One POST on a fresh connection. `headers` are sent as given (the caller
/// supplies `Host` and `Origin`); `length` overrides the Content-Length.
fn http_post(
    addr: SocketAddr,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
    length: Option<usize>,
) -> (u16, String, String) {
    let mut stream = tcp_connect(addr);
    let mut request = format!(
        "POST {path} HTTP/1.1\r\nConnection: close\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n",
        length.unwrap_or(body.len())
    );
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    request.push_str(body);
    let _ = stream.write_all(request.as_bytes());
    let mut raw = String::new();
    let _ = stream.read_to_string(&mut raw);
    let (head, body) = raw.split_once("\r\n\r\n").unwrap_or_else(|| panic!("no HTTP response: {raw:?}"));
    (head.split_whitespace().nth(1).unwrap().parse().unwrap(), head.to_string(), body.to_string())
}

/// The rules page (tester, editor, rewrites) and the
/// clients page against the real binary. The tester's verdict is compared with
/// the real DNS answer for each name, POSTs are same-origin only and bounded,
/// and hostile input and list tokens never reach the browser unescaped.
#[test]
fn ui_rules_and_clients_pages() {
    let mock = UdpMock::start(1, true);
    let addr = free_addr();
    let ui = free_tcp_addr();
    let dir = temp_dir("ui-rules");
    let list_server = TcpListener::bind("127.0.0.1:0").unwrap();
    let list_url = format!("http://{}/list.txt", list_server.local_addr().unwrap());
    thread::spawn(move || {
        for stream in list_server.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut request = [0u8; 2048];
            let _ = stream.read(&mut request);
            let body = "! list\n||listed.test^\n0.0.0.0 hosts.test\n";
            let _ =
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
        }
    });
    let text = format!(
        "listen = \"{addr}\"\nstate_dir = \"{}\"\nupstreams = []\nfallback = [\"{}\"]\nui_listen = \"{ui}\"\n\
         upstream_0x20 = false\nforward_test_names = true\nno_filter_clients = [\"10.9.9.9\"]\n\
         user_rules = [\"||blocked.test^\", \"@@||ok.blocked.test^\"]\n\
         blocklists = [\"{list_url}\", \"http://127.0.0.1:1/list.txt?token=SECRETTOKEN\"]\n\
         [rewrites]\n\"rw.test\" = \"192.0.2.77\"\n[client_names]\n\"10.9.9.9\" = \"TV\"\n\"127.0.0.1\" = \"Loop <b>x</b>\"\n",
        dir.join("state").display(),
        mock.addr
    );
    let mut server = Running::start(&dir, &text);
    server.wait_ready();
    let host = ui.to_string();
    let origin = format!("http://{ui}");
    let post = |fields: &[(&str, &str)]| {
        let (status, _, body) = http_post(ui, "/rules", &[("Host", &host), ("Origin", &origin)], &form(fields), None);
        assert_eq!(status, 200, "{body}");
        body
    };
    let test = |name: &str, client: &str| post(&[("name", name), ("qtype", "A"), ("client", client)]);

    // The tester agrees with the real answer, name by name.
    let mut id = 100;
    let mut real = |name: &str| {
        id += 1;
        udp_exchange(addr, &query(name, id), Duration::from_secs(3)).expect("an answer")
    };
    for (name, verdict) in [
        ("blocked.test", "Blocked"),
        ("a.b.blocked.test", "Blocked"),
        ("listed.test", "Blocked"),
        ("hosts.test", "Blocked"),
        ("ok.blocked.test", "Forwarded"),
        ("fresh.test", "Forwarded"),
        ("rw.test", "Rewrite"),
        ("localhost", "Special-use name"),
    ] {
        let page = test(name, "");
        assert!(page.contains("<span class=\"tag ") && page.contains(&format!(">{verdict}</span>")), "{name}: {page}");
        let answer = real(name);
        match verdict {
            "Blocked" => {
                assert_eq!(answer.metadata.response_code, ResponseCode::NXDomain, "{name}");
                assert!(page.contains("NXDOMAIN"), "{name}");
            }
            "Rewrite" => {
                assert!(page.contains("NOERROR 192.0.2.77"), "{page}");
                assert_eq!(answer.answers[0].data.to_string(), "192.0.2.77");
            }
            "Special-use name" => {
                assert!(page.contains("NOERROR 127.0.0.1") && answer.answers[0].data.to_string() == "127.0.0.1")
            }
            _ => assert_eq!(answer.answers[0].data.to_string(), "192.0.2.1", "{name} reached the upstream"),
        }
    }
    // A client in no_filter_clients is exempt; a stranger is refused.
    let page = test("blocked.test", "10.9.9.9");
    assert!(page.contains(">Forwarded</span>") && page.contains("exempt from filtering"), "{page}");
    assert!(page.contains("decides"), "the rule still shows: {page}");
    let page = test("blocked.test", "8.8.8.8");
    assert!(page.contains(">Refused</span>") && page.contains("allowed_clients"), "{page}");

    // Rules come with their list and line; secrets never show.
    let page = test("listed.test", "");
    assert!(
        page.contains("<code>||listed.test^</code>") && page.contains(&list_url) && page.contains("line 2"),
        "{page}"
    );
    assert!(
        page.contains("data-copy=\"@@||listed.test^$important\"") && page.contains("data-copy=\"||listed.test^\""),
        "{page}"
    );
    let page = test("x.hosts.test", "");
    assert!(page.contains("Forwarded") && page.contains("applies to that exact host only"), "{page}");
    let page = test("hosts.test", "");
    assert!(
        page.contains("<code>|hosts.test^</code>") && page.contains("in the list as <code>0.0.0.0 hosts.test</code>"),
        "{page}"
    );
    let page = test("ok.blocked.test", "");
    assert!(page.find("@@||ok.blocked.test^").unwrap() < page.find("||blocked.test^").unwrap(), "allow first: {page}");
    assert!(page.contains("user rules") && page.contains("overridden") && page.contains("line 2"), "{page}");
    for page in [post(&[("name", "listed.test")]), http(ui, "GET", "/rules").2, http(ui, "GET", "/clients").2] {
        assert!(!page.contains("SECRETTOKEN") && !page.contains("{{"), "{page}");
    }

    // Bad input and hostile input.
    let page = test("", "");
    assert!(page.contains("Enter a domain name"), "{page}");
    let page = test("x.test", "not-an-ip");
    assert!(page.contains("must be an IP address"), "{page}");
    let evil = "<img src=x onerror=alert(1)>.test";
    let page = post(&[("name", evil), ("qtype", "\"><script>alert(2)</script>"), ("client", "<b>")]);
    assert!(!page.contains("<img") && !page.contains("<script>alert") && !page.contains("<b>"), "{page}");
    assert!(page.contains("&lt;img src=x onerror=alert(1)&gt;"), "the echo is escaped: {page}");

    // The editor: errors with line numbers, normalized output.
    let page = post(&[("rules", "||a.test^\r\n! note\r\nbad rule here\r\nplain.test\r\n||x^$third-party\r\n</textarea><script>alert(3)</script>")]);
    assert!(page.contains("2 rules accepted, 3 errors"), "{page}");
    for line in [3, 5, 6] {
        assert!(page.contains(&format!("<td class=\"num\">{line}</td>")), "line {line}: {page}");
    }
    assert!(
        page.contains("||plain.test^") && page.contains("user_rules = [") && !page.contains("<script>alert"),
        "{page}"
    );
    let (_, _, page) = http(ui, "GET", "/rules");
    assert!(
        page.contains("||blocked.test^\n@@||ok.blocked.test^</textarea>"),
        "prefilled with the current rules: {page}"
    );
    assert!(page.contains("rw.test") && page.contains("192.0.2.77") && !page.contains("id=\"validation\""), "{page}");
    assert!(page.contains("Test a domain") && page.contains("href=\"/clients\""), "{page}");

    // POSTs are same-origin, small and only on /rules.
    let ok = form(&[("name", "blocked.test")]);
    let refused = |headers: &[(&str, &str)]| http_post(ui, "/rules", headers, &ok, None).0;
    assert_eq!(refused(&[("Host", &host)]), 403, "no Origin and no Sec-Fetch-Site");
    assert_eq!(refused(&[("Host", &host), ("Origin", "http://evil.example")]), 403);
    assert_eq!(refused(&[("Host", &host), ("Origin", "null")]), 403);
    assert_eq!(refused(&[("Host", &host), ("Origin", &origin), ("Sec-Fetch-Site", "cross-site")]), 403);
    assert_eq!(refused(&[("Host", &host), ("Sec-Fetch-Site", "same-site")]), 403);
    assert_eq!(refused(&[("Host", &host), ("Sec-Fetch-Site", "same-origin")]), 200);
    assert_eq!(refused(&[("Host", "attacker.example"), ("Origin", "http://attacker.example")]), 403, "rebinding");
    // Browsers send `Origin: null` on POSTs from a `no-referrer` page, which
    // broke every form; the policy must let the real Origin through.
    let (_, head, _) = http_post(ui, "/rules", &[("Host", &host), ("Origin", &origin)], &ok, None);
    assert!(head.to_ascii_lowercase().contains("referrer-policy: same-origin"), "{head}");
    // A refusal is readable text, not an empty body a browser saves as a file.
    let (status, head, body) = http_post(ui, "/rules", &[("Host", &host), ("Origin", "null")], &ok, None);
    assert_eq!(status, 403);
    assert!(head.to_ascii_lowercase().contains("content-type: text/plain"), "{head}");
    assert!(body.contains("cross-site"), "{body}");
    let (status, head, _) = http_post(ui, "/rules", &[("Host", &host), ("Origin", &origin)], "", Some(70_000));
    assert_eq!(status, 413, "{head}");
    assert!(head.to_ascii_lowercase().contains("connection: close"), "{head}");
    assert_eq!(http_post(ui, "/log", &[("Host", &host), ("Origin", &origin)], &ok, None).0, 405);
    assert_eq!(http_post(ui, "/clients", &[("Host", &host), ("Origin", &origin)], &ok, None).0, 405);
    assert_eq!(http(ui, "POST", "/rules").0, 403, "a bare POST is not same-origin");
    for path in ["/rules", "/clients"] {
        assert_eq!(http_host(ui, "GET", path, "attacker.example").0, 403, "{path}");
    }

    // Clients: the sketch counts, names are escaped, filtering state shows.
    assert!(
        eventually(Duration::from_secs(10), || http(ui, "GET", "/clients").2.contains("<td class=\"num\">8</td>")),
        "the log never fed the client sketch"
    );
    let (status, head, page) = http(ui, "GET", "/clients");
    assert_eq!(status, 200);
    assert!(head.to_ascii_lowercase().contains("content-security-policy: default-src 'self'"), "{head}");
    assert!(
        page.contains("<span class=\"mono\">127.0.0.1</span>") && page.contains("Loop &lt;b&gt;x&lt;/b&gt;"),
        "{page}"
    );
    assert!(!page.contains("<b>x") && !page.contains("SECRETTOKEN"), "{page}");
    assert!(
        page.contains("<span class=\"mono\">10.9.9.9</span>")
            && page.contains("no_filter_clients")
            && page.contains(">TV<"),
        "{page}"
    );
    assert!(page.contains("<span class=\"tag ok\">on</span>"), "{page}");
    assert!(!page.contains("<style") && !page.contains("style=\"") && !page.contains("<script>"), "no inline code");
    // The tester counted nothing: only real queries reach the counters.
    let (_, _, metrics) = http(ui, "GET", "/metrics");
    let queries: f64 = metrics
        .lines()
        .filter(|l| l.starts_with("dns_queries_total{"))
        .map(|l| l.rsplit_once(' ').unwrap().1.parse::<f64>().unwrap())
        .sum();
    assert_eq!(queries, 8.0, "the tester does not count or log: {metrics}");
}

/// Reads from `stream` until `needle` shows up or `limit` passes.
fn read_until(stream: &mut TcpStream, needle: &str, limit: Duration) -> String {
    stream.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
    let deadline = Instant::now() + limit;
    let mut seen = Vec::new();
    let mut buf = [0u8; 4096];
    while Instant::now() < deadline {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => seen.extend_from_slice(&buf[..n]),
            Err(_) => {}
        }
        if String::from_utf8_lossy(&seen).contains(needle) {
            break;
        }
    }
    String::from_utf8_lossy(&seen).into_owned()
}

fn open_stream(ui: SocketAddr, query: &str) -> TcpStream {
    let mut stream = tcp_connect(ui);
    write!(stream, "GET /api/log/stream?{query} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").unwrap();
    stream
}

/// `/api/log/stream`: Server-Sent Events with the filter applied, a hard cap
/// on concurrent tails, and no streams when the log is off.
#[test]
fn ui_live_tail_streams_filtered_rows_within_a_cap() {
    let mock = UdpMock::start(1, true);
    let addr = free_addr();
    let ui = free_tcp_addr();
    let dir = temp_dir("ui-stream");
    let text = format!(
        "listen = \"{addr}\"\nstate_dir = \"{}\"\nupstreams = []\nfallback = [\"{}\"]\nui_listen = \"{ui}\"\n\
         upstream_0x20 = false\nforward_test_names = true\nuser_rules = [\"||ads.test^\"]\n",
        dir.join("state").display(),
        mock.addr
    );
    let mut server = Running::start(&dir, &text);
    server.wait_ready();

    let mut tail = open_stream(ui, "result=blocked");
    let head = read_until(&mut tail, "retry:", Duration::from_secs(3)).to_ascii_lowercase();
    assert!(head.starts_with("http/1.1 200"), "{head}");
    assert!(head.contains("content-type: text/event-stream") && head.contains("cache-control: no-store"), "{head}");
    // Three more tails fill the cap of four; the fifth is refused.
    let tails: Vec<_> = (0..3).map(|_| open_stream(ui, "")).collect();
    for tail in &tails {
        let mut tail = tail.try_clone().unwrap();
        assert!(read_until(&mut tail, "retry:", Duration::from_secs(3)).contains("retry:"));
    }
    assert_eq!(http(ui, "GET", "/api/log/stream").0, 503);

    // Only the blocked query reaches the filtered tail.
    assert_eq!(response_code(addr, "fresh.test", 1), Some(ResponseCode::NoError));
    assert_eq!(response_code(addr, "ads.test", 2), Some(ResponseCode::NXDomain));
    let events = read_until(&mut tail, "ads.test", Duration::from_secs(5));
    assert!(events.contains("data: <tr>") && events.contains("ads.test"), "{events}");
    assert!(!events.contains("fresh.test"), "the filter applies to the stream: {events}");

    // Closing a tail frees its slot.
    drop(tail);
    assert!(
        eventually(Duration::from_secs(5), || http(ui, "GET", "/api/log/stream?x=1").0 == 200),
        "a closed stream must free its slot"
    );
}

#[test]
fn ui_query_log_can_be_turned_off() {
    let addr = free_addr();
    let ui = free_tcp_addr();
    let dir = temp_dir("ui-log-off");
    let text = format!(
        "listen = \"{addr}\"\nstate_dir = \"{}\"\nupstreams = []\nfallback = []\nui_listen = \"{ui}\"\n\
         query_log_capacity = 0\nuser_rules = [\"||blocked.test^\"]\n",
        dir.join("state").display()
    );
    let mut server = Running::start(&dir, &text);
    server.wait_ready();
    assert_eq!(response_code(addr, "blocked.test", 1), Some(ResponseCode::NXDomain));
    let (_, _, log) = http(ui, "GET", "/api/log");
    assert!(log.contains("\"enabled\":false") && log.contains("\"entries\":[]"), "{log}");
    assert_eq!(http(ui, "GET", "/api/log/stream").0, 404);
    let (_, _, dash) = http(ui, "GET", "/api/dashboard");
    assert!(dash.contains("\"log\":{\"enabled\":false"), "{dash}");
    // The counters and windows do not depend on the log.
    assert!(dash.contains("\"queries\":1,"), "{dash}");
    let (_, _, page) = http(ui, "GET", "/");
    assert!(page.contains("query log is off"), "{page}");
}

/// `/healthz` stays 503 until a configured list has loaded once.
#[test]
fn healthz_is_unready_while_no_blocklist_has_loaded() {
    let addr = free_addr();
    let ui = free_tcp_addr();
    let dir = temp_dir("ui-healthz-lists");
    // Nothing listens on 127.0.0.1:1, so the download fails and nothing is cached.
    let text = format!(
        "listen = \"{addr}\"\nstate_dir = \"{}\"\nupstreams = []\nfallback = []\nui_listen = \"{ui}\"\n\
         blocklists = [\"http://127.0.0.1:1/list.txt\"]\n",
        dir.join("state").display()
    );
    let mut server = Running::start(&dir, &text);
    server.wait_ready();
    let (status, _, body) = http(ui, "GET", "/healthz");
    assert_eq!((status, body.as_str()), (503, "not ready\n"));
    // The failure is visible, and the name is the sanitized one.
    let (_, _, metrics) = http(ui, "GET", "/metrics");
    assert_eq!(metric(&metrics, "dns_blocklist_rules{list=\"http://127.0.0.1:1/list.txt\"}"), 0.0);
    assert!(!metrics.contains("dns_blocklist_last_success_timestamp{"));
}

/// A taken `ui_listen` is a clear startup error, not a silent missing UI.
#[test]
fn ui_bind_failure_is_a_startup_error() {
    let addr = free_addr();
    let taken = TcpListener::bind("127.0.0.1:0").unwrap();
    let ui = taken.local_addr().unwrap();
    let dir = temp_dir("ui-bind");
    let text = format!(
        "listen = \"{addr}\"\nstate_dir = \"{}\"\nupstreams = []\nfallback = []\nui_listen = \"{ui}\"\n",
        dir.join("state").display()
    );
    let mut server = Running::start(&dir, &text);
    let status = server.wait_exit(Duration::from_secs(10));
    assert!(!status.success());
    let stderr = server.stderr();
    assert!(stderr.contains(&format!("cannot bind ui_listen {ui}")), "stderr: {stderr}");
    assert!(stderr.contains("ui_enabled = false"), "stderr: {stderr}");
}

/// Readiness is `/healthz`; liveness stays the TCP socket on :53 so a stuck
/// HTTP listener never restarts a resolver that still answers.
#[test]
fn deploy_manifest_probes_follow_the_core_plan() {
    let manifest = uncommented(include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/deploy/kubernetes.yaml")));
    let probe = |name: &str| {
        let (_, rest) = manifest.split_once(&format!("{name}:")).unwrap_or_else(|| panic!("no {name}"));
        rest.lines()
            .take_while(|line| line.starts_with("            ") || line.trim().is_empty())
            .collect::<Vec<_>>()
            .join("\n")
    };
    let readiness = probe("readinessProbe");
    assert!(readiness.contains("httpGet:") && readiness.contains("path: /healthz"), "{readiness}");
    let liveness = probe("livenessProbe");
    assert!(liveness.contains("tcpSocket:") && liveness.contains("port: 53"), "{liveness}");
}

/// The SIGHUP handler is installed before the listeners bind: a reload signal
/// sent the moment the port answers must reload, never kill the process (the
/// default SIGHUP action).
#[cfg(unix)]
#[test]
fn sighup_right_after_the_port_opens_does_not_kill_the_server() {
    let addr = free_addr();
    let dir = temp_dir("early-sighup");
    let text = config(addr, &dir, &[], "user_rules = [\"||blocked.test^\"]");
    let mut server = Running::start(&dir, &text);
    assert!(
        eventually(Duration::from_secs(10), || response_code(addr, "blocked.test", 1).is_some()),
        "the server never answered"
    );
    for _ in 0..5 {
        server.signal("HUP");
    }
    thread::sleep(Duration::from_millis(300));
    assert!(server.child.try_wait().unwrap().is_none(), "SIGHUP killed the server\n{}", server.stderr());
    assert_eq!(response_code(addr, "blocked.test", 2), Some(ResponseCode::NXDomain));
    server.signal("TERM");
    server.wait_exit(Duration::from_secs(10));
}

/// An A query with EDNS (no DO): the pre-warm queries carry the same flags, so
/// they share a cache entry with this client.
fn edns_query(name: &str, id: u16) -> Vec<u8> {
    let mut message = Message::from_vec(&query(name, id)).unwrap();
    let mut edns = hickory_proto::op::Edns::new();
    edns.set_max_payload(1232);
    message.set_edns(edns);
    message.to_vec().unwrap()
}

/// SIGTERM saves the busiest forwarded names (0600), the next boot resolves
/// them through the normal path without touching the client stats, and a client
/// query for one is then a cache hit.
#[test]
fn prewarm_saves_on_sigterm_and_warms_the_cache_on_the_next_boot() {
    let upstream = UdpMock::start(7, true);
    let addr = free_addr();
    let ui = free_tcp_addr();
    let dir = temp_dir("prewarm");
    let text = format!(
        "listen = \"{addr}\"\nstate_dir = \"{}\"\nupstreams = []\nfallback = [\"{}\"]\nui_listen = \"{ui}\"\n\
         upstream_0x20 = false\nforward_test_names = true\nuser_rules = [\"||blocked.test^\"]\n\
         prewarm_count = 3\npersist_stats = false\n",
        dir.join("state").display(),
        upstream.addr
    );
    let file = dir.join("state/prewarm.txt");
    let mut first = Running::start(&dir, &text);
    first.wait_ready();
    let ask = |name: &str, times: u16| {
        for id in 0..times {
            let answer = udp_exchange(addr, &edns_query(name, id), Duration::from_secs(3)).expect("answer");
            assert_eq!(answer.metadata.id, id);
        }
    };
    ask("busy.test", 5);
    ask("less.test", 3);
    ask("rare.test", 1);
    ask("blocked.test", 9); // blocked names are never pre-warmed
    first.signal("TERM");
    assert!(first.wait_exit(Duration::from_secs(10)).success());
    assert_eq!(fs::read_to_string(&file).unwrap(), "busy.test\nless.test\nrare.test\n");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
    }

    let before = upstream.queries.load(Ordering::Relaxed);
    let mut second = Running::start(&dir, &text);
    second.wait_ready();
    assert!(
        eventually(Duration::from_secs(10), || upstream.queries.load(Ordering::Relaxed) == before + 6),
        "A and AAAA for three names: {} -> {}",
        before,
        upstream.queries.load(Ordering::Relaxed)
    );
    assert!(eventually(Duration::from_secs(5), || second.stdout().contains("msg=prewarm_done")));
    let (_, _, metrics) = http(ui, "GET", "/metrics");
    for result in ["upstream", "cache", "stale", "servfail", "other", "dropped", "blocked", "local"] {
        assert_eq!(metric(&metrics, &format!("dns_queries_total{{result=\"{result}\"}}")), 0.0, "{result}");
    }
    // (The mock answers AAAA with an A record, which the cache refuses.)
    assert!(metric(&metrics, "dns_cache_entries") >= 3.0, "the A answers are cached");

    let hit = udp_exchange(addr, &edns_query("busy.test", 77), Duration::from_secs(3)).expect("answer");
    assert_eq!(first_a(&hit), Some(Ipv4Addr::new(192, 0, 2, 7)));
    assert_eq!(upstream.queries.load(Ordering::Relaxed), before + 6, "the client query is a cache hit");
    let (_, _, metrics) = http(ui, "GET", "/metrics");
    assert_eq!(metric(&metrics, "dns_queries_total{result=\"cache\"}"), 1.0);
    // The pre-warm queries are not in the query log either.
    let (_, _, log) = http(ui, "GET", "/api/log?limit=50");
    assert_eq!(log.matches("\"name\"").count(), 1, "only the client query is logged (no pre-warm):\n{log}");
    second.signal("TERM");
    assert!(second.wait_exit(Duration::from_secs(10)).success());

    // prewarm = false: nothing is warmed and the file is removed at startup.
    let off = format!("{text}prewarm = false\n");
    let mut third = Running::start(&dir, &off);
    third.wait_ready();
    assert!(!file.exists(), "the saved list is removed when pre-warm is off");
    let queries = upstream.queries.load(Ordering::Relaxed);
    thread::sleep(Duration::from_millis(500));
    assert_eq!(upstream.queries.load(Ordering::Relaxed), queries);
    ask("busy.test", 1);
    third.signal("TERM");
    assert!(third.wait_exit(Duration::from_secs(10)).success());
    assert!(!file.exists(), "no list is written when pre-warm is off");
}

/// The dashboard stats survive a restart: counters, the latency histogram and
/// the top lists come back from `state_dir/stats.v1` (0600), a corrupt file is
/// ignored with a warning, and `persist_stats = false` deletes it.
#[test]
fn stats_survive_a_restart_and_persist_stats_false_deletes_the_file() {
    let upstream = UdpMock::start(7, true);
    let addr = free_addr();
    let ui = free_tcp_addr();
    let dir = temp_dir("stats-persist");
    let text = format!(
        "listen = \"{addr}\"\nstate_dir = \"{}\"\nupstreams = []\nfallback = [\"{}\"]\nui_listen = \"{ui}\"\n\
         upstream_0x20 = false\nforward_test_names = true\nuser_rules = [\"||blocked.test^\"]\nprewarm = false\n",
        dir.join("state").display(),
        upstream.addr
    );
    let file = dir.join("state/stats.v1");
    let ask = |name: &str, times: u16| {
        for id in 0..times {
            udp_exchange(addr, &edns_query(name, id), Duration::from_secs(3)).expect("answer");
        }
    };
    let counts = |metrics: &str| {
        let total: f64 = ["upstream", "cache", "blocked"]
            .iter()
            .map(|result| metric(metrics, &format!("dns_queries_total{{result=\"{result}\"}}")))
            .sum();
        (total, metric(metrics, "dns_request_duration_seconds_count"))
    };

    let mut first = Running::start(&dir, &text);
    first.wait_ready();
    ask("busy.test", 5);
    ask("blocked.test", 3);
    let (_, _, metrics) = http(ui, "GET", "/metrics");
    let (total, timed) = counts(&metrics);
    assert!(total >= 8.0, "{metrics}");
    first.signal("TERM");
    assert!(first.wait_exit(Duration::from_secs(10)).success());
    let saved = fs::read_to_string(&file).unwrap();
    assert!(saved.starts_with("sopedu-stats v1\n"), "{saved}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
    }

    let mut second = Running::start(&dir, &text);
    second.wait_ready();
    assert!(second.stdout().contains("msg=stats_restored"), "{}", second.stdout());
    let (_, _, metrics) = http(ui, "GET", "/metrics");
    assert_eq!(counts(&metrics), (total, timed), "counters carry on after the restart");
    let (_, _, dash) = http(ui, "GET", "/api/dashboard");
    assert!(dash.contains("busy.test"), "top domains are restored: {dash}");
    assert!(dash.contains("blocked.test"), "top blocked is restored: {dash}");
    let (_, _, page) = http(ui, "GET", "/");
    assert!(page.contains("count since"), "the dashboard says since when");
    ask("busy.test", 2);
    let (_, _, metrics) = http(ui, "GET", "/metrics");
    assert_eq!(counts(&metrics).0, total + 2.0, "new queries add to the restored total");
    second.signal("TERM");
    assert!(second.wait_exit(Duration::from_secs(10)).success());

    // A corrupt file is ignored with one warning; the server still serves.
    fs::write(&file, "sopedu-stats v1\nnot a stats file\n").unwrap();
    let mut third = Running::start(&dir, &text);
    third.wait_ready();
    assert_eq!(third.stdout().matches("msg=stats_ignored").count(), 1, "{}", third.stdout());
    let (_, _, metrics) = http(ui, "GET", "/metrics");
    assert_eq!(counts(&metrics).0, 0.0);
    third.signal("TERM");
    assert!(third.wait_exit(Duration::from_secs(10)).success());
    assert!(fs::read_to_string(&file).unwrap().starts_with("sopedu-stats v1\n"), "a good file replaces the bad one");

    // persist_stats = false: the file is deleted at startup and never written.
    let off = format!("{text}persist_stats = false\n");
    let mut fourth = Running::start(&dir, &off);
    fourth.wait_ready();
    assert!(!file.exists(), "the snapshot is removed when persistence is off");
    ask("busy.test", 1);
    fourth.signal("TERM");
    assert!(fourth.wait_exit(Duration::from_secs(10)).success());
    assert!(!file.exists(), "nothing is written when persistence is off");
}

/// DNSBomb defence: a UDP reply is not sent to a query that waited longer than
/// `udp_discard_timeout_ms`. The answer is still cached, TCP still gets it, and
/// the discard is counted as `dropped`.
#[test]
fn udp_reply_to_a_query_that_waited_too_long_is_discarded_but_cached() {
    let upstream = DelayedUdpMock::start(7, Duration::from_millis(700));
    let addr = free_addr();
    let ui = free_tcp_addr();
    let dir = temp_dir("udp-discard");
    let text = format!(
        "listen = \"{addr}\"\nstate_dir = \"{}\"\nupstreams = []\nfallback = [\"{}\"]\nui_listen = \"{ui}\"\n\
         upstream_0x20 = false\nforward_test_names = true\nudp_discard_timeout_ms = 300\n\
         serve_stale_client_timeout_ms = 0\n",
        dir.join("state").display(),
        upstream.addr
    );
    let mut server = Running::start(&dir, &text);
    server.wait_ready();

    // Held 700 ms against a 300 ms limit: no datagram at all.
    assert!(udp_exchange(addr, &query("slow.test", 1), Duration::from_millis(1500)).is_none());
    assert_eq!(upstream.queries.load(Ordering::Relaxed), 1);
    let (_, _, metrics) = http(ui, "GET", "/metrics");
    assert_eq!(metric(&metrics, "dns_queries_total{result=\"dropped\"}"), 1.0, "the discard is counted");

    // The answer was cached: the retry is answered at once, without a new upstream query.
    let started = Instant::now();
    let retry = udp_exchange(addr, &query("slow.test", 2), Duration::from_secs(2)).expect("cached answer");
    assert_eq!(retry.metadata.response_code, ResponseCode::NoError);
    assert_eq!(retry.answers.len(), 1);
    assert!(started.elapsed() < Duration::from_millis(300));
    assert_eq!(upstream.queries.load(Ordering::Relaxed), 1);

    // TCP has no discard: a slow query is answered however long it waited.
    let mut stream = tcp_connect(addr);
    tcp_send(&mut stream, &query("slow-tcp.test", 3)).unwrap();
    let answer = tcp_receive(&mut stream).expect("TCP answer after the same delay");
    assert_eq!(answer.metadata.response_code, ResponseCode::NoError);
    assert_eq!(answer.answers.len(), 1);
}

/// RFC 8767 §5 by default: a stale hit first tries to refresh, and the stale
/// copy goes out at the 1.8 s client response timer, which the default
/// 1.9 s UDP discard limit must not swallow.
#[test]
fn default_stale_answer_on_the_client_timer_is_not_discarded() {
    // The first query is answered with TTL 1; every later one is ignored.
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let upstream = socket.local_addr().unwrap();
    let queries = Arc::new(AtomicUsize::new(0));
    let seen = queries.clone();
    thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok((n, peer)) = socket.recv_from(&mut buf) {
            let Ok(question) = Message::from_vec(&buf[..n]) else { continue };
            if seen.fetch_add(1, Ordering::Relaxed) > 0 {
                continue;
            }
            let mut answer = Message::new(question.metadata.id, MessageType::Response, OpCode::Query);
            answer.metadata.recursion_available = true;
            answer.add_queries(question.queries.iter().cloned());
            let name = question.queries[0].name().clone();
            answer.add_answer(Record::from_rdata(name, 1, RData::A(A(Ipv4Addr::new(192, 0, 2, 7)))));
            let _ = socket.send_to(&answer.to_vec().unwrap(), peer);
        }
    });
    let addr = free_addr();
    let dir = temp_dir("stale-timer");
    // Plain answers are served stale only when the plain servers are trusted.
    let text = config(addr, &dir, &[upstream], "trust_plain_upstreams = true\nprefetch = false");
    let mut server = Running::start(&dir, &text);
    server.wait_ready();
    let first = udp_exchange(addr, &query("stale.test", 1), Duration::from_secs(2)).expect("fresh answer");
    assert_eq!(first.answers.len(), 1);
    thread::sleep(Duration::from_millis(1500));

    let started = Instant::now();
    let stale = udp_exchange(addr, &query("stale.test", 2), Duration::from_secs(4)).expect("stale answer is sent");
    let elapsed = started.elapsed();
    assert_eq!(stale.answers.len(), 1);
    assert_eq!(stale.answers[0].ttl, 30, "the RFC 8767 stale copy");
    assert!(elapsed >= Duration::from_millis(1700), "a refresh was tried first: {elapsed:?}");
    assert_eq!(queries.load(Ordering::Relaxed), 2, "one refresh went upstream");
}

/// `udp_discard_timeout_ms = 0` turns the discard off: the late reply is sent.
#[test]
fn udp_discard_can_be_disabled() {
    let upstream = DelayedUdpMock::start(8, Duration::from_millis(700));
    let addr = free_addr();
    let dir = temp_dir("udp-discard-off");
    let text = config(addr, &dir, &[upstream.addr], "udp_discard_timeout_ms = 0");
    let mut server = Running::start(&dir, &text);
    server.wait_ready();
    let late = udp_exchange(addr, &query("late.test", 1), Duration::from_secs(3)).expect("late reply");
    assert_eq!(late.metadata.response_code, ResponseCode::NoError);
    assert_eq!(late.answers.len(), 1);
}

/// The default limit (1900 ms) leaves ordinary latencies alone.
#[test]
fn udp_discard_default_leaves_a_slow_but_ordinary_reply_alone() {
    let upstream = DelayedUdpMock::start(9, Duration::from_millis(700));
    let addr = free_addr();
    let dir = temp_dir("udp-discard-default");
    let text = config(addr, &dir, &[upstream.addr], "");
    let mut server = Running::start(&dir, &text);
    server.wait_ready();
    let reply = udp_exchange(addr, &query("ordinary.test", 1), Duration::from_secs(3)).expect("reply");
    assert_eq!(reply.answers.len(), 1);
}

/// Per-client upstream cap end to end: one flooding host cannot take every upstream slot while
/// another asks; over UDP the surplus gets TC=1 at once (the source may be
/// forged; a genuine client retries over TCP). Loopback is one host, so the
/// cap is checked against the same client's own surplus.
#[test]
fn per_client_upstream_cap_answers_tc_for_the_surplus_and_tcp_still_works() {
    let upstream = DelayedUdpMock::start(5, Duration::from_millis(500));
    let addr = free_addr();
    let dir = temp_dir("per-client-cap");
    let text = config(addr, &dir, &[upstream.addr], "upstream_inflight_per_client = 2");
    let mut server = Running::start(&dir, &text);
    server.wait_ready();
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    for id in 0..6u16 {
        socket.send_to(&query(&format!("surplus{id}"), id + 1), addr).unwrap();
    }
    let mut buf = [0u8; 4096];
    let (mut failed, mut answered) = (0, 0);
    let started = Instant::now();
    for index in 0..6 {
        let (n, _) = socket.recv_from(&mut buf).unwrap();
        let reply = Message::from_vec(&buf[..n]).unwrap();
        match (reply.metadata.response_code, reply.metadata.truncation) {
            (ResponseCode::NoError, true) => {
                failed += 1;
                assert!(reply.answers.is_empty() && reply.queries.len() == 1);
                assert!(started.elapsed() < Duration::from_millis(400), "TC comes at once, reply {index}");
            }
            (ResponseCode::NoError, false) => answered += 1,
            other => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!((failed, answered), (4, 2));
    assert_eq!(upstream.queries.load(Ordering::Relaxed), 2, "only two reached the upstream");
    // The same surplus name over TCP, which has its own table, is served
    // once the two UDP slots have been released.
    let mut stream = tcp_connect(addr);
    tcp_send(&mut stream, &query("surplus5", 99)).unwrap();
    let answer = tcp_receive(&mut stream).expect("TCP answer");
    assert_eq!(answer.metadata.response_code, ResponseCode::NoError);
    assert_eq!(answer.answers.len(), 1);
}

/// The discard covers replies that carry data. A SERVFAIL after an upstream
/// timeout is no bigger than the query, so it is still sent.
#[test]
fn udp_discard_still_sends_servfail_after_an_upstream_timeout() {
    let upstream = UdpMock::start(1, false);
    let addr = free_addr();
    let dir = temp_dir("udp-discard-servfail");
    let text = config(addr, &dir, &[upstream.addr], "udp_discard_timeout_ms = 300\nupstream_timeout_seconds = 1");
    let mut server = Running::start(&dir, &text);
    server.wait_ready();
    let reply = udp_exchange(addr, &query("blackhole.test", 1), Duration::from_secs(4)).expect("SERVFAIL reply");
    assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
}

/// Sends one query from `client` to `target` and returns the source address
/// of the reply, or `None` when no reply arrived.
fn reply_source(client: &str, target: SocketAddr) -> Option<SocketAddr> {
    let socket = UdpSocket::bind((client, 0)).unwrap();
    socket.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    socket.send_to(&query("blocked.test", 7), target).unwrap();
    let mut buf = [0u8; 4096];
    let (_, from) = socket.recv_from(&mut buf).ok()?;
    Some(from)
}

/// RFC 8085 5.1: on a wildcard bind the reply leaves from the address the
/// client queried, on both the plain and the batched (Linux) receive path.
#[test]
fn wildcard_bind_replies_from_the_queried_address() {
    // 127.0.0.2 is on loopback by default on Linux, an alias on macOS.
    if UdpSocket::bind("127.0.0.2:0").is_err() {
        eprintln!("skipped: 127.0.0.2 is not configured on this host");
        return;
    }
    for batch in [0, 32] {
        let port = free_addr().port();
        let dir = temp_dir("wildcard-v4");
        let text = config(
            SocketAddr::from(([0, 0, 0, 0], port)),
            &dir,
            &[],
            &format!("udp_batch = {batch}\nuser_rules = [\"||blocked.test^\"]"),
        );
        let mut server = Running::start(&dir, &text);
        server.wait_ready();
        for target in ["127.0.0.2", "127.0.0.1"] {
            let target = SocketAddr::new(target.parse().unwrap(), port);
            assert_eq!(reply_source("127.0.0.1", target), Some(target), "udp_batch = {batch}");
        }
    }
}

#[test]
fn wildcard_v6_bind_still_answers_on_loopback() {
    let Ok(probe) = UdpSocket::bind("[::1]:0") else {
        eprintln!("skipped: IPv6 loopback is not available");
        return;
    };
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    let dir = temp_dir("wildcard-v6");
    let text = config(
        SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, port)),
        &dir,
        &[],
        "user_rules = [\"||blocked.test^\"]",
    );
    let mut server = Running::start(&dir, &text);
    server.wait_ready();
    let target = SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, port));
    assert_eq!(reply_source("::1", target), Some(target));
}

/// DoH upstream certificates are verified against the system trust store,
/// here `SSL_CERT_FILE` as in the scratch image: a chain to that CA whose IP
/// SAN matches the URL answers; a chain to another CA, or to the right CA
/// for another name, fails closed (SERVFAIL, no request reaches the upstream,
/// and the upstream sees the client's TLS alert).
#[test]
fn doh_upstream_certificates_are_verified_against_ssl_cert_file() {
    let tls = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/tls");
    for (case, leaf, ca, alert) in [
        ("trusted", "leaf.pem", "ca.pem", None),
        ("unknown-ca", "leaf.pem", "other-ca.pem", Some("UnknownCA")),
        ("wrong-name", "wrong-name.pem", "ca.pem", Some("BadCertificate")),
    ] {
        let doh = DohTlsMock::start(leaf);
        let addr = free_addr();
        let dir = temp_dir(&format!("doh-tls-{case}"));
        let text = config(addr, &dir, &[], "").replace("upstreams = []", &format!("upstreams = [\"{}\"]", doh.url()));
        let mut server = Running::start_trusting(&dir, &text, &tls.join(ca));
        server.wait_ready();

        let reply = udp_exchange(addr, &query("doh-tls.test", 7), Duration::from_secs(10))
            .unwrap_or_else(|| panic!("{case}: no reply\nstdout:\n{}", server.stdout()));
        match alert {
            None => {
                assert_eq!(reply.metadata.response_code, ResponseCode::NoError, "{case}");
                assert_eq!(first_a(&reply), Some(Ipv4Addr::new(192, 0, 2, 7)), "{case}");
                assert!(doh.served.load(Ordering::Relaxed) > 0, "{case}");
            }
            Some(alert) => {
                assert_eq!(reply.metadata.response_code, ResponseCode::ServFail, "{case}");
                assert_eq!(doh.served.load(Ordering::Relaxed), 0, "{case}: a request passed an untrusted handshake");
                let errors = doh.handshake_errors.lock().unwrap().clone();
                assert!(
                    errors.iter().any(|error| error.contains(alert)),
                    "{case}: expected {alert} alert, got {errors:?}"
                );
            }
        }
    }
}
