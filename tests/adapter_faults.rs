//! Drives the conformance adapter's `faults` and `hash-collision` controls end
//! to end. Each test spawns its own adapter process, so the one-shot fault and
//! the forced hash never touch another test.
#![cfg(feature = "conformance-adapter")]

use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use hickory_proto::{
    op::{Message, MessageType, OpCode, Query, ResponseCode},
    rr::{rdata::A, Name, RData, Record, RecordType},
};
use serde_json::{json, Value};

type Tls = rustls::StreamOwned<rustls::ServerConnection, TcpStream>;
type Held = Arc<Mutex<Vec<(Tls, Vec<u8>)>>>;

/// A DoH server over TLS (the `tests/tls` leaf, HTTP/1.1). With `hold` it keeps every request
/// unanswered until `release`; otherwise it answers at once with an address
/// whose last octet is the first byte of the name.
struct Doh {
    addr: SocketAddr,
    /// Requests for the test names; the pool's own health probes are not counted.
    seen: Arc<Mutex<usize>>,
    held: Held,
}

fn answer(raw: &[u8]) -> Vec<u8> {
    let question = Message::from_vec(raw).unwrap();
    let name = question.queries[0].name().clone();
    let first = name.to_ascii().to_ascii_lowercase().bytes().next().unwrap();
    let mut reply = Message::new(question.metadata.id, MessageType::Response, OpCode::Query);
    reply.metadata.recursion_available = true;
    reply.add_queries(question.queries.iter().cloned());
    reply.add_answer(Record::from_rdata(name, 300, RData::A(A(Ipv4Addr::new(192, 0, 2, first)))));
    reply.to_vec().unwrap()
}

fn send(mut stream: Tls, body: &[u8]) {
    let head = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/dns-message\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

/// Reads one HTTP request and returns its body.
fn read_request(stream: &mut Tls) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
            let length: usize = head
                .split("content-length:")
                .nth(1)
                .and_then(|rest| rest.split("\r\n").next()?.trim().parse().ok())
                .unwrap_or(0);
            if buf.len() >= end + 4 + length {
                return Some(buf[end + 4..end + 4 + length].to_vec());
            }
        }
        match stream.read(&mut chunk) {
            Ok(n) if n > 0 => buf.extend_from_slice(&chunk[..n]),
            _ => return None,
        }
    }
}

impl Doh {
    fn start(hold: bool) -> Self {
        use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/tls");
        let chain =
            CertificateDer::pem_file_iter(dir.join("leaf.pem")).unwrap().collect::<Result<Vec<_>, _>>().unwrap();
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
        let addr = listener.local_addr().unwrap();
        let (seen, held): (_, Held) = (Arc::new(Mutex::new(0)), Arc::default());
        let (seen_in, held_in) = (seen.clone(), held.clone());
        thread::spawn(move || {
            for tcp in listener.incoming().flatten() {
                let (seen, held, config) = (seen_in.clone(), held_in.clone(), config.clone());
                thread::spawn(move || {
                    let mut stream = rustls::StreamOwned::new(rustls::ServerConnection::new(config).unwrap(), tcp);
                    let Some(body) = read_request(&mut stream) else { return };
                    let question = Message::from_vec(&body).unwrap();
                    if question.queries[0].name().to_ascii().ends_with(".test.") {
                        *seen.lock().unwrap() += 1;
                    }
                    if hold && question.queries[0].name().to_ascii().ends_with(".test.") {
                        held.lock().unwrap().push((stream, body));
                    } else {
                        send(stream, &answer(&body));
                    }
                });
            }
        });
        Self { addr, seen, held }
    }

    fn seen(&self) -> usize {
        *self.seen.lock().unwrap()
    }

    fn release(&self) {
        for (stream, body) in self.held.lock().unwrap().drain(..) {
            send(stream, &answer(&body));
        }
    }
}

struct Adapter {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    listen: SocketAddr,
    next: u64,
}

impl Adapter {
    fn start(upstream: SocketAddr, extra: Value) -> Self {
        let listen = UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_sopedu-dns"))
            .arg("--conformance-adapter")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let (stdin, stdout) = (child.stdin.take().unwrap(), BufReader::new(child.stdout.take().unwrap()));
        let mut adapter = Self { child, stdin, stdout, listen, next: 0 };
        let mut config = json!({
            "listen": listen.to_string(), "upstreams": [format!("https://{upstream}/dns-query")], "fallback": [],
            "blocklists": [], "ui_enabled": false, "trust_plain_upstreams": true, "forward_test_names": true,
            "upstream_timeout_seconds": 1,
        });
        config.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        let ca = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/tls/ca.pem")).unwrap();
        adapter.call("start", json!({"config": config, "trusted_cas": [ca]}));
        adapter
    }

    fn call(&mut self, method: &str, params: Value) -> Value {
        self.next += 1;
        let line = json!({"id": self.next, "method": method, "params": params});
        writeln!(self.stdin, "{line}").unwrap();
        let mut reply = String::new();
        self.stdout.read_line(&mut reply).unwrap();
        let reply: Value = serde_json::from_str(&reply).unwrap();
        assert!(reply.get("result").is_some(), "{method}: {reply}");
        reply["result"].clone()
    }

    /// Sends one UDP query from a thread and returns its eventual reply.
    fn ask(&self, name: &str, id: u16) -> thread::JoinHandle<(ResponseCode, Vec<Ipv4Addr>)> {
        let (listen, raw) = (self.listen, query(name, id));
        thread::spawn(move || {
            let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
            socket.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            socket.send_to(&raw, listen).unwrap();
            let mut buf = [0u8; 4096];
            let (n, _) = socket.recv_from(&mut buf).expect("no reply");
            let reply = Message::from_vec(&buf[..n]).unwrap();
            let ips = reply
                .answers
                .iter()
                .filter_map(|record| if let RData::A(a) = &record.data { Some(a.0) } else { None })
                .collect();
            (reply.metadata.response_code, ips)
        })
    }

    fn ask_now(&self, name: &str, id: u16) -> (ResponseCode, Vec<Ipv4Addr>) {
        self.ask(name, id).join().unwrap()
    }

    fn assert_clean(&mut self) {
        let state = self.call("snapshot", json!({}));
        for field in ["singleflight_keys", "singleflight_waiters", "upstream_inflight"] {
            assert_eq!(state[field], 0, "{field} leaked: {state}");
        }
    }
}

impl Drop for Adapter {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn query(name: &str, id: u16) -> Vec<u8> {
    let mut message = Message::new(id, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(Name::from_ascii(format!("{name}.")).unwrap(), RecordType::A));
    message.to_vec().unwrap()
}

fn wait_for(what: &str, mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(10));
    }
}

/// The fault ends the attempt within 100 ms (a plain dropped reply would
/// still be pending until the 1 s budget), and nothing is left behind.
fn attempt_fault(fault: &str) {
    let upstream = Doh::start(true);
    let mut adapter = Adapter::start(upstream.addr, json!({"cache_size": 0}));
    adapter.call("inject", json!({"fault": fault}));
    let client = adapter.ask("fault.test", 7);
    wait_for("the query to reach the upstream", || upstream.seen() == 1);
    adapter.call("advance", json!({"milliseconds": 100}));
    assert_eq!(client.join().unwrap().0, ResponseCode::ServFail, "{fault} ends the attempt");
    adapter.assert_clean();
    // One-shot: the next query is not faulted and runs to its timeout.
    let client = adapter.ask("again.test", 8);
    wait_for("the second query", || upstream.seen() == 2);
    adapter.call("advance", json!({"milliseconds": 5001}));
    assert_eq!(client.join().unwrap().0, ResponseCode::ServFail);
    adapter.assert_clean();
}

#[test]
#[cfg_attr(not(debug_assertions), ignore = "release builds use panic = \"abort\", so a panic ends the process")]
fn a_panicking_upstream_attempt_leaks_nothing() {
    attempt_fault("upstream_panic");
}

#[test]
fn a_failing_upstream_attempt_leaks_nothing() {
    attempt_fault("upstream_error");
}

#[test]
fn cancelled_waiters_leave_no_key_or_waiter() {
    let upstream = Doh::start(true);
    let mut adapter = Adapter::start(upstream.addr, json!({"cache_size": 0}));
    adapter.call("inject", json!({"fault": "cancel_all_waiters"}));
    let leader = adapter.ask("shared.test", 1);
    wait_for("the leader to reach the upstream", || upstream.seen() == 1);
    let follower = adapter.ask("shared.test", 2);
    wait_for("the follower to park", || adapter.call("snapshot", json!({}))["singleflight_waiters"] == 1);
    upstream.release();
    assert_eq!(leader.join().unwrap().0, ResponseCode::NoError, "the leader still answers");
    assert_eq!(follower.join().unwrap().0, ResponseCode::ServFail, "a cancelled waiter gets SERVFAIL, not a hang");
    assert_eq!(upstream.seen(), 1, "the follower never queried the upstream");
    adapter.assert_clean();
}

#[test]
fn forced_hash_collisions_keep_names_apart() {
    let upstream = Doh::start(false);
    let mut adapter = Adapter::start(upstream.addr, json!({}));
    adapter.call("inject", json!({"constant_hash": 0}));
    let (one, two) = ("aone.test", "btwo.test");
    let first = adapter.ask_now(one, 1);
    let second = adapter.ask_now(two, 2);
    assert_eq!(upstream.seen(), 2, "both names reached the upstream");
    assert_eq!((first.1[0].octets()[3], second.1[0].octets()[3]), (b'a', b'b'));
    // Cached: neither lookup is served the other's entry.
    assert_eq!(adapter.ask_now(one, 3).1, first.1);
    assert_eq!(adapter.ask_now(two, 4).1, second.1);
    assert_eq!(upstream.seen(), 2, "both were cache hits");
}
