//! Minimal UDP DNS mock for the batched-UDP benchmark.
//!
//! Answers every A query with `192.0.2.1`, TTL 3600, so the forwarder's cache
//! stays warm without a public resolver. Run it next to `sopedu-dns` and point
//! the server's `fallback` at it. Not part of the production binary.
//!
//! ```sh
//! cargo run --release --locked --example dns_mock -- 127.0.0.1:15354
//! ```

use std::{env, net::UdpSocket};

use hickory_proto::{
    op::{Message, MessageType, OpCode},
    rr::{rdata::A, RData, Record},
};

fn main() -> std::io::Result<()> {
    let addr = env::args().nth(1).unwrap_or_else(|| "127.0.0.1:15354".to_string());
    let socket = UdpSocket::bind(&addr)?;
    eprintln!("dns_mock listening on {}", socket.local_addr()?);
    let mut buf = [0u8; 65_535];
    loop {
        let (n, peer) = socket.recv_from(&mut buf)?;
        let Ok(query) = Message::from_vec(&buf[..n]) else { continue };
        let Some(question) = query.queries.first() else { continue };
        let mut answer = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
        answer.metadata.recursion_available = true;
        answer.add_queries(query.queries.iter().cloned());
        answer.add_answer(Record::from_rdata(
            question.name().clone(),
            3600,
            RData::A(A(std::net::Ipv4Addr::new(192, 0, 2, 1))),
        ));
        let _ = socket.send_to(&answer.to_vec().unwrap(), peer);
    }
}
