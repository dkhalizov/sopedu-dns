//! Exact round-trip latency of warm cache hits over UDP, one query in flight.
//!
//! `loadgen` and the server's `/metrics` histogram are log2 buckets (65-128 us
//! is one bucket), which cannot show whether a p99 is under 100 us. This client
//! records every round trip in nanoseconds and prints exact percentiles. The
//! round trip contains the server's whole packet-in to packet-out time plus the
//! client's own send/receive and the kernel's loopback path, so it is an upper
//! bound for the SLO: a p99 under 100 us here is a p99 under 100 us in process.
//!
//! One query is in flight at a time, so there is no queueing; `--gap-us` spins
//! between sends to model a given offered rate (the server's core idles and its
//! caches cool between queries, as on a home LAN).
//!
//! ```sh
//! cargo run --release --locked --example hit_rtt -- 127.0.0.1:15353 --count 200000 --gap-us 500
//! ```

use std::{
    env,
    net::UdpSocket,
    process::ExitCode,
    time::{Duration, Instant},
};

fn query(id: u16, name: &str) -> Vec<u8> {
    let mut raw = vec![(id >> 8) as u8, id as u8, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        raw.push(label.len() as u8);
        raw.extend_from_slice(label.as_bytes());
    }
    raw.extend_from_slice(&[0, 0, 1, 0, 1]);
    raw
}

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let Some(server) = args.next() else {
        eprintln!("usage: hit_rtt SERVER [--count N] [--names K] [--gap-us G]");
        return ExitCode::from(2);
    };
    let (mut count, mut names, mut gap_us) = (100_000usize, 1000usize, 0u64);
    while let Some(flag) = args.next() {
        let value = args.next().and_then(|v| v.parse::<u64>().ok());
        match (flag.as_str(), value) {
            ("--count", Some(v)) => count = v as usize,
            ("--names", Some(v)) => names = v as usize,
            ("--gap-us", Some(v)) => gap_us = v,
            _ => {
                eprintln!("hit_rtt: bad argument {flag}");
                return ExitCode::from(2);
            }
        }
    }
    // Bind the wildcard of the server's family (a loopback-bound socket cannot reach another host).
    let bind = if server.starts_with('[') { "[::]:0" } else { "0.0.0.0:0" };
    let socket = UdpSocket::bind(bind).and_then(|s| s.connect(&server).map(|()| s)).expect("socket");
    socket.set_read_timeout(Some(Duration::from_secs(2))).expect("timeout");
    let mut buf = [0u8; 4096];
    let mut exchange = |id: u16, name: &str| -> Option<Duration> {
        let raw = query(id, name);
        let start = Instant::now();
        socket.send(&raw).ok()?;
        loop {
            let n = socket.recv(&mut buf).ok()?;
            if n >= 2 && buf[..2] == raw[..2] {
                return Some(start.elapsed());
            }
        }
    };
    // Warm: every name once (a miss goes upstream; the answer is then cached).
    for i in 0..names {
        if exchange(i as u16, &format!("h{i}.hit.bench")).is_none() {
            eprintln!("hit_rtt: no answer for the warm-up query {i}");
            return ExitCode::FAILURE;
        }
    }
    std::thread::sleep(Duration::from_millis(200));
    let gap = Duration::from_micros(gap_us);
    let mut rtts: Vec<u64> = Vec::with_capacity(count);
    let mut lost = 0usize;
    let mut next = Instant::now();
    for i in 0..count {
        while Instant::now() < next {
            std::hint::spin_loop();
        }
        match exchange(i as u16, &format!("h{}.hit.bench", i % names)) {
            Some(rtt) => rtts.push(rtt.as_nanos() as u64),
            None => lost += 1,
        }
        next = if gap.is_zero() { Instant::now() } else { next + gap };
    }
    rtts.sort_unstable();
    let pct = |p: f64| rtts[(((rtts.len() - 1) as f64) * p).round() as usize] as f64 / 1000.0;
    let over = rtts.iter().filter(|&&n| n > 100_000).count();
    println!(
        "n={} lost={lost} gap_us={gap_us} p50={:.1}us p90={:.1}us p99={:.1}us p99.9={:.1}us max={:.1}us over_100us={over} ({:.3}%)",
        rtts.len(),
        pct(0.5),
        pct(0.9),
        pct(0.99),
        pct(0.999),
        *rtts.last().unwrap() as f64 / 1000.0,
        over as f64 * 100.0 / rtts.len() as f64
    );
    ExitCode::SUCCESS
}
