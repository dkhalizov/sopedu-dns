//! Allocation probe: dhat heap profiler counts allocator calls and bytes
//! for one operation.
//!
//! This is a diagnostic binary, not a timed benchmark. The profiler exists
//! only in this bench target; the library and server do not use it.

use std::collections::HashMap;
use std::hint::black_box;

use dhat::{HeapStats, Profiler};
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query, ResponseCode},
    rr::{rdata::A, Name, RData, Record, RecordType},
};
use sopedu_dns::{
    cache::{self, Cache},
    config::Config,
    reverse,
    rules::{self, Rules},
    wire,
};

#[global_allocator]
static GLOBAL: dhat::Alloc = dhat::Alloc;

fn measure<T>(op: impl FnOnce() -> T) -> (u64, u64) {
    let before = HeapStats::get();
    black_box(op());
    let after = HeapStats::get();
    (after.total_blocks - before.total_blocks, after.total_bytes - before.total_bytes)
}

fn dns_name(qname: &str) -> Name {
    Name::from_ascii(qname).expect("valid test name")
}

/// Canonical key: lowercased QNAME wire, QTYPE, QCLASS IN, no EDNS/AD/CD.
fn cache_key(qname: &str) -> Vec<u8> {
    let mut key = Vec::new();
    for label in qname.trim_end_matches('.').split('.').filter(|l| !l.is_empty()) {
        key.push(label.len() as u8);
        key.extend_from_slice(label.as_bytes());
    }
    key.push(0);
    key.extend_from_slice(&1u16.to_be_bytes());
    key.extend_from_slice(&1u16.to_be_bytes());
    key.push(0);
    key
}

fn answer_message(qname: &str, answers: usize) -> Message {
    let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
    msg.metadata.response_code = ResponseCode::NoError;
    msg.add_query(Query::query(dns_name(qname), RecordType::A));
    for i in 0..answers {
        msg.add_answer(Record::from_rdata(dns_name(qname), 300, RData::A(A::new(192, 0, 2, i as u8))));
    }
    msg
}

fn main() {
    let _profiler = Profiler::builder().file_name("target/dhat-heap.json").build();

    let lines: Vec<String> = (0..100_000).map(|i| format!("||n{i:05}.test^")).collect();
    let rules = Rules::from_lines(&lines, 0);
    assert!(rules.blocked("n00042.test"));

    let msg = answer_message("n00000.test.", 1);
    let raw = msg.to_vec().expect("response wire");
    let cache = Cache::new(10_000, 4 * 1024 * 1024, 0, 10_800);
    for i in 0..10_000 {
        cache.insert(&cache_key(&format!("n{i:05}.test")), &raw, &msg, 0);
    }
    let hot = cache_key("n00000.test");

    let (hit_allocs, hit_bytes) = measure(|| cache.get(&hot, 9, 43_200));
    let (blocked_allocs, blocked_bytes) = measure(|| rules.blocked("a.b.c.n00042.test"));

    // The inline UDP sequence with warm, reusable buffers: the policy
    // gate (allocation-free rewrite lookup, blocklist and reverse check), wire
    // query view, canonical key, get_into into the answer buffer and the 0x20
    // question-case restore. The buffers and tables are sized before measuring.
    let rewrite_rules = HashMap::from([
        ("nas.home.arpa".to_string(), "192.0.2.60".parse().unwrap()),
        ("*.home.arpa".to_string(), "192.0.2.60".parse().unwrap()),
    ]);
    let no_rules = Rules::from_lines(std::iter::empty::<&str>(), 0);
    let policy_cfg = Config::default();
    let policy_name = "n00000.test";
    let query = {
        let mut q = Message::new(0x1234, MessageType::Query, OpCode::Query);
        q.metadata.recursion_desired = true;
        q.add_query(Query::query(dns_name("n00000.test."), RecordType::A));
        q.to_vec().expect("query wire")
    };
    let mut key_buffer = [0u8; wire::MIN_CANONICAL_BUFFER];
    let mut answer = Vec::with_capacity(raw.len());
    let (fast_hit_allocs, fast_hit_bytes) = measure(|| {
        let policy = rules::rewrite(&rewrite_rules, policy_name).is_none()
            && !no_rules.blocked_bytes(policy_name.as_bytes())
            && !reverse::may_answer(&policy_cfg, u16::from(RecordType::A), policy_name, false);
        black_box(policy);
        let view = wire::parse_query(&query).expect("query view");
        let key_len = wire::canonical_key(&view, &mut key_buffer).expect("canonical key");
        cache.get_into(&key_buffer[..key_len], 9, 43_200, &mut answer).expect("warm hit");
        wire::copy_question_case(&query, &mut answer);
    });
    assert_eq!((fast_hit_allocs, fast_hit_bytes), (0, 0), "a warm inline hit must make no allocator call");

    let response = answer_message("ttl.test.", 40);
    let mut patched = response.to_vec().expect("response wire");
    let offsets = cache::ttl_offsets(&patched).expect("ttl offsets");
    assert_eq!(offsets.len(), 40);
    let (patch_allocs, patch_bytes) = measure(|| cache::patch(&mut patched, &offsets, 30, false, 7));

    println!("cache_hit allocations={hit_allocs} bytes={hit_bytes}");
    println!("blocked_lookup allocations={blocked_allocs} bytes={blocked_bytes}");
    println!("fast_hit allocations={fast_hit_allocs} bytes={fast_hit_bytes}");
    println!("ttl_patch allocations={patch_allocs} bytes={patch_bytes}");
}
