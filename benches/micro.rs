use std::{hint::black_box, time::Duration};

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use hickory_proto::{
    op::{Edns, Message, MessageType, OpCode, Query, ResponseCode},
    rr::{
        rdata::{A, SOA},
        Name, RData, Record, RecordType,
    },
};
use sopedu_dns::{
    cache::{self, Cache},
    clock::Instant,
    querylog::{self, QueryLog, Record as LogRecord, SpaceSaving},
    rules::Rules,
    stats::Outcome,
    wire,
};

const RULES: usize = 100_000;
const CACHE_ENTRIES: usize = 10_000;
const CACHE_BYTES: usize = 4 * 1024 * 1024;

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

fn rule_lines() -> Vec<String> {
    (0..RULES).map(|i| format!("||n{i:05}.test^")).collect()
}

fn parse_rules(lines: &[String]) -> Rules {
    Rules::from_lines(lines, 0)
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

fn criterion_config() -> Criterion {
    Criterion::default()
        .sample_size(20)
        .warm_up_time(Duration::from_millis(300))
        .measurement_time(Duration::from_secs(1))
}

fn rule_parse(c: &mut Criterion) {
    let lines = rule_lines();
    // Check the fixture before timing; parsing a Rules table inside the timed
    // closure would otherwise be measured together with its drop.
    assert_eq!(parse_rules(&lines).len(), RULES);
    c.bench_function("rule_parse_100k", |b| {
        b.iter_batched(|| (), |()| parse_rules(black_box(&lines)), BatchSize::PerIteration);
    });
}

/// The rules table hashes with a per-table random seed, and on these
/// near-identical synthetic names how much it clusters depends on that seed:
/// a single table makes the same build differ by tens of percent between
/// processes, and the CI gate compares two processes. Each lookup bench
/// therefore spreads many names over several tables, which averages the seed
/// inside one process.
const LOOKUP_NAMES: usize = 512;
const LOOKUP_TABLES: usize = 8;

fn lookup_names(f: impl Fn(usize) -> String) -> Vec<String> {
    (0..LOOKUP_NAMES).map(|i| f(i * 193 % RULES)).collect()
}

fn blocked_lookups(c: &mut Criterion) {
    let lines = rule_lines();
    let tables: Vec<Rules> = (0..LOOKUP_TABLES).map(|_| parse_rules(&lines)).collect();
    let hits = lookup_names(|i| format!("n{i:05}.test"));
    let misses = lookup_names(|i| format!("absent{i:05}.example"));
    let deep = lookup_names(|i| format!("a.b.c.n{i:05}.test"));
    for rules in &tables {
        assert!(hits.iter().all(|n| rules.blocked(n)));
        assert!(!misses.iter().any(|n| rules.blocked(n)));
        assert!(deep.iter().all(|n| rules.blocked(n)));
    }
    for (bench, names) in [("blocked_hit_x512", &hits), ("blocked_miss_x512", &misses), ("blocked_deep_x512", &deep)] {
        c.bench_function(bench, |b| {
            b.iter(|| names.iter().zip(tables.iter().cycle()).filter(|(n, rules)| rules.blocked(black_box(n))).count());
        });
    }
}

fn cache_ops(c: &mut Criterion) {
    let msg = answer_message("n00000.test.", 1);
    let raw = msg.to_vec().expect("response wire");
    let cache = Cache::new(CACHE_ENTRIES, CACHE_BYTES, 0, 10_800);
    for i in 0..CACHE_ENTRIES {
        cache.insert(&cache_key(&format!("n{i:05}.test")), &raw, &msg, 0);
    }
    let hot = cache_key("n00000.test");
    assert!(cache.get(&hot, 7, 43_200).is_some());
    // A hit returns a 45-byte response clone; b.iter() deliberately includes
    // freeing that clone. The free is part of the hit's allocation lifecycle
    // and is tiny next to the lookup, so clone + free is the reported cost.
    c.bench_function("cache_get_hot_10k", |b| b.iter(|| black_box(cache.get(&hot, 123, 43_200))));

    let mut next = 0u64;
    c.bench_function("cache_insert_evict_10k", |b| {
        b.iter_batched(
            || {
                next += 1;
                (cache_key(&format!("new{next}.test")), raw.clone())
            },
            |(key, raw)| cache.insert(&key, &raw, &msg, 0),
            BatchSize::SmallInput,
        );
    });
}

fn question_parse(c: &mut Criterion) {
    let mut query = Message::new(0x1234, MessageType::Query, OpCode::Query);
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(dns_name("abcdefghijklmn.abcdefg."), RecordType::A));
    let raw = query.to_vec().expect("query wire");
    assert_eq!(raw.len(), 40);
    c.bench_function("question_parse_40b", |b| {
        b.iter_with_large_drop(|| Message::from_vec(black_box(raw.as_slice())).expect("parse"));
    });
}

/// The work the wire fast path removes from a cache hit. Today's path
/// parses the whole request into a hickory `Message` before `resolve` looks
/// up the cache; the fast path runs only the question/OPT view, the canonical
/// key and the cache get.
fn hit_path(c: &mut Criterion) {
    let mut query = Message::new(0x1234, MessageType::Query, OpCode::Query);
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(dns_name("hit-path.test."), RecordType::A));
    let query_raw = query.to_vec().expect("query wire");
    let answer = answer_message("hit-path.test.", 1);
    let answer_raw = answer.to_vec().expect("answer wire");
    let cache = Cache::new(1024, 1 << 20, 0, 10_800);
    let key = {
        let view = wire::parse_query(&query_raw).expect("view");
        let mut key = [0u8; wire::MIN_CANONICAL_BUFFER];
        let len = wire::canonical_key(&view, &mut key).expect("key");
        assert!(cache.insert(&key[..len], &answer_raw, &answer, 0));
        key[..len].to_vec()
    };
    assert!(cache.get(&key, 7, 43_200).is_some());

    c.bench_function("hit_path_message_parse", |b| {
        b.iter_with_large_drop(|| Message::from_vec(black_box(query_raw.as_slice())).expect("parse"));
    });
    // The returned `Hit` owns the response copy, so its free is included as
    // in `cache_get_hot_10k`.
    c.bench_function("hit_path_wire_lookup", |b| {
        b.iter(|| {
            let view = wire::parse_query(black_box(query_raw.as_slice())).expect("view");
            let mut key = [0u8; wire::MIN_CANONICAL_BUFFER];
            let len = wire::canonical_key(&view, &mut key).expect("key");
            black_box(cache.get(&key[..len], 7, 43_200))
        });
    });
    // Before the wire fast path the request path paid both: the full parse in `handle_with`
    // and then the same wire view, key and lookup in `resolve`.
    c.bench_function("hit_path_parsed_total", |b| {
        b.iter(|| {
            let _message = Message::from_vec(black_box(query_raw.as_slice())).expect("parse");
            let view = wire::parse_query(black_box(query_raw.as_slice())).expect("view");
            let mut key = [0u8; wire::MIN_CANONICAL_BUFFER];
            let len = wire::canonical_key(&view, &mut key).expect("key");
            black_box(cache.get(&key[..len], 7, 43_200))
        });
    });
}

/// The block answer: the parsed path's hickory parse, reply build and
/// serialization against the inline path's wire view and byte copy.
fn block_reply(c: &mut Criterion) {
    let mut query = Message::new(0x1234, MessageType::Query, OpCode::Query);
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(dns_name("ads.blocked.test."), RecordType::A));
    query.edns = Some(Default::default());
    let query_raw = query.to_vec().expect("query wire");

    c.bench_function("block_reply_parsed", |b| {
        b.iter(|| {
            let q = Message::from_vec(black_box(query_raw.as_slice())).expect("parse");
            let mut m = Message::new(q.metadata.id, MessageType::Response, q.metadata.op_code);
            m.metadata.recursion_desired = q.metadata.recursion_desired;
            m.metadata.recursion_available = true;
            m.metadata.response_code = ResponseCode::NXDomain;
            m.add_queries(q.queries.iter().cloned());
            let mut edns = Edns::new();
            edns.set_max_payload(1232);
            m.set_edns(edns);
            let soa = SOA::new(Name::root(), Name::root(), 1, 3600, 600, 86400, 10);
            m.add_authority(Record::from_rdata(q.queries[0].name().clone(), 10, RData::SOA(soa)));
            black_box(m.to_vec().expect("reply wire"))
        });
    });
    let mut out = Vec::with_capacity(1232);
    c.bench_function("block_reply_wire", |b| {
        b.iter(|| {
            let view = wire::parse_query(black_box(query_raw.as_slice())).expect("view");
            wire::blocked_response_into(&view, &mut out);
            black_box(out.len())
        });
    });
}

fn ttl_patch(c: &mut Criterion) {
    let msg = answer_message("ttl.test.", 40);
    let raw = msg.to_vec().expect("response wire");
    let offsets = cache::ttl_offsets(&raw).expect("ttl offsets");
    assert_eq!(offsets.len(), 40);
    c.bench_function("ttl_patch_40a", |b| {
        b.iter_batched(
            || raw.clone(),
            |mut raw| {
                cache::patch(&mut raw, &offsets, 30, false, 0x1234);
                black_box(raw)
            },
            BatchSize::SmallInput,
        );
    });
}

/// The per-query cost the inline UDP hit path pays for the query log: one
/// 64-byte name copy and an entry write into this thread's shard. `_off` is
/// the cost with `query_log_capacity = 0` (two loads and a branch).
fn query_log_record(c: &mut Criterion) {
    let mut query = Message::new(0x1234, MessageType::Query, OpCode::Query);
    query.add_query(Query::query(dns_name("www.example-hit.test."), RecordType::A));
    let raw = query.to_vec().expect("query wire");
    let view = wire::parse_query(&raw).expect("view");
    let qname = &view.qname_lower[..usize::from(view.qname_len)];
    let ip = "192.168.1.20".parse().expect("ip");
    let record = LogRecord {
        ip,
        qname,
        qtype: view.qtype,
        outcome: Outcome::Cache,
        upstream: querylog::NO_UPSTREAM,
        list: None,
    };
    let started = Instant::now();
    let latency = Duration::from_micros(7);

    let off = QueryLog::new(0);
    c.bench_function("query_log_record_off", |b| b.iter(|| off.write(black_box(started), latency, black_box(&record))));
    let log = QueryLog::new(10_000);
    c.bench_function("query_log_record", |b| b.iter(|| log.write(black_box(started), latency, black_box(&record))));
    // The production entry point, through the process-wide `OnceLock`.
    querylog::init(10_000);
    c.bench_function("query_log_record_global", |b| {
        b.iter(|| querylog::record(black_box(started), latency, black_box(&record)))
    });
}

/// The drain's heavy-hitter sketch, run on the receive thread's runtime
/// for every logged query. Keys are the 65-byte (name + truncated flag) keys
/// `Tops::add` builds. `hit` is a tracked name; `evict` cycles more names than
/// counters, so every add misses, scans for the minimum and swaps the index.
fn space_saving(c: &mut Criterion) {
    let keys: Vec<[u8; querylog::NAME_BYTES + 1]> = (0..1000)
        .map(|i| {
            let mut key = [0u8; querylog::NAME_BYTES + 1];
            let name = format!("\x07example\x04h{i:04}\x03com\x00");
            key[..name.len()].copy_from_slice(name.as_bytes());
            key
        })
        .collect();
    let mut hot = SpaceSaving::new(querylog::TOP_K);
    for key in &keys[..querylog::TOP_K] {
        hot.add(key);
    }
    let mut next = 0;
    c.bench_function("space_saving_add_hit", |b| {
        b.iter(|| {
            next = (next + 1) % querylog::TOP_K;
            hot.add(black_box(&keys[next]));
        })
    });
    let mut churn = SpaceSaving::new(querylog::TOP_K);
    let mut next = 0;
    c.bench_function("space_saving_add_evict", |b| {
        b.iter(|| {
            next = (next + 1) % keys.len();
            churn.add(black_box(&keys[next]));
        })
    });
}

criterion_group! {
    name = benches;
    config = criterion_config();
    targets = rule_parse, blocked_lookups, cache_ops, question_parse, ttl_patch, hit_path, block_reply, query_log_record, space_saving
}
criterion_main!(benches);
