//! SLO bench: blocklist lookup at about 1M rules, every parent suffix checked.
//!
//! The rules are synthetic and deterministic (SplitMix64, fixed seeds); no
//! private list is read. They mimic real-list shapes: 2-4 label domains over a
//! weighted TLD set (including a two-label suffix), 70% `||name^`, 15% hosts
//! lines, 10% bare hostnames, 3% `$important`, 2% `@@` allow rules.
//!
//! Each class is timed three ways: `_hot` repeats one name (table slots stay in
//! L1), `_ws4k` rotates through 4,096 names (a working set about the size of a
//! home network's unique names, resident in L2) and `_rot` rotates through
//! 65,536 names, a uniform stream that mostly misses the CPU caches (worst case).
//!
//! ```sh
//! cargo bench --locked --bench blocklist_1m
//! ```

use std::{hint::black_box, time::Duration};

use criterion::{criterion_group, criterion_main, Criterion};
use sopedu_dns::rules::Rules;

const RULES: usize = 1_000_000;
const ROTATION: usize = 1 << 16;
/// About the unique names a home network queries (a few thousand).
const WORKING_SET: usize = 1 << 12;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn label(&mut self) -> String {
        const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
        let len = 4 + self.below(11);
        (0..len).map(|_| ALPHABET[self.below(ALPHABET.len())] as char).collect()
    }
}

const TLDS: [&str; 16] =
    ["com", "com", "com", "com", "net", "net", "org", "io", "co.uk", "de", "ru", "xyz", "info", "app", "cn", "online"];

/// A registrable domain with 0-2 extra subdomain labels, 60/30/10.
fn domain(rng: &mut Rng) -> String {
    let tld = TLDS[rng.below(TLDS.len())];
    let base = format!("{}.{tld}", rng.label());
    match rng.below(10) {
        0..=5 => base,
        6..=8 => format!("{}.{base}", rng.label()),
        _ => format!("{}.{}.{base}", rng.label(), rng.label()),
    }
}

/// Rule lines plus the names whose rule also blocks subdomains (hit candidates).
fn rule_set() -> (Vec<String>, Vec<String>) {
    let mut rng = Rng(0x5EED_0001);
    let (mut lines, mut blocking) = (Vec::with_capacity(RULES), Vec::new());
    for _ in 0..RULES {
        let name = domain(&mut rng);
        let roll = rng.below(100);
        lines.push(match roll {
            0..=69 => format!("||{name}^"),
            70..=84 => format!("0.0.0.0 {name}"),
            85..=94 => name.clone(),
            95..=97 => format!("||{name}^$important"),
            _ => format!("@@||{name}^"),
        });
        // Hosts lines are exact-only: a subdomain of one is not blocked.
        if !(70..=84).contains(&roll) && roll < 98 {
            blocking.push(name);
        }
    }
    (lines, blocking)
}

fn pick<T: Clone>(items: &[T], rng: &mut Rng) -> Vec<T> {
    (0..ROTATION).map(|_| items[rng.below(items.len())].clone()).collect()
}

fn lookup_bench(c: &mut Criterion, name: &str, rules: &Rules, names: &[String], expect: bool) {
    assert!(names.iter().all(|n| rules.blocked(n) == expect), "{name}: fixture disagrees with the table");
    let one = &names[0];
    c.bench_function(&format!("{name}_hot"), |b| b.iter(|| black_box(rules.blocked(black_box(one)))));
    for (suffix, size) in [("ws4k", WORKING_SET), ("rot", ROTATION)] {
        let mut i = 0usize;
        c.bench_function(&format!("{name}_{suffix}"), |b| {
            b.iter(|| {
                i = (i + 1) & (size - 1);
                black_box(rules.blocked(black_box(&names[i])))
            })
        });
    }
}

fn blocked_1m(c: &mut Criterion) {
    let (lines, blocking) = rule_set();
    let rules = Rules::from_lines(&lines, 0);
    // Duplicates are possible but rare; the table must hold about 1M rules.
    assert!(rules.len() > 990_000, "table has {} rules", rules.len());
    eprintln!("blocklist_1m: {} rules, heap {} MiB", rules.len(), rules.heap_bytes() >> 20);

    let mut rng = Rng(0x5EED_0002);
    let hits = pick(&blocking, &mut rng);
    // A subdomain of a blocked name: the parent scan finds the rule one label up.
    let sub_hits: Vec<String> = hits.iter().map(|n| format!("www.{n}")).collect();
    let deep_hits: Vec<String> = hits.iter().map(|n| format!("a.b.c.{n}")).collect();
    // Misses: fresh names from another seed (same shapes, so the same suffix
    // depths are probed); anything that happens to match a rule is dropped.
    let mut miss_rng = Rng(0x5EED_0003);
    let mut misses = Vec::with_capacity(ROTATION);
    while misses.len() < ROTATION {
        let name = domain(&mut miss_rng);
        if !rules.blocked(&name) {
            misses.push(name);
        }
    }
    let deep_misses: Vec<String> = misses.iter().map(|n| format!("a.b.c.{n}")).collect();

    lookup_bench(c, "blocked_1m_hit", &rules, &hits, true);
    lookup_bench(c, "blocked_1m_subdomain_hit", &rules, &sub_hits, true);
    lookup_bench(c, "blocked_1m_deep_hit", &rules, &deep_hits, true);
    lookup_bench(c, "blocked_1m_miss", &rules, &misses, false);
    lookup_bench(c, "blocked_1m_deep_miss", &rules, &deep_misses, false);
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(50).warm_up_time(Duration::from_secs(1)).measurement_time(Duration::from_secs(3));
    targets = blocked_1m
}
criterion_main!(benches);
