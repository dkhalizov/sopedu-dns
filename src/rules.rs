//! Fingerprint blocklist: a normalize-once table of 64-bit domain hashes.
//!
//! Each slot stores `hash`, the rule class bits and the id of the list the
//! rule came from. No domain bytes are stored. Two different domains whose
//! 64-bit hashes collide are indistinguishable, so a rule can match a name it
//! was not written for; with 516,060 rules the chance per probe is about
//! 3e-14, and a lookup probes one suffix per label (three to five for typical
//! names). The stored flags are preserved exactly, so a collision merges rule
//! classes (like a duplicate rule), never a different decision formula.

use std::{
    collections::HashMap,
    hash::BuildHasher,
    net::IpAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use foldhash::fast::RandomState;

const BLOCK: u8 = 1;
const ALLOW: u8 = 2;
const IMPORTANT_BLOCK: u8 = 4;
const IMPORTANT_ALLOW: u8 = 8;
/// Exact-host block: a bare hostname, a hosts-file entry or `|name^`.
const EXACT: u8 = 16;
/// Exact-host allow: `@@|name^` / `@@|name^|`. Never matches a parent.
const EXACT_ALLOW: u8 = 32;
/// `explain` returns at most this many matches (the most specific ones).
const MAX_EXPLAIN: usize = 64;
/// Source of [`Rules::generation`]: every built table takes the next value.
static GENERATIONS: AtomicU64 = AtomicU64::new(1);

/// One group of rules: id 0 is the inline user rules, lists start at 1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleSource {
    pub id: u16,
    pub name: String,
}

/// Entries are partitioned by the top bits of the hash into this many buckets
/// (a power of two). Each bucket is sorted, merged and moved into the table on
/// its own and freed right after, so the transient peak is one copy of the
/// entries plus the growing table rather than both in full.
const BUCKET_BITS: u32 = 5;
const BUCKETS: usize = 1 << BUCKET_BITS;

fn bucket_of(hash: u64) -> usize {
    (hash >> (64 - BUCKET_BITS)) as usize
}

/// Parses and deduplicates rules before the immutable table exists.
///
/// The hasher is cloneable, so list workers can call [`parse_line`] in
/// parallel with the builder's seed and feed [`RuleSetBuilder::add_parsed`].
pub struct RuleSetBuilder {
    hasher: RandomState,
    /// `(hash, list id << 16 | flags)`, bucketed by [`bucket_of`] so that equal
    /// hashes always share a bucket and buckets are ordered by hash.
    buckets: Vec<Vec<(u64, u32)>>,
}

impl RuleSetBuilder {
    pub fn new() -> Self {
        Self { hasher: RandomState::default(), buckets: (0..BUCKETS).map(|_| Vec::new()).collect() }
    }

    /// A clone of the seed-carrying hasher for a parallel list worker.
    pub fn hasher(&self) -> RandomState {
        self.hasher.clone()
    }

    /// Same parsing semantics as the previous blocklist parser: returns false
    /// for every ignored line, including comments, blanks and unsupported
    /// rules.
    pub fn add_line(&mut self, line: &str, list_id: u16) -> bool {
        match parse_line(&self.hasher, line) {
            Some((hash, flags)) => {
                self.add_parsed(hash, flags, list_id);
                true
            }
            None => false,
        }
    }

    /// Sizes every bucket exactly for the hashes about to be added with
    /// [`RuleSetBuilder::add_parsed`], so growth never over-allocates.
    pub fn reserve(&mut self, hashes: impl IntoIterator<Item = u64>) {
        let mut counts = [0usize; BUCKETS];
        for hash in hashes {
            counts[bucket_of(normalize_hash(hash))] += 1;
        }
        for (bucket, count) in self.buckets.iter_mut().zip(counts) {
            bucket.reserve_exact(count);
        }
    }

    /// Adds a line already parsed by a worker. `hash` must come from a
    /// [`parse_line`] call with this builder's hasher.
    pub fn add_parsed(&mut self, hash: u64, flags: u8, list_id: u16) {
        let hash = normalize_hash(hash);
        self.buckets[bucket_of(hash)].push((hash, u32::from(list_id) << 16 | u32::from(flags)));
    }

    /// Sorts and merges duplicates, then builds the probe table.
    ///
    /// Duplicate hashes OR their flags; the list id comes from the
    /// highest-priority contribution (`important-allow` > `important-block` >
    /// `allow` > `block`/exact), with ties going to the lower list id.
    pub fn finish(mut self, sources: Arc<[RuleSource]>) -> Rules {
        let mut len = 0;
        for bucket in &mut self.buckets {
            bucket.sort_unstable();
            len += merge_sorted(bucket);
            bucket.shrink_to_fit();
        }

        let capacity = (len * 4).div_ceil(3).max(16);
        let mut hashes = vec![0u64; capacity].into_boxed_slice();
        let mut flags = vec![0u8; capacity].into_boxed_slice();
        let mut lists = vec![0u16; capacity].into_boxed_slice();
        // Consuming the buckets in order drops each one as soon as it is in the
        // table (hashes ascend, so the table is also filled front to back).
        for bucket in std::mem::take(&mut self.buckets) {
            for (hash, packed) in bucket {
                let mut idx = fastrange(hash, capacity);
                while hashes[idx] != 0 {
                    idx += 1;
                    if idx == capacity {
                        idx = 0;
                    }
                }
                hashes[idx] = hash;
                flags[idx] = packed as u8;
                lists[idx] = (packed >> 16) as u16;
            }
        }
        Rules {
            hasher: self.hasher,
            hashes,
            flags,
            lists,
            sources,
            len,
            generation: GENERATIONS.fetch_add(1, Ordering::Relaxed),
        }
    }
}

/// Merges runs of equal hashes in a sorted bucket in place and returns the
/// new length. Flags OR together; the list id is the first (lowest) one whose
/// own flags reach the highest priority.
fn merge_sorted(bucket: &mut Vec<(u64, u32)>) -> usize {
    let mut out = 0;
    let mut best = 0;
    for i in 0..bucket.len() {
        let (hash, packed) = bucket[i];
        let entry_priority = priority(packed as u8);
        if out > 0 && bucket[out - 1].0 == hash {
            let last = &mut bucket[out - 1].1;
            let mut merged = *last | (packed & 0xff);
            if entry_priority > best {
                merged = (merged & 0xff) | (packed & 0xffff_0000);
                best = entry_priority;
            }
            *last = merged;
        } else {
            bucket[out] = (hash, packed);
            best = entry_priority;
            out += 1;
        }
    }
    bucket.truncate(out);
    out
}

impl Default for RuleSetBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Parses one blocklist line into `(domain hash, rule flags)`.
///
/// Accepted forms:
/// - `||name^`, `||name^|` and `||name|`, plus their `@@` allow variants and
///   `$important`: the domain and all its subdomains.
/// - `|name^` and `|name^|`, plus `@@|name^|` / `@@|name^` where the `@@`
///   makes it an exact-host allow: the hostname only, never its subdomains.
/// - `0.0.0.0 name` and `127.0.0.1 name` without `@@` or `$important`: exact
///   (hosts-file) blocks. A plain hostname is a suffix block and takes an
///   optional `$important` (an important block).
///
/// `$important` is accepted on the `||` forms and plain hostnames only; every
/// other `$` option and every other form, including `|` rules with a path or
/// query and hosts-file entries with `$important`, is ignored.
pub fn parse_line(hasher: &RandomState, line: &str) -> Option<(u64, u8)> {
    let (name, flags) = split_rule(line).ok()??;
    let name = domain(name)?;
    Some((hash_domain(hasher, name.as_bytes()), flags))
}

/// [`parse_line`] without the hash: the normalized domain and the rule flags.
/// `Ok(None)` is a blank line or a comment; `Err` says why a line is not a
/// supported rule (the editor on the rules page shows it).
pub fn parse_rule(line: &str) -> Result<Option<(String, u8)>, &'static str> {
    let Some((name, flags)) = split_rule(line)? else { return Ok(None) };
    domain(name).map(|name| Some((name, flags))).ok_or("not a valid domain name")
}

/// The one syntax decision shared by [`parse_line`] and [`parse_rule`]: the
/// raw name and flags, `Ok(None)` for a blank or comment line.
fn split_rule(line: &str) -> Result<Option<(&str, u8)>, &'static str> {
    let line = line.trim();
    if line.is_empty() || line.starts_with(['!', '#', '[', '/']) {
        return Ok(None);
    }
    let (line, important) = match line.split_once('$') {
        Some((s, "important")) => (s, true),
        Some(_) => return Err("unsupported modifier (only $important is supported)"),
        None => (line, false),
    };
    let (line, allow) = line.strip_prefix("@@").map_or((line, false), |s| (s, true));
    const SYNTAX: &str = "unsupported rule syntax (use ||name^, |name^, @@||name^ or a hostname)";
    let (name, flags) = if let Some(s) = line.strip_prefix("||") {
        // `||name^`, `||name^|` and `||name|` all anchor the domain name.
        let s = s
            .strip_suffix("^|")
            .or_else(|| s.strip_suffix('^'))
            .or_else(|| s.strip_suffix('|'))
            .ok_or("a || rule must end with ^")?;
        let flags = match (important, allow) {
            (true, true) => IMPORTANT_ALLOW,
            (true, false) => IMPORTANT_BLOCK,
            (false, true) => ALLOW,
            _ => BLOCK,
        };
        (s, flags)
    } else if let Some(s) = line.strip_prefix('|') {
        // `|name^` / `|name^|` anchor both ends, so they match the hostname
        // exactly. `$important` cannot be represented on an exact rule.
        if important {
            return Err("$important is not supported on a | rule");
        }
        let s = s.strip_suffix('|').unwrap_or(s);
        (s.strip_suffix('^').ok_or("a | rule must end with ^")?, if allow { EXACT_ALLOW } else { EXACT })
    } else {
        let mut parts = line.split_whitespace();
        match (parts.next(), parts.next(), parts.next()) {
            (Some(ip), Some(name), None) if !allow && !important && matches!(ip, "0.0.0.0" | "127.0.0.1") => {
                (name, EXACT)
            }
            (Some(name), None, None) if !allow => (name, if important { IMPORTANT_BLOCK } else { BLOCK }),
            _ => return Err(SYNTAX),
        }
    };
    Ok(Some((name, flags)))
}

/// The canonical rule text for one class bit, so a stored rule can be shown
/// and pasted back: `||name^`, `@@||name^$important`, `|name^` and so on. A
/// plain hostname normalizes to `||name^`, a hosts entry to `|name^`.
pub fn rule_text(name: &str, flags: u8) -> String {
    let (prefix, suffix) = match flags {
        IMPORTANT_ALLOW => ("@@||", "^$important"),
        IMPORTANT_BLOCK => ("||", "^$important"),
        ALLOW => ("@@||", "^"),
        EXACT_ALLOW => ("@@|", "^"),
        EXACT => ("|", "^"),
        _ => ("||", "^"),
    };
    format!("{prefix}{name}{suffix}")
}

/// Matcher priority of one rule: 4 important allow, 3 important block,
/// 2 allow, 1 block, 0 none. The highest class among the matches decides.
pub fn rank(flags: u8) -> u8 {
    priority(flags)
}

/// True for the `|name^` forms, which match the full name and never a parent.
pub fn is_exact(flags: u8) -> bool {
    flags & (EXACT | EXACT_ALLOW) != 0
}

/// Every single-class flag bit set in a stored (merged) `flags` byte.
pub fn class_bits(flags: u8) -> impl Iterator<Item = u8> {
    [IMPORTANT_ALLOW, IMPORTANT_BLOCK, ALLOW, EXACT_ALLOW, BLOCK, EXACT].into_iter().filter(move |bit| flags & bit != 0)
}

/// Normalizes a domain to lowercase without a final dot, or rejects it.
pub fn domain(s: &str) -> Option<String> {
    let s = s.trim_end_matches('.').to_ascii_lowercase();
    (s.len() <= 253
        && !s.is_empty()
        && s.split('.').all(|p| {
            !p.is_empty() && p.len() <= 63 && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        }))
    .then_some(s)
}

#[derive(Default)]
struct Scan {
    flags: u8,
    /// First (most specific) list id seen for each priority class.
    sources: [Option<u16>; 4],
}

impl Scan {
    fn add(&mut self, flags: u8, list_id: u16) {
        self.flags |= flags;
        let priority = priority(flags);
        if priority > 0 {
            let slot = &mut self.sources[priority as usize - 1];
            if slot.is_none() {
                *slot = Some(list_id);
            }
        }
    }
}

/// Rule classes that decide a query, highest first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// No rule matched the name.
    None,
    Block,
    Allow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decision {
    pub blocked: bool,
    pub action: Action,
    /// Origin of the deciding rule: user rules are 0, lists start at 1.
    /// When several parents match the deciding class, the most specific wins.
    pub list_id: Option<u16>,
}

/// One matching parent domain from [`Rules::explain`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Match {
    pub parent: String,
    /// Stored flags, including the exact-name bits.
    pub flags: u8,
    pub list_id: u16,
}

/// An immutable fingerprint table. Cheap to share behind an `Arc`.
pub struct Rules {
    hasher: RandomState,
    hashes: Box<[u64]>,
    flags: Box<[u8]>,
    lists: Box<[u16]>,
    sources: Arc<[RuleSource]>,
    len: usize,
    generation: u64,
}

impl Rules {
    /// Builds a table from one list of lines; used by tests and benchmarks.
    pub fn from_lines<I, S>(lines: I, list_id: u16) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut builder = RuleSetBuilder::new();
        for line in lines {
            builder.add_line(line.as_ref(), list_id);
        }
        let name = if list_id == 0 { "user rules".to_string() } else { format!("list {list_id}") };
        builder.finish(Arc::from([RuleSource { id: list_id, name }]))
    }

    /// True when the name (lowercase, without a final dot) or any parent is
    /// blocked. The EXACT and EXACT_ALLOW bits only count on the full name.
    pub fn blocked(&self, name: &str) -> bool {
        self.blocked_bytes(name.as_bytes())
    }

    /// [`Rules::blocked`] for bytes already lowercase and dot-free.
    pub fn blocked_bytes(&self, name: &[u8]) -> bool {
        is_blocked(self.scan(name).flags)
    }

    /// Process-unique id of this table (never 0). A derived verdict, such as a
    /// cached CNAME-target check, is current only while it matches.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Whether any rule matches the name and which class wins: `Allow` means an
    /// `@@` rule or an important allow beat every block. Same scan as
    /// [`Rules::blocked_bytes`], for bytes already lowercase and dot-free.
    pub fn action_bytes(&self, name: &[u8]) -> Action {
        let flags = self.scan(name).flags;
        if is_blocked(flags) {
            Action::Block
        } else if flags != 0 {
            Action::Allow
        } else {
            Action::None
        }
    }

    /// The blocking decision plus the rule class and list that decided it.
    /// The name must already be lowercase and without a final dot.
    pub fn decision(&self, name: &str) -> Decision {
        self.decision_bytes(name.as_bytes())
    }

    /// [`Rules::decision`] for bytes already lowercase and dot-free.
    pub fn decision_bytes(&self, name: &[u8]) -> Decision {
        let scan = self.scan(name);
        if is_blocked(scan.flags) {
            let list_id = if scan.flags & IMPORTANT_BLOCK != 0 { scan.sources[2] } else { scan.sources[0] };
            Decision { blocked: true, action: Action::Block, list_id }
        } else if scan.flags != 0 {
            let list_id = if scan.flags & IMPORTANT_ALLOW != 0 { scan.sources[3] } else { scan.sources[1] };
            Decision { blocked: false, action: Action::Allow, list_id }
        } else {
            Decision { blocked: false, action: Action::None, list_id: None }
        }
    }

    /// Every matching parent (most specific first), capped at 64 entries.
    /// The name must already be lowercase and without a final dot.
    pub fn explain(&self, name: &str) -> Vec<Match> {
        let mut out = Vec::new();
        let mut suffix = name;
        loop {
            if out.len() == MAX_EXPLAIN {
                break;
            }
            if let Some((flags, list_id)) = self.lookup(suffix.as_bytes()) {
                out.push(Match { parent: suffix.to_string(), flags, list_id });
            }
            match suffix.split_once('.') {
                Some((_, rest)) => suffix = rest,
                None => break,
            }
        }
        out
    }

    /// Number of unique domains in the table.
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Bytes held by the table and its source names (a lower bound: it does
    /// not count allocator rounding or the `Arc` header).
    pub fn heap_bytes(&self) -> usize {
        self.hashes.len() * (std::mem::size_of::<u64>() + std::mem::size_of::<u8>() + std::mem::size_of::<u16>())
            + std::mem::size_of::<RuleSource>() * self.sources.len()
            + self.sources.iter().map(|s| s.name.capacity()).sum::<usize>()
    }

    fn scan(&self, name: &[u8]) -> Scan {
        let mut scan = Scan::default();
        let mut suffix = name;
        let mut full = true;
        loop {
            if let Some((stored, list_id)) = self.lookup(suffix) {
                let mut flags = stored & !(EXACT | EXACT_ALLOW);
                if full {
                    if stored & EXACT != 0 {
                        flags |= BLOCK;
                    }
                    if stored & EXACT_ALLOW != 0 {
                        flags |= ALLOW;
                    }
                }
                scan.add(flags, list_id);
            }
            full = false;
            match suffix.iter().position(|&b| b == b'.') {
                Some(i) => suffix = &suffix[i + 1..],
                None => break,
            }
        }
        scan
    }

    fn lookup(&self, suffix: &[u8]) -> Option<(u8, u16)> {
        let hash = normalize_hash(hash_domain(&self.hasher, suffix));
        let mut idx = fastrange(hash, self.hashes.len());
        loop {
            let stored = self.hashes[idx];
            if stored == 0 {
                return None;
            }
            if stored == hash {
                return Some((self.flags[idx], self.lists[idx]));
            }
            idx += 1;
            if idx == self.hashes.len() {
                idx = 0;
            }
        }
    }
}

impl Default for Rules {
    fn default() -> Self {
        Self::from_lines(std::iter::empty::<&str>(), 0)
    }
}

fn hash_domain(hasher: &RandomState, name: &[u8]) -> u64 {
    hasher.hash_one(name)
}

/// Hash 0 marks an empty slot, so a real hash of 0 is stored as `u64::MAX`.
fn normalize_hash(hash: u64) -> u64 {
    if hash == 0 {
        u64::MAX
    } else {
        hash
    }
}

fn fastrange(hash: u64, n: usize) -> usize {
    ((u128::from(hash) * n as u128) >> 64) as usize
}

fn priority(flags: u8) -> u8 {
    if flags & IMPORTANT_ALLOW != 0 {
        4
    } else if flags & IMPORTANT_BLOCK != 0 {
        3
    } else if flags & (ALLOW | EXACT_ALLOW) != 0 {
        2
    } else if flags & (BLOCK | EXACT) != 0 {
        1
    } else {
        0
    }
}

fn is_blocked(flags: u8) -> bool {
    flags & IMPORTANT_ALLOW == 0 && (flags & IMPORTANT_BLOCK != 0 || (flags & ALLOW == 0 && flags & BLOCK != 0))
}

pub fn rewrite(rules: &HashMap<String, IpAddr>, name: &str) -> Option<IpAddr> {
    if rules.is_empty() {
        return None;
    }
    if let Some(ip) = rules.get(name) {
        return Some(*ip);
    }
    // The `*.suffix` candidate is built in place so a non-matching name never
    // allocates, including the common case of a configured rewrite table.
    let mut candidate = [0u8; 257];
    candidate[..2].copy_from_slice(b"*.");
    let mut parent = name;
    while let Some((_, suffix)) = parent.split_once('.') {
        if suffix.len() <= 255 {
            let end = 2 + suffix.len();
            candidate[2..end].copy_from_slice(suffix.as_bytes());
            if let Ok(key) = std::str::from_utf8(&candidate[..end]) {
                if let Some(ip) = rules.get(key) {
                    return Some(*ip);
                }
            }
        }
        parent = suffix;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sources(ids: &[u16]) -> Arc<[RuleSource]> {
        let mut out: Vec<RuleSource> = ids.iter().map(|&id| RuleSource { id, name: format!("list {id}") }).collect();
        out.insert(0, RuleSource { id: 0, name: "user rules".into() });
        Arc::from(out)
    }

    #[test]
    fn parsing_and_priority() {
        let mut r = RuleSetBuilder::new();
        for line in [
            "||Example.com^",
            "@@||ok.example.com^",
            "||ok.example.com^$important",
            "@@||yes.ok.example.com^$important",
            "0.0.0.0 host.test",
            "plain.test",
        ] {
            assert!(r.add_line(line, 1));
        }
        for line in [
            "! hi",
            "# hi",
            "[Adblock Plus 2.0]",
            "/foo/",
            "||x^$third-party",
            "||x^$important,badfilter",
            "https://x",
            "@@plain.test",
            "",
            "||x^junk",
        ] {
            assert!(!r.add_line(line, 1), "{line}");
        }
        let r = r.finish(sources(&[1]));
        assert!(r.blocked("a.example.com"));
        assert!(!r.blocked("notexample.com"));
        assert!(r.blocked("ok.example.com"));
        assert!(!r.blocked("yes.ok.example.com"));
        assert!(!r.blocked("a.yes.ok.example.com"));
        assert!(r.blocked("host.test"));
        assert!(!r.blocked("a.host.test"));
        assert!(r.blocked("a.plain.test"));

        let mut r = RuleSetBuilder::new();
        for line in [
            "||Example.com^",
            "@@||ok.example.com^",
            "||ok.example.com^$important",
            "@@||yes.ok.example.com^$important",
            "0.0.0.0 host.test",
            "plain.test",
            "@@||example.com^$important",
            "||com^",
        ] {
            assert!(r.add_line(line, 1));
        }
        let r = r.finish(sources(&[1]));
        assert!(!r.blocked("ok.example.com"));
        assert!(r.blocked("other.com"));
    }

    #[test]
    fn plain_important_blocks() {
        // A plain hostname with `$important` is an important block, so it
        // outranks an allow rule for the same name.
        let mut b = RuleSetBuilder::new();
        assert!(b.add_line("plain.test$important", 1));
        assert!(b.add_line("@@||plain.test^", 2));
        let r = b.finish(sources(&[1, 2]));
        assert_eq!(
            r.explain("plain.test"),
            vec![Match { parent: "plain.test".into(), flags: IMPORTANT_BLOCK | ALLOW, list_id: 1 }]
        );
        assert!(r.blocked("plain.test"));
        assert!(r.blocked("a.plain.test"));
        let d = r.decision("plain.test");
        assert!(d.blocked);
        assert_eq!(d.action, Action::Block);
        // The important block's list outranks the allow's list.
        assert_eq!(d.list_id, Some(1));

        // Without `$important` the same allow wins.
        let r = Rules::from_lines(["plain.test", "@@||plain.test^"], 1);
        assert!(!r.blocked("plain.test"));
        assert_eq!(r.decision("plain.test").action, Action::Allow);
    }

    #[test]
    fn anchored_end_forms() {
        let mut r = RuleSetBuilder::new();
        for line in [
            "||suffix-block.test^|",
            "||suffix-allow.test^",
            "@@||suffix-allow.test^|",
            "||suffix-bare.test|",
            "|host-block.test^|",
            "|host-block2.test^",
            "||host-allow.test^",
            "@@|host-allow.test^|",
            "||imp.test^|$important",
            "@@||imp-allow.test^|$important",
        ] {
            assert!(r.add_line(line, 1), "{line}");
        }
        for line in [
            "||",
            "||^",
            "||^|",
            "|||",
            "@@||",
            "@@||^|",
            "|",
            "|^",
            "|^|",
            "|host.test",
            "|host.test|",
            "@@|host.test",
            "||host.test/path^|",
            "||host.test?q^|",
            "|host.test/path^|",
            "|host.test?q^|",
            "|https://host.test^|",
            "|host.test^$important",
            "@@|host.test^|$third-party",
            "||host.test",
        ] {
            assert!(!r.add_line(line, 1), "{line}");
        }
        let r = r.finish(sources(&[1]));

        // `||name^|` and `||name|` anchor the domain like `||name^`.
        assert!(r.blocked("suffix-block.test"));
        assert!(r.blocked("a.suffix-block.test"));
        assert!(!r.blocked("suffix-allow.test"));
        assert!(!r.blocked("a.suffix-allow.test"));
        assert!(r.blocked("suffix-bare.test"));
        assert!(r.blocked("a.suffix-bare.test"));
        assert!(r.blocked("imp.test"));
        assert!(!r.blocked("imp-allow.test"));

        // `|name^|` and `|name^` match the hostname exactly, so an `@@` form
        // allows the host but leaves its subdomains blocked by the parent.
        assert!(r.blocked("host-block.test"));
        assert!(!r.blocked("a.host-block.test"));
        assert!(r.blocked("host-block2.test"));
        assert!(!r.blocked("a.host-block2.test"));
        assert!(!r.blocked("host-allow.test"));
        assert!(r.blocked("a.host-allow.test"));
        assert_eq!(r.explain("host-allow.test")[0].flags, BLOCK | EXACT_ALLOW);
    }

    #[test]
    fn wildcards() {
        let r = HashMap::from([
            ("*.local".into(), "192.0.2.1".parse().unwrap()),
            ("x.local".into(), "::1".parse().unwrap()),
            ("*.deep.local".into(), "192.0.2.2".parse().unwrap()),
        ]);
        assert_eq!(rewrite(&r, "x.local"), Some("::1".parse().unwrap()), "exact wins over *.local");
        assert_eq!(rewrite(&r, "a.deep.local"), Some("192.0.2.2".parse().unwrap()));
        assert_eq!(
            rewrite(&r, "a.b.local"),
            Some("192.0.2.1".parse().unwrap()),
            "multi-label names use the last wildcard"
        );
        assert!(rewrite(&r, "local").is_none());
        assert!(rewrite(&r, "notlocal").is_none());
        assert!(rewrite(&HashMap::new(), "x.local").is_none(), "an empty map matches nothing");
    }

    #[test]
    fn list_origin_in_decisions() {
        let mut b = RuleSetBuilder::new();
        assert!(b.add_line("||ads.test^", 2));
        assert!(b.add_line("||track.test^$important", 4));
        assert!(b.add_line("@@||track.test^$important", 5));
        assert!(b.add_line("0.0.0.0 exact.test", 6));
        let r = b.finish(sources(&[2, 4, 5, 6]));

        let d = r.decision("x.ads.test");
        assert!(d.blocked);
        assert_eq!(d.action, Action::Block);
        assert_eq!(d.list_id, Some(2));

        let d = r.decision("track.test");
        assert!(!d.blocked);
        assert_eq!(d.action, Action::Allow);
        assert_eq!(d.list_id, Some(5));

        let d = r.decision("exact.test");
        assert!(d.blocked);
        assert_eq!(d.action, Action::Block);
        assert_eq!(d.list_id, Some(6));

        let d = r.decision("clean.test");
        assert!(!d.blocked);
        assert_eq!(d.action, Action::None);
        assert_eq!(d.list_id, None);
    }

    #[test]
    fn duplicate_rule_across_lists() {
        let mut b = RuleSetBuilder::new();
        assert!(b.add_line("||dup.test^", 3));
        assert!(b.add_line("||dup.test^", 1));
        assert!(b.add_line("||dup.test^$important", 4));
        let r = b.finish(sources(&[1, 3, 4]));
        assert_eq!(r.len(), 1);
        assert_eq!(r.decision("dup.test").list_id, Some(4));
        let matches = r.explain("dup.test");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].flags, BLOCK | IMPORTANT_BLOCK);
        assert_eq!(matches[0].list_id, 4);

        let mut b = RuleSetBuilder::new();
        assert!(b.add_line("||same.test^", 3));
        assert!(b.add_line("||same.test^", 1));
        let r = b.finish(sources(&[1, 3]));
        assert_eq!(r.len(), 1);
        assert_eq!(r.decision("same.test").list_id, Some(1));
    }

    #[test]
    fn exact_vs_parent() {
        let r = Rules::from_lines(["0.0.0.0 exact.test", "127.0.0.1 other.test", "plain.test"], 1);
        assert!(r.blocked("exact.test"));
        assert!(!r.blocked("a.exact.test"));
        assert!(r.blocked("other.test"));
        assert!(!r.blocked("a.other.test"));
        assert!(r.blocked("a.plain.test"));
        assert_eq!(r.decision("exact.test").action, Action::Block);
        assert_eq!(r.decision("a.exact.test").action, Action::None);
        // `explain` reports the stored rule; the exact bit only decides the
        // full name, so the parent match carries EXACT but does not block.
        assert_eq!(r.explain("a.exact.test"), vec![Match { parent: "exact.test".into(), flags: EXACT, list_id: 1 }]);
    }

    #[test]
    fn deeper_suffix() {
        let r = Rules::from_lines(["||deep.example^"], 1);
        assert!(r.blocked("deep.example"));
        assert!(r.blocked("a.b.c.deep.example"));
        assert!(!r.blocked("notdeep.example"));
        assert_eq!(
            r.explain("a.b.c.deep.example"),
            vec![Match { parent: "deep.example".into(), flags: BLOCK, list_id: 1 }]
        );
    }

    #[test]
    fn explain_is_bounded() {
        let mut names = vec!["test".to_string()];
        let mut query = "test".to_string();
        for _ in 1..100 {
            query = format!("a.{query}");
            names.push(query.clone());
        }
        let r = Rules::from_lines(names.iter().map(String::as_str), 1);
        let matches = r.explain(&query);
        assert_eq!(matches.len(), MAX_EXPLAIN);
        assert_eq!(matches[0].parent, query);
    }

    #[test]
    fn empty_default_and_heap() {
        fn source_bytes(r: &Rules) -> usize {
            std::mem::size_of::<RuleSource>() * r.sources.len()
                + r.sources.iter().map(|s| s.name.capacity()).sum::<usize>()
        }

        let r = Rules::default();
        assert!(r.is_empty());
        assert!(!r.blocked("anything.test"));
        assert_eq!(r.decision("anything.test").action, Action::None);
        assert!(r.explain("anything.test").is_empty());
        assert_eq!(r.heap_bytes(), 16 * 11 + source_bytes(&r));
        let lines: Vec<String> = (0..100).map(|i| format!("||n{i}.test^")).collect();
        let r = Rules::from_lines(&lines, 1);
        assert_eq!(r.len(), 100);
        assert!(!r.is_empty());
        assert_eq!(r.heap_bytes(), 134 * 11 + source_bytes(&r));
    }

    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }

        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    /// The bucketed merge must give the same flags and list id as the rule
    /// documented on `finish`: flags OR together, the list is the lowest one
    /// among the contributions of the highest priority, in any add order.
    #[test]
    fn bucketed_merge_matches_reference() {
        let mut rng = Rng(0x2545_f491_4f6c_dd1d);
        let classes = [BLOCK, ALLOW, IMPORTANT_BLOCK, IMPORTANT_ALLOW, EXACT, EXACT_ALLOW];
        let mut builder = RuleSetBuilder::new();
        let hasher = builder.hasher();
        let mut expected = Vec::new();
        let mut adds = Vec::new();
        for i in 0..6000 {
            let name = format!("n{i}");
            let hash = hash_domain(&hasher, name.as_bytes());
            let mut parts = Vec::new();
            for _ in 0..=rng.below(4) {
                parts.push((classes[rng.below(classes.len())], rng.below(5) as u16));
            }
            let flags = parts.iter().fold(0, |acc, &(f, _)| acc | f);
            let top = parts.iter().map(|&(f, _)| priority(f)).max().unwrap();
            let list = parts.iter().filter(|&&(f, _)| priority(f) == top).map(|&(_, l)| l).min().unwrap();
            expected.push((name, flags, list));
            adds.extend(parts.into_iter().map(|(f, l)| (hash, f, l)));
        }
        // Add in a shuffled order so neither the list order nor the bucket
        // order of the input matters.
        for i in (1..adds.len()).rev() {
            adds.swap(i, rng.below(i + 1));
        }
        builder.reserve(adds.iter().map(|&(hash, ..)| hash));
        for (hash, flags, list) in adds {
            builder.add_parsed(hash, flags, list);
        }
        let rules = builder.finish(sources(&[0, 1, 2, 3, 4]));
        assert_eq!(rules.len(), expected.len());
        for (name, flags, list) in expected {
            let found = rules.explain(&name);
            assert_eq!(found.len(), 1, "{name}");
            assert_eq!((found[0].flags, found[0].list_id), (flags, list), "{name}");
        }
    }

    /// Hash 0 is the empty-slot marker and is stored as `u64::MAX`, so the two
    /// are one rule, in the last bucket, and still merge.
    #[test]
    fn zero_and_max_hash_merge() {
        let mut builder = RuleSetBuilder::new();
        builder.add_parsed(0, BLOCK, 2);
        builder.add_parsed(u64::MAX, IMPORTANT_ALLOW, 1);
        builder.add_parsed(1 << 63, BLOCK, 3);
        let rules = builder.finish(sources(&[1, 2, 3]));
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn randomized_matches_naive_hashmap() {
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        let suffixes = ["ads.test", "example.com", "x.ads.test", "deep.track.example.com", "net", "test"];
        let labels = ["a", "b", "c", "d", "e", "f"];
        let mut lines = Vec::new();
        let mut naive: HashMap<String, u8> = HashMap::new();
        for _ in 0..200 {
            let suffix = suffixes[rng.below(suffixes.len())];
            let domain = if rng.below(2) == 0 {
                suffix.to_string()
            } else {
                format!("{}.{suffix}", labels[rng.below(labels.len())])
            };
            let list_id = 1 + rng.below(3) as u16;
            let (line, flags) = match rng.below(6) {
                0 => (format!("||{domain}^"), BLOCK),
                1 => (format!("@@||{domain}^"), ALLOW),
                2 => (format!("||{domain}^$important"), IMPORTANT_BLOCK),
                3 => (format!("@@||{domain}^$important"), IMPORTANT_ALLOW),
                4 => (format!("0.0.0.0 {domain}"), EXACT),
                _ => (domain.clone(), BLOCK),
            };
            lines.push((line, list_id));
            *naive.entry(domain).or_default() |= flags;
        }

        let mut builder = RuleSetBuilder::new();
        for (line, list_id) in &lines {
            assert!(builder.add_line(line, *list_id));
        }
        let rules = builder.finish(sources(&[1, 2, 3]));

        fn naive_blocked(map: &HashMap<String, u8>, name: &str) -> bool {
            let mut flags = 0u8;
            let mut parent = name;
            let mut full = true;
            loop {
                if let Some(&bits) = map.get(parent) {
                    flags |= bits & !EXACT;
                    if full && bits & EXACT != 0 {
                        flags |= BLOCK;
                    }
                }
                full = false;
                match parent.split_once('.') {
                    Some((_, rest)) => parent = rest,
                    None => break,
                }
            }
            is_blocked(flags)
        }

        for _ in 0..10_000 {
            let mut name = String::new();
            for _ in 0..=rng.below(4) {
                name.push_str(labels[rng.below(labels.len())]);
                name.push('.');
            }
            name.push_str(suffixes[rng.below(suffixes.len())]);
            let expected = naive_blocked(&naive, &name);
            assert_eq!(rules.blocked(&name), expected, "{name}");
            assert_eq!(rules.blocked_bytes(name.as_bytes()), expected, "{name}");
            assert_eq!(rules.decision(&name).blocked, expected, "{name}");
        }
    }

    /// The text-level parser behind the rules page must make the same
    /// decisions as the hash parser the lists use, and a normalized rule must
    /// parse back to itself.
    #[test]
    fn parse_rule_matches_parse_line_and_normalizes_losslessly() {
        let hasher = RandomState::default();
        for line in [
            "||Example.com^",
            "||example.com^|",
            "||example.com|",
            "@@||ok.example.com^$important",
            "||x.example.com^$important",
            "|exact.example.com^",
            "|exact.example.com^|",
            "@@|exact.example.com^|",
            "0.0.0.0 Host.Test",
            "127.0.0.1 host.test",
            "plain.test",
            "plain.test$important",
            "  ||padded.test^  ",
            "! comment",
            "# comment",
            "[Adblock Plus 2.0]",
            "/regex/",
            "",
            "||x^$third-party",
            "||x^junk",
            "|host.test",
            "@@plain.test",
            "0.0.0.0 host.test$important",
            "||bad name^",
            "||^",
            "two words",
            "a b c",
        ] {
            match parse_rule(line) {
                Ok(Some((name, flags))) => {
                    assert_eq!(
                        parse_line(&hasher, line),
                        Some((hash_domain(&hasher, name.as_bytes()), flags)),
                        "{line}"
                    );
                    let text = rule_text(&name, flags);
                    assert_eq!(parse_rule(&text), Ok(Some((name, flags))), "{line} -> {text}");
                }
                other => assert_eq!(parse_line(&hasher, line), None, "{line}: {other:?}"),
            }
        }
        assert_eq!(parse_rule("! hi"), Ok(None));
        assert_eq!(parse_rule("  "), Ok(None));
        assert!(parse_rule("||x^$third-party").unwrap_err().contains("modifier"));
        assert!(parse_rule("|x^$important").unwrap_err().contains("important"));
        assert!(parse_rule("||x").unwrap_err().contains('^'));
        assert!(parse_rule("||bad_name!^").unwrap_err().contains("domain"));
        assert_eq!(rule_text("a.test", BLOCK), "||a.test^");
        assert_eq!(rule_text("a.test", IMPORTANT_ALLOW), "@@||a.test^$important");
        assert_eq!(rule_text("a.test", EXACT), "|a.test^");
        assert_eq!(rule_text("a.test", EXACT_ALLOW), "@@|a.test^");
        assert_eq!(class_bits(BLOCK | IMPORTANT_ALLOW | EXACT).collect::<Vec<_>>(), [IMPORTANT_ALLOW, BLOCK, EXACT]);
    }
    #[test]
    fn action_bytes_and_generations() {
        let rules = Rules::from_lines(["||blocked.test^", "@@||ok.blocked.test^", "||only.test^", "@@|exact.test^"], 1);
        for (name, expected) in [
            ("blocked.test", Action::Block),
            ("a.blocked.test", Action::Block),
            ("ok.blocked.test", Action::Allow),
            ("x.ok.blocked.test", Action::Allow),
            ("exact.test", Action::Allow),
            ("x.exact.test", Action::None),
            ("unrelated.test", Action::None),
        ] {
            assert_eq!(rules.action_bytes(name.as_bytes()), expected, "{name}");
            assert_eq!(rules.blocked_bytes(name.as_bytes()), expected == Action::Block, "{name}");
        }
        let other = Rules::default();
        assert_ne!(rules.generation(), other.generation());
        assert_ne!(rules.generation(), 0);
    }
}
