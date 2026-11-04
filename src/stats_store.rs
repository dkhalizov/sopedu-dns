//! Dashboard stats on disk: `state_dir/stats.v1`, a small line-oriented text
//! file written on shutdown and every 5 minutes, read once at startup.
//!
//! It keeps what the dashboard and `/metrics` accumulate: the outcome
//! counters, the request and per-upstream latency histograms, the three
//! top-N tables, the per-upstream win and hedge counters (`w` rows keyed by
//! the redacted upstream URL, so no credential reaches the disk; a file
//! without them is still valid) and the per-minute snapshots behind the 5-minute and 24-hour
//! windows (snapshots older than 24 hours are dropped on load, and the time
//! the server was down is filled in as idle, see
//! [`QueryLog::restore`](crate::querylog::QueryLog::restore)). The query log
//! ring is never written.
//!
//! The top lists are browsing history, so the file is handled like
//! `prewarm.txt`: owner-only (0600) in a 0700 directory this process creates,
//! replaced atomically, and removed at startup when `persist_stats = false`.
//!
//! Reading is defensive. The file is capped at 1 MiB, must be UTF-8 (it is
//! plain ASCII: names are hex of the wire form, so no name can inject a line),
//! must start with the version line, and every count is bounded. Any defect
//! makes the whole file ignored with one warning; a bad name row alone is
//! skipped. A missing or rejected file never blocks startup.
//!
//! Writing reads atomics and takes the query log's drain lock (the DNS path
//! never does), so it costs the query path nothing.

use crate::{
    lists, log,
    querylog::{self, Kept, Lite, Top, MINUTES, NAME_BYTES, TOP_K},
    stats::{self, HistSnap, Snapshot, BUCKETS, MAX_UPSTREAMS},
    upstream::UpstreamCount,
};
use std::{
    fmt::Write,
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

/// Larger than any file this module writes (about 150 KB with every table full).
const MAX_READ: u64 = 1 << 20;
const MAGIC: &str = "sopedu-stats v1";
/// No count or timestamp can plausibly reach this (2^56 ms is far beyond any
/// calendar), and it keeps the sums over 64 shards from overflowing.
const MAX_NUM: u64 = 1 << 56;
const DAY_MS: u64 = 86_400_000;
const OUTCOMES: usize = 8;
/// Most `w` rows read or written, and the longest URL kept. A pool of a few
/// upstreams is normal; this only bounds a damaged or hostile file.
const MAX_COUNT_ROWS: usize = 64;
const MAX_COUNT_URL: usize = 256;

fn path(dir: &Path) -> PathBuf {
    dir.join("stats.v1")
}

/// Everything in the file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Saved {
    /// Unix ms from which the counters and top lists count.
    pub since_ms: u64,
    pub saved_ms: u64,
    pub snap: Snapshot,
    pub minutes: Vec<Lite>,
    pub domains: Vec<Top>,
    pub blocked: Vec<Top>,
    pub clients: Vec<Top>,
    /// Win and hedge counters per upstream (`w` rows, absent in older files).
    pub counts: Vec<UpstreamCount>,
}

fn numbers<'a>(out: &mut String, tag: &str, head: &'a [u64], tail: impl IntoIterator<Item = &'a u64>) {
    out.push_str(tag);
    for n in head.iter().chain(tail) {
        let _ = write!(out, " {n}");
    }
    out.push('\n');
}

fn hist_line(out: &mut String, tag: &str, head: &[u64], hist: &HistSnap) {
    let head: Vec<u64> = head.iter().copied().chain([hist.sum_us]).collect();
    numbers(out, tag, &head, &hist.buckets);
}

fn top_lines(out: &mut String, tag: &str, items: &[Top]) {
    for t in items {
        let _ = write!(out, "{tag} {} {} ", t.count, t.err);
        for b in t.key.iter() {
            let _ = write!(out, "{b:02x}");
        }
        out.push('\n');
    }
}

pub fn encode(saved: &Saved) -> String {
    let mut out = String::with_capacity(64 * 1024);
    let _ = writeln!(out, "{MAGIC}\nsince {}\nsaved {}", saved.since_ms, saved.saved_ms);
    let snap = &saved.snap;
    numbers(&mut out, "o", &[], &snap.outcomes);
    numbers(&mut out, "e", &[snap.upstream_errors, snap.plain_fallback], &[]);
    hist_line(&mut out, "r", &[], &snap.request);
    for (i, hist) in snap.upstream.iter().enumerate() {
        if hist.sum_us != 0 || hist.count() != 0 {
            hist_line(&mut out, "u", &[i as u64], hist);
        }
    }
    for m in &saved.minutes {
        numbers(&mut out, "m", &[m.at_ms, m.sum_us], m.outcomes.iter().chain(&m.buckets));
    }
    top_lines(&mut out, "d", &saved.domains);
    top_lines(&mut out, "b", &saved.blocked);
    top_lines(&mut out, "c", &saved.clients);
    // The URL is the redacted origin, one token. An unparseable URL redacts to
    // text with a space; the reader skips that row.
    for c in saved.counts.iter().take(MAX_COUNT_ROWS) {
        let _ = writeln!(out, "w {} {} {}", c.wins, c.hedges, c.url);
    }
    out
}

fn nums<const N: usize>(parts: &mut std::str::SplitAsciiWhitespace<'_>) -> Result<[u64; N], String> {
    let mut out = [0u64; N];
    for slot in &mut out {
        let n: u64 = parts.next().and_then(|t| t.parse().ok()).ok_or("missing or non-numeric field")?;
        if n > MAX_NUM {
            return Err("number out of range".into());
        }
        *slot = n;
    }
    Ok(out)
}

fn once<T>(slot: &mut Option<T>, value: T, tag: &str) -> Result<(), String> {
    slot.replace(value).map_or(Ok(()), |_| Err(format!("repeated `{tag}`")))
}

fn end(parts: &mut std::str::SplitAsciiWhitespace<'_>) -> Result<(), String> {
    parts.next().map_or(Ok(()), |_| Err("trailing field".into()))
}

fn hist(parts: &mut std::str::SplitAsciiWhitespace<'_>) -> Result<HistSnap, String> {
    let [sum_us] = nums(parts)?;
    let buckets = nums::<BUCKETS>(parts)?;
    end(parts)?;
    Ok(HistSnap { buckets, sum_us })
}

/// A well-formed uncompressed wire name: labels of 1..=63 bytes and the root.
fn wire_name(name: &[u8]) -> bool {
    let mut at = 0;
    while let Some(&len) = name.get(at) {
        if len == 0 {
            return at + 1 == name.len();
        }
        if len > 63 {
            return false;
        }
        at += 1 + usize::from(len);
    }
    false
}

/// Whether `key` is what the sketch of this kind stores: a client is a 16-byte
/// address; a domain is the stored wire name plus a "truncated" flag byte. A
/// truncated name is exactly [`NAME_BYTES`] long, any other must be whole.
fn key_ok(tag: &str, key: &[u8]) -> bool {
    if tag == "c" {
        return key.len() == 16;
    }
    match key.split_last() {
        Some((0, name)) => wire_name(name),
        Some((1, name)) => name.len() == NAME_BYTES,
        _ => false,
    }
}

fn unhex(text: &str) -> Option<Box<[u8]>> {
    if !text.len().is_multiple_of(2) || text.len() > 2 * (NAME_BYTES + 1) {
        return None;
    }
    text.as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .collect::<Option<Vec<u8>>>()
        .map(Vec::into_boxed_slice)
}

/// Parses a file. `now_ms` is the current Unix time in ms: snapshots newer
/// than it or older than 24 hours are dropped.
pub fn decode(bytes: &[u8], now_ms: u64) -> Result<Saved, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "not valid UTF-8")?;
    // The writer ends every line with a newline, so a cut file is detectable.
    if !text.ends_with('\n') {
        return Err("truncated".into());
    }
    let mut lines = text.lines();
    if lines.next() != Some(MAGIC) {
        return Err("not a version 1 stats file".into());
    }
    let (mut since, mut saved_ms, mut outcomes, mut errors, mut request) = (None, None, None, None, None);
    let mut upstream = [HistSnap { buckets: [0; BUCKETS], sum_us: 0 }; MAX_UPSTREAMS];
    let mut seen_upstream = [false; MAX_UPSTREAMS];
    let (mut minutes, mut domains, mut blocked, mut clients) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let mut counts = Vec::new();
    for line in lines {
        let mut parts = line.split_ascii_whitespace();
        let Some(tag) = parts.next() else { return Err("empty line".into()) };
        match tag {
            "since" => {
                let [n] = nums(&mut parts)?;
                end(&mut parts)?;
                once(&mut since, n, tag)?;
            }
            "saved" => {
                let [n] = nums(&mut parts)?;
                end(&mut parts)?;
                once(&mut saved_ms, n, tag)?;
            }
            "o" => {
                let n = nums::<OUTCOMES>(&mut parts)?;
                end(&mut parts)?;
                once(&mut outcomes, n, tag)?;
            }
            "e" => {
                let n = nums::<2>(&mut parts)?;
                end(&mut parts)?;
                once(&mut errors, n, tag)?;
            }
            "r" => once(&mut request, hist(&mut parts)?, tag)?,
            "u" => {
                let [index] = nums(&mut parts)?;
                let slot =
                    usize::try_from(index).ok().filter(|&i| i < MAX_UPSTREAMS).ok_or("upstream index out of range")?;
                if std::mem::replace(&mut seen_upstream[slot], true) {
                    return Err("repeated `u` index".into());
                }
                upstream[slot] = hist(&mut parts)?;
            }
            "m" => {
                let [at_ms, sum_us] = nums(&mut parts)?;
                let outcomes = nums::<OUTCOMES>(&mut parts)?;
                let buckets = nums::<BUCKETS>(&mut parts)?;
                end(&mut parts)?;
                if minutes.len() >= MINUTES || minutes.last().is_some_and(|l: &Lite| l.at_ms >= at_ms) {
                    return Err("too many or unordered snapshots".into());
                }
                minutes.push(Lite { at_ms, outcomes, buckets, sum_us });
            }
            "d" | "b" | "c" => {
                let [count, err] = nums(&mut parts)?;
                let key = parts.next().and_then(unhex);
                end(&mut parts)?;
                let table = match tag {
                    "d" => &mut domains,
                    "b" => &mut blocked,
                    _ => &mut clients,
                };
                if table.len() >= TOP_K {
                    return Err("too many rows in a top table".into());
                }
                match key {
                    Some(key) if count >= 1 && err <= count && key_ok(tag, &key) => table.push(Top { key, count, err }),
                    _ => {}
                }
            }
            "w" => {
                // A bad row is skipped and rows past the cap are ignored: the
                // counters are a convenience, never a reason to drop the file.
                let row = nums::<2>(&mut parts).ok().and_then(|[wins, hedges]| {
                    let url =
                        parts.next().filter(|u| u.len() <= MAX_COUNT_URL && u.bytes().all(|b| b.is_ascii_graphic()))?;
                    end(&mut parts).ok()?;
                    Some(UpstreamCount { url: url.to_string(), wins, hedges })
                });
                if let Some(row) = row.filter(|_| counts.len() < MAX_COUNT_ROWS) {
                    counts.push(row);
                }
            }
            _ => return Err(format!("unknown line `{}`", tag.chars().take(8).collect::<String>())),
        }
    }
    let (Some(since), Some(saved_ms), Some(outcomes), Some([upstream_errors, plain_fallback]), Some(request)) =
        (since, saved_ms, outcomes, errors, request)
    else {
        return Err("a required line is missing".into());
    };
    minutes.retain(|m| m.at_ms <= now_ms && m.at_ms + DAY_MS >= now_ms);
    Ok(Saved {
        since_ms: since.min(now_ms),
        saved_ms,
        snap: Snapshot { outcomes, upstream_errors, plain_fallback, request, upstream },
        minutes,
        domains,
        blocked,
        clients,
        counts,
    })
}

/// Reads and parses the file; `Ok(None)` when there is none.
pub fn load(dir: &Path, now_ms: u64) -> Result<Option<Saved>, String> {
    let mut bytes = Vec::new();
    match lists::open_regular(&path(dir)).and_then(|file| file.take(MAX_READ + 1).read_to_end(&mut bytes)) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.to_string()),
    }
    if bytes.len() as u64 > MAX_READ {
        return Err("larger than 1 MiB".into());
    }
    decode(&bytes, now_ms).map(Some)
}

/// Writes the file atomically. Not written if the directory cannot be made.
pub fn save(dir: &Path, saved: &Saved) -> io::Result<()> {
    lists::create_private_dir(dir)?;
    lists::atomic_write(&path(dir), encode(saved).as_bytes())
}

/// Deletes the file (`persist_stats = false` keeps no browsing data on disk).
pub fn remove(dir: &Path) {
    let _ = fs::remove_file(path(dir));
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Keeps about one snapshot per 5 minutes beyond the newest 10 minutes, which
/// bounds the file (a few hundred rows) and still resolves the 5-minute window
/// right after a restart.
fn thin(minutes: Vec<Lite>) -> Vec<Lite> {
    let Some(newest) = minutes.last().map(|l| l.at_ms) else { return minutes };
    let mut kept: Vec<Lite> = Vec::new();
    for lite in minutes {
        if newest - lite.at_ms <= 600_000 || kept.last().is_none_or(|k| lite.at_ms >= k.at_ms + 300_000) {
            kept.push(lite);
        }
    }
    kept
}

/// Startup, before any listener: with `enabled` loads the file into the global
/// counters and the query log, otherwise deletes it. A bad file is ignored
/// with one warning. Needs [`querylog::init`] to have run. Returns the saved
/// per-upstream counters, which the caller hands to
/// [`UpstreamPool::restore_counters`](crate::upstream::UpstreamPool::restore_counters)
/// once the pool exists.
pub fn start(dir: &Path, enabled: bool) -> Vec<UpstreamCount> {
    if !enabled {
        remove(dir);
        return Vec::new();
    }
    let Some(log) = querylog::get() else { return Vec::new() };
    match load(dir, now_ms()) {
        Ok(None) => {}
        Ok(Some(saved)) => {
            stats::global().restore(&saved.snap);
            log.restore(
                Kept {
                    since_ms: saved.since_ms,
                    minutes: saved.minutes,
                    domains: saved.domains,
                    blocked: saved.blocked,
                    clients: saved.clients,
                },
                &saved.snap,
            );
            log::log("info", "stats_restored", &[("since_unix", (saved.since_ms / 1000).to_string())]);
            return saved.counts;
        }
        Err(reason) => log::log("warn", "stats_ignored", &[("reason", reason)]),
    }
    Vec::new()
}

/// Writes the current stats (blocking file I/O: call it off the async workers),
/// or deletes the file when `enabled` is off, as a reload can turn it off.
/// The snapshots are read before the counters, so the counters are never
/// behind the newest snapshot.
pub fn write_current(dir: &Path, enabled: bool, counts: Vec<UpstreamCount>) {
    if !enabled {
        remove(dir);
        return;
    }
    let Some(log) = querylog::get() else { return };
    let kept = log.keep();
    let saved = Saved {
        since_ms: kept.since_ms,
        saved_ms: now_ms(),
        snap: stats::global().snapshot(),
        minutes: thin(kept.minutes),
        domains: kept.domains,
        blocked: kept.blocked,
        clients: kept.clients,
        counts,
    };
    if let Err(error) = save(dir, &saved) {
        log::log("warn", "stats_save_failed", &[("error", error.to_string())]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("sopedu-stats-{tag}-{}", std::process::id()))
    }

    fn wire(name: &str) -> Box<[u8]> {
        let mut out = Vec::new();
        for label in name.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.extend([0, 0]); // root, then the "not truncated" flag
        out.into()
    }

    fn count(url: &str, wins: u64, hedges: u64) -> UpstreamCount {
        UpstreamCount { url: url.into(), wins, hedges }
    }

    fn sample() -> Saved {
        let mut snap = stats::Stats::new().snapshot();
        snap.outcomes = [5, 4, 3, 2, 1, 0, 7, 8];
        snap.upstream_errors = 9;
        snap.plain_fallback = 2;
        snap.request.buckets[3] = 11;
        snap.request.sum_us = 123_456;
        snap.upstream[1].buckets[20] = 6;
        snap.upstream[1].sum_us = 777;
        let lite = |at_ms, n| {
            let mut l = Lite { at_ms, outcomes: [n; 8], buckets: [0; BUCKETS], sum_us: n };
            l.buckets[4] = n;
            l
        };
        let top = |name: &str, count| Top { key: wire(name), count, err: 1 };
        Saved {
            since_ms: 1_000,
            saved_ms: 9_000_000,
            snap,
            minutes: vec![lite(8_000_000, 1), lite(8_060_000, 2)],
            domains: vec![top("example.com", 10), top("a.test", 3)],
            blocked: vec![top("ads.example", 4)],
            clients: vec![Top { key: querylog::client_key("192.0.2.9".parse().unwrap()).into(), count: 6, err: 0 }],
            counts: vec![count("https://a.test", 7, 2), count("https://b.test:8443", 1, 0)],
        }
    }

    #[test]
    fn round_trips_through_the_file() {
        let dir = dir("round");
        let _ = fs::remove_dir_all(&dir);
        let saved = sample();
        save(&dir, &saved).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(path(&dir)).unwrap().permissions().mode() & 0o777, 0o600);
        }
        assert_eq!(load(&dir, 9_000_000).unwrap(), Some(saved));
        remove(&dir);
        assert_eq!(load(&dir, 9_000_000), Ok(None));
        let _ = fs::remove_dir_all(&dir);
    }

    fn pool(urls: &[&str]) -> crate::upstream::UpstreamPool {
        let cfg =
            crate::config::Config { upstreams: urls.iter().map(|u| u.to_string()).collect(), ..Default::default() };
        crate::upstream::UpstreamPool::new(&cfg).unwrap()
    }

    #[test]
    fn upstream_counters_round_trip_and_drop_removed_upstreams() {
        // The token and path of the configured URL never reach the file.
        let first = pool(&["https://a.test/dns-query?token=secret", "https://gone.test/dns-query"]);
        first.restore_counters(&[count("https://a.test", 7, 2), count("https://gone.test", 4, 1)]);
        let mut saved = sample();
        saved.counts = first.counters();
        let text = encode(&saved);
        assert!(!text.contains("secret") && !text.contains("dns-query"));
        let loaded = decode(text.as_bytes(), 9_000_000).unwrap();
        assert_eq!(loaded, saved);
        // After a restart one upstream is gone and a new one appears.
        let second = pool(&["https://a.test/dns-query?token=other", "https://new.test/dns-query"]);
        second.restore_counters(&loaded.counts);
        assert_eq!(second.counters(), vec![count("https://a.test", 7, 2), count("https://new.test", 0, 0)]);
    }

    #[test]
    fn corrupt_counter_rows_are_ignored() {
        let good = encode(&sample());
        let now = 9_000_000;
        let rows =
            ["w x 1 https://c.test", "w 1 https://c.test", "w 1 2", "w 1 2 https://c.test extra", "w 1 2 caf\u{e9}"];
        let bad = format!("{good}{}\nw 3 1 https://ok.test\n", rows.join("\n"));
        let counts = decode(bad.as_bytes(), now).unwrap().counts;
        assert_eq!(counts.len(), 3, "the two sample rows and the good one: {counts:?}");
        assert_eq!(counts[2], count("https://ok.test", 3, 1));
        // Rows past the cap are dropped, and a v1 file without any loads.
        let many = "w 1 1 https://x.test\n".repeat(MAX_COUNT_ROWS + 5);
        assert_eq!(decode(format!("{good}{many}").as_bytes(), now).unwrap().counts.len(), MAX_COUNT_ROWS);
        let without: String = good.lines().filter(|l| !l.starts_with("w ")).map(|l| format!("{l}\n")).collect();
        assert!(decode(without.as_bytes(), now).unwrap().counts.is_empty());
    }

    #[test]
    fn restored_counters_merge_into_the_stats() {
        let saved = sample();
        let stats = Box::new(stats::Stats::new());
        stats.restore(&saved.snap);
        stats.count(stats::Outcome::Cache);
        stats.upstream(1, std::time::Duration::from_micros(3));
        let snap = stats.snapshot();
        assert_eq!(snap.outcomes[0], 6);
        assert_eq!(snap.upstream_errors, 9);
        assert_eq!(snap.plain_fallback, 2);
        assert_eq!(snap.request, saved.snap.request);
        assert_eq!(snap.upstream[1].count(), 7);
        assert_eq!(snap.upstream[1].sum_us, 780);
    }

    #[test]
    fn ignores_corrupt_truncated_oversized_and_old_files() {
        let good = encode(&sample());
        let now = 9_000_000;
        assert!(decode(good.as_bytes(), now).is_ok());
        for cut in (0..good.len()).filter(|&cut| cut == 0 || good.as_bytes()[cut - 1] != b'\n') {
            assert!(decode(&good.as_bytes()[..cut], now).is_err(), "cut at {cut}");
        }
        assert!(decode(good.replace("v1", "v2").as_bytes(), now).is_err(), "other version");
        assert!(decode(b"\xff\xfe", now).is_err(), "not UTF-8");
        assert!(decode(b"", now).is_err());
        assert!(decode(good.replace("o 5 ", "o x ").as_bytes(), now).is_err(), "non-numeric");
        assert!(decode(good.replace("o 5 ", "o 99999999999999999999 ").as_bytes(), now).is_err(), "overflow");
        assert!(decode(format!("{good}o 1 2 3 4 5 6 7 8\n").as_bytes(), now).is_err(), "repeated line");
        assert!(decode(format!("{good}zzz 1\n").as_bytes(), now).is_err(), "unknown line");
        assert!(decode(format!("{good}u 16 0 {}\n", "0 ".repeat(BUCKETS)).as_bytes(), now).is_err(), "upstream index");
        // A bad name row is skipped, not fatal.
        let bad_row = format!("{good}d 5 0 zz\nd 5 0 0001\nd 0 0 {}\nd 5 9 {}\n", "00".repeat(2), "00".repeat(2));
        let saved = decode(bad_row.as_bytes(), now).unwrap();
        assert_eq!(saved.domains.len(), 2);
        // Too many rows in a table is corrupt.
        let many = "d 1 0 0000\n".repeat(TOP_K + 1);
        assert!(decode(format!("{good}{many}").as_bytes(), now).is_err());
        // Snapshots from the future or older than a day are dropped.
        assert_eq!(decode(good.as_bytes(), 8_010_000).unwrap().minutes.len(), 1);
        assert!(decode(good.as_bytes(), 8_000_000 + DAY_MS + 1).unwrap().minutes.len() == 1);
        assert!(decode(good.as_bytes(), 8_060_000 + DAY_MS + 1).unwrap().minutes.is_empty());

        let dir = dir("bad");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(path(&dir), good.repeat(MAX_READ as usize / good.len() + 2)).unwrap();
        assert!(load(&dir, now).is_err(), "over 1 MiB");
        fs::write(path(&dir), &good.as_bytes()[..good.len() - 3]).unwrap();
        assert!(load(&dir, now).is_err(), "cut mid-line");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn thins_old_snapshots_and_keeps_the_newest() {
        let lite = |min: u64| Lite { at_ms: min * 60_000, outcomes: [0; 8], buckets: [0; BUCKETS], sum_us: 0 };
        let kept = thin((0..=1440).map(lite).collect());
        assert!(kept.len() < 330, "{}", kept.len());
        assert_eq!(kept.last().unwrap().at_ms, 1440 * 60_000);
        assert!(kept.iter().filter(|l| l.at_ms >= 1429 * 60_000).count() >= 11, "the last 10 minutes are whole");
        assert!(thin(Vec::new()).is_empty());
        // A full file of the worst case stays under the read limit.
        let mut big = sample();
        big.minutes = kept
            .iter()
            .map(|l| Lite { outcomes: [MAX_NUM; 8], buckets: [MAX_NUM; BUCKETS], sum_us: MAX_NUM, ..*l })
            .collect();
        assert!((encode(&big).len() as u64) < MAX_READ);
    }
}
