//! Persistent, per-list blocklist refresh.
//!
//! Each configured URL keeps a body and a small metadata file under
//! `state_dir/lists/`, named by a stable FNV-1a hash of the URL. A refresh
//! downloads the lists in parallel, sends `If-None-Match`/`If-Modified-Since`
//! when a cached copy exists, and parses each body line by line. Bad lines are
//! skipped and counted, and a failed list falls back to its last good copy
//! instead of aborting the whole refresh. The caller builds one [`crate::rules::Rules`]
//! table from the per-list results and publishes it atomically.
//!
//! The cache directory and files are owner-only on Unix because a list URL may
//! carry a token even though the list body is public. [`SourceStatus::name`]
//! is sanitized: scheme, host, port and a trailing segment with a list file
//! extension, never userinfo, other path segments or query.

use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use foldhash::fast::RandomState;
use reqwest::{
    header::{HeaderName, ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED},
    StatusCode,
};
use tokio::task::JoinSet;

use crate::{
    config::Config,
    rules::{self, RuleSetBuilder, RuleSource},
};

/// Longest accepted list line. Longer lines are skipped and counted.
const MAX_LINE_BYTES: usize = 64 * 1024;
/// Lists downloaded at the same time.
const CONCURRENCY: usize = 8;
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(180);
const CACHE_SUBDIR: &str = "lists";
/// List ids are `u16`; id 0 belongs to the inline user rules.
const MAX_LISTS: usize = u16::MAX as usize - 1;
/// Recorded when a list reaches its share of `blocklist_max_rules_total`.
const LIMIT_TOTAL: &str = "blocklist_max_rules_total reached";

/// Source scan bounds for [`ListManager::find_rules`].
const SCAN_BYTES: u64 = 128 * 1024 * 1024;
const SCAN_TIME: Duration = Duration::from_millis(250);
const SCAN_HITS: usize = 200;
const SCAN_LINE_CHARS: usize = 200;

/// One source line found by [`ListManager::find_rules`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleHit {
    /// 0 for the inline user rules, the list id otherwise.
    pub list_id: u16,
    /// 1-based line (the index in `user_rules` for id 0).
    pub line: usize,
    /// The trimmed source text, cut at 200 characters.
    pub text: String,
    /// The normalized domain the rule is for.
    pub parent: String,
    /// The rule class bit ([`rules::rule_text`], [`rules::rank`]).
    pub flags: u8,
}

pub struct SourceScan {
    pub hits: Vec<RuleHit>,
    pub complete: bool,
}

/// What the UI needs to know about one configured list after a refresh.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceStatus {
    /// 1-based list id; 0 is reserved for inline user rules.
    pub id: u16,
    /// Sanitized display name: origin plus a trailing file-name segment.
    pub name: String,
    /// Rule lines accepted from this list (comments and blanks excluded).
    pub rules: usize,
    /// Lines skipped: comments, blanks, unsupported rules, invalid UTF-8 and
    /// lines longer than 64 KiB.
    pub skipped: u64,
    /// Unix seconds of the last successful download or `304`.
    pub last_success: Option<u64>,
    /// Error from this run, if the list was served from cache or skipped.
    pub last_error: Option<String>,
    /// True when this run used the cached body (`304` or error fallback).
    pub used_cache: bool,
}

/// HTTP client builder for list downloads.
///
/// Use this rather than a bare client: it applies the redirect guard and keeps
/// the list fetches away from any proxy configuration.
pub fn client_builder() -> reqwest::ClientBuilder {
    crate::tls::client_builder().no_proxy().redirect(redirect_policy())
}

/// Five redirects at most. Targets must be http(s); an https hop may not be
/// followed by an http target, and the target host may not be `localhost` or
/// a name under it (RFC 6761 §6.3), nor a loopback, private (RFC 1918, RFC
/// 4193), shared (RFC 6598), benchmarking (RFC 2544), link-local (including
/// the cloud metadata address) or unspecified IP literal, also when written
/// as an IPv4 address inside IPv6 (mapped, compatible or NAT64).
///
/// This does not resolve hostnames, so a name that resolves to a private
/// address still passes; it is defense in depth, not full SSRF protection.
fn redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        if redirect_target_allowed(attempt.previous(), attempt.url()) {
            attempt.follow()
        } else {
            attempt.stop()
        }
    })
}

/// `previous` holds the URLs already visited, starting with the original
/// request, so its length is the redirects followed so far plus one. A length
/// above five therefore rejects the sixth redirect and allows five.
fn redirect_target_allowed(previous: &[reqwest::Url], target: &reqwest::Url) -> bool {
    if previous.len() > 5 {
        return false;
    }
    if !matches!(target.scheme(), "http" | "https") {
        return false;
    }
    if target.scheme() == "http" && previous.last().is_some_and(|hop| hop.scheme() == "https") {
        return false;
    }
    let Some(host) = target.host_str() else {
        return false;
    };
    let bare = host.strip_prefix('[').and_then(|host| host.strip_suffix(']')).unwrap_or(host);
    // The URL parser already lowercased the name.
    let name = bare.trim_end_matches('.');
    if name == "localhost" || name.ends_with(".localhost") {
        return false;
    }
    !bare.parse::<IpAddr>().is_ok_and(blocked_redirect_ip)
}

fn blocked_redirect_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => blocked_redirect_ipv4(ip),
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_unicast_link_local()
                || ip.is_unique_local()
                // 64:ff9b:1::/48 is local-use NAT64 (RFC 8215), never a public server.
                || segments[..3] == [0x64, 0xff9b, 1]
                // IPv4-mapped and IPv4-compatible (RFC 4291 §2.5.5) and the
                // well-known NAT64 prefix 64:ff9b::/96 (RFC 6052) reach the
                // IPv4 address in the last 32 bits.
                || ip.to_ipv4().is_some_and(blocked_redirect_ipv4)
                || (segments[..6] == [0x64, 0xff9b, 0, 0, 0, 0]
                    && blocked_redirect_ipv4(std::net::Ipv4Addr::from(u128::from(ip) as u32)))
        }
    }
}

// 0.0.0.0/8 is "this network" (RFC 791, RFC 1122 §3.2.1.3); 100.64.0.0/10 is
// RFC 6598 shared space (carrier NAT, Tailscale); 198.18.0.0/15 is RFC 2544
// benchmarking. None of them is the public internet.
fn blocked_redirect_ipv4(ip: std::net::Ipv4Addr) -> bool {
    ip.is_loopback()
        || ip.is_link_local()
        || ip.is_private()
        || matches!(ip.octets(), [0, ..] | [198, 18 | 19, ..])
        || matches!(ip.octets(), [100, b, ..] if (64..128).contains(&b))
}

fn valid_list_url(url: &str) -> bool {
    reqwest::Url::parse(url)
        .is_ok_and(|parsed| matches!(parsed.scheme(), "http" | "https") && parsed.host_str().is_some())
}

/// The result of one boot-cache load or one refresh.
pub struct RefreshOutcome {
    pub rules: rules::Rules,
    pub statuses: Vec<SourceStatus>,
    /// A list could not be refreshed this time (it kept its cached copy or
    /// has none); retry before the regular interval.
    pub retry_soon: bool,
}

#[derive(Clone, Default)]
struct Meta {
    etag: Option<String>,
    last_modified: Option<String>,
    last_success: Option<u64>,
    /// Rules in the cached body when it was stored.
    rules: Option<u64>,
    /// Rules in the last download that was held back as too large a shrink.
    refused: Option<u64>,
    /// When that hold started (Unix seconds). Downloads that small keep being
    /// refused until `refresh_hours` after it, across retries and restarts.
    refused_at: Option<u64>,
}

struct ListRun {
    id: u16,
    name: String,
    entries: Vec<(u64, u8)>,
    skipped: u64,
    last_success: Option<u64>,
    last_error: Option<String>,
    used_cache: bool,
    /// A body was parsed (even if a cap or read error cut it short).
    available: bool,
    /// This refresh could not replace the list; retry it early.
    failed: bool,
}

impl ListRun {
    fn new(id: u16, name: String) -> Self {
        Self {
            id,
            name,
            entries: Vec::new(),
            skipped: 0,
            last_success: None,
            last_error: None,
            used_cache: false,
            available: false,
            failed: false,
        }
    }
}

/// Equal share of the total rule cap for list `index` out of `n` lists.
///
/// The first `cap % n` lists get one extra slot, so the shares sum to exactly
/// `cap`. A small list leaves its unused share to nobody; a list over its
/// share is truncated at the same line on every refresh.
fn rule_quota(cap: u64, n: usize, index: usize) -> u64 {
    if n == 0 {
        return 0;
    }
    let n = n as u64;
    cap / n + u64::from((index as u64) < cap % n)
}

/// Owns the HTTP client, the list configuration and the on-disk cache.
///
/// Cloning is cheap and is used to give each parallel download its own copy.
#[derive(Clone)]
pub struct ListManager {
    http: reqwest::Client,
    urls: Vec<String>,
    user_rules: Vec<String>,
    state_dir: PathBuf,
    lists_dir: PathBuf,
    max_bytes: u64,
    max_lines: u64,
    max_rules_total: u64,
    /// `refresh_hours` in seconds: how long a held-back shrink stays refused.
    shrink_hold_secs: u64,
}

impl ListManager {
    pub fn new(http: reqwest::Client, config: &Config) -> Self {
        Self {
            http,
            urls: config.blocklists.clone(),
            user_rules: config.user_rules.clone(),
            state_dir: config.state_dir.clone(),
            lists_dir: config.state_dir.join(CACHE_SUBDIR),
            max_bytes: config.blocklist_max_bytes,
            max_lines: config.blocklist_max_lines,
            max_rules_total: config.blocklist_max_rules_total,
            shrink_hold_secs: config.refresh_hours.saturating_mul(3600),
        }
    }

    /// Builds a snapshot from the cached bodies only, without touching the
    /// network. Used before listeners start so blocking survives a restart
    /// during an outage.
    pub fn load_cached(&self) -> RefreshOutcome {
        let mut builder = RuleSetBuilder::new();
        let hasher = builder.hasher();
        for rule in &self.user_rules {
            builder.add_line(rule, 0);
        }
        let n = self.urls.len().min(MAX_LISTS);
        let runs = self
            .urls
            .iter()
            .take(MAX_LISTS)
            .enumerate()
            .map(|(index, url)| self.cached_run(index, url, &hasher, rule_quota(self.max_rules_total, n, index)))
            .collect();
        self.assemble(builder, runs)
    }

    /// Downloads every list (at most `CONCURRENCY` at a time), falls back to
    /// the cached copy on failure, and returns the new snapshot.
    ///
    /// An error means there is nothing to publish: every list failed without a
    /// cached copy and there are no inline user rules. The caller keeps the
    /// previous snapshot in that case.
    pub async fn refresh(&self) -> Result<RefreshOutcome, String> {
        if self.urls.len() > MAX_LISTS {
            return Err(format!("too many blocklists (max {MAX_LISTS})"));
        }
        let mut builder = RuleSetBuilder::new();
        let hasher = builder.hasher();
        for rule in &self.user_rules {
            builder.add_line(rule, 0);
        }

        let mut runs = Vec::with_capacity(self.urls.len());
        let mut tasks = JoinSet::new();
        let mut next = 0;
        let n = self.urls.len();
        while next < self.urls.len() || !tasks.is_empty() {
            while tasks.len() < CONCURRENCY && next < self.urls.len() {
                let manager = self.clone();
                let url = self.urls[next].clone();
                let hasher = hasher.clone();
                let quota = rule_quota(self.max_rules_total, n, next);
                let index = next;
                tasks.spawn(async move { manager.refresh_one(index, &url, &hasher, quota).await });
                next += 1;
            }
            match tasks.join_next().await {
                Some(Ok(run)) => runs.push(run),
                Some(Err(error)) => return Err(format!("blocklist task failed: {error}")),
                None => break,
            }
        }

        let available = self.urls.is_empty() || !self.user_rules.is_empty() || runs.iter().any(|run| run.available);
        // `finish` sorts, deduplicates and builds the probe table. Keep that
        // CPU work off the async worker; the downloads above stay async.
        let manager = self.clone();
        let outcome = tokio::task::spawn_blocking(move || manager.assemble(builder, runs))
            .await
            .map_err(|error| format!("blocklist assembly failed: {error}"))?;
        if !available {
            // Name every list and why it failed; the caller drops the statuses.
            let why: Vec<&str> = outcome.statuses.iter().filter_map(|s| s.last_error.as_deref()).collect();
            return Err(format!("no blocklist or user rules available: {}", why.join("; ")));
        }
        Ok(outcome)
    }

    fn cached_run(&self, index: usize, url: &str, hasher: &RandomState, quota: u64) -> ListRun {
        let mut run = ListRun::new(list_id(index), display_name(url));
        let (body_path, meta_path) = self.cache_paths(url);
        let meta = read_meta(&meta_path);
        if let Ok(file) = open_regular(&body_path) {
            let mut parser = ListParser::new(hasher, self.max_bytes, self.max_lines, quota);
            parse_file(file, &mut parser);
            apply(&mut run, parser);
            run.last_success = meta.last_success;
            run.used_cache = true;
            run.available = true;
        }
        run
    }

    async fn refresh_one(&self, index: usize, url: &str, hasher: &RandomState, quota: u64) -> ListRun {
        let id = list_id(index);
        let mut run = ListRun::new(id, display_name(url));
        if !valid_list_url(url) {
            run.last_error = Some(format!("{}: list URL must use http or https", run.name));
            return run;
        }
        let (body_path, meta_path) = self.cache_paths(url);
        let (meta, cached_body) = off_worker(|| (read_meta(&meta_path), body_path.exists()));
        run.last_success = meta.last_success;

        // Only ask for a 304 when there is a body to reuse.
        let mut request = self.http.get(url).timeout(DOWNLOAD_TIMEOUT);
        if cached_body {
            if let Some(etag) = &meta.etag {
                request = request.header(IF_NONE_MATCH, etag.as_str());
            }
            if let Some(modified) = &meta.last_modified {
                request = request.header(IF_MODIFIED_SINCE, modified.as_str());
            }
        }
        let mut response = match request.send().await {
            Ok(response) => response,
            Err(error) => return self.fallback(run, &meta, &body_path, hasher, describe(&error), quota),
        };

        if response.status() == StatusCode::NOT_MODIFIED {
            let mut parser = ListParser::new(hasher, self.max_bytes, self.max_lines, quota);
            if cached_body {
                match open_regular(&body_path) {
                    Ok(file) => parse_file(file, &mut parser),
                    Err(error) => parser.stop(&format!("cache read failed: {error}")),
                }
            } else {
                parser.stop("HTTP 304 without a cached copy");
            }
            let parse_error = parser.error.take();
            apply(&mut run, parser);
            if let Some(error) = &parse_error {
                if error != LIMIT_TOTAL {
                    // No usable cached body: drop the validators so the next
                    // refresh downloads the list instead of asking for it again.
                    let cleared = Meta { etag: None, last_modified: None, ..meta.clone() };
                    let meta_error = off_worker(|| write_meta(&meta_path, &cleared)).err();
                    run.used_cache = !run.entries.is_empty();
                    run.available = !run.entries.is_empty();
                    run.last_success = cleared.last_success;
                    run.failed = true;
                    run.last_error = Some(match meta_error {
                        Some(meta_error) => format!("{}: {error}; cache metadata failed: {meta_error}", run.name),
                        None => format!("{}: {error}", run.name),
                    });
                    return run;
                }
                // The cached body is readable but over this list's quota; the
                // 304 still revalidated it, so keep the validators.
            }
            run.used_cache = true;
            run.available = true;
            run.last_success = Some(now_secs());
            // The server confirmed the cached copy: forget a held-back shrink.
            let meta = Meta { last_success: run.last_success, refused: None, refused_at: None, ..meta };
            let meta_error = off_worker(|| write_meta(&meta_path, &meta)).err();
            run.last_error = parse_error.map(|error| format!("{}: {error}", run.name));
            if let Some(meta_error) = meta_error {
                run.last_error = Some(match run.last_error.take() {
                    Some(previous) => format!("{previous}; cache metadata failed: {meta_error}"),
                    None => format!("{}: cache metadata failed: {meta_error}", run.name),
                });
            }
            return run;
        }

        if response.status() != StatusCode::OK {
            return self.fallback(run, &meta, &body_path, hasher, format!("HTTP {}", response.status()), quota);
        }
        if response.content_length().is_some_and(|length| length > self.max_bytes) && cached_body {
            return self.fallback(run, &meta, &body_path, hasher, "list exceeds blocklist_max_bytes".into(), quota);
        }

        let etag = header_text(&response, ETAG);
        let last_modified = header_text(&response, LAST_MODIFIED);
        let mut cache_error = None;
        let mut temp = None;
        off_worker(|| match self.ensure_dirs() {
            Ok(()) => {
                let path = temp_path(&body_path);
                let _ = fs::remove_file(&path);
                match open_private(&path) {
                    Ok(file) => temp = Some((path, file)),
                    Err(error) => cache_error = Some(format!("cache write failed: {error}")),
                }
            }
            Err(error) => cache_error = Some(format!("cache directory failed: {error}")),
        });

        // A cancelled download (the startup wait, shutdown) drops this future
        // mid-body; remove its temp file then too. After a rename this is a
        // harmless NotFound.
        let _remove_temp = temp.as_ref().map(|(path, _)| RemoveOnDrop(path.clone()));
        let mut parser = ListParser::new(hasher, self.max_bytes, self.max_lines, quota);
        let mut read_error = None;
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    // Parsing the chunk and writing it to the cache copy are
                    // blocking work: keep both off the async worker.
                    let written = off_worker(|| {
                        parser.feed(&chunk);
                        temp.as_mut().map_or(Ok(()), |(_, file)| file.write_all(&chunk))
                    });
                    if let Err(error) = written {
                        cache_error = Some(format!("cache write failed: {error}"));
                        if let Some((path, _)) = temp.take() {
                            discard(&path);
                        }
                    }
                    if parser.stopped {
                        break;
                    }
                }
                Ok(None) => break,
                Err(error) => {
                    // reqwest's Display appends the raw URL, which may carry a token.
                    read_error = Some(format!("download interrupted: {}", describe(&error)));
                    break;
                }
            }
        }
        parser.finish();

        if let Some(error) = read_error {
            if let Some((path, _)) = temp.take() {
                discard(&path);
            }
            // Free the partial prefix before the fallback parses the cache, so
            // both copies are never resident together.
            drop(parser);
            return self.fallback(run, &meta, &body_path, hasher, error, quota);
        }
        let quota_error = parser.error.take();
        if let Some(error) = quota_error.clone().filter(|error| error != LIMIT_TOTAL) {
            let partial = std::mem::take(&mut parser.entries);
            let skipped = parser.skipped;
            if let Some((path, _)) = temp.take() {
                discard(&path);
            }
            // A per-list byte or line limit prefers the last good copy, after
            // freeing the discarded prefix.
            if off_worker(|| body_path.exists()) {
                drop(partial);
                return self.fallback(run, &meta, &body_path, hasher, error, quota);
            }
            run.entries = partial;
            run.skipped = skipped;
            run.available = true;
            run.last_error = Some(format!("{}: {error}", run.name));
            run.last_success = None;
            return run;
        }
        let (etag, last_modified) = if quota_error.is_some() {
            // A quota stop is a successful load of the list's share: cache the
            // whole lines read so far, without validators, so the next refresh
            // downloads the list again rather than revalidating a prefix.
            let cut = temp.as_ref().map(|(_, file)| off_worker(|| file.set_len(parser.kept)));
            if let Some(Err(error)) = cut {
                cache_error = Some(format!("cache write failed: {error}"));
                if let Some((path, _)) = temp.take() {
                    discard(&path);
                }
            }
            (None, None)
        } else {
            (etag, last_modified)
        };

        // An empty body, an error page or other non-list body parses to
        // nothing: never a useful update (a list is dropped by removing it from
        // the config), so it is always refused and retried early. A list that
        // loses over 90% of its rules at once is more likely a broken mirror or
        // a captive portal than a real update: such downloads are held back
        // until a full refresh interval after the first one, whatever retries,
        // reloads or restarts happen in between, and one that is still that
        // small after that is accepted, so a list that really shrank is not
        // pinned to its old rules. A quota stop is not judged here: the cap set
        // its size.
        let count = parser.entries.len() as u64;
        let previous = if cached_body { meta.rules.unwrap_or(0) } else { 0 };
        let shrunk = count > 0 && count.saturating_mul(10) < previous;
        let now = now_secs();
        // A mark without a start time predates it: its hold is over. So is
        // one that starts in the future (set while the clock ran ahead), or
        // it would last until the clock caught up, plus a whole interval.
        let held_since = meta.refused.and(meta.refused_at.or(Some(0)));
        let holding = held_since.is_none_or(|since| since <= now && now - since < self.shrink_hold_secs);
        if quota_error.is_none() && (count == 0 || (shrunk && holding)) {
            if let Some((path, _)) = temp.take() {
                discard(&path);
            }
            drop(parser);
            if count == 0 {
                return self.fallback(run, &meta, &body_path, hasher, "list contains no rules".into(), quota);
            }
            let marked = Meta { refused: Some(count), refused_at: held_since.or(Some(now)), ..meta.clone() };
            let mut error = format!(
                "refused: {count} rules, previously {previous}; accepted if a refresh a full interval later agrees"
            );
            if let Err(meta_error) = off_worker(|| write_meta(&meta_path, &marked)) {
                error.push_str(&format!("; cache metadata failed: {meta_error}"));
            }
            let mut run = self.fallback(run, &meta, &body_path, hasher, error, quota);
            run.failed = false;
            return run;
        }

        apply(&mut run, parser);
        run.available = true;
        if let Some((path, mut file)) = temp.take() {
            off_worker(|| {
                // Sync before the rename so a power loss cannot leave an empty
                // body behind validators that would keep it with a 304.
                let flushed = file.flush().and_then(|()| file.sync_all());
                drop(file);
                match flushed {
                    Ok(()) => match fs::rename(&path, &body_path) {
                        Ok(()) => {
                            let success = now_secs();
                            run.last_success = Some(success);
                            let meta = Meta {
                                etag,
                                last_modified,
                                last_success: Some(success),
                                rules: Some(count),
                                refused: None,
                                refused_at: None,
                            };
                            if let Err(error) = write_meta(&meta_path, &meta) {
                                cache_error = Some(format!("cache metadata failed: {error}"));
                            }
                        }
                        Err(error) => {
                            let _ = fs::remove_file(&path);
                            cache_error = Some(format!("cache write failed: {error}"));
                        }
                    },
                    Err(error) => {
                        let _ = fs::remove_file(&path);
                        cache_error = Some(format!("cache write failed: {error}"));
                    }
                }
            });
        } else {
            run.last_success = Some(now_secs());
        }
        let notes: Vec<String> = quota_error.into_iter().chain(cache_error).collect();
        run.last_error = (!notes.is_empty()).then(|| format!("{}: {}", run.name, notes.join("; ")));
        run
    }

    /// Uses the last good cached body if one exists. Otherwise the list is
    /// skipped and does not count as available.
    fn fallback(
        &self,
        mut run: ListRun,
        meta: &Meta,
        body_path: &Path,
        hasher: &RandomState,
        error: String,
        quota: u64,
    ) -> ListRun {
        let error = format!("{}: {error}", run.name);
        run.failed = true;
        if body_path.exists() {
            run.entries.clear();
            run.skipped = 0;
            let mut parser = ListParser::new(hasher, self.max_bytes, self.max_lines, quota);
            match open_regular(body_path) {
                Ok(file) => parse_file(file, &mut parser),
                Err(error) => parser.stop(&format!("cache read failed: {error}")),
            }
            let parse_error = parser.error.take();
            apply(&mut run, parser);
            run.used_cache = true;
            run.available = true;
            run.last_success = meta.last_success;
            run.last_error = Some(match parse_error {
                Some(parse) => format!("{error}; cached copy: {parse}"),
                None => error,
            });
        } else {
            run.entries.clear();
            run.skipped = 0;
            run.available = false;
            run.last_success = None;
            run.last_error = Some(error);
        }
        run
    }

    /// Feeds all per-list results into one builder in list order.
    ///
    /// Each parser already stops at its own quota, so this truncation is only
    /// a final guard against a quota bug; it never reorders or redistributes.
    fn assemble(&self, mut builder: RuleSetBuilder, mut runs: Vec<ListRun>) -> RefreshOutcome {
        runs.sort_by_key(|run| run.id);
        builder.reserve(runs.iter().flat_map(|run| run.entries.iter().map(|&(hash, _)| hash)));
        let mut statuses = Vec::with_capacity(runs.len());
        let retry_soon = runs.iter().any(|run| run.failed);
        let mut total = 0u64;
        for mut run in runs {
            let room = self.max_rules_total.saturating_sub(total);
            if run.entries.len() as u64 > room {
                let keep = usize::try_from(room).unwrap_or(usize::MAX);
                run.entries.truncate(keep);
                run.last_error = Some(match run.last_error.take() {
                    Some(previous) => format!("{previous}; {LIMIT_TOTAL}"),
                    None => format!("{}: {LIMIT_TOTAL}", run.name),
                });
            }
            total = total.saturating_add(run.entries.len() as u64);
            let rules = run.entries.len();
            // Consume the list's entries here so its buffer is freed before the
            // next list is moved: only one copy of the rules is live at a time.
            for (hash, flags) in std::mem::take(&mut run.entries) {
                builder.add_parsed(hash, flags, run.id);
            }
            statuses.push(SourceStatus {
                id: run.id,
                name: run.name,
                rules,
                skipped: run.skipped,
                last_success: run.last_success,
                last_error: run.last_error,
                used_cache: run.used_cache,
            });
        }
        RefreshOutcome { rules: builder.finish(self.sources()), statuses, retry_soon }
    }

    fn sources(&self) -> Arc<[RuleSource]> {
        let mut sources = Vec::with_capacity(self.urls.len().min(MAX_LISTS) + 1);
        sources.push(RuleSource { id: 0, name: "user rules".to_string() });
        for (index, url) in self.urls.iter().take(MAX_LISTS).enumerate() {
            sources.push(RuleSource { id: list_id(index), name: display_name(url) });
        }
        Arc::from(sources)
    }

    /// Finds the source lines that define any of `wanted` (lowercase parent
    /// domains), for the rules page. The matcher keeps hashes only, so this
    /// re-reads the inline rules and each list's cached body on demand. It is
    /// bounded: `SCAN_BYTES` read in total, `SCAN_TIME` of wall clock, at
    /// most `SCAN_HITS` lines, one scan at a time. `complete` is false when a
    /// bound, an unreadable file or another running scan cut it short. The
    /// body is the cached copy, which may be newer than the loaded table.
    pub fn find_rules(&self, wanted: &HashSet<String>) -> SourceScan {
        static BUSY: AtomicBool = AtomicBool::new(false);
        let mut scan = SourceScan { hits: Vec::new(), complete: false };
        if BUSY.swap(true, Ordering::Acquire) {
            return scan;
        }
        // The files are read on the caller's thread; tell the runtime so the
        // other tasks on this worker move away instead of waiting.
        match tokio::runtime::Handle::try_current().map(|handle| handle.runtime_flavor()) {
            Ok(tokio::runtime::RuntimeFlavor::MultiThread) => {
                tokio::task::block_in_place(|| self.scan_into(wanted, &mut scan));
            }
            _ => self.scan_into(wanted, &mut scan),
        }
        BUSY.store(false, Ordering::Release);
        scan
    }

    fn scan_into(&self, wanted: &HashSet<String>, scan: &mut SourceScan) {
        let deadline = Instant::now() + SCAN_TIME;
        let mut budget = SCAN_BYTES;
        let check = |scan: &mut SourceScan, list_id: u16, line_no: usize, text: &str| {
            if let Ok(Some((parent, flags))) = rules::parse_rule(text) {
                if wanted.contains(&parent) && scan.hits.len() < SCAN_HITS {
                    let text = text.trim().chars().take(SCAN_LINE_CHARS).collect();
                    scan.hits.push(RuleHit { list_id, line: line_no, text, parent, flags });
                }
            }
            scan.hits.len() < SCAN_HITS
        };
        for (index, text) in self.user_rules.iter().enumerate() {
            check(scan, 0, index + 1, text);
        }
        for (index, url) in self.urls.iter().take(MAX_LISTS).enumerate() {
            let Ok(file) = open_regular(&self.cache_paths(url).0) else { continue };
            let mut reader = BufReader::new(file);
            let mut line = Vec::new();
            for line_no in 1.. {
                line.clear();
                let read = (&mut reader).take(MAX_LINE_BYTES as u64 + 1).read_until(b'\n', &mut line);
                match read {
                    Ok(0) => break,
                    Ok(n) if n > MAX_LINE_BYTES || n as u64 > budget || Instant::now() > deadline => return,
                    Ok(n) => budget -= n as u64,
                    Err(_) => return,
                }
                if let Ok(text) = std::str::from_utf8(&line) {
                    if !check(scan, list_id(index), line_no, text) {
                        return;
                    }
                }
            }
        }
        scan.complete = true;
    }

    fn cache_paths(&self, url: &str) -> (PathBuf, PathBuf) {
        let hash = format!("{:016x}", fnv1a(url.as_bytes()));
        (self.lists_dir.join(format!("{hash}.list")), self.lists_dir.join(format!("{hash}.meta")))
    }

    /// Removes temp files a crash or kill left behind: those `temp_path`
    /// makes for a cached body or metadata file in the lists folder, and for
    /// the pre-warm list and the stats snapshot in `state_dir`. Anything else
    /// kept there is left alone. Call it at startup, before anything writes
    /// its own temp files.
    pub fn sweep_temp_files(&self) {
        remove_files_named(&self.lists_dir, |name| temp_target(name).is_some_and(is_cache_name));
        remove_files_named(&self.state_dir, |name| {
            temp_target(name).is_some_and(|target| STATE_FILES.contains(&target))
        });
    }

    /// Deletes the cached body and metadata of every list whose URL is no
    /// longer configured, so a removed list does not stay on disk for good.
    /// Only cache names in the lists folder are touched. Call it at startup and
    /// after a reload that changed the lists.
    pub fn remove_unconfigured_lists(&self) {
        let configured: HashSet<String> =
            self.urls.iter().map(|url| format!("{:016x}", fnv1a(url.as_bytes()))).collect();
        remove_files_named(&self.lists_dir, |name| {
            is_cache_name(name) && name.split_once('.').is_some_and(|(hash, _)| !configured.contains(hash))
        });
    }

    fn ensure_dirs(&self) -> std::io::Result<()> {
        create_private_dir(&self.state_dir)?;
        create_private_dir(&self.lists_dir)
    }
}

fn list_id(index: usize) -> u16 {
    u16::try_from(index + 1).unwrap_or(u16::MAX)
}

/// Stable across restarts: never the per-process seeded rules hasher.
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// The origin plus a trailing file name when there is one. Never userinfo,
/// intermediate path segments, query or fragment.
fn display_name(url: &str) -> String {
    crate::log::list_display_name(url).unwrap_or_else(|| "invalid list URL".to_string())
}

pub(crate) fn create_private_dir(path: &Path) -> std::io::Result<()> {
    // Only directories this process creates get 0700. An existing state_dir may
    // be a cluster-managed volume owned by another uid: writable, but chmod
    // fails with EPERM and must not stop the cache from working.
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.recursive(true).create(path)
}

fn open_private(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

/// Opens a state file for reading. Anything but a regular file is refused,
/// and on Linux and macOS the open itself never waits: `O_NONBLOCK` makes
/// opening a FIFO return at once (it has no effect on a regular file), so a
/// FIFO planted in state_dir cannot hang startup.
pub(crate) fn open_regular(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "not a regular file"));
    }
    Ok(file)
}

/// Removes a temp file when dropped.
struct RemoveOnDrop(PathBuf);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn temp_path(path: &Path) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let name = path.file_name().and_then(|name| name.to_str()).unwrap_or("list");
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    path.with_file_name(format!(".{name}.{}.{counter}.tmp", std::process::id()))
}

/// The files in `state_dir` itself that are written with [`atomic_write`]:
/// the pre-warm list and the stats snapshot.
const STATE_FILES: &[&str] = &["prewarm.txt", "stats.v1"];

/// The file a [`temp_path`] name (`.{file}.{pid}.{counter}.tmp`) stands for.
fn temp_target(name: &str) -> Option<&str> {
    let inner = name.strip_prefix('.')?.strip_suffix(".tmp")?;
    let (rest, counter) = inner.rsplit_once('.')?;
    let (target, pid) = rest.rsplit_once('.')?;
    let digits = |part: &str| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit());
    (digits(pid) && digits(counter)).then_some(target)
}

/// `{16 hex}.{list|meta}`, as [`ListManager::cache_paths`] names a cache file.
fn is_cache_name(name: &str) -> bool {
    matches!(name.split_once('.'), Some((hash, "list" | "meta"))
        if hash.len() == 16 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

/// Removes the regular files directly in `dir` whose name passes `ours`.
fn remove_files_named(dir: &Path, ours: impl Fn(&str) -> bool) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let matched = entry.file_name().to_str().is_some_and(&ours);
        if matched && entry.file_type().is_ok_and(|kind| kind.is_file()) {
            let _ = fs::remove_file(entry.path());
        }
    }
}

pub(crate) fn atomic_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let temp = temp_path(path);
    let _ = fs::remove_file(&temp);
    let mut file = open_private(&temp)?;
    // Sync before the rename so a power loss leaves the old file or the new
    // one, never an empty one.
    let written = file.write_all(bytes).and_then(|()| file.flush()).and_then(|()| file.sync_all());
    drop(file);
    if let Err(error) = written {
        let _ = fs::remove_file(&temp);
        return Err(error);
    }
    if let Err(error) = fs::rename(&temp, path) {
        let _ = fs::remove_file(&temp);
        return Err(error);
    }
    Ok(())
}

fn read_meta(path: &Path) -> Meta {
    let mut text = String::new();
    if open_regular(path).and_then(|mut file| file.read_to_string(&mut text)).is_err() {
        return Meta::default();
    }
    let mut meta = Meta::default();
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        match key.trim() {
            "etag" => meta.etag = Some(value.to_string()),
            "last_modified" => meta.last_modified = Some(value.to_string()),
            "last_success" => meta.last_success = value.parse().ok(),
            "rules" => meta.rules = value.parse().ok(),
            "refused" => meta.refused = value.parse().ok(),
            "refused_at" => meta.refused_at = value.parse().ok(),
            _ => {}
        }
    }
    meta
}

fn write_meta(path: &Path, meta: &Meta) -> std::io::Result<()> {
    let mut text = String::new();
    if let Some(etag) = &meta.etag {
        text.push_str("etag=");
        text.push_str(&clean_header(etag));
        text.push('\n');
    }
    if let Some(modified) = &meta.last_modified {
        text.push_str("last_modified=");
        text.push_str(&clean_header(modified));
        text.push('\n');
    }
    if let Some(success) = meta.last_success {
        text.push_str(&format!("last_success={success}\n"));
    }
    if let Some(rules) = meta.rules {
        text.push_str(&format!("rules={rules}\n"));
    }
    if let Some(refused) = meta.refused {
        text.push_str(&format!("refused={refused}\n"));
    }
    if let Some(refused_at) = meta.refused_at {
        text.push_str(&format!("refused_at={refused_at}\n"));
    }
    atomic_write(path, text.as_bytes())
}

/// Server-supplied header text must not be able to break the line format.
fn clean_header(value: &str) -> String {
    value.chars().filter(|character| !character.is_control()).collect()
}

fn header_text(response: &reqwest::Response, name: HeaderName) -> Option<String> {
    response.headers().get(name)?.to_str().ok().map(clean_header)
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |duration| duration.as_secs())
}

/// A short, URL-free description for status and logs.
fn describe(error: &reqwest::Error) -> String {
    if error.is_timeout() {
        "download timed out".to_string()
    } else if error.is_connect() {
        "connection failed".to_string()
    } else if let Some(status) = error.status() {
        format!("HTTP {status}")
    } else {
        "request failed".to_string()
    }
}

fn apply(run: &mut ListRun, mut parser: ListParser<'_>) {
    run.entries = std::mem::take(&mut parser.entries);
    // Drop the doubling slack: every list's run waits here until assembly.
    run.entries.shrink_to_fit();
    run.skipped = parser.skipped;
    if let Some(error) = parser.error.take() {
        run.last_error = Some(match run.last_error.take() {
            Some(previous) => format!("{previous}; {error}"),
            None => error,
        });
    }
}

/// Parses a whole cached list body. This is hundreds of milliseconds of CPU
/// for a large list, so on the multi-thread runtime it runs under
/// `block_in_place`: the worker's other tasks (the UDP receive loops among
/// them) move to another thread instead of stalling behind the parse. The
/// current-thread runtime (tests) cannot do that and parses inline.
fn parse_file(file: File, parser: &mut ListParser<'_>) {
    off_worker(|| parse_reader(file, parser));
}

/// Runs blocking file work or CPU parsing of a downloaded chunk so it cannot
/// stall the async worker: `block_in_place` on the multi-thread runtime, inline
/// on the current-thread runtime (tests), which cannot hand the worker off.
fn off_worker<R>(work: impl FnOnce() -> R) -> R {
    let multi = tokio::runtime::Handle::try_current()
        .is_ok_and(|handle| handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread);
    if multi {
        tokio::task::block_in_place(work)
    } else {
        work()
    }
}

/// Best-effort unlink of a (possibly large) temp file, off the async worker.
fn discard(path: &Path) {
    off_worker(|| {
        let _ = fs::remove_file(path);
    });
}

fn parse_reader(file: File, parser: &mut ListParser<'_>) {
    let mut reader = BufReader::new(file);
    let mut buffer = [0u8; 8192];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                parser.feed(&buffer[..count]);
                if parser.stopped {
                    break;
                }
            }
            Err(error) => {
                parser.stop(&format!("cache read failed: {error}"));
                break;
            }
        }
    }
    if !parser.stopped {
        parser.finish();
    }
}

/// Streaming byte-line parser with per-list byte, line and rule quotas.
///
/// Invalid UTF-8, unsupported lines and lines longer than 64 KiB increment
/// `skipped`; they never reject the list. Exceeding the byte or line budget,
/// or its rule quota, stops the list and records an error, keeping what was
/// parsed so far.
struct ListParser<'a> {
    hasher: &'a RandomState,
    quota: u64,
    entries: Vec<(u64, u8)>,
    skipped: u64,
    bytes: u64,
    /// Bytes up to the end of the last line handled before a stop.
    kept: u64,
    lines: u64,
    max_bytes: u64,
    max_lines: u64,
    line: Vec<u8>,
    oversized: bool,
    error: Option<String>,
    stopped: bool,
}

impl<'a> ListParser<'a> {
    fn new(hasher: &'a RandomState, max_bytes: u64, max_lines: u64, quota: u64) -> Self {
        observed::LIMIT_BYTES.store(max_bytes, std::sync::atomic::Ordering::SeqCst);
        Self {
            hasher,
            quota,
            entries: Vec::new(),
            skipped: 0,
            bytes: 0,
            kept: 0,
            lines: 0,
            max_bytes,
            max_lines,
            line: Vec::new(),
            oversized: false,
            error: None,
            stopped: false,
        }
    }

    fn feed(&mut self, chunk: &[u8]) {
        if self.stopped || chunk.is_empty() {
            return;
        }
        if self.bytes.saturating_add(chunk.len() as u64) > self.max_bytes {
            self.stop("list exceeds blocklist_max_bytes");
            return;
        }
        let start = self.bytes;
        self.bytes += chunk.len() as u64;
        let mut rest = chunk;
        while let Some(position) = rest.iter().position(|&byte| byte == b'\n') {
            self.push(&rest[..position]);
            rest = &rest[position + 1..];
            self.end_line();
            if self.stopped {
                return;
            }
            self.kept = start + (chunk.len() - rest.len()) as u64;
        }
        self.push(rest);
        self.observe_buffers();
    }

    fn push(&mut self, part: &[u8]) {
        if self.oversized {
            return;
        }
        if self.line.len().saturating_add(part.len()) > MAX_LINE_BYTES {
            self.oversized = true;
            self.line.clear();
        } else {
            self.line.extend_from_slice(part);
        }
    }

    fn end_line(&mut self) {
        if self.stopped {
            return;
        }
        self.lines += 1;
        if self.lines > self.max_lines {
            self.stop("list exceeds blocklist_max_lines");
            return;
        }
        if self.oversized {
            self.oversized = false;
            self.skipped += 1;
            self.line.clear();
            return;
        }
        match std::str::from_utf8(&self.line) {
            Ok(text) => match rules::parse_line(self.hasher, text) {
                Some(rule) => {
                    if self.entries.len() as u64 >= self.quota {
                        self.stop(LIMIT_TOTAL);
                        return;
                    }
                    self.entries.push(rule);
                }
                None => self.skipped += 1,
            },
            Err(_) => self.skipped += 1,
        }
        self.line.clear();
    }

    fn finish(&mut self) {
        if !self.stopped && (!self.line.is_empty() || self.oversized) {
            self.end_line();
        }
    }

    fn stop(&mut self, message: &str) {
        if self.error.is_none() {
            observed::REJECTED_OVERSIZE.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.error = Some(message.to_string());
        }
        self.stopped = true;
        self.line.clear();
        self.oversized = false;
    }
}

/// Observation of the streaming parser, reported in `/metrics`: lists stopped
/// by a size bound and the largest live parse buffers seen.
pub mod observed {
    use std::sync::atomic::{AtomicU64, Ordering};

    pub static REJECTED_OVERSIZE: AtomicU64 = AtomicU64::new(0);
    pub static PEAK_BYTES: AtomicU64 = AtomicU64::new(0);
    pub static LIMIT_BYTES: AtomicU64 = AtomicU64::new(0);

    impl super::ListParser<'_> {
        /// Capacity held for the pending line and the parsed rules.
        pub(super) fn observe_buffers(&self) {
            let held = self.line.capacity() + self.entries.capacity() * std::mem::size_of::<(u64, u8)>();
            PEAK_BYTES.fetch_max(held as u64, Ordering::SeqCst);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::HashMap, net::SocketAddr, sync::Mutex};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        task::JoinHandle,
    };

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "sopedu-dns-lists-{}-{}-{tag}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[derive(Clone, Debug)]
    struct Request {
        path: String,
        headers: HashMap<String, String>,
    }

    #[derive(Clone)]
    struct Reply {
        status: &'static str,
        headers: Vec<(&'static str, String)>,
        body: Vec<u8>,
        split: bool,
        declared_length: Option<usize>,
    }

    impl Reply {
        fn ok(body: impl Into<Vec<u8>>) -> Self {
            Self { status: "200 OK", headers: Vec::new(), body: body.into(), split: false, declared_length: None }
        }

        fn status(status: &'static str) -> Self {
            Self { status, headers: Vec::new(), body: Vec::new(), split: false, declared_length: None }
        }

        fn status_with_body(status: &'static str, body: impl Into<Vec<u8>>) -> Self {
            Self { body: body.into(), ..Self::status(status) }
        }

        fn header(mut self, key: &'static str, value: impl Into<String>) -> Self {
            self.headers.push((key, value.into()));
            self
        }

        /// Send the body in two writes with a pause, so the client sees two chunks.
        fn split(mut self) -> Self {
            self.split = true;
            self
        }

        /// Announce more bytes than are sent, then close early.
        fn declared_length(mut self, length: usize) -> Self {
            self.declared_length = Some(length);
            self
        }
    }

    struct MockServer {
        addr: SocketAddr,
        seen: Arc<Mutex<Vec<Request>>>,
        task: JoinHandle<()>,
    }

    impl MockServer {
        async fn start(handler: impl Fn(&Request) -> Reply + Send + Sync + 'static) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let seen = Arc::new(Mutex::new(Vec::new()));
            let handler = Arc::new(handler);
            let recorder = seen.clone();
            let task = tokio::spawn(async move {
                while let Ok((mut stream, _)) = listener.accept().await {
                    let handler = handler.clone();
                    let recorder = recorder.clone();
                    tokio::spawn(async move {
                        let Ok(request) = read_request(&mut stream).await else {
                            return;
                        };
                        recorder.lock().unwrap().push(request.clone());
                        let reply = handler(&request);
                        let _ = write_reply(&mut stream, reply).await;
                    });
                }
            });
            Self { addr, seen, task }
        }

        fn url(&self, path: &str) -> String {
            format!("http://{}{path}", self.addr)
        }

        fn requests(&self) -> Vec<Request> {
            self.seen.lock().unwrap().clone()
        }
    }

    impl Drop for MockServer {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn read_request(stream: &mut TcpStream) -> std::io::Result<Request> {
        let mut buffer = Vec::new();
        let mut byte = [0u8; 1];
        while !buffer.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).await?;
            buffer.push(byte[0]);
            if buffer.len() > 64 * 1024 {
                break;
            }
        }
        let text = String::from_utf8_lossy(&buffer);
        let mut lines = text.split("\r\n");
        let path = lines.next().and_then(|line| line.split_whitespace().nth(1)).unwrap_or("").to_string();
        let mut headers = HashMap::new();
        for line in lines {
            if let Some((key, value)) = line.split_once(':') {
                headers.insert(key.trim().to_ascii_lowercase(), value.trim().to_string());
            }
        }
        Ok(Request { path, headers })
    }

    async fn write_reply(stream: &mut TcpStream, reply: Reply) -> std::io::Result<()> {
        let length = reply.declared_length.unwrap_or(reply.body.len());
        let mut head = format!("HTTP/1.1 {}\r\nConnection: close\r\nContent-Length: {length}\r\n", reply.status);
        for (key, value) in reply.headers {
            head.push_str(&format!("{key}: {value}\r\n"));
        }
        head.push_str("\r\n");
        stream.write_all(head.as_bytes()).await?;
        if reply.split && reply.body.len() > 1 {
            let half = reply.body.len() / 2;
            stream.write_all(&reply.body[..half]).await?;
            stream.flush().await?;
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            stream.write_all(&reply.body[half..]).await?;
        } else {
            stream.write_all(&reply.body).await?;
        }
        stream.shutdown().await
    }

    fn test_config(dir: &Path, urls: Vec<String>) -> Config {
        Config {
            blocklists: urls,
            state_dir: dir.to_path_buf(),
            upstreams: Vec::new(),
            fallback: Vec::new(),
            user_rules: Vec::new(),
            ..Config::default()
        }
    }

    fn test_manager(config: &Config) -> ListManager {
        ListManager::new(client_builder().build().unwrap(), config)
    }

    #[test]
    fn display_name_never_leaks_credentials_or_query() {
        assert_eq!(
            display_name("https://user:secret@example.com:8443/lists/ad.txt?token=private#fragment"),
            "https://example.com:8443/ad.txt"
        );
        assert_eq!(display_name("https://example.com/ad.txt?token=private"), "https://example.com/ad.txt");
        // A path token without a file extension is dropped entirely.
        assert_eq!(display_name("https://example.com/lists/abc123token"), "https://example.com");
        // Only a known list extension keeps the segment: a dotted token does not.
        assert_eq!(display_name("https://example.com/k/eyJhbGciOi.eyJzdWIi.c2lnbmF0dXJl"), "https://example.com");
        assert_eq!(display_name("https://example.com/secret.v2"), "https://example.com");
        for file in ["filter_1.txt", "pro.hosts", "dns.list", "ad.rules", "x.conf", "geo.dat", "A.TXT"] {
            assert_eq!(display_name(&format!("https://example.com/t/{file}")), format!("https://example.com/{file}"));
        }
        assert_eq!(display_name("not a url"), "invalid list URL");
        assert_eq!(display_name("file:///tmp/list.txt"), "invalid list URL");
        let shown = display_name("https://token@example.com/list.txt?token=private");
        assert!(!shown.contains("token"));
        assert!(!shown.contains("private"));
    }

    #[test]
    fn cache_hash_is_stable() {
        assert_eq!(fnv1a(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a(b"a"), 0xaf63_dc4c_8601_ec8c);
    }

    #[tokio::test]
    async fn etag_and_modified_since_turn_into_304() {
        let dir = TempDir::new("etag");
        let body = b"||ads.test^\n@@||ok.ads.test^\n".to_vec();
        let server = MockServer::start(move |request| {
            let conditional = request.headers.get("if-none-match").map(String::as_str) == Some("\"v1\"")
                && request.headers.contains_key("if-modified-since");
            if conditional {
                Reply::status("304 Not Modified")
            } else {
                Reply::ok(body.clone())
                    .header("ETag", "\"v1\"")
                    .header("Last-Modified", "Wed, 01 Jan 2025 00:00:00 GMT")
            }
        })
        .await;
        let config = test_config(&dir.0, vec![server.url("/list.txt")]);
        let manager = test_manager(&config);

        let first = manager.refresh().await.unwrap();
        assert!(first.rules.blocked("x.ads.test"));
        assert!(!first.rules.blocked("ok.ads.test"));
        assert_eq!(first.statuses[0].rules, 2);
        assert_eq!(first.statuses[0].skipped, 0);
        assert!(!first.statuses[0].used_cache);
        assert!(first.statuses[0].last_error.is_none());
        assert!(first.statuses[0].last_success.is_some());

        let second = manager.refresh().await.unwrap();
        assert!(second.rules.blocked("x.ads.test"));
        assert_eq!(second.statuses[0].rules, 2);
        assert!(second.statuses[0].used_cache);
        assert!(second.statuses[0].last_error.is_none());

        let requests = server.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[1].headers.get("if-none-match").map(String::as_str), Some("\"v1\""));
        assert_eq!(
            requests[1].headers.get("if-modified-since").map(String::as_str),
            Some("Wed, 01 Jan 2025 00:00:00 GMT")
        );
    }

    #[tokio::test]
    async fn refresh_publishes_the_same_counts_through_the_blocking_assembly() {
        let dir = TempDir::new("blocking-assembly");
        let server = MockServer::start(|_| Reply::ok("||blocked.test^\n@@||allowed.blocked.test^\n")).await;
        let mut config = test_config(&dir.0, vec![server.url("/list.txt")]);
        config.user_rules = vec!["||inline.test^".into()];
        let outcome = test_manager(&config).refresh().await.unwrap();

        assert_eq!(outcome.rules.len(), 3);
        assert_eq!(outcome.statuses.len(), 1);
        let status = &outcome.statuses[0];
        assert_eq!((status.id, status.rules, status.skipped), (1, 2, 0));
        assert!(!status.used_cache);
        assert!(status.last_error.is_none());
        assert!(status.last_success.is_some());
        assert!(outcome.rules.blocked("x.blocked.test"));
        assert!(outcome.rules.blocked("inline.test"));
        assert!(!outcome.rules.blocked("x.allowed.blocked.test"));
    }

    #[tokio::test]
    async fn server_error_falls_back_to_cached_copy() {
        let dir = TempDir::new("error-cache");
        let failing = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let server = MockServer::start({
            let failing = failing.clone();
            move |_| {
                if failing.load(Ordering::Relaxed) {
                    Reply::status("500 Internal Server Error")
                } else {
                    Reply::ok("||cached.test^\n")
                }
            }
        })
        .await;
        let config = test_config(&dir.0, vec![server.url("/list.txt")]);
        let manager = test_manager(&config);

        let first = manager.refresh().await.unwrap();
        let success = first.statuses[0].last_success;
        assert!(success.is_some());
        failing.store(true, Ordering::Relaxed);

        let second = manager.refresh().await.unwrap();
        assert!(second.rules.blocked("x.cached.test"));
        let status = &second.statuses[0];
        assert!(status.used_cache);
        assert_eq!(status.rules, 1);
        assert!(status.last_error.as_deref().unwrap().contains("500"));
        assert_eq!(status.last_success, success);
    }

    #[tokio::test]
    async fn conditional_requests_require_a_cached_body() {
        let dir = TempDir::new("no-body");
        let server = MockServer::start(|request| {
            let conditional =
                request.headers.contains_key("if-none-match") || request.headers.contains_key("if-modified-since");
            if conditional {
                Reply::status("304 Not Modified")
            } else {
                Reply::ok("||fresh.test^\n")
                    .header("ETag", "\"v1\"")
                    .header("Last-Modified", "Wed, 01 Jan 2025 00:00:00 GMT")
            }
        })
        .await;
        let url = server.url("/list.txt");
        let manager = test_manager(&test_config(&dir.0, vec![url.clone()]));
        manager.refresh().await.unwrap();
        let (body, meta) = manager.cache_paths(&url);
        fs::remove_file(&body).unwrap();
        assert!(meta.exists());

        let outcome = manager.refresh().await.unwrap();
        assert!(outcome.rules.blocked("x.fresh.test"));
        assert!(outcome.statuses[0].last_error.is_none());
        assert!(body.exists());
        let requests = server.requests();
        assert_eq!(requests.len(), 2);
        assert!(!requests[1].headers.contains_key("if-none-match"));
        assert!(!requests[1].headers.contains_key("if-modified-since"));
    }

    #[tokio::test]
    async fn unsolicited_304_without_a_body_is_not_a_success() {
        let dir = TempDir::new("304-missing");
        let server = MockServer::start(|_| Reply::status("304 Not Modified")).await;
        let url = server.url("/list.txt");
        let mut config = test_config(&dir.0, vec![url.clone()]);
        config.user_rules = vec!["||inline.test^".into()];
        let manager = test_manager(&config);
        let (_, meta_path) = manager.cache_paths(&url);
        fs::create_dir_all(&manager.lists_dir).unwrap();
        write_meta(
            &meta_path,
            &Meta {
                etag: Some("\"old\"".into()),
                last_modified: None,
                last_success: Some(1),
                rules: None,
                refused: None,
                refused_at: None,
            },
        )
        .unwrap();

        let outcome = manager.refresh().await.unwrap();
        let status = &outcome.statuses[0];
        assert_eq!(status.last_success, Some(1));
        assert!(!status.used_cache);
        assert!(status.last_error.as_deref().unwrap().contains("304"));
        let meta = read_meta(&meta_path);
        assert!(meta.etag.is_none());
        assert_eq!(meta.last_success, Some(1));
        assert!(outcome.rules.blocked("inline.test"));
        assert!(!server.requests()[0].headers.contains_key("if-none-match"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unreadable_cached_body_is_not_a_304_success() {
        let dir = TempDir::new("304-unreadable");
        let server = MockServer::start(|request| {
            if request.headers.contains_key("if-none-match") {
                Reply::status("304 Not Modified")
            } else {
                Reply::ok("||cached.test^\n").header("ETag", "\"v1\"")
            }
        })
        .await;
        let url = server.url("/list.txt");
        let mut config = test_config(&dir.0, vec![url.clone()]);
        config.user_rules = vec!["||inline.test^".into()];
        let manager = test_manager(&config);
        let first = manager.refresh().await.unwrap();
        let success = first.statuses[0].last_success;
        let (body, meta_path) = manager.cache_paths(&url);
        fs::remove_file(&body).unwrap();
        fs::create_dir(&body).unwrap();

        let outcome = manager.refresh().await.unwrap();
        let status = &outcome.statuses[0];
        assert_eq!(status.last_success, success);
        assert!(!status.used_cache);
        assert!(status.last_error.as_deref().unwrap().contains("cache read failed"));
        assert!(read_meta(&meta_path).etag.is_none());
    }

    #[tokio::test]
    async fn only_a_200_with_rules_replaces_the_cached_copy() {
        let dir = TempDir::new("only-200");
        let phase = Arc::new(AtomicU64::new(0));
        let server = MockServer::start({
            let phase = phase.clone();
            move |_| match phase.load(Ordering::Relaxed) {
                0 => Reply::ok("||cached.test^\n").header("ETag", "\"v1\""),
                1 => Reply::status("204 No Content"),
                2 => Reply::status_with_body("206 Partial Content", "||partial.test^\n"),
                _ => Reply::ok("<html><body>not a list</body></html>"),
            }
        })
        .await;
        let url = server.url("/list.txt");
        let manager = test_manager(&test_config(&dir.0, vec![url.clone()]));
        manager.refresh().await.unwrap();

        for (number, expected) in [(1, "HTTP 204"), (2, "HTTP 206"), (3, "list contains no rules")] {
            phase.store(number, Ordering::Relaxed);
            let outcome = manager.refresh().await.unwrap();
            assert!(outcome.rules.blocked("x.cached.test"), "phase {number}");
            assert!(!outcome.rules.blocked("x.partial.test"), "phase {number}");
            let status = &outcome.statuses[0];
            assert_eq!(status.rules, 1, "phase {number}");
            assert!(status.used_cache, "phase {number}");
            assert!(status.last_error.as_deref().unwrap().contains(expected), "{:?}", status.last_error);
        }
        let boot = test_manager(&test_config(&dir.0, vec![url])).load_cached();
        assert!(boot.rules.blocked("x.cached.test"));
        assert!(!boot.rules.blocked("x.partial.test"));
    }

    #[tokio::test]
    async fn byte_budget_counts_across_stream_chunks() {
        let dir = TempDir::new("cross-chunk");
        let server = MockServer::start(|_| Reply::ok("||a.test^\n||b.test^\n").split()).await;
        let mut config = test_config(&dir.0, vec![server.url("/list.txt")]);
        config.blocklist_max_bytes = 12;
        let outcome = test_manager(&config).refresh().await.unwrap();

        assert!(outcome.rules.blocked("x.a.test"));
        assert!(!outcome.rules.blocked("x.b.test"));
        assert_eq!(outcome.statuses[0].rules, 1);
        assert!(outcome.statuses[0].last_error.as_deref().unwrap().contains("blocklist_max_bytes"));
    }

    #[tokio::test]
    async fn interrupted_download_never_leaks_the_query_token() {
        let dir = TempDir::new("interrupted");
        let server = MockServer::start(|_| Reply::ok("||partial.test^\n").declared_length(4096)).await;
        let url = server.url("/list.txt?token=supersecret");
        let mut config = test_config(&dir.0, vec![url.clone()]);
        config.user_rules = vec!["||inline.test^".into()];
        let manager = test_manager(&config);
        let outcome = manager.refresh().await.unwrap();
        let status = &outcome.statuses[0];
        assert_eq!(status.rules, 0);
        assert!(!status.used_cache);
        let error = status.last_error.as_deref().unwrap();
        assert!(error.contains("download interrupted"), "{error}");
        assert!(!error.contains("supersecret"), "{error}");
        assert!(!status.name.contains("supersecret"));
        assert!(!manager.cache_paths(&url).0.exists(), "an interrupted body must not be cached");
        assert!(outcome.rules.blocked("inline.test"));
    }

    #[tokio::test]
    async fn redirects_follow_five_hops_and_stop_the_sixth() {
        let dir = TempDir::new("redirect-hops");
        let server = MockServer::start(|request| {
            let path = request.path.as_str();
            if let Some(hop) = path.strip_prefix("/five/").and_then(|hop| hop.parse::<u32>().ok()) {
                return if hop < 5 {
                    Reply::status("302 Found").header("Location", format!("/five/{}", hop + 1))
                } else {
                    Reply::ok("||five.test^\n")
                };
            }
            if let Some(hop) = path.strip_prefix("/six/").and_then(|hop| hop.parse::<u32>().ok()) {
                return if hop < 6 {
                    Reply::status("302 Found").header("Location", format!("/six/{}", hop + 1))
                } else {
                    Reply::ok("||six.test^\n")
                };
            }
            Reply::status("404 Not Found")
        })
        .await;
        // Redirect targets may not be loopback literals or `localhost`, so
        // reach the mock by a public-looking name pinned to its address.
        let base = format!("http://hops.example:{}", server.addr.port());
        let config = test_config(&dir.0, vec![format!("{base}/five/0"), format!("{base}/six/0")]);
        let http = client_builder().resolve("hops.example", server.addr).build().unwrap();
        let outcome = ListManager::new(http, &config).refresh().await.unwrap();
        assert!(outcome.rules.blocked("x.five.test"));
        assert!(!outcome.rules.blocked("x.six.test"));
        assert!(outcome.statuses[0].last_error.is_none());
        assert!(outcome.statuses[1].last_error.as_deref().unwrap().contains("302"));
        let paths: Vec<String> = server.requests().into_iter().map(|request| request.path).collect();
        assert!(paths.contains(&"/five/5".to_string()));
        assert!(paths.contains(&"/six/5".to_string()));
        assert!(!paths.contains(&"/six/6".to_string()));
    }

    #[tokio::test]
    async fn one_failed_list_does_not_abort_the_refresh() {
        let dir = TempDir::new("partial");
        let server = MockServer::start(|request| match request.path.as_str() {
            "/good.txt" => Reply::ok("||good.test^\n"),
            _ => Reply::status("500 Internal Server Error"),
        })
        .await;
        let config = test_config(&dir.0, vec![server.url("/bad.txt"), server.url("/good.txt")]);
        let manager = test_manager(&config);

        let outcome = manager.refresh().await.unwrap();
        assert!(outcome.rules.blocked("x.good.test"));
        assert_eq!(outcome.statuses.len(), 2);
        assert_eq!(outcome.statuses[0].id, 1);
        assert_eq!(outcome.statuses[0].rules, 0);
        assert!(outcome.statuses[0].last_error.is_some());
        assert!(!outcome.statuses[0].used_cache);
        assert_eq!(outcome.statuses[1].id, 2);
        assert_eq!(outcome.statuses[1].rules, 1);
        assert!(outcome.statuses[1].last_error.is_none());
    }

    #[tokio::test]
    async fn only_no_lists_and_no_user_rules_is_an_error() {
        let dir = TempDir::new("nothing");
        let server = MockServer::start(|_| Reply::status("500 Internal Server Error")).await;
        let config = test_config(&dir.0, vec![server.url("/down.txt")]);
        let manager = test_manager(&config);
        assert!(manager.refresh().await.is_err());

        let mut with_user = test_config(&dir.0, vec![server.url("/down.txt")]);
        with_user.user_rules = vec!["||inline.test^".into()];
        let manager = test_manager(&with_user);
        let outcome = manager.refresh().await.unwrap();
        assert!(outcome.rules.blocked("inline.test"));
    }

    #[tokio::test]
    async fn invalid_utf8_is_skipped_and_the_rest_loads() {
        let dir = TempDir::new("utf8");
        let mut body = b"||first.test^\n".to_vec();
        body.extend_from_slice(&[0xff, 0xfe, b'\n']);
        body.extend_from_slice(b"||second.test^\n");
        let server = MockServer::start(move |_| Reply::ok(body.clone())).await;
        let manager = test_manager(&test_config(&dir.0, vec![server.url("/list.txt")]));

        let outcome = manager.refresh().await.unwrap();
        assert!(outcome.rules.blocked("first.test"));
        assert!(outcome.rules.blocked("second.test"));
        assert_eq!(outcome.statuses[0].rules, 2);
        assert_eq!(outcome.statuses[0].skipped, 1);
        assert!(outcome.statuses[0].last_error.is_none());
    }

    #[tokio::test]
    async fn oversized_line_is_skipped_and_the_list_continues() {
        let dir = TempDir::new("long-line");
        let body = format!("{}\n||after.test^\n", "a".repeat(70 * 1024)).into_bytes();
        let server = MockServer::start(move |_| Reply::ok(body.clone())).await;
        let manager = test_manager(&test_config(&dir.0, vec![server.url("/list.txt")]));

        let outcome = manager.refresh().await.unwrap();
        assert!(outcome.rules.blocked("x.after.test"));
        assert_eq!(outcome.statuses[0].rules, 1);
        assert_eq!(outcome.statuses[0].skipped, 1);
        assert!(outcome.statuses[0].last_error.is_none());
    }

    #[tokio::test]
    async fn line_and_byte_budgets_stop_the_list_with_an_error() {
        let dir = TempDir::new("budgets");
        let server = MockServer::start(|_| Reply::ok("||a.test^\n||b.test^\n||c.test^\n||d.test^\n||e.test^\n")).await;

        let mut lines = test_config(&dir.0, vec![server.url("/lines.txt")]);
        lines.blocklist_max_lines = 2;
        let outcome = test_manager(&lines).refresh().await.unwrap();
        assert_eq!(outcome.statuses[0].rules, 2);
        assert!(outcome.statuses[0].last_error.as_deref().unwrap().contains("blocklist_max_lines"));

        let mut bytes = test_config(&dir.0, vec![server.url("/bytes.txt")]);
        bytes.blocklist_max_bytes = 10;
        let outcome = test_manager(&bytes).refresh().await.unwrap();
        assert_eq!(outcome.statuses[0].rules, 0);
        assert!(outcome.statuses[0].last_error.as_deref().unwrap().contains("blocklist_max_bytes"));
    }

    #[tokio::test]
    async fn total_rule_cap_is_split_by_list_in_order() {
        let server = MockServer::start(|request| {
            let list = request.path.trim_start_matches('/').trim_end_matches(".txt");
            Reply::ok(format!("||{list}1.test^\n||{list}2.test^\n||{list}3.test^\n"))
        })
        .await;
        let urls = ["a", "b", "c", "d"].map(|list| server.url(&format!("/{list}.txt"))).to_vec();
        for (cap, expected) in [(4, [1, 1, 1, 1]), (3, [1, 1, 1, 0]), (2, [1, 1, 0, 0])] {
            let dir = TempDir::new("total");
            let mut config = test_config(&dir.0, urls.clone());
            config.blocklist_max_rules_total = cap;
            let outcome = test_manager(&config).refresh().await.unwrap();

            let counts: Vec<usize> = outcome.statuses.iter().map(|status| status.rules).collect();
            assert_eq!(counts, expected, "cap {cap}");
            assert_eq!(outcome.rules.len(), cap as usize, "cap {cap}");
            // Each list keeps a prefix of length quota(i), independent of the
            // order in which the parallel downloads finish.
            for (index, list) in ["a", "b", "c", "d"].iter().enumerate() {
                assert_eq!(outcome.rules.blocked(&format!("x.{list}1.test")), expected[index] > 0, "cap {cap}");
            }
            assert!(outcome.statuses.iter().all(|status| {
                status.last_error.as_deref().is_some_and(|error| error.contains("blocklist_max_rules_total"))
            }));
        }
    }

    #[tokio::test]
    async fn cached_load_truncates_lists_in_order() {
        let dir = TempDir::new("boot-total");
        let server = MockServer::start(|request| {
            let list = request.path.trim_start_matches('/').trim_end_matches(".txt");
            Reply::ok(format!("||{list}1.test^\n||{list}2.test^\n"))
        })
        .await;
        let urls = vec![server.url("/a.txt"), server.url("/b.txt")];
        test_manager(&test_config(&dir.0, urls.clone())).refresh().await.unwrap();

        let mut capped = test_config(&dir.0, urls);
        capped.blocklist_max_rules_total = 2;
        let boot = test_manager(&capped).load_cached();
        assert_eq!(boot.rules.len(), 2);
        assert_eq!(boot.statuses[0].rules, 1);
        assert_eq!(boot.statuses[1].rules, 1);
        assert!(boot.rules.blocked("x.a1.test"));
        assert!(boot.rules.blocked("x.b1.test"));
        assert!(!boot.rules.blocked("x.a2.test"));
        assert!(!boot.rules.blocked("x.b2.test"));
        for status in &boot.statuses {
            assert!(status.last_error.as_deref().unwrap().contains("blocklist_max_rules_total"));
        }
    }

    #[tokio::test]
    async fn quota_truncation_on_304_keeps_validators() {
        let dir = TempDir::new("304-quota");
        let server = MockServer::start(|request| {
            if request.headers.contains_key("if-none-match") {
                Reply::status("304 Not Modified")
            } else {
                Reply::ok("||a.test^\n||b.test^\n").header("ETag", "\"v1\"")
            }
        })
        .await;
        let url = server.url("/list.txt");
        let mut config = test_config(&dir.0, vec![url.clone()]);
        test_manager(&config).refresh().await.unwrap();
        config.blocklist_max_rules_total = 1;
        let manager = test_manager(&config);

        let outcome = manager.refresh().await.unwrap();
        let status = &outcome.statuses[0];
        assert_eq!(status.rules, 1);
        assert!(status.used_cache);
        assert!(status.last_error.as_deref().unwrap().contains("blocklist_max_rules_total"));
        let (_, meta_path) = manager.cache_paths(&url);
        assert!(read_meta(&meta_path).etag.is_some(), "a quota stop must not clear the validators");
    }

    /// A list cut at its share of `blocklist_max_rules_total` still counts as
    /// loaded: the kept prefix (whole lines only) is cached without validators,
    /// so readiness holds, a restart during an outage loads it, and the next
    /// refresh downloads the list again instead of asking for a 304.
    #[tokio::test]
    async fn a_list_over_its_rule_share_is_cached_as_a_prefix() {
        let dir = TempDir::new("quota-cache");
        let server = MockServer::start(|_| {
            Reply::ok("||a1.test^\n||a2.test^\n||a3.test^\n||a4.test^\n").header("ETag", "\"v1\"").split()
        })
        .await;
        let url = server.url("/list.txt");
        let mut config = test_config(&dir.0, vec![url.clone()]);
        config.blocklist_max_rules_total = 2;
        let manager = test_manager(&config);

        let outcome = manager.refresh().await.unwrap();
        let status = &outcome.statuses[0];
        assert_eq!(status.rules, 2);
        assert!(status.last_success.is_some(), "a truncated list is a success");
        assert!(status.last_error.as_deref().unwrap().contains("blocklist_max_rules_total"));
        assert!(!outcome.retry_soon);
        let (body_path, meta_path) = manager.cache_paths(&url);
        assert_eq!(fs::read_to_string(&body_path).unwrap(), "||a1.test^\n||a2.test^\n");
        let meta = read_meta(&meta_path);
        assert!(meta.etag.is_none() && meta.last_modified.is_none());
        assert_eq!(meta.last_success, status.last_success);

        manager.refresh().await.unwrap();
        assert!(server.requests().iter().all(|request| !request.headers.contains_key("if-none-match")));

        drop(server);
        let boot = test_manager(&config).load_cached();
        assert_eq!(boot.statuses[0].rules, 2);
        assert!(boot.statuses[0].last_success.is_some());
        assert!(boot.rules.blocked("x.a2.test") && !boot.rules.blocked("x.a3.test"));
    }

    /// A crash mid-download or mid-save leaves a temp file behind; startup
    /// removes our own temp names (cache files in the lists folder, the
    /// pre-warm list and stats snapshot in state_dir) and nothing else.
    #[test]
    fn startup_sweeps_only_our_stale_temp_files() {
        let dir = TempDir::new("sweep");
        let manager = test_manager(&test_config(&dir.0, vec!["https://lists.example/a.txt".into()]));
        manager.ensure_dirs().unwrap();
        let lists = dir.0.join(CACHE_SUBDIR);
        let (body_path, _) = manager.cache_paths("https://lists.example/a.txt");
        let stale = [
            temp_path(&body_path),
            lists.join(".0123456789abcdef.meta.1.0.tmp"),
            temp_path(&dir.0.join("prewarm.txt")),
            dir.0.join(".stats.v1.7.3.tmp"),
        ];
        let kept = [
            body_path.clone(),
            dir.0.join("prewarm.txt"),
            dir.0.join(".notes.txt.1.0.tmp"),
            dir.0.join(".stats.v1.1.x.tmp"),
            lists.join(".prewarm.txt.1.0.tmp"),
            lists.join(".notes.tmp"),
            lists.join(".0123456789abcdef.list.1.x.tmp"),
            lists.join("0123456789abcdef.list.1.0.tmp"),
            dir.0.join(".0123456789abcdef.list.1.0.tmp"),
        ];
        for path in stale.iter().chain(&kept) {
            fs::write(path, "x").unwrap();
        }
        manager.sweep_temp_files();
        for path in &stale {
            assert!(!path.exists(), "{path:?}");
        }
        for path in &kept {
            assert!(path.exists(), "{path:?}");
        }
    }

    /// A list removed from the config leaves its cached copy behind; only the
    /// cache files of unconfigured URLs are deleted.
    #[test]
    fn cache_files_of_removed_lists_are_deleted() {
        let dir = TempDir::new("prune");
        let kept_url = "https://lists.example/a.txt";
        let manager = test_manager(&test_config(&dir.0, vec![kept_url.into()]));
        manager.ensure_dirs().unwrap();
        let lists = dir.0.join(CACHE_SUBDIR);
        let (kept_body, kept_meta) = manager.cache_paths(kept_url);
        let (gone_body, gone_meta) = manager.cache_paths("https://lists.example/removed.txt");
        let kept = [
            kept_body,
            kept_meta,
            lists.join("notes.txt"),
            lists.join("0123456789abcdef.txt"),
            lists.join("0123456789abcdeg.list"),
            dir.0.join("0123456789abcdef.list"),
        ];
        for path in [&gone_body, &gone_meta].into_iter().chain(&kept) {
            fs::write(path, "x").unwrap();
        }
        manager.remove_unconfigured_lists();
        assert!(!gone_body.exists() && !gone_meta.exists());
        for path in &kept {
            assert!(path.exists(), "{path:?}");
        }
    }

    #[tokio::test]
    async fn boot_loads_from_cache_without_network() {
        let dir = TempDir::new("boot");
        let server = MockServer::start(|_| Reply::ok("||boot.test^\n")).await;
        let config = test_config(&dir.0, vec![server.url("/list.txt")]);
        let first = test_manager(&config).refresh().await.unwrap();
        let success = first.statuses[0].last_success;
        drop(server);

        let boot = test_manager(&config).load_cached();
        assert!(boot.rules.blocked("x.boot.test"));
        assert_eq!(boot.statuses[0].rules, 1);
        assert!(boot.statuses[0].used_cache);
        assert!(boot.statuses[0].last_error.is_none());
        assert_eq!(boot.statuses[0].last_success, success);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn cache_directories_and_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new("perms");
        // Point at a state dir the process must create, not the TempDir itself.
        let state = dir.0.join("state");
        let server = MockServer::start(|_| Reply::ok("||private.test^\n")).await;
        let manager = test_manager(&test_config(&state, vec![server.url("/list.txt")]));
        manager.refresh().await.unwrap();

        assert_eq!(fs::metadata(&state).unwrap().permissions().mode() & 0o777, 0o700);
        let lists = state.join(CACHE_SUBDIR);
        assert_eq!(fs::metadata(&lists).unwrap().permissions().mode() & 0o777, 0o700);
        let mut entries = 0;
        for entry in fs::read_dir(&lists).unwrap() {
            let entry = entry.unwrap();
            assert_eq!(entry.metadata().unwrap().permissions().mode() & 0o777, 0o600);
            entries += 1;
        }
        assert_eq!(entries, 2, "one body and one metadata file");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn pre_existing_state_dir_is_usable_without_chmod() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new("existing-state");
        // A cluster volume may be writable without belonging to this uid, so
        // chmod would fail; a pre-existing 0755 directory stands in for it.
        fs::set_permissions(&dir.0, fs::Permissions::from_mode(0o755)).unwrap();
        let server = MockServer::start(|_| Reply::ok("||cached.test^\n")).await;
        let config = test_config(&dir.0, vec![server.url("/list.txt")]);

        let outcome = test_manager(&config).refresh().await.unwrap();
        assert!(outcome.statuses[0].last_error.is_none());
        assert_eq!(outcome.statuses[0].rules, 1);
        assert_eq!(fs::metadata(&dir.0).unwrap().permissions().mode() & 0o777, 0o755);
        let lists = dir.0.join(CACHE_SUBDIR);
        assert_eq!(fs::metadata(&lists).unwrap().permissions().mode() & 0o777, 0o700);

        let boot = test_manager(&config).load_cached();
        assert!(boot.rules.blocked("x.cached.test"));
    }

    #[test]
    fn redirect_guard_rejects_unsafe_targets() {
        let url = |value: &str| reqwest::Url::parse(value).unwrap();
        let hops = |values: &[&str]| values.iter().map(|value| url(value)).collect::<Vec<_>>();
        let secure = hops(&["https://a.example/x"]);
        let plain = hops(&["http://a.example/x"]);

        assert!(redirect_target_allowed(&secure, &url("https://b.example/x")));
        assert!(!redirect_target_allowed(&secure, &url("http://b.example/x")));
        assert!(redirect_target_allowed(&plain, &url("http://b.example/x")));
        assert!(redirect_target_allowed(&plain, &url("https://b.example/x")));
        // A chain that upgraded to https may not downgrade later.
        let upgraded = hops(&["http://a.example/x", "https://b.example/x"]);
        assert!(!redirect_target_allowed(&upgraded, &url("http://c.example/x")));
        assert!(redirect_target_allowed(&upgraded, &url("https://c.example/x")));

        assert!(!redirect_target_allowed(&secure, &url("file:///etc/passwd")));
        assert!(!redirect_target_allowed(&secure, &url("data:text/plain,x")));
        assert!(!redirect_target_allowed(&secure, &url("https://100.64.0.1/x")));
        assert!(!redirect_target_allowed(&secure, &url("https://100.127.255.254/x")));
        assert!(redirect_target_allowed(&secure, &url("https://100.128.0.1/x")));

        // Five redirects are followed; the sixth is stopped.
        let five = hops(&[
            "https://a.example/1",
            "https://a.example/2",
            "https://a.example/3",
            "https://a.example/4",
            "https://a.example/5",
        ]);
        assert!(redirect_target_allowed(&five, &url("https://a.example/6")));
        let six = hops(&[
            "https://a.example/1",
            "https://a.example/2",
            "https://a.example/3",
            "https://a.example/4",
            "https://a.example/5",
            "https://a.example/6",
        ]);
        assert!(!redirect_target_allowed(&six, &url("https://a.example/7")));

        for target in [
            "http://127.0.0.1/x",
            "http://127.8.9.10/x",
            "http://[::1]/x",
            "http://169.254.169.254/latest/meta-data",
            "http://0.0.0.0/x",
            "http://[::]/x",
            "http://[fe80::1]/x",
            "http://[::ffff:127.0.0.1]/x",
            "http://10.1.2.3/x",
            "http://172.16.0.1/x",
            "http://192.168.1.1/x",
            "http://[fd00::1]/x",
            "http://[::ffff:192.168.1.1]/x",
            "http://localhost/x",
            "http://LocalHost./x",
            "http://router.localhost:8080/x",
            // IPv4-compatible and NAT64 forms carry the IPv4 address inside.
            "http://[::127.0.0.1]/x",
            "http://[::10.0.0.1]/x",
            "http://[64:ff9b::7f00:1]/x",
            "http://[64:ff9b::a9fe:a9fe]/x",
            "http://[64:ff9b::c0a8:101]/x",
            "http://[64:ff9b:1::1]/x",
            "http://[64:ff9b:1:ffff::5db8:d822]/x",
            "http://0.0.0.1/x",
            "http://0.255.255.255/x",
            "http://198.18.0.1/x",
            "http://198.19.255.254/x",
        ] {
            assert!(!redirect_target_allowed(&plain, &url(target)), "{target}");
        }
        // Names are not resolved, and public literals are fine.
        assert!(redirect_target_allowed(&plain, &url("http://93.184.216.34/x")));
        assert!(redirect_target_allowed(&plain, &url("http://lists.example.org/x")));
        assert!(redirect_target_allowed(&plain, &url("http://[2001:db8::1]/x")));
        assert!(redirect_target_allowed(&plain, &url("http://[64:ff9b::5db8:d822]/x")));
        assert!(redirect_target_allowed(&plain, &url("http://198.20.0.1/x")));
        assert!(redirect_target_allowed(&plain, &url("http://1.0.0.1/x")));
        assert!(redirect_target_allowed(&plain, &url("http://localhost.example/x")));
    }

    /// A 200 that would wipe most of a list (an empty body, a captive portal's
    /// "OK") is refused and the cached copy stays in use and on disk. An empty
    /// body is always refused and asks for an early retry. A shrink of over
    /// 90% is held back, without an early retry, and accepted when a download
    /// a full interval later is still that small, so a list that really did
    /// shrink is never pinned to its old rules, even across a restart.
    #[tokio::test]
    async fn a_refresh_that_loses_most_rules_is_refused() {
        let dir = TempDir::new("shrink");
        let body = Arc::new(Mutex::new(String::new()));
        let server = MockServer::start({
            let body = body.clone();
            move |request| {
                let body = body.lock().unwrap().clone();
                let etag = format!("\"{}\"", body.len());
                if request.headers.get("if-none-match") == Some(&etag) {
                    Reply::status("304 Not Modified")
                } else {
                    Reply::ok(body).header("ETag", etag)
                }
            }
        })
        .await;
        let url = server.url("/list.txt");
        let manager = test_manager(&test_config(&dir.0, vec![url.clone()]));
        let set = |text: String| *body.lock().unwrap() = text;
        let twenty: String = (0..20).map(|i| format!("||r{i}.test^\n")).collect();
        set(twenty.clone());
        let first = manager.refresh().await.unwrap();
        assert_eq!(first.statuses[0].rules, 20);
        assert!(!first.retry_soon);

        for text in ["", "<html>error</html>\n", "", "<html>error</html>\n"] {
            set(text.into());
            let outcome = manager.refresh().await.unwrap();
            let status = &outcome.statuses[0];
            assert_eq!(status.rules, 20, "{text:?}");
            assert!(status.used_cache && outcome.rules.blocked("x.r7.test"), "{text:?}");
            assert!(
                status.last_error.as_deref().unwrap().contains("list contains no rules"),
                "{:?}",
                status.last_error
            );
            assert!(outcome.retry_soon, "{text:?}");
        }

        // A captive portal's "OK" is a valid one-name list, so only the
        // shrink check catches it; the first sighting is held back.
        set("OK\n".into());
        let outcome = manager.refresh().await.unwrap();
        let status = &outcome.statuses[0];
        assert_eq!(status.rules, 20);
        assert!(status.used_cache && outcome.rules.blocked("x.r7.test"));
        assert!(status.last_error.as_deref().unwrap().contains("refused"), "{:?}", status.last_error);
        assert!(!outcome.retry_soon, "a held-back shrink waits a full interval");
        let boot = test_manager(&test_config(&dir.0, vec![url.clone()])).load_cached();
        assert_eq!(boot.statuses[0].rules, 20, "the cached copy is untouched");

        // A download a full interval later (here after a restart) is still
        // small, even if not byte-identical: accepted and cached.
        end_shrink_hold(&manager, &url);
        set("||a.test^\n||b.test^\n".into());
        let restarted = test_manager(&test_config(&dir.0, vec![url.clone()]));
        let outcome = restarted.refresh().await.unwrap();
        assert_eq!(outcome.statuses[0].rules, 2);
        assert!(outcome.statuses[0].last_error.is_none() && !outcome.retry_soon);
        assert!(outcome.rules.blocked("x.a.test") && !outcome.rules.blocked("x.r7.test"));

        // A 304 (the server confirms the cached copy) clears the mark, so the
        // next shrink is held back again.
        set(twenty.clone());
        assert_eq!(manager.refresh().await.unwrap().statuses[0].rules, 20);
        set("OK\n".into());
        assert_eq!(manager.refresh().await.unwrap().statuses[0].rules, 20);
        set(twenty.clone());
        let outcome = manager.refresh().await.unwrap();
        assert!(outcome.statuses[0].used_cache && outcome.statuses[0].last_error.is_none(), "a 304");
        set("OK\n".into());
        assert_eq!(manager.refresh().await.unwrap().statuses[0].rules, 20, "held back again");
        end_shrink_hold(&manager, &url);

        // Keeping a tenth of the rules is a legitimate update.
        set("||a.test^\n||b.test^\n".into());
        let outcome = manager.refresh().await.unwrap();
        assert_eq!(outcome.statuses[0].rules, 2);
        assert!(outcome.statuses[0].last_error.is_none() && !outcome.retry_soon);
    }

    /// Moves a held-back shrink's start one refresh interval into the past.
    fn end_shrink_hold(manager: &ListManager, url: &str) {
        let meta_path = manager.cache_paths(url).1;
        let meta = read_meta(&meta_path);
        let since = now_secs() - manager.shrink_hold_secs;
        assert!(meta.refused.is_some() && meta.refused_at.is_some_and(|at| at > since), "a hold is running");
        write_meta(&meta_path, &Meta { refused_at: Some(since), ..meta }).unwrap();
    }

    /// The hold on a shrink lasts a full refresh interval: an early retry
    /// (another list failed), a reload or a restart inside it keeps refusing,
    /// and repeated refusals never move its start.
    #[tokio::test]
    async fn a_held_back_shrink_stays_refused_for_a_full_interval() {
        let dir = TempDir::new("shrink-hold");
        let body = Arc::new(Mutex::new((0..20).map(|i| format!("||r{i}.test^\n")).collect::<String>()));
        let server = MockServer::start({
            let body = body.clone();
            move |_| Reply::ok(body.lock().unwrap().clone())
        })
        .await;
        let url = server.url("/list.txt");
        let config = test_config(&dir.0, vec![url.clone()]);
        assert_eq!(test_manager(&config).refresh().await.unwrap().statuses[0].rules, 20);

        *body.lock().unwrap() = "OK\n".into();
        let mut started = None;
        for attempt in 0..3 {
            // A fresh manager each time: a restart or a reload builds one.
            let outcome = test_manager(&config).refresh().await.unwrap();
            assert_eq!(outcome.statuses[0].rules, 20, "attempt {attempt}");
            assert!(outcome.rules.blocked("x.r7.test"), "attempt {attempt}");
            let at = read_meta(&test_manager(&config).cache_paths(&url).1).refused_at;
            assert!(at.is_some() && (started.is_none() || at == started), "attempt {attempt}");
            started = at;
        }

        let manager = test_manager(&config);
        end_shrink_hold(&manager, &url);
        let outcome = manager.refresh().await.unwrap();
        assert_eq!(outcome.statuses[0].rules, 1);
        assert!(outcome.statuses[0].last_error.is_none());
        let meta = read_meta(&manager.cache_paths(&url).1);
        assert!(meta.refused.is_none() && meta.refused_at.is_none());
    }

    /// A hold whose start is in the future (marked while the clock ran ahead)
    /// is over: it would otherwise last until the clock caught up, plus a
    /// whole interval.
    #[tokio::test]
    async fn a_shrink_hold_started_in_the_future_is_over() {
        let dir = TempDir::new("shrink-future");
        let body = Arc::new(Mutex::new((0..20).map(|i| format!("||r{i}.test^\n")).collect::<String>()));
        let server = MockServer::start({
            let body = body.clone();
            move |_| Reply::ok(body.lock().unwrap().clone())
        })
        .await;
        let url = server.url("/list.txt");
        let manager = test_manager(&test_config(&dir.0, vec![url.clone()]));
        assert_eq!(manager.refresh().await.unwrap().statuses[0].rules, 20);
        *body.lock().unwrap() = "OK\n".into();
        assert_eq!(manager.refresh().await.unwrap().statuses[0].rules, 20, "held back");

        let meta_path = manager.cache_paths(&url).1;
        let meta = read_meta(&meta_path);
        write_meta(&meta_path, &Meta { refused_at: Some(now_secs() + 86_400), ..meta }).unwrap();
        let outcome = manager.refresh().await.unwrap();
        assert_eq!(outcome.statuses[0].rules, 1);
        assert!(outcome.statuses[0].last_error.is_none());
    }

    /// A list that cannot be fetched and has no cached copy (a cold boot during
    /// an outage) asks for an early retry instead of waiting a whole interval.
    #[tokio::test]
    async fn a_failed_list_asks_for_an_early_retry() {
        let dir = TempDir::new("retry");
        let failing = Arc::new(AtomicBool::new(true));
        let server = MockServer::start({
            let failing = failing.clone();
            move |_| {
                if failing.load(Ordering::Relaxed) {
                    Reply::status("503 Service Unavailable")
                } else {
                    Reply::ok("||late.test^\n")
                }
            }
        })
        .await;
        let mut config = test_config(&dir.0, vec![server.url("/list.txt")]);
        config.user_rules = vec!["||inline.test^".into()];
        let manager = test_manager(&config);
        let outcome = manager.refresh().await.unwrap();
        assert!(outcome.retry_soon && !outcome.rules.blocked("late.test"));
        failing.store(false, Ordering::Relaxed);
        let outcome = manager.refresh().await.unwrap();
        assert!(!outcome.retry_soon && outcome.rules.blocked("late.test"));
    }

    /// A FIFO planted where a cached file belongs is refused at once instead
    /// of blocking startup until something writes to it.
    #[cfg(unix)]
    #[test]
    fn a_fifo_in_place_of_a_state_file_never_blocks() {
        let dir = TempDir::new("fifo");
        let url = "https://lists.example/list.txt".to_string();
        let manager = test_manager(&test_config(&dir.0, vec![url.clone()]));
        manager.ensure_dirs().unwrap();
        let (body, meta) = manager.cache_paths(&url);
        let fifo = dir.0.join("fifo");
        for path in [&body, &meta, &fifo] {
            assert!(std::process::Command::new("mkfifo").arg(path).status().unwrap().success());
        }
        let (done, wait) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let boot = manager.load_cached();
            let read = open_regular(&fifo).map(drop);
            done.send((boot.statuses[0].used_cache, read.is_err())).unwrap();
        });
        assert_eq!(wait.recv_timeout(Duration::from_secs(5)), Ok((false, true)));
    }

    #[tokio::test]
    async fn redirect_targets_are_not_followed() {
        let dir = TempDir::new("redirects");
        let target = Arc::new(Mutex::new(String::new()));
        let server = MockServer::start({
            let target = target.clone();
            move |request| match request.path.as_str() {
                "/good.txt" => Reply::ok("||good.test^\n"),
                "/loopback.txt" => {
                    Reply::status("302 Found").header("Location", format!("{}/followed.txt", target.lock().unwrap()))
                }
                "/metadata.txt" => {
                    Reply::status("302 Found").header("Location", "http://169.254.169.254/latest/meta-data")
                }
                _ => Reply::status("302 Found").header("Location", "file:///etc/passwd"),
            }
        })
        .await;
        *target.lock().unwrap() = format!("http://{}", server.addr);
        let config = test_config(
            &dir.0,
            vec![
                server.url("/good.txt"),
                server.url("/loopback.txt"),
                server.url("/metadata.txt"),
                server.url("/file.txt"),
            ],
        );
        let outcome = test_manager(&config).refresh().await.unwrap();
        assert!(outcome.rules.blocked("x.good.test"));
        assert!(!outcome.rules.blocked("x.followed.test"));
        for status in &outcome.statuses[1..] {
            assert!(status.last_error.as_deref().unwrap().contains("302"), "{:?}", status.last_error);
        }
        // The guarded redirects are stopped at the first hop, so the mock sees
        // exactly one request per configured list and never /followed.txt.
        assert_eq!(server.requests().len(), 4);
    }

    #[tokio::test]
    async fn tokens_never_reach_status_or_logs() {
        let dir = TempDir::new("token");
        let server = MockServer::start(|_| Reply::status("500 Internal Server Error")).await;
        let url = server.url("/list.txt?token=supersecret");
        // The connection error path, where reqwest's own Display names the URL.
        let unreachable = "http://127.0.0.1:1/list.txt?token=supersecret".to_string();
        let mut config = test_config(&dir.0, vec![url, unreachable]);
        config.user_rules = vec!["||inline.test^".into()];
        let outcome = test_manager(&config).refresh().await.unwrap();
        assert_eq!(outcome.statuses.len(), 2);
        for (status, expected) in outcome.statuses.iter().zip(["500", "connection failed"]) {
            assert!(!status.name.contains("supersecret"), "{}", status.name);
            let error = status.last_error.as_deref().unwrap();
            assert!(error.contains(expected), "{error}");
            assert!(!error.contains("supersecret"), "{error}");
            assert!(error.contains(&status.name), "the error names the sanitized source: {error}");
        }
    }

    #[tokio::test]
    async fn non_http_list_urls_are_rejected() {
        let dir = TempDir::new("scheme");
        let mut config = test_config(
            &dir.0,
            vec![
                "file:///tmp/list.txt?token=supersecret".into(),
                "data:text/plain,supersecret".into(),
                "ftp://user:secret@example.com/list.txt?token=supersecret".into(),
            ],
        );
        config.user_rules = vec!["||inline.test^".into()];
        let outcome = test_manager(&config).refresh().await.unwrap();
        assert!(outcome.rules.blocked("inline.test"));
        for status in &outcome.statuses {
            let error = status.last_error.as_deref().unwrap();
            assert!(error.contains("http or https"), "{error}");
            assert!(!error.contains("supersecret"), "{error}");
            assert!(!error.contains("secret"), "{error}");
        }
        assert_eq!(outcome.statuses[2].name, "ftp://example.com/list.txt");
    }

    /// The rules page re-reads the inline rules and the cached bodies for the
    /// parents the table matched, with line numbers, and stops at its hit cap.
    #[test]
    fn find_rules_reads_user_rules_and_cached_bodies_within_a_cap() {
        let dir = TempDir::new("find-rules");
        let url = "http://list.example/hosts.txt";
        let config = Config {
            blocklists: vec![url.to_string()],
            user_rules: vec!["||mine.test^".into(), "! note".into(), "@@||mine.test^$important".into()],
            state_dir: dir.0.clone(),
            ..Config::default()
        };
        let manager = ListManager::new(client_builder().build().unwrap(), &config);
        manager.ensure_dirs().unwrap();
        fs::write(manager.cache_paths(url).0, "! header\n0.0.0.0 Mine.Test\nother.test\r\n||MINE.test^\n").unwrap();
        let wanted: HashSet<String> = ["mine.test".to_string()].into();
        let scan = manager.find_rules(&wanted);
        assert!(scan.complete);
        let flags = |line: &str| rules::parse_rule(line).unwrap().unwrap().1;
        let found: Vec<_> = scan.hits.iter().map(|h| (h.list_id, h.line, h.text.as_str(), h.flags)).collect();
        assert_eq!(
            found,
            [
                (0, 1, "||mine.test^", flags("||mine.test^")),
                (0, 3, "@@||mine.test^$important", flags("@@||mine.test^$important")),
                (1, 2, "0.0.0.0 Mine.Test", flags("|mine.test^")),
                (1, 4, "||MINE.test^", flags("||mine.test^")),
            ]
        );
        assert!(manager.find_rules(&["absent.test".to_string()].into()).hits.is_empty());

        fs::write(manager.cache_paths(url).0, "||mine.test^\n".repeat(SCAN_HITS + 50)).unwrap();
        let scan = manager.find_rules(&wanted);
        assert_eq!(scan.hits.len(), SCAN_HITS, "hits are capped");
        assert!(!scan.complete, "a capped scan says it is incomplete");
    }
}
