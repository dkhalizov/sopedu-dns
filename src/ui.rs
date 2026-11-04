//! Read-only dashboard, query-log, rules and clients pages.
//!
//! Server-rendered: every page and JSON document is built here from data the
//! handler collected, and every DNS name or other client-controlled string is
//! escaped for the context it lands in. The three static assets are embedded.
//! Nothing here writes state; "copy rule" only displays the rule text.
//!
//! A blocked row names the list that blocked it. The matcher stores hashes, not
//! rule text, so a log row can only give the list; the rules page re-reads the
//! sources on demand for the one name tested ([`crate::lists::ListManager::find_rules`]).

use crate::{
    config::Config,
    http::{Reply, STREAM_LIFETIME},
    lists::{RuleHit, SourceStatus},
    mac::ArpTable,
    querylog::{self, Board, Entry, Filter, QueryLog, Top, Window},
    rules,
    stats::Outcome,
    upstream::UpstreamHealth,
};
use hyper::body::Bytes;
use std::time::{Duration, UNIX_EPOCH};
use std::{
    collections::HashMap,
    fmt::Write,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{
        atomic::{AtomicUsize, Ordering::Relaxed},
        Arc,
    },
};
use tokio::sync::mpsc;

pub const CSS: &str = include_str!("ui/app.css");
pub const JS: &str = include_str!("ui/app.js");
const SHELL: &str = include_str!("ui/shell.html");
const LOG: &str = include_str!("ui/log.html");

/// The pages in navigation order: `data-page`, path, title.
const PAGES: [(&str, &str, &str); 4] = [
    ("dash", "/", "Dashboard"),
    ("log", "/log", "Query log"),
    ("rules", "/rules", "Rules"),
    ("clients", "/clients", "Clients"),
];

/// The common head, navigation and script around one page's content.
fn shell(page: &str, content: &str) -> String {
    let mut nav = String::new();
    let mut title = "";
    for (id, path, name) in PAGES {
        let current = if id == page {
            title = name;
            " aria-current=\"page\""
        } else {
            ""
        };
        let _ = write!(nav, "<a href=\"{path}\"{current}>{name}</a>");
    }
    fill(SHELL, &[("title", title), ("page", page), ("nav", &nav), ("content", content)])
}

/// Fills each `{{slot}}` of `template` in one left-to-right pass. A value is
/// copied as is and never scanned again, so text echoed from a request that
/// spells `{{rows}}` stays literal instead of pulling another slot in.
fn fill(template: &str, slots: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(template.len() + slots.iter().map(|(_, v)| v.len()).sum::<usize>());
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let slot = after.find("}}").and_then(|end| Some((slots.iter().find(|(k, _)| *k == &after[..end])?.1, end)));
        match slot {
            Some((value, end)) => {
                out.push_str(value);
                rest = &after[end + 2..];
            }
            None => {
                out.push_str("{{");
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

pub const HTML: &str = "text/html; charset=utf-8";
pub const JSON: &str = "application/json";
/// Rows in the first page load and in `/api/log`.
const PAGE_ROWS: usize = 200;
/// Most rows one live-tail tick sends; a busier tick sends the newest.
const TICK_ROWS: usize = 100;
/// Concurrent live tails.
pub const MAX_STREAMS: usize = 4;
/// Chunks queued for one slow client before its stream is dropped.
const STREAM_QUEUE: usize = 8;
/// Longest error text sent to the browser.
const MAX_ERROR_CHARS: usize = 200;

/// The DNS rebinding guard: a page hosted under another name can make a
/// browser send requests here, so only an IP literal or `localhost` is a valid
/// `Host`. A request without one (HTTP/1.0 may omit it) cannot show which name
/// the browser used, so it is refused too.
pub fn host_ok(host: Option<&str>) -> bool {
    let Some(host) = host else { return false };
    let name = match host.strip_prefix('[') {
        // `[addr]` or `[addr]:port`; anything after the bracket is not a host.
        Some(rest) => match rest.split_once(']') {
            Some((addr, tail))
                if tail.is_empty() || tail.strip_prefix(':').is_some_and(|p| p.bytes().all(|b| b.is_ascii_digit())) =>
            {
                addr
            }
            _ => "",
        },
        None => {
            host.rsplit_once(':').filter(|(_, port)| port.bytes().all(|b| b.is_ascii_digit())).map_or(host, |(h, _)| h)
        }
    };
    name.parse::<Ipv4Addr>().is_ok()
        || name.parse::<Ipv6Addr>().is_ok()
        || name.trim_end_matches('.').eq_ignore_ascii_case("localhost")
}

/// HTML text/attribute escaping.
pub fn esc(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    esc_into(&mut out, text);
    out
}

fn esc_into(out: &mut String, text: &str) {
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
}

/// A JSON string literal. `<`, `>` and `&` are escaped too, so the document
/// stays inert if something ever inlines it into HTML.
fn json_str(out: &mut String, text: &str) {
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '<' | '>' | '&' | '\0'..='\u{1f}' | '\u{7f}' => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn json_opt(out: &mut String, text: Option<&str>) {
    match text {
        Some(text) => json_str(out, &clip(text)),
        None => out.push_str("null"),
    }
}

fn clip(text: &str) -> String {
    text.chars().take(MAX_ERROR_CHARS).collect()
}

fn fmt_us(us: u64) -> String {
    match us {
        0..=999 => format!("{us} µs"),
        1000..=999_999 => format!("{:.1} ms", us as f64 / 1000.0),
        _ => format!("{:.1} s", us as f64 / 1e6),
    }
}

fn pct(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        0.0
    } else {
        part as f64 * 100.0 / whole as f64
    }
}

fn cache_pct(w: &Window) -> f64 {
    pct(w.count(Outcome::Cache) + w.count(Outcome::Stale), w.total())
}

pub fn list_name(lists: &[SourceStatus], id: u16) -> String {
    if id == 0 {
        return "user rules".to_string();
    }
    if id == querylog::CNAME_TARGET {
        return "cname target".to_string();
    }
    lists.iter().find(|l| l.id == id).map_or_else(|| format!("list {id}"), |l| l.name.clone())
}

fn upstream_label(upstream: u8) -> String {
    match upstream {
        querylog::NO_UPSTREAM => String::new(),
        querylog::PLAIN_UPSTREAM => "fallback".to_string(),
        n => format!("#{n}"),
    }
}

// --------------------------------------------------------------- dashboard

/// Everything the dashboard shows, collected by the handler.
pub struct Dash<'a> {
    pub board: Board,
    pub log_enabled: bool,
    pub lists: &'a [SourceStatus],
    pub upstreams: &'a [UpstreamHealth],
    pub now_unix: u64,
    /// Upstream answers that came over the plaintext fallback since start.
    pub plain_fallback: u64,
}

fn list_status(l: &SourceStatus) -> &'static str {
    if l.last_error.is_some() {
        "error"
    } else if l.last_success.is_none() {
        "pending"
    } else if l.used_cache {
        "cached"
    } else {
        "ok"
    }
}

fn win_json(out: &mut String, w: &Window) {
    let p = |q| w.percentile_us(q).map_or("null".to_string(), |us| us.to_string());
    let _ = write!(
        out,
        "{{\"span_s\":{},\"queries\":{},\"qps\":{:.2},\"cache_pct\":{:.1},\"blocked_pct\":{:.1},\"p50_us\":{},\"p95_us\":{},\"p99_us\":{}}}",
        w.span_ms / 1000,
        w.total(),
        w.qps(),
        cache_pct(w),
        pct(w.count(Outcome::Blocked), w.total()),
        p(0.50),
        p(0.95),
        p(0.99),
    );
}

fn top_json(out: &mut String, items: &[Top], domain: bool) {
    out.push('[');
    for (i, t) in items.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"name\":");
        json_str(out, &if domain { querylog::key_domain(&t.key) } else { querylog::key_client(&t.key) });
        let _ = write!(out, ",\"count\":{},\"err\":{}}}", t.count, t.err);
    }
    out.push(']');
}

fn win_share(u: &UpstreamHealth, total_wins: u64) -> f64 {
    pct(u.wins, total_wins)
}

pub fn dashboard_json(d: &Dash<'_>) -> String {
    let b = &d.board;
    let mut out = String::with_capacity(4096);
    let _ = write!(
        out,
        "{{\"qps\":{:.2},\"log\":{{\"enabled\":{},\"capacity\":{},\"seen\":{},\"lost\":{}}},\"windows\":{{\"5m\":",
        b.qps, d.log_enabled, b.capacity, b.seen, b.lost
    );
    win_json(&mut out, &b.w5m);
    out.push_str(",\"24h\":");
    win_json(&mut out, &b.w24h);
    out.push_str("},\"upstreams\":[");
    let total_wins: u64 = d.upstreams.iter().map(|u| u.wins).sum();
    for (i, u) in d.upstreams.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let _ = write!(out, "{{\"index\":{},\"url\":", u.index);
        json_str(&mut out, &u.url);
        let _ = write!(
            out,
            ",\"healthy\":{},\"ewma_us\":{},\"outstanding\":{},\"wins\":{},\"win_share\":{:.1},\"hedges\":{},\"last_error\":",
            u.healthy,
            u.ewma_us,
            u.outstanding,
            u.wins,
            win_share(u, total_wins),
            u.hedges
        );
        json_opt(&mut out, u.last_error.as_deref());
        out.push('}');
    }
    let _ = write!(out, "],\"since_unix\":{},\"plain_fallback_answers\":{}", b.since_ms / 1000, d.plain_fallback);
    out.push_str(",\"lists\":[");
    for (i, l) in d.lists.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let _ = write!(out, "{{\"id\":{},\"name\":", l.id);
        json_str(&mut out, &l.name);
        let _ = write!(out, ",\"rules\":{},\"last_success\":", l.rules);
        match l.last_success {
            Some(at) => {
                let _ = write!(out, "{at}");
            }
            None => out.push_str("null"),
        }
        let _ = write!(out, ",\"status\":\"{}\",\"last_error\":", list_status(l));
        json_opt(&mut out, l.last_error.as_deref());
        out.push('}');
    }
    out.push_str("],\"top\":{\"domains\":");
    top_json(&mut out, &b.domains, true);
    out.push_str(",\"blocked\":");
    top_json(&mut out, &b.blocked, true);
    out.push_str(",\"clients\":");
    top_json(&mut out, &b.clients, false);
    out.push_str("}}");
    out
}

fn ago(now: u64, at: u64) -> String {
    let s = now.saturating_sub(at);
    match s {
        0..=59 => format!("{s} s ago"),
        60..=3599 => format!("{} min ago", s / 60),
        3600..=86_399 => format!("{} h ago", s / 3600),
        _ => format!("{} d ago", s / 86_400),
    }
}

fn window_card(out: &mut String, title: &str, w: &Window) {
    let p = |q| w.percentile_us(q).map_or("-".to_string(), |us| format!("≤ {}", fmt_us(us)));
    let span =
        if w.span_ms < 90_000 { format!("{} s", w.span_ms / 1000) } else { format!("{} min", w.span_ms / 60_000) };
    let _ = write!(
        out,
        "<section class=\"card\"><h2>{title} <small>covers {span}</small></h2><dl class=\"kv\">\
         <div><dt>Queries</dt><dd>{}</dd></div><div><dt>Avg qps</dt><dd>{:.1}</dd></div>\
         <div><dt>Cache hit</dt><dd>{:.1}%</dd></div><div><dt>Blocked</dt><dd>{:.1}%</dd></div>\
         <div><dt>p50</dt><dd>{}</dd></div><div><dt>p95</dt><dd>{}</dd></div><div><dt>p99</dt><dd>{}</dd></div>\
         </dl></section>",
        w.total(),
        w.qps(),
        cache_pct(w),
        pct(w.count(Outcome::Blocked), w.total()),
        p(0.50),
        p(0.95),
        p(0.99),
    );
}

fn top_table(out: &mut String, title: &str, items: &[Top], domain: bool, empty: &str) {
    let _ = write!(out, "<section class=\"card\"><h2>{title}</h2>");
    if items.is_empty() {
        let _ = write!(out, "<p class=\"muted\">{empty}</p></section>");
        return;
    }
    out.push_str("<div class=\"scroll\"><table><tbody>");
    for t in items {
        let name = if domain { querylog::key_domain(&t.key) } else { querylog::key_client(&t.key) };
        out.push_str("<tr><td class=\"mono wrap\">");
        esc_into(out, &name);
        let _ = write!(out, "</td><td class=\"num\">{}</td></tr>", t.count);
    }
    out.push_str("</tbody></table></div></section>");
}

pub fn dashboard_html(d: &Dash<'_>) -> String {
    let b = &d.board;
    let mut c = String::with_capacity(8192);
    let _ = write!(
        c,
        "<section class=\"hero\"><div><span class=\"label\">Queries per second</span><span class=\"big\">{:.1}</span></div>",
        b.qps
    );
    let _ = write!(
        c,
        "<div class=\"muted\">last ~10 s. Latency percentiles are the upper edge of a power-of-two bucket.</div></section>"
    );
    c.push_str("<div class=\"grid2\">");
    window_card(&mut c, "Last 5 minutes", &b.w5m);
    window_card(&mut c, "Last 24 hours", &b.w24h);
    c.push_str("</div>");

    c.push_str("<section class=\"card\"><h2>Upstreams</h2>");
    if d.upstreams.is_empty() {
        c.push_str(
            "<p class=\"muted\">No DoH upstream configured; misses go to the plain fallback servers, if any.</p>",
        );
    } else {
        let total_wins: u64 = d.upstreams.iter().map(|u| u.wins).sum();
        c.push_str(
            "<div class=\"scroll\"><table><thead><tr><th>#</th><th>Upstream</th><th>State</th><th class=\"num\">EWMA</th>\
             <th class=\"num\">In flight</th><th class=\"num\">Won</th><th class=\"num\">Share</th><th>Last error</th></tr></thead><tbody>",
        );
        for u in d.upstreams {
            let state = if u.healthy {
                "<span class=\"tag ok\">up</span>"
            } else {
                "<span class=\"tag bad\">circuit open</span>"
            };
            let _ = write!(c, "<tr><td>{}</td><td class=\"mono wrap\">", u.index);
            esc_into(&mut c, &u.url);
            let ewma = if u.ewma_us == 0 { "-".to_string() } else { fmt_us(u.ewma_us) };
            let _ = write!(
                c,
                "</td><td>{state}</td><td class=\"num\">{ewma}</td><td class=\"num\">{}</td><td class=\"num\">{}</td>\
                 <td class=\"num\">{:.1}%</td><td class=\"wrap\">",
                u.outstanding,
                u.wins,
                win_share(u, total_wins)
            );
            esc_into(&mut c, &clip(u.last_error.as_deref().unwrap_or("")));
            c.push_str("</td></tr>");
        }
        c.push_str("</tbody></table></div>");
    }
    if d.plain_fallback > 0 {
        let _ = write!(
            c,
            "<p><span class=\"tag warn\">degraded</span> {} answers since start came over the unauthenticated plain \
             DNS fallback because every DoH upstream failed.</p>",
            d.plain_fallback
        );
    }
    c.push_str("</section>");

    c.push_str("<section class=\"card\"><h2>Blocklists</h2>");
    if d.lists.is_empty() {
        c.push_str("<p class=\"muted\">No blocklist configured.</p>");
    } else {
        c.push_str(
            "<div class=\"scroll\"><table><thead><tr><th>List</th><th class=\"num\">Rules</th><th>Updated</th><th>Status</th>\
             </tr></thead><tbody>",
        );
        for l in d.lists {
            c.push_str("<tr><td class=\"mono wrap\">");
            esc_into(&mut c, &l.name);
            let status = list_status(l);
            let class = match status {
                "ok" => "ok",
                "error" => "bad",
                _ => "warn",
            };
            let _ = write!(
                c,
                "</td><td class=\"num\">{}</td><td>{}</td><td><span class=\"tag {class}\">{status}</span> ",
                l.rules,
                l.last_success.map_or("never".to_string(), |at| ago(d.now_unix, at)),
            );
            esc_into(&mut c, &clip(l.last_error.as_deref().unwrap_or("")));
            c.push_str("</td></tr>");
        }
        c.push_str("</tbody></table></div>");
    }
    c.push_str(
        "<p class=\"muted\">Read-only. Lists refresh on the <code>refresh_hours</code> schedule; edit the config to change them.</p></section>",
    );

    let empty = if d.log_enabled { "Nothing yet." } else { "The query log is off (query_log_capacity = 0)." };
    c.push_str("<div class=\"grid3\">");
    top_table(&mut c, "Top domains", &b.domains, true, empty);
    top_table(&mut c, "Top blocked", &b.blocked, true, empty);
    top_table(&mut c, "Top clients", &b.clients, false, empty);
    c.push_str("</div>");
    let _ = write!(
        c,
        "<p class=\"muted foot\">Top lists and the all-time counters on <code>/metrics</code> count since {}; with \
         <code>persist_stats</code> they carry over restarts.</p>",
        httpdate::fmt_http_date(UNIX_EPOCH + Duration::from_millis(b.since_ms))
    );
    if d.log_enabled {
        let _ = write!(
            c,
            "<p class=\"muted foot\">Top lists come from the query log ({} entries kept). {} entries were overwritten before they were counted{}.</p>",
            b.capacity,
            b.lost,
            if b.lost > 0 { ", so the lists are a sample under this load" } else { "" }
        );
    }
    shell("dash", &c)
}

// ---------------------------------------------------------------- query log

fn utc_hms(unix_ms: u64) -> String {
    let s = unix_ms / 1000 % 86_400;
    format!("{:02}:{:02}:{:02}", s / 3600, s / 60 % 60, s % 60)
}

/// One `<tr>`, one line (it is also an SSE `data:` payload).
pub fn row_html(log: &QueryLog, lists: &[SourceStatus], e: &Entry) -> String {
    let mut out = String::with_capacity(512);
    let ms = log.unix_ms(e);
    let _ = write!(
        out,
        "<tr><td class=\"mono\"><time data-ms=\"{ms}\">{}</time></td><td class=\"mono\">{}</td><td class=\"mono wrap\">",
        utc_hms(ms),
        e.ip
    );
    esc_into(&mut out, &e.text());
    let class = match e.outcome {
        Outcome::Blocked | Outcome::Servfail => "bad",
        Outcome::Dropped | Outcome::Other | Outcome::Stale => "warn",
        _ => "ok",
    };
    let _ = write!(
        out,
        "</td><td>{}</td><td><span class=\"tag {class}\">{}</span>",
        querylog::qtype_name(e.qtype),
        e.outcome.label()
    );
    if let Some(list) = e.list {
        out.push_str(" <span class=\"muted wrap\">");
        esc_into(&mut out, &list_name(lists, list));
        out.push_str("</span>");
    }
    let upstream = upstream_label(e.upstream);
    let _ = write!(out, "</td><td class=\"num\">{}", fmt_us(u64::from(e.latency_us)));
    if !upstream.is_empty() {
        let _ = write!(out, " <span class=\"muted\">{upstream}</span>");
    }
    out.push_str("</td><td>");
    match e.rule_domain() {
        Some(domain) => {
            let block = esc(&format!("||{domain}^"));
            let allow = esc(&format!("@@||{domain}^$important"));
            let _ = write!(
                out,
                "<details class=\"rule\"><summary>Rule</summary><div class=\"pop\">\
                 <div><code>{block}</code> <button type=\"button\" data-copy=\"{block}\">Copy block</button></div>\
                 <div><code>{allow}</code> <button type=\"button\" data-copy=\"{allow}\">Copy allow</button></div>\
                 </div></details>"
            );
        }
        None => out.push_str("<span class=\"muted\" title=\"name too long or not a hostname\">-</span>"),
    }
    out.push_str("</td></tr>");
    out
}

fn input(out: &mut String, label: &str, name: &str, value: &str, placeholder: &str) {
    let _ = write!(out, "<label>{label}<input name=\"{name}\" value=\"");
    esc_into(out, value);
    let _ = write!(out, "\" placeholder=\"{placeholder}\" maxlength=\"253\" autocomplete=\"off\"></label>");
}

pub fn log_page(log: &QueryLog, lists: &[SourceStatus], query: &str) -> String {
    let get = |key| querylog::param(query, key).unwrap_or_default();
    let mut form = String::new();
    input(&mut form, "Client", "client", &get("client"), "192.168.1.");
    input(&mut form, "Domain", "q", &get("q"), "contains");
    form.push_str("<label>Result<select name=\"result\"><option value=\"\">any</option>");
    let result = get("result");
    for o in Outcome::ALL {
        let sel = if o.label() == result { " selected" } else { "" };
        let _ = write!(form, "<option{sel}>{}</option>", o.label());
    }
    form.push_str("</select></label>");
    input(&mut form, "Type", "qtype", &get("qtype"), "A, AAAA");
    let mut rows = String::new();
    // Newest first, like the live tail that prepends to it.
    for e in log.recent(&Filter::from_query(query), PAGE_ROWS) {
        rows.push_str(&row_html(log, lists, &e));
    }
    let note = if log.enabled() { "" } else { "The query log is off (query_log_capacity = 0)." };
    shell("log", &fill(LOG, &[("form", &form), ("rows", &rows), ("note", note)]))
}

pub fn log_json(log: &QueryLog, lists: &[SourceStatus], query: &str) -> String {
    let limit = querylog::param(query, "limit").and_then(|v| v.parse().ok()).unwrap_or(PAGE_ROWS).clamp(1, 1000);
    let entries = log.recent(&Filter::from_query(query), limit);
    let mut out = String::with_capacity(256 + entries.len() * 200);
    let _ = write!(out, "{{\"enabled\":{},\"capacity\":{},\"entries\":[", log.enabled(), log.capacity());
    for (i, e) in entries.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let _ = write!(out, "{{\"time_ms\":{},\"client\":\"{}\",\"name\":", log.unix_ms(e), e.ip);
        json_str(&mut out, &e.text());
        let _ = write!(
            out,
            ",\"truncated\":{},\"qtype\":\"{}\",\"result\":\"{}\",\"upstream\":",
            e.truncated,
            querylog::qtype_name(e.qtype),
            e.outcome.label()
        );
        match e.upstream {
            querylog::NO_UPSTREAM => out.push_str("null"),
            querylog::PLAIN_UPSTREAM => out.push_str("\"fallback\""),
            n => {
                let _ = write!(out, "{n}");
            }
        }
        let _ = write!(out, ",\"latency_us\":{},\"list\":", e.latency_us);
        match e.list {
            Some(id) => {
                let _ = write!(out, "{{\"id\":{id},\"name\":");
                json_str(&mut out, &list_name(lists, id));
                out.push('}');
            }
            None => out.push_str("null"),
        }
        out.push_str(",\"allow_rule\":");
        match e.rule_domain() {
            Some(d) => {
                json_str(&mut out, &format!("@@||{d}^$important"));
                out.push_str(",\"block_rule\":");
                json_str(&mut out, &format!("||{d}^"));
            }
            None => out.push_str("null,\"block_rule\":null"),
        }
        out.push('}');
    }
    out.push_str("]}");
    out
}

static STREAMS: AtomicUsize = AtomicUsize::new(0);

/// Holds one of the [`MAX_STREAMS`] live-tail slots.
struct StreamSlot;

impl StreamSlot {
    fn take() -> Option<Self> {
        STREAMS.try_update(Relaxed, Relaxed, |n| (n < MAX_STREAMS).then_some(n + 1)).ok().map(|_| Self)
    }
}

impl Drop for StreamSlot {
    fn drop(&mut self) {
        STREAMS.fetch_sub(1, Relaxed);
    }
}

/// `/api/log/stream`: Server-Sent Events, one `data:` row (HTML `<tr>`) per
/// new matching entry, polled every [`querylog::TICK`] with a cursor of its
/// own. A client that stops reading fills an 8-chunk queue and is dropped, not
/// buffered; the stream also ends after [`STREAM_LIFETIME`] and the browser
/// reconnects. At most [`MAX_STREAMS`] run at once.
pub fn stream(log: &'static QueryLog, lists: Arc<Vec<SourceStatus>>, query: &str) -> Reply {
    stream_every(log, lists, query, querylog::TICK)
}

fn stream_every(
    log: &'static QueryLog,
    lists: Arc<Vec<SourceStatus>>,
    query: &str,
    tick: std::time::Duration,
) -> Reply {
    if !log.enabled() {
        return Reply::new(404, "text/plain; charset=utf-8", "query log disabled\n");
    }
    let Some(slot) = StreamSlot::take() else {
        return Reply::new(503, "text/plain; charset=utf-8", "too many live streams\n");
    };
    let (tx, rx) = mpsc::channel::<Bytes>(STREAM_QUEUE);
    let _ = tx.try_send(Bytes::from_static(b"retry: 3000\n\n"));
    let filter = Filter::from_query(query);
    tokio::spawn(async move {
        let _slot = slot;
        let mut cursor = log.cursor();
        let mut ticker = tokio::time::interval(tick);
        let end = tokio::time::Instant::now() + STREAM_LIFETIME;
        let mut idle = 0u32;
        loop {
            tokio::select! {
                _ = tx.closed() => return,
                _ = ticker.tick() => {}
            }
            if tokio::time::Instant::now() >= end {
                return;
            }
            let mut batch = Vec::new();
            log.read_new(&mut cursor, &mut batch);
            batch.retain(|e| filter.matches(e));
            batch.sort_unstable_by_key(|e| e.t_us);
            let skip = batch.len().saturating_sub(TICK_ROWS);
            let mut chunk = String::new();
            for e in &batch[skip..] {
                let _ = writeln!(chunk, "data: {}\n", row_html(log, &lists, e));
            }
            if chunk.is_empty() {
                // A comment every ~15 s keeps proxies and the browser from
                // timing out an idle but healthy stream.
                idle += 1;
                if !idle.is_multiple_of(30) {
                    continue;
                }
                chunk.push_str(": keep-alive\n\n");
            }
            if tx.try_send(Bytes::from(chunk)).is_err() {
                return;
            }
        }
    });
    let mut reply = Reply::new(200, "text/event-stream", "");
    reply.stream = Some(rx);
    reply
}

// -------------------------------------------------------------------- rules

/// Lines the rule editor checks; the rest is ignored and the page says so.
const MAX_EDIT_LINES: usize = 5000;
/// Error rows the editor lists (all of them are counted).
const MAX_EDIT_ERRORS: usize = 100;
/// Rows of any table on the rules and clients pages.
const MAX_ROWS: usize = 500;
/// Query types the tester offers.
const TEST_TYPES: [&str; 12] = ["A", "AAAA", "CNAME", "MX", "NS", "PTR", "SOA", "SRV", "TXT", "HTTPS", "CAA", "DS"];

fn copy_button(out: &mut String, text: &str, label: &str) {
    out.push_str("<button type=\"button\" data-copy=\"");
    esc_into(out, text);
    let _ = write!(out, "\">{label}</button>");
}

/// `<code>text</code>` plus its copy button.
fn code_copy(out: &mut String, text: &str, label: &str) {
    out.push_str("<code>");
    esc_into(out, text);
    out.push_str("</code> ");
    copy_button(out, text, label);
}

/// What the editor made of pasted rules.
#[derive(Default, Debug, PartialEq, Eq)]
pub struct Validation {
    /// Normalized rules, in order, without duplicates.
    pub rules: Vec<String>,
    /// `(line, text, problem)` for the first `MAX_EDIT_ERRORS` bad lines.
    pub errors: Vec<(usize, String, &'static str)>,
    pub error_count: usize,
    /// Blank and comment lines.
    pub ignored: usize,
    pub duplicates: usize,
    /// More than `MAX_EDIT_LINES` lines: the rest was not read.
    pub cut: bool,
}

/// Checks pasted rules with the parser the blocklists use ([`rules::parse_rule`]).
pub fn validate_rules(text: &str) -> Validation {
    let mut v = Validation::default();
    let mut seen = std::collections::HashSet::new();
    for (index, line) in text.lines().enumerate() {
        if index == MAX_EDIT_LINES {
            v.cut = true;
            break;
        }
        match rules::parse_rule(line) {
            Ok(None) => v.ignored += 1,
            Ok(Some((name, flags))) => {
                let rule = rules::rule_text(&name, flags);
                if seen.contains(&rule) {
                    v.duplicates += 1;
                } else {
                    seen.insert(rule.clone());
                    v.rules.push(rule);
                }
            }
            Err(problem) => {
                v.error_count += 1;
                if v.errors.len() < MAX_EDIT_ERRORS {
                    v.errors.push((index + 1, clip(line.trim()), problem));
                }
            }
        }
    }
    v
}

/// One rule that matches the tested name.
#[derive(Debug, PartialEq, Eq)]
pub struct RuleRow {
    /// [`rules::rank`] of the rule.
    pub rank: u8,
    pub exact: bool,
    /// The normalized rule (what to paste into the config).
    pub rule: String,
    /// The source line, when it differs from `rule`.
    pub source: Option<String>,
    /// The list that holds it; `None` when the source text was not found and
    /// the table cannot say which of several lists it came from.
    pub list: Option<u16>,
    pub line: Option<usize>,
    /// False for an exact-host rule on a parent of the name.
    pub applies: bool,
    /// The strongest applicable rule: the one that decides among rules.
    pub wins: bool,
}

/// The matching rules in priority order. `matches` is [`rules::Rules::explain`]
/// (the table, most specific parent first) and is the authority on what
/// matches; `hits` (the source scan) only add the list, line and source text.
/// A rule the scan did not find is still listed in its normalized form.
pub fn rule_rows(name: &str, matches: &[rules::Match], hits: &[RuleHit]) -> Vec<RuleRow> {
    let mut rows = Vec::new();
    for (specificity, m) in matches.iter().enumerate() {
        for bit in rules::class_bits(m.flags) {
            let rule = rules::rule_text(&m.parent, bit);
            let exact = rules::is_exact(bit);
            let applies = !exact || m.parent == name;
            let found: Vec<_> = hits.iter().filter(|h| h.parent == m.parent && h.flags == bit).collect();
            let base = RuleRow {
                rank: rules::rank(bit),
                exact,
                rule: rule.clone(),
                source: None,
                list: None,
                line: None,
                applies,
                wins: false,
            };
            if found.is_empty() {
                // The merged table keeps one list per name: the one of its
                // strongest class. Other classes have no known list.
                let list = (rules::rank(bit) == rules::rank(m.flags)).then_some(m.list_id);
                rows.push((specificity, RuleRow { list, ..base }));
            }
            for hit in found {
                let source = (hit.text != rule).then(|| hit.text.clone());
                rows.push((
                    specificity,
                    RuleRow { source, list: Some(hit.list_id), line: Some(hit.line), rule: rule.clone(), ..base },
                ));
            }
        }
    }
    rows.sort_by_key(|(specificity, r)| (!r.applies, std::cmp::Reverse(r.rank), *specificity, r.list, r.line));
    let mut rows: Vec<_> = rows.into_iter().map(|(_, row)| row).collect();
    if let Some(first) = rows.first_mut().filter(|r| r.applies) {
        first.wins = true;
    }
    rows
}

fn rank_label(rank: u8) -> &'static str {
    match rank {
        4 => "allow, important",
        3 => "block, important",
        2 => "allow",
        _ => "block",
    }
}

/// The form fields echoed back after a test.
#[derive(Default)]
pub struct TestForm {
    pub name: String,
    pub qtype: String,
    pub client: String,
}

/// What the tester decided, filled by the server from the real decision code.
#[derive(Default)]
pub struct Tested {
    /// Set when the input was refused before any decision.
    pub error: Option<String>,
    /// Short label (`Blocked`, `Forwarded`, ...) and its tag colour.
    pub verdict: String,
    pub class: &'static str,
    /// The reply the client would get, e.g. `NXDOMAIN` or `NOERROR 192.0.2.7`.
    pub answer: String,
    pub detail: String,
    pub notes: Vec<String>,
    pub rows: Vec<RuleRow>,
    /// The source scan finished: a row without a line number is then known to
    /// have no source text left (the table is newer than the cached list).
    pub scan_complete: bool,
    /// The name as a rule domain, when it can be one (offers block/allow rules).
    pub rule_domain: Option<String>,
}

/// Everything the rules page shows.
pub struct RulesPage<'a> {
    pub lists: &'a [SourceStatus],
    pub user_rules: &'a [String],
    /// Sorted rewrite table: pattern and address.
    pub rewrites: Vec<(&'a str, std::net::IpAddr)>,
    pub form: TestForm,
    pub tested: Option<Tested>,
    /// The text submitted to the editor; `None` shows the current user rules.
    pub editor: Option<String>,
}

fn tested_html(out: &mut String, t: &Tested, lists: &[SourceStatus]) {
    out.push_str("<div id=\"result\" class=\"result\">");
    if let Some(error) = &t.error {
        out.push_str("<p><span class=\"tag bad\">Not tested</span> ");
        esc_into(out, error);
        out.push_str("</p></div>");
        return;
    }
    let _ = write!(out, "<p class=\"verdict\"><span class=\"tag {}\">", t.class);
    esc_into(out, &t.verdict);
    out.push_str("</span> <strong>");
    esc_into(out, &t.answer);
    out.push_str("</strong></p><p>");
    esc_into(out, &t.detail);
    out.push_str("</p>");
    if !t.notes.is_empty() {
        out.push_str("<ul class=\"muted\">");
        for note in &t.notes {
            out.push_str("<li>");
            esc_into(out, note);
            out.push_str("</li>");
        }
        out.push_str("</ul>");
    }
    if t.rows.is_empty() {
        out.push_str("<p class=\"muted\">No blocklist rule matches this name.</p>");
    } else {
        out.push_str(
            "<h3>Matching rules, strongest first</h3><div class=\"scroll\"><table><thead><tr><th>Rule</th><th>List</th>\
             <th>Status</th></tr></thead><tbody>",
        );
        for r in &t.rows {
            out.push_str("<tr><td class=\"wrap\">");
            code_copy(out, &r.rule, "Copy");
            if let Some(source) = &r.source {
                out.push_str("<div class=\"muted\">in the list as <code>");
                esc_into(out, source);
                out.push_str("</code></div>");
            }
            let kind = if r.exact { "exact host, " } else { "" };
            let _ = write!(out, "<div class=\"muted\">{kind}{}</div></td><td class=\"wrap\">", rank_label(r.rank));
            match r.list {
                Some(id) => {
                    esc_into(out, &list_name(lists, id));
                    if let Some(line) = r.line {
                        let _ = write!(out, " <span class=\"muted\">line {line}</span>");
                    }
                }
                None => out.push_str("<span class=\"muted\">unknown</span>"),
            }
            out.push_str("</td><td>");
            let colour = if r.rank % 2 == 0 { "ok" } else { "bad" };
            let status = match (r.wins, r.applies) {
                (true, _) => format!("<span class=\"tag {colour}\">decides</span>"),
                (false, true) => "<span class=\"muted\">overridden</span>".to_string(),
                (false, false) => "<span class=\"muted\">no match: applies to that exact host only</span>".to_string(),
            };
            let _ = write!(out, "{status}</td></tr>");
        }
        out.push_str("</tbody></table></div>");
        if !t.scan_complete {
            out.push_str(
                "<p class=\"muted\">The list text could not be fully re-read (size or time cap, or another lookup was \
                 running), so some rows show only the normalized rule and an unknown list.</p>",
            );
        }
    }
    if let Some(domain) = &t.rule_domain {
        out.push_str("<h3>Rules for this name</h3><p>");
        code_copy(out, &format!("||{domain}^"), "Copy block");
        out.push_str("</p><p>");
        code_copy(out, &format!("@@||{domain}^$important"), "Copy allow");
        out.push_str("</p>");
    }
    out.push_str("</div>");
}

fn validation_html(out: &mut String, v: &Validation) {
    let _ = write!(
        out,
        "<div id=\"validation\" class=\"result\"><p><span class=\"tag {}\">{}</span> {} rule{} accepted, {} error{}, {} blank or comment line{}",
        if v.error_count == 0 { "ok" } else { "bad" },
        if v.error_count == 0 { "Valid" } else { "Errors" },
        v.rules.len(),
        if v.rules.len() == 1 { "" } else { "s" },
        v.error_count,
        if v.error_count == 1 { "" } else { "s" },
        v.ignored,
        if v.ignored == 1 { "" } else { "s" },
    );
    if v.duplicates > 0 {
        let _ = write!(out, ", {} duplicate{} dropped", v.duplicates, if v.duplicates == 1 { "" } else { "s" });
    }
    out.push_str(".</p>");
    if v.cut {
        let _ = write!(out, "<p class=\"muted\">Only the first {MAX_EDIT_LINES} lines were checked.</p>");
    }
    if !v.errors.is_empty() {
        out.push_str("<div class=\"scroll\"><table class=\"wide\"><thead><tr><th class=\"num\">Line</th><th>Text</th><th>Problem</th></tr></thead><tbody>");
        for (line, text, problem) in &v.errors {
            let _ = write!(out, "<tr><td class=\"num\">{line}</td><td class=\"mono wrap\">");
            esc_into(out, text);
            let _ = write!(out, "</td><td>{problem}</td></tr>");
        }
        out.push_str("</tbody></table></div>");
        if v.error_count > v.errors.len() {
            let _ = write!(out, "<p class=\"muted\">{} more not listed.</p>", v.error_count - v.errors.len());
        }
    }
    if !v.rules.is_empty() {
        let lines = v.rules.join("\n");
        let toml = format!(
            "user_rules = [\n{}]\n",
            v.rules.iter().fold(String::new(), |acc, r| acc + &format!("  \"{r}\",\n"))
        );
        out.push_str("<h3>Normalized rules</h3><pre>");
        esc_into(out, &lines);
        out.push_str("</pre><p>");
        copy_button(out, &lines, "Copy rules");
        out.push(' ');
        copy_button(out, &toml, "Copy as user_rules");
        out.push_str("</p>");
    }
    out.push_str("</div>");
}

pub fn rules_page(p: &RulesPage<'_>) -> String {
    let mut c = String::with_capacity(8192);
    c.push_str(
        "<section class=\"card\"><h2>Test a domain</h2>\
         <p class=\"muted\">Shows what the server would answer, using the same decision code, in the same order: \
         rewrite, local zone and special-use names, blocklist (not for a <code>no_filter</code> client), then the \
         cache and upstreams. Nothing is sent upstream or counted.</p>\
         <form class=\"filters\" method=\"post\" action=\"/rules#result\">",
    );
    input(&mut c, "Domain", "name", &p.form.name, "ads.example.com");
    c.push_str("<label>Type<select name=\"qtype\">");
    for t in TEST_TYPES {
        let selected = if t == p.form.qtype { " selected" } else { "" };
        let _ = write!(c, "<option{selected}>{t}</option>");
    }
    c.push_str("</select></label>");
    input(&mut c, "Client IP (optional)", "client", &p.form.client, "192.168.1.20");
    c.push_str("<button type=\"submit\">Test</button></form>");
    if let Some(tested) = &p.tested {
        tested_html(&mut c, tested, p.lists);
    }
    c.push_str("</section>");

    c.push_str(
        "<section class=\"card\"><h2>User rules</h2>\
         <p class=\"muted\">Check rules with the parser the server uses. Nothing is saved: copy the result into \
         <code>user_rules</code> in the ConfigMap. The box starts with the current user rules.</p>\
         <form method=\"post\" action=\"/rules#validation\"><textarea name=\"rules\" rows=\"10\" maxlength=\"16000\" \
         spellcheck=\"false\" autocomplete=\"off\" aria-label=\"User rules, one per line\">",
    );
    match &p.editor {
        Some(text) => esc_into(&mut c, text),
        None => esc_into(&mut c, &p.user_rules.join("\n")),
    }
    c.push_str("</textarea><p><button type=\"submit\">Validate</button></p></form>");
    if let Some(text) = &p.editor {
        validation_html(&mut c, &validate_rules(text));
    }
    c.push_str("</section>");

    c.push_str("<section class=\"card\"><h2>Rewrites</h2>");
    if p.rewrites.is_empty() {
        c.push_str("<p class=\"muted\">No rewrites configured.</p>");
    } else {
        c.push_str("<div class=\"scroll\"><table><thead><tr><th>Name</th><th>Answer</th><th></th></tr></thead><tbody>");
        for (name, ip) in p.rewrites.iter().take(MAX_ROWS) {
            c.push_str("<tr><td class=\"mono wrap\">");
            esc_into(&mut c, name);
            let _ = write!(c, "</td><td class=\"mono\">{ip}</td><td>");
            copy_button(&mut c, &format!("\"{name}\" = \"{ip}\""), "Copy");
            c.push_str("</td></tr>");
        }
        c.push_str("</tbody></table></div>");
        if p.rewrites.len() > MAX_ROWS {
            let _ = write!(c, "<p class=\"muted\">{} more not shown.</p>", p.rewrites.len() - MAX_ROWS);
        }
    }
    c.push_str("<p class=\"muted\">A <code>*.</code> name matches subdomains, after exact names. Edit <code>[rewrites]</code> in the config to change them.</p></section>");
    shell("rules", &c)
}

// ------------------------------------------------------------------ clients

/// One known client.
#[derive(Debug, PartialEq, Eq)]
pub struct ClientRow {
    pub ip: IpAddr,
    pub name: Option<String>,
    pub mac: Option<[u8; 6]>,
    /// Why filtering is off for this client; `None` means it is filtered.
    pub bypass: Option<&'static str>,
    /// Queries counted by the query log's client sketch, if it saw the client.
    pub queries: Option<u64>,
}

fn fmt_mac(mac: [u8; 6]) -> String {
    mac.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}

/// The known clients: the busiest ones from the log's sketch (at most
/// [`querylog::TOP_K`]), the configured `no_filter_clients` and
/// `client_names`, and neighbours whose MAC is in `no_filter_macs`. The
/// filtering state comes from [`ArpTable::is_no_filter`], the server's own
/// check. Busiest first; at most `MAX_ROWS`.
pub fn clients_rows(top: &[Top], cfg: &Config, arp: &ArpTable) -> Vec<ClientRow> {
    let mut by_ip: HashMap<IpAddr, Option<u64>> = HashMap::new();
    for t in top {
        if let Ok(ip) = querylog::key_client(&t.key).parse::<IpAddr>() {
            by_ip.insert(ip, Some(t.count));
        }
    }
    for ip in &cfg.no_filter_clients {
        by_ip.entry(*ip).or_insert(None);
    }
    for key in cfg.client_names.keys() {
        if let Ok(ip) = key.trim().parse::<IpAddr>() {
            by_ip.entry(ip).or_insert(None);
        }
    }
    for (ip, _) in arp.with_macs(&cfg.no_filter_mac_addrs) {
        by_ip.entry(ip).or_insert(None);
    }
    let mut rows: Vec<ClientRow> = by_ip
        .into_iter()
        .map(|(ip, queries)| {
            let mac = arp.get(ip);
            let bypass = if !arp.is_no_filter(ip, &cfg.no_filter_clients, &cfg.no_filter_mac_addrs) {
                None
            } else if cfg.no_filter_clients.contains(&ip) {
                Some("no_filter_clients")
            } else {
                Some("no_filter_macs")
            };
            let name = cfg
                .client_names
                .iter()
                .find(|(key, _)| key.trim().parse::<IpAddr>().is_ok_and(|k| k == ip))
                .map(|(_, name)| clip(name));
            ClientRow { ip, name, mac, bypass, queries }
        })
        .collect();
    rows.sort_by_key(|r| (std::cmp::Reverse(r.queries.unwrap_or(0)), r.ip));
    rows.truncate(MAX_ROWS);
    rows
}

pub fn clients_html(rows: &[ClientRow], log_enabled: bool) -> String {
    let mut c = String::with_capacity(4096);
    c.push_str("<section class=\"card\"><h2>Clients</h2>");
    if rows.is_empty() {
        let _ = write!(
            c,
            "<p class=\"muted\">{}</p>",
            if log_enabled {
                "No client has queried yet."
            } else {
                "The query log is off (query_log_capacity = 0), so clients are not counted."
            }
        );
    } else {
        c.push_str(
            "<div class=\"scroll\"><table><thead><tr><th>Client</th><th>Filtering</th>\
             <th class=\"num\">Queries</th></tr></thead><tbody>",
        );
        for r in rows {
            let _ = write!(c, "<tr><td><span class=\"mono\">{}</span>", r.ip);
            if let Some(name) = &r.name {
                c.push_str("<div class=\"wrap\">");
                esc_into(&mut c, name);
                c.push_str("</div>");
            }
            if let Some(mac) = r.mac {
                let _ = write!(c, "<div class=\"muted mono\">{}</div>", fmt_mac(mac));
            }
            let filtering = match r.bypass {
                Some(why) => format!("<span class=\"tag warn\">off</span> <span class=\"muted\">{why}</span>"),
                None => "<span class=\"tag ok\">on</span>".to_string(),
            };
            let queries = r.queries.map_or("-".to_string(), |n| n.to_string());
            let _ = write!(c, "</td><td>{filtering}</td><td class=\"num\">{queries}</td></tr>");
        }
        c.push_str("</tbody></table></div>");
    }
    c.push_str(
        "<p class=\"muted\">Queries are counted by the query log since the server started, from a bounded sketch of the \
         100 busiest clients (counts are approximate and quiet clients may be missing). MAC comes from the kernel ARP \
         table (IPv4, Linux only). Names come from <code>client_names</code>; filtering is off for \
         <code>no_filter_clients</code> and <code>no_filter_macs</code>. Read-only: edit the config to change them.</p></section>",
    );
    shell("clients", &c)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{clock::Instant, querylog::Record};
    use std::time::Duration;

    fn wire(labels: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for label in labels {
            out.push(label.len() as u8);
            out.extend_from_slice(label);
        }
        out.push(0);
        out
    }

    fn log_with(name: &[u8], outcome: Outcome, list: Option<u16>) -> (QueryLog, Entry) {
        let log = QueryLog::with_shards(8, 1);
        let q = Record { ip: "10.0.0.9".parse().unwrap(), qname: name, qtype: 1, outcome, upstream: 0, list };
        log.write(Instant::now(), Duration::from_micros(1500), &q);
        let entry = log.recent(&Filter::default(), 1).remove(0);
        (log, entry)
    }

    fn source(id: u16, name: &str) -> SourceStatus {
        SourceStatus {
            id,
            name: name.to_string(),
            rules: 5,
            skipped: 0,
            last_success: Some(100),
            last_error: None,
            used_cache: false,
        }
    }

    #[test]
    fn escape_covers_html_metacharacters() {
        assert_eq!(esc("<a href=\"x\" onclick='y'>&"), "&lt;a href=&quot;x&quot; onclick=&#39;y&#39;&gt;&amp;");
        let mut out = String::new();
        json_str(&mut out, "a\"b\\c</script>\n\u{7f}&");
        assert_eq!(out, "\"a\\\"b\\\\c\\u003c/script\\u003e\\u000a\\u007f\\u0026\"");
    }

    /// DNS labels may hold any byte: markup in a qname must reach neither the
    /// page, the SSE row nor the JSON as live HTML.
    #[test]
    fn hostile_qnames_are_inert_in_every_output() {
        let evil: &[u8] = b"<img/src=x/onerror=alert(1)>";
        let name = wire(&[evil, b"\"><script>alert(2)</script>", b"test"]);
        let (log, entry) = log_with(&name, Outcome::Blocked, Some(1));
        // A list name is attacker-influenced too (a URL's file name segment).
        let lists = [source(1, "https://h/<b>x</b>.txt")];
        let row = row_html(&log, &lists, &entry);
        let page = log_page(&log, &lists, "q=%3Cimg&client=%22%3E%3Cscript%3E");
        for html in [&row, &page] {
            assert!(!html.contains("<img"), "{html}");
            assert!(!html.contains("<script>alert"), "{html}");
            assert!(!html.contains("<b>x"), "{html}");
        }
        assert!(row.contains("&lt;img/src=x/onerror=alert(1)&gt;"), "{row}");
        assert!(page.contains("value=\"&quot;&gt;&lt;script&gt;\""), "the filter echo is escaped: {page}");
        assert!(!row.contains('\n'), "an SSE data line has no newline");
        let json = log_json(&log, &lists, "");
        assert!(!json.contains('<') && !json.contains("onerror=alert(1)>"), "{json}");
        assert!(json.contains("\\u003cimg/src=x/onerror=alert(1)\\u003e"), "{json}");
        // The name holds `<` but no escape sequence, so a rule would still be
        // offered, and the rule text lands in a quoted, escaped attribute.
        assert!(row.contains("data-copy=\"||&lt;img"), "{row}");
    }

    /// An echoed filter value that spells a template slot stays literal text:
    /// slots are filled once, so a value can never pull the rows (or anything
    /// else) in again and blow the page up.
    #[test]
    fn echoed_values_are_never_expanded_as_slots() {
        let (log, _) = log_with(&wire(&[b"a", b"test"]), Outcome::Blocked, Some(1));
        let bomb = "{{rows}}".repeat(40);
        // An unknown type filters nothing, so the one row is on the page.
        let page = log_page(&log, &[], &format!("qtype={bomb}{{{{content}}}}{{{{note}}}}"));
        assert!(page.contains(&format!("value=\"{bomb}{{{{content}}}}{{{{note}}}}\"")), "{page}");
        assert_eq!(page.matches("<time data-ms").count(), 1, "the row appears once");
        assert!(page.len() < 20_000, "{}", page.len());
    }

    #[test]
    fn rule_actions_follow_the_option_a_syntax() {
        let (log, entry) = log_with(&wire(&[b"ads", b"example", b"org"]), Outcome::Blocked, Some(0));
        let row = row_html(&log, &[], &entry);
        assert!(row.contains("||ads.example.org^"));
        assert!(row.contains("@@||ads.example.org^$important"));
        assert!(row.contains("user rules"), "list 0 is the inline rules: {row}");
        let json = log_json(&log, &[], "result=blocked");
        assert!(json.contains("\"allow_rule\":\"@@||ads.example.org^$important\""), "{json}");
        assert!(json.contains("\"list\":{\"id\":0,\"name\":\"user rules\"}"), "{json}");
        assert!(log_json(&log, &[], "result=cache").contains("\"entries\":[]"));
        // Escaped (non-hostname) and cut names offer no rule.
        let (log, entry) = log_with(&wire(&[b"a.b", b"test"]), Outcome::Cache, None);
        assert!(row_html(&log, &[], &entry).contains("title=\"name too long"));
    }

    /// A client that never reads fills its 8-chunk queue and is dropped: the
    /// producer exits and frees its slot instead of buffering without bound.
    /// Another client keeps receiving, and the slot cap holds.
    #[tokio::test]
    async fn slow_consumer_is_dropped_and_streams_are_capped() {
        let log: &'static QueryLog = Box::leak(Box::new(QueryLog::with_shards(64, 1)));
        let tick = Duration::from_millis(5);
        let name = wire(&[b"live", b"test"]);
        let write = |i: u16| {
            let q = Record {
                ip: "10.0.0.9".parse().unwrap(),
                qname: &name,
                qtype: i,
                outcome: Outcome::Cache,
                upstream: querylog::NO_UPSTREAM,
                list: None,
            };
            log.write(Instant::now(), Duration::ZERO, &q);
        };
        let mut slow = stream_every(log, Arc::new(Vec::new()), "", tick);
        let mut fast = stream_every(log, Arc::new(Vec::new()), "q=live", tick);
        assert_eq!(slow.status, 200);
        // Two more fill the cap; the next is refused.
        let _third = stream_every(log, Arc::new(Vec::new()), "", Duration::from_secs(60));
        let _fourth = stream_every(log, Arc::new(Vec::new()), "", Duration::from_secs(60));
        assert_eq!(stream_every(log, Arc::new(Vec::new()), "", tick).status, 503);
        let mut fast_rx = fast.stream.take().unwrap();
        let _slow_rx = slow.stream.take().unwrap();
        let mut got = 0;
        for i in 0..200u16 {
            write(i);
            tokio::time::sleep(Duration::from_millis(8)).await;
            while let Ok(chunk) = fast_rx.try_recv() {
                got += String::from_utf8_lossy(&chunk).matches("data: <tr>").count();
            }
            if STREAMS.load(Relaxed) < 4 {
                break;
            }
        }
        assert_eq!(STREAMS.load(Relaxed), 3, "only the stalled stream was dropped");
        assert!(got > 0, "the reader still gets rows");
        drop(fast_rx);
        for _ in 0..100 {
            if STREAMS.load(Relaxed) == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(STREAMS.load(Relaxed), 2, "a closed stream frees its slot");
    }

    #[test]
    fn host_guard_accepts_only_ip_literals_and_localhost() {
        for ok in ["127.0.0.1:9999", "[::1]:9999", "localhost", "LOCALHOST:80", "10.1.2.3", "localhost.:1"] {
            assert!(host_ok(Some(ok)), "{ok}");
        }
        assert!(!host_ok(None), "no Host, no proof of the name in use");
        for bad in [
            "evil.example",
            "evil.example:9999",
            "127.0.0.1.evil.example",
            "localhost.evil.test",
            "",
            // Text after the closing bracket is not part of an IP literal.
            "[::1]evil.example",
            "[::1]:99x",
            "[::1",
        ] {
            assert!(!host_ok(Some(bad)), "{bad}");
        }
    }

    #[test]
    fn dashboard_json_never_carries_secrets_and_clips_errors() {
        let log = QueryLog::with_shards(8, 1);
        let board = log.board(Instant::now(), &crate::stats::Stats::new().snapshot());
        let lists = [SourceStatus { last_error: Some("x".repeat(500)), ..source(1, "https://h/list.txt") }];
        let upstreams = [UpstreamHealth {
            index: 0,
            url: "https://dns.example".into(),
            healthy: false,
            ewma_us: 1200,
            outstanding: 0,
            wins: 3,
            hedges: 0,
            last_error: Some("timeout".into()),
        }];
        let d =
            Dash { board, log_enabled: true, lists: &lists, upstreams: &upstreams, now_unix: 200, plain_fallback: 7 };
        let json = dashboard_json(&d);
        assert!(json.contains("\"win_share\":100.0") && json.contains("\"healthy\":false"), "{json}");
        assert!(json.contains("\"plain_fallback_answers\":7"), "{json}");
        assert!(json.contains("\"status\":\"error\""), "{json}");
        assert!(!json.contains(&"x".repeat(201)), "errors are clipped");
        let html = dashboard_html(&d);
        assert!(html.contains("circuit open") && html.contains("Top blocked"));
        assert!(html.contains("degraded</span> 7 answers"), "the plaintext downgrade is visible");
        assert!(!html.contains("{{"), "every placeholder is filled");
    }

    #[test]
    fn the_editor_reports_line_numbers_normalizes_and_is_bounded() {
        let v = validate_rules(
            "||a.test^\r\n! comment\n\nplain.test\n||a.test^\n||x^$third-party\n|y.test\n@@|z.test^|\nbad name\n0.0.0.0 h.test",
        );
        assert_eq!(v.rules, ["||a.test^", "||plain.test^", "@@|z.test^", "|h.test^"]);
        assert_eq!((v.ignored, v.duplicates, v.error_count), (2, 1, 3));
        let lines: Vec<_> = v.errors.iter().map(|e| e.0).collect();
        assert_eq!(lines, [6, 7, 9], "1-based, counted over blank and comment lines");
        assert!(v.errors[0].2.contains("modifier") && v.errors[1].2.contains('^'));

        let many = "bad rule\n".repeat(MAX_EDIT_LINES + 10);
        let v = validate_rules(&many);
        assert!(v.cut);
        assert_eq!((v.error_count, v.errors.len()), (MAX_EDIT_LINES, MAX_EDIT_ERRORS));
        assert!(validate_rules("").rules.is_empty());
    }

    fn explain_from(lines: &[&str], name: &str) -> Vec<rules::Match> {
        rules::Rules::from_lines(lines, 1).explain(name)
    }

    fn hit(list_id: u16, line: usize, text: &str) -> RuleHit {
        let (parent, flags) = rules::parse_rule(text).unwrap().unwrap();
        RuleHit { list_id, line, text: text.to_string(), parent, flags }
    }

    /// Strongest class first, the winner is the one the matcher decides with,
    /// an exact rule on a parent is listed but does not apply, and a rule the
    /// source scan did not find is still shown (normalized, list unknown unless
    /// it is the merged table's own list).
    #[test]
    fn rule_rows_follow_the_matcher_priority() {
        let lines = ["||a.test^", "@@||b.a.test^", "|a.test^", "||c.b.a.test^$important", "@@||c.b.a.test^$important"];
        let name = "x.c.b.a.test";
        let matches = explain_from(&lines, name);
        let rows = rule_rows(name, &matches, &[hit(1, 2, "@@||b.a.test^")]);
        let order: Vec<_> = rows.iter().map(|r| (r.rule.as_str(), r.rank, r.applies, r.wins)).collect();
        assert_eq!(
            order,
            [
                ("@@||c.b.a.test^$important", 4, true, true),
                ("||c.b.a.test^$important", 3, true, false),
                ("@@||b.a.test^", 2, true, false),
                ("||a.test^", 1, true, false),
                ("|a.test^", 1, false, false),
            ]
        );
        assert_eq!(rows[2].list, Some(1));
        assert_eq!(rows[2].line, Some(2), "a found rule carries its line");
        assert_eq!(rows[3].line, None);
        // The strongest applicable row agrees with the matcher's own decision.
        let table = rules::Rules::from_lines(lines, 1);
        assert!(!table.decision(name).blocked);
        assert_eq!(rows.iter().find(|r| r.wins).map(|r| r.rank % 2), Some(0), "an allow wins, like the table");
        // The exact rule applies on the full name.
        let rows = rule_rows("a.test", &explain_from(&lines, "a.test"), &[]);
        assert!(rows.iter().any(|r| r.exact && r.applies));
        assert!(rule_rows("none.test", &[], &[]).is_empty());
        // The source text shows when it differs from the normalized rule.
        let rows = rule_rows("a.test", &explain_from(&["a.test"], "a.test"), &[hit(1, 7, "a.test")]);
        assert_eq!((rows[0].rule.as_str(), rows[0].source.as_deref()), ("||a.test^", Some("a.test")));
    }

    fn evil() -> String {
        "<img src=x onerror=alert(1)>\"'&".to_string()
    }

    /// Every attacker-influenced string on the rules and clients pages (a name
    /// the user typed, a list name, a pasted rule, a configured client name, a
    /// rewrite key) is escaped, and no page has inline script or style.
    #[test]
    fn rules_and_clients_pages_escape_everything() {
        let bad = evil();
        let lists = [source(1, &format!("https://h/{bad}.txt"))];
        let tested = Tested {
            verdict: bad.clone(),
            class: "bad",
            answer: bad.clone(),
            detail: bad.clone(),
            notes: vec![bad.clone()],
            rows: vec![RuleRow {
                rank: 3,
                exact: false,
                rule: format!("||{bad}^"),
                source: Some(bad.clone()),
                list: Some(1),
                line: Some(2),
                applies: true,
                wins: true,
            }],
            scan_complete: false,
            rule_domain: Some(bad.clone()),
            ..Tested::default()
        };
        let page = rules_page(&RulesPage {
            lists: &lists,
            user_rules: std::slice::from_ref(&bad),
            rewrites: vec![(bad.as_str(), "192.0.2.1".parse().unwrap())],
            form: TestForm { name: bad.clone(), qtype: bad.clone(), client: bad.clone() },
            tested: Some(tested),
            editor: Some(format!("{bad}\n||ok.test^\n</textarea><script>alert(2)</script>")),
        });
        assert!(!page.contains("{{"));
        for needle in ["<img", "<script>alert", "</textarea><script", "onerror=alert(1)>", "<style", " style=\""] {
            assert!(!page.contains(needle), "{needle} in {page}");
        }
        assert!(page.contains("&lt;img src=x onerror=alert(1)&gt;&quot;&#39;&amp;"), "{page}");
        assert!(page.contains("data-copy=\"||&lt;img"), "copy buttons carry escaped text: {page}");
        let invalid = rules_page(&RulesPage {
            lists: &[],
            user_rules: &[],
            rewrites: vec![],
            form: TestForm::default(),
            tested: Some(Tested { error: Some(bad.clone()), ..Tested::default() }),
            editor: None,
        });
        assert!(!invalid.contains("<img") && invalid.contains("&lt;img"), "{invalid}");

        let mut cfg = Config::default();
        cfg.client_names.insert("10.0.0.2".into(), bad.clone());
        let rows = clients_rows(&[], &cfg, &ArpTable::new());
        let html = clients_html(&rows, true);
        assert!(!html.contains("<img") && html.contains("&lt;img"), "{html}");
    }

    #[test]
    fn rules_page_offers_copy_for_every_rule_and_prefills_user_rules() {
        let page = rules_page(&RulesPage {
            lists: &[],
            user_rules: &["||mine.test^".to_string(), "@@||ok.test^".to_string()],
            rewrites: vec![("*.home.test", "192.0.2.9".parse().unwrap())],
            form: TestForm { qtype: "AAAA".into(), ..TestForm::default() },
            tested: Some(Tested {
                verdict: "Blocked".into(),
                class: "bad",
                answer: "NXDOMAIN".into(),
                rule_domain: Some("ads.test".into()),
                ..Tested::default()
            }),
            editor: Some("||a.test^\nbogus rule\n".to_string()),
        });
        assert!(page.contains("<option selected>AAAA</option>"), "{page}");
        assert!(page.contains("data-copy=\"||ads.test^\"") && page.contains("data-copy=\"@@||ads.test^$important\""));
        assert!(page.contains("data-copy=\"&quot;*.home.test&quot; = &quot;192.0.2.9&quot;\""), "{page}");
        assert!(page.contains("<td class=\"num\">2</td>") && page.contains("unsupported rule syntax"), "{page}");
        assert!(page.contains("data-copy=\"user_rules = [\n  &quot;||a.test^&quot;,\n]\n\""), "{page}");
        let fresh = rules_page(&RulesPage {
            lists: &[],
            user_rules: &["||mine.test^".to_string(), "@@||ok.test^".to_string()],
            rewrites: vec![],
            form: TestForm::default(),
            tested: None,
            editor: None,
        });
        assert!(fresh.contains("||mine.test^\n@@||ok.test^</textarea>"), "the editor starts with the current rules");
        assert!(fresh.contains("No rewrites configured") && !fresh.contains("id=\"validation\""));
    }

    #[test]
    fn known_clients_merge_the_sketch_config_and_arp() {
        use std::net::IpAddr;
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let arp = ArpTable::new();
        arp.replace(HashMap::from([(ip("10.0.0.7"), mac), (ip("10.0.0.8"), [1, 2, 3, 4, 5, 6])]));
        let mut cfg =
            Config { no_filter_clients: vec![ip("10.0.0.5")], no_filter_mac_addrs: vec![mac], ..Config::default() };
        cfg.client_names.insert("10.0.0.5".into(), "Living room TV".into());
        cfg.client_names.insert("not an ip".into(), "ignored".into());
        let key = |s: &str| Top { key: querylog::client_key(ip(s)).to_vec().into_boxed_slice(), count: 0, err: 0 };
        let top =
            [Top { count: 90, ..key("10.0.0.8") }, Top { count: 5, ..key("10.0.0.7") }, Top { count: 7, ..key("::1") }];
        let rows = clients_rows(&top, &cfg, &arp);
        let view: Vec<_> =
            rows.iter().map(|r| (r.ip.to_string(), r.queries, r.bypass, r.mac.is_some(), r.name.as_deref())).collect();
        assert_eq!(
            view,
            [
                ("10.0.0.8".to_string(), Some(90), None, true, None),
                ("::1".to_string(), Some(7), None, false, None),
                ("10.0.0.7".to_string(), Some(5), Some("no_filter_macs"), true, None),
                ("10.0.0.5".to_string(), None, Some("no_filter_clients"), false, Some("Living room TV")),
            ]
        );
        let html = clients_html(&rows, true);
        assert!(
            html.contains("aa:bb:cc:dd:ee:ff") && html.contains("no_filter_macs") && html.contains("Living room TV"),
            "{html}"
        );
        assert!(html.contains("<td class=\"num\">90</td>") && html.contains("<td class=\"num\">-</td>"), "{html}");
        assert!(clients_html(&[], false).contains("query log is off"));
        // Bounded: more known clients than the table size are cut.
        let many: Vec<_> = (0..MAX_ROWS as u32 + 50)
            .map(|i| Top { count: 1, ..key(&format!("10.1.{}.{}", i / 250, i % 250)) })
            .collect();
        assert_eq!(clients_rows(&many, &Config::default(), &ArpTable::new()).len(), MAX_ROWS);
    }

    #[test]
    fn every_page_marks_its_nav_entry_and_loads_no_inline_code() {
        for (id, path, _) in PAGES {
            let page = shell(id, "<p>x</p>");
            assert_eq!(page.matches("aria-current=\"page\"").count(), 1, "{id}");
            assert!(page.contains(&format!("<a href=\"{path}\" aria-current=\"page\">")), "{id}: {page}");
            assert!(page.contains(&format!("data-page=\"{id}\"")) && !page.contains("{{"));
        }
    }
}
