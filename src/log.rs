//! Structured `key=value` logging.
//!
//! One line per event on stdout:
//! `ts=<unix> level=<level> msg=<name> key=value ...`. Values (and the message
//! name) are escaped so one event always stays on one line and a value can
//! never forge a field: spaces, quotes, backslashes and control characters
//! become `\x20`, `\"`, `\\`, `\xNN` (or `\u{NN}` above U+00FF).
//!
//! Query logging is opt-in through `log_queries = true`; the hot path never
//! formats a log line otherwise.
//!
//! A DoH or blocklist URL may carry credentials in its userinfo, in a path
//! segment (for example a NextDNS profile id) or in its query string.
//! [`redact_url`] keeps only scheme, host and port so those values never reach
//! stdout, stderr, a log field or a health snapshot. Blocklist status names use
//! [`list_display_name`], which may also keep a trailing file-name segment.

use std::time::{SystemTime, UNIX_EPOCH};

/// Scheme, host and port. Userinfo, path, query and fragment are dropped
/// because a path segment can carry a credential. Returns `None` when the
/// value does not parse as a URL.
fn origin(parsed: &reqwest::Url) -> Option<String> {
    let host = parsed.host_str()?;
    let mut name = format!("{}://{host}", parsed.scheme());
    if let Some(port) = parsed.port() {
        name.push_str(&format!(":{port}"));
    }
    Some(name)
}

/// A URL that is safe for an error message or a health snapshot. An
/// unparseable value becomes `<unparseable URL>` because there is no reliable
/// way to locate the secret inside it.
pub fn redact_url(value: &str) -> String {
    reqwest::Url::parse(value)
        .ok()
        .and_then(|parsed| origin(&parsed))
        .unwrap_or_else(|| "<unparseable URL>".to_string())
}

/// A blocklist display name: the origin plus the final path segment when it
/// ends in a known list extension. That keeps the default lists
/// distinguishable (`filter_1.txt` versus `filter_27.txt`) while dropping
/// token-bearing intermediate segments and dotted tokens such as a JWT.
/// Returns `None` for an unparseable URL.
pub fn list_display_name(value: &str) -> Option<String> {
    const EXTENSIONS: &[&str] = &["txt", "list", "hosts", "conf", "rules", "dat"];
    let parsed = reqwest::Url::parse(value).ok()?;
    let mut name = origin(&parsed)?;
    if let Some(file) = parsed.path_segments().and_then(|mut segments| segments.rfind(|segment| !segment.is_empty())) {
        let extension = file.rsplit_once('.').map(|(_, extension)| extension);
        if extension.is_some_and(|extension| EXTENSIONS.iter().any(|known| known.eq_ignore_ascii_case(extension))) {
            name.push('/');
            name.push_str(file);
        }
    }
    Some(name)
}

/// Current Unix time in seconds. A pre-1970 clock logs `ts=0` rather than
/// failing the request path.
pub fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_secs())
}

/// Writes one structured line to stdout.
pub fn log(level: &str, msg: &str, fields: &[(&str, String)]) {
    #[cfg(feature = "conformance-adapter")]
    {
        // The adapter owns stdout for its JSONL protocol: logs go to stderr,
        // and reload outcomes are counted so `reload` can wait for them.
        use std::sync::atomic::Ordering;
        match msg {
            "config_reloaded" => RELOADED.fetch_add(1, Ordering::SeqCst),
            "config_reload_failed" => RELOAD_FAILED.fetch_add(1, Ordering::SeqCst),
            _ => 0,
        };
        eprintln!("{}", line(now_unix(), level, msg, fields));
    }
    #[cfg(not(feature = "conformance-adapter"))]
    {
        // `println!` panics when stdout is gone (a closed pipe: EPIPE; a full
        // disk), which would kill whichever task logged. A log line is never
        // worth that.
        use std::io::Write;
        let _ = writeln!(std::io::stdout().lock(), "{}", line(now_unix(), level, msg, fields));
    }
}

/// Production reload outcomes seen so far (used by the test-only conformance adapter).
#[cfg(feature = "conformance-adapter")]
pub static RELOADED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
#[cfg(feature = "conformance-adapter")]
pub static RELOAD_FAILED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Formats one line without writing it. Keys are compile-time identifiers and
/// are not escaped; values and the message name go through [`escape`].
pub fn line(ts: u64, level: &str, msg: &str, fields: &[(&str, String)]) -> String {
    let mut out = format!("ts={ts} level={level} msg={}", escape(msg));
    for (key, value) in fields {
        out.push(' ');
        out.push_str(key);
        out.push('=');
        out.push_str(&escape(value));
    }
    out
}

/// Escapes a value so it contains no whitespace, quotes, backslashes or
/// control characters. Printable non-ASCII text is left as is.
pub fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            ' ' => out.push_str("\\x20"),
            character if character.is_control() => {
                if character as u32 <= 0xff {
                    out.push_str(&format!("\\x{:02x}", character as u32));
                } else {
                    out.push_str(&format!("\\u{{{:x}}}", character as u32));
                }
            }
            character => out.push(character),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaping_keeps_one_token_per_value() {
        assert_eq!(escape("plain"), "plain");
        assert_eq!(escape("a b"), r"a\x20b");
        assert_eq!(escape(r#"a"b"#), r#"a\"b"#);
        assert_eq!(escape(r"a\b"), r"a\\b");
        assert_eq!(escape("a\nb"), r"a\x0ab");
        assert_eq!(escape("a\tb"), r"a\x09b");
        assert_eq!(escape("a\u{7f}b"), r"a\x7fb");
        assert_eq!(escape("a\u{85}b"), r"a\x85b");
        assert_eq!(escape("héllo"), "héllo");
    }

    #[test]
    fn a_normal_line_has_the_required_fields() {
        let line = line(1_700_000_000, "info", "config_reloaded", &[("listen", "127.0.0.1:53".into())]);
        assert!(line.starts_with("ts=1700000000 level=info msg=config_reloaded "), "{line}");
        assert!(line.ends_with(" listen=127.0.0.1:53"), "{line}");
        assert!(!line.contains('\n'));
    }

    #[test]
    fn a_message_name_and_value_cannot_forge_a_line() {
        let line = line(7, "warn", "bad msg", &[("error", "x y\nlevel=error".into())]);
        assert_eq!(line, r"ts=7 level=warn msg=bad\x20msg error=x\x20y\x0alevel=error");
        assert_eq!(line.lines().count(), 1);
    }

    #[test]
    fn urls_drop_userinfo_path_query_and_fragment() {
        assert_eq!(redact_url("http://user:pass@example.com/dns-query?token=private"), "http://example.com");
        assert_eq!(
            redact_url("https://user:secret@example.com:8443/lists/ad.txt?token=private#fragment"),
            "https://example.com:8443"
        );
        // An unparseable value is replaced entirely: it cannot be sanitized.
        assert_eq!(redact_url("user:pass@example.com/dns-query?token=private"), "<unparseable URL>");
        assert_eq!(redact_url("not a url"), "<unparseable URL>");
    }

    #[test]
    fn list_display_names_keep_only_a_file_name_segment() {
        assert_eq!(
            list_display_name("https://user:secret@example.com:8443/lists/ad.txt?token=private#fragment").unwrap(),
            "https://example.com:8443/ad.txt"
        );
        // The default lists stay distinguishable.
        assert_eq!(
            list_display_name("https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt").unwrap(),
            "https://adguardteam.github.io/filter_1.txt"
        );
        assert_eq!(
            list_display_name("https://adguardteam.github.io/HostlistsRegistry/assets/filter_27.txt").unwrap(),
            "https://adguardteam.github.io/filter_27.txt"
        );
        // A token-bearing final segment without a dot is dropped.
        assert_eq!(
            list_display_name("https://user:pass@example.com/lists/abc123token?token=private").unwrap(),
            "https://example.com"
        );
        assert_eq!(list_display_name("https://example.com?token=private").unwrap(), "https://example.com");
        assert_eq!(list_display_name("not a url"), None);
    }
}
