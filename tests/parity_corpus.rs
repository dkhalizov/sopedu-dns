//! Differential parity test: `Rules::blocked` versus AdGuard Home's recorded
//! decisions in the private query corpus.
//!
//! Opt in with `SOPEDU_PARITY=1`. Without it the test skips, so public CI
//! without private data stays green. With the flag set an unreadable or
//! non-UTF-8 corpus fails instead of skipping; the test still skips when a
//! blocklist cannot be fetched.
//!
//! The corpus and every derived file are private browsing data (gitignored).
//! This test prints aggregate counts only: corpus names never reach its output,
//! including on failure.
//!
//! Rules come from the same sources the server uses: the blocklists and
//! `user_rules` in the private config named by `SOPEDU_PARITY_CONFIG` (default
//! `config.local.toml`, which is gitignored), loaded through
//! [`sopedu_dns::lists`]. The
//! HTTP cache is a fresh temp directory, never the repository's `state/`.
//!
//! Reference decision for a `name<TAB>blocked_count<TAB>allowed_count` row:
//! - blocked when `blocked_count > 0 && allowed_count == 0`
//! - allowed when `allowed_count > 0 && blocked_count == 0`
//! - both counts positive is ambiguous: counted as `mixed`, not compared
//! - both zero records no decision: counted as skipped by the reference
//!
//! The corpus is a fixed historical snapshot, while the lists are fetched live,
//! so a few decided names can differ after the lists change. The test always
//! prints exact aggregates and fails only when mismatches exceed 1% of the
//! corpus. That ceiling catches gross regressions that move thousands of names,
//! not allow-rule semantics: dropping every user allow rule moves only one
//! name. Allow and priority semantics are covered by unit tests in
//! `src/rules.rs`.

use std::{
    env,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use sopedu_dns::{
    config::Config,
    lists::{self, ListManager},
    rules::{Action, Rules},
};

/// Set to `1` to run the private-corpus comparison.
const OPT_IN: &str = "SOPEDU_PARITY";
const CONFIG_DEFAULT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/config.local.toml");
const CORPUS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/bench/corpus/parity.tsv");

// Flag bits mirrored from `src/rules.rs`, where the constants are private. Only
// used to bucket extra blocks by parser branch as an aggregate count.
const IMPORTANT_BLOCK: u8 = 4;
const EXACT: u8 = 16;

#[derive(Default)]
struct Summary {
    total: u64,
    matched: u64,
    /// AdGuard blocked the name; our rules did not.
    missed_block: u64,
    /// Our rules blocked the name; AdGuard did not.
    extra_block: u64,
    mixed: u64,
    skipped: u64,
    malformed: u64,
    reference_blocked: u64,
    reference_allowed: u64,
    // Causes for a missed block: an allow rule matched us, or nothing did.
    allow_matched: u64,
    no_match: u64,
    // Parser branch behind an extra block: an exact (hosts/plain) rule, a
    // suffix `||name^` rule, or a `$important` suffix rule.
    exact_form: u64,
    suffix_form: u64,
    important_form: u64,
}

fn compare(rules: &Rules, corpus: &str) -> Summary {
    let mut summary = Summary::default();
    for line in corpus.lines() {
        if line.is_empty() {
            continue;
        }
        let mut fields = line.split('\t');
        let (Some(name), Some(blocked), Some(allowed), None) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            summary.malformed += 1;
            continue;
        };
        let (Ok(blocked), Ok(allowed)) = (blocked.parse::<u64>(), allowed.parse::<u64>()) else {
            summary.malformed += 1;
            continue;
        };
        if name.is_empty() {
            summary.malformed += 1;
            continue;
        }

        summary.total += 1;
        let reference = match (blocked > 0, allowed > 0) {
            (true, false) => {
                summary.reference_blocked += 1;
                true
            }
            (false, true) => {
                summary.reference_allowed += 1;
                false
            }
            (true, true) => {
                summary.mixed += 1;
                continue;
            }
            (false, false) => {
                summary.skipped += 1;
                continue;
            }
        };

        if rules.blocked(name) == reference {
            summary.matched += 1;
        } else if reference {
            summary.missed_block += 1;
            if rules.decision(name).action == Action::Allow {
                summary.allow_matched += 1;
            } else {
                summary.no_match += 1;
            }
        } else {
            summary.extra_block += 1;
            let matches = rules.explain(name);
            if matches.iter().any(|matched| matched.flags & EXACT != 0) {
                summary.exact_form += 1;
            } else if matches.iter().any(|matched| matched.flags & IMPORTANT_BLOCK != 0) {
                summary.important_form += 1;
            } else {
                summary.suffix_form += 1;
            }
        }
    }
    summary
}

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = env::temp_dir().join(format!(
            "sopedu-dns-parity-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create parity temp dir");
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test]
async fn adguard_querylog_parity() {
    if env::var(OPT_IN).as_deref() != Ok("1") {
        eprintln!("parity: skipped (set {OPT_IN}=1 to compare against the private corpus)");
        return;
    }
    let corpus = match std::fs::read(CORPUS) {
        Ok(bytes) => String::from_utf8(bytes)
            .unwrap_or_else(|_| panic!("parity: the private corpus {CORPUS} is not valid UTF-8")),
        Err(error) => panic!("parity: cannot read the private corpus {CORPUS}: {error}"),
    };

    let config_path = env::var("SOPEDU_PARITY_CONFIG").unwrap_or_else(|_| CONFIG_DEFAULT.into());
    let mut config = Config::load(&config_path).expect("the parity config must parse");
    let cache = TempDir::new();
    config.state_dir = cache.0.join("state");
    let client = lists::client_builder().build().expect("build the list HTTP client");
    let outcome = match ListManager::new(client, &config).refresh().await {
        Ok(outcome) => outcome,
        Err(error) => {
            eprintln!("parity: skipped (lists unavailable: {error})");
            return;
        }
    };
    let unavailable = outcome.statuses.iter().filter(|status| status.last_error.is_some() || status.rules == 0).count();
    if unavailable > 0 {
        eprintln!(
            "parity: skipped ({unavailable}/{} lists unavailable, {} rules loaded)",
            outcome.statuses.len(),
            outcome.rules.len()
        );
        return;
    }

    let summary = compare(&outcome.rules, &corpus);
    eprintln!(
        "parity: lists={} rules={} total={} matched={} mismatched={} mixed={} skipped={} malformed={}",
        outcome.statuses.len(),
        outcome.rules.len(),
        summary.total,
        summary.matched,
        summary.missed_block + summary.extra_block,
        summary.mixed,
        summary.skipped,
        summary.malformed,
    );
    eprintln!(
        "parity: reference blocked={} allowed={}; missed_block={} (allow_matched={} no_match={}); \
         extra_block={} (exact={} suffix={} important={})",
        summary.reference_blocked,
        summary.reference_allowed,
        summary.missed_block,
        summary.allow_matched,
        summary.no_match,
        summary.extra_block,
        summary.exact_form,
        summary.suffix_form,
        summary.important_form,
    );

    assert!(summary.total > 0, "parity corpus is empty");
    assert_eq!(summary.malformed, 0, "parity corpus rows must be name<TAB>blocked<TAB>allowed");
    let compared = summary.matched + summary.missed_block + summary.extra_block;
    assert!(
        compared > 0,
        "parity corpus has no comparable rows: matched=0, mixed={}, skipped={}",
        summary.mixed,
        summary.skipped
    );
    // The corpus is a historical snapshot while the lists are fetched live, so
    // some drift is expected. This 1% ceiling only
    // catches gross regressions that move thousands of names, such as a parser
    // that drops whole line classes. It does not certify allow-rule semantics:
    // dropping every user allow rule moves just one name, far under the
    // budget. Allow and priority semantics have unit tests in src/rules.rs.
    let budget = (summary.total / 100).max(1);
    assert!(
        summary.missed_block + summary.extra_block <= budget,
        "mismatches exceed the {budget}-name drift allowance; aggregate counts are above, names stay private"
    );
}
