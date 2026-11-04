#![no_main]

use libfuzzer_sys::fuzz_target;
use sopedu_dns::rules;

// The list parser hands parse_line one UTF-8 line at a time, so invalid
// UTF-8 is skipped here exactly as the real caller skips it.
fuzz_target!(|data: &[u8]| {
    let Ok(line) = std::str::from_utf8(data) else {
        return;
    };
    let builder = rules::RuleSetBuilder::new();
    let hasher = builder.hasher();
    let _ = rules::parse_line(&hasher, line);
    let _ = rules::domain(line);
});
