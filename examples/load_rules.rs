//! Rule-load probe: parse blocklist files and print timing, counts, heap and RSS.
//!
//! `rss_kb` comes from `ps -o rss= -p <pid>`; `--hold SECONDS` keeps the
//! process alive so an external sampler can watch peak RSS.

use std::{
    env,
    fs::File,
    io::{BufRead, BufReader},
    process::Command,
    sync::Arc,
    time::{Duration, Instant},
};

use sopedu_dns::rules::{RuleSetBuilder, RuleSource};

fn usage() -> &'static str {
    "usage: load_rules [--hold SECONDS] FILE..."
}

fn rss_kb() -> Option<u64> {
    let pid = std::process::id().to_string();
    let output = Command::new("ps").args(["-o", "rss=", "-p", &pid]).output().ok()?;
    String::from_utf8_lossy(&output.stdout).trim().parse().ok()
}

fn main() -> std::process::ExitCode {
    let mut paths = Vec::new();
    let mut hold = 0u64;
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--hold" => {
                let Some(value) = args.next() else {
                    eprintln!("load_rules: --hold requires a value");
                    return std::process::ExitCode::from(2);
                };
                hold = match value.parse() {
                    Ok(seconds) => seconds,
                    Err(_) => {
                        eprintln!("load_rules: invalid --hold value");
                        return std::process::ExitCode::from(2);
                    }
                };
            }
            "-h" | "--help" => {
                println!("{}", usage());
                return std::process::ExitCode::SUCCESS;
            }
            _ => paths.push(arg),
        }
    }
    if paths.is_empty() {
        eprintln!("load_rules: at least one list file is required\n{}", usage());
        return std::process::ExitCode::from(2);
    }

    let started = Instant::now();
    let mut builder = RuleSetBuilder::new();
    let mut sources = vec![RuleSource { id: 0, name: "user rules".into() }];
    let mut lines = 0u64;
    let mut skipped = 0u64;
    let mut invalid = 0u64;
    for (index, path) in paths.iter().enumerate() {
        let id = u16::try_from(index + 1).unwrap_or(u16::MAX);
        sources.push(RuleSource { id, name: path.clone() });
        let file = match File::open(path) {
            Ok(file) => file,
            Err(e) => {
                eprintln!("load_rules: cannot open {path}: {e}");
                return std::process::ExitCode::FAILURE;
            }
        };
        let mut reader = BufReader::new(file);
        let mut buf = Vec::new();
        loop {
            buf.clear();
            match reader.read_until(b'\n', &mut buf) {
                Ok(0) => break,
                Ok(_) => {}
                Err(e) => {
                    eprintln!("load_rules: cannot read {path}: {e}");
                    return std::process::ExitCode::FAILURE;
                }
            }
            lines += 1;
            match std::str::from_utf8(&buf) {
                Ok(line) => {
                    if !builder.add_line(line, id) {
                        skipped += 1;
                    }
                }
                Err(_) => invalid += 1,
            }
        }
    }
    let rules = builder.finish(Arc::from(sources));
    let parse_ms = started.elapsed().as_secs_f64() * 1000.0;
    let rss = rss_kb().map_or_else(|| "null".to_string(), |kb| kb.to_string());
    println!(
        "{{\"parse_ms\":{parse_ms:.1},\"lines\":{lines},\"rules\":{},\"skipped\":{skipped},\"invalid\":{invalid},\"heap_bytes\":{},\"rss_kb\":{rss}}}",
        rules.len(),
        rules.heap_bytes()
    );

    if hold > 0 {
        std::thread::sleep(Duration::from_secs(hold));
    }
    std::process::ExitCode::SUCCESS
}
