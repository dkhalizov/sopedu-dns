//! Pre-warm list on disk: `state_dir/prewarm.txt`, one domain per line, most
//! queried first. Written on shutdown and every 10 minutes from the query log's
//! pre-warm tracker; read at boot by a background task in `main.rs`.
//!
//! The file is browsing history, so it is owner-only (0600, in a 0700
//! directory this process creates), replaced atomically, and removed at startup
//! when `prewarm = false`.

use crate::{lists, rules};
use std::{
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
};

/// A name list can never be larger than this on disk (10000 x 254 B fits).
const MAX_READ: u64 = 1 << 20;

fn path(dir: &Path) -> PathBuf {
    dir.join("prewarm.txt")
}

/// Replaces the file with `names`. An empty list is not written, so a run that
/// saw no traffic keeps the previous run's list.
pub fn save(dir: &Path, names: &[String]) -> io::Result<()> {
    if names.is_empty() {
        return Ok(());
    }
    lists::create_private_dir(dir)?;
    let mut text = names.join("\n");
    text.push('\n');
    lists::atomic_write(&path(dir), text.as_bytes())
}

/// At most `limit` valid names from the first 1 MiB of the file. Malformed
/// lines are skipped; a missing or unreadable file is an empty list.
pub fn load(dir: &Path, limit: usize) -> Vec<String> {
    let mut bytes = Vec::new();
    let read = lists::open_regular(&path(dir)).and_then(|file| file.take(MAX_READ).read_to_end(&mut bytes));
    if read.is_err() {
        return Vec::new();
    }
    // A cut at the size limit can end inside a name; drop that last line.
    if bytes.len() as u64 == MAX_READ {
        let end = bytes.iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1);
        bytes.truncate(end);
    }
    String::from_utf8_lossy(&bytes).lines().filter_map(|line| rules::domain(line.trim())).take(limit).collect()
}

/// Deletes the file (`prewarm = false` keeps no browsing data on disk).
pub fn remove(dir: &Path) {
    let _ = fs::remove_file(path(dir));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("sopedu-prewarm-{tag}-{}", std::process::id()))
    }

    #[test]
    fn round_trips_and_skips_malformed_lines() {
        let dir = dir("round");
        let _ = fs::remove_dir_all(&dir);
        let names: Vec<String> = ["a.example", "b.example", "c.example"].map(String::from).into();
        save(&dir, &names).unwrap();
        assert_eq!(load(&dir, 10), names);
        assert_eq!(load(&dir, 2), &names[..2], "the limit keeps the most queried");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(path(&dir)).unwrap().permissions().mode() & 0o777, 0o600);
        }
        // An empty list never overwrites; hostile lines are dropped, not fatal.
        save(&dir, &[]).unwrap();
        assert_eq!(load(&dir, 10), names);
        let long = format!("{}.example", "a".repeat(64));
        let text = format!(
            "ok.example\n\n  spaced.example  \nBAD NAME\nno\\.escape\n{long}\n.\n-\u{fffd}.test\nUpper.Example\nlast.example"
        );
        fs::write(path(&dir), text).unwrap();
        assert_eq!(load(&dir, 10), ["ok.example", "spaced.example", "upper.example", "last.example"]);
        remove(&dir);
        assert!(load(&dir, 10).is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn reads_at_most_one_mebibyte() {
        let dir = dir("big");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let line = "name.example\n";
        let text = line.repeat(MAX_READ as usize / line.len() + 100);
        fs::write(path(&dir), &text).unwrap();
        let names = load(&dir, usize::MAX);
        assert_eq!(names.len(), MAX_READ as usize / line.len(), "the cut line is dropped");
        assert!(names.iter().all(|n| n == "name.example"));
        let _ = fs::remove_dir_all(&dir);
    }
}
