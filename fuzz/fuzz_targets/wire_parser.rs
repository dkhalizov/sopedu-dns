#![no_main]

use libfuzzer_sys::fuzz_target;
use sopedu_dns::wire;

// Untrusted packets: parsing, stack-buffer key building, TTL offset
// collection and TTL/ID patching must never panic or loop forever.
fuzz_target!(|data: &[u8]| {
    if let Some(view) = wire::parse_query(data) {
        let mut key = [0u8; wire::MIN_CANONICAL_BUFFER];
        if let Some(len) = wire::canonical_key(&view, &mut key) {
            assert!((5..=wire::MIN_CANONICAL_BUFFER).contains(&len));
        }
        // Too small a buffer is refused rather than overwritten.
        assert!(wire::canonical_key(&view, &mut [0u8; wire::MIN_CANONICAL_BUFFER - 1]).is_none());
    }

    let Some(offsets) = wire::ttl_offsets(data) else {
        return;
    };
    let byte = |i: usize| data.get(i).copied().unwrap_or(0);
    let age = u32::from_le_bytes([byte(0), byte(1), byte(2), byte(3)]);
    let id = u16::from_le_bytes([byte(4), byte(5)]);
    let stale = byte(6) & 1 != 0;

    let mut patched = data.to_vec();
    wire::patch(&mut patched, &offsets, age, stale, id);

    assert_eq!(patched.len(), data.len());
    assert_eq!(&patched[..2], &id.to_be_bytes());
    // Every byte outside the ID and the TTL fields is untouched. Offsets are
    // checked for order/overlap too; a pointer may target the TTL bytes, so
    // patching can legitimately change how a crafted packet parses.
    let mut covered = 2;
    for &off in offsets.iter() {
        let at = off as usize;
        assert!(at >= covered, "TTL offsets out of order or overlapping");
        assert_eq!(patched[covered..at], data[covered..at]);
        let old = u32::from_be_bytes(data[at..at + 4].try_into().unwrap());
        // The TTL is capped at 7 days first; only an expired RR then gets the
        // stale TTL (RFC 8767: 30 s), others keep what is left.
        let left = wire::rfc8767_ttl(old).saturating_sub(age);
        let want = if stale && left == 0 { 30 } else { left };
        assert_eq!(u32::from_be_bytes(patched[at..at + 4].try_into().unwrap()), want);
        covered = at + 4;
    }
    assert_eq!(patched[covered..], data[covered..]);
});
