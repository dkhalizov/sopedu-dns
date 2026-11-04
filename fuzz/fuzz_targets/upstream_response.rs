#![no_main]

use libfuzzer_sys::fuzz_target;
use sopedu_dns::wire;

// Untrusted upstream replies: validation/normalisation, the hickory view,
// chain classification and TTL patching must never panic, and normalising is
// idempotent (relayed bytes are already in their final form).
fuzz_target!(|data: &[u8]| {
    let Some(relayed) = wire::normalize_upstream(data) else {
        return;
    };
    let again = wire::normalize_upstream(&relayed).expect("normalised bytes stay valid");
    assert_eq!(again.as_ref(), relayed.as_ref(), "normalisation is idempotent");
    let _ = wire::hickory_view(&relayed);
    if let Some(view) = wire::parse_query(&relayed) {
        let n = view.qname_len as usize;
        let _ = wire::terminal_answer(&relayed, &view.qname_lower[..n], view.qtype);
    }
    if let Some(offsets) = wire::ttl_offsets(&relayed) {
        let mut patched = relayed.to_vec();
        wire::patch(&mut patched, &offsets, 1, false, 0);
    }
});
