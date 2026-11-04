//! Property test: `wire::patch` on real, hickory-serialized responses changes
//! only the ID and the TTL fields reported by `wire::ttl_offsets`, and the
//! patched message still parses.

use hickory_proto::{
    op::{Edns, Message, MessageType, OpCode, Query},
    rr::{
        rdata::{A, AAAA, CNAME, NS, TXT},
        Name, RData, Record, RecordType,
    },
};
use proptest::prelude::*;
use sopedu_dns::wire;

fn name() -> impl Strategy<Value = Name> {
    prop::collection::vec("[a-z][a-z0-9]{0,20}", 1..4)
        .prop_map(|labels| Name::from_ascii(format!("{}.", labels.join("."))).expect("ascii name"))
}

fn record() -> impl Strategy<Value = (Name, u32, RData)> {
    prop_oneof![
        (name(), any::<u32>(), any::<[u8; 4]>()).prop_map(|(owner, ttl, [a, b, c, d])| (
            owner,
            ttl,
            RData::A(A::new(a, b, c, d))
        )),
        (name(), any::<u32>(), any::<[u16; 8]>()).prop_map(|(owner, ttl, [a, b, c, d, e, f, g, h])| {
            (owner, ttl, RData::AAAA(AAAA::new(a, b, c, d, e, f, g, h)))
        }),
        (name(), any::<u32>(), name()).prop_map(|(owner, ttl, target)| (owner, ttl, RData::CNAME(CNAME(target)))),
        (name(), any::<u32>(), name()).prop_map(|(owner, ttl, target)| (owner, ttl, RData::NS(NS(target)))),
        (name(), any::<u32>(), "[a-z0-9 ]{0,20}").prop_map(|(owner, ttl, text)| (
            owner,
            ttl,
            RData::TXT(TXT::new(vec![text]))
        )),
    ]
}

fn response() -> impl Strategy<Value = Message> {
    (
        any::<u16>(),
        name(),
        0usize..4,
        prop::collection::vec(record(), 0..6),
        prop::collection::vec(record(), 0..4),
        prop::collection::vec(record(), 0..4),
        any::<bool>(),
    )
        .prop_map(|(id, qname, qtype, answers, authorities, additionals, edns)| {
            let qtype = [RecordType::A, RecordType::AAAA, RecordType::CNAME, RecordType::TXT][qtype];
            let mut message = Message::new(id, MessageType::Response, OpCode::Query);
            message.add_query(Query::query(qname, qtype));
            for (owner, ttl, data) in answers {
                message.add_answer(Record::from_rdata(owner, ttl, data));
            }
            for (owner, ttl, data) in authorities {
                message.add_authority(Record::from_rdata(owner, ttl, data));
            }
            for (owner, ttl, data) in additionals {
                message.add_additional(Record::from_rdata(owner, ttl, data));
            }
            if edns {
                message.edns.get_or_insert_with(Edns::new).set_max_payload(1232).set_dnssec_ok(true);
            }
            message
        })
}

proptest! {
    #[test]
    fn patch_touches_only_id_and_ttls(
        message in response(),
        age in any::<u32>(),
        stale in any::<bool>(),
        new_id in any::<u16>(),
    ) {
        let raw = message.to_vec().expect("hickory serializes the response");
        let offsets = wire::ttl_offsets(&raw).expect("a serialized response has TTL offsets");

        let mut patched = raw.clone();
        wire::patch(&mut patched, &offsets, age, stale, new_id);

        prop_assert_eq!(patched.len(), raw.len());
        prop_assert_eq!(&patched[..2], &new_id.to_be_bytes());

        let mut touched = vec![false; raw.len()];
        touched[0] = true;
        touched[1] = true;
        for &off in offsets.iter() {
            let at = off as usize;
            prop_assert!(at + 4 <= raw.len(), "TTL offset {} out of bounds", at);
            for byte in touched.iter_mut().skip(at).take(4) {
                *byte = true;
            }
            // RFC 8767 §4: a TTL with the top bit set is capped like any other.
            let old = wire::rfc8767_ttl(u32::from_be_bytes(raw[at..at + 4].try_into().unwrap()));
            let remaining = old.saturating_sub(age);
            let want = if stale && remaining == 0 { 30 } else { remaining };
            prop_assert_eq!(u32::from_be_bytes(patched[at..at + 4].try_into().unwrap()), want);
        }
        for (i, (&before, &after)) in raw.iter().zip(&patched).enumerate() {
            if !touched[i] {
                prop_assert_eq!(before, after, "byte {} outside the ID and TTLs changed", i);
            }
        }

        let reparsed = Message::from_vec(&patched).expect("the patched response still parses");
        prop_assert_eq!(reparsed.metadata.id, new_id);
    }
}
