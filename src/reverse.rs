//! Private reverse DNS matching.
//!
//! [`private_ptr_ip`] accepts only a complete four-octet `.in-addr.arpa` name
//! or a complete 32-nibble `.ip6.arpa` name. [`is_private`] is the address
//! policy that makes the local PTR answer safe. [`zone_for`] matches the
//! reverse-zone suffixes of RFC 6303 §4 by whole labels (never by a
//! text substring) and reports whether the name is the zone apex.

use crate::config::{Config, PrivatePtr};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const TYPE_PTR: u16 = 12;
const TYPE_DS: u16 = 43;

/// Which local empty zone matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZoneKind {
    Reverse,
    Home,
    /// resolver.arpa: every name is NODATA, never NXDOMAIN (RFC 9462 §§4, 6.4).
    NoData,
}

/// A local zone match: the apex name (without a final dot), whether the query
/// name is that apex, and which zone family it belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneMatch {
    pub apex: String,
    pub is_apex: bool,
    pub kind: ZoneKind,
}

/// The address encoded by a complete reverse name, or `None` for a zone apex,
/// a partial reverse name or any malformed label. Labels must be canonical
/// decimal octets or single hex nibbles.
pub fn private_ptr_ip(name: &str) -> Option<IpAddr> {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    if let Some(prefix) = name.strip_suffix(".in-addr.arpa") {
        let labels: Vec<&str> = prefix.split('.').collect();
        if labels.len() != 4 {
            return None;
        }
        let mut octets = [0u8; 4];
        for (index, label) in labels.iter().enumerate() {
            octets[3 - index] = octet(label)?;
        }
        return Some(IpAddr::V4(Ipv4Addr::from(octets)));
    }
    if let Some(prefix) = name.strip_suffix(".ip6.arpa") {
        let labels: Vec<&str> = prefix.split('.').collect();
        if labels.len() != 32 {
            return None;
        }
        let mut bytes = [0u8; 16];
        for (index, label) in labels.iter().enumerate() {
            if label.len() != 1 {
                return None;
            }
            let nibble = char::from(label.as_bytes()[0]).to_digit(16)? as u8;
            let position = 31 - index;
            bytes[position / 2] |= nibble << if position % 2 == 0 { 4 } else { 0 };
        }
        return Some(IpAddr::V6(Ipv6Addr::from(bytes)));
    }
    None
}

/// RFC 1918, loopback, link-local, CGNAT and IPv6 unique-local/link-local.
pub fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(address) => {
            let octets = address.octets();
            address.is_private()
                || address.is_loopback()
                || address.is_link_local()
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        }
        IpAddr::V6(address) => address.is_unique_local() || address.is_unicast_link_local() || address.is_loopback(),
    }
}

/// The local empty zone containing `name`, if any. The comparison is
/// case-insensitive and by whole labels.
pub fn zone_for(name: &str) -> Option<ZoneMatch> {
    let trimmed = name.trim_end_matches('.');
    // Cheap rejection for the common (non-.arpa) path: no allocation and no
    // label split unless the name could belong to a local zone.
    let bytes = trimmed.as_bytes();
    if bytes.len() < 5 || !bytes[bytes.len() - 5..].eq_ignore_ascii_case(b".arpa") {
        return None;
    }
    let name = trimmed.to_ascii_lowercase();
    // RFC 8375 home.arpa, RFC 9665 §8.4 service.arpa (MUST NOT forward) and
    // RFC 9462 §6.1 resolver.arpa (we publish no DDR designation).
    for (apex, kind) in
        [("home.arpa", ZoneKind::Home), ("service.arpa", ZoneKind::Home), ("resolver.arpa", ZoneKind::NoData)]
    {
        if name == apex {
            return Some(ZoneMatch { apex: apex.into(), is_apex: true, kind });
        }
        if name.strip_suffix(apex).is_some_and(|rest| rest.ends_with('.')) {
            return Some(ZoneMatch { apex: apex.into(), is_apex: false, kind });
        }
    }

    let labels: Vec<&str> = name.split('.').collect();
    if labels.ends_with(&["in-addr", "arpa"]) {
        let prefix = &labels[..labels.len() - 2];
        let zone_labels = in_addr_zone(prefix)?;
        let apex = labels[labels.len() - zone_labels - 2..].join(".");
        return Some(ZoneMatch { apex, is_apex: prefix.len() == zone_labels, kind: ZoneKind::Reverse });
    }
    if labels.ends_with(&["ip6", "arpa"]) {
        let prefix = &labels[..labels.len() - 2];
        let zone_labels = ip6_zone(prefix)?;
        let apex = labels[labels.len() - zone_labels - 2..].join(".");
        return Some(ZoneMatch { apex, is_apex: prefix.len() == zone_labels, kind: ZoneKind::Reverse });
    }
    None
}

/// True when `private_ptr = "forward"` sends the query upstream: any type in a
/// local reverse zone (the RFC 6303 §3 opt-out), and a PTR outside those zones.
/// Shared CGN space (100.64.0.0/10) is exempt: RFC 6598 §4 forbids sending its
/// reverse queries to global DNS, so it stays local in every mode. So are the
/// `.arpa` special-use zones, which are not reverse zones.
pub fn forwards_reverse(cfg: &Config, qtype: u16, name: &str) -> bool {
    // RFC 6303 §3 SHOULD: the opt-out per zone, too.
    if !cfg.forward_reverse_zones.is_empty()
        && zone_for(name)
            .is_some_and(|zone| zone.kind == ZoneKind::Reverse && cfg.forward_reverse_zones.contains(&zone.apex))
    {
        return true;
    }
    if cfg.private_ptr != PrivatePtr::Forward {
        return false;
    }
    match zone_for(name) {
        Some(zone) => zone.kind == ZoneKind::Reverse && !zone.apex.ends_with(".100.in-addr.arpa"),
        None => qtype == TYPE_PTR,
    }
}

/// True when `home_arpa_server` takes queries for `name` (RFC 8375 §4).
pub fn forwards_home(cfg: &Config, name: &str) -> bool {
    cfg.home_arpa_server.is_some() && zone_for(name).is_some_and(|zone| zone.apex == "home.arpa")
}

/// True when the local reverse logic answers a query with `name` (lowercase,
/// no final dot) itself: a private PTR denial or a local empty zone.
///
/// This mirrors the reply builder in the binary exactly and is used only to
/// choose the parsed slow path, so a cached entry can never bypass a local
/// reverse answer. The `private_ptr = "forward"` opt-out and the DS probe at
/// any local zone apex with DO=1 are the two exceptions.
pub fn may_answer(cfg: &Config, qtype: u16, name: &str, do_bit: bool) -> bool {
    if forwards_reverse(cfg, qtype, name) || forwards_home(cfg, name) {
        return false;
    }
    if qtype == TYPE_PTR {
        if let Some(ip) = private_ptr_ip(name) {
            if is_private(ip) {
                return true;
            }
        }
    }
    let Some(zone) = zone_for(name) else { return false };
    // The apex DS proof comes from the signed parent, never a synthetic local
    // denial (RFC 4035 §3.1.4.1, RFC 6303 §7, RFC 8375 §4).
    if zone.is_apex && qtype == TYPE_DS && do_bit {
        return false;
    }
    true
}

/// A canonical decimal octet: no sign, no leading zero and at most 255.
fn octet(label: &str) -> Option<u8> {
    if label.is_empty()
        || label.len() > 3
        || (label.len() > 1 && label.starts_with('0'))
        || !label.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    label.parse().ok()
}

/// Number of labels in the matching `in-addr.arpa` zone suffix (RFC 6303 §4.2
/// plus RFC 1918, link-local and CGN).
fn in_addr_zone(prefix: &[&str]) -> Option<usize> {
    // The address octets from the top: 192.0.2.x is ["192", "0", "2", ...].
    let top: Vec<&str> = prefix.iter().rev().copied().collect();
    let at = |i: usize| top.get(i).copied();
    match (at(0)?, at(1), at(2)) {
        ("0" | "10" | "127", _, _) => Some(1),
        ("172", Some(b), _) => (16..=31).contains(&octet(b)?).then_some(2),
        ("192", Some("168"), _) | ("169", Some("254"), _) => Some(2),
        ("100", Some(b), _) => (64..=127).contains(&octet(b)?).then_some(2),
        // TEST-NET-1/2/3 (RFC 5737).
        ("192", Some("0"), Some("2")) | ("198", Some("51"), Some("100")) | ("203", Some("0"), Some("113")) => Some(3),
        ("255", Some("255"), Some("255")) => (at(3) == Some("255")).then_some(4),
        _ => None,
    }
}

/// Number of labels in the matching `ip6.arpa` zone suffix: fc00::/7,
/// fe80::/10, 2001:db8::/32 and the :: and ::1 names (RFC 6303 §4.3-4.7).
fn ip6_zone(prefix: &[&str]) -> Option<usize> {
    let top: Vec<&str> = prefix.iter().rev().copied().collect();
    match top.as_slice() {
        ["f", "c" | "d", ..] => Some(2),
        ["f", "e", "8" | "9" | "a" | "b", ..] => Some(3),
        ["2", "0", "0", "1", "0", "d", "b", "8", ..] => Some(8),
        _ if top.len() >= 32 && top[..31].iter().all(|l| *l == "0") && matches!(top[31], "0" | "1") => Some(32),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc9665_s1411_names_below_the_unspecified_and_loopback_zones_are_local() {
        let zeros = "0.".repeat(31);
        for last in ["0", "1"] {
            let apex = format!("{last}.{zeros}ip6.arpa");
            assert!(zone_for(&apex).is_some_and(|zone| zone.is_apex), "{apex}");
            let below = zone_for(&format!("x.{apex}")).expect("a name below the zone is local");
            assert!(!below.is_apex);
            assert_eq!(below.apex, apex);
        }
        assert!(zone_for(&format!("2.{zeros}ip6.arpa")).is_none(), "::2 is not a listed zone");
        assert!(zone_for(&format!("x.2.{zeros}ip6.arpa")).is_none());
    }

    #[test]
    fn cgn_reverse_is_never_forwarded_even_in_forward_mode() {
        // RFC 6598 §4: 100.64.0.0/10 reverse queries never go to global DNS.
        let cfg = Config { private_ptr: PrivatePtr::Forward, ..Config::default() };
        for name in ["1.64.100.in-addr.arpa", "9.9.100.100.in-addr.arpa", "1.127.100.in-addr.arpa"] {
            assert!(may_answer(&cfg, TYPE_PTR, name, false), "{name}");
        }
        // Other private space still honours the opt-out.
        assert!(!may_answer(&cfg, TYPE_PTR, "1.0.0.10.in-addr.arpa", false));
        // 100.128/9 is public.
        assert!(!may_answer(&cfg, TYPE_PTR, "1.128.100.in-addr.arpa", false));
    }

    /// RFC 6303 §3: the opt-out may be chosen zone by zone.
    #[test]
    fn rfc6303_s194_one_reverse_zone_can_be_forwarded_on_its_own() {
        let mut cfg = Config { forward_reverse_zones: vec!["168.192.IN-ADDR.ARPA.".into()], ..Config::default() };
        cfg.validate().unwrap();
        assert_eq!(cfg.forward_reverse_zones, ["168.192.in-addr.arpa"], "normalized");
        for (qtype, name) in
            [(TYPE_PTR, "1.1.168.192.in-addr.arpa"), (TYPE_PTR, "168.192.in-addr.arpa"), (6, "168.192.in-addr.arpa")]
        {
            assert!(forwards_reverse(&cfg, qtype, name), "{name}");
            assert!(!may_answer(&cfg, qtype, name, false), "{name}");
        }
        assert!(may_answer(&cfg, TYPE_PTR, "1.0.0.10.in-addr.arpa", false), "other zones stay local");
        assert!(may_answer(&cfg, TYPE_PTR, "1.1.16.172.in-addr.arpa", false), "other zones stay local");

        for zone in ["0.10.in-addr.arpa", "64.100.in-addr.arpa", "example.com", "8.8.in-addr.arpa", "home.arpa"] {
            let mut bad = Config { forward_reverse_zones: vec![zone.into()], ..Config::default() };
            assert!(bad.validate().is_err(), "{zone} is rejected");
        }
        let mut v6 = Config { forward_reverse_zones: vec!["d.f.ip6.arpa".into()], ..Config::default() };
        v6.validate().unwrap();
        assert!(!may_answer(&v6, TYPE_PTR, &v6_reverse("fd00::1".parse().unwrap()), false), "an IPv6 zone too");
    }

    fn v6_reverse(address: Ipv6Addr) -> String {
        let mut labels = Vec::new();
        for byte in address.octets().iter().rev() {
            labels.push(format!("{:x}", byte & 0x0f));
            labels.push(format!("{:x}", byte >> 4));
        }
        format!("{}.ip6.arpa", labels.join("."))
    }

    #[test]
    fn complete_reverse_names_decode() {
        assert_eq!(private_ptr_ip("1.0.0.10.in-addr.arpa"), Some("10.0.0.1".parse().unwrap()));
        assert_eq!(private_ptr_ip("1.0.0.10.in-addr.arpa."), Some("10.0.0.1".parse().unwrap()));
        assert_eq!(private_ptr_ip("8.8.8.8.in-addr.arpa"), Some("8.8.8.8".parse().unwrap()));
        for address in ["::1", "fe80::1", "fd00::1234", "2001:4860:4860::8888"] {
            let address: Ipv6Addr = address.parse().unwrap();
            assert_eq!(private_ptr_ip(&v6_reverse(address)), Some(IpAddr::V6(address)));
        }
        // Mixed case input is still a DNS name.
        assert_eq!(private_ptr_ip("1.0.0.10.IN-ADDR.ARPA"), Some("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn malformed_reverse_names_do_not_decode() {
        for name in [
            "10.in-addr.arpa",
            "1.0.0.in-addr.arpa",
            "1.0.0.10.20.in-addr.arpa",
            "256.0.0.10.in-addr.arpa",
            "01.0.0.10.in-addr.arpa",
            "x.0.0.10.in-addr.arpa",
            "1.0.0.10.in-addr.arpaa",
            "1.0.0.10.not-in-addr.arpa",
            "1.0.0.10.in-addr.arpa.example",
            "1.0.0.10.ip6.arpa",
            "1.2.3.4.5.6.7.8.9.a.b.c.d.e.f.0.1.2.3.4.5.6.7.8.9.a.b.c.d.e.f.ip6.arpa",
            "g.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
            "",
        ] {
            assert_eq!(private_ptr_ip(name), None, "{name}");
        }
    }

    #[test]
    fn private_address_policy_covers_the_documented_ranges() {
        for address in [
            "10.0.0.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "100.127.255.255",
            "::1",
            "fc00::1",
            "fdff::1",
            "fe80::1",
            "febf::1",
        ] {
            assert!(is_private(address.parse().unwrap()), "{address}");
        }
        for address in ["8.8.8.8", "1.1.1.1", "172.32.0.1", "100.128.0.1", "2001:4860:4860::8888", "2606:4700::1111"] {
            assert!(!is_private(address.parse().unwrap()), "{address}");
        }
    }

    #[test]
    fn every_reverse_zone_apex_and_descendant_matches() {
        let apexes = [
            "10.in-addr.arpa",
            "16.172.in-addr.arpa",
            "31.172.in-addr.arpa",
            "168.192.in-addr.arpa",
            "127.in-addr.arpa",
            "254.169.in-addr.arpa",
            "64.100.in-addr.arpa",
            "127.100.in-addr.arpa",
            "8.e.f.ip6.arpa",
            "9.e.f.ip6.arpa",
            "a.e.f.ip6.arpa",
            "b.e.f.ip6.arpa",
            "c.f.ip6.arpa",
            "d.f.ip6.arpa",
        ];
        for apex in apexes {
            assert_eq!(
                zone_for(apex),
                Some(ZoneMatch { apex: apex.into(), is_apex: true, kind: ZoneKind::Reverse }),
                "{apex}"
            );
            let descendant = format!("1.2.{apex}");
            assert_eq!(
                zone_for(&descendant),
                Some(ZoneMatch { apex: apex.into(), is_apex: false, kind: ZoneKind::Reverse }),
                "{descendant}"
            );
            assert_eq!(
                zone_for(&apex.to_ascii_uppercase()),
                Some(ZoneMatch { apex: apex.into(), is_apex: true, kind: ZoneKind::Reverse }),
                "{apex}"
            );
        }
        assert_eq!(
            zone_for("home.arpa"),
            Some(ZoneMatch { apex: "home.arpa".into(), is_apex: true, kind: ZoneKind::Home })
        );
        assert_eq!(
            zone_for("printer.home.arpa"),
            Some(ZoneMatch { apex: "home.arpa".into(), is_apex: false, kind: ZoneKind::Home })
        );
    }

    #[test]
    fn zone_matching_is_by_whole_labels_only() {
        for name in [
            "11.in-addr.arpa",
            "110.in-addr.arpa",
            "x10.in-addr.arpa",
            "20.in-addr.arpa",
            "15.172.in-addr.arpa",
            "32.172.in-addr.arpa",
            "016.172.in-addr.arpa",
            "63.100.in-addr.arpa",
            "128.100.in-addr.arpa",
            "8.8.8.8.in-addr.arpa",
            "e.f.ip6.arpa",
            "7.e.f.ip6.arpa",
            "18.e.f.ip6.arpa",
            "e.f.ip6.arpa.example",
            "xhome.arpa",
            "home.arpa.example",
            "example.com",
        ] {
            assert_eq!(zone_for(name), None, "{name}");
        }
        // These are genuine descendants of the listed zones.
        assert_eq!(zone_for("0.10.in-addr.arpa").unwrap().apex, "10.in-addr.arpa");
        assert_eq!(zone_for("1.0.8.e.f.ip6.arpa").unwrap().apex, "8.e.f.ip6.arpa");
    }

    #[test]
    fn rfc6303_and_special_use_arpa_zones() {
        let zero32 = vec!["0"; 32].join(".");
        let one = format!("1.{}", vec!["0"; 31].join("."));
        for (name, apex) in [
            ("1.2.3.0.in-addr.arpa", "0.in-addr.arpa"),
            ("9.2.0.192.in-addr.arpa", "2.0.192.in-addr.arpa"),
            ("9.100.51.198.in-addr.arpa", "100.51.198.in-addr.arpa"),
            ("113.0.203.in-addr.arpa", "113.0.203.in-addr.arpa"),
            ("255.255.255.255.in-addr.arpa", "255.255.255.255.in-addr.arpa"),
            ("1.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa", "8.b.d.0.1.0.0.2.ip6.arpa"),
            (&*format!("{zero32}.ip6.arpa"), &*format!("{zero32}.ip6.arpa")),
            (&*format!("{one}.ip6.arpa"), &*format!("{one}.ip6.arpa")),
            ("_dns.resolver.arpa", "resolver.arpa"),
            ("x.service.arpa", "service.arpa"),
        ] {
            assert_eq!(zone_for(name).map(|z| z.apex), Some(apex.to_string()), "{name}");
        }
        // Neighbours stay public.
        for name in ["9.3.0.192.in-addr.arpa", "1.1.0.192.in-addr.arpa", "9.255.255.254.in-addr.arpa", "noservice.arpa"]
        {
            assert_eq!(zone_for(name), None, "{name}");
        }
        let two = format!("2.{}", vec!["0"; 31].join("."));
        assert_eq!(zone_for(&format!("{two}.ip6.arpa")), None);
    }
}
