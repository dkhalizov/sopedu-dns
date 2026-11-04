//! Client MAC matching through the kernel ARP table.
//!
//! `no_filter_macs` is parsed once by [`crate::config::Config::validate`] into six bytes.
//! On Linux the table is refreshed from `/proc/net/arp` every 60 seconds in a
//! spawned task. Other platforms, and a host with no ARP entries, simply match
//! nothing: MAC bypass never fails startup. IPv6 neighbours are not covered.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    sync::{Arc, Mutex},
};

/// Upper bound on remembered ARP entries. A hostile or huge neighbour table
/// cannot grow this map without bound.
pub const MAX_ENTRIES: usize = 4096;
#[cfg(target_os = "linux")]
const REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// Parses `aa:bb:cc:dd:ee:ff` or `aa-bb-cc-dd-ee-ff`. One separator style must
/// be used throughout; both cases of hex digits are accepted.
pub fn parse_mac(value: &str) -> Option<[u8; 6]> {
    let separator = match (value.contains(':'), value.contains('-')) {
        (true, false) => ':',
        (false, true) => '-',
        _ => return None,
    };
    let mut bytes = [0u8; 6];
    let mut parts = value.split(separator);
    for byte in &mut bytes {
        let part = parts.next()?;
        if part.len() != 2 {
            return None;
        }
        *byte = u8::from_str_radix(part, 16).ok()?;
    }
    parts.next().is_none().then_some(bytes)
}

/// Parses the `/proc/net/arp` table, skipping its header. Only complete
/// entries (flag 0x2) with a valid MAC are kept. The first [`MAX_ENTRIES`]
/// entries win.
pub fn parse_arp(text: &str) -> HashMap<IpAddr, [u8; 6]> {
    let mut table = HashMap::new();
    for line in text.lines().skip(1) {
        if table.len() >= MAX_ENTRIES {
            break;
        }
        let mut columns = line.split_whitespace();
        let Some(ip) = columns.next().and_then(|value| value.parse::<Ipv4Addr>().ok()) else {
            continue;
        };
        let _hw_type = columns.next();
        let Some(flags) = columns.next().and_then(|value| u32::from_str_radix(value.trim_start_matches("0x"), 16).ok())
        else {
            continue;
        };
        let Some(mac) = columns.next().and_then(parse_mac) else {
            continue;
        };
        // 0x2 is ATF_COM: the entry has a complete hardware address. Incomplete
        // entries carry flags 0 and a placeholder MAC.
        if flags & 0x2 != 0 && mac != [0; 6] {
            table.insert(IpAddr::V4(ip), mac);
        }
    }
    table
}

/// The current IP-to-MAC map shared by every runtime generation.
#[derive(Default)]
pub struct ArpTable {
    entries: Mutex<HashMap<IpAddr, [u8; 6]>>,
}

impl ArpTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replaces the snapshot. Only [`parse_arp`], which enforces the bound,
    /// feeds this in production.
    pub fn replace(&self, entries: HashMap<IpAddr, [u8; 6]>) {
        *self.entries.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = entries;
    }

    pub fn get(&self, ip: IpAddr) -> Option<[u8; 6]> {
        self.entries.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).get(&ip).copied()
    }

    /// Neighbours whose MAC is in `macs`, for the clients page. At most
    /// [`MAX_ENTRIES`], sorted by address.
    pub fn with_macs(&self, macs: &[[u8; 6]]) -> Vec<(IpAddr, [u8; 6])> {
        let table = self.entries.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut found: Vec<_> =
            table.iter().filter(|(_, mac)| macs.contains(mac)).map(|(ip, mac)| (*ip, *mac)).collect();
        found.sort_unstable();
        found
    }

    /// True when the address is listed in `no_filter_clients`, or the address
    /// has a MAC in `no_filter_macs`. The caller passes the validated config;
    /// the table only supplies the current neighbour mapping.
    pub fn is_no_filter(&self, ip: IpAddr, clients: &[IpAddr], macs: &[[u8; 6]]) -> bool {
        clients.contains(&ip) || self.get(ip).is_some_and(|mac| macs.contains(&mac))
    }

    /// Reads `/proc/net/arp` once. A read failure keeps the previous snapshot.
    #[cfg(target_os = "linux")]
    pub fn refresh_from_proc(&self) {
        if let Ok(text) = std::fs::read_to_string("/proc/net/arp") {
            self.replace(parse_arp(&text));
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn refresh_from_proc(&self) {}

    /// Starts the Linux refresh loop. The caller's startup refresh fills the
    /// table first; this sleeps one interval before re-reading.
    #[cfg(target_os = "linux")]
    pub fn spawn_refresh(self: &Arc<Self>) -> Option<tokio::task::JoinHandle<()>> {
        let table = self.clone();
        Some(tokio::spawn(async move {
            loop {
                tokio::time::sleep(REFRESH_INTERVAL).await;
                table.refresh_from_proc();
            }
        }))
    }

    #[cfg(not(target_os = "linux"))]
    pub fn spawn_refresh(self: &Arc<Self>) -> Option<tokio::task::JoinHandle<()>> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macs_accept_one_separator_style_and_normalize_case() {
        assert_eq!(parse_mac("aa:bb:cc:dd:ee:ff"), Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
        assert_eq!(parse_mac("AA-BB-CC-DD-EE-FF"), Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
        for bad in
            ["aa:bb:cc:dd:ee", "aa:bb:cc:dd:ee:ff:00", "aa:bb-cc-dd-ee-ff", "aabbccddeeff", "zz:bb:cc:dd:ee:ff", ""]
        {
            assert_eq!(parse_mac(bad), None, "{bad}");
        }
    }

    #[test]
    fn arp_parser_keeps_only_complete_valid_entries() {
        let table = parse_arp(
            "IP address       HW type     Flags       HW address            Mask     Device\n\
             192.168.1.2      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0\n\
             192.168.1.3      0x1         0x0         11:22:33:44:55:66     *        eth0\n\
             192.168.1.4      0x1         0x6         AA-BB-CC-DD-EE-FF     *        eth0\n\
             192.168.1.5      0x1         0x2         00:00:00:00:00:00     *        eth0\n\
             192.168.1.6      0x1         0x2         malformed             *        eth0\n\
             not-an-ip        0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0\n",
        );
        assert_eq!(table.get(&"192.168.1.2".parse().unwrap()), Some(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
        assert_eq!(table.get(&"192.168.1.4".parse().unwrap()), Some(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn arp_parser_stops_at_the_entry_bound() {
        let mut text = String::from("IP address HW type Flags HW address Mask Device\n");
        for i in 0..MAX_ENTRIES + 1 {
            text.push_str(&format!("10.{}.{}.1 0x1 0x2 02:00:00:00:{:02x}:01 * eth0\n", i >> 8, i & 0xff, i & 0xff));
        }
        assert_eq!(parse_arp(&text).len(), MAX_ENTRIES);
    }

    #[test]
    fn ip_and_mac_membership_both_bypass() {
        let table = ArpTable::new();
        let ip: IpAddr = "192.168.1.10".parse().unwrap();
        let other: IpAddr = "192.168.1.11".parse().unwrap();
        let configured: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        table.replace(HashMap::from([(ip, configured)]));
        assert!(table.is_no_filter(ip, &[], &[configured]));
        assert!(table.is_no_filter(other, &[other], &[]));
        assert!(!table.is_no_filter(other, &[], &[configured]));
        assert!(!table.is_no_filter(ip, &[], &[[0; 6]]));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn non_linux_refresh_is_a_noop() {
        let table = Arc::new(ArpTable::new());
        let ip: IpAddr = "192.168.1.10".parse().unwrap();
        let configured = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        table.replace(HashMap::from([(ip, configured)]));
        table.refresh_from_proc();
        assert_eq!(table.get(ip), Some(configured));
        assert!(table.spawn_refresh().is_none());
    }
}
