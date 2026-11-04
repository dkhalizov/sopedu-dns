//! RFC 8085 section 5.1: answer from the address the client queried.
//!
//! On a wildcard bind (`0.0.0.0` / `[::]`) of a multi-address host the kernel
//! picks the reply's source address by routing, which can differ from the
//! address the client sent to, and the client then drops the reply. With
//! `IP_PKTINFO` / `IPV6_RECVPKTINFO` the destination address of each datagram
//! arrives as a control message, and a `sendmsg` carrying the matching
//! `IP_PKTINFO` / `IPV6_PKTINFO` pins the reply's source to it. Only used when
//! the bound address is unspecified; a specific bind never reaches this module.
//!
//! Linux and macOS only (the platforms nix exposes safe control messages for
//! on both directions). Only nix's safe wrappers are used; no `unsafe` here.
//! Cost: nix allocates the control buffer of each `sendmsg`/`recvmsg`, so a
//! wildcard-bound reply makes one small allocation more than a plain send.
//!
//! The IPv4 reply carries the source in `ipi_spec_dst` with interface index 0,
//! so routing still picks the interface. The IPv6 reply likewise uses index 0;
//! a link-local peer's interface travels in its scope id.

use std::{
    io::{self, IoSlice, IoSliceMut},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::fd::{AsFd, AsRawFd},
};

use nix::{
    cmsg_space,
    libc::{in6_addr, in6_pktinfo, in_addr, in_pktinfo},
    sys::socket::{
        recvmsg, sendmsg, setsockopt, sockopt, ControlMessage, ControlMessageOwned, MsgFlags, SockaddrStorage,
    },
};
use tokio::{io::Interest, net::UdpSocket};

/// Asks the kernel to deliver each datagram's destination address. IPv6
/// sockets also receive it for IPv4-mapped peers (as `::ffff:a.b.c.d`).
pub fn enable(socket: &impl AsFd, v6: bool) -> io::Result<()> {
    if v6 {
        setsockopt(socket, sockopt::Ipv6RecvPacketInfo, &true)
    } else {
        setsockopt(socket, sockopt::Ipv4PacketInfo, &true)
    }
    .map_err(io::Error::from)
}

/// Space for one received pktinfo control message (the larger, IPv6 one).
pub fn control_buffer() -> Vec<u8> {
    cmsg_space!(in6_pktinfo)
}

/// The datagram's destination address, when the control message carries one.
pub fn destination(message: &ControlMessageOwned) -> Option<IpAddr> {
    match message {
        ControlMessageOwned::Ipv4PacketInfo(info) => {
            Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(info.ipi_addr.s_addr))))
        }
        ControlMessageOwned::Ipv6PacketInfo(info) => Some(IpAddr::V6(Ipv6Addr::from(info.ipi6_addr.s6_addr))),
        _ => None,
    }
}

pub fn socket_addr(address: &SockaddrStorage) -> Option<SocketAddr> {
    address
        .as_sockaddr_in()
        .map(|v4| SocketAddr::from(*v4))
        .or_else(|| address.as_sockaddr_in6().map(|v6| SocketAddr::from(*v6)))
}

/// `recv_from` plus the datagram's destination address (`None` when the kernel
/// supplied no control message).
pub async fn recv_from(socket: &UdpSocket, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, Option<IpAddr>)> {
    socket
        .async_io(Interest::READABLE, || {
            let mut control = control_buffer();
            let mut iov = [IoSliceMut::new(&mut *buf)];
            let message =
                recvmsg::<SockaddrStorage>(socket.as_raw_fd(), &mut iov, Some(&mut control), MsgFlags::empty())
                    .map_err(io::Error::from)?;
            let peer = message
                .address
                .as_ref()
                .and_then(socket_addr)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "datagram without a source address"))?;
            let local = message.cmsgs().ok().and_then(|mut cmsgs| cmsgs.find_map(|cmsg| destination(&cmsg)));
            Ok((message.bytes, peer, local))
        })
        .await
}

/// `send_to` with the reply's source address pinned to `local`.
pub async fn send_from(socket: &UdpSocket, data: &[u8], peer: SocketAddr, local: IpAddr) -> io::Result<usize> {
    let v4 = in_pktinfo { ipi_ifindex: 0, ipi_spec_dst: in_addr { s_addr: 0 }, ipi_addr: in_addr { s_addr: 0 } };
    let v6 = in6_pktinfo { ipi6_addr: in6_addr { s6_addr: [0; 16] }, ipi6_ifindex: 0 };
    let (v4, v6) = match local {
        IpAddr::V4(addr) => (in_pktinfo { ipi_spec_dst: in_addr { s_addr: u32::from(addr).to_be() }, ..v4 }, v6),
        IpAddr::V6(addr) => (v4, in6_pktinfo { ipi6_addr: in6_addr { s6_addr: addr.octets() }, ..v6 }),
    };
    let control = match local {
        IpAddr::V4(_) => ControlMessage::Ipv4PacketInfo(&v4),
        IpAddr::V6(_) => ControlMessage::Ipv6PacketInfo(&v6),
    };
    let iov = [IoSlice::new(data)];
    let destination = SockaddrStorage::from(peer);
    let send = || {
        sendmsg(socket.as_raw_fd(), &iov, &[control], MsgFlags::empty(), Some(&destination)).map_err(io::Error::from)
    };
    // Try first, as `send_reply` does: the socket is almost always writable.
    match socket.try_io(Interest::WRITABLE, send) {
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => socket.async_io(Interest::WRITABLE, send).await,
        result => result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket as StdUdpSocket;
    use std::time::Duration;

    fn wildcard(addr: &str) -> Option<UdpSocket> {
        let socket = StdUdpSocket::bind(addr).ok()?;
        socket.set_nonblocking(true).unwrap();
        enable(&socket, addr.starts_with('[')).unwrap();
        Some(UdpSocket::from_std(socket).unwrap())
    }

    /// Sends from `client_ip` to `target`, serves one datagram on `server` the
    /// way the workers do, and returns the destination seen and the source the
    /// client observed on the reply.
    async fn round_trip(server: &UdpSocket, client_ip: &str, target: IpAddr) -> (Option<IpAddr>, SocketAddr) {
        let client = StdUdpSocket::bind((client_ip, 0)).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        client.send_to(b"query", (target, server.local_addr().unwrap().port())).unwrap();
        let mut buf = [0u8; 512];
        let (n, peer, local) = recv_from(server, &mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"query");
        send_from(server, b"reply", peer, local.expect("destination address delivered")).await.unwrap();
        let (n, from) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"reply");
        (local, from)
    }

    #[tokio::test]
    async fn wildcard_v4_replies_from_the_queried_address() {
        // Linux owns all of 127/8; macOS needs `ifconfig lo0 alias 127.0.0.2`.
        if StdUdpSocket::bind("127.0.0.2:0").is_err() {
            eprintln!("skipped: 127.0.0.2 is not configured on this host");
            return;
        }
        let server = wildcard("0.0.0.0:0").unwrap();
        let port = server.local_addr().unwrap().port();
        let target: IpAddr = "127.0.0.2".parse().unwrap();
        let (local, from) = round_trip(&server, "127.0.0.1", target).await;
        assert_eq!(local, Some(target));
        assert_eq!(from, SocketAddr::new(target, port));
        // And the ordinary address still answers from itself.
        let target: IpAddr = "127.0.0.1".parse().unwrap();
        let (local, from) = round_trip(&server, "127.0.0.1", target).await;
        assert_eq!((local, from), (Some(target), SocketAddr::new(target, port)));
    }

    #[tokio::test]
    async fn wildcard_v6_replies_from_the_queried_address() {
        let Some(server) = wildcard("[::]:0") else {
            eprintln!("skipped: IPv6 is not available on this host");
            return;
        };
        let target: IpAddr = "::1".parse().unwrap();
        let (local, from) = round_trip(&server, "::1", target).await;
        assert_eq!(local, Some(target));
        assert_eq!(from, SocketAddr::new(target, server.local_addr().unwrap().port()));
    }

    /// A dual-stack `[::]` socket sees IPv4 clients as v4-mapped addresses and
    /// must answer from the queried IPv4 address.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn wildcard_v6_answers_an_ipv4_client_from_the_queried_address() {
        let Some(server) = wildcard("[::]:0") else {
            eprintln!("skipped: IPv6 is not available on this host");
            return;
        };
        let target: IpAddr = "127.0.0.2".parse().unwrap();
        let (local, from) = round_trip(&server, "127.0.0.1", target).await;
        assert_eq!(local, Some("::ffff:127.0.0.2".parse().unwrap()));
        assert_eq!(from.ip(), target);
    }
}
