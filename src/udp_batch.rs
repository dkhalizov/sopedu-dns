//! Linux batched UDP receive.
//!
//! [`RecvBatch`] wraps `recvmmsg` so one readiness wake yields up to
//! `udp_batch` datagrams. Replies use the ordinary async `UdpSocket::send_to`,
//! which awaits writability and reports each send. `sendmmsg` was evaluated
//! and rejected: nix's safe API cannot report a partial send (it returns only
//! the first error and its per-message `MultiResults` cannot be inspected
//! without `unsafe`), so a failed or partial batch would silently drop
//! replies.
//!
//! The receive payload buffer is a worker local, so the batch machinery does
//! not allocate per datagram (slow-path datagrams still allocate when copied
//! out for the spawned task). nix's `MultiHeaders` holds raw pointers and is
//! therefore not `Send`; it is built inside each synchronous syscall instead
//! of being kept across an await, which costs two small allocations per
//! syscall, not per received datagram. Only nix's safe wrappers are used;
//! there is no `unsafe` here.

use std::{
    io::{self, ErrorKind, IoSliceMut},
    net::{IpAddr, SocketAddr},
    os::fd::AsRawFd,
    sync::atomic::{AtomicU64, Ordering},
};

use crate::udp_pktinfo;
use nix::sys::socket::{recvmmsg, MsgFlags, MultiHeaders};
use sopedu_dns::{config::MAX_UDP_BATCH, log};
use tokio::{io::Interest, net::UdpSocket};

/// Accepted datagram size on the batched path: the largest UDP payload, the
/// same as the single-datagram path, so no query is truncated (a 4 KiB slot
/// silently dropped valid large-OPT queries). Untouched slot pages stay
/// virtual, so resident memory follows actual datagram sizes.
pub const RECV_BUFFER: usize = 65_536;

/// Worker-local receive state: one flat payload buffer and the parsed result
/// per slot. At `MAX_UDP_BATCH` this is 2 MiB of address space.
pub struct RecvBatch {
    size: usize,
    /// Bytes per message slot: `RECV_BUFFER`, smaller only in tests.
    slot: usize,
    buffer: Vec<u8>,
    slots: [Option<(usize, SocketAddr)>; MAX_UDP_BATCH],
    /// Wildcard bind only: ask for and record each datagram's destination
    /// address (see `udp_pktinfo`). Off, `locals` stays all `None` and the
    /// syscall is exactly the plain one.
    pktinfo: bool,
    locals: [Option<IpAddr>; MAX_UDP_BATCH],
}

impl RecvBatch {
    pub fn new(size: usize) -> Self {
        Self::with_slot(size, RECV_BUFFER)
    }

    fn with_slot(size: usize, slot: usize) -> Self {
        assert!((1..=MAX_UDP_BATCH).contains(&size), "udp_batch = {size} is out of range");
        Self {
            size,
            slot,
            buffer: vec![0; size * slot],
            slots: [None; MAX_UDP_BATCH],
            pktinfo: false,
            locals: [None; MAX_UDP_BATCH],
        }
    }

    /// Also record each datagram's destination address; the socket must have
    /// `udp_pktinfo::enable` applied.
    pub fn with_pktinfo(mut self) -> Self {
        self.pktinfo = true;
        self
    }

    /// One `recvmmsg` call. Returns the number of datagrams the kernel
    /// delivered; `datagram` returns `None` for a truncated one. Truncation
    /// is counted in `truncated`, which is shared by every worker so the log
    /// carries one server-wide total.
    pub fn recv(&mut self, socket: &UdpSocket, truncated: &AtomicU64) -> io::Result<usize> {
        let (size, cap) = (self.size, self.slot);
        let Self { buffer, slots, locals, pktinfo, .. } = self;
        let mut chunks = buffer.chunks_mut(cap);
        let mut iovs: [[IoSliceMut<'_>; 1]; MAX_UDP_BATCH] = std::array::from_fn(|index| {
            if index < size {
                [IoSliceMut::new(chunks.next().expect("one chunk per message slot"))]
            } else {
                [IoSliceMut::new(&mut [])]
            }
        });
        let mut headers = MultiHeaders::preallocate(size, pktinfo.then(udp_pktinfo::control_buffer));
        let received = recvmmsg(
            socket.as_raw_fd(),
            &mut headers,
            iovs[..size].iter_mut(),
            // MSG_TRUNC makes the kernel report the real datagram length in
            // msg_len, so an oversized datagram is detectable before parsing.
            MsgFlags::MSG_TRUNC,
            None,
        )
        .map_err(io::Error::from)?;
        slots.fill(None);
        locals.fill(None);
        let mut count = 0;
        for (slot, message) in received.enumerate() {
            count += 1;
            if message.flags.contains(MsgFlags::MSG_TRUNC) || message.bytes > cap {
                let total = truncated.fetch_add(1, Ordering::Relaxed) + 1;
                if total == 1 || total.is_multiple_of(1000) {
                    log::log("warn", "udp_truncated", &[("dropped", total.to_string()), ("cap", cap.to_string())]);
                }
                continue;
            }
            let Some(peer) = message.address.as_ref().and_then(udp_pktinfo::socket_addr) else { continue };
            slots[slot] = Some((message.bytes, peer));
            if *pktinfo {
                locals[slot] =
                    message.cmsgs().ok().and_then(|mut cmsgs| cmsgs.find_map(|cmsg| udp_pktinfo::destination(&cmsg)));
            }
        }
        Ok(count)
    }

    /// The destination address of a slot, when `with_pktinfo` recorded one.
    pub fn local(&self, slot: usize) -> Option<IpAddr> {
        self.locals.get(slot).copied().flatten()
    }

    /// The payload and source of a non-truncated slot from the last `recv`.
    pub fn datagram(&self, slot: usize) -> Option<(&[u8], SocketAddr)> {
        let (len, peer) = self.slots.get(slot).copied().flatten()?;
        let start = slot * self.slot;
        Some((&self.buffer[start..start + len], peer))
    }
}

/// Waits for readiness, then receives one batch. `try_io` clears the
/// readiness bit when the syscall reports `EAGAIN`/`EWOULDBLOCK`, so the next
/// turn waits on the reactor instead of spinning.
pub async fn recv_batch(socket: &UdpSocket, batch: &mut RecvBatch, truncated: &AtomicU64) -> io::Result<usize> {
    loop {
        socket.readable().await?;
        match socket.try_io(Interest::READABLE, || batch.recv(socket, truncated)) {
            Ok(received) => return Ok(received),
            Err(error) if error.kind() == ErrorKind::WouldBlock => continue,
            Err(error) => return Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket as StdUdpSocket;

    /// Small slots keep the truncation path testable: a real slot holds any
    /// UDP payload, so nothing sendable overflows it.
    const TEST_SLOT: usize = 4096;

    fn std_socket() -> StdUdpSocket {
        StdUdpSocket::bind("127.0.0.1:0").unwrap()
    }

    #[tokio::test]
    async fn recv_batch_records_the_destination_address_when_asked() {
        let std = StdUdpSocket::bind("0.0.0.0:0").unwrap();
        std.set_nonblocking(true).unwrap();
        udp_pktinfo::enable(&std, false).unwrap();
        let receiver = UdpSocket::from_std(std).unwrap();
        let port = receiver.local_addr().unwrap().port();
        let truncated = AtomicU64::new(0);
        let mut batch = RecvBatch::with_slot(4, TEST_SLOT).with_pktinfo();
        let a = std_socket();
        a.send_to(b"one", ("127.0.0.1", port)).unwrap();
        // 127.0.0.2 is whole-loopback on Linux; this module is Linux only.
        a.send_to(b"two", ("127.0.0.2", port)).unwrap();
        let received = recv_batch(&receiver, &mut batch, &truncated).await.unwrap();
        assert_eq!(received, 2);
        assert_eq!(batch.local(0), Some("127.0.0.1".parse().unwrap()));
        assert_eq!(batch.local(1), Some("127.0.0.2".parse().unwrap()));
        // Without the flag nothing is recorded.
        let plain = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        a.send_to(b"x", plain.local_addr().unwrap()).unwrap();
        let mut batch = RecvBatch::with_slot(4, TEST_SLOT);
        recv_batch(&plain, &mut batch, &truncated).await.unwrap();
        assert_eq!(batch.local(0), None);
    }

    #[tokio::test]
    async fn recv_batch_returns_payloads_and_peers_and_counts_truncation() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = receiver.local_addr().unwrap();
        let a = std_socket();
        let b = std_socket();

        // A nonblocking receive with nothing queued is WouldBlock, which is
        // what `try_io` uses to clear readiness.
        let truncated = AtomicU64::new(0);
        let mut batch = RecvBatch::with_slot(4, TEST_SLOT);
        assert_eq!(batch.recv(&receiver, &truncated).unwrap_err().kind(), ErrorKind::WouldBlock);

        a.send_to(b"one", addr).unwrap();
        b.send_to(b"two", addr).unwrap();
        a.send_to(b"three", addr).unwrap();
        let received = recv_batch(&receiver, &mut batch, &truncated).await.unwrap();
        assert_eq!(received, 3);
        let mut got: Vec<(Vec<u8>, SocketAddr)> =
            (0..received).filter_map(|slot| batch.datagram(slot).map(|(data, peer)| (data.to_vec(), peer))).collect();
        got.sort();
        let mut expected = vec![
            (b"one".to_vec(), a.local_addr().unwrap()),
            (b"two".to_vec(), b.local_addr().unwrap()),
            (b"three".to_vec(), a.local_addr().unwrap()),
        ];
        expected.sort();
        assert_eq!(got, expected);
        assert_eq!(truncated.load(Ordering::Relaxed), 0);

        // Oversized: Linux reports the real length with MSG_TRUNC, so the
        // datagram is dropped instead of parsed as a 4096-byte payload.
        a.send_to(&vec![0xa5; TEST_SLOT + 1], addr).unwrap();
        let received = recv_batch(&receiver, &mut batch, &truncated).await.unwrap();
        assert_eq!(received, 1);
        assert!(batch.datagram(0).is_none(), "a truncated datagram is not processed");
        assert_eq!(truncated.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn recv_batch_handles_a_valid_datagram_after_a_truncated_one() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = receiver.local_addr().unwrap();
        let a = std_socket();
        let truncated = AtomicU64::new(0);
        let mut batch = RecvBatch::with_slot(4, TEST_SLOT);

        // Same sender, same batch: slot 0 is oversized, slot 1 is valid.
        a.send_to(&vec![0xa5; TEST_SLOT + 1], addr).unwrap();
        a.send_to(b"still handled", addr).unwrap();
        let received = recv_batch(&receiver, &mut batch, &truncated).await.unwrap();
        assert_eq!(received, 2);
        assert!(batch.datagram(0).is_none());
        assert_eq!(batch.datagram(1), Some((&b"still handled"[..], a.local_addr().unwrap())));
        assert_eq!(truncated.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn recv_batch_handles_a_mixed_batch_and_shares_the_truncation_total() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = receiver.local_addr().unwrap();
        let a = std_socket();
        let b = std_socket();
        let truncated = AtomicU64::new(0);
        let mut batch = RecvBatch::with_slot(4, TEST_SLOT);

        a.send_to(b"first", addr).unwrap();
        a.send_to(&vec![0xa5; TEST_SLOT + 1], addr).unwrap();
        a.send_to(b"last", addr).unwrap();
        b.send_to(b"other peer", addr).unwrap();
        let received = recv_batch(&receiver, &mut batch, &truncated).await.unwrap();
        assert_eq!(received, 4);
        assert_eq!(batch.datagram(0), Some((&b"first"[..], a.local_addr().unwrap())));
        assert!(batch.datagram(1).is_none());
        assert_eq!(batch.datagram(2), Some((&b"last"[..], a.local_addr().unwrap())));
        assert_eq!(batch.datagram(3), Some((&b"other peer"[..], b.local_addr().unwrap())));
        assert_eq!(truncated.load(Ordering::Relaxed), 1);

        // A later batch adds to the same shared total rather than starting
        // over, so concurrent workers all contribute to one count.
        b.send_to(&vec![0xa5; TEST_SLOT + 1], addr).unwrap();
        let received = recv_batch(&receiver, &mut batch, &truncated).await.unwrap();
        assert_eq!(received, 1);
        assert_eq!(truncated.load(Ordering::Relaxed), 2);
    }
}
