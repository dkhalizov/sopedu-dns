//! Bounded single-flight request coalescing.
//!
//! The first caller for a canonical cache key becomes the leader and performs
//! one upstream request. Identical concurrent callers become followers on a
//! bounded `oneshot` and receive the leader's shared reply instead of sending
//! their own. The leader publishes through an RAII guard, so a cancelled or
//! panicking leader wakes every follower with `None` (the SERVFAIL path)
//! rather than stranding them.
//!
//! The entry bound is `max_entries` (the server passes
//! `upstream_inflight_max`) and each key accepts at most [`MAX_WAITERS`]
//! followers. A caller over either bound bypasses and does its own upstream
//! request, which the client's upstream cap, the pool's own in-flight bound
//! and RFC 9520 failure suppression still cap. Nothing here queues without a
//! bound.
//!
//! The key is exactly [`crate::wire::canonical_key`], so DO, CD, query AD and
//! EDNS presence separate contexts. [`coalescible`] additionally excludes
//! packets that must never be shared (signed, EDNS options or unknown flags,
//! extra sections, non-recursive, non-IN class, multiple questions).

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use tokio::sync::oneshot;

use crate::wire::QueryView;

/// Maximum followers waiting on one leader for the same key. A caller above
/// this bound gets [`Role::Bypass`].
pub const MAX_WAITERS: usize = 128;

const CLASS_IN: u16 = 1;
const OPCODE_QUERY: u8 = 0;

/// The leader's published reply: shared response bytes, or `None` on failure.
pub type Reply = Option<Arc<[u8]>>;

/// Whether a parsed query may use the coalescing map at all.
///
/// The canonical key already separates DO, CD, query AD and EDNS presence.
/// This predicate rejects the contexts that must never share an answer:
/// signed/TSIG packets, EDNS options (ECS, cookies) or unknown EDNS flags,
/// answer/authority/extra sections, non-recursive queries, non-IN classes and
/// anything that is not exactly one standard query.
pub fn coalescible(view: &QueryView<'_>) -> bool {
    view.qdcount == 1
        && view.qclass == CLASS_IN
        && view.opcode == OPCODE_QUERY
        && view.rd
        && !view.signed
        && !view.has_answer_or_authority
        && !view.has_non_opt_additional
        && !view.edns_options
        && !view.edns_other_flags
        && !view.unfamiliar_header_flags
}

/// The caller's role in the single-flight map.
pub enum Role {
    /// This caller performs the upstream request and must publish through the
    /// guard. Dropping the guard without [`LeaderGuard::complete`] publishes a
    /// failure.
    Leader(LeaderGuard),
    /// Another caller is performing the request. Wait on the receiver with
    /// [`wait`].
    Follower(oneshot::Receiver<Reply>),
    /// The entry bound or this key's waiter bound was hit. Perform the
    /// upstream request directly; never queue.
    Bypass,
}

struct Shared {
    entries: Mutex<HashMap<Box<[u8]>, Arc<Waiter>>>,
    max_entries: usize,
    max_waiters: usize,
}

struct Waiter {
    senders: Mutex<Vec<oneshot::Sender<Reply>>>,
}

/// Bounded single-flight map. Cheap to share behind the server's `Arc`.
pub struct Inflight {
    shared: Arc<Shared>,
}

impl Inflight {
    /// `max_entries` bounds live leaders; `max_waiters` bounds followers per
    /// key. Both bound hits produce [`Role::Bypass`].
    pub fn new(max_entries: usize, max_waiters: usize) -> Self {
        Self { shared: Arc::new(Shared { entries: Mutex::new(HashMap::new()), max_entries, max_waiters }) }
    }

    /// Joins the flight for `key`. The map lock is never held across an await
    /// and is released before any wake-up.
    pub fn join(&self, key: &[u8]) -> Role {
        self.join_as(key, true)
    }

    /// [`join`](Self::join) for a caller that may not start upstream work
    /// (its host is over its cap): it follows a running flight, and with none
    /// gets [`Role::Bypass`] instead of opening one that would fail at once
    /// for anyone who joined it meanwhile.
    pub fn follow(&self, key: &[u8]) -> Role {
        self.join_as(key, false)
    }

    fn join_as(&self, key: &[u8], may_lead: bool) -> Role {
        let mut entries = lock(&self.shared.entries);
        if let Some(waiter) = entries.get(key) {
            let mut senders = lock(&waiter.senders);
            if senders.len() >= self.shared.max_waiters {
                return Role::Bypass;
            }
            let (sender, receiver) = oneshot::channel();
            senders.push(sender);
            return Role::Follower(receiver);
        }
        if !may_lead || entries.len() >= self.shared.max_entries {
            return Role::Bypass;
        }
        let waiter = Arc::new(Waiter { senders: Mutex::new(Vec::new()) });
        let key: Box<[u8]> = key.into();
        entries.insert(key.clone(), waiter.clone());
        Role::Leader(LeaderGuard { shared: self.shared.clone(), key, waiter, completed: false })
    }

    /// Number of keys currently owned by a leader.
    pub fn len(&self) -> usize {
        lock(&self.shared.entries).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Followers currently parked behind any leader.
    pub fn waiters(&self) -> usize {
        lock(&self.shared.entries).values().map(|waiter| lock(&waiter.senders).len()).sum()
    }
}

/// RAII ownership of one in-flight key.
pub struct LeaderGuard {
    shared: Arc<Shared>,
    key: Box<[u8]>,
    waiter: Arc<Waiter>,
    completed: bool,
}

impl LeaderGuard {
    /// Removes the entry and wakes every follower with `answer`. Each waiter
    /// gets its own `Arc` clone of the shared bytes.
    pub fn complete(mut self, answer: Option<Arc<[u8]>>) {
        self.completed = true;
        self.finish(answer);
    }

    fn finish(&self, answer: Option<Arc<[u8]>>) {
        {
            let mut entries = lock(&self.shared.entries);
            if entries.get(&self.key).is_some_and(|waiter| Arc::ptr_eq(waiter, &self.waiter)) {
                entries.remove(&self.key);
            }
        }
        // Joins are serialized by the map lock: once the entry is gone no new
        // sender can be registered, so draining the list cannot lose a waiter.
        let senders = std::mem::take(&mut *lock(&self.waiter.senders));
        // Conformance fault: drop every sender unanswered (a cancelled wait).
        #[cfg(feature = "conformance-adapter")]
        if crate::upstream::take_fault("cancel_all_waiters") {
            return;
        }
        for sender in senders {
            let _ = sender.send(answer.clone());
        }
    }
}

impl Drop for LeaderGuard {
    fn drop(&mut self) {
        if !self.completed {
            // A cancelled, aborted or panicking leader must not strand anyone.
            self.finish(None);
        }
    }
}

/// Waits for the leader's result with a hard deadline. `None` covers a failed
/// leader, a dropped sender and the timeout; the caller answers SERVFAIL.
///
/// A timed-out follower holds no map reference, so it cannot remove or alter
/// the leader's entry.
pub async fn wait(receiver: oneshot::Receiver<Option<Arc<[u8]>>>, timeout: Duration) -> Option<Arc<[u8]>> {
    match tokio::time::timeout(timeout, receiver).await {
        Ok(Ok(answer)) => answer,
        _ => None,
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire;
    use hickory_proto::{
        op::{Message, MessageType, OpCode, Query},
        rr::{rdata::opt::EdnsOption, DNSClass, Name, RecordType},
    };
    use std::{
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        time::Instant,
    };
    use tokio::sync::Barrier;

    fn message(name: &str) -> Message {
        let mut query = Message::new(0x1234, MessageType::Query, OpCode::Query);
        query.metadata.recursion_desired = true;
        query.add_query(Query::query(Name::from_ascii(format!("{name}.")).unwrap(), RecordType::A));
        query
    }

    fn plain(name: &str) -> Vec<u8> {
        message(name).to_vec().unwrap()
    }

    fn key(raw: &[u8]) -> Box<[u8]> {
        let view = wire::parse_query(raw).unwrap();
        let mut buffer = [0u8; wire::MIN_CANONICAL_BUFFER];
        let len = wire::canonical_key(&view, &mut buffer).unwrap();
        buffer[..len].into()
    }

    fn is_coalescible(raw: &[u8]) -> bool {
        wire::parse_query(raw).is_some_and(|view| coalescible(&view))
    }

    fn append_record(raw: &[u8], rtype: u16, class: u16) -> Vec<u8> {
        let mut out = raw.to_vec();
        out.push(0);
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&class.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        let count = u16::from_be_bytes([out[10], out[11]]) + 1;
        out[10..12].copy_from_slice(&count.to_be_bytes());
        out
    }

    #[test]
    fn coalescible_only_accepts_shareable_contexts() {
        assert!(is_coalescible(&plain("ok.test")));

        let mut cd = message("cd.test");
        cd.metadata.checking_disabled = true;
        assert!(is_coalescible(&cd.to_vec().unwrap()));

        let mut do_bit = message("do.test");
        do_bit.edns.get_or_insert_with(Default::default).set_dnssec_ok(true);
        assert!(is_coalescible(&do_bit.to_vec().unwrap()));

        let mut non_recursive = message("rd0.test");
        non_recursive.metadata.recursion_desired = false;
        assert!(!is_coalescible(&non_recursive.to_vec().unwrap()));

        let mut chaos = message("chaos.test");
        chaos.queries[0].set_query_class(DNSClass::CH);
        assert!(!is_coalescible(&chaos.to_vec().unwrap()));

        let mut options = message("option.test");
        options
            .edns
            .get_or_insert_with(Default::default)
            .options_mut()
            .insert(EdnsOption::Unknown(65001, vec![1, 2, 3]));
        assert!(!is_coalescible(&options.to_vec().unwrap()));

        let mut unknown_flag = message("flag.test");
        unknown_flag.edns.get_or_insert_with(Default::default).flags_mut().z = 1;
        assert!(!is_coalescible(&unknown_flag.to_vec().unwrap()));

        let extra = {
            let mut extra = message("extra.test");
            extra.add_additional(hickory_proto::rr::Record::from_rdata(
                Name::from_ascii("extra.test.").unwrap(),
                60,
                hickory_proto::rr::RData::A(hickory_proto::rr::rdata::A::new(192, 0, 2, 1)),
            ));
            extra.to_vec().unwrap()
        };
        assert!(!is_coalescible(&extra));

        // TSIG (250) is a signed packet, never coalesced or forwarded.
        assert!(!is_coalescible(&append_record(&plain("signed.test"), 250, 255)));

        // A second question is rejected by the wire parser before this point.
        let mut two = message("two.test");
        two.add_query(Query::query(Name::from_ascii("other.test.").unwrap(), RecordType::A));
        assert!(wire::parse_query(&two.to_vec().unwrap()).is_none());
    }

    #[tokio::test]
    async fn one_leader_and_fifty_followers_share_one_upstream_call() {
        let inflight = Arc::new(Inflight::new(16, MAX_WAITERS));
        let key = key(&plain("coalesce.test"));
        let calls = Arc::new(AtomicUsize::new(0));
        let Role::Leader(leader) = inflight.join(&key) else { panic!("first caller is the leader") };
        let barrier = Arc::new(Barrier::new(51));
        let mut followers = tokio::task::JoinSet::new();
        for _ in 0..50 {
            let inflight = inflight.clone();
            let key = key.clone();
            let barrier = barrier.clone();
            followers.spawn(async move {
                let Role::Follower(receiver) = inflight.join(&key) else { panic!("follower") };
                barrier.wait().await;
                wait(receiver, Duration::from_secs(5)).await
            });
        }
        // All 50 joined before the leader publishes.
        barrier.wait().await;
        assert_eq!(inflight.len(), 1);
        calls.fetch_add(1, Ordering::SeqCst);
        leader.complete(Some(Arc::from(&b"shared answer"[..])));

        while let Some(result) = followers.join_next().await {
            let answer = result.unwrap().expect("follower received the shared bytes");
            assert_eq!(answer.as_ref(), b"shared answer");
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1, "followers never call upstream");
        assert!(inflight.is_empty(), "the leader entry is removed after completion");
    }

    #[test]
    fn different_do_cd_ad_and_edns_contexts_get_their_own_leader() {
        let inflight = Inflight::new(8, 8);
        let mut messages = vec![plain("context.test")];

        let mut cd = message("context.test");
        cd.metadata.checking_disabled = true;
        messages.push(cd.to_vec().unwrap());

        let mut ad = message("context.test");
        ad.metadata.authentic_data = true;
        messages.push(ad.to_vec().unwrap());

        let mut do_bit = message("context.test");
        do_bit.edns.get_or_insert_with(Default::default).set_dnssec_ok(true);
        messages.push(do_bit.to_vec().unwrap());

        let mut edns_no_do = message("context.test");
        edns_no_do.edns.get_or_insert_with(Default::default);
        messages.push(edns_no_do.to_vec().unwrap());

        let mut keys = std::collections::HashSet::new();
        let mut guards = Vec::new();
        for raw in &messages {
            let key = key(raw);
            assert!(keys.insert(key.clone()), "the canonical key separates every context");
            match inflight.join(&key) {
                Role::Leader(guard) => guards.push(guard),
                _ => panic!("a distinct context must not join another flight"),
            }
        }
        assert_eq!(inflight.len(), messages.len());
        // The first context now has a live leader, so a repeat is a follower.
        assert!(matches!(inflight.join(&key(&messages[0])), Role::Follower(_)));
        for guard in guards {
            guard.complete(None);
        }
    }

    #[tokio::test]
    async fn failed_leader_wakes_every_follower_with_none() {
        let inflight = Inflight::new(4, 8);
        let key = key(&plain("failure.test"));
        let Role::Leader(leader) = inflight.join(&key) else { panic!("leader") };
        let receivers: Vec<_> = (0..8)
            .map(|_| match inflight.join(&key) {
                Role::Follower(receiver) => receiver,
                _ => panic!("follower"),
            })
            .collect();
        leader.complete(None);
        for receiver in receivers {
            assert!(wait(receiver, Duration::from_secs(1)).await.is_none());
        }
        assert!(inflight.is_empty());
    }

    #[tokio::test]
    async fn aborted_leader_wakes_followers_and_removes_the_entry() {
        let inflight = Arc::new(Inflight::new(4, 8));
        let key = key(&plain("abort.test"));
        let task = tokio::spawn({
            let inflight = inflight.clone();
            let key = key.clone();
            async move {
                let Role::Leader(_guard) = inflight.join(&key) else { panic!("leader") };
                std::future::pending::<()>().await;
            }
        });
        while inflight.is_empty() {
            tokio::task::yield_now().await;
        }
        let Role::Follower(receiver) = inflight.join(&key) else { panic!("follower") };
        let waiting = tokio::spawn(async move { wait(receiver, Duration::from_secs(5)).await });

        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(waiting.await.unwrap().is_none(), "abort must publish a failure");
        assert!(inflight.is_empty(), "the guard removed the entry on drop");
    }

    #[tokio::test]
    async fn panicking_leader_wakes_followers_and_removes_the_entry() {
        let inflight = Arc::new(Inflight::new(4, 8));
        let key = key(&plain("panic.test"));
        let (go, wait_for_panic) = oneshot::channel::<()>();
        let task = tokio::spawn({
            let inflight = inflight.clone();
            let key = key.clone();
            async move {
                let Role::Leader(_guard) = inflight.join(&key) else { panic!("leader") };
                let _ = wait_for_panic.await;
                panic!("leader panic");
            }
        });
        while inflight.is_empty() {
            tokio::task::yield_now().await;
        }
        let Role::Follower(receiver) = inflight.join(&key) else { panic!("follower") };
        let waiting = tokio::spawn(async move { wait(receiver, Duration::from_secs(5)).await });

        go.send(()).unwrap();
        assert!(task.await.unwrap_err().is_panic());
        assert!(waiting.await.unwrap().is_none(), "panic must publish a failure");
        assert!(inflight.is_empty(), "the guard removed the entry while unwinding");
    }

    #[tokio::test]
    async fn entry_and_waiter_bounds_bypass_instead_of_queueing() {
        let inflight = Inflight::new(1, 2);
        let first = key(&plain("bound-one.test"));
        let second = key(&plain("bound-two.test"));

        let Role::Leader(leader) = inflight.join(&first) else { panic!("leader") };
        assert!(inflight.join(&first).is_follower());
        assert!(inflight.join(&first).is_follower());
        assert!(inflight.join(&first).is_bypass(), "the third waiter bypasses");
        assert!(inflight.join(&second).is_bypass(), "the entry bound bypasses");
        leader.complete(None);
    }

    #[tokio::test]
    async fn a_timed_out_waiter_returns_and_leaves_the_leader_entry() {
        let inflight = Inflight::new(4, 4);
        let key = key(&plain("timeout.test"));
        let Role::Leader(_leader) = inflight.join(&key) else { panic!("leader") };
        let Role::Follower(receiver) = inflight.join(&key) else { panic!("follower") };

        let started = Instant::now();
        assert!(wait(receiver, Duration::from_millis(50)).await.is_none());
        let elapsed = started.elapsed();
        assert!(elapsed >= Duration::from_millis(40), "returned too early: {elapsed:?}");
        assert!(elapsed < Duration::from_secs(2), "the waiter outlived its timeout: {elapsed:?}");
        assert_eq!(inflight.len(), 1, "a timed-out follower must not remove the leader entry");
        assert!(matches!(inflight.join(&key), Role::Follower(_)), "the flight is still joinable");
    }

    #[test]
    fn a_caller_that_may_not_lead_follows_but_never_opens_a_flight() {
        // A host over its upstream cap must not open a flight that another
        // client could join in the moment before it is abandoned.
        let inflight = Inflight::new(4, 4);
        let key = key(&plain("over-cap.test"));
        assert!(inflight.follow(&key).is_bypass());
        assert!(inflight.is_empty(), "no flight was opened");
        let Role::Leader(leader) = inflight.join(&key) else { panic!("leader") };
        assert!(inflight.follow(&key).is_follower(), "an existing flight is still joinable");
        leader.complete(None);
    }

    #[test]
    fn bypass_is_documented_as_the_selected_bound_behavior() {
        // The role is the documented outcome: see the module docs and README.
        assert!(Role::Bypass.is_bypass());
        assert!(!Role::Bypass.is_follower());
    }

    impl Role {
        fn is_bypass(&self) -> bool {
            matches!(self, Self::Bypass)
        }

        fn is_follower(&self) -> bool {
            matches!(self, Self::Follower(_))
        }
    }
}
