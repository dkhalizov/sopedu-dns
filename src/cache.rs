use hickory_proto::{
    op::{Message, ResponseCode},
    rr::{Name, RData, Record},
};
use quick_cache::{
    sync::{Cache as QuickCache, DefaultLifecycle},
    DefaultHashBuilder, OptionsBuilder, Weighter,
};
use std::{
    borrow::Borrow,
    hash::{BuildHasher, Hash, Hasher},
    mem::size_of,
    sync::{
        atomic::{AtomicU16, AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

pub use crate::wire::{patch, ttl_offsets};
use crate::{clock::Instant, wire::MAX_TTL};

/// RFC 8767: a stale response is served with a 30-second TTL.
const STALE_TTL: u32 = 30;
/// Entry timestamps are relative to a start shifted back by this many seconds,
/// so `backdate` can age an entry in tests without sleeping. Age uses only
/// differences.
const TIME_ORIGIN: u64 = 1 << 20;
const NEGATIVE: u8 = 1;
const HAD_EDNS: u8 = 1 << 1;
/// Learned over the unauthenticated plaintext fallback.
const PLAIN: u8 = 1 << 3;
/// The answer's CNAME/DNAME chain has targets, so `Entry::chain` is meaningful.
const HAS_CHAIN: u8 = 1 << 4;
/// The Answer holds a CNAME at the question name: an alias answer, which a new
/// CNAME at that owner does not invalidate. Set once at insert so the
/// invalidation probe never re-parses cached messages.
const ALIAS: u8 = 1 << 5;
const NO_SOA: u16 = u16::MAX;
/// An answer learned over a plaintext fallback lives at most this long, is
/// never served stale and is never prefetched, so a spoofed reply cannot
/// linger.
pub const PLAIN_TTL_CAP: u32 = 300;
/// An entry heavier than `max(LARGE_FLOOR, cache_bytes / 256)` is
/// admitted only on its second sight, so a scan of one-hit near-64 KB answers
/// cannot flush the hot set (DNS CacheFlush).
const LARGE_FLOOR: u64 = 4096;
/// First-sight slots (8 KiB of hashes), grouped into buckets of
/// `FIRST_SIGHT_WAYS`. A key may use any slot of its bucket, so one other key
/// landing on the same spot does not erase its first sight; only a full
/// bucket drops one.
const FIRST_SIGHT_SLOTS: usize = 1024;
const FIRST_SIGHT_WAYS: usize = 8;

/// Canonical wire key (see [`crate::wire::canonical_key`]).
///
/// `Hash` and `Eq` compare the bytes, so a borrowed `&[u8]` lookup cannot hit
/// a different key through a hash collision.
#[derive(Clone, PartialEq, Eq)]
struct CacheKey(Box<[u8]>);

impl CacheKey {
    fn new(bytes: &[u8]) -> Self {
        Self(bytes.into())
    }
}

impl Borrow<[u8]> for CacheKey {
    fn borrow(&self) -> &[u8] {
        &self.0
    }
}

impl Hash for CacheKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.as_ref().hash(state);
    }
}

/// The hasher of the cache table. The conformance adapter can force every
/// hash to one constant (`hooked::force`); the table still compares keys, so
/// colliding names stay distinct. Release builds use the plain hasher.
#[cfg(not(feature = "conformance-adapter"))]
type CacheHashBuilder = DefaultHashBuilder;
#[cfg(feature = "conformance-adapter")]
type CacheHashBuilder = hooked::Builder;

#[cfg(feature = "conformance-adapter")]
pub use hooked::force as force_hash;

#[cfg(feature = "conformance-adapter")]
mod hooked {
    use super::*;
    use std::sync::atomic::AtomicBool;

    static ON: AtomicBool = AtomicBool::new(false);
    static VALUE: AtomicU64 = AtomicU64::new(0);

    /// Forces every cache-table hash to `value`, or restores hashing on `None`.
    pub fn force(value: Option<u64>) {
        VALUE.store(value.unwrap_or(0), Ordering::SeqCst);
        ON.store(value.is_some(), Ordering::SeqCst);
    }

    #[derive(Clone, Default)]
    pub struct Builder(DefaultHashBuilder);

    pub struct Hook(<DefaultHashBuilder as BuildHasher>::Hasher);

    impl BuildHasher for Builder {
        type Hasher = Hook;
        fn build_hasher(&self) -> Hook {
            Hook(self.0.build_hasher())
        }
    }

    impl Hasher for Hook {
        fn write(&mut self, bytes: &[u8]) {
            self.0.write(bytes);
        }
        fn finish(&self) -> u64 {
            if ON.load(Ordering::Relaxed) {
                VALUE.load(Ordering::Relaxed)
            } else {
                self.0.finish()
            }
        }
    }
}

#[derive(Clone)]
#[repr(C)]
struct Entry {
    /// Full wire response with the ID zeroed.
    raw: Box<[u8]>,
    /// Offsets of every non-OPT TTL field.
    offsets: Box<[u16]>,
    /// Whole seconds since this cache was created.
    stored_at: u32,
    orig_ttl: u32,
    /// TTL offset of the authority SOA for a negative entry.
    soa_offset: u16,
    /// Milliseconds past `stored_at`, so ages (and the prefetch window) have
    /// millisecond precision without a second clock read.
    stored_ms: u16,
    /// [`ChainState`] of an entry flagged `HAS_CHAIN`.
    chain: ChainCell,
    flags: u8,
}
// Layout guard: an accidental field or padding change fails the build.
// 16 (raw) + 16 (offsets) + 4 + 4 + 2 + 2 + 2 + 1, padded to 8-byte alignment = 48.
const _: () = assert!(size_of::<Entry>() == 48);

/// The one mutable bit of an otherwise immutable entry.
#[derive(Default)]
struct ChainCell(AtomicU16);

impl Clone for ChainCell {
    fn clone(&self) -> Self {
        Self(AtomicU16::new(self.0.load(Ordering::Relaxed)))
    }
}

/// What the rules said about the CNAME/DNAME chain of a cached answer: whether
/// a chain target is blocked, and which [`crate::rules::Rules`] generation the
/// verdict was computed against. It is one `u16` so the hit path compares once.
///
/// Known limit: only the low 15 bits of the generation are kept (layout guard).
/// A verdict goes wrongly current only if an entry outlives exactly 32768
/// rule-table rebuilds; entries live at most their TTL plus `max_age` (hours
/// to days).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainState(u16);

impl ChainState {
    pub fn new(generation: u64, blocked: bool) -> Self {
        Self(((generation & 0x7fff) as u16) << 1 | u16::from(blocked))
    }

    /// True when no chain target is blocked and the verdict is for `generation`.
    #[inline]
    pub fn clear(self, generation: u64) -> bool {
        self.0 == Self::new(generation, false).0
    }

    /// True when the verdict was computed against `generation`.
    #[inline]
    pub fn current(self, generation: u64) -> bool {
        self.0 >> 1 == (generation & 0x7fff) as u16
    }

    pub fn blocked(self) -> bool {
        self.0 & 1 != 0
    }
}

/// The chain verdict of the entry a hit came from. `refresh` stores a newly
/// computed verdict on that very entry, so it can never land on a newer one
/// that replaced it in the meantime.
pub struct ChainHandle {
    entry: Arc<Entry>,
    pub state: ChainState,
}

impl ChainHandle {
    pub fn refresh(&mut self, state: ChainState) {
        self.entry.chain.0.store(state.0, Ordering::Relaxed);
        self.state = state;
    }
}

impl Entry {
    fn bytes(&self) -> usize {
        self.raw.len() + self.offsets.len() * size_of::<u16>()
    }
}

#[derive(Clone)]
struct ByteWeighter {
    /// `ceil(cache_bytes / cache_size)`. Every entry weighs at least this
    /// much, so the weight budget also enforces the entry-count cap.
    min_weight: u64,
}

impl Weighter<CacheKey, Arc<Entry>> for ByteWeighter {
    fn weight(&self, key: &CacheKey, value: &Arc<Entry>) -> u64 {
        ((key.0.len() + value.bytes() + size_of::<Entry>()) as u64).max(self.min_weight)
    }
}

pub struct Hit {
    pub raw: Vec<u8>,
    pub stale: bool,
    pub remaining_ttl: u32,
    pub remaining_ms: u64,
    pub orig_ttl: u32,
    pub had_edns: bool,
    /// NXDOMAIN/NODATA entry. Prefetch skips these.
    pub negative: bool,
    /// Learned over the plaintext fallback. Prefetch skips these.
    pub plain: bool,
}

/// Hit metadata without the response bytes. [`Cache::get_into`] writes the
/// patched response into the caller's buffer instead of allocating one.
pub struct HitMeta {
    pub stale: bool,
    pub remaining_ttl: u32,
    /// Remaining freshness in milliseconds (zero once stale); the prefetch
    /// window is decided on this, not on whole seconds.
    pub remaining_ms: u64,
    pub orig_ttl: u32,
    pub had_edns: bool,
    /// NXDOMAIN/NODATA entry. Prefetch skips these.
    pub negative: bool,
    /// Learned over the plaintext fallback. Prefetch skips these.
    pub plain: bool,
    /// The chain verdict, for an answer that has CNAME/DNAME targets.
    pub chain: Option<ChainHandle>,
}

pub struct Cache {
    inner: Option<QuickCache<CacheKey, Arc<Entry>, ByteWeighter, CacheHashBuilder>>,
    start: Instant,
    bytes: u64,
    negative_min: u32,
    negative_max: u32,
    /// Charged size above which an entry needs a second sight.
    large: u64,
    hasher: DefaultHashBuilder,
    /// Hashes of large keys seen once (0 is empty); consulted on insert only,
    /// so cache hits pay nothing.
    first_sight: Box<[AtomicU64]>,
    #[cfg(feature = "conformance-adapter")]
    observer: observer::Insertions,
}

impl Cache {
    /// A zero entry count or byte budget disables the cache. Both bounds are
    /// enforced: `min_weight` makes the weighted budget imply the count cap,
    /// and quick_cache enforces the weight budget per shard (each shard gets
    /// `ceil(cache_bytes / shards)` weight). The default hot allocation keeps
    /// the full S3-FIFO hot/cold/ghost queues; `insert` verifies residency
    /// because quick_cache silently drops an entry above a shard's admission
    /// threshold (97% of the per-shard cap). With `cache_size = 1` that
    /// threshold is below the weight floor (the whole byte budget), so no
    /// entry is ever admitted; the cache fails safe as effectively disabled.
    /// The shard count comes from the host's available parallelism, so the
    /// per-shard cap is not config-derived.
    pub fn new(cache_size: usize, cache_bytes: usize, negative_min: u64, negative_max: u64) -> Self {
        let inner = (cache_size > 0 && cache_bytes > 0).then(|| {
            let min_weight = (cache_bytes as u64).div_ceil(cache_size as u64);
            let options = OptionsBuilder::new()
                .estimated_items_capacity(cache_size)
                .weight_capacity(cache_bytes as u64)
                .build()
                .expect("valid cache options");
            QuickCache::with_options(
                options,
                ByteWeighter { min_weight },
                CacheHashBuilder::default(),
                DefaultLifecycle::default(),
            )
        });
        Self {
            inner,
            start: Instant::now().checked_sub(Duration::from_secs(TIME_ORIGIN)).unwrap_or_else(Instant::now),
            bytes: cache_bytes as u64,
            negative_min: negative_min.min(u32::MAX as u64) as u32,
            negative_max: negative_max.min(u32::MAX as u64) as u32,
            large: LARGE_FLOOR.max(cache_bytes as u64 / 256),
            hasher: DefaultHashBuilder::default(),
            first_sight: (0..FIRST_SIGHT_SLOTS).map(|_| AtomicU64::new(0)).collect(),
            #[cfg(feature = "conformance-adapter")]
            observer: observer::Insertions::default(),
        }
    }

    /// True when `key` was already seen once; otherwise remembers it.
    // Known limit: an attacker that sends every large name twice still fills the
    // cache; a frequency sketch would close that, at 4x the code.
    fn second_sight(&self, key: &[u8]) -> bool {
        let hash = self.hasher.hash_one(key) | 1;
        let buckets = self.first_sight.len() / FIRST_SIGHT_WAYS;
        let start = (hash >> 1) as usize % buckets * FIRST_SIGHT_WAYS;
        let bucket = &self.first_sight[start..start + FIRST_SIGHT_WAYS];
        if let Some(slot) = bucket.iter().find(|slot| slot.load(Ordering::Relaxed) == hash) {
            slot.store(0, Ordering::Relaxed);
            return true;
        }
        // Take an empty slot, else drop an arbitrary (hash-chosen) neighbour.
        let victim = bucket
            .iter()
            .find(|slot| slot.load(Ordering::Relaxed) == 0)
            .unwrap_or(&bucket[(hash >> 40) as usize % FIRST_SIGHT_WAYS]);
        victim.store(hash, Ordering::Relaxed);
        false
    }

    /// Live entry count and charged bytes, for `/metrics`.
    pub fn usage(&self) -> (u64, u64) {
        self.inner.as_ref().map_or((0, 0), |cache| (cache.len() as u64, cache.weight()))
    }

    /// Milliseconds since this cache was created.
    fn now_ms(&self) -> u64 {
        self.start.elapsed().as_millis().min(u64::MAX as u128) as u64
    }

    fn age_ms(&self, entry: &Entry) -> u64 {
        self.now_ms().saturating_sub(u64::from(entry.stored_at) * 1000 + u64::from(entry.stored_ms))
    }

    /// Returns a copy of the stored response with the client ID, aged TTLs,
    /// the RFC 8767 stale TTL and (for stale hits) AD cleared.
    pub fn get(&self, key: &[u8], id: u16, max_age: u64) -> Option<Hit> {
        let (entry, age_ms, stale) = self.lookup_entry(key, max_age)?;
        let mut raw = entry.raw.to_vec();
        let meta = patch_entry(&entry, age_ms, stale, id, &mut raw)?;
        Some(Hit {
            raw,
            stale: meta.stale,
            remaining_ttl: meta.remaining_ttl,
            remaining_ms: meta.remaining_ms,
            orig_ttl: meta.orig_ttl,
            had_edns: meta.had_edns,
            negative: meta.negative,
            plain: meta.plain,
        })
    }

    /// Like [`Cache::get`], but clears `out` and writes the patched response
    /// into its existing capacity. A hit on a warm buffer makes no allocator
    /// call; `get` stays for callers that need an owned `Vec`.
    pub fn get_into(&self, key: &[u8], id: u16, max_age: u64, out: &mut Vec<u8>) -> Option<HitMeta> {
        let (entry, age_ms, stale) = self.lookup_entry(key, max_age)?;
        out.clear();
        out.extend_from_slice(&entry.raw);
        let mut meta = patch_entry(&entry, age_ms, stale, id, out)?;
        if entry.flags & HAS_CHAIN != 0 {
            let state = ChainState(entry.chain.0.load(Ordering::Relaxed));
            meta.chain = Some(ChainHandle { entry, state });
        }
        Some(meta)
    }

    /// The entry, its age in milliseconds and whether it is stale, or `None`
    /// when the entry is absent, expired for `max_age` seconds or longer, or a
    /// plaintext-learned entry that has expired (those are never served stale).
    fn lookup_entry(&self, key: &[u8], max_age: u64) -> Option<(Arc<Entry>, u64, bool)> {
        let entry = self.inner.as_ref()?.get(key)?;
        let age_ms = self.age_ms(&entry);
        let lifetime_ms = u64::from(entry.orig_ttl) * 1000;
        let stale = age_ms >= lifetime_ms;
        // RFC 8767 §4: the maximum stale timer is the time a record may be
        // kept after it expires, so it counts from expiry, not from storage.
        // Measured from storage, a TTL at or above `max_age` got no stale
        // protection at all.
        if stale && (entry.flags & PLAIN != 0 || age_ms - lifetime_ms >= max_age.saturating_mul(1000)) {
            return None;
        }
        Some((entry, age_ms, stale))
    }

    /// Normalizes and stores `raw` under `key` when RFC 2308 / the negative
    /// policy allow caching. `age` is the HTTP Age reported by the upstream
    /// (zero for UDP). Returns whether the response was stored.
    pub fn insert(&self, key: &[u8], raw: &[u8], msg: &Message, age: u32) -> bool {
        self.insert_from(key, raw, msg, age, false, None)
    }

    /// [`Cache::insert`] for an answer learned over the plaintext fallback:
    /// lifetimes are capped at [`PLAIN_TTL_CAP`] and the entry is never served
    /// stale or prefetched.
    pub fn insert_plain(&self, key: &[u8], raw: &[u8], msg: &Message, age: u32) -> bool {
        self.insert_from(key, raw, msg, age, true, None)
    }

    /// [`Cache::insert`] or [`Cache::insert_plain`] that also records `chain`,
    /// the CNAME-target verdict for an answer whose chain has targets (`None`
    /// when it has none, or when the verdict is not wanted).
    pub fn insert_with_chain(
        &self,
        key: &[u8],
        raw: &[u8],
        msg: &Message,
        age: u32,
        plain: bool,
        chain: Option<ChainState>,
    ) -> bool {
        self.insert_from(key, raw, msg, age, plain, chain)
    }

    fn insert_from(
        &self,
        key: &[u8],
        raw: &[u8],
        msg: &Message,
        age: u32,
        plain: bool,
        chain: Option<ChainState>,
    ) -> bool {
        let Some(cache) = &self.inner else { return false };
        if msg.metadata.response_code == ResponseCode::NXDomain {
            invalidate_terminal_name(cache, key, msg);
        }
        let Some(mut entry) = self.normalize(raw, msg, age, plain) else { return false };
        if let Some(chain) = chain {
            entry.flags |= HAS_CHAIN;
            entry.chain = ChainCell(AtomicU16::new(chain.0));
        }
        if msg.metadata.response_code != ResponseCode::NXDomain {
            invalidate_alias_owners(cache, key, msg);
        }
        let cache_key = CacheKey::new(key);
        let weight = (cache_key.0.len() + entry.bytes() + size_of::<Entry>()) as u64;
        if weight > self.bytes {
            return false;
        }
        // A large entry already resident (a refresh) replaces itself;
        // a new one must be seen twice before it may displace anything.
        if weight > self.large && !cache.contains_key(key) && !self.second_sight(key) {
            return false;
        }
        #[cfg(feature = "conformance-adapter")]
        self.observer.record(msg);
        cache.insert(cache_key, Arc::new(entry));
        // quick_cache drops an entry heavier than the shard's admission
        // threshold (97% of the per-shard weight cap at the default hot
        // allocation) without reporting it. Only claim a store if resident.
        cache.contains_key(key)
    }

    /// Drops the entry for `key`: a newer valid answer that cannot be stored
    /// (TTL 0, too large) still supersedes it (as in unbound).
    pub fn remove(&self, key: &[u8]) {
        if let Some(cache) = &self.inner {
            cache.remove(key);
        }
    }

    /// A valid NXDOMAIN or NODATA that cannot be cached (no usable
    /// SOA) still ends stale service for the key. Removes the entry for `key`
    /// and, for NXDOMAIN, the older state of the terminal name. A NOERROR with
    /// no Answer and an NS authority is a referral, not a negative.
    pub fn invalidate_negative(&self, key: &[u8], msg: &Message) {
        let Some(cache) = &self.inner else { return };
        match msg.metadata.response_code {
            ResponseCode::NXDomain => invalidate_terminal_name(cache, key, msg),
            ResponseCode::NoError
                if msg.answers.is_empty() && !msg.authorities.iter().any(|r| matches!(r.data, RData::NS(_))) => {}
            _ => return,
        }
        cache.remove(key);
    }

    /// The negative lifetime the cache applies to `msg`, or `None` when the
    /// response is not a usable negative. The first relay uses it to clamp the
    /// SOA TTL before the cached template takes over later hits.
    pub fn negative_lifetime(&self, msg: &Message, age: u32) -> Option<u32> {
        let negative = match msg.metadata.response_code {
            ResponseCode::NXDomain => true,
            ResponseCode::NoError => matches!(answer_kind(msg), AnswerKind::NoData),
            _ => false,
        };
        if !negative {
            return None;
        }
        negative_ttl(msg, age).map(|ttl| ttl.clamp(self.negative_min, self.negative_max))
    }

    fn normalize(&self, raw: &[u8], msg: &Message, age: u32, plain: bool) -> Option<Entry> {
        let cap = if plain { PLAIN_TTL_CAP } else { MAX_TTL };
        if msg.signature.is_some()
            || msg.metadata.truncation
            || !matches!(msg.metadata.response_code, ResponseCode::NoError | ResponseCode::NXDomain)
        {
            return None;
        }
        // RFC 1035 §7.4: data learned for a name with a "*" label must never
        // build wildcard answers for other names, so none of it is cached.
        if msg.queries.first().is_some_and(|q| q.name().iter().any(|label| label == b"*")) {
            return None;
        }
        let fields = crate::wire::ttl_fields(raw)?;

        // Age and cap every stored TTL before it defines a lifetime.
        let mut stored = raw.to_vec();
        for &off in fields.offsets.iter() {
            let p = off as usize;
            let ttl = crate::wire::rfc8767_ttl(u32::from_be_bytes(stored.get(p..p + 4)?.try_into().ok()?));
            let ttl = ttl.saturating_sub(age).min(cap);
            stored.get_mut(p..p + 4)?.copy_from_slice(&ttl.to_be_bytes());
        }
        stored.get_mut(..2)?.copy_from_slice(&[0, 0]);

        // Zero-TTL data must never become a fresh or optimistic entry.
        let record_ttl = fields
            .offsets
            .iter()
            .filter_map(|&off| {
                let p = off as usize;
                Some(u32::from_be_bytes(stored.get(p..p + 4)?.try_into().ok()?))
            })
            .min()?;
        if record_ttl == 0 {
            return None;
        }

        let negative = match msg.metadata.response_code {
            ResponseCode::NXDomain => true,
            ResponseCode::NoError => match answer_kind(msg) {
                AnswerKind::Terminal => false,
                AnswerKind::NoData => true,
                AnswerKind::Ambiguous => return None,
            },
            _ => return None,
        };

        let (orig_ttl, soa_offset) = if negative {
            let ttl = negative_ttl(msg, age)?.clamp(self.negative_min, self.negative_max).min(cap);
            // A retained alias or proof RR with a shorter lifetime limits the
            // whole template (RFC 2308 §5). The SOA's own TTL is rewritten on every hit.
            let retained = fields
                .offsets
                .iter()
                .filter(|&&off| Some(off) != fields.soa)
                .filter_map(|&off| {
                    let p = off as usize;
                    Some(u32::from_be_bytes(stored.get(p..p + 4)?.try_into().ok()?))
                })
                .min()
                .unwrap_or(u32::MAX);
            let ttl = ttl.min(retained);
            if ttl == 0 {
                return None;
            }
            (ttl, fields.soa?)
        } else {
            (record_ttl, NO_SOA)
        };

        // Every RR keeps its own aged lifetime (RFC 1035 §3.2.1, RFC 2181 §8);
        // the template is fresh only until the earliest of them (`orig_ttl`).
        // AD is kept as stored: the caller clears it for anything but a
        // trusted DoH answer to an AD or DO client. A validating upstream caps
        // TTLs at its signatures' expiry (RFC 4035 §5.3.3), so a fresh hit is as
        // authentic as the first answer; a stale hit clears AD (`patch_entry`).
        // An answer learned over untrusted plaintext never asserts AD.
        if plain {
            crate::wire::clear_ad(&mut stored);
        }
        let mut flags = 0;
        if negative {
            flags |= NEGATIVE;
        }
        if msg.edns.is_some() {
            flags |= HAD_EDNS;
        }
        if plain {
            flags |= PLAIN;
        }
        if msg
            .queries
            .first()
            .is_some_and(|q| msg.answers.iter().any(|r| r.name == *q.name() && matches!(r.data, RData::CNAME(_))))
        {
            flags |= ALIAS;
        }
        let now_ms = self.now_ms();
        Some(Entry {
            raw: stored.into_boxed_slice(),
            offsets: fields.offsets,
            stored_at: (now_ms / 1000).min(u64::from(u32::MAX)) as u32,
            orig_ttl,
            flags,
            soa_offset,
            stored_ms: (now_ms % 1000) as u16,
            chain: ChainCell::default(),
        })
    }

    /// Test hook: makes an entry look `seconds` older.
    #[doc(hidden)]
    pub fn backdate(&self, key: &[u8], seconds: u32) {
        self.backdate_ms(key, u64::from(seconds) * 1000);
    }

    /// Test hook: makes an entry look `ms` milliseconds older.
    #[doc(hidden)]
    pub fn backdate_ms(&self, key: &[u8], ms: u64) {
        let Some(cache) = &self.inner else { return };
        if let Some(entry) = cache.get(key) {
            let mut entry = (*entry).clone();
            let stored = (u64::from(entry.stored_at) * 1000 + u64::from(entry.stored_ms)).saturating_sub(ms);
            entry.stored_at = (stored / 1000) as u32;
            entry.stored_ms = (stored % 1000) as u16;
            cache.insert(CacheKey::new(key), Arc::new(entry));
        }
    }
}

/// Test-only observation of the production cache (conformance adapter).
#[cfg(feature = "conformance-adapter")]
mod observer {
    use super::*;
    use std::{
        collections::BTreeMap,
        sync::{
            atomic::{AtomicU64, Ordering},
            Mutex,
        },
    };

    /// Monotonic insertion totals, bumped at the `quick_cache` insert call so
    /// an entry evicted at once still counts.
    #[derive(Default)]
    pub(super) struct Insertions {
        pub(super) total: AtomicU64,
        pub(super) per_type: Mutex<BTreeMap<u16, u64>>,
    }

    impl Insertions {
        pub(super) fn record(&self, msg: &Message) {
            self.total.fetch_add(1, Ordering::SeqCst);
            let mut per_type = self.per_type.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            for record in msg.answers.iter().chain(&msg.authorities).chain(&msg.additionals) {
                *per_type.entry(u16::from(record.record_type())).or_default() += 1;
            }
            // OPT and TSIG are held outside the section vectors by hickory.
            for (present, rtype) in [(msg.edns.is_some(), 41), (msg.signature.is_some(), 250)] {
                if present {
                    *per_type.entry(rtype).or_default() += 1;
                }
            }
        }
    }

    impl Cache {
        /// Entry count, charged bytes, insertion total and per-RR-type totals.
        pub fn observe(&self) -> (u64, u64, u64, BTreeMap<u16, u64>) {
            let (entries, bytes) = self.usage();
            let per_type = self.observer.per_type.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone();
            (entries, bytes, self.observer.total.load(Ordering::SeqCst), per_type)
        }

        /// Removes the entry for `key` through the cache's own removal path;
        /// `only_stale` keeps a fresh entry. True when something was removed.
        pub fn evict(&self, key: &[u8], only_stale: bool) -> bool {
            let Some(cache) = &self.inner else { return false };
            if only_stale {
                let Some(entry) = cache.get(key) else { return false };
                if self.age_ms(&entry) < u64::from(entry.orig_ttl) * 1000 {
                    return false;
                }
            }
            cache.remove(key).is_some()
        }
    }
}

/// QTYPEs probed by [`invalidate_terminal_name`].
const INVALIDATED_TYPES: [u16; 16] = [1, 2, 5, 6, 12, 15, 16, 28, 33, 35, 43, 48, 52, 64, 65, 257];

/// An accepted terminal NXDOMAIN cannot coexist with older fresh or stale
/// state for the terminal name. That is the last CNAME target, not blindly the
/// asked alias. Bounded probe of the common QTYPEs and every key flag
/// combination: O(1) work on an insert that already followed an upstream
/// round trip. Known limit: an unusual QTYPE keeps its old entry until it ages
/// out; a name-to-keys reverse index would close that if it ever matters.
fn invalidate_terminal_name(
    cache: &QuickCache<CacheKey, Arc<Entry>, ByteWeighter, CacheHashBuilder>,
    key: &[u8],
    msg: &Message,
) {
    let Some(query) = msg.queries.first() else { return };
    let mut name = query.name().clone();
    for _ in 0..8 {
        match msg.answers.iter().find(|r| r.name == name && matches!(r.data, RData::CNAME(_))) {
            Some(Record { data: RData::CNAME(cname), .. }) => name = cname.0.clone(),
            _ => break,
        }
    }
    invalidate_owner(cache, key, &name, false);
}

/// A new CNAME at an owner leaves no older address (or other) answer for that
/// owner, fresh or stale (RFC 2181 §10.1). Applies to the
/// first [`ALIAS_OWNERS`] CNAME owners of the response, never to the entry
/// being inserted. An entry that itself answers with a CNAME at that owner
/// (the AAAA beside a new A of a dual-stack alias, or a rotated CDN target) is
/// not an ordinary answer and stays: each chain keeps its own entry.
const ALIAS_OWNERS: usize = 4;

fn invalidate_alias_owners(
    cache: &QuickCache<CacheKey, Arc<Entry>, ByteWeighter, CacheHashBuilder>,
    key: &[u8],
    msg: &Message,
) {
    let mut done: Vec<&Name> = Vec::new();
    for record in &msg.answers {
        if matches!(record.data, RData::CNAME(_)) && !done.contains(&&record.name) && done.len() < ALIAS_OWNERS {
            done.push(&record.name);
            invalidate_owner(cache, key, &record.name, true);
        }
    }
}

/// Removes every common-QTYPE, every-flag-combination entry of `name` in the
/// class of `key`, except `key` itself and, with `keep_aliases`, entries that
/// hold a CNAME at `name`.
fn invalidate_owner(
    cache: &QuickCache<CacheKey, Arc<Entry>, ByteWeighter, CacheHashBuilder>,
    key: &[u8],
    name: &Name,
    keep_aliases: bool,
) {
    let Some(tail) = key.len().checked_sub(5).map(|n| &key[n..]) else { return };
    let mut probe = Vec::with_capacity(name.len() + 5 + 1);
    for label in name.iter() {
        probe.push(label.len() as u8);
        probe.extend(label.iter().map(u8::to_ascii_lowercase));
    }
    probe.push(0);
    let base = probe.len();
    probe.extend_from_slice(&[0, 0, tail[2], tail[3], 0]);
    for qtype in INVALIDATED_TYPES {
        probe[base..base + 2].copy_from_slice(&qtype.to_be_bytes());
        for flags in 0..16u8 {
            probe[base + 4] = flags;
            if probe == key {
                continue;
            }
            if keep_aliases {
                match cache.peek(probe.as_slice()) {
                    None => continue,
                    Some(entry) if entry.flags & ALIAS != 0 => continue,
                    Some(_) => {}
                }
            }
            cache.remove(probe.as_slice());
        }
    }
}

/// The per-hit transformation shared by [`Cache::get`] and
/// [`Cache::get_into`]: client ID, aged TTLs, RFC 8767 stale TTL, the
/// negative entry's remaining SOA lifetime and AD clearing on a stale hit.
fn patch_entry(entry: &Entry, age_ms: u64, stale: bool, id: u16, raw: &mut [u8]) -> Option<HitMeta> {
    let age = (age_ms / 1000).min(u64::from(u32::MAX)) as u32;
    patch(raw, &entry.offsets, age, stale, id);
    if entry.soa_offset != NO_SOA {
        // The stored SOA TTL is the negative lifetime; keep emitting it after
        // aging rather than the record's original TTL.
        let remaining = if stale { STALE_TTL } else { entry.orig_ttl.saturating_sub(age) };
        let p = entry.soa_offset as usize;
        raw.get_mut(p..p + 4)?.copy_from_slice(&remaining.to_be_bytes());
    }
    if stale {
        crate::wire::clear_ad(raw);
    }
    Some(HitMeta {
        stale,
        remaining_ttl: entry.orig_ttl.saturating_sub(age),
        remaining_ms: (u64::from(entry.orig_ttl) * 1000).saturating_sub(age_ms),
        orig_ttl: entry.orig_ttl,
        had_edns: entry.flags & HAD_EDNS != 0,
        negative: entry.flags & NEGATIVE != 0,
        plain: entry.flags & PLAIN != 0,
        chain: None,
    })
}

enum AnswerKind {
    /// The answer section holds the queried type for the name (or the final
    /// CNAME target).
    Terminal,
    /// No terminal answer; negative if an SOA proves it.
    NoData,
    /// A loop, conflicting CNAMEs or an over-long chain: do not cache.
    Ambiguous,
}

fn answer_kind(msg: &Message) -> AnswerKind {
    let Some(query) = msg.queries.first() else { return AnswerKind::Ambiguous };
    let qtype = query.query_type();
    let mut name = query.name().clone();
    for _ in 0..8 {
        let mut terminal = false;
        let mut ambiguous = false;
        let mut target = None;
        for record in &msg.answers {
            if record.name != name {
                continue;
            }
            if record.record_type() == qtype {
                terminal = true;
            } else if let RData::CNAME(cname) = &record.data {
                match &target {
                    None => target = Some(cname.0.clone()),
                    Some(existing) if existing != &cname.0 => ambiguous = true,
                    Some(_) => {}
                }
            }
        }
        if terminal {
            return AnswerKind::Terminal;
        }
        if ambiguous {
            return AnswerKind::Ambiguous;
        }
        let Some(next) = target else { return AnswerKind::NoData };
        name = next;
    }
    AnswerKind::Ambiguous
}

/// RFC 2308 §5: `min(SOA TTL, SOA MINIMUM)`, minus the HTTP Age.
fn negative_ttl(msg: &Message, age: u32) -> Option<u32> {
    // RFC 1034 §4.3.4 and RFC 2308 §5: the SOA that sets the lifetime is the
    // one of the zone holding the name the denial is about. That is the end of
    // the CNAME chain from QNAME: the aliases are positive data from their own
    // zones, the denial concerns the name they lead to.
    let mut denied = msg.queries.first().map(|q| q.name().clone());
    for _ in 0..crate::wire::MAX_CHAIN_STEPS {
        let next = denied.as_ref().and_then(|current| {
            msg.answers.iter().find_map(|r| match &r.data {
                RData::CNAME(target) if r.name == *current => Some(target.0.clone()),
                _ => None,
            })
        });
        match next {
            Some(target) => denied = Some(target),
            None => break,
        }
    }
    let mut ttl = None;
    for record in &msg.authorities {
        if !denied.as_ref().is_some_and(|name| record.name.zone_of(name)) {
            continue;
        }
        if let RData::SOA(soa) = &record.data {
            let capped = crate::wire::rfc8767_ttl;
            let value = capped(record.ttl).min(capped(soa.minimum)).saturating_sub(age);
            ttl = Some(ttl.map_or(value, |current: u32| current.min(value)));
        }
    }
    ttl
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire;
    use hickory_proto::{
        op::{MessageType, OpCode, Query},
        rr::{
            rdata::{
                tsig::{TsigAlgorithm, TSIG},
                A, AAAA, SOA,
            },
            Name, Record, RecordType,
        },
    };

    fn name(text: &str) -> Name {
        Name::from_ascii(text).unwrap()
    }

    fn wire_name(text: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in text.trim_end_matches('.').split('.').filter(|label| !label.is_empty()) {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    /// Builds a query and its canonical key. `flags` are the wire header's CD
    /// (0x10) and AD (0x20) bits; `do_bit` adds an EDNS OPT with DO.
    fn query_key(text: &str, qtype: u16, qclass: u16, flags: u16, do_bit: bool) -> (Vec<u8>, Vec<u8>) {
        query_key_edns(text, qtype, qclass, flags, do_bit.then_some(0x8000))
    }

    /// `edns_flags` is `None` for no OPT, or the 16-bit EDNS flags field.
    fn query_key_edns(text: &str, qtype: u16, qclass: u16, flags: u16, edns_flags: Option<u16>) -> (Vec<u8>, Vec<u8>) {
        let mut raw = vec![0x12, 0x34];
        raw.extend_from_slice(&(0x0100 | flags).to_be_bytes());
        raw.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
        raw.extend_from_slice(&wire_name(text));
        raw.extend_from_slice(&qtype.to_be_bytes());
        raw.extend_from_slice(&qclass.to_be_bytes());
        if let Some(edns_flags) = edns_flags {
            raw[10..12].copy_from_slice(&1u16.to_be_bytes());
            raw.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0x00, 0x00]);
            raw.extend_from_slice(&edns_flags.to_be_bytes());
            raw.extend_from_slice(&[0, 0]);
        }
        let view = wire::parse_query(&raw).unwrap();
        let mut buffer = [0u8; wire::MIN_CANONICAL_BUFFER];
        let len = wire::canonical_key(&view, &mut buffer).unwrap();
        (raw, buffer[..len].to_vec())
    }

    fn positive(text: &str, qtype: RecordType, ttl: u32, answers: usize, edns: bool) -> (Message, Vec<u8>) {
        let mut msg = Message::new(0x1234, MessageType::Response, OpCode::Query);
        msg.metadata.recursion_desired = true;
        msg.metadata.recursion_available = true;
        msg.add_query(Query::query(name(text), qtype));
        for i in 0..answers {
            msg.add_answer(Record::from_rdata(name(text), ttl, RData::A(A::new(192, 0, 2, i as u8))));
        }
        if edns {
            msg.edns.get_or_insert_with(Default::default).set_dnssec_ok(true);
        }
        let raw = msg.to_vec().unwrap();
        (msg, raw)
    }

    fn negative(
        text: &str,
        qtype: RecordType,
        rcode: ResponseCode,
        cname: bool,
        soa: Option<(u32, u32)>,
    ) -> (Message, Vec<u8>) {
        let mut msg = Message::new(0x1234, MessageType::Response, OpCode::Query);
        msg.metadata.recursion_desired = true;
        msg.metadata.recursion_available = true;
        msg.metadata.response_code = rcode;
        msg.add_query(Query::query(name(text), qtype));
        if cname {
            msg.add_answer(Record::from_rdata(
                name(text),
                300,
                RData::CNAME(hickory_proto::rr::rdata::CNAME(name("target.test."))),
            ));
        }
        if let Some((ttl, minimum)) = soa {
            msg.add_authority(Record::from_rdata(
                Name::root(),
                ttl,
                RData::SOA(SOA::new(Name::root(), Name::root(), 0, 0, 0, 0, minimum)),
            ));
        }
        let raw = msg.to_vec().unwrap();
        (msg, raw)
    }

    fn new_cache(size: usize, bytes: usize) -> Cache {
        Cache::new(size, bytes, 0, 10_800)
    }

    fn answer_ttl(raw: &[u8], index: usize) -> u32 {
        Message::from_vec(raw).unwrap().answers[index].ttl
    }

    #[test]
    fn key_case_flags_and_round_trip() {
        let (_, lower) = query_key("mixed.test", 1, 1, 0, false);
        let (_, upper) = query_key("MiXeD.TeSt", 1, 1, 0, false);
        assert_eq!(lower, upper);
        let qname = wire_name("mixed.test");
        assert_eq!(&lower[..qname.len()], qname.as_slice());
        assert_eq!(*lower.last().unwrap(), 0);

        let (_, aaaa) = query_key("mixed.test", 28, 1, 0, false);
        let (_, chaos) = query_key("mixed.test", 1, 3, 0, false);
        assert_ne!(lower, aaaa);
        assert_ne!(lower, chaos);

        let (_, cd) = query_key("mixed.test", 1, 1, 0x10, false);
        let (_, ad) = query_key("mixed.test", 1, 1, 0x20, false);
        let (_, do_bit) = query_key("mixed.test", 1, 1, 0, true);
        let (_, edns_no_do) = query_key_edns("mixed.test", 1, 1, 0, Some(0));
        assert_eq!(*cd.last().unwrap(), 0b0010);
        assert_eq!(*ad.last().unwrap(), 0b0100);
        assert_eq!(*do_bit.last().unwrap(), 0b1001);
        assert_eq!(*edns_no_do.last().unwrap(), 0b1000);
        assert_ne!(edns_no_do, lower);
        assert_ne!(edns_no_do, do_bit);
    }

    #[test]
    fn ttl_arithmetic_stale_and_ad() {
        let (_, key) = query_key("x.test", 1, 1, 0, true);
        let (mut msg, _) = positive("x.test.", RecordType::A, 100, 1, true);
        msg.metadata.authentic_data = true;
        let raw = msg.to_vec().unwrap();
        let c = new_cache(10, 1 << 20);
        assert!(c.insert(&key, &raw, &msg, 0));

        let hit = c.get(&key, 123, 43_200).unwrap();
        assert!(!hit.stale);
        assert_eq!(hit.orig_ttl, 100);
        assert_eq!(hit.remaining_ttl, 100);
        assert!(hit.had_edns);
        assert_eq!(Message::from_vec(&hit.raw).unwrap().metadata.id, 123);
        assert_eq!(answer_ttl(&hit.raw, 0), 100);
        // A fresh hit keeps the AD it was stored with (the caller stores AD
        // only for a trusted DoH answer to an AD or DO client).
        assert_eq!(wire::header(&hit.raw).unwrap().flags & 0x20, 0x20);

        c.backdate(&key, 40);
        let hit = c.get(&key, 2, 43_200).unwrap();
        assert!(!hit.stale);
        assert_eq!(answer_ttl(&hit.raw, 0), 60);
        assert_eq!(hit.remaining_ttl, 60);

        c.backdate(&key, 61);
        assert!(c.get(&key, 2, 1).is_none(), "1 s past expiry closes a 1 s stale window");
        assert!(c.get(&key, 2, 2).is_some());
        let hit = c.get(&key, 2, 43_200).unwrap();
        assert!(hit.stale);
        assert_eq!(hit.remaining_ttl, 0);
        assert_eq!(answer_ttl(&hit.raw, 0), 30);
        assert_eq!(wire::header(&hit.raw).unwrap().flags & 0x20, 0, "a stale hit never asserts AD");
    }

    #[test]
    fn records_keep_their_own_lifetimes_and_stale_keeps_unexpired_ones() {
        let (_, key) = query_key("rrset.test", 1, 1, 0, false);
        let mut msg = Message::new(0x1234, MessageType::Response, OpCode::Query);
        msg.metadata.recursion_desired = true;
        msg.add_query(Query::query(name("rrset.test."), RecordType::A));
        msg.add_answer(Record::from_rdata(name("rrset.test."), 600, RData::A(A::new(192, 0, 2, 1))));
        msg.add_answer(Record::from_rdata(
            name("rrset.test."),
            60,
            RData::AAAA(AAAA::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)),
        ));
        let raw = msg.to_vec().unwrap();
        let c = new_cache(10, 1 << 20);
        assert!(c.insert(&key, &raw, &msg, 0));

        let hit = c.get(&key, 9, 43_200).unwrap();
        assert_eq!(hit.orig_ttl, 60, "fresh only until the earliest lifetime");
        assert_eq!((answer_ttl(&hit.raw, 0), answer_ttl(&hit.raw, 1)), (600, 60));

        c.backdate(&key, 20);
        let hit = c.get(&key, 9, 43_200).unwrap();
        assert_eq!((answer_ttl(&hit.raw, 0), answer_ttl(&hit.raw, 1)), (580, 40));

        // Only the expired record gets the stale TTL (RFC 8767 §4).
        c.backdate(&key, 40);
        assert!(c.get(&key, 9, 0).is_none(), "a zero stale window serves nothing expired");
        let stale = c.get(&key, 9, 43_200).unwrap();
        assert!(stale.stale);
        assert_eq!((answer_ttl(&stale.raw, 0), answer_ttl(&stale.raw, 1)), (540, 30));
    }

    /// RFC 8767 §4: the stale window starts when the record expires. Counted
    /// from storage, a TTL at or above `max_age` never got stale protection.
    #[test]
    fn the_stale_window_counts_from_expiry() {
        let c = new_cache(10, 1 << 20);
        let (_, key) = query_key("long.test", 1, 1, 0, false);
        let (msg, raw) = positive("long.test.", RecordType::A, 7200, 1, false);
        assert!(c.insert(&key, &raw, &msg, 0));
        c.backdate(&key, 7200 + 10);
        let hit = c.get(&key, 1, 3600).expect("expired 10 s ago, inside a 1 h stale window");
        assert!(hit.stale);
        c.backdate(&key, 3600 - 11);
        assert!(c.get(&key, 1, 3600).is_some(), "1 s before the window closes");
        c.backdate(&key, 1);
        assert!(c.get(&key, 1, 3600).is_none(), "max_age after expiry the entry is gone");
    }

    #[test]
    fn terminal_nxdomain_invalidates_older_positive_state() {
        let c = new_cache(100, 1 << 20);
        let (_, a_key) = query_key("term.test", 1, 1, 0, false);
        let (_, a_do) = query_key("term.test", 1, 1, 0, true);
        let (_, other) = query_key("other.test", 1, 1, 0, false);
        for key in [&a_key, &a_do] {
            let (msg, raw) = positive("term.test.", RecordType::A, 60, 1, key == &a_do);
            assert!(c.insert(key, &raw, &msg, 0));
        }
        let (msg, raw) = positive("other.test.", RecordType::A, 60, 1, false);
        assert!(c.insert(&other, &raw, &msg, 0));
        let (_, aaaa) = query_key("term.test", 28, 1, 0, false);
        let (msg, raw) = negative("term.test", RecordType::AAAA, ResponseCode::NXDomain, false, Some((60, 60)));
        assert!(c.insert(&aaaa, &raw, &msg, 0));
        assert!(c.get(&a_key, 1, 43_200).is_none());
        assert!(c.get(&a_do, 1, 43_200).is_none());
        assert!(c.get(&aaaa, 1, 43_200).is_some(), "the new NXDOMAIN itself stays");
        assert!(c.get(&other, 1, 43_200).is_some());
    }

    #[test]
    fn alias_lifetime_limits_the_negative_template() {
        let c = new_cache(10, 1 << 20);
        let (_, key) = query_key("alias-short.test", 1, 1, 0, false);
        let (mut msg, _) = negative("alias-short.test", RecordType::A, ResponseCode::NXDomain, true, Some((100, 100)));
        msg.answers[0].ttl = 1;
        let raw = msg.to_vec().unwrap();
        assert!(c.insert(&key, &raw, &msg, 0));
        assert_eq!(c.get(&key, 1, 43_200).unwrap().orig_ttl, 1);
        c.backdate(&key, 1);
        assert!(c.get(&key, 1, 43_200).unwrap().stale, "expired at the alias lifetime");
    }

    #[test]
    fn negative_cname_ttl_bounds_the_template_and_is_never_raised() {
        // NXDOMAIN with a CNAME answer (TTL 30) and an authority SOA (TTL
        // 3600 / MINIMUM 3600): the RFC 2308 lifetime is 3600, but RFC 2181 §5
        // forbids raising the CNAME's own TTL to match it.
        let (_, key) = query_key("alias.test", 1, 1, 0, false);
        let mut msg = Message::new(0x1234, MessageType::Response, OpCode::Query);
        msg.metadata.recursion_desired = true;
        msg.metadata.recursion_available = true;
        msg.metadata.response_code = ResponseCode::NXDomain;
        msg.add_query(Query::query(name("alias.test."), RecordType::A));
        msg.add_answer(Record::from_rdata(
            name("alias.test."),
            30,
            RData::CNAME(hickory_proto::rr::rdata::CNAME(name("target.test."))),
        ));
        msg.add_authority(Record::from_rdata(
            Name::root(),
            3600,
            RData::SOA(SOA::new(Name::root(), Name::root(), 0, 0, 0, 0, 3600)),
        ));
        let raw = msg.to_vec().unwrap();
        let c = new_cache(10, 1 << 20);
        assert!(c.insert(&key, &raw, &msg, 0));

        // The stored template zeroes the ID and leaves both TTLs as sent.
        // (The 30 s alias, not the SOA, bounds the template lifetime.)
        let stored = c.inner.as_ref().unwrap().get(key.as_slice()).unwrap();
        let mut expected_template = raw.clone();
        expected_template[..2].copy_from_slice(&[0, 0]);
        assert_eq!(stored.raw.as_ref(), expected_template.as_slice());

        let hit = c.get(&key, 9, 43_200).unwrap();
        assert_eq!(hit.orig_ttl, 30);
        assert_eq!(answer_ttl(&hit.raw, 0), 30);
        assert_eq!(Message::from_vec(&hit.raw).unwrap().authorities[0].ttl, 30);

        // Only ID/TTL bytes differ from the stored template; at age 0 the TTLs
        // are rewritten to the same values, so only the ID changes.
        let mut expected_hit = stored.raw.to_vec();
        expected_hit[..2].copy_from_slice(&9u16.to_be_bytes());
        let soa = stored.soa_offset as usize;
        expected_hit[soa..soa + 4].copy_from_slice(&30u32.to_be_bytes());
        assert_eq!(hit.raw, expected_hit);
    }

    #[test]
    fn uncacheable_responses_are_refused() {
        let c = new_cache(10, 1 << 20);
        let (_, key) = query_key("bad.test", 1, 1, 0, false);

        let (mut msg, _) = positive("bad.test.", RecordType::A, 60, 1, false);
        msg.metadata.truncation = true;
        let raw = msg.to_vec().unwrap();
        assert!(!c.insert(&key, &raw, &msg, 0));
        assert!(c.get(&key, 1, 43_200).is_none());

        let mut msg = Message::new(0x1234, MessageType::Response, OpCode::Query);
        msg.metadata.response_code = ResponseCode::ServFail;
        msg.add_query(Query::query(name("bad.test."), RecordType::A));
        let raw = msg.to_vec().unwrap();
        assert!(!c.insert(&key, &raw, &msg, 0));
        assert!(c.get(&key, 1, 43_200).is_none());

        let (mut msg, raw) = positive("bad.test.", RecordType::A, 60, 1, false);
        msg.signature = Some(Box::new(Record::from_rdata(
            Name::root(),
            0,
            TSIG::new(TsigAlgorithm::HmacSha256, 0, 300, Vec::new(), 0x1234, None, Vec::new()),
        )));
        assert!(!c.insert(&key, &raw, &msg, 0));
        assert!(c.get(&key, 1, 43_200).is_none());
    }

    #[test]
    fn negative_classification_and_soa_clamp() {
        let (_, key) = query_key("nx.test", 1, 1, 0, false);
        let (msg, raw) = negative("nx.test", RecordType::A, ResponseCode::NXDomain, false, Some((100, 20)));
        let c = new_cache(10, 1 << 20);
        assert!(c.insert(&key, &raw, &msg, 0));
        let hit = c.get(&key, 6, 43_200).unwrap();
        assert_eq!(hit.orig_ttl, 20);
        assert_eq!(Message::from_vec(&hit.raw).unwrap().authorities[0].ttl, 20);
        c.backdate(&key, 15);
        assert_eq!(Message::from_vec(&c.get(&key, 6, 43_200).unwrap().raw).unwrap().authorities[0].ttl, 5);

        // NODATA with a CNAME to a name with no answer still has an SOA.
        let (_, cname_key) = query_key("alias.test", 1, 1, 0, false);
        let (msg, raw) = negative("alias.test", RecordType::A, ResponseCode::NoError, true, Some((300, 60)));
        assert!(c.insert(&cname_key, &raw, &msg, 0));
        assert_eq!(c.get(&cname_key, 1, 43_200).unwrap().orig_ttl, 60);

        // SOA-less NXDOMAIN, referrals and ambiguous chains are not cached.
        let (msg, raw) = negative("nosoa.test", RecordType::A, ResponseCode::NXDomain, false, None);
        let (_, key) = query_key("nosoa.test", 1, 1, 0, false);
        assert!(!c.insert(&key, &raw, &msg, 0));

        let mut referral = Message::new(0x1234, MessageType::Response, OpCode::Query);
        referral.add_query(Query::query(name("referral.test."), RecordType::A));
        referral.add_authority(Record::from_rdata(
            name("referral.test."),
            300,
            RData::NS(hickory_proto::rr::rdata::NS(name("ns.test."))),
        ));
        let raw = referral.to_vec().unwrap();
        let (_, key) = query_key("referral.test", 1, 1, 0, false);
        assert!(!c.insert(&key, &raw, &referral, 0));

        let mut looped = Message::new(0x1234, MessageType::Response, OpCode::Query);
        looped.add_query(Query::query(name("loop.test."), RecordType::A));
        looped.add_answer(Record::from_rdata(
            name("loop.test."),
            300,
            RData::CNAME(hickory_proto::rr::rdata::CNAME(name("a.test."))),
        ));
        looped.add_answer(Record::from_rdata(
            name("a.test."),
            300,
            RData::CNAME(hickory_proto::rr::rdata::CNAME(name("loop.test."))),
        ));
        looped.add_authority(Record::from_rdata(
            Name::root(),
            100,
            RData::SOA(SOA::new(Name::root(), Name::root(), 0, 0, 0, 0, 60)),
        ));
        let raw = looped.to_vec().unwrap();
        let (_, key) = query_key("loop.test", 1, 1, 0, false);
        assert!(!c.insert(&key, &raw, &looped, 0));

        // A zero SOA minimum is zero-TTL data and is not cached.
        let (msg, raw) = negative("zero.test", RecordType::A, ResponseCode::NXDomain, false, Some((100, 0)));
        let (_, key) = query_key("zero.test", 1, 1, 0, false);
        assert!(!c.insert(&key, &raw, &msg, 0));
    }

    #[test]
    fn negative_floor_cap_and_age() {
        let c = Cache::new(10, 1 << 20, 10, 15);
        let (_, key) = query_key("clamp.test", 1, 1, 0, false);
        let (msg, raw) = negative("clamp.test", RecordType::A, ResponseCode::NXDomain, false, Some((100, 20)));
        assert!(c.insert(&key, &raw, &msg, 0));
        // The configured floor is the documented local extension.
        assert_eq!(c.get(&key, 1, 43_200).unwrap().orig_ttl, 15);

        let (_, key) = query_key("floor.test", 1, 1, 0, false);
        let (msg, raw) = negative("floor.test", RecordType::A, ResponseCode::NXDomain, false, Some((100, 5)));
        assert!(c.insert(&key, &raw, &msg, 0));
        assert_eq!(c.get(&key, 1, 43_200).unwrap().orig_ttl, 10);

        let c = new_cache(10, 1 << 20);
        let (_, key) = query_key("age.test", 1, 1, 0, false);
        let (msg, raw) = negative("age.test", RecordType::A, ResponseCode::NXDomain, false, Some((100, 20)));
        assert!(c.insert(&key, &raw, &msg, 5));
        let hit = c.get(&key, 1, 43_200).unwrap();
        assert_eq!(hit.orig_ttl, 15);
        assert_eq!(Message::from_vec(&hit.raw).unwrap().authorities[0].ttl, 15);
    }

    #[test]
    fn a_ttl_with_the_top_bit_set_is_capped() {
        // RFC 8767 §4: positive, capped (7 days over DoH, 300 s over plaintext).
        let c = new_cache(10, 1 << 20);
        for (i, ttl) in [0x8000_0000, u32::MAX].into_iter().enumerate() {
            let (_, key) = query_key(&format!("msb{i}.test"), 1, 1, 0, false);
            let (msg, raw) = positive(&format!("msb{i}.test."), RecordType::A, ttl, 1, false);
            assert!(c.insert(&key, &raw, &msg, 0), "a DoH answer");
            assert_eq!(c.get(&key, 1, 43_200).unwrap().orig_ttl, MAX_TTL);
            assert!(c.insert_plain(&key, &raw, &msg, 0), "a plaintext answer");
            assert_eq!(c.get(&key, 1, 43_200).unwrap().orig_ttl, PLAIN_TTL_CAP);
        }
        // The SOA TTL and MINIMUM are capped the same way.
        for soa in [(0x8000_0000, 300), (300, 0x8000_0000)] {
            let (msg, _) = negative("nx.test.", RecordType::A, ResponseCode::NXDomain, false, Some(soa));
            assert_eq!(negative_ttl(&msg, 0), Some(300));
        }
    }

    #[test]
    fn positive_cap_and_zero_ttl() {
        let c = new_cache(10, 1 << 20);
        let (_, key) = query_key("cap.test", 1, 1, 0, false);
        let (msg, raw) = positive("cap.test.", RecordType::A, 1_000_000, 1, false);
        assert!(c.insert(&key, &raw, &msg, 0));
        let hit = c.get(&key, 1, 43_200).unwrap();
        assert_eq!(hit.orig_ttl, 604_800);
        assert_eq!(answer_ttl(&hit.raw, 0), 604_800);

        let (_, key) = query_key("zero.test", 1, 1, 0, false);
        let (msg, raw) = positive("zero.test.", RecordType::A, 0, 1, false);
        assert!(!c.insert(&key, &raw, &msg, 0));
        assert!(c.get(&key, 1, 43_200).is_none());

        let (_, key) = query_key("aged.test", 1, 1, 0, false);
        let (msg, raw) = positive("aged.test.", RecordType::A, 30, 1, false);
        assert!(!c.insert(&key, &raw, &msg, 30));

        let (_, key) = query_key("aged2.test", 1, 1, 0, false);
        let (msg, raw) = positive("aged2.test.", RecordType::A, 100, 1, false);
        assert!(c.insert(&key, &raw, &msg, 40));
        let hit = c.get(&key, 1, 43_200).unwrap();
        assert_eq!(hit.orig_ttl, 60);
        assert_eq!(answer_ttl(&hit.raw, 0), 60);
    }

    #[test]
    fn byte_and_entry_caps_and_oversized_entry() {
        let c = new_cache(8, 1 << 20);
        for i in 0..200 {
            let (_, key) = query_key(&format!("k{i}.test"), 1, 1, 0, false);
            let (msg, raw) = positive(&format!("k{i}.test."), RecordType::A, 300, 1, false);
            assert!(c.insert(&key, &raw, &msg, 0));
        }
        // Eight entries of ~131 KiB weight fill the 1 MiB budget exactly.
        assert_eq!(c.inner.as_ref().unwrap().len(), 8);
        let (_, newest) = query_key("k199.test", 1, 1, 0, false);
        assert!(c.get(&newest, 1, 43_200).is_some());

        let c = new_cache(10_000, 64 * 1024);
        for i in 0..2000 {
            let (_, key) = query_key(&format!("b{i}.test"), 1, 1, 0, false);
            let (msg, raw) = positive(&format!("b{i}.test."), RecordType::A, 300, 1, false);
            assert!(c.insert(&key, &raw, &msg, 0));
        }
        let inner = c.inner.as_ref().unwrap();
        assert!(!inner.is_empty());
        assert!(inner.len() < 2000);
        assert!(inner.weight() <= 64 * 1024);

        let small = new_cache(64, 512);
        let (_, key) = query_key("big.test", 1, 1, 0, false);
        let (msg, raw) = positive("big.test.", RecordType::A, 300, 100, false);
        assert!(raw.len() > 512);
        assert!(!small.insert(&key, &raw, &msg, 0));

        let (_, key) = query_key("off.test", 1, 1, 0, false);
        let (msg, raw) = positive("off.test.", RecordType::A, 300, 1, false);
        assert!(!Cache::new(0, 1 << 20, 0, 100).insert(&key, &raw, &msg, 0));
        assert!(Cache::new(64, 0, 0, 100).get(&key, 1, 43_200).is_none());
    }

    #[test]
    fn cache_size_one_admits_nothing() {
        // The weight floor is the whole byte budget, above the 97% per-shard
        // admission threshold (quick_cache collapses to one shard here), so
        // every insert is dropped safely rather than panicking.
        let c = Cache::new(1, 1 << 20, 0, 100);
        let (_, key) = query_key("single.test", 1, 1, 0, false);
        let (msg, raw) = positive("single.test.", RecordType::A, 300, 1, false);
        assert!(!c.insert(&key, &raw, &msg, 0));
        assert!(c.get(&key, 1, 43_200).is_none());
    }

    #[test]
    fn insert_reports_entries_dropped_by_a_shard() {
        // A ~20 KiB response fits the 64 KiB total budget but not the per-shard
        // weight cap, and quick_cache drops it without an error.
        let c = new_cache(10_000, 64 * 1024);
        let (_, key) = query_key("shard.test", 1, 1, 0, false);
        let (msg, raw) = positive("shard.test.", RecordType::A, 300, 1200, false);
        let weight =
            (key.len() + raw.len() + wire::ttl_offsets(&raw).unwrap().len() * size_of::<u16>() + size_of::<Entry>())
                as u64;
        assert!(weight <= 64 * 1024);
        assert!(weight > c.inner.as_ref().unwrap().shard_capacity());
        assert!(!c.insert(&key, &raw, &msg, 0));
        assert!(c.get(&key, 1, 43_200).is_none());
    }

    #[test]
    fn get_into_matches_get_and_reuses_capacity() {
        let (_, key) = query_key("into.test", 1, 1, 0, true);
        let (mut msg, _) = positive("into.test.", RecordType::A, 100, 1, true);
        msg.metadata.authentic_data = true;
        let raw = msg.to_vec().unwrap();
        let c = new_cache(10, 1 << 20);
        assert!(c.insert(&key, &raw, &msg, 0));

        let hit = c.get(&key, 9, 43_200).unwrap();
        let mut out = Vec::with_capacity(hit.raw.len());
        let capacity = out.capacity();
        let meta = c.get_into(&key, 9, 43_200, &mut out).unwrap();
        assert_eq!(out, hit.raw, "get_into and get produce the same bytes");
        assert_eq!(meta.stale, hit.stale);
        assert_eq!(meta.remaining_ttl, hit.remaining_ttl);
        assert_eq!(meta.orig_ttl, hit.orig_ttl);
        assert_eq!(meta.had_edns, hit.had_edns);
        assert_eq!(meta.negative, hit.negative);
        assert_eq!(out.capacity(), capacity, "a warm buffer is reused");

        // A stale hit takes the same stale TTL and AD path.
        c.backdate(&key, 101);
        let hit = c.get(&key, 9, 43_200).unwrap();
        assert!(hit.stale);
        let meta = c.get_into(&key, 9, 43_200, &mut out).unwrap();
        assert!(meta.stale);
        assert_eq!(out, hit.raw);
        assert_eq!(out.capacity(), capacity);

        // A miss leaves the caller's buffer untouched.
        let (_, missing) = query_key("absent.test", 1, 1, 0, false);
        let mut untouched = b"sentinel".to_vec();
        assert!(c.get_into(&missing, 9, 43_200, &mut untouched).is_none());
        assert_eq!(untouched, b"sentinel");
    }

    #[test]
    fn hit_does_not_parse_hickory() {
        let (_, key) = query_key("noparse.test", 1, 1, 0, false);
        let (msg, valid) = positive("noparse.test.", RecordType::A, 60, 1, false);
        // hickory rejects an OPT outside the additional section; the wire
        // walker does not need to. A hit must still patch the response.
        let mut raw = valid;
        raw[6..8].copy_from_slice(&2u16.to_be_bytes());
        raw.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0]);
        assert!(Message::from_vec(&raw).is_err());
        let c = new_cache(10, 1 << 20);
        assert!(c.insert(&key, &raw, &msg, 0));
        let hit = c.get(&key, 7, 43_200).unwrap();
        assert_eq!(wire::header(&hit.raw).unwrap().id, 7);
        let offsets = wire::ttl_offsets(&hit.raw).unwrap();
        let p = offsets[0] as usize;
        assert_eq!(u32::from_be_bytes(hit.raw[p..p + 4].try_into().unwrap()), 60);
    }

    #[test]
    fn had_edns_flag_and_concurrent_hits() {
        let c = Arc::new(new_cache(10, 1 << 20));
        let (_, edns_key) = query_key("edns.test", 1, 1, 0, true);
        let (msg, raw) = positive("edns.test.", RecordType::A, 60, 1, true);
        assert!(c.insert(&edns_key, &raw, &msg, 0));
        assert!(c.get(&edns_key, 1, 43_200).unwrap().had_edns);
        let (_, plain_key) = query_key("plain.test", 1, 1, 0, false);
        let (msg, raw) = positive("plain.test.", RecordType::A, 60, 1, false);
        assert!(c.insert(&plain_key, &raw, &msg, 0));
        assert!(!c.get(&plain_key, 1, 43_200).unwrap().had_edns);

        std::thread::scope(|scope| {
            for _ in 0..4 {
                let c = c.clone();
                let key = edns_key.clone();
                scope.spawn(move || {
                    for id in 0..100 {
                        let hit = c.get(&key, id, 43_200).unwrap();
                        assert_eq!(wire::header(&hit.raw).unwrap().id, id);
                    }
                });
            }
        });
    }
    #[test]
    fn remaining_freshness_has_millisecond_precision() {
        // At 90.001 s of a 100 s TTL the last-10% window has opened.
        let (_, key) = query_key("ms.test", 1, 1, 0, false);
        let (msg, raw) = positive("ms.test.", RecordType::A, 100, 1, false);
        let c = new_cache(10, 1 << 20);
        assert!(c.insert(&key, &raw, &msg, 0));
        c.backdate_ms(&key, 89_000);
        let hit = c.get(&key, 1, 43_200).unwrap();
        assert!(hit.remaining_ms * 10 >= 100_000, "{} ms left is not yet in the window", hit.remaining_ms);
        c.backdate_ms(&key, 1_001);
        let hit = c.get(&key, 1, 43_200).unwrap();
        assert_eq!(hit.remaining_ttl, 10, "whole seconds still say 10");
        assert!(hit.remaining_ms < 10_000 && hit.remaining_ms * 10 < 100_000, "{} ms", hit.remaining_ms);
    }

    #[test]
    fn plaintext_answers_are_capped_never_stale_and_flagged() {
        let (_, key) = query_key("plain.test", 1, 1, 0, false);
        let (msg, raw) = positive("plain.test.", RecordType::A, 86_400, 1, false);
        let c = new_cache(10, 1 << 20);
        assert!(c.insert_plain(&key, &raw, &msg, 0));
        let hit = c.get(&key, 1, 43_200).unwrap();
        assert!(hit.plain && !hit.stale);
        assert_eq!(hit.orig_ttl, PLAIN_TTL_CAP);
        assert_eq!(answer_ttl(&hit.raw, 0), PLAIN_TTL_CAP);
        c.backdate(&key, 301);
        assert!(c.get(&key, 1, 43_200).is_none(), "an expired plaintext entry is never served stale");
        // A DoH-learned entry keeps the normal cap and stale service.
        let (_, doh) = query_key("doh.test", 1, 1, 0, false);
        let (msg, raw) = positive("doh.test.", RecordType::A, 86_400, 1, false);
        assert!(c.insert(&doh, &raw, &msg, 0));
        let hit = c.get(&doh, 1, 43_200).unwrap();
        assert!(!hit.plain);
        assert_eq!(hit.orig_ttl, 86_400);
        c.backdate(&doh, 86_401);
        assert!(c.get(&doh, 1, 200_000).unwrap().stale);
    }

    #[test]
    fn an_uncacheable_negative_still_evicts_the_stale_positive() {
        // NXDOMAIN or NODATA without an SOA is valid but not cacheable.
        let c = new_cache(100, 1 << 20);
        for (rcode, qtype) in [(ResponseCode::NXDomain, RecordType::A), (ResponseCode::NoError, RecordType::A)] {
            let (_, key) = query_key("gone.test", u16::from(qtype), 1, 0, false);
            let (msg, raw) = positive("gone.test.", qtype, 60, 1, false);
            assert!(c.insert(&key, &raw, &msg, 0));
            c.backdate(&key, 61);
            assert!(c.get(&key, 1, 43_200).unwrap().stale);
            let (neg, neg_raw) = negative("gone.test", qtype, rcode, false, None);
            assert!(!c.insert(&key, &neg_raw, &neg, 0), "no SOA, not cacheable");
            c.invalidate_negative(&key, &neg);
            assert!(c.get(&key, 1, 43_200).is_none(), "{rcode:?} ends stale service");
        }
        // A referral (NOERROR, empty Answer, NS authority) is not a negative.
        let (_, key) = query_key("cut.test", 1, 1, 0, false);
        let (msg, raw) = positive("cut.test.", RecordType::A, 60, 1, false);
        assert!(c.insert(&key, &raw, &msg, 0));
        let (mut referral, _) = negative("cut.test", RecordType::A, ResponseCode::NoError, false, None);
        referral.add_authority(Record::from_rdata(
            name("test."),
            60,
            RData::NS(hickory_proto::rr::rdata::NS(name("ns.test."))),
        ));
        c.invalidate_negative(&key, &referral);
        assert!(c.get(&key, 1, 43_200).is_some());
    }

    #[test]
    fn a_new_cname_invalidates_older_address_variants_of_its_owner() {
        let c = new_cache(100, 1 << 20);
        let (_, a_key) = query_key("alias.test", 1, 1, 0, false);
        let (_, a_do) = query_key("alias.test", 1, 1, 0, true);
        let (_, aaaa_key) = query_key("alias.test", 28, 1, 0, false);
        let (_, other) = query_key("other.test", 1, 1, 0, false);
        for (key, text, qtype) in [
            (&a_key, "alias.test.", RecordType::A),
            (&a_do, "alias.test.", RecordType::A),
            (&other, "other.test.", RecordType::A),
        ] {
            let (msg, raw) = positive(text, qtype, 60, 1, false);
            assert!(c.insert(key, &raw, &msg, 0));
        }
        c.backdate(&a_key, 61);
        // The AAAA query now answers with a CNAME to a target with AAAA data.
        let mut msg = Message::new(0x1234, MessageType::Response, OpCode::Query);
        msg.metadata.recursion_desired = true;
        msg.add_query(Query::query(name("alias.test."), RecordType::AAAA));
        msg.add_answer(Record::from_rdata(
            name("alias.test."),
            300,
            RData::CNAME(hickory_proto::rr::rdata::CNAME(name("target.test."))),
        ));
        msg.add_answer(Record::from_rdata(
            name("target.test."),
            300,
            RData::AAAA(AAAA::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)),
        ));
        let raw = msg.to_vec().unwrap();
        assert!(c.insert(&aaaa_key, &raw, &msg, 0));
        assert!(c.get(&a_key, 1, 43_200).is_none(), "stale A for the alias owner is gone");
        assert!(c.get(&a_do, 1, 43_200).is_none(), "every flag variant");
        assert!(c.get(&aaaa_key, 1, 43_200).is_some(), "the new CNAME answer itself stays");
        assert!(c.get(&other, 1, 43_200).is_some());

        // Dual stack: an A answer through the same CNAME keeps the AAAA entry,
        // and the AAAA answer is kept by the A in turn.
        let mut a = Message::new(0x1234, MessageType::Response, OpCode::Query);
        a.metadata.recursion_desired = true;
        a.add_query(Query::query(name("alias.test."), RecordType::A));
        a.add_answer(Record::from_rdata(
            name("Alias.Test."),
            300,
            RData::CNAME(hickory_proto::rr::rdata::CNAME(name("TARGET.test."))),
        ));
        a.add_answer(Record::from_rdata(name("target.test."), 300, RData::A(A::new(192, 0, 2, 1))));
        assert!(c.insert(&a_key, &a.to_vec().unwrap(), &a, 0));
        assert!(c.get(&aaaa_key, 1, 43_200).is_some(), "same CNAME: the AAAA entry stays");
        assert!(c.get(&a_key, 1, 43_200).is_some());

        // A CNAME to a different target (a rotated CDN target) keeps the
        // other chain too: it is not an ordinary answer at the owner.
        let mut moved = msg.clone();
        moved.answers[0] = Record::from_rdata(
            name("alias.test."),
            300,
            RData::CNAME(hickory_proto::rr::rdata::CNAME(name("elsewhere.test."))),
        );
        moved.answers[1] =
            Record::from_rdata(name("elsewhere.test."), 300, RData::AAAA(AAAA::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 2)));
        assert!(c.insert(&aaaa_key, &moved.to_vec().unwrap(), &moved, 0));
        assert!(c.get(&a_key, 1, 43_200).is_some(), "each chain keeps its own entry");
    }
    #[test]
    fn chain_verdict_is_stored_per_entry_and_refreshed_in_place() {
        let c = new_cache(10, 1 << 20);
        let (_, key) = query_key("chain.test", 1, 1, 0, false);
        let (msg, raw) = positive("chain.test.", RecordType::A, 300, 1, false);
        // No chain: no verdict, nothing to compare on a hit.
        assert!(c.insert(&key, &raw, &msg, 0));
        assert!(c.get_into(&key, 1, 43_200, &mut Vec::new()).unwrap().chain.is_none());

        // A verdict is for one generation; a different one is not current.
        assert!(c.insert_with_chain(&key, &raw, &msg, 0, false, Some(ChainState::new(7, false))));
        let mut meta = c.get_into(&key, 1, 43_200, &mut Vec::new()).unwrap();
        let handle = meta.chain.as_mut().unwrap();
        assert!(handle.state.clear(7) && handle.state.current(7));
        assert!(!handle.state.clear(8) && !handle.state.current(8));
        assert!(!handle.state.blocked());

        // A blocked verdict is never clear, even for its own generation.
        handle.refresh(ChainState::new(8, true));
        let meta = c.get_into(&key, 1, 43_200, &mut Vec::new()).unwrap();
        let state = meta.chain.as_ref().unwrap().state;
        assert!(state.blocked() && state.current(8) && !state.clear(8));

        // A refresh lands on the entry the hit came from, not on a newer one.
        let stale = c.get_into(&key, 1, 43_200, &mut Vec::new()).unwrap();
        assert!(c.insert_with_chain(&key, &raw, &msg, 0, false, Some(ChainState::new(9, false))));
        let mut stale = stale;
        stale.chain.as_mut().unwrap().refresh(ChainState::new(9, true));
        let fresh = c.get_into(&key, 1, 43_200, &mut Vec::new()).unwrap();
        assert!(!fresh.chain.unwrap().state.blocked(), "the replaced entry's handle cannot touch the new entry");
    }

    /// DNS CacheFlush: warm 200 small names with 3 hits each, scan
    /// 500 one-hit 60 KB answers, re-query the hot set.
    #[test]
    fn a_scan_of_large_one_hit_answers_keeps_the_hot_set() {
        let c = new_cache(5000, 4 << 20);
        let hot: Vec<_> = (0..200).map(|i| query_key(&format!("hot{i}.test"), 1, 1, 0, false).1).collect();
        for (i, key) in hot.iter().enumerate() {
            let (msg, raw) = positive(&format!("hot{i}.test."), RecordType::A, 600, 1, false);
            assert!(c.insert(key, &raw, &msg, 0));
            for _ in 0..3 {
                assert!(c.get(key, 1, 43_200).is_some());
            }
        }
        let mut stored = 0;
        for i in 0..500 {
            let (_, key) = query_key(&format!("scan{i}.test"), 1, 1, 0, false);
            let (msg, raw) = positive(&format!("scan{i}.test."), RecordType::A, 600, 3700, false);
            stored += usize::from(c.insert(&key, &raw, &msg, 0));
        }
        let survivors = hot.iter().filter(|key| c.get(key, 1, 43_200).is_some()).count();
        eprintln!(
            "scan resistance: scan entries stored {stored}/500, hot survivors {survivors}/200, usage {:?}",
            c.usage()
        );
        assert!(survivors >= 180, "{survivors}/200 hot entries survive a scan");
        assert_eq!(stored, 0, "no one-hit large answer was admitted");

        // A large answer is not refused for good: its second sight is
        // admitted, and a resident one is replaced by a refresh at once.
        let (_, key) = query_key("twice.test", 1, 1, 0, false);
        let (msg, raw) = positive("twice.test.", RecordType::A, 600, 3700, false);
        assert!(!c.insert(&key, &raw, &msg, 0), "first sight is refused");
        assert!(c.insert(&key, &raw, &msg, 0), "second sight is admitted");
        assert!(c.insert(&key, &raw, &msg, 0), "a resident large entry is refreshed in place");
        assert!(c.get(&key, 1, 43_200).is_some());
    }

    #[test]
    fn many_large_names_each_keep_their_first_sight() {
        // 100 large answers, each asked twice in order, as a burst of cold names
        // would. A key must not lose its first sight because some other key
        // hashes to the same spot (the hasher is random per cache, so a direct
        // mapped table failed this on almost every run).
        let c = new_cache(1000, 4 << 20);
        if c.inner.as_ref().unwrap().shard_capacity() < 64 * 1024 {
            return; // a many-core host shards the budget too finely to hold these entries
        }
        let items: Vec<_> = (0..100)
            .map(|i| {
                let n = format!("big-{i}.test");
                let (_, key) = query_key(&n, 1, 1, 0, false);
                let (msg, raw) = positive(&format!("{n}."), RecordType::A, 300, 1500, false);
                assert!(charged(&key, &raw) as u64 > c.large);
                (key, msg, raw)
            })
            .collect();
        for (key, msg, raw) in &items {
            assert!(!c.insert(key, raw, msg, 0), "first sight is refused");
        }
        for (key, msg, raw) in &items {
            assert!(c.insert(key, raw, msg, 0), "every second sight is admitted");
        }
    }

    // ---- boundary and operator tests (cargo-mutants survivors) ----

    /// What the cache must charge for an entry: key, response, 2 bytes per TTL
    /// offset and the entry struct.
    fn charged(key: &[u8], raw: &[u8]) -> usize {
        key.len() + raw.len() + wire::ttl_offsets(raw).unwrap().len() * 2 + size_of::<Entry>()
    }

    #[test]
    fn an_entry_is_charged_its_key_response_offsets_and_struct() {
        let c = new_cache(10_000, 64 * 1024);
        let (_, key) = query_key("weight.test", 1, 1, 0, false);
        let (msg, raw) = positive("weight.test.", RecordType::A, 300, 3, false);
        assert!(c.insert(&key, &raw, &msg, 0));
        assert_eq!(c.usage(), (1, charged(&key, &raw) as u64));
    }

    #[test]
    fn the_second_sight_threshold_is_the_charged_weight() {
        // 1 MiB budget: the large-entry threshold is the 4096-byte floor.
        let c = new_cache(10_000, 1 << 20);
        if c.inner.as_ref().unwrap().shard_capacity() < 16 * 1024 {
            return; // a many-core host shards the budget too finely to hold 4 KiB entries
        }
        // An A answer plus an opaque additional record of `pad` bytes: the
        // charged weight moves one byte per pad byte (equal-length names).
        let padded = |text: &str, pad: usize| {
            let (_, key) = query_key(text, 1, 1, 0, false);
            let (mut msg, _) = positive(&format!("{text}."), RecordType::A, 300, 1, false);
            msg.add_additional(Record::from_rdata(
                name("pad.test."),
                300,
                RData::Unknown {
                    code: RecordType::from(65400u16),
                    rdata: hickory_proto::rr::rdata::NULL::with(vec![0; pad]),
                },
            ));
            let raw = msg.to_vec().unwrap();
            (key, msg, raw)
        };
        let (key, _, raw) = padded("probe.test", 1);
        let exact = 4096 - charged(&key, &raw) + 1;
        let (key, msg, raw) = padded("under.test", exact);
        assert_eq!(charged(&key, &raw), 4096);
        assert!(c.insert(&key, &raw, &msg, 0), "exactly 4096 bytes is not large");
        let (key, msg, raw) = padded("overs.test", exact + 1);
        assert_eq!(charged(&key, &raw), 4097);
        assert!(!c.insert(&key, &raw, &msg, 0), "a heavier entry needs a second sight");
        assert!(c.insert(&key, &raw, &msg, 0));
    }

    #[test]
    fn an_entry_keeps_the_millisecond_it_was_stored_at() {
        let c = new_cache(10, 1 << 20);
        // Start well into a second, so a dropped millisecond part shows.
        while !(400..900).contains(&(c.now_ms() % 1000)) {
            std::thread::sleep(Duration::from_millis(5));
        }
        let (_, key) = query_key("ms.test", 1, 1, 0, false);
        let (msg, raw) = positive("ms.test.", RecordType::A, 100, 1, false);
        assert!(c.insert(&key, &raw, &msg, 0));
        let hit = c.get(&key, 1, 43_200).unwrap();
        assert!(hit.remaining_ms > 100_000 - 300, "{} ms left", hit.remaining_ms);
    }

    #[test]
    fn negative_lifetime_covers_nxdomain_and_nodata_only() {
        let c = Cache::new(10, 1 << 20, 0, 10_800);
        let (nx, _) = negative("n.test", RecordType::A, ResponseCode::NXDomain, false, Some((60, 60)));
        assert_eq!(c.negative_lifetime(&nx, 0), Some(60));
        let (nodata, _) = negative("n.test", RecordType::A, ResponseCode::NoError, false, Some((90, 120)));
        assert_eq!(c.negative_lifetime(&nodata, 0), Some(90));
        assert_eq!(c.negative_lifetime(&nodata, 30), Some(60), "the Age is deducted");
        let (servfail, _) = negative("n.test", RecordType::A, ResponseCode::ServFail, false, Some((60, 60)));
        assert_eq!(c.negative_lifetime(&servfail, 0), None);
        let (answer, _) = positive("n.test.", RecordType::A, 60, 1, false);
        assert_eq!(c.negative_lifetime(&answer, 0), None, "a positive answer is not negative");
        let clamped = Cache::new(10, 1 << 20, 100, 200);
        assert_eq!(clamped.negative_lifetime(&nodata, 0), Some(100));
    }

    #[test]
    fn a_negative_with_dnssec_records_stays_negative() {
        let c = new_cache(10, 1 << 20);
        let (_, key) = query_key("proof.test", 1, 1, 0, false);
        let (mut msg, _) = negative("proof.test", RecordType::A, ResponseCode::NXDomain, false, Some((60, 60)));
        msg.add_authority(Record::from_rdata(
            name("proof.test."),
            60,
            RData::Unknown { code: RecordType::from(46u16), rdata: hickory_proto::rr::rdata::NULL::with(vec![0; 18]) },
        ));
        let raw = msg.to_vec().unwrap();
        assert!(c.insert(&key, &raw, &msg, 0));
        assert!(c.get(&key, 1, 43_200).unwrap().negative);
    }

    fn cname_to(owner: &str, target: &str) -> Record {
        Record::from_rdata(name(owner), 300, RData::CNAME(hickory_proto::rr::rdata::CNAME(name(target))))
    }

    fn a_record(owner: &str, last: u8) -> Record {
        Record::from_rdata(name(owner), 300, RData::A(A::new(192, 0, 2, last)))
    }

    fn response_to(text: &str, rcode: ResponseCode, records: Vec<Record>) -> (Message, Vec<u8>) {
        let mut msg = Message::new(0x1234, MessageType::Response, OpCode::Query);
        msg.metadata.recursion_desired = true;
        msg.metadata.response_code = rcode;
        msg.add_query(Query::query(name(text), RecordType::A));
        for record in records {
            if record.record_type() == RecordType::SOA {
                msg.add_authority(record);
            } else {
                msg.add_answer(record);
            }
        }
        let raw = msg.to_vec().unwrap();
        (msg, raw)
    }

    fn root_soa() -> Record {
        Record::from_rdata(Name::root(), 300, RData::SOA(SOA::new(Name::root(), Name::root(), 0, 0, 0, 0, 300)))
    }

    #[test]
    fn a_cname_with_two_targets_is_ambiguous_but_a_repeat_is_not() {
        let c = new_cache(10, 1 << 20);
        let (_, key) = query_key("alias.test", 1, 1, 0, false);
        let (msg, raw) = response_to(
            "alias.test.",
            ResponseCode::NoError,
            vec![cname_to("alias.test.", "one.test."), cname_to("alias.test.", "two.test."), a_record("one.test.", 1)],
        );
        assert!(!c.insert(&key, &raw, &msg, 0), "two targets at one owner are not cached");
        let (msg, raw) = response_to(
            "alias.test.",
            ResponseCode::NoError,
            vec![cname_to("alias.test.", "one.test."), cname_to("alias.test.", "one.test."), a_record("one.test.", 1)],
        );
        assert!(c.insert(&key, &raw, &msg, 0), "the same target twice is one alias");
    }

    #[test]
    fn a_negative_through_a_cname_takes_its_ttl_from_the_target_zone_soa() {
        // The SOA owns "example.", above the CNAME target but not the name asked.
        let c = new_cache(10, 1 << 20);
        let (_, key) = query_key("alias.test", 1, 1, 0, false);
        let soa =
            Record::from_rdata(name("example."), 45, RData::SOA(SOA::new(Name::root(), Name::root(), 0, 0, 0, 0, 300)));
        let (msg, raw) =
            response_to("alias.test.", ResponseCode::NoError, vec![cname_to("alias.test.", "host.example."), soa]);
        assert_eq!(c.negative_lifetime(&msg, 0), Some(45));
        assert!(c.insert(&key, &raw, &msg, 0));
        assert!(c.get(&key, 1, 43_200).unwrap().negative);
    }

    #[test]
    fn a_terminal_nxdomain_invalidates_the_cname_target_not_the_alias() {
        let c = new_cache(100, 1 << 20);
        let (_, alias) = query_key("alias.test", 1, 1, 0, false);
        let (_, alias_do) = query_key("alias.test", 1, 1, 0, true);
        let (_, target) = query_key("target.test", 1, 1, 0, false);
        for (key, text, edns) in [(&alias_do, "alias.test.", true), (&target, "target.test.", false)] {
            let (msg, raw) = positive(text, RecordType::A, 60, 1, edns);
            assert!(c.insert(key, &raw, &msg, 0));
        }
        // An unrelated CNAME comes first; the chain is alias -> target.
        let (msg, raw) = response_to(
            "alias.test.",
            ResponseCode::NXDomain,
            vec![cname_to("other.test.", "elsewhere.test."), cname_to("alias.test.", "target.test."), root_soa()],
        );
        assert!(c.insert(&alias, &raw, &msg, 0));
        assert!(c.get(&target, 1, 43_200).is_none(), "the terminal name's older state is gone");
        assert!(c.get(&alias_do, 1, 43_200).is_some(), "the alias owner keeps its own entries");
    }

    #[test]
    fn a_new_cname_chain_invalidates_only_its_first_four_owners() {
        let c = new_cache(100, 1 << 20);
        let owners = ["o1.test.", "o2.test.", "o3.test.", "o4.test.", "o5.test."];
        let keys: Vec<_> =
            owners.iter().map(|owner| query_key(owner.trim_end_matches('.'), 1, 1, 0, false).1).collect();
        for (owner, key) in owners.iter().zip(&keys).skip(1) {
            let (msg, raw) = positive(owner, RecordType::A, 60, 1, false);
            assert!(c.insert(key, &raw, &msg, 0));
        }
        let mut records: Vec<_> = owners.windows(2).map(|pair| cname_to(pair[0], pair[1])).collect();
        records.push(cname_to("o5.test.", "end.test."));
        records.push(a_record("end.test.", 1));
        let (msg, raw) = response_to("o1.test.", ResponseCode::NoError, records);
        assert!(c.insert(&keys[0], &raw, &msg, 0));
        for key in &keys[1..4] {
            assert!(c.get(key, 1, 43_200).is_none());
        }
        assert!(c.get(&keys[4], 1, 43_200).is_some(), "the fifth owner is past the bound");
    }

    /// An entry is stale from its lifetime's last millisecond on, for `get`
    /// and for the adapter's stale-only eviction alike.
    #[cfg(feature = "conformance-adapter")]
    #[tokio::test(start_paused = true)]
    async fn stale_only_eviction_agrees_with_lookup_at_the_exact_lifetime() {
        let c = new_cache(10_000, 1 << 20);
        let (_, key) = query_key("edge.test", 1, 1, 0, false);
        let (msg, raw) = positive("edge.test.", RecordType::A, 60, 1, false);
        assert!(c.insert(&key, &raw, &msg, 0));
        tokio::time::advance(Duration::from_millis(59_999)).await;
        assert!(!c.get(&key, 1, 43_200).unwrap().stale);
        assert!(!c.evict(&key, true));
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(c.get(&key, 1, 43_200).unwrap().stale);
        assert!(c.evict(&key, true));
    }

    #[cfg(feature = "conformance-adapter")]
    #[test]
    fn the_observer_counts_insertions_and_evicts_through_the_cache() {
        let c = new_cache(10_000, 1 << 20);
        let (_, key) = query_key("seen.test", 1, 1, 0, true);
        let (msg, raw) = positive("seen.test.", RecordType::A, 60, 2, true);
        assert!(c.insert(&key, &raw, &msg, 0));
        let (entries, bytes, total, per_type) = c.observe();
        assert_eq!((entries, bytes, total), (1, charged(&key, &raw) as u64, 1));
        assert_eq!(per_type, std::collections::BTreeMap::from([(1, 2), (41, 1)]));
        assert!(c.insert(&key, &raw, &msg, 0));
        let (_, _, total, per_type) = c.observe();
        assert_eq!(total, 2);
        assert_eq!(per_type, std::collections::BTreeMap::from([(1, 4), (41, 2)]));

        // A fresh entry survives a stale-only eviction, however old it is
        // relative to a one-second budget; a stale one does not.
        c.backdate(&key, 30);
        assert!(!c.evict(&key, true), "30 s into a 60 s lifetime is fresh");
        assert_eq!(c.usage().0, 1);
        c.backdate(&key, 31);
        assert!(c.evict(&key, true));
        assert_eq!(c.usage().0, 0);
        assert!(!c.evict(&key, false), "nothing left to remove");
        assert!(c.insert(&key, &raw, &msg, 0));
        assert!(c.evict(&key, false), "a fresh entry goes when stale-only is off");
    }
}

#[cfg(test)]
mod rfc_tests {
    use super::*;
    use crate::wire;
    use hickory_proto::{
        op::{MessageType, OpCode, Query},
        rr::{
            rdata::{A, NULL, SOA},
            Name, Record, RecordType,
        },
    };

    fn name(text: &str) -> Name {
        Name::from_ascii(text).unwrap()
    }

    /// Canonical key for a plain IN query (no EDNS, no flags).
    fn key_for(text: &str, qtype: u16) -> Vec<u8> {
        let mut raw = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in text.trim_end_matches('.').split('.') {
            raw.push(label.len() as u8);
            raw.extend_from_slice(label.as_bytes());
        }
        raw.push(0);
        raw.extend_from_slice(&qtype.to_be_bytes());
        raw.extend_from_slice(&[0, 1]);
        let view = wire::parse_query(&raw).unwrap();
        let mut buffer = [0u8; wire::MIN_CANONICAL_BUFFER];
        let len = wire::canonical_key(&view, &mut buffer).unwrap();
        buffer[..len].to_vec()
    }

    fn a_rr(owner: &str, ttl: u32, last: u8) -> Record {
        Record::from_rdata(name(owner), ttl, RData::A(A::new(192, 0, 2, last)))
    }

    /// A response to `qname`/A with the given sections.
    fn reply(
        qname: &str,
        rcode: ResponseCode,
        answers: Vec<Record>,
        authorities: Vec<Record>,
        additionals: Vec<Record>,
    ) -> (Message, Vec<u8>) {
        let mut msg = Message::new(0x1234, MessageType::Response, OpCode::Query);
        msg.metadata.recursion_desired = true;
        msg.metadata.recursion_available = true;
        msg.metadata.response_code = rcode;
        msg.add_query(Query::query(name(qname), RecordType::A));
        for r in answers {
            msg.add_answer(r);
        }
        for r in authorities {
            msg.add_authority(r);
        }
        for r in additionals {
            msg.add_additional(r);
        }
        let raw = msg.to_vec().unwrap();
        (msg, raw)
    }

    fn soa_at(owner: &str, ttl: u32) -> Record {
        Record::from_rdata(name(owner), ttl, RData::SOA(SOA::new(Name::root(), Name::root(), 0, 0, 0, 0, 300)))
    }

    /// A partial RRSIG (type 46) RR, as a hostile or sloppy upstream might attach.
    fn rrsig_at(owner: &str) -> Record {
        Record::from_rdata(
            name(owner),
            300,
            RData::Unknown { code: RecordType::from(46u16), rdata: NULL::with(vec![0; 18]) },
        )
    }

    #[test]
    fn rfc1034_s1503_soa_is_selected_by_owner_name() {
        // RFC 1034 4.3.4: the SOA mechanism applies "only" to data matching QNAME.
        // An SOA owned by an unrelated zone ("example.") does not set the
        // negative lifetime for n.test.
        let c = Cache::new(10, 1 << 20, 0, 10_800);
        let key = key_for("n.test", 1);
        let (msg, raw) = reply("n.test.", ResponseCode::NXDomain, vec![], vec![soa_at("example.", 60)], vec![]);
        assert_eq!(c.negative_lifetime(&msg, 0), None);
        assert!(!c.insert(&key, &raw, &msg, 0), "unrelated SOA must not be cached as a negative");
        assert!(c.get(&key, 1, 43_200).is_none());
        // Control: the same reply with the SOA at the zone of the name is cached.
        let (msg, raw) = reply("n.test.", ResponseCode::NXDomain, vec![], vec![soa_at("test.", 60)], vec![]);
        assert_eq!(c.negative_lifetime(&msg, 0), Some(60));
        assert!(c.insert(&key, &raw, &msg, 0));
    }

    #[test]
    fn rfc1034_s1503_negative_ttl_uses_the_soa_of_the_denied_name() {
        // alias.test CNAME host.example, then NODATA for host.example. The
        // denial is about host.example, so the SOA of example. (TTL 100) sets
        // the lifetime, not the SOA of test. (TTL 30) that covers only the
        // alias, whichever comes first.
        let c = Cache::new(10, 1 << 20, 0, 10_800);
        let cname = vec![Record::from_rdata(
            name("alias.test."),
            300,
            RData::CNAME(hickory_proto::rr::rdata::CNAME(name("host.example."))),
        )];
        for soas in
            [vec![soa_at("example.", 100), soa_at("test.", 30)], vec![soa_at("test.", 30), soa_at("example.", 100)]]
        {
            let (msg, _) = reply("alias.test.", ResponseCode::NoError, cname.clone(), soas, vec![]);
            assert_eq!(c.negative_lifetime(&msg, 0), Some(100));
        }
        // An SOA that covers only the alias does not answer for the target.
        let (msg, _) = reply("alias.test.", ResponseCode::NoError, cname, vec![soa_at("test.", 30)], vec![]);
        assert_eq!(c.negative_lifetime(&msg, 0), None);
    }

    #[test]
    fn rfc1035_s2641_star_label_data_never_builds_a_wildcard_answer() {
        // RFC 1035 7.4: data from a query whose QNAME contains "*" must not be
        // used to construct wildcard answers for other names.
        let c = Cache::new(10, 1 << 20, 0, 10_800);
        let star = key_for("*.wild.test", 1);
        let (msg, raw) =
            reply("*.wild.test.", ResponseCode::NoError, vec![a_rr("*.wild.test.", 300, 1)], vec![], vec![]);
        // RFC 1035 §7.4: such an answer is not cached at all, not even for
        // the literal "*" name.
        assert!(!c.insert(&star, &raw, &msg, 0));
        assert!(c.get(&star, 1, 43_200).is_none());
        assert!(c.get(&key_for("host.wild.test", 1), 1, 43_200).is_none());
        assert!(c.get(&key_for("a.b.wild.test", 1), 1, 43_200).is_none());
        assert!(c.get(&key_for("wild.test", 1), 1, 43_200).is_none());
    }

    #[test]
    fn rfc2181_s270_sig_outside_the_answer_section_is_never_cached_as_a_sig_answer() {
        // RFC 2181 5.3.1: a SIG in Authority or Additional is almost certainly a
        // partial RRSet and must not be returned for a later SIG query (s270, s273).
        let c = Cache::new(10, 1 << 20, 0, 10_800);
        for (owner, in_additional) in [("add.test", true), ("auth.test", false)] {
            let fqdn = format!("{owner}.");
            let sig = vec![rrsig_at(&fqdn)];
            let (msg, raw) = if in_additional {
                reply(&fqdn, ResponseCode::NoError, vec![a_rr(&fqdn, 300, 1)], vec![], sig)
            } else {
                reply(&fqdn, ResponseCode::NoError, vec![a_rr(&fqdn, 300, 1)], sig, vec![])
            };
            assert!(c.insert(&key_for(owner, 1), &raw, &msg, 0));
            assert!(c.get(&key_for(owner, 1), 1, 43_200).is_some(), "the A answer itself is cached");
            for qtype in [46u16, 255] {
                assert!(
                    c.get(&key_for(owner, qtype), 1, 43_200).is_none(),
                    "{owner}: partial SIG must not answer a type {qtype} query"
                );
            }
        }
    }

    #[test]
    fn rfc2181_s333_identical_rrset_refreshes_the_cached_ttl() {
        // RFC 2181 5.4: an identical RRSet may update the cached TTL, and should
        // when the new answer ranks at least as high. All forwarded answers
        // share one rank, so the later TTL replaces the older, partly spent one.
        let c = Cache::new(10, 1 << 20, 0, 10_800);
        let key = key_for("ttl.test", 1);
        let (msg, raw) = reply("ttl.test.", ResponseCode::NoError, vec![a_rr("ttl.test.", 60, 1)], vec![], vec![]);
        assert!(c.insert(&key, &raw, &msg, 0));
        c.backdate(&key, 40);
        assert_eq!(c.get(&key, 1, 43_200).unwrap().remaining_ttl, 20);
        let (msg, raw) = reply("ttl.test.", ResponseCode::NoError, vec![a_rr("ttl.test.", 300, 1)], vec![], vec![]);
        assert!(c.insert(&key, &raw, &msg, 0));
        let hit = c.get(&key, 1, 43_200).unwrap();
        assert_eq!(hit.orig_ttl, 300);
        assert_eq!(hit.remaining_ttl, 300);
    }

    #[test]
    fn rfc2181_s356_additional_data_never_creates_or_replaces_a_cached_answer() {
        // RFC 2181 5.4.1: additional information is ignored when the cache holds
        // an answer for the name.
        let c = Cache::new(10, 1 << 20, 0, 10_800);
        let x = key_for("x.test", 1);
        let (msg, raw) = reply("x.test.", ResponseCode::NoError, vec![a_rr("x.test.", 300, 1)], vec![], vec![]);
        assert!(c.insert(&x, &raw, &msg, 0));
        let (msg, raw) = reply(
            "y.test.",
            ResponseCode::NoError,
            vec![a_rr("y.test.", 300, 9)],
            vec![],
            vec![a_rr("x.test.", 3600, 66), a_rr("z.test.", 3600, 77)],
        );
        assert!(c.insert(&key_for("y.test", 1), &raw, &msg, 0));
        let hit = c.get(&x, 1, 43_200).unwrap();
        let cached = Message::from_vec(&hit.raw).unwrap();
        assert_eq!(cached.answers.len(), 1);
        assert_eq!(cached.answers[0].data, RData::A(A::new(192, 0, 2, 1)), "original address kept");
        assert_eq!(hit.orig_ttl, 300, "original TTL kept");
        assert!(c.get(&key_for("z.test", 1), 1, 43_200).is_none(), "additional data is not an entry");
    }

    #[test]
    fn rfc6891_s356_upstream_opt_is_not_replayed_from_the_cache() {
        // RFC 6891 6.1.1: OPT RRs MUST NOT be cached or forwarded. The OPT in a
        // served hit is the forwarder's own: no upstream option, no upstream flags.
        let c = Cache::new(10, 1 << 20, 0, 10_800);
        let key = key_for("opt.test", 1);
        let (_, mut raw) = reply("opt.test.", ResponseCode::NoError, vec![a_rr("opt.test.", 300, 1)], vec![], vec![]);
        raw[10..12].copy_from_slice(&1u16.to_be_bytes());
        // OPT: root, type 41, payload 4096, ext-rcode 0, version 0, flags 0xbfff,
        // one option, code 65001 (0xfde9), data de ad be ef.
        raw.extend_from_slice(&[
            0, 0, 41, 0x10, 0x00, 0, 0, 0xbf, 0xff, 0, 8, 0xfd, 0xe9, 0, 4, 0xde, 0xad, 0xbe, 0xef,
        ]);
        let msg = Message::from_vec(&raw).unwrap();
        assert!(msg.edns.is_some());
        assert!(c.insert(&key, &raw, &msg, 0));
        let mut hit = c.get(&key, 1, 43_200).unwrap().raw;
        assert!(wire::present_for_client(&mut hit, true, false, false, 1232));
        // Exactly one OPT, the forwarder's: payload 1232, flags 0, no options.
        assert_eq!(u16::from_be_bytes([hit[10], hit[11]]), 1);
        assert_eq!(hit[hit.len() - 11..], [0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0]);
        assert!(!hit.windows(4).any(|w| w == [0xde, 0xad, 0xbe, 0xef]), "upstream option bytes replayed");
    }
}
