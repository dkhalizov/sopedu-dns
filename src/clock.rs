//! Monotonic clock used by the cache, the rate limiter and request timing.
//!
//! The default build uses `std::time::Instant` exactly as before. The
//! `conformance-adapter` feature swaps in tokio's pausable `Instant`, so the
//! test adapter's virtual clock drives TTL ageing, serve-stale and every
//! timer that already goes through tokio. A compile-time alias: no runtime
//! flag, branch or indirection in the default build.

#[cfg(not(feature = "conformance-adapter"))]
pub use std::time::Instant;
#[cfg(feature = "conformance-adapter")]
pub use tokio::time::Instant;
