//! sopedu-dns internals shared by the binary, benchmarks and examples.

// The allocator features are mutually exclusive. The binary carries the
// same guard for its `#[global_allocator]`; this one also covers `--lib`
// builds, which never compile `main.rs`.
#[cfg(all(feature = "mimalloc", feature = "jemalloc"))]
compile_error!("features `mimalloc` and `jemalloc` are mutually exclusive");

pub mod cache;
pub mod clock;
pub mod config;
pub mod http;
pub mod inflight;
pub mod lists;
pub mod log;
pub mod mac;
pub mod prewarm;
pub mod querylog;
pub mod ratelimit;
pub mod reverse;
pub mod rules;
pub mod stats;
pub mod stats_store;
pub mod tls;
pub mod ui;
pub mod upstream;
pub mod wire;
