# Contributing to sopedu-dns

Thanks for helping. Small, focused pull requests with tests are easiest to
review. For anything larger than a bug fix, open an issue first.

By taking part you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
Report security problems privately; see [SECURITY.md](SECURITY.md).

## Build and test

The toolchain is pinned in `rust-toolchain.toml`, and rustup installs it for
you. CI (`.github/workflows/ci.yml`) runs the same commands:

```sh
cargo fmt -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --release --locked
cargo deny check          # cargo install cargo-deny --locked
```

CI also runs the micro-benchmarks (`cargo bench --locked --bench micro`) and
compares them with the base commit on the same runner; see
`docs/bench/ci-gate.md`.

MSRV is the pinned toolchain. We raise it only in a minor release.

## Sign your commits (DCO)

We use the [Developer Certificate of Origin](https://developercertificate.org/)
instead of a CLA. Add a `Signed-off-by` line to every commit:

```sh
git commit -s
```

To fix existing commits: `git rebase --signoff main`, then force-push your
branch. The `DCO` workflow fails a pull request if any commit lacks the line.

## Benchmark rules

If your pull request claims a performance change, or adds or edits a
benchmark document under `docs/bench/`, follow these rules:

- Record hardware (CPU, cores given to the server, RAM, kernel, NIC), the
  sopedu-dns commit, and the version or image digest of everything compared.
- Run open loop, at least 3 rounds (more is better), and report the median
  with the min-max range. Latency percentiles are p50, p90, p99, p99.9 and
  max; loss gets its own column. Discard runs where the client misses 99% of the target rate.
- Prefer a synthetic, public, deterministic corpus. You may use a real query
  log for a headline run only if it stays out of the repo (no private
  hostnames or addresses), the write-up says the input is private and its
  numbers can't be reproduced exactly, and the other inputs are public. We
  did this for the 1.0.0 headline run: 3 runs on a private real-network
  corpus, labelled as such in the README.
- Use equivalent configs for competitors (same upstream, cache size, no
  prefetch or serve-stale unless stated) and publish them.
- Claim "A is better than B" only if every run of A beats every run of B.
  Never write "fastest" or "Nx faster" without scenario, versions and N, and
  report losses and feature gaps next to wins.
- Put raw output and the exact commands next to the results so others can
  reproduce them (`bench/competitors/run.sh`). Names of other products are
  trademarks of their owners; use text only.
