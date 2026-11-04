# CI micro-benchmark gate

The `Bench` workflow (`.github/workflows/bench.yml`) runs on every pull request and every push to `main`. It benchmarks the base and the head in one job on the same runner.

| Step | What runs |
|---|---|
| Base | The pull request's base, or the previous `main` on a push, checked out into a worktree. Its own `benches/micro.rs` runs with `cargo bench --locked --bench micro -- --save-baseline base`. `target/criterion` is deleted first, so no cached result is reused. |
| Head | `cargo bench --locked --bench micro -- --baseline-lenient base`. A benchmark that exists only in the head has no baseline: it is reported, not gated. |
| Gate | `scripts/check_bench_regressions.py` reads every `change/estimates.json` under `target/criterion`. |
| Self-test | `check_bench_regressions.py --self-test` runs in every job. |

A benchmark fails when:

- the lower bound of criterion's 95% confidence interval for the mean change is above +10%, or
- the mean improved by more than 50%, which usually means a broken baseline.

The blocklist lookup (`blocked_*`) and space-saving counter (`space_saving_*`) benches use hash tables with a per-process random seed and move 15-30% between two runs of identical code, so their limits are +50% and -75%.

A mean change above the limit with the lower bound inside it prints a warning. With no base (first push, force push) or a base that cannot be benchmarked, the head runs alone with a notice and nothing is gated.

Run it locally:

```sh
root=$PWD
git worktree add --detach /tmp/base main
(cd /tmp/base && CARGO_TARGET_DIR="$root/target" CRITERION_HOME="$root/target/criterion" \
  cargo bench --bench micro -- --save-baseline base)
cargo bench --bench micro -- --baseline-lenient base
python3 scripts/check_bench_regressions.py
```

If the gate fails, rerun the job once: runner noise can move a short benchmark. If it fails again, the regression is real. Fix it, or say in the pull request why you accept the cost.
