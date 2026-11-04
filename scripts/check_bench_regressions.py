#!/usr/bin/env python3
"""Fail when a criterion benchmark regressed >10% or improved >50% vs `base`.

CI measures the base commit and the head on the same runner in one job
(.github/workflows/bench.yml), then runs this on `target/criterion`. A
regression fails only when the lower bound of criterion's 95% confidence
interval for the mean change is above +10%, so a noisy run with a +12% point
estimate but a +2% lower bound passes with a warning instead of failing.

Pass a criterion directory as the only argument to check another tree, or
`--self-test` to exercise the pass/regress/improve/missing cases with stdlib
temporary files.
"""

import contextlib
import io
import json
import pathlib
import sys
import tempfile

REGRESSION = 0.10
IMPROVEMENT = -0.50
# Benches over hash tables with a per-process random seed. On identical code
# they move 15-30% between two processes (the table clusters differently), so
# they get a wider band: a 1.5x slowdown still fails.
SEEDED = ("blocked_", "space_saving_")
SEEDED_REGRESSION = 0.50
SEEDED_IMPROVEMENT = -0.75


def check(root: pathlib.Path) -> int:
    estimates = sorted(root.rglob("change/estimates.json"))
    if not estimates:
        print("check_bench_regressions: no criterion change estimates; is the `base` baseline missing?", file=sys.stderr)
        return 1
    failures = []
    for path in estimates:
        name = path.parent.parent.relative_to(root)
        try:
            estimate = json.loads(path.read_text())["mean"]
            mean = estimate["point_estimate"]
            # Older/hand-written estimates may lack the interval; fall back to
            # the point estimate so they are still gated.
            lower = estimate.get("confidence_interval", {}).get("lower_bound", mean)
        except (KeyError, TypeError, ValueError, AttributeError, OSError) as exc:
            failures.append((str(name), f"unreadable estimate: {exc}"))
            continue
        change = mean * 100.0
        seeded = str(name).startswith(SEEDED)
        regression, improvement = (SEEDED_REGRESSION, SEEDED_IMPROVEMENT) if seeded else (REGRESSION, IMPROVEMENT)
        if lower > regression:
            failures.append((str(name), f"mean regressed {change:+.1f}% (95% CI lower bound {lower * 100:+.1f}%, limit {regression * 100:+.0f}%)"))
        elif mean > regression:
            print(f"warn {name}: mean {change:+.1f}% but CI lower bound {lower * 100:+.1f}% is within the limit")
        elif mean < improvement:
            failures.append((str(name), f"mean improved {change:+.1f}% (limit {improvement * 100:+.0f}%, baseline likely broken)"))
        else:
            print(f"ok {name}: mean {change:+.1f}%")
    for name, reason in failures:
        print(f"FAIL {name}: {reason}", file=sys.stderr)
    return 1 if failures else 0


def write_estimate(root: pathlib.Path, name: str, mean: float, lower: float | None = None) -> None:
    path = root / name / "change" / "estimates.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    interval = {"lower_bound": mean - 0.01 if lower is None else lower, "upper_bound": mean + 0.01}
    path.write_text(json.dumps({"mean": {"point_estimate": mean, "confidence_interval": interval}}))


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        base = pathlib.Path(tmp)
        for name, mean, lower, expected in [
            ("within", 0.05, None, 0),
            ("regressed", 0.15, None, 1),
            ("noisy", 0.15, 0.02, 0),
            ("improved", -0.60, None, 1),
            ("seeded-noise", 0.30, None, 0),
            ("seeded-regressed", 0.60, None, 1),
        ]:
            root = base / name
            write_estimate(root, "blocked_x" if name.startswith("seeded") else "bench", mean, lower)
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                actual = check(root)
            if actual != expected:
                print(f"self-test: {name} exited {actual}, expected {expected}", file=sys.stderr)
                return 1
        missing = base / "missing"
        missing.mkdir()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            actual = check(missing)
        if actual != 1:
            print(f"self-test: missing baseline exited {actual}, expected 1", file=sys.stderr)
            return 1
    print("self-test: ok")
    return 0


def main() -> int:
    args = sys.argv[1:]
    if args == ["--self-test"]:
        return self_test()
    if len(args) > 1:
        print("usage: check_bench_regressions.py [CRITERION_DIR | --self-test]", file=sys.stderr)
        return 2
    root = pathlib.Path(args[0]) if args else pathlib.Path("target/criterion")
    return check(root)


if __name__ == "__main__":
    sys.exit(main())
