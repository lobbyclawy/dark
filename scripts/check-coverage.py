#!/usr/bin/env python3
"""Enforce per-crate coverage floors declared in coverage-thresholds.toml.

Usage:
    scripts/check-coverage.py LCOV_FILE THRESHOLDS_TOML [--enforce]

Parses an lcov.info file emitted by `cargo llvm-cov --workspace --lcov` and
computes per-crate line coverage by attributing each `SF:<source_file>` block
to the crate whose `crates/<crate>/src/` prefix appears in the path. A crate's
coverage is total lines hit over total instrumented lines across all its
source files.

Without --enforce, prints a report and exits 0 regardless of floor violations
(report-only mode, useful while per-crate test-backfill PRs land; see #506).
With --enforce, exits 1 if any crate listed in the thresholds file falls below
its declared floor.

The TOML schema is:

    [crates]
    dark-core    = 70        # integer percent
    dark-bitcoin = 70.0      # float percent also accepted

Crates listed but absent from the lcov report are treated as 0% (missing
instrumentation is a failure, not a silent pass). Crates present in lcov but
not listed in the TOML are ignored by the enforcement check but still shown
in the report.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import sys
from collections import defaultdict

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover - fallback for older runners
    import tomli as tomllib  # type: ignore


# Matches ".../crates/<name>/..." anywhere in a source file path. Works for
# both absolute paths (GitHub runners) and relative ones.
CRATE_RE = re.compile(r"(?:^|/)crates/([^/]+)/")


def parse_lcov(path: pathlib.Path) -> dict[str, tuple[int, int]]:
    """Return {crate_name: (lines_hit, lines_found)} aggregated from lcov."""
    per_crate: dict[str, list[int]] = defaultdict(lambda: [0, 0])  # [hit, found]

    current_crate: str | None = None
    with path.open() as fp:
        for raw_line in fp:
            line = raw_line.rstrip("\n")
            if line.startswith("SF:"):
                source = line[3:]
                match = CRATE_RE.search(source)
                current_crate = match.group(1) if match else None
            elif current_crate is None:
                continue
            elif line.startswith("LH:"):
                per_crate[current_crate][0] += int(line[3:])
            elif line.startswith("LF:"):
                per_crate[current_crate][1] += int(line[3:])
            elif line == "end_of_record":
                current_crate = None

    return {k: (v[0], v[1]) for k, v in per_crate.items()}


def load_thresholds(path: pathlib.Path) -> dict[str, float]:
    with path.open("rb") as fp:
        data = tomllib.load(fp)
    crates = data.get("crates", {})
    if not isinstance(crates, dict) or not crates:
        raise SystemExit(f"no [crates] table in {path}")
    return {name: float(pct) for name, pct in crates.items()}


def pct(hit: int, found: int) -> float:
    if found == 0:
        return 100.0
    return 100.0 * hit / found


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("lcov", type=pathlib.Path)
    parser.add_argument("thresholds", type=pathlib.Path)
    parser.add_argument(
        "--enforce",
        action="store_true",
        help="Exit non-zero when any listed crate is below its floor.",
    )
    parser.add_argument(
        "--github-summary",
        action="store_true",
        help=(
            "Write a markdown table to $GITHUB_STEP_SUMMARY in addition to "
            "stdout. No-op when the env var is unset."
        ),
    )
    args = parser.parse_args(argv)

    coverage = parse_lcov(args.lcov)
    thresholds = load_thresholds(args.thresholds)

    # Build the unified report: every crate that is listed OR that appears in
    # lcov. Listed crates come first so the report has a stable ordering.
    names: list[str] = list(thresholds.keys())
    for name in sorted(coverage):
        if name not in thresholds:
            names.append(name)

    violations: list[tuple[str, float, float]] = []
    lines: list[str] = []
    header = f"{'crate':<22}{'coverage':>12}{'floor':>10}  status"
    lines.append(header)
    lines.append("-" * len(header))
    for name in names:
        missing = name not in coverage
        hit, found = coverage.get(name, (0, 0))
        actual = pct(hit, found)
        floor = thresholds.get(name)
        if floor is None:
            status = "(unlisted)"
        elif missing:
            # Crate is listed as mandatory but absent from lcov: treat as 0%.
            # Otherwise a typo in the toml or a crate accidentally dropped
            # from the build would silently disable its floor.
            status = "FAIL"
            actual = 0.0
            violations.append((name, actual, floor))
        elif actual + 1e-9 >= floor:
            status = "ok"
        else:
            status = "FAIL"
            violations.append((name, actual, floor))
        floor_s = "—" if floor is None else f"{floor:>6.1f}%"
        if missing:
            suffix = "   (no coverage data — crate not in lcov)"
        elif not found:
            suffix = "   (no instrumented lines)"
        else:
            suffix = ""
        lines.append(
            f"{name:<22}{actual:>11.2f}%{floor_s:>10}  {status}{suffix}"
        )

    report = "\n".join(lines)
    print(report)

    if args.github_summary:
        summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary_path:
            md: list[str] = [
                "## Per-crate coverage",
                "",
                "| crate | coverage | floor | status |",
                "| --- | ---: | ---: | :--- |",
            ]
            for name in names:
                missing = name not in coverage
                hit, found = coverage.get(name, (0, 0))
                actual = pct(hit, found)
                floor = thresholds.get(name)
                if floor is None:
                    status = "_unlisted_"
                elif missing:
                    status = "**FAIL** (no data)"
                    actual = 0.0
                elif actual + 1e-9 >= floor:
                    status = "ok"
                else:
                    status = "**FAIL**"
                floor_cell = "—" if floor is None else f"{floor:.1f}%"
                md.append(
                    f"| `{name}` | {actual:.2f}% | {floor_cell} | {status} |"
                )
            with open(summary_path, "a") as fp:
                fp.write("\n".join(md) + "\n")

    if violations:
        print("", file=sys.stderr)
        print(
            f"{len(violations)} crate(s) below floor:", file=sys.stderr
        )
        for name, actual, floor in violations:
            print(
                f"  {name}: {actual:.2f}% < {floor:.1f}%", file=sys.stderr
            )
        if args.enforce:
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
