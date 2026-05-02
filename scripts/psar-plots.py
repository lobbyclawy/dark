#!/usr/bin/env python3
"""Stdlib-only SVG plot generator for issue #687.

Emits the figures referenced by `BENCHMARKS.md` from the captured
numbers in this directory. No matplotlib / gnuplot dependency —
plots are simple log-x scatter+line on a 600×400 SVG canvas.

Run via `scripts/psar-plots.sh` (which invokes this script).

Outputs:
- docs/benchmarks/figures/boarding-vs-n.svg
- docs/benchmarks/figures/epoch-vs-k.svg
- docs/benchmarks/figures/storage-vs-k.svg
"""

from __future__ import annotations

import math
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FIG_DIR = REPO_ROOT / "docs" / "benchmarks" / "figures"


def svg_open(width: int, height: int) -> list[str]:
    return [
        f'<svg xmlns="http://www.w3.org/2000/svg" '
        f'viewBox="0 0 {width} {height}" '
        f'width="{width}" height="{height}" '
        f'font-family="-apple-system, sans-serif" font-size="12">'
    ]


def line(x1: float, y1: float, x2: float, y2: float, color: str = "#222", w: float = 1.0) -> str:
    return (
        f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" '
        f'stroke="{color}" stroke-width="{w}" stroke-linecap="round" />'
    )


def text(x: float, y: float, s: str, anchor: str = "start", color: str = "#222", size: int = 12) -> str:
    return (
        f'<text x="{x:.1f}" y="{y:.1f}" text-anchor="{anchor}" '
        f'fill="{color}" font-size="{size}">{s}</text>'
    )


def circle(cx: float, cy: float, r: float = 4, color: str = "#1f77b4") -> str:
    return f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="{r}" fill="{color}" />'


def polyline(points: list[tuple[float, float]], color: str = "#1f77b4", w: float = 2) -> str:
    pts = " ".join(f"{x:.1f},{y:.1f}" for x, y in points)
    return (
        f'<polyline points="{pts}" fill="none" stroke="{color}" '
        f'stroke-width="{w}" stroke-linejoin="round" />'
    )


def render_log_linear_plot(
    *,
    title: str,
    xs: list[float],
    ys: list[float],
    x_label: str,
    y_label: str,
    out_path: Path,
    annotate: list[tuple[float, float, str]] | None = None,
    width: int = 640,
    height: int = 420,
    log_x: bool = True,
) -> None:
    """One axis log (x) the other linear (y); scatter + line."""
    pad_l, pad_r, pad_t, pad_b = 70, 30, 50, 60
    plot_w = width - pad_l - pad_r
    plot_h = height - pad_t - pad_b

    # Axis ranges.
    if log_x:
        x_lo = math.log10(min(xs)) - 0.05
        x_hi = math.log10(max(xs)) + 0.05
    else:
        rng = max(xs) - min(xs)
        x_lo, x_hi = min(xs) - 0.05 * rng, max(xs) + 0.05 * rng
    y_rng = max(ys) - min(ys)
    if y_rng == 0:
        y_rng = max(ys) or 1.0
    y_lo = 0
    y_hi = max(ys) * 1.15

    def fx(x: float) -> float:
        v = math.log10(x) if log_x else x
        return pad_l + (v - x_lo) / (x_hi - x_lo) * plot_w

    def fy(y: float) -> float:
        return pad_t + plot_h - (y - y_lo) / (y_hi - y_lo) * plot_h

    out = svg_open(width, height)
    # Background.
    out.append(f'<rect width="{width}" height="{height}" fill="white" />')
    # Title.
    out.append(text(width / 2, 24, title, anchor="middle", size=15))
    # Axes.
    out.append(line(pad_l, pad_t, pad_l, pad_t + plot_h))
    out.append(line(pad_l, pad_t + plot_h, pad_l + plot_w, pad_t + plot_h))
    # X-axis ticks (log scale: at each x point).
    for x, y in zip(xs, ys):
        tx = fx(x)
        out.append(line(tx, pad_t + plot_h, tx, pad_t + plot_h + 5, color="#888"))
        out.append(
            text(
                tx,
                pad_t + plot_h + 18,
                _human(x),
                anchor="middle",
                size=11,
            )
        )
    # Y-axis ticks: 5 evenly spaced.
    for i in range(6):
        v = y_lo + (y_hi - y_lo) * i / 5
        ty = fy(v)
        out.append(line(pad_l - 5, ty, pad_l, ty, color="#888"))
        out.append(
            text(
                pad_l - 8,
                ty + 4,
                _human(v, terse=True),
                anchor="end",
                size=11,
            )
        )
        out.append(line(pad_l, ty, pad_l + plot_w, ty, color="#eee"))
    # Axis labels.
    out.append(
        text(
            pad_l + plot_w / 2,
            height - 18,
            x_label,
            anchor="middle",
            size=13,
        )
    )
    out.append(
        f'<text x="{18}" y="{pad_t + plot_h / 2}" '
        f'text-anchor="middle" font-size="13" '
        f'transform="rotate(-90 18 {pad_t + plot_h / 2})">{y_label}</text>'
    )
    # Data line.
    pts = [(fx(x), fy(y)) for x, y in zip(xs, ys)]
    out.append(polyline(pts))
    # Data points.
    for x, y in zip(xs, ys):
        out.append(circle(fx(x), fy(y)))
    # Annotations.
    if annotate:
        for x, y, label in annotate:
            out.append(circle(fx(x), fy(y), r=6, color="#d62728"))
            out.append(
                text(
                    fx(x) + 10,
                    fy(y) - 8,
                    label,
                    anchor="start",
                    color="#d62728",
                    size=11,
                )
            )
    out.append("</svg>")
    out_path.write_text("\n".join(out))


def _human(v: float, terse: bool = False) -> str:
    if abs(v) >= 1000:
        return f"{v / 1000:.1f}K" if not terse else f"{v / 1000:.0f}K"
    if v == int(v):
        return f"{int(v)}"
    return f"{v:.1f}"


def main() -> int:
    FIG_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Boarding latency vs N.
    # Numbers from docs/benchmarks/psar-boarding.md.
    boarding_n = [4, 12, 50]
    boarding_ms = [1.66, 4.75, 19.80]
    render_log_linear_plot(
        title="Single-user boarding latency vs horizon N (Apple M3 Max)",
        xs=boarding_n,
        ys=boarding_ms,
        x_label="Horizon N (epochs)",
        y_label="user_board latency (ms)",
        out_path=FIG_DIR / "boarding-vs-n.svg",
        log_x=False,
        annotate=[(12, 4.75, "★ lead row")],
    )

    # 2. Per-epoch ASP latency vs K.
    # Numbers from docs/benchmarks/psar-epoch.md.
    epoch_k = [100, 1000]
    epoch_ms = [22.9, 226.8]
    render_log_linear_plot(
        title="Per-epoch ASP processing latency vs cohort size K",
        xs=epoch_k,
        ys=epoch_ms,
        x_label="Cohort size K (log scale)",
        y_label="process_epoch latency (ms)",
        out_path=FIG_DIR / "epoch-vs-k.svg",
        log_x=True,
        annotate=[(1000, 226.8, "★ lead row")],
    )

    # 3. Storage vs K at N=12.
    # Computed from formula `186K + 98KN + 292N + 180`.
    storage_k = [100, 1000, 10000]
    n = 12
    storage_kb = [
        (186 * k + 98 * k * n + 292 * n + 180) / 1024 for k in storage_k
    ]
    render_log_linear_plot(
        title="Total in-memory storage per cohort vs K (N=12)",
        xs=storage_k,
        ys=storage_kb,
        x_label="Cohort size K (log scale)",
        y_label="In-memory storage (KB)",
        out_path=FIG_DIR / "storage-vs-k.svg",
        log_x=True,
        annotate=[(1000, storage_kb[1], "★ lead row")],
    )

    print(f"Wrote {len(list(FIG_DIR.glob('*.svg')))} SVG figures to {FIG_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
