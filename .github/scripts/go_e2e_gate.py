#!/usr/bin/env python3
"""Decide when the vendored Go arkd E2E parity gate must run.

This keeps the decision logic testable outside of GitHub Actions and makes the
confidential-VTXO parity contract explicit.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


RISKY_PREFIXES = (
    "proto/",
    "crates/dark-api/",
    "crates/dark-core/",
    "crates/dark-db/migrations/",
    "crates/dark-live-store/",
    "vendor/arkd/",
)

RISKY_PATHS = {
    ".github/workflows/e2e.yml",
    ".github/scripts/go_e2e_gate.py",
    ".github/scripts/test_go_e2e_gate.py",
}

ALWAYS_RUN_EVENTS = {"push", "schedule", "workflow_dispatch"}


@dataclass(frozen=True)
class Decision:
    run: bool
    reason: str


def _normalize_labels(labels: Iterable[str]) -> set[str]:
    return {label.strip().lower() for label in labels if label and label.strip()}


def _normalize_paths(paths: Iterable[str]) -> tuple[str, ...]:
    normalized = []
    for path in paths:
        if not path:
            continue

        candidate = path.strip()
        while candidate.startswith("./"):
            candidate = candidate[2:]

        normalized.append(candidate)
    return tuple(normalized)


def decide(event_name: str, labels: Iterable[str], changed_files: Iterable[str]) -> Decision:
    event_name = event_name.strip().lower()
    labels = _normalize_labels(labels)
    changed_files = _normalize_paths(changed_files)

    if event_name in ALWAYS_RUN_EVENTS:
        return Decision(True, f"{event_name} always runs Go E2E parity")

    if event_name != "pull_request":
        return Decision(False, f"unsupported event '{event_name}', skipping Go E2E parity")

    if "confidential-vtxos" in labels:
        return Decision(True, "PR carries confidential-vtxos label")

    risky_files = [
        path
        for path in changed_files
        if path.startswith(RISKY_PREFIXES) or path in RISKY_PATHS
    ]
    if risky_files:
        return Decision(
            True,
            "PR touches parity-sensitive surfaces: " + ", ".join(risky_files[:5]),
        )

    return Decision(False, "PR is outside confidential and parity-sensitive surfaces")


def _load_json_list(raw: str) -> list[str]:
    if not raw:
        return []
    parsed = json.loads(raw)
    if not isinstance(parsed, list):
        raise ValueError("expected a JSON array")
    return [str(item) for item in parsed]


def _load_changed_files(args: argparse.Namespace) -> list[str]:
    if args.changed_files_json:
        return _load_json_list(args.changed_files_json)

    if args.changed_files_file:
        return [
            line.strip()
            for line in Path(args.changed_files_file).read_text().splitlines()
            if line.strip()
        ]

    return []


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--event-name", required=True)
    parser.add_argument("--labels-json", default="[]")
    parser.add_argument("--changed-files-json")
    parser.add_argument("--changed-files-file")
    args = parser.parse_args()

    labels = _load_json_list(args.labels_json)
    changed_files = _load_changed_files(args)
    decision = decide(args.event_name, labels, changed_files)

    print(f"run={'true' if decision.run else 'false'}")
    print(f"reason={decision.reason}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
