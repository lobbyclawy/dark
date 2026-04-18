# Workspace conventions

This directory holds the conventions that every crate in the dark workspace
follows. They are **binding** — new code is expected to conform, and existing
code is being migrated crate-by-crate under the M1–M4 refactor milestones.

Each document is short, prescriptive, and contains at least one reference
example. When a convention is ambiguous or a new case is not covered, file an
issue linking this directory so the convention can be extended rather than
silently diverged from.

## Index

- [`errors.md`](errors.md) — when to use `anyhow` vs `thiserror`, canonical
  error enum shape, `#[from]` and `#[non_exhaustive]` policy.
- [`tracing.md`](tracing.md) — span naming, required structured fields,
  level policy.
- [`repositories.md`](repositories.md) — `Repository` trait shape, method
  naming, pagination, transaction boundaries.
- [`null-objects.md`](null-objects.md) — `Noop{Trait}` / `InMemory{Trait}` /
  `Stub{Trait}` naming and when each is permitted.
- [`async.md`](async.md) — polling (`poll_until`), cancellation-safety,
  `spawn_blocking` rules.

## Status

These conventions were introduced by #492 as part of the M0 refactor
milestone. The per-crate refactors (#495, #496, #497, #498, #499, #500,
#501, #502, #503, #504) apply them.
