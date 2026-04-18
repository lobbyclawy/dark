# Tracing & logging

## Rules

1. **Every async function that represents a meaningful unit of work is
   instrumented** with a `tracing` span. Use `#[tracing::instrument]` on
   the function, not a manual `span!` inside the body, unless you need
   conditional span construction.
2. **Span name = `crate::module::function`** in snake_case. The
   `#[instrument]` attribute already produces this; do not override the
   span name unless you have a specific disambiguation reason
   (e.g. two generic instantiations).
3. **Structured fields, not string concatenation.** Log events use named
   fields the log aggregator can index.
4. **No ad-hoc `println!` / `eprintln!` in library code.** The binary
   entry points may use them before the subscriber is installed, and
   only then.

## Required fields

When any of these identifiers is in scope, include them as span fields so
logs can be pivoted by round / VTXO / intent / request:

| Field        | Type               | When                                                  |
| ------------ | ------------------ | ----------------------------------------------------- |
| `round_id`   | `&str` / `Display` | Every function inside a round-lifecycle call path.    |
| `vtxo_id`    | `&str` / `Display` | Every function operating on a specific VTXO.          |
| `intent_id`  | `&str` / `Display` | Every function operating on a registered intent.     |
| `request_id` | `&str`             | Every gRPC/REST handler entry point.                 |
| `height`     | `u32`              | Every scanner function keyed to a block height.       |

Example:

```rust
#[tracing::instrument(
    skip(self, request),
    fields(round_id = %request.round_id, vtxo_id = %request.vtxo_id),
)]
async fn confirm_vtxo(&self, request: ConfirmVtxoRequest) -> Result<(), DomainError> {
    tracing::debug!(amount = request.amount_sat, "validating confirmation");
    // …
    tracing::info!("vtxo confirmed");
    Ok(())
}
```

Use `skip` for non-`Display` arguments; `%` for `Display`; `?` for
`Debug`. Prefer `%` — `Debug` output is noisy in production logs.

## Level policy

| Level   | Semantic                                                                     |
| ------- | ---------------------------------------------------------------------------- |
| `error` | Operator intervention required (failed round, persistent DB error, panic).   |
| `warn`  | Degraded but functional (retry succeeded after N attempts, fallback engaged).|
| `info`  | Lifecycle events visible to an operator (round start/end, boot, shutdown). |
| `debug` | Control-flow detail useful when debugging a specific incident.              |
| `trace` | Hot-path detail (every tick of a polling loop, every row read).              |

**`error` and `warn` are alert-worthy.** If a line logs at `warn` or
`error` in healthy production, either the healthy baseline is wrong or
the log level is. Revisit.

**No duplicate logging.** If a span already carries a field, don't
re-log it in every event inside the span.

## Forbidden patterns

- `tracing::info!("round {} finished", round_id)` — use a structured
  field: `tracing::info!(round_id, "round finished")`.
- `println!` / `eprintln!` in library code.
- `log::` macros — the workspace standardises on `tracing`.
- Logging an error's `Debug` output when `Display` is available.
- Logging at `info` inside a tight loop (use `debug` or `trace`).

## Migration note

Several modules today build log strings via `format!` before calling
`tracing::info!`. These migrate to structured fields as part of the
per-crate refactors.
