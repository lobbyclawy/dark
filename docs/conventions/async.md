# Async & polling

## Rules

1. **No `tokio::time::sleep` in test assertion paths.** Tests that wait
   for state to appear must use `poll_until` so a transient timing
   difference on CI doesn't flake the suite.
2. **No `spawn_blocking` for non-blocking work.** Only wrap work that is
   genuinely CPU-bound or uses a synchronous blocking API.
3. **Every long-running task is cancellation-safe.** If shutdown fires
   mid-`await`, no database row is left half-written, no Redis key
   half-deleted, no partial message sent.
4. **`tokio::select!` branches that take cancellation tokens are listed
   last** so the happy-path branch is visually prominent.

## Polling helper

The canonical helper lives at
[`tests/support/poll.rs`](../../tests/support/poll.rs) and has this
signature:

```rust
pub async fn poll_until<F, Fut>(
    deadline: Duration,
    interval: Duration,
    mut predicate: F,
) -> Result<(), PollError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{ … }
```

Use it like:

```rust
use crate::support::poll::poll_until;
use std::time::Duration;

poll_until(
    Duration::from_secs(10),
    Duration::from_millis(100),
    || async {
        std::net::TcpStream::connect(("127.0.0.1", port)).is_ok()
    },
)
.await
.expect("dark server did not accept connections within 10s");
```

On timeout, `PollError::Timeout` is returned — callers decide whether
to `.expect` with a message or propagate.

When the test needs richer diagnostics on timeout (e.g. "what was the
last observed round state?"), prefer a specialised helper that wraps
`poll_until` and records observations as it polls.

`poll_until` is currently under `tests/support/` because it is
test-only. It migrates to `crates/dark-testkit` when #505 lands, at
which point it becomes the canonical shared harness helper.

## Cancellation safety checklist

When writing a long-running task, ensure each of the following:

- [ ] Every `await` point either completes quickly (< ~100 ms worst
      case) or is inside a `tokio::select!` with a cancellation branch.
- [ ] Transactions (DB, Redis) commit or roll back fully inside a single
      `select!` arm — never split across cancellation points.
- [ ] Work done with a `Drop` guard assumes the `Drop` may run during
      unwind (panic or cancellation); the `Drop` is best-effort and
      idempotent.
- [ ] The task returns a `Result` from its outermost function, so
      supervisors can log and restart or shut down cleanly.

## `spawn_blocking` rules

- **Allowed**: synchronous filesystem I/O with no async alternative
  (`std::fs` inside a hot loop), CPU-bound work (regex over large
  strings, crypto without an async API).
- **Not allowed**: network I/O (use tokio IO types), `reqwest::blocking`
  (use the async client), database clients that have async versions.

If you reach for `spawn_blocking`, leave a one-line comment explaining
why no async alternative works — reviewers will push back otherwise.

## `tokio::select!` layout

```rust
loop {
    tokio::select! {
        biased;
        _ = shutdown.cancelled() => break,
        _ = ticker.tick() => self.tick_once().await?,
    }
}
```

- `biased;` documents that branch order matters (here: shutdown wins
  ties).
- The cancellation branch does not call `await` inside the arm — just
  flips control flow.
- The work branch propagates its `Result` via `?` so the supervisor
  sees failures.

## Forbidden patterns

- `tokio::time::sleep(Duration::from_secs(N)).await` inside a test
  assertion block. (A `sleep` inside *setup* — e.g. waiting 200 ms after
  spawning a child process before trying to connect — is fine *if* it's
  followed by a poll-until-ready check that is the actual readiness
  gate.)
- `spawn_blocking` wrapping a tokio IO call.
- `std::thread::sleep` in async code.
- `futures::executor::block_on` inside async code.
- `tokio::select!` with no cancellation branch in a supervised task.
