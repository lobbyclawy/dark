//! Polling helpers for integration tests.
//!
//! See [`docs/conventions/async.md`](../../docs/conventions/async.md) for the
//! rules these helpers implement.
//!
//! The canonical helper is [`poll_until`]: call a predicate repeatedly at a
//! fixed interval until it returns `true` or the deadline elapses. It
//! replaces fixed `tokio::time::sleep` pauses in tests that are really
//! waiting for external state to change.

use std::future::Future;
use std::time::Duration;

use thiserror::Error;

/// Error returned by [`poll_until`] when the deadline elapses before the
/// predicate returns `true`.
#[derive(Debug, Error)]
pub enum PollError {
    /// The deadline expired before the predicate returned `true`.
    #[error("polling deadline of {:?} elapsed", .0)]
    Timeout(Duration),
}

/// Poll `predicate` every `interval` until it returns `true`, or until
/// `deadline` elapses.
///
/// The first call happens immediately; subsequent calls are spaced by
/// `interval`. On timeout, returns [`PollError::Timeout`] — callers decide
/// whether to `.expect()` with a specific diagnostic or propagate.
///
/// For richer diagnostics on timeout (e.g. "last observed round state was
/// X"), prefer writing a specialised helper on top of `poll_until` that
/// captures observations as it polls.
///
/// # Example
///
/// ```no_run
/// # use std::time::Duration;
/// # async fn example() {
/// # let port: u16 = 9000;
/// use crate::support::poll::poll_until;
///
/// poll_until(
///     Duration::from_secs(10),
///     Duration::from_millis(100),
///     || async {
///         std::net::TcpStream::connect(("127.0.0.1", port)).is_ok()
///     },
/// )
/// .await
/// .expect("server did not accept connections within 10s");
/// # }
/// ```
pub async fn poll_until<F, Fut>(
    deadline: Duration,
    interval: Duration,
    mut predicate: F,
) -> Result<(), PollError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let start = tokio::time::Instant::now();
    let deadline_instant = start + deadline;
    loop {
        if predicate().await {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline_instant {
            return Err(PollError::Timeout(deadline));
        }
        let remaining = deadline_instant.saturating_duration_since(tokio::time::Instant::now());
        tokio::time::sleep(interval.min(remaining)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    #[tokio::test]
    async fn resolves_on_first_success() {
        let calls = Arc::new(AtomicU32::new(0));
        let c = Arc::clone(&calls);
        let res = poll_until(
            Duration::from_secs(1),
            Duration::from_millis(10),
            move || {
                let c = Arc::clone(&c);
                async move {
                    c.fetch_add(1, Ordering::SeqCst);
                    true
                }
            },
        )
        .await;
        assert!(res.is_ok());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn resolves_after_n_polls() {
        let calls = Arc::new(AtomicU32::new(0));
        let c = Arc::clone(&calls);
        let res = poll_until(
            Duration::from_secs(5),
            Duration::from_millis(10),
            move || {
                let c = Arc::clone(&c);
                async move { c.fetch_add(1, Ordering::SeqCst) + 1 >= 3 }
            },
        )
        .await;
        assert!(res.is_ok());
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn returns_timeout_when_predicate_never_true() {
        let res = poll_until(
            Duration::from_millis(50),
            Duration::from_millis(10),
            || async { false },
        )
        .await;
        assert!(matches!(res, Err(PollError::Timeout(_))));
    }
}
