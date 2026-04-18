# Null objects

Three naming patterns — each with a different meaning. Using the wrong
name makes the intent of the construction site unclear.

| Name             | Meaning                                                                                               | Allowed in `main`?                 |
| ---------------- | ----------------------------------------------------------------------------------------------------- | ---------------------------------- |
| `Noop{Trait}`    | Trait methods are no-ops. Used when the integration is **explicitly opted-out** via config.           | Yes, when config opts out.         |
| `InMemory{Trait}`| Full behavioural implementation backed by in-memory state. Used in tests and light-mode deployments.  | Yes, in light mode.                |
| `Stub{Trait}`    | Incomplete / placeholder. Returns a specific error on every non-trivial call.                         | **No after M1 completes** (#497). |

## `Noop{Trait}`

A Noop is the right answer when a feature is optional and an operator
has chosen to turn it off. Calls succeed silently; nothing is emitted.

```rust
pub struct NoopAlerts;

#[async_trait]
impl Alerts for NoopAlerts {
    async fn publish(&self, _topic: AlertTopic, _payload: Payload) -> Result<(), AlertsError> {
        Ok(())
    }
}
```

Wired in construction like:

```rust
let alerts: Arc<dyn Alerts> = if config.alerts.enabled {
    Arc::new(PrometheusAlertsManager::new(&config.alerts)?)
} else {
    Arc::new(NoopAlerts)
};
```

## `InMemory{Trait}`

A full implementation used in tests and light-mode deployments where no
external storage is available.

```rust
pub struct InMemoryRoundRepository {
    rounds: tokio::sync::RwLock<HashMap<RoundId, Round>>,
}

#[async_trait]
impl RoundRepository for InMemoryRoundRepository {
    async fn get_round(&self, id: &RoundId) -> Result<Round, RepoError> { … }
}
```

`InMemory*` must fully satisfy the trait contract including edge cases
(`NotFound`, `Conflict`, pagination). A partial `InMemory*` is a `Stub*`
in disguise — rename accordingly.

## `Stub{Trait}`

Only permitted during active implementation PRs, as a scaffolding that
compiles while the real implementation lands. Must fail loudly on every
non-trivial call:

```rust
pub struct StubSweepService;

#[async_trait]
impl SweepService for StubSweepService {
    async fn sweep(&self, _batch: SweepBatch) -> Result<SweepResult, SweepError> {
        Err(SweepError::NotImplemented("stub wired in, production path pending"))
    }
}
```

**After M1 completes (#497), no `Stub*` type may be constructed in
`main.rs` or wired through the `App` builder.** A reachable `Stub*` in
production is a release blocker.

## Construction

- Prefer `impl Default` for Noops (zero state) and some `InMemory*`
  (clean state) variants.
- Use an explicit `::new()` constructor when the type carries
  configuration (seed, capacity).
- Do not provide a `new()` that takes invented defaults; if a parameter
  has no sensible default, require it.

## Forbidden patterns

- `StubWallet` or similar constructed unconditionally in `main`. If the
  wallet is optional, use `NoopWallet` and make the opt-out visible in
  config.
- A Noop that logs on every call. Silent no-ops are the point; if you
  want visibility, use a real implementation backed by `tracing`.
- An `InMemory*` that silently drops data past a capacity limit without
  surfacing the drop through an error or a metric.
