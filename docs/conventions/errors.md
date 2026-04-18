# Error handling

## Rules

1. **`anyhow::Error` is allowed in exactly three places**:
   - Test code (`#[cfg(test)]`, `tests/`, `*/tests/*`).
   - Binary `main` functions and their immediate `run()` wrappers
     (`src/main.rs`, `dark-signer` bin, `dark-wallet-bin`, `ark-cli`).
   - Internal glue *inside a single module* where a function is not `pub`
     and never exposed across crate boundaries.
2. **Every `pub` function at a crate's public surface returns
   `Result<T, CrateError>`** where `CrateError` (or a more specific
   per-module enum) is defined with `thiserror`.
3. **Errors flow upward unchanged across crate boundaries.** No
   `.map_err(|e| e.to_string())`. No `anyhow::Context` at the boundary.
   If an outer crate needs extra context, it adds a variant to its own
   error enum and `#[from]`-wraps the inner error.
4. **Do not re-export another crate's error type as your crate's canonical
   error.** Wrap it via `#[from]` instead.

## Canonical enum shape

```rust
use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum WalletError {
    #[error("wallet is disabled; construct with a non-noop implementation")]
    Disabled,

    #[error("insufficient funds: need {needed} sats, have {available} sats")]
    InsufficientFunds { needed: u64, available: u64 },

    #[error("UTXO {0} is already reserved for a pending round")]
    UtxoReserved(String),

    #[error("BDK wallet failed")]
    Bdk(#[from] bdk_wallet::error::Error),

    #[error("database error")]
    Db(#[from] dark_db::DbError),
}
```

### Notes on the example above

- **Use per-variant structured fields** (`{ needed, available }`), not
  opaque `String`s. Stringly-typed variants (e.g. `DatabaseError(String)`)
  are a code smell — they preserve no structured information for callers
  that want to match.
- **`#[from]` is for wrapping**, never for flattening. If the wrapped
  error already carries the context the caller needs, `#[from]` is
  correct. If the caller needs additional context, create a named variant
  with named fields.
- **`#[non_exhaustive]`** applies when new variants are likely over the
  crate's lifetime and you want downstream callers to handle `_ => …`.
  Do not apply it reflexively.
- **Display strings are lowercase and sentence-form**, not capitalised or
  ending in a period. This matches the `anyhow` / `thiserror`
  convention and reads cleanly when chained via `{:#}`.

## Per-module error enums

For crates with multiple independent domains (e.g. `dark-core` with
registration, confirmation, finalization), prefer a module-local error
enum that is `#[from]`-wrapped by the crate-level enum:

```rust
// crates/dark-core/src/registration/error.rs
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RegistrationError {
    #[error("intent {0} has expired")]
    IntentExpired(String),
    #[error("participant {0} is banned")]
    ParticipantBanned(String),
}

// crates/dark-core/src/error.rs
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DomainError {
    #[error(transparent)]
    Registration(#[from] crate::registration::RegistrationError),
    // …
}
```

This lets reviewers reason about a single phase in isolation while the
top-level enum stays a single dispatch point for transport crates.

## Forbidden patterns

- `.expect("this should never happen")` on input-derived data — every
  `expect` either documents a proven invariant (e.g. `expect("len is
  non-zero by construction above")`) or is a bug.
- `unwrap()` outside tests and proven-invariant paths.
- `Box<dyn std::error::Error>` at a public surface.
- `panic!` on untrusted input.
- Returning `anyhow::Result` from a `pub` function in a library crate.
- Stringifying an error (`e.to_string()`) and then re-wrapping it in a
  `String` variant of another enum.

## Migration note

Several existing enums in the workspace (notably `dark_core::ArkError`)
carry stringly-typed variants like `DatabaseError(String)` and
`WalletError(String)`. These are a historical artefact and are replaced
with typed, `#[from]`-wrapped variants as part of the per-crate refactors
(#495, #496, #497).
