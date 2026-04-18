# Repository traits

## Rules

1. **Repository traits live with the domain**, not the storage
   implementation. They are defined in `dark_core::ports` (or a
   crate-local `ports` module) and implemented in `dark-db`,
   `dark-live-store`, or in-memory test doubles.
2. **Trait shape**: `#[async_trait]`, methods take `&self` (interior
   mutability is the implementation's problem), return
   `Result<T, RepoError>`.
3. **No SQL types, no `sqlx::Row`, no `sqlx::Error` in trait
   surfaces.** The trait speaks in domain types only.
4. **Method naming** follows CRUDQ prefixes so grepping is cheap:

   | Prefix     | Return                       | Semantics                                      |
   | ---------- | ---------------------------- | ---------------------------------------------- |
   | `get_*`    | `Result<T, RepoError>`       | Single row; `NotFound` when absent.            |
   | `find_*`   | `Result<Option<T>, RepoError>` | Single row or `None`; absence is not an error. |
   | `insert_*` | `Result<(), RepoError>`      | Fails with `Conflict` on duplicate key.        |
   | `update_*` | `Result<(), RepoError>`      | Fails with `NotFound` when row is missing.     |
   | `upsert_*` | `Result<(), RepoError>`      | Insert or update.                              |
   | `delete_*` | `Result<(), RepoError>`      | Idempotent; absence is not an error.           |
   | `list_*`   | `Result<Page<T>, RepoError>` | Paginated; see below.                          |
   | `count_*`  | `Result<u64, RepoError>`     | Count with the same filter as `list_*`.        |

## Pagination

```rust
pub struct Page<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<Cursor>,
}

#[async_trait]
impl RoundRepository for SqliteRoundRepository {
    async fn list_rounds(
        &self,
        filter: RoundFilter,
        cursor: Option<Cursor>,
        limit: u32,
    ) -> Result<Page<Round>, RepoError> { … }
}
```

- `cursor` is opaque (serialized keyset pointer, not an offset). Offsets
  drift under concurrent writes; cursors don't.
- `limit` is bounded at the trait layer, not at the SQL layer. A default
  max of 1000 is reasonable; enforce with a `debug_assert!` or a clamp.
- `Page<T>` is always returned — even when there is no next page, callers
  should not have to distinguish "last page" from "empty result."

## Transaction boundaries

- One `Transaction` / `UnitOfWork` type per repository group.
- Transactions are started on an explicit `&self` handle, not implicitly
  via method ordering.
- **Cross-repository transactions are not expressed through the trait
  surfaces.** They are expressed at the implementation layer (e.g. a
  single `sqlx::Transaction` passed to multiple repository adapters
  inside the same crate). The domain does not reach into transaction
  handles.

## Error surface

```rust
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RepoError {
    #[error("{entity} {id} not found")]
    NotFound { entity: &'static str, id: String },

    #[error("{entity} {id} already exists")]
    Conflict { entity: &'static str, id: String },

    #[error("transaction aborted")]
    Aborted,

    #[error("backend error")]
    Backend(#[source] Box<dyn std::error::Error + Send + Sync>),
}
```

`Backend` is the only opaque variant — it exists so sqlx, redis, or any
other concrete error can be wrapped without the trait surface growing a
generic `E` parameter.

## Forbidden patterns

- Methods that return `Vec<T>` for a listing without pagination.
- Methods taking a `sqlx::Pool`, `sqlx::Transaction`, or
  `redis::Connection` as a parameter at the trait surface.
- `Ok(())` as a signal for "nothing happened" where `NotFound` would be
  correct. `delete_*` is the only idempotent variant.
- Async traits without `#[async_trait]` (only safe with Rust 1.75+ AFIT,
  but we keep the macro for uniformity until a workspace-wide migration
  happens).

## Migration note

Per-crate refactor #497 applies these rules across `dark-db`,
`dark-wallet`, and `dark-live-store`. Existing SQL-leaking methods
(queries that return `sqlx::Row`, transactions threaded through the
trait) move to concrete adapters.
