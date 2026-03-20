# Light Mode

Light mode runs dark with no external dependencies — just SQLite and in-memory state.

## When to use

- Local development
- Testnet operators
- Small mainnet deployments (<100 concurrent users)

## Start with Docker

```bash
docker compose -f docker-compose.light.yml up
```

## Start from source

```bash
cargo run --bin dark -- --config config/dark.light.toml
```

## Mode selection

dark reads the `deployment.mode` field at startup and logs the selected mode:
- `light` → SQLite + in-memory live store
- `full` → PostgreSQL + Redis (default)

The actual store backend switching is complete for the mode selection path. Database connection wiring is tracked separately.

## Differences from full mode

| Feature | Light | Full |
|---------|-------|------|
| Database | SQLite | PostgreSQL |
| Live store | In-memory | Redis |
| External deps | None | PostgreSQL + Redis |
| Recommended for | Dev/Testnet | Production |
