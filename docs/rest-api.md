# REST wallet API (`dark-wallet-rest`)

`dark-wallet-rest` is a standalone HTTP daemon that sits in front of a running
`dark` server and exposes a curated subset of the Ark protocol as REST + SSE.
Browsers and non-Rust clients can drive dark without a gRPC-web proxy, and the
OpenAPI spec it emits feeds typed-client generators.

> **Scope.** This is not a replacement for the gRPC API. Signer-path RPCs
> (`SubmitTreeNonces`, `SubmitTreeSignatures`, `SubmitSignedForfeitTxs`) stay
> gRPC-only by design. Real wallets that participate as signers must use the
> gRPC API; the REST surface is for inspection and high-level actions.

## Running

```bash
# Assumes `dark` is listening on :7070
just rest --listen-addr 127.0.0.1:7072 --dark-grpc-url http://localhost:7070 --auth-disabled
```

| Flag                  | Env                        | Default                      |
|-----------------------|----------------------------|------------------------------|
| `--listen-addr`       | `DARK_REST_LISTEN`         | `127.0.0.1:7072`             |
| `--dark-grpc-url`     | `DARK_GRPC_URL`            | `http://localhost:7070`      |
| `--auth-disabled`     | `DARK_REST_AUTH_DISABLED`  | `false`                      |

Once running:

- Swagger UI: `http://127.0.0.1:7072/docs`
- OpenAPI JSON: `http://127.0.0.1:7072/openapi.json`
- Liveness probe: `GET /ping` → `"pong"`

## Authentication

Macaroon tokens travel as `Authorization: Bearer <macaroon>`. The daemon parses
the header and forwards the intent; deep verification against the dark root key
is a follow-up (see the issue tracker). Pass `--auth-disabled` in dev to
accept unauthenticated requests.

## Endpoint surface

| Method | Path                              | gRPC equivalent                                |
|--------|-----------------------------------|------------------------------------------------|
| GET    | `/v1/info`                        | `ArkService.GetInfo`                           |
| GET    | `/v1/vtxos?pubkey=…`              | `ArkService.GetVtxos` (legacy)                 |
| GET    | `/v1/vtxos/{outpoint}/chain`      | `IndexerService.GetVtxoChain`                  |
| GET    | `/v1/rounds`                      | `ArkService.ListRounds`                        |
| GET    | `/v1/rounds/{id}`                 | `ArkService.GetRound`                          |
| GET    | `/v1/rounds/{id}/tree`            | `IndexerService.GetVtxoTree`                   |
| GET    | `/v1/rounds/{id}/commitment-tx`   | `IndexerService.GetCommitmentTx`               |
| POST   | `/v1/txs`                         | `ArkService.SubmitTx`                          |
| POST   | `/v1/txs/{id}/finalize`           | `ArkService.FinalizeTx`                        |
| GET    | `/v1/txs/{id}`                    | (stub — waiting on dark-client)                |
| POST   | `/v1/intents`                     | `ArkService.RegisterIntent`                    |
| DELETE | `/v1/intents/{id}`                | `ArkService.DeleteIntent`                      |
| POST   | `/v1/intents/{id}/confirm`        | `ArkService.ConfirmRegistration`               |
| POST   | `/v1/intents/{id}/fee`            | `ArkService.EstimateIntentFee`                 |
| POST   | `/v1/exits`                       | `ArkService.RequestExit`                       |
| GET    | `/v1/events`                      | `ArkService.GetEventStream`     (SSE)          |
| GET    | `/v1/transactions/events`         | `ArkService.GetTransactionsStream` (SSE)       |

## Binary encoding

- PSBTs, pubkeys, signatures and other byte fields travel as **hex** strings.
- Inline-encoded proofs / messages (BIP-322) are passed through as the server
  expects them (hex PSBT for `proof`, canonical JSON text for `message`).
- The boundary encoder lives in `src/codec.rs` — centralise any encoding tweaks
  there.

## Errors

Errors use **RFC 7807 `application/problem+json`**:

```json
{ "title": "Bad Request", "status": 400, "detail": "amount must be > 0" }
```

`Content-Type: application/problem+json` is set on the response.

## Server-Sent Events

Both event streams emit `text/event-stream` with JSON-encoded DTOs:

```bash
curl -N http://127.0.0.1:7072/v1/events
```

Each SSE message looks like:

```
event: batch_finalized
data: {"type":"batch_finalized","round_id":"1234","txid":"abcd…"}
```

so browsers can filter via:

```js
const es = new EventSource("/v1/events");
es.addEventListener("batch_finalized", (e) => {
  const payload = JSON.parse(e.data);
  …
});
```

Heartbeats (`event: heartbeat`) arrive every ~15 s.

## Regenerating the OpenAPI spec

The spec lives at `crates/dark-wallet-rest/openapi.json` and is the source of
truth for client generators. Whenever you add or change a route / DTO:

```bash
just generate-rest-openapi
```

CI runs `just check-rest-openapi` which `diff`s a freshly-generated spec
against the committed one and fails on drift. Always stage the regenerated
file alongside your source changes.

## Typed clients

Two clients ship in this repo:

- **Rust** — `crates/dark-rest-client/` (hand-maintained `reqwest` wrapper).
  ```toml
  # Cargo.toml
  dark-rest-client = { path = "../dark-rest-client" }
  ```
  ```rust
  use dark_rest_client::Client;
  let client = Client::new("http://127.0.0.1:7072")?;
  let info = client.get_info().await?;
  ```
- **TypeScript** — `web/` (generated types + hand-written `DarkClient`).
  ```ts
  import { DarkClient } from "@dark/web-client/lib/client";
  const client = new DarkClient({ baseUrl: "http://127.0.0.1:7072" });
  const info = await client.getInfo();
  ```

### Regenerating

```bash
just generate-rest-openapi    # refresh openapi.json
just generate-rest-ts-client  # refresh web/lib/gen/dark.ts (needs npm)
```

CI's `rest-api.yml` workflow runs both the OpenAPI drift check and the
Rust-side `cargo test` smoke tests on every change to
`crates/dark-wallet-rest/` or `proto/`.

## Integration tests

`crates/dark-wallet-rest/tests/openapi_smoke.rs` verifies that every
documented route + schema lands in the generated spec and that `/ping`
carries an empty security override. These tests do **not** require a
running dark server.

For end-to-end flows against a live dark instance, launch the daemon and
drive it with the Rust or TS client:

```bash
# Terminal 1
cargo run -p dark --release

# Terminal 2
just rest --auth-disabled

# Terminal 3 — drive it
curl -s http://127.0.0.1:7072/v1/info | jq
```
