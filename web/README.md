# @dark/web-client

TypeScript clients for `dark-wallet-rest`.

- `lib/gen/dark.ts` — auto-generated types from
  `crates/dark-wallet-rest/openapi.json` (produced by `openapi-typescript`).
- `lib/client.ts` — thin hand-written wrapper around the generated types
  for ergonomic usage in browsers / Node.

## Regenerate

```bash
# from repo root
just generate-rest-ts-client
# or directly:
cd web && npm install && npm run generate
```

CI runs `just check-rest-openapi` on every change, so the OpenAPI spec is
guaranteed to match the Rust server. Re-run `generate` whenever the spec
changes.

## Usage

```ts
import { DarkClient } from "./lib/client";

const client = new DarkClient({ baseUrl: "http://localhost:7072" });
const info = await client.getInfo();
console.log(info.network, info.version);

const events = client.subscribeEvents();
events.addEventListener("batch_finalized", (e) => {
  const payload = JSON.parse((e as MessageEvent).data);
  console.log("batch confirmed:", payload);
});
```
