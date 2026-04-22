// Hand-written fetch + EventSource wrapper over the generated types.
// Keep this thin; regenerate `./gen/dark.ts` with `npm run generate` after
// any change to crates/dark-wallet-rest/openapi.json.

import type { components, paths } from "./gen/dark";

export type ServerInfo = components["schemas"]["ServerInfoDto"];
export type Vtxo = components["schemas"]["VtxoDto"];
export type RoundInfo = components["schemas"]["RoundInfoDto"];
export type RoundSummary = components["schemas"]["RoundSummaryDto"];
export type SubmitTxRequest = components["schemas"]["SubmitTxRequestDto"];
export type SubmitTxResponse = components["schemas"]["SubmitTxResponseDto"];
export type RequestExitRequest = components["schemas"]["RequestExitRequestDto"];
export type RequestExitResponse = components["schemas"]["RequestExitResponseDto"];
export type CreateSessionResponse = components["schemas"]["CreateSessionResponse"];
export type FaucetResponse = components["schemas"]["FaucetResponse"];
export type ProblemDetails = components["schemas"]["ProblemDetails"];

export interface DarkClientOptions {
  baseUrl: string;
  bearer?: string;
  fetchImpl?: typeof fetch;
}

export class DarkClientError extends Error {
  constructor(
    public readonly status: number,
    public readonly problem: ProblemDetails,
  ) {
    super(`${status} ${problem.title}: ${problem.detail}`);
    this.name = "DarkClientError";
  }
}

export class DarkClient {
  private readonly baseUrl: string;
  private readonly bearer?: string;
  private readonly fetchImpl: typeof fetch;

  constructor(opts: DarkClientOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/$/, "");
    this.bearer = opts.bearer;
    this.fetchImpl = opts.fetchImpl ?? fetch;
  }

  private headers(): HeadersInit {
    const h: Record<string, string> = { "Content-Type": "application/json" };
    if (this.bearer) h.Authorization = `Bearer ${this.bearer}`;
    return h;
  }

  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<T> {
    const resp = await this.fetchImpl(`${this.baseUrl}${path}`, {
      method,
      headers: this.headers(),
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (!resp.ok) {
      let problem: ProblemDetails;
      try {
        problem = (await resp.json()) as ProblemDetails;
      } catch {
        problem = { title: resp.statusText, status: resp.status, detail: "" };
      }
      throw new DarkClientError(resp.status, problem);
    }
    if (resp.status === 204) return undefined as unknown as T;
    return (await resp.json()) as T;
  }

  getInfo(): Promise<ServerInfo> {
    return this.request<ServerInfo>("GET", "/v1/info");
  }

  listVtxos(pubkey: string): Promise<{ vtxos: Vtxo[] }> {
    return this.request("GET", `/v1/vtxos?pubkey=${encodeURIComponent(pubkey)}`);
  }

  listRounds(
    limit?: number,
    offset?: number,
  ): Promise<{ rounds: RoundSummary[] }> {
    const q = new URLSearchParams();
    if (limit !== undefined) q.set("limit", String(limit));
    if (offset !== undefined) q.set("offset", String(offset));
    const qs = q.toString();
    return this.request("GET", `/v1/rounds${qs ? `?${qs}` : ""}`);
  }

  getRound(id: string): Promise<RoundInfo> {
    return this.request("GET", `/v1/rounds/${encodeURIComponent(id)}`);
  }

  submitTx(req: SubmitTxRequest): Promise<SubmitTxResponse> {
    return this.request("POST", "/v1/txs", req);
  }

  finalizeTx(id: string): Promise<void> {
    return this.request("POST", `/v1/txs/${encodeURIComponent(id)}/finalize`, {
      final_checkpoint_txs: [],
    });
  }

  requestExit(req: RequestExitRequest): Promise<RequestExitResponse> {
    return this.request("POST", "/v1/exits", req);
  }

  createPlaygroundSession(): Promise<CreateSessionResponse> {
    return this.request("POST", "/v1/playground/session", {});
  }

  getPlaygroundSession(id: string) {
    return this.request<components["schemas"]["SessionView"]>(
      "GET",
      `/v1/playground/session/${encodeURIComponent(id)}`,
    );
  }

  faucet(sessionId: string): Promise<FaucetResponse> {
    return this.request("POST", "/v1/playground/faucet", {
      session_id: sessionId,
    });
  }

  /// Subscribe to batch lifecycle events via SSE.
  subscribeEvents(): EventSource {
    return new EventSource(`${this.baseUrl}/v1/events`);
  }

  /// Subscribe to transaction events via SSE.
  subscribeTxs(): EventSource {
    return new EventSource(`${this.baseUrl}/v1/transactions/events`);
  }

  ping(): Promise<string> {
    return this.fetchImpl(`${this.baseUrl}/ping`).then((r) => r.text());
  }
}

export type { paths, components };
