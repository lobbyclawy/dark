//! `dark-rest-client` — typed HTTP client for `dark-wallet-rest`.
//!
//! Thin wrapper over `reqwest` that exposes strongly-typed methods matching
//! the REST surface documented in `crates/dark-wallet-rest/openapi.json`.
//!
//! Regenerate or extend this crate with:
//!
//! ```bash
//! just generate-rest-client
//! ```
//!
//! The committed version is hand-maintained and covers the routes a browser
//! or integration test is most likely to hit. For full coverage (every
//! obscure field, every stream), drive `openapi-generator-cli` against the
//! shipped spec instead — see the Justfile target for the exact invocation.

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use thiserror::Error;
use url::Url;

pub use reqwest::StatusCode;

#[derive(Debug, Error)]
pub enum Error {
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("url error: {0}")]
    Url(#[from] url::ParseError),
    #[error("server returned {status} {title}: {detail}")]
    Api {
        status: StatusCode,
        title: String,
        detail: String,
    },
}

pub type Result<T> = std::result::Result<T, Error>;

/// Typed client for `dark-wallet-rest`.
#[derive(Debug, Clone)]
pub struct Client {
    http: reqwest::Client,
    base: Url,
    bearer: Option<String>,
}

impl Client {
    pub fn new(base_url: impl AsRef<str>) -> Result<Self> {
        Ok(Self {
            http: reqwest::Client::builder().build()?,
            base: Url::parse(base_url.as_ref())?,
            bearer: None,
        })
    }

    pub fn with_bearer(mut self, token: impl Into<String>) -> Self {
        self.bearer = Some(token.into());
        self
    }

    fn build(&self, method: reqwest::Method, path: &str) -> Result<reqwest::RequestBuilder> {
        let url = self.base.join(path)?;
        let mut req = self.http.request(method, url);
        if let Some(b) = &self.bearer {
            req = req.bearer_auth(b);
        }
        Ok(req)
    }

    async fn handle<T: DeserializeOwned>(resp: reqwest::Response) -> Result<T> {
        let status = resp.status();
        if status.is_success() {
            Ok(resp.json::<T>().await?)
        } else {
            let body: ProblemDetails = resp.json().await.unwrap_or(ProblemDetails {
                title: status.canonical_reason().unwrap_or("Error").to_string(),
                status: status.as_u16(),
                detail: String::new(),
            });
            Err(Error::Api {
                status,
                title: body.title,
                detail: body.detail,
            })
        }
    }

    // ── Info ────────────────────────────────────────────────────────────
    pub async fn get_info(&self) -> Result<ServerInfo> {
        let resp = self.build(reqwest::Method::GET, "/v1/info")?.send().await?;
        Self::handle(resp).await
    }

    // ── VTXOs ───────────────────────────────────────────────────────────
    pub async fn list_vtxos(&self, pubkey: &str) -> Result<ListVtxosResponse> {
        let resp = self
            .build(reqwest::Method::GET, "/v1/vtxos")?
            .query(&[("pubkey", pubkey)])
            .send()
            .await?;
        Self::handle(resp).await
    }

    // ── Rounds ──────────────────────────────────────────────────────────
    pub async fn list_rounds(
        &self,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<ListRoundsResponse> {
        let mut q: Vec<(&str, String)> = Vec::new();
        if let Some(l) = limit {
            q.push(("limit", l.to_string()));
        }
        if let Some(o) = offset {
            q.push(("offset", o.to_string()));
        }
        let resp = self
            .build(reqwest::Method::GET, "/v1/rounds")?
            .query(&q)
            .send()
            .await?;
        Self::handle(resp).await
    }

    pub async fn get_round(&self, id: &str) -> Result<RoundInfo> {
        let resp = self
            .build(reqwest::Method::GET, &format!("/v1/rounds/{id}"))?
            .send()
            .await?;
        Self::handle(resp).await
    }

    // ── Txs ─────────────────────────────────────────────────────────────
    pub async fn submit_tx(&self, req: &SubmitTxRequest) -> Result<SubmitTxResponse> {
        let resp = self
            .build(reqwest::Method::POST, "/v1/txs")?
            .json(req)
            .send()
            .await?;
        Self::handle(resp).await
    }

    pub async fn finalize_tx(&self, id: &str) -> Result<()> {
        let resp = self
            .build(reqwest::Method::POST, &format!("/v1/txs/{id}/finalize"))?
            .json(&FinalizeTxRequest {
                final_checkpoint_txs: vec![],
            })
            .send()
            .await?;
        let status = resp.status();
        if status.is_success() {
            Ok(())
        } else {
            let body: ProblemDetails = resp.json().await.unwrap_or_default();
            Err(Error::Api {
                status,
                title: body.title,
                detail: body.detail,
            })
        }
    }

    // ── Exits ───────────────────────────────────────────────────────────
    pub async fn request_exit(&self, req: &RequestExitRequest) -> Result<RequestExitResponse> {
        let resp = self
            .build(reqwest::Method::POST, "/v1/exits")?
            .json(req)
            .send()
            .await?;
        Self::handle(resp).await
    }

    // ── Playground ──────────────────────────────────────────────────────
    pub async fn create_playground_session(&self) -> Result<CreateSessionResponse> {
        let resp = self
            .build(reqwest::Method::POST, "/v1/playground/session")?
            .json(&serde_json::json!({}))
            .send()
            .await?;
        Self::handle(resp).await
    }

    pub async fn get_playground_session(&self, id: &str) -> Result<SessionView> {
        let resp = self
            .build(
                reqwest::Method::GET,
                &format!("/v1/playground/session/{id}"),
            )?
            .send()
            .await?;
        Self::handle(resp).await
    }

    pub async fn faucet(&self, session_id: &str) -> Result<FaucetResponse> {
        let resp = self
            .build(reqwest::Method::POST, "/v1/playground/faucet")?
            .json(&serde_json::json!({ "session_id": session_id }))
            .send()
            .await?;
        Self::handle(resp).await
    }

    // ── Liveness ────────────────────────────────────────────────────────
    pub async fn ping(&self) -> Result<String> {
        let resp = self
            .build(reqwest::Method::GET, "/ping")?
            .send()
            .await?
            .text()
            .await?;
        Ok(resp)
    }
}

// ── Types (mirrors dark-wallet-rest DTOs) ───────────────────────────────

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ProblemDetails {
    pub title: String,
    pub status: u16,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    pub pubkey: String,
    pub forfeit_pubkey: String,
    pub network: String,
    pub session_duration: u32,
    pub unilateral_exit_delay: u32,
    pub boarding_exit_delay: u32,
    pub version: String,
    pub dust: u64,
    pub vtxo_min_amount: u64,
    pub vtxo_max_amount: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Asset {
    pub asset_id: String,
    pub amount: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vtxo {
    pub id: String,
    pub txid: String,
    pub vout: u32,
    pub amount: u64,
    pub script: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub is_spent: bool,
    pub is_swept: bool,
    pub is_unrolled: bool,
    pub spent_by: String,
    pub ark_txid: String,
    pub assets: Vec<Asset>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListVtxosResponse {
    pub vtxos: Vec<Vtxo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundSummary {
    pub id: String,
    pub starting_timestamp: i64,
    pub ending_timestamp: i64,
    pub stage: String,
    pub commitment_txid: String,
    pub failed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundInfo {
    pub id: String,
    pub starting_timestamp: i64,
    pub ending_timestamp: i64,
    pub stage: String,
    pub commitment_txid: String,
    pub failed: bool,
    pub intent_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListRoundsResponse {
    pub rounds: Vec<RoundSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitTxRequest {
    pub signed_ark_tx: String,
    #[serde(default)]
    pub checkpoint_txs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitTxResponse {
    pub ark_txid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalizeTxRequest {
    #[serde(default)]
    pub final_checkpoint_txs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestExitRequest {
    pub onchain_address: String,
    pub amount: u64,
    pub vtxo_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestExitResponse {
    pub exit_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSessionResponse {
    pub session_id: String,
    pub pubkey_hex: String,
    pub privkey_hex: String,
    pub boarding_address: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionView {
    pub session_id: String,
    pub pubkey_hex: String,
    pub boarding_address: String,
    pub created_at: i64,
    pub faucet_drips: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaucetResponse {
    pub boarding_address: String,
    pub drips_remaining: u32,
    pub note: String,
}
