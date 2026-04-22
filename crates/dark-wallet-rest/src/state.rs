//! Shared server state held in an axum `State` extractor.

use std::collections::HashMap;
use std::sync::Arc;

use dark_api::auth::Authenticator;
use dark_api::proto::ark_v1::ark_service_client::ArkServiceClient;
use dark_api::proto::ark_v1::indexer_service_client::IndexerServiceClient;
use dark_client::ArkClient;
use tokio::sync::{Mutex, RwLock};
use tonic::transport::Channel;

use crate::config::Config;

#[derive(Clone)]
pub struct AppState {
    inner: Arc<Inner>,
}

struct Inner {
    ark: Mutex<ArkClient>,
    ark_raw: Mutex<ArkServiceClient<Channel>>,
    indexer: Mutex<IndexerServiceClient<Channel>>,
    grpc_url: String,
    authenticator: Option<Arc<Authenticator>>,
    sessions: RwLock<HashMap<String, PlaygroundSession>>,
}

/// In-memory record of a playground session (keypair + timestamps).
#[derive(Clone, Debug)]
pub struct PlaygroundSession {
    pub session_id: String,
    pub pubkey_hex: String,
    pub privkey_hex: String,
    pub boarding_address: String,
    pub created_at: i64,
    pub faucet_drips: u32,
}

impl AppState {
    /// Connect to the upstream dark server and wrap it in shareable state.
    pub async fn connect(config: &Config) -> anyhow::Result<Self> {
        let mut ark = ArkClient::new(config.dark_grpc_url.clone());
        ark.connect()
            .await
            .map_err(|e| anyhow::anyhow!("connect to dark at {}: {e}", config.dark_grpc_url))?;

        let channel = Channel::from_shared(config.dark_grpc_url.clone())
            .map_err(|e| anyhow::anyhow!("invalid grpc url: {e}"))?
            .connect()
            .await
            .map_err(|e| anyhow::anyhow!("indexer channel: {e}"))?;
        let indexer = IndexerServiceClient::new(channel.clone());
        let ark_raw = ArkServiceClient::new(channel);

        let authenticator = config
            .macaroon_root_key
            .as_ref()
            .map(|key| Arc::new(Authenticator::new(key.clone())));

        Ok(Self {
            inner: Arc::new(Inner {
                ark: Mutex::new(ark),
                ark_raw: Mutex::new(ark_raw),
                indexer: Mutex::new(indexer),
                grpc_url: config.dark_grpc_url.clone(),
                authenticator,
                sessions: RwLock::new(HashMap::new()),
            }),
        })
    }

    /// Lock the Ark client for a single RPC.
    pub async fn ark(&self) -> tokio::sync::MutexGuard<'_, ArkClient> {
        self.inner.ark.lock().await
    }

    /// Lock the Indexer client for a single RPC.
    pub async fn indexer(&self) -> tokio::sync::MutexGuard<'_, IndexerServiceClient<Channel>> {
        self.inner.indexer.lock().await
    }

    /// Lock the raw ArkService client for RPCs not yet exposed by `dark-client`.
    pub async fn ark_raw(&self) -> tokio::sync::MutexGuard<'_, ArkServiceClient<Channel>> {
        self.inner.ark_raw.lock().await
    }

    /// Upstream gRPC URL.
    pub fn grpc_url(&self) -> &str {
        &self.inner.grpc_url
    }

    /// Optional macaroon authenticator. `None` means no root key is configured.
    pub fn authenticator(&self) -> Option<Arc<Authenticator>> {
        self.inner.authenticator.clone()
    }

    /// Playground session accessors.
    pub async fn sessions_write(
        &self,
    ) -> tokio::sync::RwLockWriteGuard<'_, HashMap<String, PlaygroundSession>> {
        self.inner.sessions.write().await
    }

    pub async fn sessions_read(
        &self,
    ) -> tokio::sync::RwLockReadGuard<'_, HashMap<String, PlaygroundSession>> {
        self.inner.sessions.read().await
    }
}
