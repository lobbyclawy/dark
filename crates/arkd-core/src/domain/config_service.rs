//! Static config service — returns a fixed config, no-op reload.

use async_trait::async_trait;

use crate::application::ArkConfig;
use crate::error::ArkResult;
use crate::ports::ConfigService;

/// A [`ConfigService`] that holds a fixed config in memory.
///
/// `reload()` is a no-op that returns the same config. Useful for tests
/// and deployments that don't need runtime config changes.
pub struct StaticConfigService {
    config: tokio::sync::watch::Sender<ArkConfig>,
}

impl StaticConfigService {
    /// Create a new static config service with the given config.
    pub fn new(config: ArkConfig) -> Self {
        let (tx, _) = tokio::sync::watch::channel(config);
        Self { config: tx }
    }
}

#[async_trait]
impl ConfigService for StaticConfigService {
    async fn get_config(&self) -> ArkResult<ArkConfig> {
        Ok(self.config.borrow().clone())
    }

    async fn reload(&self) -> ArkResult<ArkConfig> {
        // Static — no file to reload
        Ok(self.config.borrow().clone())
    }

    fn subscribe(&self) -> tokio::sync::watch::Receiver<ArkConfig> {
        self.config.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_static_config_service_get_config() {
        let config = ArkConfig::default();
        let svc = StaticConfigService::new(config.clone());
        let got = svc.get_config().await.unwrap();
        assert_eq!(got.network, config.network);
        assert_eq!(got.vtxo_expiry_secs, config.vtxo_expiry_secs);
    }

    #[tokio::test]
    async fn test_static_config_service_reload_returns_same() {
        let config = ArkConfig::default();
        let svc = StaticConfigService::new(config.clone());
        let first = svc.get_config().await.unwrap();
        let reloaded = svc.reload().await.unwrap();
        assert_eq!(first.network, reloaded.network);
        assert_eq!(first.vtxo_expiry_secs, reloaded.vtxo_expiry_secs);
    }

    #[tokio::test]
    async fn test_static_config_service_subscribe() {
        let config = ArkConfig::default();
        let svc = StaticConfigService::new(config.clone());
        let rx = svc.subscribe();
        let received = rx.borrow().clone();
        assert_eq!(received.network, config.network);
    }

    #[test]
    fn test_config_service_object_safe() {
        // Verify ConfigService is object-safe by constructing a trait object.
        let config = ArkConfig::default();
        let svc = StaticConfigService::new(config);
        let _dyn: std::sync::Arc<dyn ConfigService> = std::sync::Arc::new(svc);
    }
}
