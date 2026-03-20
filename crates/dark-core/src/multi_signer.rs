//! MultiSigner — wraps a primary signer plus zero or more deprecated signers.
//!
//! After a key rotation the old key(s) may still be needed to verify
//! existing VTXOs. `MultiSigner` keeps them around while always signing
//! with the current (primary) key.

use std::sync::Arc;

use async_trait::async_trait;
use bitcoin::XOnlyPublicKey;

use crate::error::ArkResult;
use crate::ports::SignerService;

/// A signer that holds the current active key plus zero or more deprecated keys.
///
/// * **Signing** always delegates to the primary signer.
/// * **Verification** can check against any key returned by [`all_pubkeys`](Self::all_pubkeys).
pub struct MultiSigner {
    primary: Arc<dyn SignerService>,
    deprecated: Vec<Arc<dyn SignerService>>,
}

impl MultiSigner {
    /// Create a new `MultiSigner`.
    pub fn new(primary: Arc<dyn SignerService>, deprecated: Vec<Arc<dyn SignerService>>) -> Self {
        Self {
            primary,
            deprecated,
        }
    }

    /// Reference to the primary (active) signer.
    pub fn primary(&self) -> &Arc<dyn SignerService> {
        &self.primary
    }

    /// All public keys: `[primary, …deprecated]`.
    pub async fn all_pubkeys(&self) -> ArkResult<Vec<XOnlyPublicKey>> {
        let mut keys = vec![self.primary.get_pubkey().await?];
        for d in &self.deprecated {
            keys.push(d.get_pubkey().await?);
        }
        Ok(keys)
    }
}

#[async_trait]
impl SignerService for MultiSigner {
    async fn get_pubkey(&self) -> ArkResult<XOnlyPublicKey> {
        self.primary.get_pubkey().await
    }

    async fn sign_transaction(&self, partial_tx: &str, extract_raw: bool) -> ArkResult<String> {
        self.primary.sign_transaction(partial_tx, extract_raw).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::LocalSigner;

    fn random_signer() -> Arc<dyn SignerService> {
        Arc::new(LocalSigner::random())
    }

    #[tokio::test]
    async fn test_multi_signer_uses_primary_pubkey() {
        let primary = random_signer();
        let expected = primary.get_pubkey().await.unwrap();

        let multi = MultiSigner::new(primary, vec![random_signer()]);
        assert_eq!(multi.get_pubkey().await.unwrap(), expected);
    }

    #[tokio::test]
    async fn test_multi_signer_signs_with_primary() {
        let primary = random_signer();
        let multi = MultiSigner::new(primary.clone(), vec![random_signer()]);

        let input = "deadbeef";
        let result = multi.sign_transaction(input, false).await.unwrap();
        let expected = primary.sign_transaction(input, false).await.unwrap();
        assert_eq!(result, expected);
    }

    #[tokio::test]
    async fn test_multi_signer_all_pubkeys_includes_all() {
        let primary = random_signer();
        let dep1 = random_signer();
        let dep2 = random_signer();

        let pk_primary = primary.get_pubkey().await.unwrap();
        let pk_dep1 = dep1.get_pubkey().await.unwrap();
        let pk_dep2 = dep2.get_pubkey().await.unwrap();

        let multi = MultiSigner::new(primary, vec![dep1, dep2]);
        let all = multi.all_pubkeys().await.unwrap();

        assert_eq!(all.len(), 3);
        assert_eq!(all[0], pk_primary);
        assert_eq!(all[1], pk_dep1);
        assert_eq!(all[2], pk_dep2);
    }

    #[tokio::test]
    async fn test_multi_signer_empty_deprecated_works() {
        let primary = random_signer();
        let pk = primary.get_pubkey().await.unwrap();

        let multi = MultiSigner::new(primary, vec![]);
        assert_eq!(multi.get_pubkey().await.unwrap(), pk);

        let all = multi.all_pubkeys().await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0], pk);
    }
}
