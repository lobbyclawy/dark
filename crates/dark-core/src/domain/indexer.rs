//! RepositoryIndexer — IndexerService backed by existing repositories.
//!
//! Wraps `VtxoRepository`, `RoundRepository`, and `ForfeitRepository` to provide
//! a unified query interface mirroring Go dark's `IndexerService`.

use std::sync::Arc;

use async_trait::async_trait;

use crate::domain::{ForfeitRecord, Round, Vtxo, VtxoOutpoint};
use crate::error::ArkResult;
use crate::ports::{
    ForfeitRepository, IndexerService, IndexerStats, RoundRepository, VtxoRepository,
};

/// IndexerService implementation that delegates to the existing repository ports.
pub struct RepositoryIndexer {
    vtxo_repo: Arc<dyn VtxoRepository>,
    round_repo: Arc<dyn RoundRepository>,
    forfeit_repo: Arc<dyn ForfeitRepository>,
}

impl RepositoryIndexer {
    /// Create a new `RepositoryIndexer` wrapping the given repositories.
    pub fn new(
        vtxo_repo: Arc<dyn VtxoRepository>,
        round_repo: Arc<dyn RoundRepository>,
        forfeit_repo: Arc<dyn ForfeitRepository>,
    ) -> Self {
        Self {
            vtxo_repo,
            round_repo,
            forfeit_repo,
        }
    }
}

#[async_trait]
impl IndexerService for RepositoryIndexer {
    async fn list_vtxos(&self, pubkey: Option<&str>) -> ArkResult<Vec<Vtxo>> {
        match pubkey {
            Some(pk) => {
                let (spendable, spent) = self.vtxo_repo.get_all_vtxos_for_pubkey(pk).await?;
                let mut all = spendable;
                all.extend(spent);
                Ok(all)
            }
            None => {
                // VtxoRepository doesn't expose a list-all method yet.
                // Return empty until a `list_all` query is added to the repo trait.
                // TODO(#133): add VtxoRepository::list_all for unfiltered listing
                Ok(Vec::new())
            }
        }
    }

    async fn get_vtxo(&self, vtxo_id: &str) -> ArkResult<Option<Vtxo>> {
        // Parse "txid:vout" into a VtxoOutpoint
        let outpoint = match VtxoOutpoint::from_string(vtxo_id) {
            Some(op) => op,
            None => return Ok(None),
        };
        let vtxos = self.vtxo_repo.get_vtxos(&[outpoint]).await?;
        Ok(vtxos.into_iter().next())
    }

    async fn list_rounds(&self, _offset: u32, _limit: u32) -> ArkResult<Vec<Round>> {
        // RoundRepository doesn't expose paginated listing yet.
        // TODO(#133): add RoundRepository::list_rounds(offset, limit)
        Ok(Vec::new())
    }

    async fn get_round(&self, round_id: &str) -> ArkResult<Option<Round>> {
        self.round_repo.get_round_with_id(round_id).await
    }

    async fn get_round_by_commitment_txid(&self, txid: &str) -> ArkResult<Option<Round>> {
        self.round_repo.get_round_by_commitment_txid(txid).await
    }

    async fn list_forfeits(&self, round_id: &str) -> ArkResult<Vec<ForfeitRecord>> {
        self.forfeit_repo.list_by_round(round_id).await
    }

    async fn get_stats(&self) -> ArkResult<IndexerStats> {
        // Without list-all queries on the repos we can only return defaults.
        // Real stats will be populated once repo list methods are added.
        // TODO(#133): compute real stats from repos
        Ok(IndexerStats::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::VtxoOutpoint;
    use crate::error::ArkResult;
    use crate::ports::{NoopForfeitRepository, RoundRepository, VtxoRepository};

    // ── Minimal in-memory stubs ──────────────────────────────────────

    struct EmptyVtxoRepo;

    #[async_trait]
    impl VtxoRepository for EmptyVtxoRepo {
        async fn add_vtxos(&self, _: &[Vtxo]) -> ArkResult<()> {
            Ok(())
        }
        async fn get_vtxos(&self, _: &[VtxoOutpoint]) -> ArkResult<Vec<Vtxo>> {
            Ok(vec![])
        }
        async fn get_all_vtxos_for_pubkey(&self, _: &str) -> ArkResult<(Vec<Vtxo>, Vec<Vtxo>)> {
            Ok((vec![], vec![]))
        }
        async fn spend_vtxos(&self, _: &[(VtxoOutpoint, String)], _: &str) -> ArkResult<()> {
            Ok(())
        }
    }

    struct EmptyRoundRepo;

    #[async_trait]
    impl RoundRepository for EmptyRoundRepo {
        async fn add_or_update_round(&self, _: &Round) -> ArkResult<()> {
            Ok(())
        }
        async fn get_round_with_id(&self, _: &str) -> ArkResult<Option<Round>> {
            Ok(None)
        }
        async fn get_round_stats(&self, _: &str) -> ArkResult<Option<crate::domain::RoundStats>> {
            Ok(None)
        }
        async fn confirm_intent(&self, _: &str, _: &str) -> ArkResult<()> {
            Ok(())
        }
        async fn get_pending_confirmations(&self, _: &str) -> ArkResult<Vec<String>> {
            Ok(vec![])
        }
    }

    fn make_indexer() -> RepositoryIndexer {
        RepositoryIndexer::new(
            Arc::new(EmptyVtxoRepo),
            Arc::new(EmptyRoundRepo),
            Arc::new(NoopForfeitRepository),
        )
    }

    #[tokio::test]
    async fn test_repository_indexer_list_vtxos_empty() {
        let idx = make_indexer();
        let vtxos = idx.list_vtxos(None).await.unwrap();
        assert!(vtxos.is_empty());

        let vtxos = idx.list_vtxos(Some("deadbeef")).await.unwrap();
        assert!(vtxos.is_empty());
    }

    #[tokio::test]
    async fn test_repository_indexer_get_round_missing() {
        let idx = make_indexer();
        let round = idx.get_round("nonexistent-round-id").await.unwrap();
        assert!(round.is_none());
    }

    #[tokio::test]
    async fn test_repository_indexer_stats_default() {
        let idx = make_indexer();
        let stats = idx.get_stats().await.unwrap();
        assert_eq!(stats.total_vtxos, 0);
        assert_eq!(stats.total_rounds, 0);
        assert_eq!(stats.total_forfeits, 0);
        assert_eq!(stats.total_sats_locked, 0);
    }

    #[test]
    fn test_indexer_service_trait_object_safe() {
        fn _assert<T: ?Sized>() {}
        _assert::<dyn IndexerService>();
    }
}
