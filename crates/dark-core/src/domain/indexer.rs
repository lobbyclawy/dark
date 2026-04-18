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
                // Use the list_all method for unfiltered listing
                let (spendable, spent) = self.vtxo_repo.list_all().await?;
                let mut all = spendable;
                all.extend(spent);
                Ok(all)
            }
        }
    }

    async fn get_vtxo(&self, vtxo_id: &str) -> ArkResult<Option<Vtxo>> {
        // Parse "txid:vout" into a VtxoOutpoint
        let Some(outpoint) = VtxoOutpoint::from_string(vtxo_id) else {
            return Ok(None);
        };
        let vtxos = self.vtxo_repo.get_vtxos(&[outpoint]).await?;
        Ok(vtxos.into_iter().next())
    }

    async fn list_rounds(&self, offset: u32, limit: u32) -> ArkResult<Vec<Round>> {
        self.round_repo.list_rounds(offset, limit).await
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
        // Compute real stats from the repositories
        let (spendable, spent) = self.vtxo_repo.list_all().await?;
        let total_vtxos = (spendable.len() + spent.len()) as u64;
        let total_sats_locked: u64 = spendable.iter().map(|v| v.amount).sum();
        let total_rounds = self.round_repo.count_rounds().await?;

        // For forfeit count, we'd need a count method on ForfeitRepository.
        // For now, return 0 (could be added in a future PR).
        let total_forfeits = 0;

        Ok(IndexerStats {
            total_vtxos,
            total_rounds,
            total_forfeits,
            total_sats_locked,
        })
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

    // ── Tests with populated repos ──────────────────────────────────

    struct PopulatedVtxoRepo {
        vtxos: Vec<Vtxo>,
    }

    impl PopulatedVtxoRepo {
        fn new(vtxos: Vec<Vtxo>) -> Self {
            Self { vtxos }
        }
    }

    #[async_trait]
    impl VtxoRepository for PopulatedVtxoRepo {
        async fn add_vtxos(&self, _: &[Vtxo]) -> ArkResult<()> {
            Ok(())
        }
        async fn get_vtxos(&self, _: &[VtxoOutpoint]) -> ArkResult<Vec<Vtxo>> {
            Ok(vec![])
        }
        async fn get_all_vtxos_for_pubkey(&self, pk: &str) -> ArkResult<(Vec<Vtxo>, Vec<Vtxo>)> {
            let (spendable, spent): (Vec<_>, Vec<_>) = self
                .vtxos
                .iter()
                .filter(|v| v.pubkey == pk)
                .cloned()
                .partition(|v| !v.spent && !v.swept);
            Ok((spendable, spent))
        }
        async fn spend_vtxos(&self, _: &[(VtxoOutpoint, String)], _: &str) -> ArkResult<()> {
            Ok(())
        }
        async fn list_all(&self) -> ArkResult<(Vec<Vtxo>, Vec<Vtxo>)> {
            let (spendable, spent): (Vec<_>, Vec<_>) = self
                .vtxos
                .iter()
                .cloned()
                .partition(|v| !v.spent && !v.swept);
            Ok((spendable, spent))
        }
    }

    struct PopulatedRoundRepo {
        rounds: Vec<Round>,
    }

    impl PopulatedRoundRepo {
        fn new(rounds: Vec<Round>) -> Self {
            Self { rounds }
        }
    }

    #[async_trait]
    impl RoundRepository for PopulatedRoundRepo {
        async fn add_or_update_round(&self, _: &Round) -> ArkResult<()> {
            Ok(())
        }
        async fn get_round_with_id(&self, id: &str) -> ArkResult<Option<Round>> {
            Ok(self.rounds.iter().find(|r| r.id == id).cloned())
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
        async fn list_rounds(&self, offset: u32, limit: u32) -> ArkResult<Vec<Round>> {
            let start = offset as usize;
            let end = std::cmp::min(start + limit as usize, self.rounds.len());
            if start >= self.rounds.len() {
                return Ok(vec![]);
            }
            Ok(self.rounds[start..end].to_vec())
        }
        async fn count_rounds(&self) -> ArkResult<u64> {
            Ok(self.rounds.len() as u64)
        }
    }

    #[tokio::test]
    async fn test_indexer_list_vtxos_all() {
        let v1 = Vtxo::new(VtxoOutpoint::new("tx1".into(), 0), 100_000, "pk1".into());
        let v2 = Vtxo::new(VtxoOutpoint::new("tx2".into(), 0), 200_000, "pk2".into());
        let vtxo_repo = Arc::new(PopulatedVtxoRepo::new(vec![v1, v2]));

        let idx = RepositoryIndexer::new(
            vtxo_repo,
            Arc::new(EmptyRoundRepo),
            Arc::new(NoopForfeitRepository),
        );

        // list_vtxos(None) should return all VTXOs
        let all = idx.list_vtxos(None).await.unwrap();
        assert_eq!(all.len(), 2);
    }

    #[tokio::test]
    async fn test_indexer_list_rounds_pagination() {
        let rounds = (0..5)
            .map(|i| {
                let mut r = Round::new();
                r.id = format!("round-{i}");
                r
            })
            .collect();
        let round_repo = Arc::new(PopulatedRoundRepo::new(rounds));

        let idx = RepositoryIndexer::new(
            Arc::new(EmptyVtxoRepo),
            round_repo,
            Arc::new(NoopForfeitRepository),
        );

        let page1 = idx.list_rounds(0, 2).await.unwrap();
        assert_eq!(page1.len(), 2);
        assert_eq!(page1[0].id, "round-0");
        assert_eq!(page1[1].id, "round-1");

        let page2 = idx.list_rounds(2, 2).await.unwrap();
        assert_eq!(page2.len(), 2);
        assert_eq!(page2[0].id, "round-2");
    }

    #[tokio::test]
    async fn test_indexer_stats_with_data() {
        let v1 = Vtxo::new(VtxoOutpoint::new("tx1".into(), 0), 100_000, "pk1".into());
        let v2 = Vtxo::new(VtxoOutpoint::new("tx2".into(), 0), 200_000, "pk2".into());
        let vtxo_repo = Arc::new(PopulatedVtxoRepo::new(vec![v1, v2]));

        let rounds = (0..3)
            .map(|i| {
                let mut r = Round::new();
                r.id = format!("round-{i}");
                r
            })
            .collect();
        let round_repo = Arc::new(PopulatedRoundRepo::new(rounds));

        let idx = RepositoryIndexer::new(vtxo_repo, round_repo, Arc::new(NoopForfeitRepository));

        let stats = idx.get_stats().await.unwrap();
        assert_eq!(stats.total_vtxos, 2);
        assert_eq!(stats.total_rounds, 3);
        assert_eq!(stats.total_sats_locked, 300_000);
    }
}
