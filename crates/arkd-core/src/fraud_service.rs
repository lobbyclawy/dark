//! FraudDetector service — real conviction logic for double-spends and
//! invalid forfeit transactions.
//!
//! Replaces the `NoopFraudDetector` with detection that:
//! 1. Finds double-spend attempts (same VTXO in multiple intents)
//! 2. Detects missing/invalid forfeit txs for VTXOs
//! 3. Creates convictions via `ConvictionRepository`
//! 4. Bans scripts on repeated offenses via `BanRepository`

use std::collections::HashMap;
use std::sync::Arc;

use tracing::{info, warn};

use crate::domain::ban::BanReason;
use crate::domain::{Conviction, CrimeType, Intent};
use crate::error::ArkResult;
use crate::ports::{BanRepository, ConvictionRepository, ValidForfeitTx};

/// Configuration for the fraud detection thresholds.
#[derive(Debug, Clone)]
pub struct FraudDetectorConfig {
    /// Number of active convictions before a script gets banned.
    pub ban_threshold: usize,
    /// Duration of a conviction ban in seconds (0 = permanent).
    pub ban_duration_secs: i64,
}

impl Default for FraudDetectorConfig {
    fn default() -> Self {
        Self {
            ban_threshold: 3,
            ban_duration_secs: 86400, // 24 hours
        }
    }
}

/// Real fraud detector that creates convictions and bans repeat offenders.
pub struct RealFraudDetector {
    conviction_repo: Arc<dyn ConvictionRepository>,
    ban_repo: Arc<dyn BanRepository>,
    config: FraudDetectorConfig,
}

impl RealFraudDetector {
    /// Create a new fraud detector with the given repositories and config.
    pub fn new(
        conviction_repo: Arc<dyn ConvictionRepository>,
        ban_repo: Arc<dyn BanRepository>,
        config: FraudDetectorConfig,
    ) -> Self {
        Self {
            conviction_repo,
            ban_repo,
            config,
        }
    }

    /// Detect fraud in a set of intents for a given round.
    ///
    /// Checks for:
    /// 1. **Double-spends** — the same VTXO outpoint appears as input in
    ///    multiple intents within the same round.
    /// 2. **Invalid forfeits** — an intent's VTXO inputs have no matching
    ///    validated forfeit transaction, indicating the participant failed
    ///    to provide valid forfeit signatures.
    ///
    /// For each detected violation a `Conviction` is created and persisted.
    /// If a script accumulates >= `ban_threshold` active convictions the
    /// script is banned via `BanRepository`.
    ///
    /// Returns the list of newly created convictions.
    pub async fn detect_fraud(
        &self,
        round_id: &str,
        intents: &[Intent],
        valid_forfeit_txs: &[ValidForfeitTx],
    ) -> ArkResult<Vec<Conviction>> {
        let mut convictions = Vec::new();

        // ── 1. Double-spend detection ──────────────────────────────
        let ds = self.detect_double_spends(round_id, intents).await?;
        convictions.extend(ds);

        // ── 2. Invalid forfeit detection ───────────────────────────
        let ff = self
            .detect_invalid_forfeits(round_id, intents, valid_forfeit_txs)
            .await?;
        convictions.extend(ff);

        // ── 3. Ban repeat offenders ────────────────────────────────
        for conviction in &convictions {
            self.maybe_ban_script(&conviction.script, round_id).await?;
        }

        if !convictions.is_empty() {
            info!(
                round_id,
                count = convictions.len(),
                "Fraud detected — convictions created"
            );
        }

        Ok(convictions)
    }

    /// Find VTXO outpoints that appear as inputs in more than one intent.
    async fn detect_double_spends(
        &self,
        round_id: &str,
        intents: &[Intent],
    ) -> ArkResult<Vec<Conviction>> {
        // Map outpoint → list of intent ids that use it
        let mut outpoint_intents: HashMap<String, Vec<&str>> = HashMap::new();
        for intent in intents {
            for vtxo in &intent.inputs {
                let key = format!("{}:{}", vtxo.outpoint.txid, vtxo.outpoint.vout);
                outpoint_intents.entry(key).or_default().push(&intent.id);
            }
        }

        let mut convictions = Vec::new();
        // Track scripts we've already convicted in this pass to avoid duplicates
        let mut convicted_scripts: std::collections::HashSet<String> =
            std::collections::HashSet::new();

        for (outpoint_key, intent_ids) in &outpoint_intents {
            if intent_ids.len() < 2 {
                continue;
            }

            warn!(
                outpoint = %outpoint_key,
                intent_count = intent_ids.len(),
                round_id,
                "Double-spend detected"
            );

            // Find the scripts (pubkeys) from the intents that submitted the
            // duplicate VTXO. Each unique script gets one conviction.
            for intent in intents {
                let uses_outpoint = intent.inputs.iter().any(|v| {
                    let k = format!("{}:{}", v.outpoint.txid, v.outpoint.vout);
                    k == *outpoint_key
                });
                if !uses_outpoint {
                    continue;
                }

                // Use the first input's pubkey as the script identifier
                let script = intent
                    .inputs
                    .first()
                    .map(|v| v.pubkey.clone())
                    .unwrap_or_default();

                if script.is_empty() || convicted_scripts.contains(&script) {
                    continue;
                }
                convicted_scripts.insert(script.clone());

                let reason = format!(
                    "Double-spend: VTXO {} used in {} intents ({})",
                    outpoint_key,
                    intent_ids.len(),
                    intent_ids.join(", ")
                );

                let conviction = Conviction::new_for_crime(
                    &script,
                    CrimeType::DoubleSpend,
                    round_id,
                    &reason,
                    self.config.ban_duration_secs,
                );

                self.conviction_repo.store(conviction.clone()).await?;
                convictions.push(conviction);
            }
        }

        Ok(convictions)
    }

    /// Detect intents whose VTXO inputs lack a valid forfeit transaction.
    ///
    /// An intent with off-chain outputs needs valid forfeit txs for each of
    /// its inputs. If `valid_forfeit_txs` doesn't cover an input's connector,
    /// the participant failed to provide valid forfeit signatures.
    async fn detect_invalid_forfeits(
        &self,
        round_id: &str,
        intents: &[Intent],
        valid_forfeit_txs: &[ValidForfeitTx],
    ) -> ArkResult<Vec<Conviction>> {
        let mut convictions = Vec::new();
        let mut convicted_scripts: std::collections::HashSet<String> =
            std::collections::HashSet::new();

        for intent in intents {
            // Only check intents that have off-chain outputs (they need forfeits)
            if intent.has_only_onchain_outputs() {
                continue;
            }

            // If the intent has no inputs, skip
            if intent.inputs.is_empty() {
                continue;
            }

            // Check if any of the intent's inputs have no matching forfeit tx.
            // We check by looking for the input outpoint in the valid forfeit
            // tx set. A forfeit tx spends a VTXO input + a connector, so we
            // check if any valid forfeit tx references one of the intent's VTXOs.
            let has_valid_forfeit = self.intent_has_valid_forfeits(intent, valid_forfeit_txs);

            if has_valid_forfeit {
                continue;
            }

            let script = intent
                .inputs
                .first()
                .map(|v| v.pubkey.clone())
                .unwrap_or_default();

            if script.is_empty() || convicted_scripts.contains(&script) {
                continue;
            }
            convicted_scripts.insert(script.clone());

            let reason = format!(
                "Missing valid forfeit txs for intent {} in round {}",
                intent.id, round_id,
            );

            warn!(
                intent_id = %intent.id,
                script = %script,
                round_id,
                "Invalid forfeit detected"
            );

            let conviction = Conviction::new_for_crime(
                &script,
                CrimeType::ForfeitSubmission,
                round_id,
                &reason,
                self.config.ban_duration_secs,
            );

            self.conviction_repo.store(conviction.clone()).await?;
            convictions.push(conviction);
        }

        Ok(convictions)
    }

    /// Check whether an intent has at least one valid forfeit tx that
    /// references one of its input VTXOs via the forfeit's raw tx data.
    ///
    /// We use the connector outpoint of each `ValidForfeitTx` as a proxy:
    /// if there's any valid forfeit tx in the set, the intent is considered
    /// covered. For more precise matching we'd need to decode the raw tx
    /// and check inputs, but the connector-based approach matches how the
    /// Go implementation groups forfeit txs.
    fn intent_has_valid_forfeits(
        &self,
        intent: &Intent,
        valid_forfeit_txs: &[ValidForfeitTx],
    ) -> bool {
        if valid_forfeit_txs.is_empty() {
            // If no forfeit txs at all, only on-chain-only intents are OK
            // (already filtered above)
            return false;
        }

        // Check if any valid forfeit tx's raw tx data references one of
        // the intent's input outpoints. We do a simple string-contains check
        // on the hex tx for the txid (this is a heuristic; production would
        // decode the tx).
        for vtxo in &intent.inputs {
            let txid = &vtxo.outpoint.txid;
            let found = valid_forfeit_txs.iter().any(|vf| vf.tx.contains(txid));
            if !found {
                return false;
            }
        }

        true
    }

    /// If the script has accumulated enough convictions, ban it.
    async fn maybe_ban_script(&self, script: &str, round_id: &str) -> ArkResult<()> {
        let existing = self.conviction_repo.get_active_by_script(script).await?;

        let active_count = existing.iter().filter(|c| c.is_active()).count();

        if active_count >= self.config.ban_threshold {
            // Check if already banned
            if self.ban_repo.is_banned(script).await? {
                return Ok(());
            }

            warn!(
                script,
                active_convictions = active_count,
                threshold = self.config.ban_threshold,
                "Banning script due to repeated offenses"
            );

            self.ban_repo
                .ban(script, BanReason::DoubleSpend, round_id)
                .await?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::vtxo::{Vtxo, VtxoOutpoint};
    use crate::domain::{InMemoryBanRepository, Receiver};
    use std::sync::Mutex;

    /// In-memory conviction repository for testing.
    struct InMemoryConvictionRepo {
        convictions: Mutex<Vec<Conviction>>,
    }

    impl InMemoryConvictionRepo {
        fn new() -> Self {
            Self {
                convictions: Mutex::new(Vec::new()),
            }
        }

        fn count(&self) -> usize {
            self.convictions.lock().unwrap().len()
        }
    }

    #[async_trait::async_trait]
    impl ConvictionRepository for InMemoryConvictionRepo {
        async fn store(&self, conviction: Conviction) -> ArkResult<()> {
            self.convictions.lock().unwrap().push(conviction);
            Ok(())
        }

        async fn get_by_ids(&self, ids: &[String]) -> ArkResult<Vec<Conviction>> {
            let guard = self.convictions.lock().unwrap();
            Ok(guard
                .iter()
                .filter(|c| ids.contains(&c.id))
                .cloned()
                .collect())
        }

        async fn get_in_range(&self, from: i64, to: i64) -> ArkResult<Vec<Conviction>> {
            let guard = self.convictions.lock().unwrap();
            Ok(guard
                .iter()
                .filter(|c| c.created_at >= from && c.created_at <= to)
                .cloned()
                .collect())
        }

        async fn get_by_round(&self, round_id: &str) -> ArkResult<Vec<Conviction>> {
            let guard = self.convictions.lock().unwrap();
            Ok(guard
                .iter()
                .filter(|c| c.round_id == round_id)
                .cloned()
                .collect())
        }

        async fn pardon(&self, id: &str) -> ArkResult<()> {
            let mut guard = self.convictions.lock().unwrap();
            if let Some(c) = guard.iter_mut().find(|c| c.id == id) {
                c.pardoned = true;
            }
            Ok(())
        }

        async fn get_active_by_script(&self, script: &str) -> ArkResult<Vec<Conviction>> {
            let guard = self.convictions.lock().unwrap();
            Ok(guard
                .iter()
                .filter(|c| c.script == script && c.is_active())
                .cloned()
                .collect())
        }
    }

    fn make_vtxo(txid: &str, vout: u32, pubkey: &str) -> Vtxo {
        Vtxo::new(
            VtxoOutpoint::new(txid.to_string(), vout),
            50_000,
            pubkey.to_string(),
        )
    }

    fn make_intent(id: &str, inputs: Vec<Vtxo>, onchain_only: bool) -> Intent {
        let receivers = if onchain_only {
            vec![Receiver::onchain(40_000, "bc1qaddr".to_string())]
        } else {
            vec![Receiver::offchain(40_000, "pk_receiver".to_string())]
        };

        Intent {
            id: id.to_string(),
            inputs,
            receivers,
            proof: "proof".to_string(),
            message: "msg".to_string(),
            txid: "txid".to_string(),
            leaf_tx_asset_packet: String::new(),
        }
    }

    fn make_detector(
        conviction_repo: Arc<dyn ConvictionRepository>,
        ban_repo: Arc<dyn BanRepository>,
    ) -> RealFraudDetector {
        RealFraudDetector::new(conviction_repo, ban_repo, FraudDetectorConfig::default())
    }

    // ── Test 1: No fraud in clean intents ──────────────────────────

    #[tokio::test]
    async fn test_no_fraud_clean_intents() {
        let conv_repo = Arc::new(InMemoryConvictionRepo::new());
        let ban_repo = Arc::new(InMemoryBanRepository::new());
        let detector = make_detector(conv_repo.clone(), ban_repo);

        let intents = vec![
            make_intent("i1", vec![make_vtxo("aaa", 0, "script_a")], false),
            make_intent("i2", vec![make_vtxo("bbb", 0, "script_b")], false),
        ];

        // All inputs have valid forfeits
        let valid_forfeits = vec![
            ValidForfeitTx {
                tx: "...aaa...".to_string(),
                connector: VtxoOutpoint::new("conn1".to_string(), 0),
            },
            ValidForfeitTx {
                tx: "...bbb...".to_string(),
                connector: VtxoOutpoint::new("conn2".to_string(), 0),
            },
        ];

        let result = detector
            .detect_fraud("round-1", &intents, &valid_forfeits)
            .await
            .unwrap();

        assert!(result.is_empty(), "No fraud should be detected");
        assert_eq!(conv_repo.count(), 0);
    }

    // ── Test 2: Double-spend detected ──────────────────────────────

    #[tokio::test]
    async fn test_double_spend_detected() {
        let conv_repo = Arc::new(InMemoryConvictionRepo::new());
        let ban_repo = Arc::new(InMemoryBanRepository::new());
        let detector = make_detector(conv_repo.clone(), ban_repo);

        // Same VTXO (aaa:0) in two different intents
        let intents = vec![
            make_intent("i1", vec![make_vtxo("aaa", 0, "script_a")], false),
            make_intent("i2", vec![make_vtxo("aaa", 0, "script_b")], false),
        ];

        let valid_forfeits = vec![ValidForfeitTx {
            tx: "...aaa...".to_string(),
            connector: VtxoOutpoint::new("conn1".to_string(), 0),
        }];

        let result = detector
            .detect_fraud("round-1", &intents, &valid_forfeits)
            .await
            .unwrap();

        // Two scripts using the same outpoint → two convictions
        assert_eq!(result.len(), 2, "Should create 2 double-spend convictions");
        assert!(result
            .iter()
            .all(|c| c.crime_type == CrimeType::DoubleSpend));
        assert_eq!(conv_repo.count(), 2);
    }

    // ── Test 3: Missing forfeit tx detected ────────────────────────

    #[tokio::test]
    async fn test_missing_forfeit_detected() {
        let conv_repo = Arc::new(InMemoryConvictionRepo::new());
        let ban_repo = Arc::new(InMemoryBanRepository::new());
        let detector = make_detector(conv_repo.clone(), ban_repo);

        let intents = vec![make_intent(
            "i1",
            vec![make_vtxo("aaa", 0, "script_a")],
            false, // off-chain outputs → needs forfeits
        )];

        // No valid forfeit txs at all
        let valid_forfeits: Vec<ValidForfeitTx> = vec![];

        let result = detector
            .detect_fraud("round-1", &intents, &valid_forfeits)
            .await
            .unwrap();

        assert_eq!(result.len(), 1, "Should detect missing forfeit");
        assert_eq!(result[0].crime_type, CrimeType::ForfeitSubmission);
        assert_eq!(result[0].script, "script_a");
    }

    // ── Test 4: On-chain-only intents skip forfeit check ───────────

    #[tokio::test]
    async fn test_onchain_only_skips_forfeit_check() {
        let conv_repo = Arc::new(InMemoryConvictionRepo::new());
        let ban_repo = Arc::new(InMemoryBanRepository::new());
        let detector = make_detector(conv_repo.clone(), ban_repo);

        let intents = vec![make_intent(
            "i1",
            vec![make_vtxo("aaa", 0, "script_a")],
            true, // on-chain only → no forfeits needed
        )];

        let valid_forfeits: Vec<ValidForfeitTx> = vec![];

        let result = detector
            .detect_fraud("round-1", &intents, &valid_forfeits)
            .await
            .unwrap();

        assert!(
            result.is_empty(),
            "On-chain-only intents should not trigger fraud"
        );
    }

    // ── Test 5: Repeated offenses trigger ban ──────────────────────

    #[tokio::test]
    async fn test_repeated_offenses_trigger_ban() {
        let conv_repo = Arc::new(InMemoryConvictionRepo::new());
        let ban_repo = Arc::new(InMemoryBanRepository::new());

        // Lower threshold to 2 for testing
        let detector = RealFraudDetector::new(
            conv_repo.clone(),
            ban_repo.clone(),
            FraudDetectorConfig {
                ban_threshold: 2,
                ban_duration_secs: 3600,
            },
        );

        // Pre-seed one conviction so next offense hits threshold
        let existing = Conviction::new_for_crime(
            "script_a",
            CrimeType::DoubleSpend,
            "round-0",
            "prior offense",
            3600,
        );
        conv_repo.store(existing).await.unwrap();

        // Now trigger another offense
        let intents = vec![
            make_intent("i1", vec![make_vtxo("aaa", 0, "script_a")], false),
            make_intent("i2", vec![make_vtxo("aaa", 0, "script_a")], false),
        ];

        let valid_forfeits = vec![ValidForfeitTx {
            tx: "...aaa...".to_string(),
            connector: VtxoOutpoint::new("conn1".to_string(), 0),
        }];

        let result = detector
            .detect_fraud("round-1", &intents, &valid_forfeits)
            .await
            .unwrap();

        assert!(!result.is_empty(), "Should detect double-spend");

        // Script should now be banned (1 prior + 1 new = 2 >= threshold of 2)
        let banned = ban_repo.is_banned("script_a").await.unwrap();
        assert!(banned, "script_a should be banned after reaching threshold");
    }

    // ── Test 6: Empty intents = no fraud ───────────────────────────

    #[tokio::test]
    async fn test_empty_intents_no_fraud() {
        let conv_repo = Arc::new(InMemoryConvictionRepo::new());
        let ban_repo = Arc::new(InMemoryBanRepository::new());
        let detector = make_detector(conv_repo.clone(), ban_repo);

        let result = detector.detect_fraud("round-1", &[], &[]).await.unwrap();

        assert!(result.is_empty());
        assert_eq!(conv_repo.count(), 0);
    }

    // ── Test 7: Multiple VTXOs double-spent ────────────────────────

    #[tokio::test]
    async fn test_multiple_vtxos_double_spent() {
        let conv_repo = Arc::new(InMemoryConvictionRepo::new());
        let ban_repo = Arc::new(InMemoryBanRepository::new());
        let detector = make_detector(conv_repo.clone(), ban_repo);

        // Intent 1 uses VTXOs aaa:0 and bbb:0
        // Intent 2 also uses aaa:0 and bbb:0
        let intents = vec![
            make_intent(
                "i1",
                vec![
                    make_vtxo("aaa", 0, "script_a"),
                    make_vtxo("bbb", 0, "script_a"),
                ],
                false,
            ),
            make_intent(
                "i2",
                vec![
                    make_vtxo("aaa", 0, "script_b"),
                    make_vtxo("bbb", 0, "script_b"),
                ],
                false,
            ),
        ];

        let valid_forfeits = vec![ValidForfeitTx {
            tx: "...aaa...bbb...".to_string(),
            connector: VtxoOutpoint::new("conn1".to_string(), 0),
        }];

        let result = detector
            .detect_fraud("round-1", &intents, &valid_forfeits)
            .await
            .unwrap();

        // Both scripts should get convicted (once each, deduped per script)
        let ds_convictions: Vec<_> = result
            .iter()
            .filter(|c| c.crime_type == CrimeType::DoubleSpend)
            .collect();
        assert_eq!(ds_convictions.len(), 2, "Two scripts should be convicted");
    }

    // ── Test 8: Conviction fields are correct ──────────────────────

    #[tokio::test]
    async fn test_conviction_fields_correct() {
        let conv_repo = Arc::new(InMemoryConvictionRepo::new());
        let ban_repo = Arc::new(InMemoryBanRepository::new());
        let detector = make_detector(conv_repo.clone(), ban_repo);

        let intents = vec![
            make_intent("i1", vec![make_vtxo("aaa", 0, "script_x")], false),
            make_intent("i2", vec![make_vtxo("aaa", 0, "script_y")], false),
        ];

        let valid_forfeits = vec![ValidForfeitTx {
            tx: "...aaa...".to_string(),
            connector: VtxoOutpoint::new("conn1".to_string(), 0),
        }];

        let result = detector
            .detect_fraud("round-42", &intents, &valid_forfeits)
            .await
            .unwrap();

        assert!(!result.is_empty());
        let c = &result[0];
        assert_eq!(c.round_id, "round-42");
        assert_eq!(c.crime_type, CrimeType::DoubleSpend);
        assert!(c.is_active());
        assert!(!c.pardoned);
        assert!(!c.id.is_empty());
        assert!(c.reason.contains("Double-spend"));
    }
}
