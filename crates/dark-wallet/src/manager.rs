//! Wallet manager implementation
//!
//! Core wallet functionality using BDK (Bitcoin Development Kit) 1.0.
//! Provides address generation, balance queries, UTXO management,
//! transaction building, and PSBT signing.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

use bdk_esplora::esplora_client::{self, AsyncClient};
use bdk_esplora::EsploraAsyncExt;
use bdk_wallet::bitcoin::bip32::Xpriv;
use bdk_wallet::file_store::Store as FileStore;
use bdk_wallet::keys::bip39::{Language, Mnemonic, WordCount};
use bdk_wallet::keys::GeneratedKey;
use bdk_wallet::keys::{DerivableKey, ExtendedKey, GeneratableKey};
use bdk_wallet::miniscript::Tap;
use bdk_wallet::template::{Bip86, DescriptorTemplate};
use bdk_wallet::{ChangeSet, KeychainKind, PersistedWallet, Wallet};
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{Keypair, Secp256k1};
use bitcoin::{Address, Amount, Network, OutPoint, Transaction, Txid, XOnlyPublicKey};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::{Signer, WalletConfig, WalletError, WalletResult};

/// Internal state for tracking reserved UTXOs
#[derive(Debug, Default)]
struct WalletState {
    /// UTXOs that have been reserved for pending transactions
    reserved_utxos: HashSet<OutPoint>,
}

/// Wallet manager for the Ark Service Provider
///
/// Manages BDK wallet operations including:
/// - Taproot (BIP86) address generation
/// - UTXO tracking and coin selection
/// - Transaction building and signing
/// - Blockchain synchronization via Esplora
pub struct WalletManager {
    /// Wallet configuration
    config: WalletConfig,

    /// BDK wallet instance wrapped for async access
    wallet: Arc<RwLock<PersistedWallet<FileStore<ChangeSet>>>>,

    /// Esplora client for blockchain data
    esplora: AsyncClient,

    /// Transaction signer
    signer: Signer,

    /// ASP keypair for signing
    asp_keypair: Keypair,

    /// Internal wallet state
    state: Arc<RwLock<WalletState>>,
}

impl WalletManager {
    /// Create a new wallet manager with BDK integration
    ///
    /// If no descriptor is provided, generates a new Taproot (BIP86) wallet
    /// from a mnemonic (either provided or newly generated).
    pub async fn new(config: WalletConfig) -> WalletResult<Self> {
        info!(network = ?config.network, "Initializing wallet manager");

        // Ensure database directory exists
        let db_path = PathBuf::from(&config.database_path);
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                WalletError::InitializationError(format!(
                    "Failed to create database directory: {e}"
                ))
            })?;
        }

        // Get or generate descriptors and mnemonic
        let (external_desc, internal_desc, mnemonic) = Self::get_or_create_descriptors(&config)?;

        debug!("Using external descriptor: {}", external_desc);

        // Initialize file store for persistence
        let mut db = FileStore::open_or_create_new(b"dark-wallet", &db_path).map_err(|e| {
            WalletError::InitializationError(format!("Failed to open wallet database: {e}"))
        })?;

        // Try to load existing wallet or create new one
        let wallet = match Wallet::load()
            .descriptor(KeychainKind::External, Some(external_desc.clone()))
            .descriptor(KeychainKind::Internal, Some(internal_desc.clone()))
            .extract_keys()
            .load_wallet(&mut db)
        {
            Ok(Some(wallet)) => {
                info!("Loaded existing wallet");
                wallet
            }
            Ok(None) | Err(_) => {
                info!("Creating new wallet");
                Wallet::create(external_desc.clone(), internal_desc.clone())
                    .network(config.network)
                    .create_wallet(&mut db)
                    .map_err(|e| {
                        WalletError::InitializationError(format!("Failed to create wallet: {e}"))
                    })?
            }
        };

        // Create Esplora client
        let esplora_url = config.esplora_url();
        let esplora: AsyncClient = esplora_client::Builder::new(&esplora_url)
            .build_async()
            .map_err(|e| {
                WalletError::InitializationError(format!("Failed to create Esplora client: {e}"))
            })?;

        // Generate ASP keypair from the mnemonic
        let secp = Secp256k1::new();
        let asp_keypair = Self::derive_asp_keypair(&mnemonic, config.network, &secp)?;

        info!(
            asp_pubkey = %asp_keypair.x_only_public_key().0,
            "Wallet manager initialized"
        );

        Ok(Self {
            config,
            wallet: Arc::new(RwLock::new(wallet)),
            esplora,
            signer: Signer::new(),
            asp_keypair,
            state: Arc::new(RwLock::new(WalletState::default())),
        })
    }

    /// Get or create wallet descriptors
    fn get_or_create_descriptors(
        config: &WalletConfig,
    ) -> WalletResult<(String, String, Mnemonic)> {
        // If descriptors are provided, use them
        if let (Some(ext), Some(int)) = (&config.external_descriptor, &config.internal_descriptor) {
            // We still need a mnemonic for the ASP key
            let mnemonic = if let Some(m) = &config.mnemonic {
                Mnemonic::parse_in(Language::English, m).map_err(|e| {
                    WalletError::KeyDerivationError(format!("Invalid mnemonic: {e}"))
                })?
            } else {
                // Generate a new one for ASP key only
                let generated: GeneratedKey<Mnemonic, Tap> =
                    Mnemonic::generate((WordCount::Words12, Language::English)).map_err(|e| {
                        WalletError::KeyDerivationError(format!("Mnemonic generation error: {e:?}"))
                    })?;
                generated.into_key()
            };
            return Ok((ext.clone(), int.clone(), mnemonic));
        }

        // Generate or parse mnemonic
        let mnemonic = if let Some(m) = &config.mnemonic {
            Mnemonic::parse_in(Language::English, m)
                .map_err(|e| WalletError::KeyDerivationError(format!("Invalid mnemonic: {e}")))?
        } else {
            info!("Generating new wallet mnemonic");
            let generated: GeneratedKey<Mnemonic, Tap> =
                Mnemonic::generate((WordCount::Words12, Language::English)).map_err(|e| {
                    WalletError::KeyDerivationError(format!("Mnemonic generation error: {e:?}"))
                })?;
            generated.into_key()
        };

        // Derive Taproot (BIP86) descriptors from mnemonic
        let xkey: ExtendedKey = mnemonic
            .clone()
            .into_extended_key()
            .map_err(|e| WalletError::KeyDerivationError(format!("Key derivation error: {e}")))?;

        let xpriv = xkey
            .into_xprv(config.network)
            .ok_or_else(|| WalletError::KeyDerivationError("Failed to derive xpriv".to_string()))?;

        // Generate BIP86 Taproot descriptors
        let (external_desc, _, _) = Bip86(xpriv, KeychainKind::External)
            .build(config.network)
            .map_err(|e| WalletError::InvalidDescriptor(format!("Descriptor build error: {e}")))?;

        let (internal_desc, _, _) = Bip86(xpriv, KeychainKind::Internal)
            .build(config.network)
            .map_err(|e| WalletError::InvalidDescriptor(format!("Descriptor build error: {e}")))?;

        Ok((
            external_desc.to_string(),
            internal_desc.to_string(),
            mnemonic,
        ))
    }

    /// Derive ASP keypair from mnemonic
    /// Uses a dedicated derivation path: m/86'/0'/1' (account 1 for ASP)
    fn derive_asp_keypair(
        mnemonic: &Mnemonic,
        network: Network,
        secp: &Secp256k1<bitcoin::secp256k1::All>,
    ) -> WalletResult<Keypair> {
        let xkey: ExtendedKey = mnemonic
            .clone()
            .into_extended_key()
            .map_err(|e| WalletError::KeyDerivationError(format!("Key derivation error: {e}")))?;

        let xpriv: Xpriv = xkey
            .into_xprv(network)
            .ok_or_else(|| WalletError::KeyDerivationError("Failed to derive xpriv".to_string()))?;

        // Derive ASP key at m/86'/coin'/1'/0/0
        let coin_type = match network {
            Network::Bitcoin => 0,
            _ => 1,
        };

        let path = format!("m/86'/{coin_type}'/1'/0/0");
        let derivation_path: bdk_wallet::bitcoin::bip32::DerivationPath = path
            .parse()
            .map_err(|e| WalletError::KeyDerivationError(format!("Invalid path: {e}")))?;

        let derived = xpriv.derive_priv(secp, &derivation_path).map_err(|e| {
            WalletError::KeyDerivationError(format!("ASP key derivation failed: {e}"))
        })?;

        Ok(Keypair::from_secret_key(secp, &derived.private_key))
    }

    /// Get wallet configuration
    pub fn config(&self) -> &WalletConfig {
        &self.config
    }

    /// Get the signer
    pub fn signer(&self) -> &Signer {
        &self.signer
    }

    /// Get a new receiving address
    pub async fn get_new_address(&self) -> WalletResult<Address> {
        let mut wallet = self.wallet.write().await;
        let address_info = wallet.reveal_next_address(KeychainKind::External);

        // Persist changes
        Self::persist_wallet_static(&mut wallet, &self.config.database_path)?;

        debug!(address = %address_info.address, index = address_info.index, "Generated new address");
        Ok(address_info.address)
    }

    /// Get a new change address
    pub async fn get_change_address(&self) -> WalletResult<Address> {
        let mut wallet = self.wallet.write().await;
        let address_info = wallet.reveal_next_address(KeychainKind::Internal);

        // Persist changes
        Self::persist_wallet_static(&mut wallet, &self.config.database_path)?;

        debug!(address = %address_info.address, index = address_info.index, "Generated new change address");
        Ok(address_info.address)
    }

    /// Persist wallet changes to the file store
    fn persist_wallet_static(
        wallet: &mut PersistedWallet<FileStore<ChangeSet>>,
        db_path: &str,
    ) -> WalletResult<()> {
        let mut db = FileStore::open_or_create_new(b"dark-wallet", db_path)
            .map_err(|e| WalletError::BdkError(format!("Failed to open store: {e}")))?;
        wallet
            .persist(&mut db)
            .map_err(|e| WalletError::BdkError(format!("Failed to persist wallet: {e}")))?;
        Ok(())
    }

    /// Get wallet balance
    pub async fn get_balance(&self) -> WalletResult<WalletBalance> {
        let wallet = self.wallet.read().await;
        let balance = wallet.balance();

        Ok(WalletBalance {
            immature: balance.immature,
            trusted_pending: balance.trusted_pending,
            untrusted_pending: balance.untrusted_pending,
            confirmed: balance.confirmed,
        })
    }

    /// Get available (spendable) balance
    pub async fn get_available_balance(&self, min_confirmations: u32) -> WalletResult<Amount> {
        let utxos = self.get_utxos(min_confirmations).await?;
        let total: u64 = utxos.iter().map(|u| u.amount.to_sat()).sum();
        Ok(Amount::from_sat(total))
    }

    /// Get list of unspent transaction outputs
    pub async fn get_utxos(&self, min_confirmations: u32) -> WalletResult<Vec<WalletUtxo>> {
        let wallet = self.wallet.read().await;
        let state = self.state.read().await;
        let current_height = wallet.latest_checkpoint().height();

        let utxos = wallet
            .list_unspent()
            .filter_map(|utxo| {
                let confirmations = utxo
                    .chain_position
                    .confirmation_height_upper_bound()
                    .map(|h| current_height.saturating_sub(h) + 1)
                    .unwrap_or(0);

                if confirmations >= min_confirmations {
                    Some(WalletUtxo {
                        outpoint: utxo.outpoint,
                        amount: utxo.txout.value,
                        confirmations,
                        reserved: state.reserved_utxos.contains(&utxo.outpoint),
                    })
                } else {
                    None
                }
            })
            .collect();

        Ok(utxos)
    }

    /// Reserve a UTXO for use in a transaction
    pub async fn reserve_utxo(&self, outpoint: OutPoint) -> WalletResult<()> {
        let mut state = self.state.write().await;
        if state.reserved_utxos.insert(outpoint) {
            debug!(?outpoint, "Reserved UTXO");
            Ok(())
        } else {
            warn!(?outpoint, "UTXO already reserved");
            Ok(())
        }
    }

    /// Release a reserved UTXO
    pub async fn release_utxo(&self, outpoint: OutPoint) -> WalletResult<()> {
        let mut state = self.state.write().await;
        state.reserved_utxos.remove(&outpoint);
        debug!(?outpoint, "Released UTXO");
        Ok(())
    }

    /// Get unreserved UTXOs for coin selection
    pub async fn get_unreserved_utxos(
        &self,
        min_confirmations: u32,
    ) -> WalletResult<Vec<WalletUtxo>> {
        let utxos = self.get_utxos(min_confirmations).await?;
        Ok(utxos.into_iter().filter(|u| !u.reserved).collect())
    }

    /// Sign a PSBT with the wallet's keys
    pub async fn sign_psbt(&self, psbt: &mut Psbt) -> WalletResult<bool> {
        let wallet = self.wallet.write().await;

        let finalized = wallet
            .sign(psbt, bdk_wallet::SignOptions::default())
            .map_err(|e| WalletError::SigningError(format!("Failed to sign PSBT: {e}")))?;

        debug!(finalized, "Signed PSBT");
        Ok(finalized)
    }

    /// Sign a message with the ASP key
    pub fn sign_message(
        &self,
        message: &[u8; 32],
    ) -> WalletResult<bitcoin::secp256k1::schnorr::Signature> {
        self.signer.sign_schnorr(message, &self.asp_keypair)
    }

    /// Get the ASP's x-only public key (for Taproot)
    pub fn asp_pubkey(&self) -> XOnlyPublicKey {
        self.asp_keypair.x_only_public_key().0
    }

    /// Broadcast a transaction via Esplora
    pub async fn broadcast_transaction(&self, tx: &Transaction) -> WalletResult<Txid> {
        let txid = tx.compute_txid();
        debug!(?txid, "Broadcasting transaction");

        self.esplora.broadcast(tx).await.map_err(|e| {
            WalletError::BroadcastError(format!("Failed to broadcast transaction: {e}"))
        })?;

        info!(?txid, "Transaction broadcast successfully");
        Ok(txid)
    }

    /// Sync wallet with the blockchain via Esplora
    pub async fn sync(&self) -> WalletResult<SyncResult> {
        info!("Starting wallet sync");

        let mut wallet = self.wallet.write().await;

        // Build sync request
        let request = wallet.start_full_scan().inspect({
            let mut once = HashSet::<KeychainKind>::new();
            move |k, spk_i, _| {
                if once.insert(k) {
                    debug!(keychain = ?k, spk_index = spk_i, "Scanning");
                }
            }
        });

        // Execute sync
        let update = self
            .esplora
            .full_scan(request, self.config.stop_gap, self.config.parallel_requests)
            .await
            .map_err(|e| WalletError::SyncError(format!("Sync failed: {e}")))?;

        // Apply update to wallet
        wallet
            .apply_update(update)
            .map_err(|e| WalletError::SyncError(format!("Failed to apply sync update: {e}")))?;

        // Persist changes
        Self::persist_wallet_static(&mut wallet, &self.config.database_path)?;

        let balance = wallet.balance();
        let utxo_count = wallet.list_unspent().count();

        info!(
            confirmed_sats = balance.confirmed.to_sat(),
            pending_sats = balance.trusted_pending.to_sat() + balance.untrusted_pending.to_sat(),
            utxo_count,
            "Wallet sync complete"
        );

        Ok(SyncResult {
            balance: WalletBalance {
                immature: balance.immature,
                trusted_pending: balance.trusted_pending,
                untrusted_pending: balance.untrusted_pending,
                confirmed: balance.confirmed,
            },
            utxo_count,
        })
    }

    /// Get a transaction from the wallet's transaction graph
    pub async fn get_transaction(&self, txid: Txid) -> WalletResult<Option<Transaction>> {
        let wallet = self.wallet.read().await;
        Ok(wallet.get_tx(txid).map(|tx| tx.tx_node.tx.as_ref().clone()))
    }

    /// Get the current block height from wallet's chain tip
    pub async fn current_height(&self) -> u32 {
        let wallet = self.wallet.read().await;
        wallet.latest_checkpoint().height()
    }
}

/// Wallet balance breakdown
#[derive(Debug, Clone, Copy)]
pub struct WalletBalance {
    /// Immature coinbase rewards
    pub immature: Amount,
    /// Trusted pending (our change)
    pub trusted_pending: Amount,
    /// Untrusted pending (incoming, unconfirmed)
    pub untrusted_pending: Amount,
    /// Confirmed balance
    pub confirmed: Amount,
}

impl WalletBalance {
    /// Total balance (confirmed + trusted pending)
    pub fn total(&self) -> Amount {
        self.confirmed + self.trusted_pending
    }

    /// Spendable balance (confirmed only)
    pub fn spendable(&self) -> Amount {
        self.confirmed
    }
}

/// A UTXO owned by the wallet
#[derive(Debug, Clone)]
pub struct WalletUtxo {
    /// The outpoint (txid:vout)
    pub outpoint: OutPoint,
    /// Amount in satoshis
    pub amount: Amount,
    /// Number of confirmations
    pub confirmations: u32,
    /// Whether this UTXO is reserved for pending use
    pub reserved: bool,
}

/// Result of a wallet sync operation
#[derive(Debug)]
pub struct SyncResult {
    /// Updated balance
    pub balance: WalletBalance,
    /// Number of UTXOs
    pub utxo_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_balance_calculations() {
        let balance = WalletBalance {
            immature: Amount::from_sat(0),
            trusted_pending: Amount::from_sat(1000),
            untrusted_pending: Amount::from_sat(500),
            confirmed: Amount::from_sat(10000),
        };

        assert_eq!(balance.total().to_sat(), 11000);
        assert_eq!(balance.spendable().to_sat(), 10000);
    }

    #[tokio::test]
    async fn test_wallet_manager_creation_with_mnemonic() {
        let config = WalletConfig::regtest("/tmp/dark-wallet-test").with_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        );

        // This test verifies the config is valid
        // Full wallet creation requires file system access
        assert_eq!(config.network, Network::Regtest);
        assert!(config.mnemonic.is_some());
    }
}
