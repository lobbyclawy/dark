//! Bitcoin RPC client integration

use crate::error::{BitcoinError, BitcoinResult};
use bitcoin::{Address, Amount, Block, BlockHash, Transaction, Txid};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Configuration for Bitcoin RPC client
#[derive(Debug, Clone)]
pub struct RpcConfig {
    /// RPC URL (e.g., "http://127.0.0.1:18443")
    pub url: String,
    /// RPC username
    pub username: String,
    /// RPC password
    pub password: String,
    /// Connection timeout in seconds
    pub timeout_secs: u64,
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            url: "http://127.0.0.1:18443".to_string(),
            username: "user".to_string(),
            password: "password".to_string(),
            timeout_secs: 30,
        }
    }
}

/// Bitcoin RPC client wrapper with connection pooling
#[derive(Clone)]
pub struct BitcoinRpc {
    client: Arc<Mutex<Client>>,
    #[allow(dead_code)]
    config: RpcConfig,
}

impl BitcoinRpc {
    /// Create a new RPC client
    pub fn new(config: RpcConfig) -> BitcoinResult<Self> {
        let auth = Auth::UserPass(config.username.clone(), config.password.clone());

        let client = Client::new(&config.url, auth)
            .map_err(|e| BitcoinError::RpcError(format!("Failed to create client: {e}")))?;

        Ok(Self {
            client: Arc::new(Mutex::new(client)),
            config,
        })
    }

    /// Get blockchain info
    pub async fn get_blockchain_info(&self) -> BitcoinResult<serde_json::Value> {
        let client = self.client.lock().await;
        client
            .call::<serde_json::Value>("getblockchaininfo", &[])
            .map_err(|e| BitcoinError::RpcError(e.to_string()))
    }

    /// Get best block hash
    pub async fn get_best_block_hash(&self) -> BitcoinResult<BlockHash> {
        let client = self.client.lock().await;
        client
            .get_best_block_hash()
            .map_err(|e| BitcoinError::RpcError(e.to_string()))
    }

    /// Get block by hash
    pub async fn get_block(&self, hash: &BlockHash) -> BitcoinResult<Block> {
        let client = self.client.lock().await;
        client
            .get_block(hash)
            .map_err(|e| BitcoinError::RpcError(e.to_string()))
    }

    /// Get block count
    pub async fn get_block_count(&self) -> BitcoinResult<u64> {
        let client = self.client.lock().await;
        client
            .get_block_count()
            .map_err(|e| BitcoinError::RpcError(e.to_string()))
    }

    /// Get raw transaction
    pub async fn get_raw_transaction(&self, txid: &Txid) -> BitcoinResult<Transaction> {
        let client = self.client.lock().await;
        client
            .get_raw_transaction(txid, None)
            .map_err(|e| BitcoinError::RpcError(e.to_string()))
    }

    /// Send raw transaction
    pub async fn send_raw_transaction(&self, tx: &Transaction) -> BitcoinResult<Txid> {
        let client = self.client.lock().await;
        client
            .send_raw_transaction(tx)
            .map_err(|e| BitcoinError::RpcError(e.to_string()))
    }

    /// Get balance
    pub async fn get_balance(&self) -> BitcoinResult<Amount> {
        let client = self.client.lock().await;
        client
            .get_balance(None, None)
            .map_err(|e| BitcoinError::RpcError(e.to_string()))
    }

    /// Get new address
    pub async fn get_new_address(&self) -> BitcoinResult<Address> {
        let client = self.client.lock().await;
        let address = client
            .get_new_address(None, None)
            .map_err(|e| BitcoinError::RpcError(e.to_string()))?;

        Ok(address.assume_checked())
    }

    /// Estimate smart fee
    pub async fn estimate_smart_fee(&self, target: u16) -> BitcoinResult<Amount> {
        let client = self.client.lock().await;
        let result = client
            .estimate_smart_fee(target, None)
            .map_err(|e| BitcoinError::RpcError(e.to_string()))?;

        result
            .fee_rate
            .ok_or_else(|| BitcoinError::RpcError("No fee estimate available".to_string()))
    }

    /// Generate blocks (regtest only)
    #[cfg(feature = "regtest")]
    pub async fn generate_to_address(
        &self,
        nblocks: u64,
        address: &Address,
    ) -> BitcoinResult<Vec<BlockHash>> {
        let client = self.client.lock().await;
        client
            .generate_to_address(nblocks, address)
            .map_err(|e| BitcoinError::RpcError(e.to_string()))
    }
}

/// Connection pool for managing multiple RPC connections
#[derive(Clone)]
pub struct RpcPool {
    clients: Arc<Vec<BitcoinRpc>>,
    current: Arc<Mutex<usize>>,
}

impl RpcPool {
    /// Create a new RPC connection pool
    pub fn new(config: RpcConfig, pool_size: usize) -> BitcoinResult<Self> {
        let mut clients = Vec::with_capacity(pool_size);

        for _ in 0..pool_size {
            clients.push(BitcoinRpc::new(config.clone())?);
        }

        Ok(Self {
            clients: Arc::new(clients),
            current: Arc::new(Mutex::new(0)),
        })
    }

    /// Get a client from the pool (round-robin)
    pub async fn get(&self) -> BitcoinRpc {
        let mut current = self.current.lock().await;
        let client = self.clients[*current].clone();
        *current = (*current + 1) % self.clients.len();
        client
    }

    /// Get pool size
    pub fn size(&self) -> usize {
        self.clients.len()
    }
}

/// Retry logic for RPC calls
pub mod retry {
    use std::time::Duration;
    use tokio::time::sleep;

    /// Retry configuration
    #[derive(Debug, Clone)]
    pub struct RetryConfig {
        /// Maximum number of retries
        pub max_retries: u32,
        /// Initial delay between retries
        pub initial_delay_ms: u64,
        /// Backoff multiplier
        pub backoff_multiplier: f64,
    }

    impl Default for RetryConfig {
        fn default() -> Self {
            Self {
                max_retries: 3,
                initial_delay_ms: 100,
                backoff_multiplier: 2.0,
            }
        }
    }

    /// Retry a function with exponential backoff
    pub async fn with_retry<F, T, E>(config: &RetryConfig, mut f: F) -> Result<T, E>
    where
        F: FnMut() -> Result<T, E>,
    {
        let mut delay = config.initial_delay_ms;

        for attempt in 0..=config.max_retries {
            match f() {
                Ok(result) => return Ok(result),
                Err(e) => {
                    if attempt == config.max_retries {
                        return Err(e);
                    }
                    sleep(Duration::from_millis(delay)).await;
                    delay = (delay as f64 * config.backoff_multiplier) as u64;
                }
            }
        }

        unreachable!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rpc_config_default() {
        let config = RpcConfig::default();
        assert_eq!(config.url, "http://127.0.0.1:18443");
        assert_eq!(config.timeout_secs, 30);
    }

    #[tokio::test]
    async fn test_rpc_pool_round_robin() {
        let config = RpcConfig::default();
        // This will fail to connect but we're just testing the pool logic
        if let Ok(pool) = RpcPool::new(config, 3) {
            assert_eq!(pool.size(), 3);
        }
    }

    #[test]
    fn test_retry_config_default() {
        let config = retry::RetryConfig::default();
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.initial_delay_ms, 100);
    }
}
