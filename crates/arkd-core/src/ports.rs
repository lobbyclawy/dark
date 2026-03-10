//! Ports - External interfaces for dependency inversion
//!
//! Following hexagonal architecture, these traits define
//! the contracts that external adapters must implement.

use async_trait::async_trait;

/// Wallet service interface for Bitcoin operations
#[async_trait]
pub trait WalletService: Send + Sync {
    // TODO: Add wallet methods
}

/// Database service interface for persistence
#[async_trait]
pub trait DatabaseService: Send + Sync {
    // TODO: Add database methods
}

/// API service interface for external communication
#[async_trait]
pub trait ApiService: Send + Sync {
    // TODO: Add API methods
}
