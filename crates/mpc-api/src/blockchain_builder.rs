//! # Blockchain Adapter Registry
//!
//! This module defines the `Chain` enumeration and the `BlockchainRegistry`, which acts 
//! as a dependency injection container for chain-specific transaction builders.
//!
//! ## Architecture
//! The API Gateway interacts with multiple blockchains through a unified interface 
//! (`BlockchainAdapter`). The `BlockchainRegistry` maps a `Chain` enum variant to its 
//! corresponding trait object (`Arc<dyn BlockchainAdapter>`), allowing the gateway to 
//! route signing requests to the correct implementation without hardcoding chain-specific 
//! logic in the HTTP handlers.

pub use adapter_core::traits::BlockchainAdapter; // Re-export the async trait

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use serde::{Deserialize, Serialize};

/// Represents the supported blockchain networks in the MPC-RS ecosystem.
///
/// This enum is used to route requests to the correct adapter implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Chain {
    /// Bitcoin and Bitcoin-compatible networks (e.g., Regtest, Testnet).
    Bitcoin,
    /// Ethereum and EVM-compatible networks.
    Ethereum,
    /// Solana network.
    Solana,
    /// XRP Ledger (XRPL).
    Xrp,
    /// Tron network.
    Tron,
}

impl FromStr for Chain {
    type Err = String;

    /// Parses a string into a `Chain` variant.
    ///
    /// # Arguments
    ///
    /// * `s` - The string to parse (case-insensitive). Supports common aliases 
    ///   (e.g., "btc" for Bitcoin, "eth" for Ethereum, "trx" for Tron).
    ///
    /// # Returns
    ///
    /// The corresponding `Chain` variant.
    ///
    /// # Errors
    ///
    /// Returns a `String` error if the input does not match any supported chain.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "bitcoin" | "btc" => Ok(Chain::Bitcoin),
            "ethereum" | "eth" => Ok(Chain::Ethereum),
            "solana" | "sol" => Ok(Chain::Solana),
            "xrp" => Ok(Chain::Xrp),
            "tron" | "trx" => Ok(Chain::Tron),
            _ => Err(format!("unknown chain: {s}")),
        }
    }
}

/// A thread-safe registry that maps `Chain` variants to their respective 
/// `BlockchainAdapter` implementations.
///
/// This registry is initialized at startup and shared across all API request 
/// handlers via Axum's `State` extractor.
#[derive(Clone)]
pub struct BlockchainRegistry {
    adapters: HashMap<Chain, Arc<dyn BlockchainAdapter>>,
}

impl BlockchainRegistry {
    /// Creates a new, empty `BlockchainRegistry`.
    pub fn new() -> Self { 
        Self { adapters: HashMap::new() } 
    }

    /// Registers a new adapter for a specific chain.
    ///
    /// # Arguments
    ///
    /// * `chain` - The `Chain` variant to associate with the adapter.
    /// * `adapter` - The `Arc`-wrapped adapter implementation.
    pub fn register(&mut self, chain: Chain, adapter: Arc<dyn BlockchainAdapter>) {
        self.adapters.insert(chain, adapter);
    }

    /// Retrieves the adapter for a specific chain.
    ///
    /// # Arguments
    ///
    /// * `chain` - The `Chain` variant to look up.
    ///
    /// # Returns
    ///
    /// An `Option` containing a cloned `Arc` of the adapter, or `None` if the 
    /// chain is not registered.
    pub fn get(&self, chain: Chain) -> Option<Arc<dyn BlockchainAdapter>> {
        self.adapters.get(&chain).cloned()
    }
}

