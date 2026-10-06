//! # Adapter Core
//!
//! This crate defines the foundational traits, types, and error handling for 
//! blockchain adapters within the MPC-RS ecosystem.
//!
//! ## Architecture
//! In MPC-RS, the API Gateway and Coordinator interact with different blockchains 
//! (Bitcoin, Ethereum, Solana, XRP, etc.) through a unified interface. This crate provides 
//! the `BlockchainAdapter` trait, which abstracts away chain-specific logic such as 
//! transaction building, signature attachment, and network broadcasting.
//!
//! By implementing these traits, individual adapter crates (e.g., `bitcoin-adapter`, 
//! `ethereum-adapter`) can be seamlessly registered into the `BlockchainRegistry`, 
//! allowing the core MPC system to remain completely agnostic to the underlying 
//! blockchain mechanics.

pub mod error;
pub mod traits;
pub mod types;

// Re-export the most commonly used items for ergonomic access by adapter implementations
// and the higher-level API/Coordinator crates.
pub use traits::{AdapterResult, BlockchainAdapter, FeeEstimator, UtxoProvider};
pub use types::Utxo;
