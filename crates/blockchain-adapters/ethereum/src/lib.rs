//! # Ethereum Blockchain Adapter
//!
//! This crate provides a production-grade implementation of the [`BlockchainAdapter`] 
//! trait for Ethereum and EVM-compatible chains. It handles the complete lifecycle 
//! of an Ethereum transaction, from state fetching (nonces, gas estimation) to 
//! EIP-1559 transaction construction, MPC signature attachment, and network broadcasting.
//!
//! ## Architecture
//! The `EthereumAdapter` is designed to be generic over its `EthStateProvider` 
//! dependency. This allows the adapter to seamlessly integrate with different backend 
//! services (e.g., a public RPC provider for mainnet, or a local Anvil node for testing) 
//! without modifying the core transaction-building logic.

pub mod eip1559;
pub mod contract;
pub mod types;
pub mod rpc_provider;

use adapter_core::traits::BlockchainAdapter;
use adapter_core::error::AdapterError;
use async_trait::async_trait;
use eip1559::{build_eip1559_tx, attach_signature_to_tx};
use contract::{build_erc20_transfer, encode_erc20_transfer_calldata};

use alloy_primitives::{Address, U256, Bytes};
use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::Mutex;

/// Represents the current EIP-1559 gas market conditions.
pub struct GasPrices {
    /// The maximum total fee per gas the sender is willing to pay (Base Fee + Priority Fee).
    pub max_fee_per_gas: u128,
    /// The maximum tip to the block producer (Priority Fee).
    pub max_priority_fee_per_gas: u128,
}

/// A trait for fetching real-time blockchain state required for transaction construction.
///
/// This trait abstracts away the underlying JSON-RPC calls, allowing the adapter to 
/// be tested with mock implementations and deployed with different RPC providers.
#[allow(clippy::double_must_use)] // Suppresses false positive from async_trait macro expansion
#[async_trait]
pub trait EthStateProvider: Send + Sync {
    /// Fetches the next available nonce for an address, including pending transactions.
    async fn get_pending_nonce(&self, address: Address) -> Result<u64, AdapterError>;
    
    /// Estimates the current EIP-1559 gas prices (max fee and priority fee).
    async fn estimate_gas_prices(&self) -> Result<GasPrices, AdapterError>;
    
    /// Estimates the gas limit required to execute a specific transaction.
    async fn estimate_gas(
        &self, 
        from: Address, 
        to: Option<Address>, 
        value: U256, 
        data: Bytes
    ) -> Result<u64, AdapterError>;
    
    /// Fetches the current balance of an address.
    async fn get_balance(&self, address: Address) -> Result<U256, AdapterError>; 
}

/// The core Ethereum adapter implementing the [`BlockchainAdapter`] trait.
///
/// This struct manages transaction construction, nonce reservation, and network 
/// interaction for EVM-compatible chains.
pub struct EthereumAdapter {
    /// The EIP-155 chain ID (e.g., 1 for Mainnet, 31337 for Anvil).
    pub chain_id: u64,
    /// The JSON-RPC endpoint URL used for broadcasting finalized transactions.
    pub rpc_url: String,
    /// The injected state provider for fetching nonces, balances, and gas estimates.
    pub state_provider: Arc<dyn EthStateProvider>,
    /// A local cache to prevent nonce collisions when building multiple concurrent 
    /// transactions for the same address before they are mined.
    pub nonce_cache: Arc<Mutex<HashMap<Address, u64>>>,
}

impl EthereumAdapter {
    /// Creates a new `EthereumAdapter` with the specified configuration.
    ///
    /// # Arguments
    ///
    /// * `chain_id` - The EIP-155 chain ID.
    /// * `rpc_url` - The JSON-RPC endpoint URL.
    /// * `state_provider` - An implementation of [`EthStateProvider`].
    pub fn new(chain_id: u64, rpc_url: String, state_provider: Arc<dyn EthStateProvider>) -> Self {
        Self { 
            chain_id,
            rpc_url,
            state_provider,
            nonce_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    
    /// Reserves a nonce for a given address, preventing concurrent transaction collisions.
    ///
    /// # Note
    ///
    /// In a high-throughput custody system, multiple withdrawal requests for the same 
    /// vault may be processed concurrently. This method checks the network's pending 
    /// nonce and compares it with the local cache, returning the maximum of the two 
    /// and incrementing the cache. This guarantees that each concurrently built 
    /// transaction receives a unique, monotonically increasing nonce.
    async fn reserve_nonce(&self, address: Address) -> Result<u64, AdapterError> {
        let network_nonce = self.state_provider.get_pending_nonce(address).await?;
        let mut cache = self.nonce_cache.lock().await;
        let local_nonce = cache.get(&address).copied().unwrap_or(network_nonce);
        let reserved = std::cmp::max(local_nonce, network_nonce);
        
        // Use saturating_add to satisfy arithmetic_side_effects
        cache.insert(address, reserved.saturating_add(1));
        
        // Explicitly drop the lock to satisfy significant_drop_tightening
        drop(cache); 
        Ok(reserved)
    }
}

#[allow(clippy::double_must_use)] // Suppresses false positive from async_trait macro expansion
#[async_trait]
impl BlockchainAdapter for EthereumAdapter {
    /// Constructs an unsigned EIP-1559 transaction (native ETH or ERC-20).
    ///
    /// # Arguments
    ///
    /// * `from` - The source address (the MPC vault).
    /// * `to` - The destination address.
    /// * `amount` - The amount to transfer (e.g., "1.5" or "all").
    /// * `token` - An optional ERC-20 contract address. If `Some`, an ERC-20 transfer is built.
    /// * `_change_address` - Ignored for Ethereum (account-based model).
    /// * `_previous_tx_hex` - Ignored for Ethereum (account-based model).
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// 1. The unsigned EIP-1559 transaction serialized as EIP-2718 typed RLP bytes.
    /// 2. The 32-byte EIP-1559 signature hash (sighash) for MPC signing.
    #[allow(clippy::arithmetic_side_effects)] // U256 arithmetic wraps on overflow and does not panic
    async fn build_unsigned_tx(
        &self,
        from: &str,
        to: &str,
        amount: &str,
        token: Option<&str>,
        _change_address: Option<&str>,
        _previous_tx_hex: Option<&str>,
    ) -> Result<(Vec<u8>, [u8; 32]), AdapterError> {
        
        let from_addr = from.parse::<Address>()
            .map_err(|e| AdapterError::InvalidAddress(e.to_string()))?;
        
        let gas_prices = self.state_provider.estimate_gas_prices().await?;
        let nonce = self.reserve_nonce(from_addr).await?;

        if let Some(contract) = token {
            // --- ERC-20 Transfer Path ---
            let contract_addr = contract.parse::<Address>()
                .map_err(|e| AdapterError::InvalidAddress(e.to_string()))?;
            let to_addr = to.parse::<Address>()
                .map_err(|e| AdapterError::InvalidAddress(e.to_string()))?;
            let value = amount.parse::<U256>()
                .map_err(|e| AdapterError::InvalidAmount(e.to_string()))?;
                
            let data = encode_erc20_transfer_calldata(to_addr, value);
            let gas_limit = self.state_provider.estimate_gas(
                from_addr, 
                Some(contract_addr), 
                U256::ZERO, 
                data.clone()
            ).await?;
            
            build_erc20_transfer(
                contract_addr, to_addr, value, nonce, gas_limit,
                gas_prices.max_fee_per_gas, gas_prices.max_priority_fee_per_gas, self.chain_id
            )
        } else {
            // --- Native ETH Transfer Path ---
            let to_addr = to.parse::<Address>()
                .map_err(|e| AdapterError::InvalidAddress(e.to_string()))?;

            let balance = self.state_provider.get_balance(from_addr).await?;
            let gas_limit = self.state_provider.estimate_gas(
                from_addr, Some(to_addr), U256::ZERO, Bytes::new()
            ).await?;

            let max_gas_cost = U256::from(gas_limit) * U256::from(gas_prices.max_fee_per_gas);
            
            // Apply a 50% buffer to the gas cost deduction.
            // This guarantees that even if the transaction builder or RPC applies a standard 
            // 20% gas limit safety buffer internally, the transaction value will still be low 
            // enough to cover the maximum possible gas cost without triggering an 
            // "Insufficient funds for gas * price + value" error.
            let safe_gas_cost = max_gas_cost * U256::from(150) / U256::from(100);

            let value = if amount == "all" {
                if balance <= safe_gas_cost {
                    return Err(AdapterError::InvalidAmount("insufficient funds to cover gas".into()));
                }
                balance - safe_gas_cost
            } else {
                let requested = amount.parse::<U256>()
                    .map_err(|e| AdapterError::InvalidAmount(e.to_string()))?;
                
                if requested >= balance {
                    if balance <= safe_gas_cost {
                        return Err(AdapterError::InvalidAmount("insufficient funds to cover gas".into()));
                    }
                    balance - safe_gas_cost
                } else {
                    requested
                }
            };
           
            tracing::info!("🔍 ETHEREUM ADAPTER DEBUG: amount={}, balance={}, safe_gas_cost={}, final_value={}", 
                amount, balance, safe_gas_cost, value);

            build_eip1559_tx(
                to_addr, value, Bytes::new(), nonce, gas_limit,
                gas_prices.max_fee_per_gas, gas_prices.max_priority_fee_per_gas, self.chain_id
            )
        }
    }

    /// Broadcasts a finalized, signed transaction to the Ethereum network via JSON-RPC.
    ///
    /// # Arguments
    ///
    /// * `finalized_tx` - The EIP-2718 encoded signed transaction bytes.
    ///
    /// # Returns
    ///
    /// The transaction hash (TXID) as a hex string upon successful broadcast.
    async fn broadcast(&self, finalized_tx: &[u8]) -> Result<String, AdapterError> {
        let raw_tx_hex = format!("0x{}", hex::encode(finalized_tx));
        let payload = serde_json::json!({
            "jsonrpc": "2.0", "method": "eth_sendRawTransaction",
            "params": [raw_tx_hex], "id": 1
        });

        let client = reqwest::Client::new();
        let res = client.post(&self.rpc_url).json(&payload).send().await
            .map_err(|e| AdapterError::Internal(format!("ETH RPC failed: {e}")))?;
            
        let body: serde_json::Value = res.json().await.map_err(|e| AdapterError::Internal(e.to_string()))?;
        
        // Safe indexing with .get() and idiomatic Option handling with map_or_else
        body.get("result")
            .and_then(|v| v.as_str())
            .map_or_else(
                || {
                    let err_msg = body.get("error").map_or_else(|| "Unknown error".to_string(), ToString::to_string);
                    Err(AdapterError::Internal(format!("ETH broadcast error: {err_msg}")))
                },
                |tx_hash| Ok(tx_hash.to_string()),
            )
    }

    /// Attaches an MPC-generated signature to an unsigned EIP-1559 transaction.
    ///
    /// # Arguments
    ///
    /// * `unsigned_tx` - The EIP-2718 encoded unsigned transaction bytes.
    /// * `signature` - The 65-byte raw signature (r, s, v) produced by the MPC nodes.
    /// * `_pubkey_hex` - Ignored for Ethereum, as the signature recovery ID (v) is sufficient 
    ///   to derive the signer's address during verification.
    ///
    /// # Returns
    ///
    /// The fully signed, EIP-2718 encoded transaction bytes ready for broadcast.
    async fn attach_signature(
        &self,
        unsigned_tx: &[u8],
        signature: &[u8],
        _pubkey_hex: &str,
    ) -> Result<Vec<u8>, AdapterError> {
        attach_signature_to_tx(unsigned_tx, signature)
    }

    /// Derives an Ethereum address from a raw secp256k1 public key.
    ///
    /// # Arguments
    ///
    /// * `pubkey` - The raw, compressed or uncompressed secp256k1 public key bytes.
    ///
    /// # Returns
    ///
    /// The 20-byte Ethereum address as a lowercase hex string (without the "0x" prefix).
    #[allow(clippy::indexing_slicing)] // Lengths are mathematically guaranteed by crypto primitives
    fn derive_address(&self, pubkey: &[u8]) -> Result<String, AdapterError> {
        use k256::ecdsa::VerifyingKey;
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        use alloy_primitives::utils::keccak256;

        let vk = VerifyingKey::from_sec1_bytes(pubkey)
            .map_err(|e| AdapterError::InvalidAddress(format!("Invalid pubkey: {e}")))?;
        
        // Uncompressed secp256k1 is always 65 bytes (0x04 prefix + 32 bytes X + 32 bytes Y)
        let uncompressed = vk.to_encoded_point(false);
        let hash = keccak256(&uncompressed.as_bytes()[1..]);
        
        // Keccak256 always returns exactly 32 bytes
        let address = &hash[12..];
        
        Ok(hex::encode(address))
    }
}

