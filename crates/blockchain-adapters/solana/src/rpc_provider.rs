//! # Solana RPC State Provider
//!
//! This module provides a standard JSON-RPC implementation of the 
//! [`SolanaStateProvider`](crate::SolanaStateProvider) trait.
//!
//! It communicates with Solana RPC nodes (e.g., Helius, `QuickNode`, or a local 
//! `solana-test-validator`) to fetch real-time state required for transaction 
//! construction, such as recent blockhashes, token mint decimals, and account balances.

use adapter_core::error::AdapterError;
use async_trait::async_trait;
use crate::SolanaStateProvider;
use solana_sdk::hash::Hash;
use solana_sdk::pubkey::Pubkey;
use std::str::FromStr;
use base64::{Engine as _, engine::general_purpose::STANDARD};

/// A JSON-RPC based implementation of [`SolanaStateProvider`].
pub struct RpcSolanaStateProvider {
    client: reqwest::Client,
    rpc_url: String,
}

impl RpcSolanaStateProvider {
    /// Creates a new `RpcSolanaStateProvider` with a default HTTP client.
    ///
    /// # Arguments
    ///
    /// * `rpc_url` - The Solana JSON-RPC endpoint URL (e.g., `https://api.mainnet-beta.solana.com`).
    #[must_use]
    pub fn new(rpc_url: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            rpc_url,
        }
    }
    
    /// Executes a generic JSON-RPC call and parses the response.
    ///
    /// # Arguments
    ///
    /// * `method` - The RPC method name (e.g., `"getLatestBlockhash"`).
    /// * `params` - The method parameters as a JSON array.
    ///
    /// # Returns
    ///
    /// The `result` field of the JSON-RPC response.
    ///
    /// # Errors
    ///
    /// Returns an [`AdapterError::Internal`] if the network request fails, the response 
    /// cannot be parsed as JSON, or the RPC node returns an error object.
    async fn rpc_call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value, AdapterError> {
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1
        });
        
        let res = self.client.post(&self.rpc_url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| AdapterError::Internal(format!("Solana RPC request failed: {e}")))?
            .json::<serde_json::Value>()
            .await
            .map_err(|e| AdapterError::Internal(format!("Solana RPC parse failed: {e}")))?;
            
        if let Some(err) = res.get("error") {
            return Err(AdapterError::Internal(format!("Solana RPC error: {err}")));
        }
        
        res.get("result")
            .cloned()
            .ok_or_else(|| AdapterError::Internal("Missing result in Solana RPC response".into()))
    }
}

#[async_trait]
impl SolanaStateProvider for RpcSolanaStateProvider {
    /// Fetches the latest blockhash from the cluster.
    ///
    /// # Note
    ///
    /// Uses the `"finalized"` commitment level to ensure the blockhash is deeply 
    /// confirmed and will not be reverted due to a chain reorganization. This is 
    /// critical for institutional custody systems to prevent transaction failures 
    /// caused by using a blockhash from an orphaned block.
    async fn get_latest_blockhash(&self) -> Result<Hash, AdapterError> {
        let params = serde_json::json!([{"commitment": "finalized"}]);
        let res = self.rpc_call("getLatestBlockhash", params).await?;
        
        let blockhash_str = res.get("value")
            .and_then(|v| v.get("blockhash"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| AdapterError::Internal("Missing blockhash string in RPC response".into()))?;
            
        Hash::from_str(blockhash_str)
            .map_err(|e| AdapterError::Internal(format!("Invalid blockhash format: {e}")))
    }

    /// Fetches the decimal precision of a given SPL Token mint.
    ///
    /// # Note
    ///
    /// Instead of relying on higher-level RPC methods, this function directly fetches 
    /// the raw account data and parses the 45th byte (0-indexed), which corresponds 
    /// to the `decimals` field in the standard 82-byte SPL Token Mint layout. This 
    /// approach is highly reliable, avoids rate limits on specialized endpoints, and 
    /// works universally across all Solana RPC providers.
    ///
    /// # Arguments
    ///
    /// * `mint` - The public key of the SPL Token mint.
    ///
    /// # Returns
    ///
    /// The number of decimals (e.g., `6` for USDC, `9` for SOL).
    ///
    /// # Errors
    ///
    /// Returns an [`AdapterError::Internal`] if the mint account does not exist, 
    /// the account data is missing or too short, or Base64 decoding fails.
    async fn get_token_decimals(&self, mint: &Pubkey) -> Result<u8, AdapterError> {
        let mint_str = mint.to_string();
        let params = serde_json::json!([mint_str, {"encoding": "base64", "commitment": "finalized"}]);
        let res = self.rpc_call("getAccountInfo", params).await?;
        
        // Handle the case where the mint account does not exist
        if res.get("value").is_none_or(serde_json::Value::is_null) {
            return Err(AdapterError::Internal(format!("Mint account {mint_str} does not exist")));
        }

        let data_array = res.get("value")
            .and_then(|v| v.get("data"))
            .and_then(|v| v.as_array())
            .ok_or_else(|| AdapterError::Internal("Missing account data array in RPC response".into()))?;
            
        let data_b64 = data_array.first()
            .and_then(|v| v.as_str())
            .ok_or_else(|| AdapterError::Internal("Missing account data string in RPC response".into()))?;
            
        let data_bytes = STANDARD.decode(data_b64)
            .map_err(|e| AdapterError::Internal(format!("Base64 decode failed: {e}")))?;
            
        // SPL Token Mint layout (82 bytes total):
        // 0..36: mint_authority (COption<Pubkey>)
        // 36..44: supply (u64, little-endian)
        // 44..45: decimals (u8)  <--- We only need this byte!
        if data_bytes.len() < 45 {
            return Err(AdapterError::Internal("Account data too short to be a valid SPL Token Mint".into()));
        }
        
        Ok(data_bytes.get(44).copied().unwrap_or(0))
    }

    /// Fetches the current SOL balance (in lamports) of a given address.
    ///
    /// # Arguments
    ///
    /// * `address` - The Solana public key to query.
    ///
    /// # Returns
    ///
    /// The balance in lamports (1 SOL = 1,000,000,000 lamports).
    ///
    /// # Errors
    ///
    /// Returns an [`AdapterError::Internal`] if the RPC response is malformed or 
    /// missing the balance value.
    async fn get_balance(&self, address: &Pubkey) -> Result<u64, AdapterError> {
        let params = serde_json::json!([address.to_string(), {"commitment": "finalized"}]);
        let res = self.rpc_call("getBalance", params).await?;
        
        res.get("value")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| AdapterError::Internal("Missing balance".into()))
    }
}