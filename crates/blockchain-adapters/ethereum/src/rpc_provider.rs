//! # Ethereum RPC State Provider
//!
//! This module provides a standard JSON-RPC implementation of the [`EthStateProvider`] 
//! trait. It communicates with EVM-compatible nodes (e.g., Geth, Erigon, Anvil) to 
//! fetch real-time state required for transaction construction.

use crate::{EthStateProvider, GasPrices};
use adapter_core::error::AdapterError;
use alloy_primitives::{Address, U256, Bytes};

/// A JSON-RPC based implementation of [`EthStateProvider`].
pub struct RpcEthStateProvider {
    client: reqwest::Client,
    rpc_url: String,
}

impl RpcEthStateProvider {
    /// Creates a new `RpcEthStateProvider` with a default HTTP client.
    ///
    /// # Arguments
    ///
    /// * `rpc_url` - The JSON-RPC endpoint URL (e.g., `https://eth-mainnet.g.alchemy.com/v2/...`).
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
    /// * `method` - The RPC method name (e.g., `"eth_getBalance"`).
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
            .map_err(|e| AdapterError::Internal(format!("RPC request failed: {e}")))?
            .json::<serde_json::Value>()
            .await
            .map_err(|e| AdapterError::Internal(format!("RPC parse failed: {e}")))?;
            
        if let Some(err) = res.get("error") {
            return Err(AdapterError::Internal(format!("RPC error: {err}")));
        }
        
        res.get("result")
            .cloned()
            .ok_or_else(|| AdapterError::Internal("Missing result in RPC response".into()))
    }
}

// ============================================================================
// Helper Functions for JSON-RPC Formatting
// ============================================================================

/// Converts a `U256` to a hex string prefixed with "0x", stripping leading zeros.
fn u256_to_hex(value: U256) -> String {
    if value.is_zero() {
        "0x0".to_string()
    } else {
        let bytes = value.to_be_bytes::<32>();
        let hex_str = hex::encode(bytes);
        let trimmed = hex_str.trim_start_matches('0');
        format!("0x{}", if trimmed.is_empty() { "0" } else { trimmed })
    }
}

/// Parses a hex string (with or without "0x" prefix) into a `u64`.
fn parse_hex_u64(hex_str: &str) -> Result<u64, AdapterError> {
    u64::from_str_radix(hex_str.trim_start_matches("0x"), 16)
        .map_err(|e| AdapterError::Internal(format!("Failed to parse hex u64: {e}")))
}

/// Parses a hex string (with or without "0x" prefix) into a `u128`.
fn parse_hex_u128(hex_str: &str) -> Result<u128, AdapterError> {
    u128::from_str_radix(hex_str.trim_start_matches("0x"), 16)
        .map_err(|e| AdapterError::Internal(format!("Failed to parse hex u128: {e}")))
}

// ============================================================================
// Trait Implementation
// ============================================================================

#[async_trait::async_trait]
impl EthStateProvider for RpcEthStateProvider {
    /// Fetches the next available nonce for an address, including pending transactions.
    ///
    /// # Note
    ///
    /// Uses the `"pending"` block tag to ensure we account for transactions that have 
    /// been submitted to the mempool but not yet mined, preventing nonce collisions.
    async fn get_pending_nonce(&self, address: Address) -> Result<u64, AdapterError> {
        let addr_hex = format!("0x{}", hex::encode(address.as_slice()));
        let res = self.rpc_call("eth_getTransactionCount", serde_json::json!([addr_hex, "pending"])).await?;
        let hex_str = res.as_str().ok_or_else(|| AdapterError::Internal("Invalid nonce format".into()))?;
        parse_hex_u64(hex_str)
    }

    /// Estimates the current EIP-1559 gas prices.
    ///
    /// # Note
    ///
    /// Adds a 20% buffer to the `max_fee_per_gas` to account for base fee fluctuations 
    /// between the time of estimation and the time of block inclusion, reducing the 
    /// risk of the transaction being dropped from the mempool.
    async fn estimate_gas_prices(&self) -> Result<GasPrices, AdapterError> {
        let gas_price_res = self.rpc_call("eth_gasPrice", serde_json::json!([])).await?;
        let priority_fee_res = self.rpc_call("eth_maxPriorityFeePerGas", serde_json::json!([])).await?;
        
        let gas_price_hex = gas_price_res.as_str().unwrap_or("0x0");
        let priority_fee_hex = priority_fee_res.as_str().unwrap_or("0x0");
        
        let max_fee = parse_hex_u128(gas_price_hex)?;
        let priority_fee = parse_hex_u128(priority_fee_hex)?;
            
        // Add 20% buffer to max_fee to account for base fee fluctuations between blocks
        let max_fee_buffered = max_fee.saturating_add(max_fee / 5);

        Ok(GasPrices {
            max_fee_per_gas: max_fee_buffered,
            max_priority_fee_per_gas: priority_fee,
        })
    }

    /// Estimates the gas limit required to execute a specific transaction.
    ///
    /// # Note
    ///
    /// Adds a 20% buffer to the RPC's gas estimate to prevent out-of-gas reverts 
    /// during execution, as the EVM's gas estimation can sometimes be slightly 
    /// inaccurate for complex smart contract interactions.
    async fn estimate_gas(
        &self,
        from: Address,
        to: Option<Address>,
        value: U256,
        data: Bytes,
    ) -> Result<u64, AdapterError> {
        let mut tx_obj = serde_json::Map::new();
        tx_obj.insert("from".into(), serde_json::json!(format!("0x{}", hex::encode(from.as_slice()))));
        if let Some(to_addr) = to {
            tx_obj.insert("to".into(), serde_json::json!(format!("0x{}", hex::encode(to_addr.as_slice()))));
        }
        tx_obj.insert("value".into(), serde_json::json!(u256_to_hex(value)));
        
        let data_hex = if data.is_empty() {
            "0x".to_string()
        } else {
            format!("0x{}", hex::encode(&data))
        };
        tx_obj.insert("data".into(), serde_json::json!(data_hex));

        let res = self.rpc_call("eth_estimateGas", serde_json::json!([serde_json::Value::Object(tx_obj)])).await?;
        let hex_str = res.as_str().ok_or_else(|| AdapterError::Internal("Invalid gas estimate format".into()))?;
        
        let gas_limit = parse_hex_u64(hex_str)?;
        // Add 20% buffer to gas limit to prevent out-of-gas reverts during execution
        Ok(gas_limit.saturating_add(gas_limit / 5))
    }

    /// Fetches the current balance of an address.
    ///
    /// # Note
    ///
    /// Uses the `"pending"` block tag to reflect the balance after any pending 
    /// transactions are mined, ensuring accurate "drain all" calculations.
    async fn get_balance(&self, address: Address) -> Result<U256, AdapterError> {
        let addr_hex = format!("0x{}", hex::encode(address.as_slice()));
        let res = self.rpc_call("eth_getBalance", serde_json::json!([addr_hex, "pending"])).await?;
        let hex_str = res.as_str().ok_or_else(|| AdapterError::Internal("Invalid balance format".into()))?;
        
        U256::from_str_radix(hex_str.trim_start_matches("0x"), 16)
            .map_err(|e| AdapterError::Internal(format!("Failed to parse balance: {e}")))
    }
}
