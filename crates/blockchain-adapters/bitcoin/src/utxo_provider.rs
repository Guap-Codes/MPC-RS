//! # Bitcoin UTXO Provider
//!
//! This module provides implementations of the [`UtxoProvider`](adapter_core::traits::UtxoProvider) 
//! trait for fetching Unspent Transaction Outputs (UTXOs) and historical transaction data 
//! from a Mempool.space-compatible REST API.

use adapter_core::traits::UtxoProvider;
use adapter_core::types::Utxo;
use adapter_core::error::AdapterError;
use async_trait::async_trait;
use bitcoin::{OutPoint, Txid};
use std::str::FromStr;

/// A UTXO provider that queries a Mempool.space-compatible REST API.
///
/// This provider is suitable for both mainnet (e.g., `https://mempool.space/api`) 
/// and local test environments (e.g., Nigiri/Esplora at `http://127.0.0.1:3000/api`).
pub struct MempoolUtxoProvider {
    client: reqwest::Client,
    api_base_url: String,
}

impl MempoolUtxoProvider {
    /// Creates a new `MempoolUtxoProvider` with a configured, timeout-protected HTTP client.
    ///
    /// # Arguments
    ///
    /// * `api_base_url` - The base URL of the Mempool API (without a trailing slash).
    #[must_use]
    pub fn new(api_base_url: String) -> Self {
        Self {
            // Add a strict timeout to prevent hanging requests and resource exhaustion in production
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
            api_base_url,
        }
    }
}

#[async_trait]
impl UtxoProvider for MempoolUtxoProvider {
    /// Fetches a suitable unspent transaction output for a given Bitcoin address.
    ///
    /// # Arguments
    ///
    /// * `address` - The Bitcoin address to query for UTXOs.
    ///
    /// # Returns
    ///
    /// A [`Utxo`] struct containing the `OutPoint` and the full `TxOut` (script and value).
    ///
    /// # Errors
    ///
    /// Returns an [`AdapterError`] if:
    /// - The API request fails or times out.
    /// - The API response cannot be parsed as JSON.
    /// - The address has no unspent outputs (`InvalidAmount`).
    /// - The fetched transaction data is malformed or the `vout` index is out of bounds.
    ///
    /// # Production Note
    ///
    /// This implementation naively selects the *first* UTXO returned by the API. 
    /// In a production environment, this should be replaced with a proper **Coin Selection** 
    /// algorithm (e.g., Branch and Bound or Knapsack) to optimize for fee efficiency and privacy.
    async fn get_utxo(&self, address: &str) -> Result<Utxo, AdapterError> {
        // 1. Fetch UTXOs for the address
        let url = format!("{}/address/{}/utxo", self.api_base_url, address);
        let response = self.client.get(&url).send().await
            .map_err(|e| AdapterError::Internal(format!("UTXO API request failed: {e}")))?;
            
        let utxos: Vec<serde_json::Value> = response.json().await
            .map_err(|e| AdapterError::Internal(format!("UTXO API parse failed: {e}")))?;
            
        // 2. Pick the first UTXO (In production, implement proper "Coin Selection" logic here)
        let utxo = utxos.first().ok_or_else(|| AdapterError::InvalidAmount("No UTXOs found for address".into()))?;
        
        let txid_str = utxo.get("txid").and_then(serde_json::Value::as_str).ok_or_else(|| AdapterError::Internal("Missing txid".into()))?;
        let txid = Txid::from_str(txid_str)
            .map_err(|e| AdapterError::Internal(format!("Invalid txid: {e}")))?;
            
        let vout_u64 = utxo.get("vout").and_then(serde_json::Value::as_u64).ok_or_else(|| AdapterError::Internal("Missing vout".into()))?;
        let vout = u32::try_from(vout_u64).map_err(|_| AdapterError::Internal("vout exceeds u32 bounds".into()))?;

        // 3. Fetch the full transaction to get the script_pubkey and exact value
        let tx_url = format!("{}/tx/{}/hex", self.api_base_url, txid_str);
        
        let response = self.client.get(&tx_url).send().await
            .map_err(|e| AdapterError::Internal(format!("Tx fetch request failed: {e}")))?;
            
        let tx_hex = response.text().await
            .map_err(|e| AdapterError::Internal(format!("Tx text fetch failed: {e}")))?;
            
        let tx_bytes = hex::decode(&tx_hex)
            .map_err(|e| AdapterError::Internal(format!("Invalid tx hex: {e}")))?;
            
        let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&tx_bytes)
            .map_err(|e| AdapterError::Internal(format!("Failed to deserialize tx: {e}")))?;
            
        let vout_usize = usize::try_from(vout).map_err(|_| AdapterError::Internal("vout exceeds usize bounds".into()))?;
        let tx_out = tx.output.get(vout_usize)
            .ok_or_else(|| AdapterError::Internal("vout index out of bounds".into()))?
            .clone();

        Ok(Utxo {
            outpoint: OutPoint::new(txid, vout),
            tx_out,
        })
    }

    /// Fetches the full, raw transaction for a given transaction ID.
    ///
    /// This is strictly required for Bitcoin `SegWit` transactions to satisfy hardware wallet 
    /// and MPC node non-witness UTXO validation rules, ensuring the input being spent is valid.
    ///
    /// # Arguments
    ///
    /// * `txid` - The transaction ID of the previous transaction.
    ///
    /// # Returns
    ///
    /// The deserialized [`bitcoin::Transaction`] object.
    ///
    /// # Errors
    ///
    /// Returns an [`AdapterError`] if the API request fails, the hex is invalid, 
    /// or the transaction cannot be deserialized by the `bitcoin` consensus rules.
    async fn get_previous_transaction(&self, txid: &Txid) -> Result<bitcoin::Transaction, AdapterError> {
        let url = format!("{}/tx/{}/hex", self.api_base_url, txid);
        
        let response = self.client.get(&url).send().await
            .map_err(|e| AdapterError::Internal(format!("Tx fetch request failed: {e}")))?;
            
        let tx_hex = response.text().await
            .map_err(|e| AdapterError::Internal(format!("Tx text fetch failed: {e}")))?;
            
        let tx_bytes = hex::decode(&tx_hex)
            .map_err(|e| AdapterError::Internal(format!("Invalid tx hex: {e}")))?;
            
        bitcoin::consensus::deserialize(&tx_bytes)
            .map_err(|e| AdapterError::Internal(format!("Failed to deserialize tx: {e}")))
    }
}
