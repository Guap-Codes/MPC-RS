//  crates/blockchain-adapters/xrp/src/lib.rs
//! # XRP Ledger (XRPL) Blockchain Adapter
//!
//! This crate provides a production-grade implementation of the [`BlockchainAdapter`] 
//! trait for the XRP Ledger. It leverages the `xrpl_mithril` SDK to handle the 
//! complete lifecycle of an XRP transaction, from building and autofilling to 
//! MPC signature attachment and network broadcasting.
//!
//! ## Architecture
//! The `XrpAdapter` abstracts away XRPL-specific mechanics, such as drop-based 
//! amount calculations, sequence number autofilling, and the unique SHA-512Half 
//! signing digest computation, presenting a uniform interface to the MPC-RS core.

use adapter_core::traits::BlockchainAdapter;
use adapter_core::error::AdapterError;
use async_trait::async_trait;

use xrpl_mithril::{
    tx::builder::PaymentBuilder,
    tx::autofill::autofill,
    types::{Amount, XrpAmount, AccountId},
};

pub use xrpl_mithril::client::JsonRpcClient;

use sha2::{Sha512, Digest};
use serde_json::Value;

/// The core XRP adapter implementing the [`BlockchainAdapter`] trait.
///
/// This struct manages transaction construction, state fetching, and network 
/// interaction for the XRP Ledger.
pub struct XrpAdapter {
    /// The XRPL JSON-RPC client used for state fetching and transaction submission.
    pub client: JsonRpcClient,
    /// The base URL of the XRPL JSON-RPC endpoint (e.g., mainnet or testnet).
    pub rpc_url: String, 
    /// The Network ID used for X-address encoding (e.g., `0` for Mainnet, `1` for Testnet).
    /// If `None`, classic addresses are used exclusively.
    pub network_id: Option<u32>,
}

impl XrpAdapter {
    /// Creates a new `XrpAdapter` with the specified configuration.
    ///
    /// # Arguments
    ///
    /// * `client` - An initialized `xrpl_mithril::JsonRpcClient`.
    /// * `rpc_url` - The base URL of the XRPL JSON-RPC endpoint.
    /// * `network_id` - An optional network ID for X-address tag encoding.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // JsonRpcClient and String contain non-const state
    pub fn new(client: JsonRpcClient, rpc_url: String, network_id: Option<u32>) -> Self {
        Self { client, rpc_url, network_id }
    }

    /// Helper method to fetch the current XRP balance of an account in drops.
    ///
    /// This is primarily used to calculate the maximum transferable amount during 
    /// "drain all" operations, ensuring the account reserve and transaction fees are respected.
    ///
    /// # Arguments
    ///
    /// * `account` - The `AccountId` of the account to query.
    ///
    /// # Returns
    ///
    /// The account balance in drops (1 XRP = 1,000,000 drops) as a `u64`.
    ///
    /// # Errors
    ///
    /// Returns an [`AdapterError::Internal`] if the RPC request fails, the response 
    /// is malformed, or the balance field is missing or unparseable.
    async fn get_balance(&self, account: &AccountId) -> Result<u64, AdapterError> {
        let payload = serde_json::json!({
            "method": "account_info",
            "params": [{
                "account": account.to_string(),
                "ledger_index": "validated"
            }]
        });
        let client = reqwest::Client::new();
        let res = client.post(&self.rpc_url).json(&payload).send().await
            .map_err(|e| AdapterError::Internal(format!("XRP RPC failed: {e}")))?;
        let body: serde_json::Value = res.json().await.map_err(|e| AdapterError::Internal(e.to_string()))?;
        
        let balance_str = body.get("result")
            .and_then(|r| r.get("account_data"))
            .and_then(|ad| ad.get("Balance"))
            .and_then(|b| b.as_str())
            .ok_or_else(|| AdapterError::Internal("Missing XRP balance".into()))?;
            
        balance_str.parse::<u64>().map_err(|e| AdapterError::Internal(format!("Failed to parse XRP balance: {e}")))
    }
}

#[allow(clippy::double_must_use)] // Suppresses false positive from async_trait macro expansion
#[async_trait]
impl BlockchainAdapter for XrpAdapter {
    /// Constructs an unsigned XRP payment transaction.
    ///
    /// # Arguments
    ///
    /// * `from` - The source classic address or X-address.
    /// * `to` - The destination classic address or X-address.
    /// * `amount` - The amount of XRP to transfer (e.g., "10.5" or "all").
    /// * `_token` - Ignored for XRP, as native XRP transfers are the primary use case here.
    /// * `_change_address` - Ignored for XRP (account-based model).
    /// * `_previous_tx_hex` - Ignored for XRP (account-based model).
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// 1. The unsigned transaction serialized as a UTF-8 JSON string (ready for signature injection).
    /// 2. The 32-byte signing digest (SHA-512Half of the binary-encoded transaction).
    ///
    /// # Errors
    ///
    /// Returns an [`AdapterError`] if the addresses are invalid, the amount cannot be parsed, 
    /// the balance is insufficient for an "all" drain, or the `xrpl_mithril` autofill fails.
    async fn build_unsigned_tx(
        &self,
        from: &str,
        to: &str,
        amount: &str,
        _token: Option<&str>,
        _change_address: Option<&str>,
        _previous_tx_hex: Option<&str>,
    ) -> Result<(Vec<u8>, [u8; 32]), AdapterError> {
        // 1. Parse addresses using the correct type annotation on the parse() call.
        // This allows the compiler to infer the correct error type for `e`.
        let from_account = from
            .parse::<AccountId>()
            .map_err(|e| AdapterError::InvalidAddress(e.to_string()))?;
        let to_account = to
            .parse::<AccountId>()
            .map_err(|e| AdapterError::InvalidAddress(e.to_string()))?;

        // 2. Parse amount (XRP drops)
        // Handle "all" by fetching balance and subtracting standard fee
        let drops = if amount == "all" {
            let balance = self.get_balance(&from_account).await?;
            let fee = 12; // Standard XRPL minimum fee in drops
            if balance <= fee {
                return Err(AdapterError::InvalidAmount("insufficient XRP to cover fee".into()));
            }
            balance.saturating_sub(fee)
        } else {
            let parsed = amount.parse::<f64>().map_err(|_| AdapterError::InvalidAmount("invalid XRP amount".into()))?;
            if parsed < 0.0 {
                return Err(AdapterError::InvalidAmount("XRP amount cannot be negative".into()));
            }
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss, clippy::as_conversions)]
            let drops = (parsed * 1_000_000.0) as u64;
            drops
        };
        
        let xrp_amount = XrpAmount::from_drops(drops)
            .map_err(|e| AdapterError::InvalidAmount(format!("invalid drops: {e}")))?;

        // 3. Build the unsigned payment transaction
        let mut unsigned = PaymentBuilder::new()
            .account(from_account)
            .destination(to_account)
            .amount(Amount::Xrp(xrp_amount))
            .build()
            .map_err(|e| AdapterError::Internal(e.to_string()))?;

        // 4. Autofill (sequence, fee, etc.) from the network
        autofill(&self.client, &mut unsigned)
            .await
            .map_err(|e| AdapterError::Internal(format!("autofill failed: {e}")))?;

        // 5. Serialise the transaction to JSON map.
        // `to_json_map()` extracts the inner transaction as a Map and ensures 
        // it is in the correct form for signing (stripping existing signatures).
        let json_map = unsigned
            .to_json_map()
            .map_err(|e| AdapterError::Internal(e.to_string()))?;

        let json_str = serde_json::to_string(&json_map)
            .map_err(|e| AdapterError::Internal(e.to_string()))?;
        let unsigned_bytes = json_str.into_bytes();

        // 6. Compute the signing digest (SHA-512Half of the binary-encoded tx)
        // XRPL requires hashing the binary serialization of the transaction with SHA-512, 
        // then taking the first 32 bytes of the resulting 64-byte hash.
        let mut binary = Vec::new();
        xrpl_mithril::codec::serializer::serialize_json_object(&json_map, &mut binary, false)
            .map_err(|e| AdapterError::Internal(e.to_string()))?;
            
        let hash = Sha512::digest(&binary);
        
        // SHA-512 mathematically guarantees a 64-byte output, making this slice and conversion infallible.
        #[allow(clippy::indexing_slicing, clippy::unwrap_used)]
        let digest: [u8; 32] = hash[..32].try_into().unwrap();

        Ok((unsigned_bytes, digest))
    }

    /// Broadcasts a finalized, signed transaction to the XRP Ledger.
    ///
    /// # Arguments
    ///
    /// * `finalized_tx` - The binary-encoded, signed transaction blob.
    ///
    /// # Returns
    ///
    /// The transaction hash (TXID) as a hex string upon successful submission.
    ///
    /// # Errors
    ///
    /// Returns an [`AdapterError::Internal`] if the RPC request fails, the response 
    /// is malformed, or the XRPL node rejects the transaction (e.g., due to low fee or bad sequence).
    async fn broadcast(&self, finalized_tx: &[u8]) -> Result<String, AdapterError> {
        let tx_blob = hex::encode(finalized_tx).to_uppercase();
        let payload = serde_json::json!({
            "method": "submit",
            "params": [{ "tx_blob": tx_blob }]
        });

        let client = reqwest::Client::new();
        let res = client.post(&self.rpc_url).json(&payload).send().await
            .map_err(|e| AdapterError::Internal(format!("XRP RPC failed: {e}")))?;
            
        let body: serde_json::Value = res.json().await.map_err(|e| AdapterError::Internal(e.to_string()))?;
        
        body.get("result")
            .and_then(|r| r.get("tx_json"))
            .and_then(|tx| tx.get("hash"))
            .and_then(|h| h.as_str())
            .map_or_else(
                || {
                    let err_msg = body.get("result")
                        .and_then(|r| r.get("error"))
                        .map_or_else(|| "Unknown error".to_string(), ToString::to_string);
                    Err(AdapterError::Internal(format!("XRP broadcast error: {err_msg}")))
                },
                |hash| Ok(hash.to_string()),
            )
    }

    /// Attaches an MPC-generated signature to an unsigned XRP transaction.
    ///
    /// # Arguments
    ///
    /// * `unsigned_tx` - The UTF-8 encoded JSON string of the unsigned transaction.
    /// * `signature` - The raw signature bytes produced by the MPC nodes.
    /// * `pubkey_hex` - The hex-encoded public key of the signer.
    ///
    /// # Returns
    ///
    /// The fully signed transaction serialized into the XRPL binary wire format (blob).
    ///
    /// # Errors
    ///
    /// Returns an [`AdapterError::InvalidTransaction`] if the unsigned transaction 
    /// is not valid UTF-8 or valid JSON, or if serialization fails.
    async fn attach_signature(
        &self,
        unsigned_tx: &[u8],
        signature: &[u8],
        pubkey_hex: &str,
    ) -> Result<Vec<u8>, AdapterError> {
        // 1. Parse the unsigned transaction JSON
        let unsigned_str = std::str::from_utf8(unsigned_tx)
            .map_err(|_| AdapterError::InvalidTransaction("invalid UTF-8".into()))?;
        let mut json_map: serde_json::Map<String, Value> =
            serde_json::from_str(unsigned_str)
                .map_err(|e| AdapterError::InvalidTransaction(e.to_string()))?;

        // 2. Insert signature and public key fields
        let sig_hex = hex::encode(signature);
        json_map.insert("TxnSignature".to_string(), Value::String(sig_hex));
        json_map.insert(
            "SigningPubKey".to_string(),
            Value::String(pubkey_hex.to_string()),
        );

        // 3. Serialise the signed transaction to binary (blob)
        // This binary format is exactly what the XRPL `submit` RPC method expects.
        let mut signed_blob = Vec::new();
        xrpl_mithril::codec::serializer::serialize_json_object(
            &json_map,
            &mut signed_blob,
            false,
        )
        .map_err(|e| AdapterError::Internal(e.to_string()))?;

        Ok(signed_blob)
    }

    /// Derives a classic XRP address from a raw secp256k1 public key.
    ///
    /// # Note
    ///
    /// XRP classic addresses are generated by:
    /// 1. Computing `RIPEMD160(SHA256(pubkey))`.
    /// 2. Prepending the version byte `0x00` (indicating a classic address).
    /// 3. Appending a 4-byte checksum (`SHA256(SHA256(payload))[..4]`).
    /// 4. Encoding the resulting 25-byte payload using Base58.
    ///
    /// # Arguments
    ///
    /// * `pubkey` - The raw, compressed or uncompressed secp256k1 public key bytes.
    ///
    /// # Returns
    ///
    /// The Base58-encoded classic XRP address string (typically starting with `r`).
    ///
    /// # Errors
    ///
    /// Returns an [`AdapterError::InvalidAddress`] if the hashing or encoding operations fail.
    #[allow(clippy::indexing_slicing)] // SHA-256 mathematically guarantees a 32-byte output
    fn derive_address(&self, pubkey: &[u8]) -> Result<String, AdapterError> {
        use ripemd::Ripemd160;
        use sha2::{Digest, Sha256};

        // XRP classic address: Base58(0x00 || RIPEMD160(SHA256(pubkey)))
        let sha = Sha256::digest(pubkey);
        let ripe = Ripemd160::digest(sha);

        let mut payload = vec![0x00];
        payload.extend_from_slice(&ripe);

        let checksum = &Sha256::digest(Sha256::digest(&payload))[..4];
        payload.extend_from_slice(checksum);

        Ok(bs58::encode(payload).into_string())
    }
}