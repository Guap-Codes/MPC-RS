//! # Tron Blockchain Adapter
//!
//! This crate provides a production-grade implementation of the [`BlockchainAdapter`] 
//! trait for the Tron network. It handles the complete lifecycle of a Tron transaction, 
//! from protobuf construction and replay protection to ECDSA signature attachment 
//! and network broadcasting.
//!
//! ## Architecture
//! The `TronAdapter` is generic over its `TronRpcClient` dependency, allowing seamless 
//! integration with different RPC providers (e.g., `TronGrid`, private full nodes). 
//! It supports both native TRX transfers and TRC-20 (ERC-20 compatible) token transfers.

pub mod tron_proto;
pub mod rpc_client;

use adapter_core::traits::{BlockchainAdapter, AdapterResult};
use adapter_core::error::AdapterError;
use async_trait::async_trait;
use prost::Message;
use sha2::{Sha256, Digest as Sha2Digest};
use sha3::{Keccak256, Digest as KeccakDigest};
use tron_proto::{
    transaction, Contract, Transaction, TransferContract, TriggerSmartContract,
    TRANSFER_CONTRACT, TRIGGER_SMART_CONTRACT,
};
pub use rpc_client::{TronRpcClient, HttpTronRpcClient};

/// The core Tron adapter implementing the [`BlockchainAdapter`] trait.
///
/// This struct manages transaction construction, protobuf serialization, and network 
/// interaction for the Tron blockchain.
pub struct TronAdapter<R: TronRpcClient> {
    /// The injected RPC client for fetching block data and state.
    pub rpc_client: R,
    /// The endpoint URL for broadcasting finalized transactions (e.g., `/wallet/broadcasthex`).
    pub broadcast_url: String,
}

impl<R: TronRpcClient> TronAdapter<R> {
    /// Creates a new `TronAdapter` with the specified RPC client and broadcast URL.
    ///
    /// # Arguments
    ///
    /// * `rpc_client` - An implementation of [`TronRpcClient`].
    /// * `broadcast_url` - The full URL for the broadcast endpoint.
    #[allow(clippy::missing_const_for_fn)] // String and generic bounds prevent const fn
    pub fn new(rpc_client: R, broadcast_url: String) -> Self {
        Self { rpc_client, broadcast_url }
    }

    /// Decodes a Tron `Base58Check` address into its 21-byte raw payload.
    ///
    /// Tron addresses are `Base58Check` encoded with a version byte of `0x41` 
    /// (indicating mainnet/testnet), followed by a 20-byte hash, and a 4-byte checksum.
    ///
    /// # Arguments
    ///
    /// * `addr` - The `Base58Check` encoded address string (e.g., `TLa2f6VPqDgRE67v1736s7bJ8Ray5wYjU7`).
    ///
    /// # Returns
    ///
    /// A 21-byte `Vec<u8>` containing the version byte and the address hash.
    ///
    /// # Errors
    ///
    /// Returns an [`AdapterError::InvalidAddress`] if the string is not valid `Base58Check`, 
    /// the checksum fails, or the version byte is not `0x41`.
    fn decode_address(addr: &str) -> Result<Vec<u8>, AdapterError> {
        let decoded = bs58::decode(addr)
            .with_check(Some(0x41))
            .into_vec()
            .map_err(|e| AdapterError::InvalidAddress(format!("Invalid Base58Check: {e}")))?;
            
        if decoded.len() != 21 || decoded.first().copied().unwrap_or(0) != 0x41 {
            return Err(AdapterError::InvalidAddress("Not a valid Tron address".into()));
        }
        Ok(decoded)
    }

    /// Encodes TRC-20 transfer data using standard Ethereum ABI formatting.
    ///
    /// This constructs the payload for the `transfer(address,uint256)` function call, 
    /// which is required when interacting with TRC-20 smart contracts.
    ///
    /// # Arguments
    ///
    /// * `to_raw` - The 21-byte raw payload of the destination address.
    /// * `amount` - The human-readable amount to transfer (e.g., "1.5").
    /// * `decimals` - The decimal precision of the TRC-20 token (e.g., 6 for USDT).
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` containing the 68-byte ABI-encoded calldata:
    /// - Bytes 0-3: Function selector (`0xa9059cbb`).
    /// - Bytes 4-35: 32-byte left-padded destination address (skipping the `0x41` version byte).
    /// - Bytes 36-67: 32-byte big-endian encoded transfer amount.
    ///
    /// # Errors
    ///
    /// Returns an [`AdapterError::InvalidAmount`] if the amount string cannot be parsed as a float.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss, clippy::as_conversions)]
    fn encode_trc20_data(to_raw: &[u8], amount: &str, decimals: u8) -> Result<Vec<u8>, AdapterError> {
        let mut data = vec![0xa9, 0x05, 0x9c, 0xbb]; // transfer(address,uint256) selector

        // Skip the 0x41 version byte and left-pad the 20-byte address to 32 bytes
        let mut addr_padded = vec![0u8; 12];
        addr_padded.extend_from_slice(to_raw.get(1..).unwrap_or_default());

        let amount_f = amount.parse::<f64>()
            .map_err(|_| AdapterError::InvalidAmount("Invalid amount".into()))?;
            
        if amount_f < 0.0 {
            return Err(AdapterError::InvalidAmount("Amount cannot be negative".into()));
        }
        
        let amount_int = (amount_f * 10f64.powi(i32::from(decimals))) as u128;
        let amount_bytes = amount_int.to_be_bytes();
        let mut amount_padded = vec![0u8; 32usize.saturating_sub(amount_bytes.len())];
        amount_padded.extend_from_slice(&amount_bytes);

        data.extend_from_slice(&addr_padded);
        data.extend_from_slice(&amount_padded);
        Ok(data)
    }

    /// Helper to fetch the native TRX balance of an address in SUN (1 TRX = 1,000,000 SUN).
    ///
    /// This is primarily used to calculate the maximum transferable amount during 
    /// "drain all" operations, ensuring sufficient funds are left to cover network fees.
    ///
    /// # Arguments
    ///
    /// * `address_b58` - The `Base58Check` encoded address to query.
    ///
    /// # Returns
    ///
    /// The account balance in SUN as an `i64`. Returns `0` if the account does not exist.
    ///
    /// # Errors
    ///
    /// Returns an [`AdapterError::Internal`] if the HTTP request fails or the response 
    /// cannot be parsed as JSON.
    async fn get_balance(&self, address_b58: &str) -> Result<i64, AdapterError> {
        // Derive the base API URL from the broadcast URL
        let base_url = self.broadcast_url.replace("/wallet/broadcasthex", "");
        let url = format!("{base_url}/wallet/getaccount");
        
        let payload = serde_json::json!({
            "address": address_b58,
            "visible": true
        });
        
        let client = reqwest::Client::new();
        let res = client.post(&url).json(&payload).send().await
            .map_err(|e| AdapterError::Internal(format!("Tron balance fetch failed: {e}")))?;
            
        let body: serde_json::Value = res.json().await
            .map_err(|e| AdapterError::Internal(format!("Failed to parse Tron balance response: {e}")))?;
        
        // If the account doesn't exist or has no balance, it defaults to 0
        let balance = body.get("balance").and_then(serde_json::Value::as_i64).unwrap_or(0);
        Ok(balance)
    }
}

#[async_trait]
impl<R: TronRpcClient> BlockchainAdapter for TronAdapter<R> {
    /// Constructs an unsigned Tron transaction (native TRX or TRC-20).
    ///
    /// # Arguments
    ///
    /// * `from` - The source address (the MPC vault).
    /// * `to` - The destination address.
    /// * `amount` - The amount to transfer (e.g., "1.5" or "all").
    /// * `token` - An optional TRC-20 contract address. If `Some`, a TRC-20 transfer is built.
    /// * `_change_address` - Ignored for Tron (account-based model).
    /// * `_previous_tx_hex` - Ignored for Tron (account-based model).
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// 1. The serialized protobuf bytes of the unsigned transaction.
    /// 2. The 32-byte SHA-256 digest of the raw transaction data, which the MPC nodes must sign.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss, clippy::as_conversions)]
    async fn build_unsigned_tx(
        &self,
        from: &str,
        to: &str,
        amount: &str,
        token: Option<&str>,
        _change_address: Option<&str>,
        _previous_tx_hex: Option<&str>,
    ) -> AdapterResult<(Vec<u8>, [u8; 32])> {
        let owner_address = Self::decode_address(from)?;
        let to_address = Self::decode_address(to)?;

        // 1. Fetch fresh block data for replay protection
        let (ref_block_bytes, ref_block_hash, expiration) =
            self.rpc_client.get_latest_block_data().await?;
            
        let timestamp = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| AdapterError::Internal(format!("Time error: {e}")))?
                .as_millis()
        ).unwrap_or(0);

        // 2. Build the contract payload
        let (contract_type, parameter_bytes, fee_limit) = if let Some(contract) = token {
            if amount == "all" {
                return Err(AdapterError::InvalidAmount("Draining 'all' TRC20 tokens is not supported in break-glass mode. Please specify an exact amount.".into()));
            }
            
            let contract_address = Self::decode_address(contract)?;
            let data = Self::encode_trc20_data(&to_address, amount, 18)?; 

            let trigger = TriggerSmartContract {
                owner_address,
                contract_address,
                call_value: 0,
                data,
            };
            (TRIGGER_SMART_CONTRACT, trigger.encode_to_vec(), 100_000_000) 
        } else {
            // Native TRX Transfer
            let amount_sun = if amount == "all" {
                let owner_address_b58 = bs58::encode(&owner_address).with_check_version(0x41).into_string();
                let balance_sun = self.get_balance(&owner_address_b58).await?;
                
                // Tron native transfer usually costs 0 TRX if you have bandwidth, 
                // but we subtract a 1 TRX (1,000,000 SUN) buffer to be safe for emergency drains.
                let fee_buffer = 1_000_000;
                if balance_sun <= fee_buffer {
                    return Err(AdapterError::InvalidAmount("insufficient TRX to cover fees".into()));
                }
                balance_sun.saturating_sub(fee_buffer)
            } else {
                let parsed = amount.parse::<f64>().map_err(|_| AdapterError::InvalidAmount("invalid TRX amount".into()))?;
                if parsed < 0.0 {
                    return Err(AdapterError::InvalidAmount("TRX amount cannot be negative".into()));
                }
                (parsed * 1_000_000.0) as i64
            };

            let transfer = TransferContract {
                owner_address,
                to_address,
                amount: amount_sun,
            };
            (TRANSFER_CONTRACT, transfer.encode_to_vec(), 0)
        };

        // 3. Assemble the Transaction Protobuf
        let tx = Transaction {
            raw_data: Some(transaction::Raw {
                ref_block_bytes,
                ref_block_num: 0,
                ref_block_hash,
                expiration,
                contract: vec![Contract {
                    r#type: contract_type,
                    parameter: parameter_bytes,
                }],
                timestamp,
                fee_limit,
            }),
            signature: vec![],
        };

        // 4. Serialize and compute signing digest
        let raw_bytes = tx.encode_to_vec();
        let digest: [u8; 32] = Sha256::digest(&raw_bytes).into();

        Ok((raw_bytes, digest))
    }

    /// Broadcasts a finalized, signed transaction to the Tron network.
    ///
    /// # Arguments
    ///
    /// * `finalized_tx` - The serialized protobuf bytes of the signed transaction.
    ///
    /// # Returns
    ///
    /// The transaction ID (TXID) as a hex string upon successful broadcast.
    ///
    /// # Errors
    ///
    /// Returns an [`AdapterError::Internal`] if the HTTP request fails, the response 
    /// is not valid JSON, or the Tron node rejects the transaction.
    async fn broadcast(&self, finalized_tx: &[u8]) -> Result<String, AdapterError> {
        let tx_hex = hex::encode(finalized_tx);
        let payload = serde_json::json!({ "transaction": tx_hex });

        let client = reqwest::Client::new();
        let res = client.post(&self.broadcast_url).json(&payload).send().await
            .map_err(|e| AdapterError::Internal(format!("Tron RPC failed: {e}")))?;
            
        let body: serde_json::Value = res.json().await.map_err(|e| AdapterError::Internal(e.to_string()))?;
        
        if body.get("result").and_then(serde_json::Value::as_bool) == Some(true) {
            Ok(body.get("txid").and_then(|v| v.as_str()).unwrap_or("").to_string())
        } else {
            let err_code = body.get("code").map_or_else(|| "Unknown error".to_string(), ToString::to_string);
            Err(AdapterError::Internal(format!("Tron broadcast error: {err_code}")))
        }
    }

    /// Attaches an MPC-generated signature to an unsigned Tron transaction.
    ///
    /// # Arguments
    ///
    /// * `unsigned_tx` - The serialized protobuf bytes of the unsigned transaction.
    /// * `signature` - The 65-byte raw ECDSA signature (r, s, v) produced by the MPC nodes.
    /// * `_pubkey_hex` - Ignored for Tron, as the signature is directly appended to the 
    ///   protobuf `signature` array without needing to derive the public key at this stage.
    ///
    /// # Returns
    ///
    /// The serialized protobuf bytes of the fully signed transaction.
    ///
    /// # Errors
    ///
    /// Returns an [`AdapterError::InvalidTransaction`] if the protobuf fails to decode 
    /// or the signature is not exactly 65 bytes.
    async fn attach_signature(
        &self,
        unsigned_tx: &[u8],
        signature: &[u8],
        _pubkey_hex: &str,
    ) -> AdapterResult<Vec<u8>> {
        let mut tx = Transaction::decode(unsigned_tx)
            .map_err(|e| AdapterError::InvalidTransaction(format!("Failed to parse Tron tx: {e}")))?;

        if signature.len() != 65 {
            return Err(AdapterError::InvalidTransaction("Tron signature must be 65 bytes".into()));
        }
        tx.signature.push(signature.to_vec());
        Ok(tx.encode_to_vec())
    }

    /// Derives a Tron address from a raw secp256k1 public key.
    ///
    /// # Arguments
    ///
    /// * `pubkey` - The raw, compressed or uncompressed secp256k1 public key bytes.
    ///
    /// # Returns
    ///
    /// The `Base58Check` encoded Tron address string (starting with `T`).
    ///
    /// # Errors
    ///
    /// Returns an [`AdapterError::InvalidAddress`] if the public key cannot be parsed 
    /// as a valid secp256k1 key.
    #[allow(clippy::indexing_slicing)] // Lengths are mathematically guaranteed by crypto primitives
    fn derive_address(&self, pubkey: &[u8]) -> AdapterResult<String> {
        use k256::ecdsa::VerifyingKey;
        use k256::elliptic_curve::sec1::ToEncodedPoint;

        let vk = VerifyingKey::from_sec1_bytes(pubkey)
            .map_err(|e| AdapterError::InvalidAddress(format!("Invalid pubkey: {e}")))?;
        let uncompressed = vk.to_encoded_point(false);

        // Hash the uncompressed public key (skipping the 0x04 prefix) with Keccak-256
        let hash = Keccak256::digest(uncompressed.as_bytes().get(1..).unwrap_or_default());
        let addr_bytes = hash.get(12..).unwrap_or_default(); // Take the last 20 bytes

        // Prepend the Tron mainnet/testnet version byte (0x41)
        let mut payload = vec![0x41];
        payload.extend_from_slice(addr_bytes);

        // Base58Check encode the 21-byte payload
        Ok(bs58::encode(&payload)
            .with_check_version(0x41)
            .into_string())
    }
}