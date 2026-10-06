//! # Solana Blockchain Adapter
//!
//! This crate provides a production-grade implementation of the [`BlockchainAdapter`] 
//! trait for the Solana network. It handles the complete lifecycle of a Solana 
//! transaction, from dynamic state fetching (blockhashes, token decimals) to 
//! message construction, Ed25519 signature attachment, and network broadcasting.
//!
//! ## Architecture
//! The `SolanaAdapter` is designed to be generic over its `SolanaStateProvider` 
//! dependency, allowing seamless integration with different RPC endpoints 
//! (e.g., Helius, `QuickNode`, or a local `solana-test-validator`).

pub mod message;
pub mod instruction;
pub mod rpc_provider;

use adapter_core::traits::BlockchainAdapter;
use adapter_core::error::AdapterError;
use async_trait::async_trait;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::hash::Hash;
use std::str::FromStr;
use std::sync::Arc;

use message::{build_message, signing_digest, serialize_message};
use instruction::{build_sol_transfer, build_spl_transfer};

/// A trait for injecting an async RPC client to fetch dynamic Solana network state.
///
/// This trait abstracts away the underlying JSON-RPC calls, allowing the adapter to 
/// be tested with mock implementations and deployed with different RPC providers.
#[allow(clippy::double_must_use)] // Suppresses false positive from async_trait macro expansion
#[async_trait]
pub trait SolanaStateProvider: Send + Sync {
    /// Fetches the latest blockhash from the cluster.
    ///
    /// # Note
    /// Solana transactions require a recent blockhash to be valid (typically expiring 
    /// after ~60-90 seconds or 150 blocks). This must be fetched immediately before 
    /// building the transaction to prevent `BlockhashNotFound` errors.
    async fn get_latest_blockhash(&self) -> Result<Hash, AdapterError>;
    
    /// Fetches the decimals for a given SPL Token mint.
    ///
    /// This is strictly required for the `transfer_checked` instruction to ensure 
    /// the transfer amount matches the mint's precision.
    async fn get_token_decimals(&self, mint: &Pubkey) -> Result<u8, AdapterError>;

    /// Fetches the current lamport balance of a given address.
    async fn get_balance(&self, address: &Pubkey) -> Result<u64, AdapterError>;
}

/// The core Solana adapter implementing the [`BlockchainAdapter`] trait.
pub struct SolanaAdapter {
    /// The JSON-RPC endpoint URL used for state fetching and broadcasting.
    pub rpc_url: String, 
    /// The injected state provider for fetching blockhashes, decimals, and balances.
    pub state_provider: Arc<dyn SolanaStateProvider>,
}

impl SolanaAdapter {
    /// Creates a new `SolanaAdapter` with the specified configuration.
    ///
    /// # Arguments
    ///
    /// * `rpc_url` - The JSON-RPC endpoint URL.
    /// * `state_provider` - An implementation of [`SolanaStateProvider`].
    pub fn new(rpc_url: String, state_provider: Arc<dyn SolanaStateProvider>) -> Self {
        Self { rpc_url, state_provider }
    }
}

#[allow(clippy::double_must_use)] // Suppresses false positive from async_trait macro expansion
#[async_trait]
impl BlockchainAdapter for SolanaAdapter {
    /// Constructs an unsigned Solana transaction message (native SOL or SPL Token).
    ///
    /// # Arguments
    ///
    /// * `from` - The source address (the MPC vault).
    /// * `to` - The destination address.
    /// * `amount` - The amount to transfer. For SOL, this is in lamports (or "all"). 
    ///   For SPL tokens, this is the raw integer string in base units (e.g., "1000000" for 1 USDC).
    /// * `token` - An optional SPL Token mint address. If `Some`, an SPL transfer is built.
    /// * `_change_address` - Ignored for Solana (account-based model).
    /// * `_previous_tx_hex` - Ignored for Solana (account-based model).
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// 1. The serialized Solana `Message` bytes (ready for signature attachment).
    /// 2. The 32-byte signing digest (the serialized message hashed for Ed25519 signing).
    async fn build_unsigned_tx(
        &self,
        from: &str,
        to: &str,
        amount: &str,
        token: Option<&str>,
        _change_address: Option<&str>,
        _previous_tx_hex: Option<&str>,
    ) -> Result<(Vec<u8>, [u8; 32]), AdapterError> {
        let from_pubkey = Pubkey::from_str(from)
            .map_err(|e| AdapterError::InvalidAddress(e.to_string()))?;
        let to_pubkey = Pubkey::from_str(to)
            .map_err(|e| AdapterError::InvalidAddress(e.to_string()))?;

        // 1. Fetch latest blockhash dynamically (blockhashes expire in ~60s)
        let recent_blockhash = self.state_provider.get_latest_blockhash().await?;

        let message = if let Some(mint_str) = token {
            // --- SPL Token Transfer Path ---
            let mint_pubkey = Pubkey::from_str(mint_str)
                .map_err(|e| AdapterError::InvalidAddress(format!("Invalid mint: {e}")))?;
                
            let decimals = self.state_provider.get_token_decimals(&mint_pubkey).await?;
            
            let raw_amount: u64 = amount.parse()
                .map_err(|_| AdapterError::InvalidAmount("SPL amount must be an integer string".into()))?;
                
            let instructions = build_spl_transfer(
                &from_pubkey, // payer (pays for ATA creation rent)
                &from_pubkey, // authority (token owner)
                &mint_pubkey, 
                &to_pubkey, 
                raw_amount, 
                decimals
            )?;
            
            build_message(&from_pubkey, &instructions, &recent_blockhash)
        } else {
            // --- Native SOL Transfer Path ---
            let lamports = if amount == "all" {
                let balance = self.state_provider.get_balance(&from_pubkey).await?;
                let fee = 5000; // Standard Solana base fee for a simple transfer
                if balance <= fee {
                    return Err(AdapterError::InvalidAmount("insufficient funds to cover fee".into()));
                }
                balance.saturating_sub(fee) // Safe arithmetic
            } else {
                amount.parse::<u64>().map_err(|_| AdapterError::InvalidAmount("lamports must be an integer string".into()))?
            };   
 
            let ix = build_sol_transfer(&from_pubkey, &to_pubkey, lamports);
            build_message(&from_pubkey, &[ix], &recent_blockhash)
        };

        let digest = signing_digest(&message)?;
        let serialized = serialize_message(&message);
        
        Ok((serialized, digest))
    }

    /// Broadcasts a finalized, signed transaction to the Solana network via JSON-RPC.
    ///
    /// # Arguments
    ///
    /// * `finalized_tx` - The fully signed transaction in Solana's legacy wire format.
    ///
    /// # Returns
    ///
    /// The transaction signature (TXID) as a Base58-encoded string upon successful broadcast.
    async fn broadcast(&self, finalized_tx: &[u8]) -> Result<String, AdapterError> {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let encoded_tx = STANDARD.encode(finalized_tx);

        let payload = serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "sendTransaction",
            "params": [encoded_tx, {"encoding": "base64"}]
        });

        let client = reqwest::Client::new();
        let res = client.post(&self.rpc_url).json(&payload).send().await
            .map_err(|e| AdapterError::Internal(format!("Solana RPC failed: {e}")))?;
            
        let body: serde_json::Value = res.json().await.map_err(|e| AdapterError::Internal(e.to_string()))?;
        
        // Safe indexing with .get() and idiomatic Option handling with map_or_else
        body.get("result")
            .and_then(|v| v.as_str())
            .map_or_else(
                || {
                    let err_msg = body.get("error").map_or_else(|| "Unknown error".to_string(), ToString::to_string);
                    Err(AdapterError::Internal(format!("Solana broadcast error: {err_msg}")))
                },
                |sig| Ok(sig.to_string()),
            )
    }

    /// Attaches an MPC-generated Ed25519 signature to a serialized Solana message.
    ///
    /// # Note on Solana Wire Format
    /// Solana's legacy transaction format is structured as:
    /// `[compact-u16 num_signatures] [signature_1 (64 bytes)] ... [signature_N] [serialized Message]`
    /// Since the MPC vault is the sole signer, `num_signatures` is 1, which encodes 
    /// to a single byte `0x01` in compact-u16 format.
    ///
    /// # Arguments
    ///
    /// * `unsigned_tx` - The serialized Solana `Message` bytes.
    /// * `signature` - The raw 64-byte Ed25519 signature produced by the MPC nodes.
    /// * `_pubkey_hex` - Ignored for Solana, as the signature is directly prepended 
    ///   to the message without needing to derive the public key at this stage.
    ///
    /// # Returns
    ///
    /// The fully signed transaction bytes ready for Base64 encoding and broadcast.
    ///
    /// # Errors
    ///
    /// Returns an [`AdapterError::InvalidTransaction`] if the signature is not exactly 64 bytes.
    async fn attach_signature(
        &self,
        unsigned_tx: &[u8], // This is the serialized Message
        signature: &[u8],   // 64 bytes ed25519 signature
        _pubkey_hex: &str,
    ) -> Result<Vec<u8>, AdapterError> {
        if signature.len() != 64 {
            return Err(AdapterError::InvalidTransaction("Solana signature must be exactly 64 bytes".into()));
        }

        // Solana legacy transaction wire format:
        // [compact-u16 num_signatures] [signature 1] ... [signature N] [serialized message]
        let mut signed_tx = Vec::new();
        signed_tx.push(1u8); // 1 signature (compact-u16 for 1 is just 0x01)
        signed_tx.extend_from_slice(signature);
        signed_tx.extend_from_slice(unsigned_tx);
        
        Ok(signed_tx)
    }

    /// Derives a Solana address from a raw Ed25519 public key.
    ///
    /// # Arguments
    ///
    /// * `pubkey` - The raw 32-byte Ed25519 public key.
    ///
    /// # Returns
    ///
    /// The Base58-encoded Solana address string.
    ///
    /// # Errors
    ///
    /// Returns an [`AdapterError::InvalidAddress`] if the provided key is not exactly 32 bytes.
    fn derive_address(&self, pubkey: &[u8]) -> Result<String, AdapterError> {
        // try_into handles the length check safely without unwrapping
        let arr: [u8; 32] = pubkey.try_into().map_err(|_| {
            AdapterError::InvalidAddress("ed25519 pubkey must be exactly 32 bytes".into())
        })?;
        Ok(Pubkey::new_from_array(arr).to_string())
    }
}

