//! # Bitcoin Blockchain Adapter
//!
//! This crate provides a production-grade implementation of the [`BlockchainAdapter`] 
//! trait for the Bitcoin network. It handles the complete lifecycle of a Bitcoin 
//! transaction, from UTXO selection and fee estimation to PSBT (Partially Signed 
//! Bitcoin Transaction) construction, MPC signature attachment, and network broadcasting.
//!
//! ## Architecture
//! The `BitcoinAdapter` is designed to be generic over its `UtxoProvider` and 
//! `FeeEstimator` dependencies. This allows the adapter to be seamlessly integrated 
//! with different backend services (e.g., Mempool.space API for mainnet, or a local 
//! Nigiri/Esplora node for regtest) without modifying the core transaction-building logic.

pub mod address;
pub mod psbt;
pub mod transaction;
pub mod utxo_provider;
pub mod fee_estimator;

use adapter_core::traits::{BlockchainAdapter, AdapterResult, FeeEstimator, UtxoProvider};
use adapter_core::error::AdapterError;
use async_trait::async_trait;
use bitcoin::{Network, Transaction};

/// A Bitcoin adapter that builds, signs, and broadcasts PSBTs.
///
/// This struct implements the core [`BlockchainAdapter`] trait for Bitcoin. It is 
/// generic over the `UtxoProvider` and `FeeEstimator` traits, allowing for flexible 
/// dependency injection based on the deployment environment (e.g., mainnet vs. testnet).
pub struct BitcoinAdapter<U: UtxoProvider, F: FeeEstimator> {
    /// The target Bitcoin network (e.g., `Network::Bitcoin`, `Network::Testnet`).
    pub network: Network,
    /// The service responsible for fetching unspent transaction outputs.
    pub utxo_provider: U,
    /// The service responsible for estimating dynamic network fees.
    pub fee_estimator: F,
}

impl<U: UtxoProvider, F: FeeEstimator> BitcoinAdapter<U, F> {
    /// Creates a new `BitcoinAdapter` with the specified network and dependencies.
    ///
    /// # Arguments
    ///
    /// * `network` - The Bitcoin network to target.
    /// * `utxo_provider` - An implementation of [`UtxoProvider`] for fetching UTXOs.
    /// * `fee_estimator` - An implementation of [`FeeEstimator`] for calculating fees.
    #[allow(clippy::missing_const_for_fn)] // Generic trait bounds prevent const fn compilation
    pub fn new(network: Network, utxo_provider: U, fee_estimator: F) -> Self {
        Self { network, utxo_provider, fee_estimator }
    }
}

#[async_trait]
impl<U: UtxoProvider, F: FeeEstimator> BlockchainAdapter for BitcoinAdapter<U, F> {
    /// Constructs an unsigned PSBT and returns its serialized bytes along with the sighash.
    ///
    /// This method fetches a suitable UTXO, estimates the network fee, and constructs 
    /// a `SegWit` V0 PSBT. It includes both the `witness_utxo` and, if provided, the 
    /// `non_witness_utxo` to ensure compatibility with hardware wallet signing policies.
    ///
    /// # Arguments
    ///
    /// * `from` - The source address (used to query the `UtxoProvider`).
    /// * `to` - The destination Bitcoin address.
    /// * `amount` - The amount to send (e.g., "0.5" or "all").
    /// * `_token` - Ignored for Bitcoin, as it is a UTXO-based chain without native tokens.
    /// * `change_address` - An optional address to receive leftover funds. If `None`, 
    ///   the `from` address is used as the change destination.
    /// * `previous_tx_hex` - An optional hex-encoded raw previous transaction. Required 
    ///   by some MPC nodes/hardware wallets to validate the `non_witness_utxo`.
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// 1. The Base64-encoded serialized PSBT bytes.
    /// 2. The 32-byte `SegWit` V0 sighash that the MPC nodes must sign.
    async fn build_unsigned_tx(
        &self,
        from: &str,
        to: &str,
        amount: &str,
        _token: Option<&str>,
        change_address: Option<&str>,
        previous_tx_hex: Option<&str>,
    ) -> AdapterResult<(Vec<u8>, [u8; 32])> {
        let prev_tx = if let Some(hex) = previous_tx_hex {
            let bytes = hex::decode(hex)
                .map_err(|e| AdapterError::InvalidTransaction(format!("Invalid hex for prev_tx: {e}")))?;
            Some(bitcoin::consensus::deserialize::<Transaction>(&bytes)
                .map_err(|e| AdapterError::InvalidTransaction(format!("Invalid prev_tx: {e}")))?)
        } else {
            None
        };

        // Fetch real UTXO via the injected provider
        let utxo = self.utxo_provider.get_utxo(from).await?;

        // Estimate fee based on a standard P2WPKH spend (approx. 140 vBytes)
        let estimated_vsize = 140;
        let fee_sats = self.fee_estimator.estimate_fee_sats(estimated_vsize).await?;
        
        let psbt = psbt::create_psbt(
            &utxo, 
            to, 
            amount, 
            fee_sats, 
            self.network,
            change_address,
            prev_tx.as_ref(),
        )?;
        
        let tx = transaction::unsigned_tx_from_psbt(&psbt)?;
        let digest = transaction::segwit_v0_digest(&tx, 0, &utxo.tx_out)?;
        let serialized = psbt::serialize_psbt_bytes(&psbt)?;
        
        Ok((serialized, digest))
    }

    /// Broadcasts a finalized, signed transaction to the Bitcoin network.
    ///
    /// This method decodes the Base64 PSBT, extracts the underlying `Transaction`, 
    /// serializes it to raw hex, and submits it to a Mempool.space-compatible API 
    /// corresponding to the adapter's configured `Network`.
    ///
    /// # Arguments
    ///
    /// * `finalized_tx` - The Base64-encoded, fully signed and finalized PSBT.
    ///
    /// # Returns
    ///
    /// The transaction ID (TXID) as a hex string upon successful broadcast.
    async fn broadcast(&self, finalized_tx: &[u8]) -> Result<String, AdapterError> {
        let psbt_base64 = std::str::from_utf8(finalized_tx)
            .map_err(|_| AdapterError::InvalidTransaction("Invalid UTF-8 PSBT".into()))?;
            
        let tx = crate::psbt::extract_transaction(psbt_base64)?;
        let raw_tx_hex = hex::encode(bitcoin::consensus::serialize(&tx));

        let url = match self.network {
            Network::Bitcoin => "https://mempool.space/api/tx",
            Network::Signet  => "https://mempool.space/signet/api/tx",
            _ => "https://mempool.space/testnet/api/tx", // Defaults to testnet for Testnet, Regtest, etc.
        };

        let client = reqwest::Client::new();
        let res = client.post(url).body(raw_tx_hex).send().await
            .map_err(|e| AdapterError::Internal(format!("Mempool broadcast failed: {e}")))?;

        if res.status().is_success() {
            res.text().await.map_err(|e| AdapterError::Internal(e.to_string()))
        } else {
            let err = res.text().await.unwrap_or_default();
            Err(AdapterError::Internal(format!("Mempool rejected TX: {err}")))
        }
    }

    /// Attaches an MPC-generated signature to the PSBT and finalizes it.
    ///
    /// This method takes the unsigned PSBT, the raw signature bytes, and the signer's 
    /// public key. It injects the partial signature into the PSBT, manually finalizes 
    /// the P2WPKH input by constructing the final witness, and returns the finalized 
    /// Base64 PSBT ready for extraction and broadcasting.
    ///
    /// # Arguments
    ///
    /// * `unsigned_tx` - The Base64-encoded unsigned PSBT.
    /// * `signature` - The raw signature bytes (supports both 65-byte compact and DER formats).
    /// * `pubkey_hex` - The hex-encoded compressed public key of the signer.
    ///
    /// # Returns
    ///
    /// The Base64-encoded, fully finalized PSBT.
    async fn attach_signature(
        &self,
        unsigned_tx: &[u8],
        signature: &[u8],
        pubkey_hex: &str,
    ) -> AdapterResult<Vec<u8>> {
        let psbt_base64 = std::str::from_utf8(unsigned_tx)
            .map_err(|_| AdapterError::InvalidTransaction("PSBT must be valid UTF-8 (Base64)".into()))?;
            
        let pubkey_bytes = hex::decode(pubkey_hex)
            .map_err(|e| AdapterError::InvalidTransaction(format!("Invalid pubkey hex: {e}")))?;
        
        let signed_psbt_base64 = psbt::update_psbt_with_signature(psbt_base64, signature, 0, &pubkey_bytes)?;
        let finalized_psbt = psbt::finalize_psbt(&signed_psbt_base64)?;
        
        Ok(finalized_psbt.into_bytes())
    }

    /// Derives a Native `SegWit` (P2WPKH) Bitcoin address from a raw public key.
    ///
    /// # Arguments
    ///
    /// * `pubkey` - The raw, compressed public key bytes (must be exactly 33 bytes).
    ///
    /// # Returns
    ///
    /// The Bech32-encoded P2WPKH address string (e.g., `bc1q...`).
    fn derive_address(&self, pubkey: &[u8]) -> AdapterResult<String> {
        address::derive_p2wpkh(pubkey, self.network)
    }
}

