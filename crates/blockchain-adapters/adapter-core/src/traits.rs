use crate::error::AdapterError;
use crate::types::Utxo;
use async_trait::async_trait;
use bitcoin::{Transaction, Txid};

/// A convenience type alias for results returned by blockchain adapters.
pub type AdapterResult<T> = Result<T, AdapterError>;

/// The core trait that all chain-specific adapters must implement.
///
/// This trait abstracts the lifecycle of a blockchain transaction, from initial 
/// construction to network submission. It allows the MPC-RS API and Coordinator 
/// to interact with any supported blockchain through a uniform interface, without 
/// needing to know chain-specific details like RLP encoding, UTXO selection, or 
/// nonce management.
#[allow(clippy::double_must_use)] // Suppresses false positive from async_trait macro expansion
#[async_trait]
pub trait BlockchainAdapter: Send + Sync {
    /// Constructs an unsigned transaction and returns the serialized bytes along 
    /// with the cryptographic digest (sighash) that needs to be signed by the MPC nodes.
    ///
    /// # Arguments
    ///
    /// * `from` - The source address (e.g., the MPC vault address).
    /// * `to` - The destination address.
    /// * `amount` - The amount to transfer (human-readable, e.g., "0.5" or "all").
    /// * `token` - An optional token contract address (e.g., for ERC-20 or SPL tokens).
    /// * `change_address` - An optional address to receive leftover funds (primarily for UTXO chains).
    /// * `previous_tx_hex` - An optional hex-encoded raw previous transaction. This is strictly 
    ///   required for Bitcoin `SegWit` transactions to satisfy hardware wallet non-witness UTXO 
    ///   validation rules. For account-based chains (like Ethereum), this is typically `None`.
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// 1. The serialized unsigned transaction bytes (or JSON map, depending on the chain).
    /// 2. The 32-byte digest (sighash) that the MPC nodes must sign.
    async fn build_unsigned_tx(
        &self,
        from: &str,
        to: &str,
        amount: &str,
        token: Option<&str>,
        change_address: Option<&str>,
        previous_tx_hex: Option<&str>,
    ) -> AdapterResult<(Vec<u8>, [u8; 32])>;

    /// Attaches an MPC-generated threshold signature to an unsigned transaction.
    ///
    /// # Arguments
    ///
    /// * `unsigned_tx` - The serialized unsigned transaction bytes returned by `build_unsigned_tx`.
    /// * `signature` - The raw signature bytes produced by the MPC signing ceremony 
    ///   (e.g., 64-byte ECDSA for Ethereum, 65-byte with recovery ID, or 64-byte `EdDSA` for Solana).
    /// * `pubkey_hex` - The hex-encoded public key corresponding to the signer. Required by 
    ///   some chains (like Bitcoin or XRP) to embed the public key or derive the address 
    ///   during transaction finalization.
    ///
    /// # Returns
    ///
    /// The fully serialized, signed transaction blob ready for network broadcast.
    async fn attach_signature(
        &self,
        unsigned_tx: &[u8],
        signature: &[u8],
        pubkey_hex: &str,
    ) -> AdapterResult<Vec<u8>>;

    /// Broadcasts a finalized, signed transaction to the blockchain network via RPC.
    ///
    /// # Arguments
    ///
    /// * `finalized_tx` - The serialized signed transaction blob returned by `attach_signature`.
    ///
    /// # Returns
    ///
    /// The transaction hash or ID as a string (e.g., `0x...` for Ethereum, reversed hex for Bitcoin).
    async fn broadcast(&self, finalized_tx: &[u8]) -> AdapterResult<String>;

    /// Derives the chain-specific human-readable address from a raw public key.
    ///
    /// # Arguments
    ///
    /// * `pubkey` - The raw public key bytes (e.g., 33-byte compressed secp256k1 or 32-byte ed25519).
    ///
    /// # Returns
    ///
    /// The formatted address string (e.g., `bc1q...` for Bitcoin, `0x...` for Ethereum, `r...` for XRP).
    ///
    /// # Errors
    ///
    /// Returns an [`AdapterError`] if the public key is invalid, malformed, or if the
    /// address derivation process fails for the specific chain.
    fn derive_address(&self, pubkey: &[u8]) -> AdapterResult<String>;
}

/// A trait for estimating network transaction fees.
///
/// Different chains calculate fees differently (e.g., satoshis per virtual byte for Bitcoin, 
/// max fee per gas for Ethereum). This trait provides a unified way for the API to request 
/// fee estimates before building a transaction.
#[allow(clippy::double_must_use)] 
#[async_trait]
pub trait FeeEstimator: Send + Sync {
    /// Estimates the total fee in the chain's base unit (e.g., satoshis for Bitcoin).
    ///
    /// # Arguments
    ///
    /// * `vsize` - The estimated virtual size of the transaction (in vBytes for Bitcoin, 
    ///   or gas limit for EVM chains).
    ///
    /// # Returns
    ///
    /// The estimated fee amount.
    async fn estimate_fee_sats(&self, vsize: usize) -> AdapterResult<u64>;
}

/// A trait for fetching Unspent Transaction Outputs (UTXOs) and historical transaction data.
///
/// This is primarily used by UTXO-based chains (like Bitcoin) to select inputs for a new 
/// transaction and to provide the full previous transaction data required for `SegWit` signing.
#[allow(clippy::double_must_use)]
#[async_trait]
pub trait UtxoProvider: Send + Sync {
    /// Fetches a suitable unspent transaction output for a given address.
    ///
    /// # Arguments
    ///
    /// * `address` - The address to fetch UTXOs for.
    ///
    /// # Returns
    ///
    /// A [`Utxo`] struct containing the outpoint and the transaction output details.
    async fn get_utxo(&self, address: &str) -> AdapterResult<Utxo>;
    
    /// Fetches the full, raw previous transaction for a given transaction ID.
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
    async fn get_previous_transaction(&self, txid: &Txid) -> AdapterResult<Transaction>;
}
