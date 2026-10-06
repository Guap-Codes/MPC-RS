//! # Bitcoin Transaction Utilities
//!
//! This module provides utilities for extracting unsigned transactions from PSBTs
//! and computing the cryptographic signature digests required for `SegWit` V0 (P2WPKH) inputs.
//!
//! In the MPC-RS architecture, the cryptographic nodes operate on raw elliptic curve points.
//! This module bridges the gap by preparing the exact 32-byte digest that the MPC nodes
//! must sign to authorize the spending of a Bitcoin UTXO.

use bitcoin::{Transaction, TxOut};
use bitcoin::psbt::Psbt;
use adapter_core::error::AdapterError;

use bitcoin::hashes::Hash;

/// Extracts the unsigned transaction from a Partially Signed Bitcoin Transaction (PSBT).
///
/// # Arguments
///
/// * `psbt` - A reference to the [`Psbt`] object.
///
/// # Returns
///
/// A cloned [`bitcoin::Transaction`] representing the unsigned transaction.
///
/// # Errors
///
/// This function currently does not return any errors, but returns a `Result` to maintain 
/// API consistency with other transaction extraction utilities that may fail.
pub fn unsigned_tx_from_psbt(psbt: &Psbt) -> Result<Transaction, AdapterError> {
    Ok(psbt.unsigned_tx.clone())
}

/// Computes the `SegWit` V0 signature digest (Sighash) for a specific input.
///
/// This function calculates the double SHA-256 hash of the sighash preimage, which is the
/// exact 32-byte digest that the MPC nodes must sign to authorize the spending of a P2WPKH input.
///
/// # Arguments
///
/// * `tx` - A reference to the unsigned [`Transaction`].
/// * `input_index` - The index of the input being signed (typically `0` for single-input transactions).
/// * `prev_output` - A reference to the [`TxOut`] being spent, containing the `script_pubkey` and `value`.
///
/// # Returns
///
/// A 32-byte array (`[u8; 32]`) representing the signature digest.
///
/// # Errors
///
/// Returns an [`AdapterError::Internal`] if the underlying `bitcoin` crate fails to compute the sighash
/// (e.g., if the `input_index` is out of bounds for the transaction).
pub fn segwit_v0_digest(
    tx: &Transaction,
    input_index: usize,
    prev_output: &TxOut,
) -> Result<[u8; 32], AdapterError> {
    use bitcoin::sighash::{SighashCache, EcdsaSighashType};
    
    let mut cache = SighashCache::new(tx);
    
    let sighash = cache.p2wpkh_signature_hash(
        input_index, 
        &prev_output.script_pubkey, 
        prev_output.value, 
        EcdsaSighashType::All
    ).map_err(|e| AdapterError::Internal(format!("Sighash computation failed: {e}")))?;
    
    Ok(sighash.to_byte_array())
}






