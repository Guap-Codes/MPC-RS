//! # Bitcoin PSBT (Partially Signed Bitcoin Transaction) Utilities
//!
//! This module provides robust, BIP-174 compliant utilities for constructing, 
//! updating, finalizing, and extracting Bitcoin transactions using the PSBT format.
//!
//! In the MPC-RS architecture, the PSBT serves as the canonical format for passing 
//! unsigned transaction state between the API Gateway, the MPC Coordinator, and the 
//! cryptographic nodes, ensuring all necessary metadata (like `witness_utxo`) is preserved.

use bitcoin::{Amount, Address, Network, Transaction, TxIn, TxOut, ScriptBuf, Sequence, absolute::LockTime};
use bitcoin::psbt::Psbt;
use adapter_core::error::AdapterError;
use adapter_core::types::Utxo;

use std::str::FromStr;

// Use the base64 crate for explicit BIP-174 Base64 encoding/decoding
use base64::{Engine as _, engine::general_purpose::STANDARD};

/// Builds a PSBT with one input, one primary output, and an optional change output.
///
/// This function handles the core logic of Bitcoin transaction construction, including 
/// parsing addresses, calculating the "drain all" amount (total input minus fee), 
/// and ensuring change outputs meet the standard dust limit (546 satoshis).
///
/// # Arguments
///
/// * `utxo` - The unspent transaction output to be spent as the sole input.
/// * `to` - The destination Bitcoin address string.
/// * `amount` - The amount to send (e.g., "0.5" or "all").
/// * `fee_sats` - The total network fee in satoshis to deduct from the input.
/// * `network` - The target Bitcoin network (used for address validation).
/// * `change_address` - An optional address to receive leftover funds. If `None`, 
///   the input's original `script_pubkey` is used as the change destination.
/// * `previous_tx` - An optional reference to the full previous transaction. If provided, 
///   it is attached as `non_witness_utxo` to satisfy strict hardware wallet validation rules.
///
/// # Returns
///
/// A fully constructed, unsigned [`Psbt`] object ready for MPC signing.
///
/// # Errors
///
/// Returns an [`AdapterError`] if:
/// - The `to` or `change_address` strings are invalid or do not match the target `network`.
/// - The `amount` is malformed or exceeds the available UTXO value (after deducting fees).
/// - The PSBT fails to serialize from the unsigned transaction.
pub fn create_psbt(
    utxo: &Utxo, 
    to: &str, 
    amount: &str, 
    fee_sats: u64,
    network: Network,
    change_address: Option<&str>,
    previous_tx: Option<&Transaction>,
) -> Result<Psbt, AdapterError> {
    let to_addr = Address::from_str(to)
        .map_err(|e| AdapterError::InvalidAddress(e.to_string()))?
        .require_network(network)
        .map_err(|e| AdapterError::InvalidAddress(e.to_string()))?;
        
    let fee_value = Amount::from_sat(fee_sats);
    let total_input = utxo.tx_out.value;

    // Handle "all" by sending total_input minus the fee
    let send_value = if amount == "all" {
        if total_input <= fee_value {
            return Err(AdapterError::InvalidAmount("insufficient funds to cover fee".into()));
        }
        total_input.checked_sub(fee_value).ok_or_else(|| AdapterError::InvalidAmount("fee exceeds total input".into()))?
    } else {
        let val = Amount::from_str(amount).map_err(|e| AdapterError::InvalidAmount(e.to_string()))?;
        let total_required = val.checked_add(fee_value).ok_or_else(|| AdapterError::InvalidAmount("amount + fee overflows".into()))?;
        if total_input < total_required {
            return Err(AdapterError::InvalidAmount("insufficient funds for amount + fee".into()));
        }
        val
    };

    let mut outputs = vec![TxOut {
        value: send_value,
        script_pubkey: to_addr.script_pubkey(),
    }];

    // Add change output if there's leftover value after fee (above standard P2WPKH dust limit)
    let change_value = total_input
        .checked_sub(send_value)
        .and_then(|v| v.checked_sub(fee_value))
        .unwrap_or(Amount::ZERO);
        
    if change_value > Amount::from_sat(546) { 
        let change_script = if let Some(addr_str) = change_address {
            Address::from_str(addr_str)
                .map_err(|e| AdapterError::InvalidAddress(e.to_string()))?
                .require_network(network)
                .map_err(|e| AdapterError::InvalidAddress(e.to_string()))?
                .script_pubkey()
        } else {
            utxo.tx_out.script_pubkey.clone()
        };
        
        outputs.push(TxOut {
            value: change_value,
            script_pubkey: change_script,
        });
    }

    let unsigned_tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: utxo.outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: bitcoin::Witness::new(),
        }],
        output: outputs,
    };

    let mut psbt = Psbt::from_unsigned_tx(unsigned_tx)
        .map_err(|e| AdapterError::Internal(format!("Failed to create PSBT: {e}")))?;

    if let Some(input) = psbt.inputs.get_mut(0) {
        // Always include witness_utxo for SegWit V0
        input.witness_utxo = Some(utxo.tx_out.clone());
        // Include non_witness_utxo if provided, for maximum hardware wallet compatibility
        if let Some(prev_tx) = previous_tx {
            input.non_witness_utxo = Some(prev_tx.clone());
        }
    }

    Ok(psbt)
}

/// Serializes a PSBT to raw bytes using BIP-174 Base64 encoding.
///
/// # Arguments
///
/// * `psbt` - A reference to the [`Psbt`] object to serialize.
///
/// # Returns
///
/// A `Vec<u8>` containing the UTF-8 encoded Base64 string of the PSBT.
///
/// # Errors
///
/// Returns an [`AdapterError::Internal`] if the underlying serialization or encoding process fails.
pub fn serialize_psbt_bytes(psbt: &Psbt) -> Result<Vec<u8>, AdapterError> {
    let raw = psbt.serialize();
    Ok(STANDARD.encode(raw).into_bytes())
}

/// Attaches an MPC-generated partial signature to a specific input of a Base64-encoded PSBT.
///
/// This function is designed to be flexible, accepting either a 65-byte compact signature 
/// (r, s, sighash) or a variable-length DER signature, as different MPC implementations 
/// may output different formats.
///
/// # Arguments
///
/// * `psbt_base64` - The Base64-encoded unsigned PSBT.
/// * `signature` - The raw signature bytes produced by the MPC signing ceremony.
/// * `input_index` - The index of the input to sign (typically `0` for single-input PSBTs).
/// * `pubkey_bytes` - The raw, compressed public key bytes of the signer.
///
/// # Returns
///
/// The Base64-encoded PSBT with the new partial signature inserted.
///
/// # Errors
///
/// Returns an [`AdapterError`] if the Base64 decoding fails, the PSBT is malformed, 
/// the `input_index` is out of bounds, or the signature/pubkey cannot be parsed.
pub fn update_psbt_with_signature(
    psbt_base64: &str,
    signature: &[u8],
    input_index: usize,
    pubkey_bytes: &[u8],
) -> Result<String, AdapterError> {
    let raw = STANDARD.decode(psbt_base64)
        .map_err(|e| AdapterError::Internal(format!("Failed to decode Base64 PSBT: {e}")))?;
        
    let mut psbt = Psbt::deserialize(&raw)
        .map_err(|e| AdapterError::Internal(format!("Failed to deserialize PSBT: {e}")))?;
        
    let input = psbt.inputs.get_mut(input_index)
        .ok_or_else(|| AdapterError::InvalidTransaction("input index out of range".into()))?;
    
    // Handle both 65-byte compact signatures and variable-length DER signatures
    let bitcoin_sig = if signature.len() == 65 {
        bitcoin::ecdsa::Signature::from_slice(signature)
            .map_err(|e| AdapterError::Internal(format!("Invalid compact signature: {e}")))?
    } else {
        let _secp = bitcoin::secp256k1::Secp256k1::verification_only();
        let sig = bitcoin::secp256k1::ecdsa::Signature::from_der(signature)
            .map_err(|e| AdapterError::Internal(format!("Invalid DER signature: {e}")))?;
        // Use the provided constructor for sighash_all to correctly map fields
        bitcoin::ecdsa::Signature::sighash_all(sig)
    };
        
    let pk = bitcoin::PublicKey::from_slice(pubkey_bytes)
        .map_err(|e| AdapterError::InvalidAddress(format!("Invalid pubkey: {e}")))?;
        
    // Insert the partial signature into the PSBT input
    input.partial_sigs.insert(pk, bitcoin_sig);
    
    // Re-serialize and Base64 encode the updated PSBT
    let raw = psbt.serialize();
    Ok(STANDARD.encode(raw))
}

/// Finalizes a PSBT by constructing the final witness for P2WPKH inputs.
///
/// As of `bitcoin` crate version 0.32+, the `finalize_mut` method was removed. 
/// This function provides the recommended manual finalization approach for Native 
/// `SegWit` (P2WPKH) inputs, clearing temporary signing data and setting the 
/// `final_script_witness` as per BIP-174 specifications.
///
/// # Arguments
///
/// * `psbt_base64` - The Base64-encoded PSBT containing at least one valid partial signature.
///
/// # Returns
///
/// The Base64-encoded, fully finalized PSBT ready for transaction extraction.
///
/// # Errors
///
/// Returns an [`AdapterError`] if the PSBT is malformed, lacks a `witness_utxo`, 
/// is missing the required partial signature, or attempts to finalize a non-P2WPKH script.
pub fn finalize_psbt(psbt_base64: &str) -> Result<String, AdapterError> {
    let raw = STANDARD.decode(psbt_base64)
        .map_err(|e| AdapterError::Internal(format!("Failed to decode Base64 PSBT: {e}")))?;
        
    let mut psbt = Psbt::deserialize(&raw)
        .map_err(|e| AdapterError::Internal(format!("Failed to deserialize PSBT: {e}")))?;
        
    for input in &mut psbt.inputs {
        // Manual finalization for P2WPKH
        if let Some(witness_utxo) = &input.witness_utxo {
            if witness_utxo.script_pubkey.is_p2wpkh() {
                if let Some((pk, sig)) = input.partial_sigs.iter().next() {
                    let mut witness = bitcoin::Witness::new();
                    witness.push(sig.to_vec());
                    witness.push(pk.to_bytes());
                    
                    // Use the BIP-174 standard final_script_witness and final_script_sig fields
                    input.final_script_witness = Some(witness);
                    input.final_script_sig = Some(ScriptBuf::new());
                    
                    // Clear signing data as per BIP 174 finalization rules
                    input.partial_sigs.clear();
                    input.sighash_type = None;
                    input.redeem_script = None;
                    input.witness_script = None;
                    input.bip32_derivation.clear();
                } else {
                    return Err(AdapterError::InvalidTransaction("Missing partial signature for P2WPKH input".into()));
                }
            } else {
                return Err(AdapterError::InvalidTransaction("Only P2WPKH finalization is supported in this adapter".into()));
            }
        } else {
            return Err(AdapterError::InvalidTransaction("Missing witness_utxo for finalization".into()));
        }
    }
    
    let raw = psbt.serialize();
    Ok(STANDARD.encode(raw))
}

/// Extracts the fully signed, ready-to-broadcast `Transaction` from a finalized PSBT.
///
/// # Arguments
///
/// * `psbt_base64` - The Base64-encoded, finalized PSBT.
///
/// # Returns
///
/// The extracted [`bitcoin::Transaction`] object.
///
/// # Errors
///
/// Returns an [`AdapterError`] if the PSBT cannot be decoded, deserialized, or if 
/// the extraction fails (e.g., if the PSBT is not fully finalized).
pub fn extract_transaction(psbt_base64: &str) -> Result<Transaction, AdapterError> {
    let raw = STANDARD.decode(psbt_base64)
        .map_err(|e| AdapterError::Internal(format!("Failed to decode Base64 PSBT: {e}")))?;
        
    let psbt = Psbt::deserialize(&raw)
        .map_err(|e| AdapterError::Internal(format!("Failed to deserialize PSBT: {e}")))?;
        
    psbt.extract_tx()
        .map_err(|e| AdapterError::InvalidTransaction(format!("Failed to extract transaction: {e}")))
}

