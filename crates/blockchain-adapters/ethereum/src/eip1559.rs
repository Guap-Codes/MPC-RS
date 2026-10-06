//! # EIP-1559 Transaction Utilities
//!
//! This module provides the core logic for building, signing, and serializing 
//! EIP-1559 (Type 2) Ethereum transactions.
//!
//! It handles the strict requirements of the EIP-2718 Typed Transaction Envelope,
//! ensuring that payloads are correctly formatted for both MPC signing (sighash extraction)
//! and network submission (`eth_sendRawTransaction`).

use alloy_primitives::{Address, U256, Bytes, TxKind, B256, Signature};
use alloy_consensus::{TxEip1559, SignableTransaction, TxEnvelope};
use alloy_rlp::{Decodable, Encodable};
use adapter_core::error::AdapterError;

/// Builds a generic, unsigned EIP-1559 transaction.
///
/// # Arguments
///
/// * `to` - The recipient address (or `TxKind::Create` for contract deployment, though this builder defaults to `Call`).
/// * `value` - The amount of native ETH to transfer (in wei).
/// * `data` - The transaction calldata (empty for simple ETH transfers).
/// * `nonce` - The sender's current transaction nonce.
/// * `gas_limit` - The maximum gas allowed for the transaction.
/// * `max_fee_per_gas` - The maximum total fee per gas the sender is willing to pay.
/// * `max_priority_fee_per_gas` - The maximum tip to the block producer.
/// * `chain_id` - The EIP-155 chain ID to prevent replay attacks.
///
/// # Returns
///
/// A tuple containing:
/// 1. The unsigned transaction serialized as EIP-2718 typed RLP bytes (`0x02` + RLP payload).
/// 2. The 32-byte EIP-1559 signature hash (sighash) for MPC signing.
///
/// # Errors
///
/// Returns an [`AdapterError::InvalidTransaction`] if the RLP encoding fails 
/// (though this is practically impossible for valid inputs).
#[allow(clippy::too_many_arguments)]
pub fn build_eip1559_tx(
    to: Address,
    value: U256,
    data: Bytes,
    nonce: u64,
    gas_limit: u64,
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
    chain_id: u64,
) -> Result<(Vec<u8>, [u8; 32]), AdapterError> {
    let tx = TxEip1559 {
        chain_id,
        nonce,
        gas_limit,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        to: TxKind::Call(to),
        value,
        input: data,
        #[allow(clippy::default_trait_access)]
        access_list: Default::default(),
    };

    let sighash: B256 = tx.signature_hash();
    
    // EIP-2718 Typed Transaction Envelope: 0x02 || RLP(TxEip1559)
    let mut unsigned_rlp = Vec::new();
    unsigned_rlp.push(0x02);
    tx.encode(&mut unsigned_rlp);

    Ok((unsigned_rlp, sighash.0))
}

/// Computes the EIP-1559 signing digest from an unsigned RLP payload.
///
/// This is useful when the unsigned transaction was constructed externally 
/// and only the raw bytes are available. It validates the EIP-2718 type prefix 
/// before decoding and hashing.
///
/// # Arguments
///
/// * `unsigned_rlp` - The raw bytes of the unsigned transaction (must start with `0x02`).
///
/// # Returns
///
/// The 32-byte signature hash (sighash).
///
/// # Errors
///
/// Returns an [`AdapterError::InvalidTransaction`] if the payload does not start 
/// with the `0x02` prefix or if the RLP decoding fails.
#[allow(clippy::indexing_slicing)]
pub fn eip1559_signing_digest(unsigned_rlp: &[u8]) -> Result<[u8; 32], AdapterError> {
    let payload = if unsigned_rlp.first() == Some(&0x02) {
        &unsigned_rlp[1..]
    } else {
        return Err(AdapterError::InvalidTransaction("Expected EIP-1559 transaction (0x02 prefix)".into()));
    };

    let tx: TxEip1559 = TxEip1559::decode(&mut &payload[..])
        .map_err(|e| AdapterError::InvalidTransaction(format!("RLP decode failed: {e}")))?;

    Ok(tx.signature_hash().0)
}

/// Serializes the unsigned RLP payload to a `Vec<u8>`.
///
/// This is a convenience function to maintain a consistent API signature 
/// across different adapter modules, even though it is currently a direct passthrough.
#[must_use]
pub fn serialize_tx(unsigned_rlp: &[u8]) -> Vec<u8> {
    unsigned_rlp.to_vec()
}

/// Attaches an MPC-generated signature to an unsigned EIP-1559 transaction.
///
/// This function takes the raw 65-byte signature (r, s, v), constructs an 
/// Alloy `Signature` object, and correctly encodes the final EIP-2718 typed 
/// transaction envelope required by the `eth_sendRawTransaction` RPC endpoint.
///
/// # Arguments
///
/// * `unsigned_rlp` - The EIP-2718 encoded unsigned transaction bytes (starting with `0x02`).
/// * `signature` - The 65-byte raw signature produced by the MPC signing ceremony.
///
/// # Returns
///
/// The fully signed, EIP-2718 encoded transaction bytes ready for network broadcast.
///
/// # Errors
///
/// Returns an [`AdapterError::InvalidTransaction`] if:
/// - The signature is not exactly 65 bytes.
/// - The unsigned payload does not start with the `0x02` prefix.
/// - The RLP decoding of the unsigned payload fails.
///
/// # Note on V-Parity
///
/// MPC libraries may output the `v` value (recovery ID) as either `0/1` (modern EIP-155 style) 
/// or `27/28` (legacy style). This function normalizes the `v` value to a boolean parity 
/// (`true` for odd/27, `false` for even/28) as expected by the `alloy` crate.
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
pub fn attach_signature_to_tx(
    unsigned_rlp: &[u8],
    signature: &[u8],
) -> Result<Vec<u8>, AdapterError> {
    if signature.len() != 65 {
        return Err(AdapterError::InvalidTransaction("Signature must be exactly 65 bytes".into()));
    }

    let payload = if unsigned_rlp.first() == Some(&0x02) {
        &unsigned_rlp[1..]
    } else {
        return Err(AdapterError::InvalidTransaction("Expected EIP-1559 transaction (0x02 prefix)".into()));
    };

    let tx: TxEip1559 = TxEip1559::decode(&mut &payload[..])
        .map_err(|e| AdapterError::InvalidTransaction(format!("RLP decode failed: {e}")))?;

    // Extract r, s, and v from the 65-byte signature
    let r = U256::from_be_slice(&signature[0..32]);
    let s = U256::from_be_slice(&signature[32..64]);
    
    // Normalize v parity: handle both legacy (27/28) and modern (0/1) recovery IDs
    let v_parity = if signature[64] >= 27 {
        (signature[64] - 27) != 0
    } else {
        signature[64] != 0
    };

    let sig = Signature::new(r, s, v_parity);
    
    // EIP-2718 Encoding:
    // TxEnvelope::encode() wraps typed transactions in an RLP string (e.g., b8 78 ...) 
    // because that is how they are stored inside Ethereum block headers.
    // However, the `eth_sendRawTransaction` RPC endpoint expects the raw EIP-2718 
    // network bytes: `0x02 || RLP(SignedTxEip1559)`.
    // We manually push the `0x02` type byte and encode the inner signed payload to match RPC expectations.
    let signed_tx = tx.into_signed(sig);
    let mut signed_rlp = Vec::new();
    signed_rlp.push(0x02);
    signed_tx.rlp_encode(&mut signed_rlp);
    
    Ok(signed_rlp)
}

