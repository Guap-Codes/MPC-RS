//! # Solana Message Construction & Signing
//!
//! This module provides utilities for constructing, serializing, and hashing 
//! Solana transaction messages.
//!
//! In the MPC-RS architecture, the cryptographic nodes operate on raw Ed25519 
//! keypairs. This module bridges the gap by preparing the exact 32-byte digest 
//! (SHA-256 of the serialized legacy message) that the MPC nodes must sign to 
//! authorize a Solana transaction.

use solana_sdk::message::Message;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::hash::Hash;
use solana_sdk::instruction::Instruction;
use adapter_core::error::AdapterError;
use sha2::Digest; // Moved to top to satisfy `items_after_statements`

/// Compiles a list of Solana instructions into a Legacy Message.
///
/// A Solana `Message` contains the instructions to be executed, the list of 
/// account keys involved, and the recent blockhash that dictates the transaction's 
/// validity window (typically ~60-90 seconds).
///
/// # Arguments
///
/// * `fee_payer` - The public key that will pay the transaction fees (typically the MPC vault).
/// * `instructions` - A slice of [`Instruction`]s to be executed atomically.
/// * `recent_blockhash` - A recent blockhash fetched from the cluster to prevent replay attacks 
///   and ensure the transaction is processed in a timely manner.
///
/// # Returns
///
/// A compiled Solana [`Message`] ready for serialization and signing.
#[must_use]
pub fn build_message(
    fee_payer: &Pubkey,
    instructions: &[Instruction],
    recent_blockhash: &Hash,
) -> Message {
    Message::new_with_blockhash(instructions, Some(fee_payer), recent_blockhash)
}

/// Computes the 32-byte signing digest for a legacy Solana message.
///
/// Solana's Ed25519 signature scheme requires signing the SHA-256 hash of the 
/// serialized message bytes. This function performs that exact computation, 
/// producing the digest that the MPC threshold signing ceremony will sign.
///
/// # Arguments
///
/// * `message` - A reference to the compiled Solana [`Message`].
///
/// # Returns
///
/// A 32-byte array (`[u8; 32]`) representing the SHA-256 hash of the serialized message.
///
/// # Errors
///
/// Returns an [`AdapterError::Internal`] if the underlying hashing operation fails 
/// (though this is practically impossible with standard SHA-256 implementations).
pub fn signing_digest(message: &Message) -> Result<[u8; 32], AdapterError> {
    let message_data = message.serialize();
    let hash = sha2::Sha256::digest(&message_data);
    Ok(hash.into())
}

/// Serializes an unsigned Solana message to raw bytes.
///
/// This serialized byte array is passed to the MPC nodes for signing. Once signed, 
/// the signature is prepended to these exact bytes to form the final Solana 
/// transaction wire format.
///
/// # Arguments
///
/// * `message` - A reference to the compiled Solana [`Message`].
///
/// # Returns
///
/// A `Vec<u8>` containing the serialized message.
#[must_use]
pub fn serialize_message(message: &Message) -> Vec<u8> {
    message.serialize()
}

