//! # Adapter Core Errors
//!
//! This module defines the unified error types used across all blockchain adapters
//! in the MPC-RS ecosystem. By standardizing errors, the coordinator and API gateway
//! can handle adapter failures consistently, regardless of the underlying chain.

use thiserror::Error;

/// Represents all possible errors that can occur during blockchain adapter operations.
///
/// This enum covers the full spectrum of failures an adapter might encounter,
/// from user-input validation failures to underlying network or RPC issues.
/// It is designed to be easily mapped to appropriate HTTP/gRPC status codes
/// by the higher-level API and Coordinator layers.
#[derive(Error, Debug)]
pub enum AdapterError {
    /// Returned when a provided wallet address cannot be parsed or is malformed 
    /// for the specific chain.
    ///
    /// # Examples
    /// - An Ethereum address that is not exactly 20 bytes (40 hex characters).
    /// - A Bitcoin address with an invalid Bech32 or `Base58Check` checksum.
    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    /// Returned when the transaction amount is malformed, negative, or insufficient 
    /// to cover network fees.
    ///
    /// # Examples
    /// - Attempting to send a negative value.
    /// - Attempting a "drain all" operation where the balance is less than the 
    ///   estimated gas/fee cost.
    /// - A token amount that exceeds the maximum representable value (e.g., u256 overflow).
    #[error("Invalid amount: {0}")]
    InvalidAmount(String),

    /// Returned when a transaction payload is malformed, missing required fields, 
    /// or fails cryptographic/structural validation.
    ///
    /// # Examples
    /// - An attached signature is the wrong length (e.g., 64 bytes instead of 65 for Ethereum).
    /// - A Bitcoin PSBT is missing required UTXO witness data.
    /// - The serialized transaction blob cannot be decoded by the chain's rules.
    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),

    /// Returned when a requested operation, token type, or chain-specific feature 
    /// is not implemented or supported by this specific adapter.
    ///
    /// # Examples
    /// - Attempting to build an ERC-20 transfer on an adapter that only supports native ETH.
    /// - Requesting a UTXO-based operation on an account-based chain like Ethereum.
    #[error("Unsupported operation: {0}")]
    Unsupported(String),

    /// Returned for unexpected, unrecoverable, or external failures.
    ///
    /// # Examples
    /// - RPC node timeouts or network connectivity issues.
    /// - Serialization/deserialization failures (e.g., JSON parsing errors).
    /// - Underlying HSM or cryptographic library panics/errors.
    #[error("Internal error: {0}")]
    Internal(String),
}
