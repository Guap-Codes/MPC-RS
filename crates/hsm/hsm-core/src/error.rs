//! # Hardware Security Module Errors
//!
//! This module defines the unified error types used across all HSM implementations
//! within the MPC-RS ecosystem. By standardizing errors, the higher-level MPC node
//! logic can handle device failures, connection drops, and cryptographic errors consistently.

use thiserror::Error;

/// Represents all possible errors that can occur during HSM operations.
///
/// This enum covers the full spectrum of failures, from physical device
/// disconnection and I/O failures to protocol-level communication errors
/// and missing key material.
#[derive(Error, Debug)]
pub enum HsmError {
    /// Returned when a local filesystem or network I/O operation fails.
    ///
    /// # Examples
    /// - Failing to read or write an encrypted key share blob to disk.
    /// - A network timeout when communicating with a remote HSM service (e.g., AWS CloudHSM).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Returned when serializing or deserializing data fails.
    ///
    /// # Examples
    /// - Failing to decode a Base64-encoded wrapped key.
    /// - Protobuf or JSON parsing errors during HSM communication.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Returned when a requested key or key share cannot be found.
    ///
    /// # Examples
    /// - Attempting to retrieve a key share for a vault that has not yet completed DKG.
    /// - The underlying HSM reports that the specified key label does not exist.
    #[error("Key not found: {0}")]
    KeyNotFound(String),

    /// Returned when a requested operation is not supported by the specific
    /// HSM implementation or its current configuration.
    ///
    /// # Examples
    /// - Attempting to use the `sign` method on an HSM that is strictly configured
    ///   for key wrapping/unwrapping only (as is common in the MPC-RS architecture).
    #[error("Operation not supported: {0}")]
    Unsupported(String),

    /// Returned for unexpected, unrecoverable, or internal state errors
    /// within the HSM abstraction layer or the underlying hardware.
    ///
    /// # Examples
    /// - The HSM returns an undocumented error code.
    /// - A PKCS#11 session becomes invalidated unexpectedly.
    #[error("Internal HSM error: {0}")]
    Internal(String),
}

