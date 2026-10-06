//! # Centralized Error Handling
//!
//! This module defines the unified error types used across the entire MPC-RS ecosystem.
//! By standardizing errors, higher-level components (like the API Gateway and Coordinator) 
//! can handle failures consistently, map them to appropriate user-facing messages, 
//! and trigger the correct recovery or alerting workflows.

use thiserror::Error;

/// Represents all possible error conditions in the MPC-RS system.
#[derive(Error, Debug)]
pub enum MpcError {
    /// Errors related to the cryptographic threshold signature scheme (TSS).
    ///
    /// # Examples
    /// - Invalid state transitions during DKG or signing.
    /// - Malformed or unexpected P2P protocol messages.
    /// - Failure to aggregate partial signatures.
    #[error("TSS protocol error: {0}")]
    TssProtocol(String),

    /// Errors related to key generation, storage, or retrieval.
    ///
    /// # Examples
    /// - Failure to derive a BIP32 path.
    /// - Missing or corrupted key share files.
    #[error("Key management error: {0}")]
    KeyManagement(String),

    /// Errors originating from the Hardware Security Module (HSM) layer.
    ///
    /// # Examples
    /// - HSM device disconnected or unresponsive.
    /// - Authentication failure (e.g., invalid PIN).
    /// - Failure to wrap or unwrap key shares.
    #[error("HSM error: {0}")]
    Hsm(String),

    /// Errors related to network communication.
    ///
    /// # Examples
    /// - gRPC connection timeouts or drops.
    /// - TLS handshake failures.
    #[error("Network error: {0}")]
    Network(String),

    /// Errors related to system configuration or initialization.
    ///
    /// # Examples
    /// - Invalid or missing TOML configuration files.
    /// - Failure to parse environment variables.
    #[error("Configuration error: {0}")]
    Config(String),

    /// Errors related to authentication or authorization.
    ///
    /// # Examples
    /// - Invalid or expired JWT.
    /// - Missing required RBAC roles for an operation.
    #[error("Auth error: {0}")]
    Auth(String),

    /// Errors indicating a violation of the custody policy.
    ///
    /// # Examples
    /// - Attempting to sign a transaction to a blacklisted address.
    /// - Exceeding daily withdrawal limits.
    #[error("Policy violation: {0}")]
    PolicyViolation(String),

    /// Errors related to invalid input data.
    ///
    /// # Examples
    /// - Malformed JSON or Protobuf payloads.
    /// - Invalid cryptographic parameters (e.g., wrong curve).
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Catch-all for unexpected, unrecoverable, or internal state errors.
    #[error("Internal error: {0}")]
    Internal(String),
}

/// A convenience type alias for `Result<T, MpcError>`.
pub type MpcResult<T> = Result<T, MpcError>;


