//! # Cryptographic Commitment Schemes
//!
//! This module provides foundational cryptographic primitives used throughout
//! the MPC-RS protocols, specifically focusing on non-interactive commitment schemes.

use sha2::{Digest, Sha256};

/// A simple, non-interactive cryptographic commitment scheme.
///
/// This scheme computes a commitment as `COMMIT(x) = SHA256(x || r)`, where
/// `x` is the data being committed to, and `r` is a cryptographically secure
/// random blinding factor. This ensures both:
/// - **Hiding**: The commitment reveals nothing about `x` to other parties.
/// - **Binding**: The committer cannot change `x` after the commitment is published.
pub struct CommitmentScheme;

impl CommitmentScheme {
    /// Computes a SHA-256 commitment of the given data and randomness.
    ///
    /// # Arguments
    ///
    /// * `data` - The payload data to be committed to.
    /// * `randomness` - A cryptographically secure random blinding factor (e.g., 32 bytes).
    ///
    /// # Returns
    ///
    /// A 32-byte array containing the SHA-256 hash of `data || randomness`.
    pub fn commit(data: &[u8], randomness: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.update(randomness);
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }

    /// Verifies that a given commitment matches the provided data and randomness.
    ///
    /// # Arguments
    ///
    /// * `commitment` - The 32-byte commitment hash to verify.
    /// * `data` - The original payload data claimed to have been committed.
    /// * `randomness` - The blinding factor used during the commitment phase.
    ///
    /// # Returns
    ///
    /// `true` if the recomputed commitment matches the provided `commitment`,
    /// `false` otherwise (indicating either tampering or incorrect inputs).
    pub fn verify(commitment: &[u8; 32], data: &[u8], randomness: &[u8]) -> bool {
        let computed = Self::commit(data, randomness);
        &computed == commitment
    }
}


