//! # Core Cryptographic and Operational Types
//!
//! This module defines the fundamental data structures used throughout the MPC-RS 
//! system, including party identifiers, session IDs, curve-agnostic public keys, 
//! and the encrypted key share bundles generated during DKG.
//!
//! ## Security Note: Memory Zeroization
//! Several types in this module implement the `Zeroize` trait (and `Drop` where 
//! applicable). This ensures that sensitive cryptographic material (e.g., nonces, 
//! ciphertexts) is securely overwritten in memory when the variable goes out of 
//! scope, preventing leakage via core dumps or memory scraping.

use chrono::{DateTime, Utc};
use k256::PublicKey as Secp256k1PublicKey;
use ed25519_dalek::VerifyingKey as Ed25519PublicKey;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;
use zeroize::Zeroize;

/// Unique identifier for an MPC party (node) in the cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Zeroize)]
pub struct PartyId(pub u32);

/// Unique identifier for an MPC session (e.g., DKG or signing ceremony).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub Uuid);

impl SessionId {
    /// Generates a new, random v4 UUID for a session.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

/// Represents the elliptic curve used for cryptographic operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Curve {
    /// secp256k1 (used for Bitcoin, Ethereum, Tron, XRP).
    Secp256k1,
    /// ed25519 (used for Solana).
    Ed25519,
    /// curve25519 (used for X25519 key exchange).
    Curve25519,
}

/// A generic public key that abstracts over different elliptic curves.
///
/// This enum allows the system to handle multiple blockchain curves uniformly 
/// while preserving type safety. Custom Serde implementations ensure it serializes 
/// as a tagged union (e.g., `(0, [bytes])`) for unambiguous deserialization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKey {
    Secp256k1(Secp256k1PublicKey),
    Ed25519(Ed25519PublicKey),
    Curve25519(Vec<u8>), // 32 bytes
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Secp256k1(k) => {
                let bytes = k.to_sec1_bytes().to_vec();
                (0u8, bytes).serialize(serializer)
            }
            Self::Ed25519(k) => {
                let bytes = k.to_bytes().to_vec();
                (1u8, bytes).serialize(serializer)
            }
            Self::Curve25519(k) => {
                (2u8, k.clone()).serialize(serializer)
            }
        }
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (id, bytes): (u8, Vec<u8>) = Deserialize::deserialize(deserializer)?;
        match id {
            0 => {
                let k = Secp256k1PublicKey::from_sec1_bytes(&bytes)
                    .map_err(serde::de::Error::custom)?;
                Ok(Self::Secp256k1(k))
            }
            1 => {
                let bytes_arr: [u8; 32] = bytes.try_into()
                    .map_err(|_| serde::de::Error::custom("invalid ed25519 key length"))?;
                let k = Ed25519PublicKey::from_bytes(&bytes_arr)
                    .map_err(|_| serde::de::Error::custom("invalid ed25519 key"))?;
                Ok(Self::Ed25519(k))
            }
            2 => Ok(Self::Curve25519(bytes)),
            _ => Err(serde::de::Error::custom("unknown curve id")),
        }
    }
}

impl PublicKey {
    /// Returns the elliptic curve associated with this public key.
    #[must_use]
    pub const fn curve(&self) -> Curve {
        match self {
            Self::Secp256k1(_) => Curve::Secp256k1,
            Self::Ed25519(_) => Curve::Ed25519,
            Self::Curve25519(_) => Curve::Curve25519,
        }
    }
}

// Note: Zeroize is a no-op for PublicKey as public keys are, by definition, 
// not secret and do not require secure memory wiping.
impl Zeroize for PublicKey {
    fn zeroize(&mut self) {}
}

/// Custom Serde module to force Chrono to use strict string serialization.
///
/// # Note
/// This prevents Chrono from calling `deserialize_any`, which the `bincode` 
/// crate does not support. This is critical for serializing metadata to disk 
/// or databases using bincode.
mod chrono_bincode {
    use chrono::{DateTime, Utc};
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(date: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&date.to_rfc3339())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<DateTime<Utc>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse::<DateTime<Utc>>().map_err(serde::de::Error::custom)
    }
}

/// Metadata attached to a key share, enabling versioning and auditability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareMetadata {
    /// The elliptic curve this share belongs to.
    pub curve: Curve,
    /// The version of the MPC protocol used to generate this share (e.g., "cggmp21-1.0.0").
    pub protocol_version: String,
    /// The UTC timestamp when the share was generated.
    #[serde(with = "chrono_bincode")] // Bypass deserialize_any for bincode compatibility
    pub created_at: DateTime<Utc>,
    /// The ID of the party that owns this share.
    pub party_id: PartyId,
}

impl Zeroize for ShareMetadata {
    fn zeroize(&mut self) {
        self.party_id.zeroize();
    }
}

/// An encrypted key share.
///
/// The `ciphertext` payload can only be decrypted by the specific HSM instance 
/// identified by `hsm_id`. This ensures that raw key shares never persist in 
/// plaintext on the local filesystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedShare {
    /// The HSM-wrapped (encrypted) key share bytes.
    pub ciphertext: Vec<u8>,
    /// Identifier for the specific HSM instance or partition that holds the wrap key.
    pub hsm_id: HsmIdentifier,
}

impl Zeroize for EncryptedShare {
    fn zeroize(&mut self) {
        self.ciphertext.zeroize();
    }
}

impl Drop for EncryptedShare {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Identifier for a specific HSM instance or partition.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HsmIdentifier(pub String);

/// A complete key share bundle as stored by a party after a successful DKG.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
pub struct KeyShare {
    /// The ID of the party owning this share.
    pub party_id: PartyId,
    /// The shared master public key for the vault.
    pub public_key: PublicKey,
    /// The HSM-encrypted portion of the secret share.
    pub encrypted_share: EncryptedShare,
    /// Metadata providing context and versioning for the share.
    pub metadata: ShareMetadata,
}

/// A nonce used during ECDSA threshold signing (one per session).
///
/// ⚠️ **Security Warning**: This contains highly sensitive cryptographic material. 
/// It must be zeroized immediately after the signing ceremony completes.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
pub struct Nonce {
    /// The secret scalar `k`.
    pub k: [u8; 32],
    /// The public point `R` (optional, depending on protocol phase).
    pub r: Option<[u8; 32]>,
}

/// Commitment to a nonce before the reveal phase of the signing protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonceCommitment {
    /// The session this commitment belongs to.
    pub session_id: SessionId,
    /// The party making the commitment.
    pub party_id: PartyId,
    /// The 32-byte hash commitment (e.g., SHA256 of the nonce).
    pub commitment: [u8; 32],
}

/// The data required at the start of a signing request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRequest {
    /// The unique session ID for this signing operation.
    pub session_id: SessionId,
    /// The 32-byte cryptographic digest (sighash) to be signed.
    pub message_hash: [u8; 32],
    /// The elliptic curve to use for the signature.
    pub curve: Curve,
    /// Optional context for policy evaluation (e.g., transaction details).
    pub policy_context: Option<serde_json::Value>,
}

/// The aggregated result of a successful threshold signing ceremony.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignResult {
    /// The session ID this result corresponds to.
    pub session_id: SessionId,
    /// The final, assembled threshold signature bytes.
    pub signature: Vec<u8>,
    /// The UTC timestamp when the signature was successfully aggregated.
    #[serde(with = "chrono_bincode")] // Bulletproofing for SignResult as well
    pub committed_at: DateTime<Utc>,
}

/// Event types for the tamper-evident audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventType {
    /// A Distributed Key Generation (DKG) ceremony has been initiated.
    DkgStarted,
    /// A DKG ceremony has successfully completed.
    DkgCompleted,
    /// A threshold signing session has been initiated.
    SigningStarted,
    /// A node has successfully generated its partial signature share.
    PartialSignatureGenerated,
    /// The Coordinator has successfully aggregated the final threshold signature.
    SignatureAggregated,
    /// A proactive key share rotation (refresh) has been initiated.
    KeyRotationStarted,
    /// A key share rotation has successfully completed.
    KeyRotationCompleted,
    /// A transaction was evaluated against the custody policy.
    PolicyEvaluation,
    /// A request was denied due to policy violation or lack of authorization.
    AccessDenied,
}

