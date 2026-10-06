// crates/mpc-common/src/audit.rs           
//! # Tamper-Evident Audit Logging
//!
//! This module provides a cryptographically chained audit log implementation.
//! Each event is hashed using HMAC-SHA256, incorporating the hash of the previous
//! event. This creates an immutable, append-only log where any modification,
//! deletion, or reordering of entries will invalidate the cryptographic chain,
//! ensuring compliance and forensic integrity for the MPC-RS custody system.

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::Sha256;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::types::{EventType, PartyId, SessionId};

type HmacSha256 = Hmac<Sha256>;

/// A tamper-evident audit event with cryptographic chaining.
///
/// Each event contains an HMAC of its own contents (excluding the `hmac` field itself),
/// computed using a shared secret key and the `prev_hmac` of the preceding event.
#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    /// Unique identifier for this specific audit event.
    pub id: Uuid,
    /// The exact UTC timestamp when the event occurred.
    pub timestamp: DateTime<Utc>,
    /// The category of the event (e.g., DKG started, signature aggregated).
    pub event_type: EventType,
    /// The MPC session this event is associated with.
    pub session_id: SessionId,
    /// The specific node (party) that generated this event, if applicable.
    pub party_id: Option<PartyId>,
    /// Arbitrary JSON metadata providing additional context for the event.
    pub metadata: serde_json::Value,
    /// HMAC-SHA256 of the previous event's `hmac` field. 
    /// `None` for the genesis (first) event in the log.
    pub prev_hmac: Option<Vec<u8>>,
    /// HMAC of the current event, computed over all fields above. 
    /// Stored to allow downstream verification of log integrity.
    pub hmac: Vec<u8>,
}

impl AuditEvent {
    /// Creates a new audit event and cryptographically chains it to the previous event.
    ///
    /// # Arguments
    ///
    /// * `event_type` - The category of the event being logged.
    /// * `session_id` - The MPC session this event belongs to.
    /// * `party_id` - The ID of the node generating the event (if applicable).
    /// * `metadata` - Additional context as a JSON value.
    /// * `prev_event` - A reference to the immediately preceding audit event, if any.
    /// * `secret_key` - A stable, securely stored secret key used to compute the HMAC chain.
    ///
    /// # Returns
    ///
    /// A fully populated `AuditEvent` with computed `prev_hmac` and `hmac` fields.
    ///
    /// # Panics
    ///
    /// Panics if the `secret_key` is invalid for HMAC-SHA256 (theoretically unreachable, 
    /// as HMAC-SHA256 accepts keys of any size), or if serializing the event metadata 
    /// to JSON fails (which should not happen for valid `serde_json::Value` types).
    #[must_use]
    #[allow(clippy::expect_used)]
    pub fn new(
        event_type: EventType,
        session_id: SessionId,
        party_id: Option<PartyId>,
        metadata: serde_json::Value,
        prev_event: Option<&Self>,
        secret_key: &[u8],
    ) -> Self {
        let id = Uuid::new_v4();
        let timestamp = Utc::now();

        // Serialise the event fields (excluding the final HMAC) for deterministic HMAC computation
        let serializable = SerializableEvent {
            id,
            timestamp,
            event_type: &event_type,
            session_id,
            party_id,
            metadata: &metadata,
            prev_hmac: prev_event.map(|e| e.hmac.as_slice()),
        };

        // HMAC-SHA256 accepts keys of any size, so this will never fail.
        let mut mac = HmacSha256::new_from_slice(secret_key)
            .expect("HMAC-SHA256 accepts keys of any size");
            
        // Use a canonical representation (JSON) for HMAC input to ensure consistency.
        // serde_json::Value serialization to string is infallible for valid JSON structures.
        let payload = serde_json::to_string(&serializable)
            .expect("Failed to serialize audit event");
            
        mac.update(payload.as_bytes());
        let hmac = mac.finalize().into_bytes().to_vec();

        Self {
            id,
            timestamp,
            event_type,
            session_id,
            party_id,
            metadata,
            prev_hmac: prev_event.map(|e| e.hmac.clone()),
            hmac,
        }
    }

    /// Verifies the cryptographic integrity of this event.
    ///
    /// # Arguments
    ///
    /// * `prev_event` - A reference to the expected preceding event (to verify `prev_hmac`).
    /// * `secret_key` - The shared secret key used to compute the HMAC.
    ///
    /// # Returns
    ///
    /// `true` if the event's `hmac` matches the recomputed value and the `prev_hmac` 
    /// correctly links to the previous event. `false` otherwise, indicating potential tampering.
    ///
    /// # Panics
    ///
    /// Panics if the `secret_key` is invalid for HMAC-SHA256 (theoretically unreachable), 
    /// or if serializing the event to JSON fails.
    #[must_use]
    #[allow(clippy::expect_used)]
    pub fn verify(&self, prev_event: Option<&Self>, secret_key: &[u8]) -> bool {
        let expected_prev = prev_event.map(|e| e.hmac.as_slice());
        let serializable = SerializableEvent {
            id: self.id,
            timestamp: self.timestamp,
            event_type: &self.event_type,
            session_id: self.session_id,
            party_id: self.party_id,
            metadata: &self.metadata,
            prev_hmac: expected_prev,
        };

        let mut mac = HmacSha256::new_from_slice(secret_key)
            .expect("HMAC-SHA256 accepts keys of any size");
            
        let payload = serde_json::to_string(&serializable)
            .expect("Failed to serialize audit event for verification");
            
        mac.update(payload.as_bytes());

        mac.verify_slice(&self.hmac).is_ok()
    }
}

/// Helper struct for deterministic JSON serialisation.
///
/// This is used exclusively as the input for HMAC computation to ensure that 
/// the serialized byte representation is stable and predictable across different 
/// runs and platforms, which is critical for cryptographic hashing.
#[derive(Serialize)]
struct SerializableEvent<'a> {
    id: Uuid,
    timestamp: DateTime<Utc>,
    event_type: &'a EventType,
    session_id: SessionId,
    party_id: Option<PartyId>,
    metadata: &'a serde_json::Value,
    prev_hmac: Option<&'a [u8]>,
}

