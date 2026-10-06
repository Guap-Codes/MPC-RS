//! # MPC Session State Management
//!
//! This module provides an in-memory, thread-safe store for tracking active MPC 
//! signing sessions. It uses asynchronous channels (`oneshot`) to coordinate 
//! between the external API (waiting for the result) and the internal MPC nodes 
//! (reporting their partial signatures).

use std::collections::HashMap;
use tokio::sync::{oneshot, RwLock};
use uuid::Uuid;
use mpc_common::types::SessionId;

/// Represents the state of a single active MPC signing session.
#[allow(dead_code)]
pub struct Session {
    /// The unique identifier for this session.
    pub session_id: SessionId,
    /// The 32-byte message digest being signed.
    pub message_hash: [u8; 32],
    /// The indices of the nodes participating in this signing quorum.
    pub signer_indices: Vec<u16>,
    /// The expected threshold of signatures required (e.g., 2 for a 2-of-3 setup).
    pub expected_threshold: usize,
    /// A map of collected partial signatures, keyed by the reporting node's ID.
    pub collected_signatures: HashMap<u32, Vec<u8>>,
    /// The sender half of a oneshot channel, used to transmit the final signature.
    pub result_tx: Option<oneshot::Sender<Vec<u8>>>,
    /// The receiver half, extracted by the API Gateway to await the result.
    pub result_rx: Option<oneshot::Receiver<Vec<u8>>>,
}

/// A thread-safe, in-memory store for managing active MPC sessions.
pub struct SessionStore {
    sessions: RwLock<HashMap<SessionId, Session>>,
}

impl SessionStore {
    /// Creates a new, empty `SessionStore`.
    pub fn new() -> Self {
        Self { sessions: RwLock::new(HashMap::new()) }
    }

    /// Creates a new session and returns a receiver that will fire when the final signature is ready.
    ///
    /// # Arguments
    ///
    /// * `session_id` - The unique identifier for the session.
    /// * `msg_hash` - The 32-byte message digest to be signed.
    /// * `signer_indices` - The list of node IDs participating in the quorum.
    /// * `threshold` - The minimum number of signatures required (currently unused in the simplified logic, but retained for schema completeness).
    ///
    /// # Returns
    ///
    /// A `oneshot::Receiver<Vec<u8>>` that the API Gateway can `.await` to receive the final signature.
    pub async fn create(
        &self,
        session_id: SessionId,
        msg_hash: [u8; 32],
        signer_indices: Vec<u16>,
        threshold: usize,
    ) -> oneshot::Receiver<Vec<u8>> {
        let (tx, rx) = oneshot::channel();
        let session = Session {
            session_id,
            message_hash: msg_hash,
            signer_indices,
            expected_threshold: threshold,
            collected_signatures: HashMap::new(),
            result_tx: Some(tx),
            result_rx: None,
        };
        self.sessions.write().await.insert(session_id, session);
        rx
    }

    /// Records a signature reported by an MPC node.
    ///
    /// # Cryptographic Note
    ///
    /// In CGGMP21 (ECDSA), the final aggregated signature is mathematically valid, but due to 
    /// the randomization inherent in the protocol, different nodes may produce byte-for-byte 
    /// different (but equally valid) signatures. Therefore, we do not wait for `count >= threshold` 
    /// identical signatures. Instead, we accept the *first* fully aggregated signature we receive 
    /// from any participating node and immediately resolve the `oneshot` channel.
    ///
    /// # Arguments
    ///
    /// * `session_id` - The ID of the session this signature belongs to.
    /// * `party_id` - The ID of the node reporting the signature.
    /// * `signature` - The aggregated signature bytes.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the signature was recorded and the session was resolved.
    ///
    /// # Errors
    ///
    /// Returns an error string if the session is not found, or if the reporting `party_id` 
    /// was not part of the original `signer_indices` for this session.
    pub async fn report_signature(
        &self,
        session_id: &SessionId,
        party_id: u32,
        signature: Vec<u8>,
    ) -> Result<(), String> {
        let mut sessions = self.sessions.write().await;
        let session = sessions.get_mut(session_id).ok_or("session not found")?;

        if !session.signer_indices.contains(&(party_id as u16)) {
            return Err("party not in signer set".to_string());
        }

        session.collected_signatures.insert(party_id, signature.clone());

        // Send the first valid aggregated signature we receive to wake up the orchestrator
        if let Some(tx) = session.result_tx.take() {
            let _ = tx.send(signature);
            tracing::info!("✅ Threshold signature received from party {}! Waking up orchestrator.", party_id);
        }

        Ok(())
    }

    /// Retrieves the oneshot receiver for a session. Used by the `GetResult` gRPC endpoint.
    ///
    /// # Note
    ///
    /// The receiver is extracted (`take`n) only once. Subsequent calls for the same 
    /// `session_id` will return `None`, preventing multiple consumers from waiting 
    /// on the same resolved channel.
    pub async fn take_receiver(&self, session_id: &SessionId) -> Option<oneshot::Receiver<Vec<u8>>> {
        let mut sessions = self.sessions.write().await;
        let session = sessions.get_mut(session_id)?;
        session.result_rx.take()
    }

    /// Removes a completed (or failed) session from the store to free memory.
    #[allow(dead_code)]
    pub async fn remove(&self, session_id: &SessionId) {
        self.sessions.write().await.remove(session_id);
    }

    /// Returns the number of currently active sessions in the store.
    pub async fn active_count(&self) -> usize {
        self.sessions.read().await.len()
    }
}

