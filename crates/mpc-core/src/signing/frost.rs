//! # FROST Threshold Signing
//!
//! This module implements the FROST (Flexible Round-Optimized Schnorr Threshold)
//! signing protocol for the Ed25519 curve, which is used for Solana vaults in
//! the MPC-RS system.
//!
//! ## Protocol Overview
//! FROST signing is a 2-round protocol (following DKG):
//! 1. **Round 1**: Each participant generates random nonces and broadcasts commitments.
//! 2. **Round 2**: Once all commitments are collected, each participant computes
//!    a signing package, generates their partial signature share, and broadcasts it.
//! 3. **Aggregation**: Any participant (or the Coordinator) can aggregate the
//!    valid partial shares into the final Ed25519 signature.
//!
//! This implementation uses a state machine (`FrostSigning`) to manage the
//! asynchronous collection of messages from peers.

use frost_ed25519::{
    self,
    keys::{KeyPackage, PublicKeyPackage, SigningShare, VerifyingShare},
    round1::{SigningCommitments, SigningNonces},
    round2::{SignatureShare},
    Identifier,
    SigningPackage,
    Signature,
};
use frost_core::{
    Ciphersuite,
    Field,
    Group,
};
use mpc_common::{
    error::MpcResult,
    types::{Curve, PartyId, SessionId, SignResult},
};
use super::state::SigningMessage;
use crate::crypto_error;

/// State machine for managing a FROST signing session for Ed25519.
///
/// This struct encapsulates the local state required to progress through the
/// two rounds of the FROST signing protocol, ensuring that messages are processed
/// in the correct order and that cryptographic state (like nonces) is preserved.
pub struct FrostSigning {
    /// Unique identifier for this signing session.
    session_id: SessionId,
    /// The raw message bytes to be signed (will be hashed internally by FROST).
    message: Vec<u8>,
    /// The local party's key package (contains the secret signing share).
    key_package: KeyPackage,
    /// The verifying (public) shares of all participants, used to validate partial signatures.
    verifying_shares: Vec<VerifyingShare>,
    /// Ordered list of participant identifiers for this specific signing run.
    participants: Vec<Identifier>,
    /// Collected round-1 commitments from all participants.
    round1_commitments: Vec<SigningCommitments>,
    /// Collected round-2 signature shares from all participants.
    round2_shares: Vec<SignatureShare>,
    /// The pre-computed signing package, generated after all round-1 commitments are received.
    signing_package: Option<SigningPackage>,
    /// Flag indicating if the protocol has successfully completed.
    finished: bool,
    /// The secret nonces generated in round-1. These MUST be kept local and never transmitted.
    nonces: Option<SigningNonces>,
}

impl FrostSigning {
    /// Creates a new FROST signing session state machine.
    ///
    /// # Arguments
    ///
    /// * `session_id` - A unique identifier for this signing session.
    /// * `message` - The raw message bytes to be signed.
    /// * `key_package` - The local party's key share (typically loaded from the HSM).
    /// * `verifying_shares` - The verifying keys of all participants in the quorum.
    /// * `participants` - An ordered list of participant identifiers (must match the shares).
    pub fn new(
        session_id: SessionId,
        message: Vec<u8>,
        key_package: KeyPackage,
        verifying_shares: Vec<VerifyingShare>,
        participants: Vec<Identifier>,
    ) -> Self {
        Self {
            session_id,
            message,
            key_package,
            verifying_shares,
            participants,
            round1_commitments: Vec::new(),
            round2_shares: Vec::new(),
            signing_package: None,
            finished: false,
            nonces: None,
        }
    }

    /// Executes Round 1: Generates secret nonces and public commitments.
    ///
    /// # Returns
    ///
    /// A `SigningMessage::FrostRound1Commitment` containing the serialized commitment
    /// payload, which must be broadcast to all other participants.
    ///
    /// # Errors
    ///
    /// Returns `MpcError::Internal` if serialization of the commitment fails.
    pub fn start_round1(&mut self) -> MpcResult<SigningMessage> {
        let (nonces, commitments) = frost_ed25519::round1::commit(
            self.key_package.signing_share(),
            &mut rand::thread_rng(),
        );
        // Store nonces locally for use in Round 2. They are NEVER sent over the network.
        self.nonces = Some(nonces);
        let payload = serde_json::to_vec(&commitments)
            .map_err(|e| crypto_error(e))?;
        Ok(SigningMessage::FrostRound1Commitment(payload))
    }

    /// Processes an incoming Round 1 commitment from another party.
    ///
    /// # Arguments
    ///
    /// * `msg` - The serialized `SigningCommitments` payload from a peer.
    ///
    /// # Returns
    ///
    /// * `Ok(Some(SigningMessage::FrostRound2Share))` if this was the final required
    ///   commitment, triggering the local generation of the Round 2 signature share.
    /// * `Ok(None)` if more commitments are still needed.
    ///
    /// # Errors
    ///
    /// Returns `MpcError::Internal` if deserialization fails or if local nonces are missing.
    /// Returns `MpcError::TssProtocol` if the FROST round 2 signing operation fails.
    pub fn handle_round1(&mut self, msg: &[u8]) -> MpcResult<Option<SigningMessage>> {
        let commitment: SigningCommitments = serde_json::from_slice(msg)
            .map_err(|e| crypto_error(e))?;
        self.round1_commitments.push(commitment);
      
        if self.round1_commitments.len() == self.participants.len() {
            let nonces = self.nonces.as_ref()
                .ok_or_else(|| crypto_error("nonces missing"))?;
            
            // Hash the message using the ciphersuite's designated hash function
            let signing_package = SigningPackage::new(
                self.round1_commitments.clone(),
                frost_ed25519::Ed25519Blake2b::hash(&self.message),
            );
            
            let share = frost_ed25519::round2::sign(
                &signing_package,
                self.key_package.signing_share(),
                nonces,   // ✅ correct nonces
            )?;

            self.signing_package = Some(signing_package);
            let payload = serde_json::to_vec(&share)
                .map_err(|e| crypto_error(e))?;
            Ok(Some(SigningMessage::FrostRound2Share(payload)))
        } else {
            Ok(None)
        }
    }

    /// Processes an incoming Round 2 signature share from another party.
    ///
    /// # Arguments
    ///
    /// * `msg` - The serialized `SignatureShare` payload from a peer.
    ///
    /// # Returns
    ///
    /// * `Ok(Some(SigningMessage::FrostComplete))` if this was the final required
    ///   share, indicating the protocol is ready for aggregation.
    /// * `Ok(None)` if more shares are still needed.
    ///
    /// # Errors
    ///
    /// Returns `MpcError::Internal` if deserialization fails or the signer is unknown.
    /// Returns `MpcError::TssProtocol` if the share fails cryptographic verification.
    pub fn handle_round2(&mut self, msg: &[u8]) -> MpcResult<Option<SigningMessage>> {
        let share: SignatureShare = serde_json::from_slice(msg)
            .map_err(|e| crypto_error(e))?;
            
        // Verify the share against the signer's verifying share (critical for security)
        let verifying_share = self
            .verifying_shares
            .iter()
            .find(|vs| vs.identifier() == share.identifier())
            .ok_or_else(|| crypto_error("unknown signer"))?;
            
        frost_ed25519::round2::verify(share.clone(), verifying_share)
            .map_err(|e| crypto_error(e))?;

        self.round2_shares.push(share);
        
        if self.round2_shares.len() == self.participants.len() {
            self.finished = true;
            Ok(Some(SigningMessage::FrostComplete(b"".to_vec())))
        } else {
            Ok(None)
        }
    }

    /// Aggregates the collected signature shares into the final Ed25519 signature.
    ///
    /// # Returns
    ///
    /// A `SignResult` containing the session ID, the raw signature bytes, and the timestamp.
    ///
    /// # Errors
    ///
    /// Returns `MpcError::Internal` if the signing package is missing (e.g., called out of order)
    /// or if the aggregation fails (e.g., due to invalid shares, though verification in Round 2
    /// should prevent this).
    pub fn aggregate(&self) -> MpcResult<SignResult> {
        let signing_package = self.signing_package.as_ref()
            .ok_or_else(|| crypto_error("signing package missing"))?;
            
        let sig = frost_ed25519::aggregate(
            &signing_package,
            &self.round2_shares,
            &frost_ed25519::keys::PublicKeyPackage::new(
                self.verifying_shares.clone(),
                // Threshold is derived from the number of shares. 
                // For a 2-of-3 setup, len is 2, so threshold = 2.
                self.verifying_shares.len() as u16 - 1, // Note: Adjust logic if threshold != participants.len() - 1
            ),
        )
        .map_err(|e| crypto_error(e))?;
        
        Ok(SignResult {
            session_id: self.session_id,
            signature: sig.serialize().to_vec(),
            committed_at: chrono::Utc::now(),
        })
    }
}

