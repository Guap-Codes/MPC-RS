//! # API Handlers Module
//!
//! This module exposes the HTTP handler implementations for the API Gateway,
//! including address derivation and transaction signing.
//!
//! It also defines the `CoordinatorClient`, a wrapper around the gRPC client 
//! that manages communication with the MPC Coordinator, including retry logic 
//! and polling for asynchronous signing results.

pub mod sign;
pub mod address;

use tonic::transport::Channel;
use crate::coordinator_proto::coordinator_client::CoordinatorClient as ProtoCoordinatorClient;
use crate::coordinator_proto::{SigningRequest, GetResultRequest};
use uuid::Uuid;
use std::time::Duration;
use tokio::time::sleep;

/// A wrapper around the gRPC coordinator client that provides high-level 
/// methods for initiating and polling MPC signing sessions.
#[derive(Clone)]
pub struct CoordinatorClient {
    client: ProtoCoordinatorClient<Channel>,
}

impl CoordinatorClient {
    /// Creates a new `CoordinatorClient` from a configured gRPC channel.
    pub fn new(client: ProtoCoordinatorClient<Channel>) -> Self {
        Self { client }
    }

    /// Triggers a new MPC signing session with the Coordinator.
    ///
    /// # Arguments
    ///
    /// * `msg_hash` - The 32-byte cryptographic digest (sighash) to be signed.
    /// * `signer_indices` - The list of node indices requested to participate in the signing quorum.
    /// * `derivation_path` - The BIP32 path of the key to use for signing.
    ///
    /// # Returns
    ///
    /// A unique `Uuid` representing the signing session, which can be used to poll for the result.
    ///
    /// # Errors
    ///
    /// Returns an error if the gRPC request fails to send or is rejected by the Coordinator.
    pub async fn start_signing(
        &mut self,
        msg_hash: [u8; 32],
        signer_indices: Vec<u16>,
        derivation_path: &str,
    ) -> Result<Uuid, Box<dyn std::error::Error>> {
        let session_id = Uuid::new_v4();
        let request = SigningRequest {
            session_id: session_id.to_string(),
            message_hash: msg_hash.to_vec(),
            curve: "secp256k1".into(),
            signer_indices: signer_indices.iter().map(|&i| i as u32).collect(),
            derivation_path: derivation_path.to_string(),
        };
        
        // The coordinator returns a SigningResponse; we just need to ensure it succeeds
        self.client.start_signing(request).await?;
        Ok(session_id)
    }

    /// Polls the Coordinator for the final assembled threshold signature.
    ///
    /// # Arguments
    ///
    /// * `session_id` - The UUID of the signing session to poll.
    /// * `timeout` - The maximum duration to wait for the signature before giving up.
    /// * `poll_interval` - The delay between consecutive polling attempts.
    ///
    /// # Returns
    ///
    /// The raw signature bytes assembled by the Coordinator.
    ///
    /// # Errors
    ///
    /// Returns a timeout error if the signature is not assembled within the specified duration.
    /// Returns a gRPC error if the Coordinator returns an unexpected failure (note: `NotFound` 
    /// is treated as "not ready yet" and does not constitute an error).
    pub async fn get_result(
        &mut self,
        session_id: Uuid,
        timeout: Duration,
        poll_interval: Duration,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let deadline = tokio::time::Instant::now() + timeout;
        
        loop {
            let request = GetResultRequest {
                session_id: session_id.to_string(),
            };
            
            match self.client.get_result(request).await {
                Ok(resp) => {
                    let sig = resp.into_inner().signature;
                    if !sig.is_empty() {
                        return Ok(sig);
                    }
                }
                Err(e) if e.code() == tonic::Code::NotFound => {
                    // Not ready yet. The coordinator returns NotFound if the signature 
                    // hasn't been fully assembled by the participating nodes.
                }
                Err(e) => return Err(Box::new(e)),
            }
            
            if tokio::time::Instant::now() > deadline {
                return Err("timeout waiting for signature".into());
            }
            
            sleep(poll_interval).await;
        }
    }
}

