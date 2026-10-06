//! # Key Share Rotation (Refresh) Command
//!
//! This module implements the CLI command for initiating a proactive key share
//! refresh (rotation) ceremony for an existing MPC vault.
//!
//! ## Security Context: Forward Secrecy
//! Key rotation updates the secret shares held by all participating nodes without
//! changing the master public key or the associated blockchain addresses. This
//! is a critical security control: if an attacker compromises a node's share,
//! a successful rotation immediately invalidates the stolen share, rendering it
//! useless for future signing operations. This provides forward secrecy for the vault.

use crate::client::AdminClient;
use crate::client::coordinator_proto::StartRefreshRequest;
use anyhow::Result;
use tracing::info;

/// Executes the key rotation initiation command.
///
/// This function sends a request to the MPC Coordinator to begin the refresh
/// ceremony for the specified vault. The Coordinator will orchestrate the
/// multi-party computation required to generate new, random zero-sum masks
/// and update each node's local share.
///
/// # Arguments
///
/// * `client` - A mutable reference to the authenticated `AdminClient`.
/// * `key_id` - The unique identifier of the vault/key to refresh.
///
/// # Returns
///
/// `Ok(())` if the request was successfully sent and accepted by the Coordinator.
///
/// # Errors
///
/// Returns an error if the gRPC request fails, the Coordinator rejects the
/// request (e.g., the `key_id` does not exist), or the network connection is lost.
///
/// # Note
///
/// Like DKG, key rotation is a multi-round, asynchronous process. This command
/// only *initiates* the ceremony. Operators should monitor the cluster status
/// to ensure all nodes successfully update their shares and securely zeroize
/// the old shares upon completion.
pub async fn execute(client: &mut AdminClient, key_id: &str) -> Result<()> {
    info!("Initiating key rotation for key_id: {}", key_id);
    
    let request = tonic::Request::new(StartRefreshRequest {
        key_id: key_id.to_string(),
    });

    let response = client.inner.start_refresh(request).await?;
    let session_id = response.into_inner().session_id;
    
    info!("Key refresh session started successfully. Session ID: {}", session_id);
    
    Ok(())
}

