//! # Distributed Key Generation (DKG) Command
//!
//! This module implements the CLI command for initiating a new Distributed Key
//! Generation (DKG) ceremony.
//!
//! ## Cryptographic Context
//! DKG is the foundational process for creating a new MPC vault. During this
//! ceremony, all participating nodes collaboratively generate a shared master
//! public key and individual secret shares, such that no single node ever knows
//! the complete private key. This is required before any AuxGen or signing
//! operations can take place for a new vault.

use crate::client::AdminClient;
use crate::client::coordinator_proto::StartKeygenRequest;
use anyhow::Result;
use tracing::info;

/// Executes the DKG initiation command.
///
/// This function sends a request to the MPC Coordinator to begin the DKG
/// ceremony across the cluster with the specified cryptographic parameters.
///
/// # Arguments
///
/// * `client` - A mutable reference to the authenticated `AdminClient`.
/// * `curve` - The elliptic curve to generate keys for (e.g., "secp256k1").
/// * `threshold` - The threshold (t) for the t-of-n secret sharing scheme.
///   For example, a threshold of 2 in a 3-node cluster means any 2 nodes
///   can collaborate to sign a transaction.
///
/// # Returns
///
/// `Ok(())` if the request was successfully sent and accepted by the Coordinator.
///
/// # Errors
///
/// Returns an error if the gRPC request fails, the Coordinator rejects the
/// request (e.g., invalid curve or threshold), or the network connection is lost.
///
/// # Note
///
/// DKG is a multi-round, asynchronous process. This command only *initiates*
/// the ceremony. Operators must monitor the cluster status (e.g., via
/// `mpc-cli status` or node logs) to verify that all nodes successfully
/// complete the protocol and store their shares.
pub async fn execute(client: &mut AdminClient, curve: &str, threshold: u32) -> Result<()> {
    info!("Initiating DKG session for curve {} with threshold {}", curve, threshold);
    
    let request = tonic::Request::new(StartKeygenRequest {
        curve: curve.to_string(),
        threshold,
    });

    let response = client.inner.start_keygen(request).await?;
    let session_id = response.into_inner().session_id;
    
    info!("DKG session started successfully. Session ID: {}", session_id);
    println!("Monitor progress using: mpc-cli status");
    
    Ok(())
}
