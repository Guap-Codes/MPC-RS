//! # Emergency Drain Command
//!
//! This module implements the CLI command for executing an emergency, break-glass
//! transaction to drain all funds from a specified MPC vault to a secure cold wallet.
//!
//! ## ⚠️ Security Warning
//! This is the most destructive and highly privileged operation in the MPC-RS system.
//! It is designed to be used *only* in catastrophic failure scenarios (e.g., suspected
//! node compromise, loss of quorum, or imminent threat). In a mature production system,
//! this command should require multi-party human approval (e.g., M-of-N signatures from
//! security officers) before the Coordinator will execute it.

use crate::client::AdminClient;
use crate::client::coordinator_proto::EmergencyDrainRequest;
use anyhow::Result;
use tracing::warn;

/// Executes the emergency drain command.
///
/// This function constructs an `EmergencyDrainRequest` and sends it to the MPC
/// Coordinator, which will orchestrate the signing and broadcasting of a transaction
/// that sweeps the entire balance of the specified vault to the target address.
///
/// # Arguments
///
/// * `client` - A mutable reference to the authenticated `AdminClient`.
/// * `chain` - The target blockchain network (e.g., "bitcoin", "ethereum").
/// * `target_address` - The destination cold wallet or recovery address.
/// * `from_address` - The source MPC vault address holding the funds.
/// * `derivation_path` - The BIP32 path of the key to authorize the drain (e.g., "m/0/0").
///
/// # Returns
///
/// `Ok(())` if the request was successfully sent to the Coordinator.
/// Note: This does *not* guarantee the transaction was mined, only that the
/// Coordinator accepted the request and initiated the signing process.
///
/// # Errors
///
/// Returns an error if the gRPC request fails, the Coordinator rejects the request
/// (e.g., due to missing approver signatures or policy violations), or the network
/// connection is lost.
///
/// # Note
///
/// The `approver_signature` field is currently set to an empty vector (`vec![]`)
/// as a placeholder. In a production environment, this must be populated with a
/// cryptographically valid signature from an authorized human approver to satisfy
/// the Coordinator's break-glass policy engine.
pub async fn execute(
    client: &mut AdminClient, 
    chain: &str, 
    target_address: &str,
    from_address: &str,    
    derivation_path: &str,
) -> Result<()> {
    warn!("!!! EMERGENCY DRAIN INITIATED !!!");
    warn!("Chain: {}, From: {}, To: {}", chain, from_address, target_address);
    
    let request = tonic::Request::new(EmergencyDrainRequest {
        chain: chain.to_string(),
        from_address: from_address.to_string(),
        target_address: target_address.to_string(),
        derivation_path: derivation_path.to_string(),
        amount: "all".to_string(), // Drain everything
        approver_signature: vec![], // TODO: Populate with valid M-of-N approver signature in production
    });

    let response = client.inner.emergency_drain(request).await?;
    let result = response.into_inner();
    
    if result.success {
        println!("🎉 Drain request accepted! TXID: {}", result.tx_id);
        println!("Monitor the blockchain for confirmation.");
    } else {
        println!("❌ Drain failed: {}", result.error_message);
    }
    
    Ok(())
}

