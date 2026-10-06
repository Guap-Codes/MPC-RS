//! # Node Registry and Session Orchestration
//!
//! This module manages the Coordinator's knowledge of the MPC cluster topology 
//! and handles the logic for triggering distributed protocols (like signing) 
//! across the registered nodes.

use std::collections::HashMap;
use std::sync::Arc;
use tonic::transport::{Certificate, Identity};
use mpc_common::types::PartyId;
use mpc_common::error::{MpcError, MpcResult};
use mpc_protocol::proto::mpc_node_client::MpcNodeClient;
use mpc_protocol::proto::SessionRequest;

/// Describes the network endpoint and identity of a single MPC node.
#[allow(dead_code)]
struct NodeEndpoint {
    /// The unique numeric identifier of the node.
    pub party_id: PartyId,
    /// The network address (IP:Port) of the node's internal gRPC service.
    pub address: String,
    /// The expected domain name in the node's TLS certificate (for SAN validation).
    pub domain: String,
}

/// Registry that manages mTLS-secured gRPC clients to MPC nodes.
///
/// This struct holds the Coordinator's own identity and the CA certificate 
/// used to verify the nodes' certificates, ensuring that all outbound 
/// communication is encrypted and authenticated.
pub struct NodeRegistry {
    entries: HashMap<PartyId, NodeEndpoint>,
    coordinator_identity: Identity,
    ca_cert: Certificate,
}

impl NodeRegistry {
    /// Creates a new, empty `NodeRegistry`.
    ///
    /// # Arguments
    ///
    /// * `coordinator_identity` - The Coordinator's TLS certificate and private key.
    /// * `ca_cert` - The Certificate Authority certificate used to verify node certificates.
    pub fn new(coordinator_identity: Identity, ca_cert: Certificate) -> Self {
        Self {
            entries: HashMap::new(),
            coordinator_identity,
            ca_cert,
        }
    }

    /// Registers a new MPC node in the cluster topology.
    ///
    /// # Arguments
    ///
    /// * `party_id` - The unique identifier of the node.
    /// * `address` - The network address of the node.
    /// * `domain` - The expected domain name in the node's TLS certificate.
    pub fn add_entry(&mut self, party_id: PartyId, address: String, domain: String) {
        self.entries.insert(party_id, NodeEndpoint { party_id, address, domain });
    }

    /// Retrieves an mTLS-secured gRPC client for a specific MPC node.
    ///
    /// # Arguments
    ///
    /// * `party_id` - The unique identifier of the target node.
    ///
    /// # Returns
    ///
    /// An `MpcNodeClient` configured with the Coordinator's identity and the CA certificate.
    ///
    /// # Errors
    ///
    /// Returns `MpcError::Config` if the `party_id` is not registered.
    /// Returns `MpcError::Network` if the TLS channel fails to establish.
    pub async fn get_client(&self, party_id: PartyId) -> MpcResult<MpcNodeClient<tonic::transport::Channel>> {
        let endpoint = self.entries.get(&party_id)
            .ok_or_else(|| MpcError::Config(format!("no endpoint for party {:?}", party_id)))?;

        let channel = mpc_protocol::transport::create_tls_channel(
            &endpoint.address,
            &endpoint.domain,
            self.coordinator_identity.clone(),
            self.ca_cert.clone(),
        ).await?;

        Ok(MpcNodeClient::new(channel))
    }

    /// Returns a list of all registered party IDs in the cluster.
    pub fn all_parties(&self) -> Vec<PartyId> {
        self.entries.keys().copied().collect()
    }
}

/// Orchestrates a signing session by triggering the specified MPC nodes.
///
/// This function iterates over the requested `signer_indices`, establishes 
/// an mTLS connection to each node, and sends a `SessionRequest` to initiate 
/// the local MPC protocol execution on that node.
///
/// # Arguments
///
/// * `session_id` - The unique UUID for this signing session.
/// * `msg_hash` - The 32-byte cryptographic digest to be signed.
/// * `signer_indices` - The list of node indices requested to participate.
/// * `derivation_path` - The BIP32 path of the key share to use.
/// * `node_registry` - The shared registry used to establish mTLS connections.
///
/// # Returns
///
/// `Ok(())` if all requested nodes successfully accepted the session request.
///
/// # Errors
///
/// Returns `MpcError::Network` if the Coordinator fails to connect to a node 
/// or if a node explicitly rejects the session request. The function fails 
/// fast and returns the error immediately upon the first node rejection.
pub async fn orchestrate_signing(
    session_id: uuid::Uuid,
    msg_hash: [u8; 32],
    signer_indices: Vec<u16>,
    derivation_path: String,
    node_registry: Arc<NodeRegistry>,
) -> MpcResult<()> {
    for &party_idx in &signer_indices {
        let party_id = PartyId(party_idx as u32);
        
        tracing::info!("Connecting to Node {} to trigger signing session...", party_id.0);
        
        let mut client = node_registry.get_client(party_id).await
            .map_err(|e| {
                tracing::error!("Failed to create TLS channel to Node {}: {:?}", party_id.0, e);
                e
            })?;

        let request = SessionRequest {
            session_id: session_id.to_string(),
            session_type: 1, // Type::SIGNING = 1
            total_parties: 0, 
            threshold: 0,
            curve: "secp256k1".into(),
            message_hash: msg_hash.to_vec(),
            signer_indices: signer_indices.iter().map(|&i| i as u32).collect(),
            derivation_path: derivation_path.clone(),
        };

        // Do NOT swallow the error. If the node rejects it, we need to know 
        // immediately to fail the session and alert the API Gateway.
        match client.start_session(request).await {
            Ok(_) => tracing::info!("✅ Node {} accepted signing session", party_id.0),
            Err(e) => {
                tracing::error!("❌ Node {} rejected signing session: {:?}", party_id.0, e);
                return Err(mpc_common::error::MpcError::Network(format!("Node {} rejected session: {}", party_id.0, e)));
            }
        }
    }
    Ok(())
}

