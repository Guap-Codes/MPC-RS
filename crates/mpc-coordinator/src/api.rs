//! # Coordinator gRPC Service Implementation
//!
//! This module implements the core gRPC services for the MPC Coordinator.
//! It acts as the central orchestration hub, bridging external clients (API Gateway, CLI)
//! with the internal MPC nodes.
//!
//! ## Architectural Boundaries
//! The Coordinator exposes two distinct gRPC services:
//! 1. **`Coordinator`**: The primary service handling external requests from the API Gateway
//!    and CLI. These endpoints are protected by JWT-based authentication and RBAC.
//! 2. **`MpcCoordinator`**: An internal service used exclusively by MPC nodes to report
//!    their partial signature shares. This service relies on network-level mTLS for
//!    authentication rather than JWTs.

use std::sync::Arc;
use tonic::{Request, Response, Status};
use uuid::Uuid;
use sha2::{Sha256, Digest};
use mpc_common::types::SessionId;
use auth::JwtManager; 

use crate::drain_orchestrator::DrainOrchestrator;
use std::collections::HashMap;
use adapter_core::traits::BlockchainAdapter;

use crate::auth::authenticate;
use crate::session_store::SessionStore;
use crate::coordinator::{NodeRegistry, orchestrate_signing};
use crate::coordinator_proto;
use mpc_protocol::proto::{
    SessionRequest, session_request::Type, 
    ExportShareRequest, GetPublicKeyRequest,
};

/// The main gRPC service implementation for the MPC Coordinator.
///
/// This struct holds the shared state required to manage MPC sessions, 
/// communicate with registered nodes, validate administrative requests, 
/// and execute break-glass procedures.
pub struct CoordinatorService {
    /// In-memory store for tracking active MPC sessions and aggregating results.
    session_store: Arc<SessionStore>,
    /// Registry of known MPC nodes and their mTLS connection parameters.
    node_registry: Arc<NodeRegistry>,
    /// JWT manager for authenticating and authorizing external API/CLI requests.
    jwt_manager: Arc<JwtManager>, 
    /// Orchestrator for executing emergency, break-glass fund drainage.
    drain_orchestrator: Arc<DrainOrchestrator>,
}

impl CoordinatorService {
    /// Creates a new `CoordinatorService` instance.
    ///
    /// # Arguments
    ///
    /// * `session_store` - The shared session state manager.
    /// * `node_registry` - The registry of MPC nodes and their mTLS configurations.
    /// * `jwt_manager` - The JWT validation engine for external requests.
    /// * `adapters` - A map of blockchain adapters required for the drain orchestrator 
    ///   to construct and broadcast emergency transactions.
    pub fn new(
        session_store: Arc<SessionStore>,
        node_registry: Arc<NodeRegistry>,
        jwt_manager: Arc<JwtManager>,
        adapters: HashMap<String, Arc<dyn BlockchainAdapter>>,
    ) -> Self {
        let orchestrator = Arc::new(DrainOrchestrator::new(
            node_registry.clone(),
            session_store.clone(),
            adapters,
        ));

        Self { 
            session_store, 
            node_registry, 
            jwt_manager, 
            drain_orchestrator: orchestrator 
        }
    }
}

#[tonic::async_trait]
impl coordinator_proto::coordinator_server::Coordinator for CoordinatorService {
    
    // ==========================================
    // SIGNING RPCs (Used by mpc-api)
    // ==========================================

    /// Initiates a new threshold signing session.
    ///
    /// This RPC is called by the API Gateway. It validates the JWT, registers the 
    /// session in the `SessionStore`, and spawns a background task to orchestrate 
    /// the signing protocol across the specified MPC nodes.
    ///
    /// # Arguments
    ///
    /// * `request` - The gRPC request containing the session ID, message hash, 
    ///   signer indices, and derivation path.
    ///
    /// # Returns
    ///
    /// A `SigningResponse` indicating whether the session was successfully accepted.
    ///
    /// # Errors
    ///
    /// Returns `Status::unauthenticated` if the JWT is missing or invalid.
    /// Returns `Status::invalid_argument` if the session ID or message hash is malformed.
    async fn start_signing(
        &self,
        request: Request<coordinator_proto::SigningRequest>,
    ) -> Result<Response<coordinator_proto::SigningResponse>, Status> {
        let _claims = authenticate(&request, &self.jwt_manager)?;
        let req = request.into_inner();

        let session_id = Uuid::parse_str(&req.session_id)
            .map_err(|_| Status::invalid_argument("invalid session id"))?;
        let session_id = SessionId(session_id);

        let msg_hash: [u8; 32] = req.message_hash.as_slice().try_into()
            .map_err(|_| Status::invalid_argument("message hash must be 32 bytes"))?;

        let signer_indices: Vec<u16> = req.signer_indices.iter().map(|&i| i as u16).collect();
        let threshold = 2; // TODO: Make this configurable based on the vault's policy

        let _rx = self.session_store.create(session_id, msg_hash, signer_indices.clone(), threshold).await;

        let registry = self.node_registry.clone();
        let derivation_path = req.derivation_path.clone();
        
        // Spawn a background task to orchestrate the P2P signing protocol with the nodes.
        // This prevents blocking the gRPC response to the API Gateway.
        tokio::spawn(async move {
            if let Err(e) = orchestrate_signing(
                session_id.0, msg_hash, signer_indices, derivation_path, registry,
            ).await {
                tracing::error!("Failed to orchestrate signing session {}: {:?}", session_id.0, e);
            }
        });

        Ok(Response::new(coordinator_proto::SigningResponse { accepted: true }))
    }

    /// Receives a partial signature report from an MPC node.
    ///
    /// # Security Note
    /// This method explicitly **bypasses JWT authentication** (`authenticate` is commented out).
    /// It is designed to be called by internal MPC nodes. Security is enforced at the 
    /// network level via mTLS (when configured on the internal port), ensuring that only 
    /// trusted nodes can submit signature shares.
    ///
    /// # Arguments
    ///
    /// * `request` - The gRPC request containing the session ID, party ID, and partial signature.
    ///
    /// # Returns
    ///
    /// A `ReportAck` confirming the Coordinator received and stored the share.
    ///
    /// # Errors
    ///
    /// Returns `Status::invalid_argument` if the session ID is malformed.
    /// Returns `Status::internal` if the session store fails to record the signature.
    async fn report_signature(
        &self,
        request: Request<coordinator_proto::SignatureReport>, 
    ) -> Result<Response<coordinator_proto::ReportAck>, Status> { 
        let req = request.into_inner();

        let session_id = Uuid::parse_str(&req.session_id)
            .map_err(|_| Status::invalid_argument("invalid session id"))?;
        let session_id = SessionId(session_id);

        self.session_store.report_signature(&session_id, req.party_id, req.signature)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        tracing::info!("✅ Coordinator received signature from party {} for session {}", req.party_id, session_id.0);
        Ok(Response::new(coordinator_proto::ReportAck {}))
    }

    /// Polls for the final, aggregated threshold signature.
    ///
    /// This RPC is called repeatedly by the API Gateway (with backoff) until the 
    /// Coordinator has collected enough partial signatures to reconstruct the final signature.
    ///
    /// # Arguments
    ///
    /// * `request` - The gRPC request containing the session ID to poll.
    ///
    /// # Returns
    ///
    /// A `SignatureResult` containing the raw, aggregated signature bytes.
    ///
    /// # Errors
    ///
    /// Returns `Status::unauthenticated` if the JWT is missing or invalid.
    /// Returns `Status::not_found` if the session does not exist or the result was already consumed.
    /// Returns `Status::internal` if the signing protocol failed or the channel was dropped.
    async fn get_result(
        &self,
        request: Request<coordinator_proto::GetResultRequest>,
    ) -> Result<Response<coordinator_proto::SignatureResult>, Status> {
        let _claims = authenticate(&request, &self.jwt_manager)?;
        let req = request.into_inner();

        let session_id = Uuid::parse_str(&req.session_id)
            .map_err(|_| Status::invalid_argument("invalid session id"))?;
        let session_id = SessionId(session_id);

        let rx = self.session_store.take_receiver(&session_id)
            .await
            .ok_or_else(|| Status::not_found("session not found or result already consumed"))?;

        let signature = rx
            .await
            .map_err(|_| Status::internal("signature generation failed"))?;

        Ok(Response::new(coordinator_proto::SignatureResult { signature }))
    }

    // ==========================================
    // ADMIN / CLI RPCs (Deep Integration)
    // ==========================================

    /// Initiates a new Distributed Key Generation (DKG) ceremony across all registered nodes.
    ///
    /// # Arguments
    ///
    /// * `request` - The gRPC request specifying the curve and threshold.
    ///
    /// # Returns
    ///
    /// A `StartKeygenResponse` containing the new session ID.
    ///
    /// # Errors
    ///
    /// Returns `Status::unauthenticated` or `Status::permission_denied` if the JWT is invalid 
    /// or lacks the "admin" role.
    /// Returns `Status::internal` if the Coordinator fails to connect to or instruct any of the nodes.
    async fn start_keygen(
        &self,
        request: Request<coordinator_proto::StartKeygenRequest>,
    ) -> Result<Response<coordinator_proto::StartKeygenResponse>, Status> {
        let _claims = authenticate(&request, &self.jwt_manager)?;
        let req = request.into_inner();
        
        let session_id = Uuid::new_v4();
        tracing::info!("Admin requested DKG: session={}, curve={}, threshold={}", session_id, req.curve, req.threshold);
        
        let parties = self.node_registry.all_parties();
        let total_parties = parties.len() as u32;
        
        for party_id in parties {
            let mut client = self.node_registry.get_client(party_id).await
                .map_err(|e| Status::internal(format!("Failed to connect to node {}: {}", party_id.0, e)))?;
            
            let session_req = SessionRequest {
                session_id: session_id.to_string(),
                session_type: Type::Dkg.into(),
                total_parties,
                threshold: req.threshold,
                curve: req.curve.clone(),
                message_hash: vec![],
                signer_indices: vec![],
                derivation_path: String::new(),
            };
            
            client.start_session(session_req).await
                .map_err(|e| Status::internal(format!("Node {} rejected DKG: {}", party_id.0, e)))?;
        }
        
        Ok(Response::new(coordinator_proto::StartKeygenResponse {
            session_id: session_id.to_string(),
        }))
    }

    /// Initiates the Auxiliary Information Generation (AuxGen) phase for CGGMP21.
    ///
    /// This is a mandatory, one-time setup step that generates Paillier/RSA keys 
    /// and Ring-Pedersen parameters required for zero-knowledge proofs during signing.
    ///
    /// # Arguments
    ///
    /// * `request` - The gRPC request specifying the total number of parties.
    ///
    /// # Returns
    ///
    /// A `StartAuxGenResponse` containing the new session ID.
    ///
    /// # Errors
    ///
    /// Returns `Status::unauthenticated` or `Status::permission_denied` for invalid/insufficient JWT.
    /// Returns `Status::internal` if node communication fails.
    async fn start_aux_gen(
        &self,
        request: Request<coordinator_proto::StartAuxGenRequest>,
    ) -> Result<Response<coordinator_proto::StartAuxGenResponse>, Status> {
        let _claims = authenticate(&request, &self.jwt_manager)?;
        let _req = request.into_inner();
        
        let session_id = Uuid::new_v4();
        tracing::info!("Admin requested AuxGen: session={}", session_id);
        
        let parties = self.node_registry.all_parties();
        let total_parties = parties.len() as u32;
        
        for party_id in parties {
            let mut client = self.node_registry.get_client(party_id).await
                .map_err(|e| Status::internal(format!("Failed to connect to node {}: {}", party_id.0, e)))?;
            
            let session_req = SessionRequest {
                session_id: session_id.to_string(),
                session_type: Type::AuxGen.into(), 
                total_parties,
                threshold: 0,
                curve: String::new(),
                message_hash: vec![],
                signer_indices: vec![],
                derivation_path: String::new(),
            };
            
            client.start_session(session_req).await
                .map_err(|e| Status::internal(format!("Node {} rejected AuxGen: {}", party_id.0, e)))?;
        }
        
        Ok(Response::new(coordinator_proto::StartAuxGenResponse {
            session_id: session_id.to_string(),
        }))
    }

    /// Initiates a proactive key share refresh (rotation) for an existing vault.
    ///
    /// This updates the secret shares held by all nodes without changing the master 
    /// public key, providing forward secrecy by invalidating any previously compromised shares.
    ///
    /// # Arguments
    ///
    /// * `request` - The gRPC request containing the `key_id` of the vault to refresh.
    ///
    /// # Returns
    ///
    /// A `StartRefreshResponse` containing the new session ID.
    ///
    /// # Errors
    ///
    /// Returns `Status::unauthenticated` or `Status::permission_denied` for invalid/insufficient JWT.
    /// Returns `Status::internal` if node communication fails.
    async fn start_refresh(
        &self,
        request: Request<coordinator_proto::StartRefreshRequest>,
    ) -> Result<Response<coordinator_proto::StartRefreshResponse>, Status> {
        let _claims = authenticate(&request, &self.jwt_manager)?;
        let req = request.into_inner();
        
        let session_id = Uuid::new_v4();
        tracing::info!("Admin requested Key Refresh: session={}, key_id={}", session_id, req.key_id);
        
        let parties = self.node_registry.all_parties();
        let total_parties = parties.len() as u32;
        
        for party_id in parties {
            let mut client = self.node_registry.get_client(party_id).await
                .map_err(|e| Status::internal(format!("Failed to connect to node {}: {}", party_id.0, e)))?;
            
            let session_req = SessionRequest {
                session_id: session_id.to_string(),
                session_type: Type::Refresh.into(),
                total_parties,
                threshold: 0, 
                curve: "secp256k1".into(), 
                message_hash: vec![],
                signer_indices: vec![],
                derivation_path: req.key_id.clone(),
            };
            
            client.start_session(session_req).await
                .map_err(|e| Status::internal(format!("Node {} rejected Refresh: {}", party_id.0, e)))?;
        }
        
        Ok(Response::new(coordinator_proto::StartRefreshResponse {
            session_id: session_id.to_string(),
        }))
    }

    /// Fetches the current operational status and health of the Coordinator and all registered nodes.
    ///
    /// # Arguments
    ///
    /// * `request` - An empty `GetStatusRequest`.
    ///
    /// # Returns
    ///
    /// A `GetStatusResponse` containing the count of active sessions and a list of `NodeStatus` objects.
    ///
    /// # Note
    ///
    /// To determine node health, this method actively probes each node by requesting its 
    /// master public key. A successful response indicates the node is online and its HSM is responsive.
    async fn get_status(
        &self,
        request: Request<coordinator_proto::GetStatusRequest>,
    ) -> Result<Response<coordinator_proto::GetStatusResponse>, Status> {
        let _claims = authenticate(&request, &self.jwt_manager)?;
        
        let active_sessions = self.session_store.active_count().await;
        let parties = self.node_registry.all_parties();
        let mut nodes = Vec::new();
        
        for party_id in parties {
            let (status_str, hsm_healthy) = match self.node_registry.get_client(party_id).await {
                Ok(mut client) => {
                    let probe_req = GetPublicKeyRequest {
                        derivation_path: "".to_string(),
                        curve: "secp256k1".to_string(),
                    };
                    match client.get_public_key(probe_req).await {
                        Ok(resp) => {
                            let pk_hex = resp.into_inner().public_key.iter().map(|b| format!("{:02x}", b)).collect::<String>();
                            tracing::info!("🔑 Node {} Master Public Key: {}", party_id.0, pk_hex);
                            ("Healthy".to_string(), true)
                        }
                        Err(e) => (format!("Degraded: {}", e.code()), false),
                    }
                }
                Err(_) => ("Unreachable".to_string(), false),
            };
            
            nodes.push(coordinator_proto::NodeStatus {
                id: party_id.0,
                status: status_str,
                hsm_healthy,
                last_ping: chrono::Utc::now().to_rfc3339(),
            });
        }

        Ok(Response::new(coordinator_proto::GetStatusResponse {
            active_sessions: active_sessions as u32,
            nodes,
        }))
    }

    /// Requests encrypted key share backups from all registered nodes.
    ///
    /// This is a critical disaster recovery operation. The retrieved blobs are encrypted 
    /// by each node's local HSM and must be stored in geographically distributed, 
    /// physically secure locations.
    ///
    /// # Arguments
    ///
    /// * `request` - An empty `RequestBackupRequest`.
    ///
    /// # Returns
    ///
    /// A `RequestBackupResponse` containing a list of `NodeBackup` objects.
    ///
    /// # Errors
    ///
    /// Returns `Status::unauthenticated` or `Status::permission_denied` for invalid/insufficient JWT.
    /// Returns `Status::internal` if any node fails to export its share.
    async fn request_backup(
        &self,
        request: Request<coordinator_proto::RequestBackupRequest>,
    ) -> Result<Response<coordinator_proto::RequestBackupResponse>, Status> {
        let _claims = authenticate(&request, &self.jwt_manager)?;
        tracing::info!("Admin requested encrypted share backups");
        
        let parties = self.node_registry.all_parties();
        let mut backups = Vec::new();
        
        for party_id in parties {
            let mut client = self.node_registry.get_client(party_id).await
                .map_err(|e| Status::internal(format!("Failed to connect to node {}: {}", party_id.0, e)))?;
            
            let req = ExportShareRequest {
                key_id: "default".to_string(),
            };
            
            let resp = client.export_share(req).await
                .map_err(|e| Status::internal(format!("Node {} failed to export share: {}", party_id.0, e)))?;
            
            backups.push(coordinator_proto::NodeBackup {
                node_id: party_id.0,
                encrypted_share: resp.into_inner().encrypted_share,
            });
        }
        
        Ok(Response::new(coordinator_proto::RequestBackupResponse { backups }))
    }

    /// Initiates a FROST DKG ceremony for Ed25519 curves (primarily for Solana).
    ///
    /// # Arguments
    ///
    /// * `request` - An empty `StartFrostDkgRequest`.
    ///
    /// # Returns
    ///
    /// A `StartFrostDkgResponse` containing the new session ID.
    ///
    /// # Errors
    ///
    /// Returns `Status::unauthenticated` or `Status::permission_denied` for invalid/insufficient JWT.
    /// Returns `Status::internal` if node communication fails.
    async fn start_frost_dkg(
        &self,
        request: Request<coordinator_proto::StartFrostDkgRequest>,
    ) -> Result<Response<coordinator_proto::StartFrostDkgResponse>, Status> {
        let _claims = authenticate(&request, &self.jwt_manager)?;
        
        let session_id = Uuid::new_v4();
        tracing::info!("Admin requested FROST DKG (Solana Ed25519): session={}", session_id);
        
        let parties = self.node_registry.all_parties();
        let total_parties = parties.len() as u32;
        
        for party_id in parties {
            let mut client = self.node_registry.get_client(party_id).await
                .map_err(|e| Status::internal(format!("Failed to connect to node {}: {}", party_id.0, e)))?;
            
            let session_req = SessionRequest {
                session_id: session_id.to_string(),
                session_type: Type::FrostDkg.into(),
                total_parties,
                threshold: 2,
                curve: "ed25519".into(),
                message_hash: vec![],
                signer_indices: vec![],
                derivation_path: String::new(),
            };
            
            client.start_session(session_req).await
                .map_err(|e| Status::internal(format!("Node {} rejected FROST DKG: {}", party_id.0, e)))?;
        }
        
        Ok(Response::new(coordinator_proto::StartFrostDkgResponse {
            session_id: session_id.to_string(),
        }))
    }

    /// Executes an emergency, break-glass transaction to drain funds from a vault.
    ///
    /// ⚠️ **Security Warning**: This is the most destructive and highly privileged operation 
    /// in the system. It should only be used in catastrophic failure scenarios. In a mature 
    /// production system, this endpoint must be protected by additional out-of-band approvals 
    /// (e.g., M-of-N human signatures) before the Coordinator executes it.
    ///
    /// # Arguments
    ///
    /// * `request` - The `EmergencyDrainRequest` specifying the chain, addresses, derivation path, and amount.
    ///
    /// # Returns
    ///
    /// An `EmergencyDrainResponse` indicating success/failure, the TXID, and any error messages.
    ///
    /// # Errors
    ///
    /// Returns `Status::unauthenticated` or `Status::permission_denied` for invalid/insufficient JWT.
    /// Returns a successful response with `success: false` if the drain orchestrator fails to 
    /// build, sign, or broadcast the transaction.
    async fn emergency_drain(
        &self,
        request: Request<coordinator_proto::EmergencyDrainRequest>,
    ) -> Result<Response<coordinator_proto::EmergencyDrainResponse>, Status> {
        let _claims = authenticate(&request, &self.jwt_manager)?;
        let req = request.into_inner();
        
        tracing::warn!("!!! EMERGENCY DRAIN TRIGGERED !!! Chain: {}, Target: {}", req.chain, req.target_address);
        
        match self.drain_orchestrator.execute_drain(
            &req.chain,
            &req.from_address,
            &req.target_address,
            &req.derivation_path,
            &req.amount,
        ).await {
            Ok(tx_id) => Ok(Response::new(coordinator_proto::EmergencyDrainResponse {
                success: true,
                tx_id,
                error_message: String::new(),
                amount_drained: 0, // TODO: Populate with actual drained amount from adapter
            })),
            Err(e) => {
                tracing::error!("Drain failed: {}", e);
                Ok(Response::new(coordinator_proto::EmergencyDrainResponse {
                    success: false,
                    tx_id: String::new(),
                    error_message: e.to_string(),
                    amount_drained: 0,
                }))
            }
        }
    }
}

// ==========================================
// NODE-TO-COORDINATOR RPCs (Internal mTLS)
// ==========================================

/// Implementation of the internal gRPC service used exclusively by MPC nodes.
///
/// This service is typically exposed on a separate, internal network port protected 
/// by mutual TLS (mTLS). It does not perform JWT validation, relying instead on the 
/// cryptographic guarantees of the mTLS handshake to authenticate the calling node.
#[tonic::async_trait]
impl mpc_protocol::proto::mpc_coordinator_server::MpcCoordinator for CoordinatorService {

    /// Placeholder for `start_signing`. 
    ///
    /// # Note
    /// Nodes do not call this method. The API Gateway uses the main `Coordinator` 
    /// service to initiate signing. This method is unimplemented to prevent accidental 
    /// misuse of the internal service endpoint.
    async fn start_signing(
        &self,
        _request: Request<mpc_protocol::proto::SigningRequest>,
    ) -> Result<Response<mpc_protocol::proto::SignedEnvelope>, Status> {
        Err(Status::unimplemented("Use the main Coordinator service for StartSigning"))
    }

    /// Receives a partial signature report from an internal MPC node.
    ///
    /// This is the internal counterpart to the public `report_signature` method. 
    /// It relies on mTLS for authentication rather than JWTs.
    ///
    /// # Arguments
    ///
    /// * `request` - The gRPC request containing the session ID, party ID, and partial signature.
    ///
    /// # Returns
    ///
    /// A `ReportAck` confirming the Coordinator received and stored the share.
    ///
    /// # Errors
    ///
    /// Returns `Status::invalid_argument` if the session ID is malformed.
    /// Returns `Status::internal` if the session store fails to record the signature.
    async fn report_signature(
        &self,
        request: Request<mpc_protocol::proto::SignatureReport>,
    ) -> Result<Response<mpc_protocol::proto::ReportAck>, Status> {
        let req = request.into_inner();

        let session_id = Uuid::parse_str(&req.session_id)
            .map_err(|_| Status::invalid_argument("invalid session id"))?;
        let session_id = SessionId(session_id);

        self.session_store.report_signature(&session_id, req.party_id, req.signature)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        tracing::info!("✅ Coordinator received signature from party {} for session {}", req.party_id, session_id.0);
        Ok(Response::new(mpc_protocol::proto::ReportAck { received: true }))
    }
}

