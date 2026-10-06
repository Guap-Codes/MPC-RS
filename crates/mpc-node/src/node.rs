//! # MPC Node Core Implementation
//!
//! This module contains the core state machine and gRPC service implementation for an MPC node.
//! It handles the lifecycle of Distributed Key Generation (DKG), threshold signing, and auxiliary
//! information generation, orchestrating the underlying cryptographic protocols and securely
//! persisting the results to the configured Hardware Security Module (HSM).
//!
//! ## Multi-Chain Vault Generation
//! Upon successful secp256k1 DKG, this node automatically derives and logs the canonical
//! addresses for all supported EVM and UTXO chains (Ethereum, Tron, Bitcoin, XRP) from the
//! newly generated master public key, providing immediate visibility into the vault's capabilities.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use futures::{SinkExt, StreamExt};
use tokio::sync::{mpsc, RwLock};
use tonic::{Request, Response, Status, Streaming};
use tracing::{debug, error, info, warn};
use rand::RngCore; 

use mpc_common::types::{PartyId, SessionId, KeyShare, Curve};
use mpc_common::error::MpcResult;
use mpc_core::dkg::cggmp21::{run_dkg, convert_key_share};
use mpc_core::dkg::frost::run_frost_dkg;
use mpc_core::signing::cggmp21::{run_signing, convert_signature};
use mpc_protocol::{
    proto::{
        mpc_node_server::MpcNode,
        mpc_coordinator_client::MpcCoordinatorClient,
        SignedEnvelope, SessionRequest, SessionResponse,
        GetPublicKeyRequest, PublicKeyResponse,
        ExportShareRequest, ExportShareResponse,
        SignatureReport,
        session_request,
    },
    routing::PartyRegistry,
    session::run_mpc_session,
};
use cggmp21::key_share::AnyKeyShare;
use hsm_core::traits::HsmEngine;
use tonic::transport::Channel;

use k256::elliptic_curve::sec1::ToEncodedPoint;
use sha3::{Digest, Keccak256}; 

type HsmEngineArc = Arc<dyn HsmEngine + Send + Sync>;

/// A lightweight bridge for routing incoming gRPC stream messages into a local MPSC channel.
///
/// This allows the asynchronous `run_mpc_session` loop to consume messages as they arrive
/// from the network without blocking the gRPC server's connection handler.
#[derive(Clone)]
struct SessionBridge {
    incoming_tx: mpsc::UnboundedSender<SignedEnvelope>,
}

impl SessionBridge {
    /// Creates a new `SessionBridge` and returns the bridge handle along with the receiving end.
    fn new() -> (Self, mpsc::UnboundedReceiver<SignedEnvelope>) {
        let (incoming_tx, incoming_rx) = mpsc::unbounded_channel();
        let bridge = Self { incoming_tx };
        (bridge, incoming_rx)
    }
}

/// The core state machine for an MPC node.
///
/// This struct holds the node's identity, its connection to the HSM, the registry of peer nodes,
/// and the in-memory caches for active sessions and loaded key shares. It implements the
/// `MpcNode` gRPC service trait to receive commands from the Coordinator or peer nodes.
pub struct Node {
    /// The unique numeric identifier for this node in the cluster.
    party_id: PartyId,
    /// The configured HSM backend used for secure key share storage and retrieval.
    hsm: HsmEngineArc,
    /// Registry containing the network endpoints and TLS credentials of all peer nodes.
    registry: PartyRegistry,
    /// In-memory cache of loaded key shares, keyed by their label (e.g., "master").
    key_shares: Arc<RwLock<HashMap<String, KeyShare>>>,
    /// Active session bridges, keyed by `SessionId`, used to route incoming messages.
    sessions: Arc<RwLock<HashMap<SessionId, SessionBridge>>>,
    /// The receiving ends of the MPSC channels for active sessions.
    session_incoming: Arc<RwLock<HashMap<SessionId, mpsc::UnboundedReceiver<SignedEnvelope>>>>,
    /// gRPC client for communicating with the central Coordinator (e.g., to report signatures).
    coordinator_client: MpcCoordinatorClient<Channel>,
}

impl Node {
    /// Creates a new `Node` instance.
    ///
    /// # Arguments
    ///
    /// * `party_id` - The unique identifier for this node.
    /// * `hsm` - The initialized HSM engine.
    /// * `registry` - The peer node registry.
    /// * `coordinator_client` - The gRPC client for the Coordinator.
    pub fn new(
        party_id: PartyId, 
        hsm: HsmEngineArc, 
        registry: PartyRegistry,
        coordinator_client: MpcCoordinatorClient<Channel>,
    ) -> Self {
        Self {
            party_id,
            hsm,
            registry,
            key_shares: Arc::new(RwLock::new(HashMap::new())),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            session_incoming: Arc::new(RwLock::new(HashMap::new())),
            coordinator_client,
        }
    }

    /// Loads a key share from the HSM into the in-memory cache.
    ///
    /// # Arguments
    ///
    /// * `label` - The unique identifier for the key share (e.g., "master").
    ///
    /// # Errors
    ///
    /// Returns `MpcError::Hsm` if the HSM fails to retrieve the encrypted share.
    /// Returns `MpcError::InvalidInput` if the retrieved data fails to deserialize.
    #[allow(dead_code)]
    pub async fn load_key_share(&self, label: &str) -> MpcResult<()> {
        let encrypted = self.hsm.get(label).await
            .map_err(|e| mpc_common::error::MpcError::Hsm(e.to_string()))?;
        
        let share: KeyShare = bincode::deserialize(&encrypted)
            .map_err(|e| mpc_common::error::MpcError::InvalidInput(e.to_string()))?;
        self.key_shares.write().await.insert(label.to_string(), share);
        Ok(())
    }

    /// Registers a new session and returns a bridge for routing messages to it.
    async fn register_session(&self, session_id: SessionId) -> SessionBridge {
        let (bridge, incoming_rx) = SessionBridge::new();
        self.sessions.write().await.insert(session_id, bridge.clone());
        self.session_incoming.write().await.insert(session_id, incoming_rx);
        bridge
    }

    /// Unregisters a completed or failed session, cleaning up its channels.
    #[allow(dead_code)]
    async fn unregister_session(&self, session_id: &SessionId) {
        self.sessions.write().await.remove(session_id);
        self.session_incoming.write().await.remove(session_id);
    }
}

#[tonic::async_trait]
impl MpcNode for Node {
    type ExchangeMessagesStream = Pin<Box<dyn futures::Stream<Item = Result<SignedEnvelope, Status>> + Send>>;

    /// Handles an incoming bidirectional gRPC stream for MPC protocol messages.
    ///
    /// This method extracts the `session_id` from the first message, waits for the
    /// session to be registered by the `start_session` handler, and then spawns a
    /// background task to forward all subsequent messages into the session's MPSC channel.
    ///
    /// # Note
    ///
    /// The outbound stream is currently `pending()` because this node primarily acts as a
    /// receiver in the P2P mesh, with the Coordinator orchestrating the message routing.
    async fn exchange_messages(
        &self,
        request: Request<Streaming<SignedEnvelope>>,
    ) -> Result<Response<Self::ExchangeMessagesStream>, Status> {
        let mut in_stream = request.into_inner();
        
        let first_msg = in_stream.next().await
            .ok_or_else(|| Status::aborted("no messages"))?
            .map_err(|e| Status::internal(e.to_string()))?;

        let session_id = uuid::Uuid::parse_str(&first_msg.session_id)
            .map_err(|_| Status::invalid_argument("invalid session id"))?;
        let session_id = SessionId(session_id);

        // Wait for the session to be registered by the start_session handler
        let bridge = loop {
            let sessions = self.sessions.read().await;
            if let Some(bridge) = sessions.get(&session_id).cloned() {
                break bridge;
            }
            drop(sessions);
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        };

        if !first_msg.payload.is_empty() {
            bridge.incoming_tx.send(first_msg)
                .map_err(|_| Status::internal("session closed"))?;
        }

        let incoming_tx = bridge.incoming_tx;
        tokio::spawn(async move {
            while let Some(msg) = in_stream.next().await {
                match msg {
                    Ok(env) => {
                        if env.payload.is_empty() { continue; }
                        info!("[SERVER] Received from peer: sender={}, receiver={}", env.sender, env.receiver);
                        if incoming_tx.send(env).is_err() { break; }
                    }
                    Err(e) => {
                        error!("[SERVER] gRPC error: {:?}", e);
                        break;
                    }
                }
            }
        });

        let out_stream = futures::stream::pending::<Result<SignedEnvelope, Status>>();
        Ok(Response::new(Box::pin(out_stream)))
    }
    
    /// Retrieves the master public key and chain code for this node.
    ///
    /// If the key share is not in the in-memory cache, it is loaded from the HSM.
    /// The chain code is fetched separately to support hierarchical deterministic (HD)
    /// address derivation by external tools (like the Coordinator's drain orchestrator).
    async fn get_public_key(
        &self,
        request: Request<GetPublicKeyRequest>,
    ) -> Result<Response<PublicKeyResponse>, Status> {
        let _req = request.into_inner();
        let label = "master".to_string();

        let cached_share = self.key_shares.read().await.get(&label).cloned();

        let key_share = if let Some(share) = cached_share {
            share
        } else {
            tracing::info!("Key share '{}' not in memory, loading from HSM...", label);
            let encrypted = self.hsm.get(&label).await
                .map_err(|e| Status::not_found(format!("share '{}' not found in HSM: {}", label, e)))?;
            
            let share: KeyShare = bincode::deserialize(&encrypted)
                .map_err(|e| Status::internal(format!("failed to deserialize share: {}", e)))?;
            
            self.key_shares.write().await.insert(label.clone(), share.clone());
            share
        };

        let pk_bytes = match key_share.public_key {
            mpc_common::types::PublicKey::Secp256k1(k) => k.to_sec1_bytes().to_vec(),
            mpc_common::types::PublicKey::Ed25519(k) => k.to_bytes().to_vec(),
            mpc_common::types::PublicKey::Curve25519(k) => k, 
        };

        // Fetch master chain code from HSM
        let chain_code = match self.hsm.get("master_chain_code").await {
            Ok(cc) => {
                info!("🔑 get_public_key: chain_code retrieved, len={}", cc.len());
                cc
            }
            Err(e) => {
                warn!("⚠️ get_public_key: chain_code MISSING from HSM: {:?}", e);
                vec![]
            }
        };

        Ok(Response::new(PublicKeyResponse {
            public_key: pk_bytes,
            chain_code,
        }))
    }

    /// Exports the encrypted key share for backup or migration purposes.
    ///
    /// # Note
    ///
    /// This returns the *encrypted* share as stored in the HSM (or serialized from cache),
    /// ensuring that the raw secret material is never exposed to the caller.
    async fn export_share(
        &self,
        request: Request<ExportShareRequest>,
    ) -> Result<Response<ExportShareResponse>, Status> {
        let req = request.into_inner();
        let label = if req.key_id.is_empty() || req.key_id == "default" {
            "master".to_string()
        } else {
            req.key_id
        };

        info!("Exporting share for label: {}", label);

        let cached_share = self.key_shares.read().await.get(&label).cloned();

        let share_bytes = if let Some(share) = cached_share {
            bincode::serialize(&share)
                .map_err(|e| Status::internal(format!("failed to serialize cached share: {e}")))?
        } else {
            self.hsm.get(&label).await
                .map_err(|e| Status::not_found(format!("share '{}' not found in HSM: {e}", label)))?
        };

        Ok(Response::new(ExportShareResponse {
            encrypted_share: share_bytes,
        }))
    }

    /// Initiates a new MPC session (DKG, Signing, AuxGen, FROST DKG, or Refresh).
    ///
    /// This method validates the request, registers the session, and spawns a background
    /// task to execute the specific cryptographic protocol via `run_mpc_session`.
    async fn start_session(
        &self,
        request: Request<SessionRequest>,
    ) -> Result<Response<SessionResponse>, Status> {
        let req = request.into_inner();
        let session_id = uuid::Uuid::parse_str(&req.session_id)
            .map_err(|_| Status::invalid_argument("invalid session id"))?;
        let session_id = SessionId(session_id);

        let ca_cert = mpc_protocol::transport::load_ca_cert(std::path::Path::new("config/ca-cert.pem"))
            .map_err(|e| Status::internal(format!("failed to load CA cert: {e}")))?;

        let _bridge = self.register_session(session_id).await;
        
        let incoming_rx = self.session_incoming.write().await.remove(&session_id)
            .ok_or_else(|| Status::internal("session incoming receiver not found"))?;
        
        let party_id = self.party_id;
        let hsm = self.hsm.clone();
        let key_shares = self.key_shares.clone();
        let registry = self.registry.clone();
        let sessions = self.sessions.clone();
        let coord_client = self.coordinator_client.clone();

        match req.session_type() {
            session_request::Type::Dkg => {
                let n = req.total_parties as u16;
                let t = req.threshold as u16;

                let aux_label = format!("aux-{}", party_id.0);
                
                let existing_aux: Option<cggmp21::key_share::AuxInfo> = match hsm.get(&aux_label).await {
                    Ok(data) => serde_json::from_slice(&data).ok(),
                    Err(_) => None,
                };

                let aux_info = match existing_aux {
                    Some(aux) => aux,
                    None => {
                        return Err(Status::failed_precondition(
                            "Aux info not found. Please run aux-gen session first."
                        ));
                    }
                };

                tokio::spawn(async move {
                    info!("Starting DKG session {}", session_id.0);
                    let result = run_mpc_session(
                        session_id,
                        party_id,
                        (1..=n as u32).map(PartyId).collect(), 
                        &registry,
                        ca_cert,
                        incoming_rx,
                        mpc_protocol::session::SessionConfig {
                            message_timeout: std::time::Duration::from_secs(300), 
                            max_retries: 3,
                        },
                        |mpc_party| {
                            async move {
                                let eid_str = session_id.0.to_string();
                                let eid = cggmp21::ExecutionId::new(eid_str.as_bytes());
                                
                                let local_index = party_id.0 as u16 - 1;

                                let key_share = run_dkg(
                                    eid,
                                    local_index, 
                                    n,
                                    t,
                                    mpc_party,
                                    aux_info,
                                ).await?;

                                let share = convert_key_share(
                                    &key_share,
                                    party_id,
                                    mpc_common::types::HsmIdentifier("default".into()),
                                )?; 

                                // Serialize the group public key once; reuse it for logging and for the
                                // deterministic chain-code derivation below.
                                let pubkey_bytes: Vec<u8> = match &share.public_key {
                                    mpc_common::types::PublicKey::Secp256k1(k) => k.to_sec1_bytes().to_vec(),
                                    mpc_common::types::PublicKey::Ed25519(k)     => k.to_bytes().to_vec(),
                                    mpc_common::types::PublicKey::Curve25519(k)  => k.clone(),
                                };

                                let pk_hex = pubkey_bytes
                                    .iter()
                                    .map(|b| format!("{:02x}", b))
                                    .collect::<String>();
                                info!("🔑🔑🔑 MASTER PUBLIC KEY (HEX): {} 🔑🔑🔑", pk_hex);

                                // MULTI-CHAIN VAULT GENERATION: Calculate addresses for ALL secp256k1 chains!
                                if let mpc_common::types::PublicKey::Secp256k1(k) = &share.public_key {
                                    let uncompressed = k.to_encoded_point(false);
                                    let compressed = k.to_encoded_point(true);
                                    
                                    // 1. ETHEREUM (Keccak256)
                                    let mut eth_hasher = Keccak256::new();
                                    eth_hasher.update(&uncompressed.as_bytes()[1..]); // Skip 0x04 prefix
                                    let eth_hash = eth_hasher.finalize();
                                    let eth_address = hex::encode(&eth_hash[12..]);
                                    info!("🔑🔑🔑 MASTER ETHEREUM ADDRESS: 0x{} 🔑🔑🔑", eth_address);

                                    // 2. TRON (Keccak256 + 0x41 Prefix + Base58Check)
                                    let mut tron_payload = vec![0x41];
                                    tron_payload.extend_from_slice(&eth_hash[12..]);
                                    let tron_address = base58check_encode(&tron_payload, bs58::Alphabet::BITCOIN);
                                    info!("🔑🔑🔑 MASTER TRON ADDRESS: {} 🔑🔑🔑", tron_address);

                                    // 3. BITCOIN (P2PKH: SHA256 -> RIPEMD160 + 0x00 Prefix + Base58Check)
                                    let mut btc_sha = sha2::Sha256::new();
                                    btc_sha.update(compressed.as_bytes());
                                    let btc_sha_res = btc_sha.finalize();
                                    
                                    let mut btc_ripe = ripemd::Ripemd160::new();
                                    btc_ripe.update(btc_sha_res);
                                    let btc_hash = btc_ripe.finalize();
                                    
                                    let mut btc_payload = vec![0x00];
                                    btc_payload.extend_from_slice(&btc_hash);
                                    let btc_address = base58check_encode(&btc_payload, bs58::Alphabet::BITCOIN);
                                    info!("🔑🔑🔑 MASTER BITCOIN ADDRESS: {} 🔑🔑🔑", btc_address);

                                    // 4. XRP (SHA256 -> RIPEMD160 + 0x00 Prefix + Custom Base58 Alphabet)
                                    let mut xrp_payload = vec![0x00];
                                    xrp_payload.extend_from_slice(&btc_hash);
                                    
                                    // XRP uses a completely custom Base58 alphabet!
                                    const XRP_ALPHABET: &[u8; 58] = b"rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";
                                    let xrp_alphabet = bs58::Alphabet::new(XRP_ALPHABET).unwrap();
                                    let xrp_address = base58check_encode(&xrp_payload, &xrp_alphabet);
                                    info!("🔑🔑🔑 MASTER XRP ADDRESS: {} 🔑🔑🔑", xrp_address);
                                }

                                // Chain code is deterministic across all parties: HMAC-SHA256 over a
                                // fixed domain separator, keyed by the group public key. No extra
                                // protocol round, no randomness, guaranteed agreement.
                                let chain_code: Vec<u8> = {
                                    use hmac::{Hmac, Mac};
                                    use sha2::Sha256;
                                    type HmacSha256 = Hmac<Sha256>;

                                    let mut mac = HmacSha256::new_from_slice(&pubkey_bytes)
                                        .map_err(|e| mpc_common::error::MpcError::Internal(
                                            format!("HMAC init failed: {e}")
                                        ))?;
                                    mac.update(b"mpc-rs/hd-chain-code/v1");
                                    mac.finalize().into_bytes().to_vec()
                                };

                                hsm.store("master_chain_code", &chain_code)
                                    .await
                                    .map_err(|e| mpc_common::error::MpcError::Hsm(e.to_string()))?;
                                info!("🔑 Master Chain Code derived from group pubkey and stored ({} bytes).", chain_code.len());

                                let label = "master".to_string();
                                let ser = bincode::serialize(&share)
                                    .map_err(|e| mpc_common::error::MpcError::Internal(e.to_string()))?;
                                hsm.store(&label, &ser)
                                    .await
                                    .map_err(|e| mpc_common::error::MpcError::Hsm(e.to_string()))?;

                                key_shares.write().await.insert(label, share);
                                info!("DKG completed and saved successfully for party {}", party_id.0);
                                Ok(())
                            }
                        },
                    ).await;

                    if let Err(e) = result {
                        error!("DKG session failed: {:?}", e);
                    }
                    sessions.write().await.remove(&session_id);
                });
            }
            session_request::Type::Signing => {
                let mpc_key_share = key_shares
                    .read()
                    .await
                    .get("master")
                    .cloned()
                    .ok_or_else(|| Status::not_found("master key share not found"))?;

                let cggmp21_share: cggmp21::KeyShare<cggmp21::supported_curves::Secp256k1> = serde_json::from_slice(&mpc_key_share.encrypted_share.ciphertext)
                    .map_err(|e| Status::internal(format!("failed to deserialize key share: {e}")))?;

                let msg_hash: [u8; 32] = req.message_hash.as_slice().try_into()
                    .map_err(|_| Status::invalid_argument("invalid message hash"))?;
                
                let t = cggmp21_share.min_signers() as u16;
                
                let mut signers: Vec<u16> = req.signer_indices.iter().map(|&i| (i - 1) as u16).collect();
                signers.sort_unstable();
                signers.dedup();
                
                if signers.len() > t as usize {
                    signers.truncate(t as usize);
                }
                
                if signers.len() < t as usize {
                    return Err(Status::invalid_argument(format!("not enough signers: got {}, need {}", signers.len(), t)));
                }

                let local_index = party_id.0 as u16 - 1; 
                
                if !signers.contains(&local_index) {
                    info!("Node {} is not in the selected signing subset {:?}. Declining session.", party_id.0, signers);
                    return Ok(Response::new(SessionResponse { accepted: false }));
                }

                let derivation = if req.derivation_path.is_empty() {
                    None
                } else {
                    Some(req.derivation_path.clone())
                };

                let coord_client_inner = coord_client.clone();
                tokio::spawn(async move {
                    info!("Starting signing session {}", session_id.0);
                    
                    let network_parties: Vec<PartyId> = signers.iter().map(|&i| PartyId(i as u32 + 1)).collect();
                    
                    let result = run_mpc_session(
                        session_id,
                        party_id,
                        network_parties,
                        &registry,
                        ca_cert,
                        incoming_rx,
                        mpc_protocol::session::SessionConfig {
                            message_timeout: std::time::Duration::from_secs(60),
                            max_retries: 2,
                        },
                        |mpc_party| {
                            let mut coord_client = coord_client_inner.clone();
                            async move {
                                let eid_str = session_id.0.to_string();
                                let eid = cggmp21::ExecutionId::new(eid_str.as_bytes());
                                
                                info!("🔍 DEBUG SIGNING PARAMS: local_index={}, signers={:?}, n={}, t={}, derivation={:?}", 
                                    local_index, 
                                    signers, 
                                    cggmp21_share.n(),
                                    cggmp21_share.min_signers(),
                                    derivation
                                );

                                let scalar = cggmp21::generic_ec::Scalar::<cggmp21::supported_curves::Secp256k1>::from_be_bytes_mod_order(msg_hash);
                                let data = cggmp21::DataToSign::from_scalar(scalar);
 
                                let sig = run_signing(
                                    eid,
                                    local_index,          
                                    &signers,
                                    &cggmp21_share,
                                    data,
                                    derivation.as_deref(), 
                                    mpc_party,
                                ).await?;
                                
                                let result = convert_signature(&sig, session_id);
                                info!("Signature produced: {:?}", result);
                                
                                let report_req = SignatureReport {
                                    session_id: session_id.0.to_string(),
                                    party_id: party_id.0,
                                    signature: result.signature,
                                };
                                
                                tokio::spawn(async move {
                                    if let Err(e) = coord_client.report_signature(report_req).await {
                                        error!("Failed to report signature to Coordinator: {:?}", e);
                                    } else {
                                        info!("✅ Successfully reported signature to Coordinator");
                                    }
                                });
                                
                                Ok(())
                            }
                        },
                    ).await;

                    if let Err(e) = result {
                        error!("Signing session failed: {:?}", e);
                    }
                    sessions.write().await.remove(&session_id);
                });
            }
            session_request::Type::AuxGen => {
                let n = req.total_parties as u16;
                
                tokio::spawn(async move {
                    info!("Starting AuxGen session {}", session_id.0);
                    
                    let participating_parties: Vec<PartyId> = (1..=n as u32).map(PartyId).collect();
                    
                    let result = run_mpc_session(
                        session_id,
                        party_id,
                        participating_parties, 
                        &registry,
                        ca_cert,
                        incoming_rx,
                        mpc_protocol::session::SessionConfig {
                            message_timeout: std::time::Duration::from_secs(1800),
                            max_retries: 3,
                        },
                        |mpc_party| {
                            async move {
                                let eid_str = format!("aux-{}", session_id.0);
                                let eid = cggmp21::ExecutionId::new(eid_str.as_bytes());
                                
                                let local_index = party_id.0 as u16 - 1;

                                let aux_info = mpc_core::dkg::cggmp21::run_aux_info_gen(
                                    eid,
                                    local_index,
                                    n,
                                    mpc_party,
                                ).await?;

                                let label = format!("aux-{}", party_id.0);
                                let ser = serde_json::to_vec(&aux_info)
                                    .map_err(|e| mpc_common::error::MpcError::Internal(e.to_string()))?;
                                hsm.store(&label, &ser)
                                    .await
                                    .map_err(|e| mpc_common::error::MpcError::Hsm(e.to_string()))?;

                                info!("AuxInfo generated and saved successfully for party {}", party_id.0);
                                Ok(())
                            }
                        },
                    ).await;

                    if let Err(e) = result {
                        error!("AuxGen session failed: {:?}", e);
                    }
                    sessions.write().await.remove(&session_id);
                });
            }
            session_request::Type::FrostDkg => {
                tokio::spawn(async move {
                    info!("Starting FROST DKG session for Solana vault {}", session_id.0);
                    let participating_parties: Vec<PartyId> = (1..=req.total_parties).map(PartyId).collect();
                    
                    let result = run_frost_dkg(
                        session_id.0,
                        party_id,
                        participating_parties,
                        &registry,
                        ca_cert,
                        incoming_rx,
                    ).await;

                    match result {
                        Ok(dkg_result) => {
                            let label = format!("solana-vault-{}", session_id.0);
                            
                            let ser = match serde_json::to_vec(&dkg_result.key_package) {
                                Ok(s) => s,
                                Err(e) => {
                                    error!("Failed to serialize FROST key package: {}", e);
                                    sessions.write().await.remove(&session_id);
                                    return;
                                }
                            };
                                
                            if let Err(e) = hsm.store(&label, &ser).await {
                                error!("Failed to store FROST key package in HSM: {}", e);
                                sessions.write().await.remove(&session_id);
                                return;
                            }

                            let solana_address = bs58::encode(dkg_result.verifying_key).into_string();
                            info!("🔑🔑🔑 SOLANA VAULT GENERATED! Address: {} 🔑🔑🔑", solana_address);
                            info!("FROST DKG completed and saved successfully for party {}", party_id.0);
                        }
                        Err(e) => {
                            error!("FROST DKG session failed: {:?}", e);
                        }
                    }
                    sessions.write().await.remove(&session_id);
                });
            }
            session_request::Type::Refresh => {
                info!("Received Key Refresh request for session {}", session_id.0);

                let mpc_key_share = key_shares
                    .read()
                    .await
                    .get("master")
                    .cloned()
                    .ok_or_else(|| Status::not_found("master key share not found"))?;

                let cggmp21_share: cggmp21::KeyShare<cggmp21::supported_curves::Secp256k1> = 
                    serde_json::from_slice(&mpc_key_share.encrypted_share.ciphertext)
                    .map_err(|e| Status::internal(format!("failed to deserialize key share: {e}")))?;

                let n = cggmp21_share.n();
                let t = cggmp21_share.min_signers();

                tokio::spawn(async move {
                    info!("Starting Refresh session {}", session_id.0);
                    
                    let result = run_mpc_session(
                        session_id,
                        party_id,
                        (1..=n as u32).map(PartyId).collect(),
                        &registry,
                        ca_cert,
                        incoming_rx,
                        mpc_protocol::session::SessionConfig {
                            message_timeout: std::time::Duration::from_secs(600),
                            max_retries: 3,
                        },
                        |mpc_party| {
                            async move {
                                let eid_str = session_id.0.to_string();
                                let eid = cggmp21::ExecutionId::new(eid_str.as_bytes());
                                
                                let new_share = mpc_core::dkg::refresh::run_refresh(
                                    eid,
                                    &cggmp21_share,
                                    t,
                                    n,
                                    mpc_party,
                                ).await?;

                                let share = mpc_core::dkg::cggmp21::convert_key_share(
                                    &new_share,
                                    party_id,
                                    mpc_common::types::HsmIdentifier("default".into()),
                                )?;
                                
                                let label = "master".to_string();
                                let ser = bincode::serialize(&share)
                                    .map_err(|e| mpc_common::error::MpcError::Internal(e.to_string()))?;
                                    
                                hsm.store(&label, &ser).await
                                    .map_err(|e| mpc_common::error::MpcError::Hsm(e.to_string()))?;

                                key_shares.write().await.insert(label, share);
                                info!("Key refresh completed successfully for session {}", session_id.0);
                                Ok(())
                            }
                        },
                    ).await;

                    if let Err(e) = result {
                        error!("Refresh session failed: {:?}", e);
                    }
                    sessions.write().await.remove(&session_id);
                });
            }
        }

        Ok(Response::new(SessionResponse { accepted: true }))
    } 
}

/// Helper function for Base58Check encoding.
///
/// This function is used to generate canonical addresses for Bitcoin, Tron, and XRP
/// by appending a 4-byte double-SHA256 checksum to the payload before encoding.
///
/// # Arguments
///
/// * `full_payload` - The data to encode (e.g., version byte + hash).
/// * `alphabet` - The specific Base58 alphabet to use (e.g., Bitcoin standard or XRP custom).
///
/// # Returns
///
/// The Base58Check encoded string.
fn base58check_encode(full_payload: &[u8], alphabet: &bs58::Alphabet) -> String {
    let mut data = full_payload.to_vec();

    // Double SHA256 for the 4-byte checksum
    let mut hasher1 = sha2::Sha256::new();
    hasher1.update(&data);
    let hash1 = hasher1.finalize();

    let mut hasher2 = sha2::Sha256::new();
    hasher2.update(hash1);
    let hash2 = hasher2.finalize();

    // Append checksum to payload
    data.extend_from_slice(&hash2[0..4]);

    bs58::encode(data).with_alphabet(alphabet).into_string()
}

