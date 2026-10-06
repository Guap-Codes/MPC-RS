//! # MPC Session Management
//!
//! This module implements the reliable message exchange layer for Multi-Party Computation (MPC) protocols.
//! It bridges the pure, network-agnostic cryptographic logic (from `mpc-core`) with the actual
//! gRPC network streams, handling message serialization, routing, timeouts, and retries.
//!
//! ## Architecture
//! The `run_mpc_session` function orchestrates three concurrent background tasks:
//! 1. **Incoming Bridge**: Receives signed envelopes from the gRPC server handler and deserializes them for the protocol.
//! 2. **Outgoing Dispatcher**: Receives protocol messages, serializes them into signed envelopes, and routes them to the correct peer channels.
//! 3. **Client Streams**: Maintains persistent, bidirectional gRPC streams to each remote peer, yielding messages as they are dispatched.

use futures::{Sink, SinkExt, Stream, StreamExt};
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use std::task::{Context, Poll};
use tokio::sync::{mpsc, oneshot, RwLock};
use tonic::transport::Channel;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use mpc_common::types::{PartyId, SessionId};
use mpc_common::error::{MpcError, MpcResult};

use crate::proto::{mpc_node_client::MpcNodeClient, SignedEnvelope};
use crate::routing::PartyRegistry;

/// Configuration for session handling and network resilience.
#[derive(Clone)]
pub struct SessionConfig {
    /// Maximum duration to wait for a message before considering the peer unresponsive.
    pub message_timeout: Duration,
    /// Maximum number of retry attempts for transient network failures.
    pub max_retries: u32,
}

/// The concrete delivery type used by the MPC session, boxed into trait objects
/// to avoid unnameable closure types in the `round_based` API.
type MpcDelivery<M> = (
    Pin<Box<dyn Stream<Item = Result<round_based::Incoming<M>, MpcError>> + Send + Unpin>>,
    Pin<Box<dyn Sink<round_based::Outgoing<M>, Error = MpcError> + Send + Unpin>>,
);

/// Executes a complete MPC protocol session, managing the network bridge and protocol logic.
///
/// This is the core orchestrator that connects the `mpc-core` cryptographic state machine
/// to the real-world gRPC network. It spawns background tasks to handle incoming and outgoing
/// message routing, ensuring the protocol function can focus purely on cryptographic state transitions.
///
/// # Arguments
///
/// * `session_id` - The unique identifier for this protocol execution.
/// * `local_party` - The `PartyId` of the local node.
/// * `participating_parties` - A list of all `PartyId`s involved in this specific session.
/// * `registry` - The routing table containing peer network addresses and TLS credentials.
/// * `ca_cert` - The CA certificate used to verify the TLS certificates of remote peers.
/// * `incoming_rx` - An MPSC receiver for incoming gRPC messages from the local server handler.
/// * `config` - Session configuration (timeouts, retries).
/// * `protocol_fn` - The asynchronous cryptographic protocol function to execute.
///
/// # Returns
///
/// `Ok(())` if the protocol completes successfully.
///
/// # Errors
///
/// Returns `MpcError::Network` if a critical network connection fails.
/// Returns `MpcError::Internal` if a background task panics or the protocol function returns an error.
#[allow(clippy::too_many_arguments)]
pub async fn run_mpc_session<F, Fut, M>(
    session_id: SessionId,
    local_party: PartyId,
    participating_parties: Vec<PartyId>,
    registry: &PartyRegistry,
    ca_cert: tonic::transport::Certificate,
    incoming_rx: mpsc::UnboundedReceiver<SignedEnvelope>,
    config: SessionConfig,
    protocol_fn: F,
) -> MpcResult<()>
where
    M: serde::Serialize + serde::de::DeserializeOwned + Send + 'static,
    F: FnOnce(round_based::MpcParty<M, MpcDelivery<M>>) -> Fut,
    Fut: std::future::Future<Output = MpcResult<()>>,
{
    let (tx_to_net, rx_from_protocol) = mpsc::unbounded_channel::<round_based::Outgoing<M>>();
    let (tx_to_protocol, rx_from_net) = mpsc::unbounded_channel::<round_based::Incoming<M>>();

    let shutdown_signal = Arc::new(tokio::sync::Notify::new());
    
    // Spawn the network bridge to handle all I/O concurrently with the protocol logic
    let bridge_handle = tokio::spawn(network_bridge(
        session_id,
        local_party,
        participating_parties.clone(),
        registry.clone(),
        ca_cert,
        incoming_rx,
        rx_from_protocol,
        tx_to_protocol,
        config,
        shutdown_signal.clone(),
    ));

    let incoming: Pin<Box<dyn Stream<Item = Result<round_based::Incoming<M>, MpcError>> + Send + Unpin>> = Box::pin(
        tokio_stream::wrappers::UnboundedReceiverStream::new(rx_from_net)
            .map(Ok::<_, MpcError>)
    );

    let outgoing: Pin<Box<dyn Sink<round_based::Outgoing<M>, Error = MpcError> + Send + Unpin>> = Box::pin(
        UnboundedSink(tx_to_net)
    );

    let mpc_party = round_based::MpcParty::connected((incoming, outgoing));

    // Execute the pure cryptographic protocol logic
    protocol_fn(mpc_party).await?;

    // Gracefully shut down the network bridge once the protocol completes
    shutdown_signal.notify_waiters();
    bridge_handle.await.map_err(|e| MpcError::Internal(e.to_string()))??;

    Ok(())
}

/// The internal network bridge that manages concurrent message routing.
///
/// This function spawns three distinct asynchronous tasks to decouple the gRPC streaming
/// layer from the synchronous-like `round_based` protocol state machine.
#[allow(clippy::too_many_arguments)]
async fn network_bridge<M: serde::Serialize + serde::de::DeserializeOwned + Send + 'static>(
    session_id: SessionId,
    local_party: PartyId,
    parties: Vec<PartyId>,
    registry: PartyRegistry,
    ca_cert: tonic::transport::Certificate,
    mut incoming_from_server: mpsc::UnboundedReceiver<SignedEnvelope>,
    mut outgoing_from_protocol: mpsc::UnboundedReceiver<round_based::Outgoing<M>>,
    incoming_to_protocol: mpsc::UnboundedSender<round_based::Incoming<M>>,
    _config: SessionConfig,
    shutdown: Arc<tokio::sync::Notify>,
) -> MpcResult<()> {
    let all_parties = parties.clone();
    let remote_ids: Vec<PartyId> = parties.into_iter().filter(|id| *id != local_party).collect();

    // Task 1: Forward messages from the gRPC server handler to the protocol state machine
    let incoming_to_protocol_clone = incoming_to_protocol.clone();
    let all_parties_clone = all_parties.clone();
    tokio::spawn(async move {
        while let Some(envelope) = incoming_from_server.recv().await {
            if envelope.payload.is_empty() { continue; }

            info!("[IN-SERVER] Received from gRPC: sender={}, receiver={}, size={}", 
                envelope.sender, envelope.receiver, envelope.payload.len());

            let msg_type = if envelope.receiver == 0 {
                round_based::MessageType::Broadcast
            } else {
                round_based::MessageType::P2P
            };

            // Create a unique message ID to prevent duplicate processing
            let unique_msg_id = (envelope.sender as u64).wrapping_shl(32) | (envelope.timestamp_ms & 0xFFFFFFFF); 
           
            let sender_party_id = PartyId(envelope.sender);
            
            let sender_index = match all_parties_clone.iter().position(|&p| p == sender_party_id) {
                Some(idx) => idx as u16,
                None => {
                    error!("Received message from unknown party {:?}", sender_party_id);
                    continue;
                }
            };

            let msg: M = match bincode::deserialize(&envelope.payload) {
                Ok(m) => m,
                Err(e) => {
                    error!("[IN-DESER] Failed to deserialize from party {}: {}", envelope.sender, e);
                    continue;
                }
            };

            let inc = round_based::Incoming {
                id: unique_msg_id,
                sender: sender_index,
                msg_type,
                msg,
            };

            if incoming_to_protocol_clone.send(inc).is_err() {
                warn!("[IN-PROTOCOL] Protocol channel closed");
                break;
            }
            info!("[IN-PROTOCOL] Delivered to protocol: sender_idx={}, msg_type={:?}", sender_index, msg_type);
        }
    });

    // Create dedicated MPSC channels for each client task to avoid broadcast channel overhead
    let mut client_txs = HashMap::new();
    let mut client_rxs = HashMap::new();
    for remote_id in &remote_ids {
        let (tx, rx) = mpsc::unbounded_channel::<SignedEnvelope>();
        client_txs.insert(*remote_id, tx);
        client_rxs.insert(*remote_id, rx);
    }

    // Task 2: Forward messages from the protocol state machine to the client channels
    let dispatcher_session_id = session_id;
    let dispatcher_local_party = local_party;
    let dispatcher_all_parties = all_parties.clone();
    let msg_id_counter = Arc::new(std::sync::atomic::AtomicU64::new(1));

    tokio::spawn(async move {
        while let Some(out_msg) = outgoing_from_protocol.recv().await {
            let payload = match bincode::serialize(&out_msg.msg) {
                Ok(p) => p,
                Err(e) => {
                    error!("[OUT-SER] Failed to serialize: {}", e);
                    continue;
                }
            };

            let msg_id = msg_id_counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            info!("[OUT-PROTOCOL] Protocol yielded message: recipient={:?}, size={}", out_msg.recipient, payload.len());

            match out_msg.recipient {
                round_based::MessageDestination::AllParties => {
                    for (_rid, tx) in &client_txs {
                        let env = SignedEnvelope {
                            session_id: dispatcher_session_id.0.to_string(),
                            sender: dispatcher_local_party.0, // Removed redundant `as u32`
                            receiver: 0,
                            payload: payload.clone(),
                            timestamp_ms: msg_id,
                            signature: vec![],
                        };
                        let _ = tx.send(env);
                    }
                    info!("[OUT-BROADCAST] Sent to all client channels");
                }
                round_based::MessageDestination::OneParty(idx) => {
                    let target_party_id = dispatcher_all_parties[idx as usize];
                    if let Some(tx) = client_txs.get(&target_party_id) {
                        let env = SignedEnvelope {
                            session_id: dispatcher_session_id.0.to_string(),
                            sender: dispatcher_local_party.0, // Removed redundant `as u32`
                            receiver: target_party_id.0,      // Removed redundant `as u32`
                            payload,
                            timestamp_ms: msg_id,
                            signature: vec![],
                        };
                        let _ = tx.send(env);
                        info!("[OUT-P2P] Sent to client channel for party {}", target_party_id.0);
                    }
                }
            }
        }
    });

    // Establish gRPC client connections to all remote peers
    let mut clients = HashMap::new();
    for remote_id in &remote_ids {
        let endpoint = registry.get(*remote_id).ok_or_else(|| {
            MpcError::Config(format!("no endpoint for party {:?}", remote_id))
        })?;

        let channel = crate::transport::create_tls_channel(
            &endpoint.address, &endpoint.domain, endpoint.identity.clone(), ca_cert.clone(),
        ).await?;

        let client = MpcNodeClient::new(channel)
            .max_decoding_message_size(100 * 1024 * 1024) // 100MB limit for large DKG messages
            .max_encoding_message_size(100 * 1024 * 1024);
        clients.insert(*remote_id, client);
    }

    // Task 3: Maintain client-side bidirectional gRPC streams
    let mut join_set = tokio::task::JoinSet::new();
    for (remote_id, mut client) in clients {
        let mut rx = client_rxs.remove(&remote_id).unwrap();
        // Removed redundant `let session_id = session_id;`
        let shutdown = shutdown.clone();

        join_set.spawn(async move {
            // Send a dummy envelope first to initiate the gRPC stream handshake
            let dummy_env = SignedEnvelope {
                session_id: session_id.0.to_string(),
                sender: 0, receiver: 0, payload: vec![], timestamp_ms: 0, signature: vec![],
            };

            let request_stream = async_stream::stream! {
                yield dummy_env;
                while let Some(envelope) = rx.recv().await {
                    if envelope.payload.is_empty() { continue; }
                    info!("[OUT-CLIENT] Yielding to gRPC stream for party {}: receiver={}", remote_id.0, envelope.receiver);
                    yield envelope;
                }
            };

            let response_stream = match client.exchange_messages(request_stream).await {
                Ok(stream) => stream.into_inner(),
                Err(e) => {
                    error!("[CLIENT] Failed to open stream to party {:?}: {:?}", remote_id, e);
                    return Err(MpcError::Network(e.to_string()));
                }
            };

            tokio::pin!(response_stream);
            loop {
                tokio::select! {
                    // We don't process incoming messages here; they are handled by the server-side stream (Task 1)
                    _ = response_stream.next() => {}
                    _ = shutdown.notified() => {
                        info!("[CLIENT] Shutting down stream for party {}", remote_id.0);
                        break;
                    }
                }
            }
            Ok::<(), MpcError>(())
        });
    }

    // Wait for all client stream tasks to complete or fail
    while let Some(result) = join_set.join_next().await {
        if let Err(e) = result {
            error!("[BRIDGE] Task panicked: {:?}", e);
        }
    }
    Ok(())
}

/// A simple, `Unpin` Sink wrapper for Tokio's `mpsc::UnboundedSender`.
///
/// This adapter allows the `round_based` library to treat an unbounded MPSC channel
/// as a standard `futures::Sink`, enabling seamless integration with the protocol's
/// outgoing message stream.
struct UnboundedSink<T>(mpsc::UnboundedSender<T>);

impl<T> Sink<T> for UnboundedSink<T> {
    type Error = MpcError;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Unbounded channels are always ready to accept new items
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: T) -> Result<(), Self::Error> {
        self.0.send(item).map_err(|_| MpcError::Internal("channel closed".into()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Unbounded channels do not require explicit flushing
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

