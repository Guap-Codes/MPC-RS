//! # Party Routing and Registry
//!
//! This module provides the routing table that maps logical party identifiers (`PartyId`)
//! to their physical network addresses and mutual TLS (mTLS) identities.
//!
//! The `PartyRegistry` is used by the MPC nodes to establish secure, authenticated
//! gRPC connections to their peers during a distributed protocol execution, ensuring
//! that messages are routed to the correct endpoints with the correct cryptographic credentials.

use std::collections::HashMap;
use std::path::PathBuf;
use tonic::transport::Identity;

use mpc_common::types::PartyId;
use mpc_common::error::MpcResult;

/// Information needed to connect to a remote MPC party.
///
/// This struct encapsulates all the network and security parameters required
/// to establish an mTLS gRPC connection to a specific peer node.
#[derive(Clone)]
pub struct PartyEndpoint {
    /// The unique numeric identifier of the remote party.
    pub party_id: PartyId,
    /// The network address of the remote party (e.g., `"https://node2.mpc.internal:50051"`).
    pub address: String,
    /// The expected domain name in the remote party's TLS certificate (for SNI and SAN validation).
    pub domain: String,
    /// The local client's mTLS identity (certificate and private key) used to authenticate with the remote party.
    pub identity: Identity,
}

/// Holds the routing table for all known parties in the MPC cluster.
///
/// This registry is initialized at startup and provides thread-safe, read-only
/// access to peer connection details during protocol execution.
#[derive(Clone)]
pub struct PartyRegistry {
    parties: HashMap<PartyId, PartyEndpoint>,
}

impl PartyRegistry {
    /// Builds the registry from a list of endpoint definitions.
    ///
    /// # Arguments
    ///
    /// * `endpoints` - A vector of tuples containing:
    ///   1. `PartyId`: The unique identifier of the party.
    ///   2. `String`: The network address.
    ///   3. `String`: The TLS domain name.
    ///   4. `PathBuf`: Path to the client certificate for this connection.
    ///   5. `PathBuf`: Path to the client private key for this connection.
    ///
    /// # Returns
    ///
    /// A fully populated `PartyRegistry` ready for use.
    ///
    /// # Errors
    ///
    /// Returns `MpcError::Config` if any of the certificate or key files fail to load.
    pub fn new(endpoints: Vec<(PartyId, String, String, PathBuf, PathBuf)>) -> MpcResult<Self> {
        let mut map = HashMap::new();
        for (id, addr, domain, cert_path, key_path) in endpoints {
            let identity = crate::transport::load_identity(&cert_path, &key_path)?;
            map.insert(id, PartyEndpoint {
                party_id: id,
                address: addr,
                domain,
                identity,
            });
        }
        Ok(Self { parties: map })
    }

    /// Retrieves the endpoint information for a specific party.
    ///
    /// # Arguments
    ///
    /// * `id` - The `PartyId` to look up.
    ///
    /// # Returns
    ///
    /// An `Option` containing a reference to the `PartyEndpoint`, or `None` if the party is not registered.
    pub fn get(&self, id: PartyId) -> Option<&PartyEndpoint> {
        self.parties.get(&id)
    }

    /// Returns a list of all registered party identifiers.
    ///
    /// # Returns
    ///
    /// A `Vec<PartyId>` containing all known party IDs in the registry.
    pub fn all_ids(&self) -> Vec<PartyId> {
        self.parties.keys().copied().collect()
    }
}

