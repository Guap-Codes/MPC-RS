//! # gRPC Client and Authentication
//!
//! This module provides the secure communication layer between the `mpc-cli` and
//! the `mpc-coordinator`. It enforces mutual TLS (mTLS) for transport security and
//! injects a JWT Bearer token into every request for identity and authorization.

use anyhow::{Result, Context};
use tonic::transport::{Channel, ClientTlsConfig, Certificate, Identity};
use tonic::service::{Interceptor, interceptor::InterceptedService};
use tonic::Request;
use std::path::Path;
use std::fs;

// Include the generated proto code for the Coordinator service.
pub mod coordinator_proto {
    tonic::include_proto!("coordinator");
}

/// A tonic interceptor that attaches a JWT Bearer token to every outgoing gRPC request.
///
/// This ensures that every administrative command is authenticated and authorized
/// by the coordinator's policy engine before execution.
#[derive(Clone)]
pub struct AuthInterceptor {
    /// The pre-signed JWT string to be injected into the `authorization` header.
    token: String,
}

impl Interceptor for AuthInterceptor {
    /// Intercepts the request and injects the `Authorization: Bearer <token>` header.
    ///
    /// # Arguments
    ///
    /// * `request` - The outgoing gRPC request to be modified.
    ///
    /// # Returns
    ///
    /// The modified request, or a `tonic::Status::internal` error if the token
    /// formatting fails (which should be impossible for a valid UTF-8 string).
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, tonic::Status> {
        // Format the token as a Bearer token and parse it into a gRPC MetadataValue
        let meta_value = format!("Bearer {}", self.token)
            .parse()
            .map_err(|_| tonic::Status::internal("Invalid token format"))?;
            
        request.metadata_mut().insert("authorization", meta_value);
        Ok(request)
    }
}

/// A secure, authenticated gRPC client for interacting with the MPC Coordinator.
///
/// This client wraps the generated `CoordinatorClient` with an `AuthInterceptor`
/// and an mTLS-configured `Channel`, ensuring end-to-end encryption and authentication.
pub struct AdminClient {
    /// The inner gRPC client, configured with mTLS and the JWT interceptor.
    pub inner: coordinator_proto::coordinator_client::CoordinatorClient<
        InterceptedService<Channel, AuthInterceptor>
    >,
}

impl AdminClient {
    /// Establishes a secure, authenticated connection to the MPC Coordinator.
    ///
    /// # Arguments
    ///
    /// * `coordinator_url` - The URL of the coordinator's gRPC endpoint (e.g., `https://127.0.0.1:50052`).
    /// * `tls_ca` - Path to the Certificate Authority (CA) PEM file.
    /// * `tls_cert` - Path to the client's public certificate PEM file.
    /// * `tls_key` - Path to the client's private key PEM file.
    ///
    /// # Returns
    ///
    /// An initialized `AdminClient` ready to execute administrative RPCs.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The `MPC_TOKEN` environment variable is not set.
    /// - Any of the TLS certificate files cannot be read or parsed.
    /// - The coordinator URL is invalid or the network connection fails.
    pub async fn connect(coordinator_url: &str, tls_ca: &Path, tls_cert: &Path, tls_key: &Path) -> Result<Self> {
        // 1. Read the JWT from the environment
        let token = std::env::var("MPC_TOKEN")
            .context("MPC_TOKEN environment variable not set. Run: export MPC_TOKEN=$(./target/release/mpc-cli dev-token)")?;

        // 2. Load TLS certificates for mTLS
        let ca_pem = fs::read_to_string(tls_ca).context("Failed to read CA cert")?;
        let cert_pem = fs::read_to_string(tls_cert).context("Failed to read client cert")?;
        let key_pem = fs::read_to_string(tls_key).context("Failed to read client key")?;

        let ca = Certificate::from_pem(ca_pem);
        let identity = Identity::from_pem(cert_pem, key_pem);

        let tls_config = ClientTlsConfig::new()
            .ca_certificate(ca)
            .identity(identity)
            .domain_name("coordinator"); // Must match the CN/SAN in the coordinator's certificate

        // 3. Establish the secure mTLS channel
        let channel = Channel::from_shared(coordinator_url.to_string())
            .context("Invalid coordinator URL")?
            .tls_config(tls_config)?
            .connect()
            .await
            .context("Failed to connect to coordinator")?;

        // 4. Attach the AuthInterceptor to the client
        let interceptor = AuthInterceptor { token };
        let inner = coordinator_proto::coordinator_client::CoordinatorClient::with_interceptor(channel, interceptor);
        
        Ok(Self { inner })
    }
}
