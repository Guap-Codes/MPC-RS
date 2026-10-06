//! # Secure gRPC Transport Layer
//!
//! This module provides the foundational networking utilities for establishing
//! secure, mutual TLS (mTLS) gRPC channels between MPC nodes.
//!
//! All communication in the MPC-RS system is encrypted in transit and mutually
//! authenticated, ensuring that nodes only communicate with verified peers and
//! that the network topology remains resistant to man-in-the-middle (MitM) attacks.

use std::fs;
use std::path::Path;

use tonic::transport::{Certificate, Identity, ClientTlsConfig, Channel};
use mpc_common::error::{MpcError, MpcResult};

/// Loads a TLS identity from a certificate file and a private key file.
///
/// # Arguments
///
/// * `cert_path` - Path to the PEM-encoded public certificate.
/// * `key_path` - Path to the PEM-encoded private key.
///
/// # Returns
///
/// A `tonic::transport::Identity` ready to be used in a `ClientTlsConfig` or `ServerTlsConfig`.
///
/// # Errors
///
/// Returns `MpcError::Config` if either file cannot be read from the filesystem.
pub fn load_identity(cert_path: &Path, key_path: &Path) -> MpcResult<Identity> {
    let cert = fs::read(cert_path)
        .map_err(|e| MpcError::Config(format!("failed to read cert: {e}")))?;
    let key = fs::read(key_path)
        .map_err(|e| MpcError::Config(format!("failed to read key: {e}")))?;

    let identity = Identity::from_pem(cert, key);
    Ok(identity)
}

/// Loads a CA certificate to use for verifying remote peer certificates.
///
/// # Arguments
///
/// * `ca_path` - Path to the PEM-encoded Certificate Authority (CA) certificate.
///
/// # Returns
///
/// A `tonic::transport::Certificate` ready to be used as the `client_ca_root` or `ca_certificate`.
///
/// # Errors
///
/// Returns `MpcError::Config` if the CA certificate file cannot be read from the filesystem.
pub fn load_ca_cert(ca_path: &Path) -> MpcResult<Certificate> {
    let ca = fs::read(ca_path)
        .map_err(|e| MpcError::Config(format!("failed to read CA: {e}")))?;
    Ok(Certificate::from_pem(ca))
}

/// Creates a secure, mTLS-enabled gRPC channel to a remote peer.
///
/// # Arguments
///
/// * `addr` - The network address of the remote peer (e.g., `"https://10.0.0.2:50051"`).
/// * `domain` - The expected domain name in the peer's TLS certificate (used for SNI and SAN validation).
/// * `identity` - The local client's mTLS identity (certificate and private key).
/// * `ca_cert` - The CA certificate used to verify the peer's server certificate.
///
/// # Returns
///
/// A connected `tonic::transport::Channel` ready for gRPC calls.
///
/// # Errors
///
/// Returns `MpcError::Network` if the address is invalid, the TLS configuration fails,
/// or the initial TCP/TLS handshake with the remote peer is unsuccessful.
///
/// # Note
///
/// The channel is configured with HTTP/2 keep-alive settings (60-second intervals, 5-minute timeout)
/// to prevent idle connections from being silently dropped by intermediate load balancers or firewalls.
pub async fn create_tls_channel(
    addr: &str,
    domain: &str,
    identity: Identity,
    ca_cert: Certificate,
) -> MpcResult<Channel> {
    let tls_config = ClientTlsConfig::new()
        .identity(identity)
        .ca_certificate(ca_cert)
        .domain_name(domain.to_owned());

    let channel = Channel::from_shared(addr.to_owned())
        .map_err(|e| MpcError::Network(e.to_string()))?
        .tls_config(tls_config)
        .map_err(|e| MpcError::Network(e.to_string()))?
        // Keep alive while idle, and wait 5 minutes before dropping the connection
        .keep_alive_while_idle(true)
        .http2_keep_alive_interval(std::time::Duration::from_secs(60))
        .keep_alive_timeout(std::time::Duration::from_secs(300))
        .connect()
        .await
        .map_err(|e| MpcError::Network(e.to_string()))?;

    Ok(channel)
}