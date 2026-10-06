//! # Node Configuration Schema
//!
//! This module defines the configuration structures for MPC-RS nodes. 
//! It supports multiple HSM backends, mTLS network settings, and operational 
//! parameters, providing a unified schema that can be parsed from TOML or JSON.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// Top-level configuration for an MPC node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// The unique numeric identifier for this node in the MPC cluster.
    pub party_id: u32,
    /// The local socket address the node listens on for P2P gRPC traffic.
    pub listen_addr: SocketAddr,
    /// The socket address of the central Coordinator (if this node operates in a coordinated mode).
    pub coordinator_addr: Option<SocketAddr>,
    /// mTLS configuration for secure gRPC communication.
    pub tls: TlsConfig,
    /// Hardware Security Module backend selection and parameters.
    pub hsm: HsmConfig,
    /// Session timeout and retry parameters for network resilience.
    pub session: SessionConfig,
    /// Logging verbosity and export targets.
    pub logging: LoggingConfig,
    /// Known peers in the MPC cluster for direct P2P communication.
    pub peers: Vec<PeerConfig>,
}

/// TLS/mTLS configuration for secure gRPC communication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Path to the node's public certificate (PEM format).
    pub certificate_path: String,
    /// Path to the node's private key (PEM format).
    pub private_key_path: String,
    /// Path to the Certificate Authority (CA) certificate used to verify peers.
    pub ca_certificate_path: String,
}

/// HSM backend selection and connection parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsmConfig {
    /// The specific HSM provider implementation to use.
    pub provider: HsmProvider,
    /// The label or identifier for the master wrap key inside the HSM.
    pub share_label: String,
    
    /// Explicit configuration for the `SoftHSM` backend.
    #[serde(default)]
    pub soft_hsm: Option<SoftHsmConfig>,

    /// Generic JSON parameters for provider-specific settings 
    /// (e.g., `YubiHSM` connector URL, AWS `CloudHSM` PIN).
    #[serde(default)]
    pub connection_params: serde_json::Value, 
}

/// SoftHSM-specific configuration.
///
/// ⚠️ **Security Warning**: `SoftHSM` is intended for **development and testing only**.
/// It stores the master key on the local filesystem and does not provide hardware-backed 
/// security guarantees. It must never be used in a production custody environment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoftHsmConfig {
    /// Directory where encrypted key share blobs are stored.
    pub data_dir: String,
    /// Path to the file containing the hex-encoded master encryption key.
    pub master_key_file: String,
}

/// Supported HSM backends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HsmProvider {
    /// File-based software HSM (development/testing only).
    SoftHsm,
    /// `YubiHSM` 2 via USB or HTTP connector.
    YubiHSM,
    /// AWS `CloudHSM` via PKCS#11.
    AwsCloudHsm,
    /// Azure Dedicated HSM (Thales Luna) via PKCS#11.
    AzureDedicatedHsm,
}

/// Session timeout and retry configuration for network resilience.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    /// Maximum time to wait for a message from a peer before timing out (in seconds).
    pub message_timeout_secs: u64,
    /// Maximum number of retry attempts for transient network failures.
    pub max_retries: u32,
    /// Delay between retry attempts (in milliseconds).
    pub retry_interval_ms: u64,
}

/// Configuration for a known peer in the MPC cluster.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConfig {
    /// The unique numeric identifier of the peer.
    pub party_id: u32,
    /// The network address (IP:Port) of the peer.
    pub address: String,
    /// The expected domain name in the peer's TLS certificate (for SAN validation).
    pub domain: String,
    /// Path to the peer's public certificate (for mTLS pinning).
    pub cert_path: std::path::PathBuf,
    /// Path to the local private key used to authenticate with this peer.
    pub key_path: std::path::PathBuf,
}

/// Logging verbosity and export target configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// The minimum log level to output (e.g., "debug", "info", "warn", "error").
    pub level: String,
    /// The format of the log output ("json" for structured logging, "plain" for human-readable).
    pub format: LogFormat,
    /// Optional OpenTelemetry collector endpoint for centralized log aggregation.
    pub otlp_endpoint: Option<String>,
}

/// Supported log output formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogFormat {
    /// Structured JSON format, ideal for ingestion by log aggregators (e.g., Datadog, ELK).
    Json,
    /// Human-readable plain text format, ideal for local development and debugging.
    Plain,
}

