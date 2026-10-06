//! # Configuration Management
//!
//! This module handles the parsing and validation of the `mpc-cli` configuration file.
//! The configuration is typically stored in `config/admin.toml` and contains the
//! necessary network endpoints and file paths for secure mTLS communication.

use serde::Deserialize;
use std::path::{Path, PathBuf};
use anyhow::{Result, Context};
use std::fs;

/// The root configuration structure for the administrative CLI.
#[derive(Debug, Deserialize)]
pub struct AdminConfig {
    /// Configuration for connecting to the MPC Coordinator.
    pub coordinator: CoordinatorConfig,
    
    /// Configuration for the mTLS certificates required for secure gRPC communication.
    pub tls: TlsConfig,
}

/// Configuration specific to the Coordinator's network endpoint.
#[derive(Debug, Deserialize)]
pub struct CoordinatorConfig {
    /// The full URL of the coordinator's gRPC service (e.g., `https://127.0.0.1:50052`).
    pub url: String,
}

/// Configuration specific to the mTLS certificate paths.
#[derive(Debug, Deserialize)]
pub struct TlsConfig {
    /// Path to the Certificate Authority (CA) public certificate.
    pub ca_cert: PathBuf,
    
    /// Path to the CLI client's public certificate.
    pub client_cert: PathBuf,
    
    /// Path to the CLI client's private key.
    pub client_key: PathBuf,
}

impl AdminConfig {
    /// Loads and parses the administrative configuration from a TOML file.
    ///
    /// # Arguments
    ///
    /// * `path` - The filesystem path to the `admin.toml` configuration file.
    ///
    /// # Returns
    ///
    /// A fully populated `AdminConfig` struct.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read, or if the TOML content
    /// fails to deserialize into the `AdminConfig` structure.
    pub fn load(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {:?}", path))?;
        let config: AdminConfig = toml::from_str(&content)
            .context("Failed to parse admin TOML config")?;
        Ok(config)
    }
}

