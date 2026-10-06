//! # Hardware Security Module (HSM) Management
//!
//! This module is responsible for instantiating the correct HSM backend
//! based on the node's configuration. It acts as a factory for the
//! `HsmEngine` trait, ensuring the node can securely store and retrieve
//! its MPC key shares.

use std::sync::Arc;
use mpc_common::config::{HsmConfig, HsmProvider};
use mpc_common::error::{MpcError, MpcResult};
use hsm_core::traits::HsmEngine;

/// Loads and initializes the configured HSM engine.
///
/// This function acts as a factory, matching the `HsmProvider` enum from
/// the configuration to the concrete implementation of the `HsmEngine` trait.
///
/// # Arguments
///
/// * `config` - The HSM configuration section from the node's TOML file.
///
/// # Returns
///
/// An `Arc<dyn HsmEngine + Send + Sync>` ready to be used by the node
/// for secure key share management.
///
/// # Errors
///
/// Returns `MpcError::Hsm` if the selected provider is not yet implemented,
/// or if the underlying HSM initialization fails (e.g., missing files,
/// invalid credentials, or hardware connection issues).
///
/// # Note
///
/// Currently, only `SoftHsm` is fully implemented for local development
/// and testing. Production deployments should use `YubiHSM`, `AwsCloudHsm`,
/// or `AzureDedicatedHsm` once their respective integrations are complete.
pub async fn load_hsm(config: &HsmConfig) -> MpcResult<Arc<dyn HsmEngine + Send + Sync>> {
    match config.provider {
        HsmProvider::SoftHsm => {
            let engine = soft_hsm::SoftHsm::new(&config.share_label, &config.connection_params)
                .map_err(|e| MpcError::Hsm(e.to_string()))?;
            Ok(Arc::new(engine))
        }
        HsmProvider::YubiHSM => {
            // TODO: Integrate yubihsm crate for production hardware security
            Err(MpcError::Hsm("YubiHSM not yet implemented".into()))
        }
        HsmProvider::AwsCloudHsm => {
            // TODO: Integrate aws-cloudhsm crate for production hardware security
            Err(MpcError::Hsm("AWS CloudHSM not yet implemented".into()))
        }
        HsmProvider::AzureDedicatedHsm => {
            // TODO: Integrate azure-hsm crate for production hardware security
            Err(MpcError::Hsm("Azure HSM not yet implemented".into()))
        }
    }
}

