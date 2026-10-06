//! # Software HSM (`soft-hsm`)
//!
//! This crate provides a software-based implementation of the [`HsmEngine`] trait,
//! backed by AES-256-GCM encrypted file storage.
//!
//! ## Purpose
//! The `SoftHsm` is designed exclusively for local development, integration testing,
//! and CI environments where provisioning a physical or cloud-based HSM is impractical.
//! It allows the MPC-RS codebase to be tested end-to-end without hardware dependencies.
//!
//! ⚠️ **Security Warning**: This crate does **not** provide hardware-backed security.
//! The master key is stored in plaintext on the local filesystem. It must **never**
//! be used in a production custody environment. Always use a hardware-backed 
//! implementation (e.g., `aws-cloudhsm`, `azure-hsm`, `yubihsm`) in production.

pub mod file_store;

use std::sync::Arc;
use async_trait::async_trait;
use hsm_core::traits::HsmEngine;
use hsm_core::error::HsmError;
use file_store::FileStore;
use serde_json::Value;

/// A software HSM backed by encrypted file storage.
///
/// This struct implements the [`HsmEngine`] trait by delegating all cryptographic 
/// operations to the underlying [`FileStore`].
pub struct SoftHsm {
    store: FileStore,
}

impl SoftHsm {
    /// Creates a new `SoftHsm` instance, initializing the underlying encrypted file store.
    ///
    /// # Arguments
    ///
    /// * `storage_dir` – The directory path where encrypted blobs will be kept.
    /// * `params` – An optional JSON configuration object. If it contains a 
    ///   `"master_key_hex"` string, that key will be used. Otherwise, the store 
    ///   will load or generate a key automatically.
    ///
    /// # Returns
    ///
    /// An initialized `SoftHsm` ready to satisfy the [`HsmEngine`] trait.
    ///
    /// # Errors
    ///
    /// Returns [`HsmError::Serialization`] or [`HsmError::Io`] if the underlying 
    /// `FileStore` fails to initialize.
    pub fn new(storage_dir: &str, params: &Value) -> Result<Self, HsmError> {
        let existing_key = params.get("master_key_hex").and_then(|v| v.as_str());
        let store = FileStore::new(storage_dir, existing_key)?;
        Ok(Self { store })
    }
}

#[async_trait]
impl HsmEngine for SoftHsm {
    /// A no-op for this implementation.
    ///
    /// # Note
    ///
    /// In the MPC-RS architecture, MPC key shares are generated locally in secure RAM 
    /// by the MPC nodes during the DKG ceremony. The HSM is only used to wrap/unwrap 
    /// these shares. Therefore, the Soft HSM does not implement internal key generation.
    async fn generate_key(&self, _label: &str) -> Result<(), HsmError> {
        Err(HsmError::Unsupported(
            "soft-hsm does not generate MPC shares".into(),
        ))
    }

    /// Encrypts and stores the provided data under the given label.
    async fn store(&self, label: &str, data: &[u8]) -> Result<(), HsmError> {
        self.store.store(label, data).await
    }

    /// Retrieves and decrypts the data stored under the given label.
    async fn get(&self, label: &str) -> Result<Vec<u8>, HsmError> {
        self.store.get(label).await
    }

    /// Securely deletes the encrypted data stored under the given label.
    async fn delete_key(&self, label: &str) -> Result<(), HsmError> {
        self.store.delete(label).await
    }

    /// Verifies that the underlying storage directory is accessible.
    async fn health_check(&self) -> Result<(), HsmError> {
        self.store.health_check().await
    }
}


