//! # Hardware Security Module Traits
//!
//! This module defines the core interfaces that HSM implementations must satisfy
//! to be integrated into the MPC-RS key management workflow.

use async_trait::async_trait;
use crate::error::HsmError;

/// The core interface for any Hardware Security Module (or software equivalent like SoftHSM).
///
/// Implementors of this trait abstract away the vendor-specific APIs (e.g., PKCS#11,
/// YubiHSM SDK) and provide a unified, asynchronous interface for securely storing,
/// retrieving, and managing encrypted MPC key shares.
///
/// # Thread Safety
/// Implementations must be `Send` and `Sync` to allow safe sharing across
/// asynchronous tasks within the MPC node's Tokio runtime.
#[allow(clippy::double_must_use)] // Suppresses false positive from async_trait macro expansion
#[async_trait]
pub trait HsmEngine: Send + Sync {
    /// Performs one-time initialization of the HSM connection.
    ///
    /// # Note
    ///
    /// This method has a default no-op implementation. Implementations that require
    /// explicit connection setup (e.g., opening a PKCS#11 session or authenticating
    /// with a remote service) should override this method.
    ///
    /// # Errors
    ///
    /// Returns [`HsmError::Internal`] or [`HsmError::Io`] if the initialization
    /// or authentication process fails.
    async fn initialize(&self) -> Result<(), HsmError> {
        Ok(())
    }

    /// Generates new key material internally within the HSM and stores it under the given label.
    ///
    /// # Arguments
    ///
    /// * `label` - A unique identifier for the generated key.
    ///
    /// # Note
    ///
    /// In the standard MPC-RS architecture, MPC key shares are generated locally
    /// in secure RAM during the DKG ceremony and then passed to the HSM via [`store`]
    /// for wrapping. This method is primarily used for generating the master AES
    /// wrapping key that resides permanently inside the HSM.
    ///
    /// # Errors
    ///
    /// Returns [`HsmError::Internal`] if the HSM fails to generate the key.
    async fn generate_key(&self, label: &str) -> Result<(), HsmError>;

    /// Encrypts (wraps) an opaque blob (e.g., an MPC key share) and stores it.
    ///
    /// # Arguments
    ///
    /// * `label` - A unique identifier for the stored blob, typically derived from the vault ID.
    /// * `data` - The raw, unencrypted data to be securely stored.
    ///
    /// # Errors
    ///
    /// Returns [`HsmError::Internal`] or [`HsmError::Io`] if the wrapping operation
    /// fails or if the encrypted blob cannot be written to the local filesystem.
    async fn store(&self, label: &str, data: &[u8]) -> Result<(), HsmError>;

    /// Retrieves and decrypts (unwraps) the blob stored under the given label.
    ///
    /// # Arguments
    ///
    /// * `label` - The unique identifier of the blob to retrieve.
    ///
    /// # Returns
    ///
    /// The raw, decrypted bytes of the stored data.
    ///
    /// # Errors
    ///
    /// Returns [`HsmError::KeyNotFound`] if the label does not exist.
    /// Returns [`HsmError::Internal`] if the unwrapping operation fails or
    /// the local filesystem read fails.
    async fn get(&self, label: &str) -> Result<Vec<u8>, HsmError>;

    /// Signs a 32-byte digest using the key referenced by the given label.
    ///
    /// # Arguments
    ///
    /// * `label` - The unique identifier of the key to use for signing.
    /// * `digest` - The 32-byte cryptographic hash to be signed.
    ///
    /// # Returns
    ///
    /// The raw signature bytes.
    ///
    /// # Note
    ///
    /// This method has a default implementation that returns [`HsmError::Unsupported`].
    /// In the MPC-RS architecture, the HSM is typically used *only* for key wrapping,
    /// while the actual MPC threshold signing is performed by the `mpc-core` nodes
    /// using the unwrapped shares. Implementations that support direct HSM signing
    /// (e.g., for break-glass scenarios) should override this method.
    ///
    /// # Errors
    ///
    /// Returns [`HsmError::KeyNotFound`] if the key does not exist.
    /// Returns [`HsmError::Unsupported`] if the HSM does not support direct signing.
    async fn sign(&self, _label: &str, _digest: &[u8]) -> Result<Vec<u8>, HsmError> {
        Err(HsmError::Unsupported("sign not implemented".to_string()))
    }

    /// Deletes the key or encrypted share stored under the given label.
    ///
    /// # Arguments
    ///
    /// * `label` - The unique identifier of the key or share to delete.
    ///
    /// # Returns
    ///
    /// `Ok(())` regardless of whether the key existed, ensuring idempotent cleanup.
    ///
    /// # Errors
    ///
    /// Returns [`HsmError::Internal`] or [`HsmError::Io`] if the deletion operation
    /// or local filesystem removal fails.
    async fn delete_key(&self, label: &str) -> Result<(), HsmError>;

    /// Replaces the share at `old_label` with `new_share` and stores it as `new_label`.
    ///
    /// This method facilitates secure key rotation by atomically (from the caller's
    /// perspective) storing the new share and optionally deleting the old one.
    ///
    /// # Arguments
    ///
    /// * `old_label` - The identifier of the existing share to be replaced.
    /// * `new_label` - The identifier for the newly rotated share.
    /// * `new_share` - The raw, unencrypted bytes of the new key share.
    /// * `delete_old` - If `true`, the old share is securely removed after the new one is stored.
    ///
    /// # Errors
    ///
    /// Returns [`HsmError::Internal`] or [`HsmError::Io`] if storing the new share
    /// or deleting the old share fails.
    async fn rotate_share(
        &self,
        old_label: &str,
        new_label: &str,
        new_share: &[u8],
        delete_old: bool,
    ) -> Result<(), HsmError> {
        self.store(new_label, new_share).await?;
        if delete_old {
            self.delete_key(old_label).await?;
        }
        Ok(())
    }

    /// Performs a liveness check to verify the HSM is connected and responsive.
    ///
    /// # Note
    ///
    /// This method has a default no-op implementation. Implementations should
    /// override this to perform a lightweight operation (e.g., querying HSM
    /// status or session info) to detect unexpected physical disconnections
    /// or network drops before attempting a critical signing operation.
    ///
    /// # Errors
    ///
    /// Returns [`HsmError::Internal`] if the HSM is no longer reachable.
    async fn health_check(&self) -> Result<(), HsmError> {
        Ok(())
    }
}

